#include "hal_acl_resource.h"
#include "hal_flow_table.h"

#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fm_sdk.h>
#include <api/fm_api_acl.h>
#include <api/fm_api_addr.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_flow.h>
#include <api/fm_api_lag.h>
#include <api/fm_api_multicast.h>
#include <api/fm_api_nexthop.h>
#include <api/fm_api_policer.h>
#include <api/fm_api_regs.h>
#include <api/fm_api_routing.h>
#include <api/fm_api_storm.h>
#include <api/fm_api_vlan.h>
#include <api/internal/fm10000/fm10000_api_regs_int.h>
#include <debug/fm_debug.h>

#ifndef FM_MAX_VLAN
#define FM_MAX_VLAN 4096
#endif

#ifndef FM_MAX_NUM_MULTICAST_GROUP
#define FM_MAX_NUM_MULTICAST_GROUP 4096
#endif

static void init_unknown_resources(struct sdk_result *result) {
    nl_pfe_resources *r = &result->data.pfe_resources;
    int *p = (int *)r;
    size_t n = offsetof(nl_pfe_resources, flow_owner_count) / sizeof(int);

    memset(r, 0, sizeof(*r));
    for (size_t i = 0; i < n; i++)
        p[i] = -1;

    r->flow_owner_count = 0;
    for (int i = 0; i < NETLAB_FLOW_TABLE_OWNER_MAX; i++) {
        r->flow_owner[i].table = -1;
        r->flow_owner[i].owner = -1;
        r->flow_owner[i].capacity = -1;
        r->flow_owner[i].used = -1;
        r->flow_owner[i].free = -1;
        r->flow_owner[i].max_actions = -1;
        r->flow_owner[i].condition = -1;
        r->flow_owner[i].name[0] = '\0';
    }
    r->acl_owner_count = 0;
    for (int i = 0; i < NETLAB_ACL_RESOURCE_OWNER_MAX; i++) {
        r->acl_owner[i].acl = -1;
        r->acl_owner[i].acl_count = -1;
        r->acl_owner[i].rules_per_acl = -1;
        r->acl_owner[i].owner = -1;
        r->acl_owner[i].first_policer = -1;
        r->acl_owner[i].policer_count = -1;
        r->acl_owner[i].name[0] = '\0';
    }
}

static bool mac_is_multicast(fm_macaddr mac) {
    return ((mac >> 40) & 0x01) != 0;
}

static bool port_is_lag_logical(int sw, int port) {
    fm_int lag = 0;
    return fmLogicalPortToLAGNumber((fm_int)sw, (fm_int)port, &lag) == FM_OK;
}

typedef struct {
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    nl_switch_entry switches[NL_MAX_SWITCHES_PER_PROFILE];
    nl_lane_entry lanes[NL_MAX_LANES_PER_PROFILE];
    nl_xcvr_entry xcvrs[NL_MAX_XCVRS_PER_PROFILE];
} profile_resource_work;

static void collect_profile_resources(struct sdk_result *result) {
    profile_resource_work *work;

    work = calloc(1, sizeof(*work));
    if (!work) {
        NL_LOG_WARN("profile resource workspace allocation failed");
        return;
    }

    result->data.pfe_resources.profile_ports =
        nl_ifid_get_all(work->ports, NL_MAX_PORTS_PER_PROFILE);
    result->data.pfe_resources.profile_switches =
        nl_platform_get_switches(work->switches,
                                 NL_MAX_SWITCHES_PER_PROFILE);
    result->data.pfe_resources.profile_lanes =
        nl_platform_get_lanes(work->lanes, NL_MAX_LANES_PER_PROFILE);
    result->data.pfe_resources.profile_xcvrs =
        nl_platform_get_xcvrs(work->xcvrs, NL_MAX_XCVRS_PER_PROFILE);
    result->data.pfe_resources.profile_max_ae = nl_platform_max_ae();
    free(work);
}

static void collect_mac_resources(int sw, struct sdk_result *result) {
    fm_uint32 table_size = 0;
    fm_status st;
    int max_entries;
    fm_macAddressEntry *entries;
    fm_int n_entries;

    st = fmGetAddressTableAttribute((fm_int)sw, FM_MAC_TABLE_SIZE,
                                    &table_size);
    if (st == FM_OK && table_size >= sizeof(fm_macAddressEntry)) {
        result->data.pfe_resources.mac_raw_bytes = (int)table_size;
        result->data.pfe_resources.mac_entry_size =
            (int)sizeof(fm_macAddressEntry);
        result->data.pfe_resources.mac_capacity =
            (int)(table_size / sizeof(fm_macAddressEntry));
    }

    max_entries = result->data.pfe_resources.mac_capacity > 0 ?
                  result->data.pfe_resources.mac_capacity : 4096;
    if (max_entries > 65536)
        max_entries = 65536;
    if (max_entries <= 0)
        max_entries = 4096;

    entries = calloc((size_t)max_entries, sizeof(*entries));
    if (!entries)
        return;

    n_entries = max_entries;
    st = fmGetAddressTableExt((fm_int)sw, &n_entries, entries, max_entries);
    if (st != FM_OK) {
        free(entries);
        return;
    }

    result->data.pfe_resources.mac_used = (int)n_entries;
    result->data.pfe_resources.mac_static = 0;
    result->data.pfe_resources.mac_dynamic = 0;
    result->data.pfe_resources.mac_multicast = 0;
    result->data.pfe_resources.mac_internal = 0;
    result->data.pfe_resources.mac_visible = 0;
    result->data.pfe_resources.mac_truncated =
        (result->data.pfe_resources.mac_capacity > max_entries &&
         n_entries >= max_entries) ? 1 : 0;

    for (fm_int i = 0; i < n_entries && i < max_entries; i++) {
        bool multicast = mac_is_multicast(entries[i].macAddress);
        bool known_port =
            nl_ifid_get_by_logical_port((int)entries[i].port, NULL) &&
            nl_ifid_is_user_port((int)entries[i].port);
        bool internal = !known_port &&
                        !port_is_lag_logical(sw, (int)entries[i].port);

        if (entries[i].type == FM_ADDRESS_STATIC ||
            entries[i].type == FM_ADDRESS_SECURE_STATIC)
            result->data.pfe_resources.mac_static++;
        else
            result->data.pfe_resources.mac_dynamic++;
        if (multicast)
            result->data.pfe_resources.mac_multicast++;
        if (internal)
            result->data.pfe_resources.mac_internal++;
        if (!internal && !multicast)
            result->data.pfe_resources.mac_visible++;
    }

    free(entries);
}

static void collect_vlan_resources(int sw, struct sdk_result *result) {
    fm_uint16 vlans[FM_MAX_VLAN];
    fm_int n_vlans = FM_MAX_VLAN;
    fm_status st;

    result->data.pfe_resources.vlan_capacity = FM_MAX_VLAN;
    st = fmGetVlanList((fm_int)sw, &n_vlans, vlans, FM_MAX_VLAN);
    if (st != FM_OK)
        return;

    result->data.pfe_resources.vlan_used = (int)n_vlans;
    result->data.pfe_resources.vlan_memberships = 0;
    for (fm_int i = 0; i < n_vlans; i++) {
        fm_int ports[512];
        fm_int n_ports = 512;
        if (fmGetVlanPortList((fm_int)sw, vlans[i], &n_ports,
                              ports, 512) == FM_OK)
            result->data.pfe_resources.vlan_memberships += (int)n_ports;
    }
}

static void collect_lag_resources(int sw, struct sdk_result *result) {
    fm_int lags[NETLAB_MAX_AE];
    fm_int n_lags = NETLAB_MAX_AE;
    int max_ae = nl_platform_max_ae();
    fm_status st;

    result->data.pfe_resources.lag_capacity =
        max_ae > 0 && max_ae <= NETLAB_MAX_AE ? max_ae : NETLAB_MAX_AE;
    result->data.pfe_resources.lag_member_capacity = NETLAB_MAX_LAG_MEMBERS;

    st = fmGetLAGList((fm_int)sw, &n_lags, lags, NETLAB_MAX_AE);
    if (st == FM_ERR_NO_LAGS) {
        result->data.pfe_resources.lag_used = 0;
        result->data.pfe_resources.lag_members = 0;
        return;
    }
    if (st != FM_OK)
        return;

    result->data.pfe_resources.lag_used = (int)n_lags;
    result->data.pfe_resources.lag_members = 0;
    for (fm_int i = 0; i < n_lags; i++) {
        fm_int ports[NETLAB_MAX_LAG_MEMBERS];
        fm_int n_ports = NETLAB_MAX_LAG_MEMBERS;
        if (fmGetLAGPortList((fm_int)sw, lags[i], &n_ports, ports,
                             NETLAB_MAX_LAG_MEMBERS) == FM_OK)
            result->data.pfe_resources.lag_members += (int)n_ports;
    }
}

static void collect_mcast_resources(int sw, struct sdk_result *result) {
    fm_int groups[FM_MAX_NUM_MULTICAST_GROUP];
    fm_int n_groups = FM_MAX_NUM_MULTICAST_GROUP;
    fm_status st;

    result->data.pfe_resources.mcast_capacity = FM_MAX_NUM_MULTICAST_GROUP;
    st = fmGetMcastGroupList((fm_int)sw, &n_groups, groups,
                             FM_MAX_NUM_MULTICAST_GROUP);
    if (st != FM_OK) {
        result->data.pfe_resources.mcast_used = 0;
        result->data.pfe_resources.mcast_listeners = 0;
        return;
    }

    result->data.pfe_resources.mcast_used = (int)n_groups;
    result->data.pfe_resources.mcast_listeners = 0;
    for (fm_int i = 0; i < n_groups; i++) {
        fm_multicastListener listeners[256];
        fm_int n_listeners = 256;
        if (fmGetMcastGroupListenerList((fm_int)sw, groups[i],
                                        &n_listeners, listeners, 256) == FM_OK)
            result->data.pfe_resources.mcast_listeners += (int)n_listeners;
    }

    /*
     * fmGetAvailableMulticastListenerCount() emits SDK lock-precedence
     * errors on this FM10000 build when called through the public API. Keep
     * free-listener capacity unknown instead of relying on internal SDK locks.
     */
}

static void collect_storm_resources(int sw, struct sdk_result *result) {
    fm_int controllers[FM_MAX_NUM_STORM_CTRL];
    fm_int n_ctrl = FM_MAX_NUM_STORM_CTRL;
    fm_status st;

    result->data.pfe_resources.storm_capacity = FM_MAX_NUM_STORM_CTRL;
    st = fmGetStormCtrlList((fm_int)sw, &n_ctrl, controllers,
                            FM_MAX_NUM_STORM_CTRL);
    if (st == FM_OK)
        result->data.pfe_resources.storm_used = (int)n_ctrl;
    else
        result->data.pfe_resources.storm_used = 0;
}

static void collect_policer_resources(int sw, struct sdk_result *result) {
    fm_int policers[4096];
    fm_int n_policers = 4096;

    if (fmGetPolicerList((fm_int)sw, &n_policers, policers, 4096) == FM_OK)
        result->data.pfe_resources.policer_used = (int)n_policers;
    else
        result->data.pfe_resources.policer_used = 0;
}

static void collect_flow_resources(int sw, struct sdk_result *result) {
    fm_int table = 0;
    fm_status st = fmGetFlowFirst((fm_int)sw, &table);

    result->data.pfe_resources.flow_tables = 0;
    result->data.pfe_resources.flow_entries_capacity = 0;
    result->data.pfe_resources.flow_entries_used = 0;
    result->data.pfe_resources.flow_entries_free = 0;

    while (st == FM_OK && table != 0) {
        fm_int next = 0;
        fm_int max_entries = 0;
        fm_int empty_entries = 0;

        result->data.pfe_resources.flow_tables++;
        if (fmGetFlowAttribute((fm_int)sw, table,
                               FM_FLOW_TABLE_MAX_ENTRIES,
                               &max_entries) == FM_OK &&
            fmGetFlowAttribute((fm_int)sw, table,
                               FM_FLOW_TABLE_EMPTY_ENTRIES,
                               &empty_entries) == FM_OK) {
            result->data.pfe_resources.flow_entries_capacity +=
                (int)max_entries;
            result->data.pfe_resources.flow_entries_free +=
                (int)empty_entries;
            result->data.pfe_resources.flow_entries_used +=
                (int)(max_entries - empty_entries);
        }
        st = fmGetFlowNext((fm_int)sw, table, &next);
        table = (st == FM_OK) ? next : 0;
    }
}

static void collect_flow_owner_resources(int sw, struct sdk_result *result) {
    hal_flow_table_owner_info owners[NETLAB_FLOW_TABLE_OWNER_MAX];
    int n_owners;

    n_owners = hal_flow_table_collect_owners(sw, owners,
                                             NETLAB_FLOW_TABLE_OWNER_MAX);
    if (n_owners < 0)
        n_owners = 0;
    if (n_owners > NETLAB_FLOW_TABLE_OWNER_MAX)
        n_owners = NETLAB_FLOW_TABLE_OWNER_MAX;

    result->data.pfe_resources.flow_owner_count = n_owners;
    for (int i = 0; i < n_owners; i++) {
        nl_flow_table_owner_resource *dst =
            &result->data.pfe_resources.flow_owner[i];

        dst->table = (int)owners[i].table;
        dst->owner = (int)owners[i].owner;
        dst->capacity = (int)owners[i].max_entries;
        dst->used = (int)owners[i].used_entries;
        dst->free = (int)owners[i].empty_entries;
        dst->max_actions = (int)owners[i].max_actions;
        dst->condition = (int)owners[i].condition;
        snprintf(dst->name, sizeof(dst->name), "%s", owners[i].name);
    }
}

static void collect_acl_owner_resources(int sw, struct sdk_result *result) {
    hal_acl_resource_owner_info owners[NETLAB_ACL_RESOURCE_OWNER_MAX];
    int n_owners;

    n_owners = hal_acl_resource_collect_owners(sw, owners,
                                               NETLAB_ACL_RESOURCE_OWNER_MAX);
    if (n_owners < 0)
        n_owners = 0;
    if (n_owners > NETLAB_ACL_RESOURCE_OWNER_MAX)
        n_owners = NETLAB_ACL_RESOURCE_OWNER_MAX;

    result->data.pfe_resources.acl_owner_count = n_owners;
    for (int i = 0; i < n_owners; i++) {
        nl_acl_resource_owner_resource *dst =
            &result->data.pfe_resources.acl_owner[i];

        dst->acl = owners[i].acl;
        dst->acl_count = owners[i].acl_count;
        dst->rules_per_acl = owners[i].rules_per_acl;
        dst->owner = (int)owners[i].owner;
        dst->first_policer = owners[i].first_policer;
        dst->policer_count = owners[i].policer_count;
        snprintf(dst->name, sizeof(dst->name), "%s", owners[i].name);
    }
}

static void collect_control_plane_resources(int sw, struct sdk_result *result) {
    int rules = -1;
    int packets = -1;
    int octets = -1;
    int table = -1;
    int capacity = -1;
    int free_entries = -1;

    if (hal_control_plane_collect_stats(sw, &rules, &packets, &octets,
                                        &table, &capacity,
                                        &free_entries) == 0) {
        result->data.pfe_resources.control_plane_rules = rules;
        result->data.pfe_resources.control_plane_packets = packets;
        result->data.pfe_resources.control_plane_octets = octets;
        result->data.pfe_resources.control_plane_table = table;
        result->data.pfe_resources.control_plane_capacity = capacity;
        result->data.pfe_resources.control_plane_free = free_entries;
    }
}

static void collect_acl_resources(int sw, struct sdk_result *result) {
    fm_int acl = 0;
    fm_status st = fmGetACLFirst((fm_int)sw, &acl);
    fm_ffuSliceAllocations alloc;

    result->data.pfe_resources.acl_count = 0;
    while (st == FM_OK && acl != 0) {
        fm_int next = 0;
        result->data.pfe_resources.acl_count++;
        st = fmGetACLNext((fm_int)sw, acl, &next);
        acl = (st == FM_OK) ? next : 0;
    }

    memset(&alloc, 0, sizeof(alloc));
    if (fmGetSwitchAttribute((fm_int)sw, FM_FFU_SLICE_ALLOCATIONS,
                             &alloc) == FM_OK) {
        result->data.pfe_resources.ffu_ipv4_uc_first =
            alloc.ipv4UnicastFirstSlice;
        result->data.pfe_resources.ffu_ipv4_uc_last =
            alloc.ipv4UnicastLastSlice;
        result->data.pfe_resources.ffu_ipv4_mc_first =
            alloc.ipv4MulticastFirstSlice;
        result->data.pfe_resources.ffu_ipv4_mc_last =
            alloc.ipv4MulticastLastSlice;
        result->data.pfe_resources.ffu_ipv6_uc_first =
            alloc.ipv6UnicastFirstSlice;
        result->data.pfe_resources.ffu_ipv6_uc_last =
            alloc.ipv6UnicastLastSlice;
        result->data.pfe_resources.ffu_ipv6_mc_first =
            alloc.ipv6MulticastFirstSlice;
        result->data.pfe_resources.ffu_ipv6_mc_last =
            alloc.ipv6MulticastLastSlice;
        result->data.pfe_resources.ffu_acl_first = alloc.aclFirstSlice;
        result->data.pfe_resources.ffu_acl_last = alloc.aclLastSlice;
    }
}

static void collect_l3_resources(int sw, struct sdk_result *result) {
    fm_int routes = 0;
    fm_int groups[1024];
    fm_int n_groups = 1024;
    fm_arpEntry *arps;
    fm_int n_arps = 4096;

    if (fmDbgGetRouteCount((fm_int)sw, &routes) == FM_OK)
        result->data.pfe_resources.route_count = (int)routes;
    else
        result->data.pfe_resources.route_count = 0;

    if (fmGetECMPGroupList((fm_int)sw, &n_groups, groups, 1024) == FM_OK)
        result->data.pfe_resources.ecmp_groups = (int)n_groups;
    else
        result->data.pfe_resources.ecmp_groups = 0;

    arps = calloc((size_t)n_arps, sizeof(*arps));
    if (!arps) {
        result->data.pfe_resources.arp_used = 0;
        return;
    }
    if (fmGetARPEntryList((fm_int)sw, &n_arps, arps, 4096) == FM_OK)
        result->data.pfe_resources.arp_used = (int)n_arps;
    else
        result->data.pfe_resources.arp_used = 0;
    free(arps);
}

static int stat_to_int(unsigned long value) {
    return value > (unsigned long)INT_MAX ? INT_MAX : (int)value;
}

static int diag_counter_to_int(fm_int sw, fm_trackingCounterIndex counter) {
    fm_uint64 value = 0;

    if (fmDbgDiagCountGet(sw, counter, &value) != FM_OK)
        return -1;
    return value > (fm_uint64)INT_MAX ? INT_MAX : (int)value;
}

static bool read_reg32_u32(fm_int sw, fm_uint reg, fm_uint32 *value) {
    return fmReadUncachedUINT32(sw, reg, value) == FM_OK;
}

static int reg32_value_to_int(fm_uint32 value) {
    return value > (fm_uint32)INT_MAX ? INT_MAX : (int)value;
}

static int reg32_to_int(fm_int sw, fm_uint reg) {
    fm_uint32 value = 0;

    if (!read_reg32_u32(sw, reg, &value))
        return -1;
    return reg32_value_to_int(value);
}

static int bit_count32(fm_uint32 value) {
    int count = 0;

    while (value != 0) {
        value &= value - 1;
        count++;
    }
    return count;
}

static void set_36_lane_half_bit(int lane, int *low, int *high) {
    if (lane < 0 || lane >= 36)
        return;
    if (lane < 18)
        *low |= 1 << lane;
    else
        *high |= 1 << (lane - 18);
}

static bool platform_model_is_fm10000(void) {
    nl_platform_identity ident;

    memset(&ident, 0, sizeof(ident));
    if (!nl_platform_identity_get(&ident) || !ident.model[0])
        return false;
    return strncmp(ident.model, "FM10", 4) == 0;
}

static void collect_epl_register_summary(fm_int sw, nl_pfe_resources *r) {
    int seen = 0;
    int pending_count = 0;
    int pending_mask = 0;
    int error_count = 0;
    int error_mask = 0;
    int fifo_count = 0;
    int fifo_mask = 0;
    int an_low = 0, an_high = 0;
    int link_low = 0, link_high = 0;
    int serdes_low = 0, serdes_high = 0;
    int error_interrupt_mask = 0;
    int jitter_uerr_low = 0, jitter_uerr_high = 0;
    int jitter_cerr_low = 0, jitter_cerr_high = 0;
    int rs_saf_uerr_mask = 0;
    int fifo_tx_low = 0, fifo_tx_high = 0;
    int fifo_rx_low = 0, fifo_rx_high = 0;

    for (int epl = 0; epl < FM10000_EPL_IP_ENTRIES; epl++) {
        int value = reg32_to_int(sw, FM10000_EPL_IP(epl));
        if (value >= 0) {
            seen = 1;
            if (value != 0) {
                pending_count++;
                pending_mask |= (1 << epl);
            }
            for (int lane = 0; lane < 4; lane++) {
                int abs_lane = epl * 4 + lane;
                if (value & (1 << lane))
                    set_36_lane_half_bit(abs_lane, &an_low, &an_high);
                if (value & (1 << (4 + lane)))
                    set_36_lane_half_bit(abs_lane, &link_low, &link_high);
                if (value & (1 << (8 + lane)))
                    set_36_lane_half_bit(abs_lane, &serdes_low, &serdes_high);
            }
            if (value & (1 << 12))
                error_interrupt_mask |= (1 << epl);
        }

        value = reg32_to_int(sw, FM10000_EPL_ERROR_IP(epl));
        if (value >= 0) {
            seen = 1;
            if (value != 0) {
                error_count++;
                error_mask |= (1 << epl);
            }
            for (int lane = 0; lane < 4; lane++) {
                int abs_lane = epl * 4 + lane;
                if (value & (1 << (lane * 2)))
                    set_36_lane_half_bit(abs_lane, &jitter_uerr_low,
                                         &jitter_uerr_high);
                if (value & (1 << (lane * 2 + 1)))
                    set_36_lane_half_bit(abs_lane, &jitter_cerr_low,
                                         &jitter_cerr_high);
            }
            if (value & (1 << 8))
                rs_saf_uerr_mask |= (1 << epl);
        }

        value = reg32_to_int(sw, FM10000_EPL_FIFO_ERROR_STATUS(epl));
        if (value >= 0) {
            seen = 1;
            if (value != 0) {
                fifo_count++;
                fifo_mask |= (1 << epl);
            }
            for (int lane = 0; lane < 4; lane++) {
                int abs_lane = epl * 4 + lane;
                if (value & (1 << lane))
                    set_36_lane_half_bit(abs_lane, &fifo_tx_low,
                                         &fifo_tx_high);
                if (value & (1 << (4 + lane)))
                    set_36_lane_half_bit(abs_lane, &fifo_rx_low,
                                         &fifo_rx_high);
            }
        }
    }

    if (!seen)
        return;
    r->fm10000_epl_pending_count = pending_count;
    r->fm10000_epl_pending_mask = pending_mask;
    r->fm10000_epl_error_pending_count = error_count;
    r->fm10000_epl_error_pending_mask = error_mask;
    r->fm10000_epl_fifo_error_count = fifo_count;
    r->fm10000_epl_fifo_error_mask = fifo_mask;
    r->fm10000_epl_an_pending_low = an_low;
    r->fm10000_epl_an_pending_high = an_high;
    r->fm10000_epl_link_pending_low = link_low;
    r->fm10000_epl_link_pending_high = link_high;
    r->fm10000_epl_serdes_pending_low = serdes_low;
    r->fm10000_epl_serdes_pending_high = serdes_high;
    r->fm10000_epl_error_interrupt_mask = error_interrupt_mask;
    r->fm10000_epl_jitter_uerr_low = jitter_uerr_low;
    r->fm10000_epl_jitter_uerr_high = jitter_uerr_high;
    r->fm10000_epl_jitter_cerr_low = jitter_cerr_low;
    r->fm10000_epl_jitter_cerr_high = jitter_cerr_high;
    r->fm10000_epl_rs_saf_uerr_mask = rs_saf_uerr_mask;
    r->fm10000_epl_fifo_tx_error_low = fifo_tx_low;
    r->fm10000_epl_fifo_tx_error_high = fifo_tx_high;
    r->fm10000_epl_fifo_rx_error_low = fifo_rx_low;
    r->fm10000_epl_fifo_rx_error_high = fifo_rx_high;
}

static void collect_fm10000_fault_resources(int sw, struct sdk_result *result) {
    nl_pfe_resources *r = &result->data.pfe_resources;
    fm_uint32 reg_value = 0;
    int trigger_pending_count = 0;
    bool trigger_seen = false;

    if (!platform_model_is_fm10000())
        return;

    r->fm10000_epl_interrupts =
        diag_counter_to_int((fm_int)sw, FM_CTR_EPL_INT);
    r->fm10000_link_change_events =
        diag_counter_to_int((fm_int)sw, FM_CTR_LINK_CHANGE_EVENT);
    r->fm10000_link_change_lost =
        diag_counter_to_int((fm_int)sw, FM_CTR_LINK_CHANGE_OUT_OF_EVENTS);
    r->fm10000_egress_timestamp_events =
        diag_counter_to_int((fm_int)sw, FM_CTR_EGRESS_TIMESTAMP_EVENT);
    r->fm10000_egress_timestamp_lost =
        diag_counter_to_int((fm_int)sw, FM_CTR_EGRESS_TIMESTAMP_LOST);
    r->fm10000_parity_area_epl =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_AREA_EPL);
    r->fm10000_parity_area_policer =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_AREA_POLICER);
    r->fm10000_parity_area_policer_u_err =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_AREA_POLICER_U_ERR);
    r->fm10000_parity_area_policer_c_err =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_AREA_POLICER_C_ERR);
    r->fm10000_parity_severity_transient =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_SEVERITY_TRANSIENT);
    r->fm10000_parity_severity_repairable =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_SEVERITY_REPAIRABLE);
    r->fm10000_parity_severity_cumulative =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_SEVERITY_CUMULATIVE);
    r->fm10000_parity_severity_fatal =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_SEVERITY_FATAL);
    r->fm10000_parity_status_fixed =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_STATUS_FIXED);
    r->fm10000_parity_status_fix_failed =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_STATUS_FIX_FAILED);
    r->fm10000_sram_c_err_interrupt =
        diag_counter_to_int((fm_int)sw, FM_CTR_SRAM_C_ERR_INTERRUPT);
    r->fm10000_sram_u_err_interrupt =
        diag_counter_to_int((fm_int)sw, FM_CTR_SRAM_U_ERR_INTERRUPT);
    r->fm10000_parity_event_lost =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_EVENT_LOST);
    r->fm10000_parity_repair_invalid =
        diag_counter_to_int((fm_int)sw, FM_CTR_PARITY_REPAIR_INVALID);

    r->fm10000_crm_ip0 = reg32_to_int((fm_int)sw, FM10000_CRM_IP(0));
    r->fm10000_crm_ip1 = reg32_to_int((fm_int)sw, FM10000_CRM_IP(1));
    r->fm10000_crm_ip2 = reg32_to_int((fm_int)sw, FM10000_CRM_IP(2));
    r->fm10000_crm_im0 = reg32_to_int((fm_int)sw, FM10000_CRM_IM(0));
    r->fm10000_crm_im1 = reg32_to_int((fm_int)sw, FM10000_CRM_IM(1));
    r->fm10000_crm_im2 = reg32_to_int((fm_int)sw, FM10000_CRM_IM(2));
    r->fm10000_fibm_ip = reg32_to_int((fm_int)sw, FM10000_FIBM_IP());
    r->fm10000_fibm_im = reg32_to_int((fm_int)sw, FM10000_FIBM_IM());
    if (read_reg32_u32((fm_int)sw, FM10000_PCIE_CLK_IP(), &reg_value)) {
        r->fm10000_pcie_clk_ip = reg32_value_to_int(reg_value);
        r->fm10000_pcie_clk_xref_high = (int)((reg_value >> 0) & 0xf);
        r->fm10000_pcie_clk_xref_low = (int)((reg_value >> 4) & 0xf);
        r->fm10000_pcie_clk_xpll_high = (int)((reg_value >> 8) & 0xf);
        r->fm10000_pcie_clk_xpll_low = (int)((reg_value >> 12) & 0xf);
    }
    r->fm10000_pcie_clk_im =
        reg32_to_int((fm_int)sw, FM10000_PCIE_CLK_IM());
    if (read_reg32_u32((fm_int)sw, FM10000_SBUS_PCIE_IP(), &reg_value)) {
        r->fm10000_sbus_pcie_ip = reg32_value_to_int(reg_value);
        r->fm10000_sbus_pcie_detect_high = (int)(reg_value & 0xffff);
        r->fm10000_sbus_pcie_detect_low = (int)((reg_value >> 16) & 0xffff);
    }
    r->fm10000_sbus_pcie_im =
        reg32_to_int((fm_int)sw, FM10000_SBUS_PCIE_IM());
    r->fm10000_sram_err_ip0 =
        reg32_to_int((fm_int)sw, FM10000_SRAM_ERR_IP(0));
    r->fm10000_sram_err_ip1 =
        reg32_to_int((fm_int)sw, FM10000_SRAM_ERR_IP(1));
    r->fm10000_sram_err_im0 =
        reg32_to_int((fm_int)sw, FM10000_SRAM_ERR_IM(0));
    r->fm10000_sram_err_im1 =
        reg32_to_int((fm_int)sw, FM10000_SRAM_ERR_IM(1));
    if (read_reg32_u32((fm_int)sw, FM10000_TRIGGER_IP(0), &reg_value)) {
        r->fm10000_trigger_ip0 = reg32_value_to_int(reg_value);
        trigger_pending_count += bit_count32(reg_value);
        trigger_seen = true;
    }
    if (read_reg32_u32((fm_int)sw, FM10000_TRIGGER_IP(1), &reg_value)) {
        r->fm10000_trigger_ip1 = reg32_value_to_int(reg_value);
        trigger_pending_count += bit_count32(reg_value);
        trigger_seen = true;
    }
    if (trigger_seen)
        r->fm10000_trigger_pending_count = trigger_pending_count;
    r->fm10000_trigger_im0 =
        reg32_to_int((fm_int)sw, FM10000_TRIGGER_IM(0));
    r->fm10000_trigger_im1 =
        reg32_to_int((fm_int)sw, FM10000_TRIGGER_IM(1));
    collect_epl_register_summary((fm_int)sw, r);
}

static void collect_event_resources(int sw, struct sdk_result *result) {
    sdk_event_stats_t stats;
    nl_pfe_resources *r = &result->data.pfe_resources;

    memset(&stats, 0, sizeof(stats));
    sdk_event_stats_snapshot(&stats);
    r->event_queue_drops = stat_to_int(stats.queue_drops);
    r->event_total = stat_to_int(stats.total);
    r->event_port = stat_to_int(stats.port);
    r->event_table_updates = stat_to_int(stats.table_updates);
    r->event_table_entries = stat_to_int(stats.table_entries);
    r->event_table_learned = stat_to_int(stats.table_learned);
    r->event_table_aged = stat_to_int(stats.table_aged);
    r->event_table_errors = stat_to_int(stats.table_errors);
    r->event_security = stat_to_int(stats.security);
    r->event_platform = stat_to_int(stats.platform);
    r->event_unsupported = stat_to_int(stats.unsupported);
    r->event_parity_errors = stat_to_int(stats.parity_errors);
    r->event_logical_port = stat_to_int(stats.logical_port);
    r->event_cable_mismatch = stat_to_int(stats.cable_mismatch);
    r->event_over_temp = stat_to_int(stats.over_temp);
    r->event_switch = stat_to_int(stats.switch_events);
    r->event_frame = stat_to_int(stats.frame);
    r->event_software = stat_to_int(stats.software);
    r->event_sflow = stat_to_int(stats.sflow);
    r->event_fibm_threshold = stat_to_int(stats.fibm_threshold);
    r->event_crm = stat_to_int(stats.crm);
    r->event_arp = stat_to_int(stats.arp);
    r->event_purge_scan_complete =
        stat_to_int(stats.purge_scan_complete);
    r->event_egress_timestamp = stat_to_int(stats.egress_timestamp);
    r->event_packet_enqueued = stat_to_int(stats.packet_enqueued);
    r->event_last = stats.last_event;
    r->event_last_unsupported = stats.last_unsupported_event;
    r->event_last_port = stats.last_port;
    r->event_last_vlan = stats.last_vlan;
    r->event_last_lane = stats.last_lane;
    r->event_last_mac = stats.last_mac;
    r->event_last_status = stats.last_status;
    r->event_last_temperature = stats.last_temperature;
    r->event_last_crm_id = stats.last_crm_id;
    r->event_last_fibm_retries = stats.last_fibm_retries;
    r->event_last_parity_type = stats.last_parity_type;
    r->event_last_parity_severity = stats.last_parity_severity;
    r->event_last_parity_area = stats.last_parity_area;
    r->event_last_parity_status = stats.last_parity_status;
    r->event_last_parity_sram = stats.last_parity_sram;
    r->event_last_logical_first = stats.last_logical_first;
    r->event_last_logical_count = stats.last_logical_count;
    r->event_last_logical_pep_id = stats.last_logical_pep_id;
    r->event_last_logical_pep_port = stats.last_logical_pep_port;
    r->event_last_logical_created = stats.last_logical_created;
    r->event_last_platform_type = stats.last_platform_type;
    r->event_last_software_events = stats.last_software_events;
    r->event_last_switch_slot = stats.last_switch_slot;
    r->event_last_arp_sip = stats.last_arp_sip;
    r->event_last_arp_dip = stats.last_arp_dip;
    r->event_last_arp_ipv6 = stats.last_arp_ipv6;
    r->event_last_egress_port = stats.last_egress_port;
    r->event_tcn_interrupts =
        diag_counter_to_int((fm_int)sw, FM_CTR_TCN_INTERRUPT);
    r->event_tcn_pending =
        diag_counter_to_int((fm_int)sw, FM_CTR_TCN_PENDING_EVENTS);
    r->event_tcn_overflow =
        diag_counter_to_int((fm_int)sw, FM_CTR_TCN_LEARNED_OVERFLOW);
    r->event_tcn_learned_events =
        diag_counter_to_int((fm_int)sw, FM_CTR_TCN_LEARNED_EVENT);
    r->event_tcn_moved_events =
        diag_counter_to_int((fm_int)sw, FM_CTR_TCN_SEC_VIOL_MOVED_EVENT);
    r->event_tcn_fifo_errors =
        diag_counter_to_int((fm_int)sw, FM_CTR_TCN_FIFO_READ_ERR);
    if (r->event_tcn_fifo_errors >= 0) {
        int parity = diag_counter_to_int((fm_int)sw,
                                         FM_CTR_TCN_FIFO_PARITY_ERR);
        int conv = diag_counter_to_int((fm_int)sw,
                                       FM_CTR_TCN_FIFO_CONV_ERR);
        if (parity > 0)
            r->event_tcn_fifo_errors += parity;
        if (conv > 0)
            r->event_tcn_fifo_errors += conv;
    }
    r->event_mac_learned_debug =
        diag_counter_to_int((fm_int)sw, FM_CTR_MAC_LEARN_LEARNED);
    r->event_mac_aged_debug =
        diag_counter_to_int((fm_int)sw, FM_CTR_MAC_LEARN_AGED);
    r->event_mac_port_changed =
        diag_counter_to_int((fm_int)sw, FM_CTR_MAC_LEARN_PORT_CHANGED);
    r->event_mac_learn_discarded =
        diag_counter_to_int((fm_int)sw, FM_CTR_MAC_LEARN_DISCARDED);
    r->event_mac_vlan_errors =
        diag_counter_to_int((fm_int)sw, FM_CTR_MAC_VLAN_ERR);
    r->event_mac_security =
        diag_counter_to_int((fm_int)sw, FM_CTR_MAC_SECURITY);
    r->event_mac_work_service_fifo =
        diag_counter_to_int((fm_int)sw, FM_CTR_MAC_WORK_SERVICE_FIFO);
    r->event_mac_work_fifo_events =
        diag_counter_to_int((fm_int)sw, FM_CTR_MAC_WORK_FIFO_EVENTS);
}

int hal_get_pfe_resources(int sw, struct sdk_result *result) {
    int aging = 0;

    if (!result)
        return -1;

    init_unknown_resources(result);
    collect_profile_resources(result);
    if (hal_mac_aging_get(sw, &aging) == 0)
        result->data.pfe_resources.mac_aging_time = aging;

    collect_mac_resources(sw, result);
    collect_vlan_resources(sw, result);
    collect_lag_resources(sw, result);
    collect_mcast_resources(sw, result);
    collect_storm_resources(sw, result);
    collect_policer_resources(sw, result);
    collect_flow_resources(sw, result);
    collect_flow_owner_resources(sw, result);
    collect_acl_owner_resources(sw, result);
    collect_control_plane_resources(sw, result);
    collect_acl_resources(sw, result);
    collect_l3_resources(sw, result);
    collect_event_resources(sw, result);
    collect_fm10000_fault_resources(sw, result);
    return 0;
}
