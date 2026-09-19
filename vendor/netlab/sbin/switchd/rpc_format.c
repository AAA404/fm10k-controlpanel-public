/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "rpc_format.h"
#include "hal_acl_resource.h"
#include "hal_flow_table.h"
#include "netlab/interface_id.h"
#include <api/fm_api_attr.h>
#include <api/fm_api_event_types.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define L3_ROUTE_ENTRIES_PER_SLICE 1024
#define L3_ARP_CAPACITY 4096
#define L3_ECMP_GROUP_CAPACITY 1024

static int append_format_text(char *buf, size_t buf_size, int off,
                              const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !fmt || off < 0 || (size_t)off >= buf_size)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(buf + off, buf_size - (size_t)off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - (size_t)off)
        return -1;
    return off + n;
}

static int slice_len(int first, int last) {
    return first >= 0 && last >= first ? last - first + 1 : 0;
}

static int resource_free(int capacity, int used) {
    return capacity > used ? capacity - used : 0;
}

static const char *resource_ceiling_status(int available, int physical) {
    if (available < 0 || physical <= 0)
        return "unavailable";
    return available <= physical ? "within-limit" : "exceeds-limit";
}

static void xml_escape_attr(const char *src, char *dst, size_t dst_len) {
    size_t off = 0;

    if (!dst_len)
        return;
    if (!src)
        src = "";
    for (const char *p = src; *p && off + 1 < dst_len; p++) {
        const char *rep = NULL;
        size_t len;

        switch (*p) {
        case '&': rep = "&amp;"; break;
        case '<': rep = "&lt;"; break;
        case '>': rep = "&gt;"; break;
        case '"': rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default:
            dst[off++] = *p;
            continue;
        }
        len = strlen(rep);
        if (off + len >= dst_len)
            break;
        memcpy(dst + off, rep, len);
        off += len;
    }
    dst[off] = '\0';
}

static const char *sdk_event_name(int event) {
    switch (event) {
        case 0: return "none";
        case FM_EVENT_SWITCH_INSERTED: return "switch-inserted";
        case FM_EVENT_SWITCH_REMOVED: return "switch-removed";
        case FM_EVENT_SWITCH_UP: return "switch-up";
        case FM_EVENT_SWITCH_DOWN: return "switch-down";
        case FM_EVENT_TABLE_UPDATE: return "table-update";
        case FM_EVENT_PKT_RECV: return "packet-recv";
        case FM_EVENT_PORT: return "port";
        case FM_EVENT_FRAME: return "frame";
        case FM_EVENT_SECURITY: return "security";
        case FM_EVENT_SOFTWARE: return "software";
        case FM_EVENT_SFLOW_PKT_RECV: return "sflow-packet-recv";
        case FM_EVENT_PARITY_ERROR: return "parity-error";
        case FM_EVENT_FIBM_THRESHOLD: return "fibm-threshold";
        case FM_EVENT_CRM: return "crm";
        case FM_EVENT_ARP: return "arp";
        case FM_EVENT_PURGE_SCAN_COMPLETE: return "purge-scan-complete";
        case FM_EVENT_EGRESS_TIMESTAMP: return "egress-timestamp";
        case FM_EVENT_PLATFORM: return "platform";
        case FM_EVENT_PACKET_ENQUEUED: return "packet-enqueued";
        case FM_EVENT_LOGICAL_PORT: return "logical-port";
        case FM_EVENT_CABLE_MISMATCH: return "cable-mismatch";
        case FM_EVENT_OVER_TEMP: return "over-temperature";
        default: return "unknown";
    }
}

int hal_rpc_format_pfe_resources(const struct sdk_result *result,
                                 char *resp, size_t resp_size) {
    int off = 0;
    nl_platform_identity ident;
    nl_board_profile board;
    char profile_attr[256];
    char model_attr[96];
    const char *profile = nl_platform_loaded_profile();
    const nl_pfe_resources *resources;

    if (!result || !resp || resp_size == 0)
        return 0;

    memset(&ident, 0, sizeof(ident));
    memset(&board, 0, sizeof(board));
    (void)nl_platform_identity_get(&ident);
    (void)nl_platform_board_get(&board);
    xml_escape_attr(profile ? profile : "", profile_attr,
                    sizeof(profile_attr));
    xml_escape_attr(ident.model, model_attr, sizeof(model_attr));

    off = append_format_text(resp, resp_size, off,
                    "<resources status=\"%d\" source=\"ies-sdk\" "
                    "profile=\"%s\" model=\"%s\">\n",
                    result->status, profile_attr, model_attr);
    if (result->status == 0) {
        resources = &result->data.pfe_resources;
        if (board.configured) {
            off = append_format_text(
                resp, resp_size, off,
                "  <physical-limits board=\"%s\" shared-memory-bytes=\"%d\" "
                "tcam-entries=\"%d\" mac-nexthop-entries=\"%d\" "
                "tcam-capacity-status=\"%s\" mac-capacity-status=\"%s\"/>\n",
                board.model, board.shared_memory_bytes, board.tcam_entries,
                board.mac_nexthop_entries,
                resource_ceiling_status(resources->flow_entries_capacity,
                                        board.tcam_entries),
                resource_ceiling_status(resources->mac_capacity,
                                        board.mac_nexthop_entries));
            if (off < 0)
                return -1;
        }
        off = append_format_text(resp, resp_size, off,
            "  <profile ports=\"%d\" switches=\"%d\" lanes=\"%d\" "
            "xcvrs=\"%d\" max-ae=\"%d\"/>\n",
            resources->profile_ports, resources->profile_switches,
            resources->profile_lanes, resources->profile_xcvrs,
            resources->profile_max_ae);
        off = append_format_text(resp, resp_size, off,
            "  <mac capacity=\"%d\" used=\"%d\" visible=\"%d\" "
            "dynamic=\"%d\" static=\"%d\" multicast=\"%d\" "
            "internal=\"%d\" truncated=\"%d\" aging-time=\"%d\" "
            "raw-bytes=\"%d\" entry-size=\"%d\"/>\n",
            resources->mac_capacity, resources->mac_used,
            resources->mac_visible, resources->mac_dynamic,
            resources->mac_static, resources->mac_multicast,
            resources->mac_internal, resources->mac_truncated,
            resources->mac_aging_time, resources->mac_raw_bytes,
            resources->mac_entry_size);
        off = append_format_text(resp, resp_size, off,
            "  <events total=\"%d\" queue-drops=\"%d\" port=\"%d\" "
            "table-updates=\"%d\" table-entries=\"%d\" "
            "table-learned=\"%d\" table-aged=\"%d\" "
            "table-errors=\"%d\" security=\"%d\" platform=\"%d\" "
            "parity-errors=\"%d\" logical-port=\"%d\" "
            "cable-mismatch=\"%d\" over-temp=\"%d\" "
            "switch-events=\"%d\" frame=\"%d\" software=\"%d\" "
            "sflow=\"%d\" fibm-threshold=\"%d\" crm=\"%d\" "
            "arp=\"%d\" purge-scan-complete=\"%d\" "
            "egress-timestamp=\"%d\" packet-enqueued=\"%d\" "
            "unsupported=\"%d\" last-event=\"%d\" "
            "last-event-name=\"%s\" last-unsupported-event=\"%d\" "
            "last-unsupported-event-name=\"%s\" tcn-interrupts=\"%d\" "
            "tcn-pending=\"%d\" tcn-overflow=\"%d\" "
            "tcn-fifo-errors=\"%d\" "
            "tcn-learned-events=\"%d\" tcn-moved-events=\"%d\" "
            "mac-learned-debug=\"%d\" mac-aged-debug=\"%d\" "
            "mac-port-changed=\"%d\" mac-learn-discarded=\"%d\" "
            "mac-vlan-errors=\"%d\" mac-security=\"%d\" "
            "mac-work-service-fifo=\"%d\" "
            "mac-work-fifo-events=\"%d\"/>\n",
            resources->event_total, resources->event_queue_drops,
            resources->event_port, resources->event_table_updates,
            resources->event_table_entries, resources->event_table_learned,
            resources->event_table_aged, resources->event_table_errors,
            resources->event_security, resources->event_platform,
            resources->event_parity_errors, resources->event_logical_port,
            resources->event_cable_mismatch, resources->event_over_temp,
            resources->event_switch, resources->event_frame,
            resources->event_software, resources->event_sflow,
            resources->event_fibm_threshold, resources->event_crm,
            resources->event_arp, resources->event_purge_scan_complete,
            resources->event_egress_timestamp,
            resources->event_packet_enqueued,
            resources->event_unsupported, resources->event_last,
            sdk_event_name(resources->event_last),
            resources->event_last_unsupported,
            sdk_event_name(resources->event_last_unsupported),
            resources->event_tcn_interrupts, resources->event_tcn_pending,
            resources->event_tcn_overflow, resources->event_tcn_fifo_errors,
            resources->event_tcn_learned_events,
            resources->event_tcn_moved_events,
            resources->event_mac_learned_debug,
            resources->event_mac_aged_debug,
            resources->event_mac_port_changed,
            resources->event_mac_learn_discarded,
            resources->event_mac_vlan_errors,
            resources->event_mac_security,
            resources->event_mac_work_service_fifo,
            resources->event_mac_work_fifo_events);
        off = append_format_text(resp, resp_size, off,
            "  <vlan capacity=\"%d\" used=\"%d\" memberships=\"%d\"/>\n",
            resources->vlan_capacity, resources->vlan_used,
            resources->vlan_memberships);
        off = append_format_text(resp, resp_size, off,
            "  <event-last port=\"%d\" vlan=\"%d\" lane=\"%d\" "
            "mac=\"%d\" status=\"%d\" temperature=\"%d\" "
            "crm-id=\"%d\" fibm-retries=\"%d\" "
            "parity-type=\"%d\" parity-severity=\"%d\" "
            "parity-area=\"%d\" parity-status=\"%d\" "
            "parity-sram=\"%d\" logical-first=\"%d\" "
            "logical-count=\"%d\" logical-pep-id=\"%d\" "
            "logical-pep-port=\"%d\" logical-created=\"%d\" "
            "platform-type=\"%d\" software-events=\"%d\" "
            "switch-slot=\"%d\" arp-sip=\"%d\" arp-dip=\"%d\" "
            "arp-ipv6=\"%d\" egress-port=\"%d\"/>\n",
            resources->event_last_port, resources->event_last_vlan,
            resources->event_last_lane, resources->event_last_mac,
            resources->event_last_status, resources->event_last_temperature,
            resources->event_last_crm_id, resources->event_last_fibm_retries,
            resources->event_last_parity_type,
            resources->event_last_parity_severity,
            resources->event_last_parity_area,
            resources->event_last_parity_status,
            resources->event_last_parity_sram,
            resources->event_last_logical_first,
            resources->event_last_logical_count,
            resources->event_last_logical_pep_id,
            resources->event_last_logical_pep_port,
            resources->event_last_logical_created,
            resources->event_last_platform_type,
            resources->event_last_software_events,
            resources->event_last_switch_slot,
            resources->event_last_arp_sip, resources->event_last_arp_dip,
            resources->event_last_arp_ipv6,
            resources->event_last_egress_port);
        off = append_format_text(resp, resp_size, off,
            "  <fm10000-fault-counters epl-interrupts=\"%d\" "
            "link-change-events=\"%d\" link-change-lost=\"%d\" "
            "egress-timestamp-events=\"%d\" "
            "egress-timestamp-lost=\"%d\" parity-area-epl=\"%d\" "
            "parity-area-policer=\"%d\" "
            "parity-area-policer-uerr=\"%d\" "
            "parity-area-policer-cerr=\"%d\" "
            "parity-severity-transient=\"%d\" "
            "parity-severity-repairable=\"%d\" "
            "parity-severity-cumulative=\"%d\" "
            "parity-severity-fatal=\"%d\" "
            "parity-status-fixed=\"%d\" "
            "parity-status-fix-failed=\"%d\" "
            "sram-cerr-interrupts=\"%d\" "
            "sram-uerr-interrupts=\"%d\" "
            "parity-event-lost=\"%d\" parity-repair-invalid=\"%d\"/>\n",
            resources->fm10000_epl_interrupts,
            resources->fm10000_link_change_events,
            resources->fm10000_link_change_lost,
            resources->fm10000_egress_timestamp_events,
            resources->fm10000_egress_timestamp_lost,
            resources->fm10000_parity_area_epl,
            resources->fm10000_parity_area_policer,
            resources->fm10000_parity_area_policer_u_err,
            resources->fm10000_parity_area_policer_c_err,
            resources->fm10000_parity_severity_transient,
            resources->fm10000_parity_severity_repairable,
            resources->fm10000_parity_severity_cumulative,
            resources->fm10000_parity_severity_fatal,
            resources->fm10000_parity_status_fixed,
            resources->fm10000_parity_status_fix_failed,
            resources->fm10000_sram_c_err_interrupt,
            resources->fm10000_sram_u_err_interrupt,
            resources->fm10000_parity_event_lost,
            resources->fm10000_parity_repair_invalid);
        off = append_format_text(resp, resp_size, off,
            "  <fm10000-interrupts crm-ip0=\"%d\" crm-ip1=\"%d\" "
            "crm-ip2=\"%d\" crm-im0=\"%d\" crm-im1=\"%d\" "
            "crm-im2=\"%d\" fibm-ip=\"%d\" fibm-im=\"%d\" "
            "pcie-clk-ip=\"%d\" pcie-clk-im=\"%d\" "
            "sbus-pcie-ip=\"%d\" sbus-pcie-im=\"%d\" "
            "sram-err-ip0=\"%d\" sram-err-ip1=\"%d\" "
            "sram-err-im0=\"%d\" sram-err-im1=\"%d\" "
            "trigger-ip0=\"%d\" trigger-ip1=\"%d\" "
            "trigger-im0=\"%d\" trigger-im1=\"%d\" "
            "epl-pending-count=\"%d\" epl-pending-mask=\"%d\" "
            "epl-error-pending-count=\"%d\" "
            "epl-error-pending-mask=\"%d\" "
            "epl-fifo-error-count=\"%d\" "
            "epl-fifo-error-mask=\"%d\" "
            "pcie-clk-xref-high=\"%d\" pcie-clk-xref-low=\"%d\" "
            "pcie-clk-xpll-high=\"%d\" pcie-clk-xpll-low=\"%d\" "
            "sbus-pcie-detect-high=\"%d\" "
            "sbus-pcie-detect-low=\"%d\" "
            "trigger-pending-count=\"%d\" "
            "epl-an-pending-low=\"%d\" "
            "epl-an-pending-high=\"%d\" "
            "epl-link-pending-low=\"%d\" "
            "epl-link-pending-high=\"%d\" "
            "epl-serdes-pending-low=\"%d\" "
            "epl-serdes-pending-high=\"%d\" "
            "epl-error-interrupt-mask=\"%d\" "
            "epl-jitter-uerr-low=\"%d\" "
            "epl-jitter-uerr-high=\"%d\" "
            "epl-jitter-cerr-low=\"%d\" "
            "epl-jitter-cerr-high=\"%d\" "
            "epl-rs-saf-uerr-mask=\"%d\" "
            "epl-fifo-tx-error-low=\"%d\" "
            "epl-fifo-tx-error-high=\"%d\" "
            "epl-fifo-rx-error-low=\"%d\" "
            "epl-fifo-rx-error-high=\"%d\"/>\n",
            resources->fm10000_crm_ip0, resources->fm10000_crm_ip1,
            resources->fm10000_crm_ip2, resources->fm10000_crm_im0,
            resources->fm10000_crm_im1, resources->fm10000_crm_im2,
            resources->fm10000_fibm_ip, resources->fm10000_fibm_im,
            resources->fm10000_pcie_clk_ip, resources->fm10000_pcie_clk_im,
            resources->fm10000_sbus_pcie_ip,
            resources->fm10000_sbus_pcie_im,
            resources->fm10000_sram_err_ip0,
            resources->fm10000_sram_err_ip1,
            resources->fm10000_sram_err_im0,
            resources->fm10000_sram_err_im1,
            resources->fm10000_trigger_ip0,
            resources->fm10000_trigger_ip1,
            resources->fm10000_trigger_im0,
            resources->fm10000_trigger_im1,
            resources->fm10000_epl_pending_count,
            resources->fm10000_epl_pending_mask,
            resources->fm10000_epl_error_pending_count,
            resources->fm10000_epl_error_pending_mask,
            resources->fm10000_epl_fifo_error_count,
            resources->fm10000_epl_fifo_error_mask,
            resources->fm10000_pcie_clk_xref_high,
            resources->fm10000_pcie_clk_xref_low,
            resources->fm10000_pcie_clk_xpll_high,
            resources->fm10000_pcie_clk_xpll_low,
            resources->fm10000_sbus_pcie_detect_high,
            resources->fm10000_sbus_pcie_detect_low,
            resources->fm10000_trigger_pending_count,
            resources->fm10000_epl_an_pending_low,
            resources->fm10000_epl_an_pending_high,
            resources->fm10000_epl_link_pending_low,
            resources->fm10000_epl_link_pending_high,
            resources->fm10000_epl_serdes_pending_low,
            resources->fm10000_epl_serdes_pending_high,
            resources->fm10000_epl_error_interrupt_mask,
            resources->fm10000_epl_jitter_uerr_low,
            resources->fm10000_epl_jitter_uerr_high,
            resources->fm10000_epl_jitter_cerr_low,
            resources->fm10000_epl_jitter_cerr_high,
            resources->fm10000_epl_rs_saf_uerr_mask,
            resources->fm10000_epl_fifo_tx_error_low,
            resources->fm10000_epl_fifo_tx_error_high,
            resources->fm10000_epl_fifo_rx_error_low,
            resources->fm10000_epl_fifo_rx_error_high);
        off = append_format_text(resp, resp_size, off,
            "  <lag capacity=\"%d\" used=\"%d\" members=\"%d\" "
            "member-capacity=\"%d\"/>\n",
            resources->lag_capacity, resources->lag_used,
            resources->lag_members, resources->lag_member_capacity);
        off = append_format_text(resp, resp_size, off,
            "  <multicast capacity=\"%d\" used=\"%d\" listeners=\"%d\" "
            "listeners-free=\"%d\"/>\n",
            resources->mcast_capacity, resources->mcast_used,
            resources->mcast_listeners, resources->mcast_listeners_free);
        off = append_format_text(resp, resp_size, off,
            "  <storm-control capacity=\"%d\" used=\"%d\"/>\n",
            resources->storm_capacity, resources->storm_used);
        off = append_format_text(resp, resp_size, off,
            "  <policer used=\"%d\"/>\n", resources->policer_used);
        off = append_format_text(resp, resp_size, off,
            "  <flow tables=\"%d\" capacity=\"%d\" used=\"%d\" free=\"%d\"/>\n",
            resources->flow_tables, resources->flow_entries_capacity,
            resources->flow_entries_used, resources->flow_entries_free);
        off = append_format_text(resp, resp_size, off,
            "  <flow-owners count=\"%d\">\n",
            resources->flow_owner_count);
        for (int i = 0;
             i < resources->flow_owner_count &&
             i < NETLAB_FLOW_TABLE_OWNER_MAX;
             i++) {
            const nl_flow_table_owner_resource *owner =
                &resources->flow_owner[i];
            char owner_name_attr[64];
            char owner_type_attr[64];

            xml_escape_attr(owner->name, owner_name_attr,
                            sizeof(owner_name_attr));
            xml_escape_attr(hal_flow_owner_name((hal_flow_owner)owner->owner),
                            owner_type_attr, sizeof(owner_type_attr));
            off = append_format_text(resp, resp_size, off,
                "    <owner table=\"%d\" owner=\"%s\" name=\"%s\" "
                "capacity=\"%d\" used=\"%d\" free=\"%d\" "
                "max-actions=\"%d\" condition=\"0x%x\"/>\n",
                owner->table, owner_type_attr, owner_name_attr,
                owner->capacity, owner->used, owner->free,
                owner->max_actions, owner->condition);
        }
        off = append_format_text(resp, resp_size, off,
            "  </flow-owners>\n");
        off = append_format_text(resp, resp_size, off,
            "  <control-plane table=\"%d\" capacity=\"%d\" free=\"%d\" "
            "rules=\"%d\" packets=\"%d\" octets=\"%d\"/>\n",
            resources->control_plane_table,
            resources->control_plane_capacity, resources->control_plane_free,
            resources->control_plane_rules, resources->control_plane_packets,
            resources->control_plane_octets);
        off = append_format_text(resp, resp_size, off,
            "  <acl count=\"%d\"/>\n", resources->acl_count);
        off = append_format_text(resp, resp_size, off,
            "  <acl-owners count=\"%d\">\n",
            resources->acl_owner_count);
        for (int i = 0;
             i < resources->acl_owner_count &&
             i < NETLAB_ACL_RESOURCE_OWNER_MAX;
             i++) {
            const nl_acl_resource_owner_resource *owner =
                &resources->acl_owner[i];
            char owner_name_attr[64];
            char owner_type_attr[64];

            xml_escape_attr(owner->name, owner_name_attr,
                            sizeof(owner_name_attr));
            xml_escape_attr(
                hal_acl_owner_name((hal_acl_owner)owner->owner),
                owner_type_attr, sizeof(owner_type_attr));
            off = append_format_text(resp, resp_size, off,
                "    <owner acl=\"%d\" owner=\"%s\" name=\"%s\" "
                "acl-count=\"%d\" rules-per-acl=\"%d\" "
                "first-policer=\"%d\" policer-count=\"%d\"/>\n",
                owner->acl, owner_type_attr, owner_name_attr,
                owner->acl_count, owner->rules_per_acl,
                owner->first_policer, owner->policer_count);
        }
        off = append_format_text(resp, resp_size, off,
            "  </acl-owners>\n");
        off = append_format_text(resp, resp_size, off,
            "  <ffu ipv4-uc-first=\"%d\" ipv4-uc-last=\"%d\" "
            "ipv4-mc-first=\"%d\" ipv4-mc-last=\"%d\" "
            "ipv6-uc-first=\"%d\" ipv6-uc-last=\"%d\" "
            "ipv6-mc-first=\"%d\" ipv6-mc-last=\"%d\" "
            "acl-first=\"%d\" acl-last=\"%d\"/>\n",
            resources->ffu_ipv4_uc_first, resources->ffu_ipv4_uc_last,
            resources->ffu_ipv4_mc_first, resources->ffu_ipv4_mc_last,
            resources->ffu_ipv6_uc_first, resources->ffu_ipv6_uc_last,
            resources->ffu_ipv6_mc_first, resources->ffu_ipv6_mc_last,
            resources->ffu_acl_first, resources->ffu_acl_last);
        int l3_route_slices =
            slice_len(resources->ffu_ipv4_uc_first,
                      resources->ffu_ipv4_uc_last) +
            slice_len(resources->ffu_ipv4_mc_first,
                      resources->ffu_ipv4_mc_last) +
            slice_len(resources->ffu_ipv6_uc_first,
                      resources->ffu_ipv6_uc_last) +
            slice_len(resources->ffu_ipv6_mc_first,
                      resources->ffu_ipv6_mc_last);
        int route_capacity = l3_route_slices * L3_ROUTE_ENTRIES_PER_SLICE;
        off = append_format_text(resp, resp_size, off,
            "  <l3 routes=\"%d\" route-capacity=\"%d\" "
            "route-free=\"%d\" route-slices=\"%d\" "
            "arp=\"%d\" arp-capacity=\"%d\" arp-free=\"%d\" "
            "ecmp-groups=\"%d\" ecmp-capacity=\"%d\" "
            "ecmp-free=\"%d\"/>\n",
            resources->route_count, route_capacity,
            resource_free(route_capacity, resources->route_count),
            l3_route_slices,
            resources->arp_used, L3_ARP_CAPACITY,
            resource_free(L3_ARP_CAPACITY, resources->arp_used),
            resources->ecmp_groups, L3_ECMP_GROUP_CAPACITY,
            resource_free(L3_ECMP_GROUP_CAPACITY, resources->ecmp_groups));
    }
    off = append_format_text(resp, resp_size, off,
                    "</resources>\n");
    return off;
}

int hal_rpc_format_board_env(const struct sdk_result *result,
                             char *resp, size_t resp_size) {
    const hal_board_env_result *env;
    const char *topology_status = "consistent";
    char model[128];
    int off = 0;

    if (!result || !resp || resp_size == 0)
        return -1;
    env = &result->data.board_env;
    if (result->status != 0 || env->sample_count != 4 ||
        env->sample_failures != 0 || env->responder_count != 12 ||
        env->restore_status != 0) {
        topology_status = "mismatch";
    } else {
        for (int i = 0; i < env->responder_count; i++) {
            if (env->responder[i].status != 0) {
                topology_status = "mismatch";
                break;
            }
        }
    }
    xml_escape_attr(env->board_model, model, sizeof(model));
    off = append_format_text(
        resp, resp_size, off,
        "<board-environment status=\"%d\" source=\"board-i2c\" "
        "board=\"%s\" bus=\"%d\" mux-address=\"0x%02x\" "
        "sample-count=\"%d\" sample-failures=\"%d\" "
        "restore-status=\"%d\" topology-status=\"%s\" "
        "expected-responders=\"12\" observed-responders=\"%d\">\n",
        result->status, model, env->bus, env->mux_addr,
        env->sample_count, env->sample_failures, env->restore_status,
        topology_status, env->responder_count);
    if (off < 0)
        return -1;
    for (int i = 0; i < env->responder_count; i++) {
        const hal_board_env_responder *entry = &env->responder[i];
        char role[64];

        xml_escape_attr(entry->role, role, sizeof(role));
        off = append_format_text(
            resp, resp_size, off,
            "  <responder role=\"%s\" branch=\"0x%02x\" addr=\"0x%02x\" "
            "status=\"%s\" sdk-status=\"%d\"/>\n",
            role, entry->branch, entry->addr,
            entry->status == 0 ? "available" : "unavailable",
            entry->status);
        if (off < 0)
            return -1;
    }
    for (int i = 0; i < env->sensor_count; i++) {
        const hal_board_env_sensor *sensor = &env->sensor[i];
        char name[96];
        char sensor_class[48];
        char unit[48];
        char chip[48];
        char raw[(NETLAB_BOARD_ENV_RAW_MAX * 2) + 1];
        int raw_off = 0;

        xml_escape_attr(sensor->name, name, sizeof(name));
        xml_escape_attr(sensor->sensor_class, sensor_class,
                        sizeof(sensor_class));
        xml_escape_attr(sensor->unit, unit, sizeof(unit));
        xml_escape_attr(sensor->chip, chip, sizeof(chip));
        raw[0] = '\0';
        for (int j = 0; j < sensor->raw_len &&
             raw_off + 2 < (int)sizeof(raw); j++) {
            int n = snprintf(raw + raw_off, sizeof(raw) - (size_t)raw_off,
                             "%02x", sensor->raw[j]);
            if (n != 2)
                break;
            raw_off += n;
        }
        off = append_format_text(
            resp, resp_size, off,
            "  <sensor name=\"%s\" source=\"board-i2c\" class=\"%s\" "
            "unit=\"%s\" chip=\"%s\" branch=\"0x%02x\" "
            "addr=\"0x%02x\" reg=\"0x%02x\" status=\"%s\" "
            "valid=\"%d\" value=\"%.6f\" raw=\"%s\"/>\n",
            name, sensor_class, unit, chip, sensor->branch, sensor->addr,
            sensor->reg, sensor->status, sensor->valid ? 1 : 0,
            sensor->value, raw);
        if (off < 0)
            return -1;
    }
    off = append_format_text(resp, resp_size, off,
                             "</board-environment>\n");
    return off;
}

int hal_rpc_format_switch_config(const struct sdk_result *result,
                                 char *resp, size_t resp_size) {
    int off = 0;

    if (!result || !resp || resp_size == 0)
        return 0;

    off = append_format_text(resp, resp_size, off,
                    "<switch-config source=\"ies-sdk\" status=\"%d\">\n",
                    result->status);
    if (result->status == 0) {
        int count = result->data.switch_config.n_fields;
        if (count < 0)
            count = 0;
        if (count > NETLAB_SWITCH_CONFIG_MAX_FIELDS)
            count = NETLAB_SWITCH_CONFIG_MAX_FIELDS;
        for (int i = 0; i < count; i++) {
            char name[96];
            char value[256];
            char status[32];

            xml_escape_attr(result->data.switch_config.field[i].name,
                            name, sizeof(name));
            xml_escape_attr(result->data.switch_config.field[i].value,
                            value, sizeof(value));
            xml_escape_attr(result->data.switch_config.field[i].status,
                            status, sizeof(status));
            off = append_format_text(resp, resp_size, off,
                            "  <field name=\"%s\" value=\"%s\" "
                            "status=\"%s\"/>\n",
                            name, value, status);
            if (off >= (int)resp_size - 512)
                break;
        }
    }
    off = append_format_text(resp, resp_size, off,
                    "</switch-config>\n");
    return off;
}

int hal_rpc_format_switch_sensors(const struct sdk_result *result,
                                  char *resp, size_t resp_size) {
    int off = 0;

    if (!result || !resp || resp_size == 0)
        return 0;

    off = append_format_text(resp, resp_size, off,
                    "<switch-sensors source=\"sbus\" status=\"%d\">",
                    result->status);
    if (result->status == 0) {
        int count = result->data.switch_sensors.n_sensors;

        if (count < 0)
            count = 0;
        if (count > NETLAB_SWITCH_SENSOR_MAX)
            count = NETLAB_SWITCH_SENSOR_MAX;
        for (int i = 0; i < count; i++) {
            char label[96];
            char sensor_class[32];
            char unit[32];
            const char *fmt;

            xml_escape_attr(result->data.switch_sensors.sensor[i].label,
                            label, sizeof(label));
            xml_escape_attr(
                result->data.switch_sensors.sensor[i].sensor_class,
                sensor_class, sizeof(sensor_class));
            xml_escape_attr(result->data.switch_sensors.sensor[i].unit,
                            unit, sizeof(unit));
            fmt = strcmp(result->data.switch_sensors.sensor[i].unit,
                         "volts") == 0 ? "%.4f" : "%.1f";
            off = append_format_text(resp, resp_size, off,
                            "<sensor index=\"%d\" label=\"%s\" "
                            "class=\"%s\" unit=\"%s\" valid=\"%d\" "
                            "value=\"",
                            result->data.switch_sensors.sensor[i].index,
                            label, sensor_class, unit,
                            result->data.switch_sensors.sensor[i].valid);
            off = append_format_text(resp, resp_size, off,
                            fmt,
                            result->data.switch_sensors.sensor[i].value);
            off = append_format_text(resp, resp_size, off,
                            "\"/>");
            if (off >= (int)resp_size - 128)
                break;
        }
    }
    off = append_format_text(resp, resp_size, off,
                    "</switch-sensors>");
    return off;
}

int hal_rpc_format_control_plane_protection(const struct sdk_result *result,
                                            char *resp, size_t resp_size) {
    int off = 0;

    if (!result || !resp || resp_size == 0)
        return 0;

    off = append_format_text(resp, resp_size, off,
                    "<control-plane-protection source=\"ies-sdk\" "
                    "status=\"%d\" table=\"%d\" capacity=\"%d\" "
                    "free=\"%d\" policers=\"%d\">\n",
                    result->status, result->data.cp_protection.table,
                    result->data.cp_protection.capacity,
                    result->data.cp_protection.free,
                    result->data.cp_protection.policers);
    if (result->status == 0) {
        int count = result->data.cp_protection.n_classes;
        if (count < 0)
            count = 0;
        if (count > NETLAB_CP_PROTECTION_CLASS_MAX)
            count = NETLAB_CP_PROTECTION_CLASS_MAX;

        for (int i = 0; i < count; i++) {
            const nl_control_plane_protection_class *c =
                &result->data.cp_protection.classes[i];
            char name[64];
            char protocol[64];
            char match[128];
            char action[64];
            char enforcement[128];
            char state[64];
            char packets[32];
            char octets[32];

            xml_escape_attr(c->name, name, sizeof(name));
            xml_escape_attr(c->protocol, protocol, sizeof(protocol));
            xml_escape_attr(c->match, match, sizeof(match));
            xml_escape_attr(c->action, action, sizeof(action));
            xml_escape_attr(c->enforcement, enforcement,
                            sizeof(enforcement));
            xml_escape_attr(c->state, state, sizeof(state));
            if (c->packets == (u64)-1)
                snprintf(packets, sizeof(packets), "-1");
            else
                snprintf(packets, sizeof(packets), "%llu",
                         (unsigned long long)c->packets);
            if (c->octets == (u64)-1)
                snprintf(octets, sizeof(octets), "-1");
            else
                snprintf(octets, sizeof(octets), "%llu",
                         (unsigned long long)c->octets);

            off = append_format_text(resp, resp_size, off,
                "  <class name=\"%s\" protocol=\"%s\" "
                "match=\"%s\" action=\"%s\" enforcement=\"%s\" "
                "state=\"%s\" table=\"%d\" flow=\"%d\" "
                "policer=\"%d\" rate-kbps=\"%d\" "
                "burst-bytes=\"%d\" packets=\"%s\" "
                "octets=\"%s\"/>\n",
                name, protocol, match, action, enforcement, state,
                c->table, c->flow, c->policer, c->rate_kbps,
                c->burst_bytes, packets, octets);
            if (off >= (int)resp_size - 512)
                break;
        }
    }
    off = append_format_text(resp, resp_size, off,
                    "</control-plane-protection>\n");
    return off;
}

static int hal_rpc_format_rate_entries(const char *root,
                                       const hal_storm_control_entry *entries,
                                       int n_entries, char *resp,
                                       size_t resp_size) {
    int off = 0;

    if (!resp || resp_size == 0)
        return 0;
    if (n_entries < 0)
        n_entries = 0;

    off = append_format_text(resp, resp_size, off,
                    "<%s>\n", root);
    for (int i = 0; entries && i < n_entries; i++) {
        char ifname[64] = {0};
        if (!nl_ifid_logical_port_to_name(entries[i].port,
                                          ifname, sizeof(ifname)))
            snprintf(ifname, sizeof(ifname), "port-%d", entries[i].port);
        off = append_format_text(resp, resp_size, off,
            "  <entry port=\"%d\" interface=\"%s\" controller=\"%d\" "
            "rate=\"%d\" burst=\"%d\" packets=\"%llu\" kind=\"%s\"/>\n",
            entries[i].port, ifname, entries[i].controller,
            entries[i].rate_kbps, entries[i].burst_bytes,
            (unsigned long long)entries[i].packets, nl_storm_kind_name(entries[i].kind));
        if (off >= (int)resp_size)
            break;
    }
    off = append_format_text(resp, resp_size, off,
                    "</%s>\n", root);
    return off;
}

int hal_rpc_format_storm_control(const hal_storm_control_entry *entries,
                                 int n_entries, char *resp,
                                 size_t resp_size) {
    return hal_rpc_format_rate_entries("storm-control", entries, n_entries,
                                       resp, resp_size);
}

int hal_rpc_format_ingress_rate_limit(const hal_storm_control_entry *entries,
                              int n_entries, char *resp,
                              size_t resp_size) {
    return hal_rpc_format_rate_entries("ingress-rate-limit", entries, n_entries,
                                       resp, resp_size);
}

int hal_rpc_format_egress_rate_limit(
    const hal_egress_rate_limit_entry *entries,
    int n_entries, char *resp, size_t resp_size) {
    int off = 0;

    if (!resp || resp_size == 0)
        return 0;
    if (n_entries < 0)
        n_entries = 0;

    off = append_format_text(resp, resp_size, off,
                    "<egress-rate-limit>\n");
    for (int i = 0; entries && i < n_entries; i++) {
        char ifname[64] = {0};
        if (!nl_ifid_logical_port_to_name(entries[i].port,
                                          ifname, sizeof(ifname)))
            snprintf(ifname, sizeof(ifname), "port-%d", entries[i].port);
        off = append_format_text(resp, resp_size, off,
            "  <entry port=\"%d\" interface=\"%s\" group=\"%d\" "
            "rate=\"%d\" burst=\"%d\"/>\n",
            entries[i].port, ifname, entries[i].shaping_group,
            entries[i].rate_kbps, entries[i].burst_bytes);
        if (off >= (int)resp_size)
            break;
    }
    off = append_format_text(resp, resp_size, off,
                    "</egress-rate-limit>\n");
    return off;
}

static const char *qos_trust_name(int trust_mode) {
    switch (trust_mode) {
    case HAL_QOS_TRUST_NONE:
        return "none";
    case HAL_QOS_TRUST_DSCP:
        return "dscp";
    case HAL_QOS_TRUST_IEEE8021P:
    default:
        return "ieee-802.1p";
    }
}

static const char *qos_bool_state(int value) {
    if (value < 0)
        return "unsupported";
    return value ? "on" : "off";
}

static const char *qos_tx_pause_mode_name(int value) {
    switch (value) {
    case FM_PORT_TX_PAUSE_NORMAL:
        return "normal";
    case FM_PORT_TX_PAUSE_CLASS_BASED:
        return "class-based";
    case -1:
        return "unsupported";
    default:
        return "unknown";
    }
}

static const char *qos_cn_mode_name(int value) {
    switch (value) {
    case FM_QOS_CN_MODE_DISABLED:
        return "disabled";
    case FM_QOS_CN_MODE_VCN:
        return "vcn";
    case FM_QOS_CN_MODE_FCN:
        return "fcn";
    case -1:
        return "unsupported";
    default:
        return "unknown";
    }
}

static const char *qos_tc_smp_name(int value, char *buf, size_t buf_len) {
    if (value < 0)
        return "unsupported";
    if (value == FM_QOS_TC_SMP_NONE)
        return "none";
    if (value >= FM_QOS_TC_SMP_0 && value <= FM_QOS_TC_SMP_11) {
        snprintf(buf, buf_len, "smp-%d", value - FM_QOS_TC_SMP_0);
        return buf;
    }
    if (value == FM_QOS_TC_SMP_INVALID)
        return "invalid";
    return "unknown";
}

static void qos_mask_text(int value, char *buf, size_t buf_len) {
    if (value < 0)
        snprintf(buf, buf_len, "unsupported");
    else
        snprintf(buf, buf_len, "0x%02x", (unsigned)value);
}

static void qos_int_text(int value, char *buf, size_t buf_len) {
    if (value < 0)
        snprintf(buf, buf_len, "unsupported");
    else
        snprintf(buf, buf_len, "%d", value);
}

static void qos_hex16_text(int value, char *buf, size_t buf_len) {
    if (value < 0)
        snprintf(buf, buf_len, "unsupported");
    else
        snprintf(buf, buf_len, "0x%04x", (unsigned)(value & 0xffff));
}

static void qos_u64_text(int supported, u64 value,
                         char *buf, size_t buf_len) {
    if (!supported)
        snprintf(buf, buf_len, "unsupported");
    else
        snprintf(buf, buf_len, "%llu", (unsigned long long)value);
}

static void qos_rate_text(const hal_qos_scheduler_entry *entry, int group,
                          char *buf, size_t buf_len) {
    if (!entry->group_rate_supported[group])
        snprintf(buf, buf_len, "unsupported");
    else if (entry->group_rate_default[group])
        snprintf(buf, buf_len, "default");
    else
        snprintf(buf, buf_len, "%llu",
                 (unsigned long long)entry->group_rate_bps[group]);
}

static void qos_mac_text(u64 mac, char *buf, size_t buf_len) {
    snprintf(buf, buf_len, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
             (unsigned long long)((mac >> 40) & 0xff),
             (unsigned long long)((mac >> 32) & 0xff),
             (unsigned long long)((mac >> 24) & 0xff),
             (unsigned long long)((mac >> 16) & 0xff),
             (unsigned long long)((mac >> 8) & 0xff),
             (unsigned long long)(mac & 0xff));
}

int hal_rpc_format_qos_interfaces(const hal_qos_interface_entry *entries,
                                  int n_entries, char *resp,
                                  size_t resp_size) {
    int off = 0;

    if (!resp || resp_size == 0)
        return 0;
    if (n_entries < 0)
        n_entries = 0;

    off = append_format_text(resp, resp_size, off,
                    "<class-of-service><interfaces>\n");
    for (int i = 0; entries && i < n_entries; i++) {
        char ifname[64] = {0};
        if (!nl_ifid_logical_port_to_name(entries[i].port,
                                          ifname, sizeof(ifname)))
            snprintf(ifname, sizeof(ifname), "port-%d", entries[i].port);
        off = append_format_text(resp, resp_size, off,
                        "  <interface port=\"%d\" name=\"%s\" trust=\"%s\" "
                        "default-priority=\"%d\"/>\n",
                        entries[i].port, ifname,
                        qos_trust_name(entries[i].trust_mode),
                        entries[i].default_priority);
        if (off >= (int)resp_size)
            break;
    }
    off = append_format_text(resp, resp_size, off,
                    "</interfaces></class-of-service>\n");
    return off;
}

int hal_rpc_format_qos_dscp_map(const int *priorities, int n_entries,
                                char *resp, size_t resp_size) {
    int off = append_format_text(resp, resp_size, 0,
                                 "<class-of-service><dscp-map>\n");
    for (int i = 0; priorities && i < n_entries && i < 64; i++)
        off = append_format_text(resp, resp_size, off,
            "<entry dscp=\"%d\" switch-priority=\"%d\"/>\n", i, priorities[i]);
    return append_format_text(resp, resp_size, off,
                               "</dscp-map></class-of-service>\n");
}

int hal_rpc_format_qos_priority_map(
    const hal_qos_priority_map_entry *entries,
    int n_entries, char *resp, size_t resp_size) {
    int off = 0;

    if (!resp || resp_size == 0)
        return 0;
    if (n_entries < 0)
        n_entries = 0;

    off = append_format_text(resp, resp_size, off,
                    "<class-of-service><forwarding>\n");
    for (int i = 0; entries && i < n_entries; i++) {
        off = append_format_text(resp, resp_size, off,
                        "  <switch-priority priority=\"%d\" "
                        "traffic-class=\"%d\"/>\n",
                        entries[i].switch_priority,
                        entries[i].traffic_class);
        if (off >= (int)resp_size)
            break;
    }
    off = append_format_text(resp, resp_size, off,
                    "</forwarding></class-of-service>\n");
    return off;
}

int hal_rpc_format_qos_flow_control(
    const hal_qos_flow_control_global *global,
    const hal_qos_flow_control_entry *entries,
    int n_entries, char *resp, size_t resp_size) {
    int off = 0;
    char pause_smac[32] = "unsupported";

    if (!resp || resp_size == 0)
        return 0;
    if (n_entries < 0)
        n_entries = 0;
    if (global && global->pause_smac_valid)
        qos_mac_text(global->pause_smac, pause_smac, sizeof(pause_smac));

    off = append_format_text(resp, resp_size, off,
                    "<class-of-service><flow-control auto-pause=\"%s\" "
                    "drop-pause=\"%s\" pause-smac=\"%s\" roce-buffer-status=\"%d\" smp0-usage=\"%d\" smp1-usage=\"%d\">\n",
                    qos_bool_state(global ? global->auto_pause_mode : -1),
                    qos_bool_state(global ? global->drop_pause : -1),
                    pause_smac, global ? global->roce_buffer_status : -1,
                    global ? global->smp_usage[0] : -1, global ? global->smp_usage[1] : -1);
    if (global) {
        for (int tc = 0; tc < 8; tc++) {
            char smp_buf[16];
            off = append_format_text(resp, resp_size, off,
                            "  <traffic-class id=\"%d\" smp=\"%s\"/>\n",
                            tc, qos_tc_smp_name(global->tc_smp_map[tc],
                                                smp_buf, sizeof(smp_buf)));
            if (off >= (int)resp_size - 256)
                break;
        }
    }
    for (int i = 0; entries && i < n_entries; i++) {
        char ifname[64] = {0};
        char rx_class[24];
        char tx_class[24];
        char smp_lossless[24];
        char shared_pause[24];
        char tx_quanta[24];
        char tx_resend[24];

        if (!nl_ifid_logical_port_to_name(entries[i].port,
                                          ifname, sizeof(ifname)))
            snprintf(ifname, sizeof(ifname), "port-%d", entries[i].port);
        qos_mask_text(entries[i].rx_class_pause_mask,
                      rx_class, sizeof(rx_class));
        qos_mask_text(entries[i].tx_class_pause_mask,
                      tx_class, sizeof(tx_class));
        qos_mask_text(entries[i].smp_lossless_pause_mask,
                      smp_lossless, sizeof(smp_lossless));
        qos_mask_text(entries[i].shared_pause_enable_mask,
                      shared_pause, sizeof(shared_pause));
        qos_int_text(entries[i].tx_pause_quanta,
                     tx_quanta, sizeof(tx_quanta));
        qos_int_text(entries[i].tx_pause_resend_time_ns,
                     tx_resend, sizeof(tx_resend));

        off = append_format_text(resp, resp_size, off,
                        "  <interface port=\"%d\" name=\"%s\" "
                        "rx-pause=\"%s\" rx-class-mask=\"%s\" "
                        "tx-pause-mode=\"%s\" tx-class-mask=\"%s\" "
                        "smp-lossless-mask=\"%s\" "
                        "shared-pause-mask=\"%s\" "
                        "tx-pause-quanta=\"%s\" "
                        "tx-pause-resend-ns=\"%s\" tc3-usage=\"%d\" rx-smp0-usage=\"%d\" "
                        "rx-smp1-usage=\"%d\" tc3-pause-class=\"%d\" "
                        "pause-state-status=\"%d\" paused-class-mask=\"%d\" generated-smp-pause-mask=\"%d\" "
                        "rx-pause-quanta=\"%d %d %d %d %d %d %d %d\" cnp-tc-usage=\"%d\" "
                        "rx-class-mask-hardware=\"%d\" pc3-smp=\"%d\" watchdog-supported=\"%d\" watchdog-phase=\"%d\" "
                        "watchdog-detect-ms=\"%u\" watchdog-recovery-ms=\"%u\" watchdog-cooldown-ms=\"%u\" "
                        "watchdog-sample-status=\"%d\" watchdog-sampled-ms=\"%llu\" watchdog-saved-rx-mask=\"%d\" "
                        "watchdog-detections=\"%llu\" watchdog-restorations=\"%llu\" watchdog-failures=\"%llu\" watchdog-gaps=\"%llu\"/>\n",
                        entries[i].port, ifname,
                        qos_bool_state(entries[i].rx_pause),
                        rx_class,
                        qos_tx_pause_mode_name(entries[i].tx_pause_mode),
                        tx_class, smp_lossless, shared_pause,
                        tx_quanta, tx_resend, entries[i].tc3_usage,
                        entries[i].rx_smp0_usage, entries[i].rx_smp1_usage, entries[i].tc3_pause_class,
                        entries[i].pause_state_status, entries[i].paused_class_mask, entries[i].generated_smp_pause_mask,
                        entries[i].rx_pause_quanta[0], entries[i].rx_pause_quanta[1], entries[i].rx_pause_quanta[2], entries[i].rx_pause_quanta[3],
                        entries[i].rx_pause_quanta[4], entries[i].rx_pause_quanta[5], entries[i].rx_pause_quanta[6], entries[i].rx_pause_quanta[7], entries[i].cnp_tc_usage,
                        entries[i].rx_class_mask_hardware, entries[i].pc3_smp, entries[i].watchdog.supported, entries[i].watchdog.phase,
                        entries[i].watchdog.policy.detect_ms, entries[i].watchdog.policy.recovery_ms, entries[i].watchdog.policy.cooldown_ms,
                        entries[i].watchdog.sample_status, (unsigned long long)entries[i].watchdog.sampled_ms, entries[i].watchdog.saved_rx_mask,
                        (unsigned long long)entries[i].watchdog.detections, (unsigned long long)entries[i].watchdog.restorations,
                        (unsigned long long)entries[i].watchdog.failures, (unsigned long long)entries[i].watchdog.gaps);
        if (off >= (int)resp_size - 256)
            break;
    }
    off = append_format_text(resp, resp_size, off,
                    "</flow-control></class-of-service>\n");
    return off;
}

int hal_rpc_format_qos_scheduler(
    const hal_qos_scheduler_entry *entries,
    int n_entries, char *resp, size_t resp_size) {
    int off = 0;

    if (!resp || resp_size == 0)
        return 0;
    if (n_entries < 0)
        n_entries = 0;

    off = append_format_text(resp, resp_size, off,
                    "<class-of-service><scheduler>\n");
    for (int i = 0; entries && i < n_entries; i++) {
        char ifname[64] = {0};
        char sched_groups[24];
        char free_bw[24];
        char tc_enable[24];
        char tc_zero[24];
        int groups_to_emit = entries[i].num_sched_groups;

        if (!nl_ifid_logical_port_to_name(entries[i].port,
                                          ifname, sizeof(ifname)))
            snprintf(ifname, sizeof(ifname), "port-%d", entries[i].port);
        qos_int_text(entries[i].num_sched_groups,
                     sched_groups, sizeof(sched_groups));
        qos_int_text(entries[i].free_bandwidth_percent,
                     free_bw, sizeof(free_bw));
        qos_mask_text(entries[i].traffic_class_enable_mask,
                      tc_enable, sizeof(tc_enable));
        qos_mask_text(entries[i].traffic_class_zero_length_mask,
                      tc_zero, sizeof(tc_zero));

        if (groups_to_emit <= 0 || groups_to_emit > HAL_QOS_MAX_SCHED_GROUPS)
            groups_to_emit = HAL_QOS_MAX_SCHED_GROUPS;

        off = append_format_text(resp, resp_size, off,
                        "  <interface port=\"%d\" name=\"%s\" "
                        "sched-groups=\"%s\" free-bandwidth-percent=\"%s\" "
                        "tc-enable-mask=\"%s\" "
                        "tc-zero-length-mask=\"%s\">\n",
                        entries[i].port, ifname, sched_groups, free_bw,
                        tc_enable, tc_zero);
        if (off >= (int)resp_size - 512)
            break;

        for (int tc = 0; tc < HAL_QOS_MAX_TRAFFIC_CLASSES; tc++) {
            char shaping_group[24];

            qos_int_text(entries[i].tc_shaping_group_map[tc],
                         shaping_group, sizeof(shaping_group));
            off = append_format_text(resp, resp_size, off,
                            "    <traffic-class id=\"%d\" "
                            "shaping-group=\"%s\"/>\n",
                            tc, shaping_group);
            if (off >= (int)resp_size - 512)
                break;
        }

        for (int group = 0; group < groups_to_emit; group++) {
            char priset[24];
            char strict[16];
            char weight[24];
            char boundary_a[24];
            char boundary_b[24];
            char rate[32];
            char burst[32];

            qos_int_text(entries[i].group_priset[group],
                         priset, sizeof(priset));
            snprintf(strict, sizeof(strict), "%s",
                     qos_bool_state(entries[i].group_strict[group]));
            qos_int_text(entries[i].group_weight[group],
                         weight, sizeof(weight));
            qos_int_text(entries[i].group_tc_boundary_a[group],
                         boundary_a, sizeof(boundary_a));
            qos_int_text(entries[i].group_tc_boundary_b[group],
                         boundary_b, sizeof(boundary_b));
            qos_rate_text(&entries[i], group, rate, sizeof(rate));
            qos_u64_text(entries[i].group_burst_supported[group],
                         entries[i].group_burst_bits[group],
                         burst, sizeof(burst));

            off = append_format_text(resp, resp_size, off,
                            "    <group id=\"%d\" priset=\"%s\" "
                            "strict=\"%s\" weight=\"%s\" "
                            "tc-boundary-a=\"%s\" "
                            "tc-boundary-b=\"%s\" "
                            "rate-bps=\"%s\" burst-bits=\"%s\"/>\n",
                            group, priset, strict, weight,
                            boundary_a, boundary_b, rate, burst);
            if (off >= (int)resp_size - 512)
                break;
        }

        off = append_format_text(resp, resp_size, off,
                        "  </interface>\n");
        if (off >= (int)resp_size - 512)
            break;
    }
    off = append_format_text(resp, resp_size, off,
                    "</scheduler></class-of-service>\n");
    return off;
}

static void qos_queue_bw_text(const hal_qos_queue_entry *entry, bool min_bw,
                              char *buf, size_t len) {
    if (!entry || !entry->present) {
        snprintf(buf, len, "unsupported");
        return;
    }
    if (!min_bw && entry->max_bw_default) {
        snprintf(buf, len, "unlimited");
        return;
    }
    snprintf(buf, len, "%llu",
             (unsigned long long)(min_bw ? entry->min_bw_mbps :
                                           entry->max_bw_mbps));
}

int hal_rpc_format_qos_queues(
    const hal_qos_queue_entry *entries,
    int n_entries, char *resp, size_t resp_size) {
    int off = 0;
    int current_port = -1;

    if (!resp || resp_size == 0)
        return 0;
    if (n_entries < 0)
        n_entries = 0;

    off = append_format_text(resp, resp_size, off,
                    "<class-of-service><queues owner=\"sdk-readback\" "
                    "config-open=\"false\">\n");
    for (int i = 0; entries && i < n_entries; i++) {
        char ifname[64] = {0};
        char tc[24];
        char min_bw[32];
        char max_bw[32];

        if (entries[i].port != current_port) {
            if (current_port >= 0) {
                off = append_format_text(resp, resp_size, off,
                                "  </interface>\n");
                if (off >= (int)resp_size - 512)
                    break;
            }
            current_port = entries[i].port;
            if (!nl_ifid_logical_port_to_name(entries[i].port,
                                              ifname, sizeof(ifname)))
                snprintf(ifname, sizeof(ifname), "port-%d", entries[i].port);
            off = append_format_text(resp, resp_size, off,
                            "  <interface port=\"%d\" name=\"%s\">\n",
                            entries[i].port, ifname);
            if (off >= (int)resp_size - 512)
                break;
        }

        qos_int_text(entries[i].traffic_class, tc, sizeof(tc));
        qos_queue_bw_text(&entries[i], true, min_bw, sizeof(min_bw));
        qos_queue_bw_text(&entries[i], false, max_bw, sizeof(max_bw));

        off = append_format_text(resp, resp_size, off,
                        "    <queue id=\"%d\" state=\"%s\" "
                        "sdk-status=\"%d\" traffic-class=\"%s\" "
                        "min-bw-mbps=\"%s\" max-bw-mbps=\"%s\"/>\n",
                        entries[i].queue_id,
                        entries[i].present ? "present" : "absent",
                        entries[i].sdk_status, tc, min_bw, max_bw);
        if (off >= (int)resp_size - 512)
            break;
    }
    if (current_port >= 0 && off < (int)resp_size - 512)
        off = append_format_text(resp, resp_size, off,
                        "  </interface>\n");
    off = append_format_text(resp, resp_size, off,
                    "</queues></class-of-service>\n");
    return off;
}

int hal_rpc_format_qos_watermarks(
    const hal_qos_watermark_global *global,
    const hal_qos_watermark_entry *entries,
    int n_entries, char *resp, size_t resp_size) {
    int off = 0;
    char priv_wm[24];
    char high_wm[24];
    char low_wm[24];
    char cn_etype[24];
    char cn_vpri[24];
    char cn_vlan[24];
    char cn_src_port[24];
    char cn_smac[32] = "unsupported";
    char cn_dmac[32] = "unsupported";

    if (!resp || resp_size == 0)
        return 0;
    if (n_entries < 0)
        n_entries = 0;

    qos_int_text(global ? global->priv_wm : -1, priv_wm, sizeof(priv_wm));
    qos_int_text(global ? global->high_wm : -1, high_wm, sizeof(high_wm));
    qos_int_text(global ? global->low_wm : -1, low_wm, sizeof(low_wm));
    qos_hex16_text(global ? global->cn_frame_etype : -1,
                   cn_etype, sizeof(cn_etype));
    qos_int_text(global ? global->cn_frame_vpri : -1,
                 cn_vpri, sizeof(cn_vpri));
    qos_int_text(global ? global->cn_frame_vlan : -1,
                 cn_vlan, sizeof(cn_vlan));
    qos_int_text(global ? global->cn_frame_src_port : -1,
                 cn_src_port, sizeof(cn_src_port));
    if (global && global->cn_frame_smac_valid)
        qos_mac_text(global->cn_frame_smac, cn_smac, sizeof(cn_smac));
    if (global && global->cn_frame_dmac_valid)
        qos_mac_text(global->cn_frame_dmac, cn_dmac, sizeof(cn_dmac));

    off = append_format_text(resp, resp_size, off,
                    "<class-of-service><watermarks auto-pause=\"%s\" "
                    "cn-mode=\"%s\" cn-frame-etype=\"%s\" "
                    "cn-frame-vpri=\"%s\" cn-frame-vlan=\"%s\" "
                    "cn-frame-src-port=\"%s\" cn-frame-smac=\"%s\" "
                    "cn-frame-dmac=\"%s\" priv-wm=\"%s\" "
                    "high-wm=\"%s\" low-wm=\"%s\">\n",
                    qos_bool_state(global ? global->auto_pause_mode : -1),
                    qos_cn_mode_name(global ? global->cn_mode : -1),
                    cn_etype, cn_vpri, cn_vlan, cn_src_port, cn_smac,
                    cn_dmac, priv_wm, high_wm, low_wm);

    if (global) {
        for (int smp = 0; smp < HAL_QOS_MAX_MEMORY_PARTITIONS; smp++) {
            char pause_on[24];
            char pause_off[24];

            qos_int_text(global->shared_pause_on_wm[smp],
                         pause_on, sizeof(pause_on));
            qos_int_text(global->shared_pause_off_wm[smp],
                         pause_off, sizeof(pause_off));
            off = append_format_text(resp, resp_size, off,
                            "  <shared-memory id=\"%d\" "
                            "pause-on-wm=\"%s\" "
                            "pause-off-wm=\"%s\"/>\n",
                            smp, pause_on, pause_off);
            if (off >= (int)resp_size - 512)
                break;
        }

        for (int pri = 0; pri < HAL_QOS_MAX_SWITCH_PRIORITIES; pri++) {
            char shared_pri[24];
            char soft_drop[24];
            char jitter[24];
            char hog[24];

            qos_int_text(global->shared_pri_wm[pri],
                         shared_pri, sizeof(shared_pri));
            qos_int_text(global->shared_soft_drop_wm[pri],
                         soft_drop, sizeof(soft_drop));
            qos_int_text(global->shared_soft_drop_jitter[pri],
                         jitter, sizeof(jitter));
            qos_int_text(global->shared_soft_drop_hog[pri],
                         hog, sizeof(hog));
            off = append_format_text(resp, resp_size, off,
                            "  <switch-priority id=\"%d\" "
                            "shared-pri-wm=\"%s\" "
                            "soft-drop-wm=\"%s\" "
                            "soft-drop-jitter=\"%s\" "
                            "soft-drop-hog-wm=\"%s\"/>\n",
                            pri, shared_pri, soft_drop, jitter, hog);
            if (off >= (int)resp_size - 512)
                break;
        }
    }

    for (int i = 0; entries && i < n_entries; i++) {
        char ifname[64] = {0};

        if (!nl_ifid_logical_port_to_name(entries[i].port,
                                          ifname, sizeof(ifname)))
            snprintf(ifname, sizeof(ifname), "port-%d", entries[i].port);
        off = append_format_text(resp, resp_size, off,
                        "  <interface port=\"%d\" name=\"%s\">\n",
                        entries[i].port, ifname);
        if (off >= (int)resp_size - 512)
            break;

        for (int tc = 0; tc < HAL_QOS_MAX_TRAFFIC_CLASSES; tc++) {
            char tx_hog[24];
            char tx_private[24];

            qos_int_text(entries[i].tx_hog_wm[tc],
                         tx_hog, sizeof(tx_hog));
            qos_int_text(entries[i].tx_tc_private_wm[tc],
                         tx_private, sizeof(tx_private));
            off = append_format_text(resp, resp_size, off,
                            "    <traffic-class id=\"%d\" "
                            "tx-hog-wm=\"%s\" "
                            "tx-private-wm=\"%s\"/>\n",
                            tc, tx_hog, tx_private);
            if (off >= (int)resp_size - 512)
                break;
        }

        for (int smp = 0; smp < HAL_QOS_MAX_MEMORY_PARTITIONS; smp++) {
            char rx_hog[24];
            char rx_private[24];
            char pause_on[24];
            char pause_off[24];

            qos_int_text(entries[i].rx_hog_wm[smp],
                         rx_hog, sizeof(rx_hog));
            qos_int_text(entries[i].rx_private_wm[smp],
                         rx_private, sizeof(rx_private));
            qos_int_text(entries[i].private_pause_on_wm[smp],
                         pause_on, sizeof(pause_on));
            qos_int_text(entries[i].private_pause_off_wm[smp],
                         pause_off, sizeof(pause_off));
            off = append_format_text(resp, resp_size, off,
                            "    <memory-partition id=\"%d\" "
                            "rx-hog-wm=\"%s\" rx-private-wm=\"%s\" "
                            "private-pause-on-wm=\"%s\" "
                            "private-pause-off-wm=\"%s\"/>\n",
                            smp, rx_hog, rx_private, pause_on, pause_off);
            if (off >= (int)resp_size - 512)
                break;
        }
        for (int priority = 0;
             priority < HAL_QOS_MAX_SWITCH_PRIORITIES; priority++) {
            char on_private[24];
            char on_rxmp_free[24];

            qos_int_text(
                entries[i].tx_soft_drop_on_private[priority],
                on_private, sizeof(on_private));
            qos_int_text(
                entries[i].tx_soft_drop_on_rxmp_free[priority],
                on_rxmp_free, sizeof(on_rxmp_free));
            off = append_format_text(
                resp, resp_size, off,
                "    <switch-priority id=\"%d\" "
                "tx-soft-drop-on-private=\"%s\" "
                "tx-soft-drop-on-rxmp-free=\"%s\"/>\n",
                priority, on_private, on_rxmp_free);
            if (off >= (int)resp_size - 512)
                break;
        }

        off = append_format_text(resp, resp_size, off,
                        "  </interface>\n");
        if (off >= (int)resp_size - 512)
            break;
    }

    off = append_format_text(resp, resp_size, off,
                    "</watermarks></class-of-service>\n");
    return off;
}
