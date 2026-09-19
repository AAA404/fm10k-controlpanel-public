/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/hal.h"
#include "hal_pfc_watchdog.h"
#include "netlab/hal_transaction_snapshot.h"
#include "netlab/interface_id.h"
#include "netlab/journal.h"
#include "netlab/log.h"
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_qos.h>
#include <api/fm_api_regs.h>
#include <api/internal/fm_api_common_int.h>
#include <api/internal/fm_api_portmask.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NETLAB_QOS_MAX_SWITCH_PRIORITIES 16
#define NETLAB_QOS_MAX_TRAFFIC_CLASSES 8
#define NETLAB_QOS_UNSUPPORTED -1
#define NETLAB_QOS_WATERMARK_CONFIG_MAX 512

#define NETLAB_QOS_WATERMARK_PROVENANCE_MAGIC \
    "NETLAB_QOS_WATERMARK_PROVENANCE_V1"

int hal_qos_dscp_get(int sw, int dscp, int *priority) {
    fm_uint32 value = 0;
    if (!priority || dscp < 0 || dscp > 63) return FM_ERR_INVALID_ARGUMENT;
    fm_status st = fmGetSwitchQOS(sw, FM_QOS_DSCP_SWPRI_MAP, dscp, &value);
    if (st != FM_OK) return st;
    if (value > 15) return FM_ERR_INVALID_STATE;
    *priority = (int)value;
    return FM_OK;
}

int hal_qos_dscp_set(int sw, int dscp, int priority) {
    if (dscp < 0 || dscp > 63 || priority < 0 || priority > 15)
        return FM_ERR_INVALID_ARGUMENT;
    fm_uint32 value = (fm_uint32)priority;
    fm_status st = fmSetSwitchQOS(sw, FM_QOS_DSCP_SWPRI_MAP, dscp, &value);
    if (st != FM_OK) return st; /* The transaction compensates partial writes. */
    int actual = -1;
    st = hal_qos_dscp_get(sw, dscp, &actual);
    return st != FM_OK ? st : actual == priority ? FM_OK : FM_ERR_INVALID_STATE;
}

int hal_qos_dscp_list(int sw, int priorities[64]) {
    if (!priorities) return -1;
    for (int dscp = 0; dscp < 64; dscp++)
        if (hal_qos_dscp_get(sw, dscp, &priorities[dscp]) != FM_OK) return -1;
    return 64;
}

static bool qos_trust_valid(int trust_mode) {
    return trust_mode == HAL_QOS_TRUST_NONE ||
           trust_mode == HAL_QOS_TRUST_IEEE8021P ||
           trust_mode == HAL_QOS_TRUST_DSCP;
}

static fm_uint32 qos_source_for_trust(int trust_mode) {
    switch (trust_mode) {
    case HAL_QOS_TRUST_NONE:
        return FM_PORT_SWPRI_ISL_TAG;
    case HAL_QOS_TRUST_DSCP:
        return FM_PORT_SWPRI_DSCP | FM_PORT_SWPRI_VPRI1 |
               FM_PORT_SWPRI_ISL_TAG;
    case HAL_QOS_TRUST_IEEE8021P:
    default:
        return FM_PORT_SWPRI_VPRI1 | FM_PORT_SWPRI_ISL_TAG;
    }
}

static int qos_trust_from_source(fm_uint32 source, fm_bool dscp_pref) {
    fm_uint32 data_sources = source & (FM_PORT_SWPRI_DSCP |
                                       FM_PORT_SWPRI_VPRI1);

    if (data_sources == 0)
        return HAL_QOS_TRUST_NONE;
    if ((source & FM_PORT_SWPRI_DSCP) && dscp_pref == TRUE)
        return HAL_QOS_TRUST_DSCP;
    return HAL_QOS_TRUST_IEEE8021P;
}

static int qos_default_tc(int switch_priority) {
    return switch_priority & (NETLAB_QOS_MAX_TRAFFIC_CLASSES - 1);
}

static hal_qos_interface_transaction_snapshot
qos_interface_transaction_read_error(fm_status status) {
    hal_qos_interface_transaction_snapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = (int)status;
    return snapshot;
}

hal_qos_interface_transaction_snapshot
hal_qos_interface_transaction_snapshot_get(int sw, int port) {
    hal_qos_interface_transaction_snapshot snapshot;
    fm_bool dscp_preference = FALSE;
    fm_status st;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    if (port <= 0 || !nl_ifid_is_user_port(port))
        return snapshot;

    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SWPRI_SOURCE, &snapshot.source);
    if (st != FM_OK)
        return qos_interface_transaction_read_error(st);
    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SWPRI_DSCP_PREF, &dscp_preference);
    if (st != FM_OK)
        return qos_interface_transaction_read_error(st);
    snapshot.dscp_preference = (u32)dscp_preference;
    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_DEF_PRI, &snapshot.default_priority);
    if (st != FM_OK)
        return qos_interface_transaction_read_error(st);
    st = fmGetPortAttribute(
        (fm_int)sw, (fm_int)port, FM_PORT_DEF_SWPRI,
        &snapshot.default_switch_priority);
    if (st != FM_OK)
        return qos_interface_transaction_read_error(st);

    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    return snapshot;
}

static bool qos_interface_transaction_snapshots_equal(
    const hal_qos_interface_transaction_snapshot *left,
    const hal_qos_interface_transaction_snapshot *right) {
    return left && right &&
           left->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           right->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           left->source == right->source &&
           left->dscp_preference == right->dscp_preference &&
           left->default_priority == right->default_priority &&
           left->default_switch_priority ==
               right->default_switch_priority;
}

int hal_qos_interface_transaction_restore(
    int sw, int port,
    const hal_qos_interface_transaction_snapshot *snapshot) {
    hal_qos_interface_transaction_snapshot readback;
    fm_bool dscp_preference;
    fm_uint32 value;
    fm_status st;

    if (!snapshot ||
        snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        port <= 0 || !nl_ifid_is_user_port(port) ||
        snapshot->dscp_preference > 1)
        return FM_ERR_INVALID_ARGUMENT;

    value = (fm_uint32)snapshot->default_priority;
    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_DEF_PRI, &value);
    if (st != FM_OK)
        return (int)st;
    value = (fm_uint32)snapshot->default_switch_priority;
    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_DEF_SWPRI, &value);
    if (st != FM_OK)
        return (int)st;
    dscp_preference = snapshot->dscp_preference != 0 ? TRUE : FALSE;
    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SWPRI_DSCP_PREF, &dscp_preference);
    if (st != FM_OK)
        return (int)st;
    value = (fm_uint32)snapshot->source;
    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SWPRI_SOURCE, &value);
    if (st != FM_OK)
        return (int)st;

    readback = hal_qos_interface_transaction_snapshot_get(sw, port);
    if (readback.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return readback.sdk_status != FM_OK ?
               readback.sdk_status : FM_ERR_INVALID_STATE;
    return qos_interface_transaction_snapshots_equal(snapshot, &readback) ?
           0 : FM_ERR_INVALID_STATE;
}

static int get_port_u32_attr(int sw, int port, fm_int attr) {
    fm_uint32 value = 0;
    fm_status st;

    st = fmGetPortAttribute((fm_int)sw, (fm_int)port, attr, &value);
    if (st != FM_OK)
        return NETLAB_QOS_UNSUPPORTED;
    return (int)value;
}

static int get_port_bool_attr(int sw, int port, fm_int attr) {
    fm_bool value = FALSE;
    fm_status st;

    st = fmGetPortAttribute((fm_int)sw, (fm_int)port, attr, &value);
    if (st != FM_OK)
        return NETLAB_QOS_UNSUPPORTED;
    return value ? 1 : 0;
}

static int get_port_qos_u32_attr(int sw, int port, fm_int attr,
                                 fm_int index) {
    fm_uint32 value = 0;
    fm_status st;

    st = fmGetPortQOS((fm_int)sw, (fm_int)port, attr, index, &value);
    if (st != FM_OK)
        return NETLAB_QOS_UNSUPPORTED;
    return (int)value;
}

static int get_port_qos_u64_attr(int sw, int port, fm_int attr,
                                 fm_int index, u64 *out) {
    fm_uint64 value = 0;
    fm_status st;

    if (!out)
        return -1;
    st = fmGetPortQOS((fm_int)sw, (fm_int)port, attr, index, &value);
    if (st != FM_OK)
        return -1;
    *out = (u64)value;
    return 0;
}

static int get_switch_bool_attr(int sw, fm_int attr) {
    fm_bool value = FALSE;
    fm_status st;

    st = fmGetSwitchAttribute((fm_int)sw, attr, &value);
    if (st != FM_OK)
        return NETLAB_QOS_UNSUPPORTED;
    return value ? 1 : 0;
}

static int get_switch_qos_bool_attr(int sw, fm_int attr) {
    fm_bool value = FALSE;
    fm_status st;

    st = fmGetSwitchQOS((fm_int)sw, attr, 0, &value);
    if (st != FM_OK)
        return NETLAB_QOS_UNSUPPORTED;
    return value ? 1 : 0;
}

static int get_switch_qos_u32_attr(int sw, fm_int attr, fm_int index) {
    fm_uint32 value = 0;
    fm_status st;

    st = fmGetSwitchQOS((fm_int)sw, attr, index, &value);
    if (st != FM_OK)
        return NETLAB_QOS_UNSUPPORTED;
    return (int)value;
}

static int get_switch_qos_mac_attr(int sw, fm_int attr, u64 *out) {
    fm_macaddr value = 0;
    fm_status st;

    if (!out)
        return -1;
    st = fmGetSwitchQOS((fm_int)sw, attr, 0, &value);
    if (st != FM_OK)
        return -1;
    *out = (u64)value;
    return 0;
}

int hal_qos_interface_set(int sw, int port, int trust_mode,
                          int default_priority) {
    fm_uint32 source;
    fm_uint32 def_pri;
    fm_bool dscp_pref;
    fm_status st;

    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        !qos_trust_valid(trust_mode) ||
        default_priority < 0 ||
        default_priority >= NETLAB_QOS_MAX_TRAFFIC_CLASSES)
        return -1;

    source = qos_source_for_trust(trust_mode);
    dscp_pref = trust_mode == HAL_QOS_TRUST_DSCP ? TRUE : FALSE;
    def_pri = (fm_uint32)default_priority;

    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_DEF_PRI, &def_pri);
    if (st != FM_OK) {
        NL_LOG_ERR("qos interface port=%d set default priority failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_DEF_SWPRI, &def_pri);
    if (st != FM_OK) {
        NL_LOG_ERR("qos interface port=%d set default switch priority failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SWPRI_DSCP_PREF, &dscp_pref);
    if (st != FM_OK) {
        NL_LOG_ERR("qos interface port=%d set DSCP preference failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SWPRI_SOURCE, &source);
    if (st != FM_OK) {
        NL_LOG_ERR("qos interface port=%d set trust source failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    NL_LOG_INFO("qos interface port=%d trust=%d default-priority=%d",
                port, trust_mode, default_priority);
    return 0;
}

int hal_qos_interface_delete(int sw, int port) {
    return hal_qos_interface_set(sw, port, HAL_QOS_TRUST_IEEE8021P, 0);
}

int hal_qos_interface_get(int sw, int port,
                          hal_qos_interface_entry *entry) {
    fm_uint32 source = 0;
    fm_uint32 def_pri = 0;
    fm_uint32 def_swpri = 0;
    fm_bool dscp_pref = FALSE;
    fm_status st;

    if (!entry || port <= 0 || !nl_ifid_is_user_port(port))
        return -1;

    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SWPRI_SOURCE, &source);
    if (st != FM_OK)
        return -1;
    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SWPRI_DSCP_PREF, &dscp_pref);
    if (st != FM_OK)
        return -1;
    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_DEF_PRI, &def_pri);
    if (st != FM_OK)
        return -1;
    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_DEF_SWPRI, &def_swpri);
    if (st != FM_OK)
        def_swpri = def_pri;

    memset(entry, 0, sizeof(*entry));
    entry->port = port;
    entry->trust_mode = qos_trust_from_source(source, dscp_pref);
    entry->default_priority =
        def_swpri < NETLAB_QOS_MAX_TRAFFIC_CLASSES ?
        (int)def_swpri : (int)def_pri;
    return 0;
}

int hal_qos_interface_list(int sw, hal_qos_interface_entry *entries,
                           int max_entries) {
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n_ports;
    int n = 0;

    if (!entries || max_entries <= 0)
        return -1;

    n_ports = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_ports && n < max_entries; i++) {
        hal_qos_interface_entry entry;

        if (!nl_ifid_is_user_port(ports[i].logical_port))
            continue;
        if (hal_qos_interface_get(sw, ports[i].logical_port, &entry) != 0)
            continue;
        entries[n++] = entry;
    }
    return n;
}

int hal_qos_priority_map_set(int sw, int switch_priority,
                             int traffic_class) {
    fm_uint32 tc = (fm_uint32)traffic_class;
    fm_status st;

    if (switch_priority < 0 ||
        switch_priority >= NETLAB_QOS_MAX_SWITCH_PRIORITIES ||
        traffic_class < 0 ||
        traffic_class >= NETLAB_QOS_MAX_TRAFFIC_CLASSES)
        return -1;

    st = fmSetSwitchQOS((fm_int)sw, FM_QOS_SWPRI_TC_MAP,
                        (fm_int)switch_priority, &tc);
    if (st != FM_OK) {
        NL_LOG_ERR("qos priority-map swpri=%d tc=%d failed: %s",
                   switch_priority, traffic_class, fmErrorMsg(st));
        return (int)st;
    }
    NL_LOG_INFO("qos priority-map swpri=%d tc=%d",
                switch_priority, traffic_class);
    return 0;
}

int hal_qos_priority_map_delete(int sw, int switch_priority) {
    return hal_qos_priority_map_set(sw, switch_priority,
                                    qos_default_tc(switch_priority));
}

int hal_qos_priority_map_get(int sw, int switch_priority,
                             hal_qos_priority_map_entry *entry) {
    fm_uint32 tc = 0;
    fm_status st;

    if (!entry ||
        switch_priority < 0 ||
        switch_priority >= NETLAB_QOS_MAX_SWITCH_PRIORITIES)
        return -1;

    st = fmGetSwitchQOS((fm_int)sw, FM_QOS_SWPRI_TC_MAP,
                        (fm_int)switch_priority, &tc);
    if (st != FM_OK)
        return -1;

    memset(entry, 0, sizeof(*entry));
    entry->switch_priority = switch_priority;
    entry->traffic_class = (int)tc;
    return 0;
}

int hal_qos_priority_map_list(int sw,
                              hal_qos_priority_map_entry *entries,
                              int max_entries) {
    int n = 0;

    if (!entries || max_entries <= 0)
        return -1;

    for (int pri = 0; pri < NETLAB_QOS_MAX_SWITCH_PRIORITIES &&
                       n < max_entries; pri++) {
        hal_qos_priority_map_entry entry;
        if (hal_qos_priority_map_get(sw, pri, &entry) != 0)
            continue;
        entries[n++] = entry;
    }
    return n;
}

int hal_qos_flow_control_global_get(int sw,
                                    hal_qos_flow_control_global *global) {
    fm_macaddr smac = 0;

    if (!global)
        return -1;

    memset(global, 0, sizeof(*global));
    global->roce_buffer_status = hal_qos_roce_buffer_ready(sw);
    for (int smp = 0; smp < 2; smp++)
        global->smp_usage[smp] = get_switch_qos_u32_attr(sw, FM_QOS_SHARED_USAGE, smp);
    global->auto_pause_mode = get_switch_qos_bool_attr(sw,
                                                       FM_AUTO_PAUSE_MODE);
    global->drop_pause = get_switch_bool_attr(sw, FM_DROP_PAUSE);
    global->pause_smac_valid =
        fmGetSwitchAttribute((fm_int)sw, FM_SWITCH_PAUSE_SMAC, &smac) == FM_OK;
    global->pause_smac = (u64)smac;

    for (int tc = 0; tc < NETLAB_QOS_MAX_TRAFFIC_CLASSES; tc++)
        global->tc_smp_map[tc] =
            get_switch_qos_u32_attr(sw, FM_QOS_TC_SMP_MAP, (fm_int)tc);

    return 0;
}

int hal_qos_flow_control_get(int sw, int port,
                             hal_qos_flow_control_entry *entry) {
    if (!entry || port <= 0 || !nl_ifid_is_user_port(port))
        return -1;

    memset(entry, 0, sizeof(*entry));
    entry->port = port;
    entry->tc3_usage = get_port_qos_u32_attr(sw, port, FM_QOS_TX_TC_USAGE, 3);
    entry->pause_state_status = NETLAB_QOS_UNSUPPORTED;
    entry->rx_class_mask_hardware = -1;
    hal_pfc_watchdog_get(sw, port, &entry->watchdog);
    entry->paused_class_mask = entry->generated_smp_pause_mask = entry->cnp_tc_usage = -1;
    for (int i = 0; i < 8; i++) entry->rx_pause_quanta[i] = -1;
    entry->rx_smp0_usage = get_port_qos_u32_attr(sw, port, FM_QOS_RX_SMP_USAGE, 0);
    entry->rx_smp1_usage = get_port_qos_u32_attr(sw, port, FM_QOS_RX_SMP_USAGE, 1);
    entry->tc3_pause_class = get_port_qos_u32_attr(sw, port, FM_QOS_TC_PC_MAP, 3);
    entry->pc3_smp = get_port_qos_u32_attr(sw, port, FM_QOS_PC_RXMP_MAP, 3);
    entry->rx_pause = get_port_bool_attr(sw, port, FM_PORT_RX_PAUSE);
    entry->rx_class_pause_mask =
        get_port_u32_attr(sw, port, FM_PORT_RX_CLASS_PAUSE);
    entry->tx_pause_mode =
        get_port_u32_attr(sw, port, FM_PORT_TX_PAUSE_MODE);
    entry->tx_class_pause_mask =
        get_port_u32_attr(sw, port, FM_PORT_TX_CLASS_PAUSE);
    entry->smp_lossless_pause_mask =
        get_port_u32_attr(sw, port, FM_PORT_SMP_LOSSLESS_PAUSE);
    entry->shared_pause_enable_mask =
        get_port_qos_u32_attr(sw, port, FM_QOS_SHARED_PAUSE_ENABLE, 0);
    entry->tx_pause_quanta =
        get_port_u32_attr(sw, port, FM_PORT_TX_PAUSE);
    entry->tx_pause_resend_time_ns =
        get_port_u32_attr(sw, port, FM_PORT_TX_PAUSE_RESEND_TIME);
    return 0;
}

int hal_qos_pause_state_get(int sw, hal_qos_flow_control_entry *entry) {
    if (!entry) return FM_ERR_INVALID_ARGUMENT;
    entry->pause_state_status = FM_ERR_INVALID_STATE;
    entry->paused_class_mask = entry->generated_smp_pause_mask = -1;
    entry->cnp_tc_usage = -1;
    entry->rx_class_mask_hardware = -1;
    for (int i = 0; i < 8; i++) entry->rx_pause_quanta[i] = -1;
    if (sw != 0 || entry->port < 1 || entry->port > 24 || !nl_ifid_is_user_port(entry->port))
        return entry->pause_state_status;
    fm_portmask mask = {{0}};
    fm_status st = fmGetLogicalPortAttribute(sw, entry->port, FM_LPORT_DEST_MASK, &mask);
    if (st != FM_OK) return entry->pause_state_status = st;
    int physical = -1;
    for (int i = 0; i < FM_PORTMASK_NUM_BITS; i++) if (FM_PORTMASK_GET_BIT(&mask, i)) {
        if (physical >= 0 || i >= 48) return entry->pause_state_status;
        physical = i;
    }
    if (physical < 0) return entry->pause_state_status;
    /* FM10000 datasheet 333497-002 sections 11.20.2.28 and .31.
     * Fixed read-only observations. Never write CM_EGRESS_PAUSE_COUNT while
     * the sweeper runs. Each 64-bit read contains four independent classes. */
    fm_uint64 quanta[2] = {0}; fm_uint32 generated = 0, pause_cfg = 0;
    st = fmReadUncachedUINT64Mult(sw, 0xE61400U + 4U * (fm_uint)physical, 2, quanta);
    if (st != FM_OK) return entry->pause_state_status = st;
    st = fmReadUncachedUINT32(sw, 0xE612C0U + (fm_uint)physical, &generated);
    if (st != FM_OK) return entry->pause_state_status = st;
    st = fmReadUncachedUINT32(sw, 0xE60800U + (fm_uint)physical, &pause_cfg);
    if (st != FM_OK) return entry->pause_state_status = st;
    entry->rx_class_mask_hardware = (int)(pause_cfg & 0xffU);
    entry->paused_class_mask = 0;
    for (int i = 0; i < 8; i++) {
        entry->rx_pause_quanta[i] = (int)((quanta[i / 4] >> (16 * (i % 4))) & 0xffffU);
        if (entry->rx_pause_quanta[i]) entry->paused_class_mask |= 1 << i;
    }
    entry->generated_smp_pause_mask = (int)(generated & 3U);
    entry->cnp_tc_usage = get_port_qos_u32_attr(sw, entry->port, FM_QOS_TX_TC_USAGE, 7);
    return entry->pause_state_status = FM_OK;
}

int hal_qos_flow_control_list(int sw,
                              hal_qos_flow_control_entry *entries,
                              int max_entries) {
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n_ports;
    int n = 0;

    if (!entries || max_entries <= 0)
        return -1;

    n_ports = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_ports && n < max_entries; i++) {
        hal_qos_flow_control_entry entry;

        if (!nl_ifid_is_user_port(ports[i].logical_port))
            continue;
        if (hal_qos_flow_control_get(sw, ports[i].logical_port, &entry) != 0)
            continue;
        entries[n++] = entry;
    }
    return n;
}

static void qos_scheduler_init(hal_qos_scheduler_entry *entry) {
    for (int tc = 0; tc < HAL_QOS_MAX_TRAFFIC_CLASSES; tc++)
        entry->tc_shaping_group_map[tc] = NETLAB_QOS_UNSUPPORTED;
    for (int group = 0; group < HAL_QOS_MAX_SCHED_GROUPS; group++) {
        entry->group_priset[group] = NETLAB_QOS_UNSUPPORTED;
        entry->group_strict[group] = NETLAB_QOS_UNSUPPORTED;
        entry->group_weight[group] = NETLAB_QOS_UNSUPPORTED;
        entry->group_tc_boundary_a[group] = NETLAB_QOS_UNSUPPORTED;
        entry->group_tc_boundary_b[group] = NETLAB_QOS_UNSUPPORTED;
        entry->group_rate_supported[group] = 0;
        entry->group_rate_default[group] = 0;
        entry->group_rate_bps[group] = 0;
        entry->group_burst_supported[group] = 0;
        entry->group_burst_bits[group] = 0;
    }
}

int hal_qos_scheduler_get(int sw, int port,
                          hal_qos_scheduler_entry *entry) {
    int groups_to_read;

    if (!entry || port <= 0 || !nl_ifid_is_user_port(port))
        return -1;

    memset(entry, 0, sizeof(*entry));
    entry->port = port;
    qos_scheduler_init(entry);

    /* Read-only SDK hook: copy the active egress scheduler into attributes. */
    (void)get_port_qos_u32_attr(sw, port, FM_QOS_RETRIEVE_ACTIVE_SCHED, 0);

    entry->num_sched_groups =
        get_port_qos_u32_attr(sw, port, FM_QOS_NUM_SCHED_GROUPS, 0);
    entry->free_bandwidth_percent =
        get_port_qos_u32_attr(sw, port, FM_QOS_QUEUE_FREE_BW, 0);
    entry->traffic_class_enable_mask =
        get_port_qos_u32_attr(sw, port, FM_QOS_TC_ENABLE, 0);
    entry->traffic_class_zero_length_mask =
        get_port_qos_u32_attr(sw, port, FM_QOS_TC_ZERO_LENGTH, 0);

    for (int tc = 0; tc < HAL_QOS_MAX_TRAFFIC_CLASSES; tc++) {
        entry->tc_shaping_group_map[tc] =
            get_port_qos_u32_attr(sw, port, FM_QOS_TC_SHAPING_GROUP_MAP,
                                  (fm_int)tc);
    }

    groups_to_read = entry->num_sched_groups;
    if (groups_to_read <= 0 || groups_to_read > HAL_QOS_MAX_SCHED_GROUPS)
        groups_to_read = HAL_QOS_MAX_SCHED_GROUPS;

    for (int group = 0; group < groups_to_read; group++) {
        u64 value = 0;

        entry->group_priset[group] =
            get_port_qos_u32_attr(sw, port, FM_QOS_SCHED_GROUP_PRISET_NUM,
                                  (fm_int)group);
        entry->group_strict[group] =
            get_port_qos_u32_attr(sw, port, FM_QOS_SCHED_GROUP_STRICT,
                                  (fm_int)group);
        entry->group_weight[group] =
            get_port_qos_u32_attr(sw, port, FM_QOS_SCHED_GROUP_WEIGHT,
                                  (fm_int)group);
        entry->group_tc_boundary_a[group] =
            get_port_qos_u32_attr(sw, port,
                                  FM_QOS_SCHED_GROUP_TCBOUNDARY_A,
                                  (fm_int)group);
        entry->group_tc_boundary_b[group] =
            get_port_qos_u32_attr(sw, port,
                                  FM_QOS_SCHED_GROUP_TCBOUNDARY_B,
                                  (fm_int)group);

        if (get_port_qos_u64_attr(sw, port, FM_QOS_SHAPING_GROUP_RATE,
                                  (fm_int)group, &value) == 0) {
            entry->group_rate_supported[group] = 1;
            entry->group_rate_bps[group] = value;
            entry->group_rate_default[group] =
                value == (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT;
        }
        if (get_port_qos_u64_attr(sw, port, FM_QOS_SHAPING_GROUP_MAX_BURST,
                                  (fm_int)group, &value) == 0) {
            entry->group_burst_supported[group] = 1;
            entry->group_burst_bits[group] = value;
        }
    }

    return 0;
}

int hal_qos_scheduler_list(int sw,
                           hal_qos_scheduler_entry *entries,
                           int max_entries) {
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n_ports;
    int n = 0;

    if (!entries || max_entries <= 0)
        return -1;

    n_ports = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_ports && n < max_entries; i++) {
        hal_qos_scheduler_entry entry;

        if (!nl_ifid_is_user_port(ports[i].logical_port))
            continue;
        if (hal_qos_scheduler_get(sw, ports[i].logical_port, &entry) != 0)
            continue;
        entries[n++] = entry;
    }
    return n;
}

int hal_qos_scheduler_tc_map_set(int sw, int port, int traffic_class,
                                 int shaping_group) {
    fm_uint32 group = (fm_uint32)shaping_group;
    fm_status st;

    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        traffic_class < 0 ||
        traffic_class >= HAL_QOS_MAX_TRAFFIC_CLASSES ||
        shaping_group < 0 ||
        shaping_group >= HAL_QOS_MAX_SCHED_GROUPS)
        return -1;

    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_TC_SHAPING_GROUP_MAP,
                      (fm_int)traffic_class, &group);
    if (st != FM_OK) {
        NL_LOG_ERR("qos scheduler port=%d tc=%d shaping-group=%d failed: %s",
                   port, traffic_class, shaping_group, fmErrorMsg(st));
        return (int)st;
    }

    NL_LOG_INFO("qos scheduler port=%d tc=%d shaping-group=%d",
                port, traffic_class, shaping_group);
    return 0;
}

int hal_qos_scheduler_tc_map_delete(int sw, int port, int traffic_class) {
    return hal_qos_scheduler_tc_map_set(sw, port, traffic_class, 0);
}

int hal_qos_scheduler_tc_map_get(int sw, int port, int traffic_class,
                                 int *shaping_group) {
    fm_uint32 group = 0;
    fm_status st;

    if (!shaping_group || port <= 0 || !nl_ifid_is_user_port(port) ||
        traffic_class < 0 ||
        traffic_class >= HAL_QOS_MAX_TRAFFIC_CLASSES)
        return -1;

    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_TC_SHAPING_GROUP_MAP,
                      (fm_int)traffic_class, &group);
    if (st != FM_OK)
        return (int)st;

    *shaping_group = (int)group;
    return 0;
}

static int qos_scheduler_group_count(const hal_qos_scheduler_entry *entry) {
    if (!entry ||
        entry->num_sched_groups <= 0 ||
        entry->num_sched_groups > HAL_QOS_MAX_SCHED_GROUPS)
        return HAL_QOS_MAX_SCHED_GROUPS;
    return entry->num_sched_groups;
}

static int qos_scheduler_apply_group_config(
    int sw, int port, const hal_qos_scheduler_entry *entry,
    int groups_to_apply) {
    fm_status st;
    fm_uint32 value;

    if (!entry || port <= 0 || !nl_ifid_is_user_port(port) ||
        groups_to_apply <= 0 ||
        groups_to_apply > HAL_QOS_MAX_SCHED_GROUPS)
        return -1;

    value = (fm_uint32)groups_to_apply;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_NUM_SCHED_GROUPS, 0, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("qos scheduler port=%d set groups=%d failed: %s",
                   port, groups_to_apply, fmErrorMsg(st));
        return (int)st;
    }

    for (int group = 0; group < groups_to_apply; group++) {
        int boundary_a = entry->group_tc_boundary_a[group];
        int boundary_b = entry->group_tc_boundary_b[group];
        int strict = entry->group_strict[group];
        int weight = entry->group_weight[group];

        if (boundary_a < 0 || boundary_a >= HAL_QOS_MAX_TRAFFIC_CLASSES)
            boundary_a = group < HAL_QOS_MAX_TRAFFIC_CLASSES ? group : 0;
        if (boundary_b < 0 || boundary_b >= HAL_QOS_MAX_TRAFFIC_CLASSES)
            boundary_b = boundary_a;
        if (strict < 0)
            strict = 1;
        if (weight < 0)
            weight = 0;

        value = (fm_uint32)boundary_a;
        st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                          FM_QOS_SCHED_GROUP_TCBOUNDARY_A,
                          (fm_int)group, &value);
        if (st != FM_OK)
            return (int)st;
        value = (fm_uint32)boundary_b;
        st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                          FM_QOS_SCHED_GROUP_TCBOUNDARY_B,
                          (fm_int)group, &value);
        if (st != FM_OK)
            return (int)st;
        value = (fm_uint32)strict;
        st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                          FM_QOS_SCHED_GROUP_STRICT,
                          (fm_int)group, &value);
        if (st != FM_OK)
            return (int)st;
        value = (fm_uint32)weight;
        st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                          FM_QOS_SCHED_GROUP_WEIGHT,
                          (fm_int)group, &value);
        if (st != FM_OK)
            return (int)st;
    }

    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_APPLY_NEW_SCHED, 0, NULL);
    if (st != FM_OK) {
        NL_LOG_ERR("qos scheduler port=%d apply failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }
    return 0;
}

int hal_qos_scheduler_group_set(int sw, int port, int group,
                                int strict_priority, int weight) {
    hal_qos_scheduler_entry entry;
    int groups_to_apply;
    int rc;

    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        group < 0 || group >= HAL_QOS_MAX_SCHED_GROUPS ||
        (strict_priority != 0 && strict_priority != 1) ||
        weight < 0 || weight > 0xffffff)
        return -1;

    rc = hal_qos_scheduler_get(sw, port, &entry);
    if (rc != 0)
        return rc;

    groups_to_apply = qos_scheduler_group_count(&entry);
    if (group >= groups_to_apply) {
        NL_LOG_ERR("qos scheduler port=%d group=%d exceeds active groups=%d",
                   port, group, groups_to_apply);
        return -1;
    }

    entry.group_strict[group] = strict_priority;
    entry.group_weight[group] = weight;

    rc = qos_scheduler_apply_group_config(sw, port, &entry,
                                          groups_to_apply);
    if (rc != 0)
        return rc;

    NL_LOG_INFO("qos scheduler port=%d group=%d strict=%d weight=%d",
                port, group, strict_priority, weight);
    return 0;
}

int hal_qos_scheduler_group_delete(int sw, int port, int group) {
    return hal_qos_scheduler_group_set(sw, port, group, 1, 0);
}

int hal_qos_scheduler_group_get(int sw, int port, int group,
                                int *strict_priority, int *weight) {
    hal_qos_scheduler_entry entry;
    int groups_to_read;
    int rc;

    if (!strict_priority || !weight ||
        port <= 0 || !nl_ifid_is_user_port(port) ||
        group < 0 || group >= HAL_QOS_MAX_SCHED_GROUPS)
        return -1;

    rc = hal_qos_scheduler_get(sw, port, &entry);
    if (rc != 0)
        return rc;
    groups_to_read = qos_scheduler_group_count(&entry);
    if (group >= groups_to_read ||
        entry.group_strict[group] < 0 ||
        entry.group_weight[group] < 0)
        return -1;

    *strict_priority = entry.group_strict[group];
    *weight = entry.group_weight[group];
    return 0;
}

static hal_qos_scheduler_topology_transaction_snapshot
qos_scheduler_topology_transaction_read_error(fm_status status) {
    hal_qos_scheduler_topology_transaction_snapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = (int)status;
    return snapshot;
}

hal_qos_scheduler_topology_transaction_snapshot
hal_qos_scheduler_topology_transaction_snapshot_get(int sw, int port) {
    hal_qos_scheduler_topology_transaction_snapshot snapshot;
    fm_uint32 value = 0;
    fm_status st;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    if (port <= 0 || !nl_ifid_is_user_port(port))
        return snapshot;

    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_RETRIEVE_ACTIVE_SCHED, 0, &value);
    if (st != FM_OK)
        return qos_scheduler_topology_transaction_read_error(st);
    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_NUM_SCHED_GROUPS, 0, &value);
    if (st != FM_OK)
        return qos_scheduler_topology_transaction_read_error(st);
    if (value == 0 ||
        value > HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
        return qos_scheduler_topology_transaction_read_error(
            FM_ERR_INVALID_ACTIVE_ESCHED_CONFIG);
    snapshot.num_groups = (u32)value;

    for (u32 group = 0; group < snapshot.num_groups; group++) {
        hal_qos_scheduler_group_transaction_state *out =
            &snapshot.groups[group];

        st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                          FM_QOS_SCHED_GROUP_STRICT,
                          (fm_int)group, &out->strict_priority);
        if (st != FM_OK)
            return qos_scheduler_topology_transaction_read_error(st);
        st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                          FM_QOS_SCHED_GROUP_WEIGHT,
                          (fm_int)group, &out->weight);
        if (st != FM_OK)
            return qos_scheduler_topology_transaction_read_error(st);
        st = fmGetPortQOS(
            (fm_int)sw, (fm_int)port,
            FM_QOS_SCHED_GROUP_TCBOUNDARY_A,
            (fm_int)group, &out->traffic_class_boundary_a);
        if (st != FM_OK)
            return qos_scheduler_topology_transaction_read_error(st);
        st = fmGetPortQOS(
            (fm_int)sw, (fm_int)port,
            FM_QOS_SCHED_GROUP_TCBOUNDARY_B,
            (fm_int)group, &out->traffic_class_boundary_b);
        if (st != FM_OK)
            return qos_scheduler_topology_transaction_read_error(st);
    }

    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    return snapshot;
}

static bool qos_scheduler_topology_transaction_snapshots_equal(
    const hal_qos_scheduler_topology_transaction_snapshot *left,
    const hal_qos_scheduler_topology_transaction_snapshot *right) {
    if (!left || !right ||
        left->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        right->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        left->num_groups != right->num_groups)
        return false;
    return memcmp(left->groups, right->groups,
                  (size_t)left->num_groups *
                  sizeof(left->groups[0])) == 0;
}

int hal_qos_scheduler_topology_transaction_restore(
    int sw, int port,
    const hal_qos_scheduler_topology_transaction_snapshot *snapshot) {
    hal_qos_scheduler_topology_transaction_snapshot readback;
    fm_uint32 value;
    fm_status st;

    if (!snapshot ||
        snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        snapshot->num_groups == 0 ||
        snapshot->num_groups >
            HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS ||
        port <= 0 || !nl_ifid_is_user_port(port))
        return FM_ERR_INVALID_ARGUMENT;

    /*
     * Reset the SDK's staging topology from active state before replacing all
     * fields.  This prevents residue from a failed earlier APPLY_NEW_SCHED
     * attempt from becoming part of the rollback image.
     */
    value = 0;
    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_RETRIEVE_ACTIVE_SCHED, 0, &value);
    if (st != FM_OK)
        return (int)st;
    value = (fm_uint32)snapshot->num_groups;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_NUM_SCHED_GROUPS, 0, &value);
    if (st != FM_OK)
        return (int)st;

    for (u32 group = 0; group < snapshot->num_groups; group++) {
        const hal_qos_scheduler_group_transaction_state *saved =
            &snapshot->groups[group];

        value = (fm_uint32)saved->traffic_class_boundary_a;
        st = fmSetPortQOS(
            (fm_int)sw, (fm_int)port,
            FM_QOS_SCHED_GROUP_TCBOUNDARY_A,
            (fm_int)group, &value);
        if (st != FM_OK)
            return (int)st;
        value = (fm_uint32)saved->traffic_class_boundary_b;
        st = fmSetPortQOS(
            (fm_int)sw, (fm_int)port,
            FM_QOS_SCHED_GROUP_TCBOUNDARY_B,
            (fm_int)group, &value);
        if (st != FM_OK)
            return (int)st;
        value = (fm_uint32)saved->strict_priority;
        st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                          FM_QOS_SCHED_GROUP_STRICT,
                          (fm_int)group, &value);
        if (st != FM_OK)
            return (int)st;
        value = (fm_uint32)saved->weight;
        st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                          FM_QOS_SCHED_GROUP_WEIGHT,
                          (fm_int)group, &value);
        if (st != FM_OK)
            return (int)st;
    }

    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_APPLY_NEW_SCHED, 0, NULL);
    if (st != FM_OK)
        return (int)st;

    readback = hal_qos_scheduler_topology_transaction_snapshot_get(
        sw, port);
    if (readback.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return readback.sdk_status != FM_OK ?
               readback.sdk_status : FM_ERR_INVALID_STATE;
    return qos_scheduler_topology_transaction_snapshots_equal(
               snapshot, &readback) ?
           0 : FM_ERR_INVALID_STATE;
}

#define NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS 67100672ULL

static bool qos_scheduler_group_shaping_is_default(
    u64 rate_bps, u64 burst_bits) {
    return rate_bps == (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT &&
           burst_bits == NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS;
}

static hal_qos_scheduler_group_shaping_transaction_snapshot
qos_scheduler_group_shaping_transaction_read_error(fm_status status) {
    hal_qos_scheduler_group_shaping_transaction_snapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = (int)status;
    return snapshot;
}

hal_qos_scheduler_group_shaping_transaction_snapshot
hal_qos_scheduler_group_shaping_transaction_snapshot_get(
    int sw, int port, int group) {
    hal_qos_scheduler_group_shaping_transaction_snapshot snapshot;
    fm_uint64 rate = 0;
    fm_uint64 burst = 0;
    fm_status st;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        group < 0 || group >= HAL_QOS_MAX_SCHED_GROUPS)
        return snapshot;

    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      (fm_int)group, &rate);
    if (st != FM_OK)
        return qos_scheduler_group_shaping_transaction_read_error(st);
    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_MAX_BURST,
                      (fm_int)group, &burst);
    if (st != FM_OK)
        return qos_scheduler_group_shaping_transaction_read_error(st);

    snapshot.raw_rate_bps = (u64)rate;
    snapshot.raw_burst_bits = (u64)burst;
    snapshot.state = qos_scheduler_group_shaping_is_default(
                         snapshot.raw_rate_bps,
                         snapshot.raw_burst_bits) ?
                     HAL_TRANSACTION_SNAPSHOT_ABSENT :
                     HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    return snapshot;
}

static bool qos_scheduler_group_shaping_transaction_snapshots_equal(
    const hal_qos_scheduler_group_shaping_transaction_snapshot *left,
    const hal_qos_scheduler_group_shaping_transaction_snapshot *right) {
    return left && right &&
           left->state == right->state &&
           left->state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           left->raw_rate_bps == right->raw_rate_bps &&
           left->raw_burst_bits == right->raw_burst_bits;
}

int hal_qos_scheduler_group_shaping_transaction_restore(
    int sw, int port, int group,
    const hal_qos_scheduler_group_shaping_transaction_snapshot *snapshot) {
    hal_qos_scheduler_group_shaping_transaction_snapshot readback;
    fm_uint64 value;
    bool raw_is_default;
    fm_status st;

    if (!snapshot ||
        (snapshot->state != HAL_TRANSACTION_SNAPSHOT_ABSENT &&
         snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT) ||
        port <= 0 || !nl_ifid_is_user_port(port) ||
        group < 0 || group >= HAL_QOS_MAX_SCHED_GROUPS)
        return FM_ERR_INVALID_ARGUMENT;

    raw_is_default = qos_scheduler_group_shaping_is_default(
        snapshot->raw_rate_bps, snapshot->raw_burst_bits);
    if ((snapshot->state == HAL_TRANSACTION_SNAPSHOT_ABSENT) !=
        raw_is_default)
        return FM_ERR_INVALID_ARGUMENT;

    value = (fm_uint64)snapshot->raw_burst_bits;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_MAX_BURST,
                      (fm_int)group, &value);
    if (st != FM_OK)
        return (int)st;
    value = (fm_uint64)snapshot->raw_rate_bps;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      (fm_int)group, &value);
    if (st != FM_OK)
        return (int)st;

    readback = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        sw, port, group);
    if (readback.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return readback.sdk_status != FM_OK ?
               readback.sdk_status : FM_ERR_INVALID_STATE;
    return qos_scheduler_group_shaping_transaction_snapshots_equal(
               snapshot, &readback) ?
           0 : FM_ERR_INVALID_STATE;
}

int hal_qos_scheduler_group_shaping_set(int sw, int port, int group,
                                        u64 rate_bps, u64 burst_bits) {
    fm_uint64 value;
    fm_status st;

    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        group < 0 || group >= HAL_QOS_MAX_SCHED_GROUPS ||
        rate_bps < 1 || rate_bps > 100000000000ULL ||
        burst_bits < 1 || burst_bits > NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS)
        return -1;

    value = (fm_uint64)burst_bits;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_MAX_BURST,
                      (fm_int)group, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("qos scheduler port=%d group=%d set burst=%llu bits failed: %s",
                   port, group, (unsigned long long)burst_bits,
                   fmErrorMsg(st));
        return (int)st;
    }

    value = (fm_uint64)rate_bps;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      (fm_int)group, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("qos scheduler port=%d group=%d set rate=%llu bps failed: %s",
                   port, group, (unsigned long long)rate_bps,
                   fmErrorMsg(st));
        return (int)st;
    }

    NL_LOG_INFO("qos scheduler port=%d group=%d rate=%llu bps burst=%llu bits",
                port, group, (unsigned long long)rate_bps,
                (unsigned long long)burst_bits);
    return 0;
}

int hal_qos_scheduler_group_shaping_delete(int sw, int port, int group) {
    fm_uint64 rate_bps = FM_QOS_SHAPING_GROUP_RATE_DEFAULT;
    fm_uint64 burst_bits = NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS;
    fm_status st;

    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        group < 0 || group >= HAL_QOS_MAX_SCHED_GROUPS)
        return -1;

    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_MAX_BURST,
                      (fm_int)group, &burst_bits);
    if (st != FM_OK)
        return (int)st;

    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHAPING_GROUP_RATE,
                      (fm_int)group, &rate_bps);
    if (st != FM_OK) {
        NL_LOG_ERR("qos scheduler port=%d group=%d delete shaping failed: %s",
                   port, group, fmErrorMsg(st));
        return (int)st;
    }
    return 0;
}

int hal_qos_scheduler_group_shaping_get(int sw, int port, int group,
                                        u64 *rate_bps, u64 *burst_bits) {
    bool present = false;
    int rc = hal_qos_scheduler_group_shaping_snapshot(
        sw, port, group, &present, rate_bps, burst_bits);

    return rc == 0 && present ? 0 : -1;
}

int hal_qos_scheduler_group_shaping_snapshot(
    int sw, int port, int group, bool *present,
    u64 *rate_bps, u64 *burst_bits) {
    hal_qos_scheduler_group_shaping_transaction_snapshot snapshot;

    if (!present || !rate_bps || !burst_bits ||
        port <= 0 || !nl_ifid_is_user_port(port) ||
        group < 0 || group >= HAL_QOS_MAX_SCHED_GROUPS)
        return -1;
    *present = false;

    snapshot = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        sw, port, group);
    if (snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return snapshot.sdk_status != FM_OK ?
               snapshot.sdk_status : FM_ERR_INVALID_STATE;

    *rate_bps = snapshot.raw_rate_bps;
    *burst_bits = snapshot.raw_burst_bits;
    *present = snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT;
    return 0;
}

static int qos_scheduler_port_raw_set(
    int sw, int port, u32 traffic_class_enable_mask) {
    fm_uint32 value;
    fm_status st;

    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        traffic_class_enable_mask > 0xffU)
        return FM_ERR_INVALID_ARGUMENT;

    value = (fm_uint32)traffic_class_enable_mask;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_TC_ENABLE, 0, &value);
    return st == FM_OK ? 0 : (int)st;
}

int hal_qos_scheduler_port_set(int sw, int port,
                               int traffic_class_enable_mask) {
    int rc;

    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        traffic_class_enable_mask < 1 ||
        traffic_class_enable_mask > 0xff)
        return -1;

    rc = qos_scheduler_port_raw_set(
        sw, port, (u32)traffic_class_enable_mask);
    if (rc != 0) {
        NL_LOG_ERR("qos scheduler port=%d set tc-enable-mask=0x%02x failed: %s",
                   port, traffic_class_enable_mask, fmErrorMsg(rc));
        return rc;
    }

    NL_LOG_INFO("qos scheduler port=%d tc-enable-mask=0x%02x",
                port, traffic_class_enable_mask);
    return 0;
}

int hal_qos_scheduler_port_delete(int sw, int port) {
    return hal_qos_scheduler_port_set(sw, port, 0xff);
}

int hal_qos_scheduler_port_get(int sw, int port,
                               int *traffic_class_enable_mask) {
    int mask;

    if (!traffic_class_enable_mask ||
        port <= 0 || !nl_ifid_is_user_port(port))
        return -1;

    mask = get_port_qos_u32_attr(sw, port, FM_QOS_TC_ENABLE, 0);
    if (mask < 0 || mask > 0xff)
        return -1;

    *traffic_class_enable_mask = mask;
    return 0;
}

int hal_qos_scheduler_port_transaction_restore(
    int sw, int port, u32 traffic_class_enable_mask) {
    fm_uint32 readback = 0;
    fm_status st;
    int rc;

    if (traffic_class_enable_mask > 0xffU)
        return FM_ERR_INVALID_ARGUMENT;

    rc = qos_scheduler_port_raw_set(
        sw, port, traffic_class_enable_mask);
    if (rc != 0)
        return rc;

    st = fmGetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_TC_ENABLE, 0, &readback);
    if (st != FM_OK)
        return (int)st;
    if (readback > 0xffU ||
        readback != (fm_uint32)traffic_class_enable_mask)
        return FM_ERR_INVALID_STATE;
    return 0;
}

int hal_qos_queue_get(int sw, int port, int queue_id,
                      hal_qos_queue_entry *entry) {
    fm_uint32 tc = 0;
    fm_uint32 min_bw = 0;
    fm_uint32 max_bw = 0;
    fm_status st;

    if (!entry || port <= 0 || !nl_ifid_is_user_port(port) ||
        queue_id < 0 || queue_id >= HAL_QOS_MAX_TRAFFIC_CLASSES)
        return -1;

    memset(entry, 0, sizeof(*entry));
    entry->port = port;
    entry->queue_id = queue_id;
    entry->traffic_class = NETLAB_QOS_UNSUPPORTED;

    st = fmGetAttributeQueueQOS((fm_int)sw, (fm_int)port,
                                (fm_int)queue_id,
                                FM_QOS_QUEUE_TRAFFIC_CLASS, &tc);
    entry->sdk_status = (int)st;
    if (st != FM_OK)
        return 0;

    entry->present = 1;
    entry->traffic_class = (int)tc;

    st = fmGetAttributeQueueQOS((fm_int)sw, (fm_int)port,
                                (fm_int)queue_id,
                                FM_QOS_QUEUE_MIN_BW, &min_bw);
    if (st != FM_OK) {
        entry->sdk_status = (int)st;
        entry->present = 0;
        return 0;
    }

    st = fmGetAttributeQueueQOS((fm_int)sw, (fm_int)port,
                                (fm_int)queue_id,
                                FM_QOS_QUEUE_MAX_BW, &max_bw);
    if (st != FM_OK) {
        entry->sdk_status = (int)st;
        entry->present = 0;
        return 0;
    }

    entry->sdk_status = 0;
    entry->min_bw_mbps = (u64)min_bw;
    entry->max_bw_mbps = (u64)max_bw;
    entry->max_bw_default =
        max_bw == (fm_uint32)FM_QOS_QUEUE_MAX_BW_DEFAULT;
    return 0;
}

int hal_qos_queue_list(int sw, hal_qos_queue_entry *entries,
                       int max_entries) {
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n_ports;
    int n = 0;

    if (!entries || max_entries <= 0)
        return -1;

    n_ports = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_ports && n < max_entries; i++) {
        if (!nl_ifid_is_user_port(ports[i].logical_port))
            continue;
        for (int queue = 0;
             queue < HAL_QOS_MAX_TRAFFIC_CLASSES && n < max_entries;
             queue++) {
            hal_qos_queue_entry entry;

            if (hal_qos_queue_get(sw, ports[i].logical_port,
                                  queue, &entry) != 0)
                continue;
            entries[n++] = entry;
        }
    }
    return n;
}

static bool qos_queue_missing_status_ok(fm_status st) {
    return st == FM_OK ||
           st == FM_ERR_NOT_FOUND ||
           st == FM_ERR_INVALID_VALUE ||
           st == FM_ERR_INVALID_ARGUMENT;
}

static void qos_queue_record_cleanup(hal_qos_queue_probe_result *result,
                                     fm_status st) {
    if (!result || result->cleanup_status != 0 ||
        qos_queue_missing_status_ok(st))
        return;
    result->cleanup_status = (int)st;
}

static fm_uint32 qos_queue_max_arg(const hal_qos_queue_probe_args *args) {
    if (!args || args->max_bw_default)
        return (fm_uint32)FM_QOS_QUEUE_MAX_BW_DEFAULT;
    return (fm_uint32)args->max_bw_mbps;
}

typedef struct {
    bool active;
    hal_qos_queue_owner_args args;
} qos_queue_owner_state;

static qos_queue_owner_state g_qos_queue_owner;

typedef struct {
    bool active;
    hal_qos_queue_profile_owner_args args;
} qos_queue_profile_owner_state;

static qos_queue_profile_owner_state g_qos_queue_profile_owner;

static bool qos_queue_args_valid(const hal_qos_queue_owner_args *args) {
    return args &&
           args->port > 0 &&
           nl_ifid_is_user_port(args->port) &&
           args->queue_id >= 0 &&
           args->queue_id < HAL_QOS_MAX_TRAFFIC_CLASSES &&
           args->traffic_class >= 0 &&
           args->traffic_class < HAL_QOS_MAX_TRAFFIC_CLASSES &&
           args->min_bw_mbps <= 100000ULL &&
           (args->max_bw_default ||
            (args->max_bw_mbps >= 1ULL &&
             args->max_bw_mbps <= 100000ULL &&
             args->max_bw_mbps >= args->min_bw_mbps));
}

static void qos_queue_owner_init_result(
    hal_qos_queue_owner_result *result,
    const hal_qos_queue_owner_args *args) {
    if (!result)
        return;
    memset(result, 0, sizeof(*result));
    if (args) {
        result->port = args->port;
        result->queue_id = args->queue_id;
        result->traffic_class = args->traffic_class;
        result->min_bw_mbps = args->min_bw_mbps;
        result->max_bw_mbps = args->max_bw_mbps;
        result->max_bw_default = args->max_bw_default ? 1 : 0;
    }
    snprintf(result->detail, sizeof(result->detail), "not-run");
}

static int qos_queue_owner_compare(
    const hal_qos_queue_owner_args *expected,
    const hal_qos_queue_entry *actual,
    hal_qos_queue_owner_result *result) {
    int mismatches = 0;

    if (!expected || !actual || !result)
        return -1;

    result->read_status = actual->sdk_status;
    result->compared = 4;
    if (!actual->present) {
        mismatches++;
    } else {
        if (actual->traffic_class != expected->traffic_class)
            mismatches++;
        if (actual->min_bw_mbps != expected->min_bw_mbps)
            mismatches++;
        if (expected->max_bw_default) {
            if (!actual->max_bw_default)
                mismatches++;
        } else if (actual->max_bw_mbps != expected->max_bw_mbps) {
            mismatches++;
        }
    }
    result->mismatches = mismatches;
    return mismatches == 0 ? 0 : -1;
}

int hal_qos_queue_owner_apply(int sw,
                              const hal_qos_queue_owner_args *args,
                              hal_qos_queue_owner_result *result) {
    hal_qos_queue_entry entry;
    fm_qosQueueParam param;
    fm_uint32 value;
    fm_status st;

    qos_queue_owner_init_result(result, args);
    if (!args || !result)
        return -1;
    if (!qos_queue_args_valid(args)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid queue owner arguments");
        return -1;
    }
    if (g_qos_queue_owner.active) {
        result->active = true;
        snprintf(result->detail, sizeof(result->detail),
                 "queue owner already active");
        return -1;
    }

    memset(&entry, 0, sizeof(entry));
    if (hal_qos_queue_get(sw, args->port, args->queue_id, &entry) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "pre-read failed");
        return -1;
    }
    result->pre_status = entry.sdk_status;
    result->pre_present = entry.present ? 1 : 0;
    if (entry.present) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue already present; refusing to overwrite");
        return -1;
    }

    memset(&param, 0, sizeof(param));
    param.queueId = (fm_int)args->queue_id;
    param.tc = (fm_int)args->traffic_class;
    param.minBw = (fm_uint32)args->min_bw_mbps;
    param.maxBw = qos_queue_max_arg(args);

    st = fmAddQueueQOS((fm_int)sw, (fm_int)args->port, &param);
    result->add_status = (int)st;
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue add failed: %s", fmErrorMsg(st));
        return (int)st;
    }

    value = (fm_uint32)args->traffic_class;
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)args->port,
                                (fm_int)args->queue_id,
                                FM_QOS_QUEUE_TRAFFIC_CLASS, &value);
    result->set_tc_status = (int)st;
    if (st != FM_OK)
        goto fail_cleanup;

    value = (fm_uint32)args->min_bw_mbps;
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)args->port,
                                (fm_int)args->queue_id,
                                FM_QOS_QUEUE_MIN_BW, &value);
    result->set_min_status = (int)st;
    if (st != FM_OK)
        goto fail_cleanup;

    value = qos_queue_max_arg(args);
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)args->port,
                                (fm_int)args->queue_id,
                                FM_QOS_QUEUE_MAX_BW, &value);
    result->set_max_status = (int)st;
    if (st != FM_OK)
        goto fail_cleanup;

    memset(&entry, 0, sizeof(entry));
    if (hal_qos_queue_get(sw, args->port, args->queue_id, &entry) != 0) {
        result->read_status = -1;
        st = FM_ERR_INVALID_VALUE;
        goto fail_cleanup;
    }
    if (qos_queue_owner_compare(args, &entry, result) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue owner read-back mismatch");
        st = FM_ERR_INVALID_VALUE;
        goto fail_cleanup;
    }

    g_qos_queue_owner.active = true;
    g_qos_queue_owner.args = *args;
    result->active = true;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS queue owner applied and verified");
    return 0;

fail_cleanup:
    if (strcmp(result->detail, "not-run") == 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue owner apply failed: %s", fmErrorMsg(st));
    }
    st = fmDeleteQueueQOS((fm_int)sw, (fm_int)args->port,
                          (fm_int)args->queue_id);
    result->rollback_status = (int)st;
    return (int)(st == FM_OK ? FM_ERR_INVALID_VALUE : st);
}

int hal_qos_queue_owner_readback(int sw,
                                 hal_qos_queue_owner_result *result) {
    hal_qos_queue_entry entry;
    const hal_qos_queue_owner_args *args;

    args = g_qos_queue_owner.active ? &g_qos_queue_owner.args : NULL;
    qos_queue_owner_init_result(result, args);
    if (!result)
        return -1;
    if (!g_qos_queue_owner.active) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no active queue owner");
        return 0;
    }

    result->active = true;
    memset(&entry, 0, sizeof(entry));
    if (hal_qos_queue_get(sw, args->port, args->queue_id, &entry) != 0) {
        result->read_status = -1;
        snprintf(result->detail, sizeof(result->detail),
                 "queue owner read-back failed");
        return -1;
    }
    if (qos_queue_owner_compare(args, &entry, result) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue owner read-back mismatch");
        return -1;
    }

    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS queue owner read-back verified");
    return 0;
}

int hal_qos_queue_owner_rollback(int sw,
                                 hal_qos_queue_owner_result *result) {
    hal_qos_queue_entry entry;
    hal_qos_queue_owner_args args;
    fm_status st;

    if (g_qos_queue_owner.active)
        args = g_qos_queue_owner.args;
    else
        memset(&args, 0, sizeof(args));
    qos_queue_owner_init_result(result,
                                g_qos_queue_owner.active ? &args : NULL);
    if (!result)
        return -1;
    if (!g_qos_queue_owner.active) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no active queue owner");
        return 0;
    }

    result->active = true;
    st = fmDeleteQueueQOS((fm_int)sw, (fm_int)args.port,
                          (fm_int)args.queue_id);
    result->rollback_status = (int)st;
    if (st != FM_OK && !qos_queue_missing_status_ok(st)) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue owner rollback failed: %s", fmErrorMsg(st));
        return (int)st;
    }

    memset(&entry, 0, sizeof(entry));
    if (hal_qos_queue_get(sw, args.port, args.queue_id, &entry) != 0) {
        result->post_read_status = -1;
        snprintf(result->detail, sizeof(result->detail),
                 "post-rollback read failed");
        return -1;
    }
    result->post_read_status = entry.sdk_status;
    result->post_present = entry.present ? 1 : 0;
    if (entry.present) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue still present after rollback");
        return -1;
    }

    g_qos_queue_owner.active = false;
    memset(&g_qos_queue_owner.args, 0, sizeof(g_qos_queue_owner.args));
    result->active = false;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS queue owner rolled back and verified absent");
    return 0;
}

static fm_uint32 qos_queue_profile_max_arg(
    const hal_qos_queue_profile_item *item) {
    if (!item || item->max_bw_default)
        return (fm_uint32)FM_QOS_QUEUE_MAX_BW_DEFAULT;
    return (fm_uint32)item->max_bw_mbps;
}

static bool qos_queue_profile_item_valid(
    const hal_qos_queue_profile_item *item) {
    return item &&
           item->queue_id >= 0 &&
           item->queue_id < HAL_QOS_MAX_TRAFFIC_CLASSES &&
           item->traffic_class >= 0 &&
           item->traffic_class < HAL_QOS_MAX_TRAFFIC_CLASSES &&
           item->min_bw_mbps <= 100000ULL &&
           (item->max_bw_default ||
            (item->max_bw_mbps >= 1ULL &&
             item->max_bw_mbps <= 100000ULL &&
             item->max_bw_mbps >= item->min_bw_mbps));
}

static bool qos_queue_profile_args_valid(
    const hal_qos_queue_profile_owner_args *args) {
    bool seen[HAL_QOS_MAX_TRAFFIC_CLASSES] = {false};

    if (!args ||
        args->port <= 0 ||
        !nl_ifid_is_user_port(args->port) ||
        args->queue_count <= 0 ||
        args->queue_count > HAL_QOS_QUEUE_PROFILE_MAX_QUEUES)
        return false;
    for (int i = 0; i < args->queue_count; i++) {
        int queue_id = args->queue[i].queue_id;

        if (!qos_queue_profile_item_valid(&args->queue[i]))
            return false;
        if (seen[queue_id])
            return false;
        seen[queue_id] = true;
    }
    return true;
}

static void qos_queue_profile_owner_init_result(
    hal_qos_queue_profile_owner_result *result,
    const hal_qos_queue_profile_owner_args *args) {
    if (!result)
        return;
    memset(result, 0, sizeof(*result));
    if (args) {
        result->port = args->port;
        result->queue_count = args->queue_count;
        for (int i = 0; i < args->queue_count &&
             i < HAL_QOS_QUEUE_PROFILE_MAX_QUEUES; i++) {
            result->queue[i].queue_id = args->queue[i].queue_id;
            result->queue[i].traffic_class = args->queue[i].traffic_class;
            result->queue[i].min_bw_mbps = args->queue[i].min_bw_mbps;
            result->queue[i].max_bw_mbps = args->queue[i].max_bw_mbps;
            result->queue[i].max_bw_default =
                args->queue[i].max_bw_default ? 1 : 0;
        }
    }
    snprintf(result->detail, sizeof(result->detail), "not-run");
}

static int qos_queue_profile_compare_item(
    const hal_qos_queue_profile_item *expected,
    const hal_qos_queue_entry *actual,
    hal_qos_queue_profile_item_result *item_result) {
    int mismatches = 0;

    if (!expected || !actual || !item_result)
        return -1;

    item_result->read_status = actual->sdk_status;
    item_result->compared = 4;
    if (!actual->present) {
        mismatches++;
    } else {
        if (actual->traffic_class != expected->traffic_class)
            mismatches++;
        if (actual->min_bw_mbps != expected->min_bw_mbps)
            mismatches++;
        if (expected->max_bw_default) {
            if (!actual->max_bw_default)
                mismatches++;
        } else if (actual->max_bw_mbps != expected->max_bw_mbps) {
            mismatches++;
        }
    }
    item_result->mismatches = mismatches;
    return mismatches == 0 ? 0 : -1;
}

static int qos_queue_profile_apply_one(
    int sw,
    int port,
    const hal_qos_queue_profile_item *item,
    hal_qos_queue_profile_item_result *item_result) {
    hal_qos_queue_entry entry;
    fm_qosQueueParam param;
    fm_uint32 value;
    fm_status st;

    memset(&param, 0, sizeof(param));
    param.queueId = (fm_int)item->queue_id;
    param.tc = (fm_int)item->traffic_class;
    param.minBw = (fm_uint32)item->min_bw_mbps;
    param.maxBw = qos_queue_profile_max_arg(item);

    st = fmAddQueueQOS((fm_int)sw, (fm_int)port, &param);
    item_result->add_status = (int)st;
    if (st != FM_OK)
        return (int)st;

    value = (fm_uint32)item->traffic_class;
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)port,
                                (fm_int)item->queue_id,
                                FM_QOS_QUEUE_TRAFFIC_CLASS, &value);
    item_result->set_tc_status = (int)st;
    if (st != FM_OK)
        return (int)st;

    value = (fm_uint32)item->min_bw_mbps;
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)port,
                                (fm_int)item->queue_id,
                                FM_QOS_QUEUE_MIN_BW, &value);
    item_result->set_min_status = (int)st;
    if (st != FM_OK)
        return (int)st;

    value = qos_queue_profile_max_arg(item);
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)port,
                                (fm_int)item->queue_id,
                                FM_QOS_QUEUE_MAX_BW, &value);
    item_result->set_max_status = (int)st;
    if (st != FM_OK)
        return (int)st;

    memset(&entry, 0, sizeof(entry));
    if (hal_qos_queue_get(sw, port, item->queue_id, &entry) != 0) {
        item_result->read_status = -1;
        return (int)FM_ERR_INVALID_VALUE;
    }
    if (qos_queue_profile_compare_item(item, &entry, item_result) != 0)
        return (int)FM_ERR_INVALID_VALUE;

    return 0;
}

static int qos_queue_profile_cleanup(
    int sw,
    const hal_qos_queue_profile_owner_args *args,
    hal_qos_queue_profile_owner_result *result) {
    int cleanup_status = 0;

    if (!args || !result)
        return -1;

    for (int i = 0; i < args->queue_count; i++) {
        hal_qos_queue_entry entry;
        fm_status st;

        st = fmDeleteQueueQOS((fm_int)sw, (fm_int)args->port,
                              (fm_int)args->queue[i].queue_id);
        result->queue[i].rollback_status = (int)st;

        memset(&entry, 0, sizeof(entry));
        if (hal_qos_queue_get(sw, args->port,
                              args->queue[i].queue_id, &entry) != 0) {
            result->queue[i].post_read_status = -1;
            if (cleanup_status == 0)
                cleanup_status = -1;
            continue;
        }
        result->queue[i].post_read_status = entry.sdk_status;
        result->queue[i].post_present = entry.present ? 1 : 0;
        if (entry.present && cleanup_status == 0)
            cleanup_status = (int)FM_ERR_INVALID_VALUE;
    }

    result->cleanup_status = cleanup_status;
    return cleanup_status;
}

static int qos_queue_profile_compare_all(
    int sw,
    const hal_qos_queue_profile_owner_args *args,
    hal_qos_queue_profile_owner_result *result) {
    int mismatches = 0;
    int compared = 0;

    if (!args || !result)
        return -1;

    for (int i = 0; i < args->queue_count; i++) {
        hal_qos_queue_entry entry;

        memset(&entry, 0, sizeof(entry));
        if (hal_qos_queue_get(sw, args->port,
                              args->queue[i].queue_id, &entry) != 0) {
            result->queue[i].read_status = -1;
            mismatches++;
            continue;
        }
        if (qos_queue_profile_compare_item(&args->queue[i], &entry,
                                           &result->queue[i]) != 0) {
            mismatches++;
        }
        compared += result->queue[i].compared;
    }

    result->compared = compared;
    result->mismatches = mismatches;
    return mismatches == 0 ? 0 : -1;
}

int hal_qos_queue_profile_owner_apply(
    int sw,
    const hal_qos_queue_profile_owner_args *args,
    hal_qos_queue_profile_owner_result *result) {
    fm_status original_status = FM_OK;

    qos_queue_profile_owner_init_result(result, args);
    if (!args || !result)
        return -1;
    if (!qos_queue_profile_args_valid(args)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid queue profile owner arguments");
        return -1;
    }
    if (g_qos_queue_profile_owner.active) {
        result->active = true;
        snprintf(result->detail, sizeof(result->detail),
                 "queue profile owner already active");
        return -1;
    }

    for (int i = 0; i < args->queue_count; i++) {
        hal_qos_queue_entry entry;

        memset(&entry, 0, sizeof(entry));
        if (hal_qos_queue_get(sw, args->port,
                              args->queue[i].queue_id, &entry) != 0) {
            result->queue[i].pre_status = -1;
            snprintf(result->detail, sizeof(result->detail),
                     "pre-read failed");
            return -1;
        }
        result->queue[i].pre_status = entry.sdk_status;
        result->queue[i].pre_present = entry.present ? 1 : 0;
        if (entry.present) {
            snprintf(result->detail, sizeof(result->detail),
                     "queue %d already present; refusing to overwrite",
                     args->queue[i].queue_id);
            return -1;
        }
    }

    for (int i = 0; i < args->queue_count; i++) {
        int st = qos_queue_profile_apply_one(
            sw, args->port, &args->queue[i], &result->queue[i]);

        if (result->queue[i].add_status == FM_OK)
            result->applied_count++;
        if (st != 0) {
            original_status = (fm_status)st;
            if (strcmp(result->detail, "not-run") == 0) {
                snprintf(result->detail, sizeof(result->detail),
                         "queue profile apply failed at queue %d: %s",
                         args->queue[i].queue_id,
                         fmErrorMsg((fm_status)st));
            }
            (void)qos_queue_profile_cleanup(sw, args, result);
            return result->cleanup_status ? result->cleanup_status :
                   (int)original_status;
        }
    }

    if (qos_queue_profile_compare_all(sw, args, result) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue profile read-back mismatch");
        (void)qos_queue_profile_cleanup(sw, args, result);
        return result->cleanup_status ? result->cleanup_status :
               (int)FM_ERR_INVALID_VALUE;
    }

    g_qos_queue_profile_owner.active = true;
    g_qos_queue_profile_owner.args = *args;
    result->active = true;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS queue profile owner applied and verified");
    return 0;
}

int hal_qos_queue_profile_owner_readback(
    int sw,
    hal_qos_queue_profile_owner_result *result) {
    const hal_qos_queue_profile_owner_args *args;

    args = g_qos_queue_profile_owner.active ?
           &g_qos_queue_profile_owner.args : NULL;
    qos_queue_profile_owner_init_result(result, args);
    if (!result)
        return -1;
    if (!g_qos_queue_profile_owner.active) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no active queue profile owner");
        return 0;
    }

    result->active = true;
    if (qos_queue_profile_compare_all(sw, args, result) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue profile owner read-back mismatch");
        return -1;
    }

    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS queue profile owner read-back verified");
    return 0;
}

int hal_qos_queue_profile_owner_rollback(
    int sw,
    hal_qos_queue_profile_owner_result *result) {
    hal_qos_queue_profile_owner_args args;

    if (g_qos_queue_profile_owner.active)
        args = g_qos_queue_profile_owner.args;
    else
        memset(&args, 0, sizeof(args));
    qos_queue_profile_owner_init_result(
        result, g_qos_queue_profile_owner.active ? &args : NULL);
    if (!result)
        return -1;
    if (!g_qos_queue_profile_owner.active) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no active queue profile owner");
        return 0;
    }

    result->active = true;
    if (qos_queue_profile_cleanup(sw, &args, result) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue profile owner rollback failed");
        return result->cleanup_status;
    }

    g_qos_queue_profile_owner.active = false;
    memset(&g_qos_queue_profile_owner.args, 0,
           sizeof(g_qos_queue_profile_owner.args));
    result->active = false;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS queue profile owner rolled back and verified absent");
    return 0;
}

int hal_qos_queue_probe(int sw,
                        const hal_qos_queue_probe_args *args,
                        hal_qos_queue_probe_result *result) {
    hal_qos_queue_entry entry;
    fm_qosQueueParam param;
    fm_uint32 value;
    fm_status st;

    if (!args || !result)
        return -1;

    memset(result, 0, sizeof(*result));
    result->port = args->port;
    result->queue_id = args->queue_id;
    result->traffic_class = args->traffic_class;
    result->min_bw_mbps = args->min_bw_mbps;
    result->max_bw_mbps = args->max_bw_mbps;
    result->max_bw_default = args->max_bw_default ? 1 : 0;
    snprintf(result->detail, sizeof(result->detail), "not-run");

    if (args->port <= 0 || !nl_ifid_is_user_port(args->port) ||
        args->queue_id < 0 ||
        args->queue_id >= HAL_QOS_MAX_TRAFFIC_CLASSES ||
        args->traffic_class < 0 ||
        args->traffic_class >= HAL_QOS_MAX_TRAFFIC_CLASSES ||
        args->min_bw_mbps > 100000ULL ||
        (!args->max_bw_default &&
         (args->max_bw_mbps < 1ULL || args->max_bw_mbps > 100000ULL)) ||
        (!args->max_bw_default && args->max_bw_mbps < args->min_bw_mbps)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid probe arguments");
        return -1;
    }

    memset(&entry, 0, sizeof(entry));
    if (hal_qos_queue_get(sw, args->port, args->queue_id, &entry) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "pre-read failed");
        return -1;
    }
    result->pre_status = entry.sdk_status;
    if (entry.present) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue already present; refusing to overwrite");
        return -1;
    }

    memset(&param, 0, sizeof(param));
    param.queueId = (fm_int)args->queue_id;
    param.tc = (fm_int)args->traffic_class;
    param.minBw = (fm_uint32)args->min_bw_mbps;
    param.maxBw = qos_queue_max_arg(args);

    st = fmAddQueueQOS((fm_int)sw, (fm_int)args->port, &param);
    result->add_status = (int)st;
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue add failed: %s", fmErrorMsg(st));
        return (int)st;
    }

    value = (fm_uint32)args->traffic_class;
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)args->port,
                                (fm_int)args->queue_id,
                                FM_QOS_QUEUE_TRAFFIC_CLASS, &value);
    result->set_tc_status = (int)st;
    if (st != FM_OK)
        goto fail_cleanup;

    value = (fm_uint32)args->min_bw_mbps;
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)args->port,
                                (fm_int)args->queue_id,
                                FM_QOS_QUEUE_MIN_BW, &value);
    result->set_min_status = (int)st;
    if (st != FM_OK)
        goto fail_cleanup;

    value = qos_queue_max_arg(args);
    st = fmSetAttributeQueueQOS((fm_int)sw, (fm_int)args->port,
                                (fm_int)args->queue_id,
                                FM_QOS_QUEUE_MAX_BW, &value);
    result->set_max_status = (int)st;
    if (st != FM_OK)
        goto fail_cleanup;

    memset(&entry, 0, sizeof(entry));
    if (hal_qos_queue_get(sw, args->port, args->queue_id, &entry) != 0) {
        result->read_status = -1;
        st = FM_ERR_INVALID_VALUE;
        goto fail_cleanup;
    }
    result->read_status = entry.sdk_status;
    if (!entry.present ||
        entry.traffic_class != args->traffic_class ||
        entry.min_bw_mbps != args->min_bw_mbps ||
        entry.max_bw_default != result->max_bw_default ||
        (!result->max_bw_default &&
         entry.max_bw_mbps != args->max_bw_mbps)) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue read-back mismatch");
        st = FM_ERR_INVALID_VALUE;
        goto fail_cleanup;
    }

    st = fmDeleteQueueQOS((fm_int)sw, (fm_int)args->port,
                          (fm_int)args->queue_id);
    result->delete_status = (int)st;
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue delete failed: %s", fmErrorMsg(st));
        return (int)st;
    }

    memset(&entry, 0, sizeof(entry));
    if (hal_qos_queue_get(sw, args->port, args->queue_id, &entry) != 0) {
        result->post_read_status = -1;
        snprintf(result->detail, sizeof(result->detail),
                 "post-delete read failed");
        return -1;
    }
    result->post_read_status = entry.sdk_status;
    result->post_present = entry.present ? 1 : 0;
    if (entry.present) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue still present after delete");
        return -1;
    }

    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS queue add/set/read-back/delete path verified");
    return 0;

fail_cleanup:
    if (strcmp(result->detail, "not-run") == 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "queue attribute set failed: %s", fmErrorMsg(st));
    }
    st = fmDeleteQueueQOS((fm_int)sw, (fm_int)args->port,
                          (fm_int)args->queue_id);
    result->delete_status = (int)st;
    qos_queue_record_cleanup(result, st);
    return result->cleanup_status ? result->cleanup_status : -1;
}

static void qos_watermark_global_init(hal_qos_watermark_global *global) {
    global->auto_pause_mode = NETLAB_QOS_UNSUPPORTED;
    global->cn_mode = NETLAB_QOS_UNSUPPORTED;
    global->cn_frame_etype = NETLAB_QOS_UNSUPPORTED;
    global->cn_frame_vpri = NETLAB_QOS_UNSUPPORTED;
    global->cn_frame_vlan = NETLAB_QOS_UNSUPPORTED;
    global->cn_frame_src_port = NETLAB_QOS_UNSUPPORTED;
    global->priv_wm = NETLAB_QOS_UNSUPPORTED;
    global->high_wm = NETLAB_QOS_UNSUPPORTED;
    global->low_wm = NETLAB_QOS_UNSUPPORTED;

    for (int smp = 0; smp < HAL_QOS_MAX_MEMORY_PARTITIONS; smp++) {
        global->shared_pause_on_wm[smp] = NETLAB_QOS_UNSUPPORTED;
        global->shared_pause_off_wm[smp] = NETLAB_QOS_UNSUPPORTED;
    }
    for (int pri = 0; pri < HAL_QOS_MAX_SWITCH_PRIORITIES; pri++) {
        global->shared_pri_wm[pri] = NETLAB_QOS_UNSUPPORTED;
        global->shared_soft_drop_wm[pri] = NETLAB_QOS_UNSUPPORTED;
        global->shared_soft_drop_jitter[pri] = NETLAB_QOS_UNSUPPORTED;
        global->shared_soft_drop_hog[pri] = NETLAB_QOS_UNSUPPORTED;
    }
}

int hal_qos_watermark_global_get(int sw,
                                 hal_qos_watermark_global *global) {
    u64 mac = 0;

    if (!global)
        return -1;

    memset(global, 0, sizeof(*global));
    qos_watermark_global_init(global);

    global->auto_pause_mode = get_switch_qos_bool_attr(sw,
                                                       FM_AUTO_PAUSE_MODE);
    global->cn_mode = get_switch_qos_u32_attr(sw, FM_QOS_CN_MODE, 0);
    global->cn_frame_etype =
        get_switch_qos_u32_attr(sw, FM_QOS_CN_FRAME_ETYPE, 0);
    global->cn_frame_vpri =
        get_switch_qos_u32_attr(sw, FM_QOS_CN_FRAME_VPRI, 0);
    global->cn_frame_vlan =
        get_switch_qos_u32_attr(sw, FM_QOS_CN_FRAME_VLAN, 0);
    global->cn_frame_src_port =
        get_switch_qos_u32_attr(sw, FM_QOS_CN_FRAME_SRC_PORT, 0);
    if (get_switch_qos_mac_attr(sw, FM_QOS_CN_FRAME_SMAC, &mac) == 0) {
        global->cn_frame_smac_valid = 1;
        global->cn_frame_smac = mac;
    }
    if (get_switch_qos_mac_attr(sw, FM_QOS_CN_FRAME_DMAC, &mac) == 0) {
        global->cn_frame_dmac_valid = 1;
        global->cn_frame_dmac = mac;
    }

    global->priv_wm = get_switch_qos_u32_attr(sw, FM_QOS_PRIV_WM, 0);
    global->high_wm = get_switch_qos_u32_attr(sw, FM_QOS_HIGH_WM, 0);
    global->low_wm = get_switch_qos_u32_attr(sw, FM_QOS_LOW_WM, 0);

    for (int smp = 0; smp < HAL_QOS_MAX_MEMORY_PARTITIONS; smp++) {
        global->shared_pause_on_wm[smp] =
            get_switch_qos_u32_attr(sw, FM_QOS_SHARED_PAUSE_ON_WM,
                                    (fm_int)smp);
        global->shared_pause_off_wm[smp] =
            get_switch_qos_u32_attr(sw, FM_QOS_SHARED_PAUSE_OFF_WM,
                                    (fm_int)smp);
    }
    for (int pri = 0; pri < HAL_QOS_MAX_SWITCH_PRIORITIES; pri++) {
        global->shared_pri_wm[pri] =
            get_switch_qos_u32_attr(sw, FM_QOS_SHARED_PRI_WM,
                                    (fm_int)pri);
        global->shared_soft_drop_wm[pri] =
            get_switch_qos_u32_attr(sw, FM_QOS_SHARED_SOFT_DROP_WM,
                                    (fm_int)pri);
        global->shared_soft_drop_jitter[pri] =
            get_switch_qos_u32_attr(sw, FM_QOS_SHARED_SOFT_DROP_WM_JITTER,
                                    (fm_int)pri);
        global->shared_soft_drop_hog[pri] =
            get_switch_qos_u32_attr(sw, FM_QOS_SHARED_SOFT_DROP_WM_HOG,
                                    (fm_int)pri);
    }

    return 0;
}

static void qos_watermark_entry_init(hal_qos_watermark_entry *entry) {
    for (int tc = 0; tc < HAL_QOS_MAX_TRAFFIC_CLASSES; tc++) {
        entry->tx_hog_wm[tc] = NETLAB_QOS_UNSUPPORTED;
        entry->tx_tc_private_wm[tc] = NETLAB_QOS_UNSUPPORTED;
    }
    for (int smp = 0; smp < HAL_QOS_MAX_MEMORY_PARTITIONS; smp++) {
        entry->rx_hog_wm[smp] = NETLAB_QOS_UNSUPPORTED;
        entry->rx_private_wm[smp] = NETLAB_QOS_UNSUPPORTED;
        entry->private_pause_on_wm[smp] = NETLAB_QOS_UNSUPPORTED;
        entry->private_pause_off_wm[smp] = NETLAB_QOS_UNSUPPORTED;
    }
    for (int priority = 0;
         priority < HAL_QOS_MAX_SWITCH_PRIORITIES; priority++) {
        entry->tx_soft_drop_on_private[priority] =
            NETLAB_QOS_UNSUPPORTED;
        entry->tx_soft_drop_on_rxmp_free[priority] =
            NETLAB_QOS_UNSUPPORTED;
    }
}

int hal_qos_watermark_get(int sw, int port,
                          hal_qos_watermark_entry *entry) {
    if (!entry || port <= 0 || !nl_ifid_is_user_port(port))
        return -1;

    memset(entry, 0, sizeof(*entry));
    entry->port = port;
    qos_watermark_entry_init(entry);

    for (int tc = 0; tc < HAL_QOS_MAX_TRAFFIC_CLASSES; tc++) {
        entry->tx_hog_wm[tc] =
            get_port_qos_u32_attr(sw, port, FM_QOS_TX_HOG_WM,
                                  (fm_int)tc);
        entry->tx_tc_private_wm[tc] =
            get_port_qos_u32_attr(sw, port, FM_QOS_TX_TC_PRIVATE_WM,
                                  (fm_int)tc);
    }
    for (int smp = 0; smp < HAL_QOS_MAX_MEMORY_PARTITIONS; smp++) {
        entry->rx_hog_wm[smp] =
            get_port_qos_u32_attr(sw, port, FM_QOS_RX_HOG_WM,
                                  (fm_int)smp);
        entry->rx_private_wm[smp] =
            get_port_qos_u32_attr(sw, port, FM_QOS_RX_PRIVATE_WM,
                                  (fm_int)smp);
        entry->private_pause_on_wm[smp] =
            get_port_qos_u32_attr(sw, port, FM_QOS_PRIVATE_PAUSE_ON_WM,
                                  (fm_int)smp);
        entry->private_pause_off_wm[smp] =
            get_port_qos_u32_attr(sw, port, FM_QOS_PRIVATE_PAUSE_OFF_WM,
                                  (fm_int)smp);
    }
    for (int priority = 0;
         priority < HAL_QOS_MAX_SWITCH_PRIORITIES; priority++) {
        entry->tx_soft_drop_on_private[priority] =
            get_port_qos_u32_attr(
                sw, port, FM_QOS_TX_SOFT_DROP_ON_PRIVATE,
                (fm_int)priority);
        entry->tx_soft_drop_on_rxmp_free[priority] =
            get_port_qos_u32_attr(
                sw, port, FM_QOS_TX_SOFT_DROP_ON_RXMP_FREE,
                (fm_int)priority);
    }

    return 0;
}

int hal_qos_watermark_list(int sw,
                           hal_qos_watermark_entry *entries,
                           int max_entries) {
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n_ports;
    int n = 0;

    if (!entries || max_entries <= 0)
        return -1;

    n_ports = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_ports && n < max_entries; i++) {
        hal_qos_watermark_entry entry;

        if (!nl_ifid_is_user_port(ports[i].logical_port))
            continue;
        if (hal_qos_watermark_get(sw, ports[i].logical_port, &entry) != 0)
            continue;
        entries[n++] = entry;
    }
    return n;
}

int hal_qos_watermark_read(int sw, int port, int attr, int index,
                           int *value);
int hal_qos_watermark_set(int sw, int port, int attr, int index, int value);
int hal_qos_watermark_delete(int sw, int port, int attr, int index);

typedef struct {
    bool active;
    hal_qos_watermark_owner_args args;
    int original_value;
    int requested_value;
} qos_watermark_owner_state;

static qos_watermark_owner_state g_qos_watermark_owner;

typedef struct {
    bool active;
    bool baseline_known;
    int port;
    int attr;
    int index;
    int baseline;
    int value;
} qos_watermark_config_state;

static qos_watermark_config_state
    g_qos_watermark_config[NETLAB_QOS_WATERMARK_CONFIG_MAX];
static bool g_qos_watermark_provenance_loaded;
static int g_qos_watermark_provenance_load_status;

static qos_watermark_config_state *qos_watermark_config_find(
    int port, int attr, int index) {
    for (int i = 0; i < NETLAB_QOS_WATERMARK_CONFIG_MAX; i++) {
        if (g_qos_watermark_config[i].active &&
            g_qos_watermark_config[i].port == port &&
            g_qos_watermark_config[i].attr == attr &&
            g_qos_watermark_config[i].index == index)
            return &g_qos_watermark_config[i];
    }
    return NULL;
}

static qos_watermark_config_state *qos_watermark_config_slot(
    int port, int attr, int index) {
    qos_watermark_config_state *slot =
        qos_watermark_config_find(port, attr, index);

    if (slot)
        return slot;
    for (int i = 0; i < NETLAB_QOS_WATERMARK_CONFIG_MAX; i++) {
        if (!g_qos_watermark_config[i].active)
            return &g_qos_watermark_config[i];
    }
    return NULL;
}

static bool qos_watermark_attr_is_port(int attr) {
    return attr == HAL_QOS_WATERMARK_ATTR_TX_HOG ||
           attr == HAL_QOS_WATERMARK_ATTR_TX_PRIVATE ||
           attr == HAL_QOS_WATERMARK_ATTR_RX_HOG ||
           attr == HAL_QOS_WATERMARK_ATTR_RX_PRIVATE ||
           attr == HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_ON ||
           attr == HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_OFF ||
           attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
           attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE;
}

static bool qos_watermark_attr_is_switch(int attr) {
    return attr == HAL_QOS_WATERMARK_ATTR_SHARED_PRI ||
           attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
           attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
           attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
}

static int qos_watermark_sdk_attr(int attr) {
    switch (attr) {
    case HAL_QOS_WATERMARK_ATTR_TX_HOG:
        return FM_QOS_TX_HOG_WM;
    case HAL_QOS_WATERMARK_ATTR_TX_PRIVATE:
        return FM_QOS_TX_TC_PRIVATE_WM;
    case HAL_QOS_WATERMARK_ATTR_RX_HOG:
        return FM_QOS_RX_HOG_WM;
    case HAL_QOS_WATERMARK_ATTR_RX_PRIVATE:
        return FM_QOS_RX_PRIVATE_WM;
    case HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_ON:
        return FM_QOS_PRIVATE_PAUSE_ON_WM;
    case HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_OFF:
        return FM_QOS_PRIVATE_PAUSE_OFF_WM;
    case HAL_QOS_WATERMARK_ATTR_SHARED_PRI:
        return FM_QOS_SHARED_PRI_WM;
    case HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP:
        return FM_QOS_SHARED_SOFT_DROP_WM;
    case HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER:
        return FM_QOS_SHARED_SOFT_DROP_WM_JITTER;
    case HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG:
        return FM_QOS_SHARED_SOFT_DROP_WM_HOG;
    case HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE:
        return FM_QOS_TX_SOFT_DROP_ON_PRIVATE;
    case HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE:
        return FM_QOS_TX_SOFT_DROP_ON_RXMP_FREE;
    default:
        return -1;
    }
}

static int qos_watermark_index_limit(int attr) {
    if (attr == HAL_QOS_WATERMARK_ATTR_TX_HOG ||
        attr == HAL_QOS_WATERMARK_ATTR_TX_PRIVATE)
        return HAL_QOS_MAX_TRAFFIC_CLASSES;
    if (attr == HAL_QOS_WATERMARK_ATTR_RX_HOG ||
        attr == HAL_QOS_WATERMARK_ATTR_RX_PRIVATE ||
        attr == HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_ON ||
        attr == HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_OFF)
        return HAL_QOS_MAX_MEMORY_PARTITIONS;
    if (attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
        attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE)
        return HAL_QOS_MAX_SWITCH_PRIORITIES;
    if (qos_watermark_attr_is_switch(attr))
        return HAL_QOS_MAX_SWITCH_PRIORITIES;
    return 0;
}

static int qos_watermark_value_max(int attr) {
    if (attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER)
        return 7;
    if (attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
        attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE)
        return 1;
    return 6291264;
}

static bool qos_watermark_args_valid(
    const hal_qos_watermark_owner_args *args) {
    int index_limit;

    if (!args)
        return false;
    if (args->scope == HAL_QOS_WATERMARK_SCOPE_PORT) {
        if (!qos_watermark_attr_is_port(args->attr) ||
            args->port <= 0 ||
            !nl_ifid_is_user_port(args->port))
            return false;
    } else if (args->scope == HAL_QOS_WATERMARK_SCOPE_SWITCH) {
        if (!qos_watermark_attr_is_switch(args->attr) ||
            args->port != 0)
            return false;
    } else {
        return false;
    }
    index_limit = qos_watermark_index_limit(args->attr);
    if (args->index < 0 || args->index >= index_limit)
        return false;
    if (args->value < -1 || args->value > qos_watermark_value_max(args->attr))
        return false;
    return qos_watermark_sdk_attr(args->attr) >= 0;
}

static int qos_watermark_write_all(int fd, const char *data, size_t size) {
    size_t written = 0;

    while (written < size) {
        ssize_t n = write(fd, data + written, size - written);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        written += (size_t)n;
    }
    return 0;
}

static void qos_watermark_provenance_path(char *path, size_t size) {
#ifdef NETLAB_QOS_WATERMARK_PROVENANCE_PATH
    snprintf(path, size, "%s", NETLAB_QOS_WATERMARK_PROVENANCE_PATH);
#else
    nl_config_file_path(
        path, size, "qos-watermark-provenance.v1");
#endif
}

static int qos_watermark_provenance_sync_directory(
    const char *provenance_path) {
    char directory[512];
    char *slash;
    int fd;
    int status;

    if (!provenance_path ||
        strlen(provenance_path) >= sizeof(directory))
        return -1;
    snprintf(directory, sizeof(directory), "%s", provenance_path);
    slash = strrchr(directory, '/');
    if (!slash)
        return -1;
    if (slash == directory)
        slash[1] = '\0';
    else
        *slash = '\0';
#ifdef O_DIRECTORY
    fd = open(directory, O_RDONLY | O_DIRECTORY);
#else
    fd = open(directory, O_RDONLY);
#endif
    if (fd < 0)
        return -1;
    status = fsync(fd);
    if (close(fd) != 0)
        status = -1;
    return status == 0 ? 0 : -1;
}

static int qos_watermark_provenance_persist(void) {
    const size_t capacity =
        64U + (size_t)NETLAB_QOS_WATERMARK_CONFIG_MAX * 128U;
    char temporary[640];
    char provenance_path[512];
    char *buffer;
    size_t offset = 0;
    int fd = -1;
    int status = -1;

    qos_watermark_provenance_path(
        provenance_path, sizeof(provenance_path));
    if (!g_qos_watermark_provenance_loaded ||
        g_qos_watermark_provenance_load_status != 0 ||
        snprintf(temporary, sizeof(temporary), "%s.tmp.%ld",
                 provenance_path,
                 (long)getpid()) >= (int)sizeof(temporary))
        return -1;

    buffer = calloc(1, capacity);
    if (!buffer)
        return -1;
    offset = (size_t)snprintf(
        buffer, capacity, "%s\n",
        NETLAB_QOS_WATERMARK_PROVENANCE_MAGIC);
    if (offset >= capacity)
        goto out;

    for (int i = 0; i < NETLAB_QOS_WATERMARK_CONFIG_MAX; i++) {
        const qos_watermark_config_state *slot =
            &g_qos_watermark_config[i];
        int n;

        if (!slot->active)
            continue;
        n = snprintf(
            buffer + offset, capacity - offset,
            "%d %d %d %d %d %d\n",
            slot->port, slot->attr, slot->index,
            slot->baseline_known ? 1 : 0,
            slot->baseline, slot->value);
        if (n < 0 || (size_t)n >= capacity - offset)
            goto out;
        offset += (size_t)n;
    }

    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        goto out;
    if (qos_watermark_write_all(fd, buffer, offset) != 0 ||
        fsync(fd) != 0) {
        (void)close(fd);
        fd = -1;
        (void)unlink(temporary);
        goto out;
    }
    if (close(fd) != 0) {
        fd = -1;
        (void)unlink(temporary);
        goto out;
    }
    fd = -1;
    if (rename(temporary, provenance_path) != 0) {
        (void)unlink(temporary);
        goto out;
    }
    if (qos_watermark_provenance_sync_directory(
            provenance_path) != 0)
        goto out;
    status = 0;

out:
    if (fd >= 0) {
        (void)close(fd);
        (void)unlink(temporary);
    }
    free(buffer);
    return status;
}

static int qos_watermark_provenance_parse_line(const char *line) {
    hal_qos_watermark_owner_args args;
    qos_watermark_config_state *slot;
    int port;
    int attr;
    int index;
    int baseline_known;
    int baseline;
    int value;
    int consumed = 0;

    if (!line ||
        sscanf(line, "%d %d %d %d %d %d %n",
               &port, &attr, &index, &baseline_known,
               &baseline, &value, &consumed) != 6 ||
        line[consumed] != '\0' ||
        (baseline_known != 0 && baseline_known != 1))
        return -1;

    memset(&args, 0, sizeof(args));
    args.scope = qos_watermark_attr_is_switch(attr) ?
                 HAL_QOS_WATERMARK_SCOPE_SWITCH :
                 HAL_QOS_WATERMARK_SCOPE_PORT;
    args.port = args.scope == HAL_QOS_WATERMARK_SCOPE_SWITCH ? 0 : port;
    args.attr = attr;
    args.index = index;
    args.value = 0;
    if (!qos_watermark_args_valid(&args) ||
        port != args.port ||
        value < 0 || value > qos_watermark_value_max(attr) ||
        (baseline_known != 0 &&
         (baseline < 0 || baseline > qos_watermark_value_max(attr))) ||
        (baseline_known == 0 && baseline != NETLAB_QOS_UNSUPPORTED) ||
        qos_watermark_config_find(port, attr, index))
        return -1;

    slot = qos_watermark_config_slot(port, attr, index);
    if (!slot)
        return -1;
    memset(slot, 0, sizeof(*slot));
    slot->active = true;
    slot->baseline_known = baseline_known != 0;
    slot->port = port;
    slot->attr = attr;
    slot->index = index;
    slot->baseline = baseline;
    slot->value = value;
    return 0;
}

static int qos_watermark_provenance_load(void) {
    struct stat stat_buffer;
    char provenance_path[512];
    char *buffer = NULL;
    char *save = NULL;
    char *line;
    ssize_t received = 0;
    int fd = -1;
    int status = -1;

    if (g_qos_watermark_provenance_loaded)
        return g_qos_watermark_provenance_load_status;
    g_qos_watermark_provenance_loaded = true;
    g_qos_watermark_provenance_load_status = -1;
    memset(g_qos_watermark_config, 0, sizeof(g_qos_watermark_config));

    qos_watermark_provenance_path(
        provenance_path, sizeof(provenance_path));
    fd = open(provenance_path, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT)
            status = 0;
        goto out;
    }
    if (fstat(fd, &stat_buffer) != 0 ||
        !S_ISREG(stat_buffer.st_mode) ||
        stat_buffer.st_size <= 0 ||
        stat_buffer.st_size > 131072)
        goto out;
    buffer = calloc(1, (size_t)stat_buffer.st_size + 1U);
    if (!buffer)
        goto out;
    while (received < stat_buffer.st_size) {
        ssize_t n = read(fd, buffer + received,
                         (size_t)(stat_buffer.st_size - received));

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            goto out;
        received += n;
    }
    if (close(fd) != 0)
        goto out;
    fd = -1;

    line = strtok_r(buffer, "\n", &save);
    if (!line ||
        strcmp(line, NETLAB_QOS_WATERMARK_PROVENANCE_MAGIC) != 0)
        goto out;
    while ((line = strtok_r(NULL, "\n", &save)) != NULL) {
        if (line[0] == '\0')
            continue;
        if (qos_watermark_provenance_parse_line(line) != 0)
            goto out;
    }
    status = 0;

out:
    if (fd >= 0)
        (void)close(fd);
    free(buffer);
    if (status != 0)
        memset(g_qos_watermark_config, 0,
               sizeof(g_qos_watermark_config));
    g_qos_watermark_provenance_load_status = status;
    return status;
}

static void qos_watermark_owner_init_result(
    hal_qos_watermark_owner_result *result,
    const hal_qos_watermark_owner_args *args) {
    if (!result)
        return;
    memset(result, 0, sizeof(*result));
    if (args) {
        result->scope = args->scope;
        result->port = args->port;
        result->attr = args->attr;
        result->index = args->index;
        result->requested_value = args->value;
    }
    result->original_value = NETLAB_QOS_UNSUPPORTED;
    result->applied_value = NETLAB_QOS_UNSUPPORTED;
    result->current_value = NETLAB_QOS_UNSUPPORTED;
    snprintf(result->detail, sizeof(result->detail), "not-run");
}

static fm_status qos_watermark_read_value(
    int sw,
    const hal_qos_watermark_owner_args *args,
    int *value) {
    fm_uint32 sdk_value = 0;
    fm_status st;
    int sdk_attr;

    if (!args || !value)
        return FM_ERR_INVALID_ARGUMENT;
    sdk_attr = qos_watermark_sdk_attr(args->attr);
    if (sdk_attr < 0)
        return FM_ERR_INVALID_ARGUMENT;

    if (args->scope == HAL_QOS_WATERMARK_SCOPE_PORT) {
        st = fmGetPortQOS((fm_int)sw, (fm_int)args->port,
                          (fm_int)sdk_attr, (fm_int)args->index,
                          &sdk_value);
    } else {
        st = fmGetSwitchQOS((fm_int)sw, (fm_int)sdk_attr,
                            (fm_int)args->index, &sdk_value);
    }
    if (st != FM_OK)
        return st;
    *value = (int)sdk_value;
    return FM_OK;
}

static fm_status qos_watermark_write_value(
    int sw,
    const hal_qos_watermark_owner_args *args,
    int value) {
    fm_uint32 sdk_value = (fm_uint32)value;
    int sdk_attr;

    if (!args || value < 0)
        return FM_ERR_INVALID_ARGUMENT;
    sdk_attr = qos_watermark_sdk_attr(args->attr);
    if (sdk_attr < 0)
        return FM_ERR_INVALID_ARGUMENT;

    if (args->scope == HAL_QOS_WATERMARK_SCOPE_PORT) {
        return fmSetPortQOS((fm_int)sw, (fm_int)args->port,
                            (fm_int)sdk_attr, (fm_int)args->index,
                            &sdk_value);
    }
    return fmSetSwitchQOS((fm_int)sw, (fm_int)sdk_attr,
                          (fm_int)args->index, &sdk_value);
}

static hal_qos_auto_pause_watermark_transaction_snapshot
qos_auto_pause_watermark_transaction_read_error(fm_status status) {
    hal_qos_auto_pause_watermark_transaction_snapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = (int)status;
    return snapshot;
}

static fm_status qos_auto_pause_get_port_u32(
    int sw, int port, fm_int attr, int index, u32 *value) {
    fm_uint32 sdk_value = 0;
    fm_status st;

    if (!value)
        return FM_ERR_INVALID_ARGUMENT;
    st = fmGetPortQOS((fm_int)sw, (fm_int)port, attr,
                      (fm_int)index, &sdk_value);
    if (st == FM_OK)
        *value = (u32)sdk_value;
    return st;
}

static fm_status qos_auto_pause_set_port_u32(
    int sw, int port, fm_int attr, int index, u32 value) {
    fm_uint32 sdk_value = (fm_uint32)value;

    return fmSetPortQOS((fm_int)sw, (fm_int)port, attr,
                        (fm_int)index, &sdk_value);
}

static fm_status qos_auto_pause_get_switch_u32(
    int sw, fm_int attr, int index, u32 *value) {
    fm_uint32 sdk_value = 0;
    fm_status st;

    if (!value)
        return FM_ERR_INVALID_ARGUMENT;
    st = fmGetSwitchQOS((fm_int)sw, attr, (fm_int)index, &sdk_value);
    if (st == FM_OK)
        *value = (u32)sdk_value;
    return st;
}

static fm_status qos_auto_pause_set_switch_u32(
    int sw, fm_int attr, int index, u32 value) {
    fm_uint32 sdk_value = (fm_uint32)value;

    return fmSetSwitchQOS((fm_int)sw, attr, (fm_int)index, &sdk_value);
}

static void qos_auto_pause_sort_ports(fm_int *ports, fm_int count) {
    for (fm_int i = 1; i < count; i++) {
        fm_int value = ports[i];
        fm_int j = i;

        while (j > 0 && ports[j - 1] > value) {
            ports[j] = ports[j - 1];
            j--;
        }
        ports[j] = value;
    }
}

static fm_status qos_auto_pause_cardinal_ports_get(
    int sw, fm_int *count,
    fm_int ports[HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS]) {
    fm_status st;

    if (!count || !ports)
        return FM_ERR_INVALID_ARGUMENT;
    *count = 0;
    st = fmGetCardinalPortList(
        (fm_int)sw, count, ports,
        HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS);
    if (st != FM_OK)
        return st;
    if (*count <= 0 ||
        *count > HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS)
        return FM_ERR_INVALID_STATE;

    qos_auto_pause_sort_ports(ports, *count);
    for (fm_int i = 1; i < *count; i++)
        if (ports[i - 1] == ports[i])
            return FM_ERR_INVALID_STATE;
    return FM_OK;
}

hal_qos_auto_pause_watermark_transaction_snapshot
hal_qos_auto_pause_watermark_transaction_snapshot_get(int sw) {
    hal_qos_auto_pause_watermark_transaction_snapshot snapshot;
    fm_int cardinal_ports[HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS];
    fm_bool auto_pause_mode = FALSE;
    fm_int num_ports = 0;
    fm_status st;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;

    st = fmGetSwitchQOS((fm_int)sw, FM_AUTO_PAUSE_MODE, 0,
                        &auto_pause_mode);
    if (st != FM_OK)
        return qos_auto_pause_watermark_transaction_read_error(st);
    if (auto_pause_mode != FALSE && auto_pause_mode != TRUE)
        return qos_auto_pause_watermark_transaction_read_error(
            FM_ERR_INVALID_STATE);
    snapshot.auto_pause_mode = auto_pause_mode == TRUE ? 1U : 0U;

    st = qos_auto_pause_cardinal_ports_get(
        sw, &num_ports, cardinal_ports);
    if (st != FM_OK)
        return qos_auto_pause_watermark_transaction_read_error(st);
    snapshot.num_ports = (u32)num_ports;

    st = qos_auto_pause_get_switch_u32(
        sw, FM_QOS_PRIV_WM, 0, &snapshot.global_private_wm);
    if (st != FM_OK)
        return qos_auto_pause_watermark_transaction_read_error(st);
    for (int smp = 0;
         smp < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS; smp++) {
        st = qos_auto_pause_get_switch_u32(
            sw, FM_QOS_SHARED_PAUSE_ON_WM, smp,
            &snapshot.shared_pause_on_wm[smp]);
        if (st != FM_OK)
            return qos_auto_pause_watermark_transaction_read_error(st);
        st = qos_auto_pause_get_switch_u32(
            sw, FM_QOS_SHARED_PAUSE_OFF_WM, smp,
            &snapshot.shared_pause_off_wm[smp]);
        if (st != FM_OK)
            return qos_auto_pause_watermark_transaction_read_error(st);
    }
    for (int priority = 0;
         priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
        st = qos_auto_pause_get_switch_u32(
            sw, FM_QOS_SHARED_PRI_WM, priority,
            &snapshot.shared_priority_wm[priority]);
        if (st != FM_OK)
            return qos_auto_pause_watermark_transaction_read_error(st);
        st = qos_auto_pause_get_switch_u32(
            sw, FM_QOS_SHARED_SOFT_DROP_WM, priority,
            &snapshot.shared_soft_drop_wm[priority]);
        if (st != FM_OK)
            return qos_auto_pause_watermark_transaction_read_error(st);
        st = qos_auto_pause_get_switch_u32(
            sw, FM_QOS_SHARED_SOFT_DROP_WM_HOG, priority,
            &snapshot.shared_soft_drop_hog_wm[priority]);
        if (st != FM_OK)
            return qos_auto_pause_watermark_transaction_read_error(st);
        st = qos_auto_pause_get_switch_u32(
            sw, FM_QOS_SHARED_SOFT_DROP_WM_JITTER, priority,
            &snapshot.shared_soft_drop_jitter[priority]);
        if (st != FM_OK)
            return qos_auto_pause_watermark_transaction_read_error(st);
    }

    for (fm_int port_index = 0;
         port_index < num_ports; port_index++) {
        hal_qos_auto_pause_port_watermark_transaction_state *port_state =
            &snapshot.ports[port_index];

        port_state->port = (int)cardinal_ports[port_index];
        for (int smp = 0;
             smp < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS; smp++) {
            st = qos_auto_pause_get_port_u32(
                sw, port_state->port, FM_QOS_RX_PRIVATE_WM, smp,
                &port_state->rx_private_wm[smp]);
            if (st != FM_OK)
                return qos_auto_pause_watermark_transaction_read_error(st);
            st = qos_auto_pause_get_port_u32(
                sw, port_state->port, FM_QOS_RX_HOG_WM, smp,
                &port_state->rx_hog_wm[smp]);
            if (st != FM_OK)
                return qos_auto_pause_watermark_transaction_read_error(st);
            st = qos_auto_pause_get_port_u32(
                sw, port_state->port, FM_QOS_PRIVATE_PAUSE_ON_WM, smp,
                &port_state->private_pause_on_wm[smp]);
            if (st != FM_OK)
                return qos_auto_pause_watermark_transaction_read_error(st);
            st = qos_auto_pause_get_port_u32(
                sw, port_state->port, FM_QOS_PRIVATE_PAUSE_OFF_WM, smp,
                &port_state->private_pause_off_wm[smp]);
            if (st != FM_OK)
                return qos_auto_pause_watermark_transaction_read_error(st);
        }
        for (int tc = 0;
             tc < HAL_TRANSACTION_QOS_TRAFFIC_CLASSES; tc++) {
            st = qos_auto_pause_get_port_u32(
                sw, port_state->port, FM_QOS_TX_TC_PRIVATE_WM, tc,
                &port_state->tx_private_wm[tc]);
            if (st != FM_OK)
                return qos_auto_pause_watermark_transaction_read_error(st);
            st = qos_auto_pause_get_port_u32(
                sw, port_state->port, FM_QOS_TX_HOG_WM, tc,
                &port_state->tx_hog_wm[tc]);
            if (st != FM_OK)
                return qos_auto_pause_watermark_transaction_read_error(st);
        }
        for (int priority = 0;
             priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
            st = qos_auto_pause_get_port_u32(
                sw, port_state->port,
                FM_QOS_TX_SOFT_DROP_ON_PRIVATE, priority,
                &port_state->tx_soft_drop_on_private[priority]);
            if (st != FM_OK)
                return qos_auto_pause_watermark_transaction_read_error(st);
            st = qos_auto_pause_get_port_u32(
                sw, port_state->port,
                FM_QOS_TX_SOFT_DROP_ON_RXMP_FREE, priority,
                &port_state->tx_soft_drop_on_rxmp_free[priority]);
            if (st != FM_OK)
                return qos_auto_pause_watermark_transaction_read_error(st);
        }
    }

    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    return snapshot;
}

bool hal_qos_auto_pause_watermark_transaction_snapshot_equal(
    const hal_qos_auto_pause_watermark_transaction_snapshot *left,
    const hal_qos_auto_pause_watermark_transaction_snapshot *right) {
    if (!left || !right ||
        left->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        right->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        left->sdk_status != FM_OK ||
        right->sdk_status != FM_OK ||
        left->auto_pause_mode != right->auto_pause_mode ||
        left->num_ports != right->num_ports ||
        left->num_ports > HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS ||
        left->global_private_wm != right->global_private_wm ||
        memcmp(left->shared_pause_on_wm,
               right->shared_pause_on_wm,
               sizeof(left->shared_pause_on_wm)) != 0 ||
        memcmp(left->shared_pause_off_wm,
               right->shared_pause_off_wm,
               sizeof(left->shared_pause_off_wm)) != 0 ||
        memcmp(left->shared_priority_wm,
               right->shared_priority_wm,
               sizeof(left->shared_priority_wm)) != 0 ||
        memcmp(left->shared_soft_drop_wm,
               right->shared_soft_drop_wm,
               sizeof(left->shared_soft_drop_wm)) != 0 ||
        memcmp(left->shared_soft_drop_hog_wm,
               right->shared_soft_drop_hog_wm,
               sizeof(left->shared_soft_drop_hog_wm)) != 0 ||
        memcmp(left->shared_soft_drop_jitter,
               right->shared_soft_drop_jitter,
               sizeof(left->shared_soft_drop_jitter)) != 0)
        return false;

    for (u32 i = 0; i < left->num_ports; i++) {
        const hal_qos_auto_pause_port_watermark_transaction_state
            *left_port = &left->ports[i];
        const hal_qos_auto_pause_port_watermark_transaction_state
            *right_port = &right->ports[i];

        if (left_port->port != right_port->port ||
            memcmp(left_port->rx_private_wm,
                   right_port->rx_private_wm,
                   sizeof(left_port->rx_private_wm)) != 0 ||
            memcmp(left_port->rx_hog_wm,
                   right_port->rx_hog_wm,
                   sizeof(left_port->rx_hog_wm)) != 0 ||
            memcmp(left_port->private_pause_on_wm,
                   right_port->private_pause_on_wm,
                   sizeof(left_port->private_pause_on_wm)) != 0 ||
            memcmp(left_port->private_pause_off_wm,
                   right_port->private_pause_off_wm,
                   sizeof(left_port->private_pause_off_wm)) != 0 ||
            memcmp(left_port->tx_private_wm,
                   right_port->tx_private_wm,
                   sizeof(left_port->tx_private_wm)) != 0 ||
            memcmp(left_port->tx_hog_wm,
                   right_port->tx_hog_wm,
                   sizeof(left_port->tx_hog_wm)) != 0 ||
            memcmp(left_port->tx_soft_drop_on_private,
                   right_port->tx_soft_drop_on_private,
                   sizeof(left_port->tx_soft_drop_on_private)) != 0 ||
            memcmp(left_port->tx_soft_drop_on_rxmp_free,
                   right_port->tx_soft_drop_on_rxmp_free,
                   sizeof(left_port->tx_soft_drop_on_rxmp_free)) != 0)
            return false;
    }
    return true;
}

static bool qos_auto_pause_watermark_snapshot_valid(
    const hal_qos_auto_pause_watermark_transaction_snapshot *snapshot) {
    if (!snapshot ||
        snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        snapshot->sdk_status != FM_OK ||
        snapshot->auto_pause_mode > 1 ||
        snapshot->num_ports == 0 ||
        snapshot->num_ports > HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS)
        return false;
    for (u32 i = 1; i < snapshot->num_ports; i++)
        if (snapshot->ports[i - 1].port >= snapshot->ports[i].port)
            return false;
    return true;
}

static fm_status qos_auto_pause_replay_port_image(
    int sw,
    const hal_qos_auto_pause_port_watermark_transaction_state *port_state,
    bool include_auto_owned) {
    fm_status st;

    if (include_auto_owned) {
        for (int smp = 0;
             smp < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS; smp++) {
            st = qos_auto_pause_set_port_u32(
                sw, port_state->port, FM_QOS_RX_PRIVATE_WM, smp,
                port_state->rx_private_wm[smp]);
            if (st != FM_OK)
                return st;
            st = qos_auto_pause_set_port_u32(
                sw, port_state->port, FM_QOS_RX_HOG_WM, smp,
                port_state->rx_hog_wm[smp]);
            if (st != FM_OK)
                return st;
            st = qos_auto_pause_set_port_u32(
                sw, port_state->port, FM_QOS_PRIVATE_PAUSE_ON_WM, smp,
                port_state->private_pause_on_wm[smp]);
            if (st != FM_OK)
                return st;
            st = qos_auto_pause_set_port_u32(
                sw, port_state->port, FM_QOS_PRIVATE_PAUSE_OFF_WM, smp,
                port_state->private_pause_off_wm[smp]);
            if (st != FM_OK)
                return st;
        }
    }
    for (int tc = 0;
         tc < HAL_TRANSACTION_QOS_TRAFFIC_CLASSES; tc++) {
        st = qos_auto_pause_set_port_u32(
            sw, port_state->port, FM_QOS_TX_TC_PRIVATE_WM, tc,
            port_state->tx_private_wm[tc]);
        if (st != FM_OK)
            return st;
        st = qos_auto_pause_set_port_u32(
            sw, port_state->port, FM_QOS_TX_HOG_WM, tc,
            port_state->tx_hog_wm[tc]);
        if (st != FM_OK)
            return st;
    }
    for (int priority = 0;
         priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
        st = qos_auto_pause_set_port_u32(
            sw, port_state->port,
            FM_QOS_TX_SOFT_DROP_ON_PRIVATE, priority,
            port_state->tx_soft_drop_on_private[priority]);
        if (st != FM_OK)
            return st;
        st = qos_auto_pause_set_port_u32(
            sw, port_state->port,
            FM_QOS_TX_SOFT_DROP_ON_RXMP_FREE, priority,
            port_state->tx_soft_drop_on_rxmp_free[priority]);
        if (st != FM_OK)
            return st;
    }
    return FM_OK;
}

static fm_status qos_auto_pause_replay_switch_image(
    int sw,
    const hal_qos_auto_pause_watermark_transaction_snapshot *snapshot,
    bool include_auto_owned) {
    fm_status st;

    if (include_auto_owned) {
        st = qos_auto_pause_set_switch_u32(
            sw, FM_QOS_PRIV_WM, 0, snapshot->global_private_wm);
        if (st != FM_OK)
            return st;
        for (int smp = 0;
             smp < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS; smp++) {
            st = qos_auto_pause_set_switch_u32(
                sw, FM_QOS_SHARED_PAUSE_ON_WM, smp,
                snapshot->shared_pause_on_wm[smp]);
            if (st != FM_OK)
                return st;
            st = qos_auto_pause_set_switch_u32(
                sw, FM_QOS_SHARED_PAUSE_OFF_WM, smp,
                snapshot->shared_pause_off_wm[smp]);
            if (st != FM_OK)
                return st;
        }
        for (int priority = 0;
             priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
            st = qos_auto_pause_set_switch_u32(
                sw, FM_QOS_SHARED_PRI_WM, priority,
                snapshot->shared_priority_wm[priority]);
            if (st != FM_OK)
                return st;
        }
    }
    for (int priority = 0;
         priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
        st = qos_auto_pause_set_switch_u32(
            sw, FM_QOS_SHARED_SOFT_DROP_WM, priority,
            snapshot->shared_soft_drop_wm[priority]);
        if (st != FM_OK)
            return st;
        st = qos_auto_pause_set_switch_u32(
            sw, FM_QOS_SHARED_SOFT_DROP_WM_HOG, priority,
            snapshot->shared_soft_drop_hog_wm[priority]);
        if (st != FM_OK)
            return st;
        st = qos_auto_pause_set_switch_u32(
            sw, FM_QOS_SHARED_SOFT_DROP_WM_JITTER, priority,
            snapshot->shared_soft_drop_jitter[priority]);
        if (st != FM_OK)
            return st;
    }
    return FM_OK;
}

int hal_qos_auto_pause_watermark_transaction_restore(
    int sw,
    const hal_qos_auto_pause_watermark_transaction_snapshot *snapshot) {
    hal_qos_auto_pause_watermark_transaction_snapshot readback;
    fm_int cardinal_ports[HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS];
    fm_bool current_auto_pause = FALSE;
    fm_int num_ports = 0;
    fm_status st;

    if (!qos_auto_pause_watermark_snapshot_valid(snapshot))
        return FM_ERR_INVALID_ARGUMENT;

    st = fmGetSwitchQOS((fm_int)sw, FM_AUTO_PAUSE_MODE, 0,
                        &current_auto_pause);
    if (st != FM_OK)
        return (int)st;
    if (current_auto_pause != FALSE && current_auto_pause != TRUE)
        return FM_ERR_INVALID_STATE;
    if ((current_auto_pause == TRUE ? 1U : 0U) !=
        snapshot->auto_pause_mode)
        return FM_ERR_INVALID_STATE;
    st = qos_auto_pause_cardinal_ports_get(
        sw, &num_ports, cardinal_ports);
    if (st != FM_OK)
        return (int)st;
    if ((u32)num_ports != snapshot->num_ports)
        return FM_ERR_INVALID_STATE;
    for (fm_int i = 0; i < num_ports; i++)
        if ((int)cardinal_ports[i] != snapshot->ports[i].port)
            return FM_ERR_INVALID_STATE;

    if (snapshot->auto_pause_mode != 0) {
        fm_bool enabled = TRUE;

        /*
         * Re-run the SDK authority after all calculator inputs have been
         * restored.  Index zero deliberately preserves the current maps.
         */
        st = fmSetSwitchQOS(
            (fm_int)sw, FM_AUTO_PAUSE_MODE, 0, &enabled);
        if (st != FM_OK)
            return (int)st;
    }

    for (u32 i = 0; i < snapshot->num_ports; i++) {
        st = qos_auto_pause_replay_port_image(
            sw, &snapshot->ports[i],
            snapshot->auto_pause_mode == 0);
        if (st != FM_OK)
            return (int)st;
    }
    st = qos_auto_pause_replay_switch_image(
        sw, snapshot, snapshot->auto_pause_mode == 0);
    if (st != FM_OK)
        return (int)st;

    readback = hal_qos_auto_pause_watermark_transaction_snapshot_get(sw);
    if (readback.state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return readback.sdk_status != FM_OK ?
               readback.sdk_status : FM_ERR_INVALID_STATE;
    return hal_qos_auto_pause_watermark_transaction_snapshot_equal(
               snapshot, &readback) ?
           0 : FM_ERR_INVALID_STATE;
}

static hal_qos_watermark_transaction_snapshot
qos_watermark_transaction_read_error(fm_status status) {
    hal_qos_watermark_transaction_snapshot snapshot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = (int)status;
    snapshot.owner_baseline = NETLAB_QOS_UNSUPPORTED;
    snapshot.owner_value = NETLAB_QOS_UNSUPPORTED;
    return snapshot;
}

static bool qos_watermark_value_matches(int attr, int expected, int actual);

static bool qos_watermark_transaction_snapshot_valid(
    int attr,
    const hal_qos_watermark_transaction_snapshot *snapshot) {
    int max_value = qos_watermark_value_max(attr);

    if (!snapshot ||
        snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        snapshot->sdk_status != FM_OK ||
        snapshot->value > (u32)max_value)
        return false;
    if (!snapshot->owner_present)
        return true;
    if (snapshot->owner_value < 0 ||
        snapshot->owner_value > max_value)
        return false;
    if (snapshot->owner_baseline_known)
        return snapshot->owner_baseline >= 0 &&
               snapshot->owner_baseline <= max_value;
    return snapshot->owner_baseline == NETLAB_QOS_UNSUPPORTED;
}

hal_qos_watermark_transaction_snapshot
hal_qos_watermark_transaction_snapshot_get(
    int sw, int port, int attr, int index) {
    hal_qos_watermark_transaction_snapshot snapshot;
    hal_qos_watermark_owner_args args;
    int value = 0;
    fm_status st;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    snapshot.owner_baseline = NETLAB_QOS_UNSUPPORTED;
    snapshot.owner_value = NETLAB_QOS_UNSUPPORTED;
    memset(&args, 0, sizeof(args));
    args.scope = qos_watermark_attr_is_switch(attr) ?
                 HAL_QOS_WATERMARK_SCOPE_SWITCH :
                 HAL_QOS_WATERMARK_SCOPE_PORT;
    args.port = args.scope == HAL_QOS_WATERMARK_SCOPE_SWITCH ? 0 : port;
    args.attr = attr;
    args.index = index;
    args.value = 0;
    if (!qos_watermark_args_valid(&args))
        return snapshot;
    if (qos_watermark_provenance_load() != 0)
        return qos_watermark_transaction_read_error(
            FM_ERR_INVALID_STATE);

    st = qos_watermark_read_value(sw, &args, &value);
    if (st != FM_OK)
        return qos_watermark_transaction_read_error(st);
    snapshot.value = (u32)value;
    qos_watermark_config_state *slot =
        qos_watermark_config_find(args.port, args.attr, args.index);
    if (slot) {
        snapshot.owner_present = true;
        snapshot.owner_baseline_known = slot->baseline_known;
        snapshot.owner_baseline = slot->baseline;
        snapshot.owner_value = slot->value;
    }
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    return snapshot;
}

bool hal_qos_watermark_transaction_snapshot_equal(
    const hal_qos_watermark_transaction_snapshot *left,
    const hal_qos_watermark_transaction_snapshot *right) {
    return left && right &&
        left->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        right->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        left->sdk_status == FM_OK &&
        right->sdk_status == FM_OK &&
        left->value == right->value &&
        left->owner_present == right->owner_present &&
        (!left->owner_present ||
         (left->owner_baseline_known ==
              right->owner_baseline_known &&
          left->owner_baseline == right->owner_baseline &&
          left->owner_value == right->owner_value));
}

hal_qos_watermark_transaction_snapshot
hal_qos_watermark_delete_target_get(
    int sw, int port, int attr, int index) {
    hal_qos_watermark_transaction_snapshot snapshot;
    hal_qos_watermark_owner_args args;
    qos_watermark_config_state *slot;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    snapshot.owner_baseline = NETLAB_QOS_UNSUPPORTED;
    snapshot.owner_value = NETLAB_QOS_UNSUPPORTED;
    memset(&args, 0, sizeof(args));
    args.scope = qos_watermark_attr_is_switch(attr) ?
                 HAL_QOS_WATERMARK_SCOPE_SWITCH :
                 HAL_QOS_WATERMARK_SCOPE_PORT;
    args.port = args.scope == HAL_QOS_WATERMARK_SCOPE_SWITCH ? 0 : port;
    args.attr = attr;
    args.index = index;
    args.value = 0;
    if (!qos_watermark_args_valid(&args))
        return snapshot;
    if (qos_watermark_provenance_load() != 0)
        return qos_watermark_transaction_read_error(
            FM_ERR_INVALID_STATE);

    slot = qos_watermark_config_find(
        args.port, args.attr, args.index);
    if (!slot || !slot->baseline_known)
        return qos_watermark_transaction_read_error(
            FM_ERR_INVALID_STATE);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    snapshot.value = (u32)slot->baseline;
    snapshot.owner_present = true;
    snapshot.owner_baseline_known = true;
    snapshot.owner_baseline = slot->baseline;
    snapshot.owner_value = slot->value;
    (void)sw;
    return snapshot;
}

static int qos_watermark_owner_cache_restore(
    const hal_qos_watermark_owner_args *args,
    const hal_qos_watermark_transaction_snapshot *snapshot) {
    qos_watermark_config_state *slot;

    if (!args || !snapshot)
        return -1;
    slot = qos_watermark_config_find(
        args->port, args->attr, args->index);
    if (!snapshot->owner_present) {
        if (slot)
            memset(slot, 0, sizeof(*slot));
        return qos_watermark_provenance_persist();
    }
    if (!slot)
        slot = qos_watermark_config_slot(
            args->port, args->attr, args->index);
    if (!slot)
        return -1;
    memset(slot, 0, sizeof(*slot));
    slot->active = true;
    slot->baseline_known = snapshot->owner_baseline_known;
    slot->port = args->port;
    slot->attr = args->attr;
    slot->index = args->index;
    slot->baseline = snapshot->owner_baseline;
    slot->value = snapshot->owner_value;
    return qos_watermark_provenance_persist();
}

int hal_qos_watermark_transaction_restore(
    int sw, int port, int attr, int index,
    const hal_qos_watermark_transaction_snapshot *snapshot) {
    hal_qos_watermark_owner_args args;
    int actual = 0;
    fm_status st;

    if (!qos_watermark_transaction_snapshot_valid(attr, snapshot))
        return FM_ERR_INVALID_ARGUMENT;
    memset(&args, 0, sizeof(args));
    args.scope = qos_watermark_attr_is_switch(attr) ?
                 HAL_QOS_WATERMARK_SCOPE_SWITCH :
                 HAL_QOS_WATERMARK_SCOPE_PORT;
    args.port = args.scope == HAL_QOS_WATERMARK_SCOPE_SWITCH ? 0 : port;
    args.attr = attr;
    args.index = index;
    args.value = (int)snapshot->value;
    if (!qos_watermark_args_valid(&args))
        return FM_ERR_INVALID_ARGUMENT;

    st = qos_watermark_write_value(sw, &args, (int)snapshot->value);
    if (st != FM_OK)
        return (int)st;
    st = qos_watermark_read_value(sw, &args, &actual);
    if (st != FM_OK)
        return (int)st;
    if (actual != (int)snapshot->value)
        return FM_ERR_INVALID_STATE;
    return qos_watermark_owner_cache_restore(&args, snapshot) == 0 ?
           0 : FM_ERR_INVALID_STATE;
}

static int qos_watermark_pick_probe_value(int attr, int original) {
    int max_value = qos_watermark_value_max(attr);

    if (original < 0 || original > max_value)
        return -1;
    if (attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER) {
        if (original < max_value)
            return original + 1;
        if (original > 0)
            return original - 1;
        return -1;
    }
    if (attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
        attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE)
        return original ? 0 : 1;
    if (original >= 192)
        return original - 192;
    if (original + 192 <= max_value)
        return original + 192;
    return -1;
}

static int qos_watermark_canonical_value(int attr, int requested) {
    u64 canonical;

    if (requested < 0 ||
        requested > qos_watermark_value_max(attr))
        return NETLAB_QOS_UNSUPPORTED;
    if (attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
        attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
        attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE)
        return requested;

    canonical = ((u64)(u32)requested + UINT64_C(191)) /
                UINT64_C(192) * UINT64_C(192);
    return canonical <= (u64)qos_watermark_value_max(attr) ?
           (int)canonical : NETLAB_QOS_UNSUPPORTED;
}

static bool qos_watermark_value_matches(int attr, int expected, int actual) {
    int canonical = qos_watermark_canonical_value(attr, expected);

    return canonical >= 0 && actual == canonical;
}

static int qos_watermark_write_requested(
    int sw, const hal_qos_watermark_owner_args *args,
    int value, int *actual) {
    fm_status st;
    int readback = NETLAB_QOS_UNSUPPORTED;

    st = qos_watermark_write_value(sw, args, value);
    if (st != FM_OK)
        return (int)st;
    st = qos_watermark_read_value(sw, args, &readback);
    if (st != FM_OK)
        return (int)st;
    if (!qos_watermark_value_matches(args->attr, value, readback))
        return FM_ERR_INVALID_STATE;
    if (actual)
        *actual = readback;
    return 0;
}

static int qos_watermark_current_snapshot_matches(
    int sw, int port, int attr, int index,
    const hal_qos_watermark_transaction_snapshot *snapshot) {
    hal_qos_watermark_transaction_snapshot current =
        hal_qos_watermark_transaction_snapshot_get(
            sw, port, attr, index);

    if (current.state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return current.sdk_status != FM_OK ?
               current.sdk_status : FM_ERR_INVALID_STATE;
    return hal_qos_watermark_transaction_snapshot_equal(
               snapshot, &current) ?
           0 : FM_ERR_INVALID_STATE;
}

static int qos_watermark_auto_pause_enabled(int sw, bool *enabled) {
    fm_bool value = FALSE;
    fm_status st;

    if (!enabled)
        return FM_ERR_INVALID_ARGUMENT;
    st = fmGetSwitchQOS(
        (fm_int)sw, FM_AUTO_PAUSE_MODE, 0, &value);
    if (st != FM_OK)
        return (int)st;
    if (value != FALSE && value != TRUE)
        return FM_ERR_INVALID_STATE;
    *enabled = value == TRUE;
    return 0;
}

int hal_qos_watermark_transaction_apply(
    int sw, int port, int attr, int index, int value,
    bool owner_create, bool calculator_reconciled,
    const hal_qos_watermark_transaction_snapshot *snapshot) {
    hal_qos_watermark_owner_args args;
    qos_watermark_config_state *slot;
    bool auto_pause_enabled = false;
    bool establish_baseline = false;
    int actual = NETLAB_QOS_UNSUPPORTED;
    int status;

    if (!qos_watermark_transaction_snapshot_valid(attr, snapshot) ||
        value < 0)
        return FM_ERR_INVALID_ARGUMENT;
    memset(&args, 0, sizeof(args));
    args.scope = qos_watermark_attr_is_switch(attr) ?
                 HAL_QOS_WATERMARK_SCOPE_SWITCH :
                 HAL_QOS_WATERMARK_SCOPE_PORT;
    args.port = args.scope == HAL_QOS_WATERMARK_SCOPE_SWITCH ? 0 : port;
    args.attr = attr;
    args.index = index;
    args.value = value;
    if (!qos_watermark_args_valid(&args))
        return FM_ERR_INVALID_ARGUMENT;
    status = qos_watermark_current_snapshot_matches(
        sw, port, attr, index, snapshot);
    if (status != 0)
        return status;

    if (calculator_reconciled) {
        status = qos_watermark_auto_pause_enabled(
            sw, &auto_pause_enabled);
        if (status != 0)
            return status;
        if (!auto_pause_enabled)
            return FM_ERR_INVALID_STATE;
    }
    if (owner_create && snapshot->owner_present)
        return FM_ERR_INVALID_STATE;
    if (!snapshot->owner_present) {
        if (!owner_create && !calculator_reconciled)
            return FM_ERR_INVALID_STATE;
        establish_baseline = true;
    } else if (!snapshot->owner_baseline_known) {
        if (!calculator_reconciled)
            return FM_ERR_INVALID_STATE;
        establish_baseline = true;
    }

    status = qos_watermark_write_requested(
        sw, &args, value, &actual);
    if (status != 0) {
        (void)hal_qos_watermark_transaction_restore(
            sw, port, attr, index, snapshot);
        return status;
    }

    slot = qos_watermark_config_find(
        args.port, args.attr, args.index);
    if (!slot)
        slot = qos_watermark_config_slot(
            args.port, args.attr, args.index);
    if (!slot) {
        (void)hal_qos_watermark_transaction_restore(
            sw, port, attr, index, snapshot);
        return FM_ERR_INVALID_STATE;
    }
    memset(slot, 0, sizeof(*slot));
    slot->active = true;
    slot->baseline_known =
        establish_baseline || snapshot->owner_baseline_known;
    slot->port = args.port;
    slot->attr = args.attr;
    slot->index = args.index;
    slot->baseline = establish_baseline ?
        (int)snapshot->value : snapshot->owner_baseline;
    slot->value = actual;
    if (qos_watermark_provenance_persist() != 0) {
        (void)hal_qos_watermark_transaction_restore(
            sw, port, attr, index, snapshot);
        return FM_ERR_INVALID_STATE;
    }
    return 0;
}

int hal_qos_watermark_transaction_delete(
    int sw, int port, int attr, int index,
    bool calculator_reconciled,
    const hal_qos_watermark_transaction_snapshot *snapshot,
    const hal_qos_watermark_transaction_snapshot *target) {
    hal_qos_watermark_owner_args args;
    qos_watermark_config_state *slot;
    bool auto_pause_enabled = false;
    int actual = NETLAB_QOS_UNSUPPORTED;
    int status;

    if (!qos_watermark_transaction_snapshot_valid(attr, snapshot) ||
        !target ||
        target->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        target->value > (u32)qos_watermark_value_max(attr))
        return FM_ERR_INVALID_ARGUMENT;
    memset(&args, 0, sizeof(args));
    args.scope = qos_watermark_attr_is_switch(attr) ?
                 HAL_QOS_WATERMARK_SCOPE_SWITCH :
                 HAL_QOS_WATERMARK_SCOPE_PORT;
    args.port = args.scope == HAL_QOS_WATERMARK_SCOPE_SWITCH ? 0 : port;
    args.attr = attr;
    args.index = index;
    args.value = 0;
    if (!qos_watermark_args_valid(&args))
        return FM_ERR_INVALID_ARGUMENT;
    status = qos_watermark_current_snapshot_matches(
        sw, port, attr, index, snapshot);
    if (status != 0)
        return status;

    if (calculator_reconciled) {
        status = qos_watermark_auto_pause_enabled(
            sw, &auto_pause_enabled);
        if (status != 0)
            return status;
        if (!auto_pause_enabled ||
            target->value != snapshot->value)
            return FM_ERR_INVALID_STATE;
        status = qos_watermark_read_value(sw, &args, &actual);
        if (status != FM_OK)
            return status;
        if (actual != (int)target->value)
            return FM_ERR_INVALID_STATE;
    } else {
        if (!snapshot->owner_present ||
            !snapshot->owner_baseline_known ||
            target->value != (u32)snapshot->owner_baseline)
            return FM_ERR_INVALID_STATE;
        status = qos_watermark_write_value(
            sw, &args, (int)target->value);
        if (status != FM_OK)
            return status;
        status = qos_watermark_read_value(sw, &args, &actual);
        if (status != FM_OK ||
            actual != (int)target->value) {
            (void)hal_qos_watermark_transaction_restore(
                sw, port, attr, index, snapshot);
            return status != FM_OK ?
                   status : FM_ERR_INVALID_STATE;
        }
    }

    slot = qos_watermark_config_find(
        args.port, args.attr, args.index);
    if (slot)
        memset(slot, 0, sizeof(*slot));
    if (qos_watermark_provenance_persist() != 0) {
        (void)hal_qos_watermark_transaction_restore(
            sw, port, attr, index, snapshot);
        return FM_ERR_INVALID_STATE;
    }
    return 0;
}

int hal_qos_watermark_read(int sw, int port, int attr, int index,
                           int *value) {
    hal_qos_watermark_owner_args args;

    if (!value)
        return -1;
    memset(&args, 0, sizeof(args));
    args.scope = qos_watermark_attr_is_switch(attr) ?
                 HAL_QOS_WATERMARK_SCOPE_SWITCH :
                 HAL_QOS_WATERMARK_SCOPE_PORT;
    args.port = args.scope == HAL_QOS_WATERMARK_SCOPE_SWITCH ? 0 : port;
    args.attr = attr;
    args.index = index;
    args.value = 0;
    if (!qos_watermark_args_valid(&args))
        return -1;
    return qos_watermark_read_value(sw, &args, value) == FM_OK ? 0 : -1;
}

int hal_qos_watermark_set(int sw, int port, int attr, int index, int value) {
    hal_qos_watermark_owner_args args;
    hal_qos_watermark_transaction_snapshot before;
    qos_watermark_config_state *slot;
    int actual = NETLAB_QOS_UNSUPPORTED;
    int status;

    memset(&args, 0, sizeof(args));
    args.scope = qos_watermark_attr_is_switch(attr) ?
                 HAL_QOS_WATERMARK_SCOPE_SWITCH :
                 HAL_QOS_WATERMARK_SCOPE_PORT;
    if (args.scope == HAL_QOS_WATERMARK_SCOPE_SWITCH)
        port = 0;
    args.port = port;
    args.attr = attr;
    args.index = index;
    args.value = value;
    if (!qos_watermark_args_valid(&args) || value < 0)
        return -1;
    before = hal_qos_watermark_transaction_snapshot_get(
        sw, port, attr, index);
    if (before.state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return before.sdk_status != FM_OK ?
               before.sdk_status : FM_ERR_INVALID_STATE;
    slot = qos_watermark_config_slot(port, attr, index);
    if (!slot)
        return -1;
    status = qos_watermark_write_requested(
        sw, &args, value, &actual);
    if (status != 0) {
        NL_LOG_ERR("qos-watermark port=%d attr=%d index=%d set failed: %s",
                   port, attr, index,
                   fmErrorMsg((fm_status)status));
        (void)hal_qos_watermark_transaction_restore(
            sw, port, attr, index, &before);
        return status;
    }
    memset(slot, 0, sizeof(*slot));
    slot->active = true;
    slot->baseline_known =
        before.owner_present && before.owner_baseline_known;
    slot->port = port;
    slot->attr = attr;
    slot->index = index;
    slot->baseline = slot->baseline_known ?
        before.owner_baseline : NETLAB_QOS_UNSUPPORTED;
    slot->value = actual;
    if (qos_watermark_provenance_persist() != 0) {
        (void)hal_qos_watermark_transaction_restore(
            sw, port, attr, index, &before);
        return FM_ERR_INVALID_STATE;
    }
    return 0;
}

int hal_qos_watermark_delete(int sw, int port, int attr, int index) {
    hal_qos_watermark_transaction_snapshot before =
        hal_qos_watermark_transaction_snapshot_get(
            sw, port, attr, index);
    hal_qos_watermark_transaction_snapshot target =
        hal_qos_watermark_delete_target_get(
            sw, port, attr, index);

    if (before.state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        target.state != HAL_TRANSACTION_SNAPSHOT_PRESENT) {
        NL_LOG_ERR("qos-watermark port=%d attr=%d index=%d delete has no trustworthy baseline",
                   port, attr, index);
        return FM_ERR_INVALID_STATE;
    }
    return hal_qos_watermark_transaction_delete(
        sw, port, attr, index, false, &before, &target);
}

int hal_qos_watermark_owner_apply(
    int sw,
    const hal_qos_watermark_owner_args *args,
    hal_qos_watermark_owner_result *result) {
    fm_status st;
    int original = NETLAB_QOS_UNSUPPORTED;
    int target;
    int actual = NETLAB_QOS_UNSUPPORTED;

    qos_watermark_owner_init_result(result, args);
    if (!args || !result)
        return -1;
    if (!qos_watermark_args_valid(args)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid watermark owner arguments");
        return -1;
    }
    if (g_qos_watermark_owner.active) {
        result->active = true;
        snprintf(result->detail, sizeof(result->detail),
                 "watermark owner already active");
        return -1;
    }

    st = qos_watermark_read_value(sw, args, &original);
    result->pre_read_status = (int)st;
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "watermark pre-read failed: %s", fmErrorMsg(st));
        return (int)st;
    }
    result->original_value = original;

    target = args->value >= 0 ?
             args->value : qos_watermark_pick_probe_value(args->attr,
                                                          original);
    if (target < 0 || target > qos_watermark_value_max(args->attr) ||
        target == original) {
        snprintf(result->detail, sizeof(result->detail),
                 "unable to choose safe watermark probe value");
        return -1;
    }
    result->requested_value = target;

    st = qos_watermark_write_value(sw, args, target);
    result->set_status = (int)st;
    if (st != FM_OK) {
        (void)qos_watermark_read_value(sw, args, &actual);
        result->current_value = actual;
        snprintf(result->detail, sizeof(result->detail),
                 "watermark set failed: %s", fmErrorMsg(st));
        return (int)st;
    }

    st = qos_watermark_read_value(sw, args, &actual);
    result->read_status = (int)st;
    result->current_value = actual;
    result->applied_value = actual;
    result->compared = 1;
    if (st != FM_OK ||
        !qos_watermark_value_matches(args->attr, target, actual)) {
        result->mismatches = 1;
        result->rollback_status =
            (int)qos_watermark_write_value(sw, args, original);
        snprintf(result->detail, sizeof(result->detail),
                 "watermark owner read-back mismatch");
        return (int)FM_ERR_INVALID_VALUE;
    }

    g_qos_watermark_owner.active = true;
    g_qos_watermark_owner.args = *args;
    g_qos_watermark_owner.original_value = original;
    g_qos_watermark_owner.requested_value = target;
    result->active = true;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS watermark owner applied and verified");
    return 0;
}

int hal_qos_watermark_owner_readback(
    int sw,
    hal_qos_watermark_owner_result *result) {
    const hal_qos_watermark_owner_args *args;
    fm_status st;
    int actual = NETLAB_QOS_UNSUPPORTED;

    args = g_qos_watermark_owner.active ?
           &g_qos_watermark_owner.args : NULL;
    qos_watermark_owner_init_result(result, args);
    if (!result)
        return -1;
    if (!g_qos_watermark_owner.active) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no active watermark owner");
        return 0;
    }

    result->active = true;
    result->original_value = g_qos_watermark_owner.original_value;
    result->requested_value = g_qos_watermark_owner.requested_value;
    st = qos_watermark_read_value(sw, args, &actual);
    result->read_status = (int)st;
    result->current_value = actual;
    result->applied_value = actual;
    result->compared = 1;
    if (st != FM_OK ||
        !qos_watermark_value_matches(args->attr,
                                     g_qos_watermark_owner.requested_value,
                                     actual)) {
        result->mismatches = 1;
        snprintf(result->detail, sizeof(result->detail),
                 "watermark owner read-back mismatch");
        return -1;
    }

    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS watermark owner read-back verified");
    return 0;
}

int hal_qos_watermark_owner_rollback(
    int sw,
    hal_qos_watermark_owner_result *result) {
    hal_qos_watermark_owner_args args;
    fm_status st;
    int actual = NETLAB_QOS_UNSUPPORTED;
    int original;

    if (g_qos_watermark_owner.active)
        args = g_qos_watermark_owner.args;
    else
        memset(&args, 0, sizeof(args));
    qos_watermark_owner_init_result(
        result, g_qos_watermark_owner.active ? &args : NULL);
    if (!result)
        return -1;
    if (!g_qos_watermark_owner.active) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no active watermark owner");
        return 0;
    }

    original = g_qos_watermark_owner.original_value;
    result->active = true;
    result->original_value = original;
    result->requested_value = g_qos_watermark_owner.requested_value;
    st = qos_watermark_write_value(sw, &args, original);
    result->rollback_status = (int)st;
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "watermark owner rollback failed: %s", fmErrorMsg(st));
        return (int)st;
    }

    st = qos_watermark_read_value(sw, &args, &actual);
    result->post_read_status = (int)st;
    result->current_value = actual;
    result->compared = 1;
    if (st != FM_OK ||
        !qos_watermark_value_matches(args.attr, original, actual)) {
        result->mismatches = 1;
        snprintf(result->detail, sizeof(result->detail),
                 "watermark owner rollback read-back mismatch");
        return -1;
    }

    g_qos_watermark_owner.active = false;
    memset(&g_qos_watermark_owner, 0, sizeof(g_qos_watermark_owner));
    result->active = false;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "QoS watermark owner rolled back and verified");
    return 0;
}

/* Read actual ASIC state before authorizing the static lossless class.
 * The pinned mixed profile reserves 49152 bytes per cardinal port. */
int hal_qos_roce_buffer_ready(int sw) {
    fm_int ports[HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS], count = 0;
    fm_bool automatic = FALSE;
    fm_uint32 global = 0, on = 0, off = 0;
    fm_int max_frame = 0;
    fm_status st = fmGetSwitchQOS(sw, FM_AUTO_PAUSE_MODE, 0, &automatic);
    if (st != FM_OK) return st;
    if (!automatic) return FM_ERR_INVALID_STATE;
    st = qos_auto_pause_cardinal_ports_get(sw, &count, ports);
    if (st != FM_OK) return st;
    if (count > 30) return FM_ERR_INVALID_STATE;
    /* Use the same eight-entry VLAN MTU table as IES SetAutoPauseMode.
     * CPU/TE ports are cardinal ports too, but do not all expose EPL attrs. */
    for (int i = 0; i < 8; i++) {
        fm_mtuEntry entry = {.index = i};
        st = fmGetSwitchAttribute(sw, FM_MTU_LIST, &entry);
        if (st != FM_OK) return st;
        if (entry.mtu > 16384) return FM_ERR_INVALID_STATE;
        if ((fm_int)entry.mtu > max_frame) max_frame = (fm_int)entry.mtu;
    }
    if (max_frame <= 0) return FM_ERR_INVALID_STATE;
    st = fmGetSwitchQOS(sw, FM_QOS_PRIV_WM, 0, &global);
    if (st != FM_OK) return st;
    st = fmGetSwitchQOS(sw, FM_QOS_SHARED_PAUSE_ON_WM, 1, &on);
    if (st != FM_OK) return st;
    st = fmGetSwitchQOS(sw, FM_QOS_SHARED_PAUSE_OFF_WM, 1, &off);
    if (st != FM_OK) return st;
    u64 reserve = (u64)count * (49152U + (u32)max_frame);
    if (reserve + 192 >= global / 2 || !off || off >= on ||
        on > global / 2 - reserve + 192) return FM_ERR_INVALID_STATE;
    return FM_OK;
}

int hal_qos_tc_smp_get(int sw, int tc, int *smp) {
    fm_uint32 value = 0;
    if (!smp || tc < 0 || tc > 7) return FM_ERR_INVALID_ARGUMENT;
    fm_status st = fmGetSwitchQOS(sw, FM_QOS_TC_SMP_MAP, tc, &value);
    if (st != FM_OK) return st;
    if (value != FM_QOS_TC_SMP_0 && value != FM_QOS_TC_SMP_1)
        return FM_ERR_INVALID_STATE;
    *smp = value == FM_QOS_TC_SMP_1 ? 1 : 0;
    return FM_OK;
}

int hal_qos_tc_smp_set(int sw, int tc, int smp) {
    int actual = -1;
    if (tc < 0 || tc > 7 || smp < 0 || smp > 1) return FM_ERR_INVALID_ARGUMENT;
    if (smp) {
        int status = hal_qos_roce_buffer_ready(sw);
        if (status) return status;
    }
    fm_uint32 value = smp ? FM_QOS_TC_SMP_1 : FM_QOS_TC_SMP_0;
    fm_status st = fmSetSwitchQOS(sw, FM_QOS_TC_SMP_MAP, tc, &value);
    if (st != FM_OK) return st; /* transaction owns compensation, even after partial writes */
    st = hal_qos_tc_smp_get(sw, tc, &actual);
    if (st != FM_OK) return st;
    if (actual != smp) return FM_ERR_INVALID_STATE;
    return smp ? hal_qos_roce_buffer_ready(sw) : FM_OK;
}

int hal_qos_pfc_pc3_smp_set(int sw, int port, int smp) {
    if (sw != 0 || port <= 0 || !nl_ifid_is_user_port(port) || smp < 0 || smp > 2)
        return FM_ERR_INVALID_ARGUMENT;
    fm_uint32 value = (fm_uint32)smp, actual = 3;
    fm_status st = fmSetPortQOS(sw, port, FM_QOS_PC_RXMP_MAP, 3, &value);
    if (st != FM_OK) return st; /* The transaction restores partial writes. */
    st = fmGetPortQOS(sw, port, FM_QOS_PC_RXMP_MAP, 3, &actual);
    return st != FM_OK ? st : actual == value ? FM_OK : FM_ERR_INVALID_STATE;
}

int hal_qos_pfc_apply(int sw, int port, int rx_class_mask,
                      int tx_pause_mode, int tx_class_mask,
                      int lossless_smp_mask, int shared_pause_mask) {
    fm_uint32 value;
    fm_status st;

    if (port <= 0 || !nl_ifid_is_user_port(port) ||
        rx_class_mask < 0 || rx_class_mask > 0xff ||
        tx_class_mask < 0 || tx_class_mask > 0xff ||
        (tx_pause_mode != FM_PORT_TX_PAUSE_NORMAL &&
         tx_pause_mode != FM_PORT_TX_PAUSE_CLASS_BASED) ||
        lossless_smp_mask < 0 || lossless_smp_mask > FM_PORT_SMP_ALL ||
        shared_pause_mask < 0 || shared_pause_mask > FM_PORT_SMP_ALL)
        return -1;

    if (lossless_smp_mask == 2) {
        int ready = hal_qos_roce_buffer_ready(sw), smp = -1;
        fm_uint32 pc = 0;
        if (ready) return ready;
        ready = hal_qos_tc_smp_get(sw, 3, &smp);
        if (ready) return ready;
        if (smp != 1) return FM_ERR_INVALID_STATE;
        ready = fmGetPortQOS(sw, port, FM_QOS_TC_PC_MAP, 3, &pc);
        if (ready) return ready;
        if (pc != 3) return FM_ERR_INVALID_STATE;
    }

    value = (fm_uint32)rx_class_mask;
    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_RX_CLASS_PAUSE, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("qos pfc port=%d set rx class mask failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    value = (fm_uint32)tx_class_mask;
    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_TX_CLASS_PAUSE, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("qos pfc port=%d set tx class mask failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    value = (fm_uint32)tx_pause_mode;
    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_TX_PAUSE_MODE, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("qos pfc port=%d set tx pause mode failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    value = (fm_uint32)lossless_smp_mask;
    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SMP_LOSSLESS_PAUSE, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("qos pfc port=%d set lossless SMP mask failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    value = (fm_uint32)shared_pause_mask;
    st = fmSetPortQOS((fm_int)sw, (fm_int)port,
                      FM_QOS_SHARED_PAUSE_ENABLE, 0, &value);
    if (st != FM_OK) {
        NL_LOG_ERR("qos pfc port=%d set shared pause mask failed: %s",
                   port, fmErrorMsg(st));
        return (int)st;
    }

    NL_LOG_INFO("qos pfc port=%d rx=0x%02x tx-mode=%d tx=0x%02x "
                "lossless-smp=0x%02x shared=0x%02x",
                port, rx_class_mask, tx_pause_mode, tx_class_mask,
                lossless_smp_mask, shared_pause_mask);
    /* CM_TC_PC_MAP controls received pause frames. Transmitted PFC needs the
     * separate CM_PC_SMP_MAP (FM10000 datasheet 11.20.2.16). The mixed lossy/
     * lossless SDK profile initializes every pause class to 2 = always OFF.
     * Configure this after automatic watermark updates, using the supported
     * API. Only priority 3 is owned by this fixed RoCE profile. */
    return hal_qos_pfc_pc3_smp_set(sw, port, lossless_smp_mask == 2 ? 1 : 2);
}

int hal_qos_pfc_delete(int sw, int port) {
    return hal_qos_pfc_apply(sw, port, 0, FM_PORT_TX_PAUSE_NORMAL,
                             0xff, 0, 0);
}
