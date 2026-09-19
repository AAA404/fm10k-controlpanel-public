/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/error.h"
#include "netlab/hal.h"
#include "../../sbin/switchd/fm10k_lag.h"
#include "watchdog_disabled_fixture.h"

bool fm10k_native_profile(void) { return false; }
bool fm10k_native_aux_port(int sw, int port) { (void)sw; (void)port; return false; }
int hal_fm10k_lag_member_set(int sw, int lag, int port, bool attached) {
    (void)sw; (void)lag; (void)port; (void)attached; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_members_status(int lag, const int *members, int count) {
    (void)lag; (void)members; (void)count; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_restore_port(int sw, int lag, int port, uint64_t tx) {
    (void)sw; (void)lag; (void)port; (void)tx; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_transaction_check(uint64_t tx, bool committed) {
    (void)tx; (void)committed; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
void hal_fm10k_lag_transaction_retire(uint64_t tx) { (void)tx; }
int hal_fm10k_lag_del_port_transaction(int sw, int lag, int port, uint64_t tx) {
    (void)sw; (void)lag; (void)port; (void)tx; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_attributes_capture(int sw, int lag, fm10k_lag_attributes *out) {
    (void)sw; (void)lag; (void)out; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_attributes_restore(int sw, int lag, const fm10k_lag_attributes *before) {
    (void)sw; (void)lag; (void)before; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
hal_qos_interface_transaction_snapshot hal_fm10k_lag_qos_snapshot(int sw, int lag) {
    (void)sw; (void)lag;
    return (hal_qos_interface_transaction_snapshot){.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR,
                                                   .sdk_status = NL_ERR_CAPABILITY_INSUFFICIENT};
}
int hal_fm10k_lag_qos_restore(int sw, int lag, const hal_qos_interface_transaction_snapshot *before) {
    (void)sw; (void)lag; (void)before; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_qos_set(int sw, int lag, int trust, int priority) {
    (void)sw; (void)lag; (void)trust; (void)priority; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
int hal_fm10k_lag_qos_get(int sw, int lag, hal_qos_interface_entry *out) {
    (void)sw; (void)lag; (void)out; return NL_ERR_CAPABILITY_INSUFFICIENT;
}
#include "netlab/hal_l2_flow_snapshot.h"
#include "netlab/log.h"

#include <fm_sdk.h>
#include <api/fm_api_addr.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_lag.h>
#include <api/fm_api_vlan.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIM_MAX_VLANS 24
#define SIM_MAX_MEMBERS 24
#define SIM_MAX_LAGS 24
#define SIM_MAX_MACS 96
#define SIM_DEFAULT_STP 1
#define SIM_HASH_ROTATION_A 0
#define SIM_HASH_ROTATION_B 1
#define SIM_QOS_PORT 7
#define SIM_QOS_WATERMARK_COUNT 2

typedef struct {
    int port;
    bool tagged;
    int stp;
} sim_vlan_member;

typedef struct {
    bool used;
    u16 vid;
    int n_members;
    sim_vlan_member members[SIM_MAX_MEMBERS];
} sim_vlan;

typedef struct {
    bool used;
    int id;
    int logical_port;
    int hash_rotation;
    fm_uint32 lacp_disposition;
    int n_members;
    int members[SIM_MAX_MEMBERS];
} sim_lag;

typedef struct {
    bool used;
    fm_macAddressEntry entry;
} sim_mac;

typedef enum {
    SIM_FAULT_NONE,
    SIM_FAULT_VLAN_FIRST,
    SIM_FAULT_VLAN_NEXT,
    SIM_FAULT_VLAN_PORT_NEXT,
    SIM_FAULT_VLAN_TAG,
    SIM_FAULT_VLAN_STP,
    SIM_FAULT_ADDRESS_READ,
    SIM_FAULT_LAG_NEXT,
    SIM_FAULT_LAG_LIST,
    SIM_FAULT_LAG_ATTRIBUTE,
    SIM_FAULT_LAG_TO_LOGICAL,
    SIM_FAULT_LAG_HASH_READ,
} sim_fault;

static sim_vlan g_vlans[SIM_MAX_VLANS];
static sim_lag g_lags[SIM_MAX_LAGS];
static sim_mac g_macs[SIM_MAX_MACS];
static sim_fault g_fault;
static int g_next_lag_id;
static int g_write_calls;
static int g_lag_create_calls;
static int g_lag_create_fail_without_mutation;
static int g_lag_create_fail_after_mutation;
static int g_lag_post_create_enum_failures;
static bool g_lag_post_create_enum_fault_armed;
static int g_lag_create_remove_foreign_id;
static int g_lag_create_extra_additions;
static int g_lag_delete_fail_after_mutation;
static int g_hash_set_failures;
static int g_failures;
static bool g_trace_logs;
static bool g_security_table_present;
static bool g_security_dhcp_present;
static u16 g_security_dhcp_vid;
static int g_security_dhcp_port;
static bool g_security_ingress_present;
static hal_ingress_ipv4_acl_match g_security_ingress_match;
static hal_flow_table_creation_token g_security_pending_token;
static u64 g_security_next_generation;
static u64 g_security_active_generation;
static int g_security_release_failures;
static int g_security_set_failures;
static int g_security_create_calls;
static int g_security_release_calls;
static int g_qos_priority_map[HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
static int g_qos_tc_smp[8], g_smp_writes, g_smp_fail_after, g_smp_restore_fail, g_smp_drop;
static u32 g_qos_watermark[SIM_QOS_WATERMARK_COUNT];
static bool g_qos_owner_present[SIM_QOS_WATERMARK_COUNT];
static bool g_qos_owner_baseline_known[SIM_QOS_WATERMARK_COUNT];
static int g_qos_owner_baseline[SIM_QOS_WATERMARK_COUNT];
static int g_qos_owner_value[SIM_QOS_WATERMARK_COUNT];
static u32 g_qos_calculated_watermark[SIM_QOS_WATERMARK_COUNT];
static int g_qos_shared_snapshot_calls;
static int g_qos_shared_pre_mutation_snapshots;
static int g_qos_shared_restore_calls;
static int g_qos_event;
static int g_qos_last_trigger_event;
static int g_qos_last_direct_restore_event;
static int g_qos_shared_restore_event;
static int g_qos_apply_failures;
static bool g_qos_mutation_started;
static bool g_qos_auto_pause_mode;

static void expect(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        g_failures++;
}

static sim_vlan *find_vlan(u16 vid) {
    for (int i = 0; i < SIM_MAX_VLANS; i++)
        if (g_vlans[i].used && g_vlans[i].vid == vid)
            return &g_vlans[i];
    return NULL;
}

static sim_vlan *seed_vlan(u16 vid) {
    sim_vlan *vlan = find_vlan(vid);

    if (vlan)
        return vlan;
    for (int i = 0; i < SIM_MAX_VLANS; i++) {
        if (g_vlans[i].used)
            continue;
        memset(&g_vlans[i], 0, sizeof(g_vlans[i]));
        g_vlans[i].used = true;
        g_vlans[i].vid = vid;
        return &g_vlans[i];
    }
    return NULL;
}

static sim_vlan_member *find_vlan_member(sim_vlan *vlan, int port) {
    if (!vlan)
        return NULL;
    for (int i = 0; i < vlan->n_members; i++)
        if (vlan->members[i].port == port)
            return &vlan->members[i];
    return NULL;
}

static bool seed_vlan_member(u16 vid, int port, bool tagged, int stp) {
    sim_vlan *vlan = seed_vlan(vid);
    sim_vlan_member *member;

    if (!vlan)
        return false;
    member = find_vlan_member(vlan, port);
    if (!member) {
        if (vlan->n_members >= SIM_MAX_MEMBERS)
            return false;
        member = &vlan->members[vlan->n_members++];
    }
    member->port = port;
    member->tagged = tagged;
    member->stp = stp;
    return true;
}

static sim_lag *find_lag(int lag_id) {
    for (int i = 0; i < SIM_MAX_LAGS; i++)
        if (g_lags[i].used && g_lags[i].id == lag_id)
            return &g_lags[i];
    return NULL;
}

static sim_lag *allocate_lag(int lag_id) {
    for (int i = 0; i < SIM_MAX_LAGS; i++) {
        if (g_lags[i].used)
            continue;
        memset(&g_lags[i], 0, sizeof(g_lags[i]));
        g_lags[i].used = true;
        g_lags[i].id = lag_id;
        g_lags[i].logical_port = 1000 + lag_id;
        g_lags[i].hash_rotation = SIM_HASH_ROTATION_A;
        g_lags[i].lacp_disposition = FM_PDU_TOCPU;
        return &g_lags[i];
    }
    return NULL;
}

static bool lag_has_member(const sim_lag *lag, int port) {
    if (!lag)
        return false;
    for (int i = 0; i < lag->n_members; i++)
        if (lag->members[i] == port)
            return true;
    return false;
}

static bool seed_lag_member(sim_lag *lag, int port) {
    if (!lag)
        return false;
    if (lag_has_member(lag, port))
        return true;
    if (lag->n_members >= SIM_MAX_MEMBERS)
        return false;
    lag->members[lag->n_members++] = port;
    return true;
}

static fm_macaddr mac_to_u64(const u8 mac[6]) {
    fm_macaddr value = 0;

    for (int i = 0; i < 6; i++)
        value = (value << 8) | mac[i];
    return value;
}

static sim_mac *find_mac(u16 vid, fm_macaddr mac) {
    for (int i = 0; i < SIM_MAX_MACS; i++) {
        if (g_macs[i].used &&
            (u16)g_macs[i].entry.vlanID == vid &&
            g_macs[i].entry.macAddress == mac)
            return &g_macs[i];
    }
    return NULL;
}

static bool seed_mac(u16 vid, const u8 mac[6], int port, int type) {
    sim_mac *slot = find_mac(vid, mac_to_u64(mac));

    if (!slot) {
        for (int i = 0; i < SIM_MAX_MACS; i++) {
            if (g_macs[i].used)
                continue;
            slot = &g_macs[i];
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
            break;
        }
    }
    if (!slot)
        return false;
    memset(&slot->entry, 0, sizeof(slot->entry));
    slot->entry.macAddress = mac_to_u64(mac);
    slot->entry.vlanID = (fm_uint16)vid;
    slot->entry.port = (fm_int)port;
    slot->entry.type = (fm_int)type;
    slot->entry.destMask = FM_DESTMASK_UNUSED;
    return true;
}

static void flush_macs_for_vlan_port(u16 vid, int port) {
    for (int i = 0; i < SIM_MAX_MACS; i++) {
        if (g_macs[i].used &&
            (u16)g_macs[i].entry.vlanID == vid &&
            (int)g_macs[i].entry.port == port)
            g_macs[i].used = false;
    }
}

static void flush_macs_for_vlan(u16 vid) {
    for (int i = 0; i < SIM_MAX_MACS; i++)
        if (g_macs[i].used &&
            (u16)g_macs[i].entry.vlanID == vid)
            g_macs[i].used = false;
}

static int count_vlan_macs(u16 vid) {
    int count = 0;

    for (int i = 0; i < SIM_MAX_MACS; i++)
        if (g_macs[i].used &&
            (u16)g_macs[i].entry.vlanID == vid)
            count++;
    return count;
}

static int count_lags(void) {
    int count = 0;

    for (int i = 0; i < SIM_MAX_LAGS; i++)
        if (g_lags[i].used)
            count++;
    return count;
}

static void reset_simulator(void) {
    memset(g_qos_tc_smp, 0, sizeof(g_qos_tc_smp));
    g_smp_writes = g_smp_fail_after = g_smp_restore_fail = g_smp_drop = 0;
    memset(g_vlans, 0, sizeof(g_vlans));
    memset(g_lags, 0, sizeof(g_lags));
    memset(g_macs, 0, sizeof(g_macs));
    g_fault = SIM_FAULT_NONE;
    g_next_lag_id = 10;
    g_write_calls = 0;
    g_lag_create_calls = 0;
    g_lag_create_fail_without_mutation = 0;
    g_lag_create_fail_after_mutation = 0;
    g_lag_post_create_enum_failures = 0;
    g_lag_post_create_enum_fault_armed = false;
    g_lag_create_remove_foreign_id = 0;
    g_lag_create_extra_additions = 0;
    g_lag_delete_fail_after_mutation = 0;
    g_hash_set_failures = 0;
    g_security_table_present = false;
    g_security_dhcp_present = false;
    g_security_dhcp_vid = 0;
    g_security_dhcp_port = 0;
    g_security_ingress_present = false;
    memset(&g_security_ingress_match, 0,
           sizeof(g_security_ingress_match));
    memset(&g_security_pending_token, 0,
           sizeof(g_security_pending_token));
    g_security_pending_token.sw = -1;
    g_security_pending_token.table = -1;
    g_security_next_generation = 1;
    g_security_active_generation = 0;
    g_security_release_failures = 0;
    g_security_set_failures = 0;
    g_security_create_calls = 0;
    g_security_release_calls = 0;
    for (int priority = 0;
         priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++)
        g_qos_priority_map[priority] = priority & 7;
    for (int index = 0; index < SIM_QOS_WATERMARK_COUNT; index++) {
        g_qos_watermark[index] = 192U * (u32)(100 + index);
        g_qos_calculated_watermark[index] =
            192U * (u32)(80 + index);
        g_qos_owner_present[index] = true;
        g_qos_owner_baseline_known[index] = true;
        g_qos_owner_baseline[index] = (int)g_qos_watermark[index] - 192;
        g_qos_owner_value[index] = (int)g_qos_watermark[index];
    }
    g_qos_shared_snapshot_calls = 0;
    g_qos_shared_pre_mutation_snapshots = 0;
    g_qos_shared_restore_calls = 0;
    g_qos_event = 0;
    g_qos_last_trigger_event = 0;
    g_qos_last_direct_restore_event = 0;
    g_qos_shared_restore_event = 0;
    g_qos_apply_failures = 0;
    g_qos_mutation_started = false;
    g_qos_auto_pause_mode = true;
}

static l2_apply_plan *new_plan(int n_steps, u64 tx_id) {
    l2_apply_plan *plan = calloc(1, sizeof(*plan));

    if (!plan)
        return NULL;
    l2_apply_plan_init(plan);
    if (l2_apply_plan_allocate_steps(plan, n_steps) != 0) {
        free(plan);
        return NULL;
    }
    plan->n_steps = n_steps;
    plan->tx_id = tx_id;
    for (int i = 0; i < n_steps; i++) {
        plan->steps[i].ae_id = -1;
        plan->steps[i].pre_mac_ae_id = -1;
    }
    return plan;
}

static void free_plan(l2_apply_plan *plan) {
    if (!plan)
        return;
    l2_apply_plan_reset(plan);
    free((void *)plan);
}

static int apply_plan(l2_apply_plan *plan) {
    struct sdk_result results[8];

    memset(results, 0, sizeof(results));
    return hal_apply_l2_plan(0, plan, results, 8);
}

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) {
    va_list args;

    if (!g_trace_logs || level > NL_LOG_ERR)
        return;
    fprintf(stderr, "TRACE:%s:%d: ", file, line);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

const char *fmErrorMsg(fm_int error) {
    (void)error;
    return "mock FM status";
}

fm_status fmGetVlanFirst(fm_int sw, fm_int *first_id) {
    int first = 0;

    (void)sw;
    if (g_fault == SIM_FAULT_VLAN_FIRST)
        return FM_FAIL;
    for (int i = 0; i < SIM_MAX_VLANS; i++) {
        if (!g_vlans[i].used)
            continue;
        if (first == 0 || g_vlans[i].vid < first)
            first = g_vlans[i].vid;
    }
    *first_id = first == 0 ? -1 : first;
    return FM_OK;
}

fm_status fmGetVlanNext(fm_int sw, fm_int start_id, fm_int *next_id) {
    int next = 0;

    (void)sw;
    if (g_fault == SIM_FAULT_VLAN_NEXT)
        return FM_FAIL;
    for (int i = 0; i < SIM_MAX_VLANS; i++) {
        if (!g_vlans[i].used || g_vlans[i].vid <= start_id)
            continue;
        if (next == 0 || g_vlans[i].vid < next)
            next = g_vlans[i].vid;
    }
    *next_id = next == 0 ? -1 : next;
    return FM_OK;
}

fm_status fmCreateVlan(fm_int sw, fm_uint16 vid) {
    (void)sw;
    g_write_calls++;
    if (find_vlan((u16)vid))
        return FM_ERR_VLAN_ALREADY_EXISTS;
    return seed_vlan((u16)vid) ? FM_OK : FM_FAIL;
}

fm_status fmDeleteVlan(fm_int sw, fm_uint16 vid) {
    sim_vlan *vlan = find_vlan((u16)vid);

    (void)sw;
    g_write_calls++;
    if (!vlan)
        return FM_ERR_INVALID_VLAN;
    vlan->used = false;
    vlan->n_members = 0;
    flush_macs_for_vlan((u16)vid);
    return FM_OK;
}

fm_status fmGetVlanPortFirst(fm_int sw, fm_int vid, fm_int *first_port) {
    sim_vlan *vlan = find_vlan((u16)vid);
    int first = 0;

    (void)sw;
    if (!vlan)
        return FM_ERR_INVALID_VLAN;
    for (int i = 0; i < vlan->n_members; i++) {
        if (first == 0 || vlan->members[i].port < first)
            first = vlan->members[i].port;
    }
    *first_port = first == 0 ? -1 : first;
    return FM_OK;
}

fm_status fmGetVlanPortNext(fm_int sw, fm_int vid, fm_int start_port,
                            fm_int *next_port) {
    sim_vlan *vlan = find_vlan((u16)vid);
    int next = 0;

    (void)sw;
    if (!vlan)
        return FM_ERR_INVALID_VLAN;
    if (g_fault == SIM_FAULT_VLAN_PORT_NEXT)
        return FM_FAIL;
    for (int i = 0; i < vlan->n_members; i++) {
        int port = vlan->members[i].port;
        if (port <= start_port)
            continue;
        if (next == 0 || port < next)
            next = port;
    }
    *next_port = next == 0 ? -1 : next;
    return FM_OK;
}

fm_status fmGetVlanPortTag(fm_int sw, fm_int vid, fm_int port,
                           fm_bool *tagged) {
    sim_vlan *vlan = find_vlan((u16)vid);
    sim_vlan_member *member;

    (void)sw;
    if (g_fault == SIM_FAULT_VLAN_TAG)
        return FM_FAIL;
    if (!vlan)
        return FM_ERR_INVALID_VLAN;
    member = find_vlan_member(vlan, port);
    if (!member)
        return FM_ERR_INVALID_PORT;
    *tagged = member->tagged ? TRUE : FALSE;
    return FM_OK;
}

fm_status fmAddVlanPort(fm_int sw, fm_uint16 vid, fm_int port,
                        fm_bool tagged) {
    sim_vlan *vlan = find_vlan((u16)vid);
    sim_vlan_member *member;

    (void)sw;
    g_write_calls++;
    if (!vlan)
        return FM_ERR_INVALID_VLAN;
    member = find_vlan_member(vlan, port);
    if (member) {
        if (member->tagged != (tagged ? true : false)) {
            flush_macs_for_vlan_port((u16)vid, port);
            member->stp = SIM_DEFAULT_STP;
        }
        member->tagged = tagged ? true : false;
        return FM_OK;
    }
    return seed_vlan_member(
        (u16)vid, port, tagged ? true : false,
        SIM_DEFAULT_STP) ? FM_OK : FM_FAIL;
}

fm_status fmDeleteVlanPort(fm_int sw, fm_uint16 vid, fm_int port) {
    sim_vlan *vlan = find_vlan((u16)vid);

    (void)sw;
    g_write_calls++;
    if (!vlan)
        return FM_ERR_INVALID_VLAN;
    for (int i = 0; i < vlan->n_members; i++) {
        if (vlan->members[i].port != port)
            continue;
        for (int j = i + 1; j < vlan->n_members; j++)
            vlan->members[j - 1] = vlan->members[j];
        vlan->n_members--;
        flush_macs_for_vlan_port((u16)vid, port);
        return FM_OK;
    }
    return FM_ERR_INVALID_PORT;
}

fm_status fmGetVlanPortState(fm_int sw, fm_uint16 vid, fm_int port,
                             fm_int *state) {
    sim_vlan *vlan = find_vlan((u16)vid);
    sim_vlan_member *member;

    (void)sw;
    if (g_fault == SIM_FAULT_VLAN_STP)
        return FM_FAIL;
    if (!vlan)
        return FM_ERR_INVALID_VLAN;
    member = find_vlan_member(vlan, port);
    if (!member)
        return FM_ERR_INVALID_PORT;
    *state = member->stp;
    return FM_OK;
}

fm_status fmSetVlanPortState(fm_int sw, fm_uint16 vid, fm_int port,
                             fm_int state) {
    sim_vlan *vlan = find_vlan((u16)vid);
    sim_vlan_member *member;

    (void)sw;
    g_write_calls++;
    if (!vlan)
        return FM_ERR_INVALID_VLAN;
    member = find_vlan_member(vlan, port);
    if (!member)
        return FM_ERR_INVALID_PORT;
    member->stp = state;
    return FM_OK;
}

fm_status fmGetAddressTableExt(fm_int sw, fm_int *n_entries,
                               fm_macAddressEntry *entries,
                               fm_int max_entries) {
    int count = 0;

    (void)sw;
    if (g_fault == SIM_FAULT_ADDRESS_READ)
        return FM_FAIL;
    for (int i = 0; i < SIM_MAX_MACS; i++) {
        if (!g_macs[i].used)
            continue;
        if (entries && count < max_entries)
            entries[count] = g_macs[i].entry;
        count++;
    }
    if (entries && count > max_entries)
        return FM_FAIL;
    *n_entries = count;
    return FM_OK;
}

fm_status fmAddAddress(fm_int sw, fm_macAddressEntry *entry) {
    u8 mac[6];
    fm_uint64 value;

    (void)sw;
    g_write_calls++;
    if (!entry)
        return FM_FAIL;
    value = (fm_uint64)entry->macAddress;
    mac[0] = (u8)((value >> 40) & 0xff);
    mac[1] = (u8)((value >> 32) & 0xff);
    mac[2] = (u8)((value >> 24) & 0xff);
    mac[3] = (u8)((value >> 16) & 0xff);
    mac[4] = (u8)((value >> 8) & 0xff);
    mac[5] = (u8)(value & 0xff);
    return seed_mac(
        (u16)entry->vlanID, mac, (int)entry->port,
        (int)entry->type) ? FM_OK : FM_FAIL;
}

fm_status fmGetLAGFirst(fm_int sw, fm_int *first_lag) {
    int first = 0;

    (void)sw;
    if (g_lag_post_create_enum_fault_armed &&
        g_lag_post_create_enum_failures > 0) {
        g_lag_post_create_enum_failures--;
        if (g_lag_post_create_enum_failures == 0)
            g_lag_post_create_enum_fault_armed = false;
        return FM_FAIL;
    }
    for (int i = 0; i < SIM_MAX_LAGS; i++) {
        if (!g_lags[i].used)
            continue;
        if (first == 0 || g_lags[i].id < first)
            first = g_lags[i].id;
    }
    if (first == 0)
        return FM_ERR_NO_LAGS;
    *first_lag = first;
    return FM_OK;
}

fm_status fmGetLAGNext(fm_int sw, fm_int current_lag,
                       fm_int *next_lag) {
    int next = 0;

    (void)sw;
    if (g_fault == SIM_FAULT_LAG_NEXT)
        return FM_FAIL;
    for (int i = 0; i < SIM_MAX_LAGS; i++) {
        if (!g_lags[i].used || g_lags[i].id <= current_lag)
            continue;
        if (next == 0 || g_lags[i].id < next)
            next = g_lags[i].id;
    }
    if (next == 0)
        return FM_ERR_NO_LAGS;
    *next_lag = next;
    return FM_OK;
}

fm_status fmCreateLAG(fm_int sw, fm_int *lag_id) {
    sim_lag *lag;
    int extra_additions;
    int foreign_id;

    (void)sw;
    g_write_calls++;
    g_lag_create_calls++;
    if (g_lag_create_fail_without_mutation > 0) {
        g_lag_create_fail_without_mutation--;
        return FM_FAIL;
    }
    lag = allocate_lag(g_next_lag_id++);
    if (!lag)
        return FM_FAIL;
    *lag_id = lag->id;
    extra_additions = g_lag_create_extra_additions;
    g_lag_create_extra_additions = 0;
    for (int i = 0; i < extra_additions; i++) {
        if (!allocate_lag(g_next_lag_id++))
            return FM_FAIL;
    }
    foreign_id = g_lag_create_remove_foreign_id;
    g_lag_create_remove_foreign_id = 0;
    if (foreign_id > 0) {
        sim_lag *foreign = find_lag(foreign_id);

        if (foreign) {
            foreign->used = false;
            foreign->n_members = 0;
        }
    }
    if (g_lag_post_create_enum_failures > 0)
        g_lag_post_create_enum_fault_armed = true;
    if (g_lag_create_fail_after_mutation > 0) {
        g_lag_create_fail_after_mutation--;
        *lag_id = -777;
        return FM_FAIL;
    }
    return FM_OK;
}

fm_status fmDeleteLAG(fm_int sw, fm_int lag_id) {
    sim_lag *lag = find_lag(lag_id);

    (void)sw;
    g_write_calls++;
    if (!lag)
        return FM_ERR_INVALID_LAG;
    for (int i = 0; i < SIM_MAX_VLANS; i++) {
        sim_vlan *vlan = &g_vlans[i];
        if (!vlan->used)
            continue;
        for (int j = vlan->n_members - 1; j >= 0; j--) {
            if (vlan->members[j].port != lag->logical_port)
                continue;
            for (int k = j + 1; k < vlan->n_members; k++)
                vlan->members[k - 1] = vlan->members[k];
            vlan->n_members--;
        }
    }
    lag->used = false;
    lag->n_members = 0;
    if (g_lag_delete_fail_after_mutation > 0) {
        g_lag_delete_fail_after_mutation--;
        return FM_FAIL;
    }
    return FM_OK;
}

fm_status fmGetLAGPortFirst(fm_int sw, fm_int lag_id,
                            fm_int *first_port) {
    sim_lag *lag = find_lag(lag_id);
    int first = 0;

    (void)sw;
    if (!lag)
        return FM_ERR_INVALID_LAG;
    if (lag->n_members == 0)
        return FM_ERR_NO_PORTS_IN_LAG;
    for (int i = 0; i < lag->n_members; i++)
        if (first == 0 || lag->members[i] < first)
            first = lag->members[i];
    *first_port = first;
    return FM_OK;
}

fm_status fmGetLAGPortNext(fm_int sw, fm_int lag_id,
                           fm_int current_port, fm_int *next_port) {
    sim_lag *lag = find_lag(lag_id);
    int next = 0;

    (void)sw;
    if (!lag)
        return FM_ERR_INVALID_LAG;
    for (int i = 0; i < lag->n_members; i++) {
        int port = lag->members[i];
        if (port <= current_port)
            continue;
        if (next == 0 || port < next)
            next = port;
    }
    if (next == 0)
        return FM_ERR_NO_PORTS_IN_LAG;
    *next_port = next;
    return FM_OK;
}

fm_status fmGetLAGPortList(fm_int sw, fm_int lag_id,
                           fm_int *n_ports, fm_int *ports,
                           fm_int max_ports) {
    sim_lag *lag = find_lag(lag_id);

    (void)sw;
    if (g_fault == SIM_FAULT_LAG_LIST)
        return FM_FAIL;
    if (!lag)
        return FM_ERR_INVALID_LAG;
    if (lag->n_members > max_ports)
        return FM_FAIL;
    *n_ports = lag->n_members;
    for (int i = 0; i < lag->n_members; i++)
        ports[i] = lag->members[i];
    return FM_OK;
}

fm_status fmAddLAGPort(fm_int sw, fm_int lag_id, fm_int port) {
    sim_lag *lag = find_lag(lag_id);

    (void)sw;
    g_write_calls++;
    if (!lag)
        return FM_ERR_INVALID_LAG;
    return seed_lag_member(lag, port) ? FM_OK : FM_FAIL;
}

fm_status fmDeleteLAGPort(fm_int sw, fm_int lag_id, fm_int port) {
    sim_lag *lag = find_lag(lag_id);

    (void)sw;
    g_write_calls++;
    if (!lag)
        return FM_ERR_INVALID_LAG;
    for (int i = 0; i < lag->n_members; i++) {
        if (lag->members[i] != port)
            continue;
        for (int j = i + 1; j < lag->n_members; j++)
            lag->members[j - 1] = lag->members[j];
        lag->n_members--;
        return FM_OK;
    }
    return FM_ERR_INVALID_PORT;
}

fm_status fmGetLAGAttribute(fm_int sw, fm_int attribute, fm_int lag_id,
                            void *value) {
    sim_lag *lag = find_lag(lag_id);

    (void)sw;
    if ((attribute == FM_LAG_LACP_DISPOSITION &&
         g_fault == SIM_FAULT_LAG_ATTRIBUTE) ||
        (attribute == FM_LAG_HASH_ROTATION &&
         g_fault == SIM_FAULT_LAG_HASH_READ))
        return FM_FAIL;
    if (!lag || !value)
        return FM_ERR_INVALID_ATTRIB;
    if (attribute == FM_LAG_LACP_DISPOSITION)
        *(fm_uint32 *)value = lag->lacp_disposition;
    else if (attribute == FM_LAG_HASH_ROTATION)
        *(fm_uint32 *)value = (fm_uint32)lag->hash_rotation;
    else
        return FM_ERR_INVALID_ATTRIB;
    return FM_OK;
}

fm_status fmSetLAGAttribute(fm_int sw, fm_int attribute, fm_int lag_id,
                            void *value) {
    sim_lag *lag = find_lag(lag_id);

    (void)sw;
    g_write_calls++;
    if (!lag || !value)
        return FM_ERR_INVALID_ATTRIB;
    if (attribute == FM_LAG_LACP_DISPOSITION) {
        lag->lacp_disposition = *(fm_uint32 *)value;
    } else if (attribute == FM_LAG_HASH_ROTATION) {
        if (g_hash_set_failures > 0) {
            g_hash_set_failures--;
            return FM_FAIL;
        }
        lag->hash_rotation = (int)*(fm_uint32 *)value;
    } else {
        return FM_ERR_INVALID_ATTRIB;
    }
    return FM_OK;
}

fm_status fmLAGNumberToLogicalPort(fm_int sw, fm_int lag_id,
                                   fm_int *logical_port) {
    sim_lag *lag = find_lag(lag_id);

    (void)sw;
    if (g_fault == SIM_FAULT_LAG_TO_LOGICAL)
        return FM_FAIL;
    if (!lag)
        return FM_ERR_INVALID_LAG;
    *logical_port = lag->logical_port;
    return FM_OK;
}

fm_status fmLogicalPortToLAGNumber(fm_int sw, fm_int logical_port,
                                   fm_int *lag_id) {
    (void)sw;
    for (int i = 0; i < SIM_MAX_LAGS; i++) {
        if (g_lags[i].used &&
            g_lags[i].logical_port == logical_port) {
            *lag_id = g_lags[i].id;
            return FM_OK;
        }
    }
    return FM_ERR_INVALID_PORT;
}

fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr,
                             void *value) {
    (void)sw;
    (void)port;
    (void)attr;
    (void)value;
    return FM_FAIL;
}

fm_status fmSetPortAttribute(fm_int sw, fm_int port, fm_int attr,
                             void *value) {
    (void)sw;
    (void)port;
    (void)attr;
    (void)value;
    g_write_calls++;
    return FM_FAIL;
}

fm_status fmGetPortState(fm_int sw, fm_int port, fm_int *mode,
                         fm_int *state, fm_int *info) {
    (void)sw;
    (void)port;
    (void)mode;
    (void)state;
    (void)info;
    return FM_FAIL;
}

fm_status fmSetPortState(fm_int sw, fm_int port, fm_int mode,
                         fm_int submode) {
    (void)sw;
    (void)port;
    (void)mode;
    (void)submode;
    g_write_calls++;
    return FM_FAIL;
}

int hal_mac_entry_snapshot(int sw, u16 vid, const u8 mac[6],
                           bool *present, int *port, bool *is_static,
                           int *entry_type) {
    sim_mac *slot = find_mac(vid, mac_to_u64(mac));

    (void)sw;
    if (!present || !port || !is_static || !entry_type)
        return -1;
    *present = slot != NULL;
    *port = slot ? (int)slot->entry.port : 0;
    *entry_type = slot ? (int)slot->entry.type : 0;
    *is_static = slot &&
        (slot->entry.type == FM_ADDRESS_STATIC ||
         slot->entry.type == FM_ADDRESS_SECURE_STATIC);
    return 0;
}

int hal_static_mac_add(int sw, u16 vid, const u8 mac[6], int port) {
    fm_macAddressEntry entry;

    memset(&entry, 0, sizeof(entry));
    entry.macAddress = mac_to_u64(mac);
    entry.vlanID = (fm_uint16)vid;
    entry.port = (fm_int)port;
    entry.type = FM_ADDRESS_STATIC;
    entry.destMask = FM_DESTMASK_UNUSED;
    return fmAddAddress((fm_int)sw, &entry) == FM_OK ? 0 : -1;
}

int hal_static_mac_delete(int sw, u16 vid, const u8 mac[6]) {
    sim_mac *slot = find_mac(vid, mac_to_u64(mac));

    (void)sw;
    g_write_calls++;
    if (slot)
        slot->used = false;
    return 0;
}

int verify_apply_plan(int sw, l2_apply_plan *plan,
                      struct verify_result *results, int max_results) {
    int status = 0;

    (void)sw;
    if (!plan || max_results < plan->n_steps)
        return -1;
    for (int i = 0; i < plan->n_steps; i++) {
        const l2_apply_step *step = &plan->steps[i];
        bool readback_ok = true;

        memset(&results[i], 0, sizeof(results[i]));
        if ((step->type == L2_STEP_QOS_WATERMARK_SET ||
             step->type == L2_STEP_QOS_WATERMARK_DEL) &&
            step->port == SIM_QOS_PORT &&
            step->qos_watermark_attr ==
                HAL_QOS_WATERMARK_ATTR_TX_HOG &&
            step->qos_watermark_index >= 0 &&
            step->qos_watermark_index < SIM_QOS_WATERMARK_COUNT) {
            int index = step->qos_watermark_index;
            u32 expected =
                step->type == L2_STEP_QOS_WATERMARK_SET ?
                (u32)step->qos_watermark_value :
                step->qos_watermark_delete_target.value;

            readback_ok = g_qos_watermark[index] == expected;
            if (step->type == L2_STEP_QOS_WATERMARK_DEL)
                readback_ok =
                    readback_ok && !g_qos_owner_present[index];
            else
                readback_ok =
                    readback_ok && g_qos_owner_present[index];
        }
        results[i].readback_ok = readback_ok;
        if (!readback_ok)
            status = -1;
    }
    return status;
}

/*
 * hal_config.c's three switch statements intentionally reference every L2
 * feature owner.  These exact-signature stubs keep this fixture linked to the
 * real transaction implementation while making any out-of-scope call fail.
 */
#define UNUSED1(a) do { (void)(a); } while (0)
#define UNUSED2(a, b) do { (void)(a); (void)(b); } while (0)
#define UNUSED3(a, b, c) do { (void)(a); (void)(b); (void)(c); } while (0)
#define UNUSED4(a, b, c, d) \
    do { (void)(a); (void)(b); (void)(c); (void)(d); } while (0)
#define UNUSED5(a, b, c, d, e) \
    do { UNUSED4(a, b, c, d); (void)(e); } while (0)
#define UNUSED6(a, b, c, d, e, f) \
    do { UNUSED5(a, b, c, d, e); (void)(f); } while (0)
#define UNUSED7(a, b, c, d, e, f, g) \
    do { UNUSED6(a, b, c, d, e, f); (void)(g); } while (0)
#define UNUSED8(a, b, c, d, e, f, g, h) \
    do { UNUSED7(a, b, c, d, e, f, g); (void)(h); } while (0)
#define UNUSED9(a, b, c, d, e, f, g, h, i) \
    do { UNUSED8(a, b, c, d, e, f, g, h); (void)(i); } while (0)

int hal_port_set_admin_state(int sw, int port, int mode) {
    UNUSED3(sw, port, mode); return -1;
}
hal_port_admin_transaction_snapshot
hal_port_admin_transaction_snapshot_get(int sw, int port) {
    hal_port_admin_transaction_snapshot snapshot;

    UNUSED2(sw, port);
    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
bool hal_port_admin_transaction_snapshot_equal(
    const hal_port_admin_transaction_snapshot *left,
    const hal_port_admin_transaction_snapshot *right) {
    UNUSED2(left, right); return false;
}
int hal_port_admin_transaction_apply(
    int sw, int port, int mode,
    const hal_port_admin_transaction_snapshot *before) {
    UNUSED4(sw, port, mode, before); return -1;
}
int hal_port_admin_transaction_restore(
    int sw, int port,
    const hal_port_admin_transaction_snapshot *snapshot) {
    UNUSED3(sw, port, snapshot); return -1;
}
int hal_port_set_mtu(int sw, int port, int mtu) {
    UNUSED3(sw, port, mtu); return -1;
}
int hal_port_get_mtu(int sw, int port, int *mtu, int *max_frame) {
    UNUSED4(sw, port, mtu, max_frame); return -1;
}
int hal_port_set_speed(int sw, int port, int speed) {
    UNUSED3(sw, port, speed); return -1;
}
int hal_port_restore_speed(
    int sw, int port, int speed, int ethernet_mode,
    const hal_port_admin_transaction_snapshot *admin_snapshot) {
    UNUSED5(sw, port, speed, ethernet_mode, admin_snapshot); return -1;
}
int hal_port_set_ethernet_mode(int sw, int port, int mode) {
    UNUSED3(sw, port, mode); return -1;
}
bool hal_port_ethernet_mode_restorable(int mode) {
    UNUSED1(mode); return true;
}
int hal_port_get_speed_mode(int sw, int port, int *speed, int *mode) {
    UNUSED4(sw, port, speed, mode); return -1;
}
int hal_mac_aging_set(int sw, int seconds) {
    UNUSED2(sw, seconds); return -1;
}
int hal_mac_aging_get(int sw, int *seconds) {
    UNUSED2(sw, seconds); return -1;
}
int hal_l2_mcast_listener_set(int sw, u16 vid, const u8 mac[6], int port) {
    UNUSED4(sw, vid, mac, port); return -1;
}
int hal_l2_mcast_listener_delete(int sw, u16 vid, const u8 mac[6], int port) {
    UNUSED4(sw, vid, mac, port); return -1;
}
int hal_l2_mcast_listener_present(int sw, u16 vid, const u8 mac[6], int port) {
    UNUSED4(sw, vid, mac, port); return -1;
}
int hal_l2_security_dhcp_snooping_set(int sw, u16 vid, int port) {
    memset(&g_security_pending_token, 0,
           sizeof(g_security_pending_token));
    g_security_pending_token.sw = -1;
    g_security_pending_token.table = -1;
    if (!g_security_table_present) {
        g_security_table_present = true;
        g_security_active_generation = g_security_next_generation++;
        g_security_pending_token.valid = true;
        g_security_pending_token.sw = sw;
        g_security_pending_token.table = 28;
        g_security_pending_token.owner = HAL_FLOW_OWNER_L2_SECURITY;
        g_security_pending_token.generation =
            g_security_active_generation;
        g_security_pending_token.condition = UINT64_C(0x1fff);
        g_security_pending_token.max_entries = 64;
        g_security_pending_token.max_actions = 2;
        g_security_create_calls++;
        g_write_calls++;
    }
    if (g_security_set_failures > 0) {
        g_security_set_failures--;
        return -1;
    }
    if (!g_security_dhcp_present ||
        g_security_dhcp_vid != vid ||
        g_security_dhcp_port != port) {
        g_security_dhcp_present = true;
        g_security_dhcp_vid = vid;
        g_security_dhcp_port = port;
        g_write_calls++;
    }
    return 0;
}
int hal_l2_security_dhcp_snooping_delete(int sw, u16 vid, int port) {
    UNUSED1(sw);
    memset(&g_security_pending_token, 0,
           sizeof(g_security_pending_token));
    g_security_pending_token.sw = -1;
    g_security_pending_token.table = -1;
    if (!g_security_table_present)
        return 0;
    if (g_security_dhcp_present &&
        g_security_dhcp_vid == vid &&
        g_security_dhcp_port == port) {
        g_security_dhcp_present = false;
        g_write_calls++;
    }
    return 0;
}
int hal_l2_security_arp_inspection_set(int sw, u16 vid, int port) {
    UNUSED3(sw, vid, port); return -1;
}
int hal_l2_security_arp_inspection_delete(int sw, u16 vid, int port) {
    UNUSED3(sw, vid, port); return -1;
}
int hal_l2_security_rule_present(int sw, const char *kind, u16 vid, int port) {
    UNUSED4(sw, kind, vid, port); return -1;
}
hal_flow_presence_snapshot hal_l2_security_table_snapshot(int sw) {
    hal_flow_presence_snapshot snapshot = {0};

    UNUSED1(sw);
    snapshot.table = 28;
    snapshot.sdk_status = FM_OK;
    snapshot.state = g_security_table_present ?
        HAL_PRESENCE_PRESENT : HAL_PRESENCE_ABSENT;
    snapshot.exact = g_security_table_present;
    return snapshot;
}
hal_flow_presence_snapshot hal_l2_security_rule_snapshot(
    int sw, const char *kind, u16 vid, int port) {
    hal_flow_presence_snapshot snapshot = {0};

    UNUSED1(sw);
    snapshot.table = 28;
    snapshot.sdk_status = FM_OK;
    if (!kind || strcmp(kind, "dhcp-snooping") != 0) {
        snapshot.state = HAL_PRESENCE_READ_ERROR;
        return snapshot;
    }
    snapshot.state =
        g_security_table_present &&
        g_security_dhcp_present &&
        g_security_dhcp_vid == vid &&
        g_security_dhcp_port == port ?
        HAL_PRESENCE_PRESENT : HAL_PRESENCE_ABSENT;
    snapshot.exact = snapshot.state == HAL_PRESENCE_PRESENT;
    return snapshot;
}
int hal_l2_security_take_created_table_token(
    hal_flow_table_creation_token *token) {
    if (!token)
        return -1;
    *token = g_security_pending_token;
    memset(&g_security_pending_token, 0,
           sizeof(g_security_pending_token));
    g_security_pending_token.sw = -1;
    g_security_pending_token.table = -1;
    return token->valid ? 1 : 0;
}
int hal_l2_security_release_created_table_empty(
    const hal_flow_table_creation_token *token) {
    if (!token || !token->valid ||
        token->sw != 0 || token->table != 28 ||
        token->owner != HAL_FLOW_OWNER_L2_SECURITY ||
        token->generation != g_security_active_generation ||
        g_security_dhcp_present ||
        g_security_ingress_present)
        return -1;
    g_security_release_calls++;
    if (g_security_release_failures > 0) {
        g_security_release_failures--;
        return -1;
    }
    if (g_security_table_present) {
        g_security_table_present = false;
        g_write_calls++;
    }
    g_security_active_generation = 0;
    return 0;
}
int hal_l2_security_arp_binding_set(int sw, u16 vid, int port,
                                    const u8 mac[6], u32 ip) {
    UNUSED5(sw, vid, port, mac, ip); return -1;
}
int hal_l2_security_arp_binding_delete(int sw, u16 vid, int port,
                                       const u8 mac[6], u32 ip) {
    UNUSED5(sw, vid, port, mac, ip); return -1;
}
int hal_l2_security_arp_binding_present(int sw, u16 vid, int port,
                                        const u8 mac[6], u32 ip) {
    UNUSED5(sw, vid, port, mac, ip); return -1;
}
hal_flow_presence_snapshot hal_l2_security_arp_binding_snapshot(
    int sw, u16 vid, int port, const u8 mac[6], u32 ip) {
    hal_flow_presence_snapshot snapshot = {0};
    UNUSED5(sw, vid, port, mac, ip);
    snapshot.state = HAL_PRESENCE_READ_ERROR;
    return snapshot;
}
int hal_l2_security_user_filter_set(int sw, u16 vid, int port,
                                    const u8 mac[6], int kind) {
    UNUSED5(sw, vid, port, mac, kind); return -1;
}
int hal_l2_security_user_filter_delete(int sw, u16 vid, int port,
                                       const u8 mac[6], int kind) {
    UNUSED5(sw, vid, port, mac, kind); return -1;
}
int hal_l2_security_user_filter_present(int sw, u16 vid, int port,
                                        const u8 mac[6], int kind) {
    UNUSED5(sw, vid, port, mac, kind); return -1;
}
hal_flow_presence_snapshot hal_l2_security_user_filter_snapshot(
    int sw, u16 vid, int port, const u8 mac[6], int kind) {
    hal_flow_presence_snapshot snapshot = {0};
    UNUSED5(sw, vid, port, mac, kind);
    snapshot.state = HAL_PRESENCE_READ_ERROR;
    return snapshot;
}
int hal_ingress_ipv4_acl_set(int sw,
                             const hal_ingress_ipv4_acl_match *match) {
    if (!match)
        return -1;
    memset(&g_security_pending_token, 0,
           sizeof(g_security_pending_token));
    g_security_pending_token.sw = -1;
    g_security_pending_token.table = -1;
    if (!g_security_table_present) {
        g_security_table_present = true;
        g_security_active_generation = g_security_next_generation++;
        g_security_pending_token.valid = true;
        g_security_pending_token.sw = sw;
        g_security_pending_token.table = 28;
        g_security_pending_token.owner = HAL_FLOW_OWNER_L2_SECURITY;
        g_security_pending_token.generation =
            g_security_active_generation;
        g_security_pending_token.condition = UINT64_C(0x1fff);
        g_security_pending_token.max_entries = 64;
        g_security_pending_token.max_actions = 2;
        g_security_create_calls++;
        g_write_calls++;
    }
    if (g_security_set_failures > 0) {
        g_security_set_failures--;
        return -1;
    }
    if (!g_security_ingress_present ||
        memcmp(&g_security_ingress_match, match,
               sizeof(*match)) != 0) {
        g_security_ingress_present = true;
        g_security_ingress_match = *match;
        g_write_calls++;
    }
    return 0;
}
int hal_ingress_ipv4_acl_delete(int sw,
                                const hal_ingress_ipv4_acl_match *match) {
    UNUSED1(sw);
    if (!match)
        return -1;
    memset(&g_security_pending_token, 0,
           sizeof(g_security_pending_token));
    g_security_pending_token.sw = -1;
    g_security_pending_token.table = -1;
    if (!g_security_table_present)
        return 0;
    if (g_security_ingress_present &&
        memcmp(&g_security_ingress_match, match,
               sizeof(*match)) == 0) {
        g_security_ingress_present = false;
        g_write_calls++;
    }
    return 0;
}
int hal_ingress_ipv4_acl_present(int sw,
                                 const hal_ingress_ipv4_acl_match *match) {
    UNUSED2(sw, match); return -1;
}
hal_flow_presence_snapshot hal_ingress_ipv4_acl_snapshot(
    int sw, const hal_ingress_ipv4_acl_match *match) {
    hal_flow_presence_snapshot snapshot = {0};

    UNUSED1(sw);
    snapshot.table = 28;
    snapshot.sdk_status = FM_OK;
    if (!match) {
        snapshot.state = HAL_PRESENCE_READ_ERROR;
        return snapshot;
    }
    snapshot.state =
        g_security_table_present &&
        g_security_ingress_present &&
        memcmp(&g_security_ingress_match, match,
               sizeof(*match)) == 0 ?
        HAL_PRESENCE_PRESENT : HAL_PRESENCE_ABSENT;
    snapshot.exact = snapshot.state == HAL_PRESENCE_PRESENT;
    return snapshot;
}
int hal_acl_policer_owner_apply(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_result *result) {
    UNUSED3(sw, args, result); return -1;
}
int hal_acl_policer_owner_readback_match(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_result *result) {
    UNUSED3(sw, args, result); return -1;
}
int hal_acl_policer_owner_rollback_match(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_result *result) {
    UNUSED3(sw, args, result); return -1;
}
int hal_acl_egress_owner_apply(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_egress_owner_result *result) {
    UNUSED3(sw, args, result); return -1;
}
int hal_acl_egress_owner_readback_match(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_egress_owner_result *result) {
    UNUSED3(sw, args, result); return -1;
}
int hal_acl_egress_owner_rollback_match(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_egress_owner_result *result) {
    UNUSED3(sw, args, result); return -1;
}
int hal_acl_independent_apply(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_result *result) {
    UNUSED3(sw, args, result); return -1;
}
int hal_acl_independent_readback_match(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_result *result) {
    UNUSED3(sw, args, result); return -1;
}
int hal_acl_independent_rollback_match(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_result *result) {
    UNUSED3(sw, args, result); return -1;
}
hal_acl_policer_owner_transaction_snapshot
hal_acl_policer_owner_transaction_snapshot_get(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_owner_transaction_query query) {
    hal_acl_policer_owner_transaction_snapshot snapshot = {0};

    UNUSED3(sw, args, query);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
hal_acl_egress_owner_transaction_snapshot
hal_acl_egress_owner_transaction_snapshot_get(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_owner_transaction_query query) {
    hal_acl_egress_owner_transaction_snapshot snapshot = {0};

    UNUSED3(sw, args, query);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
hal_acl_independent_transaction_snapshot
hal_acl_independent_transaction_snapshot_get(
    int sw, const hal_acl_independent_args *args,
    hal_acl_owner_transaction_query query) {
    hal_acl_independent_transaction_snapshot snapshot = {0};

    UNUSED3(sw, args, query);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
int hal_acl_policer_owner_transaction_apply(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_transaction_snapshot *snapshot,
    hal_acl_policer_owner_result *result) {
    UNUSED4(sw, args, snapshot, result); return -1;
}
int hal_acl_independent_transaction_apply(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_transaction_snapshot *snapshot,
    hal_acl_independent_result *result) {
    UNUSED4(sw, args, snapshot, result); return -1;
}
int hal_acl_policer_owner_transaction_restore(
    int sw, const hal_acl_policer_owner_args *desired,
    const hal_acl_policer_owner_transaction_snapshot *snapshot) {
    UNUSED3(sw, desired, snapshot); return -1;
}
int hal_acl_egress_owner_transaction_restore(
    int sw, const hal_acl_egress_owner_args *desired,
    const hal_acl_egress_owner_transaction_snapshot *snapshot) {
    UNUSED3(sw, desired, snapshot); return -1;
}
int hal_acl_independent_transaction_restore(
    int sw, const hal_acl_independent_args *desired,
    const hal_acl_independent_transaction_snapshot *snapshot) {
    UNUSED3(sw, desired, snapshot); return -1;
}
int hal_control_plane_copp_set(int sw, const char *name,
                               int rate, int burst) {
    UNUSED4(sw, name, rate, burst); return -1;
}
int hal_control_plane_copp_get(int sw, const char *name, int *rate,
                               int *burst, int *policer, int *acl,
                               int *rule, u64 *packets, u64 *octets) {
    UNUSED9(sw, name, rate, burst, policer, acl, rule, packets, octets);
    return -1;
}
hal_copp_policer_transaction_snapshot
hal_control_plane_copp_transaction_snapshot(int sw, const char *name) {
    hal_copp_policer_transaction_snapshot snapshot = {0};
    UNUSED2(sw, name);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
int hal_control_plane_copp_transaction_restore(
    int sw, const char *name,
    const hal_copp_policer_transaction_snapshot *snapshot) {
    UNUSED3(sw, name, snapshot);
    return -1;
}
int hal_storm_control_set(int sw, int port, int rate, int burst) {
    UNUSED4(sw, port, rate, burst); return -1;
}
int hal_storm_control_delete(int sw, int port) {
    UNUSED2(sw, port); return -1;
}
int hal_storm_control_get(int sw, int port, hal_storm_control_entry *entry) {
    UNUSED3(sw, port, entry); return -1;
}
int hal_storm_control_list(int sw, hal_storm_control_entry *entries, int max) {
    UNUSED3(sw, entries, max); return -1;
}
hal_storm_rate_transaction_snapshot
hal_storm_control_transaction_snapshot(int sw, int port) {
    hal_storm_rate_transaction_snapshot snapshot = {0};
    UNUSED2(sw, port);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
int hal_storm_control_set_kind(int sw, int port, nl_storm_kind kind, int rate, int burst) {
    (void)kind; return hal_storm_control_set(sw, port, rate, burst);
}
int hal_storm_control_delete_kind(int sw, int port, nl_storm_kind kind) {
    (void)kind; return hal_storm_control_delete(sw, port);
}
int hal_storm_control_get_kind(int sw, int port, nl_storm_kind kind, hal_storm_control_entry *entry) {
    (void)kind; return hal_storm_control_get(sw, port, entry);
}
hal_storm_rate_transaction_snapshot
hal_storm_control_transaction_snapshot_kind(int sw, int port, nl_storm_kind kind) {
    (void)kind; return hal_storm_control_transaction_snapshot(sw, port);
}
int hal_ingress_rate_limit_set(int sw, int port, int rate, int burst) {
    UNUSED4(sw, port, rate, burst); return -1;
}
int hal_ingress_rate_limit_delete(int sw, int port) {
    UNUSED2(sw, port); return -1;
}
int hal_ingress_rate_limit_get(int sw, int port,
                               hal_storm_control_entry *entry) {
    UNUSED3(sw, port, entry); return -1;
}
int hal_ingress_rate_limit_list(
    int sw, hal_storm_control_entry *entries, int max) {
    UNUSED3(sw, entries, max); return -1;
}
hal_storm_rate_transaction_snapshot
hal_ingress_rate_limit_transaction_snapshot(int sw, int port) {
    hal_storm_rate_transaction_snapshot snapshot = {0};
    UNUSED2(sw, port);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
int hal_egress_rate_limit_set(int sw, int port, int rate, int burst) {
    UNUSED4(sw, port, rate, burst); return -1;
}
int hal_egress_rate_limit_delete(int sw, int port) {
    UNUSED2(sw, port); return -1;
}
int hal_egress_rate_limit_get(
    int sw, int port, hal_egress_rate_limit_entry *entry) {
    UNUSED3(sw, port, entry); return -1;
}
int hal_egress_rate_limit_snapshot(
    int sw, int port, bool *present,
    hal_egress_rate_limit_entry *entry) {
    UNUSED4(sw, port, present, entry); return -1;
}
hal_egress_rate_transaction_snapshot
hal_egress_rate_limit_transaction_snapshot(int sw, int port) {
    hal_egress_rate_transaction_snapshot snapshot = {0};
    UNUSED2(sw, port);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
int hal_egress_rate_limit_transaction_restore(
    int sw, int port,
    const hal_egress_rate_transaction_snapshot *snapshot) {
    UNUSED3(sw, port, snapshot); return -1;
}
int hal_qos_interface_set(int sw, int port, int trust, int priority) {
    UNUSED4(sw, port, trust, priority); return -1;
}
int hal_qos_interface_delete(int sw, int port) {
    UNUSED2(sw, port); return -1;
}
int hal_qos_interface_get(int sw, int port,
                          hal_qos_interface_entry *entry) {
    UNUSED3(sw, port, entry); return -1;
}
hal_qos_interface_transaction_snapshot
hal_qos_interface_transaction_snapshot_get(int sw, int port) {
    hal_qos_interface_transaction_snapshot snapshot = {0};
    UNUSED2(sw, port);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
int hal_qos_interface_transaction_restore(
    int sw, int port,
    const hal_qos_interface_transaction_snapshot *snapshot) {
    UNUSED3(sw, port, snapshot); return -1;
}
static int g_dscp_map[64], g_dscp_writes, g_dscp_fail_after, g_dscp_drop, g_dscp_restore_fail, g_dscp_read_fail;
int hal_qos_dscp_get(int sw, int dscp, int *priority) {
    UNUSED1(sw);
    if (!priority || dscp < 0 || dscp > 63 || g_dscp_read_fail) return -1;
    *priority = g_dscp_map[dscp]; return 0;
}
int hal_qos_dscp_set(int sw, int dscp, int priority) {
    UNUSED1(sw);
    if (dscp < 0 || dscp > 63 || priority < 0 || priority > 15) return -1;
    ++g_dscp_writes;
    if (g_dscp_restore_fail && g_dscp_writes > 2) return -1;
    if (g_dscp_drop != g_dscp_writes) g_dscp_map[dscp] = priority;
    return g_dscp_fail_after == g_dscp_writes ? -1 : 0;
}
int hal_qos_tc_smp_get(int sw, int tc, int *smp) {
    UNUSED1(sw);
    if (!smp || tc < 0 || tc > 7) return -1;
    *smp = g_qos_tc_smp[tc];
    return 0;
}
int hal_qos_tc_smp_set(int sw, int tc, int smp) {
    UNUSED1(sw);
    if (tc < 0 || tc > 7 || smp < 0 || smp > 1) return -1;
    ++g_smp_writes;
    if (g_smp_restore_fail && g_smp_writes > 1) return -1;
    if (!g_smp_drop) g_qos_tc_smp[tc] = smp;
    if (g_qos_auto_pause_mode)
        memcpy(g_qos_watermark, g_qos_calculated_watermark, sizeof(g_qos_watermark));
    g_qos_mutation_started = true;
    return g_smp_fail_after && g_smp_writes == 1 ? -1 : 0;
}
int hal_qos_priority_map_set(int sw, int priority, int traffic_class) {
    UNUSED1(sw);
    if (priority < 0 ||
        priority >= HAL_TRANSACTION_QOS_SWITCH_PRIORITIES ||
        traffic_class < 0 ||
        traffic_class >= HAL_TRANSACTION_QOS_TRAFFIC_CLASSES)
        return -1;
    g_qos_priority_map[priority] = traffic_class;
    if (g_qos_auto_pause_mode)
        memcpy(g_qos_watermark, g_qos_calculated_watermark,
               sizeof(g_qos_watermark));
    g_qos_mutation_started = true;
    g_qos_last_trigger_event = ++g_qos_event;
    g_write_calls++;
    return 0;
}
int hal_qos_priority_map_delete(int sw, int priority) {
    return hal_qos_priority_map_set(sw, priority, priority & 7);
}
int hal_qos_priority_map_get(
    int sw, int priority, hal_qos_priority_map_entry *entry) {
    UNUSED1(sw);
    if (!entry || priority < 0 ||
        priority >= HAL_TRANSACTION_QOS_SWITCH_PRIORITIES)
        return -1;
    memset(entry, 0, sizeof(*entry));
    entry->switch_priority = priority;
    entry->traffic_class = g_qos_priority_map[priority];
    return 0;
}
int hal_qos_flow_control_get(
    int sw, int port, hal_qos_flow_control_entry *entry) {
    UNUSED3(sw, port, entry); return -1;
}
int hal_qos_pfc_apply(int sw, int port, int rx_mask, int pause_mode,
                      int tx_mask, int lossless, int shared) {
    UNUSED7(sw, port, rx_mask, pause_mode, tx_mask, lossless, shared);
    return -1;
}
int hal_qos_pfc_delete(int sw, int port) {
    UNUSED2(sw, port); return -1;
}
int hal_qos_pfc_pc3_smp_set(int sw, int port, int smp) {
    UNUSED3(sw, port, smp); return -1;
}
int hal_qos_scheduler_tc_map_set(
    int sw, int port, int traffic_class, int group) {
    UNUSED4(sw, port, traffic_class, group); return -1;
}
int hal_qos_scheduler_tc_map_delete(
    int sw, int port, int traffic_class) {
    UNUSED3(sw, port, traffic_class); return -1;
}
int hal_qos_scheduler_tc_map_get(
    int sw, int port, int traffic_class, int *group) {
    UNUSED4(sw, port, traffic_class, group); return -1;
}
int hal_qos_scheduler_group_set(
    int sw, int port, int group, int strict, int weight) {
    UNUSED5(sw, port, group, strict, weight); return -1;
}
int hal_qos_scheduler_group_delete(int sw, int port, int group) {
    UNUSED3(sw, port, group); return -1;
}
int hal_qos_scheduler_group_get(
    int sw, int port, int group, int *strict, int *weight) {
    UNUSED5(sw, port, group, strict, weight); return -1;
}
hal_qos_scheduler_topology_transaction_snapshot
hal_qos_scheduler_topology_transaction_snapshot_get(int sw, int port) {
    hal_qos_scheduler_topology_transaction_snapshot snapshot = {0};
    UNUSED2(sw, port);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
int hal_qos_scheduler_topology_transaction_restore(
    int sw, int port,
    const hal_qos_scheduler_topology_transaction_snapshot *snapshot) {
    UNUSED3(sw, port, snapshot); return -1;
}
int hal_qos_scheduler_group_shaping_set(
    int sw, int port, int group, u64 rate, u64 burst) {
    UNUSED5(sw, port, group, rate, burst); return -1;
}
int hal_qos_scheduler_group_shaping_delete(int sw, int port, int group) {
    UNUSED3(sw, port, group); return -1;
}
int hal_qos_scheduler_group_shaping_get(
    int sw, int port, int group, u64 *rate, u64 *burst) {
    UNUSED5(sw, port, group, rate, burst); return -1;
}
int hal_qos_scheduler_group_shaping_snapshot(
    int sw, int port, int group, bool *present, u64 *rate, u64 *burst) {
    UNUSED6(sw, port, group, present, rate, burst); return -1;
}
hal_qos_scheduler_group_shaping_transaction_snapshot
hal_qos_scheduler_group_shaping_transaction_snapshot_get(
    int sw, int port, int group) {
    hal_qos_scheduler_group_shaping_transaction_snapshot snapshot = {0};
    UNUSED3(sw, port, group);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    return snapshot;
}
int hal_qos_scheduler_group_shaping_transaction_restore(
    int sw, int port, int group,
    const hal_qos_scheduler_group_shaping_transaction_snapshot *snapshot) {
    UNUSED4(sw, port, group, snapshot); return -1;
}
int hal_qos_scheduler_port_set(int sw, int port, int mask) {
    UNUSED3(sw, port, mask); return -1;
}
int hal_qos_scheduler_port_delete(int sw, int port) {
    UNUSED2(sw, port); return -1;
}
int hal_qos_scheduler_port_get(int sw, int port, int *mask) {
    UNUSED3(sw, port, mask); return -1;
}
int hal_qos_scheduler_port_transaction_restore(int sw, int port, u32 mask) {
    UNUSED3(sw, port, mask); return -1;
}
int hal_qos_watermark_set(
    int sw, int port, int attr, int index, int value) {
    UNUSED5(sw, port, attr, index, value); return -1;
}
int hal_qos_watermark_delete(int sw, int port, int attr, int index) {
    UNUSED4(sw, port, attr, index); return -1;
}
int hal_qos_watermark_read(
    int sw, int port, int attr, int index, int *value) {
    UNUSED5(sw, port, attr, index, value); return -1;
}
hal_qos_watermark_transaction_snapshot
hal_qos_watermark_transaction_snapshot_get(
    int sw, int port, int attr, int index) {
    hal_qos_watermark_transaction_snapshot snapshot = {0};
    UNUSED1(sw);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    snapshot.owner_baseline = -1;
    snapshot.owner_value = -1;
    if (port != SIM_QOS_PORT ||
        attr != HAL_QOS_WATERMARK_ATTR_TX_HOG ||
        index < 0 || index >= SIM_QOS_WATERMARK_COUNT)
        return snapshot;
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    snapshot.value = g_qos_watermark[index];
    snapshot.owner_present = g_qos_owner_present[index];
    snapshot.owner_baseline_known =
        g_qos_owner_baseline_known[index];
    snapshot.owner_baseline = g_qos_owner_baseline[index];
    snapshot.owner_value = g_qos_owner_value[index];
    return snapshot;
}
bool hal_qos_watermark_transaction_snapshot_equal(
    const hal_qos_watermark_transaction_snapshot *left,
    const hal_qos_watermark_transaction_snapshot *right) {
    return left && right &&
        left->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        right->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        left->sdk_status == right->sdk_status &&
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
    hal_qos_watermark_transaction_snapshot snapshot = {0};
    UNUSED1(sw);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_STATE;
    snapshot.owner_baseline = -1;
    snapshot.owner_value = -1;
    if (port != SIM_QOS_PORT ||
        attr != HAL_QOS_WATERMARK_ATTR_TX_HOG ||
        index < 0 || index >= SIM_QOS_WATERMARK_COUNT ||
        !g_qos_owner_present[index] ||
        !g_qos_owner_baseline_known[index])
        return snapshot;
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    snapshot.value = (u32)g_qos_owner_baseline[index];
    snapshot.owner_present = true;
    snapshot.owner_baseline_known = true;
    snapshot.owner_baseline = g_qos_owner_baseline[index];
    snapshot.owner_value = g_qos_owner_value[index];
    return snapshot;
}
int hal_qos_watermark_transaction_apply(
    int sw, int port, int attr, int index, int value,
    bool owner_create, bool calculator_reconciled,
    const hal_qos_watermark_transaction_snapshot *snapshot) {
    hal_qos_watermark_transaction_snapshot current =
        hal_qos_watermark_transaction_snapshot_get(
            sw, port, attr, index);

    if (value < 0 ||
        !hal_qos_watermark_transaction_snapshot_equal(
            snapshot, &current) ||
        (!owner_create && !calculator_reconciled &&
         !snapshot->owner_present))
        return -1;
    if (g_qos_apply_failures > 0) {
        g_qos_apply_failures--;
        return FM_FAIL;
    }
    g_qos_watermark[index] = (u32)value;
    g_qos_owner_present[index] = true;
    g_qos_owner_baseline_known[index] =
        snapshot->owner_baseline_known ||
        !snapshot->owner_present || calculator_reconciled;
    g_qos_owner_baseline[index] =
        snapshot->owner_present &&
        snapshot->owner_baseline_known ?
        snapshot->owner_baseline : (int)snapshot->value;
    g_qos_owner_value[index] = value;
    g_qos_mutation_started = true;
    ++g_qos_event;
    g_write_calls++;
    return 0;
}
int hal_qos_watermark_transaction_delete(
    int sw, int port, int attr, int index,
    bool calculator_reconciled,
    const hal_qos_watermark_transaction_snapshot *snapshot,
    const hal_qos_watermark_transaction_snapshot *target) {
    hal_qos_watermark_transaction_snapshot current =
        hal_qos_watermark_transaction_snapshot_get(
            sw, port, attr, index);

    if (!target ||
        !hal_qos_watermark_transaction_snapshot_equal(
            snapshot, &current) ||
        target->state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return -1;
    if (calculator_reconciled) {
        if (target->value != snapshot->value)
            return -1;
    } else {
        if (!snapshot->owner_present ||
            !snapshot->owner_baseline_known ||
            target->value != (u32)snapshot->owner_baseline)
            return -1;
        g_qos_watermark[index] = target->value;
    }
    g_qos_owner_present[index] = false;
    g_qos_owner_baseline_known[index] = false;
    g_qos_owner_baseline[index] = -1;
    g_qos_owner_value[index] = -1;
    g_qos_mutation_started = true;
    ++g_qos_event;
    g_write_calls++;
    return 0;
}
int hal_qos_watermark_transaction_restore(
    int sw, int port, int attr, int index,
    const hal_qos_watermark_transaction_snapshot *snapshot) {
    UNUSED1(sw);
    if (!snapshot ||
        snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        port != SIM_QOS_PORT ||
        attr != HAL_QOS_WATERMARK_ATTR_TX_HOG ||
        index < 0 || index >= SIM_QOS_WATERMARK_COUNT)
        return -1;
    g_qos_watermark[index] = snapshot->value;
    g_qos_owner_present[index] = snapshot->owner_present;
    g_qos_owner_baseline_known[index] =
        snapshot->owner_baseline_known;
    g_qos_owner_baseline[index] = snapshot->owner_baseline;
    g_qos_owner_value[index] = snapshot->owner_value;
    g_qos_mutation_started = true;
    g_qos_last_direct_restore_event = ++g_qos_event;
    g_write_calls++;
    return 0;
}
hal_qos_auto_pause_watermark_transaction_snapshot
hal_qos_auto_pause_watermark_transaction_snapshot_get(int sw) {
    hal_qos_auto_pause_watermark_transaction_snapshot snapshot = {0};
    UNUSED1(sw);
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    snapshot.auto_pause_mode = g_qos_auto_pause_mode ? 1U : 0U;
    snapshot.num_ports = 1;
    snapshot.ports[0].port = SIM_QOS_PORT;
    for (int index = 0; index < SIM_QOS_WATERMARK_COUNT; index++)
        snapshot.ports[0].tx_hog_wm[index] =
            g_qos_watermark[index];
    g_qos_shared_snapshot_calls++;
    if (!g_qos_mutation_started)
        g_qos_shared_pre_mutation_snapshots++;
    return snapshot;
}
bool hal_qos_auto_pause_watermark_transaction_snapshot_equal(
    const hal_qos_auto_pause_watermark_transaction_snapshot *left,
    const hal_qos_auto_pause_watermark_transaction_snapshot *right) {
    return left && right &&
        memcmp(left, right, sizeof(*left)) == 0;
}
int hal_qos_auto_pause_watermark_transaction_restore(
    int sw,
    const hal_qos_auto_pause_watermark_transaction_snapshot *snapshot) {
    UNUSED1(sw);
    if (!snapshot ||
        snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        snapshot->auto_pause_mode !=
            (g_qos_auto_pause_mode ? 1U : 0U) ||
        snapshot->num_ports != 1 ||
        snapshot->ports[0].port != SIM_QOS_PORT)
        return -1;
    for (int index = 0; index < SIM_QOS_WATERMARK_COUNT; index++)
        g_qos_watermark[index] =
            snapshot->ports[0].tx_hog_wm[index];
    g_qos_shared_restore_calls++;
    g_qos_shared_restore_event = ++g_qos_event;
    g_write_calls++;
    return 0;
}
int hal_mirror_state_get(int sw, int group, hal_mirror_state *state) {
    UNUSED3(sw, group, state); return -1;
}
int hal_mirror_session_replace(int sw, const hal_mirror_state *state) {
    UNUSED2(sw, state); return -1;
}
int hal_mirror_session_delete(int sw, int group) {
    UNUSED2(sw, group); return -1;
}
bool hal_mirror_state_equal(
    const hal_mirror_state *left, const hal_mirror_state *right) {
    UNUSED2(left, right); return false;
}

static bool mac_has_target(
    u16 vid, const u8 mac[6], int port, int type) {
    sim_mac *slot = find_mac(vid, mac_to_u64(mac));

    return slot &&
        (int)slot->entry.port == port &&
        (int)slot->entry.type == type;
}

static int bootstrap_lag(int ae_id) {
    l2_apply_plan *plan = new_plan(1, UINT64_C(0x9000) + (u64)ae_id);
    int status;
    int lag_id;

    if (!plan)
        return 0;
    plan->steps[0].type = L2_STEP_LAG_CREATE;
    plan->steps[0].ae_id = ae_id;
    status = apply_plan(plan);
    lag_id = status == 0 ? hal_lag_id_for_ae(ae_id) : 0;
    free_plan(plan);
    return lag_id;
}

static void test_absent_vlan_parent_transaction(void) {
    l2_apply_plan *plan;
    sim_vlan *vlan;
    sim_vlan_member *member;

    reset_simulator();
    plan = new_plan(3, UINT64_C(0x1001));
    expect("absent-parent VLAN plan allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_VLAN_CREATE;
    plan->steps[0].vid = 100;
    plan->steps[1].type = L2_STEP_VLAN_ADD_PORT;
    plan->steps[1].vid = 100;
    plan->steps[1].port = 7;
    plan->steps[1].tagged = false;
    plan->steps[2].type = L2_STEP_VLAN_STP_SET;
    plan->steps[2].vid = 100;
    plan->steps[2].port = 7;
    plan->steps[2].stp_state = 5;

    expect("absent parent permits ordered VLAN/member/STP apply",
           apply_plan(plan) == 0);
    vlan = find_vlan(100);
    member = find_vlan_member(vlan, 7);
    expect("VLAN/member/STP are live after apply",
           vlan && member && !member->tagged && member->stp == 5);
    expect("zero-write original snapshot records all parents absent",
           plan->original_n_steps == 3 &&
           !plan->original_steps[0].pre_vlan_existed &&
           !plan->original_steps[1].pre_member_existed &&
           !plan->original_steps[2].pre_stp_valid);
    expect("method41 exactly restores absent VLAN parent",
           hal_rollback_l2_plan(0, plan) == 0 &&
           find_vlan(100) == NULL &&
           plan->rollback_last_idx == -1);
    free_plan(plan);
}

static void test_absent_lag_parent_and_ae_target(void) {
    l2_apply_plan *plan;
    sim_lag *lag;
    sim_vlan *vlan;
    int lag_id;

    reset_simulator();
    plan = new_plan(4, UINT64_C(0x1002));
    expect("absent-parent LAG plan allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_CREATE;
    plan->steps[0].ae_id = 10;
    plan->steps[1].type = L2_STEP_LAG_HASH_ROTATION_SET;
    plan->steps[1].ae_id = 10;
    plan->steps[1].lag_hash_rotation = SIM_HASH_ROTATION_B;
    plan->steps[2].type = L2_STEP_VLAN_CREATE;
    plan->steps[2].vid = 110;
    plan->steps[3].type = L2_STEP_VLAN_ADD_PORT;
    plan->steps[3].vid = 110;
    plan->steps[3].ae_id = 10;
    plan->steps[3].tagged = true;

    expect("new LAG/hash/AE target applies from absent parent",
           apply_plan(plan) == 0);
    lag_id = hal_lag_id_for_ae(10);
    lag = find_lag(lag_id);
    vlan = find_vlan(110);
    expect("AE target resolves the allocator-owned logical port",
           lag && lag->hash_rotation == SIM_HASH_ROTATION_B &&
           find_vlan_member(vlan, lag->logical_port) != NULL);
    expect("new LAG/hash/AE original authority stays absent",
           !plan->original_steps[0].pre_lag_existed &&
           !plan->original_steps[1].pre_lag_existed &&
           !plan->original_steps[3].pre_member_existed);
    expect("method41 removes new AE target, VLAN, and LAG",
           hal_rollback_l2_plan(0, plan) == 0 &&
           find_vlan(110) == NULL &&
           count_lags() == 0 &&
           hal_lag_id_for_ae(10) == 0);
    free_plan(plan);
}

static void test_lag_non_idempotent_error_classification(void) {
    l2_apply_plan *plan;
    sim_lag *restored;
    int old_lag_id;
    int restored_lag_id;
    int status;

    reset_simulator();
    plan = new_plan(1, UINT64_C(0x10021));
    expect("mutate-then-error LAG-create plan allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_CREATE;
    plan->steps[0].ae_id = 30;
    g_lag_create_fail_after_mutation = 1;
    g_lag_delete_fail_after_mutation = 1;
    status = apply_plan(plan);
    expect("mutate-then-error LAG create returns the SDK failure",
           status == NL_ERR_SDK_CALL_FAILED);
    expect("failed LAG create rolls back the authoritative live delta",
           count_lags() == 0 &&
           hal_lag_id_for_ae(30) == 0 &&
           plan->rollback_last_idx == -1 &&
           g_lag_create_fail_after_mutation == 0 &&
           g_lag_delete_fail_after_mutation == 0);
    free_plan(plan);

    reset_simulator();
    plan = new_plan(1, UINT64_C(0x10022));
    expect("no-mutation LAG-create plan allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_CREATE;
    plan->steps[0].ae_id = 31;
    g_lag_create_fail_without_mutation = 1;
    status = apply_plan(plan);
    expect("no-mutation LAG create is classified as an SDK failure",
           status == NL_ERR_SDK_CALL_FAILED &&
           count_lags() == 0 &&
           hal_lag_id_for_ae(31) == 0 &&
           plan->rollback_last_idx == -1);
    free_plan(plan);

    reset_simulator();
    old_lag_id = bootstrap_lag(21);
    restored = find_lag(old_lag_id);
    expect("LAG restore fixture bootstraps semantic AE",
           old_lag_id > 0 && restored != NULL);
    if (!restored)
        return;
    restored->hash_rotation = SIM_HASH_ROTATION_B;
    restored->lacp_disposition = 91U;
    plan = new_plan(1, UINT64_C(0x10023));
    expect("mutate-then-error LAG-restore plan allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_DELETE;
    plan->steps[0].ae_id = 21;
    g_lag_delete_fail_after_mutation = 1;
    expect("delete mutate-then-error accepts authoritative absence",
           apply_plan(plan) == 0 &&
           find_lag(old_lag_id) == NULL &&
           hal_lag_id_for_ae(21) == 0 &&
           g_lag_delete_fail_after_mutation == 0);

    g_lag_create_fail_after_mutation = 1;
    expect("rollback reuses a uniquely classified created handle",
           hal_rollback_l2_plan(0, plan) == 0 &&
           g_lag_create_fail_after_mutation == 0);
    restored_lag_id = hal_lag_id_for_ae(21);
    restored = find_lag(restored_lag_id);
    expect("rollback restores exact LAG state despite create SDK error",
           restored && restored_lag_id != old_lag_id &&
           restored->hash_rotation == SIM_HASH_ROTATION_B &&
           restored->lacp_disposition == 91U &&
           count_lags() == 1 &&
           plan->rollback_last_idx == -1);
    free_plan(plan);
}

static void test_lag_global_handle_set_faults(void) {
    const int foreign_lag_id = 90;
    l2_apply_plan *plan;
    int status;

    reset_simulator();
    plan = new_plan(1, UINT64_C(0x10024));
    expect("transient post-create enumeration plan allocates",
           plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_CREATE;
    plan->steps[0].ae_id = 32;
    g_lag_post_create_enum_failures = 1;
    status = apply_plan(plan);
    expect("transient post-create read failure is reported",
           status == NL_ERR_HW_STATE_OUT_OF_SYNC);
    expect("transient post-create read failure removes its orphan",
           count_lags() == 0 &&
           hal_lag_id_for_ae(32) == 0 &&
           plan->rollback_last_idx == -1 &&
           g_lag_post_create_enum_failures == 0);
    free_plan(plan);

    reset_simulator();
    plan = new_plan(1, UINT64_C(0x10025));
    expect("persistent post-create enumeration plan allocates",
           plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_CREATE;
    plan->steps[0].ae_id = 33;
    g_lag_post_create_enum_failures = 32;
    status = apply_plan(plan);
    expect("persistent post-create read failure retains rollback authority",
           status == NL_ERR_ROLLBACK_FAILED &&
           count_lags() == 1 &&
           hal_lag_id_for_ae(33) == 0 &&
           plan->rollback_last_idx == 0 &&
           g_lag_post_create_enum_failures > 0);
    g_lag_post_create_enum_failures = 0;
    g_lag_post_create_enum_fault_armed = false;
    expect("retry after post-create reads recover removes the orphan",
           hal_rollback_l2_plan(0, plan) == 0 &&
           count_lags() == 0 &&
           hal_lag_id_for_ae(33) == 0 &&
           plan->rollback_last_idx == -1);
    free_plan(plan);

    reset_simulator();
    expect("foreign-handle fixture seeds an unowned LAG",
           allocate_lag(foreign_lag_id) != NULL &&
           count_lags() == 1);
    plan = new_plan(1, UINT64_C(0x10026));
    expect("foreign-handle ambiguous create plan allocates",
           plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_CREATE;
    plan->steps[0].ae_id = 34;
    g_lag_create_remove_foreign_id = foreign_lag_id;
    status = apply_plan(plan);
    expect("foreign removal retains the exact global rollback cursor",
           status == NL_ERR_ROLLBACK_FAILED &&
           find_lag(foreign_lag_id) == NULL &&
           count_lags() == 0 &&
           hal_lag_id_for_ae(34) == 0 &&
           plan->rollback_last_idx == 0);
    expect("foreign removal repair recreates the authorized baseline",
           allocate_lag(foreign_lag_id) != NULL);
    expect("foreign baseline repair lets retained rollback finish exactly",
           hal_rollback_l2_plan(0, plan) == 0 &&
           find_lag(foreign_lag_id) != NULL &&
           count_lags() == 1 &&
           hal_lag_id_for_ae(34) == 0 &&
           plan->rollback_last_idx == -1);
    free_plan(plan);

    reset_simulator();
    plan = new_plan(1, UINT64_C(0x10027));
    expect("multiple-addition ambiguous create plan allocates",
           plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_CREATE;
    plan->steps[0].ae_id = 35;
    g_lag_create_extra_additions = 1;
    status = apply_plan(plan);
    expect("multiple additions are all compensated without an orphan",
           status == NL_ERR_HW_STATE_OUT_OF_SYNC &&
           count_lags() == 0 &&
           hal_lag_id_for_ae(35) == 0 &&
           plan->rollback_last_idx == -1);
    free_plan(plan);
}

static void test_two_lag_delete_handle_replacement(void) {
    l2_apply_plan *plan;
    int old_first;
    int old_second;
    int restored_first;
    int restored_second;
    int apply_status;
    int rollback_status;

    reset_simulator();
    old_first = bootstrap_lag(40);
    old_second = bootstrap_lag(41);
    expect("two-LAG restore fixture seeds distinct semantic AEs",
           old_first > 0 && old_second > 0 &&
           old_first != old_second && count_lags() == 2);
    if (old_first <= 0 || old_second <= 0)
        return;

    plan = new_plan(2, UINT64_C(0x10028));
    expect("two-LAG delete plan allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_LAG_DELETE;
    plan->steps[0].ae_id = 40;
    plan->steps[1].type = L2_STEP_LAG_DELETE;
    plan->steps[1].ae_id = 41;
    apply_status = apply_plan(plan);
    expect("one plan deletes both semantic LAGs",
           apply_status == 0 &&
           count_lags() == 0 &&
           hal_lag_id_for_ae(40) == 0 &&
           hal_lag_id_for_ae(41) == 0 &&
           plan->rollback_last_idx == 1);

    rollback_status = hal_rollback_l2_plan(0, plan);
    restored_first = hal_lag_id_for_ae(40);
    restored_second = hal_lag_id_for_ae(41);
    if (rollback_status != 0) {
        printf("DETAIL: two-LAG rollback=%d old=%d,%d restored=%d,%d "
               "live=%d cursor=%d\n",
               rollback_status, old_first, old_second,
               restored_first, restored_second,
               count_lags(), plan->rollback_last_idx);
    }
    expect("reverse rollback preserves both allocator replacements",
           rollback_status == 0 &&
           restored_first > 0 && restored_second > 0 &&
           restored_first != restored_second &&
           restored_first != old_first &&
           restored_second != old_second &&
           find_lag(restored_first) != NULL &&
           find_lag(restored_second) != NULL &&
           count_lags() == 2 &&
           plan->rollback_last_idx == -1);
    free_plan(plan);
}

static void test_vlan_tag_side_effect_restore(void) {
    static const u8 static_mac[6] =
        {0x02, 0x00, 0x00, 0x00, 0x12, 0x01};
    static const u8 secure_mac[6] =
        {0x02, 0x00, 0x00, 0x00, 0x12, 0x02};
    l2_apply_plan *plan;
    sim_vlan_member *member;

    reset_simulator();
    expect("tag fixture seeds member and static MACs",
           seed_vlan_member(120, 7, false, 6) &&
           seed_mac(120, static_mac, 7, FM_ADDRESS_STATIC) &&
           seed_mac(120, secure_mac, 7, FM_ADDRESS_SECURE_STATIC));
    plan = new_plan(1, UINT64_C(0x1003));
    expect("tag transaction allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_VLAN_ADD_PORT;
    plan->steps[0].vid = 120;
    plan->steps[0].port = 7;
    plan->steps[0].tagged = true;

    expect("tag mutation applies through real hal_config",
           apply_plan(plan) == 0);
    member = find_vlan_member(find_vlan(120), 7);
    expect("SDK tag side effect is observable before rollback",
           member && member->tagged &&
           member->stp == SIM_DEFAULT_STP &&
           count_vlan_macs(120) == 0);
    expect("method41 restores tag, STP, static, and secure-static MAC",
           hal_rollback_l2_plan(0, plan) == 0);
    member = find_vlan_member(find_vlan(120), 7);
    expect("tag transaction exact state is restored",
           member && !member->tagged && member->stp == 6 &&
           mac_has_target(120, static_mac, 7, FM_ADDRESS_STATIC) &&
           mac_has_target(
               120, secure_mac, 7, FM_ADDRESS_SECURE_STATIC));
    free_plan(plan);
}

static void test_vlan_remove_side_effect_restore(void) {
    static const u8 static_mac[6] =
        {0x02, 0x00, 0x00, 0x00, 0x13, 0x01};
    static const u8 secure_mac[6] =
        {0x02, 0x00, 0x00, 0x00, 0x13, 0x02};
    l2_apply_plan *plan;
    sim_vlan_member *member;

    reset_simulator();
    expect("remove fixture seeds member and static MACs",
           seed_vlan_member(130, 8, true, 7) &&
           seed_mac(130, static_mac, 8, FM_ADDRESS_STATIC) &&
           seed_mac(130, secure_mac, 8, FM_ADDRESS_SECURE_STATIC));
    plan = new_plan(1, UINT64_C(0x1004));
    expect("remove transaction allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_VLAN_REM_PORT;
    plan->steps[0].vid = 130;
    plan->steps[0].port = 8;

    expect("member removal applies through real hal_config",
           apply_plan(plan) == 0);
    expect("apply preserves static/secure MACs despite SDK remove side effect",
           find_vlan_member(find_vlan(130), 8) == NULL &&
           mac_has_target(130, static_mac, 8, FM_ADDRESS_STATIC) &&
           mac_has_target(
               130, secure_mac, 8, FM_ADDRESS_SECURE_STATIC));
    expect("method41 restores removed member exactly",
           hal_rollback_l2_plan(0, plan) == 0);
    member = find_vlan_member(find_vlan(130), 8);
    expect("removed member tag, STP, and MAC set are exact",
           member && member->tagged && member->stp == 7 &&
           mac_has_target(130, static_mac, 8, FM_ADDRESS_STATIC) &&
           mac_has_target(
               130, secure_mac, 8, FM_ADDRESS_SECURE_STATIC));
    free_plan(plan);
}

static void test_lag_delete_retry_and_semantic_mac(void) {
    static const u8 mac[6] =
        {0x02, 0x00, 0x00, 0x00, 0x14, 0x01};
    l2_apply_plan *plan;
    sim_lag *old_lag;
    sim_lag *restored;
    int old_lag_id;
    int restored_lag_id;
    int creates_before_rollback;
    int apply_status;
    int first_status;
    int retry_status;

    reset_simulator();
    old_lag_id = bootstrap_lag(20);
    old_lag = find_lag(old_lag_id);
    expect("LAG-delete fixture bootstraps semantic AE",
           old_lag_id > 0 && old_lag != NULL);
    if (!old_lag)
        return;
    old_lag->hash_rotation = SIM_HASH_ROTATION_B;
    old_lag->lacp_disposition = 77U;
    expect("LAG-delete fixture seeds both members and semantic MAC",
           seed_lag_member(old_lag, 11) &&
           seed_lag_member(old_lag, 12) &&
           seed_vlan_member(140, old_lag->logical_port, true, 4) &&
           seed_mac(
               140, mac, old_lag->logical_port, FM_ADDRESS_STATIC));

    plan = new_plan(5, UINT64_C(0x1005));
    expect("LAG-delete transaction allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_STATIC_MAC_ADD;
    plan->steps[0].vid = 140;
    plan->steps[0].port = 9;
    memcpy(plan->steps[0].mac, mac, sizeof(mac));
    plan->steps[1].type = L2_STEP_VLAN_REM_PORT;
    plan->steps[1].vid = 140;
    plan->steps[1].ae_id = 20;
    plan->steps[2].type = L2_STEP_LAG_DEL_PORT;
    plan->steps[2].ae_id = 20;
    plan->steps[2].port = 11;
    plan->steps[3].type = L2_STEP_LAG_DEL_PORT;
    plan->steps[3].ae_id = 20;
    plan->steps[3].port = 12;
    plan->steps[4].type = L2_STEP_LAG_DELETE;
    plan->steps[4].ae_id = 20;

    g_trace_logs = true;
    apply_status = apply_plan(plan);
    g_trace_logs = false;
    if (apply_status != 0 || hal_lag_id_for_ae(20) != 0 ||
        find_lag(old_lag_id) != NULL) {
        printf("DETAIL: LAG delete apply=%d mapped=%d old-present=%d "
               "rollback-index=%d\n",
               apply_status, hal_lag_id_for_ae(20),
               find_lag(old_lag_id) != NULL,
               plan->rollback_last_idx);
    }
    expect("planned member deletes permit composite LAG delete",
           apply_status == 0 &&
           hal_lag_id_for_ae(20) == 0 &&
           find_lag(old_lag_id) == NULL);
    expect("original snapshot owns hash B, LACP, and member set",
           plan->original_steps[4].pre_lag_hash_rotation_valid &&
           plan->original_steps[4].pre_lag_hash_rotation ==
               SIM_HASH_ROTATION_B &&
           plan->original_steps[4].pre_lag_lacp_disposition_valid &&
           plan->original_steps[4].pre_lag_lacp_disposition == 77 &&
           plan->original_steps[4].pre_lag_member_count == 2 &&
           plan->original_steps[0].pre_mac_ae_id == 20);

    creates_before_rollback = g_lag_create_calls;
    g_hash_set_failures = 1;
    g_trace_logs = true;
    first_status = hal_rollback_l2_plan(0, plan);
    g_trace_logs = false;
    restored_lag_id = hal_lag_id_for_ae(20);
    restored = find_lag(restored_lag_id);
    expect("first method41 fails after creating one replacement handle",
           first_status == NL_ERR_ROLLBACK_FAILED &&
           restored && restored_lag_id != old_lag_id &&
           g_lag_create_calls == creates_before_rollback + 1);
    expect("failed attempt retains semantic MAC on replacement AE",
           restored &&
           mac_has_target(
               140, mac, restored->logical_port, FM_ADDRESS_STATIC));

    g_trace_logs = true;
    retry_status = hal_rollback_l2_plan(0, plan);
    g_trace_logs = false;
    if (first_status != NL_ERR_ROLLBACK_FAILED || retry_status != 0) {
        printf("DETAIL: LAG rollback first=%d retry=%d mapped=%d "
               "creates=%d restored-field=%d rollback-index=%d\n",
               first_status, retry_status, hal_lag_id_for_ae(20),
               g_lag_create_calls, plan->steps[4].restored_lag_id,
               plan->rollback_last_idx);
    }
    expect("method41 retry restores exact composite LAG state",
           retry_status == 0);
    restored_lag_id = hal_lag_id_for_ae(20);
    restored = find_lag(restored_lag_id);
    expect("retry reuses handle and restores hash/LACP/members",
           restored && restored_lag_id != old_lag_id &&
           g_lag_create_calls == creates_before_rollback + 1 &&
           restored->hash_rotation == SIM_HASH_ROTATION_B &&
           restored->lacp_disposition == 77U &&
           lag_has_member(restored, 11) &&
           lag_has_member(restored, 12));
    expect("static MAC rollback follows AE semantics, not stale handle",
           restored &&
           mac_has_target(
               140, mac, restored->logical_port, FM_ADDRESS_STATIC) &&
           !mac_has_target(140, mac, 9, FM_ADDRESS_STATIC));
    expect("successful method41 clears the rollback cursor",
           retry_status == 0 && plan->rollback_last_idx == -1);
    free_plan(plan);
}

static void test_security_table_creator_method41(void) {
    l2_apply_plan *plan;
    l2_apply_plan *failed_plan;
    l2_apply_plan *delete_plan;
    int writes_before;
    int first_status;

    reset_simulator();
    plan = new_plan(2, UINT64_C(0x1006));
    expect("security-table transaction allocates", plan != NULL);
    if (!plan)
        return;
    plan->steps[0].type = L2_STEP_INGRESS_IPV4_ACL_SET;
    plan->steps[0].ingress_ipv4_acl.vid = 150;
    plan->steps[0].ingress_ipv4_acl.port = 7;
    plan->steps[0].ingress_ipv4_acl.has_protocol = true;
    plan->steps[0].ingress_ipv4_acl.protocol = 6;
    plan->steps[1].type = L2_STEP_DHCP_SNOOPING_SET;
    plan->steps[1].security_vid = 150;
    plan->steps[1].security_port = 7;

    expect("shared security table applies ingress ACL then DHCP",
           apply_plan(plan) == 0 &&
           g_security_table_present &&
           g_security_ingress_present &&
           g_security_dhcp_present &&
           g_security_create_calls == 1);
    expect("only the actual ingress creator owns the generation token",
           plan->steps[0].security_table_creation_token.valid &&
           plan->steps[0].security_table_creation_token.generation ==
               g_security_active_generation &&
           !plan->steps[1].security_table_creation_token.valid);
    expect("creation token is excluded from original before-image",
           !plan->original_steps[0].security_table_creation_token.valid &&
           !plan->original_steps[1].security_table_creation_token.valid &&
           !plan->original_steps[0].pre_security_table_present &&
           !plan->original_steps[1].pre_security_table_present);

    g_security_release_failures = 1;
    first_status = hal_rollback_l2_plan(0, plan);
    expect("method41 release failure is fail-closed and retains token",
           first_status == NL_ERR_ROLLBACK_FAILED &&
           g_security_table_present &&
           !g_security_ingress_present &&
           !g_security_dhcp_present &&
           plan->steps[0].security_table_creation_token.valid &&
           plan->rollback_last_idx == 1);
    expect("method41 retry releases the creator-owned empty table",
           hal_rollback_l2_plan(0, plan) == 0 &&
           !g_security_table_present &&
           !plan->steps[0].security_table_creation_token.valid &&
           g_security_release_calls == 2 &&
           plan->rollback_last_idx == -1);
    free_plan(plan);

    reset_simulator();
    failed_plan = new_plan(1, UINT64_C(0x1007));
    expect("failed security SET transaction allocates",
           failed_plan != NULL);
    if (!failed_plan)
        return;
    failed_plan->steps[0].type = L2_STEP_DHCP_SNOOPING_SET;
    failed_plan->steps[0].security_vid = 151;
    failed_plan->steps[0].security_port = 8;
    g_security_set_failures = 1;
    expect("failed SET still transfers and consumes creator token",
           apply_plan(failed_plan) != 0 &&
           !g_security_table_present &&
           !failed_plan->steps[0].security_table_creation_token.valid &&
           g_security_create_calls == 1 &&
           g_security_release_calls == 1 &&
           failed_plan->rollback_last_idx == -1);
    free_plan(failed_plan);

    reset_simulator();
    delete_plan = new_plan(1, UINT64_C(0x1008));
    expect("absent security DELETE transaction allocates",
           delete_plan != NULL);
    if (!delete_plan)
        return;
    delete_plan->steps[0].type = L2_STEP_DHCP_SNOOPING_DEL;
    delete_plan->steps[0].security_vid = 152;
    delete_plan->steps[0].security_port = 9;
    writes_before = g_write_calls;
    expect("absent DELETE is zero-write and never creates table",
           apply_plan(delete_plan) == 0 &&
           g_write_calls == writes_before &&
           g_security_create_calls == 0 &&
           !delete_plan->steps[0].security_table_creation_token.valid);
    expect("method41 keeps absent DELETE zero-write",
           hal_rollback_l2_plan(0, delete_plan) == 0 &&
           g_write_calls == writes_before &&
           !g_security_table_present);
    free_plan(delete_plan);
}

static void expect_prestate_failure(
    const char *name, l2_apply_plan *plan, sim_fault fault) {
    int writes_before = g_write_calls;

    g_fault = fault;
    expect(name,
           apply_plan(plan) == NL_ERR_PRE_STATE_MISSING &&
           g_write_calls == writes_before &&
           plan->original_n_steps == 0 &&
           plan->rollback_last_idx == -1);
    g_fault = SIM_FAULT_NONE;
}

static void test_presence_and_read_errors_fail_closed(void) {
    l2_apply_plan *plan;
    sim_lag *lag;
    int lag_id;

    reset_simulator();
    plan = new_plan(1, UINT64_C(0x2001));
    plan->steps[0].type = L2_STEP_VLAN_CREATE;
    plan->steps[0].vid = 200;
    expect_prestate_failure(
        "VLAN presence first-read error is zero-write fail-closed",
        plan, SIM_FAULT_VLAN_FIRST);
    free_plan(plan);

    reset_simulator();
    expect("VLAN iterator fixture seeds lower VLAN", seed_vlan(50) != NULL);
    plan = new_plan(1, UINT64_C(0x2002));
    plan->steps[0].type = L2_STEP_VLAN_CREATE;
    plan->steps[0].vid = 200;
    expect_prestate_failure(
        "VLAN presence iterator error is zero-write fail-closed",
        plan, SIM_FAULT_VLAN_NEXT);
    free_plan(plan);

    reset_simulator();
    expect("member iterator fixture seeds ordered members",
           seed_vlan_member(210, 3, false, 1) &&
           seed_vlan_member(210, 7, true, 5));
    plan = new_plan(1, UINT64_C(0x2003));
    plan->steps[0].type = L2_STEP_VLAN_ADD_PORT;
    plan->steps[0].vid = 210;
    plan->steps[0].port = 7;
    plan->steps[0].tagged = false;
    expect_prestate_failure(
        "VLAN member iterator error is zero-write fail-closed",
        plan, SIM_FAULT_VLAN_PORT_NEXT);
    free_plan(plan);

    reset_simulator();
    expect("tag/STP/read fixture seeds member",
           seed_vlan_member(211, 7, true, 5));
    plan = new_plan(1, UINT64_C(0x2004));
    plan->steps[0].type = L2_STEP_VLAN_ADD_PORT;
    plan->steps[0].vid = 211;
    plan->steps[0].port = 7;
    plan->steps[0].tagged = false;
    expect_prestate_failure(
        "VLAN tag read error is zero-write fail-closed",
        plan, SIM_FAULT_VLAN_TAG);
    expect_prestate_failure(
        "VLAN STP read error is zero-write fail-closed",
        plan, SIM_FAULT_VLAN_STP);
    expect_prestate_failure(
        "static/secure MAC table read error is zero-write fail-closed",
        plan, SIM_FAULT_ADDRESS_READ);
    free_plan(plan);

    reset_simulator();
    lag_id = bootstrap_lag(30);
    lag = find_lag(lag_id);
    expect("LAG read-error fixture bootstraps target", lag != NULL);
    if (!lag)
        return;
    expect("LAG iterator fixture seeds lower handle",
           allocate_lag(lag_id - 1) != NULL);
    plan = new_plan(1, UINT64_C(0x2005));
    plan->steps[0].type = L2_STEP_LAG_HASH_ROTATION_SET;
    plan->steps[0].ae_id = 30;
    plan->steps[0].lag_hash_rotation = SIM_HASH_ROTATION_B;
    expect_prestate_failure(
        "LAG presence iterator error is zero-write fail-closed",
        plan, SIM_FAULT_LAG_NEXT);
    free_plan(plan);

    g_lags[SIM_MAX_LAGS - 1].used = false;
    plan = new_plan(1, UINT64_C(0x2006));
    plan->steps[0].type = L2_STEP_LAG_DELETE;
    plan->steps[0].ae_id = 30;
    expect_prestate_failure(
        "LAG member-list read error is zero-write fail-closed",
        plan, SIM_FAULT_LAG_LIST);
    expect_prestate_failure(
        "LAG hash read error is zero-write fail-closed",
        plan, SIM_FAULT_LAG_HASH_READ);
    expect_prestate_failure(
        "LAG LACP read error is zero-write fail-closed",
        plan, SIM_FAULT_LAG_ATTRIBUTE);
    free_plan(plan);

    plan = new_plan(1, UINT64_C(0x2007));
    plan->steps[0].type = L2_STEP_VLAN_ADD_PORT;
    plan->steps[0].vid = 220;
    plan->steps[0].ae_id = 30;
    expect("AE read-error fixture seeds VLAN", seed_vlan(220) != NULL);
    expect_prestate_failure(
        "AE logical-port read error is zero-write fail-closed",
        plan, SIM_FAULT_LAG_TO_LOGICAL);
    free_plan(plan);
}

static l2_apply_plan *new_qos_watermark_transaction_plan(u64 tx_id) {
    l2_apply_plan *plan = new_plan(3, tx_id);

    if (!plan)
        return NULL;
    plan->steps[0].type = L2_STEP_QOS_PRIORITY_MAP_SET;
    plan->steps[0].qos_switch_priority = 3;
    plan->steps[0].qos_traffic_class = 6;

    plan->steps[1].type = L2_STEP_QOS_WATERMARK_DEL;
    plan->steps[1].port = SIM_QOS_PORT;
    plan->steps[1].qos_watermark_attr =
        HAL_QOS_WATERMARK_ATTR_TX_HOG;
    plan->steps[1].qos_watermark_index = 0;
    plan->steps[1].qos_watermark_reconcile = 1;

    plan->steps[2].type = L2_STEP_QOS_WATERMARK_SET;
    plan->steps[2].port = SIM_QOS_PORT;
    plan->steps[2].qos_watermark_attr =
        HAL_QOS_WATERMARK_ATTR_TX_HOG;
    plan->steps[2].qos_watermark_index = 1;
    plan->steps[2].qos_watermark_value = 192 * 120;
    plan->steps[2].qos_watermark_owner_create = 0;
    plan->steps[2].qos_watermark_reconcile = 1;
    return plan;
}

static bool qos_watermark_original_state_restored(
    const u32 original_watermark[SIM_QOS_WATERMARK_COUNT],
    const bool original_owner_present[SIM_QOS_WATERMARK_COUNT],
    const bool original_baseline_known[SIM_QOS_WATERMARK_COUNT],
    const int original_baseline[SIM_QOS_WATERMARK_COUNT],
    const int original_owner_value[SIM_QOS_WATERMARK_COUNT],
    int original_priority) {
    return memcmp(g_qos_watermark, original_watermark,
                  sizeof(g_qos_watermark)) == 0 &&
        memcmp(g_qos_owner_present, original_owner_present,
               sizeof(g_qos_owner_present)) == 0 &&
        memcmp(g_qos_owner_baseline_known, original_baseline_known,
               sizeof(g_qos_owner_baseline_known)) == 0 &&
        memcmp(g_qos_owner_baseline, original_baseline,
               sizeof(g_qos_owner_baseline)) == 0 &&
        memcmp(g_qos_owner_value, original_owner_value,
               sizeof(g_qos_owner_value)) == 0 &&
        g_qos_priority_map[3] == original_priority;
}

static void test_qos_shared_watermark_plan_transaction(void) {
    l2_apply_plan *plan;
    u32 original_watermark[SIM_QOS_WATERMARK_COUNT];
    bool original_owner_present[SIM_QOS_WATERMARK_COUNT];
    bool original_baseline_known[SIM_QOS_WATERMARK_COUNT];
    int original_baseline[SIM_QOS_WATERMARK_COUNT];
    int original_owner_value[SIM_QOS_WATERMARK_COUNT];
    int original_priority;

    reset_simulator();
    memcpy(original_watermark, g_qos_watermark,
           sizeof(original_watermark));
    memcpy(original_owner_present, g_qos_owner_present,
           sizeof(original_owner_present));
    memcpy(original_baseline_known, g_qos_owner_baseline_known,
           sizeof(original_baseline_known));
    memcpy(original_baseline, g_qos_owner_baseline,
           sizeof(original_baseline));
    memcpy(original_owner_value, g_qos_owner_value,
           sizeof(original_owner_value));
    original_priority = g_qos_priority_map[3];
    plan = new_qos_watermark_transaction_plan(UINT64_C(0x3001));
    expect("QoS shared-image transaction allocates", plan != NULL);
    if (!plan)
        return;
    expect("trigger, reconciled DEL, and candidate replay apply together",
           apply_plan(plan) == 0);
    expect("plan captures one complete shared image before any mutation",
           plan->qos_auto_pause_watermark_snapshot_required &&
           g_qos_shared_snapshot_calls == 1 &&
           g_qos_shared_pre_mutation_snapshots == 1 &&
           g_qos_shared_restore_calls == 0);
    expect("DEL target is captured after the calculator and before owner mutation",
           plan->steps[1].pre_qos_watermark.value ==
               g_qos_calculated_watermark[0] &&
           plan->steps[1].qos_watermark_delete_target.value ==
               g_qos_calculated_watermark[0] &&
           !g_qos_owner_present[0] &&
           g_qos_watermark[0] == g_qos_calculated_watermark[0]);
    expect("positive path ends with the surviving candidate override replayed",
           g_qos_owner_present[1] &&
           g_qos_watermark[1] ==
               (u32)plan->steps[2].qos_watermark_value &&
           g_qos_shared_restore_calls == 0);
    expect("persistent rollback restores the exact combined QoS state",
           hal_rollback_l2_plan(0, plan) == 0 &&
           qos_watermark_original_state_restored(
               original_watermark, original_owner_present,
               original_baseline_known, original_baseline,
               original_owner_value, original_priority));
    expect("rollback restores direct and trigger inputs before one shared image",
           g_qos_shared_restore_calls == 1 &&
           g_qos_last_direct_restore_event > 0 &&
           g_qos_last_trigger_event >
               g_qos_last_direct_restore_event &&
           g_qos_shared_restore_event >
               g_qos_last_trigger_event &&
           plan->rollback_last_idx == -1);
    free_plan(plan);

    reset_simulator();
    memcpy(original_watermark, g_qos_watermark,
           sizeof(original_watermark));
    memcpy(original_owner_present, g_qos_owner_present,
           sizeof(original_owner_present));
    memcpy(original_baseline_known, g_qos_owner_baseline_known,
           sizeof(original_baseline_known));
    memcpy(original_baseline, g_qos_owner_baseline,
           sizeof(original_baseline));
    memcpy(original_owner_value, g_qos_owner_value,
           sizeof(original_owner_value));
    original_priority = g_qos_priority_map[3];
    plan = new_qos_watermark_transaction_plan(UINT64_C(0x3002));
    expect("QoS failure-rollback transaction allocates", plan != NULL);
    if (!plan)
        return;
    g_qos_apply_failures = 1;
    expect("failed candidate replay rolls back the complete combined image",
           apply_plan(plan) != 0 &&
           qos_watermark_original_state_restored(
               original_watermark, original_owner_present,
               original_baseline_known, original_baseline,
               original_owner_value, original_priority));
    expect("failure rollback also restores shared image exactly once and last",
           g_qos_shared_pre_mutation_snapshots == 1 &&
           g_qos_shared_restore_calls == 1 &&
           g_qos_last_direct_restore_event > 0 &&
           g_qos_last_trigger_event >
               g_qos_last_direct_restore_event &&
           g_qos_shared_restore_event >
               g_qos_last_trigger_event &&
           plan->rollback_last_idx == -1);
    free_plan(plan);

    reset_simulator();
    g_qos_auto_pause_mode = false;
    memcpy(original_watermark, g_qos_watermark,
           sizeof(original_watermark));
    memcpy(original_owner_present, g_qos_owner_present,
           sizeof(original_owner_present));
    memcpy(original_baseline_known, g_qos_owner_baseline_known,
           sizeof(original_baseline_known));
    memcpy(original_baseline, g_qos_owner_baseline,
           sizeof(original_baseline));
    memcpy(original_owner_value, g_qos_owner_value,
           sizeof(original_owner_value));
    original_priority = g_qos_priority_map[3];
    plan = new_qos_watermark_transaction_plan(UINT64_C(0x3003));
    expect("disabled auto-pause QoS transaction allocates", plan != NULL);
    if (!plan)
        return;
    expect("disabled auto-pause uses durable authority instead of false calculator authority",
           apply_plan(plan) == 0 &&
           plan->steps[1].qos_watermark_reconcile == 0 &&
           plan->steps[2].qos_watermark_reconcile == 0 &&
           plan->steps[1].qos_watermark_delete_target.value ==
               (u32)original_baseline[0]);
    expect("disabled auto-pause transaction still rolls back the raw shared image exactly",
           hal_rollback_l2_plan(0, plan) == 0 &&
           g_qos_shared_restore_calls == 1 &&
           qos_watermark_original_state_restored(
               original_watermark, original_owner_present,
               original_baseline_known, original_baseline,
               original_owner_value, original_priority));
    free_plan(plan);
}

int main(void) {
    test_absent_vlan_parent_transaction();
    test_absent_lag_parent_and_ae_target();
    test_lag_non_idempotent_error_classification();
    test_lag_global_handle_set_faults();
    test_two_lag_delete_handle_replacement();
    test_vlan_tag_side_effect_restore();
    test_vlan_remove_side_effect_restore();
    test_lag_delete_retry_and_semantic_mac();
    test_security_table_creator_method41();
    test_presence_and_read_errors_fail_closed();
    test_qos_shared_watermark_plan_transaction();
    return g_failures == 0 ? 0 : 1;
}
