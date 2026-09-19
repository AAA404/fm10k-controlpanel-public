/* The production member adapter and public HAL run against pinned SDK types.
 * Only the SDK boundary is simulated, including IES's partial mutations and
 * its failure to remove VLAN membership when detaching a member. */
#include "../vendor/netlab/sbin/switchd/fm10k_lag.c"
#include "../vendor/netlab/sbin/switchd/hal_lag.c"
#include <assert.h>
#include <limits.h>
#include <stdio.h>

static fm_rootApi api;
static fm_rootPlatform platform;
static fm_switch switch_state;
static fm_rwLock switch_lock;
fm_rootApi *fmRootApi = &api;
fm_rootPlatform *fmRootPlatform = &platform;
static lag_port_image hardware[128], saved[25], initial[128];
static int membership[25], initial_membership[25], closed[25];
static bool vlans[LAG_VLANS], property = true, native = true, lock_held;
static int writes, fault_at, drop_at, fail_after, fail_delete, fail_close;
static int fail_read_after_write, fail_read_lag, count_override, logical_error, lag_cycle, invalid_handle;
static int attr_read_error, take_error, drop_error, close_calls, adds, deletes;
static nl_port_scope_status active_scope;
static bool swapped_handles;

bool fm10k_native_profile(void) { return native; }
nl_port_scope_status nl_port_scope_get(void) { return active_scope; }
int hal_lag_ae_for_id(int lag) { return lag == 7 ? (swapped_handles ? 1 : 0) : lag == 9 ? (swapped_handles ? 0 : 1) : -1; }
int hal_lag_id_for_ae(int ae) { return ae == 0 ? (swapped_handles ? 9 : 7) : ae == 1 ? (swapped_handles ? 7 : 9) : 0; }
bool nl_ifid_get_by_logical_port(int port, nl_port_entry *entry) {
    if (port < 1 || port > 24) return false;
    memset(entry, 0, sizeof(*entry)); entry->logical_port = port; entry->flags = NL_PORT_FLAG_EXTERNAL;
    return true;
}
const char *fmErrorMsg(fm_int error) { (void)error; return "fixture"; }
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
fm_status fmCaptureReadLock(fm_rwLock *lock, fm_timestamp *timeout) {
    (void)timeout; assert(lock == &switch_lock && !lock_held);
    if (take_error) return FM_FAIL;
    lock_held = true; return FM_OK;
}
fm_status fmReleaseReadLock(fm_rwLock *lock) {
    assert(lock == &switch_lock && lock_held); lock_held = false;
    return drop_error ? FM_FAIL : FM_OK;
}
fm_status fmGetApiProperty(fm_text key, fm_apiAttrType type, void *out) {
    assert(!strcmp(key, FM_AAK_API_PER_LAG_MANAGEMENT) && type == FM_API_ATTR_BOOL && !lock_held);
    *(fm_bool *)out = property ? TRUE : FALSE; return FM_OK;
}
static int attribute_index(int attr) {
    for (size_t index = 0; index < LAG_ATTR_COUNT; ++index)
        if (lag_attributes[index].id == attr) return (int)index;
    assert(false); return -1;
}
fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(sw == 0 && port > 0 && port < 128 && !lock_held);
    if (attr_read_error) return FM_FAIL;
    int index = attribute_index(attr); u32 value = hardware[port].attributes[index];
    if (lag_attributes[index].type == LAG_BOOL) *(fm_bool *)out = value ? TRUE : FALSE;
    else if (lag_attributes[index].type == LAG_INT) *(fm_int *)out = (fm_int)value;
    else *(fm_uint32 *)out = value;
    return FM_OK;
}
static bool begin_write(void) { ++writes; return writes == fault_at && !fail_after; }
static fm_status end_write(void) { return writes == fault_at ? FM_FAIL : FM_OK; }
fm_status fmSetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *in) {
    assert(sw == 0 && port > 0 && port <= 24 && !membership[port] && !lock_held);
    int index = attribute_index(attr);
    if (begin_write()) return FM_FAIL;
    if (writes != drop_at) hardware[port].attributes[index] = lag_attributes[index].type == LAG_BOOL ?
        (*(fm_bool *)in != FALSE) : lag_attributes[index].type == LAG_INT ? (u32)*(fm_int *)in : *(fm_uint32 *)in;
    return end_write();
}
fm_status fmGetVlanFirst(fm_int sw, fm_int *vid) {
    assert(!sw && !lock_held); *vid = -1;
    for (int i = 1; i < LAG_VLANS; ++i) if (vlans[i]) { *vid = i; break; }
    return FM_OK;
}
fm_status fmGetVlanNext(fm_int sw, fm_int current, fm_int *next) {
    assert(!sw && current > 0 && current < LAG_VLANS && !lock_held); *next = -1;
    for (int i = current + 1; i < LAG_VLANS; ++i) if (vlans[i]) { *next = i; break; }
    return FM_OK;
}
fm_status fmGetVlanPortTag(fm_int sw, fm_int vid, fm_int port, fm_bool *tag) {
    assert(!sw && port > 0 && port < 128 && !lock_held);
    if (vid <= 0 || vid >= LAG_VLANS || !vlans[vid]) return FM_ERR_INVALID_VLAN;
    u8 flags = hardware[port].vlans[vid];
    if (!(flags & VLAN_PRESENT)) return FM_ERR_INVALID_PORT;
    *tag = flags & VLAN_TAGGED ? TRUE : FALSE; return FM_OK;
}
fm_status fmGetVlanPortState(fm_int sw, fm_uint16 vid, fm_int port, fm_int *stp) {
    fm_bool tag; fm_status status = fmGetVlanPortTag(sw, vid, port, &tag);
    if (status == FM_OK) *stp = hardware[port].vlans[vid] >> VLAN_STP_SHIFT;
    return status;
}
fm_status fmAddVlanPort(fm_int sw, fm_uint16 vid, fm_int port, fm_bool tag) {
    assert(!sw && vid > 0 && vid < LAG_VLANS && vlans[vid] && port > 0 && port <= 24 && !lock_held);
    if (begin_write()) return FM_FAIL;
    if (writes != drop_at) hardware[port].vlans[vid] = VLAN_PRESENT | (tag ? VLAN_TAGGED : 0) |
        (FM_STP_STATE_FORWARDING << VLAN_STP_SHIFT);
    return end_write();
}
fm_status fmChangeVlanPort(fm_int sw, fm_uint16 vid, fm_int port, fm_bool tag) {
    return fmAddVlanPort(sw, vid, port, tag);
}
fm_status fmDeleteVlanPort(fm_int sw, fm_uint16 vid, fm_int port) {
    assert(!sw && vid > 0 && vid < LAG_VLANS && port > 0 && port <= 24 && !lock_held);
    if (begin_write()) return FM_FAIL;
    if (writes != drop_at) hardware[port].vlans[vid] = 0;
    return end_write();
}
fm_status fmSetVlanPortState(fm_int sw, fm_uint16 vid, fm_int port, fm_int stp) {
    assert(!sw && port > 0 && port <= 24 && stp >= 0 && stp <= 4 && !lock_held);
    if (begin_write()) return FM_FAIL;
    if (writes != drop_at) hardware[port].vlans[vid] = (hardware[port].vlans[vid] & 3) | (u8)(stp << VLAN_STP_SHIFT);
    return end_write();
}
fm_status fmGetLAGFirst(fm_int sw, fm_int *lag) {
    assert(!sw && !lock_held);
    if (writes && fail_read_after_write) { --fail_read_after_write; return FM_FAIL; }
    *lag = invalid_handle == 1 ? 0 : 7; return FM_OK;
}
fm_status fmGetLAGNext(fm_int sw, fm_int current, fm_int *lag) {
    assert(!sw && !lock_held);
    if (invalid_handle == 2) { *lag = 0; return FM_OK; }
    if (lag_cycle) { *lag = current; return FM_OK; }
    if (current == 7) { *lag = 9; return FM_OK; }
    assert(current == 9); return FM_ERR_NO_LAGS;
}
fm_status fmGetLAGPortList(fm_int sw, fm_int lag, fm_int *count, fm_int *ports, fm_int capacity) {
    assert(!sw && (lag == 7 || lag == 9) && capacity >= 24 && !lock_held);
    if (fail_read_lag == lag) return FM_FAIL;
    *count = 0;
    for (int port = 1; port <= 24; ++port) if (membership[port] == lag) ports[(*count)++] = port;
    if (count_override != INT_MIN && lag == 7) *count = count_override;
    return FM_OK;
}
fm_status fmGetLAGPortFirst(fm_int sw, fm_int lag, fm_int *port) {
    fm_int ports[24], count;
    fm_status result = fmGetLAGPortList(sw, lag, &count, ports, 24);
    if (result != FM_OK) return result;
    if (!count) return FM_ERR_NO_PORTS_IN_LAG;
    *port = ports[0]; return FM_OK;
}
fm_status fmGetLAGPortNext(fm_int sw, fm_int lag, fm_int current, fm_int *port) {
    assert(!sw);
    for (int i = current + 1; i <= 24; ++i) if (membership[i] == lag) { *port = i; return FM_OK; }
    return FM_ERR_NO_PORTS_IN_LAG;
}
fm_status fmLAGNumberToLogicalPort(fm_int sw, fm_int lag, fm_int *logical) {
    assert(!sw && !lock_held);
    if (logical_error) return FM_FAIL;
    if (lag != 7 && lag != 9) return FM_ERR_INVALID_LAG;
    *logical = lag == 7 ? 100 : 101; return FM_OK;
}
fm_status fmAddLAGPort(fm_int sw, fm_int lag, fm_int port) {
    assert(!sw && (lag == 7 || lag == 9) && port > 0 && port <= 24 && !lock_held);
    ++adds;
    if (membership[port]) return FM_ERR_ALREADYUSED_PORT;
    int logical = lag == 7 ? 100 : 101;
    saved[port] = hardware[port];
    if (begin_write()) return FM_FAIL;
    if (writes != drop_at) membership[port] = lag;
    if (end_write() != FM_OK) return FM_FAIL;
    for (size_t i = 0; i < LAG_ATTR_COUNT; ++i) {
        if (begin_write()) return FM_FAIL;
        if (writes != drop_at) hardware[port].attributes[i] = hardware[logical].attributes[i];
        if (end_write() != FM_OK) return FM_FAIL;
    }
    for (int vid = 1; vid < LAG_VLANS; ++vid) if (hardware[logical].vlans[vid]) {
        if (begin_write()) return FM_FAIL;
        if (writes != drop_at) hardware[port].vlans[vid] = hardware[logical].vlans[vid];
        if (end_write() != FM_OK) return FM_FAIL;
    }
    return FM_OK;
}
fm_status fmDeleteLAGPort(fm_int sw, fm_int lag, fm_int port) {
    assert(!sw && port > 0 && port <= 24 && membership[port] == lag && !lock_held);
    ++deletes;
    if (fail_delete || begin_write()) return FM_FAIL;
    if (writes != drop_at) membership[port] = 0;
    if (end_write() != FM_OK) return FM_FAIL;
    /* Like IES, restore attributes but deliberately leave the VLANs. */
    for (size_t i = 0; i < LAG_ATTR_COUNT; ++i) {
        if (begin_write()) return FM_FAIL;
        if (writes != drop_at) hardware[port].attributes[i] = saved[port].attributes[i];
        if (end_write() != FM_OK) return FM_FAIL;
    }
    return FM_OK;
}
int hal_port_set_admin_state(int sw, int port, int mode) {
    assert(!sw && port > 0 && port <= 24 && mode == FM_PORT_MODE_ADMIN_DOWN && !lock_held);
    ++close_calls; closed[port] = 1; return fail_close ? NL_ERR_SDK_CALL_FAILED : 0;
}

static void reset(void) {
    memset(&api, 0, sizeof(api)); memset(&platform, 0, sizeof(platform));
    memset(&switch_state, 0, sizeof(switch_state));
    api.fmSwitchStateTable[0] = &switch_state; api.fmSwitchLockTable[0] = &switch_lock;
    platform.cfg.numSwitches = 1; switch_state.perLagMgmt = TRUE;
    memset(lag_owners, 0, sizeof(lag_owners)); lag_thread_set = lag_lock_fault = false;
    memset(lag_rollback_images, 0, sizeof(lag_rollback_images));
    memset(&active_scope, 0, sizeof(active_scope)); swapped_handles = false;
    memset(hardware, 0, sizeof(hardware)); memset(membership, 0, sizeof(membership));
    memset(closed, 0, sizeof(closed)); memset(vlans, 0, sizeof(vlans));
    property = native = true; lock_held = false;
    writes = fault_at = drop_at = fail_after = fail_delete = fail_close = 0;
    fail_read_after_write = fail_read_lag = logical_error = lag_cycle = invalid_handle = 0;
    take_error = drop_error = attr_read_error = close_calls = adds = deletes = 0; count_override = INT_MIN;
    for (int port = 1; port <= 24; ++port)
        for (size_t i = 0; i < LAG_ATTR_COUNT; ++i)
            hardware[port].attributes[i] = lag_attributes[i].type == LAG_BOOL ? (i & 1) : (u32)(100 + i + port);
    for (int logical = 100; logical <= 101; ++logical) {
        for (size_t i = 0; i < LAG_ATTR_COUNT; ++i)
            hardware[logical].attributes[i] = lag_attributes[i].type == LAG_BOOL ? !(i & 1) : (u32)(1000 + i + logical);
        hardware[logical].vlans[10] = VLAN_PRESENT | VLAN_TAGGED | (FM_STP_STATE_BLOCKING << VLAN_STP_SHIFT);
        hardware[logical].vlans[100] = VLAN_PRESENT | (FM_STP_STATE_FORWARDING << VLAN_STP_SHIFT);
        hardware[logical].vlans[4094] = VLAN_PRESENT | VLAN_TAGGED | (FM_STP_STATE_LEARNING << VLAN_STP_SHIFT);
    }
    vlans[1] = vlans[10] = vlans[100] = vlans[4094] = true;
    memcpy(initial, hardware, sizeof(initial)); memcpy(initial_membership, membership, sizeof(membership));
}
static void unchanged_others(int port) {
    for (int i = 1; i < 128; ++i) if (i != port) assert(image_equal(&hardware[i], &initial[i]));
    for (int i = 1; i <= 24; ++i) if (i != port)
        assert(membership[i] == initial_membership[i] && !closed[i]);
    assert(!lock_held);
}
static void readback_faults(void) {
    struct sdk_result result;
    reset(); assert(!hal_lag_get_all(0, &result) && result.data.lag_list.n_lags == 2);
    fail_read_lag = 7;
    assert(!hal_lag_get_all(0, &result));
    assert(result.data.lag_list.lag[0].member_status && !result.data.lag_list.lag[1].member_status);
    fail_read_lag = 0;
    const int invalid_counts[] = {-1, NETLAB_MAX_LAG_MEMBERS + 1};
    for (unsigned i = 0; i < sizeof(invalid_counts) / sizeof(invalid_counts[0]); ++i) {
        count_override = invalid_counts[i]; assert(!hal_lag_get_all(0, &result));
        assert(result.data.lag_list.lag[0].member_status);
    }
    count_override = INT_MIN; logical_error = 1;
    assert(!hal_lag_get_all(0, &result) && result.data.lag_list.lag[0].logical_port_status);
    logical_error = 0; lag_cycle = 1; assert(hal_lag_get_all(0, &result));
    lag_cycle = 0;
    for (invalid_handle = 1; invalid_handle <= 2; ++invalid_handle)
        assert(hal_lag_get_all(0, &result) == NL_ERR_PRE_STATE_MISSING);
    reset(); membership[1] = 7;
    assert(!hal_lag_get_all(0, &result) && result.data.lag_list.lag[0].member_status);
}
static void transaction_images(void) {
    reset(); assert(!hal_lag_add_port(0, 7, 5));
    active_scope = (nl_port_scope_status){.schema = NL_PORT_SCOPE_SCHEMA, .tx_id = 101, .mask = 0x10};
    assert(!hal_lag_del_port_transaction(0, 7, 5, 101));
    assert(lag_rollback_images[4].tx_id == 101 && !lag_owners[4].valid);
    assert(hal_lag_transaction_check(101, false) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    /* Reverse per-port operations can restore the previously visible LAG
     * projection before the member-removal step itself is rolled back. */
    hardware[5] = hardware[100];
    int before = writes;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_COMMIT_LOCKED && writes == before);
    assert(hal_lag_restore_port(0, 7, 5, 102) == NL_ERR_COMMIT_LOCKED && writes == before);
    assert(!hal_lag_restore_port(0, 7, 5, 101));
    assert(image_equal(&lag_owners[4].detached, &initial[5]));
    before = writes;
    assert(!hal_lag_restore_port(0, 7, 5, 101) && writes == before);
    attr_read_error = 1;
    assert(hal_lag_transaction_check(101, false) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    assert(lag_rollback_images[4].tx_id == 101);
    attr_read_error = 0;
    assert(!hal_lag_transaction_check(101, false));
    hal_lag_transaction_retire(101); assert(!lag_rollback_images[4].tx_id);
    memset(&active_scope, 0, sizeof(active_scope));
    assert(!hal_lag_del_port(0, 7, 5) && image_equal(&hardware[5], &initial[5]));
    unchanged_others(5);

    reset(); assert(!hal_lag_add_port(0, 7, 5));
    active_scope = (nl_port_scope_status){.schema = NL_PORT_SCOPE_SCHEMA, .tx_id = 103, .mask = 0x10};
    assert(!hal_lag_del_port_transaction(0, 7, 5, 103));
    swapped_handles = true; hardware[101] = hardware[100];
    assert(!hal_lag_restore_port(0, 9, 5, 103));
    assert(!hal_lag_transaction_check(103, false)); hal_lag_transaction_retire(103);
    memset(&active_scope, 0, sizeof(active_scope));
    assert(!hal_lag_del_port(0, 9, 5) && image_equal(&hardware[5], &initial[5]));

    reset(); assert(!hal_lag_add_port(0, 7, 5));
    active_scope = (nl_port_scope_status){.schema = NL_PORT_SCOPE_SCHEMA, .tx_id = 104, .mask = 0x10};
    assert(!hal_lag_del_port_transaction(0, 7, 5, 104));
    hardware[5] = hardware[100]; fault_at = writes + 2; fail_after = 1;
    assert(hal_lag_restore_port(0, 7, 5, 104) != 0 && lag_rollback_images[4].tx_id == 104);
    assert(!membership[5] && !close_calls);
    fault_at = 0;
    assert(!hal_lag_restore_port(0, 7, 5, 104));
    assert(!hal_lag_transaction_check(104, false)); hal_lag_transaction_retire(104);
    memset(&active_scope, 0, sizeof(active_scope));
    assert(!hal_lag_del_port(0, 7, 5) && image_equal(&hardware[5], &initial[5]));

    reset(); assert(!hal_lag_add_port(0, 7, 1) && !hal_lag_add_port(0, 7, 5));
    active_scope = (nl_port_scope_status){.schema = NL_PORT_SCOPE_SCHEMA, .tx_id = 105, .mask = 0x11};
    assert(!hal_lag_del_port_transaction(0, 7, 1, 105) && !hal_lag_del_port_transaction(0, 7, 5, 105));
    assert(!hal_lag_restore_port(0, 7, 1, 105));
    assert(hal_lag_transaction_check(105, false) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    assert(lag_rollback_images[0].tx_id == 105 && lag_rollback_images[4].tx_id == 105);
    assert(!hal_lag_restore_port(0, 7, 5, 105));
    assert(!hal_lag_transaction_check(105, false)); hal_lag_transaction_retire(105);
    assert(!lag_rollback_images[0].tx_id && !lag_rollback_images[4].tx_id);

    reset(); assert(!hal_lag_add_port(0, 7, 5));
    active_scope = (nl_port_scope_status){.schema = NL_PORT_SCOPE_SCHEMA, .tx_id = 106, .mask = 0x10};
    assert(!hal_lag_del_port_transaction(0, 7, 5, 106));
    hardware[5].attributes[0] = 777; lag_port_image committed = hardware[5];
    membership[5] = 7;
    assert(hal_lag_transaction_check(106, true) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    membership[5] = 0;
    assert(!hal_lag_transaction_check(106, true)); hal_lag_transaction_retire(106);
    memset(&active_scope, 0, sizeof(active_scope));
    assert(!hal_lag_add_port(0, 7, 5) && !hal_lag_del_port(0, 7, 5));
    assert(image_equal(&hardware[5], &committed));

    reset();
    active_scope = (nl_port_scope_status){.schema = NL_PORT_SCOPE_SCHEMA, .tx_id = 107, .mask = 0x10};
    fault_at = 2; fail_after = 1; fail_delete = 1;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    assert(!lag_rollback_images[4].tx_id && lag_owners[4].faulted);
    assert(hal_lag_transaction_check(107, false) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    assert(hal_lag_transaction_check(107, true) == NL_ERR_HW_STATE_OUT_OF_SYNC);
}
int main(void) {
    for (int port = 1; port <= 24; ++port) {
        reset(); int lag = port <= 12 ? 7 : 9, logical = lag == 7 ? 100 : 101;
        assert(!hal_lag_add_port(0, lag, port));
        assert(membership[port] == lag && image_equal(&hardware[port], &hardware[logical]));
        int before = writes; assert(!hal_lag_add_port(0, lag, port) && writes == before);
        struct sdk_result result; assert(!hal_lag_get_all(0, &result));
        assert(!result.data.lag_list.lag[lag == 7 ? 0 : 1].member_status);
        assert(!hal_lag_del_port(0, lag, port) && !membership[port]);
        assert(image_equal(&hardware[port], &initial[port]) && !lag_owners[port - 1].valid && !close_calls);
        before = writes; assert(!hal_lag_del_port(0, lag, port) && writes == before);
        unchanged_others(port);
    }
    /* Fail every list, attribute and VLAN mutation inside SDK attach. */
    const int attach_writes = 1 + (int)LAG_ATTR_COUNT + 3;
    for (int after = 0; after <= 1; ++after) for (int fault = 1; fault <= attach_writes; ++fault) {
        reset(); fault_at = fault; fail_after = after;
        assert(hal_lag_add_port(0, 7, 5) != 0);
        assert(!membership[5] && image_equal(&hardware[5], &initial[5]));
        assert(!lag_owners[4].valid && !lag_owners[4].faulted && !close_calls);
        unchanged_others(5);
    }
    for (int drop = 1; drop <= attach_writes; ++drop) {
        reset(); drop_at = drop;
        assert(hal_lag_add_port(0, 7, 5) == NL_ERR_READBACK_MISMATCH);
        assert(!membership[5] && image_equal(&hardware[5], &initial[5]) && !close_calls);
        unchanged_others(5);
    }
    /* Partial SDK detach is repaired to the detached image, never reattached
     * after partner loss. A failure before removal closes the one port. */
    for (int after = 0; after <= 1; ++after) for (int fault = 1; fault <= 1 + (int)LAG_ATTR_COUNT; ++fault) {
        reset(); assert(!hal_lag_add_port(0, 7, 5));
        fault_at = writes + fault; fail_after = after;
        int result = hal_lag_del_port(0, 7, 5);
        if (fault == 1 && !after) {
            assert(result == NL_ERR_HW_STATE_OUT_OF_SYNC && closed[5] && lag_owners[4].faulted);
        } else {
            assert(!result && !membership[5] && image_equal(&hardware[5], &initial[5]) && !close_calls);
        }
        assert(adds == 1); unchanged_others(5);
    }
    reset(); fail_read_after_write = 1;
    assert(hal_lag_add_port(0, 7, 5) != 0 && !membership[5]);
    assert(image_equal(&hardware[5], &initial[5]) && !close_calls);
    reset(); fault_at = 2; fail_after = 1; fail_delete = fail_close = 1;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_HW_STATE_OUT_OF_SYNC && lag_owners[4].faulted && close_calls == 1);
    int before = writes;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_HW_STATE_OUT_OF_SYNC && writes == before);
    unchanged_others(5);

    reset(); hardware[5].vlans[1] = VLAN_PRESENT | (FM_STP_STATE_FORWARDING << VLAN_STP_SHIFT);
    initial[5] = hardware[5];
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_READBACK_MISMATCH);
    assert(image_equal(&hardware[5], &initial[5]) && !membership[5]);
    reset(); hardware[5].vlans[10] = VLAN_PRESENT | (FM_STP_STATE_LEARNING << VLAN_STP_SHIFT);
    initial[5] = hardware[5];
    assert(!hal_lag_add_port(0, 7, 5) && !hal_lag_del_port(0, 7, 5));
    assert(image_equal(&hardware[5], &initial[5]));

    reset(); property = false;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_CAPABILITY_INSUFFICIENT && !writes);
    property = true; switch_state.perLagMgmt = FALSE;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_CAPABILITY_INSUFFICIENT && !writes);
    switch_state.perLagMgmt = TRUE; take_error = 1;
    assert(hal_lag_add_port(0, 7, 5) != 0 && !writes);
    take_error = 0; drop_error = 1;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_HW_STATE_OUT_OF_SYNC && lag_lock_fault && !writes);
    reset(); attr_read_error = 1;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_PRE_STATE_MISSING && !writes);
    reset(); membership[5] = 9;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_COMMIT_LOCKED && !writes);
    reset(); membership[5] = 7;
    assert(hal_lag_add_port(0, 7, 5) == NL_ERR_HW_STATE_OUT_OF_SYNC && closed[5]);
    reset(); assert(hal_lag_add_port(0, 7, 25) == NL_ERR_INVALID_VALUE && !writes);
    readback_faults();
    transaction_images();
    puts("Native LAG: 24 slots, per-LAG ABI, attribute/VLAN/STP projection, partial writes, compensation and scoped readback passed");
    return 0;
}
