/* Reuse the reference fake SDK and out-of-scope failure stubs, but link the
 * production transaction engine AND production final readback verifier. */
#define main reference_hal_fixture_entry
#define verify_apply_plan reference_verify_apply_plan
#define fmGetPortAttribute reference_get_port_attribute
#define fmSetPortAttribute reference_set_port_attribute
#include "../vendor/netlab/tests/integration/switchd_l2_persistent_hal_test.c"
#undef fmGetPortAttribute
#undef fmSetPortAttribute
#undef verify_apply_plan
#undef main
#include "netlab/port_scope.h"
#include "../vendor/netlab/sbin/switchd/hw_state_tracker.h"
#include <assert.h>
#define FM10K_SAMPLING_FIXTURE_ONLY
#include "native_sampling_test.c"
#include "fm10k_monitor.h"

static fm_bool filter_actual[2048];
static int filter_reads, filter_read_fault, filter_writes, filter_write_fault;
static int filter_drop, filter_fail_after, filter_restore_fault;
fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    if (attr != FM_PORT_DROP_BV) return reference_get_port_attribute(sw, port, attr, out);
    assert(!sw && port > 0 && port < 2048);
    if (++filter_reads == filter_read_fault) return FM_FAIL;
    *(fm_bool *)out = filter_actual[port];
    return FM_OK;
}
fm_status fmSetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *value) {
    if (attr != FM_PORT_DROP_BV) return reference_set_port_attribute(sw, port, attr, value);
    assert(!sw && port > 0 && port < 2048 && (*(fm_bool *)value == TRUE || *(fm_bool *)value == FALSE));
    ++filter_writes;
    bool fail = filter_writes == filter_write_fault;
    if ((fail && !filter_fail_after) || (filter_restore_fault && filter_writes > 1)) return FM_FAIL;
    if (filter_writes != filter_drop) filter_actual[port] = *(fm_bool *)value;
    return fail ? FM_FAIL : FM_OK;
}

/* These paths are outside this fixture; accidental use must abort. */
int hal_port_effective_admin_mode(int mode) { (void)mode; assert(false); return -1; }
int hal_port_mtu_to_max_frame(int mtu) { (void)mtu; assert(false); return -1; }
const char *hal_port_ethernet_mode_name(int mode) { (void)mode; assert(false); return "unexpected"; }
int hal_mac_entry_get(int sw, u16 vid, const u8 mac[6], int *port, bool *is_static) {
    (void)sw; (void)vid; (void)mac; (void)port; (void)is_static; assert(false); return -1;
}

static fm10k_group groups[6], initial_groups[6];
static fm10k_fan_snapshot fan, initial_fan;
static fm10k_monitor monitor;
static fm10k_bus fan_bus;
static int writes, fault_write, fault_after, verify_fault, restore_fault;
static int group_verifications;
static u64 transaction;
static unsigned checkpoints;
static void check_unlocked_step(void *context) {
    int group = *(const int *)context;
    assert(!f.locked && nl_port_scope_get().tx_id == transaction);
    assert(!nl_port_scope_enter_epoch_mask(15U << (4 * group), nl_port_scope_clock()));
    u32 sibling = 1U << (4 * ((group + 1) % 6));
    assert(nl_port_scope_enter_epoch_mask(sibling, nl_port_scope_clock()));
    nl_port_scope_leave_mask(sibling);
    ++checkpoints;
}
static void board_lease(int epl, u64 tx) {
    nl_port_scope_status scope = nl_port_scope_get();
    int index = nl_fm10k_group_index(epl);
    assert(index >= 0 && tx == transaction && scope.tx_id == tx &&
        (scope.mask & (15U << (4 * index))) == (15U << (4 * index)));
}
int hal_fm10k_group_capture(int sw, int epl, fm10k_group *out) {
    assert(sw == 0); int index = nl_fm10k_group_index(epl); assert(index >= 0);
    *out = groups[index]; return 0;
}
int hal_fm10k_group_apply(int sw, const fm10k_group *target, const fm10k_group *before, uint64_t tx) {
    assert(sw == 0); board_lease(target->epl, tx); ++writes;
    int index = nl_fm10k_group_index(target->epl);
    assert(nl_fm10k_group_valid(target) && nl_fm10k_group_equal(&groups[index], before));
    bool fail = fault_write == writes;
    if (!fail || fault_after) groups[index] = *target;
    return fail ? NL_ERR_SDK_CALL_FAILED : 0;
}
int hal_fm10k_group_restore(int sw, const fm10k_group *before, uint64_t tx) {
    assert(sw == 0); board_lease(before->epl, tx);
    int index = nl_fm10k_group_index(before->epl);
    if (restore_fault) return NL_ERR_ROLLBACK_FAILED;
    groups[index] = *before; return 0;
}
int hal_fm10k_group_verify(int sw, const fm10k_group *target) {
    assert(sw == 0); ++group_verifications;
    return verify_fault || !nl_fm10k_group_equal(target, &groups[nl_fm10k_group_index(target->epl)]) ? NL_ERR_READBACK_MISMATCH : 0;
}
int hal_fm10k_fan_capture(int sw, fm10k_fan_snapshot *out) {
    assert(!sw); return fm10k_monitor_fan_capture(&monitor, out);
}
int hal_fm10k_fan_apply(int sw, const fm10k_fan_curve *target, const fm10k_fan_snapshot *before) {
    assert(!sw && fm10k_fan_snapshot_equal(before, &fan) && nl_fm10k_fan_valid(target)); ++writes;
    bool fail = fault_write == writes;
    if (!fail || fault_after) {
        assert(!fm10k_monitor_fan_apply(&monitor, target, before, 1000));
        assert(!hal_fm10k_fan_capture(0, &fan));
    }
    return fail ? NL_ERR_SDK_CALL_FAILED : 0;
}
int hal_fm10k_fan_restore(int sw, const fm10k_fan_snapshot *before) {
    assert(!sw); int rc = fm10k_monitor_fan_restore(&monitor, before, 1000);
    assert(!hal_fm10k_fan_capture(0, &fan)); return rc;
}
int hal_fm10k_fan_verify(int sw, const fm10k_fan_curve *target) {
    assert(!sw); return nl_fm10k_fan_equal(target, &fan.curve) ? 0 : NL_ERR_READBACK_MISMATCH;
}
int hal_acl_shared_creation_tokens_retire(const hal_acl_shared_creation_token *tokens, int count) {
    (void)tokens; assert(count == 0); return 0;
}

static l2_apply_plan *prepare(int index) {
    reset_simulator(); g_trace_logs = true;
    writes = fault_write = fault_after = verify_fault = restore_fault = group_verifications = 0;
    for (int i = 0; i < 6; ++i) groups[i] = (fm10k_group){.epl = i < 3 ? i : i + 2,
        .mode = 100, .lane_gbps = {25,25,25,25}, .enabled = 1};
    memcpy(initial_groups, groups, sizeof(groups));
    reset();
    fan_bus = (fm10k_bus){.context = &f, .read = read_bytes, .write = write_bytes,
        .enter = enter, .leave = leave, .delay_ms = delay};
    fm10k_monitor_init(&monitor, &fan_bus);
    assert(!fm10k_fan_full(&fan_bus));
    fm10k_fan_snapshot full;
    assert(!hal_fm10k_fan_capture(0, &full));
    fm10k_fan_curve curve = {35,70,80,50,80,4,10900};
    assert(!fm10k_monitor_fan_apply(&monitor, &curve, &full, 1000));
    assert(!hal_fm10k_fan_capture(0, &fan));
    initial_fan = fan;
    int port = index * 4 + 1;
    assert(seed_vlan_member(10, port, false, 3)); assert(seed_vlan_member(20, 30, true, 3));
    ++transaction; assert(!nl_port_scope_begin(transaction, 15U << (4 * index), 100));
    l2_apply_plan *p = new_plan(6, transaction); assert(p);
    p->steps[0].type = L2_STEP_FM10K_GROUP_SET; p->steps[0].fm10k_group = groups[index];
    p->steps[0].fm10k_group.enabled = 0;
    p->steps[1].type = L2_STEP_VLAN_REM_PORT; p->steps[1].vid = 10; p->steps[1].port = port;
    p->steps[2].type = L2_STEP_FM10K_GROUP_SET;
    p->steps[2].fm10k_group = (fm10k_group){.epl = groups[index].epl, .mode = 0, .lane_gbps = {10,25,10,25}};
    p->steps[3].type = L2_STEP_VLAN_ADD_PORT; p->steps[3].vid = 20; p->steps[3].port = port; p->steps[3].tagged = true;
    p->steps[4].type = L2_STEP_FM10K_FAN_SET; p->steps[4].fm10k_fan = (fm10k_fan_curve){35,70,80,60,90,4,10900};
    p->steps[5] = p->steps[2]; p->steps[5].fm10k_group.enabled = 5;
    return p;
}
static void original_restored(int index) {
    assert(!memcmp(groups, initial_groups, sizeof(groups)) && fm10k_fan_snapshot_equal(&fan, &initial_fan));
    sim_vlan_member *old = find_vlan_member(find_vlan(10), index * 4 + 1);
    assert(old && !old->tagged && old->stp == 3);
    assert(!find_vlan_member(find_vlan(20), index * 4 + 1));
    assert(find_vlan_member(find_vlan(20), 30));
}
static void finish_plan(l2_apply_plan *p) {
    assert(!nl_port_scope_end(transaction)); free_plan(p);
}
static l2_apply_plan *prepare_filter(int port) {
    l2_apply_plan *p = prepare((port - 1) / 4);
    p->n_steps = 1;
    p->steps[0] = (l2_apply_step){.type = L2_STEP_PORT_INGRESS_FILTER_SET,
        .port = port, .ae_id = -1, .ingress_filtering = 0};
    for (size_t i = 0; i < sizeof(filter_actual) / sizeof(filter_actual[0]); ++i) filter_actual[i] = TRUE;
    filter_reads = filter_read_fault = filter_writes = filter_write_fault = 0;
    filter_drop = filter_fail_after = filter_restore_fault = 0;
    return p;
}
static void ingress_filter_transactions(void) {
    for (int port = 1; port <= 24; ++port) {
        l2_apply_plan *p = prepare_filter(port);
        assert(!apply_plan(p) && filter_actual[port] == FALSE);
        for (int other = 1; other <= 24; ++other)
            if (other != port) assert(filter_actual[other] == TRUE);
        assert(!hal_rollback_l2_plan(0, p) && filter_actual[port] == TRUE);
        finish_plan(p);
    }
    l2_apply_plan *p = prepare_filter(1);
    p->n_steps = 2; p->steps[1] = p->steps[0]; p->steps[1].ingress_filtering = 1;
    assert(!apply_plan(p) && filter_actual[1] == TRUE && filter_writes == 2);
    assert(!hal_rollback_l2_plan(0, p) && filter_actual[1] == TRUE); finish_plan(p);
    for (int read = 1; read <= 3; ++read) {
        p = prepare_filter(5); filter_read_fault = read;
        assert(apply_plan(p) != 0 && filter_actual[5] == TRUE); finish_plan(p);
    }
    for (int after = 0; after <= 1; ++after) {
        p = prepare_filter(5); filter_write_fault = 1; filter_fail_after = after;
        assert(apply_plan(p) != 0 && filter_actual[5] == TRUE); finish_plan(p);
    }
    p = prepare_filter(5); filter_drop = 1;
    assert(apply_plan(p) == NL_ERR_READBACK_MISMATCH && filter_actual[5] == TRUE); finish_plan(p);
    p = prepare_filter(5); filter_actual[5] = 2;
    assert(apply_plan(p) != 0 && !filter_writes); finish_plan(p);
    p = prepare_filter(5); filter_write_fault = filter_fail_after = filter_restore_fault = 1;
    assert(apply_plan(p) == NL_ERR_ROLLBACK_FAILED && filter_actual[5] == FALSE);
    assert(nl_port_scope_get().tx_id == transaction);
    filter_restore_fault = 0;
    assert(!hal_rollback_l2_plan(0, p) && filter_actual[5] == TRUE); finish_plan(p);
    p = prepare_filter(1);
    int lag = bootstrap_lag(0); assert(lag > 0);
    p->steps[0].port = 0; p->steps[0].ae_id = 0;
    assert(!apply_plan(p) && filter_actual[1000 + lag] == FALSE);
    assert(!hal_rollback_l2_plan(0, p) && filter_actual[1000 + lag] == TRUE); finish_plan(p);
}
static void tc_smp_transactions(void) {
    for (int failure = 0; failure < 4; failure++) {
        l2_apply_plan *p = prepare(0);
        p->n_steps = 1;
        p->steps[0] = (l2_apply_step){.type=L2_STEP_QOS_TC_SMP_SET,
            .ae_id=-1, .qos_traffic_class=3, .qos_smp=1};
        g_smp_fail_after = failure == 1 || failure == 3;
        g_smp_restore_fail = failure == 3;
        g_smp_drop = failure == 2;
        int rc = apply_plan(p);
        if (!failure) {
            assert(!rc && g_qos_tc_smp[3] == 1);
            assert(p->qos_auto_pause_watermark_snapshot_required);
            assert(!hal_rollback_l2_plan(0, p));
        } else if (failure == 3) {
            assert(rc == NL_ERR_ROLLBACK_FAILED && g_qos_tc_smp[3] == 1);
            assert(nl_port_scope_get().tx_id == transaction);
            g_smp_restore_fail = 0;
            assert(!hal_rollback_l2_plan(0, p));
        } else assert(rc != 0);
        assert(g_qos_tc_smp[3] == 0);
        finish_plan(p);
    }
}
static void dscp_transactions(void) {
    for (int failure = 0; failure < 5; failure++) {
        l2_apply_plan *p = prepare(0);
        p->n_steps = 2;
        p->steps[0] = (l2_apply_step){.type=L2_STEP_QOS_DSCP_SET, .ae_id=-1, .qos_dscp=26, .qos_dscp_priority=3};
        p->steps[1] = (l2_apply_step){.type=L2_STEP_QOS_DSCP_SET, .ae_id=-1, .qos_dscp=48, .qos_dscp_priority=6};
        g_dscp_map[26] = 7; g_dscp_map[48] = 1; g_dscp_writes = 0;
        g_dscp_fail_after = failure == 1 || failure == 3 ? 2 : 0;
        g_dscp_drop = failure == 2 ? 2 : 0;
        g_dscp_restore_fail = failure == 3;
        g_dscp_read_fail = failure == 4;
        int rc = apply_plan(p);
        if (!failure) {
            assert(!rc && g_dscp_map[26] == 3 && g_dscp_map[48] == 6);
            assert(!hal_rollback_l2_plan(0, p));
        } else if (failure == 3) {
            assert(rc == NL_ERR_ROLLBACK_FAILED && nl_port_scope_get().tx_id == transaction);
            g_dscp_restore_fail = 0;
            assert(!hal_rollback_l2_plan(0, p));
        } else {
            assert(rc != 0);
            if (failure == 4) assert(g_dscp_writes == 0);
        }
        assert(g_dscp_map[26] == 7 && g_dscp_map[48] == 1);
        g_dscp_read_fail = 0;
        finish_plan(p);
    }
}
int main(void) {
    assert(!nl_port_scope_init("switchd"));
    l2_apply_plan *blocked = prepare(0);
    unsigned before_quiesce = watchdog_quiesce_calls;
    watchdog_quiesce_error = NL_ERR_HW_STATE_OUT_OF_SYNC;
    assert(apply_plan(blocked) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    assert(watchdog_quiesce_calls == before_quiesce + 1 && !blocked->original_n_steps && !writes);
    watchdog_quiesce_error = 0;
    assert(!apply_plan(blocked));
    int before_writes = writes;
    watchdog_quiesce_error = NL_ERR_HW_STATE_OUT_OF_SYNC;
    assert(hal_rollback_l2_plan(0, blocked) == NL_ERR_HW_STATE_OUT_OF_SYNC && writes == before_writes);
    watchdog_quiesce_error = 0;
    assert(!hal_rollback_l2_plan(0, blocked));
    original_restored(0); finish_plan(blocked);
    for (int group = 0; group < 6; ++group) {
        l2_apply_plan *p = prepare(group);
        checkpoints = 0; p->checkpoint = check_unlocked_step; p->checkpoint_context = &group;
        assert(!apply_plan(p));
        assert(checkpoints >= 18); /* initial images, apply steps and final verification */
        /* Only the final group write is verified, while all three original
         * images refer to the pre-transaction mode. */
        assert(group_verifications == 1 && p->original_n_steps == 6);
        assert(p->steps[2].pre_fm10k_group.mode == 100 && p->steps[2].pre_fm10k_group.enabled == 0);
        assert(p->steps[5].pre_fm10k_group.mode == 0 && p->steps[5].pre_fm10k_group.enabled == 0);
        for (int i = 0; i < 6; ++i) if (i != group) assert(!memcmp(&groups[i], &initial_groups[i], sizeof(groups[i])));
        unsigned applied_checkpoints = checkpoints;
        assert(!hal_rollback_l2_plan(0, p));
        assert(checkpoints >= applied_checkpoints + 12); /* restore and original-image verification */
        original_restored(group); finish_plan(p);
        for (int fault = 1; fault <= 4; ++fault) for (int after = 0; after < 2; ++after) {
            p = prepare(group); fault_write = fault; fault_after = after;
            p->checkpoint = check_unlocked_step; p->checkpoint_context = &group;
            assert(apply_plan(p) != 0); original_restored(group); finish_plan(p);
        }
        p = prepare(group); verify_fault = 1;
        p->checkpoint = check_unlocked_step; p->checkpoint_context = &group;
        assert(apply_plan(p) == NL_ERR_READBACK_MISMATCH); original_restored(group); finish_plan(p);
    }
    l2_apply_plan *p = prepare(0), *owned = NULL;
    struct hw_state_tracker *tracker = NULL; assert(!hw_state_tracker_init(&tracker));
    assert(hal_commit_mark_failed(tracker, transaction) == NL_ERR_PRE_STATE_MISSING);
    assert(!hw_state_tracker_reserve_l2(tracker, transaction, p, &owned));
    assert(!apply_plan(owned)); assert(!hw_state_tracker_finish_l2_apply(tracker, transaction, 0));
    assert(hal_commit_mark_failed(tracker, transaction) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    assert(!hal_commit_mark_success(tracker, transaction, "fixture"));
    assert(!hal_commit_mark_success(tracker, transaction, "fixture"));
    hw_state_tracker_destroy(&tracker); finish_plan(p);

    p = prepare(0); assert(!hw_state_tracker_init(&tracker));
    assert(!hw_state_tracker_reserve_l2(tracker, transaction, p, &owned));
    fault_write = 4; fault_after = 1; restore_fault = 1;
    int rc = apply_plan(owned); assert(rc == NL_ERR_ROLLBACK_FAILED);
    assert(!hw_state_tracker_finish_l2_apply(tracker, transaction, rc));
    assert(hal_commit_mark_failed(tracker, transaction) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    assert(nl_port_scope_get().tx_id == transaction && tracker->pending);
    restore_fault = 0; assert(!hal_rollback_l2_plan(0, owned)); original_restored(0);
    hw_state_tracker_destroy(&tracker); finish_plan(p);
    ingress_filter_transactions();
    tc_smp_transactions();
    dscp_transactions();
    puts("production HAL: six EPLs, 48 board faults, ingress filtering, readback rollback and finalization passed");
    return 0;
}
