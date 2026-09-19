/* Exercise the production plan engine, verifier, tracker and native LAG
 * adapter together. Only SDK calls and unrelated HAL families are simulated. */
#include <fm_sdk_int.h>
#include "netlab/hal.h"
#include "../vendor/netlab/sbin/switchd/fm10k_lag.h"
#define main reference_hal_entry
#define verify_apply_plan reference_verify_apply_plan
#define fm10k_native_profile reference_native_profile
#define fm10k_native_aux_port reference_native_aux_port
#define hal_fm10k_lag_member_set reference_native_member_set
#define hal_fm10k_lag_members_status reference_native_members_status
#define hal_fm10k_lag_restore_port reference_native_restore_port
#define hal_fm10k_lag_transaction_check reference_native_transaction_check
#define hal_fm10k_lag_transaction_retire reference_native_transaction_retire
#define hal_fm10k_lag_del_port_transaction reference_native_del_port_transaction
#define hal_fm10k_lag_attributes_capture reference_native_attributes_capture
#define hal_fm10k_lag_attributes_restore reference_native_attributes_restore
#define hal_fm10k_lag_qos_snapshot reference_native_qos_snapshot
#define hal_fm10k_lag_qos_restore reference_native_qos_restore
#define hal_fm10k_lag_qos_set reference_native_qos_set
#define hal_fm10k_lag_qos_get reference_native_qos_get
#define fmGetPortAttribute reference_get_port_attribute
#define fmSetPortAttribute reference_set_port_attribute
#define fmAddLAGPort reference_add_lag_port
#define fmDeleteLAGPort reference_delete_lag_port
#define fmGetVlanFirst reference_vlan_first
#define fmGetVlanNext reference_vlan_next
#define fmGetVlanPortFirst reference_vlan_port_first
#define fmGetVlanPortNext reference_vlan_port_next
#define fmAddVlanPort reference_add_vlan_port
#define fmDeleteVlanPort reference_delete_vlan_port
#define fmSetVlanPortState reference_set_vlan_port_state
#define hal_port_set_admin_state reference_set_admin
#include "../vendor/netlab/tests/integration/switchd_l2_persistent_hal_test.c"
#undef main
#undef verify_apply_plan
#undef fm10k_native_profile
#undef fm10k_native_aux_port
#undef hal_fm10k_lag_member_set
#undef hal_fm10k_lag_members_status
#undef hal_fm10k_lag_restore_port
#undef hal_fm10k_lag_transaction_check
#undef hal_fm10k_lag_transaction_retire
#undef hal_fm10k_lag_del_port_transaction
#undef hal_fm10k_lag_attributes_capture
#undef hal_fm10k_lag_attributes_restore
#undef hal_fm10k_lag_qos_snapshot
#undef hal_fm10k_lag_qos_restore
#undef hal_fm10k_lag_qos_set
#undef hal_fm10k_lag_qos_get
#undef fmGetPortAttribute
#undef fmSetPortAttribute
#undef fmAddLAGPort
#undef fmDeleteLAGPort
#undef fmGetVlanFirst
#undef fmGetVlanNext
#undef fmGetVlanPortFirst
#undef fmGetVlanPortNext
#undef fmAddVlanPort
#undef fmDeleteVlanPort
#undef fmSetVlanPortState
#undef hal_port_set_admin_state
#include "../vendor/netlab/sbin/switchd/fm10k_lag.c"
#include "../vendor/netlab/sbin/switchd/hw_state_tracker.h"
#include <assert.h>

static fm_rootApi api;
static fm_rootPlatform platform;
static fm_switch switch_state;
static fm_rwLock switch_lock;
fm_rootApi *fmRootApi = &api;
fm_rootPlatform *fmRootPlatform = &platform;
static u32 attributes[2048][LAG_ATTR_COUNT], sdk_saved[25][LAG_ATTR_COUNT];
static bool locked;
static int fail_attach, fail_retire, close_calls, restore_attempts;
static bool fail_restore_attribute, fail_apply_attribute, arm_readback_failure, readback_failure_armed;
static int fail_attribute_reads;
static int apply_error = FM_FAIL;
static int qos_writes, qos_fault_at, qos_drop_at;
static bool qos_fail_after;

bool fm10k_native_profile(void) { return true; }
bool fm10k_native_aux_port(int sw, int port) { return sw == 0 && (port == 28 || port == 29); }
bool nl_ifid_get_by_logical_port(int port, nl_port_entry *entry) {
    if (port < 1 || port > 24) return false;
    *entry = (nl_port_entry){.logical_port = port, .flags = NL_PORT_FLAG_EXTERNAL};
    return true;
}
fm_status fmCaptureReadLock(fm_rwLock *lock, fm_timestamp *timeout) {
    (void)timeout; assert(lock == &switch_lock && !locked); locked = true; return FM_OK;
}
fm_status fmReleaseReadLock(fm_rwLock *lock) {
    assert(lock == &switch_lock && locked); locked = false; return FM_OK;
}
fm_status fmGetApiProperty(fm_text key, fm_apiAttrType type, void *out) {
    assert(!strcmp(key, FM_AAK_API_PER_LAG_MANAGEMENT) && type == FM_API_ATTR_BOOL && !locked);
    *(fm_bool *)out = TRUE; return FM_OK;
}
static int attribute_index(int attr) {
    for (size_t i = 0; i < LAG_ATTR_COUNT; ++i) if (lag_attributes[i].id == attr) return (int)i;
    assert(false); return -1;
}
static sim_lag *lag_for_logical(int port) {
    for (int i = 0; i < SIM_MAX_LAGS; ++i)
        if (g_lags[i].used && g_lags[i].logical_port == port) return &g_lags[i];
    return NULL;
}
fm_status fmGetVlanFirst(fm_int sw, fm_int *vid) {
    return reference_vlan_first(sw, vid);
}
fm_status fmGetVlanNext(fm_int sw, fm_int previous, fm_int *vid) {
    return reference_vlan_next(sw, previous, vid);
}
fm_status fmGetVlanPortFirst(fm_int sw, fm_int vlan, fm_int *port) {
    fm_status status = reference_vlan_port_first(sw, vlan, port);
    if (status == FM_OK) *port = 0; /* The real SDK enumerates the CPU first. */
    return status;
}
fm_status fmGetVlanPortNext(fm_int sw, fm_int vlan, fm_int previous, fm_int *port) {
    if (previous == 28) { *port = 29; return FM_OK; }
    if (previous == 29) { *port = -1; return FM_OK; }
    fm_status status = previous == 0 ? reference_vlan_port_first(sw, vlan, port) :
        reference_vlan_port_next(sw, vlan, previous, port);
    if (status == FM_OK && *port == -1) *port = 28;
    return status;
}
fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(!sw && port > 0 && port < 2048 && !locked);
    if (fail_attribute_reads) { --fail_attribute_reads; return FM_FAIL; }
    int index = attribute_index(attr);
    u32 value = attributes[port][index];
    if (lag_attributes[index].type == LAG_BOOL) *(fm_bool *)out = value ? TRUE : FALSE;
    else if (lag_attributes[index].type == LAG_INT) *(fm_int *)out = (fm_int)value;
    else *(fm_uint32 *)out = value;
    return FM_OK;
}
fm_status fmSetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *in) {
    assert(!sw && port > 0 && port < 2048 && !locked);
    for (int i = 0; i < SIM_MAX_LAGS; ++i)
        if (g_lags[i].used && lag_has_member(&g_lags[i], port)) return FM_ERR_PER_LAG_ATTRIBUTE;
    int index = attribute_index(attr);
    u32 value = lag_attributes[index].type == LAG_BOOL ? (*(fm_bool *)in != FALSE) :
        lag_attributes[index].type == LAG_INT ? (u32)*(fm_int *)in : *(fm_uint32 *)in;
    bool classifier = index >= LAG_QOS_DEF_PRI && index <= LAG_QOS_DSCP_PREF;
    bool qos_failure = classifier && ++qos_writes == qos_fault_at;
    if (qos_failure && !qos_fail_after) return FM_FAIL;
    if (classifier && qos_writes == qos_drop_at) return FM_OK;
    ++g_write_calls; attributes[port][index] = value;
    sim_lag *lag = lag_for_logical(port);
    if (lag) for (int i = 0; i < lag->n_members; ++i) attributes[lag->members[i]][index] = value;
    if (port > 1000 && fail_restore_attribute) { fail_restore_attribute = false; return FM_FAIL; }
    if (port == 5 && value == 777 && fail_apply_attribute) { fail_apply_attribute = false; return apply_error; }
    if (qos_failure) return FM_FAIL;
    return FM_OK;
}
fm_status fmAddVlanPort(fm_int sw, fm_uint16 vid, fm_int port, fm_bool tagged) {
    fm_status status = reference_add_vlan_port(sw, vid, port, tagged);
    sim_lag *lag = lag_for_logical(port);
    if (status == FM_OK && lag)
        for (int i = 0; i < lag->n_members; ++i)
            assert(seed_vlan_member(vid, lag->members[i], tagged, SIM_DEFAULT_STP));
    return status;
}
fm_status fmChangeVlanPort(fm_int sw, fm_uint16 vid, fm_int port, fm_bool tagged) {
    assert(!sw && !locked);
    sim_vlan_member *member = find_vlan_member(find_vlan(vid), port);
    if (!member) return FM_ERR_INVALID_PORT;
    ++g_write_calls; member->tagged = tagged; return FM_OK;
}
fm_status fmDeleteVlanPort(fm_int sw, fm_uint16 vid, fm_int port) {
    fm_status status = reference_delete_vlan_port(sw, vid, port);
    sim_lag *lag = lag_for_logical(port);
    if (status == FM_OK && lag)
        for (int i = 0; i < lag->n_members; ++i)
            assert(reference_delete_vlan_port(sw, vid, lag->members[i]) == FM_OK);
    return status;
}
fm_status fmSetVlanPortState(fm_int sw, fm_uint16 vid, fm_int port, fm_int state) {
    fm_status status = reference_set_vlan_port_state(sw, vid, port, state);
    sim_lag *lag = lag_for_logical(port);
    if (status == FM_OK && lag)
        for (int i = 0; i < lag->n_members; ++i)
            assert(reference_set_vlan_port_state(sw, vid, lag->members[i], state) == FM_OK);
    return status;
}
fm_status fmAddLAGPort(fm_int sw, fm_int id, fm_int port) {
    assert(!sw && port > 0 && port <= 24 && !locked);
    sim_lag *lag = find_lag(id); assert(lag && !lag_has_member(lag, port));
    memcpy(sdk_saved[port], attributes[port], sizeof(sdk_saved[port]));
    fm_status status = reference_add_lag_port(sw, id, port);
    if (status != FM_OK) return status;
    ++restore_attempts;
    if (restore_attempts == fail_attach) return FM_FAIL; /* mutated list */
    memcpy(attributes[port], attributes[lag->logical_port], sizeof(attributes[port]));
    for (int i = 0; i < SIM_MAX_VLANS; ++i) {
        sim_vlan_member *member = find_vlan_member(&g_vlans[i], lag->logical_port);
        if (g_vlans[i].used && member)
            assert(seed_vlan_member(g_vlans[i].vid, port, member->tagged, member->stp));
    }
    return FM_OK;
}
fm_status fmDeleteLAGPort(fm_int sw, fm_int id, fm_int port) {
    assert(!sw && port > 0 && port <= 24 && !locked);
    fm_status status = reference_delete_lag_port(sw, id, port);
    if (status == FM_OK) memcpy(attributes[port], sdk_saved[port], sizeof(attributes[port]));
    return status; /* IES leaves VLANs behind. */
}
int hal_port_set_admin_state(int sw, int port, int mode) {
    assert(!sw && port > 0 && port <= 24 && mode == FM_PORT_MODE_ADMIN_DOWN);
    ++close_calls; return 0;
}

/* The linked production executor has these branches; using one here is a
 * fixture error, never a simulated success. */
int hal_port_effective_admin_mode(int mode) { (void)mode; assert(false); return -1; }
int hal_port_mtu_to_max_frame(int mtu) { (void)mtu; assert(false); return -1; }
const char *hal_port_ethernet_mode_name(int mode) { (void)mode; assert(false); return "unexpected"; }
int hal_mac_entry_get(int sw, u16 vid, const u8 mac[6], int *port, bool *is_static) {
    (void)sw; (void)vid; (void)mac; (void)port; (void)is_static; assert(false); return -1;
}
int hal_fm10k_group_capture(int sw, int epl, fm10k_group *out) {
    (void)sw; (void)epl; (void)out; assert(false); return -1;
}
int hal_fm10k_group_apply(int sw, const fm10k_group *target, const fm10k_group *before, uint64_t tx) {
    (void)sw; (void)target; (void)before; (void)tx; assert(false); return -1;
}
int hal_fm10k_group_restore(int sw, const fm10k_group *before, uint64_t tx) {
    (void)sw; (void)before; (void)tx; assert(false); return -1;
}
int hal_fm10k_group_verify(int sw, const fm10k_group *target) {
    (void)sw; (void)target; assert(false); return -1;
}
int hal_fm10k_fan_capture(int sw, fm10k_fan_snapshot *out) {
    (void)sw; (void)out; assert(false); return -1;
}
int hal_fm10k_fan_apply(int sw, const fm10k_fan_curve *target, const fm10k_fan_snapshot *before) {
    (void)sw; (void)target; (void)before; assert(false); return -1;
}
int hal_fm10k_fan_restore(int sw, const fm10k_fan_snapshot *before) {
    (void)sw; (void)before; assert(false); return -1;
}
int hal_fm10k_fan_verify(int sw, const fm10k_fan_curve *target) {
    (void)sw; (void)target; assert(false); return -1;
}
int hal_acl_shared_creation_tokens_retire(const hal_acl_shared_creation_token *tokens, int count) {
    (void)tokens; assert(count == 1); return fail_retire ? -1 : 0;
}

static void final_readback_boundary(void *context) {
    (void)context;
    sim_lag *lag = find_lag(hal_lag_id_for_ae(0));
    if (arm_readback_failure && !readback_failure_armed &&
        lag_has_member(lag, 1) && lag_has_member(lag, 5)) {
        readback_failure_armed = true;
        fail_attribute_reads = 1;
    }
}

static void seed_classifier(int logical, int priority) {
    for (size_t i = 0; i < LAG_ATTR_COUNT; ++i)
        attributes[logical][i] = lag_attributes[i].type == LAG_BOOL ? 1 : 100 + (u32)i;
    attributes[logical][LAG_QOS_DEF_PRI] = attributes[logical][LAG_QOS_DEF_SWPRI] = (u32)priority;
    attributes[logical][LAG_QOS_SOURCE] = FM_PORT_SWPRI_ISL_TAG | FM_PORT_SWPRI_VPRI1;
    attributes[logical][LAG_QOS_DSCP_PREF] = 0;
}

static int qos_transaction(const char *scenario) {
    bool creating = !strcmp(scenario, "qos-create");
    bool deleting = !strcmp(scenario, "qos-delete");
    bool resetting = !strcmp(scenario, "qos-default");
    bool retry = !strcmp(scenario, "qos-restore-retry");
    bool dropping = !strcmp(scenario, "qos-drop");
    int fault = 0;
    (void)sscanf(scenario, "qos-fail-%d", &fault);
    reset_simulator(); g_trace_logs = true;
    api.fmSwitchStateTable[0] = &switch_state; api.fmSwitchLockTable[0] = &switch_lock;
    platform.cfg.numSwitches = 1; switch_state.perLagMgmt = TRUE;
    int other = bootstrap_lag(1); assert(other > 0);
    int other_port = find_lag(other)->logical_port;
    seed_classifier(other_port, 4);
    lag_port_image original_other, original, detached, unrelated;
    assert(!capture_image(0, other_port, &original_other));
    assert(!capture_image(0, 1, &detached) && !capture_image(0, 9, &unrelated));
    int lag = 0;
    if (!creating) {
        lag = bootstrap_lag(0); assert(lag > 0);
        int logical = find_lag(lag)->logical_port;
        seed_classifier(logical, 0);
        assert(seed_vlan_member(100, logical, true, FM_STP_STATE_FORWARDING));
        assert(!capture_image(0, logical, &original));
        assert(!hal_lag_add_port(0, lag, 1) && !hal_lag_add_port(0, lag, 5));
    }
    const u64 tx = 60;
    assert(!nl_port_scope_begin(tx, 0x11, 100));
    l2_apply_plan *plan = new_plan(deleting ? 5 : resetting ? 3 : 2, tx), *owned = NULL;
    plan->fm10k_scope_present = true; plan->fm10k_scope_mask = 0x11;
    int index = 0;
    if (creating) plan->steps[index++] = (l2_apply_step){.type = L2_STEP_LAG_CREATE, .ae_id = 0};
    if (deleting) {
        plan->steps[index++] = (l2_apply_step){.type = L2_STEP_LAG_DEL_PORT, .ae_id = 0, .port = 1};
        plan->steps[index++] = (l2_apply_step){.type = L2_STEP_LAG_DEL_PORT, .ae_id = 0, .port = 5};
    }
    plan->steps[index++] = (l2_apply_step){.type = L2_STEP_QOS_INTERFACE_SET, .ae_id = 0,
                                        .qos_trust_mode = HAL_QOS_TRUST_DSCP, .qos_default_priority = 7};
    if (resetting) plan->steps[index++] = (l2_apply_step){.type = L2_STEP_QOS_INTERFACE_DEL, .ae_id = 0};
    if (deleting) {
        plan->steps[index++] = (l2_apply_step){.type = L2_STEP_VLAN_REM_PORT, .ae_id = 0, .vid = 100};
        plan->steps[index++] = (l2_apply_step){.type = L2_STEP_LAG_DELETE, .ae_id = 0};
    } else if (!creating) {
        plan->steps[index++] = (l2_apply_step){.type = L2_STEP_QOS_INTERFACE_SET, .ae_id = 1,
                                            .qos_trust_mode = HAL_QOS_TRUST_NONE, .qos_default_priority = 2};
    }
    assert(index == plan->n_steps);
    struct hw_state_tracker *tracker = NULL; assert(!hw_state_tracker_init(&tracker));
    assert(!hw_state_tracker_reserve_l2(tracker, tx, plan, &owned));
    qos_writes = 0;
    if (fault) { qos_fault_at = (fault + 1) / 2; qos_fail_after = !(fault & 1); }
    if (dropping) qos_drop_at = 1;
    int applied = apply_plan(owned);
    assert((applied != 0) == (fault || dropping));
    assert(!hw_state_tracker_finish_l2_apply(tracker, tx, applied));
    if (!applied) {
        if (!deleting) {
            hal_qos_interface_entry qos;
            assert(!hal_lag_qos_get(0, hal_lag_id_for_ae(0), &qos));
            assert(qos.trust_mode == (resetting ? HAL_QOS_TRUST_IEEE8021P : HAL_QOS_TRUST_DSCP));
            assert(qos.default_priority == (resetting ? 0 : 7));
            struct sdk_result result;
            assert(!hal_lag_get_all(0, &result));
            bool found = false;
            for (int i = 0; i < result.data.lag_list.n_lags; ++i) {
                hal_lag_readback_entry *item = &result.data.lag_list.lag[i];
                if (item->ae_id != 0) continue;
                assert(!item->qos_status && item->qos_trust == qos.trust_mode && item->qos_default_priority == qos.default_priority);
                found = true;
            }
            assert(found);
            if (!creating) {
                int logical = find_lag(lag)->logical_port;
                for (size_t i = 0; i < LAG_ATTR_COUNT; ++i)
                    if (i < LAG_QOS_DEF_PRI || i > LAG_QOS_DSCP_PREF)
                        assert(attributes[logical][i] == original.attributes[i]);
                /* A second AE must not hide a mismatching first AE when
                 * the verifier receives unresolved semantic identities. */
                l2_apply_plan copy; l2_apply_plan_init(&copy);
                assert(!l2_apply_plan_clone(&copy, owned));
                for (int i = 0; i < copy.n_steps; ++i) copy.steps[i].port = 0;
                struct verify_result results[3];
                attributes[logical][LAG_QOS_DEF_PRI] ^= 1;
                assert(verify_apply_plan(0, &copy, results, 3) != 0);
                attributes[logical][LAG_QOS_DEF_PRI] ^= 1;
                assert(!verify_apply_plan(0, &copy, results, 3));
                l2_apply_plan_reset(&copy);
            }
        }
        bool already = false;
        assert(!hw_state_tracker_begin_l2_rollback(tracker, tx, &owned, &already) && !already);
        if (retry) { qos_fault_at = qos_writes + 1; qos_fail_after = true; }
        int restored = hal_rollback_l2_plan(0, owned);
        assert(!hw_state_tracker_finish_l2_rollback(tracker, tx, restored));
        if (retry) {
            assert(restored && tracker->pending && nl_port_scope_get().tx_id == tx);
            assert(hal_commit_mark_failed(tracker, tx) == NL_ERR_HW_STATE_OUT_OF_SYNC);
            assert(!hw_state_tracker_begin_l2_rollback(tracker, tx, &owned, &already) && !already);
            restored = hal_rollback_l2_plan(0, owned);
            assert(!hw_state_tracker_finish_l2_rollback(tracker, tx, restored));
        }
        assert(!restored);
        assert(!hal_commit_mark_failed(tracker, tx));
    } else {
        assert(!tracker->pending && tracker->last_failed_verified == tx);
    }
    assert(!nl_port_scope_end(tx));
    lag_port_image actual;
    assert(!capture_image(0, other_port, &actual) && image_equal(&actual, &original_other));
    if (creating) {
        assert(hal_lag_id_for_ae(0) == 0);
    } else {
        int recovered = hal_lag_id_for_ae(0); assert(recovered > 0);
        if (deleting) assert(recovered != lag);
        assert(!capture_image(0, find_lag(recovered)->logical_port, &actual) && image_equal(&actual, &original));
        for (int p = 1; p <= 5; p += 4) {
            assert(!hal_lag_del_port(0, recovered, p));
            assert(!capture_image(0, p, &actual) && image_equal(&actual, &detached));
        }
    }
    assert(!capture_image(0, 9, &actual) && image_equal(&actual, &unrelated) && !close_calls);
    hw_state_tracker_destroy(&tracker); free_plan(plan);
    printf("Native LAG classifier transaction %s passed\n", scenario);
    return 0;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    assert(!nl_port_scope_init("switchd"));
    if (!strncmp(argv[1], "qos-", 4)) return qos_transaction(argv[1]);
    bool retry_second = !strcmp(argv[1], "retry-second");
    bool retry_readback = !strcmp(argv[1], "readback");
    bool retry_attribute = !strcmp(argv[1], "delete-partial");
    bool deleting = !strcmp(argv[1], "delete") || retry_attribute;
    bool retry = !strcmp(argv[1], "retry") || retry_second || retry_readback || retry_attribute;
    bool committing = !strcmp(argv[1], "commit");
    bool added = !strcmp(argv[1], "added");
    bool apply_negative = !strcmp(argv[1], "apply-negative");
    bool apply_failed = !strcmp(argv[1], "apply-failure") || apply_negative;
    if (apply_negative) apply_error = -1;
    reset_simulator(); g_trace_logs = true;
    api.fmSwitchStateTable[0] = &switch_state; api.fmSwitchLockTable[0] = &switch_lock;
    platform.cfg.numSwitches = 1; switch_state.perLagMgmt = TRUE;
    int lag = bootstrap_lag(0); assert(lag > 0);
    sim_lag *aggregate = find_lag(lag); assert(aggregate);
    for (size_t i = 0; i < LAG_ATTR_COUNT; ++i) {
        attributes[1][i] = attributes[5][i] = lag_attributes[i].type == LAG_BOOL ? 0 : 10 + (u32)i;
        attributes[aggregate->logical_port][i] = lag_attributes[i].type == LAG_BOOL ? 1 : 100 + (u32)i;
    }
    assert(seed_vlan_member(100, aggregate->logical_port, true, FM_STP_STATE_FORWARDING));
    assert(seed_vlan_member(100, 9, false, FM_STP_STATE_BLOCKING)); /* unrelated EPL */
    lag_port_image independent, projected, unrelated;
    assert(!capture_image(0, 5, &independent) && !capture_image(0, aggregate->logical_port, &projected));
    assert(!capture_image(0, 9, &unrelated));
    if (!added) assert(!hal_lag_add_port(0, lag, 1) && !hal_lag_add_port(0, lag, 5));
    const u64 tx = 50;
    assert(!nl_port_scope_begin(tx, 0x11, 100));
    l2_apply_plan *plan = new_plan(added ? 1 : deleting ? 6 : 4, tx), *owned = NULL;
    assert(plan);
    plan->fm10k_scope_present = true; plan->fm10k_scope_mask = 0x11;
    if (added) {
        plan->steps[0] = (l2_apply_step){.type = L2_STEP_LAG_ADD_PORT, .ae_id = 0, .port = 5};
    } else {
        plan->steps[0] = (l2_apply_step){.type = L2_STEP_LAG_DEL_PORT, .ae_id = 0, .port = 1};
        plan->steps[1] = (l2_apply_step){.type = L2_STEP_LAG_DEL_PORT, .ae_id = 0, .port = 5};
        int index = 2;
        if (deleting) {
            plan->steps[index++] = (l2_apply_step){.type = L2_STEP_VLAN_REM_PORT, .ae_id = 0, .vid = 100};
            plan->steps[index++] = (l2_apply_step){.type = L2_STEP_LAG_DELETE, .ae_id = 0};
        }
        plan->steps[index++] = (l2_apply_step){.type = L2_STEP_PVID_SET, .ae_id = -1, .port = 1, .vid = 777};
        plan->steps[index++] = (l2_apply_step){.type = L2_STEP_PVID_SET, .ae_id = -1, .port = 5, .vid = 777};
    }
    struct hw_state_tracker *tracker = NULL; assert(!hw_state_tracker_init(&tracker));
    assert(!hw_state_tracker_reserve_l2(tracker, tx, plan, &owned));
    fail_apply_attribute = apply_failed;
    int applied = apply_plan(owned);
    assert(applied == (apply_failed ? (apply_negative ? NL_ERR_SDK_CALL_FAILED : FM_FAIL) : 0));
    assert(!hw_state_tracker_finish_l2_apply(tracker, tx, applied));
    if (apply_failed) assert(!tracker->pending && tracker->last_failed_verified == tx);
    if (!apply_failed) assert(hal_commit_mark_failed(tracker, tx) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    if (committing) {
        /* A later finalizer failure must not retire member images early. */
        owned->steps[0].pre_acl_policer.shared_acl_creation.valid = true;
        fail_retire = 1;
        assert(hal_commit_mark_success(tracker, tx, "fixture") == NL_ERR_HW_STATE_OUT_OF_SYNC);
        assert(tracker->pending && lag_rollback_images[0].tx_id == tx && lag_rollback_images[4].tx_id == tx);
        fail_retire = 0;
        assert(!hal_commit_mark_success(tracker, tx, "fixture"));
        assert(!hal_commit_mark_success(tracker, tx, "fixture"));
        assert(!nl_port_scope_end(tx));
        assert(!hal_lag_add_port(0, lag, 5) && !hal_lag_del_port(0, lag, 5));
        lag_port_image actual; assert(!capture_image(0, 5, &actual));
        independent.attributes[attribute_index(FM_PORT_DEF_VLAN)] = 777;
        assert(image_equal(&actual, &independent));
    } else {
        bool already = false;
        int status = 0;
        if (!apply_failed) {
            assert(!hw_state_tracker_begin_l2_rollback(tracker, tx, &owned, &already) && !already);
            if (retry && !retry_attribute && !retry_readback) fail_attach = retry_second ? 4 : 3;
            fail_restore_attribute = retry_attribute;
            arm_readback_failure = retry_readback;
            owned->checkpoint = final_readback_boundary;
            status = hal_rollback_l2_plan(0, owned);
            assert(!hw_state_tracker_finish_l2_rollback(tracker, tx, status));
        }
        if (retry) {
            assert(status && tracker->pending && nl_port_scope_get().tx_id == tx);
            assert(hal_commit_mark_failed(tracker, tx) == NL_ERR_HW_STATE_OUT_OF_SYNC);
            l2_apply_plan copy; l2_apply_plan_init(&copy);
            assert(!l2_apply_plan_clone(&copy, &tracker->pending->plan));
            int expected_next = retry_attribute ? 3 : retry_readback ? -1 : retry_second ? 0 : 1;
            assert(copy.rollback_started && copy.rollback_next_idx == expected_next);
            l2_apply_plan_move(&tracker->pending->plan, &copy);
            assert(!hw_state_tracker_begin_l2_rollback(tracker, tx, &owned, &already) && !already);
            int writes_before = g_write_calls;
            status = hal_rollback_l2_plan(0, owned);
            if (retry_readback) assert(g_write_calls == writes_before && readback_failure_armed);
            assert(!hw_state_tracker_finish_l2_rollback(tracker, tx, status));
        }
        assert(!status);
        assert(!hal_commit_mark_failed(tracker, tx) && !hal_commit_mark_failed(tracker, tx));
        if (!apply_failed) assert(!hw_state_tracker_begin_l2_rollback(tracker, tx, &owned, &already) && already);
        assert(!nl_port_scope_end(tx));
        lag = hal_lag_id_for_ae(0); assert(lag > 0);
        lag_port_image actual; assert(!capture_image(0, find_lag(lag)->logical_port, &actual));
        assert(image_equal(&actual, &projected));
        for (int i = 1; i <= 5; i += 4) {
            if (!added) assert(!hal_lag_del_port(0, lag, i));
            assert(!capture_image(0, i, &actual) && image_equal(&actual, &independent));
        }
    }
    lag_port_image actual;
    assert(!capture_image(0, 9, &actual) && image_equal(&actual, &unrelated) && !close_calls);
    hw_state_tracker_destroy(&tracker); free_plan(plan);
    printf("Native LAG production transaction %s passed (%d attaches)\n", argv[1], restore_attempts);
    return 0;
}
