/* Production plan engine, readback and storm HAL with only SDK boundaries simulated. */
#include <fm_sdk_int.h>
#include <api/fm_api_storm.h>
#include <api/fm_api_portset.h>
#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/port_scope.h"
#include <assert.h>
#define main reference_storm_hal_entry
#define verify_apply_plan reference_verify_apply_plan
#define hal_storm_control_set reference_hal_storm_control_set
#define hal_storm_control_set_kind reference_hal_storm_control_set_kind
#define hal_storm_control_delete reference_hal_storm_control_delete
#define hal_storm_control_delete_kind reference_hal_storm_control_delete_kind
#define hal_storm_control_get reference_hal_storm_control_get
#define hal_storm_control_get_kind reference_hal_storm_control_get_kind
#define hal_storm_control_list reference_hal_storm_control_list
#define hal_storm_control_transaction_snapshot reference_hal_storm_control_transaction_snapshot
#define hal_storm_control_transaction_snapshot_kind reference_hal_storm_control_transaction_snapshot_kind
#define hal_ingress_rate_limit_set reference_hal_ingress_rate_limit_set
#define hal_ingress_rate_limit_delete reference_hal_ingress_rate_limit_delete
#define hal_ingress_rate_limit_get reference_hal_ingress_rate_limit_get
#define hal_ingress_rate_limit_list reference_hal_ingress_rate_limit_list
#define hal_ingress_rate_limit_transaction_snapshot reference_hal_ingress_rate_limit_transaction_snapshot
#include "../vendor/netlab/tests/integration/switchd_l2_persistent_hal_test.c"
#undef main
#undef verify_apply_plan
#undef hal_storm_control_set
#undef hal_storm_control_set_kind
#undef hal_storm_control_delete
#undef hal_storm_control_delete_kind
#undef hal_storm_control_get
#undef hal_storm_control_get_kind
#undef hal_storm_control_list
#undef hal_storm_control_transaction_snapshot
#undef hal_storm_control_transaction_snapshot_kind
#undef hal_ingress_rate_limit_set
#undef hal_ingress_rate_limit_delete
#undef hal_ingress_rate_limit_get
#undef hal_ingress_rate_limit_list
#undef hal_ingress_rate_limit_transaction_snapshot
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
    (void)tokens; assert(count == 0); return 0;
}
typedef struct {
    bool used;
    fm_stormCondition conditions[16];
    fm_stormAction actions[8];
    int n_conditions, n_actions;
    u32 rate, burst;
} test_storm;
static test_storm controllers[16];
static struct { bool used; u32 ports; } portsets[64];
static int attribute_writes, fail_attribute, delete_calls;
static bool fail_list, ignore_rate, fail_action, block_delete, block_set_delete;

bool nl_ifid_is_user_port(int port) { return port >= 1 && port <= 24; }
int nl_ifid_get_all(nl_port_entry *out, int capacity) {
    assert(capacity >= 24);
    for (int p = 1; p <= 24; ++p) out[p - 1] = (nl_port_entry){.logical_port = p, .flags = NL_PORT_FLAG_EXTERNAL};
    return 24;
}
fm_status fmComputeFHClockFreq(fm_int sw, fm_float *mhz) { assert(!sw); *mhz = 700; return FM_OK; }
static test_storm *controller(int id) {
    assert(id >= 0 && id < 16 && controllers[id].used); return &controllers[id];
}
fm_status fmGetStormCtrlList(fm_int sw, fm_int *count, fm_int *ids, fm_int max) {
    assert(!sw && max >= 16); *count = 0;
    if (fail_list) { fail_list = false; return FM_FAIL; }
    for (int i = 0; i < 16; ++i) if (controllers[i].used) ids[(*count)++] = i;
    return FM_OK;
}
fm_status fmCreateStormCtrl(fm_int sw, fm_int *id) {
    assert(!sw);
    for (int i = 0; i < 16; ++i) if (!controllers[i].used) {
        controllers[i] = (test_storm){.used = true, .rate = 131250, .burst = 1024}; *id = i; return FM_OK;
    }
    return FM_ERR_NO_FREE_STORM_CTRL;
}
fm_status fmDeleteStormCtrl(fm_int sw, fm_int id) {
    assert(!sw); ++delete_calls;
    if (block_delete) return FM_FAIL;
    if (id < 0 || id >= 16 || !controllers[id].used) return FM_ERR_INVALID_STORM_CTRL;
    memset(&controllers[id], 0, sizeof(controllers[id])); return FM_OK;
}
fm_status fmGetStormCtrlConditionList(fm_int sw, fm_int id, fm_int *count, fm_stormCondition *out, fm_int max) {
    assert(!sw); test_storm *c = controller(id); assert(max >= c->n_conditions);
    *count = c->n_conditions; memcpy(out, c->conditions, (size_t)*count * sizeof(*out)); return FM_OK;
}
fm_status fmGetStormCtrlActionList(fm_int sw, fm_int id, fm_int *count, fm_stormAction *out, fm_int max) {
    assert(!sw); test_storm *c = controller(id); assert(max >= c->n_actions);
    *count = c->n_actions; memcpy(out, c->actions, (size_t)*count * sizeof(*out)); return FM_OK;
}
fm_status fmAddStormCtrlCondition(fm_int sw, fm_int id, fm_stormCondition *condition) {
    assert(!sw); test_storm *c = controller(id); assert(c->n_conditions < 16);
    assert(condition->type != FM_STORM_COND_FLOOD_UCAST);
    c->conditions[c->n_conditions++] = *condition; return FM_OK;
}
fm_status fmAddStormCtrlAction(fm_int sw, fm_int id, fm_stormAction *action) {
    assert(!sw); test_storm *c = controller(id); assert(c->n_actions < 8);
    c->actions[c->n_actions++] = *action;
    if (fail_action) { fail_action = false; return FM_FAIL; }
    return FM_OK;
}
fm_status fmGetStormCtrlAttribute(fm_int sw, fm_int id, fm_int attr, void *out) {
    assert(!sw); test_storm *c = controller(id);
    if (attr == FM_STORM_RATE) *(fm_uint32 *)out = c->rate;
    else if (attr == FM_STORM_CAPACITY) *(fm_uint32 *)out = c->burst;
    else { assert(attr == FM_STORM_COUNT); *(fm_uint64 *)out = 42; }
    return FM_OK;
}
fm_status fmSetStormCtrlAttribute(fm_int sw, fm_int id, fm_int attr, void *in) {
    assert(!sw); test_storm *c = controller(id); ++attribute_writes;
    if (attr == FM_STORM_RATE) {
        u32 requested = *(fm_uint32 *)in; assert(requested < 89000000);
        if (ignore_rate) ignore_rate = false;
        else c->rate = requested / 21875 * 21875; /* 700 MHz, exponent 3 */
    } else { assert(attr == FM_STORM_CAPACITY); c->burst = *(fm_uint32 *)in / 1024 * 1024; }
    return attribute_writes == fail_attribute ? FM_FAIL : FM_OK;
}
fm_status fmCreatePortSet(fm_int sw, fm_int *set) {
    assert(!sw);
    for (int i = 1; i < 64; ++i) if (!portsets[i].used) {
        portsets[i].used = true; portsets[i].ports = 0; *set = i; return FM_OK;
    }
    return FM_ERR_NO_FREE_PORT_SET;
}
fm_status fmDeletePortSet(fm_int sw, fm_int set) {
    assert(!sw && set > 0 && set < 64);
    if (block_set_delete) return FM_FAIL;
    if (!portsets[set].used) return FM_ERR_INVALID_PORT_SET;
    portsets[set].used = false; portsets[set].ports = 0; return FM_OK;
}
fm_status fmAddPortSetPort(fm_int sw, fm_int set, fm_int port) {
    assert(!sw && set > 0 && set < 64 && portsets[set].used && nl_ifid_is_user_port(port));
    portsets[set].ports |= 1U << (port - 1); return FM_OK;
}
fm_status fmGetPortSetPortNext(fm_int sw, fm_int set, fm_int current, fm_int *next) {
    assert(!sw && set > 0 && set < 64);
    if (!portsets[set].used) return FM_ERR_INVALID_PORT_SET;
    for (int p = current + 1; p <= 24; ++p) if (portsets[set].ports & (1U << (p - 1))) {
        *next = p; return FM_OK;
    }
    return FM_ERR_NO_PORT_SET_PORT;
}
fm_status fmGetPortSetPortFirst(fm_int sw, fm_int set, fm_int *first) {
    return fmGetPortSetPortNext(sw, set, 0, first);
}

static int set_count(void) { int n = 0; for (int i = 1; i < 64; ++i) n += portsets[i].used; return n; }
static hal_storm_control_entry policy(int port, nl_storm_kind kind) {
    hal_storm_control_entry out;
    int rc = kind == NL_STORM_INGRESS ? hal_ingress_rate_limit_get(0, port, &out) :
        hal_storm_control_get_kind(0, port, kind, &out);
    assert(!rc); return out;
}
static bool traffic_matches(int id, int frame_class, bool flooded) {
    test_storm *c = controller(id); unsigned classes = 0, handlers = 0;
    for (int i = 0; i < c->n_conditions; ++i) {
        switch (c->conditions[i].type) {
        case FM_STORM_COND_BROADCAST: classes |= 1; break;
        case FM_STORM_COND_MULTICAST: classes |= 2; break;
        case FM_STORM_COND_UNICAST: classes |= 4; break;
        case FM_STORM_COND_FLOOD: handlers |= 1; break;
        case FM_STORM_COND_FIDFORWARD: handlers |= 2; break;
        default: break;
        }
    }
    return (classes & (unsigned)frame_class) && (handlers & (flooded ? 1 : 2));
}
static void verify_siblings(test_storm before_mc, test_storm before_uc, test_storm before_ingress, test_storm before_other) {
    assert(!memcmp(&before_mc, controller(policy(1, NL_STORM_MULTICAST).controller), sizeof(before_mc)));
    assert(!memcmp(&before_uc, controller(policy(1, NL_STORM_UNKNOWN_UNICAST).controller), sizeof(before_uc)));
    assert(!memcmp(&before_ingress, controller(policy(1, NL_STORM_INGRESS).controller), sizeof(before_ingress)));
    assert(!memcmp(&before_other, controller(policy(5, NL_STORM_BROADCAST).controller), sizeof(before_other)));
}
int main(void) {
    assert(!nl_port_scope_init("switchd")); reset_simulator(); g_trace_logs = true;
    assert(!hal_storm_control_set_kind(0, 1, NL_STORM_BROADCAST, 22000, 65536));
    assert(!hal_storm_control_set_kind(0, 1, NL_STORM_MULTICAST, 200000, 65536));
    assert(!hal_storm_control_set_kind(0, 1, NL_STORM_UNKNOWN_UNICAST, 300000, 65536));
    assert(!hal_ingress_rate_limit_set(0, 1, 400000, 65536));
    assert(!hal_storm_control_set_kind(0, 5, NL_STORM_BROADCAST, 500000, 65536));
    hal_storm_control_entry entries[16];
    assert(hal_storm_control_list(0, entries, 16) == 4 && hal_ingress_rate_limit_list(0, entries, 16) == 1);
    assert(policy(1, NL_STORM_BROADCAST).rate_kbps == 21875);
    int bc = policy(1, NL_STORM_BROADCAST).controller, mc = policy(1, NL_STORM_MULTICAST).controller;
    int uc = policy(1, NL_STORM_UNKNOWN_UNICAST).controller, ingress = policy(1, NL_STORM_INGRESS).controller;
    for (int flood = 0; flood <= 1; ++flood) {
        assert(traffic_matches(bc, 1, flood) && !traffic_matches(bc, 2, flood) && !traffic_matches(bc, 4, flood));
        assert(traffic_matches(mc, 2, flood) && !traffic_matches(mc, 1, flood) && !traffic_matches(mc, 4, flood));
        assert(!traffic_matches(uc, 1, flood) && !traffic_matches(uc, 2, flood));
        for (int cls = 1; cls <= 4; cls *= 2) assert(traffic_matches(ingress, cls, flood));
    }
    assert(traffic_matches(uc, 4, true) && !traffic_matches(uc, 4, false));
    test_storm old_mc = *controller(mc), old_uc = *controller(uc), old_ingress = *controller(ingress);
    test_storm old_other = *controller(policy(5, NL_STORM_BROADCAST).controller);

    for (int fault = 0; fault < 3; ++fault) {
        u64 tx = 100 + (u64)fault;
        assert(!nl_port_scope_begin(tx, 1, 100));
        l2_apply_plan *p = new_plan(1, tx); assert(p);
        p->fm10k_scope_present = true; p->fm10k_scope_mask = 1;
        p->steps[0] = (l2_apply_step){.type = L2_STEP_STORM_CONTROL_SET, .ae_id = -1, .port = 1,
            .storm_kind = NL_STORM_BROADCAST, .storm_rate_kbps = 110000, .storm_burst_bytes = 65536};
        ignore_rate = fault == 1;
        fail_attribute = fault == 2 ? attribute_writes + 2 : 0;
        int rc = apply_plan(p);
        if (!fault) {
            assert(!rc && policy(1, NL_STORM_BROADCAST).rate_kbps == 109375);
            assert(!hal_rollback_l2_plan(0, p));
        } else assert(rc);
        assert(policy(1, NL_STORM_BROADCAST).rate_kbps == 21875);
        verify_siblings(old_mc, old_uc, old_ingress, old_other);
        assert(!nl_port_scope_end(tx)); free_plan(p);
    }
    assert(!nl_port_scope_begin(200, 1, 100));
    l2_apply_plan *p = new_plan(3, 200); assert(p);
    p->fm10k_scope_present = true; p->fm10k_scope_mask = 1;
    for (int i = 0; i < 3; ++i) p->steps[i] = (l2_apply_step){.type = L2_STEP_STORM_CONTROL_SET,
        .ae_id = -1, .port = 1, .storm_kind = (nl_storm_kind)(i + 1),
        .storm_rate_kbps = 600000 + i * 100000, .storm_burst_bytes = 65536};
    assert(!apply_plan(p));
    struct verify_result result[3]; memset(result, 0, sizeof(result));
    controller(policy(1, NL_STORM_BROADCAST).controller)->rate = 21875;
    assert(verify_apply_plan(0, p, result, 3) != 0 && !result[0].readback_ok);
    assert(!hal_rollback_l2_plan(0, p));
    verify_siblings(old_mc, old_uc, old_ingress, old_other);
    assert(!nl_port_scope_end(200)); free_plan(p);

    int original_sets = set_count(), deletes = delete_calls;
    test_storm *malformed = controller(policy(1, NL_STORM_BROADCAST).controller);
    malformed->conditions[malformed->n_conditions++] = (fm_stormCondition){.type = FM_STORM_COND_UNICAST};
    assert(hal_storm_control_transaction_snapshot_kind(0, 1, NL_STORM_BROADCAST).state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR);
    assert(hal_storm_control_delete_kind(0, 1, NL_STORM_BROADCAST) && delete_calls == deletes);
    --malformed->n_conditions;
    fail_list = true;
    assert(hal_storm_control_delete_kind(0, 1, NL_STORM_BROADCAST) && delete_calls == deletes);
    struct verify_result verification;
    fail_list = true;
    assert(verify_storm_control_kind(0, 9, NL_STORM_BROADCAST, 0, 0, false, &verification));
    for (int phase = 0; phase < 2; ++phase) {
        fail_action = true; block_delete = phase == 0; block_set_delete = phase == 1;
        assert(hal_storm_control_set_kind(0, 9, NL_STORM_BROADCAST, 100000, 65536));
        assert(hal_storm_control_transaction_snapshot_kind(0, 9, NL_STORM_BROADCAST).state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR);
        block_delete = block_set_delete = false;
        assert(!hal_storm_control_delete_kind(0, 9, NL_STORM_BROADCAST) && set_count() == original_sets);
        verify_siblings(old_mc, old_uc, old_ingress, old_other);
    }
    /* Independent policies consume actual global slots, including ingress. */
    for (int port = 6; port <= 16; ++port) assert(!hal_storm_control_set_kind(0, port, NL_STORM_BROADCAST, 100000, 65536));
    assert(hal_storm_control_set_kind(0, 17, NL_STORM_BROADCAST, 100000, 65536));
    assert(!hal_storm_control_delete_kind(0, 1, NL_STORM_BROADCAST));
    verify_siblings(old_mc, old_uc, old_ingress, old_other);
    assert(hal_storm_control_transaction_snapshot_kind(0, 1, NL_STORM_BROADCAST).state == HAL_TRANSACTION_SNAPSHOT_ABSENT);
    puts("typed storm: class isolation, quantization, production rollback, read errors, cleanup retry and capacity passed");
    return 0;
}
