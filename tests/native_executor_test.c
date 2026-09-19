/* Production SDK queue and scope admission, with the SDK dispatch boundary
 * replaced by a recorder. No SDK library is linked or initialized. */
#include "netlab/hal.h"
#include <assert.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int recorded_dispatch(int sw, struct sdk_op *op, struct sdk_result *result);
#define NETLAB_SDK_EXECUTOR_DISPATCH recorded_dispatch
#include "../vendor/netlab/sbin/switchd/sdk_executor.c"
#include "../vendor/netlab/tests/integration/watchdog_disabled_fixture.h"

static atomic_bool native_profile = true;
static atomic_uint_fast64_t native_generation = 1;
static pthread_mutex_t recorder_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t recorder_changed = PTHREAD_COND_INITIALIZER;
static bool owner_held, owner_waiting;
static pthread_t sdk_owner;
static unsigned port_writes[128], writes, dispatches;
static u64 cooperative_tx;
static bool cooperative_started, cooperative_start, cooperative_checkpointed;
static bool cooperative_continue, cooperative_finished, cooperative_finish;
static unsigned checkpoint_dispatches, foreign_config_dispatches, fan_polls;
static int failed_runtime_port;
static int commit_dispatches;
static int configuration_read_failure, physical_state_reads;
bool fm10k_native_profile(void) { return atomic_load(&native_profile); }
uint64_t fm10k_native_generation(void) { return atomic_load(&native_generation); }
bool fm10k_native_aux_port(int sw, int port) { return sw == 0 && (port == 28 || port == 29); }
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}

static int recorded_dispatch(int sw, struct sdk_op *op, struct sdk_result *result) {
    assert(sw == 0);
    pthread_mutex_lock(&recorder_lock);
    int status = 0;
    ++dispatches;
    if (op->type == SDK_OP_NOP && op->args.port.port == -1) {
        sdk_owner = pthread_self();
        owner_waiting = true;
        pthread_cond_broadcast(&recorder_changed);
        while (owner_held) pthread_cond_wait(&recorder_changed, &recorder_lock);
    } else if (op->type == SDK_OP_RUNTIME_STP_SET) {
        int port = op->args.vlan.port;
        assert(port > 0 && port < 128);
        ++port_writes[port]; ++writes;
        if (port == failed_runtime_port) status = NL_ERR_SDK_CALL_FAILED;
    } else if (op->type == SDK_OP_PACKET_TX) {
        assert(op->args.pkt_tx.port > 0 && op->args.pkt_tx.port <= 24);
        ++port_writes[op->args.pkt_tx.port]; ++writes;
    } else if (op->type == SDK_OP_LAG_ADD_PORT || op->type == SDK_OP_LAG_DEL_PORT) {
        assert(op->args.lag.port >= 1 && op->args.lag.port <= 24);
        ++port_writes[op->args.lag.port]; ++writes;
    } else if (op->type == SDK_OP_APPLY_L2_PLAN && op->args.apply_plan->tx_id == cooperative_tx) {
        assert(op->args.apply_plan->checkpoint && op->args.apply_plan->checkpoint_context);
        cooperative_started = true; pthread_cond_broadcast(&recorder_changed);
        while (!cooperative_start) pthread_cond_wait(&recorder_changed, &recorder_lock);
        for (int step = 0; step < 20; ++step) {
            unsigned before = dispatches;
            pthread_mutex_unlock(&recorder_lock);
            l2_apply_plan_checkpoint(op->args.apply_plan);
            pthread_mutex_lock(&recorder_lock);
            assert(dispatches - before <= SDK_PLAN_CHECKPOINT_MAX_OPS);
            checkpoint_dispatches += dispatches - before;
            assert(!foreign_config_dispatches);
            if (!step) {
                cooperative_checkpointed = true; pthread_cond_broadcast(&recorder_changed);
                while (!cooperative_continue) pthread_cond_wait(&recorder_changed, &recorder_lock);
            }
        }
        cooperative_finished = true; pthread_cond_broadcast(&recorder_changed);
        while (!cooperative_finish) pthread_cond_wait(&recorder_changed, &recorder_lock);
    } else if (op->type == SDK_OP_FM10K_BOARD_POLL) {
        ++fan_polls;
    } else if (op->type == SDK_OP_COMMIT_MARK_SUCCESS || op->type == SDK_OP_COMMIT_MARK_FAILED) {
        assert(pthread_equal(sdk_owner, pthread_self()) && !op->runtime);
        assert(op->args.commit.tx_id == 902);
        ++commit_dispatches;
        if (op->type == SDK_OP_COMMIT_MARK_FAILED) status = NL_ERR_HW_STATE_OUT_OF_SYNC;
    } else {
        assert(op->type == SDK_OP_NOP || op->type == SDK_OP_GET_PORT_STATE ||
               op->type == SDK_OP_PORT_SET_SPEED || op->type == SDK_OP_APPLY_L2_PLAN);
        if (op->type == SDK_OP_APPLY_L2_PLAN && cooperative_tx) ++foreign_config_dispatches;
        if (op->type == SDK_OP_GET_PORT_STATE && op->args.port.configuration_only)
            status = sdk_read_port_state(sw, op->args.port.port, &result->data.port_state, true);
    }
    result->status = status;
    pthread_mutex_unlock(&recorder_lock);
    return status;
}

fm_status fmGetPortState(fm_int sw, fm_int port, fm_int *mode, fm_int *state, fm_int *info) {
    (void)mode; (void)state; (void)info;
    assert(sw == 0 && port == 100 && pthread_equal(sdk_owner, pthread_self()));
    ++physical_state_reads;
    return FM_ERR_INVALID_PORT; /* Pinned IES excludes LAGs from this API. */
}
int hal_port_get_mtu(int sw, int port, int *mtu, int *max_frame) {
    assert(sw == 0 && port == 100 && pthread_equal(sdk_owner, pthread_self()));
    if (configuration_read_failure == 1) return -1;
    *mtu = 9000; *max_frame = 9024; return 0;
}
fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(sw == 0 && port == 100 && pthread_equal(sdk_owner, pthread_self()));
    assert(attr == FM_PORT_DEF_VLAN);
    if (configuration_read_failure == 2) return FM_FAIL;
    *(fm_uint32 *)out = 100; return FM_OK;
}

fm_status fmLogicalPortToLAGNumber(fm_int sw, fm_int port, fm_int *lag) {
    assert(sw == 0 && pthread_equal(sdk_owner, pthread_self()));
    if (port != 100 && port != 101) return FM_FAIL;
    *lag = port - 99; return FM_OK;
}
int hal_lag_ae_for_id(int lag) { return lag >= 1 && lag <= 2 ? lag - 1 : -1; }
int hal_lag_id_for_ae(int ae) { return ae >= 0 && ae < 2 ? ae + 1 : -1; }
bool nl_ifid_get_by_logical_port(int port, nl_port_entry *out) { (void)port; (void)out; return false; }
fm_status fmGetLAGPortList(fm_int sw, fm_int lag, fm_int *count, fm_int *ports, fm_int size) {
    assert(sw == 0 && pthread_equal(sdk_owner, pthread_self()) && size >= 2);
    assert(lag == 1 || lag == 2);
    *count = 2; ports[0] = lag == 1 ? 1 : 9; ports[1] = lag == 1 ? 5 : 10;
    return FM_OK;
}
fm_status fmGetVlanPortList(fm_int sw, fm_uint16 vid, fm_int *count, fm_int *ports, fm_int size) {
    assert(sw == 0 && pthread_equal(sdk_owner, pthread_self()) && size >= 5);
    if (vid != 100) return FM_ERR_INVALID_VLAN;
    *count = 5; ports[0] = 0; ports[1] = 1; ports[2] = 5; ports[3] = 28; ports[4] = 29;
    return FM_OK;
}
fm_status fmPlatformI2cWriteRead(fm_int sw, fm_int bus, fm_int address,
                                 fm_uint32 *data, fm_int write_length, fm_int read_length) {
    (void)sw; (void)bus; (void)address; (void)data; (void)write_length; (void)read_length;
    assert(false); return FM_FAIL; /* Native generic mux probes must never execute. */
}
fm_status fmI2cWriteRead(fm_int sw, fm_uint device, fm_byte *data,
                         fm_uint write_length, fm_uint read_length) {
    (void)sw; (void)device; (void)data; (void)write_length; (void)read_length;
    assert(false); return FM_FAIL;
}
void nl_mac_snapshot_reset(nl_mac_snapshot *snapshot) { (void)snapshot; assert(false); }
void nl_stp_snapshot_reset(nl_stp_snapshot *snapshot) { (void)snapshot; assert(false); }
int l3_fib_snapshot_sweep(u64 now) { (void)now; return 0; }

typedef struct {
    struct sdk_executor *exec;
    struct sdk_op op;
    struct sdk_result result;
    u32 timeout;
    int priority, status;
    pthread_t thread;
} request;
static void *submit(void *arg) {
    request *r = arg;
    r->status = sdk_exec_with_prio(r->exec, &r->op, &r->result, r->priority, r->timeout);
    assert(r->status == r->result.status);
    return NULL;
}
static void init_request(request *r, struct sdk_executor *exec, sdk_op_type type, int port, u64 issued) {
    memset(r, 0, sizeof(*r));
    r->exec = exec; r->timeout = 3000; r->priority = SDK_PRIO_CONTROL_PACKET;
    sdk_rpc_op_init(&r->op, NL_DAEMON_STPD, issued);
    r->op.type = type;
    if (type == SDK_OP_RUNTIME_STP_SET) r->op.args.vlan.port = port;
    else r->op.args.port.port = port;
    if (type == SDK_OP_LAG_ADD_PORT || type == SDK_OP_LAG_DEL_PORT)
        r->op.args.lag.native_generation = fm10k_native_generation();
}
static void start(request *r) { assert(!pthread_create(&r->thread, NULL, submit, r)); }
static void join(request *r) { assert(!pthread_join(r->thread, NULL)); }
static void queue_depth(struct sdk_executor *exec, unsigned wanted) {
    for (int i = 0; i < 3000; ++i) {
        sdk_executor_stats stats; sdk_executor_stats_snapshot(exec, &stats);
        unsigned total = 0;
        for (int q = 0; q < SDK_PRIO_COUNT; ++q) total += stats.priority[q].queue_depth;
        if (total == wanted) return;
        struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
    }
    assert(false);
}
static void hold(request *r, struct sdk_executor *exec) {
    pthread_mutex_lock(&recorder_lock); owner_held = true; owner_waiting = false; pthread_mutex_unlock(&recorder_lock);
    init_request(r, exec, SDK_OP_NOP, -1, nl_port_scope_clock()); start(r);
    pthread_mutex_lock(&recorder_lock);
    while (!owner_waiting) pthread_cond_wait(&recorder_changed, &recorder_lock);
    pthread_mutex_unlock(&recorder_lock);
}
static void release(request *r) {
    pthread_mutex_lock(&recorder_lock); owner_held = false; pthread_cond_broadcast(&recorder_changed); pthread_mutex_unlock(&recorder_lock);
    join(r); assert(!r->status);
}

static void cooperative_plan_test(struct sdk_executor *exec, request *r, bool changes_fan) {
    u64 stale = nl_port_scope_clock();
    assert(!nl_port_scope_begin(1100, 1U << 8, 100));
    assert(!nl_port_scope_end(1100));
    pthread_mutex_lock(&recorder_lock);
    cooperative_tx = changes_fan ? 1201 : 1200;
    cooperative_started = cooperative_start = cooperative_checkpointed = false;
    cooperative_continue = cooperative_finished = cooperative_finish = false;
    checkpoint_dispatches = foreign_config_dispatches = fan_polls = 0;
    failed_runtime_port = 17;
    pthread_mutex_unlock(&recorder_lock);
    assert(!nl_port_scope_begin(cooperative_tx, 15, 100));
    l2_apply_plan plan, other;
    l2_apply_plan_init(&plan); l2_apply_plan_init(&other);
    assert(!l2_apply_plan_allocate_steps(&plan, changes_fan ? 2 : 1));
    plan.n_steps = changes_fan ? 2 : 1; plan.tx_id = cooperative_tx;
    plan.fm10k_scope_present = true; plan.fm10k_scope_mask = 15;
    plan.steps[0].type = L2_STEP_PORT_SET_ADMIN; plan.steps[0].port = 1; plan.steps[0].ae_id = -1;
    if (changes_fan) plan.steps[1].type = L2_STEP_FM10K_FAN_SET;
    assert(!l2_apply_plan_allocate_steps(&other, 1));
    other.n_steps = 1; other.tx_id = 1300; other.fm10k_scope_present = true;
    other.steps[0].type = L2_STEP_FM10K_FAN_SET;
    init_request(&r[0], exec, SDK_OP_APPLY_L2_PLAN, 0, nl_port_scope_clock());
    r[0].op.runtime = false; r[0].op.args.apply_plan = &plan; r[0].priority = SDK_PRIO_CONFIG_CHANGE;
    start(&r[0]);
    pthread_mutex_lock(&recorder_lock);
    while (!cooperative_started) pthread_cond_wait(&recorder_changed, &recorder_lock);
    pthread_mutex_unlock(&recorder_lock);
    /* Put another transaction first in the config queue. Runtime work behind
     * it must proceed without executing that transaction inside this one. */
    init_request(&r[1], exec, SDK_OP_APPLY_L2_PLAN, 0, nl_port_scope_clock());
    r[1].op.runtime = false; r[1].op.args.apply_plan = &other; r[1].priority = SDK_PRIO_CONFIG_CHANGE;
    start(&r[1]); queue_depth(exec, 1);
    const int ports[] = {9, 1, 17, 9};
    for (int index = 0; index < 4; ++index) {
        init_request(&r[index + 2], exec, SDK_OP_RUNTIME_STP_SET, ports[index],
                     index == 3 ? stale : nl_port_scope_clock());
        r[index + 2].priority = index == 2 ? SDK_PRIO_CONFIG_CHANGE : SDK_PRIO_CONTROL_PACKET;
        start(&r[index + 2]);
    }
    init_request(&r[6], exec, SDK_OP_FM10K_BOARD_POLL, 0, 0);
    r[6].op.runtime = false; r[6].priority = SDK_PRIO_PLATFORM_POLL; start(&r[6]);
    queue_depth(exec, 6);
    pthread_mutex_lock(&recorder_lock);
    cooperative_start = true; pthread_cond_broadcast(&recorder_changed);
    while (!cooperative_checkpointed) pthread_cond_wait(&recorder_changed, &recorder_lock);
    assert(checkpoint_dispatches > 0 && checkpoint_dispatches <= SDK_PLAN_CHECKPOINT_MAX_OPS);
    assert(!foreign_config_dispatches);
    cooperative_continue = true; pthread_cond_broadcast(&recorder_changed);
    while (!cooperative_finished) pthread_cond_wait(&recorder_changed, &recorder_lock);
    assert(fan_polls == (changes_fan ? 0U : 1U) && !foreign_config_dispatches);
    pthread_mutex_unlock(&recorder_lock);
    for (int index = 2; index <= 5; ++index) join(&r[index]);
    assert(!r[2].status && r[3].status == NL_ERR_RPC_BUSY);
    assert(r[4].status == NL_ERR_SDK_CALL_FAILED && r[5].status == NL_ERR_RPC_BUSY);
    queue_depth(exec, changes_fan ? 2 : 1);
    pthread_mutex_lock(&recorder_lock);
    cooperative_finish = true; pthread_cond_broadcast(&recorder_changed);
    pthread_mutex_unlock(&recorder_lock);
    join(&r[0]); join(&r[1]); join(&r[6]);
    assert(!r[0].status && !r[1].status && !r[6].status);
    assert(foreign_config_dispatches == 1 && fan_polls == 1);
    assert(!plan.checkpoint && !plan.checkpoint_context && !other.checkpoint && !other.checkpoint_context);
    assert(!nl_port_scope_end(cooperative_tx));
    cooperative_tx = 0; failed_runtime_port = 0;
    l2_apply_plan_reset(&plan); l2_apply_plan_reset(&other);
}

int main(void) {
    assert(!nl_port_scope_init("executor-test"));
    struct sdk_executor *exec = NULL; assert(!sdk_executor_init(&exec, 0));
    request *r = calloc(7, sizeof(*r)); assert(r);
    hold(&r[0], exec);
    u64 old = nl_port_scope_clock();
    init_request(&r[1], exec, SDK_OP_RUNTIME_STP_SET, 1, old); start(&r[1]);
    init_request(&r[2], exec, SDK_OP_RUNTIME_STP_SET, 9, old); start(&r[2]);
    queue_depth(exec, 2);
    assert(!nl_port_scope_begin(801, 15, 100));
    assert(!nl_port_scope_end(801));
    init_request(&r[3], exec, SDK_OP_RUNTIME_STP_SET, 1, nl_port_scope_clock()); start(&r[3]);
    queue_depth(exec, 3); release(&r[0]);
    for (int i = 1; i <= 3; ++i) join(&r[i]);
    assert(r[1].status == NL_ERR_RPC_BUSY && !r[2].status && !r[3].status);
    assert(writes == 2 && port_writes[1] == 1 && port_writes[9] == 1);

    assert(!nl_port_scope_begin(802, 15, 100));
    const int ports[] = {1, 17, 100, 101};
    const int expected[] = {NL_ERR_RPC_BUSY, 0, NL_ERR_RPC_BUSY, 0};
    for (int i = 0; i < 4; ++i) {
        init_request(&r[1], exec, SDK_OP_RUNTIME_STP_SET, ports[i], nl_port_scope_clock());
        submit(&r[1]); assert(r[1].status == expected[i]);
    }
    assert(writes == 4 && port_writes[17] == 1 && port_writes[101] == 1);
    assert(!nl_port_scope_end(802));

    /* An expired queued request is removed without reaching the SDK. */
    hold(&r[0], exec);
    init_request(&r[1], exec, SDK_OP_RUNTIME_STP_SET, 9, nl_port_scope_clock());
    r[1].timeout = 10; start(&r[1]); join(&r[1]); assert(r[1].status != 0);
    queue_depth(exec, 0); release(&r[0]); assert(writes == 4);

    const sdk_op_type forbidden[] = {SDK_OP_OPTICS_MUX_PROBE, SDK_OP_L3_SDK_WRITE_CANARY,
        SDK_OP_L3_RUNTIME, SDK_OP_QOS_QUEUE_OWNER_APPLY, SDK_OP_PORT_SET_SPEED, SDK_OP_VLAN_CREATE,
        SDK_OP_PORT_RECOVERY_POLL, (sdk_op_type)9999};
    unsigned before = dispatches;
    for (unsigned i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
        init_request(&r[1], exec, forbidden[i], 1, nl_port_scope_clock());
        r[1].op.runtime = false; /* A cleared caller flag must not allow legacy writes. */
        submit(&r[1]); assert(r[1].status == NL_ERR_CAPABILITY_INSUFFICIENT);
    }
    assert(dispatches == before);
    l2_apply_plan plan; l2_apply_plan_init(&plan); assert(!l2_apply_plan_allocate_steps(&plan, 1));
    plan.n_steps = 1; plan.steps[0].type = L2_STEP_PORT_SET_ADMIN; plan.steps[0].port = 1;
    init_request(&r[1], exec, SDK_OP_APPLY_L2_PLAN, 0, nl_port_scope_clock());
    r[1].op.args.apply_plan = &plan; submit(&r[1]); assert(r[1].status == NL_ERR_INVALID_VALUE);
    assert(dispatches == before);
    /* Persistent plans must declare all actual ports, including VLAN and LAG
     * members. These checks run on the production owner thread before HAL. */
    r[1].op.runtime = false; plan.tx_id = 900;
    submit(&r[1]); assert(r[1].status == NL_ERR_INVALID_VALUE);
    plan.fm10k_scope_present = true; plan.fm10k_scope_mask = 1;
    plan.steps[0].type = L2_STEP_VLAN_STP_SET; plan.steps[0].port = 1; plan.steps[0].ae_id = -1;
    submit(&r[1]); assert(r[1].status == NL_ERR_COMMIT_LOCKED);
    assert(!nl_port_scope_begin(900, 1, 100));
    submit(&r[1]); assert(!r[1].status && dispatches == before + 1);
    before = dispatches;
    plan.steps[0].type = L2_STEP_VLAN_DELETE; plan.steps[0].vid = 100;
    submit(&r[1]); assert(r[1].status == NL_ERR_COMMIT_LOCKED && dispatches == before);
    plan.steps[0].type = L2_STEP_VLAN_STP_SET; plan.steps[0].ae_id = 0;
    submit(&r[1]); assert(r[1].status == NL_ERR_COMMIT_LOCKED && dispatches == before);
    assert(!nl_port_scope_end(900));
    plan.fm10k_scope_mask = 0x11; assert(!nl_port_scope_begin(900, 0x11, 100));
    submit(&r[1]); assert(!r[1].status && dispatches == before + 1);
    assert(!nl_port_scope_end(900)); l2_apply_plan_reset(&plan);

    /* A LACP operation on an unpaused port still affects every current
     * member of its aggregate. Test the actual SDK resolver at dispatch. */
    u64 lag_epoch = nl_port_scope_clock();
    assert(!nl_port_scope_begin(901, 1, 100));
    init_request(&r[1], exec, SDK_OP_LAG_ADD_PORT, 0, lag_epoch);
    r[1].op.args.lag.lag_id = 1; r[1].op.args.lag.port = 9;
    before = dispatches; submit(&r[1]);
    assert(r[1].status == NL_ERR_RPC_BUSY && dispatches == before);
    r[1].op.type = SDK_OP_LAG_DEL_PORT; r[1].op.args.lag.port = 5;
    submit(&r[1]); assert(r[1].status == NL_ERR_RPC_BUSY && dispatches == before);
    r[1].op.type = SDK_OP_LAG_ADD_PORT; r[1].op.args.lag.lag_id = 2; r[1].op.args.lag.port = 17;
    submit(&r[1]); assert(!r[1].status && dispatches == before + 1);
    assert(!nl_port_scope_end(901));
    r[1].op.args.lag.lag_id = 1; r[1].op.args.lag.port = 9;
    submit(&r[1]); assert(r[1].status == NL_ERR_RPC_BUSY); /* old aggregate epoch */
    r[1].op.issued_at = nl_port_scope_clock();
    r[1].op.args.lag.lag_id = 999;
    submit(&r[1]); assert(r[1].status == NL_ERR_INTERFACE_NOT_FOUND);

    /* Reusing a numeric LAG handle after SDK restart must not authorize a
     * queued operation selected with the old peer's synchronization. */
    hold(&r[0], exec);
    init_request(&r[1], exec, SDK_OP_LAG_ADD_PORT, 0, nl_port_scope_clock());
    r[1].op.args.lag.lag_id = 1; r[1].op.args.lag.port = 9;
    start(&r[1]); queue_depth(exec, 1);
    atomic_store(&native_generation, 2);
    before = dispatches; release(&r[0]); join(&r[1]);
    assert(r[1].status == NL_ERR_HW_STATE_OUT_OF_SYNC && dispatches == before);
    for (int i = 0; i < 2; ++i) {
        r[1].op.type = i ? SDK_OP_LAG_DEL_PORT : SDK_OP_LAG_ADD_PORT;
        r[1].op.args.lag.native_generation = 0;
        submit(&r[1]); assert(r[1].status == NL_ERR_HW_STATE_OUT_OF_SYNC && dispatches == before);
        r[1].op.args.lag.native_generation = fm10k_native_generation();
        submit(&r[1]); assert(!r[1].status && dispatches == ++before);
    }

    cooperative_plan_test(exec, r, false);
    cooperative_plan_test(exec, r, true);

    /* Finalization belongs to the same SDK thread; runtime callers cannot
     * invoke it, and completion errors must reach configd unchanged. */
    init_request(&r[1], exec, SDK_OP_COMMIT_MARK_SUCCESS, 0, nl_port_scope_clock());
    r[1].op.args.commit.tx_id = 902;
    submit(&r[1]); assert(r[1].status == NL_ERR_CAPABILITY_INSUFFICIENT && !commit_dispatches);
    r[1].op.runtime = false;
    submit(&r[1]); assert(!r[1].status && commit_dispatches == 1);
    r[1].op.type = SDK_OP_COMMIT_MARK_FAILED;
    submit(&r[1]); assert(r[1].status == NL_ERR_HW_STATE_OUT_OF_SYNC && commit_dispatches == 2);

    /* MTU/PVID readback reaches the owner thread and must bypass physical
     * MAC state. Attribute errors stay errors instead of zero-valued success. */
    init_request(&r[1], exec, SDK_OP_GET_PORT_STATE, 100, nl_port_scope_clock());
    r[1].priority = SDK_PRIO_READBACK;
    r[1].op.args.port.configuration_only = true;
    for (configuration_read_failure = 0; configuration_read_failure <= 2; ++configuration_read_failure) {
        submit(&r[1]);
        assert((r[1].status != 0) == (configuration_read_failure != 0));
        if (!configuration_read_failure)
            assert(r[1].result.data.port_state.mtu == 9000 && r[1].result.data.port_state.max_frame == 9024 &&
                   r[1].result.data.port_state.pvid == 100);
    }
    assert(!physical_state_reads);

    /* The shared executor still accepts other profiles' physical port range. */
    atomic_store(&native_profile, false);
    init_request(&r[1], exec, SDK_OP_RUNTIME_STP_SET, 49, 0); submit(&r[1]);
    assert(!r[1].status && port_writes[49] == 1);
    init_request(&r[1], exec, SDK_OP_PORT_SET_SPEED, 49, 0); submit(&r[1]); assert(!r[1].status);
    sdk_executor_shutdown(&exec); free(r);
    puts("Production SDK queue: scoped admission, bounded plan checkpoints, sibling activity, fan exclusion and cancellation passed");
    return 0;
}
