#include "netlab/port_scope.h"
#include "netlab/packet_event.h"
#include "netlab/error.h"
#include "../vendor/netlab/sbin/switchd/sdk_runtime_scope.h"
#include "netlab/fm10k_plan_scope.h"
#include "netlab/fm10k_plan_codec.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static atomic_bool running;
static atomic_ulong activity[24];
static int resumed;
static void resume_hook(u32 mask, time_t seconds) {
    assert(seconds >= 0 && (nl_port_scope_get().mask & mask) == mask);
    assert(!nl_port_scope_enter_mask(mask));
    ++resumed;
}
static void *traffic(void *unused) {
    (void)unused;
    while (atomic_load(&running)) {
        for (int port = 1; port <= 24; ++port) {
            if (!nl_port_scope_enter(port)) continue;
            atomic_fetch_add(&activity[port - 1], 1);
            nl_port_scope_leave(port);
        }
    }
    return NULL;
}
static void codec(void) {
    u8 frame[64], event[128];
    memset(frame, 0x55, sizeof(frame));
    u64 stamp = nl_port_scope_clock();
    int n = nl_packet_event_encode(event, sizeof(event), 17, 4094, stamp, frame, sizeof(frame));
    assert(n == sizeof(frame) + NL_PACKET_EVENT_HEADER);
    int port, vlan; u64 actual;
    assert(nl_packet_event_decode(event, n, &port, &vlan, &actual) == NL_PACKET_EVENT_HEADER);
    assert(port == 17 && vlan == 4094 && actual == stamp);
    assert(!memcmp(event + NL_PACKET_EVENT_HEADER, frame, sizeof(frame)));
    assert(nl_packet_event_decode(event, 12, &port, &vlan, &actual) < 0);
    assert(nl_packet_event_encode(event, 40, 17, 4094, stamp, frame, sizeof(frame)) < 0);
    assert(nl_packet_event_encode(event, 128, 17, 4095, stamp, frame, sizeof(frame)) < 0);
}
static int resolve_test_lag(int sw, int id, bool lag_handle, u32 *mask) {
    assert(sw == 0);
    if (id != (lag_handle ? 7 : 100)) return NL_ERR_INTERFACE_NOT_FOUND;
    *mask |= 0x11; return 0;
}
static int resolve_plan_scope(void *context, nl_fm10k_scope_target kind, int id, u32 *mask) {
    (void)context;
    if (kind == NL_FM10K_SCOPE_AE && id == 0) { *mask = 0x11; return 0; }
    if (kind == NL_FM10K_SCOPE_VLAN && id == 100) { *mask = 0x22; return 0; }
    return NL_ERR_PRE_STATE_MISSING;
}
static void plan_scopes(void) {
    bool present; u32 mask;
    const char text[] = "# fm10k-scope-v1 mask=00000f\nfm10k-fan-set\n";
    assert(nl_fm10k_parse_scope_header(text, strlen(text), &present, &mask) && present && mask == 15);
    assert(!nl_fm10k_parse_scope_header(text, sizeof(NL_FM10K_SCOPE_HEADER) + 2, &present, &mask));
    const char duplicate[] = "# fm10k-scope-v1 mask=00000f\n# fm10k-scope-v1 mask=0000f0\n";
    assert(!nl_fm10k_parse_scope_header(duplicate, strlen(duplicate), &present, &mask));
    l2_apply_step step = {.type = L2_STEP_FM10K_GROUP_SET, .fm10k_group = {.epl = 5}, .ae_id = -1};
    l2_apply_plan p = {.steps = &step, .n_steps = 1, .step_capacity = 1};
    assert(!nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) && mask == NL_PORT_SCOPE_MASK);
    step.type = L2_STEP_FM10K_FAN_SET;
    assert(!nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) && !mask);
    step.type = L2_STEP_PORT_SET_MTU; step.port = 24;
    assert(!nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) && mask == NL_PORT_SCOPE_MASK);
    step.type = L2_STEP_VLAN_STP_SET; step.ae_id = 0;
    assert(!nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) && mask == 0x11);
    step.type = L2_STEP_PORT_INGRESS_FILTER_SET;
    assert(!nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) && mask == 0x11);
    step.type = L2_STEP_LAG_DEL_PORT; step.port = 9;
    assert(!nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) && mask == 0x111);
    step.ae_id = -1;
    assert(nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) == NL_ERR_INVALID_VALUE);
    step.ae_id = 0;
    step.type = L2_STEP_VLAN_DELETE; step.vid = 100;
    assert(!nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) && mask == 0x22);
    step.vid = 101;
    assert(nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) == NL_ERR_PRE_STATE_MISSING);
    step.type = L2_STEP_QOS_PRIORITY_MAP_SET;
    assert(!nl_fm10k_plan_port_mask(&p, resolve_plan_scope, NULL, &mask) && mask == NL_PORT_SCOPE_MASK);
}
static void runtime_operations(void) {
    struct sdk_op reset;
    memset(&reset, 0xff, sizeof(reset));
    sdk_rpc_op_init(&reset, NL_DAEMON_STPD, 1234);
    assert(reset.runtime && reset.issued_at == 1234 && reset.args.port.port == 0);
    sdk_rpc_op_init(&reset, NL_DAEMON_CONFIGD, 5678);
    assert(!reset.runtime && reset.issued_at == 5678);
    assert(sdk_native_rpc_supported(NL_SWITCHD_L2_PLAN_APPLY));
    assert(!sdk_native_rpc_supported(NL_SWITCHD_L3_TX_APPLY));
    assert(!sdk_native_rpc_supported(NL_SWITCHD_OPTICS_MUX_PROBE));
    assert(!sdk_native_rpc_supported(NL_SWITCHD_PORT_MODE_SET));
    assert(!sdk_native_rpc_supported(9999));
    struct sdk_context observation = {0};
    assert(!sdk_native_observation_readable(&observation, NL_SWITCHD_PORT_SNAPSHOT_GET));
    observation.initialized = observation.pfe_cap.sdk_initialized = true;
    observation.pfe_cap.switch_enabled = observation.pfe_cap.port_inventory_ok = true;
    observation.exec = (void *)&observation;
    assert(sdk_native_observation_readable(&observation, NL_SWITCHD_PORT_SNAPSHOT_GET));
    assert(sdk_native_observation_readable(&observation, NL_SWITCHD_FM10K_CONFIG_GET));
    assert(!sdk_native_observation_readable(&observation, NL_SWITCHD_L2_PLAN_APPLY));
    assert(!sdk_native_observation_readable(&observation, NL_SWITCHD_FM10K_FAN_MANUAL));
    assert(!sdk_native_observation_readable(&observation, NL_SWITCHD_STP_RUNTIME_SET));
    assert(!sdk_native_observation_readable(&observation, NL_SWITCHD_PACKET_TX));
    assert(!sdk_native_observation_readable(&observation, NL_SWITCHD_PORT_COUNTERS_RESET));
    observation.pfe_cap.sdk_initialized = false;
    assert(!sdk_native_observation_readable(&observation, NL_SWITCHD_PORT_SNAPSHOT_GET));
    struct sdk_op op = {.type = SDK_OP_RUNTIME_STP_SET, .runtime = true};
    op.issued_at = nl_port_scope_clock(); op.args.vlan.port = 100;
    u32 mask;
    assert(!sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) && mask == 0x11);
    assert(!nl_port_scope_begin(555, 15, 50));
    assert(!nl_port_scope_enter_epoch_mask(mask, op.issued_at));
    assert(!nl_port_scope_end(555));
    assert(!nl_port_scope_enter_epoch_mask(mask, op.issued_at)); /* delayed SDK job */
    u64 resumed_at = nl_port_scope_clock();
    do { op.issued_at = nl_port_scope_clock(); } while (op.issued_at <= resumed_at);
    assert(nl_port_scope_enter_epoch_mask(mask, op.issued_at)); nl_port_scope_leave_mask(mask);
    op.args.vlan.port = 101;
    assert(sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) == NL_ERR_INTERFACE_NOT_FOUND);
    op.type = SDK_OP_LAG_ADD_PORT; op.args.lag.port = 9; op.args.lag.lag_id = 7;
    assert(!sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) && mask == 0x111);
    assert(!nl_port_scope_begin(556, 15, 50));
    assert(!nl_port_scope_enter_epoch_mask(mask, nl_port_scope_clock()));
    assert(!nl_port_scope_end(556));
    op.type = SDK_OP_LAG_DEL_PORT;
    assert(!sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) && mask == 0x111);
    op.args.lag.lag_id = 8;
    assert(sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) == NL_ERR_INTERFACE_NOT_FOUND);
    op.type = SDK_OP_PACKET_TX; op.args.pkt_tx.port = 9;
    assert(!sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) && mask == 0x100);
    op.type = SDK_OP_CLEAR_DYNAMIC_MAC_TABLE; op.args.vlan.port = 0;
    assert(!sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) && mask == NL_PORT_SCOPE_MASK);
    l2_apply_step step = {.type = L2_STEP_IGMP_LISTENER_SET, .port = 17, .ae_id = -1};
    l2_apply_plan plan = {.steps = &step, .n_steps = 1, .step_capacity = 1};
    op.type = SDK_OP_APPLY_L2_PLAN; op.args.apply_plan = &plan;
    assert(!sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) && mask == 0x10000);
    step.type = L2_STEP_FM10K_GROUP_SET;
    assert(sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) == NL_ERR_INVALID_VALUE);
    op.runtime = false;
    assert(!sdk_runtime_scope_mask(0, &op, resolve_test_lag, &mask) && mask == 0);
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "concurrency";
    int rc = nl_port_scope_init("testd");
    if (!strcmp(mode, "invalid")) {
        assert(rc == NL_ERR_HW_STATE_OUT_OF_SYNC);
        assert(nl_port_scope_get().mask == NL_PORT_SCOPE_MASK);
        assert(!nl_port_scope_enter(1) && !nl_port_scope_enter(24)); return 0;
    }
    assert(rc == 0);
    if (!strcmp(mode, "persist")) {
        assert(nl_port_scope_begin(123, 15, 100) == 0); return 0;
    }
    if (!strcmp(mode, "expand")) {
        assert(nl_port_scope_get().tx_id == 123 && nl_port_scope_get().mask == 15);
        assert(!nl_port_scope_begin(123, 255, 100));
        assert(nl_port_scope_begin(123, 15, 100) == NL_ERR_COMMIT_LOCKED);
        assert(!nl_port_scope_enter(8) && nl_port_scope_enter(9)); nl_port_scope_leave(9);
        return 0;
    }
    if (!strcmp(mode, "expanded")) {
        assert(nl_port_scope_get().tx_id == 123 && nl_port_scope_get().mask == 255);
        assert(nl_port_scope_now(1, time(NULL)) <= nl_port_scope_now(5, time(NULL)));
        assert(!nl_port_scope_end(123)); return 0;
    }
    if (!strcmp(mode, "degrade")) {
        assert(nl_port_scope_begin(123, 15, 100) == 0);
        nl_port_scope_degrade(123); return 0;
    }
    if (!strcmp(mode, "restore") || !strcmp(mode, "degraded")) {
        nl_port_scope_status s = nl_port_scope_get();
        assert(s.tx_id == 123 && s.mask == 15);
        assert(!nl_port_scope_enter(1) && nl_port_scope_enter(5)); nl_port_scope_leave(5);
        if (!strcmp(mode, "degraded")) {
            assert(s.degraded && !nl_port_scope_ready());
            assert(nl_port_scope_end(123) == NL_ERR_HW_STATE_OUT_OF_SYNC);
        } else assert(nl_port_scope_end(123) == 0);
        return 0;
    }
    assert(nl_port_scope_ready()); codec(); plan_scopes(); runtime_operations();
    nl_port_scope_on_resume(resume_hook);
    assert(nl_port_scope_enter(1));
    u64 old_packet = nl_port_scope_clock();
    assert(nl_port_scope_begin(1, 15, 1) == NL_ERR_RPC_TIMEOUT);
    assert(nl_port_scope_get().tx_id == 1 && nl_port_scope_get().mask == 15);
    assert(!nl_port_scope_enter(2));
    assert(nl_port_scope_enter(5)); nl_port_scope_leave(5);
    assert(nl_port_scope_end(1) == NL_ERR_RPC_BUSY);
    nl_port_scope_leave(1);
    assert(nl_port_scope_begin(1, 15, 100) == 0);
    assert(nl_port_scope_begin(2, 15, 100) == NL_ERR_COMMIT_LOCKED);
    assert(nl_port_scope_begin(1, 240, 100) == NL_ERR_COMMIT_LOCKED);
    assert(nl_port_scope_end(2) == NL_ERR_COMMIT_LOCKED);
    assert(nl_port_scope_end(1) == 0 && resumed == 1);
    assert(nl_port_scope_end(1) == 0 && resumed == 1);
    assert(!nl_port_scope_packet_enter(1, old_packet));
    assert(!nl_port_scope_enter_epoch_mask(0x11, old_packet));
    assert(nl_port_scope_enter_epoch_mask(0xf0, old_packet)); nl_port_scope_leave_mask(0xf0);
    assert(nl_port_scope_packet_enter(5, old_packet)); nl_port_scope_leave(5);
    assert(nl_port_scope_packet_enter(1, nl_port_scope_clock())); nl_port_scope_leave(1);
    pthread_t worker;
    atomic_store(&running, true);
    assert(!pthread_create(&worker, NULL, traffic, NULL));
    for (u64 tx = 2; tx <= 101; ++tx) {
        int group = (int)(tx % 6), first = group * 4;
        u32 mask = 15U << first;
        assert(nl_port_scope_begin(tx, mask, 1000) == 0);
        unsigned long before[4];
        for (int lane = 0; lane < 4; ++lane) before[lane] = atomic_load(&activity[first + lane]);
        int sibling = (first + 4) % 24;
        unsigned long other = atomic_load(&activity[sibling]);
        for (int tries = 0; tries < 1000 && atomic_load(&activity[sibling]) == other; ++tries) usleep(100);
        assert(atomic_load(&activity[sibling]) > other);
        for (int lane = 0; lane < 4; ++lane) assert(atomic_load(&activity[first + lane]) == before[lane]);
        assert(nl_port_scope_end(tx) == 0);
    }
    atomic_store(&running, false); pthread_join(worker, NULL);
    assert(resumed == 101);
    puts("scoped activity drain, packet epochs and 100 concurrent transitions passed");
    return 0;
}
