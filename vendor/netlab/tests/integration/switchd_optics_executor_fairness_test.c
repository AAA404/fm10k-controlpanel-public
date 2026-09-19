/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/hal.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int test_sdk_dispatch(int sw, struct sdk_op *op,
                             struct sdk_result *result);
#define NETLAB_SDK_EXECUTOR_DISPATCH test_sdk_dispatch
#include "../../sbin/switchd/sdk_executor.c"
#include "watchdog_disabled_fixture.h"

static volatile int sdk_active;
static volatile int sdk_max_active;
static volatile int sdk_calls;
static long sdk_delay_ns = 200000L;
static int mux_value = 0x0a;
static int failed;

bool fm10k_native_profile(void) { return false; }
bool fm10k_native_aux_port(int sw, int port) { (void)sw; (void)port; return false; }
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
int hal_lag_ae_for_id(int id) { (void)id; return -1; }
int hal_lag_id_for_ae(int id) { (void)id; return -1; }
bool nl_ifid_get_by_logical_port(int port, nl_port_entry *out) { (void)port; (void)out; return false; }
fm_status fmGetVlanPortList(fm_int sw, fm_uint16 vid, fm_int *count, fm_int *ports, fm_int size) {
    (void)sw; (void)vid; (void)count; (void)ports; (void)size; return FM_FAIL;
}
fm_status fmLogicalPortToLAGNumber(fm_int sw, fm_int port, fm_int *lag) {
    (void)sw; (void)port; (void)lag; return FM_FAIL;
}
fm_status fmGetLAGPortList(fm_int sw, fm_int lag, fm_int *count, fm_int *ports, fm_int size) {
    (void)sw; (void)lag; (void)count; (void)ports; (void)size; return FM_FAIL;
}

static void sdk_call_begin(void) {
    int active = __sync_add_and_fetch(&sdk_active, 1);
    int observed;

    do {
        observed = sdk_max_active;
        if (observed >= active)
            break;
    } while (!__sync_bool_compare_and_swap(&sdk_max_active,
                                            observed, active));
    __sync_add_and_fetch(&sdk_calls, 1);
}

static void sdk_call_end(void) {
    __sync_sub_and_fetch(&sdk_active, 1);
}

static void sdk_delay(void) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = sdk_delay_ns};

    while (nanosleep(&delay, &delay) != 0)
        ;
}

fm_status fmPlatformI2cWriteRead(fm_int sw, fm_int bus, fm_int address,
                                 fm_uint32 *data, fm_int write_length,
                                 fm_int read_length) {
    (void)sw;
    (void)bus;
    (void)address;
    sdk_call_begin();
    sdk_delay();
    if (write_length == 0 && read_length == 1)
        *data = (fm_uint32)mux_value;
    else if (write_length == 1 && read_length == 0)
        mux_value = (int)(*data & 0xff);
    else {
        sdk_call_end();
        return (fm_status)-101;
    }
    sdk_call_end();
    return FM_OK;
}

fm_status fmI2cWriteRead(fm_int sw, fm_uint device, fm_byte *data,
                         fm_uint write_length, fm_uint read_length) {
    (void)sw;
    (void)device;
    sdk_call_begin();
    sdk_delay();
    if ((write_length == 0 && read_length == 1) ||
        (write_length == 1 && read_length > 0))
        memset(data, 0x5a, read_length);
    else if (!(write_length == 2 && read_length == 0)) {
        sdk_call_end();
        return (fm_status)-102;
    }
    sdk_call_end();
    return FM_OK;
}

void nl_mac_snapshot_reset(nl_mac_snapshot *snapshot) {
    (void)snapshot;
}

void nl_stp_snapshot_reset(nl_stp_snapshot *snapshot) {
    (void)snapshot;
}

int l3_fib_snapshot_sweep(u64 now_ns) {
    (void)now_ns;
    return 0;
}

void l2_apply_plan_init(l2_apply_plan *plan) {
    if (plan)
        memset(plan, 0, sizeof(*plan));
}

void l2_apply_plan_reset(l2_apply_plan *plan) {
    (void)plan;
}

int l2_apply_plan_clone(l2_apply_plan *destination,
                        const l2_apply_plan *source) {
    (void)destination;
    (void)source;
    return -1;
}

void l2_apply_plan_move(l2_apply_plan *destination,
                        l2_apply_plan *source) {
    (void)destination;
    (void)source;
}

static int test_sdk_dispatch(int sw, struct sdk_op *op,
                             struct sdk_result *result) {
    (void)sw;
    sdk_call_begin();
    sdk_delay();
    sdk_call_end();
    if (op->type == SDK_OP_GET_PORT_STATE) {
        result->data.port_state.state = 1;
        return 0;
    }
    return op->type == SDK_OP_NOP ? 0 : -1;
}

static uint64_t elapsed_us(const struct timespec *start,
                           const struct timespec *end) {
    uint64_t start_ns = (uint64_t)start->tv_sec * 1000000000ULL +
        (uint64_t)start->tv_nsec;
    uint64_t end_ns = (uint64_t)end->tv_sec * 1000000000ULL +
        (uint64_t)end->tv_nsec;
    return (end_ns - start_ns) / 1000ULL;
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;

    return a < b ? -1 : (a > b ? 1 : 0);
}

static void expect(const char *name, int condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        failed++;
}

typedef struct {
    struct sdk_executor *exec;
    struct sdk_result result;
    int status;
    uint32_t timeout_ms;
} probe_request;

static void *run_probe(void *argument) {
    probe_request *request = argument;
    struct sdk_op op;

    memset(&op, 0, sizeof(op));
    op.type = SDK_OP_OPTICS_MUX_PROBE;
    op.args.optics_mux_probe.bus = 0;
    op.args.optics_mux_probe.mux_addr = 0x58;
    op.args.optics_mux_probe.branch[0] = 1;
    op.args.optics_mux_probe.branch[1] = 2;
    request->status = sdk_exec_with_prio(
        request->exec, &op, &request->result,
        SDK_PRIO_PLATFORM_POLL, request->timeout_ms);
    return NULL;
}

static int wait_for_calls(int minimum) {
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000L};

    for (int i = 0; i < 1000; i++) {
        if (sdk_calls >= minimum)
            return 0;
        nanosleep(&delay, NULL);
    }
    return -1;
}

int main(void) {
    struct sdk_executor *exec = NULL;
    probe_request request;
    pthread_t thread;
    uint64_t control_latency[30];
    uint64_t readback_latency[30];
    uint64_t control_max = 0;
    uint64_t readback_max = 0;
    struct sdk_op op;
    struct sdk_result result;
    struct timespec start;
    struct timespec end;

    expect("executor initializes", sdk_executor_init(&exec, 0) == 0);
    memset(&request, 0, sizeof(request));
    request.exec = exec;
    request.timeout_ms = 30000;
    expect("long optics probe starts",
           pthread_create(&thread, NULL, run_probe, &request) == 0);
    expect("probe reaches vendor SDK", wait_for_calls(8) == 0);

    for (int i = 0; i < 30; i++) {
        memset(&op, 0, sizeof(op));
        memset(&result, 0, sizeof(result));
        op.type = SDK_OP_NOP;
        clock_gettime(CLOCK_MONOTONIC, &start);
        expect("control request completes during probe",
               sdk_exec_with_prio(exec, &op, &result,
                                  SDK_PRIO_CONTROL_PACKET, 250) == 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        control_latency[i] = elapsed_us(&start, &end);
        if (control_latency[i] > control_max)
            control_max = control_latency[i];

        memset(&op, 0, sizeof(op));
        memset(&result, 0, sizeof(result));
        op.type = SDK_OP_GET_PORT_STATE;
        clock_gettime(CLOCK_MONOTONIC, &start);
        expect("readback request completes during probe",
               sdk_exec_with_prio(exec, &op, &result,
                                  SDK_PRIO_READBACK, 250) == 0);
        clock_gettime(CLOCK_MONOTONIC, &end);
        readback_latency[i] = elapsed_us(&start, &end);
        if (readback_latency[i] > readback_max)
            readback_max = readback_latency[i];
    }
    pthread_join(thread, NULL);
    qsort(control_latency, 30, sizeof(control_latency[0]), compare_u64);
    qsort(readback_latency, 30, sizeof(readback_latency[0]), compare_u64);
    printf("INFO: control p95=%llu us max=%llu us; readback p95=%llu us "
           "max=%llu us\n",
           (unsigned long long)control_latency[28],
           (unsigned long long)control_max,
           (unsigned long long)readback_latency[28],
           (unsigned long long)readback_max);
    expect("optics probe completes with a fresh exact snapshot",
           request.status == 0 && request.result.data.optics_mux_probe.complete &&
           request.result.data.optics_mux_probe.generation > 0 &&
           request.result.data.optics_mux_probe.sampled_monotonic_ms > 0);
    expect("mux is restored after every yielded slice", mux_value == 0x0a);
    expect("control wait P95 is bounded below 100ms",
           control_latency[28] < 100000ULL);
    expect("control maximum wait is bounded below 200ms",
           control_max < 200000ULL);
    expect("readback wait P95 is bounded below 100ms",
           readback_latency[28] < 100000ULL);
    expect("readback maximum wait is bounded below 200ms",
           readback_max < 200000ULL);
    expect("vendor SDK authority remains single-threaded", sdk_max_active == 1);

    sdk_delay_ns = 2000000L;
    memset(&request, 0, sizeof(request));
    request.exec = exec;
    request.timeout_ms = 5;
    expect("deadline probe starts",
           pthread_create(&thread, NULL, run_probe, &request) == 0);
    pthread_join(thread, NULL);
    expect("deadline returns fail-closed without a partial snapshot",
           request.status != 0 &&
           !request.result.data.optics_mux_probe.complete);
    memset(&op, 0, sizeof(op));
    op.type = SDK_OP_NOP;
    expect("control work proceeds after cancelled probe",
           sdk_exec_with_prio(exec, &op, &result,
                              SDK_PRIO_CONTROL_PACKET, 250) == 0);
    expect("cancelled slice restores the mux", mux_value == 0x0a);
    expect("cancellation does not introduce SDK concurrency",
           sdk_max_active == 1);

    sdk_executor_shutdown(&exec);
    return failed ? 1 : 0;
}
