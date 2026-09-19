#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "netlab/types.h"
#include <fm_sdk.h>
#include <api/fm_api_event_types.h>

#define FIXTURE_QUEUE_CAPACITY 8U

static fm_uint32 g_masks[FIXTURE_QUEUE_CAPACITY];
static fm_uint32 g_tokens[FIXTURE_QUEUE_CAPACITY];
static u32 g_mask_calls;
static u32 g_send_calls;
static int g_mask_fail_call;
static int g_send_fail_call;
static u64 g_fake_now;
static int g_advance_time;
static int g_release_old_distributor;
static int g_old_callback_done;
static int g_barrier_after_old;
static int g_drain_done;
static int g_drain_rc;

static fm_status fixture_set_mask(fm_uint32 mask);
static fm_status fixture_send(fm_int sw, fm_uint32 token);
static int fixture_monotonic_ns(u64 *out);
static void fixture_sleep(void);

#define SDK_EVENT_BARRIER_TIMEOUT_NS UINT64_C(100)
#define SDK_EVENT_BARRIER_SET_MASK(mask) fixture_set_mask((mask))
#define SDK_EVENT_BARRIER_SEND(sw, token) fixture_send((sw), (token))
#define SDK_EVENT_BARRIER_MONOTONIC_NS(out) \
    fixture_monotonic_ns((out))
#define SDK_EVENT_BARRIER_SLEEP() fixture_sleep()

#include "../../sbin/switchd/sdk_event_barrier.c"

static fm_status fixture_set_mask(fm_uint32 mask)
{
    u32 call = g_mask_calls++;

    if (call < FIXTURE_QUEUE_CAPACITY)
        g_masks[call] = mask;
    if (g_mask_fail_call > 0 &&
        call + 1U == (u32)g_mask_fail_call)
        return FM_FAIL;
    return FM_OK;
}

static fm_status fixture_send(fm_int sw, fm_uint32 token)
{
    u32 call = __atomic_load_n(&g_send_calls, __ATOMIC_SEQ_CST);

    (void)sw;
    if (call < FIXTURE_QUEUE_CAPACITY)
        g_tokens[call] = token;
    /*
     * Publish the completed token slot after its contents.  The dispatcher
     * uses this counter as the acquire side of the fixture queue.
     */
    __atomic_store_n(&g_send_calls, call + 1U, __ATOMIC_SEQ_CST);
    if (g_send_fail_call > 0 &&
        call + 1U == (u32)g_send_fail_call)
        return FM_FAIL;
    return FM_OK;
}

static int fixture_monotonic_ns(u64 *out)
{
    if (!out)
        return -1;
    *out = __atomic_load_n(&g_fake_now, __ATOMIC_SEQ_CST);
    return 0;
}

static void fixture_sleep(void)
{
    if (__atomic_load_n(&g_advance_time, __ATOMIC_SEQ_CST) != 0)
        (void)__atomic_fetch_add(
            &g_fake_now, UINT64_C(10), __ATOMIC_SEQ_CST);
    sched_yield();
}

static void fixture_reset(void)
{
    memset(g_masks, 0, sizeof(g_masks));
    memset(g_tokens, 0, sizeof(g_tokens));
    g_mask_calls = 0;
    g_send_calls = 0;
    g_mask_fail_call = 0;
    g_send_fail_call = 0;
    g_fake_now = 0;
    g_advance_time = 0;
    g_release_old_distributor = 0;
    g_old_callback_done = 0;
    g_barrier_after_old = 0;
    g_drain_done = 0;
    g_drain_rc = -99;
    sdk_event_barrier_init();
}

static int wait_for_u32(const u32 *value, u32 expected)
{
    for (u32 attempt = 0; attempt < 1000000U; attempt++) {
        if (__atomic_load_n(value, __ATOMIC_SEQ_CST) >= expected)
            return 0;
        sched_yield();
    }
    return -1;
}

static void *fixture_global_dispatcher(void *arg)
{
    fm_eventSoftware software;

    (void)arg;
    while (__atomic_load_n(
               &g_release_old_distributor, __ATOMIC_SEQ_CST) == 0)
        sched_yield();

    /*
     * This models a vendor distributor that copied the old process mask
     * before shutdown and stalled before its local callback enqueue.
     */
    __atomic_store_n(&g_old_callback_done, 1, __ATOMIC_SEQ_CST);
    if (wait_for_u32(&g_send_calls, 2U) != 0)
        return NULL;
    for (u32 i = 0; i < 2U; i++) {
        software.activeEvents = g_tokens[i];
        if (!sdk_event_barrier_handle(FM_EVENT_SOFTWARE, &software))
            return NULL;
    }
    if (__atomic_load_n(
            &g_old_callback_done, __ATOMIC_SEQ_CST) != 0)
        __atomic_store_n(
            &g_barrier_after_old, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static void *fixture_drain(void *arg)
{
    (void)arg;
    g_drain_rc = sdk_event_barrier_drain(0, true);
    __atomic_store_n(&g_drain_done, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static int fixture_deliver_token(u32 index, bool expected_handled)
{
    fm_eventSoftware software;
    bool handled;

    if (index >= FIXTURE_QUEUE_CAPACITY)
        return -1;
    software.activeEvents = g_tokens[index];
    handled = sdk_event_barrier_handle(FM_EVENT_SOFTWARE, &software);
    return handled == expected_handled ? 0 : -1;
}

static int fixture_deliver_pair(u32 first, bool expected_handled)
{
    if (fixture_deliver_token(first, expected_handled) != 0 ||
        fixture_deliver_token(first + 1U, expected_handled) != 0)
        return -1;
    return 0;
}

static int fixture_start_drain(pthread_t *drain, u32 expected_sends)
{
    if (!drain)
        return -1;
    g_drain_rc = -99;
    __atomic_store_n(&g_drain_done, 0, __ATOMIC_SEQ_CST);
    if (pthread_create(drain, NULL, fixture_drain, NULL) != 0)
        return -1;
    if (wait_for_u32(&g_send_calls, expected_sends) != 0) {
        __atomic_store_n(&g_advance_time, 1, __ATOMIC_SEQ_CST);
        (void)pthread_join(*drain, NULL);
        return -1;
    }
    return 0;
}

static int fixture_join_successful_drain(pthread_t drain)
{
    (void)pthread_join(drain, NULL);
    return g_drain_rc == 0 &&
        __atomic_load_n(&g_drain_done, __ATOMIC_SEQ_CST) != 0 ?
        0 : -1;
}

static int test_delayed_old_distributor(void)
{
    const struct timespec old_quiet_window = {
        .tv_sec = 0,
        .tv_nsec = 120000000L,
    };
    pthread_t dispatcher;
    pthread_t drain;

    fixture_reset();
    if (pthread_create(
            &dispatcher, NULL, fixture_global_dispatcher, NULL) != 0 ||
        pthread_create(&drain, NULL, fixture_drain, NULL) != 0)
        return 1;
    if (wait_for_u32(&g_send_calls, 2U) != 0)
        return 1;
    (void)nanosleep(&old_quiet_window, NULL);
    if (__atomic_load_n(&g_drain_done, __ATOMIC_SEQ_CST) != 0 ||
        __atomic_load_n(
            &g_old_callback_done, __ATOMIC_SEQ_CST) != 0)
        return 1;
    __atomic_store_n(
        &g_release_old_distributor, 1, __ATOMIC_SEQ_CST);
    (void)pthread_join(dispatcher, NULL);
    (void)pthread_join(drain, NULL);
    if (g_drain_rc != 0 || g_mask_calls != 1U ||
        g_masks[0] != FM_EVENT_SOFTWARE ||
        __atomic_load_n(
            &g_barrier_after_old, __ATOMIC_SEQ_CST) == 0)
        return 1;
    if (sdk_event_barrier_stop() != 0 ||
        g_mask_calls != 2U || g_masks[1] != 0U)
        return 1;
    return 0;
}

static int test_stale_tokens_across_retries(void)
{
    pthread_t drain;

    /*
     * The first token may already be queued when the second send fails.
     * It must not advance the next generation's state machine.
     */
    fixture_reset();
    g_send_fail_call = 2;
    if (sdk_event_barrier_drain(0, true) == 0 ||
        g_send_calls != 2U)
        return 1;
    g_send_fail_call = 0;
    if (fixture_start_drain(&drain, 4U) != 0)
        return 1;
    if (fixture_deliver_token(0U, false) != 0 ||
        __atomic_load_n(
            &g_barrier_phase, __ATOMIC_SEQ_CST) !=
            SDK_EVENT_BARRIER_PHASE_FIRST ||
        fixture_deliver_pair(2U, true) != 0 ||
        fixture_join_successful_drain(drain) != 0)
        return 1;

    /*
     * A timed-out generation can leave both sentinels queued.  Deliver both
     * during a retry and prove that neither is accepted as the new pair.
     */
    fixture_reset();
    g_advance_time = 1;
    if (sdk_event_barrier_drain(0, true) == 0 ||
        g_send_calls != 2U)
        return 1;
    g_advance_time = 0;
    if (fixture_start_drain(&drain, 4U) != 0)
        return 1;
    if (fixture_deliver_pair(0U, false) != 0 ||
        __atomic_load_n(
            &g_barrier_phase, __ATOMIC_SEQ_CST) !=
            SDK_EVENT_BARRIER_PHASE_FIRST ||
        fixture_deliver_pair(2U, true) != 0 ||
        fixture_join_successful_drain(drain) != 0)
        return 1;
    return 0;
}

static int test_final_mask_retry(void)
{
    pthread_t drain;

    fixture_reset();
    if (fixture_start_drain(&drain, 2U) != 0 ||
        fixture_deliver_pair(0U, true) != 0 ||
        fixture_join_successful_drain(drain) != 0)
        return 1;
    g_mask_fail_call = 2;
    if (sdk_event_barrier_stop() == 0 ||
        g_mask_calls != 2U || g_masks[1] != 0U)
        return 1;

    g_mask_fail_call = 0;
    if (fixture_start_drain(&drain, 4U) != 0 ||
        fixture_deliver_pair(2U, true) != 0 ||
        fixture_join_successful_drain(drain) != 0 ||
        sdk_event_barrier_stop() != 0 ||
        g_mask_calls != 4U || g_masks[3] != 0U)
        return 1;
    return 0;
}

static int test_fail_closed_paths(void)
{
    fixture_reset();
    g_mask_fail_call = 1;
    if (sdk_event_barrier_drain(0, true) == 0 ||
        g_send_calls != 0U)
        return 1;

    fixture_reset();
    g_send_fail_call = 2;
    if (sdk_event_barrier_drain(0, true) == 0 ||
        g_mask_calls != 1U || g_send_calls != 2U)
        return 1;

    fixture_reset();
    g_advance_time = 1;
    if (sdk_event_barrier_drain(0, true) == 0 ||
        g_mask_calls != 1U || g_send_calls != 2U)
        return 1;

    fixture_reset();
    if (sdk_event_barrier_drain(0, false) != 0 ||
        g_mask_calls != 0U || g_send_calls != 0U)
        return 1;

    fixture_reset();
    g_mask_fail_call = 1;
    if (sdk_event_barrier_stop() == 0 ||
        g_mask_calls != 1U || g_masks[0] != 0U)
        return 1;
    return 0;
}

int main(void)
{
    if (test_delayed_old_distributor() != 0) {
        fprintf(stderr, "delayed vendor distributor crossed barrier\n");
        return 1;
    }
    if (test_fail_closed_paths() != 0) {
        fprintf(stderr, "event barrier failure path did not fail closed\n");
        return 1;
    }
    if (test_stale_tokens_across_retries() != 0) {
        fprintf(stderr, "stale sentinel crossed a retry generation\n");
        return 1;
    }
    if (test_final_mask_retry() != 0) {
        fprintf(stderr, "final mask failure was not safely retryable\n");
        return 1;
    }
    printf(
        "PASS: SDK software sentinel is FIFO, fail closed, and retry safe\n");
    return 0;
}
