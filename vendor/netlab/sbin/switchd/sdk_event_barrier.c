#include "sdk_event_barrier.h"

#include "netlab/types.h"
#include <errno.h>
#include <time.h>
#include <fm_sdk.h>
#include <api/fm_api_event_mgmt.h>
#include <api/fm_api_event_types.h>

#define SDK_EVENT_BARRIER_TOKEN_FIRST_SEED UINT32_C(0x4e4c5346)
#define SDK_EVENT_BARRIER_TOKEN_LAST_SEED  UINT32_C(0xb1b3acb9)
#define SDK_EVENT_BARRIER_PHASE_FIRST 1U
#define SDK_EVENT_BARRIER_PHASE_LAST  2U
#define SDK_EVENT_BARRIER_PHASE_DONE  3U

#ifndef SDK_EVENT_BARRIER_TIMEOUT_NS
#define SDK_EVENT_BARRIER_TIMEOUT_NS UINT64_C(5000000000)
#endif
#ifndef SDK_EVENT_BARRIER_POLL_NS
#define SDK_EVENT_BARRIER_POLL_NS UINT64_C(1000000)
#endif
#ifndef SDK_EVENT_BARRIER_SET_MASK
#define SDK_EVENT_BARRIER_SET_MASK(mask) fmSetProcessEventMask((mask))
#endif
#ifndef SDK_EVENT_BARRIER_SEND
#define SDK_EVENT_BARRIER_SEND(sw, token) \
    fmSendSoftwareEvent((fm_int)(sw), (fm_uint32)(token))
#endif

static u32 g_barrier_armed;
static u32 g_barrier_phase;
static u64 g_barrier_generation;
static u32 g_barrier_token_first;
static u32 g_barrier_token_last;

#ifndef SDK_EVENT_BARRIER_MONOTONIC_NS
static int sdk_event_barrier_monotonic_ns(u64 *out)
{
    struct timespec now;

    if (!out || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= 1000000000L)
        return -1;
    if ((u64)now.tv_sec >
        (UINT64_MAX - (u64)now.tv_nsec) / UINT64_C(1000000000))
        return -1;
    *out = (u64)now.tv_sec * UINT64_C(1000000000) + (u64)now.tv_nsec;
    return 0;
}
#define SDK_EVENT_BARRIER_MONOTONIC_NS(out) \
    sdk_event_barrier_monotonic_ns((out))
#endif

#ifndef SDK_EVENT_BARRIER_SLEEP
static void sdk_event_barrier_sleep(void)
{
    struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = (long)SDK_EVENT_BARRIER_POLL_NS,
    };

    while (nanosleep(&delay, &delay) != 0 && errno == EINTR)
        ;
}
#define SDK_EVENT_BARRIER_SLEEP() sdk_event_barrier_sleep()
#endif

void sdk_event_barrier_init(void)
{
    __atomic_store_n(
        &g_barrier_generation, UINT64_C(0), __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_barrier_token_first, 0U, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_barrier_token_last, 0U, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_barrier_phase, 0U, __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_barrier_armed, 0U, __ATOMIC_SEQ_CST);
}

bool sdk_event_barrier_handle(int event, void *event_info)
{
    const fm_eventSoftware *software = event_info;
    u32 phase;
    u32 next;

    if (event != FM_EVENT_SOFTWARE || !software ||
        __atomic_load_n(&g_barrier_armed, __ATOMIC_SEQ_CST) == 0)
        return false;

    phase = __atomic_load_n(&g_barrier_phase, __ATOMIC_SEQ_CST);
    if (phase == SDK_EVENT_BARRIER_PHASE_FIRST &&
        software->activeEvents == __atomic_load_n(
            &g_barrier_token_first, __ATOMIC_SEQ_CST)) {
        next = SDK_EVENT_BARRIER_PHASE_LAST;
        (void)__atomic_compare_exchange_n(
            &g_barrier_phase, &phase, next, false,
            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        return true;
    }
    if (phase == SDK_EVENT_BARRIER_PHASE_LAST &&
        software->activeEvents == __atomic_load_n(
            &g_barrier_token_last, __ATOMIC_SEQ_CST)) {
        next = SDK_EVENT_BARRIER_PHASE_DONE;
        (void)__atomic_compare_exchange_n(
            &g_barrier_phase, &phase, next, false,
            __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        return true;
    }
    return false;
}

static int sdk_event_barrier_wait(void)
{
    u64 started;
    u64 now;

    if (SDK_EVENT_BARRIER_MONOTONIC_NS(&started) != 0)
        return -1;
    for (;;) {
        if (__atomic_load_n(
                &g_barrier_phase, __ATOMIC_SEQ_CST) ==
            SDK_EVENT_BARRIER_PHASE_DONE)
            return 0;
        SDK_EVENT_BARRIER_SLEEP();
        if (SDK_EVENT_BARRIER_MONOTONIC_NS(&now) != 0 ||
            now < started ||
            now - started >= SDK_EVENT_BARRIER_TIMEOUT_NS)
            return -1;
    }
}

int sdk_event_barrier_drain(int sw, bool switch_up)
{
    u64 generation;
    u32 folded;
    u32 first;
    u32 last;
    int rc = -1;

    if (!switch_up)
        return 0;
    /*
     * Mask packet delivery before arming the sentinel.  A distributor that
     * copied the old mask already occupies the SDK's sole global dispatcher;
     * it must enqueue its local callback before either sentinel can cross the
     * same global and local FIFO queues.
     */
    if (SDK_EVENT_BARRIER_SET_MASK(FM_EVENT_SOFTWARE) != FM_OK)
        return -1;
    generation = __atomic_add_fetch(
        &g_barrier_generation, UINT64_C(1), __ATOMIC_SEQ_CST);
    folded = (u32)generation ^ (u32)(generation >> 32);
    first = SDK_EVENT_BARRIER_TOKEN_FIRST_SEED ^
        folded * UINT32_C(0x9e3779b9);
    last = SDK_EVENT_BARRIER_TOKEN_LAST_SEED ^
        folded * UINT32_C(0x85ebca6b);
    if (last == first)
        last ^= UINT32_C(0xffffffff);
    __atomic_store_n(
        &g_barrier_token_first, first, __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &g_barrier_token_last, last, __ATOMIC_SEQ_CST);
    __atomic_store_n(
        &g_barrier_phase, SDK_EVENT_BARRIER_PHASE_FIRST,
        __ATOMIC_SEQ_CST);
    __atomic_store_n(&g_barrier_armed, 1U, __ATOMIC_SEQ_CST);
    if (SDK_EVENT_BARRIER_SEND(sw, first) != FM_OK ||
        SDK_EVENT_BARRIER_SEND(sw, last) != FM_OK)
        goto complete;
    rc = sdk_event_barrier_wait();

complete:
    __atomic_store_n(&g_barrier_armed, 0U, __ATOMIC_SEQ_CST);
    return rc;
}

int sdk_event_barrier_stop(void)
{
    return SDK_EVENT_BARRIER_SET_MASK(0) == FM_OK ? 0 : -1;
}
