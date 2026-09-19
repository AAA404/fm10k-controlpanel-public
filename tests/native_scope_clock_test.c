#include <time.h>
#include <assert.h>
#include <stdio.h>

static unsigned mono_calls, fail_call;
static long mono_ns = 1000;
static time_t mono_seconds = 10;
static time_t wall = 100;
static time_t fixture_time(time_t *out) { if (out) *out = wall; return wall; }
static int fixture_clock_gettime(clockid_t kind, struct timespec *out) {
    if (kind != CLOCK_MONOTONIC) return clock_gettime(kind, out);
    if (++mono_calls == fail_call) return -1;
    *out = (struct timespec){.tv_sec = mono_seconds, .tv_nsec = mono_ns};
    return 0;
}
#define clock_gettime fixture_clock_gettime
#define time fixture_time
#include "../vendor/netlab/lib/libipc/port_scope.c"
#undef clock_gettime
#undef time

static int cohorts;
static void expanded_resume(u32 mask, time_t seconds) {
    assert(nl_port_scope_get().mask == 3);
    assert((mask == 1 && seconds == 10) || (mask == 2 && seconds == 5));
    ++cohorts;
}
static unsigned mono_resumes;
static void resumed_after_clock_change(u32 mask, time_t seconds) {
    assert(mask == 1 && seconds == 5);
    ++mono_resumes;
}

int main(void) {
    assert(!nl_port_scope_init("clock-test"));
    u64 issued = nl_port_scope_clock();
    assert(!nl_port_scope_begin(1, 1, 20) && !nl_port_scope_end(1));
    assert(!nl_port_scope_enter_epoch_mask(1, issued));
    assert(nl_port_scope_enter_epoch_mask(2, issued)); nl_port_scope_leave_mask(2);
    ++mono_ns;
    assert(nl_port_scope_enter_epoch_mask(1, nl_port_scope_clock())); nl_port_scope_leave_mask(1);
    nl_port_scope_on_resume(expanded_resume);
    assert(!nl_port_scope_begin(3, 1, 20));
    wall = 105; assert(!nl_port_scope_begin(3, 3, 20));
    assert(nl_port_scope_now(1, wall) == 100 && nl_port_scope_now(2, wall) == 105);
    wall = 110; assert(!nl_port_scope_end(3) && cohorts == 2);
    nl_port_scope_on_resume_monotonic(resumed_after_clock_change);
    mono_seconds = 20;
    assert(!nl_port_scope_begin(4, 1, 20));
    wall -= 86400; mono_seconds = 25;
    assert(nl_port_scope_now_monotonic(1, mono_seconds) == 20);
    assert(nl_port_scope_now_monotonic(2, mono_seconds) == 25);
    assert(!nl_port_scope_end(4) && mono_resumes == 1);
    wall = 110; mono_seconds = 30;
    assert(!nl_port_scope_begin(5, 1, 20));
    wall += 86400; mono_seconds = 35;
    assert(!nl_port_scope_end(5) && mono_resumes == 2);
    nl_port_scope_on_resume(NULL);
    assert(!nl_port_scope_begin(2, 1, 20));
    mono_calls = 0; fail_call = 2;
    assert(nl_port_scope_end(2) == NL_ERR_HW_STATE_OUT_OF_SYNC);
    nl_port_scope_status status = nl_port_scope_get();
    assert(status.tx_id == 2 && status.mask == 1 && status.degraded);
    puts("Port scope: equal timestamps rejected and a failed resume clock keeps the affected port paused");
    return 0;
}
