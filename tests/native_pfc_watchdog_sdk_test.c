/* Production adapter, fake SDK reads/writes; never initialize a device. */
#define clock_gettime watchdog_test_clock_gettime
#include "../vendor/netlab/sbin/switchd/hal_pfc_watchdog.c"
#undef clock_gettime
#include <assert.h>

static uint64_t test_now = 1000, test_pfc, test_pause, test_tx;
static int actual_mask = 8, cache_mask = 8, writes, destination = 20;
static bool test_ready = true, paused = true, queued = true, link_up = true;
static bool scope_busy, counter_error, partial_release, drop_restore, clock_error;

int watchdog_test_clock_gettime(clockid_t kind, struct timespec *ts) {
    assert(kind == CLOCK_MONOTONIC);
    if (clock_error) return -1;
    ts->tv_sec = (time_t)(test_now / 1000);
    ts->tv_nsec = (long)(test_now % 1000) * 1000000;
    return 0;
}
bool fm10k_native_profile(void) { return true; }
bool fm10k_native_ready(void) { return test_ready; }
bool nl_port_scope_ready(void) { return true; }
nl_port_scope_status nl_port_scope_get(void) {
    return (nl_port_scope_status){.tx_id=scope_busy ? 1 : 0};
}
bool nl_port_scope_enter(int port) { assert(port == 13); return !scope_busy; }
void nl_port_scope_leave(int port) { assert(port == 13); }
fm_status fmGetLogicalPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(!sw && port == 13 && attr == FM_LPORT_DEST_MASK);
    fm_portmask *mask = out;
    mask->maskWord[0] = 1U << destination;
    return FM_OK;
}
fm_status fmReadUncachedUINT32(fm_int sw, fm_uint reg, fm_uint32 *out) {
    assert(!sw && reg == 0xE60800U + (unsigned)destination);
    *out = (fm_uint32)actual_mask | 0x100U;
    return FM_OK;
}
fm_status fmReadUncachedUINT64Mult(fm_int sw, fm_uint reg, fm_int count, fm_uint64 *out) {
    assert(!sw && reg == 0xE61400U + 4U * (unsigned)destination && count == 2);
    out[0] = paused ? (fm_uint64)65535U << 48 : 0;
    out[1] = 0;
    return FM_OK;
}
fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(!sw && port == 13 && attr == FM_PORT_RX_CLASS_PAUSE);
    *(fm_uint32 *)out = (fm_uint32)cache_mask;
    return FM_OK;
}
fm_status fmGetPortState(fm_int sw, fm_int port, fm_int *mode, fm_int *state, fm_int *info) {
    assert(!sw && port == 13 && info);
    *mode = FM_PORT_MODE_UP;
    *state = link_up ? FM_PORT_STATE_UP : FM_PORT_STATE_DOWN;
    return FM_OK;
}
fm_status fmSetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *value) {
    assert(!sw && port == 13 && attr == FM_PORT_RX_CLASS_PAUSE);
    int mask = (int)*(fm_uint32 *)value;
    assert(mask == 0 || mask == 8); /* No timer-register or other-priority writes. */
    ++writes;
    if (!mask && partial_release) { actual_mask = 0; return FM_FAIL; }
    if (!(mask == 8 && drop_restore)) actual_mask = mask;
    cache_mask = mask;
    return FM_OK;
}
fm_status fmGetPortQOS(fm_int sw, fm_int port, fm_int attr, fm_int index, void *out) {
    assert(!sw && port == 13 && index == 3);
    if (attr == FM_QOS_TC_PC_MAP) *(fm_uint32 *)out = 3;
    else { assert(attr == FM_QOS_TX_TC_USAGE); *(fm_uint32 *)out = queued ? 192U : 0; }
    return FM_OK;
}
fm_status fmGetPortCounters(fm_int sw, fm_int port, fm_portCounters *out) {
    assert(!sw && port == 13);
    if (counter_error) return FM_FAIL;
    out->cntTxUcstPkts = test_tx;
    out->cntRxCBPausePkts = test_pfc;
    out->cntRxPausePkts = test_pause;
    return FM_OK;
}
void nl_log_write(nl_log_level level, const char *file, int line, const char *fmt, ...) {
    (void)level; (void)file; (void)line; (void)fmt;
}
static void reset(void) {
    memset(ports, 0, sizeof(ports)); last_poll_ms = 0;
    test_now = 1000; test_pfc = test_pause = test_tx = 0;
    actual_mask = cache_mask = 8; writes = 0; destination = 20;
    test_ready = paused = queued = link_up = true;
    scope_busy = counter_error = partial_release = drop_restore = clock_error = false;
    fm10k_pfc_wd_policy policy = {1000, 500, 10000};
    assert(!hal_pfc_watchdog_configure(0, 13, &policy));
}
static void tick(void) {
    test_pfc += 20;
    hal_pfc_watchdog_poll(0, test_now);
    test_now += 100;
}
static void detect(void) {
    for (unsigned i = 0; i < 12; ++i) tick();
    assert(ports[13].core.detections == 1);
}

int main(void) {
    reset();
    for (int i = 0; i < 30; ++i) { ++test_tx; tick(); }
    assert(!writes); /* Some data traffic vetoes recovery. */
    for (int i = 0; i < 30; ++i) { ++test_pause; tick(); }
    assert(!writes); /* Ordinary PAUSE is never accepted as PFC evidence. */
    paused = false;
    for (int i = 0; i < 30; ++i) tick();
    assert(!writes);
    reset(); queued = false;
    for (int i = 0; i < 30; ++i) tick();
    assert(!writes);

    reset(); detect();
    assert(actual_mask == 0 && cache_mask == 0 && ports[13].core.active);
    hal_pfc_wd_status status;
    hal_pfc_watchdog_get(0, 13, &status);
    assert(status.supported && status.phase == HAL_PFC_WD_RECOVERING && status.saved_rx_mask == 8);
    int before = writes;
    assert(!hal_pfc_watchdog_quiesce(0));
    assert(writes == before + 1 && actual_mask == 8 && cache_mask == 8 && !ports[13].core.active);
    for (int i = 0; i < 30; ++i) tick();
    assert(ports[13].core.detections == 1); /* Cooldown prevents a storm. */

    reset(); partial_release = true; detect();
    assert(writes == 2 && actual_mask == 8 && cache_mask == 8 && !ports[13].core.active);
    assert(ports[13].core.failures == 1);

    reset(); detect(); drop_restore = true;
    assert(hal_pfc_watchdog_quiesce(0));
    assert(ports[13].core.active && actual_mask == 0 && cache_mask == 8);
    fm10k_pfc_wd_policy disabled = fm10k_pfc_wd_default_policy();
    assert(hal_pfc_watchdog_configure(0, 13, &disabled));
    assert(ports[13].core.active); /* A failed lease cannot be discarded. */
    drop_restore = false;
    assert(!hal_pfc_watchdog_quiesce(0) && actual_mask == 8);

    reset(); detect(); destination = 21; before = writes;
    assert(hal_pfc_watchdog_quiesce(0) && writes == before);
    destination = 20;
    assert(!hal_pfc_watchdog_quiesce(0));

    reset(); detect(); scope_busy = true; tick();
    assert(actual_mask == 8 && !ports[13].core.active);
    reset(); detect(); test_ready = false; tick();
    assert(actual_mask == 8 && !ports[13].core.active);
    reset(); detect(); clock_error = true; hal_pfc_watchdog_poll(0, 0);
    assert(actual_mask == 8 && !ports[13].core.active && ports[13].core.cooldown_needs_clock);

    reset();
    for (int i = 0; i < 11; ++i) tick();
    counter_error = true; tick(); counter_error = false;
    for (int i = 0; i < 10; ++i) tick();
    assert(!writes); /* Read failure breaks continuous detection. */
    test_now += 1000; tick();
    assert(!writes && ports[13].core.gaps == 1);
    puts("PFC owner adapter: uncached verification, rollback leases, ordinary-Pause veto and maintenance passed");
    return 0;
}
