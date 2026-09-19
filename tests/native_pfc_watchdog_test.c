#include "fm10k_pfc_watchdog.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const fm10k_pfc_wd_policy enabled = {1000, 200, 10000};
static const fm10k_pfc_wd_policy disabled = {0, 200, 10000};
static const fm10k_pfc_wd_sample stalled = {true, true, true, true, 123};

static void trigger(fm10k_pfc_wd_state *state, uint64_t start) {
    for (uint64_t now = start; now < start + 1000; now += 100)
        assert(fm10k_pfc_wd_observe(state, &stalled, now, false) == FM10K_PFC_WD_NONE);
    assert(fm10k_pfc_wd_observe(state, &stalled, start + 1000, false) == FM10K_PFC_WD_RELEASE);
}

int main(void) {
    fm10k_pfc_wd_state state = {0};
    assert(fm10k_pfc_wd_configure(&state, &disabled));
    for (uint64_t n = 100; n < 10000; n += 100)
        assert(fm10k_pfc_wd_observe(&state, &stalled, n, false) == FM10K_PFC_WD_NONE);
    assert(!state.detections);
    assert(fm10k_pfc_wd_configure(&state, &enabled));
    trigger(&state, 100);
    fm10k_pfc_wd_releasing(&state, 1100);
    assert(state.active && state.detections == 1);
    assert(!fm10k_pfc_wd_configure(&state, &disabled));
    assert(fm10k_pfc_wd_observe(&state, &stalled, 1200, false) == FM10K_PFC_WD_NONE);
    assert(fm10k_pfc_wd_observe(&state, &stalled, 1300, false) == FM10K_PFC_WD_RESTORE);
    fm10k_pfc_wd_restored(&state, 1300, false);
    assert(state.active && state.restore_failed && state.failures == 1);
    assert(fm10k_pfc_wd_observe(&state, NULL, 0, true) == FM10K_PFC_WD_RESTORE);
    fm10k_pfc_wd_restored(&state, 1400, true);
    assert(!state.active && state.recoveries == 1 && state.cooldown_until_ms == 11400);
    for (uint64_t n = 1500; n < 11400; n += 100)
        assert(fm10k_pfc_wd_observe(&state, &stalled, n, false) == FM10K_PFC_WD_NONE);
    trigger(&state, 11400);

    /* Progress in any non-PAUSE traffic is a conservative veto. */
    memset(&state, 0, sizeof(state));
    assert(fm10k_pfc_wd_configure(&state, &enabled));
    fm10k_pfc_wd_sample sample = stalled;
    for (uint64_t n = 100; n <= 2000; n += 100) {
        sample.tx_data_packets++;
        assert(fm10k_pfc_wd_observe(&state, &sample, n, false) == FM10K_PFC_WD_NONE);
    }
    assert(!state.detections);
    fm10k_pfc_wd_gap(&state);
    assert(fm10k_pfc_wd_observe(&state, &stalled, 2100, false) == FM10K_PFC_WD_NONE);
    assert(fm10k_pfc_wd_observe(&state, &stalled, 3000, false) == FM10K_PFC_WD_NONE);
    assert(state.suspect_ms == 3000 && state.gaps == 1);
    assert(fm10k_pfc_wd_observe(&state, &stalled, 2900, false) == FM10K_PFC_WD_NONE);
    assert(state.suspect_ms == 2900 && state.gaps == 2);
    assert(fm10k_pfc_wd_observe(&state, &stalled, 3000, true) == FM10K_PFC_WD_NONE);
    assert(!state.observing);
    for (int field = 0; field < 4; ++field) {
        sample = stalled;
        if (field == 0) sample.valid = false;
        if (field == 1) sample.eligible = false;
        if (field == 2) sample.paused = false;
        if (field == 3) sample.queued = false;
        for (uint64_t n = 3100; n < 6000; n += 100)
            assert(fm10k_pfc_wd_observe(&state, &sample, n, false) == FM10K_PFC_WD_NONE);
    }

    /* Active overrides must be restored on every loss of authority/evidence. */
    fm10k_pfc_wd_releasing(&state, 7000);
    assert(fm10k_pfc_wd_observe(&state, &stalled, 6900, false) == FM10K_PFC_WD_RESTORE);
    assert(fm10k_pfc_wd_observe(&state, &stalled, 7100, true) == FM10K_PFC_WD_RESTORE);
    sample = stalled; sample.eligible = false;
    assert(fm10k_pfc_wd_observe(&state, &sample, 7100, false) == FM10K_PFC_WD_RESTORE);
    fm10k_pfc_wd_restored(&state, 0, true);
    assert(state.cooldown_needs_clock);
    assert(fm10k_pfc_wd_observe(&state, &stalled, 100000, false) == FM10K_PFC_WD_NONE);
    assert(state.cooldown_until_ms == 110000 && !state.observing);
    fm10k_pfc_wd_policy invalid = enabled; invalid.detect_ms = 500;
    assert(!fm10k_pfc_wd_configure(&state, &invalid));
    invalid = enabled; invalid.cooldown_ms = 1000;
    assert(!fm10k_pfc_wd_policy_valid(&invalid));
    invalid = enabled; invalid.recovery_ms = 1001;
    assert(!fm10k_pfc_wd_policy_valid(&invalid));
    puts("PFC watchdog timing, observation gaps, maintenance, recovery failures and cooldown passed");
    return 0;
}
