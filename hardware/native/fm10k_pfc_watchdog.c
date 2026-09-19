#include "fm10k_pfc_watchdog.h"

#include <limits.h>

static uint64_t deadline(uint64_t now, uint32_t interval) {
    return UINT64_MAX - now < interval ? UINT64_MAX : now + interval;
}

void fm10k_pfc_wd_gap(fm10k_pfc_wd_state *state) {
    if (!state) return;
    state->observing = false;
    state->suspect_ms = 0;
    state->last_ms = 0;
}

bool fm10k_pfc_wd_configure(fm10k_pfc_wd_state *state, const fm10k_pfc_wd_policy *policy) {
    if (!state || state->active || !fm10k_pfc_wd_policy_valid(policy)) return false;
    state->policy = *policy;
    state->restore_failed = false;
    fm10k_pfc_wd_gap(state);
    return true;
}

fm10k_pfc_wd_action fm10k_pfc_wd_observe(fm10k_pfc_wd_state *state,
                                       const fm10k_pfc_wd_sample *sample,
                                       uint64_t now_ms, bool paused) {
    if (!state) return FM10K_PFC_WD_NONE;
    if (state->active) {
        /* Restoration must remain possible during maintenance, link loss,
         * disabled policy, invalid samples and monotonic-clock failures. */
        return state->restore_failed || paused || !now_ms || now_ms < state->released_at_ms || !sample ||
            !sample->valid || !sample->eligible || now_ms >= state->restore_at_ms ?
            FM10K_PFC_WD_RESTORE : FM10K_PFC_WD_NONE;
    }
    if (!state->policy.detect_ms || !now_ms || paused || !sample ||
        !sample->valid || !sample->eligible) {
        fm10k_pfc_wd_gap(state);
        return FM10K_PFC_WD_NONE;
    }
    if (state->cooldown_needs_clock) {
        state->cooldown_until_ms = deadline(now_ms, state->policy.cooldown_ms);
        state->cooldown_needs_clock = false;
    }
    bool continuous = state->last_ms && now_ms > state->last_ms &&
        now_ms - state->last_ms <= FM10K_PFC_WD_MAX_GAP_MS;
    if (state->last_ms && !continuous) state->gaps++;
    bool suspect = sample->paused && sample->queued && now_ms >= state->cooldown_until_ms;
    if (!suspect || !continuous || !state->observing ||
        sample->tx_data_packets != state->tx_data_packets) {
        state->observing = suspect;
        state->suspect_ms = suspect ? now_ms : 0;
    }
    state->last_ms = now_ms;
    state->tx_data_packets = sample->tx_data_packets;
    if (state->observing && now_ms - state->suspect_ms >= state->policy.detect_ms)
        return FM10K_PFC_WD_RELEASE;
    return FM10K_PFC_WD_NONE;
}

void fm10k_pfc_wd_releasing(fm10k_pfc_wd_state *state, uint64_t now_ms) {
    if (!state || state->active) return;
    state->active = true;
    state->restore_failed = false;
    state->released_at_ms = now_ms;
    state->restore_at_ms = deadline(now_ms, state->policy.recovery_ms);
    state->detections++;
    fm10k_pfc_wd_gap(state);
}

void fm10k_pfc_wd_restored(fm10k_pfc_wd_state *state, uint64_t now_ms, bool success) {
    if (!state || !state->active) return;
    if (!success) {
        state->restore_failed = true;
        state->failures++;
        return;
    }
    state->active = false;
    state->restore_failed = false;
    state->recoveries++;
    state->cooldown_until_ms = deadline(now_ms, state->policy.cooldown_ms);
    state->cooldown_needs_clock = !now_ms;
    fm10k_pfc_wd_gap(state);
}
