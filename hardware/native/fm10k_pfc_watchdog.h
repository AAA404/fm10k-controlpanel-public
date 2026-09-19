#ifndef FM10K_PFC_WATCHDOG_H
#define FM10K_PFC_WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>
#include "netlab/pfc_watchdog.h"

/* Conservative port-progress watchdog: FM10000 has no per-TC TX counter.
 * The SDK owner supplies uncached observations and owns every recovery write. */
#define FM10K_PFC_WD_POLL_MS 100U
#define FM10K_PFC_WD_MAX_GAP_MS 300U

typedef struct {
    bool valid;
    bool eligible; /* link Up, unchanged physical port, configured TC3 PFC */
    bool paused;
    bool queued;
    uint64_t tx_data_packets; /* L2 unicast/multicast/broadcast; excludes PAUSE */
} fm10k_pfc_wd_sample;

typedef enum {
    FM10K_PFC_WD_NONE,
    FM10K_PFC_WD_RELEASE,
    FM10K_PFC_WD_RESTORE
} fm10k_pfc_wd_action;

typedef struct {
    fm10k_pfc_wd_policy policy;
    bool observing;
    bool active;
    bool restore_failed;
    bool cooldown_needs_clock;
    uint64_t last_ms;
    uint64_t suspect_ms;
    uint64_t tx_data_packets;
    uint64_t restore_at_ms;
    uint64_t released_at_ms;
    uint64_t cooldown_until_ms;
    uint64_t detections;
    uint64_t recoveries;
    uint64_t failures;
    uint64_t gaps;
} fm10k_pfc_wd_state;

/* Configuration changes require a restored mask; active leases cannot vanish. */
bool fm10k_pfc_wd_configure(fm10k_pfc_wd_state *state, const fm10k_pfc_wd_policy *policy);
void fm10k_pfc_wd_gap(fm10k_pfc_wd_state *state);
fm10k_pfc_wd_action fm10k_pfc_wd_observe(fm10k_pfc_wd_state *state,
                                       const fm10k_pfc_wd_sample *sample,
                                       uint64_t now_ms, bool paused);
/* Record a lease BEFORE attempting the SDK write, including partial failures. */
void fm10k_pfc_wd_releasing(fm10k_pfc_wd_state *state, uint64_t now_ms);
void fm10k_pfc_wd_restored(fm10k_pfc_wd_state *state, uint64_t now_ms, bool success);

#endif
