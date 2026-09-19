#ifndef NETLAB_PFC_WATCHDOG_H
#define NETLAB_PFC_WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>

/* SDK-free policy shared by configd/l2d, the owner and the state machine. */
typedef struct {
    uint32_t detect_ms; /* zero disables automatic recovery */
    uint32_t recovery_ms;
    uint32_t cooldown_ms;
} fm10k_pfc_wd_policy;

static inline fm10k_pfc_wd_policy fm10k_pfc_wd_default_policy(void) {
    return (fm10k_pfc_wd_policy){0, 100, 30000};
}

static inline bool fm10k_pfc_wd_policy_valid(const fm10k_pfc_wd_policy *p) {
    return p && (!p->detect_ms || (p->detect_ms >= 1000U && p->detect_ms <= 60000U)) &&
        p->recovery_ms >= 100U && p->recovery_ms <= 1000U &&
        p->cooldown_ms >= 10000U && p->cooldown_ms <= 600000U &&
        (!p->detect_ms || p->cooldown_ms >= p->detect_ms);
}

static inline bool fm10k_pfc_wd_policy_equal(const fm10k_pfc_wd_policy *a,
                                           const fm10k_pfc_wd_policy *b) {
    return a && b && a->detect_ms == b->detect_ms &&
        a->recovery_ms == b->recovery_ms && a->cooldown_ms == b->cooldown_ms;
}

typedef enum {
    HAL_PFC_WD_DISABLED,
    HAL_PFC_WD_OBSERVING,
    HAL_PFC_WD_SUSPECT,
    HAL_PFC_WD_RECOVERING,
    HAL_PFC_WD_COOLDOWN,
    HAL_PFC_WD_SUSPENDED,
    HAL_PFC_WD_RESTORE_FAILED
} hal_pfc_wd_phase;

typedef struct {
    fm10k_pfc_wd_policy policy;
    bool supported;
    hal_pfc_wd_phase phase;
    int sample_status;
    int saved_rx_mask; /* only meaningful while a recovery lease is active */
    uint64_t sampled_ms, detections, restorations, failures, gaps;
} hal_pfc_wd_status;

#endif
