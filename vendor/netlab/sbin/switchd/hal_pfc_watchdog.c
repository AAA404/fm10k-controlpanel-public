#include "hal_pfc_watchdog.h"
#include "fm10k_pfc_watchdog.h"
#include "fm10k_board_runtime.h"
#include "netlab/hal.h"
#include "netlab/log.h"
#include "netlab/port_scope.h"
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_regs.h>
#include <api/fm_api_stats.h>
#include <api/internal/fm_api_common_int.h>
#include <api/internal/fm_api_portmask.h>
#include <string.h>
#include <time.h>

typedef struct {
    fm10k_pfc_wd_state core;
    bool initialized;
    int physical, saved_physical, saved_mask, sample_status;
    uint64_t sampled_ms;
    uint64_t rx_pfc_packets, rx_pause_packets;
    bool counter_baseline;
    hal_pfc_wd_phase phase;
} watchdog_port;

static watchdog_port ports[25];
static uint64_t last_poll_ms;

static uint64_t clock_ms(void) {
    struct timespec ts;
    return clock_gettime(CLOCK_MONOTONIC, &ts) ? 0 :
        (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

static watchdog_port *port_state(int port) {
    if (port < 1 || port > 24) return NULL;
    watchdog_port *p = &ports[port];
    if (!p->initialized) {
        p->core.policy = fm10k_pfc_wd_default_policy();
        p->physical = p->saved_physical = p->saved_mask = -1;
        p->sample_status = FM_ERR_INVALID_STATE;
        p->initialized = true;
    }
    return p;
}

int hal_pfc_watchdog_rx_mask(int sw, int port, int *physical, int *mask) {
    if (!physical || !mask || sw != 0 || port < 1 || port > 24)
        return FM_ERR_INVALID_ARGUMENT;
    *physical = *mask = -1;
    fm_portmask dest = {{0}};
    int st = fmGetLogicalPortAttribute(sw, port, FM_LPORT_DEST_MASK, &dest);
    if (st) return st;
    for (int i = 0; i < FM_PORTMASK_NUM_BITS; ++i) if (FM_PORTMASK_GET_BIT(&dest, i)) {
        if (*physical >= 0 || i >= 48) return FM_ERR_INVALID_STATE;
        *physical = i;
    }
    if (*physical < 0) return FM_ERR_INVALID_STATE;
    fm_uint32 actual = 0;
    st = fmReadUncachedUINT32(sw, 0xE60800U + (fm_uint)*physical, &actual);
    if (!st) *mask = (int)(actual & 0xffU);
    return st;
}

static int write_mask(int sw, int port, int physical, int mask) {
    int actual_physical = -1, actual = -1;
    int st = hal_pfc_watchdog_rx_mask(sw, port, &actual_physical, &actual);
    if (st || actual_physical != physical) return st ? st : FM_ERR_INVALID_STATE;
    fm_uint32 value = (fm_uint32)mask, cached = UINT32_MAX;
    int write_st = fmSetPortAttribute(sw, port, FM_PORT_RX_CLASS_PAUSE, &value);
    st = hal_pfc_watchdog_rx_mask(sw, port, &actual_physical, &actual);
    int cache_st = fmGetPortAttribute(sw, port, FM_PORT_RX_CLASS_PAUSE, &cached);
    /* A nonzero SDK result may follow a partial write. Only exact hardware
     * AND cache readback releases our obligation to restore the saved mask. */
    if (!st && !cache_st && actual_physical == physical && actual == mask && cached == value)
        return FM_OK;
    return st ? st : cache_st ? cache_st : write_st ? write_st : NL_ERR_READBACK_MISMATCH;
}

static int restore(int sw, int port, watchdog_port *p, uint64_t now_ms) {
    if (!p->core.active) return 0;
    bool was_failed = p->core.restore_failed;
    int st = write_mask(sw, port, p->saved_physical, p->saved_mask);
    fm10k_pfc_wd_restored(&p->core, now_ms, !st);
    p->phase = st ? HAL_PFC_WD_RESTORE_FAILED : HAL_PFC_WD_COOLDOWN;
    if (st && !was_failed)
        NL_LOG_ERR("PFC watchdog port=%d cannot restore rx mask=0x%02x status=%d", port, p->saved_mask, st);
    if (!st)
        NL_LOG_WARN("PFC watchdog port=%d restored rx mask=0x%02x; this does not establish losslessness", port, p->saved_mask);
    return st;
}

int hal_pfc_watchdog_quiesce(int sw) {
    int failed = 0;
    uint64_t now_ms = clock_ms();
    for (int port = 1; port <= 24; ++port) {
        watchdog_port *p = port_state(port);
        if (restore(sw, port, p, now_ms)) failed = NL_ERR_HW_STATE_OUT_OF_SYNC;
        fm10k_pfc_wd_gap(&p->core);
        p->counter_baseline = false;
        if (!p->core.active) p->phase = p->core.policy.detect_ms ? HAL_PFC_WD_SUSPENDED : HAL_PFC_WD_DISABLED;
    }
    return failed;
}

int hal_pfc_watchdog_configure(int sw, int port, const fm10k_pfc_wd_policy *policy) {
    watchdog_port *p = port_state(port);
    if (!p || !fm10k_pfc_wd_policy_valid(policy)) return FM_ERR_INVALID_ARGUMENT;
    if (!fm10k_native_profile() || sw != 0)
        return policy->detect_ms ? NL_ERR_CAPABILITY_INSUFFICIENT : 0;
    if (p->core.active) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    if (policy->detect_ms) {
        int physical = -1, mask = -1;
        fm_uint32 pause_class = UINT32_MAX;
        int st = hal_pfc_watchdog_rx_mask(sw, port, &physical, &mask);
        if (st) return st;
        st = fmGetPortQOS(sw, port, FM_QOS_TC_PC_MAP, 3, &pause_class);
        if (st || mask != 8 || pause_class != 3) return st ? st : FM_ERR_INVALID_STATE;
        p->physical = physical;
    }
    if (!fm10k_pfc_wd_configure(&p->core, policy)) return FM_ERR_INVALID_STATE;
    p->counter_baseline = false;
    p->phase = policy->detect_ms ? HAL_PFC_WD_SUSPENDED : HAL_PFC_WD_DISABLED;
    return 0;
}

bool hal_pfc_watchdog_enabled(void) {
    for (int port = 1; port <= 24; ++port)
        if (ports[port].core.policy.detect_ms || ports[port].core.active) return true;
    return false;
}

void hal_pfc_watchdog_get(int sw, int port, hal_pfc_wd_status *status) {
    if (!status) return;
    memset(status, 0, sizeof(*status));
    status->policy = fm10k_pfc_wd_default_policy();
    status->sample_status = FM_ERR_INVALID_STATE;
    status->saved_rx_mask = -1;
    watchdog_port *p = port_state(port);
    if (!p || sw != 0 || !fm10k_native_profile()) return;
    status->supported = true;
    status->policy = p->core.policy;
    status->phase = p->phase;
    status->sample_status = p->sample_status;
    status->sampled_ms = p->sampled_ms;
    status->saved_rx_mask = p->core.active ? p->saved_mask : -1;
    status->detections = p->core.detections;
    status->restorations = p->core.recoveries;
    status->failures = p->core.failures;
    status->gaps = p->core.gaps;
}

static int sample_port(int sw, int port, watchdog_port *p, fm10k_pfc_wd_sample *sample) {
    int physical = -1, mask = -1;
    int st = hal_pfc_watchdog_rx_mask(sw, port, &physical, &mask);
    if (st) return st;
    if (physical != p->physical) {
        fm10k_pfc_wd_gap(&p->core);
        p->physical = physical;
    }
    fm_int mode = FM_PORT_MODE_ADMIN_DOWN, state = FM_PORT_STATE_DOWN;
    fm_int info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
    st = fmGetPortState(sw, port, &mode, &state, info);
    if (st) return st;
    fm_uint32 pause_class = UINT32_MAX, usage = 0;
    st = fmGetPortQOS(sw, port, FM_QOS_TC_PC_MAP, 3, &pause_class);
    if (st) return st;
    sample->eligible = mode == FM_PORT_MODE_UP && state == FM_PORT_STATE_UP && pause_class == 3 &&
        (p->core.active ? physical == p->saved_physical && mask == (p->saved_mask & ~8) : mask == 8);
    if (!sample->eligible) { p->counter_baseline = false; sample->valid = true; return 0; }
    st = fmGetPortQOS(sw, port, FM_QOS_TX_TC_USAGE, 3, &usage);
    if (st) return st;
    fm_uint64 quanta[2] = {0};
    st = fmReadUncachedUINT64Mult(sw, 0xE61400U + 4U * (fm_uint)physical, 2, quanta);
    if (st) return st;
    sample->queued = usage > 0;
    sample->paused = ((quanta[0] >> 48) & 0xffffU) != 0;
    if (sample->queued && sample->paused && !p->core.active) {
        fm_portCounters counters;
        memset(&counters, 0, sizeof(counters));
        st = fmGetPortCounters(sw, port, &counters);
        if (st) return st;
        sample->tx_data_packets = counters.cntTxUcstPkts + counters.cntTxMcstPkts + counters.cntTxBcstPkts;
        /* The hardware timer can also reflect ordinary 802.3 PAUSE. Require
         * fresh PFC frames and no ordinary PAUSE growth throughout detection. */
        sample->eligible = p->counter_baseline && counters.cntRxCBPausePkts > p->rx_pfc_packets &&
            counters.cntRxPausePkts == p->rx_pause_packets;
        p->rx_pfc_packets = counters.cntRxCBPausePkts;
        p->rx_pause_packets = counters.cntRxPausePkts;
        p->counter_baseline = true;
    } else {
        p->counter_baseline = false;
    }
    sample->valid = true;
    return 0;
}

void hal_pfc_watchdog_poll(int sw, uint64_t now_ms) {
    if (sw != 0 || !fm10k_native_profile() || !hal_pfc_watchdog_enabled()) return;
    if (now_ms && now_ms >= last_poll_ms && now_ms - last_poll_ms < FM10K_PFC_WD_POLL_MS) return;
    last_poll_ms = now_ms;
    nl_port_scope_status scope = nl_port_scope_get();
    if (!now_ms || !fm10k_native_ready() || !nl_port_scope_ready() || scope.tx_id || scope.mask || scope.degraded) {
        (void)hal_pfc_watchdog_quiesce(sw);
        return;
    }
    for (int port = 1; port <= 24; ++port) {
        watchdog_port *p = port_state(port);
        if (!p->core.policy.detect_ms && !p->core.active) continue;
        if (p->core.active && (p->core.restore_failed || now_ms >= p->core.restore_at_ms || now_ms < p->core.released_at_ms)) {
            (void)restore(sw, port, p, clock_ms());
            continue;
        }
        bool allowed = nl_port_scope_enter(port);
        fm10k_pfc_wd_sample sample = {0};
        p->sample_status = allowed ? sample_port(sw, port, p, &sample) : NL_ERR_COMMIT_LOCKED;
        uint64_t observed_ms = clock_ms();
        p->sampled_ms = observed_ms;
        fm10k_pfc_wd_action action = fm10k_pfc_wd_observe(&p->core, &sample, observed_ms, !allowed);
        if (action == FM10K_PFC_WD_RESTORE) {
            (void)restore(sw, port, p, observed_ms);
        } else if (action == FM10K_PFC_WD_RELEASE) {
            int actual = -1, physical = -1;
            int st = hal_pfc_watchdog_rx_mask(sw, port, &physical, &actual);
            uint64_t release_ms = clock_ms();
            if (!st && physical == p->physical && actual == 8 && observed_ms &&
                release_ms >= observed_ms && release_ms - observed_ms <= FM10K_PFC_WD_MAX_GAP_MS) {
                p->saved_mask = actual;
                p->saved_physical = physical;
                fm10k_pfc_wd_releasing(&p->core, release_ms);
                st = write_mask(sw, port, physical, actual & ~8);
                p->phase = HAL_PFC_WD_RECOVERING;
                NL_LOG_WARN("PFC watchdog port=%d releasing TC3 for %u ms after %u ms stalled; packets may be lost", port, p->core.policy.recovery_ms, p->core.policy.detect_ms);
                if (st) {
                    p->core.failures++;
                    (void)restore(sw, port, p, clock_ms());
                }
            } else {
                p->sample_status = st ? st : FM_ERR_INVALID_STATE;
                fm10k_pfc_wd_gap(&p->core);
                p->phase = HAL_PFC_WD_SUSPENDED;
            }
        } else if (!p->core.active) {
            p->phase = !sample.valid || !sample.eligible ? HAL_PFC_WD_SUSPENDED :
                observed_ms < p->core.cooldown_until_ms ? HAL_PFC_WD_COOLDOWN :
                p->core.observing ? HAL_PFC_WD_SUSPECT : HAL_PFC_WD_OBSERVING;
        }
        if (allowed) nl_port_scope_leave(port);
    }
}
