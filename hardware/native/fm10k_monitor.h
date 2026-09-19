#ifndef FM10K_PANEL_MONITOR_H
#define FM10K_PANEL_MONITOR_H

#include "fm10k_board.h"

typedef struct {
    bool available, valid;
    double value, sampled_at;
    uint64_t sampled_ms;
} fm10k_measurement;
typedef struct {
    fm10k_bus *bus;
    char profile[32];
    bool native_ready, native_bound;
    uint64_t native_generation, native_commit;
    fm10k_fan_state fan;
    fm10k_fan_sample fan_readback;
    fm10k_measurement temperatures[3], pwm, tach, tx[2];
    fm10k_measurement tx_cdr[2], rx_cdr[2], rx_enable[2], rx_status[2];
    fm10k_measurement rx_power[2][12];
    bool rx_power_not_ready[2];
    uint8_t pwm_mode;
    uint64_t fan_due, obt_due[2], identity_due[2];
    unsigned identity_offset[2];
    uint8_t identity_partial[2][128];
    uint8_t identity[2][128];
    bool identity_valid[2], identity_fresh[2];
    uint64_t identity_sample_ms[2];
    double identity_at[2];
    uint32_t tach_factor;
    uint64_t samples, io_errors;
} fm10k_monitor;

/* No I/O during initialization. Polling and configuration run only on the
 * SDK owner, independently of HTTP requests. A caller must synchronize a
 * copied snapshot before exposing it to other threads. */
void fm10k_monitor_init(fm10k_monitor *, fm10k_bus *);
int fm10k_monitor_step(fm10k_monitor *, uint64_t monotonic_ms, double unix_seconds);
int fm10k_monitor_curve(fm10k_monitor *, const fm10k_fan_curve *);
int fm10k_monitor_fan_capture(fm10k_monitor *, fm10k_fan_snapshot *);
int fm10k_monitor_fan_restore(fm10k_monitor *, const fm10k_fan_snapshot *, uint64_t now);
int fm10k_monitor_fan_apply(fm10k_monitor *, const fm10k_fan_curve *,
                            const fm10k_fan_snapshot *, uint64_t now);
int fm10k_monitor_manual(fm10k_monitor *, int pwm, int seconds,
                         uint64_t monotonic_ms);
int fm10k_monitor_shutdown(fm10k_monitor *);
int fm10k_monitor_format(const fm10k_monitor *, uint64_t monotonic_ms,
                         double unix_seconds, char *out, size_t size);

#endif
