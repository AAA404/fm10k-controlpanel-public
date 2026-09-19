#ifndef FM10K_EYE_SCAN_H
#define FM10K_EYE_SCAN_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FM10K_EYE_X_MAX 129
#define FM10K_EYE_Y_MAX 256
/* All callbacks run on the existing SDK owner. No raw command is exposed. */
typedef struct {
    void *context;
    int (*serdes)(void *, unsigned irq, unsigned data, uint32_t *);
    int (*master)(void *, unsigned data, uint32_t *, bool wait);
    int (*read)(void *, unsigned reg, uint32_t *);
    int (*write)(void *, unsigned reg, uint32_t);
    int (*compare)(void *, uint32_t *);
    int (*signal)(void *);
    /* Optional setup: 1 yields, 0 is ready, negative fails. Restore runs even
     * after partial setup or cancellation. */
    int (*prepare)(void *);
    /* Restore also follows sampling without signal preparation.
     * -2 blocks dependent DFE resume until the SDK is recovered. */
    int (*restore)(void *);
    uint64_t (*now)(void *);
} fm10k_eye_io;
typedef struct {
    unsigned sbus, phase_multiplier, firmware, master_firmware, protocol;
    unsigned compare_mode;
    bool internal_loopback, temporary_master;
    int port, epl, lane, speed_mbps;
} fm10k_eye_target;
typedef struct {
    fm10k_eye_io io;
    fm10k_eye_target target;
    char id[33], error[96], failure_reason[96];
    unsigned x_resolution, y_step, x_points, y_points, x_step, dwell_bits;
    unsigned columns_done, row, read_index;
    int phase_center;
    uint32_t errors[FM10K_EYE_X_MAX][FM10K_EYE_Y_MAX];
    uint64_t started_ms, updated_ms, column_ms;
    double started_at;
    enum { EYE_IDLE, EYE_PREPARING, EYE_RUNNING, EYE_COMPLETE, EYE_CANCELLED, EYE_FAILED } state;
    bool paused, prepared, preparation_done, configured, priming, column_pending, cancel_requested, restored, restore_failed;
} fm10k_eye_scan;

bool fm10k_eye_active(const fm10k_eye_scan *);
int fm10k_eye_start(fm10k_eye_scan *, const fm10k_eye_io *, const fm10k_eye_target *,
                    const char *id, unsigned x_resolution, unsigned y_step,
                    unsigned dwell_bits, double wall);
void fm10k_eye_tick(fm10k_eye_scan *);
void fm10k_eye_cancel(fm10k_eye_scan *, const char *reason);
int fm10k_eye_format(const fm10k_eye_scan *, unsigned column, char *, size_t);
uint32_t fm10k_eye_decode_count(uint16_t encoded);
#endif
