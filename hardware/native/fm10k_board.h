#ifndef FM10K_PANEL_BOARD_H
#define FM10K_PANEL_BOARD_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* The common data types have no SDK or libyang dependency. */
#include "../../vendor/netlab/include/netlab/fm10k_board_types.h"

/* All calls run on switchd's SDK owner thread. Each mux transaction reserves
 * the shared bus through enter/leave; SDK mode callbacks run outside that
 * reservation. No HTTP-process I2C, shell command or reset hook. */
enum { FM10K_OK = 0, FM10K_IO = -1, FM10K_INVALID = -2,
       FM10K_ROLLBACK_FAILED = -3 };
typedef struct {
    void *context;
    int (*read)(void *, uint8_t address, int reg, uint8_t *out, size_t n);
    int (*write)(void *, uint8_t address, int reg, const uint8_t *data, size_t n);
    /* Optional as a pair for an already-reserved fixture. A failed enter
     * must release any partially acquired locks itself. */
    int (*enter)(void *);
    int (*leave)(void *);
    void (*delay_ms)(void *, unsigned milliseconds);
} fm10k_bus;
enum { FM10K_TACH_NONE = 0, FM10K_TACH_CPLD = 1, FM10K_TACH_LM96163 = 2 };
typedef struct {
    bool core_valid, pwm_valid, tach_read, tach_valid;
    double core_c;
    uint8_t pwm, pwm_mode;
    uint16_t tach_count;
    bool lm_tach_read, cpld_tach_read, tach_configuration_valid;
    bool tach_shadow_matches;
    uint8_t tach_configuration, tach_source;
    uint16_t lm_tach_count, cpld_tach_count;
} fm10k_fan_sample;
typedef struct {
    bool temperature_valid, tx_valid;
    double temperature_c;
    uint16_t tx_enabled;
    bool diagnostic_valid;
    uint8_t tx_cdr, rx_cdr;
    uint16_t rx_enabled, rx_status_raw;
} fm10k_obt_sample;
typedef struct {
    bool valid, not_ready;
    uint16_t raw[12]; /* CXP channel 0..11, 0.1 microwatt per count. */
} fm10k_obt_power_sample;
enum { FM10K_OBT_SETUP_REGISTERS = 22 };
typedef struct {
    uint8_t before[FM10K_OBT_SETUP_REGISTERS], after[FM10K_OBT_SETUP_REGISTERS];
    unsigned changed;
    bool captured, verified, restored;
    int failed_address, failed_register;
} fm10k_obt_setup_report;
typedef struct { uint8_t celsius, pwm; } fm10k_lut_point;
typedef struct {
    void *context;
    int (*capture)(void *, int epl, fm10k_group *);
    int (*quiesce)(void *, int epl, bool paused);
    int (*disable)(void *, int epl);
    int (*set_modes)(void *, const fm10k_group *);
    int (*restore_ports)(void *, const fm10k_group *);
    int (*verify)(void *, const fm10k_group *);
    void (*degraded)(void *, int epl);
} fm10k_group_ops;
typedef struct {
    fm10k_fan_curve curve;
    uint64_t manual_deadline_ms;
    bool curve_valid;
    bool manual;
    bool failsafe;
} fm10k_fan_state;

int fm10k_group_index(int epl);
int fm10k_group_validate(const fm10k_group *);
bool fm10k_group_equal(const fm10k_group *, const fm10k_group *);
uint16_t fm10k_group_tx_mask(const fm10k_group *);
int fm10k_tx_read(fm10k_bus *, int mpo, uint16_t *);
int fm10k_tx_update(fm10k_bus *, int mpo, uint16_t lanes, uint16_t enabled);
int fm10k_fan_read(fm10k_bus *, fm10k_fan_sample *);
int fm10k_obt_read(fm10k_bus *, int mpo, fm10k_obt_sample *);
/* Fixed FCI RX address 0x40, page 1, bytes 206..229. Restores page and mux
 * on every exit. The caller must first qualify the module's page-0 identity. */
int fm10k_obt_rx_power_read(fm10k_bus *, int mpo, fm10k_obt_power_sample *);
/* Cold bootstrap only: TX must already be closed for all 12 module lanes.
 * Uses the pinned SDK's optical defaults, including A11 TX/RX CDR 1/0.
 * No page selection, laser enable, other-MPO mutation or runtime reset. */
int fm10k_obt_setup(fm10k_bus *, int mpo, fm10k_obt_setup_report *);
/* One <=12-byte page-zero identity slice; saves/restores both page and mux. */
int fm10k_obt_identity_read(fm10k_bus *, int mpo, unsigned offset,
                           uint8_t *out, size_t n);
int fm10k_fan_validate(const fm10k_fan_curve *);
int fm10k_fan_lut(const fm10k_fan_curve *, fm10k_lut_point out[12]);
int fm10k_fan_apply(fm10k_bus *, const fm10k_fan_curve *);
int fm10k_fan_configure(fm10k_bus *, const fm10k_fan_curve *, bool full_speed);
int fm10k_fan_image_read(fm10k_bus *, fm10k_fan_image *);
bool fm10k_fan_image_matches(const fm10k_fan_image *, const fm10k_fan_curve *);
int fm10k_fan_image_restore(fm10k_bus *, const fm10k_fan_image *,
                             const fm10k_fan_curve *, bool full_speed);
bool fm10k_fan_curve_equal(const fm10k_fan_curve *, const fm10k_fan_curve *);
bool fm10k_fan_snapshot_equal(const fm10k_fan_snapshot *, const fm10k_fan_snapshot *);
int fm10k_fan_bootstrap(fm10k_bus *);
int fm10k_fan_full(fm10k_bus *);
int fm10k_fan_manual(fm10k_bus *, fm10k_fan_state *, int pwm, int seconds,
                     uint64_t now_ms, bool temperature_valid, double core_c);
int fm10k_fan_tick(fm10k_bus *, fm10k_fan_state *, uint64_t now_ms,
                   bool temperature_valid, double core_c);
int fm10k_tach_rpm(uint16_t count, uint32_t factor);
int fm10k_group_apply(fm10k_bus *, const fm10k_group_ops *, const fm10k_group *);
#endif
