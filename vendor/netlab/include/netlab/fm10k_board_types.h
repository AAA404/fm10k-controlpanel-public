#ifndef NETLAB_FM10K_BOARD_TYPES_H
#define NETLAB_FM10K_BOARD_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* SDK-free configuration contract shared by the planner and board HAL. */
#define FM10K_GROUP_COUNT 6
#define FM10K_FAN_IMAGE_BYTES 35
/* Recognition is not authorization to initialize the SDK or write hardware. */
static inline bool nl_fm10k_profile_known(const char *profile) {
    return profile && (!strcmp(profile, "sil001-hw4-b0") ||
                       !strcmp(profile, "sil001-hw5-a11"));
}
typedef struct {
    int idle_c, load_c, critical_c, idle_pwm, load_pwm, hysteresis_c;
    int response_milliseconds;
} fm10k_fan_curve;
typedef struct { uint8_t values[FM10K_FAN_IMAGE_BYTES]; } fm10k_fan_image;
typedef struct {
    bool valid, curve_valid;
    fm10k_fan_curve curve;
    fm10k_fan_image image;
} fm10k_fan_snapshot;
typedef struct {
    int epl, mode; /* 0: split; 40/100: four-lane aggregate */
    int lane_gbps[4];
    uint8_t enabled; /* logical slot bitmap; aggregate uses only bit zero */
} fm10k_group;
#define NL_FM10K_CONFIG_SCHEMA 1U
typedef struct {
    uint32_t schema, bytes, group_valid_mask;
    fm10k_group groups[FM10K_GROUP_COUNT];
    fm10k_fan_snapshot fan;
} nl_fm10k_config_snapshot;

static inline int nl_fm10k_group_index(int epl) {
    return epl >= 0 && epl <= 2 ? epl : epl >= 5 && epl <= 7 ? epl - 2 : -1;
}
static inline bool nl_fm10k_group_valid(const fm10k_group *g) {
    if (!g || nl_fm10k_group_index(g->epl) < 0 ||
        (g->mode != 0 && g->mode != 40 && g->mode != 100) ||
        g->enabled > 15 || (g->mode && g->enabled > 1)) return false;
    for (int i = 0; i < 4; ++i)
        if (g->lane_gbps[i] != 10 && g->lane_gbps[i] != 25) return false;
    return true;
}
static inline bool nl_fm10k_group_modes_equal(const fm10k_group *a, const fm10k_group *b) {
    if (!nl_fm10k_group_valid(a) || !nl_fm10k_group_valid(b) ||
        a->epl != b->epl || a->mode != b->mode) return false;
    for (int lane = 0; !a->mode && lane < 4; ++lane)
        if (a->lane_gbps[lane] != b->lane_gbps[lane]) return false;
    return true;
}
static inline bool nl_fm10k_group_equal(const fm10k_group *a, const fm10k_group *b) {
    return nl_fm10k_group_modes_equal(a, b) && a->enabled == b->enabled;
}
static inline bool nl_fm10k_fan_valid(const fm10k_fan_curve *f) {
    if (!f || f->idle_c < 10 || f->idle_c > 80 || f->load_c < 20 ||
        f->load_c > 90 || f->critical_c < 30 || f->critical_c > 100 ||
        f->idle_c + 10 > f->load_c || f->load_c >= f->critical_c ||
        f->idle_pwm < 25 || f->idle_pwm > 100 || f->load_pwm < f->idle_pwm ||
        f->load_pwm > 100 || f->hysteresis_c < 1 || f->hysteresis_c > 15) return false;
    int r = f->response_milliseconds;
    return r == 5450 || r == 10900 || r == 21600 || r == 43700;
}
static inline bool nl_fm10k_fan_equal(const fm10k_fan_curve *a, const fm10k_fan_curve *b) {
    return a && b && a->idle_c == b->idle_c && a->load_c == b->load_c &&
        a->critical_c == b->critical_c && a->idle_pwm == b->idle_pwm &&
        a->load_pwm == b->load_pwm && a->hysteresis_c == b->hysteresis_c &&
        a->response_milliseconds == b->response_milliseconds;
}

#endif
