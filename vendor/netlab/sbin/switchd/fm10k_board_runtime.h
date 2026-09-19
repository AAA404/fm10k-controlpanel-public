#ifndef NETLAB_FM10K_BOARD_RUNTIME_H
#define NETLAB_FM10K_BOARD_RUNTIME_H
#include "fm10k_board.h"

bool fm10k_native_profile(void);
bool fm10k_native_bound(void);
bool fm10k_native_ready(void);
uint64_t fm10k_native_generation(void);
int fm10k_native_mark_ready(void);
int fm10k_native_bind(uint64_t generation, uint64_t tx);
int fm10k_native_bootstrap_closed(int sw);
int fm10k_native_poll(int sw);
int fm10k_native_curve(const fm10k_fan_curve *);
int fm10k_native_manual(int pwm, int seconds, double *expires_at);
int fm10k_native_shutdown(void);
int fm10k_native_cache(char *out, size_t size);
int fm10k_native_config_snapshot(int sw, nl_fm10k_config_snapshot *);
#endif
