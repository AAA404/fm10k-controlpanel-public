#ifndef NETLAB_HAL_FM10K_H
#define NETLAB_HAL_FM10K_H

#include "fm10k_board_types.h"

/* Ordered, typed values used by the pinned per-LAG adapter. Kept in the
 * transaction image so recreating an SDK handle preserves its port policy. */
#define NL_FM10K_LAG_ATTRIBUTES 22
typedef struct {
    bool valid;
    uint32_t values[NL_FM10K_LAG_ATTRIBUTES];
} fm10k_lag_attributes;

/* SDK-owner operations. No RPC, shell, or board initialization occurs here. */
bool fm10k_native_aux_port(int sw, int port);
int hal_fm10k_fan_capture(int sw, fm10k_fan_snapshot *);
int hal_fm10k_fan_apply(int sw, const fm10k_fan_curve *, const fm10k_fan_snapshot *);
int hal_fm10k_fan_restore(int sw, const fm10k_fan_snapshot *);
int hal_fm10k_fan_verify(int sw, const fm10k_fan_curve *);
bool fm10k_fan_snapshot_equal(const fm10k_fan_snapshot *, const fm10k_fan_snapshot *);
int hal_fm10k_group_capture(int sw, int epl, fm10k_group *);
int hal_fm10k_group_apply(int sw, const fm10k_group *, const fm10k_group *, uint64_t tx_id);
int hal_fm10k_group_restore(int sw, const fm10k_group *, uint64_t tx_id);
int hal_fm10k_group_verify(int sw, const fm10k_group *);

#endif
