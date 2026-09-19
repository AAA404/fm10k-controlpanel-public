#ifndef NETLAB_L2_FM10K_H
#define NETLAB_L2_FM10K_H

#include "netlab/yang_config.h"
#include "netlab/fm10k_board_types.h"
#include <stddef.h>

#define L2_FM10K_ROOT "/netlab:netlab-config/chassis/fm10k-panel"
typedef struct {
    bool managed;
    uint32_t changed_mask;
    fm10k_group before[FM10K_GROUP_COUNT], target[FM10K_GROUP_COUNT];
} l2_fm10k_groups;
int l2_fm10k_read_groups(nl_yang_session *, fm10k_group out[FM10K_GROUP_COUNT], char *, size_t);
int l2_fm10k_groups_prepare(nl_yang_session *, nl_yang_session *, bool, l2_fm10k_groups *, char *, size_t);
bool l2_fm10k_port_active(const l2_fm10k_groups *, int port);
bool l2_fm10k_port_changed(const l2_fm10k_groups *, int port);
/* 0: close before dependency removal; 1: change modes; 2: enable after L2 restoration. */
int l2_fm10k_groups_emit(const l2_fm10k_groups *, int phase, char *, size_t, int *, bool *);
int l2_fm10k_scope_plan(nl_yang_session *, nl_yang_session *, char *, size_t, int *, char *, size_t);
int l2_fm10k_read_fan(nl_yang_session *, fm10k_fan_curve *);
int l2_fm10k_read_hardware(nl_fm10k_config_snapshot *, char *err, size_t err_size);
int l2_fm10k_fan_plan(nl_yang_session *active, nl_yang_session *candidate,
                       bool require_hw, char *plan, size_t size, int *offset,
                       bool *has_l2, char *err, size_t err_size);

#endif
