#ifndef NETLAB_HAL_PRESENCE_H
#define NETLAB_HAL_PRESENCE_H

#include "types.h"

/*
 * Presence is a live SDK read result, not a boolean guess.  ABSENT is a
 * successful observation of absence; READ_ERROR means no state conclusion
 * may be drawn from sdk_status.
 */
typedef enum {
    HAL_PRESENCE_READ_ERROR = -1,
    HAL_PRESENCE_ABSENT = 0,
    HAL_PRESENCE_PRESENT = 1,
} hal_presence_state;

typedef struct {
    hal_presence_state state;
    int sdk_status;
    /*
     * Valid only for a PRESENT VLAN-member snapshot.  Keeping the tag in the
     * same observation prevents a second read from racing the presence check.
     */
    bool tagged;
} hal_presence_snapshot;

hal_presence_snapshot hal_vlan_presence_snapshot(int sw, u16 vid);
hal_presence_snapshot hal_vlan_member_snapshot(int sw, u16 vid, int port);
hal_presence_snapshot hal_lag_first_snapshot(int sw, int *lag_id);
hal_presence_snapshot hal_lag_presence_snapshot(int sw, int lag_id);
hal_presence_snapshot hal_lag_member_snapshot(int sw, int lag_id, int port);

/*
 * FM10840 LAG deletion can complete asynchronously.  This bounded barrier
 * returns ABSENT only after a successful absence observation and returns a
 * READ_ERROR immediately rather than treating an unknown read as deletion.
 */
hal_presence_snapshot hal_lag_wait_absent(int sw, int lag_id);

#endif
