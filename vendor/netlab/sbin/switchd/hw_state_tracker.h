/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_SWITCHD_HW_STATE_TRACKER_H
#define NETLAB_SWITCHD_HW_STATE_TRACKER_H

#include "netlab/hal.h"
#include <pthread.h>

typedef enum {
    HW_L2_TX_RESERVED = 1,
    HW_L2_TX_APPLIED,
    HW_L2_TX_ROLLING_BACK,
    HW_L2_TX_ROLLBACK_FAILED,
} hw_l2_tx_state;

typedef struct {
    u64 commit_id;
    hw_l2_tx_state state;
    l2_apply_plan plan;
} hw_l2_transaction;

struct hw_state_tracker {
    pthread_mutex_t lock;
    hw_l2_transaction *pending;
    unsigned int external_mutations;
    struct {
        u64 commit_id;
        char hash[64];
    } last_applied;
    u64 last_rolled_back;
    u64 last_failed_verified;
};

#endif
