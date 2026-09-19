/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/error.h"
#include "hw_state_tracker.h"
#include <stdlib.h>
#include <string.h>
#include <fm_sdk.h>

static void free_l2_transaction(hw_l2_transaction *transaction) {
    if (!transaction)
        return;
    l2_apply_plan_reset(&transaction->plan);
    free(transaction);
}

int hw_state_tracker_init(struct hw_state_tracker **out) {
    struct hw_state_tracker *t;

    if (!out)
        return NL_ERR;
    *out = NULL;
    t = calloc(1, sizeof(*t));
    if (!t)
        return NL_ERR;
    if (pthread_mutex_init(&t->lock, NULL) != 0) {
        free(t);
        return NL_ERR;
    }
    t->last_applied.commit_id = 0;
    *out = t;
    NL_LOG_INFO("HW state tracker initialized");
    return NL_OK;
}

void hw_state_tracker_destroy(struct hw_state_tracker **tracker) {
    struct hw_state_tracker *owned;

    if (!tracker || !*tracker)
        return;
    owned = *tracker;
    free_l2_transaction(owned->pending);
    owned->pending = NULL;
    pthread_mutex_destroy(&owned->lock);
    free(owned);
    *tracker = NULL;
}

int hw_state_tracker_record_pre(struct sdk_op *op) {
    if (!op) return NL_ERR;

    switch (op->type) {
        case SDK_OP_PORT_SET_ADMIN:
            op->pre_state.port.port = op->args.port.port;
            op->pre_state.port.mode = FM_PORT_MODE_ADMIN_DOWN; // assume
            break;
        default:
            break;
    }
    return NL_OK;
}

int hw_state_tracker_reserve_l2(struct hw_state_tracker *tracker,
                                       u64 tx_id,
                                       const l2_apply_plan *plan,
                                       l2_apply_plan **owned_plan) {
    hw_l2_transaction *tx;
    int status = NL_OK;

    if (!tracker || !plan || !owned_plan || tx_id == 0)
        return NL_ERR_INVALID_VALUE;
    *owned_plan = NULL;

    pthread_mutex_lock(&tracker->lock);
    if (tracker->pending || tracker->external_mutations > 0) {
        status = NL_ERR_RPC_BUSY;
        goto out;
    }
    tx = calloc(1, sizeof(*tx));
    if (!tx) {
        status = NL_ERR;
        goto out;
    }
    tx->commit_id = tx_id;
    tx->state = HW_L2_TX_RESERVED;
    l2_apply_plan_init(&tx->plan);
    if (l2_apply_plan_clone(&tx->plan, plan) != 0) {
        free_l2_transaction(tx);
        status = NL_ERR;
        goto out;
    }
    tx->plan.tx_id = tx_id;
    tx->plan.rollback_last_idx = -1;
    tracker->pending = tx;
    *owned_plan = &tx->plan;

out:
    pthread_mutex_unlock(&tracker->lock);
    return status;
}

int hw_state_tracker_begin_l2_mutation(
    struct hw_state_tracker *tracker) {
    int status = NL_OK;

    if (!tracker)
        return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&tracker->lock);
    if (tracker->pending) {
        status = NL_ERR_RPC_BUSY;
    } else {
        tracker->external_mutations++;
    }
    pthread_mutex_unlock(&tracker->lock);
    return status;
}

void hw_state_tracker_end_l2_mutation(
    struct hw_state_tracker *tracker) {
    if (!tracker)
        return;
    pthread_mutex_lock(&tracker->lock);
    if (tracker->external_mutations > 0)
        tracker->external_mutations--;
    pthread_mutex_unlock(&tracker->lock);
}

int hw_state_tracker_finish_l2_apply(
    struct hw_state_tracker *tracker, u64 tx_id, int apply_status) {
    int status = NL_OK;

    if (!tracker || tx_id == 0)
        return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&tracker->lock);
    if (!tracker->pending || tracker->pending->commit_id != tx_id ||
        tracker->pending->state != HW_L2_TX_RESERVED) {
        status = NL_ERR_HW_STATE_OUT_OF_SYNC;
        goto out;
    }

    if (apply_status == NL_OK) {
        tracker->pending->state = HW_L2_TX_APPLIED;
    } else if (apply_status == NL_ERR_ROLLBACK_FAILED ||
               apply_status == NL_ERR_VERIFY_AFTER_ROLLBACK_FAILED ||
               apply_status == NL_ERR_HW_STATE_OUT_OF_SYNC ||
               apply_status == NL_ERR_RPC_TIMEOUT || apply_status == NL_ERR_SDK_TIMEOUT ||
               apply_status < 0) {
        tracker->pending->state = HW_L2_TX_ROLLBACK_FAILED;
    } else {
        tracker->last_failed_verified = tx_id;
        free_l2_transaction(tracker->pending);
        tracker->pending = NULL;
    }

out:
    pthread_mutex_unlock(&tracker->lock);
    return status;
}

int hw_state_tracker_begin_l2_rollback(
    struct hw_state_tracker *tracker, u64 tx_id,
    l2_apply_plan **owned_plan, bool *already_rolled_back) {
    int status = NL_OK;

    if (!tracker || !owned_plan || !already_rolled_back || tx_id == 0)
        return NL_ERR_INVALID_VALUE;
    *owned_plan = NULL;
    *already_rolled_back = false;

    pthread_mutex_lock(&tracker->lock);
    if (!tracker->pending) {
        if (tracker->last_rolled_back == tx_id) {
            *already_rolled_back = true;
            status = NL_OK;
        } else {
            status = NL_ERR_PRE_STATE_MISSING;
        }
        goto out;
    }
    if (tracker->pending->commit_id != tx_id) {
        status = NL_ERR_RPC_BUSY;
        goto out;
    }
    if (tracker->pending->state == HW_L2_TX_RESERVED ||
        tracker->pending->state == HW_L2_TX_ROLLING_BACK) {
        status = NL_ERR_RPC_BUSY;
        goto out;
    }
    if (tracker->pending->state != HW_L2_TX_APPLIED &&
        tracker->pending->state != HW_L2_TX_ROLLBACK_FAILED) {
        status = NL_ERR_HW_STATE_OUT_OF_SYNC;
        goto out;
    }

    tracker->pending->state = HW_L2_TX_ROLLING_BACK;
    *owned_plan = &tracker->pending->plan;

out:
    pthread_mutex_unlock(&tracker->lock);
    return status;
}

int hw_state_tracker_finish_l2_rollback(
    struct hw_state_tracker *tracker, u64 tx_id, int rollback_status) {
    int status = NL_OK;

    if (!tracker || tx_id == 0)
        return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&tracker->lock);
    if (!tracker->pending || tracker->pending->commit_id != tx_id ||
        tracker->pending->state != HW_L2_TX_ROLLING_BACK) {
        status = NL_ERR_HW_STATE_OUT_OF_SYNC;
        goto out;
    }

    if (rollback_status == NL_OK) {
        free_l2_transaction(tracker->pending);
        tracker->pending = NULL;
        tracker->last_rolled_back = tx_id;
    } else {
        tracker->pending->state = HW_L2_TX_ROLLBACK_FAILED;
    }

out:
    pthread_mutex_unlock(&tracker->lock);
    return status;
}
