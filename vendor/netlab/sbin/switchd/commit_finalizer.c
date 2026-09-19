/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/error.h"
#include "netlab/hal.h"
#include "hal_acl_owner_transaction_api.h"
#include "hw_state_tracker.h"
#include "netlab/port_scope.h"
#include <stdlib.h>
#include <string.h>

#define ACL_COMMIT_TOKEN_MAX (L2_PLAN_MAX_STEPS * 2)

static int retire_acl_creation_tokens(l2_apply_plan *plan) {
    hal_acl_shared_creation_token *tokens = NULL;
    int count = 0;
    int status = -1;

    if (!plan || plan->n_steps < 0 ||
        plan->n_steps > L2_PLAN_MAX_STEPS ||
        plan->n_steps > plan->step_capacity ||
        plan->original_n_steps > plan->original_capacity ||
        (plan->n_steps > 0 && (!plan->steps || !plan->original_steps)))
        return -1;
    if (plan->n_steps > 0) {
        tokens = calloc((size_t)plan->n_steps * 2U, sizeof(*tokens));
        if (!tokens)
            return -1;
    }
    for (int i = 0; i < plan->n_steps; i++) {
        const hal_acl_shared_creation_token *policer =
            &plan->steps[i].pre_acl_policer.shared_acl_creation;
        const hal_acl_shared_creation_token *independent =
            &plan->steps[i].pre_acl_independent.shared_acl_creation;

        if (plan->original_steps[i].
                pre_acl_policer.shared_acl_creation.valid ||
            plan->original_steps[i].
                pre_acl_independent.shared_acl_creation.valid)
            goto out;
        if (policer->valid) {
            if (count >= ACL_COMMIT_TOKEN_MAX)
                goto out;
            tokens[count++] = *policer;
        }
        if (independent->valid) {
            if (count >= ACL_COMMIT_TOKEN_MAX)
                goto out;
            tokens[count++] = *independent;
        }
    }
    if (count == 0) {
        status = 0;
        goto out;
    }
    if (plan->original_n_steps != plan->n_steps)
        goto out;
    status = hal_acl_shared_creation_tokens_retire(tokens, count);

out:
    free(tokens);
    return status;
}

int hal_commit_mark_success(struct hw_state_tracker *tracker,
                            u64 tx_id, const char *hash) {
    int status = NL_OK;

    if (!tracker || tx_id == 0)
        return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&tracker->lock);
    if (!tracker->pending) {
        if (tracker->last_applied.commit_id == tx_id) {
            NL_LOG_INFO("commit mark_success tx=0x%lx already finalized",
                        tx_id);
        } else {
            NL_LOG_ERR("commit mark_success: tx=0x%lx has no pending state",
                       tx_id);
            status = NL_ERR_HW_STATE_OUT_OF_SYNC;
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
    if (tracker->pending->state != HW_L2_TX_APPLIED) {
        status = NL_ERR_HW_STATE_OUT_OF_SYNC;
        goto out;
    }
    status = hal_lag_transaction_check(tx_id, true);
    if (status != 0) goto out;
    if (retire_acl_creation_tokens(
            &tracker->pending->plan) != 0) {
        NL_LOG_CRIT(
            "commit mark_success tx=0x%lx could not retire "
            "ACL creation-token authority",
            tx_id);
        status = NL_ERR_HW_STATE_OUT_OF_SYNC;
        goto out;
    }

    hal_lag_transaction_retire(tx_id);
    tracker->last_applied.commit_id = tx_id;
    memset(tracker->last_applied.hash, 0,
           sizeof(tracker->last_applied.hash));
    if (hash)
        strncpy(tracker->last_applied.hash, hash,
                sizeof(tracker->last_applied.hash) - 1);
    l2_apply_plan_reset(&tracker->pending->plan);
    free(tracker->pending);
    tracker->pending = NULL;
    NL_LOG_INFO("commit mark_success tx=0x%lx", tx_id);

out:
    pthread_mutex_unlock(&tracker->lock);
    return status;
}

int hal_commit_mark_failed(struct hw_state_tracker *tracker, u64 tx_id) {
    int status = NL_OK;

    if (!tracker || tx_id == 0)
        return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&tracker->lock);
    if (!tracker->pending) {
        nl_port_scope_status scope = nl_port_scope_get();
        if (scope.tx_id == tx_id && scope.mask &&
            tracker->last_rolled_back != tx_id && tracker->last_failed_verified != tx_id)
            status = NL_ERR_PRE_STATE_MISSING;
        goto out;
    }
    if (tracker->pending->commit_id != tx_id) {
        status = NL_ERR_RPC_BUSY;
        goto out;
    }

    /*
     * A successful apply owns real hardware pre-state. It may only leave the
     * tracker through method 41 after reverse mutation and exact read-back.
     */
    if (tracker->pending->state == HW_L2_TX_APPLIED ||
        tracker->pending->state == HW_L2_TX_ROLLBACK_FAILED) {
        status = NL_ERR_HW_STATE_OUT_OF_SYNC;
        goto out;
    }
    if (tracker->pending->state == HW_L2_TX_RESERVED ||
        tracker->pending->state == HW_L2_TX_ROLLING_BACK) {
        status = NL_ERR_RPC_BUSY;
        goto out;
    }

out:
    if (status == NL_OK) {
        status = hal_lag_transaction_check(tx_id, false);
        if (status == NL_OK) hal_lag_transaction_retire(tx_id);
    }
    pthread_mutex_unlock(&tracker->lock);
    return status;
}

int hal_commit_abort(struct hw_state_tracker *tracker, u64 tx_id) {
    return hal_commit_mark_failed(tracker, tx_id);
}
