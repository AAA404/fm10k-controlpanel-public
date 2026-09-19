#ifndef NETLAB_HAL_ACL_OWNER_TRANSACTION_API_H
#define NETLAB_HAL_ACL_OWNER_TRANSACTION_API_H

#include "netlab/hal.h"
#include "netlab/hal_acl_owner_transaction.h"

hal_acl_policer_owner_transaction_snapshot
hal_acl_policer_owner_transaction_snapshot_get(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_owner_transaction_query query);

hal_acl_egress_owner_transaction_snapshot
hal_acl_egress_owner_transaction_snapshot_get(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_owner_transaction_query query);

hal_acl_independent_transaction_snapshot
hal_acl_independent_transaction_snapshot_get(
    int sw, const hal_acl_independent_args *args,
    hal_acl_owner_transaction_query query);

int hal_acl_policer_owner_transaction_apply(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_transaction_snapshot *snapshot,
    hal_acl_policer_owner_result *result);

int hal_acl_independent_transaction_apply(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_transaction_snapshot *snapshot,
    hal_acl_independent_result *result);

int hal_acl_policer_owner_transaction_restore(
    int sw, const hal_acl_policer_owner_args *desired,
    const hal_acl_policer_owner_transaction_snapshot *snapshot);

int hal_acl_egress_owner_transaction_restore(
    int sw, const hal_acl_egress_owner_args *desired,
    const hal_acl_egress_owner_transaction_snapshot *snapshot);

int hal_acl_independent_transaction_restore(
    int sw, const hal_acl_independent_args *desired,
    const hal_acl_independent_transaction_snapshot *snapshot);

/*
 * Relinquish transaction-scoped delete authority after the hardware state
 * becomes durable.  This never deletes an ACL.  The operation validates the
 * complete batch before retiring any generation so duplicated/copied tokens
 * fail atomically.
 */
int hal_acl_shared_creation_tokens_retire(
    const hal_acl_shared_creation_token *tokens, int count);

#endif
