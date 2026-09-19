#ifndef NETLAB_HAL_ACL_OWNER_TRANSACTION_H
#define NETLAB_HAL_ACL_OWNER_TRANSACTION_H

#include "hal_transaction_snapshot.h"

/*
 * This header intentionally has no dependency on hal.h.  l2_apply_step owns
 * these before-images, so hal.h must be able to include this file without a
 * reverse include cycle.
 */
typedef enum {
    HAL_ACL_OWNER_QUERY_SET_SEMANTIC = 0,
    HAL_ACL_OWNER_QUERY_DELETE_EXACT = 1,
} hal_acl_owner_transaction_query;

typedef enum {
    HAL_ACL_SHARED_CREATOR_POLICER = 1,
    HAL_ACL_SHARED_CREATOR_INDEPENDENT = 2,
} hal_acl_shared_creator;

/*
 * Destructive authority for a shared ACL created by one successful
 * fmCreateACL() call.  Before-absence alone is not authority to delete an ACL
 * that could have been created by another owner after capture.
 */
typedef struct {
    bool valid;
    int sw;
    int acl;
    hal_acl_shared_creator creator;
    u64 generation;
} hal_acl_shared_creation_token;

typedef struct {
    int port;
    u64 dst_mac;
    int rate_kbps;
    int burst_bytes;
} hal_acl_policer_owner_transaction_before;

typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    int slot;
    bool shared_acl_present;
    hal_acl_shared_creation_token shared_acl_creation;
    hal_acl_policer_owner_transaction_before before;
} hal_acl_policer_owner_transaction_snapshot;

typedef struct {
    int port;
    u64 src_mac;
    u64 dst_mac;
} hal_acl_egress_owner_transaction_before;

typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    int slot;
    bool acl_present;
    hal_acl_egress_owner_transaction_before before;
} hal_acl_egress_owner_transaction_snapshot;

#define HAL_ACL_OWNER_SNAPSHOT_NAME_MAX 64
#define HAL_ACL_OWNER_SNAPSHOT_FAMILY_MAX 16
#define HAL_ACL_OWNER_SNAPSHOT_ACTION_MAX 16

typedef struct {
    bool has_src_ip;
    bool has_dst_ip;
    bool has_src_ip_mask;
    bool has_dst_ip_mask;
    bool has_dscp;
    bool has_ecn;
    bool has_protocol;
    bool has_src_port;
    bool has_dst_port;
    bool has_src_port_range;
    bool has_dst_port_range;
    bool has_tcp_flags;
    bool has_tcp_flags_mask;
    bool count_only;
    u32 src_ip;
    u32 dst_ip;
    u32 src_ip_mask;
    u32 dst_ip_mask;
    int dscp;
    int ecn;
    int protocol;
    int src_port;
    int dst_port;
    int src_port_start;
    int src_port_end;
    int dst_port_start;
    int dst_port_end;
    int tcp_flags;
    int tcp_flags_mask;
} hal_acl_independent_transaction_match;

typedef struct {
    char group[HAL_ACL_OWNER_SNAPSHOT_NAME_MAX];
    char term[HAL_ACL_OWNER_SNAPSHOT_NAME_MAX];
    char family[HAL_ACL_OWNER_SNAPSHOT_FAMILY_MAX];
    char action[HAL_ACL_OWNER_SNAPSHOT_ACTION_MAX];
    int slot;
    int vid;
    int port;
    bool has_src_mac;
    bool has_dst_mac;
    u64 src_mac;
    u64 dst_mac;
    hal_acl_independent_transaction_match inet_match;
    int rate_kbps;
    int burst_bytes;
} hal_acl_independent_transaction_before;

typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    int slot;
    bool shared_acl_present;
    hal_acl_shared_creation_token shared_acl_creation;
    hal_acl_independent_transaction_before before;
} hal_acl_independent_transaction_snapshot;

#endif
