#ifndef NETLAB_HAL_FLOW_TABLE_TOKEN_H
#define NETLAB_HAL_FLOW_TABLE_TOKEN_H

#include "types.h"

typedef enum {
    HAL_FLOW_OWNER_CONTROL_PLANE = 1,
    HAL_FLOW_OWNER_ACL,
    HAL_FLOW_OWNER_QOS,
    HAL_FLOW_OWNER_STORM_CONTROL,
    HAL_FLOW_OWNER_L2_SECURITY,
} hal_flow_owner;

/*
 * Destructive release authority for a table created by one successful SDK
 * reserve call.  generation binds the token to the exact live registry
 * entry; table absence observed before that call is not release authority.
 */
typedef struct {
    bool valid;
    int sw;
    int table;
    hal_flow_owner owner;
    u64 generation;
    u64 condition;
    u32 max_entries;
    u32 max_actions;
    bool with_priority;
} hal_flow_table_creation_token;

#endif
