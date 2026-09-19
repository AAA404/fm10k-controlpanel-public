#ifndef NETLAB_HAL_FLOW_TABLE_H
#define NETLAB_HAL_FLOW_TABLE_H

#include "netlab/hal_flow_table_token.h"
#include <stdbool.h>
#include <fm_sdk.h>
#include <api/fm_api_flow.h>

typedef struct {
    hal_flow_owner owner;
    const char *name;
    fm_int preferred_table;
    fm_flowCondition condition;
    fm_uint32 max_entries;
    fm_uint32 max_actions;
    bool with_priority;
} hal_flow_table_spec;

typedef struct {
    fm_int table;
    fm_uint32 max_entries;
    fm_uint32 empty_entries;
    bool existed;
} hal_flow_table_reservation;

typedef struct {
    fm_int table;
    hal_flow_owner owner;
    char name[32];
    fm_uint32 max_entries;
    fm_uint32 used_entries;
    fm_uint32 empty_entries;
    fm_uint32 max_actions;
    fm_flowCondition condition;
} hal_flow_table_owner_info;

const char *hal_flow_owner_name(hal_flow_owner owner);
int hal_flow_table_reserve(int sw, const hal_flow_table_spec *spec,
                           hal_flow_table_reservation *out);
int hal_flow_table_reserve_with_token(
    int sw, const hal_flow_table_spec *spec,
    hal_flow_table_reservation *out,
    hal_flow_table_creation_token *creation_token);
int hal_flow_table_release_created_empty(
    int sw, const hal_flow_table_spec *spec,
    const hal_flow_table_creation_token *creation_token);
int hal_flow_table_collect_owners(int sw, hal_flow_table_owner_info *owners,
                                  int max_owners);
int hal_l2_security_flow_table(int sw);
int hal_l2_security_take_created_table_token(
    hal_flow_table_creation_token *creation_token);
int hal_l2_security_release_created_table_empty(
    const hal_flow_table_creation_token *creation_token);
void hal_l2_security_begin_table_operation(void);

#endif
