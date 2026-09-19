#ifndef NETLAB_HAL_ACL_RESOURCE_H
#define NETLAB_HAL_ACL_RESOURCE_H

#include <stdbool.h>

typedef enum {
    HAL_ACL_OWNER_COPP = 1,
    HAL_ACL_OWNER_ACL_POLICER = 2,
    HAL_ACL_OWNER_EGRESS_ACL = 3,
    HAL_ACL_OWNER_GENERAL_INGRESS = 4,
    HAL_ACL_OWNER_GENERAL_EGRESS = 5,
} hal_acl_owner;

typedef struct {
    hal_acl_owner owner;
    const char *name;
    int preferred_acl;
    int acl_count;
    int rules_per_acl;
    int first_policer;
    int policer_count;
} hal_acl_resource_spec;

typedef struct {
    int acl;
    int acl_count;
    int rules_per_acl;
    int first_policer;
    int policer_count;
    bool existed;
} hal_acl_resource_reservation;

typedef struct {
    int acl;
    int acl_count;
    int rules_per_acl;
    int first_policer;
    int policer_count;
    hal_acl_owner owner;
    char name[32];
} hal_acl_resource_owner_info;

const char *hal_acl_owner_name(hal_acl_owner owner);
int hal_acl_resource_reserve(int sw, const hal_acl_resource_spec *spec,
                             hal_acl_resource_reservation *out);
int hal_acl_resource_release_owner(int sw, hal_acl_owner owner);
int hal_acl_resource_collect_owners(int sw,
                                    hal_acl_resource_owner_info *owners,
                                    int max_owners);

#endif
