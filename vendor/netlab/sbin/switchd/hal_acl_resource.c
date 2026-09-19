#include "hal_acl_resource.h"

#include "netlab/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HAL_ACL_RESOURCE_MAX 8
#define HAL_ACL_COPP_DEFAULT_ACL 3100
#define HAL_ACL_COPP_DEFAULT_POLICER 100
#define HAL_ACL_POLICER_DEFAULT_ACL 3100
#define HAL_ACL_POLICER_DEFAULT_POLICER 201
#define HAL_ACL_EGRESS_DEFAULT_ACL 3201
#define HAL_ACL_GENERAL_INGRESS_DEFAULT_ACL 3300
#define HAL_ACL_GENERAL_EGRESS_DEFAULT_ACL 3400

typedef struct {
    bool used;
    int sw;
    int acl;
    int acl_count;
    int rules_per_acl;
    int first_policer;
    int policer_count;
    hal_acl_owner owner;
    char name[32];
} hal_acl_resource_entry;

static hal_acl_resource_entry g_acl_resources[HAL_ACL_RESOURCE_MAX];

const char *hal_acl_owner_name(hal_acl_owner owner) {
    switch (owner) {
    case HAL_ACL_OWNER_COPP:
        return "copp-hardware";
    case HAL_ACL_OWNER_ACL_POLICER:
        return "acl-policer-owner";
    case HAL_ACL_OWNER_EGRESS_ACL:
        return "egress-acl-owner";
    case HAL_ACL_OWNER_GENERAL_INGRESS:
        return "general-ingress-acl-allocator";
    case HAL_ACL_OWNER_GENERAL_EGRESS:
        return "general-egress-acl-allocator";
    default:
        return "unknown";
    }
}

static int default_acl_for_owner(hal_acl_owner owner) {
    switch (owner) {
    case HAL_ACL_OWNER_COPP:
        return HAL_ACL_COPP_DEFAULT_ACL;
    case HAL_ACL_OWNER_ACL_POLICER:
        return HAL_ACL_POLICER_DEFAULT_ACL;
    case HAL_ACL_OWNER_EGRESS_ACL:
        return HAL_ACL_EGRESS_DEFAULT_ACL;
    case HAL_ACL_OWNER_GENERAL_INGRESS:
        return HAL_ACL_GENERAL_INGRESS_DEFAULT_ACL;
    case HAL_ACL_OWNER_GENERAL_EGRESS:
        return HAL_ACL_GENERAL_EGRESS_DEFAULT_ACL;
    default:
        return 0;
    }
}

static int default_policer_for_owner(hal_acl_owner owner) {
    switch (owner) {
    case HAL_ACL_OWNER_COPP:
        return HAL_ACL_COPP_DEFAULT_POLICER;
    case HAL_ACL_OWNER_ACL_POLICER:
        return HAL_ACL_POLICER_DEFAULT_POLICER;
    default:
        return 0;
    }
}

static bool policer_ranges_overlap(int first_a, int count_a,
                                   int first_b, int count_b) {
    int last_a;
    int last_b;

    if (first_a <= 0 || first_b <= 0 || count_a <= 0 || count_b <= 0)
        return false;
    last_a = first_a + count_a - 1;
    last_b = first_b + count_b - 1;
    return first_a <= last_b && first_b <= last_a;
}

static bool acl_ranges_overlap(int first_a, int count_a,
                               int first_b, int count_b) {
    int last_a;
    int last_b;

    if (first_a <= 0 || first_b <= 0 || count_a <= 0 || count_b <= 0)
        return false;
    last_a = first_a + count_a - 1;
    last_b = first_b + count_b - 1;
    return first_a <= last_b && first_b <= last_a;
}

static bool acl_share_allowed(const hal_acl_resource_entry *entry,
                              int acl, int acl_count,
                              hal_acl_owner owner) {
    if (!entry || entry->acl != acl || entry->acl_count != 1 ||
        acl_count != 1)
        return false;
    return (entry->owner == HAL_ACL_OWNER_COPP &&
            owner == HAL_ACL_OWNER_ACL_POLICER) ||
           (entry->owner == HAL_ACL_OWNER_ACL_POLICER &&
            owner == HAL_ACL_OWNER_COPP) ||
           (entry->owner == HAL_ACL_OWNER_COPP &&
            owner == HAL_ACL_OWNER_GENERAL_INGRESS) ||
           (entry->owner == HAL_ACL_OWNER_GENERAL_INGRESS &&
            owner == HAL_ACL_OWNER_COPP) ||
           (entry->owner == HAL_ACL_OWNER_ACL_POLICER &&
            owner == HAL_ACL_OWNER_GENERAL_INGRESS) ||
           (entry->owner == HAL_ACL_OWNER_GENERAL_INGRESS &&
            owner == HAL_ACL_OWNER_ACL_POLICER);
}

static int compare_owner_by_acl(const void *a, const void *b) {
    const hal_acl_resource_owner_info *oa = a;
    const hal_acl_resource_owner_info *ob = b;

    if (oa->acl < ob->acl)
        return -1;
    if (oa->acl > ob->acl)
        return 1;
    if (oa->first_policer < ob->first_policer)
        return -1;
    if (oa->first_policer > ob->first_policer)
        return 1;
    return 0;
}

int hal_acl_resource_reserve(int sw, const hal_acl_resource_spec *spec,
                             hal_acl_resource_reservation *out) {
    int acl;
    int acl_count;
    int rules_per_acl;
    int first_policer;
    hal_acl_resource_entry *entry;

    if (!spec || spec->owner <= 0 || spec->policer_count < 0)
        return -1;

    acl = spec->preferred_acl > 0 ?
          spec->preferred_acl : default_acl_for_owner(spec->owner);
    acl_count = spec->acl_count > 0 ? spec->acl_count : 1;
    rules_per_acl = spec->rules_per_acl > 0 ? spec->rules_per_acl : 0;
    first_policer = spec->first_policer > 0 ?
                    spec->first_policer :
                    default_policer_for_owner(spec->owner);
    if (acl <= 0 || (spec->policer_count > 0 && first_policer <= 0))
        return -1;

    for (int i = 0; i < HAL_ACL_RESOURCE_MAX; i++) {
        entry = &g_acl_resources[i];
        if (!entry->used || entry->sw != sw)
            continue;
        if (entry->acl == acl &&
            entry->acl_count == acl_count &&
            entry->owner == spec->owner &&
            entry->first_policer == first_policer &&
            entry->policer_count == spec->policer_count &&
            entry->rules_per_acl == rules_per_acl) {
            if (out) {
                out->acl = entry->acl;
                out->acl_count = entry->acl_count;
                out->rules_per_acl = entry->rules_per_acl;
                out->first_policer = entry->first_policer;
                out->policer_count = entry->policer_count;
                out->existed = true;
            }
            return 0;
        }
        if (acl_ranges_overlap(entry->acl, entry->acl_count,
                               acl, acl_count) &&
            entry->owner != spec->owner &&
            !acl_share_allowed(entry, acl, acl_count, spec->owner)) {
            NL_LOG_ERR("ACL range %d-%d already reserved by %s, cannot reuse for %s",
                       entry->acl, entry->acl + entry->acl_count - 1,
                       hal_acl_owner_name(entry->owner),
                       hal_acl_owner_name(spec->owner));
            return -1;
        }
        if (policer_ranges_overlap(entry->first_policer,
                                   entry->policer_count,
                                   first_policer,
                                   spec->policer_count)) {
            NL_LOG_ERR("ACL policer range %d-%d already reserved by %s, cannot reuse for %s",
                       entry->first_policer,
                       entry->first_policer + entry->policer_count - 1,
                       hal_acl_owner_name(entry->owner),
                       hal_acl_owner_name(spec->owner));
            return -1;
        }
        if (entry->acl == acl && entry->owner != spec->owner) {
            NL_LOG_INFO("sharing ACL resource %d between %s and %s using non-overlapping policers",
                        acl, hal_acl_owner_name(entry->owner),
                        hal_acl_owner_name(spec->owner));
        }
    }

    for (int i = 0; i < HAL_ACL_RESOURCE_MAX; i++) {
        if (!g_acl_resources[i].used) {
            g_acl_resources[i].used = true;
            g_acl_resources[i].sw = sw;
            g_acl_resources[i].acl = acl;
            g_acl_resources[i].acl_count = acl_count;
            g_acl_resources[i].rules_per_acl = rules_per_acl;
            g_acl_resources[i].first_policer = first_policer;
            g_acl_resources[i].policer_count = spec->policer_count;
            g_acl_resources[i].owner = spec->owner;
            snprintf(g_acl_resources[i].name, sizeof(g_acl_resources[i].name),
                     "%s", spec->name ? spec->name :
                     hal_acl_owner_name(spec->owner));
            if (out) {
                out->acl = acl;
                out->acl_count = acl_count;
                out->rules_per_acl = rules_per_acl;
                out->first_policer = first_policer;
                out->policer_count = spec->policer_count;
                out->existed = false;
            }
            if (spec->policer_count > 0) {
                NL_LOG_INFO("reserved ACL resource acl=%d-%d policers=%d-%d for %s",
                            acl, acl + acl_count - 1, first_policer,
                            first_policer + spec->policer_count - 1,
                            spec->name ? spec->name :
                            hal_acl_owner_name(spec->owner));
            } else {
                NL_LOG_INFO("reserved ACL resource acl=%d-%d no-policer owner=%s",
                            acl, acl + acl_count - 1,
                            spec->name ? spec->name :
                            hal_acl_owner_name(spec->owner));
            }
            return 0;
        }
    }

    NL_LOG_ERR("ACL resource registry is full");
    return -1;
}

int hal_acl_resource_release_owner(int sw, hal_acl_owner owner) {
    int released = 0;

    if (owner <= 0)
        return -1;

    for (int i = 0; i < HAL_ACL_RESOURCE_MAX; i++) {
        hal_acl_resource_entry *entry = &g_acl_resources[i];

        if (!entry->used || entry->sw != sw || entry->owner != owner)
            continue;
        memset(entry, 0, sizeof(*entry));
        released++;
    }

    return released;
}

int hal_acl_resource_collect_owners(int sw,
                                    hal_acl_resource_owner_info *owners,
                                    int max_owners) {
    int count = 0;

    if (!owners || max_owners <= 0)
        return 0;

    memset(owners, 0, (size_t)max_owners * sizeof(*owners));

    for (int i = 0; i < HAL_ACL_RESOURCE_MAX && count < max_owners; i++) {
        hal_acl_resource_entry *entry = &g_acl_resources[i];

        if (!entry->used || entry->sw != sw)
            continue;

        owners[count].acl = entry->acl;
        owners[count].acl_count = entry->acl_count > 0 ?
                                  entry->acl_count : 1;
        owners[count].rules_per_acl = entry->rules_per_acl;
        owners[count].first_policer = entry->first_policer;
        owners[count].policer_count = entry->policer_count;
        owners[count].owner = entry->owner;
        snprintf(owners[count].name, sizeof(owners[count].name), "%s",
                 entry->name[0] ? entry->name :
                 hal_acl_owner_name(entry->owner));
        count++;
    }

    qsort(owners, (size_t)count, sizeof(*owners), compare_owner_by_acl);
    return count;
}
