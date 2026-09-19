#include "public_capabilities.h"

#include "netlab/public_capabilities.h"

#include <stdio.h>
#include <string.h>


#define GENERAL_ACL_XPATH \
    "/netlab:netlab-config/ethernet-switching-options/acl-independent"
#define MANAGEMENT_SERVICES_XPATH \
    "/netlab:netlab-config/system/services"
#define SNMP_XPATH "/netlab:netlab-config/snmp"

#define GENERAL_ACL_CAPABILITY_ID "general-acl-independent"
#define MANAGEMENT_SERVICES_CAPABILITY_ID "management-services"
#define GENERAL_ACL_CLEANUP_DELETE \
    "delete ethernet-switching-options acl independent-group"
#define MANAGEMENT_SERVICES_CLEANUP_DELETE "delete system services"
#define SNMP_CLEANUP_DELETE "delete snmp"


#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT || \
    !NETLAB_PUBLIC_MANAGEMENT_SERVICES
static bool path_is_or_descends_from(const char *path, const char *root) {
    size_t root_len;

    if (!path || !root)
        return false;
    root_len = strlen(root);
    return strncmp(path, root, root_len) == 0 &&
           (path[root_len] == '\0' || path[root_len] == '/');
}
#endif

static void set_detail(char *detail, size_t detail_size, const char *text) {
    if (detail && detail_size > 0)
        snprintf(detail, detail_size, "%s", text);
}

bool configd_public_capability_path_allowed(const char *xpath,
                                            char *detail,
                                            size_t detail_size) {
#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT
    if (path_is_or_descends_from(xpath, GENERAL_ACL_XPATH)) {
        set_detail(
            detail, detail_size,
            "independent General ACL is closed by immutable public capability authority");
        return false;
    }
#endif
#if !NETLAB_PUBLIC_MANAGEMENT_SERVICES
    if (path_is_or_descends_from(xpath, MANAGEMENT_SERVICES_XPATH) ||
        path_is_or_descends_from(xpath, SNMP_XPATH)) {
        set_detail(
            detail, detail_size,
            "management services have no runtime owner and are closed by immutable public capability authority");
        return false;
    }
#endif
    set_detail(detail, detail_size, "");
    return true;
}

#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT || \
    !NETLAB_PUBLIC_MANAGEMENT_SERVICES
static int tree_xpath_count(const struct lyd_node *tree, const char *xpath) {
    struct ly_set *set = NULL;
    LY_ERR error;
    int count;

    if (!tree)
        return 0;
    error = lyd_find_xpath(tree, xpath, &set);
    count = error == LY_SUCCESS && set ? (int)set->count : -1;
    if (set)
        ly_set_free(set, NULL);
    return count;
}
#endif

bool configd_public_capabilities_validate_tree(const struct lyd_node *tree,
                                               char *detail,
                                               size_t detail_size) {
#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT
    if (tree_xpath_count(tree, GENERAL_ACL_XPATH) != 0) {
        set_detail(
            detail, detail_size,
            "independent General ACL is not promoted for public commit/replay");
        return false;
    }
#endif
#if !NETLAB_PUBLIC_MANAGEMENT_SERVICES
    if (tree_xpath_count(tree, MANAGEMENT_SERVICES_XPATH) != 0 ||
        tree_xpath_count(tree, SNMP_XPATH) != 0) {
        set_detail(
            detail, detail_size,
            "management service intent has no runtime owner and cannot be committed or replayed");
        return false;
    }
#endif
    set_detail(detail, detail_size, "");
    return true;
}

bool configd_public_capabilities_validate(nl_yang_session *session,
                                          char *detail,
                                          size_t detail_size) {
    if (!session) {
        set_detail(detail, detail_size,
                   "configuration session is unavailable");
        return false;
    }
#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT
    if (nl_yang_count(session, GENERAL_ACL_XPATH) != 0) {
        set_detail(
            detail, detail_size,
            "independent General ACL is not promoted for public commit/replay");
        return false;
    }
#endif
#if !NETLAB_PUBLIC_MANAGEMENT_SERVICES
    if (nl_yang_count(session, MANAGEMENT_SERVICES_XPATH) != 0 ||
        nl_yang_count(session, SNMP_XPATH) != 0) {
        set_detail(
            detail, detail_size,
            "management service intent has no runtime owner and cannot be committed or replayed");
        return false;
    }
#endif
    set_detail(detail, detail_size, "");
    return true;
}

bool configd_public_capabilities_cleanup_required(
        nl_yang_session *session, char *detail, size_t detail_size) {
    char validation_detail[512] = {0};

    if (configd_public_capabilities_validate(
            session, validation_detail, sizeof(validation_detail))) {
        set_detail(detail, detail_size, "");
        return false;
    }
    set_detail(
        detail, detail_size,
        validation_detail[0] ? validation_detail :
        "active configuration contains intent closed by public capability authority");
    return true;
}

#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT || \
    !NETLAB_PUBLIC_MANAGEMENT_SERVICES
static bool remove_cleanup_root(struct lyd_node *tree, const char *xpath) {
    struct ly_set *set = NULL;
    LY_ERR error;

    if (!tree)
        return true;
    error = lyd_find_xpath(tree, xpath, &set);
    if (error != LY_SUCCESS || !set) {
        if (set)
            ly_set_free(set, NULL);
        return false;
    }
    for (uint32_t i = 0; i < set->count; i++) {
        struct lyd_node *parent = lyd_parent(set->dnodes[i]);

        lyd_free_tree(set->dnodes[i]);
        /*
         * nl_yang_delete() and libyang may retain an empty non-presence
         * ancestor.  It carries no configuration authority, so prune it up
         * to (but never including) the explicit netlab-config root before
         * performing the exact cleanup-only comparison.
         */
        while (parent && lyd_parent(parent) && !lyd_child(parent)) {
            struct lyd_node *next = lyd_parent(parent);

            lyd_free_tree(parent);
            parent = next;
        }
    }
    ly_set_free(set, NULL);
    return true;
}

static bool cleanup_tree_empty(const struct lyd_node *tree) {
    return !tree ||
        (!tree->next && tree->schema && tree->schema->name &&
         strcmp(tree->schema->name, "netlab-config") == 0 &&
         !lyd_child(tree));
}
#endif

bool configd_public_capabilities_cleanup_candidate(
        nl_yang_session *active, nl_yang_session *candidate,
        char *detail, size_t detail_size) {
    struct lyd_node *sanitized = NULL;
    struct lyd_node *candidate_tree = NULL;
    char validation_detail[512] = {0};
    bool equivalent = false;
    bool cleanup_ok = true;

    if (!active || !candidate ||
        !configd_public_capabilities_cleanup_required(
            active, validation_detail, sizeof(validation_detail))) {
        set_detail(detail, detail_size,
                   "active configuration does not require public capability cleanup");
        return false;
    }
    if (!configd_public_capabilities_validate(
            candidate, validation_detail, sizeof(validation_detail))) {
        set_detail(detail, detail_size,
                   validation_detail[0] ? validation_detail :
                   "cleanup candidate still contains closed public capability intent");
        return false;
    }

    sanitized = nl_yang_data_clone_into(candidate, active);
    candidate_tree = nl_yang_data_clone(candidate);
    if (!sanitized) {
        set_detail(detail, detail_size,
                   "failed to clone active configuration for cleanup proof");
        lyd_free_all(candidate_tree);
        return false;
    }
#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT
    if (!remove_cleanup_root(sanitized, GENERAL_ACL_XPATH))
        cleanup_ok = false;
#endif
#if !NETLAB_PUBLIC_MANAGEMENT_SERVICES
    if (!remove_cleanup_root(sanitized, MANAGEMENT_SERVICES_XPATH) ||
        !remove_cleanup_root(sanitized, SNMP_XPATH))
        cleanup_ok = false;
#endif
    equivalent = cleanup_ok &&
        ((cleanup_tree_empty(sanitized) &&
          cleanup_tree_empty(candidate_tree)) ||
        (sanitized && candidate_tree &&
         lyd_compare_siblings(sanitized, candidate_tree,
                              LYD_COMPARE_FULL_RECURSION) == LY_SUCCESS));
    lyd_free_all(sanitized);
    lyd_free_all(candidate_tree);
    set_detail(
        detail, detail_size,
        equivalent ? "" :
        "cleanup-required mode permits only exact removal of all closed public capability intent");
    return equivalent;
}

#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT || \
    !NETLAB_PUBLIC_MANAGEMENT_SERVICES
static bool append_closed_root(
        configd_public_capability_status *status,
        const char *capability_id, const char *xpath,
        const char *cleanup_delete_command) {
    configd_public_capability_closed_root *root;

    if (!status || status->closed_root_count >=
            CONFIGD_PUBLIC_CAPABILITY_CLOSED_ROOT_MAX)
        return false;
    root = &status->closed_roots[status->closed_root_count++];
    root->capability_id = capability_id;
    root->xpath = xpath;
    root->cleanup_delete_command = cleanup_delete_command;
    return true;
}

static bool inspect_closed_root(
        nl_yang_session *session, configd_public_capability_status *status,
        const char *capability_id, const char *xpath,
        const char *cleanup_delete_command) {
    int count = nl_yang_count(session, xpath);

    if (count < 0)
        return false;
    return count == 0 || append_closed_root(
        status, capability_id, xpath, cleanup_delete_command);
}
#endif

bool configd_public_capabilities_status(
        nl_yang_session *session, configd_public_capability_status *status,
        char *detail, size_t detail_size) {
    bool complete = true;

    if (!status) {
        set_detail(detail, detail_size,
                   "public capability status output is unavailable");
        return false;
    }
    memset(status, 0, sizeof(*status));
    if (!session) {
        set_detail(detail, detail_size,
                   "active configuration session is unavailable");
        return false;
    }
#if !NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT
    if (!inspect_closed_root(
            session, status, GENERAL_ACL_CAPABILITY_ID, GENERAL_ACL_XPATH,
            GENERAL_ACL_CLEANUP_DELETE))
        complete = false;
#endif
#if !NETLAB_PUBLIC_MANAGEMENT_SERVICES
    if (!inspect_closed_root(
            session, status, MANAGEMENT_SERVICES_CAPABILITY_ID,
            MANAGEMENT_SERVICES_XPATH,
            MANAGEMENT_SERVICES_CLEANUP_DELETE))
        complete = false;
    if (!inspect_closed_root(
            session, status, MANAGEMENT_SERVICES_CAPABILITY_ID, SNMP_XPATH,
            SNMP_CLEANUP_DELETE))
        complete = false;
#endif
    status->inspection_complete = complete;
    set_detail(
        detail, detail_size,
        complete ? "" : "failed to inspect one or more closed capability roots");
    return complete;
}
