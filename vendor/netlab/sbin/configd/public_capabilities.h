#ifndef CONFIGD_PUBLIC_CAPABILITIES_H
#define CONFIGD_PUBLIC_CAPABILITIES_H

#include "netlab/yang_config.h"

#include <stdbool.h>
#include <stddef.h>

#define CONFIGD_PUBLIC_CAPABILITY_CLOSED_ROOT_MAX 3U

typedef struct {
    const char *capability_id;
    const char *xpath;
    const char *cleanup_delete_command;
} configd_public_capability_closed_root;

typedef struct {
    bool inspection_complete;
    size_t closed_root_count;
    configd_public_capability_closed_root
        closed_roots[CONFIGD_PUBLIC_CAPABILITY_CLOSED_ROOT_MAX];
} configd_public_capability_status;

bool configd_public_capability_path_allowed(const char *xpath,
                                            char *detail,
                                            size_t detail_size);
bool configd_public_capabilities_validate_tree(const struct lyd_node *tree,
                                               char *detail,
                                               size_t detail_size);
bool configd_public_capabilities_validate(nl_yang_session *session,
                                          char *detail,
                                          size_t detail_size);
bool configd_public_capabilities_cleanup_required(
    nl_yang_session *session, char *detail, size_t detail_size);
bool configd_public_capabilities_cleanup_candidate(
    nl_yang_session *active, nl_yang_session *candidate,
    char *detail, size_t detail_size);
bool configd_public_capabilities_status(
    nl_yang_session *session, configd_public_capability_status *status,
    char *detail, size_t detail_size);

#endif
