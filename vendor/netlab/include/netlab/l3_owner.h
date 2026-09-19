#ifndef NETLAB_L3_OWNER_H
#define NETLAB_L3_OWNER_H

#include "ipc.h"
#include <stddef.h>

typedef struct nl_l3_owner nl_l3_owner;

typedef enum {
    NL_L3_OWNER_SHOW = NL_RPD_SHOW,
    NL_L3_OWNER_READBACK = NL_RPD_READBACK,
    NL_L3_OWNER_RESOURCE_CHECK = NL_RPD_VALIDATE_PLAN,
    NL_L3_OWNER_APPLY = NL_RPD_APPLY_PLAN,
    NL_L3_OWNER_ROLLBACK = NL_RPD_ROLLBACK,
} nl_l3_owner_method;

typedef struct {
    const char *switchd_socket_path;
    const char *authority_name;
    const char *public_reason;
    u16 switchd_caller_daemon;
} nl_l3_owner_options;

nl_l3_owner *nl_l3_owner_create(const nl_l3_owner_options *options);
void nl_l3_owner_destroy(nl_l3_owner *owner);

int nl_l3_owner_handle(nl_l3_owner *owner, nl_l3_owner_method method,
                       nl_conn *conn, nl_msg_hdr *msg);

int nl_l3_owner_plan_validate(const char *text, char *summary,
                              size_t summary_size, char *error,
                              size_t error_size);
int nl_l3_owner_plan_compile(const char *text, char *transaction,
                             size_t transaction_size, char *error,
                             size_t error_size);
int nl_l3_owner_plan_resource_check(nl_l3_owner *owner, const char *text,
                                    const char *profile_path, char *xml,
                                    size_t xml_size, char *error,
                                    size_t error_size);

#endif
