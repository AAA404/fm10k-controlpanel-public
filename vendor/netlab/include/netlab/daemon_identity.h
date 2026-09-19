#ifndef NETLAB_DAEMON_IDENTITY_H
#define NETLAB_DAEMON_IDENTITY_H

#include "ipc_contract.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define NL_DAEMON_PRIVATE_IPC_GROUP "netlab-ipc"
#define NL_DAEMON_EXECUTABLE_PATH_MAX 4096
#define NL_DAEMON_INTERNAL_AUTHORITY_BINARY "netlab-internal-rpc"
/* Legacy root daemons are unrestricted; this is a policy sentinel. */
#define NL_DAEMON_CAPABILITY_MASK_ROOT UINT64_MAX
#define NL_DAEMON_CAP_SYS_PTRACE_MASK (UINT64_C(1) << 19)

typedef enum {
    NL_DAEMON_IDENTITY_REAL = 0,
    NL_DAEMON_IDENTITY_VIRTUAL,
    NL_DAEMON_IDENTITY_RETIRED,
} nl_daemon_identity_kind;

/*
 * The registry describes the current executable identity.  When a dedicated
 * account is active, expected_account/primary_group match it and the common
 * root launcher must establish the declared groups, capabilities, and NNP
 * policy before the daemon handles input.
 */
typedef struct {
    nl_daemon_id wire_id;
    nl_daemon_identity_kind kind;
    const char *name;
    const char *binary;
    const char *expected_account;
    const char *primary_group;
    const char *dedicated_account;
    const char *dedicated_primary_group;
    const char *private_ipc_group;
    const char *socket_path;
    u64 capability_mask;
    bool no_new_privileges;
} nl_daemon_identity;

typedef struct {
    uid_t uid;
    gid_t primary_gid;
} nl_daemon_credentials;

size_t nl_daemon_identity_count(void);
const nl_daemon_identity *nl_daemon_identity_at(size_t index);
const nl_daemon_identity *nl_daemon_identity_lookup(nl_daemon_id wire_id);
const nl_daemon_identity *nl_daemon_identity_lookup_name(const char *name);
const char *nl_daemon_identity_kind_name(nl_daemon_identity_kind kind);
bool nl_daemon_identity_registry_valid(void);
bool nl_daemon_identity_is_peer_process(const nl_daemon_identity *identity);

/* Resolve names at runtime; the registry never embeds numeric UID/GID values. */
bool nl_daemon_identity_resolve_credentials(
    const nl_daemon_identity *identity, nl_daemon_credentials *credentials);
bool nl_daemon_identity_resolve_private_ipc_gid(
    const nl_daemon_identity *identity, gid_t *gid);

/*
 * Return a named binary beside the current server binary.  Immutable releases
 * install all native authorities in one build directory, so deriving from
 * /proc/self/exe binds authorization to that exact release.
 */
bool nl_daemon_identity_expected_release_binary(
    const char *binary, char *path, size_t path_size);
bool nl_daemon_identity_expected_executable(
    const nl_daemon_identity *identity, char *path, size_t path_size);

#endif
