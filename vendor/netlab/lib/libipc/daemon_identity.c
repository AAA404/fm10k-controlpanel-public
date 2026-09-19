#define _POSIX_C_SOURCE 200809L

#include "netlab/daemon_identity.h"
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REAL_ROOT(id_, name_) \
    { \
        (id_), NL_DAEMON_IDENTITY_REAL, (name_), (name_), \
        "root", "root", NULL, NULL, NL_DAEMON_PRIVATE_IPC_GROUP, \
        "/var/run/netlab/" name_ ".sock", \
        NL_DAEMON_CAPABILITY_MASK_ROOT, false \
    }

static const nl_daemon_identity g_daemon_identities[] = {
    {
        NL_DAEMON_INTERNAL, NL_DAEMON_IDENTITY_VIRTUAL, "internal", NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, 0, false,
    },
    REAL_ROOT(NL_DAEMON_MGMTD, "mgmtd"),
    REAL_ROOT(NL_DAEMON_CONFIGD, "configd"),
    REAL_ROOT(NL_DAEMON_IFD, "ifd"),
    REAL_ROOT(NL_DAEMON_RPD, "rpd"),
    {
        NL_DAEMON_CHASSISD, NL_DAEMON_IDENTITY_REAL, "chassisd", "chassisd",
        "netlab-chassisd", "netlab-chassisd",
        "netlab-chassisd", "netlab-chassisd",
        NL_DAEMON_PRIVATE_IPC_GROUP, "/var/run/netlab/chassisd.sock",
        0, true,
    },
    {
        NL_DAEMON_XCVRD, NL_DAEMON_IDENTITY_VIRTUAL, "xcvrd", NULL,
        NULL, NULL, NULL, NULL, NULL, "/var/run/netlab/switchd.sock",
        0, false,
    },
    REAL_ROOT(NL_DAEMON_SWITCHD, "switchd"),
    REAL_ROOT(NL_DAEMON_PACKETD, "packetd"),
    {
        NL_DAEMON_SNMPD, NL_DAEMON_IDENTITY_VIRTUAL, "snmpd", NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, 0, false,
    },
    REAL_ROOT(NL_DAEMON_LLDPD, "lldpd"),
    REAL_ROOT(NL_DAEMON_LACPD, "lacpd"),
    {
        NL_DAEMON_CLI, NL_DAEMON_IDENTITY_VIRTUAL, "cli", NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, 0, false,
    },
    REAL_ROOT(NL_DAEMON_LINKMOND, "linkmond"),
    REAL_ROOT(NL_DAEMON_L2D, "l2d"),
    REAL_ROOT(NL_DAEMON_STATSD, "statsd"),
    REAL_ROOT(NL_DAEMON_STPD, "stpd"),
    {
        NL_DAEMON_L3D, NL_DAEMON_IDENTITY_RETIRED, "l3d", NULL,
        NULL, NULL, NULL, NULL, NULL, NULL, 0, false,
    },
    {
        NL_DAEMON_IDENTITYD, NL_DAEMON_IDENTITY_REAL, "identityd",
        "identityd", "netlab-identityd", "netlab-identityd",
        "netlab-identityd", "netlab-identityd",
        NL_DAEMON_PRIVATE_IPC_GROUP, "/var/run/netlab/identityd.sock",
        NL_DAEMON_CAP_SYS_PTRACE_MASK, true,
    },
};

_Static_assert(NL_DAEMON_IDENTITYD == 18,
               "daemon identity registry requires contiguous wire IDs 0-18");
_Static_assert(
    sizeof(g_daemon_identities) / sizeof(g_daemon_identities[0]) ==
        (size_t)NL_DAEMON_IDENTITYD + 1U,
    "daemon identity registry must cover every wire ID");

static bool lookup_user(const char *name, uid_t *uid, gid_t *primary_gid) {
    struct passwd pwd;
    struct passwd *result = NULL;
    char buffer[65536];

    if (!name || !name[0] || !uid || !primary_gid ||
        getpwnam_r(name, &pwd, buffer, sizeof(buffer), &result) != 0 ||
        !result)
        return false;
    *uid = result->pw_uid;
    *primary_gid = result->pw_gid;
    return true;
}

static bool lookup_group(const char *name, gid_t *gid) {
    struct group group;
    struct group *result = NULL;
    char buffer[65536];

    if (!name || !name[0] || !gid ||
        getgrnam_r(name, &group, buffer, sizeof(buffer), &result) != 0 ||
        !result)
        return false;
    *gid = result->gr_gid;
    return true;
}

size_t nl_daemon_identity_count(void) {
    return sizeof(g_daemon_identities) / sizeof(g_daemon_identities[0]);
}

const nl_daemon_identity *nl_daemon_identity_at(size_t index) {
    return index < nl_daemon_identity_count() ?
        &g_daemon_identities[index] : NULL;
}

const nl_daemon_identity *nl_daemon_identity_lookup(nl_daemon_id wire_id) {
    size_t index;

    if ((int)wire_id < (int)NL_DAEMON_INTERNAL ||
        (int)wire_id > (int)NL_DAEMON_IDENTITYD)
        return NULL;
    index = (size_t)wire_id;
    if (g_daemon_identities[index].wire_id != wire_id)
        return NULL;
    return &g_daemon_identities[index];
}

const nl_daemon_identity *nl_daemon_identity_lookup_name(const char *name) {
    if (!name || !name[0])
        return NULL;
    for (size_t i = 0; i < nl_daemon_identity_count(); i++) {
        if (strcmp(g_daemon_identities[i].name, name) == 0)
            return &g_daemon_identities[i];
    }
    return NULL;
}

const char *nl_daemon_identity_kind_name(nl_daemon_identity_kind kind) {
    switch (kind) {
    case NL_DAEMON_IDENTITY_REAL:
        return "real";
    case NL_DAEMON_IDENTITY_VIRTUAL:
        return "virtual";
    case NL_DAEMON_IDENTITY_RETIRED:
        return "retired";
    }
    return "unknown";
}

bool nl_daemon_identity_is_peer_process(
    const nl_daemon_identity *identity) {
    return identity && identity->kind == NL_DAEMON_IDENTITY_REAL;
}

bool nl_daemon_identity_resolve_credentials(
    const nl_daemon_identity *identity, nl_daemon_credentials *credentials) {
    uid_t uid;
    gid_t passwd_gid;
    gid_t named_gid;

    if (!identity || !credentials || !identity->expected_account ||
        !identity->primary_group ||
        !lookup_user(identity->expected_account, &uid, &passwd_gid) ||
        !lookup_group(identity->primary_group, &named_gid) ||
        passwd_gid != named_gid)
        return false;
    credentials->uid = uid;
    credentials->primary_gid = named_gid;
    return true;
}

bool nl_daemon_identity_resolve_private_ipc_gid(
    const nl_daemon_identity *identity, gid_t *gid) {
    return identity && identity->private_ipc_group &&
        lookup_group(identity->private_ipc_group, gid);
}

bool nl_daemon_identity_expected_release_binary(
    const char *binary, char *path, size_t path_size) {
    char self[NL_DAEMON_EXECUTABLE_PATH_MAX];
    char *separator;
    ssize_t self_len;
    int path_len;

    if (!binary || !binary[0] || strchr(binary, '/') ||
        !path || path_size < 2)
        return false;
    path[0] = '\0';
    self_len = readlink("/proc/self/exe", self, sizeof(self) - 1U);
    if (self_len <= 0 || (size_t)self_len >= sizeof(self) - 1U)
        return false;
    self[self_len] = '\0';
    if (self[0] != '/' ||
        (self_len >= 10 &&
         strcmp(self + self_len - 10, " (deleted)") == 0))
        return false;
    separator = strrchr(self, '/');
    if (!separator || separator == self)
        return false;
    *separator = '\0';
    path_len = snprintf(path, path_size, "%s/%s", self, binary);
    if (path_len <= 0 || (size_t)path_len >= path_size) {
        path[0] = '\0';
        return false;
    }
    return true;
}

bool nl_daemon_identity_expected_executable(
    const nl_daemon_identity *identity, char *path, size_t path_size) {
    return nl_daemon_identity_is_peer_process(identity) &&
        identity->binary &&
        nl_daemon_identity_expected_release_binary(
            identity->binary, path, path_size);
}

bool nl_daemon_identity_registry_valid(void) {
    for (size_t i = 0; i < nl_daemon_identity_count(); i++) {
        const nl_daemon_identity *identity = &g_daemon_identities[i];

        if ((size_t)identity->wire_id != i || !identity->name ||
            !identity->name[0] ||
            ((identity->dedicated_account == NULL) !=
             (identity->dedicated_primary_group == NULL)))
            return false;
        for (size_t j = i + 1; j < nl_daemon_identity_count(); j++) {
            if (strcmp(identity->name, g_daemon_identities[j].name) == 0)
                return false;
        }
        if (identity->kind == NL_DAEMON_IDENTITY_REAL) {
            bool dedicated_active =
                identity->dedicated_account &&
                identity->expected_account &&
                identity->primary_group &&
                strcmp(identity->expected_account,
                       identity->dedicated_account) == 0 &&
                strcmp(identity->primary_group,
                       identity->dedicated_primary_group) == 0;

            if (!identity->binary || !identity->binary[0] ||
                strchr(identity->binary, '/') ||
                !identity->expected_account || !identity->primary_group ||
                !identity->private_ipc_group || !identity->socket_path ||
                strncmp(identity->socket_path, "/var/run/netlab/", 16) != 0 ||
                (dedicated_active &&
                 (!identity->no_new_privileges ||
                  identity->capability_mask ==
                      NL_DAEMON_CAPABILITY_MASK_ROOT)) ||
                (!dedicated_active &&
                 (identity->no_new_privileges ||
                  identity->capability_mask !=
                      NL_DAEMON_CAPABILITY_MASK_ROOT)))
                return false;
        } else if (identity->binary || identity->expected_account ||
                   identity->primary_group ||
                   identity->dedicated_account ||
                   identity->private_ipc_group ||
                   identity->capability_mask ||
                   identity->no_new_privileges) {
            return false;
        }
        if (identity->kind == NL_DAEMON_IDENTITY_RETIRED &&
            (identity->expected_account || identity->primary_group ||
             identity->dedicated_account || identity->private_ipc_group ||
             identity->socket_path))
            return false;
    }
    return true;
}
