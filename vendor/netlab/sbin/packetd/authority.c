/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "authority.h"
#include "netlab/daemon_identity.h"
#include <string.h>

#define PACKETD_PRODUCTION_SOCKET "/var/run/netlab/packetd.sock"

bool packetd_test_socket_allowed(const char *path) {
    return path && path[0] == '/' &&
        nl_ipc_socket_path_safe(path) &&
        (strncmp(path, "/tmp/", 5) == 0 ||
         strncmp(path, "/var/tmp/", 9) == 0) &&
        strcmp(path, PACKETD_PRODUCTION_SOCKET) != 0;
}

static bool verify_real_peer(
    const nl_conn *conn, const nl_process_identity_handle *process,
    nl_daemon_id daemon_id) {
    const nl_daemon_identity *identity =
        nl_daemon_identity_lookup(daemon_id);
    nl_process_identity_expectation expectation;
    nl_daemon_credentials credentials;
    char executable[NL_DAEMON_EXECUTABLE_PATH_MAX];

    if (!conn || !process ||
        !nl_daemon_identity_is_peer_process(identity) ||
        !nl_daemon_identity_resolve_credentials(identity, &credentials) ||
        conn->peer_uid != credentials.uid ||
        conn->peer_gid != credentials.primary_gid ||
        !nl_daemon_identity_expected_executable(
            identity, executable, sizeof(executable)))
        return false;

    memset(&expectation, 0, sizeof(expectation));
    expectation.check_euid = true;
    expectation.euid = credentials.uid;
    expectation.check_egid = true;
    expectation.egid = credentials.primary_gid;
    expectation.executable = executable;
    return nl_process_identity_verify(
               process, &expectation, NULL) == NL_PROCESS_IDENTITY_OK;
}

static bool authorize_one_of(
    const nl_conn *conn, packetd_peer_authority *authority,
    const nl_daemon_id *allowed, size_t allowed_count) {
    if (!conn || !authority || !allowed || allowed_count == 0)
        return false;
    for (size_t i = 0; i < allowed_count; i++) {
        if (verify_real_peer(conn, &authority->process, allowed[i])) {
            authority->daemon_id = allowed[i];
            authority->test_peer = false;
            return true;
        }
    }
    return false;
}

static bool authorize_test_peer(
    const nl_conn *conn, packetd_peer_authority *authority,
    packetd_command command, const char *socket_path,
    bool test_control_enabled) {
    bool command_allowed =
        command == PACKETD_COMMAND_CLASSIFY ||
        command == PACKETD_COMMAND_INJECT_RX ||
        command == PACKETD_COMMAND_STATS;

    if (!conn || !authority || !test_control_enabled || !command_allowed ||
        !packetd_test_socket_allowed(socket_path) ||
        !verify_real_peer(conn, &authority->process, NL_DAEMON_PACKETD))
        return false;
    authority->daemon_id = NL_DAEMON_PACKETD;
    authority->test_peer = true;
    return true;
}

void packetd_peer_authority_init(packetd_peer_authority *authority) {
    if (!authority)
        return;
    nl_process_identity_init(&authority->process);
    authority->daemon_id = NL_DAEMON_INTERNAL;
    authority->test_peer = false;
}

bool packetd_peer_authority_capture(
    const nl_conn *conn, packetd_peer_authority *authority) {
    nl_process_identity_result result;

    if (!conn || !authority || conn->peer_pid <= 0)
        return false;
    packetd_peer_authority_init(authority);
    result = nl_process_identity_open(conn->peer_pid, &authority->process);
    if (result != NL_PROCESS_IDENTITY_OK)
        return false;
    if (authority->process.baseline.pid != conn->peer_pid ||
        authority->process.baseline.euid != conn->peer_uid ||
        authority->process.baseline.egid != conn->peer_gid) {
        packetd_peer_authority_close(authority);
        return false;
    }
    return true;
}

bool packetd_peer_authority_authorize(
    const nl_conn *conn, packetd_peer_authority *authority,
    packetd_command command, const char *socket_path,
    bool test_control_enabled) {
    static const nl_daemon_id subscribe_callers[] = {
        NL_DAEMON_L2D,
        NL_DAEMON_LLDPD,
        NL_DAEMON_LACPD,
        NL_DAEMON_STPD,
    };
    static const nl_daemon_id tx_callers[] = {
        NL_DAEMON_LLDPD,
        NL_DAEMON_LACPD,
        NL_DAEMON_STPD,
    };
    static const nl_daemon_id stats_callers[] = {
        NL_DAEMON_MGMTD,
    };
    static const nl_daemon_id reload_callers[] = {
        NL_DAEMON_MGMTD,
        NL_DAEMON_CONFIGD,
    };
    const nl_daemon_id *allowed = NULL;
    size_t allowed_count = 0;

    if (!conn || !authority || authority->process.fd < 0)
        return false;
    switch (command) {
    case PACKETD_COMMAND_SUBSCRIBE:
        allowed = subscribe_callers;
        allowed_count =
            sizeof(subscribe_callers) / sizeof(subscribe_callers[0]);
        break;
    case PACKETD_COMMAND_TX:
        allowed = tx_callers;
        allowed_count = sizeof(tx_callers) / sizeof(tx_callers[0]);
        break;
    case PACKETD_COMMAND_STATS:
        allowed = stats_callers;
        allowed_count =
            sizeof(stats_callers) / sizeof(stats_callers[0]);
        break;
    case PACKETD_COMMAND_SCOPE:
    case PACKETD_COMMAND_RELOAD:
        allowed = reload_callers;
        allowed_count =
            sizeof(reload_callers) / sizeof(reload_callers[0]);
        break;
    case PACKETD_COMMAND_CLASSIFY:
    case PACKETD_COMMAND_INJECT_RX:
    case PACKETD_COMMAND_INVALID:
        break;
    }
    if (allowed &&
        authorize_one_of(conn, authority, allowed, allowed_count))
        return true;
    return authorize_test_peer(
        conn, authority, command, socket_path, test_control_enabled);
}

bool packetd_peer_authority_revalidate(
    const packetd_peer_authority *authority) {
    return authority && authority->process.fd >= 0 &&
        nl_process_identity_revalidate(
            &authority->process, NULL) == NL_PROCESS_IDENTITY_OK;
}

bool packetd_peer_authority_move(
    packetd_peer_authority *destination,
    packetd_peer_authority *source) {
    if (!destination || !source ||
        destination->process.fd != -1 ||
        destination->process.kind != NL_PROCESS_HANDLE_NONE ||
        !nl_process_identity_move(
            &destination->process, &source->process))
        return false;
    destination->daemon_id = source->daemon_id;
    destination->test_peer = source->test_peer;
    source->daemon_id = NL_DAEMON_INTERNAL;
    source->test_peer = false;
    return true;
}

void packetd_peer_authority_close(packetd_peer_authority *authority) {
    if (!authority)
        return;
    nl_process_identity_close(&authority->process);
    authority->daemon_id = NL_DAEMON_INTERNAL;
    authority->test_peer = false;
}

const char *packetd_command_name(packetd_command command) {
    switch (command) {
    case PACKETD_COMMAND_SUBSCRIBE:
        return "subscribe";
    case PACKETD_COMMAND_TX:
        return "tx";
    case PACKETD_COMMAND_CLASSIFY:
        return "classify";
    case PACKETD_COMMAND_INJECT_RX:
        return "inject-rx";
    case PACKETD_COMMAND_STATS:
        return "stats";
    case PACKETD_COMMAND_RELOAD:
        return "reload";
    case PACKETD_COMMAND_SCOPE:
        return "scope";
    case PACKETD_COMMAND_INVALID:
        return "invalid";
    }
    return "invalid";
}
