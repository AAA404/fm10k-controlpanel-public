/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_PACKETD_AUTHORITY_H
#define NETLAB_PACKETD_AUTHORITY_H

#include "netlab/ipc.h"
#include "netlab/process_identity.h"
#include <stdbool.h>

typedef enum {
    PACKETD_COMMAND_INVALID = 0,
    PACKETD_COMMAND_SUBSCRIBE,
    PACKETD_COMMAND_TX,
    PACKETD_COMMAND_CLASSIFY,
    PACKETD_COMMAND_INJECT_RX,
    PACKETD_COMMAND_STATS,
    PACKETD_COMMAND_RELOAD,
    PACKETD_COMMAND_SCOPE,
} packetd_command;

typedef struct {
    nl_process_identity_handle process;
    nl_daemon_id daemon_id;
    bool test_peer;
} packetd_peer_authority;

#define PACKETD_PEER_AUTHORITY_INITIALIZER \
    { \
        .process = NL_PROCESS_IDENTITY_HANDLE_INITIALIZER, \
        .daemon_id = NL_DAEMON_INTERNAL, \
        .test_peer = false, \
    }

void packetd_peer_authority_init(packetd_peer_authority *authority);
bool packetd_peer_authority_capture(
    const nl_conn *conn, packetd_peer_authority *authority);
bool packetd_peer_authority_authorize(
    const nl_conn *conn, packetd_peer_authority *authority,
    packetd_command command, const char *socket_path,
    bool test_control_enabled);
bool packetd_peer_authority_revalidate(
    const packetd_peer_authority *authority);
bool packetd_peer_authority_move(
    packetd_peer_authority *destination,
    packetd_peer_authority *source);
void packetd_peer_authority_close(packetd_peer_authority *authority);
bool packetd_test_socket_allowed(const char *path);
const char *packetd_command_name(packetd_command command);

#endif
