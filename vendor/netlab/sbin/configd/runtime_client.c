/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "runtime_client.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define STPD_SOCKET "/var/run/netlab/stpd.sock"
#define IFD_SOCKET "/var/run/netlab/ifd.sock"
#define LLDPD_SOCKET "/var/run/netlab/lldpd.sock"
#define LACPD_SOCKET "/var/run/netlab/lacpd.sock"
#define PACKETD_SOCKET "/var/run/netlab/packetd.sock"

static bool is_expected_reload_response(const char *name, const char *resp) {
    char expected[64];

    snprintf(expected, sizeof(expected), "%s reload complete", name);
    return strcmp(resp, expected) == 0;
}

static bool notify_runtime_daemon(const char *name, const char *socket_path,
                                  nl_daemon_id service,
                                  nl_rpc_method method) {
    char resp[128] = {0};
    s32 ec = 0;
    int rn = nl_rpc_call_ex(socket_path, NL_DAEMON_CONFIGD, service, method, 0,
                            NULL, 0, (u8 *)resp, sizeof(resp) - 1,
                            2000, &ec);

    if (rn < 0 || ec != 0) {
        NL_LOG_WARN("commit runtime reload notify failed daemon=%s rn=%d ec=%d",
                    name, rn, ec);
        return false;
    }
    if (rn == 0 || !is_expected_reload_response(name, resp)) {
        NL_LOG_WARN("commit runtime reload notify unexpected daemon=%s resp=%s",
                    name, resp);
        return false;
    }
    NL_LOG_INFO("commit runtime reload notified daemon=%s", name);
    return true;
}

static bool recv_packetd_record(
    nl_conn *conn, void *buffer, size_t expected) {
    return nl_recv_peer_record(
               conn, buffer, expected, MSG_TRUNC) ==
        (ssize_t)expected;
}

static bool notify_packetd_reload(void) {
    static const char reload_cmd[] = "reload";
    nl_conn conn;
    u32 cmd_len = htonl((u32)strlen(reload_cmd));
    u32 resp_len_net = 0;
    u32 resp_len = 0;
    char resp[128] = {0};

    if (nl_client_connect_timeout(
            nl_ipc_socket_path_from_env("NETLAB_PACKETD_SOCKET", PACKETD_SOCKET), &conn, 2000) != NL_OK) {
        NL_LOG_WARN("commit runtime reload notify failed daemon=packetd connect");
        return false;
    }

    if (nl_send_record(&conn, &cmd_len, sizeof(cmd_len)) != NL_OK ||
        nl_send_record(
            &conn, reload_cmd, strlen(reload_cmd)) != NL_OK ||
        !recv_packetd_record(
            &conn, &resp_len_net, sizeof(resp_len_net))) {
        NL_LOG_WARN("commit runtime reload notify failed daemon=packetd io");
        nl_client_close(&conn);
        return false;
    }

    resp_len = ntohl(resp_len_net);
    if (resp_len == 0 || resp_len >= sizeof(resp) ||
        !recv_packetd_record(&conn, resp, resp_len)) {
        NL_LOG_WARN("commit runtime reload notify failed daemon=packetd response");
        nl_client_close(&conn);
        return false;
    }

    if (is_expected_reload_response("packetd", resp))
        NL_LOG_INFO("commit runtime reload notified daemon=packetd");
    else
        NL_LOG_WARN("commit runtime reload notify unexpected daemon=packetd resp=%s",
                    resp);
    nl_client_close(&conn);
    return is_expected_reload_response("packetd", resp);
}

void configd_runtime_notify_reload(void) {
    notify_runtime_daemon("l2d", nl_ipc_socket_path_from_env("NETLAB_L2D_SOCKET", "/var/run/netlab/l2d.sock"),
                          NL_DAEMON_L2D, NL_L2D_RELOAD);
    notify_runtime_daemon("ifd", nl_ipc_socket_path_from_env("NETLAB_IFD_SOCKET", IFD_SOCKET), NL_DAEMON_IFD, NL_IFD_RELOAD);
    notify_runtime_daemon("stpd", nl_ipc_socket_path_from_env("NETLAB_STPD_SOCKET", STPD_SOCKET), NL_DAEMON_STPD,
                          NL_STPD_RELOAD);
    notify_runtime_daemon("lldpd", nl_ipc_socket_path_from_env("NETLAB_LLDPD_SOCKET", LLDPD_SOCKET), NL_DAEMON_LLDPD,
                          NL_LLDPD_RELOAD);
    notify_runtime_daemon("lacpd", nl_ipc_socket_path_from_env("NETLAB_LACPD_SOCKET", LACPD_SOCKET), NL_DAEMON_LACPD,
                          NL_LACPD_RELOAD);
    notify_packetd_reload();
}

bool configd_runtime_reload_checked(void) {
    bool ok = true;
    ok = notify_runtime_daemon("l2d", nl_ipc_socket_path_from_env("NETLAB_L2D_SOCKET", "/var/run/netlab/l2d.sock"),
                                NL_DAEMON_L2D, NL_L2D_RELOAD) && ok;
    ok = notify_runtime_daemon("ifd", nl_ipc_socket_path_from_env("NETLAB_IFD_SOCKET", IFD_SOCKET), NL_DAEMON_IFD, NL_IFD_RELOAD) && ok;
    ok = notify_runtime_daemon("stpd", nl_ipc_socket_path_from_env("NETLAB_STPD_SOCKET", STPD_SOCKET), NL_DAEMON_STPD, NL_STPD_RELOAD) && ok;
    ok = notify_runtime_daemon("lldpd", nl_ipc_socket_path_from_env("NETLAB_LLDPD_SOCKET", LLDPD_SOCKET), NL_DAEMON_LLDPD, NL_LLDPD_RELOAD) && ok;
    ok = notify_runtime_daemon("lacpd", nl_ipc_socket_path_from_env("NETLAB_LACPD_SOCKET", LACPD_SOCKET), NL_DAEMON_LACPD, NL_LACPD_RELOAD) && ok;
    return notify_packetd_reload() && ok;
}
