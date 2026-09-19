#include "mgmtd.h"
#include "netlab/error.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>

#define MGMTD_DEFAULT_TIMEOUT_MS 10000
#define MGMTD_MAX_TIMEOUT_MS     60000

static int request_timeout_ms(const nl_msg_hdr *msg) {
    u32 timeout_ms = msg ? msg->timeout_ms : 0;

    if (timeout_ms == 0)
        return MGMTD_DEFAULT_TIMEOUT_MS;
    if (timeout_ms > MGMTD_MAX_TIMEOUT_MS)
        return MGMTD_MAX_TIMEOUT_MS;
    return (int)timeout_ms;
}

static s32 forward_nl_rpc(nl_conn *client_conn, nl_msg_hdr *msg,
                          nl_conn *backend, const mgmtd_route *route) {
    nl_msg_hdr *forwarded = NULL;
    nl_msg_hdr *resp = NULL;
    u32 timeout_ms;
    s32 result = NL_ERR_DAEMON_UNREACHABLE;

    timeout_ms = nl_rpc_effective_timeout_ms(
        (u32)request_timeout_ms(msg));
    if (timeout_ms == 0) {
        nl_send_response(client_conn, msg->request_id, NL_ERR_RPC_TIMEOUT);
        return NL_ERR_RPC_TIMEOUT;
    }
    forwarded = nl_msg_alloc(msg->payload_len);
    if (!forwarded) {
        nl_send_response(client_conn, msg->request_id, NL_ERR_RPC_TIMEOUT);
        return NL_ERR_RPC_TIMEOUT;
    }
    memcpy(forwarded, msg, NL_HDR_SIZE + msg->payload_len);
    forwarded->daemon_id = NL_DAEMON_MGMTD;
    forwarded->timeout_ms = timeout_ms;

    if (nl_send(backend, forwarded) != NL_OK) {
        nl_send_response(client_conn, msg->request_id, NL_ERR_RPC_TIMEOUT);
        nl_msg_free(forwarded);
        return NL_ERR_RPC_TIMEOUT;
    }
    nl_msg_free(forwarded);

    if (nl_recv(backend, &resp) == NL_OK && resp &&
        (resp->type == NL_MSG_RESPONSE || resp->type == NL_MSG_ERROR) &&
        resp->request_id == msg->request_id && route && route->contract &&
        (resp->type == NL_MSG_ERROR ||
         nl_rpc_contract_payload_valid(
             route->contract->response_format, resp->payload,
             resp->payload_len, route->contract->max_response_len))) {
        result = resp->error_code;
        if (nl_send(client_conn, resp) != NL_OK)
            result = NL_ERR_RPC_TIMEOUT;
        nl_msg_free(resp);
    } else {
        nl_msg_free(resp);
        nl_send_response(client_conn, msg->request_id,
                         NL_ERR_DAEMON_UNREACHABLE);
    }

    return result;
}

static bool recv_packetd_record(
    nl_conn *conn, void *buffer, size_t expected) {
    return nl_recv_peer_record(
               conn, buffer, expected, MSG_TRUNC) ==
        (ssize_t)expected;
}

static s32 forward_packetd_command(nl_conn *client_conn, nl_msg_hdr *msg,
                                   nl_conn *backend, const char *cmd) {
    u32 cmd_len;
    u32 resp_len_net = 0;
    u32 resp_len = 0;
    char payload[8192];
    nl_msg_hdr *resp;

    if (!cmd || !cmd[0]) {
        nl_send_response(client_conn, msg->request_id,
                         NL_ERR_MALFORMED_REQUEST);
        return NL_ERR_MALFORMED_REQUEST;
    }

    cmd_len = htonl((u32)strlen(cmd));
    if (nl_send_record(backend, &cmd_len, sizeof(cmd_len)) != NL_OK ||
        nl_send_record(backend, cmd, strlen(cmd)) != NL_OK) {
        nl_send_response(client_conn, msg->request_id, NL_ERR_RPC_TIMEOUT);
        return NL_ERR_RPC_TIMEOUT;
    }

    if (!recv_packetd_record(
            backend, &resp_len_net, sizeof(resp_len_net))) {
        nl_send_response(client_conn, msg->request_id,
                         NL_ERR_DAEMON_UNREACHABLE);
        return NL_ERR_DAEMON_UNREACHABLE;
    }

    resp_len = ntohl(resp_len_net);
    if (resp_len == 0 || resp_len >= sizeof(payload)) {
        nl_send_response(client_conn, msg->request_id,
                         NL_ERR_MALFORMED_REQUEST);
        return NL_ERR_MALFORMED_REQUEST;
    }

    if (!recv_packetd_record(backend, payload, resp_len)) {
        nl_send_response(client_conn, msg->request_id,
                         NL_ERR_DAEMON_UNREACHABLE);
        return NL_ERR_DAEMON_UNREACHABLE;
    }

    resp = nl_msg_alloc(resp_len);
    if (!resp) {
        nl_send_response(client_conn, msg->request_id, NL_ERR_RPC_TIMEOUT);
        return NL_ERR_RPC_TIMEOUT;
    }
    resp->type = NL_MSG_RESPONSE;
    resp->request_id = msg->request_id;
    resp->payload_len = resp_len;
    memcpy(resp->payload, payload, resp_len);
    if (nl_send(client_conn, resp) != NL_OK) {
        nl_msg_free(resp);
        return NL_ERR_RPC_TIMEOUT;
    }
    nl_msg_free(resp);
    return 0;
}

static s32 forward_packetd_stats(nl_conn *client_conn, nl_msg_hdr *msg,
                                 nl_conn *backend) {
    return forward_packetd_command(client_conn, msg, backend, "stats");
}

static s32 forward_packetd_reload(nl_conn *client_conn, nl_msg_hdr *msg,
                                  nl_conn *backend) {
    return forward_packetd_command(client_conn, msg, backend, "reload");
}

s32 mgmtd_forward_to_backend(nl_conn *client_conn, nl_msg_hdr *msg,
                             const mgmtd_route *route) {
    nl_conn backend;
    int timeout_ms;
    struct timeval tv;
    s32 result;

    if (!client_conn || !msg || !route || !route->socket_path) {
        if (client_conn && msg)
            nl_send_response(client_conn, msg->request_id,
                             NL_ERR_MALFORMED_REQUEST);
        return NL_ERR_MALFORMED_REQUEST;
    }

    timeout_ms = (int)nl_rpc_effective_timeout_ms(
        (u32)request_timeout_ms(msg));
    if (timeout_ms <= 0) {
        nl_send_response(client_conn, msg->request_id, NL_ERR_RPC_TIMEOUT);
        return NL_ERR_RPC_TIMEOUT;
    }
    if (nl_client_connect_timeout(
            route->socket_path, &backend, (u32)timeout_ms) != NL_OK) {
        NL_LOG_ERR("mgmtd: cannot connect to %s", route->socket_path);
        nl_send_response(client_conn, msg->request_id,
                         NL_ERR_DAEMON_UNREACHABLE);
        return NL_ERR_DAEMON_UNREACHABLE;
    }

    timeout_ms = (int)nl_rpc_effective_timeout_ms((u32)timeout_ms);
    if (timeout_ms <= 0) {
        nl_client_close(&backend);
        nl_send_response(client_conn, msg->request_id, NL_ERR_RPC_TIMEOUT);
        return NL_ERR_RPC_TIMEOUT;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(backend.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(backend.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    switch (route->adapter) {
    case MGMTD_BACKEND_PACKETD_STATS:
        result = forward_packetd_stats(client_conn, msg, &backend);
        break;
    case MGMTD_BACKEND_PACKETD_RELOAD:
        result = forward_packetd_reload(client_conn, msg, &backend);
        break;
    case MGMTD_BACKEND_NL_RPC:
    default:
        result = forward_nl_rpc(client_conn, msg, &backend, route);
        break;
    }

    nl_client_close(&backend);
    return result;
}
