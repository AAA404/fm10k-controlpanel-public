/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "lacp_packet_io.h"
#include "netlab/packet_event.h"
#include "netlab/port_scope.h"
#include "netlab/hal.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static nl_conn g_packetd_subscription = {.fd = -1};

static int read_packetd_record(
    nl_conn *conn, void *buffer, int expected) {
    if (expected <= 0)
        return -1;
    return nl_recv_peer_record(
               conn, buffer, (size_t)expected, MSG_TRUNC) == expected ?
        expected : -1;
}

int lacp_packet_tx(const char *socket_path, int port,
                   const u8 *frame, int frame_len) {
    nl_conn conn;
    char header[32];
    u8 msg[2048];
    u8 resp[64];
    u32 net_len;
    int header_len;
    int msg_len;
    int resp_len;

    if (!socket_path || port <= 0 || !frame || frame_len <= 0)
        return -1;
    u64 issued_at = nl_port_scope_clock();
    if (nl_client_connect(socket_path, &conn) != NL_OK)
        return -1;

    header_len = snprintf(header, sizeof(header), "tx %d %016llx\n", port, (unsigned long long)issued_at);
    if (header_len <= 0 || header_len >= (int)sizeof(header) ||
        header_len + frame_len > (int)sizeof(msg)) {
        nl_client_close(&conn);
        return -1;
    }
    memcpy(msg, header, (size_t)header_len);
    memcpy(msg + header_len, frame, (size_t)frame_len);
    msg_len = header_len + frame_len;

    net_len = htonl((u32)msg_len);
    if (nl_send_record(&conn, &net_len, sizeof(net_len)) != NL_OK ||
        nl_send_record(&conn, msg, (size_t)msg_len) != NL_OK) {
        nl_client_close(&conn);
        return -1;
    }

    if (read_packetd_record(
            &conn, &net_len, sizeof(net_len)) !=
            (int)sizeof(net_len)) {
        nl_client_close(&conn);
        return -1;
    }
    resp_len = (int)ntohl(net_len);
    if (resp_len <= 0 || resp_len >= (int)sizeof(resp) ||
        read_packetd_record(&conn, resp, resp_len) != resp_len) {
        nl_client_close(&conn);
        return -1;
    }
    nl_client_close(&conn);
    return resp_len >= 3 && memcmp(resp, "ok\n", 3) == 0 ? 0 : -1;
}

static bool packetd_subscribe(
    const char *socket_path, u16 ethertype, nl_conn *conn) {
    char sub[32];
    int len;
    u32 net_len;

    if (!socket_path || !conn)
        return false;
    if (nl_client_connect(socket_path, conn) != NL_OK)
        return false;

    len = snprintf(sub, sizeof(sub), "subscribe %04x", ethertype);
    net_len = htonl((u32)len);
    if (nl_send_record(conn, &net_len, sizeof(net_len)) != NL_OK ||
        nl_send_record(conn, sub, (size_t)len) != NL_OK) {
        nl_client_close(conn);
        return false;
    }
    return true;
}

static int wait_readable(int fd, int timeout_sec,
                         volatile sig_atomic_t *running) {
    fd_set rfds;
    struct timeval tv = {timeout_sec, 0};
    int r;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    do {
        r = select(fd + 1, &rfds, NULL, NULL, &tv);
    } while (r < 0 && errno == EINTR && (!running || *running));

    if (r < 0)
        return -1;
    return r > 0 ? 1 : 0;
}

int lacp_packet_read_event(const char *socket_path, u16 ethertype,
                           int idle_sec,
                           volatile sig_atomic_t *running,
                           u8 *frame, int frame_max, int *src_port, u64 *captured_at) {
    u32 net_len;
    u8 event[NETLAB_PACKET_IO_MAX + NL_PACKET_EVENT_HEADER];
    int ready;
    int len;
    int frame_len;

    if (g_packetd_subscription.fd < 0) {
        if (!packetd_subscribe(
                socket_path, ethertype, &g_packetd_subscription)) {
            sleep(1);
            return -1;
        }
    }

    ready = wait_readable(
        g_packetd_subscription.fd, idle_sec, running);
    if (ready == 0)
        return 0;
    if (ready < 0) {
        NL_LOG_WARN("LACP packetd subscription wait failed; reconnecting");
        nl_client_close(&g_packetd_subscription);
        return -1;
    }

    if (read_packetd_record(
            &g_packetd_subscription, &net_len, sizeof(net_len)) !=
            (int)sizeof(net_len)) {
        NL_LOG_WARN("LACP packetd subscription lost; reconnecting");
        nl_client_close(&g_packetd_subscription);
        return -1;
    }
    len = (int)ntohl(net_len);
    if (len < 4 || len > (int)sizeof(event)) {
        nl_client_close(&g_packetd_subscription);
        return -1;
    }
    if (read_packetd_record(
            &g_packetd_subscription, event, len) != len) {
        NL_LOG_WARN("LACP packetd event read failed; reconnecting");
        nl_client_close(&g_packetd_subscription);
        return -1;
    }

    int port, vlan;
    u64 stamp;
    int header = nl_packet_event_decode(event, len, &port, &vlan, &stamp);
    if (header < 0) return -1;
    if (src_port) *src_port = port;
    if (captured_at) *captured_at = stamp;
    frame_len = len - header;
    if (frame_len > frame_max)
        frame_len = frame_max;
    memcpy(frame, event + header, (size_t)frame_len);
    return frame_len;
}

void lacp_packet_close_subscription(void) {
    nl_client_close(&g_packetd_subscription);
}
