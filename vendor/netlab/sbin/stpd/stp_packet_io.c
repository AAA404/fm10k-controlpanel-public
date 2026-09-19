/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "stp_packet_io.h"

#include "netlab/ipc.h"
#include "netlab/port_scope.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

int stp_packet_read_record(nl_conn *conn, void *buf, int len) {
    if (len <= 0)
        return -1;
    return nl_recv_peer_record(
               conn, buf, (size_t)len, MSG_TRUNC) == len ?
        len : -1;
}

int stp_packet_tx(const char *socket_path, int port,
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

    if (stp_packet_read_record(
            &conn, &net_len, sizeof(net_len)) !=
            (int)sizeof(net_len)) {
        nl_client_close(&conn);
        return -1;
    }
    resp_len = (int)ntohl(net_len);
    if (resp_len <= 0 || resp_len >= (int)sizeof(resp) ||
        stp_packet_read_record(&conn, resp, resp_len) != resp_len) {
        nl_client_close(&conn);
        return -1;
    }
    nl_client_close(&conn);
    return resp_len >= 3 && memcmp(resp, "ok\n", 3) == 0 ? 0 : -1;
}

bool stp_packet_subscribe(
    const char *socket_path, u16 synthetic_type, nl_conn *conn) {
    char sub[32];
    int len;
    u32 net_len;

    if (!socket_path || !conn)
        return false;
    if (nl_client_connect(socket_path, conn) != NL_OK)
        return false;

    len = snprintf(sub, sizeof(sub), "subscribe %04x", synthetic_type);
    net_len = htonl((u32)len);
    if (nl_send_record(conn, &net_len, sizeof(net_len)) != NL_OK ||
        nl_send_record(conn, sub, (size_t)len) != NL_OK) {
        nl_client_close(conn);
        return false;
    }
    return true;
}

int stp_packet_wait_readable(int fd, int timeout_sec,
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
