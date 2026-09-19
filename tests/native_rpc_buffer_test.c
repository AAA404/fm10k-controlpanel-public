/* Real RPC client/contract handling; only the socket peer is deterministic. */
#include "netlab/ipc.h"
#include "netlab/error.h"
#include "netlab/port_scope.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int peer = -1, sends;
static u64 request;
static u8 reply[32];
static u32 reply_length;
static s32 reply_error;
nl_status nl_client_connect_timeout(const char *path, nl_conn *out, u32 timeout) {
    (void)path; (void)timeout;
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
    memset(out, 0, sizeof(*out)); out->fd = pair[0]; peer = pair[1]; return NL_OK;
}
void nl_client_close(nl_conn *conn) { close(conn->fd); close(peer); conn->fd = -1; peer = -1; }
nl_msg_hdr *nl_msg_alloc(u32 length) { return calloc(1, sizeof(nl_msg_hdr) + length + 1U); }
void nl_msg_free(nl_msg_hdr *msg) { free(msg); }
nl_status nl_send(nl_conn *conn, nl_msg_hdr *msg) {
    (void)conn; request = msg->request_id; ++sends; return NL_OK;
}
nl_status nl_recv(nl_conn *conn, nl_msg_hdr **out) {
    (void)conn;
    *out = nl_msg_alloc(reply_length);
    (*out)->type = NL_MSG_RESPONSE; (*out)->request_id = request;
    (*out)->payload_len = reply_length; (*out)->error_code = reply_error;
    memcpy((*out)->payload, reply, reply_length);
    return NL_OK;
}
int main(void) {
    u8 guarded[7]; memset(guarded, 0xa5, sizeof(guarded));
    const u8 binary[4] = {0, 0xff, 0, 0x17};
    memcpy(reply, binary, sizeof(binary)); reply_length = sizeof(binary);
    s32 error = -1;
    assert(nl_rpc_call_ex("/fixture", NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD,
        NL_PORT_SCOPE_STATUS, 0, NULL, 0, guarded + 1, 4, 1000, &error) == 4);
    assert(!error && !memcmp(guarded + 1, binary, 4) && guarded[0] == 0xa5 && guarded[5] == 0xa5);
    reply_length = 5;
    assert(nl_rpc_call_ex("/fixture", NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD,
        NL_PORT_SCOPE_STATUS, 0, NULL, 0, guarded + 1, 4, 1000, &error) < 0);
    assert(guarded[0] == 0xa5 && guarded[5] == 0xa5);
    memcpy(reply, "text", 4); reply_length = 4;
    assert(nl_rpc_call_ex("/fixture", NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_FM10K_BOARD_GET, 0, (const u8 *)"contract", 8, guarded + 1, 4, 1000, &error) < 0);
    assert(nl_rpc_call_ex("/fixture", NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_FM10K_BOARD_GET, 0, (const u8 *)"contract", 8, guarded + 1, 5, 1000, &error) == 4);
    assert(!memcmp(guarded + 1, "text\0", 5) && guarded[6] == 0xa5);
    reply_length = 0;
    u8 bind[16] = {1};
    assert(nl_rpc_call_ex("/fixture", NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_FM10K_BIND, 42, bind, sizeof(bind), NULL, 0, 1000, &error) == 0 && !error);
    int before = sends;
    assert(nl_rpc_call_ex("/fixture", NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_FM10K_BOARD_GET, 0, NULL, 0, NULL, 0, 1000, &error) < 0 && sends == before);
    return 0;
}
