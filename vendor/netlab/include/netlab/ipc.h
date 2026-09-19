#ifndef NETLAB_IPC_H
#define NETLAB_IPC_H

#include "types.h"
#include "ipc_contract.h"
#include <sys/un.h>
#include <sys/socket.h>

#define NETLAB_MAGIC     0x4e454c42
#define NETLAB_MAX_MSG   (256 * 1024)
#define NETLAB_CONFIG_XML_MAX (NETLAB_MAX_MSG - 4096U)
#define NETLAB_IPC_PATH  "/var/run/netlab"

#define NETLAB_IPC_SCHEMA_V1      1
#define NETLAB_IPC_SCHEMA_V2      2
#define NETLAB_IPC_SCHEMA_CURRENT NETLAB_IPC_SCHEMA_V2

/* Schema V2 transport flags. Application flags occupy the lower bits. */
#define NL_MSG_F_CHUNKED     0x80000000U
#define NL_MSG_F_CHUNK_FIRST 0x40000000U
#define NL_MSG_F_CHUNK_LAST  0x20000000U
#define NL_MSG_F_TRANSPORT_MASK \
    (NL_MSG_F_CHUNKED | NL_MSG_F_CHUNK_FIRST | NL_MSG_F_CHUNK_LAST)

/* Keep every physical AF_UNIX SOCK_SEQPACKET frame well below host limits. */
#define NETLAB_IPC_CHUNK_DATA_MAX (64 * 1024)

int nl_ipc_socket_path_safe(const char *path);
const char *nl_ipc_socket_path_from_env(const char *env_name,
                                        const char *fallback);
nl_status nl_ipc_unlink_socket(const char *path);

typedef enum {
    NL_MSG_REQUEST  = 0,
    NL_MSG_RESPONSE = 1,
    NL_MSG_EVENT    = 2,
    NL_MSG_ERROR    = 3,
} nl_msg_type;

typedef struct __attribute__((packed)) {
    u32 magic;
    u16 schema_version;
    u16 type;
    u64 request_id;
    u64 tx_id;
    u16 daemon_id;
    u16 method;
    u32 flags;
    s32 error_code;
    u32 timeout_ms;
    u32 payload_len;
    u8  payload[];
} nl_msg_hdr;

#define NL_HDR_SIZE offsetof(nl_msg_hdr, payload)

typedef struct __attribute__((packed)) {
    u32 total_payload_len;
    u32 offset;
    u32 data_len;
} nl_ipc_chunk_hdr;

#define NL_IPC_CHUNK_HDR_SIZE sizeof(nl_ipc_chunk_hdr)
#define NETLAB_IPC_MAX_FRAME \
    (NL_HDR_SIZE + NL_IPC_CHUNK_HDR_SIZE + NETLAB_IPC_CHUNK_DATA_MAX)

typedef struct {
    int fd;
    struct sockaddr_un addr;
    char peername[64];
    uid_t peer_uid;
    gid_t peer_gid;
    pid_t peer_pid;
    u16   daemon_id;
    u16   peer_schema_version;
    bool  peer_schema_known;
    bool  peer_credentials_enabled;
    bool  peer_authenticated;
} nl_conn;

// Server
nl_status nl_server_listen(const char *path, int *fd);
nl_status nl_server_accept(int listen_fd, nl_conn *conn);
/*
 * Complete the server-issued nonce challenge only after the caller has
 * captured the SO_PEERCRED PID's stable executable identity.
 */
nl_status nl_server_authenticate(nl_conn *conn);
nl_status nl_server_authenticate_timeout(nl_conn *conn, u32 timeout_ms);

// Client
nl_status nl_client_connect(const char *path, nl_conn *conn);
nl_status nl_client_connect_timeout(
    const char *path, nl_conn *conn, u32 timeout_ms);
void      nl_client_close(nl_conn *conn);

// Send / Recv
nl_status nl_send(nl_conn *conn, nl_msg_hdr *msg);
nl_status nl_recv(nl_conn *conn, nl_msg_hdr **msg);
nl_status nl_send_response(nl_conn *conn, u64 request_id, s32 error_code);
/* Send one application-defined SOCK_SEQPACKET record after authentication. */
nl_status nl_send_record(
    nl_conn *conn, const void *buffer, size_t length);
/*
 * Receive one raw record and require its SCM_CREDENTIALS to match the
 * authenticated effective peer.  A root-prebound dedicated listener may
 * transition once during the client challenge; subsequent records remain
 * pinned to the registry UID/GID established by that challenge.
 */
ssize_t nl_recv_peer_record(nl_conn *conn, void *buffer, size_t capacity,
                            int flags);

// Peer credentials
nl_status nl_get_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid);

// Allocated and received messages reserve one trailing byte;
// payload[payload_len] is always '\0' without changing payload_len. Binary
// payload consumers must continue to use payload_len rather than the sentinel.
nl_msg_hdr *nl_msg_alloc(u32 payload_len);
void        nl_msg_free(nl_msg_hdr *msg);

typedef struct {
    u8 *payload;
    u32 payload_len;
    s32 error_code;
    u64 request_id;
} nl_rpc_response;

u64 nl_rpc_next_request_id(void);
void nl_rpc_deadline_scope_enter(u32 timeout_ms);
void nl_rpc_deadline_scope_leave(void);
u32 nl_rpc_effective_timeout_ms(u32 requested_timeout_ms);

// Contract-aware RPC with a dynamically allocated, NUL-padded response.
// Returns payload length on success, -1 on transport/contract failure.
int nl_rpc_call_alloc_ex(const char *socket_path, nl_daemon_id caller,
                         nl_daemon_id service, nl_rpc_method method, u64 tx_id,
                         const u8 *payload, int payload_len, int timeout_ms,
                         nl_rpc_response *response);
void nl_rpc_response_free(nl_rpc_response *response);

// Fixed-buffer adapter for bounded call sites. New variable-size consumers
// should use nl_rpc_call_alloc_ex instead of guessing a response capacity.
int nl_rpc_call_ex(const char *socket_path, nl_daemon_id caller,
                   nl_daemon_id service, nl_rpc_method method, u64 tx_id,
                   const u8 *payload, int payload_len,
                   u8 *resp_buf, int max_resp, int timeout_ms,
                   s32 *error_code);

#endif
