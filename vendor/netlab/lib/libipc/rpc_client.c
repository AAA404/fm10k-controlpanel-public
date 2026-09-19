/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/ipc.h"
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    bool active;
    u64 expires_ms;
} nl_rpc_deadline_scope;

static _Thread_local nl_rpc_deadline_scope g_deadline_scope;
static pthread_once_t g_request_id_once = PTHREAD_ONCE_INIT;
static _Atomic u64 g_request_id;

static u64 monotonic_ms(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (u64)now.tv_sec * UINT64_C(1000) + (u64)now.tv_nsec / UINT64_C(1000000);
}

static void request_id_init(void) {
    u64 seed = 0;
    ssize_t n = getrandom(&seed, sizeof(seed), GRND_NONBLOCK);

    if (n != (ssize_t)sizeof(seed)) {
        seed = (monotonic_ms() << 16) ^ ((u64)(u32)getpid() << 32) ^
               (u64)(uintptr_t)&g_request_id;
    }
    if (seed == 0)
        seed = UINT64_C(1);
    atomic_store_explicit(&g_request_id, seed, memory_order_relaxed);
}

u64 nl_rpc_next_request_id(void) {
    u64 request_id;

    (void)pthread_once(&g_request_id_once, request_id_init);
    request_id = atomic_fetch_add_explicit(
        &g_request_id, UINT64_C(1), memory_order_relaxed);
    if (request_id == 0)
        request_id = atomic_fetch_add_explicit(
            &g_request_id, UINT64_C(1), memory_order_relaxed);
    return request_id;
}

void nl_rpc_deadline_scope_enter(u32 timeout_ms) {
    u64 now = monotonic_ms();

    memset(&g_deadline_scope, 0, sizeof(g_deadline_scope));
    if (timeout_ms == 0 || now == 0)
        return;
    g_deadline_scope.active = true;
    g_deadline_scope.expires_ms = now + timeout_ms;
    if (g_deadline_scope.expires_ms < now)
        g_deadline_scope.expires_ms = UINT64_MAX;
}

void nl_rpc_deadline_scope_leave(void) {
    memset(&g_deadline_scope, 0, sizeof(g_deadline_scope));
}

u32 nl_rpc_effective_timeout_ms(u32 requested_timeout_ms) {
    u64 now;
    u64 remaining;

    if (!g_deadline_scope.active)
        return requested_timeout_ms;
    now = monotonic_ms();
    if (now == 0 || now >= g_deadline_scope.expires_ms)
        return 0;
    remaining = g_deadline_scope.expires_ms - now;
    if (remaining > UINT32_MAX)
        remaining = UINT32_MAX;
    if (requested_timeout_ms == 0 || remaining < requested_timeout_ms)
        return (u32)remaining;
    return requested_timeout_ms;
}

void nl_rpc_response_free(nl_rpc_response *response) {
    if (!response)
        return;
    free(response->payload);
    memset(response, 0, sizeof(*response));
}

static int set_io_timeout(int fd, u32 timeout_ms) {
    struct timeval tv = {
        .tv_sec = (time_t)(timeout_ms / 1000),
        .tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000),
    };

    if (timeout_ms == 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
        return -1;
    return 0;
}

int nl_rpc_call_alloc_ex(const char *socket_path, nl_daemon_id caller,
                         nl_daemon_id service, nl_rpc_method method, u64 tx_id,
                         const u8 *payload, int payload_len, int timeout_ms,
                         nl_rpc_response *response) {
    const nl_rpc_contract *contract;
    nl_conn conn;
    nl_msg_hdr *msg = NULL;
    nl_msg_hdr *resp_msg = NULL;
    u64 request_id;
    u32 effective_timeout;
    int result = -1;

    if (response)
        memset(response, 0, sizeof(*response));
    if (!socket_path || !response || payload_len < 0 || timeout_ms <= 0)
        return -1;
    contract = nl_rpc_contract_lookup(service, method);
    if (!contract || !nl_rpc_contract_caller_allowed(contract, caller) ||
        !nl_rpc_contract_payload_valid(
            contract->request_format, payload, (u32)payload_len,
            contract->max_request_len) ||
        ((contract->flags & NL_RPC_CONTRACT_TX_ID_REQUIRED) && tx_id == 0))
        return -1;

    effective_timeout = nl_rpc_effective_timeout_ms((u32)timeout_ms);
    if (effective_timeout == 0)
        return -1;
    if (nl_client_connect_timeout(
            socket_path, &conn, effective_timeout) != NL_OK)
        return -1;
    effective_timeout = nl_rpc_effective_timeout_ms(effective_timeout);
    if (set_io_timeout(conn.fd, effective_timeout) != 0)
        goto out;

    request_id = nl_rpc_next_request_id();
    msg = nl_msg_alloc((u32)payload_len);
    if (!msg)
        goto out;
    msg->type = NL_MSG_REQUEST;
    msg->request_id = request_id;
    msg->tx_id = tx_id;
    msg->method = method;
    msg->daemon_id = caller;
    msg->timeout_ms = effective_timeout;
    msg->payload_len = (u32)payload_len;
    if (payload_len > 0)
        memcpy(msg->payload, payload, (size_t)payload_len);
    if (nl_send(&conn, msg) != NL_OK)
        goto out;
    if (nl_recv(&conn, &resp_msg) != NL_OK || !resp_msg)
        goto out;
    if ((resp_msg->type != NL_MSG_RESPONSE &&
         resp_msg->type != NL_MSG_ERROR) ||
        resp_msg->request_id != request_id)
        goto out;
    if (resp_msg->type == NL_MSG_RESPONSE &&
        !nl_rpc_contract_payload_valid(
            contract->response_format, resp_msg->payload,
            resp_msg->payload_len, contract->max_response_len))
        goto out;
    if (resp_msg->type == NL_MSG_ERROR &&
        resp_msg->payload_len > NETLAB_MAX_MSG)
        goto out;
    response->payload = calloc((size_t)resp_msg->payload_len + 1, 1);
    if (!response->payload)
        goto out;
    if (resp_msg->payload_len > 0)
        memcpy(response->payload, resp_msg->payload, resp_msg->payload_len);
    response->payload_len = resp_msg->payload_len;
    response->error_code = resp_msg->error_code;
    response->request_id = request_id;
    result = (int)response->payload_len;

out:
    nl_msg_free(msg);
    nl_msg_free(resp_msg);
    nl_client_close(&conn);
    if (result < 0)
        nl_rpc_response_free(response);
    return result;
}

int nl_rpc_call_ex(const char *socket_path, nl_daemon_id caller,
                   nl_daemon_id service, nl_rpc_method method, u64 tx_id,
                   const u8 *payload, int payload_len,
                   u8 *resp_buf, int max_resp, int timeout_ms,
                   s32 *error_code) {
    nl_rpc_response response;
    const nl_rpc_contract *contract = nl_rpc_contract_lookup(service, method);
    int result;

    if (error_code)
        *error_code = 0;
    if (!contract || max_resp < 0 || (!resp_buf && max_resp > 0) ||
        (max_resp == 0 && contract->response_format != NL_RPC_PAYLOAD_NONE))
        return -1;
    bool terminate = contract->response_format != NL_RPC_PAYLOAD_BINARY && resp_buf && max_resp > 0;
    if (terminate) resp_buf[0] = '\0';
    result = nl_rpc_call_alloc_ex(socket_path, caller, service, method, tx_id,
                                  payload, payload_len, timeout_ms, &response);
    if (result < 0)
        return -1;
    if (error_code)
        *error_code = response.error_code;
    /* A binary reply may fill its buffer exactly and must never receive a
     * string terminator. NONE replies also support a caller with no buffer. */
    if (response.payload_len > (u32)max_resp - (terminate ? 1U : 0U)) {
        nl_rpc_response_free(&response);
        return -1;
    }
    if (response.payload_len > 0)
        memcpy(resp_buf, response.payload, response.payload_len);
    if (terminate) resp_buf[response.payload_len] = '\0';
    result = (int)response.payload_len;
    nl_rpc_response_free(&response);
    return result;
}
