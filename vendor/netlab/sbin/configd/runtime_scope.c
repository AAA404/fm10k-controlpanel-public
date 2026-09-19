#include "runtime_scope.h"
#include "runtime_client.h"
#include "netlab/port_scope.h"
#include "netlab/fm10k_plan_codec.h"
#include "netlab/ipc.h"
#include "netlab/error.h"
#include "netlab/l2_plan.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static bool engaged;
static u64 not_dispatched;
bool configd_scope_was_not_dispatched(u64 tx) { return tx && tx == not_dispatched; }
bool configd_scope_engaged(void) { return engaged; }
static const struct { nl_daemon_id id; const char *name, *env, *path; } peers[] = {
    {NL_DAEMON_PACKETD, "packetd", "NETLAB_PACKETD_SOCKET", "/var/run/netlab/packetd.sock"},
    {NL_DAEMON_STPD, "stpd", "NETLAB_STPD_SOCKET", "/var/run/netlab/stpd.sock"},
    {NL_DAEMON_LACPD, "lacpd", "NETLAB_LACPD_SOCKET", "/var/run/netlab/lacpd.sock"},
    {NL_DAEMON_LLDPD, "lldpd", "NETLAB_LLDPD_SOCKET", "/var/run/netlab/lldpd.sock"},
    {NL_DAEMON_L2D, "l2d", "NETLAB_L2D_SOCKET", "/var/run/netlab/l2d.sock"},
    {NL_DAEMON_SWITCHD, "switchd", "NETLAB_SWITCHD_SOCKET", "/var/run/netlab/switchd.sock"},
};
#define PEERS (sizeof(peers) / sizeof(peers[0]))
static int packet_scope_call(const char *path, int method, u64 tx, u32 mask, nl_port_scope_status *status) {
    char request[100], reply[128] = {0};
    const char *verb = method == NL_PORT_SCOPE_BEGIN ? "begin" : method == NL_PORT_SCOPE_END ? "end" : "status";
    int n = snprintf(request, sizeof(request), "scope %s %016llx %06x", verb, (unsigned long long)tx, mask);
    nl_conn conn;
    if (nl_client_connect_timeout(path, &conn, 7000) != NL_OK) return NL_ERR_DAEMON_UNREACHABLE;
    u32 count = htonl((u32)n), reply_size = 0;
    int rc = NL_ERR_RPC_TIMEOUT;
    if (nl_send_record(&conn, &count, sizeof(count)) != NL_OK ||
        nl_send_record(&conn, request, (size_t)n) != NL_OK ||
        nl_recv_peer_record(&conn, &reply_size, sizeof(reply_size), MSG_TRUNC) != sizeof(reply_size)) goto done;
    reply_size = ntohl(reply_size);
    if (!reply_size || reply_size >= sizeof(reply) ||
        nl_recv_peer_record(&conn, reply, reply_size, MSG_TRUNC) != reply_size) goto done;
    unsigned schema = 0, actual_mask = 0, degraded = 0;
    unsigned long long actual_tx = 0;
    int used = -1, result;
    if (sscanf(reply, "scope %u %llx %x %u %d %n", &schema, &actual_tx, &actual_mask, &degraded, &result, &used) != 5 ||
        used != (int)reply_size || schema != NL_PORT_SCOPE_SCHEMA ||
        (actual_mask & ~NL_PORT_SCOPE_MASK) || degraded > 1 || (!!actual_tx != !!actual_mask)) goto done;
    *status = (nl_port_scope_status){schema, actual_mask, actual_tx, degraded, 0}; rc = result;
done:
    nl_client_close(&conn); return rc;
}
static int call_peer(unsigned peer, int method, u64 tx, u32 mask, nl_port_scope_status *status) {
    const char *path = nl_ipc_socket_path_from_env(peers[peer].env, peers[peer].path);
    memset(status, 0, sizeof(*status));
    if (peers[peer].id == NL_DAEMON_PACKETD) return packet_scope_call(path, method, tx, mask, status);
    u32 request[2] = {NL_PORT_SCOPE_SCHEMA, mask};
    s32 error = 0;
    int n = nl_rpc_call_ex(path, NL_DAEMON_CONFIGD, peers[peer].id, (nl_rpc_method)method, tx,
        method == NL_PORT_SCOPE_BEGIN ? (const u8 *)request : NULL,
        method == NL_PORT_SCOPE_BEGIN ? sizeof(request) : 0, (u8 *)status, sizeof(*status), 7000, &error);
    if (n != sizeof(*status) || status->schema != NL_PORT_SCOPE_SCHEMA ||
        (status->mask & ~NL_PORT_SCOPE_MASK) || status->degraded > 1 || status->reserved ||
        (!!status->tx_id != !!status->mask))
        return NL_ERR_DAEMON_UNREACHABLE;
    return error;
}
static int failed(char *error, size_t size, unsigned peer, const char *operation, int rc) {
    if (error && size) snprintf(error, size, "%s port scope %s failed (%d); affected ports remain paused", peers[peer].name, operation, rc);
    return rc ? rc : NL_ERR_HW_STATE_OUT_OF_SYNC;
}
bool configd_scope_peers_available(void) {
    for (unsigned i = 0; i < PEERS; ++i) {
        nl_port_scope_status status;
        if (call_peer(i, NL_PORT_SCOPE_STATUS, 0, 0, &status) || status.degraded) return false;
    }
    return true;
}
int configd_scope_begin(u64 tx, const char *plan, size_t size, char *error, size_t error_size) {
    not_dispatched = 0;
    if (!tx || !plan || size > NL_L2_PLAN_MAX_BYTES) return NL_ERR_INVALID_VALUE;
    u32 mask = 0;
    bool declared;
    const char *native = getenv("NETLAB_FM10K_NATIVE");
    if (!nl_fm10k_parse_scope_header(plan, size, &declared, &mask) ||
        (!declared && native && !strcmp(native, "1"))) {
        not_dispatched = tx;
        return NL_ERR_INVALID_VALUE;
    }
    const char *p = plan, *limit = plan + size;
    while (!declared && p < limit) {
        const char *end = memchr(p, '\n', (size_t)(limit - p));
        if (!end) end = limit;
        if ((size_t)(end - p) > 16 && !strncmp(p, "fm10k-group-set ", 16)) {
            char args[192]; fm10k_group group;
            size_t n = (size_t)(end - p) - 16;
            if (n >= sizeof(args)) return NL_ERR_INVALID_VALUE;
            memcpy(args, p + 16, n); args[n] = 0;
            if (!nl_fm10k_parse_group(args, &group)) return NL_ERR_INVALID_VALUE;
            mask |= 15U << (4 * nl_fm10k_group_index(group.epl));
        }
        p = end < limit ? end + 1 : limit;
    }
    if (!mask) return 0;
    bool retained = false;
    for (unsigned i = 0; i < PEERS; ++i) {
        nl_port_scope_status state;
        int rc = call_peer(i, NL_PORT_SCOPE_STATUS, 0, 0, &state);
        if (rc || state.degraded) return failed(error, error_size, i, "preflight", rc);
        if (state.tx_id && state.tx_id != tx)
            return failed(error, error_size, i, "owner mismatch", NL_ERR_COMMIT_LOCKED);
        if (state.tx_id == tx) { retained = true; mask |= state.mask; }
    }
    engaged = true;
    for (unsigned i = 0; i < PEERS; ++i) {
        nl_port_scope_status state;
        int rc = call_peer(i, NL_PORT_SCOPE_BEGIN, tx, mask, &state);
        if (!rc && (state.tx_id != tx || state.mask != mask || state.degraded)) rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
        if (rc) {
            /* A recovery attempt must never release an older barrier whose
             * hardware outcome still needs verification. Expansion only
             * adds ports; keep all peers fenced when any acknowledgement fails. */
            if (retained)
                return failed(error, error_size, i, "recovery expansion", NL_ERR_HW_STATE_OUT_OF_SYNC);
            not_dispatched = tx;
            /* No ASIC step was dispatched; unwind only this token. A lost
             * reply can leave the current peer acquired, so include it. */
            bool released = true;
            for (unsigned j = 0; j <= i; ++j) {
                nl_port_scope_status status;
                int end_rc = call_peer(j, NL_PORT_SCOPE_END, tx, 0, &status);
                if (end_rc || status.tx_id == tx) released = false;
            }
            if (released) engaged = false;
            if (!released) rc = NL_ERR_HW_STATE_OUT_OF_SYNC;
            return failed(error, error_size, i, "begin", rc);
        }
    }
    return 0;
}
int configd_scope_finish(u64 tx, bool committed, char *error, size_t error_size) {
    (void)committed; /* Reload the authoritative active configuration in either outcome. */
    const char *native = getenv("NETLAB_FM10K_NATIVE");
    if (!engaged && (!native || strcmp(native, "1"))) return 0;
    bool ours = false;
    u32 mask = 0;
    u32 masks[PEERS];
    for (unsigned i = 0; i < PEERS; ++i) {
        nl_port_scope_status state;
        int rc = call_peer(i, NL_PORT_SCOPE_STATUS, 0, 0, &state);
        if (rc || state.degraded) return failed(error, error_size, i, "status", rc);
        masks[i] = state.mask;
        if (state.tx_id == tx) { ours = true; mask |= state.mask; }
        else if (state.tx_id) return failed(error, error_size, i, "owner mismatch", NL_ERR_COMMIT_LOCKED);
    }
    if (!ours) { engaged = false; return 0; }
    for (unsigned i = 0; i < PEERS; ++i) if (masks[i] != mask) {
        nl_port_scope_status state;
        int rc = call_peer(i, NL_PORT_SCOPE_BEGIN, tx, mask, &state);
        if (rc || state.tx_id != tx || state.mask != mask || state.degraded)
            return failed(error, error_size, i, "rejoin", rc);
    }
    if (!configd_runtime_reload_checked())
        return failed(error, error_size, 0, "runtime reload", NL_ERR_HW_STATE_OUT_OF_SYNC);
    /* Keep packet ingress fenced until all protocol consumers have resumed. */
    for (unsigned n = 1; n <= PEERS; ++n) {
        unsigned i = n % PEERS;
        nl_port_scope_status state;
        int rc = call_peer(i, NL_PORT_SCOPE_END, tx, 0, &state);
        if (rc || state.tx_id || state.mask) {
            /* Packet ingress remains held. Re-freeze already released peers
             * so a retry does not consume their protocol timers. */
            for (unsigned j = 0; j < PEERS; ++j) {
                nl_port_scope_status held;
                (void)call_peer(j, NL_PORT_SCOPE_BEGIN, tx, mask, &held);
            }
            return failed(error, error_size, i, "end", rc);
        }
    }
    engaged = false;
    return 0;
}
