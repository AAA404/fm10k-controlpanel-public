/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "mgmtd.h"
#include "netlab/daemon.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include "netlab/error.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define MGMTD_MAX_CONCURRENT_HANDLERS 16

typedef struct {
    u16 daemon_id;
    u64 requests;
    u64 failures;
    s32 last_result;
    long last_elapsed_ms;
    time_t last_update;
} mgmtd_backend_runtime;

typedef struct {
    pthread_mutex_t lock;
    mgmtd_session_store sessions;
    mgmtd_backend_runtime backends[32];
    size_t n_backends;
} mgmtd_ctx;

static mgmtd_ctx g_mgmtd;

static void mgmtd_audit_log_path(char *path, size_t size) {
    const char *directory = getenv("NETLAB_CONFIG_DIR");

    if (!directory || directory[0] != '/' || strstr(directory, "..")) {
        snprintf(path, size, "%s", MGMTD_AUDIT_LOG);
        return;
    }
    snprintf(path, size, "%s/mgmtd-audit.log", directory);
}

static int append_status(char *buf, size_t buf_size, int off,
                         const char *text) {
    int n;

    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    n = snprintf(buf + off, buf_size - (size_t)off, "%s", text);
    if (n < 0)
        return -1;
    if ((size_t)n >= buf_size - (size_t)off)
        return -1;
    return off + n;
}

static int append_statusf(char *buf, size_t buf_size, int off,
                          const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !fmt || off < 0 || (size_t)off >= buf_size)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(buf + off, buf_size - (size_t)off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - (size_t)off)
        return -1;
    return off + n;
}

static void init_backend_runtime(mgmtd_ctx *ctx) {
    size_t count;

    if (!ctx)
        return;
    memset(ctx->backends, 0, sizeof(ctx->backends));
    count = mgmtd_backend_count();
    if (count > sizeof(ctx->backends) / sizeof(ctx->backends[0]))
        count = sizeof(ctx->backends) / sizeof(ctx->backends[0]);
    ctx->n_backends = count;
    for (size_t i = 0; i < count; i++) {
        const mgmtd_backend_info *b = mgmtd_backend_at(i);
        if (b)
            ctx->backends[i].daemon_id = b->daemon_id;
    }
}

static mgmtd_backend_runtime *backend_runtime_for(mgmtd_ctx *ctx,
                                                  u16 daemon_id) {
    if (!ctx)
        return NULL;
    for (size_t i = 0; i < ctx->n_backends; i++)
        if (ctx->backends[i].daemon_id == daemon_id)
            return &ctx->backends[i];
    return NULL;
}

static const mgmtd_backend_runtime *backend_runtime_for_const(
        const mgmtd_ctx *ctx, u16 daemon_id) {
    if (!ctx)
        return NULL;
    for (size_t i = 0; i < ctx->n_backends; i++)
        if (ctx->backends[i].daemon_id == daemon_id)
            return &ctx->backends[i];
    return NULL;
}

static void note_backend_runtime(mgmtd_ctx *ctx, const mgmtd_route *route,
                                 s32 result, long elapsed_ms) {
    mgmtd_backend_runtime *rt;

    if (!ctx || !route || !route->ok)
        return;
    rt = backend_runtime_for(ctx, route->daemon_id);
    if (!rt)
        return;
    rt->requests++;
    if (result != 0)
        rt->failures++;
    rt->last_result = result;
    rt->last_elapsed_ms = elapsed_ms;
    rt->last_update = time(NULL);
}

static void audit_request(u64 session_id, const nl_conn *conn,
                          const mgmtd_route *route, s32 result,
                          u32 payload_len, long elapsed_ms) {
    FILE *f;
    char audit_path[512];
    time_t now = time(NULL);
    char ts[64];
    struct tm tm;

    localtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", &tm);
    mgmtd_audit_log_path(audit_path, sizeof(audit_path));
    f = fopen(audit_path, "a");
    if (!f)
        return;
    fprintf(f,
            "%s session=%lu uid=%d gid=%d pid=%d schema=%u access=%s "
            "daemon=%u/%s "
            "method=%u result=%d payload=%u elapsed_ms=%ld desc=\"%s\"\n",
            ts, session_id,
            conn ? (int)conn->peer_uid : -1,
            conn ? (int)conn->peer_gid : -1,
            conn ? (int)conn->peer_pid : -1,
            conn && conn->peer_schema_known ? conn->peer_schema_version : 0,
            route ? mgmtd_access_name(route->access) : "unknown",
            route ? route->daemon_id : 0,
            route && route->daemon_name ? route->daemon_name : "-",
            route ? route->method : 0,
            result, payload_len, elapsed_ms,
            route && route->description ? route->description : "-");
    fclose(f);
}

static int send_status(nl_conn *conn, nl_msg_hdr *msg, mgmtd_ctx *ctx) {
    char body[16384];
    char audit_path[512];
    mgmtd_session_stats stats;
    mgmtd_session_event recent[MGMTD_RECENT_SESSIONS_MAX];
    size_t recent_count;
    int n;
    int off;
    s32 error_code = 0;
    const char *payload = body;
    nl_msg_hdr *resp;

    if (ctx)
        pthread_mutex_lock(&ctx->lock);
    mgmtd_audit_log_path(audit_path, sizeof(audit_path));
    mgmtd_sessions_snapshot(ctx ? &ctx->sessions : NULL, &stats);
    recent_count = mgmtd_sessions_recent(ctx ? &ctx->sessions : NULL, recent,
                                         sizeof(recent) / sizeof(recent[0]));

    off = snprintf(body, sizeof(body),
                 "<mgmtd total-sessions=\"%lu\" active-sessions=\"%lu\" "
                 "total-requests=\"%lu\" routed-requests=\"%lu\" "
                 "denied-requests=\"%lu\" malformed-requests=\"%lu\" "
                 "backend-errors=\"%lu\" max-concurrent-handlers=\"%d\" "
                 "ipc-schema-current=\"%u\" ipc-max-payload=\"%u\" "
                 "ipc-chunk-data-max=\"%u\" "
                 "audit-log=\"%s\">\n",
                 stats.total_sessions,
                 stats.active_sessions,
                 stats.total_requests,
                 stats.routed_requests,
                 stats.denied_requests,
                 stats.malformed_requests,
                 stats.backend_errors,
                 MGMTD_MAX_CONCURRENT_HANDLERS,
                 NETLAB_IPC_SCHEMA_CURRENT,
                 (unsigned)NETLAB_MAX_MSG,
                 (unsigned)NETLAB_IPC_CHUNK_DATA_MAX,
                 audit_path);
    if (off < 0) {
        if (ctx)
            pthread_mutex_unlock(&ctx->lock);
        return -1;
    }
    if ((size_t)off >= sizeof(body))
        off = -1;

    off = append_statusf(body, sizeof(body), off,
                         "  <backends count=\"%zu\">\n",
                         mgmtd_backend_count());
    for (size_t i = 0; off >= 0 && i < mgmtd_backend_count(); i++) {
        const mgmtd_backend_info *b = mgmtd_backend_at(i);
        const mgmtd_backend_runtime *rt;
        long last_age = -1;
        if (!b)
            continue;
        rt = backend_runtime_for_const(ctx, b->daemon_id);
        if (rt && rt->last_update > 0)
            last_age = (long)(time(NULL) - rt->last_update);
        const char *socket_path = mgmtd_backend_socket_path(b);
        off = append_statusf(body, sizeof(body), off,
                        "    <backend daemon=\"%u\" name=\"%s\" "
                        "socket=\"%s\" socket-present=\"%s\" "
                        "virtual=\"%s\" requests=\"%lu\" "
                        "failures=\"%lu\" last-result=\"%d\" "
                        "last-elapsed-ms=\"%ld\" last-age=\"%ld\" "
                        "desc=\"%s\"/>\n",
                        b->daemon_id, b->daemon_name, socket_path,
                        socket_path && access(socket_path, F_OK) == 0 ?
                            "true" : "false",
                        b->virtual_route ? "true" : "false",
                        rt ? rt->requests : 0,
                        rt ? rt->failures : 0,
                        rt ? rt->last_result : 0,
                        rt ? rt->last_elapsed_ms : -1,
                        last_age,
                        b->description);
    }
    off = append_status(body, sizeof(body), off, "  </backends>\n");
    off = append_statusf(body, sizeof(body), off,
                         "  <recent-sessions count=\"%zu\">\n", recent_count);
    for (size_t i = 0; off >= 0 && i < recent_count; i++) {
        mgmtd_session_event *event = &recent[i];
        off = append_statusf(body, sizeof(body), off,
                        "    <session id=\"%lu\" age=\"%ld\" uid=\"%d\" "
                        "gid=\"%d\" pid=\"%d\" schema=\"%u\" daemon=\"%u\" "
                        "name=\"%s\" method=\"%u\" access=\"%s\" "
                        "result=\"%d\" payload=\"%u\" elapsed-ms=\"%ld\" "
                        "desc=\"%s\"/>\n",
                        event->session_id, event->age_sec,
                        (int)event->uid, (int)event->gid, (int)event->pid,
                        event->schema_version, event->daemon_id,
                        event->daemon_name, event->method,
                        event->access, event->result, event->payload_len,
                        event->elapsed_ms, event->description);
    }
    off = append_status(body, sizeof(body), off,
                        "  </recent-sessions>\n</mgmtd>");
    if (ctx)
        pthread_mutex_unlock(&ctx->lock);

    if (off < 0) {
        static const char capacity_error[] =
            "mgmtd status response exceeds the IPC message capacity";

        payload = capacity_error;
        off = (int)sizeof(capacity_error) - 1;
        error_code = NL_ERR_CAPABILITY_INSUFFICIENT;
    }
    n = off;

    resp = nl_msg_alloc((u32)n);
    if (!resp)
        return -1;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)n;
    memcpy(resp->payload, payload, (size_t)n);
    int rc = nl_send(conn, resp) == NL_OK ? 0 : -1;
    nl_msg_free(resp);
    return rc;
}

static int mgmtd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    mgmtd_ctx *mctx = ctx ? (mgmtd_ctx *)ctx : &g_mgmtd;
    mgmtd_route route;
    struct timespec start;
    struct timespec end;
    long elapsed_ms;
    s32 result;
    mgmtd_session session;

    clock_gettime(CLOCK_MONOTONIC, &start);
    pthread_mutex_lock(&mctx->lock);
    session = mgmtd_session_begin(&mctx->sessions);
    pthread_mutex_unlock(&mctx->lock);

    route = mgmtd_lookup_route(msg->daemon_id, msg->method);
    if (!route.ok) {
        pthread_mutex_lock(&mctx->lock);
        mgmtd_session_note_malformed(&mctx->sessions);
        mgmtd_session_note_denied(&mctx->sessions);
        pthread_mutex_unlock(&mctx->lock);
        NL_LOG_WARN("mgmtd: no route for daemon=%d method=%d uid=%d pid=%d",
                    msg->daemon_id, msg->method, conn->peer_uid,
                    conn->peer_pid);
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        route.access = MGMTD_ACCESS_ADMIN;
        route.daemon_id = msg->daemon_id;
        route.method = msg->method;
        result = NL_ERR_MALFORMED_REQUEST;
        goto done;
    }

    if (!route.contract ||
        !nl_rpc_contract_payload_valid(
            route.contract->request_format, msg->payload, msg->payload_len,
            route.contract->max_request_len) ||
        ((route.contract->flags & NL_RPC_CONTRACT_TX_ID_REQUIRED) &&
         msg->tx_id == 0)) {
        pthread_mutex_lock(&mctx->lock);
        mgmtd_session_note_malformed(&mctx->sessions);
        pthread_mutex_unlock(&mctx->lock);
        NL_LOG_WARN("mgmtd: invalid contract payload daemon=%d method=%d "
                    "payload=%u", msg->daemon_id, msg->method,
                    msg->payload_len);
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        result = NL_ERR_MALFORMED_REQUEST;
        goto done;
    }

    if (!mgmtd_access_allowed(conn, route.access) &&
        !mgmtd_panel_request_allowed(conn, &route)) {
        pthread_mutex_lock(&mctx->lock);
        mgmtd_session_note_denied(&mctx->sessions);
        pthread_mutex_unlock(&mctx->lock);
        NL_LOG_WARN("mgmtd: denied uid=%d pid=%d access=%s daemon=%d method=%d",
                    conn->peer_uid, conn->peer_pid,
                    mgmtd_access_name(route.access), msg->daemon_id, msg->method);
        nl_send_response(conn, msg->request_id, NL_ERR_PERMISSION_DENIED);
        result = NL_ERR_PERMISSION_DENIED;
        goto done;
    }

    if (msg->daemon_id == NL_DAEMON_MGMTD &&
        msg->method == NL_MGMTD_SHOW_STATUS) {
        result = send_status(conn, msg, mctx) == 0 ? 0 : NL_ERR_RPC_TIMEOUT;
    } else {
        pthread_mutex_lock(&mctx->lock);
        mgmtd_session_note_routed(&mctx->sessions);
        pthread_mutex_unlock(&mctx->lock);
        result = mgmtd_forward_to_backend(conn, msg, &route);
        if (result == NL_ERR_DAEMON_UNREACHABLE ||
            result == NL_ERR_RPC_TIMEOUT) {
            pthread_mutex_lock(&mctx->lock);
            mgmtd_session_note_backend_error(&mctx->sessions);
            pthread_mutex_unlock(&mctx->lock);
        }
    }

done:
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_ms = (long)((end.tv_sec - start.tv_sec) * 1000L +
                        (end.tv_nsec - start.tv_nsec) / 1000000L);
    pthread_mutex_lock(&mctx->lock);
    note_backend_runtime(mctx, &route, result, elapsed_ms);
    audit_request(session.session_id, conn, &route, result, msg->payload_len,
                  elapsed_ms);
    mgmtd_session_finish(&mctx->sessions, &session, conn, &route, result,
                         msg->payload_len, elapsed_ms);
    pthread_mutex_unlock(&mctx->lock);
    if (route.access == MGMTD_ACCESS_VIEW && result == 0) {
        NL_LOG_DBG("mgmtd: session=%lu uid=%d daemon=%d method=%d result=%d",
                   session.session_id, conn->peer_uid, msg->daemon_id,
                   msg->method, result);
    } else {
        NL_LOG_NOTICE("mgmtd: session=%lu uid=%d access=%s daemon=%d "
                      "method=%d result=%d",
                      session.session_id, conn->peer_uid,
                      mgmtd_access_name(route.access), msg->daemon_id,
                      msg->method, result);
    }
    return 0;
}

static int mgmtd_on_init(void *ctx) {
    mgmtd_ctx *mctx = ctx ? (mgmtd_ctx *)ctx : &g_mgmtd;
    pthread_mutex_init(&mctx->lock, NULL);
    mgmtd_sessions_init(&mctx->sessions);
    init_backend_runtime(mctx);
    return 0;
}

static void mgmtd_on_shutdown(void *ctx) {
    mgmtd_ctx *mctx = ctx ? (mgmtd_ctx *)ctx : &g_mgmtd;
    pthread_mutex_destroy(&mctx->lock);
}

int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name        = "mgmtd",
        .socket_path = nl_ipc_socket_path_from_env("NETLAB_MGMTD_SOCKET",
                                                   MGMTD_SOCKET),
        .service_id  = NL_DAEMON_MGMTD,
        .auth_mode   = NL_DAEMON_AUTH_MANAGEMENT_GATEWAY,
        .dispatch    = mgmtd_dispatch,
        .ctx         = &g_mgmtd,
        .on_init     = mgmtd_on_init,
        .on_shutdown = mgmtd_on_shutdown,
        .max_concurrent_handlers = MGMTD_MAX_CONCURRENT_HANDLERS,
    };
    (void)argc; (void)argv;
    return nl_daemon_run(&cfg);
}
