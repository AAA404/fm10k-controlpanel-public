/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/daemon.h"
#include "netlab/error.h"
#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include "netlab/l2_plan_build.h"
#include "netlab/l2_plan.h"
#include "netlab/log.h"
#include "netlab/yang_config.h"
#include "l2_plan_text.h"
#include "l2_plan_stage.h"
#include "l2d_cache.h"
#include "l2d_paths.h"
#include "l2d_show.h"
#include "l2d_state.h"
#include "igmp_snooping.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define L2D_REFRESH_INTERVAL_SEC 2

l2d_ctx g_l2d;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t thread;
    bool started;
    bool running;
    bool requested;
    u64 requested_generation;
    u64 completed_generation;
} l2d_refresh_worker;

static l2d_refresh_worker g_refresh;

static l2_plan_stage g_plan_stage;

static bool l2d_request_refresh(bool wait);

static u64 monotonic_seconds(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (u64)now.tv_sec;
}

static void *l2d_refresh_main(void *arg) {
    l2d_refresh_worker *worker = arg;

    for (;;) {
        struct timespec deadline;
        u64 target_generation;

        pthread_mutex_lock(&worker->lock);
        if (worker->running && !worker->requested) {
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += L2D_REFRESH_INTERVAL_SEC;
            (void)pthread_cond_timedwait(&worker->cond, &worker->lock,
                                         &deadline);
        }
        if (!worker->running) {
            pthread_mutex_unlock(&worker->lock);
            break;
        }
        target_generation = worker->requested_generation;
        worker->requested = false;
        pthread_mutex_unlock(&worker->lock);

        l2d_refresh_cache();
        igmp_snooping_tick();
        if (l2_plan_stage_expire(&g_plan_stage, monotonic_seconds()))
            NL_LOG_WARN("expired abandoned L2 plan-build session");

        pthread_mutex_lock(&worker->lock);
        if (target_generation > worker->completed_generation)
            worker->completed_generation = target_generation;
        pthread_cond_broadcast(&worker->cond);
        pthread_mutex_unlock(&worker->lock);
    }
    return NULL;
}

static bool l2d_request_refresh(bool wait) {
    u64 generation;
    bool completed;

    pthread_mutex_lock(&g_refresh.lock);
    if (!g_refresh.running) {
        pthread_mutex_unlock(&g_refresh.lock);
        return false;
    }
    generation = ++g_refresh.requested_generation;
    g_refresh.requested = true;
    pthread_cond_signal(&g_refresh.cond);
    while (wait && g_refresh.running &&
           g_refresh.completed_generation < generation)
        pthread_cond_wait(&g_refresh.cond, &g_refresh.lock);
    completed = !wait || g_refresh.completed_generation >= generation;
    pthread_mutex_unlock(&g_refresh.lock);
    return completed;
}

static int l2d_on_init(void *ctx) {
    (void)ctx;
    memset(&g_l2d, 0, sizeof(g_l2d));
    if (pthread_mutex_init(&g_l2d.lock, NULL) != 0)
        return -1;
    if (l2_plan_stage_init(&g_plan_stage) != NL_OK) {
        pthread_mutex_destroy(&g_l2d.lock);
        return -1;
    }
    l2d_refresh_cache();
    if (igmp_snooping_init() != 0) {
        l2_plan_stage_destroy(&g_plan_stage);
        pthread_mutex_destroy(&g_l2d.lock);
        return -1;
    }
    memset(&g_refresh, 0, sizeof(g_refresh));
    pthread_mutex_init(&g_refresh.lock, NULL);
    pthread_cond_init(&g_refresh.cond, NULL);
    g_refresh.running = true;
    if (pthread_create(&g_refresh.thread, NULL,
                       l2d_refresh_main, &g_refresh) != 0) {
        g_refresh.running = false;
        igmp_snooping_shutdown();
        pthread_cond_destroy(&g_refresh.cond);
        pthread_mutex_destroy(&g_refresh.lock);
        l2_plan_stage_destroy(&g_plan_stage);
        pthread_mutex_destroy(&g_l2d.lock);
        return -1;
    }
    g_refresh.started = true;
    NL_LOG_NOTICE("l2d ready (cached L2 state)");
    return 0;
}

static void l2d_on_stopping(void *ctx) {
    (void)ctx;
    igmp_snooping_stop();
    pthread_mutex_lock(&g_refresh.lock);
    g_refresh.running = false;
    pthread_cond_broadcast(&g_refresh.cond);
    pthread_mutex_unlock(&g_refresh.lock);
}

static void l2d_on_shutdown(void *ctx) {
    (void)ctx;
    if (g_refresh.started)
        pthread_join(g_refresh.thread, NULL);
    igmp_snooping_shutdown();
    pthread_cond_destroy(&g_refresh.cond);
    pthread_mutex_destroy(&g_refresh.lock);
    pthread_mutex_destroy(&g_l2d.lock);
    l2_plan_stage_destroy(&g_plan_stage);
}

static int send_l2d_text(nl_conn *conn, nl_msg_hdr *msg, s32 error_code,
                         const char *text) {
    size_t len = text ? strlen(text) : 0;
    nl_msg_hdr *resp = nl_msg_alloc((u32)len);

    if (!resp)
        return -1;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)len;
    if (len > 0)
        memcpy(resp->payload, text, len);
    nl_send(conn, resp);
    nl_msg_free(resp);
    return 0;
}

static int load_xml_into_session(nl_yang_session *session, const char *xml,
                                 const char *name, char *err,
                                 size_t err_size) {
    struct lyd_node *tree;

    if (!session || !xml || !xml[0]) {
        snprintf(err, err_size, "missing %s XML", name);
        return -1;
    }
    tree = nl_yang_from_xml(session, xml);
    if (!tree) {
        snprintf(err, err_size, "invalid %s XML", name);
        return -1;
    }
    nl_yang_data_set(session, tree);
    return 0;
}

static int execute_build_plan(nl_conn *conn, nl_msg_hdr *msg,
                              char *active_xml, char *candidate_xml,
                              bool require_hw) {
    nl_yang_session *active = NULL;
    nl_yang_session *candidate = NULL;
    char *plan = NULL;
    char err[NL_L2_PLAN_ERROR_BYTES] = {0};
    char header[96];
    int plan_len = 0;
    bool has_l2 = false;
    nl_msg_hdr *resp;

    active = nl_yang_session_create(NULL);
    candidate = nl_yang_session_create(NULL);
    plan = calloc(1, NL_L2_PLAN_MAX_BYTES);
    if (!active || !candidate || !plan) {
        snprintf(err, sizeof(err), "out of memory");
        goto invalid;
    }
    if (load_xml_into_session(active, active_xml, "active",
                              err, sizeof(err)) != 0 ||
        load_xml_into_session(candidate, candidate_xml, "candidate",
                              err, sizeof(err)) != 0)
        goto invalid;

    if (nl_l2_build_plan(active, candidate, require_hw,
                         plan, NL_L2_PLAN_MAX_BYTES,
                         &plan_len, &has_l2, err, sizeof(err)) != 0)
        goto invalid;

    snprintf(header, sizeof(header), "has-l2=%d plan-len=%d\n",
             has_l2 ? 1 : 0, plan_len);
    resp = nl_msg_alloc((u32)(strlen(header) + (size_t)plan_len));
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->error_code = 0;
        resp->payload_len = (u32)(strlen(header) + (size_t)plan_len);
        memcpy(resp->payload, header, strlen(header));
        if (plan_len > 0)
            memcpy(resp->payload + strlen(header), plan, (size_t)plan_len);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    free(active_xml);
    free(candidate_xml);
    free(plan);
    nl_yang_session_destroy(active);
    nl_yang_session_destroy(candidate);
    return 0;

invalid:
    {
        char detail[NL_L2_PLAN_ERROR_BYTES + 64];
        snprintf(detail, sizeof(detail), "error: l2d plan build failed: %s",
                 err[0] ? err : "invalid request");
        free(active_xml);
        free(candidate_xml);
        free(plan);
        nl_yang_session_destroy(active);
        nl_yang_session_destroy(candidate);
        return send_l2d_text(conn, msg, NL_ERR_INVALID_VALUE, detail);
    }
}

static int handle_build_plan_begin(nl_conn *conn, nl_msg_hdr *msg) {
    nl_l2_plan_build_begin begin;
    int status;

    if (nl_l2_plan_build_begin_decode(
            msg->payload, msg->payload_len, &begin) != 0) {
        nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE);
        return 0;
    }
    status = l2_plan_stage_begin(
        &g_plan_stage, &begin, monotonic_seconds());
    nl_send_response(conn, msg->request_id, status);
    return 0;
}

static int handle_build_plan_part(nl_conn *conn, nl_msg_hdr *msg) {
    nl_l2_plan_build_part part;
    const u8 *data = NULL;
    size_t data_length = 0;
    int status;

    if (nl_l2_plan_build_part_decode(
            msg->payload, msg->payload_len, &part,
            &data, &data_length) != 0 ||
        memchr(data, '\0', data_length) != NULL) {
        nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE);
        return 0;
    }
    status = l2_plan_stage_append(
        &g_plan_stage, &part, data, data_length,
        monotonic_seconds());
    nl_send_response(conn, msg->request_id, status);
    return 0;
}

static int handle_build_plan_commit(nl_conn *conn, nl_msg_hdr *msg) {
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
    char *active_xml = NULL;
    char *candidate_xml = NULL;
    bool require_hardware = false;
    int status;

    if (nl_l2_plan_build_token_decode(
            msg->payload, msg->payload_len, token) != 0) {
        nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE);
        return 0;
    }
    status = l2_plan_stage_take(
        &g_plan_stage, token, monotonic_seconds(),
        &active_xml, &candidate_xml, &require_hardware);
    if (status != NL_OK) {
        nl_send_response(conn, msg->request_id, status);
        return 0;
    }
    if (!l2d_request_refresh(true)) {
        free(active_xml);
        free(candidate_xml);
        return send_l2d_text(
            conn, msg, NL_ERR_DAEMON_UNREACHABLE,
            "error: L2 cache refresh worker unavailable");
    }
    return execute_build_plan(
        conn, msg, active_xml, candidate_xml, require_hardware);
}

static int handle_build_plan_abort(nl_conn *conn, nl_msg_hdr *msg) {
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
    int status;

    if (nl_l2_plan_build_token_decode(
            msg->payload, msg->payload_len, token) != 0) {
        nl_send_response(conn, msg->request_id, NL_ERR_INVALID_VALUE);
        return 0;
    }
    status = l2_plan_stage_abort(
        &g_plan_stage, token, monotonic_seconds());
    nl_send_response(conn, msg->request_id, status);
    return 0;
}

static int handle_validate(nl_conn *conn, nl_msg_hdr *msg) {
    char *plan_text = NULL;
    char err[256] = {0};
    char resp[128];
    int steps = 0;

    if (msg->payload_len == 0) {
        if (!l2d_request_refresh(true))
            return send_l2d_text(
                conn, msg, NL_ERR_DAEMON_UNREACHABLE,
                "error: L2 cache refresh worker unavailable");
        nl_send_response(conn, msg->request_id, NL_OK);
        return 0;
    }
    plan_text = calloc(1, (size_t)msg->payload_len + 1);
    if (!plan_text) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }
    memcpy(plan_text, msg->payload, msg->payload_len);
    if (l2_plan_text_validate(plan_text, &steps, err, sizeof(err)) != 0) {
        char detail[320];
        snprintf(detail, sizeof(detail), "error: l2d validate failed: %s",
                 err[0] ? err : "invalid L2 plan");
        free(plan_text);
        return send_l2d_text(conn, msg, NL_ERR_INVALID_VALUE, detail);
    }
    free(plan_text);
    snprintf(resp, sizeof(resp), "l2d validate ok steps=%d", steps);
    send_l2d_text(conn, msg, 0, resp);
    return 0;
}

static int l2d_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    (void)ctx;
    switch (msg->method) {
    case NL_L2D_SHOW_VLANS: return l2d_show_vlans(conn, msg);
    case NL_L2D_SHOW_ETHERNET_SWITCHING:
        return l2d_show_ethernet_switching(conn, msg);
    case NL_L2D_VALIDATE_PLAN: return handle_validate(conn, msg);
    case NL_L2D_SHOW_MAC_SECURITY:
        return l2d_show_mac_security(conn, msg);
    case NL_L2D_CLEAR_SECURE_ACCESS:
        return l2d_clear_secure_access(conn, msg);
    case NL_L2D_CLEAR_MAC_MOVE: return l2d_clear_mac_move(conn, msg);
    case NL_L2D_SHOW_PORT_MIRRORING:
        return l2d_show_port_mirroring(conn, msg);
    case NL_L2D_SHOW_IGMP_SNOOPING: return igmp_snooping_show(conn, msg);
    case NL_L2D_RELOAD: {
        bool ok = igmp_snooping_reload();
        return send_l2d_text(conn, msg, ok ? NL_OK : NL_ERR_HW_STATE_OUT_OF_SYNC,
                             ok ? "l2d reload complete" : "l2d reload failed");
    }
    case NL_L2D_BUILD_PLAN_BEGIN:
        return handle_build_plan_begin(conn, msg);
    case NL_L2D_BUILD_PLAN_PART:
        return handle_build_plan_part(conn, msg);
    case NL_L2D_BUILD_PLAN_COMMIT:
        return handle_build_plan_commit(conn, msg);
    case NL_L2D_BUILD_PLAN_ABORT:
        return handle_build_plan_abort(conn, msg);
    default: nl_send_response(conn, msg->request_id, -1); return 0;
    }
}

int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name        = "l2d",
        .socket_path = l2d_socket_path(),
        .service_id  = NL_DAEMON_L2D,
        .auth_mode   = NL_DAEMON_AUTH_STANDARD,
        .dispatch    = l2d_dispatch,
        .ctx         = NULL,
        .on_init     = l2d_on_init,
        .on_stopping = l2d_on_stopping,
        .on_shutdown = l2d_on_shutdown,
        .max_concurrent_handlers = 4,
        .poll_interval_ms = 1000,
    };
    (void)argc; (void)argv;
    return nl_daemon_run(&cfg);
}
