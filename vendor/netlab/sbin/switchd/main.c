/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/daemon.h"
#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include "fm10k_board_runtime.h"
#include "fm10k_eye.h"
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
#define SWITCHD_MAX_CONCURRENT_HANDLERS 8

typedef struct {
    struct sdk_context *ctx;
    pthread_t recovery_thread;
    volatile sig_atomic_t recovery_running;
    bool recovery_thread_started;
    bool event_started;
} switchd_state;

static switchd_state g_switchd;

/*
 * Port recovery mutates the same admin/XCVR state owned by method 40.
 * Acquire the transaction tracker's external-mutation lease before the
 * executor request is even queued, and retain it until the non-detachable SDK
 * operation has either completed or was removed from the queue.  This closes
 * both the RESERVED apply/read-back window and the APPLIED before-image
 * retention window.
 */
static bool switchd_recovery_poll_once(switchd_state *state) {
    struct sdk_op op;
    struct sdk_result result;

    if (!state || !state->ctx || !state->ctx->exec ||
        !state->ctx->hw_tracker)
        return false;
    if (hw_state_tracker_begin_l2_mutation(
            state->ctx->hw_tracker) != NL_OK)
        return false;

    memset(&op, 0, sizeof(op));
    memset(&result, 0, sizeof(result));
    op.type = SDK_OP_PORT_RECOVERY_POLL;
    op.args.port_recovery.ctx = state->ctx;
    (void)sdk_exec_with_prio(state->ctx->exec, &op, &result,
                             SDK_PRIO_PLATFORM_POLL, 30000);
    hw_state_tracker_end_l2_mutation(state->ctx->hw_tracker);
    return true;
}

static void *switchd_recovery_main(void *arg) {
    switchd_state *state = arg;
    bool board = fm10k_native_profile();

    while (state && state->recovery_running) {
        if (board) {
            /* One bounded board slice per turn; protocol traffic retains
             * executor priority. Do not auto-retrain configured board EPLs. */
            struct sdk_op op = {.type = SDK_OP_FM10K_BOARD_POLL};
            struct sdk_result result = {0};
            (void)sdk_exec_with_prio(state->ctx->exec, &op, &result,
                                    SDK_PRIO_PLATFORM_POLL, 3000);
            usleep(fm10k_eye_poll_interval_us());
        } else {
            (void)switchd_recovery_poll_once(state);
            for (int i = 0; i < 10 && state->recovery_running; i++)
                usleep(100000);
        }
    }
    if (state && board) {
        struct sdk_op op = {.type = SDK_OP_FM10K_BOARD_SHUTDOWN};
        struct sdk_result result = {0};
        (void)sdk_exec_with_prio(state->ctx->exec, &op, &result,
                                SDK_PRIO_CONFIG_CHANGE, 3000);
    }
    return NULL;
}

static int switchd_on_init(void *arg) {
    switchd_state *state = arg;
    nl_platform_identity ident;
    nl_status status;

    if (!state)
        return -1;
    if (nl_platform_identity_get(&ident) && ident.model[0])
        NL_LOG_INFO("switchd SDK platform: IES SDK v4.3.2, %s", ident.model);

    nl_pfe_cap_init(&g_pfe_cap);
    sdk_pfe_capability_register(&g_pfe_cap);
    status = sdk_bringup(&state->ctx);
    if (status != NL_OK) {
        bool cleanup_failed =
            state->ctx && state->ctx->cleanup_failed;

        NL_LOG_CRIT("SDK bringup failed, PFE_DOWN mode: %s",
                    state->ctx && state->ctx->pfe_cap.init_error[0] ?
                    state->ctx->pfe_cap.init_error : "no initialization detail");
        if (state->ctx)
            g_pfe_cap = state->ctx->pfe_cap;
        g_pfe_cap.sdk_initialized = false;
        sdk_pfe_capability_register(&g_pfe_cap);
        if (cleanup_failed) {
            NL_LOG_CRIT(
                "SDK partial bringup could not unwind; exiting fail closed");
            return -1;
        }
        return 0;
    }

    g_pfe_cap = state->ctx->pfe_cap;
    sdk_pfe_capability_register(&g_pfe_cap);
    if (state->ctx->initialized) {
        if (sdk_event_publisher_start(state->ctx) != 0) {
            NL_LOG_CRIT("switchd event publisher could not start");
            if (sdk_shutdown(state->ctx) == 0)
                state->ctx = NULL;
            else
                NL_LOG_CRIT(
                    "switchd retained SDK context after cleanup failure");
            return -1;
        }
        state->event_started = true;
        state->recovery_running = 1;
        if (pthread_create(&state->recovery_thread, NULL,
                           switchd_recovery_main, state) == 0) {
            state->recovery_thread_started = true;
        } else {
            state->recovery_running = 0;
            NL_LOG_WARN("switchd port recovery worker could not start");
        }
    }

    NL_LOG_NOTICE("PFE capabilities: SDK=%s SWITCH=%s PORTS=%d",
                  g_pfe_cap.sdk_initialized ? "OK" : "FAIL",
                  g_pfe_cap.switch_enabled ? "OK" : "FAIL",
                  g_pfe_cap.port_inventory_ok ? state->ctx->num_cardinal_ports : 0);
    return 0;
}

static int switchd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *arg) {
    switchd_state *state = arg;

    if ((!state || !state->ctx) && msg &&
        (msg->method == NL_SWITCHD_FM10K_BOARD_GET ||
         msg->method == NL_SWITCHD_FM10K_FAN_MANUAL)) {
        hal_rpc_dispatch(NULL, conn, msg);
        return NL_OK;
    }
    if (!state || !state->ctx) {
        nl_send_response(conn, msg->request_id, NL_ERR_DAEMON_UNREACHABLE);
        return NL_OK;
    }
    hal_rpc_dispatch(state->ctx, conn, msg);
    return NL_OK;
}

static void switchd_on_shutdown(void *arg) {
    switchd_state *state = arg;

    if (!state)
        return;
    state->recovery_running = 0;
    if (state->recovery_thread_started)
        pthread_join(state->recovery_thread, NULL);
    if (state->event_started)
        sdk_event_publisher_stop();
    if (sdk_shutdown(state->ctx) == 0)
        state->ctx = NULL;
    else
        NL_LOG_CRIT(
            "switchd retained SDK context after cleanup failure");
}

int main(int argc, char *argv[]) {
    const char *socket_path = nl_ipc_socket_path_from_env(
        "NETLAB_SWITCHD_SOCKET", SWITCHD_SOCKET);
    nl_daemon_config cfg = {
        .name = "switchd",
        .socket_path = socket_path,
        .service_id = NL_DAEMON_SWITCHD,
        .auth_mode = NL_DAEMON_AUTH_STANDARD,
        .dispatch = switchd_dispatch,
        .ctx = &g_switchd,
        .on_init = switchd_on_init,
        .on_shutdown = switchd_on_shutdown,
        .max_concurrent_handlers = SWITCHD_MAX_CONCURRENT_HANDLERS,
    };

    (void)argc;
    (void)argv;
    return nl_daemon_run(&cfg);
}
