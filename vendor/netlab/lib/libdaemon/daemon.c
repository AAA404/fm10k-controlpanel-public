/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/port_scope.h"
#include "netlab/daemon.h"
#include "netlab/daemon_identity.h"
#include "netlab/error.h"
#include "netlab/identity_broker.h"
#include "netlab/log.h"
#include "netlab/process_identity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <pthread.h>

#define DAEMON_AUTH_TIMEOUT_MS 2000U
#define DAEMON_AUTH_HEADROOM 16
#define DAEMON_MAX_CONNECTIONS 64
#define DAEMON_INHERITED_LISTENER_FD 3
#define DAEMON_INHERITED_READY_FD 4
#define DAEMON_CAPABILITY_BITS 64U

// Globals managed by the framework
static volatile sig_atomic_t g_running = 1;

typedef enum {
    DAEMON_WORKER_FREE = 0,
    DAEMON_WORKER_ACTIVE,
    DAEMON_WORKER_DONE,
    DAEMON_WORKER_REAPING,
} daemon_worker_slot_state;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    int active_connections;
    int max_connections;
    int active_dispatch;
    int max_dispatch;
    bool stopping;
    pthread_t workers[DAEMON_MAX_CONNECTIONS];
    daemon_worker_slot_state worker_slots[DAEMON_MAX_CONNECTIONS];
} daemon_handler_state;

typedef enum {
    DAEMON_PEER_AUTHORITY_NONE = 0,
    DAEMON_PEER_AUTHORITY_LOCAL,
    DAEMON_PEER_AUTHORITY_BROKER,
} daemon_peer_authority_kind;

typedef struct {
    daemon_peer_authority_kind kind;
    nl_process_identity_handle local;
    nl_identity_lease lease;
} daemon_peer_authority;

typedef struct {
    nl_daemon_config *cfg;
    nl_conn conn;
    daemon_peer_authority peer_authority;
    daemon_handler_state *state;
    int worker_slot;
} daemon_handler_job;

static void daemon_signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static bool daemon_capture_local_peer_identity(
    const nl_conn *conn, nl_process_identity_handle *identity) {
    nl_process_identity_result result;

    if (!conn || !identity || conn->peer_pid <= 0)
        return false;
    nl_process_identity_init(identity);
    result = nl_process_identity_open(conn->peer_pid, identity);
    if (result != NL_PROCESS_IDENTITY_OK) {
        NL_LOG_DBG("peer identity capture failed pid=%d result=%s",
                   (int)conn->peer_pid,
                   nl_process_identity_result_name(result));
        return false;
    }
    if (identity->baseline.pid != conn->peer_pid ||
        identity->baseline.euid != conn->peer_uid ||
        identity->baseline.egid != conn->peer_gid) {
        NL_LOG_WARN("peer credentials changed during accept "
                    "pid=%d socket-uid=%d socket-gid=%d "
                    "observed-uid=%d observed-gid=%d",
                    (int)conn->peer_pid, (int)conn->peer_uid,
                    (int)conn->peer_gid, (int)identity->baseline.euid,
                    (int)identity->baseline.egid);
        nl_process_identity_close(identity);
        return false;
    }
    return true;
}

static void daemon_peer_authority_init(daemon_peer_authority *authority) {
    if (!authority)
        return;
    memset(authority, 0, sizeof(*authority));
    nl_process_identity_init(&authority->local);
}

static void daemon_peer_authority_close(
    const nl_daemon_config *cfg, daemon_peer_authority *authority) {
    if (!authority)
        return;
    if (authority->kind == DAEMON_PEER_AUTHORITY_BROKER &&
        authority->lease.active && cfg &&
        cfg->identity_broker_socket_path) {
        (void)nl_identity_broker_release(
            cfg->identity_broker_socket_path, cfg->service_id,
            &authority->lease);
    }
    nl_process_identity_close(&authority->local);
    memset(&authority->lease, 0, sizeof(authority->lease));
    authority->kind = DAEMON_PEER_AUTHORITY_NONE;
}

static bool daemon_peer_authority_move(
    daemon_peer_authority *destination,
    daemon_peer_authority *source) {
    if (!destination || !source ||
        destination->kind != DAEMON_PEER_AUTHORITY_NONE)
        return false;
    if (source->kind == DAEMON_PEER_AUTHORITY_LOCAL) {
        if (!nl_process_identity_move(
                &destination->local, &source->local))
            return false;
    } else if (source->kind == DAEMON_PEER_AUTHORITY_BROKER) {
        destination->lease = source->lease;
        memset(&source->lease, 0, sizeof(source->lease));
    } else {
        return false;
    }
    destination->kind = source->kind;
    source->kind = DAEMON_PEER_AUTHORITY_NONE;
    return true;
}

static bool daemon_capture_peer_authority(
    const nl_daemon_config *cfg, const nl_conn *conn,
    daemon_peer_authority *authority) {
    if (!cfg || !conn || !authority)
        return false;
    daemon_peer_authority_init(authority);
    if (cfg->identity_broker_socket_path) {
        if (nl_identity_broker_capture(
                cfg->identity_broker_socket_path, cfg->service_id,
                conn->peer_pid, conn->peer_uid, conn->peer_gid,
                &authority->lease) != NL_ERR_OK)
            return false;
        authority->kind = DAEMON_PEER_AUTHORITY_BROKER;
        return true;
    }
    if (!daemon_capture_local_peer_identity(conn, &authority->local))
        return false;
    authority->kind = DAEMON_PEER_AUTHORITY_LOCAL;
    return true;
}

static s32 daemon_verify_standard_peer(
    const nl_conn *conn, const nl_msg_hdr *msg,
    const nl_process_identity_handle *identity, const char **reason) {
    const nl_daemon_identity *claimed;
    nl_process_identity_expectation expectation;
    nl_process_identity_result process_result;
    nl_daemon_credentials credentials;
    char executable[NL_DAEMON_EXECUTABLE_PATH_MAX];

    if (reason)
        *reason = "peer-identity-unavailable";
    if (!conn || !msg || !identity)
        return NL_ERR_PERMISSION_DENIED;

    /*
     * INTERNAL is a sealed release authority, not a generic uid-0 identity.
     * Python and ad-hoc root processes cannot claim it directly.
     */
    if (msg->daemon_id == NL_DAEMON_INTERNAL) {
        if (conn->peer_uid != 0 || conn->peer_gid != 0 ||
            identity->baseline.euid != 0 ||
            identity->baseline.egid != 0) {
            if (reason)
                *reason = "internal-authority-credentials-mismatch";
            return NL_ERR_PERMISSION_DENIED;
        }
        if (!nl_daemon_identity_expected_release_binary(
                NL_DAEMON_INTERNAL_AUTHORITY_BINARY, executable,
                sizeof(executable))) {
            if (reason)
                *reason = "internal-authority-executable-unavailable";
            return NL_ERR_PERMISSION_DENIED;
        }
        memset(&expectation, 0, sizeof(expectation));
        expectation.check_euid = true;
        expectation.euid = 0;
        expectation.check_egid = true;
        expectation.egid = 0;
        expectation.executable = executable;
        process_result = nl_process_identity_verify(
            identity, &expectation, NULL);
        if (process_result != NL_PROCESS_IDENTITY_OK) {
            if (reason)
                *reason = nl_process_identity_result_name(process_result);
            return NL_ERR_PERMISSION_DENIED;
        }
        if (reason)
            *reason = "ok";
        return NL_ERR_OK;
    }

    claimed = nl_daemon_identity_lookup((nl_daemon_id)msg->daemon_id);
    if (!nl_daemon_identity_is_peer_process(claimed)) {
        if (reason)
            *reason = claimed ? "non-process-daemon-identity" :
                                "unknown-daemon-identity";
        return NL_ERR_PERMISSION_DENIED;
    }
    if (!nl_daemon_identity_resolve_credentials(claimed, &credentials)) {
        if (reason)
            *reason = "daemon-credentials-unavailable";
        return NL_ERR_PERMISSION_DENIED;
    }
    if (conn->peer_uid != credentials.uid ||
        conn->peer_gid != credentials.primary_gid) {
        if (reason)
            *reason = "socket-credentials-mismatch";
        return NL_ERR_PERMISSION_DENIED;
    }
    if (!nl_daemon_identity_expected_executable(
            claimed, executable, sizeof(executable))) {
        if (reason)
            *reason = "expected-executable-unavailable";
        return NL_ERR_PERMISSION_DENIED;
    }

    memset(&expectation, 0, sizeof(expectation));
    expectation.check_euid = true;
    expectation.euid = credentials.uid;
    expectation.check_egid = true;
    expectation.egid = credentials.primary_gid;
    expectation.executable = executable;
    process_result = nl_process_identity_verify(
        identity, &expectation, NULL);
    if (process_result != NL_PROCESS_IDENTITY_OK) {
        if (reason)
            *reason = nl_process_identity_result_name(process_result);
        return NL_ERR_PERMISSION_DENIED;
    }
    if (reason)
        *reason = "ok";
    return NL_ERR_OK;
}

static s32 daemon_authorize_request(
    const nl_daemon_config *cfg, const nl_conn *conn, const nl_msg_hdr *msg,
    daemon_peer_authority *authority, nl_identity_verify_phase phase,
    const char **reason) {
    const nl_rpc_contract *contract;
    nl_process_identity_result process_result;

    if (reason)
        *reason = "malformed-request";
    if (!cfg || !conn || !msg || !authority ||
        authority->kind == DAEMON_PEER_AUTHORITY_NONE ||
        msg->type != NL_MSG_REQUEST)
        return NL_ERR_MALFORMED_REQUEST;

    if (cfg->auth_mode == NL_DAEMON_AUTH_MANAGEMENT_GATEWAY) {
        if (authority->kind != DAEMON_PEER_AUTHORITY_LOCAL) {
            if (reason)
                *reason = "invalid-peer-authority";
            return NL_ERR_PERMISSION_DENIED;
        }
        process_result = nl_process_identity_revalidate(
            &authority->local, NULL);
        if (process_result != NL_PROCESS_IDENTITY_OK) {
            if (reason)
                *reason = nl_process_identity_result_name(process_result);
            return NL_ERR_PERMISSION_DENIED;
        }
        if (reason)
            *reason = "ok";
        return NL_ERR_OK;
    }

    contract = nl_rpc_contract_lookup(
        cfg->service_id, (nl_rpc_method)msg->method);
    if (!contract ||
        !nl_rpc_contract_payload_valid(
            contract->request_format, msg->payload, msg->payload_len,
            contract->max_request_len)) {
        if (reason)
            *reason = !contract ? "unknown-method" : "invalid-payload";
        return NL_ERR_MALFORMED_REQUEST;
    }
    if ((contract->flags & NL_RPC_CONTRACT_TX_ID_REQUIRED) &&
        msg->tx_id == 0) {
        if (reason)
            *reason = "transaction-id-required";
        return NL_ERR_TX_ID_REQUIRED;
    }
    if (!nl_rpc_contract_caller_allowed(
            contract, (nl_daemon_id)msg->daemon_id)) {
        if (reason)
            *reason = "caller-not-allowed";
        return NL_ERR_PERMISSION_DENIED;
    }
    if (authority->kind == DAEMON_PEER_AUTHORITY_BROKER) {
        if ((nl_daemon_id)msg->daemon_id != cfg->brokered_peer_id ||
            nl_identity_broker_verify(
                cfg->identity_broker_socket_path, cfg->service_id,
                &authority->lease, phase) != NL_ERR_OK) {
            if (reason)
                *reason = "broker-peer-identity-denied";
            return NL_ERR_PERMISSION_DENIED;
        }
        if (reason)
            *reason = "ok";
        return NL_ERR_OK;
    }
    return daemon_verify_standard_peer(
        conn, msg, &authority->local, reason);
}

static void daemon_process_connection(
    nl_daemon_config *cfg, nl_conn *conn,
    daemon_peer_authority *peer_authority,
    daemon_handler_state *state);

static bool scope_participant(nl_daemon_id service) {
    return service == NL_DAEMON_SWITCHD || service == NL_DAEMON_STPD || service == NL_DAEMON_LACPD ||
        service == NL_DAEMON_LLDPD || service == NL_DAEMON_L2D;
}
static bool dispatch_port_scope(nl_conn *conn, const nl_msg_hdr *msg) {
    if (msg->method != NL_PORT_SCOPE_BEGIN && msg->method != NL_PORT_SCOPE_END &&
        msg->method != NL_PORT_SCOPE_STATUS) return false;
    int rc = msg->daemon_id == NL_DAEMON_CONFIGD ? 0 : NL_ERR_PERMISSION_DENIED;
    if (!rc && msg->method == NL_PORT_SCOPE_BEGIN) {
        u32 request[2];
        if (msg->payload_len != sizeof(request)) rc = NL_ERR_MALFORMED_REQUEST;
        else {
            memcpy(request, msg->payload, sizeof(request));
            rc = request[0] != NL_PORT_SCOPE_SCHEMA ? NL_ERR_MALFORMED_REQUEST :
                nl_port_scope_begin(msg->tx_id, request[1], 5000);
        }
    } else if (!rc && msg->method == NL_PORT_SCOPE_END) rc = nl_port_scope_end(msg->tx_id);
    nl_port_scope_status status = nl_port_scope_get();
    nl_msg_hdr *response = nl_msg_alloc(sizeof(status));
    if (response) {
        response->type = NL_MSG_RESPONSE; response->request_id = msg->request_id;
        response->error_code = rc; response->payload_len = sizeof(status);
        memcpy(response->payload, &status, sizeof(status));
        nl_send(conn, response); nl_msg_free(response);
    }
    return true;
}

static bool daemon_dispatch_enter(daemon_handler_state *state) {
    bool entered = false;

    if (!state)
        return false;
    pthread_mutex_lock(&state->lock);
    while (!state->stopping &&
           state->active_dispatch >= state->max_dispatch)
        pthread_cond_wait(&state->cond, &state->lock);
    if (!state->stopping) {
        state->active_dispatch++;
        entered = true;
    }
    pthread_mutex_unlock(&state->lock);
    return entered;
}

static void daemon_dispatch_leave(daemon_handler_state *state) {
    if (!state)
        return;
    pthread_mutex_lock(&state->lock);
    if (state->active_dispatch > 0)
        state->active_dispatch--;
    pthread_cond_broadcast(&state->cond);
    pthread_mutex_unlock(&state->lock);
}

static bool daemon_dispatch_try_enter(daemon_handler_state *state) {
    bool entered = false;

    if (!state)
        return false;
    pthread_mutex_lock(&state->lock);
    if (!state->stopping &&
        state->active_dispatch < state->max_dispatch) {
        state->active_dispatch++;
        entered = true;
    }
    pthread_mutex_unlock(&state->lock);
    return entered;
}

static void daemon_process_connection(
    nl_daemon_config *cfg, nl_conn *conn,
    daemon_peer_authority *peer_authority,
    daemon_handler_state *state) {
    nl_msg_hdr *msg = NULL;
    struct timeval io_timeout = {5, 0};
    const char *reason = "receive-failed";
    s32 authorization;

    if (nl_server_authenticate_timeout(
            conn, DAEMON_AUTH_TIMEOUT_MS) != NL_OK) {
        NL_LOG_DBG("%s: peer authentication failed "
                   "uid=%d gid=%d pid=%d",
                   cfg->name, (int)conn->peer_uid,
                   (int)conn->peer_gid, (int)conn->peer_pid);
        goto out;
    }

    (void)setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO,
                     &io_timeout, sizeof(io_timeout));
    (void)setsockopt(conn->fd, SOL_SOCKET, SO_SNDTIMEO,
                     &io_timeout, sizeof(io_timeout));

    if (nl_recv(conn, &msg) == NL_OK) {
        authorization = daemon_authorize_request(
            cfg, conn, msg, peer_authority,
            NL_IDENTITY_VERIFY_PREQUEUE, &reason);
        if (authorization == NL_ERR_OK) {
            if (!daemon_dispatch_enter(state))
                goto out;
            /*
             * A request may wait behind a serial dispatch.  Revalidate the
             * stable process identity at the final side-effect boundary.
             */
            authorization = daemon_authorize_request(
                cfg, conn, msg, peer_authority,
                NL_IDENTITY_VERIFY_PREDISPATCH, &reason);
            if (authorization == NL_ERR_OK) {
                nl_rpc_deadline_scope_enter(msg->timeout_ms);
                if (!scope_participant(cfg->service_id) || !dispatch_port_scope(conn, msg))
                    cfg->dispatch(conn, msg, cfg->ctx);
                nl_rpc_deadline_scope_leave();
            } else {
                NL_LOG_WARN("%s: peer identity expired while queued "
                            "method=%u caller=%u pid=%d reason=%s",
                            cfg->name, msg->method, msg->daemon_id,
                            (int)conn->peer_pid, reason);
                (void)nl_send_response(
                    conn, msg->request_id, authorization);
            }
            daemon_dispatch_leave(state);
        } else {
            NL_LOG_WARN("%s: request denied method=%u caller=%u "
                        "uid=%d gid=%d pid=%d reason=%s",
                        cfg->name, msg->method, msg->daemon_id,
                        (int)conn->peer_uid, (int)conn->peer_gid,
                        (int)conn->peer_pid, reason);
            (void)nl_send_response(
                conn, msg->request_id, authorization);
        }
    }
out:
    nl_msg_free(msg);
    daemon_peer_authority_close(cfg, peer_authority);
    close(conn->fd);
    conn->fd = -1;
}

static void daemon_handler_complete(
    daemon_handler_state *state, int worker_slot) {
    if (!state || worker_slot < 0 ||
        worker_slot >= DAEMON_MAX_CONNECTIONS)
        return;
    pthread_mutex_lock(&state->lock);
    if (state->active_connections > 0)
        state->active_connections--;
    if (state->worker_slots[worker_slot] == DAEMON_WORKER_ACTIVE)
        state->worker_slots[worker_slot] = DAEMON_WORKER_DONE;
    pthread_cond_broadcast(&state->cond);
    pthread_mutex_unlock(&state->lock);
}

static void *daemon_handler_main(void *arg) {
    daemon_handler_job *job = arg;
    daemon_handler_state *state;
    int worker_slot;

    if (!job)
        return NULL;
    state = job->state;
    worker_slot = job->worker_slot;
    daemon_process_connection(
        job->cfg, &job->conn, &job->peer_authority, state);
    free(job);
    daemon_handler_complete(state, worker_slot);
    return NULL;
}

static void daemon_reap_completed_handlers(daemon_handler_state *state) {
    if (!state)
        return;

    for (;;) {
        pthread_t tid;
        int slot = -1;
        int join_result;

        pthread_mutex_lock(&state->lock);
        for (int i = 0; i < DAEMON_MAX_CONNECTIONS; i++) {
            if (state->worker_slots[i] == DAEMON_WORKER_DONE) {
                state->worker_slots[i] = DAEMON_WORKER_REAPING;
                tid = state->workers[i];
                slot = i;
                break;
            }
        }
        pthread_mutex_unlock(&state->lock);
        if (slot < 0)
            return;

        join_result = pthread_join(tid, NULL);
        if (join_result != 0) {
            NL_LOG_CRIT("failed to join IPC worker slot=%d error=%d",
                        slot, join_result);
            abort();
        }

        pthread_mutex_lock(&state->lock);
        state->worker_slots[slot] = DAEMON_WORKER_FREE;
        memset(&state->workers[slot], 0, sizeof(state->workers[slot]));
        pthread_cond_broadcast(&state->cond);
        pthread_mutex_unlock(&state->lock);
    }
}

static bool daemon_start_handler(daemon_handler_state *state,
                                 nl_daemon_config *cfg,
                                 const nl_conn *conn,
                                 daemon_peer_authority *peer_authority) {
    daemon_handler_job *job;
    int worker_slot = -1;

    if (!state || !cfg || !conn || !peer_authority)
        return false;

    daemon_reap_completed_handlers(state);
    pthread_mutex_lock(&state->lock);
    if (state->stopping ||
        state->active_connections >= state->max_connections) {
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    for (int i = 0; i < DAEMON_MAX_CONNECTIONS; i++) {
        if (state->worker_slots[i] == DAEMON_WORKER_FREE) {
            worker_slot = i;
            break;
        }
    }
    if (worker_slot < 0) {
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    state->worker_slots[worker_slot] = DAEMON_WORKER_ACTIVE;
    state->active_connections++;
    pthread_mutex_unlock(&state->lock);

    job = calloc(1, sizeof(*job));
    if (!job) {
        pthread_mutex_lock(&state->lock);
        state->worker_slots[worker_slot] = DAEMON_WORKER_FREE;
        state->active_connections--;
        pthread_cond_broadcast(&state->cond);
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    job->cfg = cfg;
    job->conn = *conn;
    job->state = state;
    job->worker_slot = worker_slot;
    daemon_peer_authority_init(&job->peer_authority);
    if (!daemon_peer_authority_move(
            &job->peer_authority, peer_authority)) {
        pthread_mutex_lock(&state->lock);
        state->worker_slots[worker_slot] = DAEMON_WORKER_FREE;
        state->active_connections--;
        pthread_cond_broadcast(&state->cond);
        pthread_mutex_unlock(&state->lock);
        free(job);
        return false;
    }

    pthread_mutex_lock(&state->lock);
    if (pthread_create(
            &state->workers[worker_slot], NULL,
            daemon_handler_main, job) != 0) {
        state->worker_slots[worker_slot] = DAEMON_WORKER_FREE;
        state->active_connections--;
        pthread_cond_broadcast(&state->cond);
        pthread_mutex_unlock(&state->lock);
        daemon_peer_authority_close(cfg, &job->peer_authority);
        free(job);
        return false;
    }
    pthread_mutex_unlock(&state->lock);
    return true;
}

static void daemon_begin_stopping(daemon_handler_state *state) {
    if (!state)
        return;
    pthread_mutex_lock(&state->lock);
    state->stopping = true;
    pthread_cond_broadcast(&state->cond);
    pthread_mutex_unlock(&state->lock);
}

static void daemon_wait_for_handlers(daemon_handler_state *state) {
    if (!state)
        return;
    pthread_mutex_lock(&state->lock);
    while (state->active_connections > 0)
        pthread_cond_wait(&state->cond, &state->lock);
    pthread_mutex_unlock(&state->lock);
    daemon_reap_completed_handlers(state);
}

static void daemon_destroy_handler_state(daemon_handler_state *state) {
    if (!state)
        return;
    daemon_begin_stopping(state);
    daemon_wait_for_handlers(state);
    pthread_cond_destroy(&state->cond);
    pthread_mutex_destroy(&state->lock);
}

static bool daemon_set_cloexec(int fd) {
    int flags;

    if (fd < 0)
        return false;
    flags = fcntl(fd, F_GETFD);
    return flags >= 0 &&
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static bool daemon_expected_credentials_active(
    const nl_daemon_identity *identity) {
    nl_daemon_credentials expected;
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;
    gid_t real_gid;
    gid_t effective_gid;
    gid_t saved_gid;

    if (!identity ||
        !nl_daemon_identity_resolve_credentials(identity, &expected) ||
        getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0)
        return false;
    return real_uid == expected.uid &&
        effective_uid == expected.uid &&
        saved_uid == expected.uid &&
        real_gid == expected.primary_gid &&
        effective_gid == expected.primary_gid &&
        saved_gid == expected.primary_gid;
}

static bool daemon_dedicated_groups_active(
    const nl_daemon_identity *identity) {
    gid_t expected_group;
    gid_t groups[2];
    int count;

    if (!identity ||
        !identity->dedicated_account ||
        strcmp(identity->expected_account,
               identity->dedicated_account) != 0 ||
        !nl_daemon_identity_resolve_private_ipc_gid(
            identity, &expected_group))
        return false;
    count = getgroups(0, NULL);
    if (count != 1 ||
        getgroups((int)(sizeof(groups) / sizeof(groups[0])), groups) != 1)
        return false;
    return groups[0] == expected_group;
}

static bool daemon_capability_set_active(
    const nl_daemon_identity *identity) {
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    u64 permitted;
    u64 effective;
    u64 inheritable;
    u64 bounding = 0;
    int no_new_privileges;

    if (!identity)
        return false;
    memset(&header, 0, sizeof(header));
    memset(data, 0, sizeof(data));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    if (syscall(SYS_capget, &header, data) != 0)
        return false;
    permitted = (u64)data[0].permitted |
        ((u64)data[1].permitted << 32);
    effective = (u64)data[0].effective |
        ((u64)data[1].effective << 32);
    inheritable = (u64)data[0].inheritable |
        ((u64)data[1].inheritable << 32);
    for (unsigned int capability = 0;
         capability < DAEMON_CAPABILITY_BITS; capability++) {
        int bounded = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        int ambient = prctl(
            PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);

        if (bounded < 0) {
            if (errno == EINVAL)
                break;
            return false;
        }
        if (bounded == 1)
            bounding |= UINT64_C(1) << capability;
        if (ambient != 0)
            return false;
    }
    no_new_privileges = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    return permitted == identity->capability_mask &&
        effective == identity->capability_mask &&
        inheritable == 0 &&
        bounding == identity->capability_mask &&
        no_new_privileges ==
            (identity->no_new_privileges ? 1 : 0);
}

static bool daemon_inherited_listener_valid(
    const nl_daemon_config *cfg,
    const nl_daemon_identity *identity) {
    struct sockaddr_un address;
    char canonical_ready[NL_DAEMON_EXECUTABLE_PATH_MAX];
    char descriptor_path[64];
    char ready_path[sizeof(address.sun_path) + 16];
    char ready_target[sizeof(ready_path) + 16];
    struct stat listener_stat;
    struct stat socket_stat;
    struct stat ready_stat;
    socklen_t address_length = sizeof(address);
    socklen_t option_length;
    gid_t expected_group;
    int socket_type = 0;
    int accepting = 0;
    int written;
    ssize_t target_length;

    if (!cfg || !identity ||
        cfg->inherited_listen_fd != DAEMON_INHERITED_LISTENER_FD ||
        cfg->ready_fd != DAEMON_INHERITED_READY_FD ||
        !daemon_expected_credentials_active(identity) ||
        !daemon_dedicated_groups_active(identity) ||
        !daemon_capability_set_active(identity) ||
        !nl_daemon_identity_resolve_private_ipc_gid(
            identity, &expected_group))
        return false;

    memset(&address, 0, sizeof(address));
    if (getsockname(
            cfg->inherited_listen_fd, (struct sockaddr *)&address,
            &address_length) != 0 ||
        address.sun_family != AF_UNIX ||
        address.sun_path[0] != '/' ||
        strcmp(address.sun_path, cfg->socket_path) != 0)
        return false;
    option_length = sizeof(socket_type);
    if (getsockopt(
            cfg->inherited_listen_fd, SOL_SOCKET, SO_TYPE,
            &socket_type, &option_length) != 0 ||
        option_length != sizeof(socket_type) ||
        socket_type != SOCK_SEQPACKET)
        return false;
    option_length = sizeof(accepting);
    if (getsockopt(
            cfg->inherited_listen_fd, SOL_SOCKET, SO_ACCEPTCONN,
            &accepting, &option_length) != 0 ||
        option_length != sizeof(accepting) || accepting != 1)
        return false;
    if (fstat(cfg->inherited_listen_fd, &listener_stat) != 0 ||
        !S_ISSOCK(listener_stat.st_mode) ||
        lstat(cfg->socket_path, &socket_stat) != 0 ||
        !S_ISSOCK(socket_stat.st_mode) ||
        socket_stat.st_uid != 0 ||
        socket_stat.st_gid != expected_group ||
        (socket_stat.st_mode &
         (S_IRWXU | S_IRWXG | S_IRWXO |
          S_ISUID | S_ISGID | S_ISVTX)) != 0660)
        return false;
    if (fstat(cfg->ready_fd, &ready_stat) != 0 ||
        !S_ISREG(ready_stat.st_mode) ||
        ready_stat.st_uid != 0 ||
        ready_stat.st_gid != 0 ||
        ready_stat.st_nlink != 1 ||
        (ready_stat.st_mode &
         (S_IRWXU | S_IRWXG | S_IRWXO |
          S_ISUID | S_ISGID | S_ISVTX)) != 0600)
        return false;
    written = snprintf(
        ready_path, sizeof(ready_path), "%s.ready", cfg->socket_path);
    if (written <= 0 || (size_t)written >= sizeof(ready_path))
        return false;
    written = snprintf(
        descriptor_path, sizeof(descriptor_path), "/proc/self/fd/%d",
        cfg->ready_fd);
    if (written <= 0 || (size_t)written >= sizeof(descriptor_path))
        return false;
    target_length = readlink(
        descriptor_path, ready_target, sizeof(ready_target) - 1U);
    if (target_length <= 0 ||
        (size_t)target_length >= sizeof(ready_target) - 1U)
        return false;
    ready_target[target_length] = '\0';
    if (!realpath(ready_path, canonical_ready) ||
        strcmp(ready_target, canonical_ready) != 0)
        return false;
    return daemon_set_cloexec(cfg->inherited_listen_fd) &&
        daemon_set_cloexec(cfg->ready_fd);
}

static bool daemon_publish_ready(int ready_fd) {
    nl_process_identity_handle identity =
        NL_PROCESS_IDENTITY_HANDLE_INITIALIZER;
    char record[128];
    size_t offset = 0;
    int length;
    bool ok = false;

    if (ready_fd < 0)
        return true;
    if (nl_process_identity_open(getpid(), &identity) !=
        NL_PROCESS_IDENTITY_OK)
        goto out;
    length = snprintf(
        record, sizeof(record), "pid=%ld starttime=%llu\n",
        (long)getpid(),
        (unsigned long long)identity.baseline.starttime);
    if (length <= 0 || (size_t)length >= sizeof(record) ||
        ftruncate(ready_fd, 0) != 0 ||
        lseek(ready_fd, 0, SEEK_SET) < 0)
        goto out;
    while (offset < (size_t)length) {
        ssize_t written = write(
            ready_fd, record + offset, (size_t)length - offset);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            goto out;
        offset += (size_t)written;
    }
    ok = fsync(ready_fd) == 0;
out:
    nl_process_identity_close(&identity);
    return ok;
}

int nl_daemon_run(nl_daemon_config *cfg) {
    daemon_handler_state handler_state;
    const nl_daemon_identity *service_identity;
    bool dedicated_identity;
    bool inherited_listener;
    int configured_dispatch;
    int listen_fd = -1;
    int epfd = -1;
    int ready_fd = -1;

    if (!cfg || !cfg->name || !cfg->socket_path || !cfg->dispatch ||
        (cfg->auth_mode != NL_DAEMON_AUTH_STANDARD &&
         cfg->auth_mode != NL_DAEMON_AUTH_MANAGEMENT_GATEWAY)) {
        return 1;
    }
    service_identity = nl_daemon_identity_lookup(cfg->service_id);
    if (!service_identity ||
        strcmp(service_identity->name, cfg->name) != 0 ||
        (cfg->auth_mode == NL_DAEMON_AUTH_STANDARD &&
         !nl_daemon_identity_is_peer_process(service_identity)) ||
        (cfg->auth_mode == NL_DAEMON_AUTH_MANAGEMENT_GATEWAY &&
         cfg->service_id != NL_DAEMON_MGMTD))
        return 1;
    dedicated_identity =
        service_identity->dedicated_account &&
        strcmp(service_identity->expected_account,
               service_identity->dedicated_account) == 0;
    inherited_listener =
        cfg->inherited_listen_fd >= DAEMON_INHERITED_LISTENER_FD ||
        cfg->ready_fd >= DAEMON_INHERITED_LISTENER_FD;
    if (!daemon_expected_credentials_active(service_identity) ||
        (dedicated_identity != inherited_listener) ||
        (inherited_listener &&
         !daemon_inherited_listener_valid(cfg, service_identity)))
        return 1;
    if (dedicated_identity &&
        !daemon_dedicated_groups_active(service_identity))
        return 1;
    if ((cfg->identity_broker_socket_path != NULL) !=
            (cfg->brokered_peer_id != NL_DAEMON_INTERNAL) ||
        (cfg->identity_broker_socket_path &&
         (cfg->service_id != NL_DAEMON_CHASSISD ||
          cfg->brokered_peer_id != NL_DAEMON_MGMTD ||
          strcmp(cfg->identity_broker_socket_path,
                 "/var/run/netlab/identityd.sock") != 0)))
        return 1;
    configured_dispatch = cfg->max_concurrent_handlers > 0 ?
        cfg->max_concurrent_handlers : 1;
    if (configured_dispatch > DAEMON_MAX_CONNECTIONS)
        return 1;

    // Initialize logging
    nl_log_init(cfg->name, LOG_DAEMON, NL_LOG_INFO);
    NL_LOG_INFO("%s starting...", cfg->name);

    // Set up signal handlers
    signal(SIGINT, daemon_signal_handler);
    signal(SIGTERM, daemon_signal_handler);
    signal(SIGPIPE, SIG_IGN);

    // Root daemons may prepare development paths. Dedicated identities must
    // consume the root-controlled host layout without trying to create it.
    if (geteuid() == 0) {
        (void)mkdir("/var/run/netlab", 0755);
        (void)mkdir("/var/lib/netlab", 0755);
    }

    if (scope_participant(cfg->service_id) && nl_port_scope_init(cfg->name)) return 1;

    memset(&handler_state, 0, sizeof(handler_state));
    handler_state.max_dispatch = configured_dispatch;
    handler_state.max_connections =
        configured_dispatch + DAEMON_AUTH_HEADROOM;
    if (handler_state.max_connections > DAEMON_MAX_CONNECTIONS)
        handler_state.max_connections = DAEMON_MAX_CONNECTIONS;
    pthread_mutex_init(&handler_state.lock, NULL);
    pthread_cond_init(&handler_state.cond, NULL);
    NL_LOG_INFO("%s: bounded IPC workers connections=%d dispatch=%d",
                cfg->name, handler_state.max_connections,
                handler_state.max_dispatch);

    // Create or adopt the listening socket before daemon-owned workers start.
    if (inherited_listener) {
        listen_fd = cfg->inherited_listen_fd;
        ready_fd = cfg->ready_fd;
    } else if (nl_server_listen(cfg->socket_path, &listen_fd) != NL_OK) {
        NL_LOG_CRIT("%s: failed to create listening socket", cfg->name);
        daemon_begin_stopping(&handler_state);
        if (cfg->on_stopping)
            cfg->on_stopping(cfg->ctx);
        daemon_destroy_handler_state(&handler_state);
        if (cfg->on_shutdown)
            cfg->on_shutdown(cfg->ctx);
        return 1;
    }

    // Set up epoll
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        NL_LOG_CRIT("%s: epoll_create1 failed", cfg->name);
        daemon_begin_stopping(&handler_state);
        if (cfg->on_stopping)
            cfg->on_stopping(cfg->ctx);
        daemon_destroy_handler_state(&handler_state);
        if (cfg->on_shutdown)
            cfg->on_shutdown(cfg->ctx);
        close(listen_fd);
        if (!inherited_listener)
            (void)nl_ipc_unlink_socket(cfg->socket_path);
        return 1;
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        NL_LOG_CRIT("%s: epoll_ctl failed", cfg->name);
        daemon_begin_stopping(&handler_state);
        if (cfg->on_stopping)
            cfg->on_stopping(cfg->ctx);
        daemon_destroy_handler_state(&handler_state);
        if (cfg->on_shutdown)
            cfg->on_shutdown(cfg->ctx);
        close(epfd);
        close(listen_fd);
        if (!inherited_listener)
            (void)nl_ipc_unlink_socket(cfg->socket_path);
        return 1;
    }

    // Optional daemon initialization happens only after every root-owned
    // descriptor has been validated and registered.
    if (cfg->on_init && cfg->on_init(cfg->ctx) != 0) {
        NL_LOG_CRIT("%s: on_init failed", cfg->name);
        daemon_begin_stopping(&handler_state);
        daemon_destroy_handler_state(&handler_state);
        close(epfd);
        close(listen_fd);
        if (!inherited_listener)
            (void)nl_ipc_unlink_socket(cfg->socket_path);
        return 1;
    }
    if (!daemon_publish_ready(ready_fd)) {
        NL_LOG_CRIT("%s: failed to publish readiness", cfg->name);
        daemon_begin_stopping(&handler_state);
        if (cfg->on_stopping)
            cfg->on_stopping(cfg->ctx);
        daemon_destroy_handler_state(&handler_state);
        if (cfg->on_shutdown)
            cfg->on_shutdown(cfg->ctx);
        close(epfd);
        close(listen_fd);
        close(ready_fd);
        if (!inherited_listener)
            (void)nl_ipc_unlink_socket(cfg->socket_path);
        return 1;
    }
    if (ready_fd >= 0) {
        close(ready_fd);
        ready_fd = -1;
    }

    NL_LOG_NOTICE("%s ready, listening on %s", cfg->name, cfg->socket_path);

    s64 last_idle = 0;
    struct timespec ts_now;

    if (cfg->on_idle && cfg->poll_interval_ms > 0) {
        clock_gettime(CLOCK_MONOTONIC, &ts_now);
        last_idle = ts_now.tv_sec * 1000LL + ts_now.tv_nsec / 1000000LL;
    }

    while (g_running) {
        int timeout_ms = cfg->poll_interval_ms;
        if (timeout_ms <= 0) timeout_ms = 1000;  // default 1s for signal check

        struct epoll_event events[16];
        int nfds = epoll_wait(epfd, events, 16, timeout_ms);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // Idle callback
        if (cfg->on_idle && cfg->poll_interval_ms > 0) {
            clock_gettime(CLOCK_MONOTONIC, &ts_now);
            s64 now_ms = ts_now.tv_sec * 1000LL + ts_now.tv_nsec / 1000000LL;
            if (now_ms - last_idle >= cfg->poll_interval_ms) {
                bool run_idle = handler_state.max_dispatch != 1 ||
                    daemon_dispatch_try_enter(&handler_state);
                if (run_idle) {
                    cfg->on_idle(cfg->ctx, now_ms - last_idle);
                    if (handler_state.max_dispatch == 1)
                        daemon_dispatch_leave(&handler_state);
                    last_idle = now_ms;
                }
            }
        }

        // Process events
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == listen_fd) {
                nl_conn conn;
                daemon_peer_authority peer_authority;

                if (nl_server_accept(listen_fd, &conn) != NL_OK)
                    continue;

                NL_LOG_DBG("%s: new connection from uid=%d",
                           cfg->name, conn.peer_uid);
                daemon_peer_authority_init(&peer_authority);
                if (!daemon_capture_peer_authority(
                        cfg, &conn, &peer_authority)) {
                    close(conn.fd);
                    conn.fd = -1;
                    continue;
                }
                if (daemon_start_handler(
                        &handler_state, cfg, &conn, &peer_authority))
                    continue;
                NL_LOG_DBG("%s: connection worker limit reached; "
                           "closing connection", cfg->name);
                daemon_peer_authority_close(cfg, &peer_authority);
                close(conn.fd);
                conn.fd = -1;
            }
        }
    }

    // Shutdown
    daemon_begin_stopping(&handler_state);
    if (cfg->on_stopping)
        cfg->on_stopping(cfg->ctx);
    daemon_destroy_handler_state(&handler_state);
    if (cfg->on_shutdown) cfg->on_shutdown(cfg->ctx);

    close(epfd);
    close(listen_fd);
    if (!inherited_listener)
        (void)nl_ipc_unlink_socket(cfg->socket_path);
    NL_LOG_NOTICE("%s stopped", cfg->name);
    return 0;
}
