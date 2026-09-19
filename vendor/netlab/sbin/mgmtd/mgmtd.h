/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_MGMTD_H
#define NETLAB_MGMTD_H

#include "netlab/ipc.h"
#include "netlab/types.h"
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

#define MGMTD_SOCKET "/var/run/netlab/mgmtd.sock"
#define MGMTD_AUDIT_LOG "/var/lib/netlab/mgmtd-audit.log"

typedef enum {
    MGMTD_ACCESS_VIEW = 0,
    MGMTD_ACCESS_CONFIG,
    MGMTD_ACCESS_COMMIT,
    MGMTD_ACCESS_CLEAR,
    MGMTD_ACCESS_ADMIN,
} mgmtd_access;

typedef enum {
    MGMTD_BACKEND_NL_RPC = 0,
    MGMTD_BACKEND_PACKETD_STATS,
    MGMTD_BACKEND_PACKETD_RELOAD,
} mgmtd_backend_adapter;

typedef struct {
    bool ok;
    u16 daemon_id;
    u16 method;
    const nl_rpc_contract *contract;
    const char *daemon_name;
    const char *socket_path;
    const char *description;
    mgmtd_access access;
    mgmtd_backend_adapter adapter;
} mgmtd_route;

typedef struct {
    u16 daemon_id;
    const char *daemon_name;
    const char *socket_path;
    const char *description;
    bool virtual_route;
} mgmtd_backend_info;

#define MGMTD_RECENT_SESSIONS_MAX 16

typedef struct {
    u64 total_sessions;
    u64 active_sessions;
    u64 total_requests;
    u64 routed_requests;
    u64 denied_requests;
    u64 malformed_requests;
    u64 backend_errors;
} mgmtd_session_stats;

typedef struct {
    u64 session_id;
    long age_sec;
    uid_t uid;
    gid_t gid;
    pid_t pid;
    u16 schema_version;
    u16 daemon_id;
    u16 method;
    char daemon_name[32];
    char access[16];
    char description[80];
    s32 result;
    u32 payload_len;
    long elapsed_ms;
} mgmtd_session_event;

typedef struct {
    mgmtd_session_stats stats;
    u64 next_session_id;
    mgmtd_session_event recent[MGMTD_RECENT_SESSIONS_MAX];
    size_t recent_head;
    size_t recent_count;
} mgmtd_session_store;

typedef struct {
    u64 session_id;
    struct timespec start_mono;
    time_t start_wall;
} mgmtd_session;

const char *mgmtd_access_name(mgmtd_access access);
mgmtd_route mgmtd_lookup_route(u16 daemon_id, u16 method);
bool mgmtd_access_allowed(const nl_conn *conn, mgmtd_access access);
bool mgmtd_panel_request_allowed(const nl_conn *conn, const mgmtd_route *route);

size_t mgmtd_backend_count(void);
const mgmtd_backend_info *mgmtd_backend_at(size_t index);
const char *mgmtd_backend_socket_path(const mgmtd_backend_info *backend);

s32 mgmtd_forward_to_backend(nl_conn *client_conn, nl_msg_hdr *msg,
                             const mgmtd_route *route);

void mgmtd_sessions_init(mgmtd_session_store *store);
mgmtd_session mgmtd_session_begin(mgmtd_session_store *store);
void mgmtd_session_note_routed(mgmtd_session_store *store);
void mgmtd_session_note_denied(mgmtd_session_store *store);
void mgmtd_session_note_malformed(mgmtd_session_store *store);
void mgmtd_session_note_backend_error(mgmtd_session_store *store);
void mgmtd_session_finish(mgmtd_session_store *store,
                          const mgmtd_session *session,
                          const nl_conn *conn,
                          const mgmtd_route *route,
                          s32 result,
                          u32 payload_len,
                          long elapsed_ms);
void mgmtd_sessions_snapshot(const mgmtd_session_store *store,
                             mgmtd_session_stats *stats);
size_t mgmtd_sessions_recent(const mgmtd_session_store *store,
                             mgmtd_session_event *out,
                             size_t max_events);

#endif
