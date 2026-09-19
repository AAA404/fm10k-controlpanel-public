#include "mgmtd.h"
#include <stdio.h>
#include <string.h>

static void copy_text(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0)
        return;
    snprintf(dst, dst_size, "%s", src ? src : "-");
}

void mgmtd_sessions_init(mgmtd_session_store *store) {
    if (store)
        memset(store, 0, sizeof(*store));
}

mgmtd_session mgmtd_session_begin(mgmtd_session_store *store) {
    mgmtd_session session;

    memset(&session, 0, sizeof(session));
    clock_gettime(CLOCK_MONOTONIC, &session.start_mono);
    session.start_wall = time(NULL);

    if (!store)
        return session;

    session.session_id = ++store->next_session_id;
    store->stats.total_sessions++;
    store->stats.active_sessions++;
    store->stats.total_requests++;
    return session;
}

void mgmtd_session_note_routed(mgmtd_session_store *store) {
    if (store)
        store->stats.routed_requests++;
}

void mgmtd_session_note_denied(mgmtd_session_store *store) {
    if (store)
        store->stats.denied_requests++;
}

void mgmtd_session_note_malformed(mgmtd_session_store *store) {
    if (store)
        store->stats.malformed_requests++;
}

void mgmtd_session_note_backend_error(mgmtd_session_store *store) {
    if (store)
        store->stats.backend_errors++;
}

void mgmtd_session_finish(mgmtd_session_store *store,
                          const mgmtd_session *session,
                          const nl_conn *conn,
                          const mgmtd_route *route,
                          s32 result,
                          u32 payload_len,
                          long elapsed_ms) {
    mgmtd_session_event *event;
    time_t now;

    if (!store || !session)
        return;

    if (store->stats.active_sessions > 0)
        store->stats.active_sessions--;

    event = &store->recent[store->recent_head];
    memset(event, 0, sizeof(*event));
    now = time(NULL);

    event->session_id = session->session_id;
    event->age_sec = session->start_wall > 0 ? (long)(now - session->start_wall) : 0;
    event->uid = conn ? conn->peer_uid : (uid_t)-1;
    event->gid = conn ? conn->peer_gid : (gid_t)-1;
    event->pid = conn ? conn->peer_pid : (pid_t)-1;
    event->schema_version = conn && conn->peer_schema_known ?
                            conn->peer_schema_version : 0;
    event->daemon_id = route ? route->daemon_id : 0;
    event->method = route ? route->method : 0;
    copy_text(event->daemon_name, sizeof(event->daemon_name),
              route ? route->daemon_name : "-");
    copy_text(event->access, sizeof(event->access),
              route ? mgmtd_access_name(route->access) : "unknown");
    copy_text(event->description, sizeof(event->description),
              route ? route->description : "-");
    event->result = result;
    event->payload_len = payload_len;
    event->elapsed_ms = elapsed_ms;

    store->recent_head = (store->recent_head + 1) % MGMTD_RECENT_SESSIONS_MAX;
    if (store->recent_count < MGMTD_RECENT_SESSIONS_MAX)
        store->recent_count++;
}

void mgmtd_sessions_snapshot(const mgmtd_session_store *store,
                             mgmtd_session_stats *stats) {
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (store)
        *stats = store->stats;
}

size_t mgmtd_sessions_recent(const mgmtd_session_store *store,
                             mgmtd_session_event *out,
                             size_t max_events) {
    size_t n;

    if (!store || !out || max_events == 0)
        return 0;

    n = store->recent_count < max_events ? store->recent_count : max_events;
    for (size_t i = 0; i < n; i++) {
        size_t newest = (store->recent_head + MGMTD_RECENT_SESSIONS_MAX - 1 - i) %
                        MGMTD_RECENT_SESSIONS_MAX;
        out[i] = store->recent[newest];
    }
    return n;
}
