#include "netlab/session.h"
#include "netlab/log.h"
#include <stdlib.h>
#include <string.h>

nl_session_mgr *nl_session_mgr_create(void) {
    nl_session_mgr *mgr = calloc(1, sizeof(*mgr));
    if (!mgr) return NULL;
    return mgr;
}

void nl_session_mgr_destroy(nl_session_mgr *mgr) {
    free(mgr);
}

nl_session *nl_session_create(nl_session_mgr *mgr, int fd,
                              uid_t uid, gid_t gid, pid_t pid) {
    if (!mgr || mgr->num_sessions >= NL_SESSION_ID_MAX) return NULL;

    nl_session *s = &mgr->sessions[mgr->num_sessions++];
    s->session_id = mgr->num_sessions;
    s->fd = fd;
    s->uid = uid;
    s->gid = gid;
    s->pid = pid;
    s->base_active_commit_id = 0;
    s->exclusive = false;
    s->started_at = 0;
    s->is_dirty = false;
    snprintf(s->remote_addr, sizeof(s->remote_addr), "pid=%d", pid);

    NL_LOG_INFO("session created id=%lu uid=%d gid=%d pid=%d",
                s->session_id, uid, gid, pid);
    return s;
}

nl_session *nl_session_find(nl_session_mgr *mgr, u64 session_id) {
    if (!mgr) return NULL;
    for (int i = 0; i < mgr->num_sessions; i++) {
        if (mgr->sessions[i].session_id == session_id)
            return &mgr->sessions[i];
    }
    return NULL;
}

void nl_session_destroy(nl_session_mgr *mgr, u64 session_id) {
    if (!mgr) return;
    for (int i = 0; i < mgr->num_sessions; i++) {
        if (mgr->sessions[i].session_id == session_id) {
            mgr->sessions[i] = mgr->sessions[--mgr->num_sessions];
            NL_LOG_INFO("session destroyed id=%lu", session_id);
            return;
        }
    }
}

nl_status nl_session_check_conflict(nl_session_mgr *mgr,
                                    u64 session_id,
                                    u64 current_active_commit_id) {
    nl_session *s = nl_session_find(mgr, session_id);
    if (!s) return NL_ERR;

    if (s->base_active_commit_id != 0 &&
        s->base_active_commit_id != current_active_commit_id) {
        NL_LOG_WARN("commit conflict session=%lu base=0x%lx current=0x%lx",
                    session_id, s->base_active_commit_id, current_active_commit_id);
        return NL_ERR;
    }
    return NL_OK;
}
