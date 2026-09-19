#ifndef NETLAB_SESSION_H
#define NETLAB_SESSION_H

#include "types.h"
#include <sys/types.h>
#include <stdio.h>

#define NL_SESSION_ID_MAX 128

typedef struct {
    u64     session_id;
    int     fd;
    uid_t   uid;
    gid_t   gid;
    pid_t   pid;
    u64     base_active_commit_id;
    bool    exclusive;
    s64     started_at;
    bool    is_dirty;
    char    remote_addr[64];
} nl_session;

typedef struct {
    nl_session sessions[NL_SESSION_ID_MAX];
    int        num_sessions;
} nl_session_mgr;

nl_session_mgr *nl_session_mgr_create(void);
void            nl_session_mgr_destroy(nl_session_mgr *mgr);
nl_session     *nl_session_create(nl_session_mgr *mgr, int fd,
                                  uid_t uid, gid_t gid, pid_t pid);
nl_session     *nl_session_find(nl_session_mgr *mgr, u64 session_id);
void            nl_session_destroy(nl_session_mgr *mgr, u64 session_id);
nl_status       nl_session_check_conflict(nl_session_mgr *mgr,
                                          u64 session_id,
                                          u64 current_active_commit_id);

#endif
