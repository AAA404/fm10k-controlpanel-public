#include "fpm.h"
#include "rib.h"
#include "netlab/log.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/nexthop.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RPD_FPM_VERSION 1
#define RPD_FPM_MSG_TYPE_NETLINK 1

typedef struct rpd_fpm_pending_frame {
    struct rpd_fpm_pending_frame *next;
    u8 *message;
    size_t message_len;
} rpd_fpm_pending_frame;

typedef enum {
    RPD_FPM_PROCESS_HANDLE_NONE = 0,
    RPD_FPM_PROCESS_HANDLE_PIDFD,
    RPD_FPM_PROCESS_HANDLE_PROCFD,
} rpd_fpm_process_handle_kind;

typedef struct {
    int fd;
    rpd_fpm_process_handle_kind kind;
} rpd_fpm_process_handle;

typedef struct {
    rpd_fpm_peer_identity peer;
    rpd_fpm_process_handle process;
} rpd_fpm_connection_identity;

static void str_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0)
        return;
    snprintf(dst, dst_size, "%s", src ? src : "");
}

static bool decimal_string(const char *s) {
    if (!s || !s[0])
        return false;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return false;
    }
    return true;
}

static bool proc_tcp_client_inode(int fd, unsigned long long *inode) {
    struct sockaddr_in local;
    struct sockaddr_in peer;
    socklen_t local_len = sizeof(local);
    socklen_t peer_len = sizeof(peer);
    FILE *fp;
    char line[512];
    bool found = false;

    if (!inode)
        return false;
    *inode = 0;
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0 ||
        getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0 ||
        local.sin_family != AF_INET || peer.sin_family != AF_INET)
        return false;

    fp = fopen("/proc/net/tcp", "r");
    if (!fp)
        return false;
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }
    while (fgets(line, sizeof(line), fp)) {
        unsigned int local_addr = 0;
        unsigned int local_port = 0;
        unsigned int remote_addr = 0;
        unsigned int remote_port = 0;
        unsigned int state = 0;
        unsigned long long candidate_inode = 0;
        int n = sscanf(line,
                       " %*d: %8X:%4X %8X:%4X %2X %*s %*s %*s %*u %*u %llu",
                       &local_addr, &local_port, &remote_addr, &remote_port,
                       &state, &candidate_inode);

        if (n == 6 && state == 1 &&
            local_addr == peer.sin_addr.s_addr &&
            local_port == ntohs(peer.sin_port) &&
            remote_addr == local.sin_addr.s_addr &&
            remote_port == ntohs(local.sin_port)) {
            *inode = candidate_inode;
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

static int proc_handle_open_file(const rpd_fpm_process_handle *process,
                                 pid_t pid, const char *name, int flags) {
    char path[160];

    if (process &&
        process->kind == RPD_FPM_PROCESS_HANDLE_PROCFD) {
        return openat(process->fd, name, flags | O_CLOEXEC);
    }
    if (pid <= 0 ||
        snprintf(path, sizeof(path), "/proc/%ld/%s",
                 (long)pid, name) >= (int)sizeof(path))
        return -1;
    return open(path, flags | O_CLOEXEC);
}

static bool proc_handle_owns_socket(
    const rpd_fpm_process_handle *process, pid_t pid,
    unsigned long long inode) {
    DIR *fds;
    struct dirent *fd_ent;
    char fd_dir[128];
    char expected[64];
    int fd_dir_fd;

    if (pid <= 0 || inode == 0)
        return false;
    snprintf(expected, sizeof(expected), "socket:[%llu]", inode);
    if (process &&
        process->kind == RPD_FPM_PROCESS_HANDLE_PROCFD) {
        fd_dir_fd = openat(process->fd, "fd",
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } else {
        if (snprintf(fd_dir, sizeof(fd_dir), "/proc/%ld/fd",
                     (long)pid) >= (int)sizeof(fd_dir))
            return false;
        fd_dir_fd = open(fd_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    if (fd_dir_fd < 0)
        return false;
    fds = fdopendir(fd_dir_fd);
    if (!fds)
        close(fd_dir_fd);
    if (!fds)
        return false;
    while ((fd_ent = readdir(fds))) {
        char target[256];
        ssize_t target_len;

        if (!decimal_string(fd_ent->d_name))
            continue;
        target_len = readlinkat(fd_dir_fd, fd_ent->d_name,
                                target, sizeof(target) - 1);
        if (target_len <= 0)
            continue;
        target[target_len] = '\0';
        if (strcmp(target, expected) == 0) {
            closedir(fds);
            return true;
        }
    }
    closedir(fds);
    return false;
}

static bool proc_pid_owns_socket(pid_t pid, unsigned long long inode) {
    return proc_handle_owns_socket(NULL, pid, inode);
}

static bool proc_handle_executable(
    const rpd_fpm_process_handle *process, pid_t pid,
    char *out, size_t out_size) {
    char path[128];
    ssize_t len;

    if (pid <= 0 || !out || out_size < 2)
        return false;
    out[0] = '\0';
    if (process &&
        process->kind == RPD_FPM_PROCESS_HANDLE_PROCFD) {
        len = readlinkat(process->fd, "exe", out, out_size - 1);
    } else {
        if (snprintf(path, sizeof(path), "/proc/%ld/exe",
                     (long)pid) >= (int)sizeof(path))
            return false;
        len = readlink(path, out, out_size - 1);
    }
    if (len <= 0 || (size_t)len >= out_size - 1)
        return false;
    out[len] = '\0';
    return out[0] == '/';
}

static bool proc_handle_effective_uid(
    const rpd_fpm_process_handle *process, pid_t pid, uid_t *uid) {
    char line[256];
    FILE *fp;
    int fd;

    if (pid <= 0 || !uid)
        return false;
    fd = proc_handle_open_file(process, pid, "status", O_RDONLY);
    if (fd < 0)
        return false;
    fp = fdopen(fd, "r");
    if (!fp)
        close(fd);
    if (!fp)
        return false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long real_uid;
        unsigned long effective_uid;

        if (sscanf(line, "Uid:%lu%lu", &real_uid, &effective_uid) == 2) {
            (void)real_uid;
            if ((unsigned long)(uid_t)effective_uid != effective_uid) {
                fclose(fp);
                return false;
            }
            *uid = (uid_t)effective_uid;
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

static bool proc_handle_starttime(
    const rpd_fpm_process_handle *process, pid_t pid,
    unsigned long long *starttime) {
    char line[4096];
    char *fields;
    char *save = NULL;
    char *token;
    FILE *fp;
    int fd;
    int field = 3;

    if (pid <= 0 || !starttime)
        return false;
    fd = proc_handle_open_file(process, pid, "stat", O_RDONLY);
    if (fd < 0)
        return false;
    fp = fdopen(fd, "r");
    if (!fp)
        close(fd);
    if (!fp)
        return false;
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    fields = strrchr(line, ')');
    if (!fields || fields[1] != ' ')
        return false;
    fields += 2;
    token = strtok_r(fields, " \n", &save);
    while (token) {
        if (field == 22) {
            char *end = NULL;
            unsigned long long value;

            errno = 0;
            value = strtoull(token, &end, 10);
            if (errno != 0 || !end || *end != '\0' || value == 0)
                return false;
            *starttime = value;
            return true;
        }
        field++;
        token = strtok_r(NULL, " \n", &save);
    }
    return false;
}

static bool process_handle_open(pid_t pid,
                                rpd_fpm_process_handle *process) {
    char path[128];
    int fd = -1;

    if (pid <= 0 || !process)
        return false;
    memset(process, 0, sizeof(*process));
    process->fd = -1;
#ifndef NETLAB_FPM_FORCE_PROCFD
#ifdef SYS_pidfd_open
    fd = (int)syscall(SYS_pidfd_open, pid, 0);
#elif defined(__x86_64__) || defined(__aarch64__)
    fd = (int)syscall(434, pid, 0);
#else
    errno = ENOSYS;
#endif
    if (fd >= 0) {
        process->fd = fd;
        process->kind = RPD_FPM_PROCESS_HANDLE_PIDFD;
        return true;
    }
    if (errno != ENOSYS)
        return false;
#endif
    if (snprintf(path, sizeof(path), "/proc/%ld",
                 (long)pid) >= (int)sizeof(path))
        return false;
    fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return false;
    process->fd = fd;
    process->kind = RPD_FPM_PROCESS_HANDLE_PROCFD;
    return true;
}

static void process_handle_close(rpd_fpm_process_handle *process) {
    if (process && process->fd >= 0)
        close(process->fd);
    if (process) {
        process->fd = -1;
        process->kind = RPD_FPM_PROCESS_HANDLE_NONE;
    }
}

static bool process_handle_alive(
    const rpd_fpm_process_handle *process, pid_t pid) {
    struct pollfd pfd;
    int stat_fd;
    int rc;

    if (!process || process->fd < 0)
        return false;
    if (process->kind == RPD_FPM_PROCESS_HANDLE_PROCFD) {
        stat_fd = proc_handle_open_file(
            process, pid, "stat", O_RDONLY);
        if (stat_fd < 0)
            return false;
        close(stat_fd);
        return true;
    }
    if (process->kind != RPD_FPM_PROCESS_HANDLE_PIDFD)
        return false;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = process->fd;
    rc = poll(&pfd, 1, 0);
    return rc == 0;
}

static bool proc_stable_peer_identity(pid_t pid,
                                      unsigned long long socket_inode,
                                      rpd_fpm_connection_identity *identity) {
    unsigned long long starttime_before = 0;
    unsigned long long starttime_after = 0;
    uid_t uid_before = (uid_t)-1;
    uid_t uid_after = (uid_t)-1;
    char executable_before[RPD_FPM_PEER_PATH_MAX];
    char executable_after[RPD_FPM_PEER_PATH_MAX];

    if (!identity)
        return false;
    memset(identity, 0, sizeof(*identity));
    identity->process.fd = -1;
    if (!process_handle_open(pid, &identity->process) ||
        !proc_handle_starttime(&identity->process, pid,
                               &starttime_before) ||
        !proc_handle_effective_uid(&identity->process, pid,
                                   &uid_before) ||
        !proc_handle_executable(&identity->process, pid,
                                executable_before,
                                sizeof(executable_before)) ||
        !proc_handle_owns_socket(&identity->process, pid,
                                 socket_inode) ||
        !proc_handle_starttime(&identity->process, pid,
                               &starttime_after) ||
        !proc_handle_effective_uid(&identity->process, pid,
                                   &uid_after) ||
        !proc_handle_executable(&identity->process, pid,
                                executable_after,
                                sizeof(executable_after)) ||
        !process_handle_alive(&identity->process, pid) ||
        starttime_before != starttime_after ||
        uid_before != uid_after ||
        strcmp(executable_before, executable_after) != 0) {
        process_handle_close(&identity->process);
        return false;
    }
    identity->peer.pid = pid;
    identity->peer.uid = uid_after;
    identity->peer.starttime = starttime_after;
    identity->peer.socket_inode = socket_inode;
    str_copy(identity->peer.executable, sizeof(identity->peer.executable),
             executable_after);
    return true;
}

static bool proc_revalidate_peer_identity(
    const rpd_fpm_connection_identity *identity,
    rpd_fpm_peer_identity *observed) {
    unsigned long long starttime_before = 0;
    unsigned long long starttime_after = 0;
    uid_t uid_before = (uid_t)-1;
    uid_t uid_after = (uid_t)-1;
    char executable_before[RPD_FPM_PEER_PATH_MAX];
    char executable_after[RPD_FPM_PEER_PATH_MAX];

    if (!identity || !observed ||
        !process_handle_alive(&identity->process,
                              identity->peer.pid) ||
        !proc_handle_starttime(&identity->process,
                               identity->peer.pid,
                               &starttime_before) ||
        !proc_handle_effective_uid(&identity->process,
                                   identity->peer.pid,
                                   &uid_before) ||
        !proc_handle_executable(&identity->process,
                                identity->peer.pid,
                                executable_before,
                                sizeof(executable_before)) ||
        !proc_handle_owns_socket(&identity->process,
                                 identity->peer.pid,
                                 identity->peer.socket_inode) ||
        !proc_handle_starttime(&identity->process,
                               identity->peer.pid,
                               &starttime_after) ||
        !proc_handle_effective_uid(&identity->process,
                                   identity->peer.pid,
                                   &uid_after) ||
        !proc_handle_executable(&identity->process,
                                identity->peer.pid,
                                executable_after,
                                sizeof(executable_after)) ||
        !process_handle_alive(&identity->process,
                              identity->peer.pid) ||
        starttime_before != starttime_after ||
        uid_before != uid_after ||
        strcmp(executable_before, executable_after) != 0)
        return false;
    memset(observed, 0, sizeof(*observed));
    observed->pid = identity->peer.pid;
    observed->uid = uid_after;
    observed->starttime = starttime_after;
    observed->socket_inode = identity->peer.socket_inode;
    observed->authority_generation =
        identity->peer.authority_generation;
    str_copy(observed->executable, sizeof(observed->executable),
             executable_after);
    return true;
}

static bool proc_socket_has_unique_owner(unsigned long long inode,
                                         pid_t expected_pid,
                                         char *err, size_t err_size) {
    DIR *proc;
    struct dirent *proc_ent;
    unsigned int owners = 0;
    bool expected_owner = false;

    if (inode == 0 || expected_pid <= 0)
        return false;
    proc = opendir("/proc");
    if (!proc)
        return false;
    while ((proc_ent = readdir(proc))) {
        long raw_pid;
        char *end = NULL;

        if (!decimal_string(proc_ent->d_name))
            continue;
        errno = 0;
        raw_pid = strtol(proc_ent->d_name, &end, 10);
        if (errno != 0 || !end || *end != '\0' ||
            raw_pid <= 0 || raw_pid > INT32_MAX)
            continue;
        if (!proc_pid_owns_socket((pid_t)raw_pid, inode))
            continue;
        owners++;
        if ((pid_t)raw_pid == expected_pid)
            expected_owner = true;
    }
    closedir(proc);
    if (owners != 1 || !expected_owner) {
        snprintf(err, err_size,
                 "FPM peer authentication failed: socket inode %llu has %u owners; managed pid %ld owner=%s",
                 inode, owners, (long)expected_pid,
                 expected_owner ? "true" : "false");
        return false;
    }
    return true;
}

static void close_connection_identity(
    rpd_fpm_connection_identity *identity) {
    if (identity)
        process_handle_close(&identity->process);
}

static bool current_peer_authority(rpd_fpm_listener *fpm,
                                   rpd_fpm_peer_authority *authority,
                                   char *err, size_t err_size) {
    if (!fpm || !authority || !fpm->authority) {
        snprintf(err, err_size,
                 "FPM peer authentication failed: managed zebra authority is unavailable");
        return false;
    }
    memset(authority, 0, sizeof(*authority));
    if (fpm->authority(fpm->authority_ctx, authority,
                       err, err_size) != 0) {
        if (!err[0])
            snprintf(err, err_size,
                     "FPM peer authentication failed: rpd has no active managed zebra");
        return false;
    }
    if (authority->pid <= 0 || authority->starttime == 0 ||
        authority->generation == 0 ||
        authority->executable[0] != '/') {
        snprintf(err, err_size,
                 "FPM peer authentication failed: managed zebra authority is incomplete");
        return false;
    }
    return true;
}

static bool authority_matches_peer(
    const rpd_fpm_peer_authority *authority,
    const rpd_fpm_peer_identity *peer) {
    return authority && peer &&
           authority->pid == peer->pid &&
           authority->uid == peer->uid &&
           authority->starttime == peer->starttime &&
           authority->generation == peer->authority_generation &&
           strcmp(authority->executable, peer->executable) == 0;
}

static void record_peer_auth_failure(rpd_fpm_listener *fpm,
                                     const char *err) {
    pthread_mutex_lock(&fpm->lock);
    fpm->peer_auth_failures++;
    str_copy(fpm->last_error, sizeof(fpm->last_error), err);
    pthread_mutex_unlock(&fpm->lock);
}

static bool authorize_fpm_peer(
    rpd_fpm_listener *fpm, int fd,
    rpd_fpm_connection_identity *identity,
    char *err, size_t err_size) {
    rpd_fpm_peer_authority authority;
    rpd_fpm_peer_authority authority_after;
    unsigned long long inode = 0;

    memset(identity, 0, sizeof(*identity));
    identity->process.fd = -1;
    if (!current_peer_authority(fpm, &authority, err, err_size) ||
        !proc_tcp_client_inode(fd, &inode) ||
        !proc_socket_has_unique_owner(inode, authority.pid,
                                      err, err_size) ||
        !proc_stable_peer_identity(authority.pid, inode, identity)) {
        if (!err[0])
            snprintf(err, err_size,
                     "FPM peer authentication failed: managed zebra does not uniquely own the TCP producer socket");
        close_connection_identity(identity);
        return false;
    }
    identity->peer.authority_generation = authority.generation;
    if (!authority_matches_peer(&authority, &identity->peer) ||
        !process_handle_alive(&identity->process,
                              identity->peer.pid) ||
        !current_peer_authority(fpm, &authority_after, err, err_size) ||
        !authority_matches_peer(&authority_after, &identity->peer) ||
        !proc_socket_has_unique_owner(inode, identity->peer.pid,
                                      err, err_size)) {
        if (!err[0])
            snprintf(err, err_size,
                     "FPM peer authentication failed: managed zebra identity changed during authorization");
        close_connection_identity(identity);
        return false;
    }
    pthread_mutex_lock(&fpm->lock);
    fpm->expected_peer_uid = authority.uid;
    str_copy(fpm->expected_peer_executable,
             sizeof(fpm->expected_peer_executable),
             authority.executable);
    pthread_mutex_unlock(&fpm->lock);
    return true;
}

static bool revalidate_fpm_peer(
    rpd_fpm_listener *fpm, int fd,
    rpd_fpm_connection_identity *identity,
    char *err, size_t err_size) {
    rpd_fpm_peer_authority authority;
    rpd_fpm_peer_identity observed;
    unsigned long long inode = 0;
    bool ok;

    memset(&observed, 0, sizeof(observed));
    if (!identity || identity->process.fd < 0 ||
        !process_handle_alive(&identity->process,
                              identity->peer.pid) ||
        !current_peer_authority(fpm, &authority, err, err_size) ||
        !authority_matches_peer(&authority, &identity->peer) ||
        !proc_tcp_client_inode(fd, &inode) ||
        inode != identity->peer.socket_inode ||
        !proc_socket_has_unique_owner(inode, identity->peer.pid,
                                      err, err_size) ||
        !proc_revalidate_peer_identity(identity, &observed)) {
        if (!err[0])
            snprintf(err, err_size,
                     "FPM peer revalidation failed: managed zebra or socket ownership changed");
        return false;
    }
    ok = process_handle_alive(&identity->process,
                              identity->peer.pid) &&
         observed.pid == identity->peer.pid &&
         observed.uid == identity->peer.uid &&
         observed.starttime == identity->peer.starttime &&
         observed.socket_inode == identity->peer.socket_inode &&
         observed.authority_generation ==
             identity->peer.authority_generation &&
         strcmp(observed.executable,
                identity->peer.executable) == 0;
    if (!ok) {
        snprintf(err, err_size,
                 "FPM peer revalidation failed: managed zebra process identity drifted");
        return false;
    }
    pthread_mutex_lock(&fpm->lock);
    fpm->peer_revalidations++;
    pthread_mutex_unlock(&fpm->lock);
    return true;
}

static u32 fnv1a_bytes(const u8 *data, size_t len) {
    u32 h = 2166136261u;

    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

static u32 fpm_semantic_key(const char *op, const char *protocol,
                            const char *prefix, u32 table_id, int metric,
                            const char *nexthops) {
    char semantic[1400];
    int n;

    n = snprintf(semantic, sizeof(semantic),
                 "op=%s|protocol=%s|prefix=%s|table-id=%u|metric=%d|"
                 "nexthops=%s",
                 op ? op : "-", protocol ? protocol : "-",
                 prefix ? prefix : "-", table_id, metric,
                 nexthops && nexthops[0] ? nexthops : "-");
    if (n < 0)
        return 0;
    if ((size_t)n >= sizeof(semantic))
        n = (int)sizeof(semantic) - 1;
    return fnv1a_bytes((const u8 *)semantic, (size_t)n);
}

static void set_status(rpd_fpm_listener *fpm, const char *status,
                       const char *err) {
    if (!fpm)
        return;
    pthread_mutex_lock(&fpm->lock);
    str_copy(fpm->status, sizeof(fpm->status), status);
    if (err)
        str_copy(fpm->last_error, sizeof(fpm->last_error), err);
    pthread_mutex_unlock(&fpm->lock);
}

static bool stop_requested(rpd_fpm_listener *fpm) {
    bool stop;

    pthread_mutex_lock(&fpm->lock);
    stop = fpm->stop_requested;
    pthread_mutex_unlock(&fpm->lock);
    return stop;
}

static int read_exact(int fd, u8 *buf, size_t len, rpd_fpm_listener *fpm,
                      rpd_fpm_connection_identity *identity) {
    size_t off = 0;

    while (off < len) {
        struct pollfd pfds[2];
        char auth_err[192] = {0};
        ssize_t n;
        int rc;

        if (stop_requested(fpm))
            return -1;
        memset(pfds, 0, sizeof(pfds));
        pfds[0].fd = fd;
        pfds[0].events = POLLIN;
        pfds[1].fd =
            identity &&
            identity->process.kind ==
                RPD_FPM_PROCESS_HANDLE_PIDFD ?
            identity->process.fd : -1;
        pfds[1].events = POLLIN;
        rc = poll(pfds, 2, 250);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (rc == 0) {
            if (identity &&
                !revalidate_fpm_peer(fpm, fd, identity,
                                     auth_err, sizeof(auth_err))) {
                record_peer_auth_failure(fpm, auth_err);
                NL_LOG_WARN("%s", auth_err);
                return -1;
            }
            continue;
        }
        if (pfds[1].revents != 0)
            return -1;
        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
            return -1;
        n = recv(fd, buf + off, len - off, 0);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static const char *route_protocol_name(unsigned char proto) {
    switch (proto) {
    case RTPROT_BGP:
        return "bgp";
    case RTPROT_OSPF:
        return "ospf";
    default:
        return NULL;
    }
}

static int appendf(char *buf, size_t buf_size, size_t *off,
                   const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !off || *off >= buf_size)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_size - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}

static int ipv4_prefix_text(const struct rtmsg *rtm, const struct rtattr *dst,
                            char *out, size_t out_size) {
    struct in_addr addr;
    u32 host = 0;
    u32 mask;

    if (!rtm || !out || out_size == 0)
        return -1;
    if (rtm->rtm_dst_len > 32)
        return -1;
    if (dst) {
        if (RTA_PAYLOAD((struct rtattr *)dst) < 4)
            return -1;
        memcpy(&host, RTA_DATA((struct rtattr *)dst), 4);
        host = ntohl(host);
    }
    if (rtm->rtm_dst_len == 0)
        mask = 0;
    else
        mask = 0xffffffffu << (32 - rtm->rtm_dst_len);
    host &= mask;
    addr.s_addr = htonl(host);
    if (!inet_ntop(AF_INET, &addr, out, out_size))
        return -1;
    if (appendf(out, out_size, &(size_t){strlen(out)}, "/%u",
                rtm->rtm_dst_len) != 0)
        return -1;
    return 0;
}

static bool ipv4_prefix_is_v1_unicast(const char *prefix) {
    char tmp[64];
    char *slash;
    struct in_addr addr;
    int plen;
    char *end = NULL;
    u32 host;

    if (!prefix || strlen(prefix) >= sizeof(tmp))
        return false;
    str_copy(tmp, sizeof(tmp), prefix);
    slash = strchr(tmp, '/');
    if (!slash)
        return false;
    *slash++ = '\0';
    plen = (int)strtol(slash, &end, 10);
    if (!end || *end != '\0' || plen < 0 || plen > 32)
        return false;
    if (!inet_pton(AF_INET, tmp, &addr))
        return false;
    if (plen == 0)
        return true;
    host = ntohl(addr.s_addr);
    return (host >> 28) < 14;
}

static int append_nexthop_addr(char *nh_buf, size_t nh_size, int *nh_count,
                               const void *addr, int ifindex) {
    struct in_addr gw;
    char ip[INET_ADDRSTRLEN];
    size_t off;

    if (!nh_buf || !nh_count || !addr)
        return -1;
    memcpy(&gw, addr, sizeof(gw));
    if (!inet_ntop(AF_INET, &gw, ip, sizeof(ip)))
        return -1;
    off = strlen(nh_buf);
    if (snprintf(nh_buf + off, nh_size - off, "%s%s@ifindex%d",
                 *nh_count == 0 ? "" : ",", ip, ifindex) >=
        (int)(nh_size - off))
        return -1;
    (*nh_count)++;
    return 0;
}

static int append_nexthop_gateway(char *nh_buf, size_t nh_size,
                                  int *nh_count,
                                  const struct rtattr *gateway,
                                  int ifindex) {
    if (!gateway || RTA_PAYLOAD((struct rtattr *)gateway) < 4)
        return -1;
    return append_nexthop_addr(nh_buf, nh_size, nh_count,
                               RTA_DATA((struct rtattr *)gateway),
                               ifindex);
}

static int append_nexthop_via(char *nh_buf, size_t nh_size, int *nh_count,
                              const struct rtattr *via, int ifindex) {
    const struct rtvia *rtvia;

    if (!via || RTA_PAYLOAD((struct rtattr *)via) <
        (int)(sizeof(*rtvia) + sizeof(struct in_addr)))
        return -1;
    rtvia = (const struct rtvia *)RTA_DATA((struct rtattr *)via);
    if (rtvia->rtvia_family != AF_INET)
        return -1;
    return append_nexthop_addr(nh_buf, nh_size, nh_count,
                               rtvia->rtvia_addr, ifindex);
}

static int count_nexthop_text(const char *text) {
    int count = 1;

    if (!text || !text[0])
        return 0;
    for (const char *p = text; *p; p++)
        if (*p == ',')
            count++;
    return count;
}

static int append_nexthop_text(char *nh_buf, size_t nh_size, int *nh_count,
                               const char *text) {
    size_t off;
    int n;

    if (!nh_buf || !nh_count || !text || !text[0])
        return -1;
    off = strlen(nh_buf);
    n = snprintf(nh_buf + off, nh_size - off, "%s%s",
                 *nh_count == 0 ? "" : ",", text);
    if (n < 0 || (size_t)n >= nh_size - off)
        return -1;
    *nh_count += count_nexthop_text(text);
    return 0;
}

static int nh_cache_lookup(rpd_fpm_listener *fpm, u32 id, char *out,
                           size_t out_size) {
    if (!fpm || id == 0 || !out || out_size == 0)
        return -1;
    pthread_mutex_lock(&fpm->lock);
    for (int i = 0; i < RPD_FPM_NH_CACHE_MAX; i++) {
        if (fpm->nh_cache[i].active && fpm->nh_cache[i].id == id) {
            str_copy(out, out_size, fpm->nh_cache[i].nexthops);
            fpm->nh_cache_hits++;
            pthread_mutex_unlock(&fpm->lock);
            return 0;
        }
    }
    fpm->nh_cache_misses++;
    pthread_mutex_unlock(&fpm->lock);
    return -1;
}

static int nh_cache_set(rpd_fpm_listener *fpm, u32 id,
                        const char *nexthops) {
    int free_slot = -1;

    if (!fpm || id == 0 || !nexthops || !nexthops[0])
        return -1;
    pthread_mutex_lock(&fpm->lock);
    for (int i = 0; i < RPD_FPM_NH_CACHE_MAX; i++) {
        if (fpm->nh_cache[i].active && fpm->nh_cache[i].id == id) {
            str_copy(fpm->nh_cache[i].nexthops,
                     sizeof(fpm->nh_cache[i].nexthops), nexthops);
            fpm->nh_cache_updates++;
            pthread_mutex_unlock(&fpm->lock);
            return 0;
        }
        if (!fpm->nh_cache[i].active && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0) {
        pthread_mutex_unlock(&fpm->lock);
        return -1;
    }
    fpm->nh_cache[free_slot].active = true;
    fpm->nh_cache[free_slot].id = id;
    str_copy(fpm->nh_cache[free_slot].nexthops,
             sizeof(fpm->nh_cache[free_slot].nexthops), nexthops);
    fpm->nh_cache_updates++;
    pthread_mutex_unlock(&fpm->lock);
    return 0;
}

static void nh_cache_delete(rpd_fpm_listener *fpm, u32 id) {
    if (!fpm || id == 0)
        return;
    pthread_mutex_lock(&fpm->lock);
    for (int i = 0; i < RPD_FPM_NH_CACHE_MAX; i++) {
        if (fpm->nh_cache[i].active && fpm->nh_cache[i].id == id) {
            memset(&fpm->nh_cache[i], 0, sizeof(fpm->nh_cache[i]));
            fpm->nh_cache_updates++;
            break;
        }
    }
    pthread_mutex_unlock(&fpm->lock);
}

static void nh_cache_clear(rpd_fpm_listener *fpm) {
    if (!fpm)
        return;
    pthread_mutex_lock(&fpm->lock);
    memset(fpm->nh_cache, 0, sizeof(fpm->nh_cache));
    fpm->nh_cache_resets++;
    pthread_mutex_unlock(&fpm->lock);
}

static int append_multipath(char *nh_buf, size_t nh_size, int *nh_count,
                            const struct rtattr *mp) {
    int rem;
    struct rtnexthop *rtnh;

    if (!mp)
        return 0;
    rem = RTA_PAYLOAD((struct rtattr *)mp);
    rtnh = (struct rtnexthop *)RTA_DATA((struct rtattr *)mp);
    while (rem > 0) {
        int hop_len;
        int aligned_len;
        int attr_len;
        struct rtattr *attr = NULL;
        struct rtattr *gateway = NULL;
        struct rtattr *via = NULL;

        /* RTNH_OK dereferences rtnh before checking the remaining bytes. */
        if (rem < (int)sizeof(*rtnh))
            return -1;
        hop_len = rtnh->rtnh_len;
        if (hop_len < (int)RTNH_LENGTH(0) || hop_len > rem)
            return -1;
        aligned_len = RTNH_ALIGN(hop_len);
        if (aligned_len > rem)
            return -1;
        attr_len = hop_len - RTNH_LENGTH(0);
        attr = RTNH_DATA(rtnh);
        while (RTA_OK(attr, attr_len)) {
            if (attr->rta_type == RTA_GATEWAY)
                gateway = attr;
            else if (attr->rta_type == RTA_VIA)
                via = attr;
            attr = RTA_NEXT(attr, attr_len);
        }
        if (attr_len != 0)
            return -1;
        if (gateway &&
            append_nexthop_gateway(nh_buf, nh_size, nh_count, gateway,
                                   rtnh->rtnh_ifindex) != 0)
            return -1;
        if (!gateway && via &&
            append_nexthop_via(nh_buf, nh_size, nh_count, via,
                               rtnh->rtnh_ifindex) != 0)
            return -1;
        rem -= aligned_len;
        rtnh = (struct rtnexthop *)((char *)rtnh + aligned_len);
    }
    return 0;
}

static int decode_nexthop_object(rpd_fpm_listener *fpm,
                                 const struct nlmsghdr *nlh,
                                 bool *cache_only,
                                 char *err, size_t err_size) {
    const struct nhmsg *nhm;
    struct rtattr *attr;
    int attr_len;
    const struct rtattr *gateway = NULL;
    const struct rtattr *group = NULL;
    u32 id = 0;
    int oif = 0;
    char nexthops[RPD_FPM_NH_TEXT_MAX] = {0};
    int n_nexthops = 0;

    if (!fpm || !nlh || nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*nhm))) {
        snprintf(err, err_size, "invalid FPM nexthop object context");
        return RPD_FPM_DECODE_ERROR;
    }
    if (cache_only)
        *cache_only = true;
    nhm = (const struct nhmsg *)NLMSG_DATA((struct nlmsghdr *)nlh);
    if (nhm->nh_family != AF_INET && nhm->nh_family != AF_UNSPEC) {
        snprintf(err, err_size, "unsupported FPM nexthop family: %u",
                 nhm->nh_family);
        return RPD_FPM_DECODE_IGNORED;
    }
    attr_len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*nhm)));
    attr = (struct rtattr *)((char *)nhm + NLMSG_ALIGN(sizeof(*nhm)));
    while (RTA_OK(attr, attr_len)) {
        switch (attr->rta_type) {
        case NHA_ID:
            if (RTA_PAYLOAD(attr) >= (int)sizeof(id))
                memcpy(&id, RTA_DATA(attr), sizeof(id));
            break;
        case NHA_OIF:
            if (RTA_PAYLOAD(attr) >= (int)sizeof(oif))
                memcpy(&oif, RTA_DATA(attr), sizeof(oif));
            break;
        case NHA_GATEWAY:
            gateway = attr;
            break;
        case NHA_GROUP:
            group = attr;
            break;
        default:
            break;
        }
        attr = RTA_NEXT(attr, attr_len);
    }
    if (attr_len != 0) {
        snprintf(err, err_size, "malformed FPM nexthop attributes");
        return RPD_FPM_DECODE_ERROR;
    }
    if (id == 0) {
        snprintf(err, err_size, "FPM nexthop object missing id");
        return RPD_FPM_DECODE_ERROR;
    }
    if (nlh->nlmsg_type == RTM_DELNEXTHOP) {
        nh_cache_delete(fpm, id);
        return RPD_FPM_DECODE_OK;
    }
    if (group) {
        int rem = RTA_PAYLOAD((struct rtattr *)group);
        struct nexthop_grp *grp =
            (struct nexthop_grp *)RTA_DATA((struct rtattr *)group);

        while (rem >= (int)sizeof(*grp)) {
            char cached[RPD_FPM_NH_TEXT_MAX];

            if (nh_cache_lookup(fpm, grp->id, cached,
                                sizeof(cached)) != 0) {
                snprintf(err, err_size,
                         "FPM nexthop group %u references unknown id %u",
                         id, grp->id);
                return RPD_FPM_DECODE_DEFERRED;
            }
            if (append_nexthop_text(nexthops, sizeof(nexthops),
                                    &n_nexthops, cached) != 0) {
                snprintf(err, err_size,
                         "FPM nexthop group %u exceeds buffer", id);
                return RPD_FPM_DECODE_ERROR;
            }
            rem -= (int)sizeof(*grp);
            grp++;
        }
        if (rem != 0) {
            snprintf(err, err_size, "malformed FPM nexthop group");
            return RPD_FPM_DECODE_ERROR;
        }
    } else if (gateway) {
        if (RTA_PAYLOAD((struct rtattr *)gateway) < 4 ||
            append_nexthop_addr(nexthops, sizeof(nexthops), &n_nexthops,
                                RTA_DATA((struct rtattr *)gateway),
                                oif) != 0) {
            snprintf(err, err_size, "invalid FPM nexthop object gateway");
            return RPD_FPM_DECODE_ERROR;
        }
    }
    if (n_nexthops <= 0) {
        snprintf(err, err_size, "FPM nexthop object %u has no nexthops",
                 id);
        return RPD_FPM_DECODE_IGNORED;
    }
    if (nh_cache_set(fpm, id, nexthops) != 0) {
        snprintf(err, err_size, "FPM nexthop cache is full");
        return RPD_FPM_DECODE_ERROR;
    }
    return RPD_FPM_DECODE_OK;
}

int rpd_fpm_decode_message_stateful(rpd_fpm_listener *fpm,
                                    const u8 *msg, size_t msg_len,
                                    char *out, size_t out_size,
                                    bool *cache_only,
                                    char *err, size_t err_size) {
    const u8 *payload;
    size_t payload_len;
    u16 fpm_len;
    const struct nlmsghdr *nlh;
    const struct rtmsg *rtm;
    int attr_len;
    struct rtattr *attr;
    const struct rtattr *dst = NULL;
    const struct rtattr *gateway = NULL;
    const struct rtattr *via = NULL;
    const struct rtattr *nh_id_attr = NULL;
    const struct rtattr *multipath = NULL;
    int oif = 0;
    int metric = 0;
    char prefix[64];
    char nexthops[1024] = {0};
    char attr_summary[256] = {0};
    size_t attr_off = 0;
    int n_nexthops = 0;
    const char *protocol;
    const char *op;
    u32 key_hash;
    u32 nh_id = 0;
    u32 table_id = 0;

    if (!msg || msg_len < RPD_FPM_HEADER_LEN || !out || out_size == 0) {
        snprintf(err, err_size, "invalid FPM message buffer");
        return RPD_FPM_DECODE_ERROR;
    }
    out[0] = '\0';
    if (cache_only)
        *cache_only = false;
    if (msg[0] != RPD_FPM_VERSION) {
        snprintf(err, err_size, "unsupported FPM version: %u", msg[0]);
        return RPD_FPM_DECODE_ERROR;
    }
    if (msg[1] != RPD_FPM_MSG_TYPE_NETLINK) {
        snprintf(err, err_size, "unsupported FPM message type: %u", msg[1]);
        return RPD_FPM_DECODE_ERROR;
    }
    memcpy(&fpm_len, msg + 2, sizeof(fpm_len));
    fpm_len = ntohs(fpm_len);
    if (fpm_len < RPD_FPM_HEADER_LEN || fpm_len != msg_len) {
        snprintf(err, err_size, "invalid FPM message length: %u", fpm_len);
        return RPD_FPM_DECODE_ERROR;
    }
    payload = msg + RPD_FPM_HEADER_LEN;
    payload_len = msg_len - RPD_FPM_HEADER_LEN;
    if (payload_len < sizeof(struct nlmsghdr)) {
        snprintf(err, err_size, "short FPM netlink payload");
        return RPD_FPM_DECODE_ERROR;
    }
    nlh = (const struct nlmsghdr *)payload;
    if (nlh->nlmsg_len > payload_len || nlh->nlmsg_len < NLMSG_HDRLEN) {
        snprintf(err, err_size, "invalid netlink message length");
        return RPD_FPM_DECODE_ERROR;
    }
    if (nlh->nlmsg_type == RTM_NEWNEXTHOP ||
        nlh->nlmsg_type == RTM_DELNEXTHOP)
        return decode_nexthop_object(fpm, nlh, cache_only,
                                     err, err_size);
    if (nlh->nlmsg_type != RTM_NEWROUTE &&
        nlh->nlmsg_type != RTM_DELROUTE) {
        snprintf(err, err_size, "ignored netlink message type: %u",
                 nlh->nlmsg_type);
        return RPD_FPM_DECODE_IGNORED;
    }
    if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg))) {
        snprintf(err, err_size, "invalid netlink route message length");
        return RPD_FPM_DECODE_ERROR;
    }
    rtm = (const struct rtmsg *)NLMSG_DATA((struct nlmsghdr *)nlh);
    if (rtm->rtm_family != AF_INET ||
        (nlh->nlmsg_type == RTM_NEWROUTE && rtm->rtm_type != RTN_UNICAST) ||
        (nlh->nlmsg_type == RTM_DELROUTE &&
         rtm->rtm_type != RTN_UNICAST && rtm->rtm_type != RTN_UNSPEC)) {
        snprintf(err, err_size, "unsupported netlink route family/type");
        return RPD_FPM_DECODE_IGNORED;
    }
    table_id = rtm->rtm_table;
    attr_len = (int)RTM_PAYLOAD((struct nlmsghdr *)nlh);
    attr = RTM_RTA((struct rtmsg *)rtm);
    while (RTA_OK(attr, attr_len)) {
        switch (attr->rta_type) {
        case RTA_DST:
            dst = attr;
            break;
        case RTA_GATEWAY:
            gateway = attr;
            break;
        case RTA_VIA:
            via = attr;
            break;
        case RTA_MULTIPATH:
            multipath = attr;
            break;
        case RTA_NH_ID:
            nh_id_attr = attr;
            break;
        case RTA_OIF:
            if (RTA_PAYLOAD(attr) >= (int)sizeof(int))
                memcpy(&oif, RTA_DATA(attr), sizeof(oif));
            break;
        case RTA_PRIORITY:
            if (RTA_PAYLOAD(attr) >= (int)sizeof(int))
                memcpy(&metric, RTA_DATA(attr), sizeof(metric));
            break;
        case RTA_TABLE:
            if (RTA_PAYLOAD(attr) >= (int)sizeof(table_id))
                memcpy(&table_id, RTA_DATA(attr), sizeof(table_id));
            break;
        default:
            break;
        }
        appendf(attr_summary, sizeof(attr_summary), &attr_off,
                "%s%d/%d", attr_off == 0 ? "" : ",",
                attr->rta_type, RTA_PAYLOAD(attr));
        attr = RTA_NEXT(attr, attr_len);
    }
    if (attr_len != 0) {
        snprintf(err, err_size, "malformed netlink route attributes");
        return RPD_FPM_DECODE_ERROR;
    }
    if (table_id != RT_TABLE_MAIN &&
        table_id != RPD_RIB_VRF_V1_KERNEL_TABLE) {
        snprintf(err, err_size,
                 "unsupported netlink route table: %u", table_id);
        return RPD_FPM_DECODE_IGNORED;
    }
    if (ipv4_prefix_text(rtm, dst, prefix, sizeof(prefix)) != 0) {
        snprintf(err, err_size, "invalid FPM IPv4 route prefix");
        return RPD_FPM_DECODE_ERROR;
    }
    if (!ipv4_prefix_is_v1_unicast(prefix)) {
        snprintf(err, err_size,
                 "unsupported FPM IPv4 route prefix: %s", prefix);
        return RPD_FPM_DECODE_IGNORED;
    }
    protocol = route_protocol_name(rtm->rtm_protocol);
    if (!protocol) {
        snprintf(err, err_size,
                 "unsupported route protocol: %u prefix=%s metric=%d "
                 "dst-len=%u type=%u attrs=%s",
                 rtm->rtm_protocol, prefix, metric, rtm->rtm_dst_len,
                 rtm->rtm_type, attr_summary);
        return RPD_FPM_DECODE_IGNORED;
    }
    op = nlh->nlmsg_type == RTM_DELROUTE ? "delete" : "replace";
    if (nlh->nlmsg_type == RTM_DELROUTE) {
        key_hash = fpm_semantic_key(op, protocol, prefix, table_id, 0, "-");
        return snprintf(out, out_size,
                        "op=delete protocol=%s prefix=%s table-id=%u "
                        "key=fpm-%08x\n",
                        protocol, prefix, table_id, key_hash) >=
            (int)out_size ? RPD_FPM_DECODE_ERROR : RPD_FPM_DECODE_OK;
    }
    if (multipath &&
        append_multipath(nexthops, sizeof(nexthops), &n_nexthops,
                         multipath) != 0) {
        snprintf(err, err_size, "invalid FPM multipath nexthops");
        return RPD_FPM_DECODE_ERROR;
    }
    if (!multipath && gateway &&
        append_nexthop_gateway(nexthops, sizeof(nexthops), &n_nexthops,
                               gateway, oif) != 0) {
        snprintf(err, err_size, "invalid FPM nexthop");
        return RPD_FPM_DECODE_ERROR;
    }
    if (!multipath && !gateway && via &&
        append_nexthop_via(nexthops, sizeof(nexthops), &n_nexthops,
                           via, oif) != 0) {
        snprintf(err, err_size, "invalid FPM via nexthop");
        return RPD_FPM_DECODE_ERROR;
    }
    if (!multipath && !gateway && !via && nh_id_attr) {
        char cached[RPD_FPM_NH_TEXT_MAX];

        if (RTA_PAYLOAD((struct rtattr *)nh_id_attr) < (int)sizeof(nh_id)) {
            snprintf(err, err_size, "malformed FPM nexthop id attribute");
            return RPD_FPM_DECODE_ERROR;
        }
        memcpy(&nh_id, RTA_DATA((struct rtattr *)nh_id_attr),
               sizeof(nh_id));
        if (nh_id == 0) {
            snprintf(err, err_size, "invalid FPM nexthop id 0");
            return RPD_FPM_DECODE_ERROR;
        }
        if (nh_cache_lookup(fpm, nh_id, cached, sizeof(cached)) != 0) {
            snprintf(err, err_size,
                     "FPM route references unknown nexthop id %u attrs=%s",
                     nh_id, attr_summary[0] ? attr_summary : "-");
            return RPD_FPM_DECODE_DEFERRED;
        }
        if (append_nexthop_text(nexthops, sizeof(nexthops), &n_nexthops,
                                cached) != 0) {
            snprintf(err, err_size,
                     "FPM route nexthop id %u exceeds buffer", nh_id);
            return RPD_FPM_DECODE_ERROR;
        }
    }
    if (n_nexthops <= 0) {
        snprintf(err, err_size, "FPM route update has no nexthop attrs=%s",
                 attr_summary[0] ? attr_summary : "-");
        return RPD_FPM_DECODE_ERROR;
    }
    key_hash = fpm_semantic_key(op, protocol, prefix, table_id, metric,
                               nexthops);
    return snprintf(out, out_size,
                    "op=%s protocol=%s prefix=%s table-id=%u metric=%d "
                    "nexthops=%s key=fpm-%08x\n",
                    op, protocol, prefix, table_id, metric, nexthops,
                    key_hash) >=
        (int)out_size ? RPD_FPM_DECODE_ERROR : RPD_FPM_DECODE_OK;
}

int rpd_fpm_decode_message(const u8 *msg, size_t msg_len,
                           char *out, size_t out_size,
                           char *err, size_t err_size) {
    bool cache_only = false;

    return rpd_fpm_decode_message_stateful(NULL, msg, msg_len, out,
                                           out_size, &cache_only,
                                           err, err_size);
}

static void fpm_record_decode_error(rpd_fpm_listener *fpm,
                                    const char *err) {
    pthread_mutex_lock(&fpm->lock);
    fpm->decode_errors++;
    str_copy(fpm->last_error, sizeof(fpm->last_error), err);
    pthread_mutex_unlock(&fpm->lock);
}

static void fpm_record_ignored(rpd_fpm_listener *fpm) {
    pthread_mutex_lock(&fpm->lock);
    fpm->ignored_updates++;
    pthread_mutex_unlock(&fpm->lock);
}

static void fpm_record_deferred_drop(rpd_fpm_listener *fpm,
                                     const char *err) {
    pthread_mutex_lock(&fpm->lock);
    fpm->deferred_drops++;
    str_copy(fpm->last_error, sizeof(fpm->last_error), err);
    pthread_mutex_unlock(&fpm->lock);
}

static int fpm_apply_decoded(rpd_fpm_listener *fpm,
                             int fd,
                             rpd_fpm_connection_identity *identity,
                             const char *update,
                             char *err, size_t err_size) {
    int apply_rc;

    if (!revalidate_fpm_peer(fpm, fd, identity, err, err_size)) {
        record_peer_auth_failure(fpm, err);
        return RPD_FPM_APPLY_AUTHORITY_REJECTED;
    }
    apply_rc = fpm->apply ?
        fpm->apply(fpm->apply_ctx, &identity->peer, update,
                   (int)strlen(update), err, err_size) : -1;
    if (apply_rc == RPD_FPM_APPLY_AUTHORITY_REJECTED) {
        record_peer_auth_failure(
            fpm, err[0] ? err :
            "FPM apply rejected: managed zebra authority changed");
        return RPD_FPM_APPLY_AUTHORITY_REJECTED;
    }
    if (apply_rc != 0) {
        pthread_mutex_lock(&fpm->lock);
        fpm->apply_errors++;
        str_copy(fpm->last_error, sizeof(fpm->last_error),
                 err[0] ? err : "FPM route apply failed");
        pthread_mutex_unlock(&fpm->lock);
        return -1;
    }
    pthread_mutex_lock(&fpm->lock);
    fpm->route_updates++;
    pthread_mutex_unlock(&fpm->lock);
    return 0;
}

static int fpm_pending_enqueue(rpd_fpm_listener *fpm, u8 *message,
                               size_t message_len, char *err,
                               size_t err_size) {
    rpd_fpm_pending_frame *pending;
    u32 pending_frames;
    u64 pending_bytes;

    if (!fpm || !message || message_len == 0)
        return -1;
    pending = calloc(1, sizeof(*pending));
    if (!pending) {
        snprintf(err, err_size, "FPM pending frame allocation failed");
        return -1;
    }
    pthread_mutex_lock(&fpm->lock);
    if (fpm->pending_frames >= RPD_FPM_PENDING_MAX ||
        fpm->pending_bytes > RPD_FPM_PENDING_BYTES_MAX ||
        message_len > RPD_FPM_PENDING_BYTES_MAX - fpm->pending_bytes) {
        pending_frames = fpm->pending_frames;
        pending_bytes = fpm->pending_bytes;
        pthread_mutex_unlock(&fpm->lock);
        free(pending);
        snprintf(err, err_size,
                 "FPM pending frame queue full frames=%u bytes=%llu",
                 pending_frames, (unsigned long long)pending_bytes);
        return -1;
    }
    pending->message = message;
    pending->message_len = message_len;
    if (fpm->pending_tail)
        fpm->pending_tail->next = pending;
    else
        fpm->pending_head = pending;
    fpm->pending_tail = pending;
    fpm->pending_frames++;
    fpm->pending_bytes += message_len;
    fpm->deferred_updates++;
    pthread_mutex_unlock(&fpm->lock);
    return 0;
}

static void fpm_pending_unlink(rpd_fpm_listener *fpm,
                               rpd_fpm_pending_frame *previous,
                               rpd_fpm_pending_frame *pending) {
    if (previous)
        previous->next = pending->next;
    else
        fpm->pending_head = pending->next;
    if (fpm->pending_tail == pending)
        fpm->pending_tail = previous;
    pthread_mutex_lock(&fpm->lock);
    if (fpm->pending_frames > 0)
        fpm->pending_frames--;
    if (fpm->pending_bytes >= pending->message_len)
        fpm->pending_bytes -= pending->message_len;
    else
        fpm->pending_bytes = 0;
    pthread_mutex_unlock(&fpm->lock);
}

static void fpm_pending_clear(rpd_fpm_listener *fpm, bool dropped) {
    rpd_fpm_pending_frame *pending;
    u64 count = 0;

    if (!fpm)
        return;
    pending = fpm->pending_head;
    while (pending) {
        rpd_fpm_pending_frame *next = pending->next;

        free(pending->message);
        free(pending);
        pending = next;
        count++;
    }
    fpm->pending_head = NULL;
    fpm->pending_tail = NULL;
    pthread_mutex_lock(&fpm->lock);
    fpm->pending_frames = 0;
    fpm->pending_bytes = 0;
    if (dropped && count > 0) {
        fpm->deferred_drops += count;
        snprintf(fpm->last_error, sizeof(fpm->last_error),
                 "FPM producer disconnected with %llu deferred frame(s)",
                 (unsigned long long)count);
    }
    pthread_mutex_unlock(&fpm->lock);
}

static int fpm_replay_pending(
    rpd_fpm_listener *fpm, int fd,
    rpd_fpm_connection_identity *identity) {
    bool cache_progress;

    do {
        rpd_fpm_pending_frame *previous = NULL;
        rpd_fpm_pending_frame *pending = fpm->pending_head;

        cache_progress = false;
        while (pending) {
            rpd_fpm_pending_frame *next = pending->next;
            char update[2048];
            char err[192] = {0};
            bool cache_only = false;
            int rc;

            if (!revalidate_fpm_peer(fpm, fd, identity,
                                     err, sizeof(err))) {
                record_peer_auth_failure(fpm, err);
                return -1;
            }
            rc = rpd_fpm_decode_message_stateful(
                fpm, pending->message, pending->message_len,
                update, sizeof(update), &cache_only, err, sizeof(err));

            if (rc == RPD_FPM_DECODE_DEFERRED) {
                previous = pending;
                pending = next;
                continue;
            }
            fpm_pending_unlink(fpm, previous, pending);
            if (rc == RPD_FPM_DECODE_OK) {
                pthread_mutex_lock(&fpm->lock);
                fpm->deferred_replays++;
                pthread_mutex_unlock(&fpm->lock);
                if (cache_only)
                    cache_progress = true;
                else if (fpm_apply_decoded(
                             fpm, fd, identity, update,
                             err, sizeof(err)) ==
                         RPD_FPM_APPLY_AUTHORITY_REJECTED)
                    return -1;
            } else if (rc == RPD_FPM_DECODE_IGNORED) {
                fpm_record_ignored(fpm);
            } else {
                fpm_record_decode_error(fpm, err);
            }
            free(pending->message);
            free(pending);
            pending = next;
        }
    } while (cache_progress);
    return 0;
}

static int handle_client(rpd_fpm_listener *fpm, int fd,
                         rpd_fpm_connection_identity *identity) {
    while (!stop_requested(fpm)) {
        u8 hdr[RPD_FPM_HEADER_LEN];
        u16 len;
        u8 *msg;
        char update[2048];
        char err[192] = {0};
        bool cache_only = false;
        int decode_rc;

        if (read_exact(fd, hdr, sizeof(hdr), fpm, identity) != 0)
            return -1;
        memcpy(&len, hdr + 2, sizeof(len));
        len = ntohs(len);
        if (len < RPD_FPM_HEADER_LEN) {
            snprintf(err, sizeof(err), "invalid FPM frame length: %u", len);
            fpm_record_decode_error(fpm, err);
            return -1;
        }
        msg = malloc(len);
        if (!msg) {
            set_status(fpm, "error", "FPM frame allocation failed");
            return -1;
        }
        memcpy(msg, hdr, sizeof(hdr));
        if (read_exact(fd, msg + sizeof(hdr), len - sizeof(hdr),
                       fpm, identity) != 0) {
            free(msg);
            return -1;
        }
        if (!revalidate_fpm_peer(fpm, fd, identity,
                                 err, sizeof(err))) {
            record_peer_auth_failure(fpm, err);
            NL_LOG_WARN("%s", err);
            free(msg);
            return -1;
        }
        pthread_mutex_lock(&fpm->lock);
        fpm->frames++;
        fpm->last_frame = time(NULL);
        pthread_mutex_unlock(&fpm->lock);
        decode_rc = rpd_fpm_decode_message_stateful(
            fpm, msg, len, update, sizeof(update), &cache_only,
            err, sizeof(err));
        if (decode_rc == RPD_FPM_DECODE_DEFERRED) {
            if (fpm_pending_enqueue(fpm, msg, len,
                                    err, sizeof(err)) == 0)
                continue;
            fpm_record_deferred_drop(fpm, err);
            free(msg);
            continue;
        }
        free(msg);
        if (decode_rc == RPD_FPM_DECODE_IGNORED) {
            fpm_record_ignored(fpm);
            continue;
        }
        if (decode_rc != RPD_FPM_DECODE_OK) {
            fpm_record_decode_error(fpm, err);
            continue;
        }
        if (cache_only) {
            if (fpm_replay_pending(fpm, fd, identity) != 0)
                return -1;
            continue;
        }
        if (fpm_apply_decoded(fpm, fd, identity, update,
                              err, sizeof(err)) ==
            RPD_FPM_APPLY_AUTHORITY_REJECTED)
            return -1;
    }
    return 0;
}

static void *fpm_thread_main(void *arg) {
    rpd_fpm_listener *fpm = arg;

    set_status(fpm, "listening", "");
    while (!stop_requested(fpm)) {
        struct pollfd pfd;
        rpd_fpm_connection_identity identity;
        char auth_err[192] = {0};
        int fd;

        pfd.fd = fpm->listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 1000) <= 0)
            continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            set_status(fpm, "error", "FPM listener poll failed");
            break;
        }
        fd = accept(fpm->listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            set_status(fpm, "error", "FPM accept failed");
            continue;
        }
        memset(&identity, 0, sizeof(identity));
        identity.process.fd = -1;
        if (!authorize_fpm_peer(fpm, fd, &identity,
                                auth_err, sizeof(auth_err))) {
            record_peer_auth_failure(fpm, auth_err);
            NL_LOG_WARN("%s", auth_err);
            set_status(fpm, "listening", auth_err);
            close(fd);
            continue;
        }
        pthread_mutex_lock(&fpm->lock);
        fpm->last_peer_pid = identity.peer.pid;
        fpm->last_peer_uid = identity.peer.uid;
        fpm->last_peer_starttime = identity.peer.starttime;
        fpm->last_peer_socket_inode = identity.peer.socket_inode;
        fpm->last_authority_generation =
            identity.peer.authority_generation;
        str_copy(fpm->last_peer_process_handle,
                 sizeof(fpm->last_peer_process_handle),
                 identity.process.kind ==
                     RPD_FPM_PROCESS_HANDLE_PIDFD ?
                 "pidfd" : "procfd");
        str_copy(fpm->last_peer_executable,
                 sizeof(fpm->last_peer_executable),
                 identity.peer.executable);
        pthread_mutex_unlock(&fpm->lock);
        NL_LOG_INFO("rpd FPM peer accepted: pid=%ld uid=%lu "
                    "starttime=%llu authority-generation=%llu "
                    "socket-inode=%llu executable=%s",
                    (long)identity.peer.pid,
                    (unsigned long)identity.peer.uid,
                    (unsigned long long)identity.peer.starttime,
                    (unsigned long long)
                        identity.peer.authority_generation,
                    (unsigned long long)identity.peer.socket_inode,
                    identity.peer.executable);
        pthread_mutex_lock(&fpm->lock);
        fpm->client_fd = fd;
        fpm->connections++;
        fpm->last_connect = time(NULL);
        str_copy(fpm->status, sizeof(fpm->status), "connected");
        pthread_mutex_unlock(&fpm->lock);
        (void)handle_client(fpm, fd, &identity);
        fpm_pending_clear(fpm, true);
        nh_cache_clear(fpm);
        close(fd);
        close_connection_identity(&identity);
        pthread_mutex_lock(&fpm->lock);
        if (fpm->client_fd == fd)
            fpm->client_fd = -1;
        if (!fpm->stop_requested)
            str_copy(fpm->status, sizeof(fpm->status), "listening");
        pthread_mutex_unlock(&fpm->lock);
    }
    set_status(fpm, "stopped", NULL);
    return NULL;
}

void rpd_fpm_init(rpd_fpm_listener *fpm) {
    if (!fpm)
        return;
    memset(fpm, 0, sizeof(*fpm));
    fpm->listen_fd = -1;
    fpm->client_fd = -1;
    fpm->port = RPD_FPM_DEFAULT_PORT;
    pthread_mutex_init(&fpm->lock, NULL);
    str_copy(fpm->status, sizeof(fpm->status), "disabled");
    str_copy(fpm->last_error, sizeof(fpm->last_error),
             "FPM listener is disabled until FRR is available or explicitly enabled");
}

int rpd_fpm_start(rpd_fpm_listener *fpm, int port,
                  rpd_fpm_authority_fn authority, void *authority_ctx,
                  rpd_fpm_apply_fn apply, void *apply_ctx,
                  char *err, size_t err_size) {
    int fd;
    int one = 1;
    struct sockaddr_in addr;

    if (!fpm || !authority || !apply) {
        snprintf(err, err_size, "invalid FPM listener start request");
        return -1;
    }
    if (port <= 0)
        port = RPD_FPM_DEFAULT_PORT;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, err_size, "FPM listener socket failed");
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 4) != 0) {
        snprintf(err, err_size, "FPM listener bind/listen failed on 127.0.0.1:%d",
                 port);
        close(fd);
        pthread_mutex_lock(&fpm->lock);
        str_copy(fpm->status, sizeof(fpm->status), "error");
        str_copy(fpm->last_error, sizeof(fpm->last_error), err);
        pthread_mutex_unlock(&fpm->lock);
        return -1;
    }
    pthread_mutex_lock(&fpm->lock);
    fpm->enabled = true;
    fpm->listen_fd = fd;
    fpm->port = port;
    fpm->authority = authority;
    fpm->authority_ctx = authority_ctx;
    fpm->apply = apply;
    fpm->apply_ctx = apply_ctx;
    fpm->stop_requested = false;
    str_copy(fpm->status, sizeof(fpm->status), "starting");
    str_copy(fpm->last_error, sizeof(fpm->last_error), "");
    pthread_mutex_unlock(&fpm->lock);
    if (pthread_create(&fpm->thread, NULL, fpm_thread_main, fpm) != 0) {
        snprintf(err, err_size, "FPM listener thread start failed");
        close(fd);
        pthread_mutex_lock(&fpm->lock);
        fpm->listen_fd = -1;
        fpm->enabled = false;
        str_copy(fpm->status, sizeof(fpm->status), "error");
        pthread_mutex_unlock(&fpm->lock);
        return -1;
    }
    pthread_mutex_lock(&fpm->lock);
    fpm->thread_started = true;
    pthread_mutex_unlock(&fpm->lock);
    NL_LOG_NOTICE("rpd FPM listener enabled on 127.0.0.1:%d", port);
    return 0;
}

void rpd_fpm_stop(rpd_fpm_listener *fpm) {
    bool join = false;
    int listen_fd = -1;
    int client_fd = -1;

    if (!fpm)
        return;
    pthread_mutex_lock(&fpm->lock);
    fpm->stop_requested = true;
    listen_fd = fpm->listen_fd;
    client_fd = fpm->client_fd;
    join = fpm->thread_started;
    pthread_mutex_unlock(&fpm->lock);
    if (listen_fd >= 0)
        shutdown(listen_fd, SHUT_RDWR);
    if (client_fd >= 0)
        shutdown(client_fd, SHUT_RDWR);
    if (join)
        pthread_join(fpm->thread, NULL);
    fpm_pending_clear(fpm, false);
    if (listen_fd >= 0)
        close(listen_fd);
    pthread_mutex_lock(&fpm->lock);
    fpm->listen_fd = -1;
    fpm->client_fd = -1;
    fpm->thread_started = false;
    fpm->enabled = false;
    pthread_mutex_unlock(&fpm->lock);
}

void rpd_fpm_destroy(rpd_fpm_listener *fpm) {
    if (!fpm)
        return;
    rpd_fpm_stop(fpm);
    pthread_mutex_destroy(&fpm->lock);
}

typedef struct {
    bool enabled;
    int port;
    uid_t expected_peer_uid;
    pid_t last_peer_pid;
    uid_t last_peer_uid;
    u64 last_peer_starttime;
    u64 last_peer_socket_inode;
    u64 last_authority_generation;
    char last_peer_process_handle[16];
    char status[32];
    char last_error[160];
    time_t last_connect;
    time_t last_frame;
    u64 connections;
    u64 peer_auth_failures;
    u64 peer_revalidations;
    u64 frames;
    u64 route_updates;
    u64 decode_errors;
    u64 ignored_updates;
    u64 deferred_updates;
    u64 deferred_replays;
    u64 deferred_drops;
    u64 apply_errors;
    u64 nh_cache_updates;
    u64 nh_cache_resets;
    u64 nh_cache_hits;
    u64 nh_cache_misses;
    u32 pending_frames;
    u64 pending_bytes;
} rpd_fpm_status_snapshot;

static void rpd_fpm_status_snapshot_get(
    rpd_fpm_listener *fpm, rpd_fpm_status_snapshot *out) {
    if (!fpm || !out)
        return;
    pthread_mutex_lock(&fpm->lock);
    memset(out, 0, sizeof(*out));
    out->enabled = fpm->enabled;
    out->port = fpm->port;
    out->expected_peer_uid = fpm->expected_peer_uid;
    out->last_peer_pid = fpm->last_peer_pid;
    out->last_peer_uid = fpm->last_peer_uid;
    out->last_peer_starttime = fpm->last_peer_starttime;
    out->last_peer_socket_inode = fpm->last_peer_socket_inode;
    out->last_authority_generation =
        fpm->last_authority_generation;
    str_copy(out->last_peer_process_handle,
             sizeof(out->last_peer_process_handle),
             fpm->last_peer_process_handle);
    str_copy(out->status, sizeof(out->status), fpm->status);
    str_copy(out->last_error, sizeof(out->last_error), fpm->last_error);
    out->last_connect = fpm->last_connect;
    out->last_frame = fpm->last_frame;
    out->connections = fpm->connections;
    out->peer_auth_failures = fpm->peer_auth_failures;
    out->peer_revalidations = fpm->peer_revalidations;
    out->frames = fpm->frames;
    out->route_updates = fpm->route_updates;
    out->decode_errors = fpm->decode_errors;
    out->ignored_updates = fpm->ignored_updates;
    out->deferred_updates = fpm->deferred_updates;
    out->deferred_replays = fpm->deferred_replays;
    out->deferred_drops = fpm->deferred_drops;
    out->apply_errors = fpm->apply_errors;
    out->nh_cache_updates = fpm->nh_cache_updates;
    out->nh_cache_resets = fpm->nh_cache_resets;
    out->nh_cache_hits = fpm->nh_cache_hits;
    out->nh_cache_misses = fpm->nh_cache_misses;
    out->pending_frames = fpm->pending_frames;
    out->pending_bytes = fpm->pending_bytes;
    pthread_mutex_unlock(&fpm->lock);
}

int rpd_fpm_append_xml(rpd_fpm_listener *fpm, char *buf,
                       size_t buf_size, size_t *off) {
    rpd_fpm_status_snapshot snap;
    int n;
    time_t now = time(NULL);

    if (!fpm || !buf || !off || *off >= buf_size)
        return -1;
    memset(&snap, 0, sizeof(snap));
    rpd_fpm_status_snapshot_get(fpm, &snap);
    n = snprintf(buf + *off, buf_size - *off,
                 "  <fpm-listener enabled=\"%s\" status=\"%s\" "
                 "port=\"%d\" connections=\"%llu\" frames=\"%llu\" "
                 "peer-auth-failures=\"%llu\" "
                 "peer-revalidations=\"%llu\" "
                 "route-updates=\"%llu\" decode-errors=\"%llu\" "
                 "ignored-updates=\"%llu\" deferred-updates=\"%llu\" "
                 "deferred-replays=\"%llu\" deferred-drops=\"%llu\" "
                 "pending-frames=\"%u\" pending-bytes=\"%llu\" "
                 "apply-errors=\"%llu\" nh-cache-updates=\"%llu\" "
                 "nh-cache-resets=\"%llu\" "
                 "nh-cache-hits=\"%llu\" nh-cache-misses=\"%llu\" "
                 "expected-peer-uid=\"%lu\" last-peer-pid=\"%ld\" "
                 "last-peer-uid=\"%lu\" last-peer-starttime=\"%llu\" "
                 "last-authority-generation=\"%llu\" "
                 "last-peer-process-handle=\"%s\" "
                 "last-peer-socket-inode=\"%llu\" "
                 "last-connect-age=\"%ld\" "
                 "last-frame-age=\"%ld\" last-error=\"%s\"/>\n",
                 snap.enabled ? "true" : "false", snap.status, snap.port,
                 (unsigned long long)snap.connections,
                 (unsigned long long)snap.frames,
                 (unsigned long long)snap.peer_auth_failures,
                 (unsigned long long)snap.peer_revalidations,
                 (unsigned long long)snap.route_updates,
                 (unsigned long long)snap.decode_errors,
                 (unsigned long long)snap.ignored_updates,
                 (unsigned long long)snap.deferred_updates,
                 (unsigned long long)snap.deferred_replays,
                 (unsigned long long)snap.deferred_drops,
                 snap.pending_frames,
                 (unsigned long long)snap.pending_bytes,
                 (unsigned long long)snap.apply_errors,
                 (unsigned long long)snap.nh_cache_updates,
                 (unsigned long long)snap.nh_cache_resets,
                 (unsigned long long)snap.nh_cache_hits,
                 (unsigned long long)snap.nh_cache_misses,
                 (unsigned long)snap.expected_peer_uid,
                 (long)snap.last_peer_pid,
                 (unsigned long)snap.last_peer_uid,
                 (unsigned long long)snap.last_peer_starttime,
                 (unsigned long long)snap.last_authority_generation,
                 snap.last_peer_process_handle,
                 (unsigned long long)snap.last_peer_socket_inode,
                 snap.last_connect ? (long)(now - snap.last_connect) : -1L,
                 snap.last_frame ? (long)(now - snap.last_frame) : -1L,
                 snap.last_error);
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}
