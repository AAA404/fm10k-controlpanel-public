#include "netlab/ipc.h"
#include "netlab/daemon_identity.h"
#include "netlab/log.h"
#include <ctype.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/uio.h>

#define NETLAB_IPC_AUTH_MAGIC UINT32_C(0x4e4c4155)
#define NETLAB_IPC_AUTH_VERSION UINT16_C(1)
#define NETLAB_IPC_AUTH_CHALLENGE UINT16_C(1)
#define NETLAB_IPC_AUTH_RESPONSE UINT16_C(2)
#define NETLAB_IPC_AUTH_NONCE_SIZE 32U
#define NETLAB_IPC_AUTH_RECORD_SIZE (8U + NETLAB_IPC_AUTH_NONCE_SIZE)
#define NETLAB_IPC_AUTH_TIMEOUT_MS 5000U
#define NETLAB_IPC_MAX_RIGHTS_FDS 253U

typedef struct {
    struct timeval receive;
    struct timeval send;
    bool valid;
} ipc_socket_timeouts;

static void store_u16_be(u8 *out, u16 value) {
    out[0] = (u8)(value >> 8);
    out[1] = (u8)value;
}

static void store_u32_be(u8 *out, u32 value) {
    out[0] = (u8)(value >> 24);
    out[1] = (u8)(value >> 16);
    out[2] = (u8)(value >> 8);
    out[3] = (u8)value;
}

static u16 load_u16_be(const u8 *in) {
    return (u16)(((u16)in[0] << 8) | (u16)in[1]);
}

static u32 load_u32_be(const u8 *in) {
    return ((u32)in[0] << 24) | ((u32)in[1] << 16) |
        ((u32)in[2] << 8) | (u32)in[3];
}

static void auth_record_encode(u8 *record, u16 type, const u8 *nonce) {
    store_u32_be(record, NETLAB_IPC_AUTH_MAGIC);
    store_u16_be(record + 4, NETLAB_IPC_AUTH_VERSION);
    store_u16_be(record + 6, type);
    memcpy(record + 8, nonce, NETLAB_IPC_AUTH_NONCE_SIZE);
}

static int auth_record_valid(
    const u8 *record, u16 expected_type, const u8 *nonce) {
    return record &&
        load_u32_be(record) == NETLAB_IPC_AUTH_MAGIC &&
        load_u16_be(record + 4) == NETLAB_IPC_AUTH_VERSION &&
        load_u16_be(record + 6) == expected_type &&
        memcmp(record + 8, nonce, NETLAB_IPC_AUTH_NONCE_SIZE) == 0;
}

static int fill_auth_nonce(u8 nonce[NETLAB_IPC_AUTH_NONCE_SIZE]) {
    size_t filled = 0;

    while (filled < NETLAB_IPC_AUTH_NONCE_SIZE) {
        ssize_t count = getrandom(
            nonce + filled, NETLAB_IPC_AUTH_NONCE_SIZE - filled, 0);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return 0;
        filled += (size_t)count;
    }
    return 1;
}

static int enable_peer_credentials(nl_conn *conn) {
    int enabled = 1;

    if (!conn || conn->fd < 0 ||
        setsockopt(conn->fd, SOL_SOCKET, SO_PASSCRED,
                   &enabled, sizeof(enabled)) != 0)
        return 0;
    conn->peer_credentials_enabled = true;
    return 1;
}

static int save_and_set_auth_timeouts(
    int fd, u32 timeout_ms, ipc_socket_timeouts *saved) {
    struct timeval timeout;
    socklen_t size = sizeof(struct timeval);
    int receive_changed = 0;

    if (fd < 0 || timeout_ms == 0 || !saved)
        return 0;
    if (timeout_ms > NETLAB_IPC_AUTH_TIMEOUT_MS)
        timeout_ms = NETLAB_IPC_AUTH_TIMEOUT_MS;
    timeout.tv_sec = (time_t)(timeout_ms / 1000U);
    timeout.tv_usec = (suseconds_t)((timeout_ms % 1000U) * 1000U);
    memset(saved, 0, sizeof(*saved));
    if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   &saved->receive, &size) != 0)
        return 0;
    size = sizeof(struct timeval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                   &saved->send, &size) != 0)
        return 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) != 0)
        return 0;
    receive_changed = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, sizeof(timeout)) != 0) {
        if (receive_changed)
            (void)setsockopt(
                fd, SOL_SOCKET, SO_RCVTIMEO,
                &saved->receive, sizeof(saved->receive));
        return 0;
    }
    saved->valid = true;
    return 1;
}

static void restore_auth_timeouts(
    int fd, const ipc_socket_timeouts *saved) {
    if (fd < 0 || !saved || !saved->valid)
        return;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     &saved->receive, sizeof(saved->receive));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                     &saved->send, sizeof(saved->send));
}

int nl_ipc_socket_path_safe(const char *path) {
    size_t len;

    if (!path || !path[0])
        return 0;
    len = strlen(path);
    if (len >= sizeof(((struct sockaddr_un *)0)->sun_path))
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];

        if (!(isalnum(c) || c == '/' || c == '.' || c == '_' ||
              c == '-' || c == ':'))
            return 0;
    }
    return 1;
}

const char *nl_ipc_socket_path_from_env(const char *env_name,
                                        const char *fallback) {
    const char *path;

    if (!env_name || !env_name[0])
        return fallback;
    path = getenv(env_name);
    if (path && path[0] == '/' && nl_ipc_socket_path_safe(path))
        return path;
    return fallback;
}

static int path_has_prefix(const char *path, const char *prefix) {
    size_t prefix_len;

    if (!path || !prefix)
        return 0;
    prefix_len = strlen(prefix);
    return strncmp(path, prefix, prefix_len) == 0 &&
           (path[prefix_len] == '\0' || path[prefix_len] == '/');
}

static int socket_basename_safe(const char *path) {
    const char *base;
    size_t len;

    if (!path || path[0] != '/')
        return 0;
    if (strstr(path, "/../") || strstr(path, "/./") ||
        strcmp(path, "/..") == 0 || strcmp(path, "/.") == 0)
        return 0;
    len = strlen(path);
    if ((len >= 3 && strcmp(path + len - 3, "/..") == 0) ||
        (len >= 2 && strcmp(path + len - 2, "/.") == 0))
        return 0;
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    len = strlen(base);
    if (len <= 5 || strcmp(base + len - 5, ".sock") != 0)
        return 0;
    return 1;
}

static int socket_parent_dir_safe(const char *path) {
    char parent[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char *slash;
    struct stat st;

    if (!path || strlen(path) >= sizeof(parent))
        return 0;
    snprintf(parent, sizeof(parent), "%s", path);
    slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return 0;
    *slash = '\0';
    if (lstat(parent, &st) != 0) {
        if (errno == ENOENT && path_has_prefix(path, NETLAB_IPC_PATH))
            return 1;
        return 0;
    }
    if (!S_ISDIR(st.st_mode))
        return 0;
    if (!path_has_prefix(path, NETLAB_IPC_PATH)) {
        if ((st.st_mode & (S_IWGRP | S_IWOTH)) &&
            !(st.st_mode & S_ISVTX))
            return 0;
        if (st.st_uid != geteuid() && st.st_uid != 0)
            return 0;
    }
    return 1;
}

static int nl_ipc_server_socket_path_safe(const char *path) {
    return nl_ipc_socket_path_safe(path) &&
           socket_basename_safe(path) &&
           socket_parent_dir_safe(path);
}

nl_status nl_ipc_unlink_socket(const char *path) {
    struct stat st;

    if (!nl_ipc_server_socket_path_safe(path)) {
        NL_LOG_ERR("unsafe IPC socket path: %s", path ? path : "(null)");
        return NL_ERR;
    }
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT)
            return NL_OK;
        NL_LOG_ERR("lstat(%s): %s", path, strerror(errno));
        return NL_ERR;
    }
    if (!S_ISSOCK(st.st_mode)) {
        NL_LOG_ERR("refusing to unlink non-socket IPC path %s", path);
        return NL_ERR;
    }
    if (unlink(path) != 0) {
        NL_LOG_ERR("unlink(%s): %s", path, strerror(errno));
        return NL_ERR;
    }
    return NL_OK;
}

static int apply_socket_permissions(const char *path) {
    struct group *grp;
    int private_path;

    if (!path)
        return 0;
    private_path = path_has_prefix(path, NETLAB_IPC_PATH);
    if (private_path) {
        grp = getgrnam(NL_DAEMON_PRIVATE_IPC_GROUP);
        if (!grp) {
            NL_LOG_ERR("required socket group %s is unavailable",
                       NL_DAEMON_PRIVATE_IPC_GROUP);
            return 0;
        }
        if (chown(path, 0, grp->gr_gid) != 0) {
            NL_LOG_ERR("chown(%s,root:%s): %s", path,
                       NL_DAEMON_PRIVATE_IPC_GROUP, strerror(errno));
            return 0;
        }
    }
    if (chmod(path, 0660) != 0) {
        NL_LOG_ERR("chmod(%s,0660): %s", path, strerror(errno));
        return 0;
    }
    return 1;
}

nl_status nl_server_listen(const char *path, int *fd) {
    struct sockaddr_un addr;
    int sfd;

    if (!fd || !nl_ipc_server_socket_path_safe(path)) {
        NL_LOG_ERR("unsafe IPC listen path: %s", path ? path : "(null)");
        return NL_ERR;
    }

    sfd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (sfd < 0) {
        NL_LOG_ERR("socket: %s", strerror(errno));
        return NL_ERR;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (nl_ipc_unlink_socket(path) != NL_OK) {
        close(sfd);
        return NL_ERR;
    }
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        NL_LOG_ERR("bind(%s): %s", path, strerror(errno));
        close(sfd);
        return NL_ERR;
    }

    if (!apply_socket_permissions(path)) {
        close(sfd);
        (void)nl_ipc_unlink_socket(path);
        return NL_ERR;
    }

    if (listen(sfd, 32) < 0) {
        NL_LOG_ERR("listen: %s", strerror(errno));
        close(sfd);
        (void)nl_ipc_unlink_socket(path);
        return NL_ERR;
    }

    *fd = sfd;
    NL_LOG_INFO("listening on %s", path);
    return NL_OK;
}

static ssize_t recv_peer_record_impl(
    nl_conn *conn, void *buffer, size_t capacity, int flags,
    int require_authenticated, int require_peer_match,
    struct ucred *observed_credentials) {
    union {
        struct cmsghdr alignment;
        char bytes[
            CMSG_SPACE(sizeof(struct ucred)) +
            CMSG_SPACE(sizeof(int) * NETLAB_IPC_MAX_RIGHTS_FDS)];
    } control;
    struct iovec iov;
    struct msghdr message;
    struct cmsghdr *cmsg;
    struct ucred credentials;
    int credential_count = 0;
    int ancillary_invalid = 0;
    ssize_t received;

    if (!conn || conn->fd < 0 || !buffer || capacity == 0 ||
        !conn->peer_credentials_enabled ||
        (flags & MSG_PEEK) != 0 ||
        (require_authenticated && !conn->peer_authenticated)) {
        errno = EPERM;
        return -1;
    }
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    memset(&credentials, 0, sizeof(credentials));
    iov.iov_base = buffer;
    iov.iov_len = capacity;
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);

    do {
        received = recvmsg(
            conn->fd, &message, flags | MSG_CMSG_CLOEXEC);
    } while (received < 0 && errno == EINTR);
    if (received < 0)
        return -1;
    for (cmsg = CMSG_FIRSTHDR(&message); cmsg;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_RIGHTS) {
            size_t payload_size;
            size_t fd_count;
            int *received_fds;

            ancillary_invalid = 1;
            if (cmsg->cmsg_len < CMSG_LEN(0))
                continue;
            payload_size = cmsg->cmsg_len - CMSG_LEN(0);
            if (payload_size % sizeof(int) != 0)
                continue;
            received_fds = (int *)CMSG_DATA(cmsg);
            fd_count = payload_size / sizeof(int);
            for (size_t i = 0; i < fd_count; i++) {
                if (received_fds[i] >= 0)
                    close(received_fds[i]);
            }
            continue;
        }
        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_CREDENTIALS) {
            if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct ucred)) ||
                credential_count != 0) {
                ancillary_invalid = 1;
                continue;
            }
            memcpy(&credentials, CMSG_DATA(cmsg), sizeof(credentials));
            credential_count++;
            continue;
        }
        ancillary_invalid = 1;
    }
    if ((message.msg_flags & MSG_CTRUNC) != 0 ||
        ancillary_invalid) {
        errno = EPROTO;
        return -1;
    }
    if (received == 0 && credential_count == 0)
        return 0;
    if (credential_count != 1) {
        errno = EPERM;
        return -1;
    }
    if (observed_credentials)
        *observed_credentials = credentials;
    if (require_peer_match &&
        (credentials.pid != conn->peer_pid ||
         credentials.uid != conn->peer_uid ||
         credentials.gid != conn->peer_gid)) {
        errno = EPERM;
        return -1;
    }
    return received;
}

ssize_t nl_recv_peer_record(
    nl_conn *conn, void *buffer, size_t capacity, int flags) {
    return recv_peer_record_impl(
        conn, buffer, capacity, flags, true, true, NULL);
}

nl_status nl_send_record(
    nl_conn *conn, const void *buffer, size_t length) {
    ssize_t sent;

    if (!conn || conn->fd < 0 || !buffer || length == 0 ||
        length > NETLAB_MAX_MSG || !conn->peer_credentials_enabled ||
        !conn->peer_authenticated)
        return NL_ERR;
    do {
        sent = send(conn->fd, buffer, length, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)length ? NL_OK : NL_ERR;
}

static nl_status send_auth_record(
    nl_conn *conn, u16 type,
    const u8 nonce[NETLAB_IPC_AUTH_NONCE_SIZE]) {
    u8 record[NETLAB_IPC_AUTH_RECORD_SIZE];
    ssize_t sent;

    if (!conn || conn->fd < 0 || !nonce)
        return NL_ERR;
    auth_record_encode(record, type, nonce);
    do {
        sent = send(conn->fd, record, sizeof(record), MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    return sent == (ssize_t)sizeof(record) ? NL_OK : NL_ERR;
}

static nl_status receive_auth_record(
    nl_conn *conn, u16 expected_type,
    const u8 nonce[NETLAB_IPC_AUTH_NONCE_SIZE]) {
    u8 record[NETLAB_IPC_AUTH_RECORD_SIZE];
    ssize_t received;

    received = recv_peer_record_impl(
        conn, record, sizeof(record), MSG_TRUNC, false, true, NULL);
    if (received < 0)
        return NL_ERR;
    if (received != (ssize_t)sizeof(record) ||
        !auth_record_valid(record, expected_type, nonce)) {
        errno = EPROTO;
        return NL_ERR;
    }
    return NL_OK;
}

static const nl_daemon_identity *dedicated_identity_for_socket(
    const char *path) {
    if (!path)
        return NULL;
    for (size_t i = 0; i < nl_daemon_identity_count(); i++) {
        const nl_daemon_identity *identity = nl_daemon_identity_at(i);

        if (identity &&
            identity->kind == NL_DAEMON_IDENTITY_REAL &&
            identity->socket_path &&
            identity->dedicated_account &&
            identity->dedicated_primary_group &&
            identity->expected_account &&
            identity->primary_group &&
            strcmp(identity->socket_path, path) == 0 &&
            strcmp(identity->expected_account,
                   identity->dedicated_account) == 0 &&
            strcmp(identity->primary_group,
                   identity->dedicated_primary_group) == 0)
            return identity;
    }
    return NULL;
}

static bool process_starttime(pid_t pid, u64 *starttime) {
    char path[64];
    char line[4096];
    char *fields;
    char *save = NULL;
    char *token;
    FILE *stream;
    int field = 3;
    int written;

    if (pid <= 0 || !starttime)
        return false;
    written = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (written <= 0 || (size_t)written >= sizeof(path))
        return false;
    stream = fopen(path, "r");
    if (!stream)
        return false;
    if (!fgets(line, sizeof(line), stream)) {
        fclose(stream);
        return false;
    }
    fclose(stream);
    fields = strrchr(line, ')');
    if (!fields || fields[1] != ' ')
        return false;
    fields += 2;
    token = strtok_r(fields, " \n", &save);
    while (token) {
        if (field == 3 &&
            (token[0] == '\0' || token[1] != '\0' ||
             token[0] == 'Z' || token[0] == 'X' || token[0] == 'x'))
            return false;
        if (field == 22) {
            char *end = NULL;
            unsigned long long value;

            errno = 0;
            value = strtoull(token, &end, 10);
            if (errno != 0 || !end || *end != '\0' || value == 0)
                return false;
            *starttime = (u64)value;
            return true;
        }
        field++;
        token = strtok_r(NULL, " \n", &save);
    }
    return false;
}

static bool dedicated_ready_metadata_valid(
    const nl_daemon_identity *identity, pid_t pid) {
    char path[sizeof(((struct sockaddr_un *)0)->sun_path) + 16];
    char expected_record[128];
    struct stat metadata;
    u64 live_starttime;
    int expected_length;
    int written;

    if (!identity || !identity->socket_path || pid <= 0)
        return false;
    written = snprintf(
        path, sizeof(path), "%s.ready", identity->socket_path);
    if (written <= 0 || (size_t)written >= sizeof(path))
        return false;
    if (lstat(path, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != 0 || metadata.st_gid != 0 ||
        metadata.st_nlink != 1 ||
        (metadata.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO |
                             S_ISUID | S_ISGID | S_ISVTX)) != 0600 ||
        !process_starttime(pid, &live_starttime))
        return false;
    expected_length = snprintf(
        expected_record, sizeof(expected_record),
        "pid=%ld starttime=%llu\n", (long)pid,
        (unsigned long long)live_starttime);
    /*
     * The readiness record is deliberately root:root 0600, so a dedicated
     * client must not read it.  Its immutable metadata and exact expected
     * size prove publication; nl_daemon_run cannot accept/send a challenge
     * until after it has fsync'd this exact record.
     */
    return expected_length > 0 &&
        (size_t)expected_length < sizeof(expected_record) &&
        metadata.st_size == (off_t)expected_length;
}

static bool dedicated_release_executable_valid(
    const nl_daemon_identity *identity, pid_t pid) {
    char expected[NL_DAEMON_EXECUTABLE_PATH_MAX];
    char proc_path[64];
    char observed[NL_DAEMON_EXECUTABLE_PATH_MAX];
    struct stat st;
    ssize_t length;
    int written;

    if (!identity ||
        !nl_daemon_identity_expected_executable(
            identity, expected, sizeof(expected)) ||
        lstat(expected, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode &
         (S_IWGRP | S_IWOTH | S_ISUID | S_ISGID | S_ISVTX)) != 0 ||
        (st.st_mode & S_IXOTH) == 0)
        return false;
    written = snprintf(
        proc_path, sizeof(proc_path), "/proc/%ld/exe", (long)pid);
    if (written <= 0 || (size_t)written >= sizeof(proc_path))
        return false;
    length = readlink(proc_path, observed, sizeof(observed) - 1U);
    if (length >= 0) {
        if ((size_t)length >= sizeof(observed) - 1U)
            return false;
        observed[length] = '\0';
        return strcmp(observed, expected) == 0;
    }
    /*
     * Linux denies cross-UID /proc/<pid>/exe inspection without ptrace.
     * The same-PID root listener transition plus root-owned readiness and
     * the launcher's safe same-release fexec remain the executable anchor.
     */
    return errno == EACCES || errno == EPERM;
}

static bool dedicated_prebind_transition_valid(
    const char *path, const nl_conn *conn,
    const struct ucred *observed) {
    const nl_daemon_identity *identity;
    nl_daemon_credentials expected;

    if (!path || !conn || !observed ||
        conn->peer_pid <= 0 ||
        conn->peer_uid != 0 || conn->peer_gid != 0 ||
        observed->pid != conn->peer_pid)
        return false;
    identity = dedicated_identity_for_socket(path);
    if (!identity ||
        !nl_daemon_identity_resolve_credentials(identity, &expected) ||
        observed->uid != expected.uid ||
        observed->gid != expected.primary_gid)
        return false;
    return dedicated_ready_metadata_valid(identity, observed->pid) &&
        dedicated_release_executable_valid(identity, observed->pid);
}

static nl_status receive_auth_challenge(
    const char *path, nl_conn *conn,
    u8 nonce[NETLAB_IPC_AUTH_NONCE_SIZE]) {
    u8 record[NETLAB_IPC_AUTH_RECORD_SIZE];
    struct ucred observed;
    ssize_t received;

    if (!path || !conn || !nonce)
        return NL_ERR;
    memset(&observed, 0, sizeof(observed));
    received = recv_peer_record_impl(
        conn, record, sizeof(record), MSG_TRUNC, false, false, &observed);
    if (received < 0)
        return NL_ERR;
    if (received != (ssize_t)sizeof(record) ||
        load_u32_be(record) != NETLAB_IPC_AUTH_MAGIC ||
        load_u16_be(record + 4) != NETLAB_IPC_AUTH_VERSION ||
        load_u16_be(record + 6) != NETLAB_IPC_AUTH_CHALLENGE) {
        errno = EPROTO;
        return NL_ERR;
    }
    if (observed.pid != conn->peer_pid ||
        observed.uid != conn->peer_uid ||
        observed.gid != conn->peer_gid) {
        if (!dedicated_prebind_transition_valid(path, conn, &observed)) {
            errno = EPERM;
            return NL_ERR;
        }
        conn->peer_uid = observed.uid;
        conn->peer_gid = observed.gid;
    }
    memcpy(nonce, record + 8, NETLAB_IPC_AUTH_NONCE_SIZE);
    return NL_OK;
}

nl_status nl_server_accept(int listen_fd, nl_conn *conn) {
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);

    if (!conn)
        return NL_ERR;
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    conn->peer_uid = (uid_t)-1;
    conn->peer_gid = (gid_t)-1;
    conn->peer_pid = (pid_t)-1;
    conn->fd = accept4(
        listen_fd, (struct sockaddr *)&addr, &addrlen, SOCK_CLOEXEC);
    if (conn->fd < 0) {
        NL_LOG_ERR("accept: %s", strerror(errno));
        return NL_ERR;
    }

    if (nl_get_peer_cred(conn->fd, &conn->peer_uid, &conn->peer_gid,
                         &conn->peer_pid) != NL_OK) {
        NL_LOG_ERR("get peer credentials failed");
        close(conn->fd);
        conn->fd = -1;
        return NL_ERR;
    }
    if (!enable_peer_credentials(conn)) {
        NL_LOG_ERR("enable peer credentials failed");
        close(conn->fd);
        conn->fd = -1;
        return NL_ERR;
    }
    NL_LOG_DBG("accepted connection uid=%d gid=%d pid=%d",
                conn->peer_uid, conn->peer_gid, conn->peer_pid);
    return NL_OK;
}

nl_status nl_server_authenticate_timeout(
    nl_conn *conn, u32 timeout_ms) {
    ipc_socket_timeouts saved;
    u8 nonce[NETLAB_IPC_AUTH_NONCE_SIZE];
    nl_status result = NL_ERR;

    if (!conn || conn->fd < 0 || conn->peer_authenticated ||
        !conn->peer_credentials_enabled || !fill_auth_nonce(nonce) ||
        !save_and_set_auth_timeouts(conn->fd, timeout_ms, &saved))
        return NL_ERR;
    if (send_auth_record(
            conn, NETLAB_IPC_AUTH_CHALLENGE, nonce) == NL_OK &&
        receive_auth_record(
            conn, NETLAB_IPC_AUTH_RESPONSE, nonce) == NL_OK) {
        conn->peer_authenticated = true;
        result = NL_OK;
    }
    restore_auth_timeouts(conn->fd, &saved);
    memset(nonce, 0, sizeof(nonce));
    return result;
}

nl_status nl_server_authenticate(nl_conn *conn) {
    return nl_server_authenticate_timeout(
        conn, NETLAB_IPC_AUTH_TIMEOUT_MS);
}

nl_status nl_client_connect_timeout(
    const char *path, nl_conn *conn, u32 timeout_ms) {
    struct sockaddr_un addr;
    ipc_socket_timeouts saved = {0};
    u8 nonce[NETLAB_IPC_AUTH_NONCE_SIZE];
    nl_status auth_result = NL_ERR;

    if (!conn)
        return NL_ERR;
    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;
    conn->peer_uid = (uid_t)-1;
    conn->peer_gid = (gid_t)-1;
    conn->peer_pid = (pid_t)-1;
    if (!path || path[0] != '/' || timeout_ms == 0 ||
        !nl_ipc_socket_path_safe(path))
        return NL_ERR;

    conn->fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (conn->fd < 0) {
        NL_LOG_ERR("socket: %s", strerror(errno));
        return NL_ERR;
    }
    /*
     * Enable credential delivery before connect.  The server may send its
     * challenge immediately after accept, so enabling SO_PASSCRED afterwards
     * would leave a send/setsockopt race at the authentication boundary.
     */
    if (!enable_peer_credentials(conn))
        goto auth_failed;
    if (!save_and_set_auth_timeouts(conn->fd, timeout_ms, &saved))
        goto auth_failed;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        NL_LOG_ERR("connect(%s): %s", path, strerror(errno));
        goto auth_failed;
    }
    if (nl_get_peer_cred(conn->fd, &conn->peer_uid, &conn->peer_gid,
                         &conn->peer_pid) != NL_OK)
        goto auth_failed;
    if (receive_auth_challenge(path, conn, nonce) == NL_OK &&
        send_auth_record(
            conn, NETLAB_IPC_AUTH_RESPONSE, nonce) == NL_OK) {
        conn->peer_authenticated = true;
        auth_result = NL_OK;
    }
    restore_auth_timeouts(conn->fd, &saved);
    memset(nonce, 0, sizeof(nonce));
    if (auth_result != NL_OK)
        goto auth_failed;

    strncpy(conn->addr.sun_path, path, sizeof(conn->addr.sun_path) - 1);
    conn->addr.sun_family = AF_UNIX;

    NL_LOG_DBG("connected to %s", path);
    return NL_OK;

auth_failed:
    NL_LOG_DBG("IPC peer authentication failed for %s",
               path ? path : "(null)");
    close(conn->fd);
    conn->fd = -1;
    memset(nonce, 0, sizeof(nonce));
    return NL_ERR;
}

nl_status nl_client_connect(const char *path, nl_conn *conn) {
    return nl_client_connect_timeout(
        path, conn, NETLAB_IPC_AUTH_TIMEOUT_MS);
}

void nl_client_close(nl_conn *conn) {
    if (!conn)
        return;
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }
    conn->peer_credentials_enabled = false;
    conn->peer_authenticated = false;
    conn->peer_uid = (uid_t)-1;
    conn->peer_gid = (gid_t)-1;
    conn->peer_pid = (pid_t)-1;
}

static int ipc_timeout_error(int error) {
    return error == EAGAIN || error == EWOULDBLOCK;
}

static int ipc_peer_closed_error(int error) {
    return error == EPIPE || error == ECONNRESET || error == ENOTCONN;
}

static void log_ipc_io_error(const char *operation, int error) {
    if (ipc_timeout_error(error)) {
        NL_LOG_DBG("%s timed out: %s", operation, strerror(error));
    } else if (ipc_peer_closed_error(error)) {
        NL_LOG_DBG("%s peer closed connection: %s", operation,
                   strerror(error));
    } else {
        NL_LOG_ERR("%s: %s", operation, strerror(error));
    }
}

static int ipc_schema_supported(u16 schema_version) {
    /* Schema zero was emitted by the original C allocator. */
    return schema_version <= NETLAB_IPC_SCHEMA_CURRENT;
}

static int ipc_message_type_valid(u16 type) {
    return type <= NL_MSG_ERROR;
}

static nl_status send_iov(nl_conn *conn, struct iovec *iov, size_t iov_len,
                          size_t total, u16 schema_version) {
    struct msghdr wire = {0};
    ssize_t ret;

    wire.msg_iov = iov;
    wire.msg_iovlen = iov_len;
    ret = sendmsg(conn->fd, &wire, MSG_NOSIGNAL);
    if (ret < 0) {
        if (errno == EMSGSIZE && schema_version < NETLAB_IPC_SCHEMA_V2) {
            NL_LOG_ERR("send: legacy IPC schema %u message exceeds the "
                       "SOCK_SEQPACKET frame limit; schema 2 is required",
                       schema_version);
        } else {
            log_ipc_io_error("send", errno);
        }
        return NL_ERR;
    }
    if ((size_t)ret != total) {
        NL_LOG_ERR("short send: %zd < %zu", ret, total);
        return NL_ERR;
    }
    return NL_OK;
}

static nl_status send_direct(nl_conn *conn, const nl_msg_hdr *msg,
                             u16 schema_version) {
    nl_msg_hdr wire_hdr;
    struct iovec iov[2];
    size_t iov_len = 1;

    memcpy(&wire_hdr, msg, NL_HDR_SIZE);
    wire_hdr.schema_version = schema_version;
    iov[0].iov_base = &wire_hdr;
    iov[0].iov_len = NL_HDR_SIZE;
    if (msg->payload_len > 0) {
        iov[1].iov_base = (void *)msg->payload;
        iov[1].iov_len = msg->payload_len;
        iov_len++;
    }
    return send_iov(conn, iov, iov_len,
                    NL_HDR_SIZE + msg->payload_len, schema_version);
}

static nl_status send_chunked(nl_conn *conn, const nl_msg_hdr *msg) {
    const u32 app_flags = msg->flags & ~NL_MSG_F_TRANSPORT_MASK;
    u32 offset = 0;

    while (offset < msg->payload_len) {
        const u32 remaining = msg->payload_len - offset;
        const u32 data_len = remaining > NETLAB_IPC_CHUNK_DATA_MAX ?
            NETLAB_IPC_CHUNK_DATA_MAX : remaining;
        nl_ipc_chunk_hdr chunk = {
            .total_payload_len = msg->payload_len,
            .offset = offset,
            .data_len = data_len,
        };
        nl_msg_hdr wire_hdr;
        struct iovec iov[3];

        memcpy(&wire_hdr, msg, NL_HDR_SIZE);
        wire_hdr.schema_version = NETLAB_IPC_SCHEMA_V2;
        wire_hdr.flags = app_flags | NL_MSG_F_CHUNKED;
        if (offset == 0)
            wire_hdr.flags |= NL_MSG_F_CHUNK_FIRST;
        if (offset + data_len == msg->payload_len)
            wire_hdr.flags |= NL_MSG_F_CHUNK_LAST;
        wire_hdr.payload_len = (u32)NL_IPC_CHUNK_HDR_SIZE + data_len;

        iov[0].iov_base = &wire_hdr;
        iov[0].iov_len = NL_HDR_SIZE;
        iov[1].iov_base = &chunk;
        iov[1].iov_len = NL_IPC_CHUNK_HDR_SIZE;
        iov[2].iov_base = (void *)(msg->payload + offset);
        iov[2].iov_len = data_len;
        if (send_iov(conn, iov, 3,
                     NL_HDR_SIZE + NL_IPC_CHUNK_HDR_SIZE + data_len,
                     NETLAB_IPC_SCHEMA_V2) != NL_OK)
            return NL_ERR;
        offset += data_len;
    }
    return NL_OK;
}

nl_status nl_send(nl_conn *conn, nl_msg_hdr *msg) {
    u16 schema_version;

    if (!conn || !msg || msg->magic != NETLAB_MAGIC ||
        msg->payload_len > NETLAB_MAX_MSG ||
        !ipc_schema_supported(msg->schema_version) ||
        !ipc_message_type_valid(msg->type) ||
        (msg->flags & NL_MSG_F_TRANSPORT_MASK) != 0)
        return NL_ERR;

    schema_version = msg->schema_version;
    if (conn->peer_schema_known &&
        conn->peer_schema_version < NETLAB_IPC_SCHEMA_V2)
        schema_version = conn->peer_schema_version;

    if (schema_version >= NETLAB_IPC_SCHEMA_V2 &&
        msg->payload_len > NETLAB_IPC_CHUNK_DATA_MAX)
        return send_chunked(conn, msg);
    return send_direct(conn, msg, schema_version);
}

static nl_status recv_frame(nl_conn *conn, nl_msg_hdr **out) {
    u8 header_buf[NL_HDR_SIZE];
    nl_msg_hdr header;
    size_t expected;
    ssize_t ret;

    *out = NULL;
    ret = recv(conn->fd, header_buf, sizeof(header_buf),
               MSG_PEEK | MSG_TRUNC);
    if (ret <= 0) {
        if (ret == 0)
            NL_LOG_DBG("connection closed");
        else
            log_ipc_io_error("recv", errno);
        return NL_ERR;
    }
    if (ret < (ssize_t)NL_HDR_SIZE) {
        NL_LOG_ERR("short header: %zd < %u", ret, (unsigned)NL_HDR_SIZE);
        return NL_ERR;
    }

    memcpy(&header, header_buf, NL_HDR_SIZE);
    if (header.magic != NETLAB_MAGIC) {
        NL_LOG_ERR("bad magic: 0x%x", header.magic);
        return NL_ERR;
    }
    if (!ipc_schema_supported(header.schema_version)) {
        NL_LOG_ERR("unsupported IPC schema: %u", header.schema_version);
        return NL_ERR;
    }
    if (!ipc_message_type_valid(header.type)) {
        NL_LOG_ERR("invalid IPC message type: %u", header.type);
        return NL_ERR;
    }
    if (header.payload_len > NETLAB_MAX_MSG) {
        NL_LOG_ERR("payload too large: %u > %u", header.payload_len,
                   NETLAB_MAX_MSG);
        return NL_ERR;
    }
    expected = NL_HDR_SIZE + header.payload_len;
    if ((size_t)ret != expected) {
        NL_LOG_ERR("IPC packet length mismatch: %zd != %zu", ret, expected);
        return NL_ERR;
    }

    nl_msg_hdr *msg = nl_msg_alloc(header.payload_len);
    if (!msg)
        return NL_ERR;
    if (conn->peer_credentials_enabled) {
        if (!conn->peer_authenticated) {
            errno = EPERM;
            ret = -1;
        } else {
            ret = nl_recv_peer_record(
                conn, msg, expected, MSG_TRUNC);
        }
    } else {
        /*
         * Pure framing tests may build a local socketpair-backed nl_conn
         * directly. Every accepted/connected production nl_conn enables
         * credentials and therefore must pass authentication above.
         */
        ret = recv(conn->fd, msg, expected, MSG_TRUNC);
    }
    if (ret < 0) {
        log_ipc_io_error("recv payload", errno);
        free(msg);
        return NL_ERR;
    }
    if ((size_t)ret != expected) {
        NL_LOG_ERR("short message: %zd != %zu", ret, expected);
        free(msg);
        return NL_ERR;
    }
    msg->payload[msg->payload_len] = '\0';
    *out = msg;
    return NL_OK;
}

static int chunk_header_decode(const nl_msg_hdr *frame,
                               nl_ipc_chunk_hdr *chunk) {
    if (!frame || !chunk ||
        frame->schema_version != NETLAB_IPC_SCHEMA_V2 ||
        (frame->flags & NL_MSG_F_CHUNKED) == 0 ||
        frame->payload_len < NL_IPC_CHUNK_HDR_SIZE)
        return 0;
    memcpy(chunk, frame->payload, NL_IPC_CHUNK_HDR_SIZE);
    if (chunk->total_payload_len <= NETLAB_IPC_CHUNK_DATA_MAX ||
        chunk->total_payload_len > NETLAB_MAX_MSG ||
        chunk->data_len == 0 ||
        chunk->data_len > NETLAB_IPC_CHUNK_DATA_MAX ||
        frame->payload_len != NL_IPC_CHUNK_HDR_SIZE + chunk->data_len ||
        chunk->offset > chunk->total_payload_len ||
        chunk->data_len > chunk->total_payload_len - chunk->offset)
        return 0;
    if (chunk->offset + chunk->data_len < chunk->total_payload_len &&
        chunk->data_len != NETLAB_IPC_CHUNK_DATA_MAX)
        return 0;
    return 1;
}

static int logical_headers_match(const nl_msg_hdr *first,
                                 const nl_msg_hdr *next) {
    return first->magic == next->magic &&
           next->schema_version == NETLAB_IPC_SCHEMA_V2 &&
           first->type == next->type &&
           first->request_id == next->request_id &&
           first->tx_id == next->tx_id &&
           first->daemon_id == next->daemon_id &&
           first->method == next->method &&
           (first->flags & ~NL_MSG_F_TRANSPORT_MASK) ==
               (next->flags & ~NL_MSG_F_TRANSPORT_MASK) &&
           first->error_code == next->error_code &&
           first->timeout_ms == next->timeout_ms;
}

static void note_peer_schema(nl_conn *conn, u16 schema_version) {
    conn->peer_schema_version = schema_version;
    conn->peer_schema_known = true;
}

nl_status nl_recv(nl_conn *conn, nl_msg_hdr **out) {
    nl_msg_hdr *first = NULL;
    nl_msg_hdr *logical = NULL;
    nl_ipc_chunk_hdr chunk;
    u32 received;

    if (!conn || !out)
        return NL_ERR;
    *out = NULL;
    if (recv_frame(conn, &first) != NL_OK)
        return NL_ERR;

    if ((first->flags & NL_MSG_F_TRANSPORT_MASK) == 0) {
        if (first->schema_version == NETLAB_IPC_SCHEMA_V2 &&
            first->payload_len > NETLAB_IPC_CHUNK_DATA_MAX) {
            NL_LOG_ERR("non-canonical direct IPC V2 frame: %u > %u",
                       first->payload_len,
                       (unsigned)NETLAB_IPC_CHUNK_DATA_MAX);
            free(first);
            return NL_ERR;
        }
        note_peer_schema(conn, first->schema_version);
        *out = first;
        return NL_OK;
    }
    if (first->schema_version != NETLAB_IPC_SCHEMA_V2 ||
        (first->flags & NL_MSG_F_CHUNKED) == 0 ||
        (first->flags & NL_MSG_F_CHUNK_FIRST) == 0 ||
        (first->flags & NL_MSG_F_CHUNK_LAST) != 0 ||
        !chunk_header_decode(first, &chunk) || chunk.offset != 0) {
        NL_LOG_ERR("invalid first IPC V2 chunk");
        free(first);
        return NL_ERR;
    }

    logical = nl_msg_alloc(chunk.total_payload_len);
    if (!logical) {
        free(first);
        return NL_ERR;
    }
    memcpy(logical, first, NL_HDR_SIZE);
    logical->schema_version = NETLAB_IPC_SCHEMA_V2;
    logical->flags &= ~NL_MSG_F_TRANSPORT_MASK;
    logical->payload_len = chunk.total_payload_len;
    memcpy(logical->payload,
           first->payload + NL_IPC_CHUNK_HDR_SIZE, chunk.data_len);
    received = chunk.data_len;

    while (received < logical->payload_len) {
        nl_msg_hdr *next = NULL;
        nl_ipc_chunk_hdr next_chunk;
        int final;

        if (recv_frame(conn, &next) != NL_OK || !next) {
            NL_LOG_ERR("incomplete IPC V2 chunk sequence");
            free(first);
            free(logical);
            return NL_ERR;
        }
        if (!logical_headers_match(first, next) ||
            (next->flags & NL_MSG_F_CHUNKED) == 0 ||
            (next->flags & NL_MSG_F_CHUNK_FIRST) != 0 ||
            !chunk_header_decode(next, &next_chunk) ||
            next_chunk.total_payload_len != logical->payload_len ||
            next_chunk.offset != received) {
            NL_LOG_ERR("invalid IPC V2 chunk sequence");
            free(next);
            free(first);
            free(logical);
            return NL_ERR;
        }
        final = next_chunk.offset + next_chunk.data_len ==
                logical->payload_len;
        if (((next->flags & NL_MSG_F_CHUNK_LAST) != 0) != final) {
            NL_LOG_ERR("invalid IPC V2 final chunk marker");
            free(next);
            free(first);
            free(logical);
            return NL_ERR;
        }
        memcpy(logical->payload + received,
               next->payload + NL_IPC_CHUNK_HDR_SIZE,
               next_chunk.data_len);
        received += next_chunk.data_len;
        free(next);
    }

    note_peer_schema(conn, NETLAB_IPC_SCHEMA_V2);
    free(first);
    *out = logical;
    return NL_OK;
}

nl_status nl_send_response(nl_conn *conn, u64 request_id, s32 error_code) {
    nl_msg_hdr *resp = nl_msg_alloc(0);
    if (!resp) return NL_ERR;
    resp->type = NL_MSG_RESPONSE;
    resp->request_id = request_id;
    resp->error_code = error_code;
    nl_status st = nl_send(conn, resp);
    nl_msg_free(resp);
    return st;
}

nl_status nl_get_peer_cred(int fd, uid_t *uid, gid_t *gid, pid_t *pid) {
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        return NL_ERR;
    }
    *uid = cred.uid;
    *gid = cred.gid;
    *pid = cred.pid;
    return NL_OK;
}

static int allocation_size_add(size_t left, size_t right, size_t *out) {
    if (!out || left > SIZE_MAX - right)
        return 0;
    *out = left + right;
    return 1;
}

nl_msg_hdr *nl_msg_alloc(u32 payload_len) {
    size_t allocation_size;

    if (payload_len > NETLAB_MAX_MSG ||
        !allocation_size_add(NL_HDR_SIZE, (size_t)payload_len,
                             &allocation_size) ||
        !allocation_size_add(allocation_size, 1U, &allocation_size))
        return NULL;
    nl_msg_hdr *msg = calloc(1, allocation_size);
    if (!msg) return NULL;
    msg->magic = NETLAB_MAGIC;
    msg->schema_version = NETLAB_IPC_SCHEMA_CURRENT;
    msg->payload_len = payload_len;
    return msg;
}

void nl_msg_free(nl_msg_hdr *msg) {
    free(msg);
}
