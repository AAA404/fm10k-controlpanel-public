#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "netlab/daemon_identity.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define NETLAB_LISTENER_FD 3
#define NETLAB_READY_FD 4
#define NETLAB_FIRST_PRIVATE_FD 5
#define NETLAB_LISTEN_BACKLOG 32
#define NETLAB_READY_SUFFIX ".ready"
#define NETLAB_RUNTIME_DIRECTORY "/var/run/netlab"
#define NETLAB_EXEC_WATCHDOG_TIMEOUT_MS 10000

typedef struct {
    char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    char ready_path[
        sizeof(((struct sockaddr_un *)0)->sun_path) +
        sizeof(NETLAB_READY_SUFFIX)];
    dev_t socket_device;
    ino_t socket_inode;
    dev_t ready_device;
    ino_t ready_inode;
    bool socket_created;
    bool ready_created;
    bool watchdog_owns_cleanup;
} launch_cleanup;

static launch_cleanup g_cleanup;

static void usage(const char *program) {
    fprintf(stderr, "usage: %s <daemon>\n",
            program && program[0] ? program : "netlab-daemon-launch");
}

static void report_errno(const char *operation) {
    fprintf(stderr, "netlab-daemon-launch: %s: %s\n",
            operation, strerror(errno));
}

static bool mode_exact(mode_t actual, mode_t expected) {
    return (actual & (S_IRWXU | S_IRWXG | S_IRWXO |
                      S_ISUID | S_ISGID | S_ISVTX)) == expected;
}

static bool unlink_matching_path(const char *path, dev_t device, ino_t inode,
                                 mode_t type) {
    struct stat st;

    if (!path || !path[0])
        return false;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if ((st.st_mode & S_IFMT) != type ||
        st.st_dev != device || st.st_ino != inode)
        return false;
    return unlink(path) == 0 || errno == ENOENT;
}

static void cleanup_created_paths(void) {
    if (g_cleanup.watchdog_owns_cleanup)
        return;
    if (g_cleanup.ready_created) {
        (void)unlink_matching_path(
            g_cleanup.ready_path, g_cleanup.ready_device,
            g_cleanup.ready_inode, S_IFREG);
        g_cleanup.ready_created = false;
    }
    if (g_cleanup.socket_created) {
        (void)unlink_matching_path(
            g_cleanup.socket_path, g_cleanup.socket_device,
            g_cleanup.socket_inode, S_IFSOCK);
        g_cleanup.socket_created = false;
    }
}

static bool lookup_user(const char *name, uid_t *uid, gid_t *primary_gid) {
    struct passwd pwd;
    struct passwd *result = NULL;
    char buffer[65536];

    return name && name[0] && uid && primary_gid &&
        getpwnam_r(name, &pwd, buffer, sizeof(buffer), &result) == 0 &&
        result &&
        ((*uid = result->pw_uid), (*primary_gid = result->pw_gid), true);
}

static bool lookup_group(const char *name, gid_t *gid) {
    struct group group;
    struct group *result = NULL;
    char buffer[65536];

    return name && name[0] && gid &&
        getgrnam_r(name, &group, buffer, sizeof(buffer), &result) == 0 &&
        result && ((*gid = result->gr_gid), true);
}

static bool resolve_target_credentials(
    const nl_daemon_identity *identity, uid_t *uid, gid_t *primary_gid,
    gid_t *ipc_gid) {
    gid_t passwd_gid;

    if (!identity || !identity->dedicated_account ||
        !identity->dedicated_primary_group ||
        !identity->private_ipc_group ||
        strcmp(identity->private_ipc_group,
               NL_DAEMON_PRIVATE_IPC_GROUP) != 0 ||
        !lookup_user(identity->dedicated_account, uid, &passwd_gid) ||
        !lookup_group(identity->dedicated_primary_group, primary_gid) ||
        !lookup_group(NL_DAEMON_PRIVATE_IPC_GROUP, ipc_gid) ||
        passwd_gid != *primary_gid || *uid == 0 || *primary_gid == 0 ||
        *ipc_gid == 0 || *primary_gid == *ipc_gid) {
        errno = EINVAL;
        return false;
    }
    return true;
}

static bool executable_path(
    const nl_daemon_identity *identity, char *path, size_t path_size,
    int *target_fd, struct stat *target_st) {
    char self[NL_DAEMON_EXECUTABLE_PATH_MAX];
    char directory[NL_DAEMON_EXECUTABLE_PATH_MAX];
    char *separator;
    struct stat directory_st;
    struct stat path_st;
    unsigned char elf_magic[4];
    ssize_t length;
    int directory_fd = -1;
    int fd = -1;
    int written;

    if (!identity || !identity->binary || !identity->binary[0] ||
        strchr(identity->binary, '/') || !path || path_size < 2 ||
        !target_fd || !target_st) {
        errno = EINVAL;
        return false;
    }
    length = readlink("/proc/self/exe", self, sizeof(self) - 1U);
    if (length <= 0 || (size_t)length >= sizeof(self) - 1U) {
        errno = EINVAL;
        return false;
    }
    self[length] = '\0';
    if (self[0] != '/' ||
        ((size_t)length >= strlen(" (deleted)") &&
         strcmp(self + length - (ssize_t)strlen(" (deleted)"),
                " (deleted)") == 0)) {
        errno = EPERM;
        return false;
    }
    if (snprintf(directory, sizeof(directory), "%s", self) >=
        (int)sizeof(directory)) {
        errno = ENAMETOOLONG;
        return false;
    }
    separator = strrchr(directory, '/');
    if (!separator || separator == directory) {
        errno = EINVAL;
        return false;
    }
    *separator = '\0';
    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0)
        return false;
    if (fstat(directory_fd, &directory_st) != 0 ||
        !S_ISDIR(directory_st.st_mode) || directory_st.st_uid != 0 ||
        (directory_st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        errno = EPERM;
        goto failed;
    }
    written = snprintf(path, path_size, "%s/%s",
                       directory, identity->binary);
    if (written <= 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        goto failed;
    }
    fd = openat(directory_fd, identity->binary,
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        goto failed;
    if (fstat(fd, target_st) != 0 ||
        !S_ISREG(target_st->st_mode) || target_st->st_uid != 0 ||
        (target_st->st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (target_st->st_mode & (S_ISUID | S_ISGID)) != 0 ||
        (target_st->st_mode & S_IXOTH) == 0 ||
        pread(fd, elf_magic, sizeof(elf_magic), 0) !=
            (ssize_t)sizeof(elf_magic) ||
        memcmp(elf_magic, "\177ELF", sizeof(elf_magic)) != 0 ||
        stat(path, &path_st) != 0 ||
        path_st.st_dev != target_st->st_dev ||
        path_st.st_ino != target_st->st_ino) {
        errno = EPERM;
        goto failed;
    }
    close(directory_fd);
    *target_fd = fd;
    return true;

failed:
    {
        int saved = errno;
        if (fd >= 0)
            close(fd);
        close(directory_fd);
        errno = saved;
        return false;
    }
}

static bool runtime_directory_valid(void) {
    struct stat st;

    if (lstat(NETLAB_RUNTIME_DIRECTORY, &st) != 0)
        return false;
    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 ||
        st.st_gid != 0 || !mode_exact(st.st_mode, 0711)) {
        errno = EPERM;
        return false;
    }
    return true;
}

static bool socket_path_is_active(const char *path) {
    struct sockaddr_un address;
    int fd;
    int saved;

    fd = socket(
        AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return true;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s", path) >=
        (int)sizeof(address.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return true;
    }
    if (connect(fd, (struct sockaddr *)&address,
                offsetof(struct sockaddr_un, sun_path) +
                strlen(address.sun_path) + 1U) == 0) {
        close(fd);
        errno = EADDRINUSE;
        return true;
    }
    saved = errno;
    close(fd);
    errno = saved;
    return saved != ECONNREFUSED && saved != ENOENT;
}

static bool remove_stale_socket(const char *path, gid_t ipc_gid) {
    struct stat st;

    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISSOCK(st.st_mode) || st.st_uid != 0 ||
        st.st_gid != ipc_gid || !mode_exact(st.st_mode, 0660)) {
        errno = EPERM;
        return false;
    }
    if (socket_path_is_active(path))
        return false;
    return unlink(path) == 0;
}

static bool remove_stale_ready(const char *path) {
    struct stat st;

    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
        st.st_nlink != 1 || !mode_exact(st.st_mode, 0600)) {
        errno = EPERM;
        return false;
    }
    return unlink(path) == 0;
}

static bool create_listener(
    const char *path, gid_t ipc_gid, int *listener_fd) {
    struct sockaddr_un address;
    struct stat st;
    int fd = -1;

    if (!path || !listener_fd ||
        strncmp(path, NETLAB_RUNTIME_DIRECTORY "/",
                strlen(NETLAB_RUNTIME_DIRECTORY) + 1U) != 0 ||
        strchr(path + strlen(NETLAB_RUNTIME_DIRECTORY) + 1U, '/') ||
        snprintf(g_cleanup.socket_path, sizeof(g_cleanup.socket_path),
                 "%s", path) >= (int)sizeof(g_cleanup.socket_path)) {
        errno = EINVAL;
        return false;
    }
    if (!remove_stale_socket(path, ipc_gid))
        return false;

    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s", path) >=
        (int)sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        goto failed;
    }
    if (bind(fd, (struct sockaddr *)&address,
             offsetof(struct sockaddr_un, sun_path) +
             strlen(address.sun_path) + 1U) != 0)
        goto failed;
    g_cleanup.socket_created = true;
    if (lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode))
        goto failed;
    g_cleanup.socket_device = st.st_dev;
    g_cleanup.socket_inode = st.st_ino;
    if (chown(path, 0, ipc_gid) != 0 || chmod(path, 0660) != 0 ||
        lstat(path, &st) != 0 || !S_ISSOCK(st.st_mode) ||
        st.st_uid != 0 || st.st_gid != ipc_gid ||
        !mode_exact(st.st_mode, 0660) ||
        listen(fd, NETLAB_LISTEN_BACKLOG) != 0)
        goto failed;
    if (st.st_dev != g_cleanup.socket_device ||
        st.st_ino != g_cleanup.socket_inode) {
        errno = ESTALE;
        goto failed;
    }
    *listener_fd = fd;
    return true;

failed:
    {
        int saved = errno;
        if (fd >= 0)
            close(fd);
        cleanup_created_paths();
        errno = saved;
        return false;
    }
}

static bool create_ready_file(const char *socket_path, int *ready_fd) {
    struct stat st;
    int fd;
    int written;

    if (!socket_path || !ready_fd) {
        errno = EINVAL;
        return false;
    }
    written = snprintf(g_cleanup.ready_path, sizeof(g_cleanup.ready_path),
                       "%s%s", socket_path, NETLAB_READY_SUFFIX);
    if (written <= 0 || (size_t)written >= sizeof(g_cleanup.ready_path)) {
        errno = ENAMETOOLONG;
        return false;
    }
    if (!remove_stale_ready(g_cleanup.ready_path))
        return false;
    fd = open(g_cleanup.ready_path,
              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    g_cleanup.ready_created = true;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        int saved = errno;
        close(fd);
        cleanup_created_paths();
        errno = saved;
        return false;
    }
    g_cleanup.ready_device = st.st_dev;
    g_cleanup.ready_inode = st.st_ino;
    if (fchown(fd, 0, 0) != 0 || fchmod(fd, 0600) != 0 ||
        fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || st.st_gid != 0 || st.st_nlink != 1 ||
        !mode_exact(st.st_mode, 0600) ||
        st.st_dev != g_cleanup.ready_device ||
        st.st_ino != g_cleanup.ready_inode) {
        int saved = errno;
        close(fd);
        cleanup_created_paths();
        errno = saved;
        return false;
    }
    *ready_fd = fd;
    return true;
}

static bool fd_at_least(int *fd, int minimum) {
    int moved;

    if (!fd || *fd < 0) {
        errno = EINVAL;
        return false;
    }
    if (*fd >= minimum)
        return true;
    moved = fcntl(*fd, F_DUPFD_CLOEXEC, minimum);
    if (moved < 0)
        return false;
    close(*fd);
    *fd = moved;
    return true;
}

static bool install_fixed_fd(int source, int target) {
    int flags;

    if (source < NETLAB_FIRST_PRIVATE_FD ||
        (target != NETLAB_LISTENER_FD && target != NETLAB_READY_FD)) {
        errno = EINVAL;
        return false;
    }
    if (dup2(source, target) < 0)
        return false;
    flags = fcntl(target, F_GETFD);
    return flags >= 0 &&
        fcntl(target, F_SETFD, flags & ~FD_CLOEXEC) == 0;
}

static bool mark_private_fds_cloexec(void) {
    DIR *directory;
    struct dirent *entry;
    int scan_fd;
    bool valid = true;

    directory = opendir("/proc/self/fd");
    if (!directory)
        return false;
    scan_fd = dirfd(directory);
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long parsed;
        int flags;

        if (entry->d_name[0] == '.')
            continue;
        errno = 0;
        parsed = strtol(entry->d_name, &end, 10);
        if (errno != 0 || !end || *end != '\0' ||
            parsed <= NETLAB_READY_FD || parsed > INT32_MAX ||
            parsed == scan_fd)
            continue;
        flags = fcntl((int)parsed, F_GETFD);
        if (flags < 0 ||
            fcntl((int)parsed, F_SETFD, flags | FD_CLOEXEC) != 0) {
            valid = false;
            break;
        }
    }
    closedir(directory);
    return valid;
}

static bool listener_fd_valid(int fd, const char *path,
                              gid_t ipc_gid) {
    struct sockaddr_un address;
    struct stat st;
    socklen_t address_size = sizeof(address);
    socklen_t value_size;
    int value;

    memset(&address, 0, sizeof(address));
    if (getsockname(fd, (struct sockaddr *)&address, &address_size) != 0 ||
        address.sun_family != AF_UNIX ||
        strcmp(address.sun_path, path) != 0)
        return false;
    value_size = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &value_size) != 0 ||
        value != SOCK_SEQPACKET)
        return false;
    value_size = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN,
                   &value, &value_size) != 0 || value != 1)
        return false;
#ifdef SO_DOMAIN
    value_size = sizeof(value);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN,
                   &value, &value_size) != 0 || value != AF_UNIX)
        return false;
#endif
    return lstat(path, &st) == 0 && S_ISSOCK(st.st_mode) &&
        st.st_uid == 0 && st.st_gid == ipc_gid &&
        mode_exact(st.st_mode, 0660);
}

static bool ready_fd_valid(int fd) {
    struct stat st;

    return fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == 0 && st.st_gid == 0 && st.st_nlink == 1 &&
        mode_exact(st.st_mode, 0600);
}

static bool set_capabilities(uint64_t permitted, uint64_t effective,
                             uint64_t inheritable) {
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

    memset(&header, 0, sizeof(header));
    memset(data, 0, sizeof(data));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    data[0].permitted = (uint32_t)permitted;
    data[1].permitted = (uint32_t)(permitted >> 32);
    data[0].effective = (uint32_t)effective;
    data[1].effective = (uint32_t)(effective >> 32);
    data[0].inheritable = (uint32_t)inheritable;
    data[1].inheritable = (uint32_t)(inheritable >> 32);
    return syscall(SYS_capset, &header, data) == 0;
}

static bool get_capabilities(uint64_t *permitted, uint64_t *effective,
                             uint64_t *inheritable) {
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];

    if (!permitted || !effective || !inheritable) {
        errno = EINVAL;
        return false;
    }
    memset(&header, 0, sizeof(header));
    memset(data, 0, sizeof(data));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    if (syscall(SYS_capget, &header, data) != 0)
        return false;
    *permitted = (uint64_t)data[0].permitted |
        ((uint64_t)data[1].permitted << 32);
    *effective = (uint64_t)data[0].effective |
        ((uint64_t)data[1].effective << 32);
    *inheritable = (uint64_t)data[0].inheritable |
        ((uint64_t)data[1].inheritable << 32);
    return true;
}

static int capability_supported(int capability) {
    int present;

    errno = 0;
    present = prctl(PR_CAPBSET_READ, capability, 0L, 0L, 0L);
    if (present >= 0)
        return 1;
    return errno == EINVAL ? 0 : -1;
}

static bool drop_bounding_set(bool identity_broker) {
    for (int capability = 0; capability < 64; capability++) {
        int supported = capability_supported(capability);

        if (supported < 0)
            return false;
        if (supported == 0)
            continue;
        if (identity_broker && capability == CAP_SYS_PTRACE)
            continue;
        if (prctl(PR_CAPBSET_DROP, capability, 0L, 0L, 0L) != 0)
            return false;
    }
    return true;
}

static bool bounding_set_valid(bool identity_broker) {
    for (int capability = 0; capability < 64; capability++) {
        int expected =
            identity_broker && capability == CAP_SYS_PTRACE ? 1 : 0;
        int supported = capability_supported(capability);
        int actual;

        if (supported < 0)
            return false;
        if (supported == 0)
            continue;
        actual = prctl(PR_CAPBSET_READ, capability, 0L, 0L, 0L);
        if (actual < 0 || actual != expected)
            return false;
    }
    return true;
}

static bool ambient_set_valid(bool identity_broker) {
    for (int capability = 0; capability < 64; capability++) {
        int expected =
            identity_broker && capability == CAP_SYS_PTRACE ? 1 : 0;
        int supported = capability_supported(capability);
        int actual;

        if (supported < 0)
            return false;
        if (supported == 0)
            continue;
        actual = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
                       capability, 0L, 0L);
        if (actual < 0 || actual != expected)
            return false;
    }
    return true;
}

static bool credentials_valid(uid_t uid, gid_t gid, gid_t ipc_gid) {
    uid_t real_uid;
    uid_t effective_uid;
    uid_t saved_uid;
    gid_t real_gid;
    gid_t effective_gid;
    gid_t saved_gid;
    gid_t groups[2];
    int group_count;

    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_uid != uid || effective_uid != uid || saved_uid != uid ||
        real_gid != gid || effective_gid != gid || saved_gid != gid)
        return false;
    group_count = getgroups(2, groups);
    return group_count == 1 && groups[0] == ipc_gid;
}

static bool privilege_state_valid(bool identity_broker) {
    uint64_t permitted;
    uint64_t effective;
    uint64_t inheritable;
    uint64_t expected =
        identity_broker ? UINT64_C(1) << CAP_SYS_PTRACE : 0;

    if (!get_capabilities(&permitted, &effective, &inheritable) ||
        permitted != expected || effective != expected ||
        /*
         * A non-root exec cannot retain a capability with both file
         * capabilities and Ambient empty.  identityd therefore receives
         * CAP_SYS_PTRACE through a one-exec Inheritable/Ambient handoff and
         * must clear both before handling any external input.
         */
        inheritable != expected ||
        !bounding_set_valid(identity_broker) ||
        !ambient_set_valid(identity_broker) ||
        prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) != 1)
        return false;
    return true;
}

static bool drop_privileges(uid_t uid, gid_t gid, gid_t ipc_gid,
                            bool identity_broker) {
    uint64_t retained =
        identity_broker ? UINT64_C(1) << CAP_SYS_PTRACE : 0;

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL,
              0L, 0L, 0L) != 0 ||
        !drop_bounding_set(identity_broker))
        return false;
    if (identity_broker &&
        prctl(PR_SET_KEEPCAPS, 1L, 0L, 0L, 0L) != 0)
        return false;
    if (setgroups(1, &ipc_gid) != 0 ||
        setresgid(gid, gid, gid) != 0 ||
        setresuid(uid, uid, uid) != 0)
        return false;
    if (!set_capabilities(retained, retained, retained))
        return false;
    if (identity_broker &&
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
              CAP_SYS_PTRACE, 0L, 0L) != 0)
        return false;
    if (prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
        return false;
    return credentials_valid(uid, gid, ipc_gid) &&
        privilege_state_valid(identity_broker);
}

static bool process_executes_target(
    pid_t pid, const struct stat *target_st) {
    char path[64];
    struct stat st;
    int written;

    if (pid <= 0 || !target_st)
        return false;
    written = snprintf(path, sizeof(path), "/proc/%ld/exe", (long)pid);
    return written > 0 && (size_t)written < sizeof(path) &&
        stat(path, &st) == 0 && st.st_dev == target_st->st_dev &&
        st.st_ino == target_st->st_ino;
}

static void watchdog_cleanup(void) {
    (void)unlink_matching_path(
        g_cleanup.ready_path, g_cleanup.ready_device,
        g_cleanup.ready_inode, S_IFREG);
    (void)unlink_matching_path(
        g_cleanup.socket_path, g_cleanup.socket_device,
        g_cleanup.socket_inode, S_IFSOCK);
}

static void exec_watchdog_main(
    int status_fd, pid_t launcher_pid, const struct stat *target_st) {
    struct pollfd descriptor;
    char marker;
    int result;
    ssize_t count;

    descriptor.fd = status_fd;
    descriptor.events = POLLIN | POLLHUP;
    descriptor.revents = 0;
    do {
        result = poll(
            &descriptor, 1, NETLAB_EXEC_WATCHDOG_TIMEOUT_MS);
    } while (result < 0 && errno == EINTR);
    if (result > 0) {
        do {
            count = read(status_fd, &marker, sizeof(marker));
        } while (count < 0 && errno == EINTR);
        close(status_fd);
        if (count > 0 || !process_executes_target(
                launcher_pid, target_st))
            watchdog_cleanup();
        _exit(0);
    }
    close(status_fd);
    if (!process_executes_target(launcher_pid, target_st))
        watchdog_cleanup();
    _exit(0);
}

static bool start_exec_watchdog(
    int listener_fd, int ready_fd, int target_fd,
    const struct stat *target_st, int *status_fd) {
    int status_pipe[2] = {-1, -1};
    pid_t intermediate;
    pid_t launcher_pid = getpid();
    int wait_status;
    pid_t waited;

    if (!target_st || !status_fd ||
        pipe2(status_pipe, O_CLOEXEC) != 0)
        return false;
    intermediate = fork();
    if (intermediate < 0)
        goto failed;
    if (intermediate == 0) {
        pid_t watchdog;

        close(status_pipe[1]);
        watchdog = fork();
        if (watchdog < 0)
            _exit(1);
        if (watchdog > 0)
            _exit(0);
        if (listener_fd >= 0)
            close(listener_fd);
        if (ready_fd >= 0)
            close(ready_fd);
        if (target_fd >= 0)
            close(target_fd);
        close(NETLAB_LISTENER_FD);
        close(NETLAB_READY_FD);
        exec_watchdog_main(
            status_pipe[0], launcher_pid, target_st);
    }
    close(status_pipe[0]);
    status_pipe[0] = -1;
    do {
        waited = waitpid(intermediate, &wait_status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != intermediate)
        goto failed;
    if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0)
        goto failed;
    *status_fd = status_pipe[1];
    return true;

failed:
    {
        int saved = errno;
        if (status_pipe[0] >= 0)
            close(status_pipe[0]);
        if (status_pipe[1] >= 0)
            close(status_pipe[1]);
        errno = saved;
        return false;
    }
}

static void notify_exec_failure(int fd) {
    static const char failure = 'F';
    ssize_t written;

    if (fd < 0)
        return;
    do {
        written = write(fd, &failure, sizeof(failure));
    } while (written < 0 && errno == EINTR);
}

static bool block_setup_signals(sigset_t *previous) {
    sigset_t blocked;

    if (!previous || sigemptyset(&blocked) != 0 ||
        sigaddset(&blocked, SIGINT) != 0 ||
        sigaddset(&blocked, SIGTERM) != 0 ||
        sigaddset(&blocked, SIGHUP) != 0)
        return false;
    return sigprocmask(SIG_BLOCK, &blocked, previous) == 0;
}

int main(int argc, char **argv) {
    const nl_daemon_identity *identity;
    char target_path[NL_DAEMON_EXECUTABLE_PATH_MAX];
    char *target_argv[4];
    char *target_environment[] = {
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C",
        "LC_ALL=C",
        NULL,
    };
    struct stat target_st;
    uid_t target_uid;
    gid_t target_gid;
    gid_t ipc_gid;
    int listener_fd = -1;
    int ready_fd = -1;
    int target_fd = -1;
    int watchdog_fd = -1;
    bool identity_broker;
    sigset_t original_signal_mask;

    memset(&g_cleanup, 0, sizeof(g_cleanup));
    if (atexit(cleanup_created_paths) != 0) {
        report_errno("atexit");
        return 1;
    }
    if (argc != 2) {
        usage(argv ? argv[0] : NULL);
        return 2;
    }
    if (getuid() != 0 || geteuid() != 0) {
        fprintf(stderr, "netlab-daemon-launch: root is required\n");
        return 1;
    }
    if (!block_setup_signals(&original_signal_mask)) {
        report_errno("block setup signals");
        return 1;
    }
    if (!nl_daemon_identity_registry_valid()) {
        fprintf(stderr,
                "netlab-daemon-launch: daemon identity registry is invalid\n");
        return 1;
    }
    identity = nl_daemon_identity_lookup_name(argv[1]);
    if (!identity || identity->kind != NL_DAEMON_IDENTITY_REAL ||
        !identity->dedicated_account ||
        !identity->dedicated_primary_group ||
        !identity->expected_account || !identity->primary_group ||
        strcmp(identity->expected_account,
               identity->dedicated_account) != 0 ||
        strcmp(identity->primary_group,
               identity->dedicated_primary_group) != 0 ||
        !identity->socket_path || !identity->no_new_privileges ||
        (identity->capability_mask != 0 &&
         identity->capability_mask != NL_DAEMON_CAP_SYS_PTRACE_MASK) ||
        ((identity->capability_mask ==
          NL_DAEMON_CAP_SYS_PTRACE_MASK) !=
         (identity->wire_id == NL_DAEMON_IDENTITYD))) {
        fprintf(stderr,
                "netlab-daemon-launch: %s has no supported dedicated "
                "privilege profile\n",
                argv[1]);
        return 1;
    }
    identity_broker =
        identity->capability_mask == NL_DAEMON_CAP_SYS_PTRACE_MASK;
    if (!resolve_target_credentials(
            identity, &target_uid, &target_gid, &ipc_gid)) {
        report_errno("resolve dedicated daemon credentials");
        return 1;
    }
    if (!runtime_directory_valid()) {
        report_errno("validate /var/run/netlab");
        return 1;
    }
    if (!executable_path(
            identity, target_path, sizeof(target_path),
            &target_fd, &target_st)) {
        report_errno("resolve same-release daemon executable");
        return 1;
    }
    if (!create_listener(
            identity->socket_path, ipc_gid, &listener_fd)) {
        report_errno("create daemon listener");
        close(target_fd);
        return 1;
    }
    if (!create_ready_file(identity->socket_path, &ready_fd)) {
        report_errno("create daemon readiness file");
        close(listener_fd);
        close(target_fd);
        return 1;
    }
    if (!fd_at_least(&listener_fd, NETLAB_FIRST_PRIVATE_FD) ||
        !fd_at_least(&ready_fd, NETLAB_FIRST_PRIVATE_FD) ||
        !fd_at_least(&target_fd, NETLAB_FIRST_PRIVATE_FD) ||
        !install_fixed_fd(listener_fd, NETLAB_LISTENER_FD) ||
        !install_fixed_fd(ready_fd, NETLAB_READY_FD) ||
        !listener_fd_valid(
            NETLAB_LISTENER_FD, identity->socket_path, ipc_gid) ||
        !ready_fd_valid(NETLAB_READY_FD) ||
        !mark_private_fds_cloexec()) {
        report_errno("install inherited daemon file descriptors");
        close(listener_fd);
        close(ready_fd);
        close(target_fd);
        return 1;
    }
    if (!start_exec_watchdog(
            listener_fd, ready_fd, target_fd,
            &target_st, &watchdog_fd)) {
        report_errno("start exec cleanup watchdog");
        close(listener_fd);
        close(ready_fd);
        close(target_fd);
        return 1;
    }
    g_cleanup.watchdog_owns_cleanup = true;
    close(listener_fd);
    close(ready_fd);
    if (sigprocmask(
            SIG_SETMASK, &original_signal_mask, NULL) != 0) {
        report_errno("restore daemon signal mask");
        notify_exec_failure(watchdog_fd);
        close(watchdog_fd);
        close(target_fd);
        return 1;
    }

    if (!drop_privileges(
            target_uid, target_gid, ipc_gid, identity_broker)) {
        report_errno("drop daemon privileges");
        notify_exec_failure(watchdog_fd);
        close(watchdog_fd);
        close(target_fd);
        return 1;
    }

    target_argv[0] = target_path;
    target_argv[1] = "--inherited-listener-fd=3";
    target_argv[2] = "--ready-fd=4";
    target_argv[3] = NULL;
    /*
     * The launcher starts as root and identityd crosses exec with one ambient
     * capability.  Never expose that exec boundary to inherited loader,
     * locale, logging, or test override variables.
     */
    fexecve(target_fd, target_argv, target_environment);
    {
        report_errno("exec same-release daemon");
        notify_exec_failure(watchdog_fd);
        close(watchdog_fd);
        close(target_fd);
        return 1;
    }
}
