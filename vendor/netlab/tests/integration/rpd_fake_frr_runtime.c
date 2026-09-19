#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;

static void request_stop(int signal_number) {
    (void)signal_number;
    running = 0;
}

static const char *argument_after(int argc, char **argv,
                                  const char *option) {
    for (int index = 1; index + 1 < argc; index++) {
        if (strcmp(argv[index], option) == 0)
            return argv[index + 1];
    }
    return NULL;
}

static int record_arguments(int argc, char **argv) {
    const char *path = getenv("TEST_FRR_ARG_LOG");
    char line[8192];
    size_t offset = 0;
    int fd;
    ssize_t written;

    if (!path || !path[0]) {
        errno = EINVAL;
        return -1;
    }
    for (int index = 0; index < argc; index++) {
        int length = snprintf(line + offset, sizeof(line) - offset,
                              "%s%s", index == 0 ? "" : " ", argv[index]);

        if (length < 0 || (size_t)length >= sizeof(line) - offset) {
            errno = EOVERFLOW;
            return -1;
        }
        offset += (size_t)length;
    }
    if (offset + 1 >= sizeof(line)) {
        errno = EOVERFLOW;
        return -1;
    }
    line[offset++] = '\n';
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    do {
        written = write(fd, line, offset);
    } while (written < 0 && errno == EINTR);
    if (written != (ssize_t)offset) {
        int saved_errno = written < 0 ? errno : EIO;

        close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static int runtime_socket_path(int argc, char **argv,
                               char *path, size_t path_size) {
    const char *pid_path = argument_after(argc, argv, "-i");
    const char *run_dir = argument_after(argc, argv, "--vty_socket");
    const char *zserv = argument_after(argc, argv, "-z");
    const char *basename;
    const char *daemon = NULL;
    int written;

    if (!pid_path || !run_dir ||
        !(basename = strrchr(pid_path, '/')) || !basename[1]) {
        errno = EINVAL;
        return -1;
    }
    basename++;
    if (strcmp(basename, "zebra.pid") == 0) {
        if (!zserv) {
            errno = EINVAL;
            return -1;
        }
        written = snprintf(path, path_size, "%s", zserv);
    } else {
        if (strcmp(basename, "ospfd.pid") == 0)
            daemon = "ospfd";
        else if (strcmp(basename, "bgpd.pid") == 0)
            daemon = "bgpd";
        if (!daemon) {
            errno = EINVAL;
            return -1;
        }
        written = snprintf(path, path_size, "%s/%s.vty", run_dir, daemon);
    }
    if (written < 0 || (size_t)written >= path_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int drop_runtime_identity(int argc, char **argv) {
    const char *user = argument_after(argc, argv, "-u");
    const char *group = argument_after(argc, argv, "-g");
    struct passwd *password;
    struct group *group_entry;

    if (!user || !group) {
        errno = EINVAL;
        return -1;
    }
    password = getpwnam(user);
    group_entry = getgrnam(group);
    if (!password || !group_entry) {
        errno = EINVAL;
        return -1;
    }
    if (geteuid() != 0) {
        if (password->pw_uid != geteuid() ||
            group_entry->gr_gid != getegid()) {
            errno = EPERM;
            return -1;
        }
        return 0;
    }
    if (initgroups(user, group_entry->gr_gid) != 0 ||
        setgid(group_entry->gr_gid) != 0 ||
        setuid(password->pw_uid) != 0)
        return -1;
    return 0;
}

static int write_pid_file(const char *path) {
    char value[64];
    int length;
    int fd;
    ssize_t written;

    if (!path || !path[0]) {
        errno = EINVAL;
        return -1;
    }
    length = snprintf(value, sizeof(value), "%ld\n", (long)getpid());
    if (length < 0 || (size_t)length >= sizeof(value)) {
        errno = EOVERFLOW;
        return -1;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0)
        return -1;
    do {
        written = write(fd, value, (size_t)length);
    } while (written < 0 && errno == EINTR);
    if (written != length) {
        int saved_errno = written < 0 ? errno : EIO;

        close(fd);
        errno = saved_errno;
        return -1;
    }
    return close(fd);
}

static void unlink_owned_pid_file(const char *path) {
    char value[64];
    char *end = NULL;
    long pid;
    int fd;
    ssize_t length;

    if (!path || !path[0])
        return;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return;
    do {
        length = read(fd, value, sizeof(value) - 1);
    } while (length < 0 && errno == EINTR);
    close(fd);
    if (length <= 0)
        return;
    value[length] = '\0';
    errno = 0;
    pid = strtol(value, &end, 10);
    if (errno == 0 && end && (*end == '\n' || *end == '\0') &&
        pid == (long)getpid())
        (void)unlink(path);
}

static void unlink_owned_socket(const char *path,
                                const struct stat *owned_path_stat) {
    struct stat path_stat;

    if (!path || !path[0] || !owned_path_stat ||
        lstat(path, &path_stat) != 0)
        return;
    if (S_ISSOCK(path_stat.st_mode) &&
        owned_path_stat->st_dev == path_stat.st_dev &&
        owned_path_stat->st_ino == path_stat.st_ino)
        (void)unlink(path);
}

int main(int argc, char **argv) {
    const char *pid_path = argument_after(argc, argv, "-i");
    struct sockaddr_un address;
    struct sigaction action;
    struct stat socket_path_stat;
    char socket_path[sizeof(address.sun_path)] = {0};
    bool pid_file_written = false;
    bool socket_path_owned = false;
    int listener = -1;
    int rc = 1;

    memset(&action, 0, sizeof(action));
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGINT, &action, NULL) != 0 ||
        record_arguments(argc, argv) != 0 ||
        runtime_socket_path(argc, argv, socket_path,
                            sizeof(socket_path)) != 0 ||
        drop_runtime_identity(argc, argv) != 0 ||
        write_pid_file(pid_path) != 0)
        goto out;
    pid_file_written = true;

    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0)
        goto out;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0)
        goto out;
    if (lstat(socket_path, &socket_path_stat) != 0 ||
        !S_ISSOCK(socket_path_stat.st_mode))
        goto out;
    socket_path_owned = true;
    if (listen(listener, 16) != 0)
        goto out;

    while (running) {
        struct pollfd pfd = {
            .fd = listener,
            .events = POLLIN,
        };
        int poll_rc = poll(&pfd, 1, 100);

        if (poll_rc < 0 && errno == EINTR)
            continue;
        if (poll_rc < 0)
            goto out;
        if (poll_rc > 0 && (pfd.revents & POLLIN)) {
            int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);

            if (client >= 0)
                close(client);
            else if (errno != EINTR)
                goto out;
        }
    }
    rc = 0;

out:
    if (listener >= 0) {
        if (socket_path_owned)
            unlink_owned_socket(socket_path, &socket_path_stat);
        close(listener);
    }
    if (pid_file_written)
        unlink_owned_pid_file(pid_path);
    if (rc != 0)
        fprintf(stderr, "fake FRR runtime failed: %s\n", strerror(errno));
    return rc;
}
