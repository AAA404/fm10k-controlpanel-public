#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "netlab/process_identity.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int proc_open_file(const nl_process_identity_handle *handle,
                          const char *name, int flags) {
    char path[128];

    if (!handle || handle->fd < 0 || !name || !name[0])
        return -1;
    if (handle->kind == NL_PROCESS_HANDLE_PROCFD)
        return openat(handle->fd, name, flags | O_CLOEXEC);
    if (handle->kind != NL_PROCESS_HANDLE_PIDFD ||
        snprintf(path, sizeof(path), "/proc/%ld/%s",
                 (long)handle->baseline.pid, name) >= (int)sizeof(path))
        return -1;
    return open(path, flags | O_CLOEXEC);
}

static bool proc_read_starttime(const nl_process_identity_handle *handle,
                                u64 *starttime) {
    char line[4096];
    char *fields;
    char *save = NULL;
    char *token;
    FILE *stream;
    int fd;
    int field = 3;
    bool live_state = false;

    if (!handle || !starttime)
        return false;
    fd = proc_open_file(handle, "stat", O_RDONLY);
    if (fd < 0)
        return false;
    stream = fdopen(fd, "r");
    if (!stream) {
        close(fd);
        return false;
    }
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
        if (field == 3) {
            if (token[0] == '\0' || token[1] != '\0' ||
                token[0] == 'Z' || token[0] == 'X' || token[0] == 'x')
                return false;
            live_state = true;
        }
        if (field == 22) {
            char *end = NULL;
            unsigned long long value;

            errno = 0;
            value = strtoull(token, &end, 10);
            if (!live_state || errno != 0 || !end || *end != '\0' ||
                value == 0)
                return false;
            *starttime = (u64)value;
            return true;
        }
        field++;
        token = strtok_r(NULL, " \n", &save);
    }
    return false;
}

static bool proc_read_effective_ids(
    const nl_process_identity_handle *handle, uid_t *euid, gid_t *egid) {
    char line[512];
    FILE *stream;
    int fd;
    bool have_uid = false;
    bool have_gid = false;

    if (!handle || !euid || !egid)
        return false;
    fd = proc_open_file(handle, "status", O_RDONLY);
    if (fd < 0)
        return false;
    stream = fdopen(fd, "r");
    if (!stream) {
        close(fd);
        return false;
    }
    while (fgets(line, sizeof(line), stream)) {
        unsigned long real_id;
        unsigned long effective_id;

        if (!have_uid &&
            sscanf(line, "Uid:%lu%lu", &real_id, &effective_id) == 2) {
            (void)real_id;
            if ((unsigned long)(uid_t)effective_id != effective_id) {
                fclose(stream);
                return false;
            }
            *euid = (uid_t)effective_id;
            have_uid = true;
        } else if (!have_gid &&
                   sscanf(line, "Gid:%lu%lu",
                          &real_id, &effective_id) == 2) {
            (void)real_id;
            if ((unsigned long)(gid_t)effective_id != effective_id) {
                fclose(stream);
                return false;
            }
            *egid = (gid_t)effective_id;
            have_gid = true;
        }
        if (have_uid && have_gid) {
            fclose(stream);
            return true;
        }
    }
    fclose(stream);
    return false;
}

static bool has_deleted_suffix(const char *path) {
    static const char suffix[] = " (deleted)";
    size_t path_len;

    if (!path)
        return false;
    path_len = strlen(path);
    return path_len >= sizeof(suffix) - 1U &&
        strcmp(path + path_len - (sizeof(suffix) - 1U), suffix) == 0;
}

static bool proc_read_executable(
    const nl_process_identity_handle *handle, char *path, size_t path_size,
    dev_t *device, ino_t *inode) {
    char proc_path[128];
    struct stat st;
    ssize_t path_len;
    int stat_result;

    if (!handle || !path || path_size < 2 || !device || !inode)
        return false;
    path[0] = '\0';
    if (handle->kind == NL_PROCESS_HANDLE_PROCFD) {
        path_len = readlinkat(handle->fd, "exe", path, path_size - 1U);
        stat_result = fstatat(handle->fd, "exe", &st, 0);
    } else if (handle->kind == NL_PROCESS_HANDLE_PIDFD &&
               snprintf(proc_path, sizeof(proc_path), "/proc/%ld/exe",
                        (long)handle->baseline.pid) < (int)sizeof(proc_path)) {
        path_len = readlink(proc_path, path, path_size - 1U);
        stat_result = stat(proc_path, &st);
    } else {
        return false;
    }
    if (path_len <= 0 || (size_t)path_len >= path_size - 1U ||
        stat_result != 0)
        return false;
    path[path_len] = '\0';
    if (path[0] != '/' || has_deleted_suffix(path) || !S_ISREG(st.st_mode))
        return false;
    *device = st.st_dev;
    *inode = st.st_ino;
    return true;
}

static bool process_handle_alive(
    const nl_process_identity_handle *handle) {
    struct pollfd pfd;
    u64 ignored_starttime;
    int rc;

    if (!handle || handle->fd < 0)
        return false;
    if (handle->kind == NL_PROCESS_HANDLE_PROCFD)
        return proc_read_starttime(handle, &ignored_starttime);
    if (handle->kind != NL_PROCESS_HANDLE_PIDFD)
        return false;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = handle->fd;
    do {
        rc = poll(&pfd, 1, 0);
    } while (rc < 0 && errno == EINTR);
    return rc == 0;
}

static bool observations_equal(
    const nl_process_identity_observation *left,
    const nl_process_identity_observation *right) {
    return left && right &&
        left->pid == right->pid &&
        left->euid == right->euid &&
        left->egid == right->egid &&
        left->starttime == right->starttime &&
        left->executable_dev == right->executable_dev &&
        left->executable_ino == right->executable_ino &&
        strcmp(left->executable, right->executable) == 0;
}

static bool observe_once(const nl_process_identity_handle *handle,
                         nl_process_identity_observation *observation) {
    if (!handle || !observation)
        return false;
    memset(observation, 0, sizeof(*observation));
    observation->pid = handle->baseline.pid;
    return proc_read_starttime(handle, &observation->starttime) &&
        proc_read_effective_ids(handle, &observation->euid,
                                &observation->egid) &&
        proc_read_executable(handle, observation->executable,
                             sizeof(observation->executable),
                             &observation->executable_dev,
                             &observation->executable_ino);
}

static nl_process_identity_result observe_stable(
    const nl_process_identity_handle *handle,
    nl_process_identity_observation *observation) {
    nl_process_identity_observation before;
    nl_process_identity_observation after;

    if (!handle || handle->fd < 0 || !observation)
        return NL_PROCESS_IDENTITY_INVALID_ARGUMENT;
    if (!process_handle_alive(handle))
        return NL_PROCESS_IDENTITY_NOT_ALIVE;
    if (!observe_once(handle, &before)) {
        return process_handle_alive(handle) ?
            NL_PROCESS_IDENTITY_OBSERVATION_UNAVAILABLE :
            NL_PROCESS_IDENTITY_NOT_ALIVE;
    }
    if (!observe_once(handle, &after)) {
        return process_handle_alive(handle) ?
            NL_PROCESS_IDENTITY_OBSERVATION_UNAVAILABLE :
            NL_PROCESS_IDENTITY_NOT_ALIVE;
    }
    if (!process_handle_alive(handle))
        return NL_PROCESS_IDENTITY_NOT_ALIVE;
    if (!observations_equal(&before, &after))
        return NL_PROCESS_IDENTITY_UNSTABLE;
    *observation = after;
    return NL_PROCESS_IDENTITY_OK;
}

static bool set_cloexec(int fd) {
    int flags;

    if (fd < 0)
        return false;
    flags = fcntl(fd, F_GETFD);
    return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static nl_process_identity_result process_handle_open(
    pid_t pid, nl_process_identity_handle *handle) {
    char path[128];
    int fd = -1;

    if (pid <= 0 || !handle)
        return NL_PROCESS_IDENTITY_INVALID_ARGUMENT;
#ifdef NETLAB_PROCESS_IDENTITY_FORCE_PIDFD_ENOSYS
    errno = ENOSYS;
#else
#ifdef SYS_pidfd_open
    fd = (int)syscall(SYS_pidfd_open, pid, 0);
#elif defined(__x86_64__) || defined(__aarch64__)
    fd = (int)syscall(434, pid, 0);
#else
    errno = ENOSYS;
#endif
#endif
    if (fd >= 0) {
        if (!set_cloexec(fd)) {
            close(fd);
            return NL_PROCESS_IDENTITY_HANDLE_OPEN_FAILED;
        }
        handle->fd = fd;
        handle->kind = NL_PROCESS_HANDLE_PIDFD;
        handle->baseline.pid = pid;
        return NL_PROCESS_IDENTITY_OK;
    }
    if (errno != ENOSYS)
        return NL_PROCESS_IDENTITY_HANDLE_OPEN_FAILED;
    if (snprintf(path, sizeof(path), "/proc/%ld", (long)pid) >=
        (int)sizeof(path))
        return NL_PROCESS_IDENTITY_HANDLE_OPEN_FAILED;
    fd = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return NL_PROCESS_IDENTITY_HANDLE_OPEN_FAILED;
    if (!set_cloexec(fd)) {
        close(fd);
        return NL_PROCESS_IDENTITY_HANDLE_OPEN_FAILED;
    }
    handle->fd = fd;
    handle->kind = NL_PROCESS_HANDLE_PROCFD;
    handle->baseline.pid = pid;
    return NL_PROCESS_IDENTITY_OK;
}

void nl_process_identity_init(nl_process_identity_handle *handle) {
    if (!handle)
        return;
    memset(handle, 0, sizeof(*handle));
    handle->fd = -1;
    handle->kind = NL_PROCESS_HANDLE_NONE;
}

bool nl_process_identity_move(nl_process_identity_handle *destination,
                              nl_process_identity_handle *source) {
    if (!destination || !source || destination == source ||
        destination->fd != -1 ||
        destination->kind != NL_PROCESS_HANDLE_NONE || source->fd < 0 ||
        (source->kind != NL_PROCESS_HANDLE_PIDFD &&
         source->kind != NL_PROCESS_HANDLE_PROCFD))
        return false;
    *destination = *source;
    nl_process_identity_init(source);
    return true;
}

nl_process_identity_result nl_process_identity_open(
    pid_t pid, nl_process_identity_handle *handle) {
    nl_process_identity_handle opened =
        NL_PROCESS_IDENTITY_HANDLE_INITIALIZER;
    nl_process_identity_observation observation;
    nl_process_identity_result result;

    if (pid <= 0 || !handle || handle->fd != -1 ||
        handle->kind != NL_PROCESS_HANDLE_NONE)
        return NL_PROCESS_IDENTITY_INVALID_ARGUMENT;
    result = process_handle_open(pid, &opened);
    if (result != NL_PROCESS_IDENTITY_OK)
        return result;
    result = observe_stable(&opened, &observation);
    if (result != NL_PROCESS_IDENTITY_OK) {
        nl_process_identity_close(&opened);
        return result;
    }
    opened.baseline = observation;
    *handle = opened;
    return NL_PROCESS_IDENTITY_OK;
}

nl_process_identity_result nl_process_identity_revalidate(
    const nl_process_identity_handle *handle,
    nl_process_identity_observation *observation) {
    nl_process_identity_observation current;
    nl_process_identity_result result;

    if (!handle || handle->fd < 0 ||
        handle->kind == NL_PROCESS_HANDLE_NONE)
        return NL_PROCESS_IDENTITY_INVALID_ARGUMENT;
    result = observe_stable(handle, &current);
    if (result != NL_PROCESS_IDENTITY_OK)
        return result;
    if (!observations_equal(&handle->baseline, &current))
        return NL_PROCESS_IDENTITY_CHANGED;
    if (observation)
        *observation = current;
    return NL_PROCESS_IDENTITY_OK;
}

nl_process_identity_result nl_process_identity_verify(
    const nl_process_identity_handle *handle,
    const nl_process_identity_expectation *expectation,
    nl_process_identity_observation *observation) {
    nl_process_identity_observation current;
    struct stat executable_before;
    struct stat executable_after;
    nl_process_identity_result result;
    bool check_executable;

    if (!handle || !expectation)
        return NL_PROCESS_IDENTITY_INVALID_ARGUMENT;
    check_executable = expectation->executable != NULL;
    if (check_executable &&
        (expectation->executable[0] != '/' ||
         has_deleted_suffix(expectation->executable)))
        return NL_PROCESS_IDENTITY_INVALID_ARGUMENT;
    if (check_executable &&
        (stat(expectation->executable, &executable_before) != 0 ||
         !S_ISREG(executable_before.st_mode)))
        return NL_PROCESS_IDENTITY_EXECUTABLE_UNAVAILABLE;
    result = nl_process_identity_revalidate(handle, &current);
    if (result != NL_PROCESS_IDENTITY_OK)
        return result;
    if (expectation->check_euid && current.euid != expectation->euid)
        return NL_PROCESS_IDENTITY_EUID_MISMATCH;
    if (expectation->check_egid && current.egid != expectation->egid)
        return NL_PROCESS_IDENTITY_EGID_MISMATCH;
    if (check_executable &&
        strcmp(current.executable, expectation->executable) != 0)
        return NL_PROCESS_IDENTITY_EXECUTABLE_PATH_MISMATCH;
    if (check_executable &&
        (stat(expectation->executable, &executable_after) != 0 ||
         !S_ISREG(executable_after.st_mode)))
        return NL_PROCESS_IDENTITY_EXECUTABLE_UNAVAILABLE;
    if (check_executable &&
        (executable_before.st_dev != executable_after.st_dev ||
         executable_before.st_ino != executable_after.st_ino))
        return NL_PROCESS_IDENTITY_EXECUTABLE_UNAVAILABLE;
    if (check_executable &&
        (current.executable_dev != executable_after.st_dev ||
         current.executable_ino != executable_after.st_ino))
        return NL_PROCESS_IDENTITY_EXECUTABLE_INODE_MISMATCH;
    if (observation)
        *observation = current;
    return NL_PROCESS_IDENTITY_OK;
}

void nl_process_identity_close(nl_process_identity_handle *handle) {
    if (!handle)
        return;
    if (handle->fd >= 0)
        close(handle->fd);
    nl_process_identity_init(handle);
}

const char *nl_process_handle_kind_name(nl_process_handle_kind kind) {
    switch (kind) {
    case NL_PROCESS_HANDLE_NONE:
        return "none";
    case NL_PROCESS_HANDLE_PIDFD:
        return "pidfd";
    case NL_PROCESS_HANDLE_PROCFD:
        return "procfd";
    }
    return "unknown";
}

const char *nl_process_identity_result_name(
    nl_process_identity_result result) {
    switch (result) {
    case NL_PROCESS_IDENTITY_OK:
        return "ok";
    case NL_PROCESS_IDENTITY_INVALID_ARGUMENT:
        return "invalid-argument";
    case NL_PROCESS_IDENTITY_HANDLE_OPEN_FAILED:
        return "handle-open-failed";
    case NL_PROCESS_IDENTITY_NOT_ALIVE:
        return "not-alive";
    case NL_PROCESS_IDENTITY_OBSERVATION_UNAVAILABLE:
        return "observation-unavailable";
    case NL_PROCESS_IDENTITY_UNSTABLE:
        return "unstable";
    case NL_PROCESS_IDENTITY_CHANGED:
        return "changed";
    case NL_PROCESS_IDENTITY_EUID_MISMATCH:
        return "euid-mismatch";
    case NL_PROCESS_IDENTITY_EGID_MISMATCH:
        return "egid-mismatch";
    case NL_PROCESS_IDENTITY_EXECUTABLE_PATH_MISMATCH:
        return "executable-path-mismatch";
    case NL_PROCESS_IDENTITY_EXECUTABLE_UNAVAILABLE:
        return "executable-unavailable";
    case NL_PROCESS_IDENTITY_EXECUTABLE_INODE_MISMATCH:
        return "executable-inode-mismatch";
    }
    return "unknown";
}
