#include "fpm_test_authority.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool proc_pid_starttime(pid_t pid, u64 *starttime) {
    char path[128];
    char line[4096];
    char *fields;
    char *save = NULL;
    char *token;
    FILE *fp;
    int field = 3;

    if (pid <= 0 || !starttime ||
        snprintf(path, sizeof(path), "/proc/%ld/stat",
                 (long)pid) >= (int)sizeof(path))
        return false;
    fp = fopen(path, "r");
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
            *starttime = (u64)value;
            return true;
        }
        field++;
        token = strtok_r(NULL, " \n", &save);
    }
    return false;
}

static bool proc_pid_effective_uid(pid_t pid, uid_t *uid) {
    char path[128];
    char line[256];
    FILE *fp;

    if (pid <= 0 || !uid ||
        snprintf(path, sizeof(path), "/proc/%ld/status",
                 (long)pid) >= (int)sizeof(path))
        return false;
    fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long real_uid;
        unsigned long effective_uid;

        if (sscanf(line, "Uid:%lu%lu", &real_uid, &effective_uid) == 2) {
            (void)real_uid;
            fclose(fp);
            if ((unsigned long)(uid_t)effective_uid != effective_uid)
                return false;
            *uid = (uid_t)effective_uid;
            return true;
        }
    }
    fclose(fp);
    return false;
}

static bool proc_pid_executable(pid_t pid, char *out, size_t out_size) {
    char path[128];
    ssize_t len;

    if (pid <= 0 || !out || out_size < 2 ||
        snprintf(path, sizeof(path), "/proc/%ld/exe",
                 (long)pid) >= (int)sizeof(path))
        return false;
    len = readlink(path, out, out_size - 1);
    if (len <= 0 || (size_t)len >= out_size - 1)
        return false;
    out[len] = '\0';
    return out[0] == '/';
}

static pid_t test_authority_pid(char *err, size_t err_size) {
    const char *pid_file =
        getenv("NETLAB_TEST_RPD_FPM_AUTHORITY_PID_FILE");
    char text[64];
    char *end = NULL;
    long value;
    FILE *fp;

    if (!pid_file || !pid_file[0])
        return getppid();
    fp = fopen(pid_file, "r");
    if (!fp || !fgets(text, sizeof(text), fp)) {
        if (fp)
            fclose(fp);
        snprintf(err, err_size,
                 "test FPM authority fixture cannot read PID file");
        return -1;
    }
    fclose(fp);
    errno = 0;
    value = strtol(text, &end, 10);
    while (end && (*end == ' ' || *end == '\t' ||
                   *end == '\r' || *end == '\n'))
        end++;
    if (errno != 0 || !end || *end != '\0' ||
        value <= 0 || (long)(pid_t)value != value) {
        snprintf(err, err_size,
                 "test FPM authority fixture PID is invalid");
        return -1;
    }
    return (pid_t)value;
}

int rpd_fpm_test_authority_snapshot(
    rpd_fpm_peer_authority *authority, char *err, size_t err_size) {
    u64 starttime_before = 0;
    u64 starttime_after = 0;
    pid_t pid;

    if (!authority) {
        snprintf(err, err_size,
                 "test FPM authority output is missing");
        return -1;
    }
    memset(authority, 0, sizeof(*authority));
    pid = test_authority_pid(err, err_size);
    if (pid <= 0 ||
        !proc_pid_starttime(pid, &starttime_before) ||
        !proc_pid_effective_uid(pid, &authority->uid) ||
        !proc_pid_executable(pid, authority->executable,
                             sizeof(authority->executable)) ||
        !proc_pid_starttime(pid, &starttime_after) ||
        starttime_before != starttime_after) {
        if (!err[0])
            snprintf(err, err_size,
                     "test FPM authority process identity is unstable");
        return -1;
    }
    authority->pid = pid;
    authority->starttime = starttime_after;
    authority->generation =
        starttime_after ^ ((u64)(unsigned int)pid << 32);
    if (authority->generation == 0)
        authority->generation = 1;
    return 0;
}
