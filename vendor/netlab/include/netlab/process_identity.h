#ifndef NETLAB_PROCESS_IDENTITY_H
#define NETLAB_PROCESS_IDENTITY_H

#include "types.h"
#include <stdbool.h>
#include <sys/types.h>

#define NL_PROCESS_EXECUTABLE_PATH_MAX 4096

typedef enum {
    NL_PROCESS_HANDLE_NONE = 0,
    NL_PROCESS_HANDLE_PIDFD,
    NL_PROCESS_HANDLE_PROCFD,
} nl_process_handle_kind;

typedef struct {
    pid_t pid;
    uid_t euid;
    gid_t egid;
    u64 starttime;
    dev_t executable_dev;
    ino_t executable_ino;
    char executable[NL_PROCESS_EXECUTABLE_PATH_MAX];
} nl_process_identity_observation;

/*
 * This value owns fd.  Move it into a dispatch job only with
 * nl_process_identity_move(), which clears the source owner.  Always close
 * the final owner with nl_process_identity_close().
 */
typedef struct {
    int fd;
    nl_process_handle_kind kind;
    nl_process_identity_observation baseline;
} nl_process_identity_handle;

#define NL_PROCESS_IDENTITY_HANDLE_INITIALIZER \
    { .fd = -1, .kind = NL_PROCESS_HANDLE_NONE }

typedef struct {
    bool check_euid;
    uid_t euid;
    bool check_egid;
    gid_t egid;
    const char *executable;
} nl_process_identity_expectation;

typedef enum {
    NL_PROCESS_IDENTITY_OK = 0,
    NL_PROCESS_IDENTITY_INVALID_ARGUMENT,
    NL_PROCESS_IDENTITY_HANDLE_OPEN_FAILED,
    NL_PROCESS_IDENTITY_NOT_ALIVE,
    NL_PROCESS_IDENTITY_OBSERVATION_UNAVAILABLE,
    NL_PROCESS_IDENTITY_UNSTABLE,
    NL_PROCESS_IDENTITY_CHANGED,
    NL_PROCESS_IDENTITY_EUID_MISMATCH,
    NL_PROCESS_IDENTITY_EGID_MISMATCH,
    NL_PROCESS_IDENTITY_EXECUTABLE_PATH_MISMATCH,
    NL_PROCESS_IDENTITY_EXECUTABLE_UNAVAILABLE,
    NL_PROCESS_IDENTITY_EXECUTABLE_INODE_MISMATCH,
} nl_process_identity_result;

/* Initialize a handle before open or before receiving a move. */
void nl_process_identity_init(nl_process_identity_handle *handle);
bool nl_process_identity_move(nl_process_identity_handle *destination,
                              nl_process_identity_handle *source);
nl_process_identity_result nl_process_identity_open(
    pid_t pid, nl_process_identity_handle *handle);
nl_process_identity_result nl_process_identity_revalidate(
    const nl_process_identity_handle *handle,
    nl_process_identity_observation *observation);
nl_process_identity_result nl_process_identity_verify(
    const nl_process_identity_handle *handle,
    const nl_process_identity_expectation *expectation,
    nl_process_identity_observation *observation);
void nl_process_identity_close(nl_process_identity_handle *handle);
const char *nl_process_handle_kind_name(nl_process_handle_kind kind);
const char *nl_process_identity_result_name(
    nl_process_identity_result result);

#endif
