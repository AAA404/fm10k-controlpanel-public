#ifndef NETLAB_IDENTITY_BROKER_H
#define NETLAB_IDENTITY_BROKER_H

#include "error.h"
#include "ipc.h"
#include <sys/types.h>

#define NL_IDENTITY_BROKER_PROTOCOL_VERSION 1U
#define NL_IDENTITY_TOKEN_SIZE 32U
#define NL_IDENTITY_BROKER_TTL_MS 15000U
#define NL_IDENTITY_BROKER_MAX_LEASES 128U
#define NL_IDENTITY_BROKER_MAX_PER_REQUESTER 32U
#define NL_IDENTITY_BROKER_DEFAULT_TIMEOUT_MS 2000

enum nl_identityd_method {
    NL_IDENTITYD_CAPTURE = 1,
    NL_IDENTITYD_VERIFY = 2,
    NL_IDENTITYD_RELEASE = 3,
};

typedef enum {
    NL_IDENTITY_VERIFY_PREQUEUE = 1,
    NL_IDENTITY_VERIFY_PREDISPATCH = 2,
} nl_identity_verify_phase;

typedef struct __attribute__((packed)) {
    u32 version;
    u32 target_pid;
    u32 target_uid;
    u32 target_gid;
} nl_identity_capture_request;

typedef struct __attribute__((packed)) {
    u32 version;
    u32 reserved;
    u64 expires_at_monotonic_ms;
    u8 token[NL_IDENTITY_TOKEN_SIZE];
} nl_identity_capture_response;

typedef struct __attribute__((packed)) {
    u32 version;
    u32 phase;
    u8 token[NL_IDENTITY_TOKEN_SIZE];
} nl_identity_verify_request;

typedef struct __attribute__((packed)) {
    u32 version;
    u32 phase;
} nl_identity_verify_response;

typedef struct __attribute__((packed)) {
    u32 version;
    u32 reserved;
    u8 token[NL_IDENTITY_TOKEN_SIZE];
} nl_identity_release_request;

typedef struct __attribute__((packed)) {
    u32 version;
    u32 reserved;
} nl_identity_release_response;

typedef struct {
    u8 token[NL_IDENTITY_TOKEN_SIZE];
    u64 expires_at_monotonic_ms;
    bool active;
} nl_identity_lease;

#define NL_IDENTITY_LEASE_INITIALIZER { .active = false }

/*
 * Client API.  Every authority, expiry, capacity, transport, or executable
 * identity failure is reported as NL_ERR_PERMISSION_DENIED.
 */
s32 nl_identity_broker_capture(const char *socket_path,
                               nl_daemon_id requester_service,
                               pid_t target_pid, uid_t target_uid,
                               gid_t target_gid,
                               nl_identity_lease *lease);
s32 nl_identity_broker_verify(const char *socket_path,
                              nl_daemon_id requester_service,
                              nl_identity_lease *lease,
                              nl_identity_verify_phase phase);
s32 nl_identity_broker_release(const char *socket_path,
                               nl_daemon_id requester_service,
                               nl_identity_lease *lease);

typedef struct nl_identity_broker nl_identity_broker;

nl_identity_broker *nl_identity_broker_create(void);
void nl_identity_broker_destroy(nl_identity_broker *broker);
int nl_identity_broker_dispatch(nl_identity_broker *broker, nl_conn *conn,
                                nl_msg_hdr *msg);
void nl_identity_broker_reap(nl_identity_broker *broker);

#endif
