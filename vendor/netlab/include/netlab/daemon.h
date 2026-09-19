#ifndef NETLAB_DAEMON_H
#define NETLAB_DAEMON_H

#include "types.h"
#include "ipc.h"

// Dispatch callback: receive a request, return a heap-allocated nl_msg_hdr* response
// (or NULL if response was sent directly via conn).
// Return NL_OK on success, error code on failure.
typedef int (*nl_dispatch_fn)(nl_conn *conn, nl_msg_hdr *msg, void *ctx);

// Idle callback called periodically when no connections are active.
// Return value ignored.
typedef void (*nl_idle_fn)(void *ctx, s64 elapsed_ms);

typedef enum {
    NL_DAEMON_AUTH_INVALID = 0,
    /*
     * Normal daemon endpoint: daemon_id is the caller identity and every
     * request is checked against the service contract before dispatch.
     */
    NL_DAEMON_AUTH_STANDARD,
    /*
     * Management gateway endpoint: daemon_id is the requested backend route.
     * mgmtd performs route, payload, and role authorization in its dispatch.
     */
    NL_DAEMON_AUTH_MANAGEMENT_GATEWAY,
} nl_daemon_auth_mode;

// Daemon configuration
typedef struct {
    const char   *name;           // daemon name (for logging)
    const char   *socket_path;    // unix domain socket path
    nl_daemon_id service_id;      // receiving service's wire identity
    nl_daemon_auth_mode auth_mode;
    nl_dispatch_fn dispatch;      // request handler
    void         *ctx;            // user context passed to callbacks

    // Optional: called before entering the main loop
    int  (*on_init)(void *ctx);

    // Optional: called after the dispatch gate closes, before waiting for
    // accepted workers. Wake active callbacks without destroying shared state.
    void (*on_stopping)(void *ctx);

    // Optional: called after every accepted worker has exited.
    void (*on_shutdown)(void *ctx);

    // Optional: maximum concurrent dispatch callbacks. Authentication and
    // receive work always use a bounded worker pool; values <= 1 keep
    // callbacks and on_idle serialized.
    int max_concurrent_handlers;

    // Optional: idle handler. poll_interval_ms=0 means don't call.
    int  poll_interval_ms;
    nl_idle_fn on_idle;

    /*
     * Dedicated-identity daemons receive a root-created listener and a
     * root-owned readiness record from netlab-daemon-launch.  Values below
     * three mean that no descriptor was supplied.  The daemon validates both
     * descriptors against its registry identity before on_init runs.
     */
    int inherited_listen_fd;
    int ready_fd;

    /*
     * One explicitly configured cross-UID edge may delegate stable peer
     * identity checks to identityd.  A configured broker is authoritative:
     * the daemon never falls back to local /proc inspection.
     */
    const char *identity_broker_socket_path;
    nl_daemon_id brokered_peer_id;
} nl_daemon_config;

// Run the daemon event loop. Blocks until signal (SIGINT/SIGTERM).
// Returns 0 on clean exit, non-zero on error.
int nl_daemon_run(nl_daemon_config *cfg);

#endif
