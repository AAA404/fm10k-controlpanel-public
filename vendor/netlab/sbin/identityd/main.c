#include "netlab/daemon.h"
#include "netlab/identity_broker.h"
#include "netlab/ipc.h"
#include <errno.h>
#include <linux/capability.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define IDENTITYD_SOCKET "/var/run/netlab/identityd.sock"
#define IDENTITYD_MAX_HANDLERS 8
#define IDENTITYD_REAP_INTERVAL_MS 1000
#define IDENTITYD_INHERITED_LISTEN_FD 3
#define IDENTITYD_READY_FD 4
#define IDENTITYD_CAPABILITY_BITS 64U

typedef struct {
    nl_identity_broker *broker;
} identityd_ctx;

static bool identityd_seal_exec_capabilities(void) {
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
    const u64 expected = UINT64_C(1) << CAP_SYS_PTRACE;
    u64 permitted;
    u64 effective;
    u64 inheritable;
    u64 bounding = 0;

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL,
              0L, 0L, 0L) != 0)
        return false;
    memset(&header, 0, sizeof(header));
    memset(data, 0, sizeof(data));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    data[0].permitted = (u32)expected;
    data[0].effective = (u32)expected;
    if (syscall(SYS_capset, &header, data) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
        return false;

    memset(data, 0, sizeof(data));
    if (syscall(SYS_capget, &header, data) != 0)
        return false;
    permitted = (u64)data[0].permitted |
        ((u64)data[1].permitted << 32);
    effective = (u64)data[0].effective |
        ((u64)data[1].effective << 32);
    inheritable = (u64)data[0].inheritable |
        ((u64)data[1].inheritable << 32);
    for (unsigned int capability = 0;
         capability < IDENTITYD_CAPABILITY_BITS; capability++) {
        int bounded = prctl(
            PR_CAPBSET_READ, capability, 0L, 0L, 0L);
        int ambient;

        if (bounded < 0) {
            if (errno == EINVAL)
                break;
            return false;
        }
        ambient = prctl(
            PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
            capability, 0L, 0L);
        if (ambient != 0)
            return false;
        if (bounded == 1)
            bounding |= UINT64_C(1) << capability;
    }
    return permitted == expected &&
        effective == expected &&
        inheritable == 0 &&
        bounding == expected &&
        prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L) == 1;
}

static int identityd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    identityd_ctx *identityd = ctx;

    if (!identityd || !identityd->broker)
        return NL_ERR;
    return nl_identity_broker_dispatch(identityd->broker, conn, msg);
}

static void identityd_on_idle(void *ctx, s64 elapsed_ms) {
    identityd_ctx *identityd = ctx;

    (void)elapsed_ms;
    if (identityd)
        nl_identity_broker_reap(identityd->broker);
}

static int identityd_on_init(void *ctx) {
    identityd_ctx *identityd = ctx;

    if (!identityd || identityd->broker)
        return -1;
    identityd->broker = nl_identity_broker_create();
    return identityd->broker ? 0 : -1;
}

static void identityd_on_shutdown(void *ctx) {
    identityd_ctx *identityd = ctx;

    if (!identityd)
        return;
    nl_identity_broker_destroy(identityd->broker);
    identityd->broker = NULL;
}

int main(int argc, char **argv) {
    identityd_ctx identityd = {0};
    nl_daemon_config cfg;

    /*
     * The launcher needs Inheritable/Ambient for exactly one exec.  Erase
     * that handoff before parsing caller-controlled arguments or creating
     * any daemon state.
     */
    if (!identityd_seal_exec_capabilities())
        return 1;
    if (argc != 3 || !argv || !argv[0] || !argv[1] || !argv[2] ||
        argv[3] != NULL ||
        strcmp(argv[1], "--inherited-listener-fd=3") != 0 ||
        strcmp(argv[2], "--ready-fd=4") != 0)
        return 1;
    cfg = (nl_daemon_config){
        .name = "identityd",
        .socket_path = IDENTITYD_SOCKET,
        .service_id = NL_DAEMON_IDENTITYD,
        .auth_mode = NL_DAEMON_AUTH_STANDARD,
        .dispatch = identityd_dispatch,
        .ctx = &identityd,
        .on_init = identityd_on_init,
        .on_shutdown = identityd_on_shutdown,
        .max_concurrent_handlers = IDENTITYD_MAX_HANDLERS,
        .poll_interval_ms = IDENTITYD_REAP_INTERVAL_MS,
        .on_idle = identityd_on_idle,
        .inherited_listen_fd = IDENTITYD_INHERITED_LISTEN_FD,
        .ready_fd = IDENTITYD_READY_FD,
    };
    return nl_daemon_run(&cfg);
}
