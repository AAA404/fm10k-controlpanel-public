/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "mgmtd.h"
#include "netlab/ipc.h"
#include <stdlib.h>
#include <string.h>
#include <pwd.h>

static const mgmtd_backend_info g_backends[] = {
    {NL_DAEMON_MGMTD,    "mgmtd",    MGMTD_SOCKET,
     "management gateway", false},
    {NL_DAEMON_CONFIGD,  "configd",  "/var/run/netlab/configd.sock",
     "configuration", false},
    {NL_DAEMON_IFD,      "ifd",      "/var/run/netlab/ifd.sock",
     "interface state", false},
    {NL_DAEMON_CHASSISD, "chassisd", "/var/run/netlab/chassisd.sock",
     "chassis state", false},
    {NL_DAEMON_XCVRD,    "xcvrd",    "/var/run/netlab/switchd.sock",
     "transceiver state via switchd", true},
    {NL_DAEMON_SWITCHD,  "switchd",  "/var/run/netlab/switchd.sock",
     "hardware state", false},
    {NL_DAEMON_PACKETD,  "packetd",  "/var/run/netlab/packetd.sock",
     "packet service", false},
    {NL_DAEMON_LLDPD,    "lldpd",    "/var/run/netlab/lldpd.sock",
     "lldp state", false},
    {NL_DAEMON_LACPD,    "lacpd",    "/var/run/netlab/lacpd.sock",
     "lacp state", false},
    {NL_DAEMON_LINKMOND, "linkmond", "/var/run/netlab/linkmond.sock",
     "link monitor", false},
    {NL_DAEMON_L2D,      "l2d",      "/var/run/netlab/l2d.sock",
     "l2 state", false},
    {NL_DAEMON_RPD,      "rpd",      "/var/run/netlab/rpd.sock",
     "routing control plane", false},
    {NL_DAEMON_STATSD,   "statsd",   "/var/run/netlab/statsd.sock",
     "counter state", false},
    {NL_DAEMON_STPD,     "stpd",     "/var/run/netlab/stpd.sock",
     "spanning-tree state", false},
};

static const char *socket_path_for_daemon(u16 daemon_id,
                                          const char *fallback) {
    switch (daemon_id) {
    case NL_DAEMON_MGMTD:
        return nl_ipc_socket_path_from_env("NETLAB_MGMTD_SOCKET", fallback);
    case NL_DAEMON_CONFIGD:
        return nl_ipc_socket_path_from_env("NETLAB_CONFIGD_SOCKET", fallback);
    case NL_DAEMON_IFD:
        return nl_ipc_socket_path_from_env("NETLAB_IFD_SOCKET", fallback);
    case NL_DAEMON_CHASSISD:
        return nl_ipc_socket_path_from_env("NETLAB_CHASSISD_SOCKET",
                                           fallback);
    case NL_DAEMON_SWITCHD:
    case NL_DAEMON_XCVRD:
        return nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET", fallback);
    case NL_DAEMON_PACKETD:
        return nl_ipc_socket_path_from_env("NETLAB_PACKETD_SOCKET", fallback);
    case NL_DAEMON_LLDPD:
        return nl_ipc_socket_path_from_env("NETLAB_LLDPD_SOCKET", fallback);
    case NL_DAEMON_LACPD:
        return nl_ipc_socket_path_from_env("NETLAB_LACPD_SOCKET", fallback);
    case NL_DAEMON_LINKMOND:
        return nl_ipc_socket_path_from_env("NETLAB_LINKMOND_SOCKET", fallback);
    case NL_DAEMON_L2D:
        return nl_ipc_socket_path_from_env("NETLAB_L2D_SOCKET", fallback);
    case NL_DAEMON_RPD:
        return nl_ipc_socket_path_from_env("NETLAB_RPD_SOCKET", fallback);
    case NL_DAEMON_STATSD:
        return nl_ipc_socket_path_from_env("NETLAB_STATSD_SOCKET", fallback);
    case NL_DAEMON_STPD:
        return nl_ipc_socket_path_from_env("NETLAB_STPD_SOCKET", fallback);
    default:
        return fallback;
    }
}

const char *mgmtd_backend_socket_path(const mgmtd_backend_info *backend) {
    if (!backend)
        return NULL;
    return socket_path_for_daemon(backend->daemon_id, backend->socket_path);
}

const char *mgmtd_access_name(mgmtd_access access) {
    switch (access) {
    case MGMTD_ACCESS_VIEW:   return "view";
    case MGMTD_ACCESS_CONFIG: return "config";
    case MGMTD_ACCESS_COMMIT: return "commit";
    case MGMTD_ACCESS_CLEAR:  return "clear";
    case MGMTD_ACCESS_ADMIN:  return "admin";
    }
    return "unknown";
}

static const mgmtd_backend_info *backend_for_daemon(u16 daemon_id) {
    for (size_t i = 0; i < mgmtd_backend_count(); i++) {
        const mgmtd_backend_info *backend = mgmtd_backend_at(i);

        if (backend && backend->daemon_id == daemon_id)
            return backend;
    }
    return NULL;
}

static bool access_from_contract(nl_rpc_access access, mgmtd_access *out) {
    if (!out)
        return false;
    switch (access) {
    case NL_RPC_ACCESS_VIEW:   *out = MGMTD_ACCESS_VIEW; return true;
    case NL_RPC_ACCESS_CONFIG: *out = MGMTD_ACCESS_CONFIG; return true;
    case NL_RPC_ACCESS_COMMIT: *out = MGMTD_ACCESS_COMMIT; return true;
    case NL_RPC_ACCESS_CLEAR:  *out = MGMTD_ACCESS_CLEAR; return true;
    case NL_RPC_ACCESS_ADMIN:  *out = MGMTD_ACCESS_ADMIN; return true;
    case NL_RPC_ACCESS_INTERNAL:
        return false;
    }
    return false;
}

mgmtd_route mgmtd_lookup_route(u16 daemon_id, u16 method) {
    mgmtd_route route = {
        .daemon_id = daemon_id,
        .method = method,
        .adapter = MGMTD_BACKEND_NL_RPC,
    };
    const mgmtd_backend_info *backend = backend_for_daemon(daemon_id);
    nl_daemon_id contract_service = (nl_daemon_id)daemon_id;

    if (!backend)
        return route;
    if (daemon_id == NL_DAEMON_XCVRD) {
        if (method != NL_SWITCHD_XCVR_INFO_GET)
            return route;
        contract_service = NL_DAEMON_SWITCHD;
    }
    route.contract = nl_rpc_contract_lookup(contract_service, method);
    if (!route.contract ||
        !(route.contract->flags & NL_RPC_CONTRACT_MGMT_EXPOSED) ||
        !access_from_contract(route.contract->access, &route.access))
        return route;
    if (daemon_id != NL_DAEMON_MGMTD &&
        !nl_rpc_contract_caller_allowed(route.contract, NL_DAEMON_MGMTD))
        return route;

    route.daemon_name = backend->daemon_name;
    route.socket_path = socket_path_for_daemon(daemon_id,
                                               backend->socket_path);
    route.description = route.contract->name;
    if (daemon_id == NL_DAEMON_PACKETD) {
        if (method == NL_PACKETD_SHOW_STATISTICS)
            route.adapter = MGMTD_BACKEND_PACKETD_STATS;
        else if (method == NL_PACKETD_RELOAD)
            route.adapter = MGMTD_BACKEND_PACKETD_RELOAD;
        else
            return (mgmtd_route){.daemon_id = daemon_id, .method = method};
    }
    route.ok = true;
    return route;
}

bool mgmtd_access_allowed(const nl_conn *conn, mgmtd_access access) {
    const char *allow_unprivileged;

    if (access == MGMTD_ACCESS_VIEW)
        return true;
    if (conn && conn->peer_uid == 0)
        return true;

    allow_unprivileged =
        getenv("NETLAB_LAB_ONLY_MGMTD_ALLOW_UNPRIVILEGED_WRITE");
    return allow_unprivileged && strcmp(allow_unprivileged, "1") == 0;
}

bool mgmtd_panel_request_allowed(const nl_conn *conn, const mgmtd_route *route) {
    struct passwd value, *user = NULL;
    char buffer[4096];
    if (!conn || !route || getpwnam_r("fm10k-web", &value, buffer, sizeof(buffer), &user) ||
        !user || user->pw_uid == 0 || user->pw_uid != conn->peer_uid) return false;
    if (route->daemon_id == NL_DAEMON_CONFIGD)
        return route->method >= NL_CONFIGD_PANEL_VALIDATE &&
               route->method <= NL_CONFIGD_PANEL_RECOVER;
    if (route->daemon_id == NL_DAEMON_SWITCHD)
        return route->method == NL_SWITCHD_DYNAMIC_MAC_CLEAR ||
               route->method == NL_SWITCHD_FM10K_FAN_MANUAL ||
               route->method == NL_SWITCHD_FM10K_EYE_CONTROL;
    return false;
}

size_t mgmtd_backend_count(void) {
    return sizeof(g_backends) / sizeof(g_backends[0]);
}

const mgmtd_backend_info *mgmtd_backend_at(size_t index) {
    if (index >= mgmtd_backend_count())
        return NULL;
    return &g_backends[index];
}
