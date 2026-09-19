#ifndef NETLAB_L2D_PATHS_H
#define NETLAB_L2D_PATHS_H

#include "netlab/ipc.h"

#define L2D_SOCKET_DEFAULT     "/var/run/netlab/l2d.sock"
#define SWITCHD_SOCKET_DEFAULT "/var/run/netlab/switchd.sock"
#define PACKETD_SOCKET_DEFAULT  "/var/run/netlab/packetd.sock"

static inline const char *l2d_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_L2D_SOCKET",
                                       L2D_SOCKET_DEFAULT);
}

static inline const char *l2d_switchd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET",
                                       SWITCHD_SOCKET_DEFAULT);
}

static inline const char *l2d_packetd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_PACKETD_SOCKET",
                                       PACKETD_SOCKET_DEFAULT);
}

#endif
