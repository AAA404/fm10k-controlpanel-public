#ifndef L2D_CACHE_H
#define L2D_CACHE_H

#include "netlab/ipc.h"

void l2d_refresh_cache(void);
int l2d_clear_secure_access(nl_conn *conn, nl_msg_hdr *msg);
int l2d_clear_mac_move(nl_conn *conn, nl_msg_hdr *msg);

#endif
