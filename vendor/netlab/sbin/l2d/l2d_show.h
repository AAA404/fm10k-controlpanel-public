#ifndef L2D_SHOW_H
#define L2D_SHOW_H

#include "netlab/ipc.h"

int l2d_show_vlans(nl_conn *conn, nl_msg_hdr *msg);
int l2d_show_ethernet_switching(nl_conn *conn, nl_msg_hdr *msg);
int l2d_show_mac_security(nl_conn *conn, nl_msg_hdr *msg);
int l2d_show_port_mirroring(nl_conn *conn, nl_msg_hdr *msg);

#endif
