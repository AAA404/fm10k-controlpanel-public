#ifndef NETLAB_STPD_STP_SHOW_H
#define NETLAB_STPD_STP_SHOW_H

#include "netlab/ipc.h"

void stp_show_send_monitor(nl_conn *conn, nl_msg_hdr *msg);
void stp_show_send_state(nl_conn *conn, nl_msg_hdr *msg);

#endif
