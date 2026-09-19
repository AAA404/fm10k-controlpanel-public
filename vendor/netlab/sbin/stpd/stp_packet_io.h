#ifndef STPD_STP_PACKET_IO_H
#define STPD_STP_PACKET_IO_H

#include "netlab/ipc.h"
#include <signal.h>

int stp_packet_read_record(nl_conn *conn, void *buf, int len);
int stp_packet_tx(const char *socket_path, int port,
                  const u8 *frame, int frame_len);
bool stp_packet_subscribe(
    const char *socket_path, u16 synthetic_type, nl_conn *conn);
int stp_packet_wait_readable(int fd, int timeout_sec,
                             volatile sig_atomic_t *running);

#endif
