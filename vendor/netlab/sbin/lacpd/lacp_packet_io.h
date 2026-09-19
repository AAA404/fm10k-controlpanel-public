/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef LACPD_LACP_PACKET_IO_H
#define LACPD_LACP_PACKET_IO_H

#include "netlab/types.h"
#include <signal.h>

int lacp_packet_tx(const char *socket_path, int port,
                   const u8 *frame, int frame_len);
int lacp_packet_read_event(const char *socket_path, u16 ethertype,
                           int idle_sec,
                           volatile sig_atomic_t *running,
                           u8 *frame, int frame_max, int *src_port, u64 *captured_at);
void lacp_packet_close_subscription(void);

#endif
