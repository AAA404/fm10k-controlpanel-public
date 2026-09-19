/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_IGMP_SNOOPING_H
#define NETLAB_IGMP_SNOOPING_H

#include "netlab/ipc.h"

int igmp_snooping_init(void);
void igmp_snooping_stop(void);
void igmp_snooping_shutdown(void);
void igmp_snooping_tick(void);
bool igmp_snooping_reload(void);
int igmp_snooping_show(nl_conn *conn, nl_msg_hdr *msg);
bool igmp_snooping_dynamic_hardware_key_present(int vid, int port,
                                                 const u8 mac[6]);

#endif
