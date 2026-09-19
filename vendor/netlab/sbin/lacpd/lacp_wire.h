#ifndef NETLAB_LACPD_LACP_WIRE_H
#define NETLAB_LACPD_LACP_WIRE_H

#include "netlab/types.h"

#define LACP_ETHERTYPE 0x8809
#define LACP_SUBTYPE   0x01
#define LACP_VERSION   0x01

#define LACP_STATE_ACTIVITY     0x01
#define LACP_STATE_TIMEOUT      0x02
#define LACP_STATE_AGGREGATION  0x04
#define LACP_STATE_SYNC         0x08
#define LACP_STATE_COLLECTING   0x10
#define LACP_STATE_DISTRIBUTING 0x20
#define LACP_STATE_DEFAULTED    0x40

typedef struct {
    u16 system_priority;
    u8  system_mac[6];
    u16 key;
    u16 port_priority;
    u16 port;
    u8  state;
} lacp_info;

void lacp_put16(u8 *p, u16 v);
void lacp_write_info(u8 *p, const lacp_info *info);
bool lacp_parse_pdu(const u8 *frame, int len,
                    lacp_info *actor, lacp_info *partner);

#endif
