#include "lacp_wire.h"

#include <string.h>

void lacp_put16(u8 *p, u16 v) {
    p[0] = (u8)((v >> 8) & 0xff);
    p[1] = (u8)(v & 0xff);
}

static u16 lacp_get16(const u8 *p) {
    return (u16)(((u16)p[0] << 8) | p[1]);
}

static void lacp_parse_info(const u8 *p, lacp_info *info) {
    info->system_priority = lacp_get16(p);
    memcpy(info->system_mac, p + 2, 6);
    info->key = lacp_get16(p + 8);
    info->port_priority = lacp_get16(p + 10);
    info->port = lacp_get16(p + 12);
    info->state = p[14];
}

void lacp_write_info(u8 *p, const lacp_info *info) {
    lacp_put16(p, info->system_priority);
    memcpy(p + 2, info->system_mac, 6);
    lacp_put16(p + 8, info->key);
    lacp_put16(p + 10, info->port_priority);
    lacp_put16(p + 12, info->port);
    p[14] = info->state;
    p[15] = 0;
    p[16] = 0;
    p[17] = 0;
}

bool lacp_parse_pdu(const u8 *frame, int len,
                    lacp_info *actor, lacp_info *partner) {
    if (!frame || !actor || !partner || len < 60)
        return false;
    if ((((u16)frame[12] << 8) | frame[13]) != LACP_ETHERTYPE)
        return false;
    if (frame[14] != LACP_SUBTYPE || frame[15] != LACP_VERSION)
        return false;
    if (frame[16] != 1 || frame[17] != 20 ||
        frame[36] != 2 || frame[37] != 20)
        return false;
    lacp_parse_info(frame + 18, actor);
    lacp_parse_info(frame + 38, partner);
    return true;
}
