#ifndef NETLAB_PACKET_EVENT_H
#define NETLAB_PACKET_EVENT_H
#include "types.h"
#include <string.h>

/* Versioned local CPU-packet envelope. Preserve the physical ingress port,
 * VLAN and original capture time through switchd, packetd and subscribers. */
#define NL_PACKET_EVENT_HEADER 20
static inline int nl_packet_event_encode(u8 *out, int capacity, int port, int vlan,
                                         u64 received_at, const u8 *frame, int length) {
    if (!out || !frame || length < 0 || length > capacity - NL_PACKET_EVENT_HEADER ||
        port < 0 || port > 65535 || vlan < 0 || vlan > 4094 || !received_at) return -1;
    memmove(out + NL_PACKET_EVENT_HEADER, frame, (size_t)length);
    memcpy(out, "NLPKT001", 8);
    out[8] = (u8)(port >> 8); out[9] = (u8)port;
    out[10] = (u8)(vlan >> 8); out[11] = (u8)vlan;
    for (int i = 0; i < 8; ++i) out[12 + i] = (u8)(received_at >> (56 - 8 * i));
    return length + NL_PACKET_EVENT_HEADER;
}
static inline int nl_packet_event_decode(const u8 *event, int length, int *port,
                                         int *vlan, u64 *received_at) {
    if (!event || length < 4 || !port || !vlan || !received_at) return -1;
    *received_at = 0;
    if (length >= 8 && !memcmp(event, "NLPKT001", 8)) {
        if (length < NL_PACKET_EVENT_HEADER) return -1;
        *port = ((int)event[8] << 8) | event[9];
        *vlan = ((int)event[10] << 8) | event[11];
        for (int i = 0; i < 8; ++i) *received_at = (*received_at << 8) | event[12 + i];
        return *received_at && *vlan <= 4094 ? NL_PACKET_EVENT_HEADER : -1;
    }
    /* Legacy public-control-plane fixtures; native scopes reject time zero. */
    *port = ((int)event[0] << 8) | event[1];
    *vlan = ((int)event[2] << 8) | event[3];
    return *vlan <= 4094 ? 4 : -1;
}
#endif
