#ifndef NETLAB_FM10K_PHY_H
#define NETLAB_FM10K_PHY_H
#include <stddef.h>

/* Only the six four-lane EPL anchors are accepted. No register or SDK
 * attribute address is supplied by a caller. */
static inline int fm10k_phy_port_parse(const char *text) {
    if (!text || !*text) return -1;
    unsigned port = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9' || port > 24) return -1;
        port = port * 10 + (unsigned)(*p - '0');
    }
    return port >= 1 && port <= 21 && (port - 1) % 4 == 0 ? (int)port : -1;
}

/* Called only by the SDK executor; each EPL is cached for five seconds. */
int fm10k_phy_snapshot(int sw, int port, char *out, size_t capacity);
#endif
