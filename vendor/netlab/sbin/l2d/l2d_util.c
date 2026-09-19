#include "l2d_util.h"

#include "l2d_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int l2d_max_ae(void) {
    int n = nl_platform_max_ae();
    if (n <= 0)
        return 0;
    if (n > L2D_AE_LIMIT)
        return L2D_AE_LIMIT;
    return n;
}

int l2d_ae_id_from_name(const char *ifname) {
    char *end = NULL;
    long id;

    if (!ifname || ifname[0] != 'a' || ifname[1] != 'e' ||
        ifname[2] == '\0')
        return -1;
    id = strtol(ifname + 2, &end, 10);
    if (!end || *end || id < 0 || id >= l2d_max_ae())
        return -1;
    return (int)id;
}

bool l2d_stp_has_member(const nl_stp_snapshot *snapshot, int vid, int port) {
    return nl_stp_snapshot_has_member(snapshot, vid, port);
}

bool l2d_xml_attr_value(const char *start, const char *end,
                        const char *attr, char *out, size_t out_size) {
    char needle[64];
    const char *p;
    const char *q;
    size_t n;

    if (!start || !attr || !out || out_size == 0)
        return false;
    out[0] = '\0';
    snprintf(needle, sizeof(needle), "%s=\"", attr);
    p = strstr(start, needle);
    if (!p || (end && p >= end))
        return false;
    p += strlen(needle);
    q = strchr(p, '"');
    if (!q || (end && q > end))
        return false;
    n = (size_t)(q - p);
    if (n >= out_size)
        n = out_size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

int l2d_extract_xml_leaf(const char *start, const char *end,
                         const char *leaf, char *out, size_t out_size) {
    char open[64];
    char close[64];
    const char *p;
    const char *q;
    size_t len;

    if (!start || !end || !leaf || !out || out_size == 0)
        return -1;
    out[0] = '\0';
    snprintf(open, sizeof(open), "<%s>", leaf);
    snprintf(close, sizeof(close), "</%s>", leaf);
    p = strstr(start, open);
    if (!p || p >= end)
        return -1;
    p += strlen(open);
    q = strstr(p, close);
    if (!q || q > end)
        return -1;
    len = (size_t)(q - p);
    if (len >= out_size)
        len = out_size - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

static bool mac_is_multicast(const char *mac) {
    unsigned int first = 0;

    if (!mac || sscanf(mac, "%2x", &first) != 1)
        return false;
    return (first & 0x01) != 0;
}

static bool mac_is_zero(const char *mac) {
    if (!mac)
        return true;
    for (int i = 0; mac[i]; i++) {
        if (mac[i] != ':' && mac[i] != '0')
            return false;
    }
    return true;
}

bool l2d_mac_entry_visible(const char *mac, const char *type,
                           const char *ifname) {
    if (!mac || !type || !ifname || !ifname[0])
        return false;
    if (strcmp(type, "dynamic") != 0)
        return false;
    if (mac_is_zero(mac) || mac_is_multicast(mac))
        return false;
    if (strncmp(ifname, "logical-port-", strlen("logical-port-")) == 0)
        return false;
    return true;
}
