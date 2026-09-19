#include "lldp_xml.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int lldp_xml_leaf(const char *start, const char *end,
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

void lldp_xml_unescape(const char *src, char *dst, size_t dst_len) {
    size_t off = 0;

    if (!dst || dst_len == 0)
        return;
    if (!src)
        src = "";
    for (const char *p = src; *p && off + 1 < dst_len; p++) {
        if (*p == '&') {
            if (strncmp(p, "&amp;", 5) == 0) {
                dst[off++] = '&';
                p += 4;
                continue;
            }
            if (strncmp(p, "&lt;", 4) == 0) {
                dst[off++] = '<';
                p += 3;
                continue;
            }
            if (strncmp(p, "&gt;", 4) == 0) {
                dst[off++] = '>';
                p += 3;
                continue;
            }
            if (strncmp(p, "&quot;", 6) == 0) {
                dst[off++] = '"';
                p += 5;
                continue;
            }
            if (strncmp(p, "&apos;", 6) == 0) {
                dst[off++] = '\'';
                p += 5;
                continue;
            }
        }
        dst[off++] = *p;
    }
    dst[off] = '\0';
}

void lldp_xml_escape(const char *src, char *dst, size_t dst_len) {
    size_t off = 0;

    if (!dst || dst_len == 0)
        return;
    if (!src)
        src = "";
    for (const char *p = src; *p && off + 1 < dst_len; p++) {
        const char *rep = NULL;

        switch (*p) {
        case '&':
            rep = "&amp;";
            break;
        case '<':
            rep = "&lt;";
            break;
        case '>':
            rep = "&gt;";
            break;
        case '"':
            rep = "&quot;";
            break;
        case '\'':
            rep = "&apos;";
            break;
        default:
            dst[off++] = *p;
            continue;
        }
        size_t len = strlen(rep);
        if (off + len >= dst_len)
            break;
        memcpy(dst + off, rep, len);
        off += len;
    }
    dst[off] = '\0';
}

bool lldp_parse_int_text(const char *text, int min, int max, int *value) {
    char *end = NULL;
    long v;

    if (!text || !text[0] || !value)
        return false;
    errno = 0;
    v = strtol(text, &end, 10);
    if (errno != 0 || !end || *end || v < min || v > max)
        return false;
    *value = (int)v;
    return true;
}

bool lldp_parse_management_address_text(const char *text,
                                        lldp_config *cfg) {
    u8 addr[16];

    if (!text || !text[0] || !cfg)
        return false;
    if (inet_pton(AF_INET, text, addr) == 1) {
        cfg->mgmt_configured = true;
        cfg->mgmt_subtype = 1;
        cfg->mgmt_addr_len = 4;
        memcpy(cfg->mgmt_addr, addr, 4);
        snprintf(cfg->mgmt_addr_text, sizeof(cfg->mgmt_addr_text),
                 "%s", text);
        return true;
    }
    if (inet_pton(AF_INET6, text, addr) == 1) {
        cfg->mgmt_configured = true;
        cfg->mgmt_subtype = 2;
        cfg->mgmt_addr_len = 16;
        memcpy(cfg->mgmt_addr, addr, 16);
        snprintf(cfg->mgmt_addr_text, sizeof(cfg->mgmt_addr_text),
                 "%s", text);
        return true;
    }
    return false;
}
