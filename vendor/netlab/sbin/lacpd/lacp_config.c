/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "lacp_config.h"

#include "netlab/interface_id.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *lacp_xml_leaf(const char *start, const char *end, const char *tag,
                    char *out, size_t out_size) {
    char open[64];
    char close[64];
    char *p;
    char *q;
    size_t n;

    if (!start || !end || !tag || !out || out_size == 0)
        return NULL;
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    p = strstr((char *)start, open);
    if (!p || p >= end)
        return NULL;
    p += strlen(open);
    q = strstr(p, close);
    if (!q || q > end)
        return NULL;
    n = (size_t)(q - p);
    if (n >= out_size)
        n = out_size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return out;
}

bool lacp_xml_attr(const char *start, const char *end, const char *attr,
                   char *out, size_t out_size) {
    char needle[64];
    char *p;
    char *q;
    size_t n;

    if (!start || !attr || !out || out_size == 0)
        return false;
    out[0] = '\0';
    snprintf(needle, sizeof(needle), "%s=\"", attr);
    p = strstr((char *)start, needle);
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

bool lacp_xml_find_container(const char *xml, const char *tag,
                             char **body_start, char **body_end) {
    char open[64];
    char close[64];
    char *p;
    char *q;

    if (!xml || !tag || !body_start || !body_end)
        return false;
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    p = strstr((char *)xml, open);
    if (!p)
        return false;
    q = strstr(p, close);
    if (!q)
        return false;
    *body_start = p + strlen(open);
    *body_end = q;
    return true;
}

static u16 parse_priority_or_default(const char *text, u16 fallback) {
    char *end = NULL;
    long value;

    if (!text || !text[0])
        return fallback;
    value = strtol(text, &end, 10);
    if (!end || *end || value < 1 || value > 65535)
        return fallback;
    return (u16)value;
}

bool lacp_config_extract_aggregator(const char *start, const char *end,
                                    char *mode, size_t mode_size,
                                    char *min_links, size_t min_links_size,
                                    char *periodic, size_t periodic_size,
                                    u16 *actor_key) {
    char *agg;
    char *agg_end;
    char *lacp;
    char *lacp_end;

    if (!start || !end)
        return false;
    agg = strstr((char *)start, "<aggregated-ether-options>");
    if (!agg || agg >= end)
        return false;
    agg_end = strstr(agg, "</aggregated-ether-options>");
    if (!agg_end || agg_end > end)
        return false;
    char fixed[8] = {0};
    if (lacp_xml_leaf(agg, agg_end, "static", fixed, sizeof(fixed)) && !strcmp(fixed, "true")) {
        snprintf(mode, mode_size, "static");
        (void)lacp_xml_leaf(agg, agg_end, "minimum-links", min_links, min_links_size);
        if (periodic && periodic_size) periodic[0] = 0;
        if (actor_key) *actor_key = 0;
        return true;
    }
    lacp = strstr(agg, "<lacp>");
    if (!lacp || lacp >= agg_end)
        return false;
    lacp_end = strstr(lacp, "</lacp>");
    if (!lacp_end || lacp_end > agg_end)
        return false;
    if (!lacp_xml_leaf(lacp, lacp_end, "mode", mode, mode_size))
        return false;
    (void)lacp_xml_leaf(agg, agg_end, "minimum-links",
                        min_links, min_links_size);
    (void)lacp_xml_leaf(lacp, lacp_end, "periodic",
                        periodic, periodic_size);
    if (actor_key) {
        char value[32] = {0};
        if (lacp_xml_leaf(lacp, lacp_end, "actor-key",
                          value, sizeof(value)))
            *actor_key = parse_priority_or_default(value, 0);
        else
            *actor_key = 0;
    }
    return true;
}

u16 lacp_config_extract_member_port_priority(const char *start,
                                             const char *end) {
    char *ether;
    char *ether_end;
    char *lacp;
    char *lacp_end;
    char value[32] = {0};

    if (!start || !end)
        return 0;
    ether = strstr((char *)start, "<ether-options>");
    if (!ether || ether >= end)
        return 0;
    ether_end = strstr(ether, "</ether-options>");
    if (!ether_end || ether_end > end)
        return 0;
    lacp = strstr(ether, "<lacp>");
    if (!lacp || lacp >= ether_end)
        return 0;
    lacp_end = strstr(lacp, "</lacp>");
    if (!lacp_end || lacp_end > ether_end)
        return 0;
    if (!lacp_xml_leaf(lacp, lacp_end, "port-priority",
                       value, sizeof(value)))
        return 0;
    return parse_priority_or_default(value, 0);
}

static bool parse_actor_system_id(const char *text, u8 mac[6]) {
    return nl_platform_parse_mac(text, mac) && ((mac[0] & 0x01) == 0);
}

void lacp_config_extract_global(const char *xml,
                                u16 *system_priority,
                                u16 *port_priority,
                                u8 actor_system[6]) {
    char *protocols;
    char *protocols_end;
    char *lacp;
    char *lacp_end;
    char value[32] = {0};

    if (!xml || !system_priority || !port_priority)
        return;
    protocols = strstr((char *)xml, "<protocols>");
    if (!protocols)
        return;
    protocols_end = strstr(protocols, "</protocols>");
    if (!protocols_end)
        return;
    lacp = strstr(protocols, "<lacp>");
    if (!lacp || lacp >= protocols_end)
        return;
    lacp_end = strstr(lacp, "</lacp>");
    if (!lacp_end || lacp_end > protocols_end)
        return;

    if (lacp_xml_leaf(lacp, lacp_end, "system-priority",
                      value, sizeof(value)))
        *system_priority = parse_priority_or_default(value, *system_priority);
    value[0] = '\0';
    if (actor_system &&
        lacp_xml_leaf(lacp, lacp_end, "system-id", value, sizeof(value)))
        (void)parse_actor_system_id(value, actor_system);
    value[0] = '\0';
    if (lacp_xml_leaf(lacp, lacp_end, "port-priority",
                      value, sizeof(value)))
        *port_priority = parse_priority_or_default(value, *port_priority);
}

int lacp_config_parse_min_links(const char *text) {
    char *end = NULL;
    long value;

    if (!text || !text[0])
        return 1;
    value = strtol(text, &end, 10);
    if (!end || *end || value < 1 || value > 16)
        return 1;
    return (int)value;
}
