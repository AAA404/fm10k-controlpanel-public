/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "stp_config_text.h"
#include "stp_lag.h"

#include "netlab/interface_id.h"
#include "netlab/journal.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int stp_config_xml_leaf(const char *start, const char *end,
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

char *stp_config_read_active(void) {
    char path[512];
    FILE *f;
    long n;
    char *buf;

    nl_config_file_path(path, sizeof(path), "active.conf");
    f = fopen(path, "r");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    n = ftell(f);
    if (n < 0 || n > 1024 * 1024) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = calloc(1, (size_t)n + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    return buf;
}

bool stp_config_vlan_seen(const int *vlans, int n_vlans, int vid) {
    for (int i = 0; i < n_vlans; i++)
        if (vlans[i] == vid)
            return true;
    return false;
}

static int vlan_name_to_id_from_xml(const char *xml, const char *vlan_name) {
    const char *p;

    if (!xml || !vlan_name || !vlan_name[0])
        return 0;

    p = xml;
    while ((p = strstr(p, "<vlan>"))) {
        const char *end = strstr(p, "</vlan>");
        char name[64] = {0};
        char vid_text[32] = {0};
        int vid;

        if (!end)
            break;
        if (stp_config_xml_leaf(p, end, "name", name, sizeof(name)) == 0 &&
            strcmp(name, vlan_name) == 0 &&
            stp_config_xml_leaf(p, end, "vlan-id", vid_text,
                                sizeof(vid_text)) == 0) {
            vid = atoi(vid_text);
            if (vid >= 1 && vid <= 4094)
                return vid;
            return 0;
        }
        p = end + strlen("</vlan>");
    }
    return 0;
}

int stp_config_collect_port_vlans(int port, int *vlans, int max_vlans) {
    char ifname[32];
    char *xml;
    const char *p;
    int n = 0;

    if (!vlans || max_vlans <= 0 || port <= 0)
        return 0;

    stp_port_name(port, ifname, sizeof(ifname));
    xml = stp_config_read_active();
    if (!xml)
        return 0;

    p = xml;
    while ((p = strstr(p, "<interface>"))) {
        const char *end = strstr(p, "</interface>");
        char name[64] = {0};
        const char *m;
        char native_text[32] = {0};

        if (!end)
            break;
        if (stp_config_xml_leaf(p, end, "name", name, sizeof(name)) != 0 ||
            strcmp(name, ifname) != 0) {
            p = end + strlen("</interface>");
            continue;
        }

        m = p;
        while ((m = strstr(m, "<vlan-members>")) && m < end &&
               n < max_vlans) {
            const char *vstart = m + strlen("<vlan-members>");
            const char *vend = strstr(vstart, "</vlan-members>");
            char member[64];
            size_t len;
            int vid;

            if (!vend || vend > end)
                break;
            len = (size_t)(vend - vstart);
            if (len >= sizeof(member))
                len = sizeof(member) - 1;
            memcpy(member, vstart, len);
            member[len] = '\0';

            vid = vlan_name_to_id_from_xml(xml, member);
            if (vid >= 1 && vid <= 4094 &&
                !stp_config_vlan_seen(vlans, n, vid))
                vlans[n++] = vid;
            m = vend + strlen("</vlan-members>");
        }

        if (stp_config_xml_leaf(p, end, "native-vlan-id", native_text,
                                sizeof(native_text)) == 0 &&
            n < max_vlans) {
            int vid = atoi(native_text);
            if (vid >= 1 && vid <= 4094 &&
                !stp_config_vlan_seen(vlans, n, vid))
                vlans[n++] = vid;
        }
        break;
    }

    free(xml);
    return n;
}
