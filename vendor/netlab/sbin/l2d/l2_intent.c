/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "l2_plan_internal.h"

int l2_plan_set_error(char *err, size_t err_size, const char *fmt,
                     const char *a, const char *b) {
    if (err && err_size > 0)
        snprintf(err, err_size, fmt, a ? a : "", b ? b : "");
    return -1;
}

int l2_plan_append(char *plan, size_t plan_size, int *off,
                       const char *fmt, int a, int b, int c) {
    int n;

    if (!plan || !off || *off < 0 || (size_t)*off >= plan_size)
        return -1;

    n = snprintf(plan + *off, plan_size - (size_t)*off, fmt, a, b, c);
    if (n < 0 || (size_t)n >= plan_size - (size_t)*off)
        return -1;
    *off += n;
    return 0;
}

int l2_plan_appendf(char *plan, size_t plan_size, int *off,
                        const char *fmt, ...) {
    va_list ap;
    int n;

    if (!plan || !off || *off < 0 || (size_t)*off >= plan_size)
        return -1;

    va_start(ap, fmt);
    n = vsnprintf(plan + *off, plan_size - (size_t)*off, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= plan_size - (size_t)*off)
        return -1;
    *off += n;
    return 0;
}

bool l2_text_eq(const char *a, const char *b) {
    if (!a) a = "";
    if (!b) b = "";
    return strcmp(a, b) == 0;
}

int l2_cfg_max_ae(void) {
    int n = nl_platform_max_ae();
    if (n <= 0)
        return 0;
    if (n > CFG_AE_LIMIT)
        return CFG_AE_LIMIT;
    return n;
}

bool l2_bool_leaf_true(const char *value) {
    return value && strcmp(value, "true") == 0;
}

u32 l2_ipv4_mask_from_prefix_len(int prefix_len) {
    if (prefix_len <= 0)
        return 0;
    if (prefix_len >= 32)
        return 0xffffffffU;
    return 0xffffffffU << (32 - prefix_len);
}

bool l2_format_ipv4_text(u32 ip, char *out, size_t out_size) {
    struct in_addr addr;

    if (!out || out_size == 0)
        return false;
    addr.s_addr = htonl(ip);
    return inet_ntop(AF_INET, &addr, out, out_size) != NULL;
}

bool l2_format_ipv4_prefix_text(u32 ip, int prefix_len, char *out,
                                size_t out_size) {
    char ip_text[16];
    int n;

    if (!out || out_size == 0 || prefix_len < 0 || prefix_len > 32)
        return false;
    if (!l2_format_ipv4_text(ip, ip_text, sizeof(ip_text)))
        return false;
    n = snprintf(out, out_size, "%s/%d", ip_text, prefix_len);
    return n > 0 && (size_t)n < out_size;
}

bool l2_parse_ipv4_prefix_text(const char *text, u32 *ip, u32 *mask,
                               int *prefix_len) {
    char buf[32];
    char *slash;
    char *endp;
    long len;
    struct in_addr addr;
    u32 parsed_mask;

    if (!text || !ip || !mask || !prefix_len)
        return false;
    if (strlen(text) >= sizeof(buf))
        return false;
    snprintf(buf, sizeof(buf), "%s", text);
    slash = strchr(buf, '/');
    if (!slash)
        return false;
    *slash++ = '\0';
    if (!buf[0] || !slash[0] || strchr(slash, '/'))
        return false;
    len = strtol(slash, &endp, 10);
    if (*endp != '\0' || len < 0 || len > 32)
        return false;
    if (inet_pton(AF_INET, buf, &addr) != 1)
        return false;
    parsed_mask = l2_ipv4_mask_from_prefix_len((int)len);
    *ip = ntohl(addr.s_addr) & parsed_mask;
    *mask = parsed_mask;
    *prefix_len = (int)len;
    return true;
}

bool l2_parse_port_range_text(const char *text, int *start, int *end) {
    char buf[32];
    char *dash;
    char *endp;
    long lo;
    long hi;

    if (!text || !start || !end)
        return false;
    if (strlen(text) >= sizeof(buf))
        return false;
    snprintf(buf, sizeof(buf), "%s", text);
    dash = strchr(buf, '-');
    if (!dash || dash == buf || dash[1] == '\0' ||
        strchr(dash + 1, '-'))
        return false;
    *dash++ = '\0';
    lo = strtol(buf, &endp, 10);
    if (*endp != '\0')
        return false;
    hi = strtol(dash, &endp, 10);
    if (*endp != '\0' || lo < 0 || hi < 0 ||
        lo > 65535 || hi > 65535 || lo > hi)
        return false;
    *start = (int)lo;
    *end = (int)hi;
    return true;
}

int l2_port_range_entry_count(int start, int end) {
    int count = 0;
    unsigned int cur;
    unsigned int last;

    if (start < 0 || end < 0 || start > end ||
        start > 65535 || end > 65535)
        return 0;
    cur = (unsigned int)start;
    last = (unsigned int)end;
    while (cur <= last) {
        unsigned int size = cur ? (cur & (~cur + 1U)) : 65536U;
        unsigned int remaining = last - cur + 1U;

        while (size > remaining)
            size >>= 1;
        if (size == 0)
            return 0;
        count++;
        cur += size;
        if (cur == 0)
            break;
    }
    return count;
}

int l2_ingress_ipv4_acl_hw_entry_count(
    const cfg_ingress_ipv4_acl_intent *entry) {
    int src_count = 1;
    int dst_count = 1;

    if (!entry)
        return 0;
    if (entry->match.has_src_port_range)
        src_count = l2_port_range_entry_count(entry->match.src_port_start,
                                              entry->match.src_port_end);
    if (entry->match.has_dst_port_range)
        dst_count = l2_port_range_entry_count(entry->match.dst_port_start,
                                              entry->match.dst_port_end);
    if (src_count <= 0 || dst_count <= 0)
        return 0;
    return src_count * dst_count;
}

bool l2_normalize_mac_text(const char *in, char *out, size_t out_size) {
    unsigned int values[6];

    if (!in || !out || out_size < 18 || strlen(in) != 17)
        return false;
    for (int i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (in[i] != ':')
                return false;
        } else if (!isxdigit((unsigned char)in[i])) {
            return false;
        }
    }
    if (sscanf(in, "%2x:%2x:%2x:%2x:%2x:%2x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++)
        if (values[i] > 255)
            return false;
    snprintf(out, out_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             values[0], values[1], values[2],
             values[3], values[4], values[5]);
    return true;
}

static bool mac_text_to_u64(const char *text, u64 *out) {
    unsigned int values[6];
    u64 mac = 0;

    if (!text || !out)
        return false;
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6)
        return false;
    if (values[0] & 0x01)
        return false;
    for (int i = 0; i < 6; i++) {
        if (values[i] > 255)
            return false;
        mac = (mac << 8) | values[i];
    }
    if (mac == 0)
        return false;
    *out = mac;
    return true;
}

bool l2_static_mac_is_unicast_nonzero(const char *mac) {
    unsigned int first = 0;
    bool any = false;

    if (!mac || sscanf(mac, "%2x", &first) != 1 || (first & 0x01))
        return false;
    for (int i = 0; mac[i]; i++) {
        if (mac[i] != ':' && mac[i] != '0') {
            any = true;
            break;
        }
    }
    return any;
}

int l2_extract_xml_leaf(const char *start, const char *end,
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

int l2_extract_xml_attr(const char *start, const char *end,
                            const char *attr, char *out, size_t out_size) {
    char needle[64];
    const char *p;
    const char *q;
    size_t len;

    if (!start || !attr || !out || out_size == 0)
        return -1;
    out[0] = '\0';
    snprintf(needle, sizeof(needle), "%s=\"", attr);
    p = strstr(start, needle);
    if (!p || (end && p >= end))
        return -1;
    p += strlen(needle);
    q = strchr(p, '"');
    if (!q || (end && q > end))
        return -1;
    len = (size_t)(q - p);
    if (len >= out_size)
        len = out_size - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

int l2_collect_vlans(nl_yang_session *ys, cfg_vlan_ref *vlans,
                         int max_vlans) {
    char *xml;
    char *p;
    int n = 0;

    if (!ys || !vlans || max_vlans <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    p = xml;
    while ((p = strstr(p, "<vlan>")) && n < max_vlans) {
        char *end = strstr(p, "</vlan>");
        char name[64];
        char vid_buf[32];
        int vid;

        if (!end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0 &&
            l2_extract_xml_leaf(p, end, "vlan-id", vid_buf, sizeof(vid_buf)) == 0) {
            vid = atoi(vid_buf);
            if (vid >= 1 && vid <= 4094) {
                snprintf(vlans[n].name, sizeof(vlans[n].name), "%s", name);
                vlans[n].vid = vid;
                n++;
            }
        }
        p = end + strlen("</vlan>");
    }

    free(xml);
    return n;
}

int l2_collect_static_mac_intents(nl_yang_session *ys,
                                      cfg_static_mac_intent *entries,
                                      int max_entries) {
    char *xml;
    char *eso;
    char *static_node;
    char *static_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    eso = strstr(xml, "<ethernet-switching-options>");
    if (!eso) {
        free(xml);
        return 0;
    }
    static_node = strstr(eso, "<static>");
    if (!static_node) {
        free(xml);
        return 0;
    }
    static_end = strstr(static_node, "</static>");
    if (!static_end) {
        free(xml);
        return 0;
    }

    p = static_node;
    while ((p = strstr(p, "<mac-table-entry>")) &&
           p < static_end && n < max_entries) {
        char *end = strstr(p, "</mac-table-entry>");
        char mac[32];
        char vlan[64];
        char ifname[64];
        char norm[18];

        if (!end || end > static_end)
            break;
        if (l2_extract_xml_leaf(p, end, "mac-address", mac, sizeof(mac)) == 0 &&
            l2_extract_xml_leaf(p, end, "vlan", vlan, sizeof(vlan)) == 0 &&
            l2_extract_xml_leaf(p, end, "interface", ifname, sizeof(ifname)) == 0 &&
            l2_normalize_mac_text(mac, norm, sizeof(norm))) {
            snprintf(entries[n].mac, sizeof(entries[n].mac), "%s", norm);
            snprintf(entries[n].vlan, sizeof(entries[n].vlan), "%s", vlan);
            snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", ifname);
            entries[n].vid = l2_get_vlan_id(ys, vlan);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        p = end + strlen("</mac-table-entry>");
    }

    free(xml);
    return n;
}

static int collect_legacy_storm_control_intents(nl_yang_session *ys,
                                     cfg_storm_control_intent *entries,
                                     int max_entries) {
    char *xml;
    char *eso;
    char *storm;
    char *storm_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    eso = strstr(xml, "<ethernet-switching-options>");
    if (!eso) {
        free(xml);
        return 0;
    }
    storm = strstr(eso, "<storm-control>");
    if (!storm) {
        free(xml);
        return 0;
    }
    storm_end = strstr(storm, "</storm-control>");
    if (!storm_end) {
        free(xml);
        return 0;
    }

    p = storm;
    while ((p = strstr(p, "<interface>")) &&
           p < storm_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char rate[32];
        char burst[32];

        if (!end || end > storm_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0 &&
            l2_extract_xml_leaf(p, end, "bandwidth", rate, sizeof(rate)) == 0) {
            memset(&entries[n], 0, sizeof(entries[n]));
            snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", name);
            entries[n].rate_kbps = atoi(rate);
            entries[n].burst_bytes = CFG_STORM_CONTROL_DEFAULT_BURST_BYTES;
            if (l2_extract_xml_leaf(p, end, "burst-size", burst,
                                    sizeof(burst)) == 0)
                entries[n].burst_bytes = atoi(burst);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

int l2_collect_storm_control_intents(nl_yang_session *ys,
                                     cfg_storm_control_intent *entries,
                                     int max_entries) {
    const char *path = "/netlab:netlab-config/interfaces/interface/fm10k-port";
    const char *leaves[] = {"broadcast-kbps", "multicast-kbps", "unknown-unicast-kbps"};
    struct ly_set *set = NULL;
    struct lyd_node *tree = NULL;
    int n;

    if (!ys || !entries || max_entries <= 0) return -1;
    if (nl_yang_count(ys, "/netlab:netlab-config/ethernet-switching-options/storm-control/interface") > max_entries)
        return -1;
    n = collect_legacy_storm_control_intents(ys, entries, max_entries);
    int count = nl_yang_count(ys, path);
    if (count <= 0) return count < 0 ? -1 : n;
    tree = nl_yang_data_clone(ys);
    if (!tree || lyd_find_xpath(tree, path, &set) != LY_SUCCESS) {
        n = -1;
        goto done;
    }
    for (uint32_t i = 0; i < set->count; ++i) {
        const struct lyd_node *node, *board = set->dnodes[i];
        const char *name = NULL;
        LY_LIST_FOR(lyd_child((const struct lyd_node *)board->parent), node)
            if (!strcmp(LYD_NAME(node), "name")) name = lyd_get_value(node);
        if (!name || strlen(name) >= sizeof(entries[0].ifname)) { n = -1; goto done; }
        LY_LIST_FOR(lyd_child(board), node) {
            for (int kind = 0; kind < 3; ++kind) {
                if (strcmp(LYD_NAME(node), leaves[kind])) continue;
                int rate = atoi(lyd_get_value(node));
                if (!rate) continue;
                if (n >= max_entries) { n = -1; goto done; }
                entries[n] = (cfg_storm_control_intent){
                    .kind = (nl_storm_kind)(NL_STORM_BROADCAST + kind),
                    .rate_kbps = rate,
                    .burst_bytes = CFG_STORM_CONTROL_DEFAULT_BURST_BYTES,
                };
                snprintf(entries[n++].ifname, sizeof(entries[0].ifname), "%s", name);
            }
        }
    }
done:
    ly_set_free(set, NULL);
    lyd_free_all(tree);
    return n;
}

int l2_collect_ingress_rate_limit_intents(
    nl_yang_session *ys, cfg_ingress_rate_limit_intent *entries,
    int max_entries) {
    char *xml;
    char *eso;
    char *ingress_rate_limit;
    char *ingress_rate_limit_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    eso = strstr(xml, "<ethernet-switching-options>");
    if (!eso) {
        free(xml);
        return 0;
    }
    ingress_rate_limit = strstr(eso, "<ingress-rate-limit>");
    if (!ingress_rate_limit) {
        free(xml);
        return 0;
    }
    ingress_rate_limit_end = strstr(ingress_rate_limit,
                                    "</ingress-rate-limit>");
    if (!ingress_rate_limit_end) {
        free(xml);
        return 0;
    }

    p = ingress_rate_limit;
    while ((p = strstr(p, "<interface>")) &&
           p < ingress_rate_limit_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char rate[32];
        char burst[32];

        if (!end || end > ingress_rate_limit_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0 &&
            l2_extract_xml_leaf(p, end, "bandwidth", rate, sizeof(rate)) == 0) {
            snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", name);
            entries[n].rate_kbps = atoi(rate);
            entries[n].burst_bytes = CFG_INGRESS_RATE_LIMIT_DEFAULT_BURST_BYTES;
            if (l2_extract_xml_leaf(p, end, "burst-size", burst,
                                    sizeof(burst)) == 0)
                entries[n].burst_bytes = atoi(burst);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

int l2_collect_egress_rate_limit_intents(
    nl_yang_session *ys, cfg_egress_rate_limit_intent *entries,
    int max_entries) {
    char *xml;
    char *eso;
    char *egress_rate_limit;
    char *egress_rate_limit_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    eso = strstr(xml, "<ethernet-switching-options>");
    if (!eso) {
        free(xml);
        return 0;
    }
    egress_rate_limit = strstr(eso, "<egress-rate-limit>");
    if (!egress_rate_limit) {
        free(xml);
        return 0;
    }
    egress_rate_limit_end = strstr(egress_rate_limit,
                                   "</egress-rate-limit>");
    if (!egress_rate_limit_end) {
        free(xml);
        return 0;
    }

    p = egress_rate_limit;
    while ((p = strstr(p, "<interface>")) &&
           p < egress_rate_limit_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char rate[32];
        char burst[32];

        if (!end || end > egress_rate_limit_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0 &&
            l2_extract_xml_leaf(p, end, "bandwidth", rate, sizeof(rate)) == 0) {
            snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", name);
            entries[n].rate_kbps = atoi(rate);
            entries[n].burst_bytes = CFG_EGRESS_RATE_LIMIT_DEFAULT_BURST_BYTES;
            if (l2_extract_xml_leaf(p, end, "burst-size", burst,
                                    sizeof(burst)) == 0)
                entries[n].burst_bytes = atoi(burst);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

static cfg_l2_security_kind security_feature_kind(const char *feature) {
    if (feature && strcmp(feature, "dhcp-snooping") == 0)
        return CFG_L2_SECURITY_DHCP_SNOOPING;
    if (feature && strcmp(feature, "arp-inspection") == 0)
        return CFG_L2_SECURITY_ARP_INSPECTION;
    return 0;
}

static bool security_trusted(nl_yang_session *ys, const char *feature,
                             const char *ifname) {
    char path[256];
    const char *trusted;

    if (!ys || !feature || !ifname)
        return false;
    snprintf(path, sizeof(path),
             "/netlab:netlab-config/ethernet-switching-options"
             "/%s/interface[name='%s']/trusted", feature, ifname);
    trusted = nl_yang_get(ys, path);
    return trusted && strcmp(trusted, "true") == 0;
}

int l2_collect_l2_security_rule_intents(nl_yang_session *ys,
                                        const char *feature,
                                        cfg_l2_security_rule_intent *entries,
                                        int max_entries,
                                        const cfg_port_ref *ports,
                                        int n_ports) {
    char *xml;
    char open_tag[64];
    char close_tag[64];
    char *feature_xml;
    char *feature_end;
    char *p;
    cfg_l2_security_kind kind = security_feature_kind(feature);
    int n = 0;

    if (!ys || !feature || !entries || max_entries <= 0 ||
        !ports || n_ports <= 0 || kind == 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    snprintf(open_tag, sizeof(open_tag), "<%s>", feature);
    snprintf(close_tag, sizeof(close_tag), "</%s>", feature);
    feature_xml = strstr(xml, open_tag);
    if (!feature_xml) {
        free(xml);
        return 0;
    }
    feature_end = strstr(feature_xml, close_tag);
    if (!feature_end) {
        free(xml);
        return 0;
    }

    p = feature_xml;
    while ((p = strstr(p, "<vlan>")) && p < feature_end) {
        char *end = strstr(p, "</vlan>");
        char vlan[64];
        int vid;

        if (!end || end > feature_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", vlan, sizeof(vlan)) != 0) {
            p = end + strlen("</vlan>");
            continue;
        }
        vid = l2_get_vlan_id(ys, vlan);
        if (vid <= 0) {
            p = end + strlen("</vlan>");
            continue;
        }

        for (int i = 0; i < n_ports && n < max_entries; i++) {
            cfg_if_intent intent;

            if (ports[i].is_aggregate || ports[i].hw_port <= 0)
                continue;
            if (security_trusted(ys, feature, ports[i].name))
                continue;
            l2_read_interface_intent(ys, ports[i].name, &intent);
            if (!intent.has_l2 || !l2_intent_has_vid(&intent, vid))
                continue;
            entries[n].kind = kind;
            entries[n].vid = vid;
            entries[n].port = ports[i];
            n++;
        }

        p = end + strlen("</vlan>");
    }

    free(xml);
    return n;
}

int l2_collect_dhcp_binding_intents(nl_yang_session *ys,
                                    cfg_dhcp_binding_intent *entries,
                                    int max_entries,
                                    const cfg_port_ref *ports,
                                    int n_ports) {
    char *xml;
    char *feature_xml;
    char *feature_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0 || !ports || n_ports <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;
    feature_xml = strstr(xml, "<dhcp-snooping>");
    if (!feature_xml) {
        free(xml);
        return 0;
    }
    feature_end = strstr(feature_xml, "</dhcp-snooping>");
    if (!feature_end) {
        free(xml);
        return 0;
    }

    p = feature_xml;
    while ((p = strstr(p, "<binding>")) && p < feature_end &&
           n < max_entries) {
        char *end = strstr(p, "</binding>");
        char mac[32];
        char vlan[64];
        char ifname[64];
        char ip[16];
        const cfg_port_ref *port;
        struct in_addr addr;
        int vid;

        if (!end || end > feature_end)
            break;
        if (l2_extract_xml_leaf(p, end, "mac-address", mac,
                                sizeof(mac)) != 0 ||
            l2_extract_xml_leaf(p, end, "vlan", vlan,
                                sizeof(vlan)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0 ||
            l2_extract_xml_leaf(p, end, "ip-address", ip,
                                sizeof(ip)) != 0) {
            p = end + strlen("</binding>");
            continue;
        }
        port = l2_find_port_ref(ports, n_ports, ifname);
        vid = l2_get_vlan_id(ys, vlan);
        if (!port || vid <= 0 || inet_pton(AF_INET, ip, &addr) != 1) {
            p = end + strlen("</binding>");
            continue;
        }
        if (!l2_normalize_mac_text(mac, entries[n].mac,
                                   sizeof(entries[n].mac))) {
            p = end + strlen("</binding>");
            continue;
        }
        snprintf(entries[n].vlan, sizeof(entries[n].vlan), "%s", vlan);
        entries[n].vid = vid;
        snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", ifname);
        entries[n].port = *port;
        snprintf(entries[n].ip, sizeof(entries[n].ip), "%s", ip);
        entries[n].ip_addr = ntohl(addr.s_addr);
        n++;

        p = end + strlen("</binding>");
    }

    free(xml);
    return n;
}

static int collect_user_filter_feature(nl_yang_session *ys, const char *xml,
                                       const char *feature_name,
                                       cfg_user_filter_intent *entries,
                                       int max_entries,
                                       const cfg_port_ref *ports,
                                       int n_ports,
                                       int n) {
    char *feature_xml;
    char *feature_end;
    char *p;
    char open_tag[64];
    char close_tag[64];

    snprintf(open_tag, sizeof(open_tag), "<%s>", feature_name);
    snprintf(close_tag, sizeof(close_tag), "</%s>", feature_name);
    feature_xml = strstr(xml, open_tag);
    if (!feature_xml)
        return n;
    feature_end = strstr(feature_xml, close_tag);
    if (!feature_end)
        return n;
    p = feature_xml;
    while ((p = strstr(p, "<term>")) && p < feature_end &&
           n < max_entries) {
        char *end = strstr(p, "</term>");
        char name[64];
        char vlan[64];
        char ifname[64];
        char mac[32];
        char dst_mac[32];
        char action[16];
        const cfg_port_ref *port;
        int vid;
        bool has_src;
        bool has_dst;

        if (!end || end > feature_end)
            break;
        has_src = l2_extract_xml_leaf(p, end, "source-mac", mac,
                                      sizeof(mac)) == 0;
        has_dst = l2_extract_xml_leaf(p, end, "destination-mac", dst_mac,
                                      sizeof(dst_mac)) == 0;
        if (l2_extract_xml_leaf(p, end, "name", name,
                                sizeof(name)) != 0 ||
            l2_extract_xml_leaf(p, end, "vlan", vlan,
                                sizeof(vlan)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0 ||
            has_src == has_dst) {
            p = end + strlen("</term>");
            continue;
        }
        port = l2_find_port_ref(ports, n_ports, ifname);
        vid = l2_get_vlan_id(ys, vlan);
        if (!port || vid <= 0 ||
            !l2_normalize_mac_text(has_src ? mac : dst_mac, entries[n].mac,
                                   sizeof(entries[n].mac))) {
            p = end + strlen("</term>");
            continue;
        }
        snprintf(entries[n].name, sizeof(entries[n].name), "%s", name);
        snprintf(entries[n].feature, sizeof(entries[n].feature), "%s",
                 feature_name);
        snprintf(entries[n].vlan, sizeof(entries[n].vlan), "%s", vlan);
        entries[n].vid = vid;
        snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", ifname);
        entries[n].port = *port;
        snprintf(entries[n].mac_kind, sizeof(entries[n].mac_kind), "%s",
                 has_dst ? "destination" : "source");
        if (l2_extract_xml_leaf(p, end, "action", action,
                                sizeof(action)) == 0 && action[0])
            snprintf(entries[n].action, sizeof(entries[n].action),
                     "%s", action);
        else
            snprintf(entries[n].action, sizeof(entries[n].action), "drop");
        n++;

        p = end + strlen("</term>");
    }
    return n;
}

int l2_collect_user_filter_intents(nl_yang_session *ys,
                                   cfg_user_filter_intent *entries,
                                   int max_entries,
                                   const cfg_port_ref *ports,
                                   int n_ports) {
    char *xml;
    int n = 0;

    if (!ys || !entries || max_entries <= 0 || !ports || n_ports <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    n = collect_user_filter_feature(ys, xml, "user-filter", entries,
                                    max_entries, ports, n_ports, n);
    n = collect_user_filter_feature(ys, xml, "ingress-acl", entries,
                                    max_entries, ports, n_ports, n);

    free(xml);
    return n;
}

int l2_collect_ingress_ipv4_acl_intents(
    nl_yang_session *ys, cfg_ingress_ipv4_acl_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports) {
    char *xml;
    char *feature;
    char *feature_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0 || !ports || n_ports <= 0)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    feature = strstr(xml, "<ingress-ipv4-acl>");
    feature_end = feature ? strstr(feature, "</ingress-ipv4-acl>") : NULL;
    p = feature;
    while (feature && feature_end &&
           (p = strstr(p, "<term>")) && p < feature_end &&
           n < max_entries) {
        char *end = strstr(p, "</term>");
        char name[64];
        char vlan[64];
        char ifname[64];
        char action[16] = "drop";
        char src_ip[16];
        char dst_ip[16];
        char src_prefix[32];
        char dst_prefix[32];
        char dscp_text[16];
        char ecn_text[16];
        char proto_text[16];
        char src_port_text[16];
        char dst_port_text[16];
        char src_port_range_text[16];
        char dst_port_range_text[16];
        char tcp_flags_text[16];
        char tcp_flags_mask_text[16];
        struct in_addr addr;
        u32 prefix_ip;
        u32 prefix_mask;
        int prefix_len;
        int range_start;
        int range_end;
        const cfg_port_ref *port;
        int vid;
        bool has_src_ip;
        bool has_dst_ip;
        bool has_src_prefix;
        bool has_dst_prefix;
        bool has_dscp;
        bool has_ecn;
        bool has_proto;
        bool has_src_port;
        bool has_dst_port;
        bool has_src_port_range;
        bool has_dst_port_range;
        bool has_tcp_flags;
        bool has_tcp_flags_mask;

        if (!end || end > feature_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name,
                                sizeof(name)) != 0 ||
            l2_extract_xml_leaf(p, end, "vlan", vlan,
                                sizeof(vlan)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0) {
            p = end + strlen("</term>");
            continue;
        }

        port = l2_find_port_ref(ports, n_ports, ifname);
        vid = l2_get_vlan_id(ys, vlan);
        if (!port || vid <= 0) {
            p = end + strlen("</term>");
            continue;
        }

        memset(&entries[n], 0, sizeof(entries[n]));
        snprintf(entries[n].name, sizeof(entries[n].name), "%s", name);
        snprintf(entries[n].vlan, sizeof(entries[n].vlan), "%s", vlan);
        snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", ifname);
        entries[n].vid = vid;
        entries[n].port = *port;
        entries[n].match.vid = vid;
        entries[n].match.port = port->hw_port;

        has_src_ip = l2_extract_xml_leaf(p, end, "source-ip", src_ip,
                                         sizeof(src_ip)) == 0;
        has_dst_ip = l2_extract_xml_leaf(p, end, "destination-ip", dst_ip,
                                         sizeof(dst_ip)) == 0;
        has_src_prefix = l2_extract_xml_leaf(p, end, "source-prefix",
                                             src_prefix,
                                             sizeof(src_prefix)) == 0;
        has_dst_prefix = l2_extract_xml_leaf(p, end, "destination-prefix",
                                             dst_prefix,
                                             sizeof(dst_prefix)) == 0;
        has_dscp = l2_extract_xml_leaf(p, end, "dscp", dscp_text,
                                       sizeof(dscp_text)) == 0;
        has_ecn = l2_extract_xml_leaf(p, end, "ecn", ecn_text,
                                      sizeof(ecn_text)) == 0;
        has_proto = l2_extract_xml_leaf(p, end, "protocol", proto_text,
                                        sizeof(proto_text)) == 0;
        has_src_port = l2_extract_xml_leaf(p, end, "source-port",
                                           src_port_text,
                                           sizeof(src_port_text)) == 0;
        has_dst_port = l2_extract_xml_leaf(p, end, "destination-port",
                                           dst_port_text,
                                           sizeof(dst_port_text)) == 0;
        has_src_port_range =
            l2_extract_xml_leaf(p, end, "source-port-range",
                                src_port_range_text,
                                sizeof(src_port_range_text)) == 0;
        has_dst_port_range =
            l2_extract_xml_leaf(p, end, "destination-port-range",
                                dst_port_range_text,
                                sizeof(dst_port_range_text)) == 0;
        has_tcp_flags = l2_extract_xml_leaf(p, end, "tcp-flags",
                                            tcp_flags_text,
                                            sizeof(tcp_flags_text)) == 0;
        has_tcp_flags_mask = l2_extract_xml_leaf(p, end,
                                                 "tcp-flags-mask",
                                                 tcp_flags_mask_text,
                                                 sizeof(tcp_flags_mask_text)) == 0;
        if (has_src_ip && inet_pton(AF_INET, src_ip, &addr) == 1) {
            snprintf(entries[n].src_ip_text, sizeof(entries[n].src_ip_text),
                     "%s", src_ip);
            entries[n].match.has_src_ip = true;
            entries[n].match.src_ip = ntohl(addr.s_addr);
            entries[n].match.has_src_ip_mask = true;
            entries[n].match.src_ip_mask = 0xffffffffU;
        } else if (has_src_prefix &&
                   l2_parse_ipv4_prefix_text(src_prefix, &prefix_ip,
                                             &prefix_mask,
                                             &prefix_len)) {
            l2_format_ipv4_text(prefix_ip, entries[n].src_ip_text,
                                sizeof(entries[n].src_ip_text));
            l2_format_ipv4_prefix_text(prefix_ip, prefix_len,
                                       entries[n].src_prefix_text,
                                       sizeof(entries[n].src_prefix_text));
            entries[n].match.has_src_ip = true;
            entries[n].match.has_src_ip_mask = true;
            entries[n].match.src_ip = prefix_ip;
            entries[n].match.src_ip_mask = prefix_mask;
        }
        if (has_dst_ip && inet_pton(AF_INET, dst_ip, &addr) == 1) {
            snprintf(entries[n].dst_ip_text, sizeof(entries[n].dst_ip_text),
                     "%s", dst_ip);
            entries[n].match.has_dst_ip = true;
            entries[n].match.dst_ip = ntohl(addr.s_addr);
            entries[n].match.has_dst_ip_mask = true;
            entries[n].match.dst_ip_mask = 0xffffffffU;
        } else if (has_dst_prefix &&
                   l2_parse_ipv4_prefix_text(dst_prefix, &prefix_ip,
                                             &prefix_mask,
                                             &prefix_len)) {
            l2_format_ipv4_text(prefix_ip, entries[n].dst_ip_text,
                                sizeof(entries[n].dst_ip_text));
            l2_format_ipv4_prefix_text(prefix_ip, prefix_len,
                                       entries[n].dst_prefix_text,
                                       sizeof(entries[n].dst_prefix_text));
            entries[n].match.has_dst_ip = true;
            entries[n].match.has_dst_ip_mask = true;
            entries[n].match.dst_ip = prefix_ip;
            entries[n].match.dst_ip_mask = prefix_mask;
        }
        if (has_dscp) {
            entries[n].match.has_dscp = true;
            entries[n].match.dscp = atoi(dscp_text);
        }
        if (has_ecn) {
            entries[n].match.has_ecn = true;
            entries[n].match.ecn = atoi(ecn_text);
        }
        if (has_proto) {
            entries[n].match.has_protocol = true;
            entries[n].match.protocol = atoi(proto_text);
        }
        if (has_src_port) {
            entries[n].match.has_src_port = true;
            entries[n].match.src_port = atoi(src_port_text);
        }
        if (has_dst_port) {
            entries[n].match.has_dst_port = true;
            entries[n].match.dst_port = atoi(dst_port_text);
        }
        if (has_src_port_range &&
            l2_parse_port_range_text(src_port_range_text,
                                     &range_start, &range_end)) {
            entries[n].match.has_src_port_range = true;
            entries[n].match.src_port_start = range_start;
            entries[n].match.src_port_end = range_end;
            snprintf(entries[n].src_port_range_text,
                     sizeof(entries[n].src_port_range_text), "%d-%d",
                     range_start, range_end);
        }
        if (has_dst_port_range &&
            l2_parse_port_range_text(dst_port_range_text,
                                     &range_start, &range_end)) {
            entries[n].match.has_dst_port_range = true;
            entries[n].match.dst_port_start = range_start;
            entries[n].match.dst_port_end = range_end;
            snprintf(entries[n].dst_port_range_text,
                     sizeof(entries[n].dst_port_range_text), "%d-%d",
                     range_start, range_end);
        }
        if (has_tcp_flags) {
            entries[n].match.has_tcp_flags = true;
            entries[n].match.tcp_flags = atoi(tcp_flags_text);
            entries[n].match.has_tcp_flags_mask = true;
            entries[n].match.tcp_flags_mask = 63;
        }
        if (has_tcp_flags_mask) {
            entries[n].match.has_tcp_flags_mask = true;
            entries[n].match.tcp_flags_mask = atoi(tcp_flags_mask_text);
        }
        if (l2_extract_xml_leaf(p, end, "action", action,
                                sizeof(action)) == 0 && action[0])
            snprintf(entries[n].action, sizeof(entries[n].action), "%s",
                     action);
        else
            snprintf(entries[n].action, sizeof(entries[n].action), "drop");
        entries[n].match.count_only =
            strcmp(entries[n].action, "count") == 0;
        n++;
        p = end + strlen("</term>");
    }

    free(xml);
    return n;
}

int l2_collect_acl_policer_intents(
    nl_yang_session *ys, cfg_acl_policer_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports) {
    char *xml;
    char *feature;
    char *feature_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0 || !ports || n_ports <= 0)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    feature = strstr(xml, "<acl-policer>");
    feature_end = feature ? strstr(feature, "</acl-policer>") : NULL;
    p = feature;
    while (feature && feature_end &&
           (p = strstr(p, "<term>")) && p < feature_end &&
           n < max_entries) {
        char *end = strstr(p, "</term>");
        char name[64];
        char ifname[64];
        char mac_text[32];
        char rate_text[32];
        char burst_text[32];
        const cfg_port_ref *port;

        if (!end || end > feature_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name,
                                sizeof(name)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0 ||
            l2_extract_xml_leaf(p, end, "destination-mac", mac_text,
                                sizeof(mac_text)) != 0 ||
            l2_extract_xml_leaf(p, end, "bandwidth", rate_text,
                                sizeof(rate_text)) != 0) {
            p = end + strlen("</term>");
            continue;
        }
        port = l2_find_port_ref(ports, n_ports, ifname);
        if (!port ||
            !l2_normalize_mac_text(mac_text, entries[n].dst_mac_text,
                                   sizeof(entries[n].dst_mac_text)) ||
            !mac_text_to_u64(entries[n].dst_mac_text, &entries[n].dst_mac)) {
            p = end + strlen("</term>");
            continue;
        }

        snprintf(entries[n].name, sizeof(entries[n].name), "%s", name);
        snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s",
                 ifname);
        entries[n].port = *port;
        entries[n].rate_kbps = atoi(rate_text);
        entries[n].burst_bytes = CFG_ACL_POLICER_DEFAULT_BURST_BYTES;
        if (l2_extract_xml_leaf(p, end, "burst-size", burst_text,
                                sizeof(burst_text)) == 0)
            entries[n].burst_bytes = atoi(burst_text);
        n++;
        p = end + strlen("</term>");
    }
    free(xml);
    return n;
}

int l2_collect_egress_acl_intents(
    nl_yang_session *ys, cfg_egress_acl_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports) {
    char *xml;
    char *feature;
    char *feature_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0 || !ports || n_ports <= 0)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    feature = strstr(xml, "<egress-acl>");
    feature_end = feature ? strstr(feature, "</egress-acl>") : NULL;
    p = feature;
    while (feature && feature_end &&
           (p = strstr(p, "<term>")) && p < feature_end &&
           n < max_entries) {
        char *end = strstr(p, "</term>");
        char name[64];
        char ifname[64];
        char src_mac_text[32] = {0};
        char dst_mac_text[32] = {0};
        char action[16];
        bool has_src;
        bool has_dst;
        const cfg_port_ref *port;

        if (!end || end > feature_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name,
                                sizeof(name)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0) {
            p = end + strlen("</term>");
            continue;
        }
        has_src = l2_extract_xml_leaf(p, end, "source-mac", src_mac_text,
                                      sizeof(src_mac_text)) == 0 &&
                  src_mac_text[0] != '\0';
        has_dst = l2_extract_xml_leaf(p, end, "destination-mac", dst_mac_text,
                                      sizeof(dst_mac_text)) == 0 &&
                  dst_mac_text[0] != '\0';
        port = l2_find_port_ref(ports, n_ports, ifname);
        if (!port || (!has_src && !has_dst)) {
            p = end + strlen("</term>");
            continue;
        }
        if (has_src &&
            (!l2_normalize_mac_text(src_mac_text, entries[n].src_mac_text,
                                    sizeof(entries[n].src_mac_text)) ||
             !mac_text_to_u64(entries[n].src_mac_text,
                              &entries[n].src_mac))) {
            p = end + strlen("</term>");
            continue;
        }
        if (has_dst &&
            (!l2_normalize_mac_text(dst_mac_text, entries[n].dst_mac_text,
                                    sizeof(entries[n].dst_mac_text)) ||
             !mac_text_to_u64(entries[n].dst_mac_text,
                              &entries[n].dst_mac))) {
            p = end + strlen("</term>");
            continue;
        }

        snprintf(entries[n].name, sizeof(entries[n].name), "%s", name);
        snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s",
                 ifname);
        entries[n].port = *port;
        entries[n].has_src_mac = has_src;
        entries[n].has_dst_mac = has_dst;
        if (l2_extract_xml_leaf(p, end, "action", action,
                                sizeof(action)) == 0 && action[0])
            snprintf(entries[n].action, sizeof(entries[n].action),
                     "%s", action);
        else
            snprintf(entries[n].action, sizeof(entries[n].action), "drop");
        n++;
        p = end + strlen("</term>");
    }
    free(xml);
    return n;
}

int l2_collect_acl_independent_intents(
    nl_yang_session *ys, cfg_acl_independent_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports) {
    char *xml;
    char *feature;
    char *feature_end;
    char *g;
    int n = 0;

    if (!ys || !entries || max_entries <= 0 || !ports || n_ports <= 0)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    feature = strstr(xml, "<acl-independent>");
    feature_end = feature ? strstr(feature, "</acl-independent>") : NULL;
    g = feature;
    while (feature && feature_end &&
           (g = strstr(g, "<group>")) && g < feature_end &&
           n < max_entries) {
        char *g_end = strstr(g, "</group>");
        char *first_term;
        char *group_leaf_end;
        char group_name[64];
        char *p;

        if (!g_end || g_end > feature_end)
            break;
        first_term = strstr(g, "<term>");
        group_leaf_end = (first_term && first_term < g_end) ? first_term : g_end;
        if (l2_extract_xml_leaf(g, group_leaf_end, "name", group_name,
                                sizeof(group_name)) != 0 ||
            !group_name[0]) {
            g = g_end + strlen("</group>");
            continue;
        }

        p = g;
        while ((p = strstr(p, "<term>")) && p < g_end && n < max_entries) {
            char *end = strstr(p, "</term>");
            char term_name[64];
            char family[16];
            char vlan[64] = {0};
            char ifname[64] = {0};
            char action[16] = {0};
            char src_mac_text[32] = {0};
            char dst_mac_text[32] = {0};
            char src_ip[16] = {0};
            char dst_ip[16] = {0};
            char src_prefix[32] = {0};
            char dst_prefix[32] = {0};
            char dscp_text[16] = {0};
            char ecn_text[16] = {0};
            char proto_text[16] = {0};
            char src_port_text[16] = {0};
            char dst_port_text[16] = {0};
            char src_port_range_text[16] = {0};
            char dst_port_range_text[16] = {0};
            char tcp_flags_text[16] = {0};
            char tcp_flags_mask_text[16] = {0};
            char rate_text[32] = {0};
            char burst_text[32] = {0};
            const cfg_port_ref *port = NULL;
            struct in_addr addr;
            u32 prefix_ip;
            u32 prefix_mask;
            int prefix_len;
            int range_start;
            int range_end;
            bool has_src_mac;
            bool has_dst_mac;

            if (!end || end > g_end)
                break;
            if (l2_extract_xml_leaf(p, end, "name", term_name,
                                    sizeof(term_name)) != 0 ||
                l2_extract_xml_leaf(p, end, "family", family,
                                    sizeof(family)) != 0) {
                p = end + strlen("</term>");
                continue;
            }

            memset(&entries[n], 0, sizeof(entries[n]));
            entries[n].slot = n;
            snprintf(entries[n].group, sizeof(entries[n].group), "%s",
                     group_name);
            snprintf(entries[n].term, sizeof(entries[n].term), "%s",
                     term_name);
            snprintf(entries[n].family, sizeof(entries[n].family), "%s",
                     family);

            if (l2_extract_xml_leaf(p, end, "vlan", vlan,
                                    sizeof(vlan)) == 0 && vlan[0]) {
                snprintf(entries[n].vlan, sizeof(entries[n].vlan), "%s",
                         vlan);
                entries[n].vid = l2_get_vlan_id(ys, vlan);
                entries[n].inet_match.vid = entries[n].vid;
            }
            if (l2_extract_xml_leaf(p, end, "interface", ifname,
                                    sizeof(ifname)) == 0 && ifname[0]) {
                port = l2_find_port_ref(ports, n_ports, ifname);
                if (port) {
                    snprintf(entries[n].ifname, sizeof(entries[n].ifname),
                             "%s", ifname);
                    entries[n].port = *port;
                    entries[n].inet_match.port = port->hw_port;
                }
            }

            has_src_mac =
                l2_extract_xml_leaf(p, end, "source-mac", src_mac_text,
                                    sizeof(src_mac_text)) == 0 &&
                src_mac_text[0] != '\0';
            has_dst_mac =
                l2_extract_xml_leaf(p, end, "destination-mac", dst_mac_text,
                                    sizeof(dst_mac_text)) == 0 &&
                dst_mac_text[0] != '\0';
            if (has_src_mac &&
                l2_normalize_mac_text(src_mac_text, entries[n].src_mac_text,
                                      sizeof(entries[n].src_mac_text)) &&
                mac_text_to_u64(entries[n].src_mac_text,
                                &entries[n].src_mac)) {
                entries[n].has_src_mac = true;
            }
            if (has_dst_mac &&
                l2_normalize_mac_text(dst_mac_text, entries[n].dst_mac_text,
                                      sizeof(entries[n].dst_mac_text)) &&
                mac_text_to_u64(entries[n].dst_mac_text,
                                &entries[n].dst_mac)) {
                entries[n].has_dst_mac = true;
            }

            if (l2_extract_xml_leaf(p, end, "source-ip", src_ip,
                                    sizeof(src_ip)) == 0 &&
                inet_pton(AF_INET, src_ip, &addr) == 1) {
                snprintf(entries[n].src_ip_text,
                         sizeof(entries[n].src_ip_text), "%s", src_ip);
                entries[n].inet_match.has_src_ip = true;
                entries[n].inet_match.src_ip = ntohl(addr.s_addr);
                entries[n].inet_match.has_src_ip_mask = true;
                entries[n].inet_match.src_ip_mask = 0xffffffffU;
            } else if (l2_extract_xml_leaf(p, end, "source-prefix",
                                           src_prefix,
                                           sizeof(src_prefix)) == 0 &&
                       l2_parse_ipv4_prefix_text(src_prefix, &prefix_ip,
                                                 &prefix_mask,
                                                 &prefix_len)) {
                l2_format_ipv4_text(prefix_ip, entries[n].src_ip_text,
                                    sizeof(entries[n].src_ip_text));
                l2_format_ipv4_prefix_text(prefix_ip, prefix_len,
                                           entries[n].src_prefix_text,
                                           sizeof(entries[n].src_prefix_text));
                entries[n].inet_match.has_src_ip = true;
                entries[n].inet_match.has_src_ip_mask = true;
                entries[n].inet_match.src_ip = prefix_ip;
                entries[n].inet_match.src_ip_mask = prefix_mask;
            }

            if (l2_extract_xml_leaf(p, end, "destination-ip", dst_ip,
                                    sizeof(dst_ip)) == 0 &&
                inet_pton(AF_INET, dst_ip, &addr) == 1) {
                snprintf(entries[n].dst_ip_text,
                         sizeof(entries[n].dst_ip_text), "%s", dst_ip);
                entries[n].inet_match.has_dst_ip = true;
                entries[n].inet_match.dst_ip = ntohl(addr.s_addr);
                entries[n].inet_match.has_dst_ip_mask = true;
                entries[n].inet_match.dst_ip_mask = 0xffffffffU;
            } else if (l2_extract_xml_leaf(p, end, "destination-prefix",
                                           dst_prefix,
                                           sizeof(dst_prefix)) == 0 &&
                       l2_parse_ipv4_prefix_text(dst_prefix, &prefix_ip,
                                                 &prefix_mask,
                                                 &prefix_len)) {
                l2_format_ipv4_text(prefix_ip, entries[n].dst_ip_text,
                                    sizeof(entries[n].dst_ip_text));
                l2_format_ipv4_prefix_text(prefix_ip, prefix_len,
                                           entries[n].dst_prefix_text,
                                           sizeof(entries[n].dst_prefix_text));
                entries[n].inet_match.has_dst_ip = true;
                entries[n].inet_match.has_dst_ip_mask = true;
                entries[n].inet_match.dst_ip = prefix_ip;
                entries[n].inet_match.dst_ip_mask = prefix_mask;
            }

            if (l2_extract_xml_leaf(p, end, "dscp", dscp_text,
                                    sizeof(dscp_text)) == 0) {
                entries[n].inet_match.has_dscp = true;
                entries[n].inet_match.dscp = atoi(dscp_text);
            }
            if (l2_extract_xml_leaf(p, end, "ecn", ecn_text,
                                    sizeof(ecn_text)) == 0) {
                entries[n].inet_match.has_ecn = true;
                entries[n].inet_match.ecn = atoi(ecn_text);
            }
            if (l2_extract_xml_leaf(p, end, "protocol", proto_text,
                                    sizeof(proto_text)) == 0) {
                entries[n].inet_match.has_protocol = true;
                entries[n].inet_match.protocol = atoi(proto_text);
            }
            if (l2_extract_xml_leaf(p, end, "source-port", src_port_text,
                                    sizeof(src_port_text)) == 0) {
                entries[n].inet_match.has_src_port = true;
                entries[n].inet_match.src_port = atoi(src_port_text);
            }
            if (l2_extract_xml_leaf(p, end, "destination-port",
                                    dst_port_text,
                                    sizeof(dst_port_text)) == 0) {
                entries[n].inet_match.has_dst_port = true;
                entries[n].inet_match.dst_port = atoi(dst_port_text);
            }
            if (l2_extract_xml_leaf(p, end, "source-port-range",
                                    src_port_range_text,
                                    sizeof(src_port_range_text)) == 0 &&
                l2_parse_port_range_text(src_port_range_text,
                                         &range_start, &range_end)) {
                entries[n].inet_match.has_src_port_range = true;
                entries[n].inet_match.src_port_start = range_start;
                entries[n].inet_match.src_port_end = range_end;
                snprintf(entries[n].src_port_range_text,
                         sizeof(entries[n].src_port_range_text), "%d-%d",
                         range_start, range_end);
            }
            if (l2_extract_xml_leaf(p, end, "destination-port-range",
                                    dst_port_range_text,
                                    sizeof(dst_port_range_text)) == 0 &&
                l2_parse_port_range_text(dst_port_range_text,
                                         &range_start, &range_end)) {
                entries[n].inet_match.has_dst_port_range = true;
                entries[n].inet_match.dst_port_start = range_start;
                entries[n].inet_match.dst_port_end = range_end;
                snprintf(entries[n].dst_port_range_text,
                         sizeof(entries[n].dst_port_range_text), "%d-%d",
                         range_start, range_end);
            }
            if (l2_extract_xml_leaf(p, end, "tcp-flags", tcp_flags_text,
                                    sizeof(tcp_flags_text)) == 0) {
                entries[n].inet_match.has_tcp_flags = true;
                entries[n].inet_match.tcp_flags = atoi(tcp_flags_text);
                entries[n].inet_match.has_tcp_flags_mask = true;
                entries[n].inet_match.tcp_flags_mask = 63;
            }
            if (l2_extract_xml_leaf(p, end, "tcp-flags-mask",
                                    tcp_flags_mask_text,
                                    sizeof(tcp_flags_mask_text)) == 0) {
                entries[n].inet_match.has_tcp_flags_mask = true;
                entries[n].inet_match.tcp_flags_mask =
                    atoi(tcp_flags_mask_text);
            }

            if (l2_extract_xml_leaf(p, end, "action", action,
                                    sizeof(action)) == 0 && action[0])
                snprintf(entries[n].action, sizeof(entries[n].action), "%s",
                         action);
            else
                snprintf(entries[n].action, sizeof(entries[n].action), "%s",
                         strcmp(family, "policer") == 0 ? "policer" :
                         "drop");
            if (strcmp(entries[n].action, "count") == 0)
                entries[n].inet_match.count_only = true;

            if (l2_extract_xml_leaf(p, end, "bandwidth", rate_text,
                                    sizeof(rate_text)) == 0)
                entries[n].rate_kbps = atoi(rate_text);
            entries[n].burst_bytes = CFG_ACL_POLICER_DEFAULT_BURST_BYTES;
            if (l2_extract_xml_leaf(p, end, "burst-size", burst_text,
                                    sizeof(burst_text)) == 0)
                entries[n].burst_bytes = atoi(burst_text);

            n++;
            p = end + strlen("</term>");
        }
        g = g_end + strlen("</group>");
    }
    free(xml);
    return n;
}

typedef struct {
    const char *name;
    int rate_pps;
    int burst_pkts;
} default_copp_class;

static const default_copp_class DEFAULT_COPP_CLASSES[] = {
    { "rstp", 256, 512 },
    { "lldp", 128, 256 },
    { "lacp", 512, 1024 },
    { "igmp", 512, 1024 },
    { "arp", 1024, 2048 },
    { "icmp", 512, 1024 },
    { "ospf", 512, 1024 },
    { "bgp", 512, 1024 },
};

int l2_collect_copp_class_intents(nl_yang_session *ys,
                                  cfg_copp_class_intent *entries,
                                  int max_entries) {
    if (!ys || !entries || max_entries <= 0)
        return 0;

    int n = 0;
    for (size_t i = 0; i < sizeof(DEFAULT_COPP_CLASSES) /
                           sizeof(DEFAULT_COPP_CLASSES[0]) &&
                     n < max_entries; i++) {
        char path[256];
        const char *rate;
        const char *burst;

        snprintf(entries[n].class_name, sizeof(entries[n].class_name), "%s",
                 DEFAULT_COPP_CLASSES[i].name);
        entries[n].rate_pps = DEFAULT_COPP_CLASSES[i].rate_pps;
        entries[n].burst_pkts = DEFAULT_COPP_CLASSES[i].burst_pkts;

        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/control-plane/protection"
                 "/class[name='%s']/rate-pps",
                 DEFAULT_COPP_CLASSES[i].name);
        rate = nl_yang_get(ys, path);
        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/control-plane/protection"
                 "/class[name='%s']/burst-pkts",
                 DEFAULT_COPP_CLASSES[i].name);
        burst = nl_yang_get(ys, path);
        if (rate && rate[0])
            entries[n].rate_pps = atoi(rate);
        if (burst && burst[0])
            entries[n].burst_pkts = atoi(burst);
        n++;
    }
    return n;
}

static int qos_trust_mode_from_text(const char *text) {
    if (!text || !text[0] || strcmp(text, "ieee-802.1p") == 0)
        return HAL_QOS_TRUST_IEEE8021P;
    if (strcmp(text, "dscp") == 0)
        return HAL_QOS_TRUST_DSCP;
    if (strcmp(text, "none") == 0)
        return HAL_QOS_TRUST_NONE;
    return -1;
}

int l2_collect_qos_interface_intents(nl_yang_session *ys,
                                     cfg_qos_interface_intent *entries,
                                     int max_entries) {
    char *xml;
    char *cos;
    char *interfaces;
    char *interfaces_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    if (!cos) {
        free(xml);
        return 0;
    }
    interfaces = strstr(cos, "<interfaces>");
    if (!interfaces) {
        free(xml);
        return 0;
    }
    interfaces_end = strstr(interfaces, "</interfaces>");
    if (!interfaces_end) {
        free(xml);
        return 0;
    }

    p = interfaces;
    while ((p = strstr(p, "<interface>")) &&
           p < interfaces_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char trust[32] = {0};
        char priority[32] = {0};

        if (!end || end > interfaces_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0) {
            snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", name);
            entries[n].trust_mode = HAL_QOS_TRUST_IEEE8021P;
            entries[n].default_priority = 0;
            if (l2_extract_xml_leaf(p, end, "trust", trust,
                                    sizeof(trust)) == 0)
                entries[n].trust_mode = qos_trust_mode_from_text(trust);
            if (l2_extract_xml_leaf(p, end, "default-priority", priority,
                                    sizeof(priority)) == 0)
                entries[n].default_priority = atoi(priority);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

int l2_collect_qos_pfc_intents(nl_yang_session *ys,
                               cfg_qos_pfc_intent *entries,
                               int max_entries) {
    char *xml;
    char *cos;
    char *interfaces;
    char *interfaces_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    if (!cos) {
        free(xml);
        return 0;
    }
    interfaces = strstr(cos, "<interfaces>");
    if (!interfaces) {
        free(xml);
        return 0;
    }
    interfaces_end = strstr(interfaces, "</interfaces>");
    if (!interfaces_end) {
        free(xml);
        return 0;
    }

    p = interfaces;
    while ((p = strstr(p, "<interface>")) &&
           p < interfaces_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char *pfc;
        char *pfc_end;
        char name[64];
        char rx[32] = {0};
        char tx[32] = {0};
        char lossless[32] = {0};
        char shared[32] = {0};

        if (!end || end > interfaces_end)
            break;
        pfc = strstr(p, "<priority-flow-control>");
        pfc_end = pfc ? strstr(pfc, "</priority-flow-control>") : NULL;
        if (pfc && pfc < end && pfc_end && pfc_end < end &&
            l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0) {
            snprintf(entries[n].ifname, sizeof(entries[n].ifname),
                     "%s", name);
            entries[n].rx_class_mask = 0;
            entries[n].tx_class_mask = 0;
            entries[n].lossless_smp_mask = 0;
            entries[n].shared_pause_mask = 0;
            entries[n].watchdog = fm10k_pfc_wd_default_policy();
            if (l2_extract_xml_leaf(pfc, pfc_end, "rx-class-mask",
                                    rx, sizeof(rx)) == 0)
                entries[n].rx_class_mask = atoi(rx);
            if (l2_extract_xml_leaf(pfc, pfc_end, "tx-class-mask",
                                    tx, sizeof(tx)) == 0)
                entries[n].tx_class_mask = atoi(tx);
            if (l2_extract_xml_leaf(pfc, pfc_end, "lossless-smp-mask",
                                    lossless, sizeof(lossless)) == 0)
                entries[n].lossless_smp_mask = atoi(lossless);
            if (l2_extract_xml_leaf(pfc, pfc_end, "shared-pause-mask",
                                    shared, sizeof(shared)) == 0)
                entries[n].shared_pause_mask = atoi(shared);
            char watchdog[32] = {0};
            if (l2_extract_xml_leaf(pfc, pfc_end, "watchdog-detect-ms", watchdog, sizeof(watchdog)) == 0)
                entries[n].watchdog.detect_ms = (uint32_t)strtoul(watchdog, NULL, 10);
            if (l2_extract_xml_leaf(pfc, pfc_end, "watchdog-recovery-ms", watchdog, sizeof(watchdog)) == 0)
                entries[n].watchdog.recovery_ms = (uint32_t)strtoul(watchdog, NULL, 10);
            if (l2_extract_xml_leaf(pfc, pfc_end, "watchdog-cooldown-ms", watchdog, sizeof(watchdog)) == 0)
                entries[n].watchdog.cooldown_ms = (uint32_t)strtoul(watchdog, NULL, 10);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

int l2_collect_qos_priority_map_intents(
    nl_yang_session *ys, cfg_qos_priority_map_intent *entries,
    int max_entries) {
    char *xml;
    char *cos;
    char *forwarding;
    char *forwarding_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    if (!cos) {
        free(xml);
        return 0;
    }
    forwarding = strstr(cos, "<forwarding>");
    if (!forwarding) {
        free(xml);
        return 0;
    }
    forwarding_end = strstr(forwarding, "</forwarding>");
    if (!forwarding_end) {
        free(xml);
        return 0;
    }

    p = forwarding;
    while ((p = strstr(p, "<switch-priority>")) &&
           p < forwarding_end && n < max_entries) {
        char *end = strstr(p, "</switch-priority>");
        char priority[32];
        char tc[32];

        if (!end || end > forwarding_end)
            break;
        if (l2_extract_xml_leaf(p, end, "priority", priority,
                                sizeof(priority)) == 0 &&
            l2_extract_xml_leaf(p, end, "traffic-class", tc,
                                sizeof(tc)) == 0) {
            entries[n].switch_priority = atoi(priority);
            entries[n].traffic_class = atoi(tc);
            n++;
        }
        p = end + strlen("</switch-priority>");
    }

    free(xml);
    return n;
}

static char *qos_scheduler_find_template(char *scheduler,
                                         char *scheduler_end,
                                         const char *name,
                                         char **template_end) {
    char *p;

    if (template_end)
        *template_end = NULL;
    if (!scheduler || !scheduler_end || !name || !name[0])
        return NULL;

    p = scheduler;
    while ((p = strstr(p, "<template>")) && p < scheduler_end) {
        char *end = strstr(p, "</template>");
        char tmpl_name[64] = {0};

        if (!end || end > scheduler_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", tmpl_name,
                                sizeof(tmpl_name)) == 0 &&
            strcmp(tmpl_name, name) == 0) {
            if (template_end)
                *template_end = end;
            return p;
        }
        p = end + strlen("</template>");
    }

    return NULL;
}

static int qos_scheduler_collect_tc_maps_from_block(
    char *block, char *block_end, const char *ifname,
    cfg_qos_scheduler_tc_map_intent *entries, int max_entries, int n,
    bool overlay) {
    char *tc;

    if (!block || !block_end || !ifname || !entries)
        return n;

    tc = block;
    while ((tc = strstr(tc, "<traffic-class>")) && tc < block_end) {
        char *tc_end = strstr(tc, "</traffic-class>");
        char class_id[32];
        char group[32];

        if (!tc_end || tc_end > block_end)
            break;
        if (l2_extract_xml_leaf(tc, tc_end, "class", class_id,
                                sizeof(class_id)) == 0 &&
            l2_extract_xml_leaf(tc, tc_end, "shaping-group", group,
                                sizeof(group)) == 0) {
            int existing = overlay ?
                l2_find_qos_scheduler_tc_map(entries, n, ifname,
                                             atoi(class_id)) : -1;
            if (existing >= 0) {
                entries[existing].shaping_group = atoi(group);
                tc = tc_end + strlen("</traffic-class>");
                continue;
            }
            if (n >= max_entries)
                break;
            snprintf(entries[n].ifname, sizeof(entries[n].ifname),
                     "%s", ifname);
            entries[n].traffic_class = atoi(class_id);
            entries[n].shaping_group = atoi(group);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        tc = tc_end + strlen("</traffic-class>");
    }

    return n;
}

static int qos_scheduler_collect_groups_from_block(
    char *block, char *block_end, const char *ifname,
    cfg_qos_scheduler_group_intent *entries, int max_entries, int n,
    bool overlay) {
    char *group;

    if (!block || !block_end || !ifname || !entries)
        return n;

    group = block;
    while ((group = strstr(group, "<group>")) && group < block_end) {
        char *group_end = strstr(group, "</group>");
        char group_id[32];
        char strict[32] = {0};
        char weight[32] = {0};

        if (!group_end || group_end > block_end)
            break;
        if (l2_extract_xml_leaf(group, group_end, "id", group_id,
                                sizeof(group_id)) == 0) {
            bool has_strict =
                l2_extract_xml_leaf(group, group_end, "strict-priority",
                                    strict, sizeof(strict)) == 0;
            bool has_weight =
                l2_extract_xml_leaf(group, group_end, "weight",
                                    weight, sizeof(weight)) == 0;
            int existing = overlay ?
                l2_find_qos_scheduler_group(entries, n, ifname,
                                            atoi(group_id)) : -1;
            if (existing >= 0) {
                if (has_strict)
                    entries[existing].strict_priority =
                        l2_bool_leaf_true(strict) ? 1 : 0;
                if (has_weight)
                    entries[existing].weight = atoi(weight);
                group = group_end + strlen("</group>");
                continue;
            }
            if (n >= max_entries)
                break;
            snprintf(entries[n].ifname, sizeof(entries[n].ifname),
                     "%s", ifname);
            entries[n].group = atoi(group_id);
            entries[n].strict_priority = 1;
            entries[n].weight = 0;
            if (has_strict)
                entries[n].strict_priority =
                    l2_bool_leaf_true(strict) ? 1 : 0;
            if (has_weight)
                entries[n].weight = atoi(weight);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        group = group_end + strlen("</group>");
    }

    return n;
}

static int qos_scheduler_collect_group_shaping_from_block(
    char *block, char *block_end, const char *ifname,
    cfg_qos_scheduler_group_shaping_intent *entries,
    int max_entries, int n, bool overlay) {
    char *group;

    if (!block || !block_end || !ifname || !entries)
        return n;

    group = block;
    while ((group = strstr(group, "<group>")) && group < block_end) {
        char *group_end = strstr(group, "</group>");
        char group_id[32];
        char rate[32] = {0};
        char burst[32] = {0};
        bool has_rate;
        bool has_burst;

        if (!group_end || group_end > block_end)
            break;
        has_rate = l2_extract_xml_leaf(group, group_end, "rate-bps",
                                       rate, sizeof(rate)) == 0;
        has_burst = l2_extract_xml_leaf(group, group_end, "burst-bits",
                                        burst, sizeof(burst)) == 0;
        if ((has_rate || has_burst) &&
            l2_extract_xml_leaf(group, group_end, "id", group_id,
                                sizeof(group_id)) == 0) {
            int existing = overlay ?
                l2_find_qos_scheduler_group_shaping(entries, n, ifname,
                                                    atoi(group_id)) : -1;
            if (existing >= 0) {
                if (has_rate)
                    entries[existing].rate_bps = strtoull(rate, NULL, 0);
                if (has_burst)
                    entries[existing].burst_bits = strtoull(burst, NULL, 0);
                group = group_end + strlen("</group>");
                continue;
            }
            if (n >= max_entries)
                break;
            snprintf(entries[n].ifname, sizeof(entries[n].ifname),
                     "%s", ifname);
            entries[n].group = atoi(group_id);
            entries[n].rate_bps = has_rate ?
                strtoull(rate, NULL, 0) : 0;
            entries[n].burst_bits = has_burst ?
                strtoull(burst, NULL, 0) :
                CFG_QOS_SCHEDULER_GROUP_DEFAULT_BURST_BITS;
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        group = group_end + strlen("</group>");
    }

    return n;
}

static int qos_scheduler_collect_port_from_block(
    char *block, char *block_end, const char *ifname,
    cfg_qos_scheduler_port_intent *entries, int max_entries, int n,
    bool overlay) {
    char mask[32];

    if (!block || !block_end || !ifname || !entries)
        return n;

    if (l2_extract_xml_leaf(block, block_end, "traffic-class-enable-mask",
                            mask, sizeof(mask)) == 0) {
        int existing = overlay ?
            l2_find_qos_scheduler_port_by_ifname(entries, n, ifname) : -1;
        if (existing >= 0) {
            entries[existing].traffic_class_enable_mask =
                (int)strtol(mask, NULL, 0);
            return n;
        }
        if (n >= max_entries)
            return n;
        snprintf(entries[n].ifname, sizeof(entries[n].ifname),
                 "%s", ifname);
        entries[n].traffic_class_enable_mask =
            (int)strtol(mask, NULL, 0);
        memset(&entries[n].port, 0, sizeof(entries[n].port));
        n++;
    }

    return n;
}

int l2_collect_qos_scheduler_tc_map_intents(
    nl_yang_session *ys, cfg_qos_scheduler_tc_map_intent *entries,
    int max_entries) {
    char *xml;
    char *cos;
    char *scheduler;
    char *interfaces;
    char *interfaces_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    if (!cos) {
        free(xml);
        return 0;
    }
    scheduler = strstr(cos, "<scheduler>");
    if (!scheduler) {
        free(xml);
        return 0;
    }
    interfaces = strstr(scheduler, "<interfaces>");
    if (!interfaces) {
        free(xml);
        return 0;
    }
    interfaces_end = strstr(interfaces, "</interfaces>");
    if (!interfaces_end) {
        free(xml);
        return 0;
    }

    p = interfaces;
    while ((p = strstr(p, "<interface>")) &&
           p < interfaces_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char template_name[64] = {0};
        char *template_block = NULL;
        char *template_end = NULL;

        if (!end || end > interfaces_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) != 0) {
            p = end + strlen("</interface>");
            continue;
        }

        if (l2_extract_xml_leaf(p, end, "template", template_name,
                                sizeof(template_name)) == 0) {
            template_block = qos_scheduler_find_template(
                scheduler, interfaces_end, template_name, &template_end);
            n = qos_scheduler_collect_tc_maps_from_block(
                template_block, template_end, name, entries, max_entries, n,
                false);
        }
        n = qos_scheduler_collect_tc_maps_from_block(
            p, end, name, entries, max_entries, n, true);
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

int l2_collect_qos_scheduler_group_intents(
    nl_yang_session *ys, cfg_qos_scheduler_group_intent *entries,
    int max_entries) {
    char *xml;
    char *cos;
    char *scheduler;
    char *interfaces;
    char *interfaces_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    if (!cos) {
        free(xml);
        return 0;
    }
    scheduler = strstr(cos, "<scheduler>");
    if (!scheduler) {
        free(xml);
        return 0;
    }
    interfaces = strstr(scheduler, "<interfaces>");
    if (!interfaces) {
        free(xml);
        return 0;
    }
    interfaces_end = strstr(interfaces, "</interfaces>");
    if (!interfaces_end) {
        free(xml);
        return 0;
    }

    p = interfaces;
    while ((p = strstr(p, "<interface>")) &&
           p < interfaces_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char template_name[64] = {0};
        char *template_block = NULL;
        char *template_end = NULL;

        if (!end || end > interfaces_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) != 0) {
            p = end + strlen("</interface>");
            continue;
        }

        if (l2_extract_xml_leaf(p, end, "template", template_name,
                                sizeof(template_name)) == 0) {
            template_block = qos_scheduler_find_template(
                scheduler, interfaces_end, template_name, &template_end);
            n = qos_scheduler_collect_groups_from_block(
                template_block, template_end, name, entries, max_entries, n,
                false);
        }
        n = qos_scheduler_collect_groups_from_block(
            p, end, name, entries, max_entries, n, true);
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

int l2_collect_qos_scheduler_group_shaping_intents(
    nl_yang_session *ys, cfg_qos_scheduler_group_shaping_intent *entries,
    int max_entries) {
    char *xml;
    char *cos;
    char *scheduler;
    char *interfaces;
    char *interfaces_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    if (!cos) {
        free(xml);
        return 0;
    }
    scheduler = strstr(cos, "<scheduler>");
    if (!scheduler) {
        free(xml);
        return 0;
    }
    interfaces = strstr(scheduler, "<interfaces>");
    if (!interfaces) {
        free(xml);
        return 0;
    }
    interfaces_end = strstr(interfaces, "</interfaces>");
    if (!interfaces_end) {
        free(xml);
        return 0;
    }

    p = interfaces;
    while ((p = strstr(p, "<interface>")) &&
           p < interfaces_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char template_name[64] = {0};
        char *template_block = NULL;
        char *template_end = NULL;

        if (!end || end > interfaces_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) != 0) {
            p = end + strlen("</interface>");
            continue;
        }

        if (l2_extract_xml_leaf(p, end, "template", template_name,
                                sizeof(template_name)) == 0) {
            template_block = qos_scheduler_find_template(
                scheduler, interfaces_end, template_name, &template_end);
            n = qos_scheduler_collect_group_shaping_from_block(
                template_block, template_end, name, entries,
                max_entries, n, false);
        }
        n = qos_scheduler_collect_group_shaping_from_block(
            p, end, name, entries, max_entries, n, true);
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

int l2_collect_qos_scheduler_port_intents(
    nl_yang_session *ys, cfg_qos_scheduler_port_intent *entries,
    int max_entries) {
    char *xml;
    char *cos;
    char *scheduler;
    char *interfaces;
    char *interfaces_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    if (!cos) {
        free(xml);
        return 0;
    }
    scheduler = strstr(cos, "<scheduler>");
    if (!scheduler) {
        free(xml);
        return 0;
    }
    interfaces = strstr(scheduler, "<interfaces>");
    if (!interfaces) {
        free(xml);
        return 0;
    }
    interfaces_end = strstr(interfaces, "</interfaces>");
    if (!interfaces_end) {
        free(xml);
        return 0;
    }

    p = interfaces;
    while ((p = strstr(p, "<interface>")) &&
           p < interfaces_end && n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char template_name[64] = {0};
        char *template_block = NULL;
        char *template_end = NULL;

        if (!end || end > interfaces_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0) {
            if (l2_extract_xml_leaf(p, end, "template", template_name,
                                    sizeof(template_name)) == 0) {
                template_block = qos_scheduler_find_template(
                    scheduler, interfaces_end, template_name, &template_end);
                n = qos_scheduler_collect_port_from_block(
                    template_block, template_end, name, entries,
                    max_entries, n, false);
            }
            n = qos_scheduler_collect_port_from_block(
                p, end, name, entries, max_entries, n, true);
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return n;
}

static int qos_watermark_attr_from_leaf(const char *leaf) {
    if (!leaf)
        return 0;
    if (strcmp(leaf, "tx-hog") == 0)
        return HAL_QOS_WATERMARK_ATTR_TX_HOG;
    if (strcmp(leaf, "tx-private") == 0)
        return HAL_QOS_WATERMARK_ATTR_TX_PRIVATE;
    if (strcmp(leaf, "soft-drop") == 0)
        return HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP;
    if (strcmp(leaf, "soft-drop-jitter") == 0)
        return HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER;
    if (strcmp(leaf, "soft-drop-hog") == 0)
        return HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
    return 0;
}

int l2_collect_qos_watermark_intents(
    nl_yang_session *ys, cfg_qos_watermark_intent *entries,
    int max_entries) {
    char *xml;
    char *cos;
    char *watermarks;
    char *watermarks_end;
    char *p;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    watermarks = cos ? strstr(cos, "<watermarks>") : NULL;
    watermarks_end = watermarks ? strstr(watermarks, "</watermarks>") : NULL;
    p = watermarks;
    while (watermarks && watermarks_end &&
           (p = strstr(p, "<interface>")) && p < watermarks_end &&
           n < max_entries) {
        char *end = strstr(p, "</interface>");
        char name[64];
        char *tc;

        if (!end || end > watermarks_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) != 0) {
            p = end + strlen("</interface>");
            continue;
        }
        tc = p;
        while ((tc = strstr(tc, "<traffic-class>")) &&
               tc < end && n < max_entries) {
            char *tc_end = strstr(tc, "</traffic-class>");
            char class_id[32];
            const char *leaves[] = {"tx-hog", "tx-private"};

            if (!tc_end || tc_end > end)
                break;
            if (l2_extract_xml_leaf(tc, tc_end, "class",
                                    class_id, sizeof(class_id)) != 0) {
                tc = tc_end + strlen("</traffic-class>");
                continue;
            }
            for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]) &&
                               n < max_entries; i++) {
                char value[32];
                if (l2_extract_xml_leaf(tc, tc_end, leaves[i],
                                        value, sizeof(value)) != 0)
                    continue;
                snprintf(entries[n].ifname, sizeof(entries[n].ifname),
                         "%s", name);
                entries[n].traffic_class = atoi(class_id);
                entries[n].attr = qos_watermark_attr_from_leaf(leaves[i]);
                entries[n].value = atoi(value);
                memset(&entries[n].port, 0, sizeof(entries[n].port));
                n++;
            }
            tc = tc_end + strlen("</traffic-class>");
        }
        p = end + strlen("</interface>");
    }

    p = watermarks;
    while (watermarks && watermarks_end &&
           (p = strstr(p, "<switch-priority>")) && p < watermarks_end &&
           n < max_entries) {
        char *end = strstr(p, "</switch-priority>");
        char priority[32];
        const char *leaves[] = {
            "soft-drop",
            "soft-drop-jitter",
            "soft-drop-hog",
        };

        if (!end || end > watermarks_end)
            break;
        if (l2_extract_xml_leaf(p, end, "priority",
                                priority, sizeof(priority)) != 0) {
            p = end + strlen("</switch-priority>");
            continue;
        }
        for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]) &&
                           n < max_entries; i++) {
            char value[32];
            if (l2_extract_xml_leaf(p, end, leaves[i],
                                    value, sizeof(value)) != 0)
                continue;
            snprintf(entries[n].ifname, sizeof(entries[n].ifname),
                     "switch-priority");
            entries[n].traffic_class = atoi(priority);
            entries[n].attr = qos_watermark_attr_from_leaf(leaves[i]);
            entries[n].value = atoi(value);
            memset(&entries[n].port, 0, sizeof(entries[n].port));
            n++;
        }
        p = end + strlen("</switch-priority>");
    }

    free(xml);
    return n;
}

static int mirror_direction_from_text(const char *text) {
    if (!text || !text[0] || strcmp(text, "ingress") == 0)
        return HAL_MIRROR_DIRECTION_INGRESS;
    if (strcmp(text, "egress") == 0)
        return HAL_MIRROR_DIRECTION_EGRESS;
    if (strcmp(text, "both") == 0)
        return HAL_MIRROR_DIRECTION_BOTH;
    return 0;
}

static void sort_mirror_sources(cfg_port_mirror_intent *intent) {
    if (!intent)
        return;
    for (int i = 1; i < intent->n_sources; i++) {
        cfg_port_mirror_source source = intent->sources[i];
        int j = i - 1;

        while (j >= 0 && intent->sources[j].port.hw_port >
                         source.port.hw_port) {
            intent->sources[j + 1] = intent->sources[j];
            j--;
        }
        intent->sources[j + 1] = source;
    }
}

int l2_collect_port_mirror_intent(nl_yang_session *ys,
                                  cfg_port_mirror_intent *intent,
                                  const cfg_port_ref *ports, int n_ports) {
    char *xml;
    char *forwarding;
    char *mirroring;
    char *instance;
    char *instance_end;
    char *input;
    char *input_end;
    char *p;

    if (!intent)
        return 0;
    memset(intent, 0, sizeof(*intent));
    if (!ys)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;
    forwarding = strstr(xml, "<forwarding-options>");
    mirroring = forwarding ? strstr(forwarding, "<port-mirroring>") : NULL;
    instance = mirroring ? strstr(mirroring, "<instance>") : NULL;
    instance_end = instance ? strstr(instance, "</instance>") : NULL;
    if (!instance || !instance_end) {
        free(xml);
        return 0;
    }

    intent->exists = true;
    (void)l2_extract_xml_leaf(instance, instance_end, "name",
                              intent->name, sizeof(intent->name));
    p = strstr(instance, "<output>");
    if (p && p < instance_end) {
        char *end = strstr(p, "</output>");
        if (end && end < instance_end)
            (void)l2_extract_xml_leaf(
                p, end, "interface", intent->destination_ifname,
                sizeof(intent->destination_ifname));
    }
    const cfg_port_ref *destination = l2_find_port_ref(
        ports, n_ports, intent->destination_ifname);
    if (destination)
        intent->destination = *destination;

    input = strstr(instance, "<input>");
    input_end = input ? strstr(input, "</input>") : NULL;
    p = input;
    while (input && input_end &&
           (p = strstr(p, "<interface>")) && p < input_end &&
           intent->n_sources < NETLAB_MIRROR_MAX_SOURCES) {
        char *end = strstr(p, "</interface>");
        cfg_port_mirror_source *source;
        char direction[16] = {0};

        if (!end || end > input_end)
            break;
        source = &intent->sources[intent->n_sources];
        memset(source, 0, sizeof(*source));
        if (l2_extract_xml_leaf(p, end, "name", source->ifname,
                                sizeof(source->ifname)) == 0) {
            const cfg_port_ref *port = l2_find_port_ref(
                ports, n_ports, source->ifname);
            if (port)
                source->port = *port;
            (void)l2_extract_xml_leaf(p, end, "direction", direction,
                                      sizeof(direction));
            source->direction = mirror_direction_from_text(direction);
            intent->n_sources++;
        }
        p = end + strlen("</interface>");
    }
    sort_mirror_sources(intent);
    free(xml);
    return 1;
}

bool l2_port_mirror_same(const cfg_port_mirror_intent *a,
                         const cfg_port_mirror_intent *b) {
    if (!a || !b || a->exists != b->exists)
        return false;
    if (!a->exists)
        return true;
    if (a->destination.hw_port != b->destination.hw_port ||
        a->n_sources != b->n_sources)
        return false;
    for (int i = 0; i < a->n_sources; i++) {
        if (a->sources[i].port.hw_port != b->sources[i].port.hw_port ||
            a->sources[i].direction != b->sources[i].direction)
            return false;
    }
    return true;
}

bool l2_parse_igmp_group(const char *text, u32 *group_ip, u8 mac[6]) {
    struct in_addr addr;
    u32 value;

    if (!text || inet_pton(AF_INET, text, &addr) != 1)
        return false;
    value = ntohl(addr.s_addr);
    if (value < 0xe0000100U || value > 0xefffffffU)
        return false;
    if (group_ip)
        *group_ip = value;
    if (mac) {
        mac[0] = 0x01;
        mac[1] = 0x00;
        mac[2] = 0x5e;
        mac[3] = (u8)((value >> 16) & 0x7f);
        mac[4] = (u8)((value >> 8) & 0xff);
        mac[5] = (u8)(value & 0xff);
    }
    return true;
}

int l2_collect_igmp_scope_intents(nl_yang_session *ys,
    cfg_igmp_scope_intent *entries, int max_entries,
    const cfg_port_ref *ports, int n_ports) {
    char *xml = ys ? nl_yang_to_xml(ys) : NULL;
    if (!xml || !entries || max_entries <= 0) { free(xml); return -1; }
    const char *igmp = strstr(xml, "<igmp-snooping>");
    const char *limit = igmp ? strstr(igmp, "</igmp-snooping>") : NULL;
    const char *vlan = igmp;
    int count = 0;
    while (limit && (vlan = strstr(vlan, "<vlan>")) && vlan < limit) {
        const char *end = strstr(vlan, "</vlan>");
        char name[64] = {0};
        if (!end || end > limit) { count = -1; break; }
        (void)l2_extract_xml_leaf(vlan, end, "name", name, sizeof(name));
        const char *iface = vlan;
        while ((iface = strstr(iface, "<interface>")) && iface < end) {
            const char *iface_end = strstr(iface, "</interface>");
            if (!iface_end || iface_end > end) { free(xml); return -1; }
            if (count == max_entries) { free(xml); return max_entries + 1; }
            cfg_igmp_scope_intent *entry = &entries[count++];
            memset(entry, 0, sizeof(*entry));
            snprintf(entry->vlan, sizeof(entry->vlan), "%s", name);
            entry->vid = l2_get_vlan_id(ys, name);
            (void)l2_extract_xml_leaf(iface, iface_end, "name", entry->ifname, sizeof(entry->ifname));
            const cfg_port_ref *port = l2_find_port_ref(ports, n_ports, entry->ifname);
            if (port) entry->port = *port;
            char value[16] = {0}, path[256];
            entry->mrouter = l2_extract_xml_leaf(iface, iface_end, "mrouter", value, sizeof(value)) == 0 &&
                !strcmp(value, "true");
            entry->fast_leave = l2_extract_xml_leaf(iface, iface_end, "fast-leave", value, sizeof(value)) == 0 &&
                !strcmp(value, "true");
            snprintf(path, sizeof(path), "/netlab:netlab-config/interfaces/interface[name='%s']/fm10k-port/direct-receiver", entry->ifname);
            const char *direct = nl_yang_get(ys, path);
            entry->direct_receiver = direct && !strcmp(direct, "true");
            iface = iface_end + strlen("</interface>");
        }
        vlan = end + strlen("</vlan>");
    }
    free(xml);
    return count;
}

int l2_collect_igmp_listener_intents(
    nl_yang_session *ys, cfg_igmp_listener_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports) {
    char *xml;
    char *igmp;
    char *igmp_end;
    char *vlan;
    int n = 0;

    if (!ys || !entries || max_entries <= 0)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;
    igmp = strstr(xml, "<igmp-snooping>");
    igmp_end = igmp ? strstr(igmp, "</igmp-snooping>") : NULL;
    vlan = igmp;
    while (igmp && igmp_end &&
           (vlan = strstr(vlan, "<vlan>")) && vlan < igmp_end) {
        char *vlan_end = strstr(vlan, "</vlan>");
        char vlan_name[64] = {0};
        char *iface;

        if (!vlan_end || vlan_end > igmp_end)
            break;
        (void)l2_extract_xml_leaf(vlan, vlan_end, "name", vlan_name,
                                  sizeof(vlan_name));
        iface = vlan;
        while ((iface = strstr(iface, "<interface>")) && iface < vlan_end) {
            char *iface_end = strstr(iface, "</interface>");
            char ifname[64] = {0};
            char *group;

            if (!iface_end || iface_end > vlan_end)
                break;
            (void)l2_extract_xml_leaf(iface, iface_end, "name", ifname,
                                      sizeof(ifname));
            group = iface;
            while ((group = strstr(group, "<static-group>")) &&
                   group < iface_end && n < max_entries) {
                char *group_end = strstr(group, "</static-group>");
                cfg_igmp_listener_intent *entry;
                const cfg_port_ref *port;

                if (!group_end || group_end > iface_end)
                    break;
                entry = &entries[n];
                memset(entry, 0, sizeof(*entry));
                snprintf(entry->vlan, sizeof(entry->vlan), "%s", vlan_name);
                entry->vid = l2_get_vlan_id(ys, vlan_name);
                snprintf(entry->ifname, sizeof(entry->ifname), "%s", ifname);
                if ((size_t)(group_end - (group + 14)) <
                    sizeof(entry->group)) {
                    size_t len = (size_t)(group_end - (group + 14));
                    memcpy(entry->group, group + 14, len);
                    entry->group[len] = '\0';
                }
                port = l2_find_port_ref(ports, n_ports, ifname);
                if (port)
                    entry->port = *port;
                (void)l2_parse_igmp_group(entry->group,
                                          &entry->group_ip, entry->mac);
                n++;
                group = group_end + strlen("</static-group>");
            }
            iface = iface_end + strlen("</interface>");
        }
        vlan = vlan_end + strlen("</vlan>");
    }
    free(xml);
    /* Router ports receive each known static group in the same VLAN. These
     * are normal transactional listeners: scope, readback and rollback use
     * the existing multicast HAL instead of an unverified SDK extension. */
    cfg_igmp_scope_intent *scopes = calloc(CFG_IGMP_MAX_SCOPES, sizeof(*scopes));
    if (!scopes) return -1;
    int ns = l2_collect_igmp_scope_intents(ys, scopes, CFG_IGMP_MAX_SCOPES, ports, n_ports);
    if (ns < 0 || ns > CFG_IGMP_MAX_SCOPES) { free(scopes); return -1; }
    int listeners = n;
    for (int s = 0; s < ns && n < max_entries; ++s) {
        if (!scopes[s].mrouter) continue;
        for (int i = 0; i < listeners && n < max_entries; ++i) {
            if (entries[i].vid != scopes[s].vid) continue;
            bool present = false;
            for (int j = 0; j < n; ++j)
                if (entries[j].vid == scopes[s].vid &&
                    entries[j].port.hw_port == scopes[s].port.hw_port &&
                    entries[j].group_ip == entries[i].group_ip) present = true;
            if (present) continue;
            entries[n] = entries[i];
            entries[n].port = scopes[s].port;
            snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s", scopes[s].ifname);
            entries[n].router = true;
            ++n;
        }
    }
    free(scopes);
    return n;
}

int l2_find_igmp_listener(const cfg_igmp_listener_intent *entries,
                          int n_entries, int vid, int port, u32 group_ip) {
    if (!entries)
        return -1;
    for (int i = 0; i < n_entries; i++) {
        if (entries[i].vid == vid && entries[i].port.hw_port == port &&
            entries[i].group_ip == group_ip)
            return i;
    }
    return -1;
}

bool l2_vlan_vid_present(const cfg_vlan_ref *vlans, int n_vlans, int vid) {
    for (int i = 0; i < n_vlans; i++)
        if (vlans[i].vid == vid)
            return true;
    return false;
}

bool l2_vlan_marked_missing(const bool *missing_by_vid, int vid) {
    return missing_by_vid && vid >= 1 && vid <= 4094 && missing_by_vid[vid];
}

static void intent_add_member(nl_yang_session *ys, cfg_if_intent *intent,
                              const char *member) {
    if (!intent || !member || !member[0])
        return;
    for (int i = 0; i < intent->n_members; i++) {
        if (strcmp(intent->members[i], member) == 0)
            return;
    }
    if (intent->n_members >= CFG_IF_MAX_MEMBERS) {
        intent->members_complete = false;
        return;
    }
    snprintf(intent->members[intent->n_members],
             sizeof(intent->members[intent->n_members]), "%s", member);
    intent->member_vids[intent->n_members] = l2_get_vlan_id(ys, member);
    if (intent->n_members == 0) {
        snprintf(intent->member, sizeof(intent->member), "%s", member);
        intent->member_vid = intent->member_vids[intent->n_members];
    }
    intent->n_members++;
}

static void collect_interface_members(nl_yang_session *ys, const char *ifname,
                                      cfg_if_intent *intent) {
    char *xml;
    char *p;

    if (!ys || !ifname || !intent)
        return;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return;

    p = xml;
    while ((p = strstr(p, "<interface>"))) {
        char *end = strstr(p, "</interface>");
        char name[64];

        if (!end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0 &&
            strcmp(name, ifname) == 0) {
            char *m = p;
            while ((m = strstr(m, "<vlan-members>")) && m < end) {
                char *vstart = m + strlen("<vlan-members>");
                char *vend = strstr(vstart, "</vlan-members>");
                char member[64];
                size_t len;

                if (!vend || vend > end)
                    break;
                len = (size_t)(vend - vstart);
                if (len >= sizeof(member))
                    len = sizeof(member) - 1;
                memcpy(member, vstart, len);
                member[len] = '\0';
                intent_add_member(ys, intent, member);
                m = vend + strlen("</vlan-members>");
            }
            break;
        }
        p = end + strlen("</interface>");
    }
    free(xml);
}

void l2_read_interface_intent(nl_yang_session *ys, const char *ifname,
                                  cfg_if_intent *intent) {
    const char *mode;
    const char *native_vid;
    const char *disable;
    const char *mtu;
    const char *speed;

    memset(intent, 0, sizeof(*intent));
    intent->members_complete = true;
    if (!ys || !ifname)
        return;

    mode = l2_get_l2_leaf(ys, ifname, "interface-mode");
    native_vid = l2_get_interface_leaf(ys, ifname, "native-vlan-id");
    disable = l2_get_interface_leaf(ys, ifname, "disable");
    mtu = l2_get_interface_leaf(ys, ifname, "mtu");
    speed = l2_get_interface_leaf(ys, ifname, "speed");
    char rstp_path[256];
    snprintf(rstp_path, sizeof(rstp_path), "/netlab:netlab-config/protocols/rstp/interface[name='%s']", ifname);
    intent->rstp_managed = nl_yang_exists(ys, "/netlab:netlab-config/chassis/fm10k-panel") &&
                           nl_yang_exists(ys, rstp_path);

    collect_interface_members(ys, ifname, intent);

    intent->exists = mode || intent->n_members > 0 || native_vid ||
                     disable || mtu || speed;
    intent->disabled = l2_bool_leaf_true(disable);

    if (mode && mode[0])
        snprintf(intent->mode, sizeof(intent->mode), "%s", mode);
    if (mtu && mtu[0]) {
        intent->has_mtu = true;
        intent->mtu = atoi(mtu);
    }
    if (speed && speed[0]) {
        intent->has_speed = true;
        if (strcmp(speed, "10g") == 0)
            intent->speed_mbps = NL_PORT_SPEED_10G_MBPS;
        else if (strcmp(speed, "25g") == 0)
            intent->speed_mbps = NL_PORT_SPEED_25G_MBPS;
        else if (strcmp(speed, "40g") == 0)
            intent->speed_mbps = 40000;
        else if (strcmp(speed, "100g") == 0)
            intent->speed_mbps = 100000;
    }
    if (native_vid && native_vid[0]) {
        intent->has_native = true;
        intent->native_vid = atoi(native_vid);
    }

    intent->has_l2 = intent->mode[0] || intent->n_members > 0 || intent->has_native;
}

bool l2_intent_is_trunk(const cfg_if_intent *intent) {
    return intent && strcmp(intent->mode, "trunk") == 0;
}

bool l2_intent_vid_tagged(const cfg_if_intent *intent, int vid) {
    if (!l2_intent_is_trunk(intent))
        return false;
    return !(intent->has_native && intent->native_vid == vid);
}

bool l2_intent_has_member_tagged(const cfg_if_intent *intent, int vid,
                                     bool tagged) {
    if (!intent || vid <= 0)
        return false;
    for (int i = 0; i < intent->n_members; i++) {
        if (intent->member_vids[i] == vid)
            return l2_intent_vid_tagged(intent, vid) == tagged;
    }
    return false;
}

bool l2_intent_has_vid(const cfg_if_intent *intent, int vid) {
    if (!intent || vid <= 0)
        return false;
    for (int i = 0; i < intent->n_members; i++) {
        if (intent->member_vids[i] == vid)
            return true;
    }
    return false;
}

bool l2_membership_changed(const cfg_if_intent *old_i,
                                  const cfg_if_intent *new_i) {
    if (!old_i->has_l2 && !new_i->has_l2)
        return false;
    if (old_i->has_l2 != new_i->has_l2)
        return true;
    if (old_i->n_members != new_i->n_members)
        return true;
    for (int i = 0; i < old_i->n_members; i++) {
        if (!l2_intent_has_vid(new_i, old_i->member_vids[i]))
            return true;
        if (l2_intent_vid_tagged(old_i, old_i->member_vids[i]) !=
            l2_intent_vid_tagged(new_i, old_i->member_vids[i]))
            return true;
    }
    return false;
}

int l2_get_vlan_id(nl_yang_session *ys, const char *vlan_name) {
    char path[256];
    const char *vid;

    if (!ys || !vlan_name || !vlan_name[0])
        return 0;

    snprintf(path, sizeof(path),
             "/netlab:netlab-config/vlans/vlan[name='%s']/vlan-id",
             vlan_name);
    vid = nl_yang_get(ys, path);
    if (!vid || !vid[0])
        return 0;
    return atoi(vid);
}

const char *l2_get_interface_leaf(nl_yang_session *ys, const char *ifname,
                                      const char *leaf) {
    char path[384];

    snprintf(path, sizeof(path),
             "/netlab:netlab-config/interfaces/interface[name='%s']/%s",
             ifname, leaf);
    return nl_yang_get(ys, path);
}

const char *l2_get_l2_leaf(nl_yang_session *ys, const char *ifname,
                               const char *leaf) {
    char path[512];

    snprintf(path, sizeof(path),
             "/netlab:netlab-config/interfaces/interface[name='%s']"
             "/unit/logical-unit[unit-id='0']"
             "/family/ethernet-switching/%s",
             ifname, leaf);
    return nl_yang_get(ys, path);
}

const char *l2_get_lag_member(nl_yang_session *ys, const char *ifname) {
    return l2_get_interface_leaf(ys, ifname, "ether-options/ieee8023ad");
}

bool l2_get_ingress_filtering(nl_yang_session *ys, const char *ifname) {
    const char *value = l2_get_interface_leaf(ys, ifname, "fm10k-port/ingress-filtering");
    return !value || strcmp(value, "false") != 0;
}

const char *l2_get_lacp_member_port_priority(nl_yang_session *ys,
                                                 const char *ifname) {
    return l2_get_interface_leaf(ys, ifname,
                              "ether-options/lacp/port-priority");
}

const char *l2_get_lacp_mode(nl_yang_session *ys, const char *ifname) {
    const char *fixed = l2_get_interface_leaf(ys, ifname, "aggregated-ether-options/static");
    if (fixed && !strcmp(fixed, "true")) return "static";
    return l2_get_interface_leaf(ys, ifname, "aggregated-ether-options/lacp/mode");
}

const char *l2_get_lacp_periodic(nl_yang_session *ys, const char *ifname) {
    return l2_get_interface_leaf(ys, ifname,
                              "aggregated-ether-options/lacp/periodic");
}

const char *l2_get_lacp_actor_key(nl_yang_session *ys, const char *ifname) {
    return l2_get_interface_leaf(ys, ifname,
                              "aggregated-ether-options/lacp/actor-key");
}

const char *l2_get_lag_hash_rotation(nl_yang_session *ys,
                                     const char *ifname) {
    return l2_get_interface_leaf(ys, ifname,
                              "aggregated-ether-options/hash-policy/rotation");
}

int l2_get_lacp_min_links(nl_yang_session *ys, const char *ifname,
                              bool *configured, bool *valid) {
    const char *value = l2_get_interface_leaf(ys, ifname,
                                           "aggregated-ether-options/minimum-links");
    char *end = NULL;
    long n;

    if (configured)
        *configured = value && value[0];
    if (valid)
        *valid = true;
    if (!value || !value[0])
        return 1;

    n = strtol(value, &end, 10);
    if (!end || *end || n < 1 || n > 16) {
        if (valid)
            *valid = false;
        return -1;
    }
    return (int)n;
}

int l2_get_mac_aging_time(nl_yang_session *ys, bool *configured) {
    const char *value = nl_yang_get(ys,
        "/netlab:netlab-config/ethernet-switching-options/mac-table-aging-time");
    int seconds;

    if (configured)
        *configured = value && value[0];
    if (!value || !value[0])
        return CFG_MAC_AGING_DEFAULT_SECONDS;

    seconds = atoi(value);
    if (seconds < 0 || seconds > CFG_MAC_AGING_MAX_SECONDS)
        return -1;
    return seconds;
}

void l2_port_target_arg(const cfg_port_ref *port, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0)
        return;
    if (port && port->is_aggregate)
        snprintf(buf, buf_len, "ae=%d", port->ae_id);
    else
        snprintf(buf, buf_len, "port=%d", port ? port->hw_port : 0);
}

void l2_resolve_static_mac_ports(cfg_static_mac_intent *entries,
                                     int n_entries,
                                     const cfg_port_ref *ports,
                                     int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                 entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_storm_control_ports(cfg_storm_control_intent *entries,
                                    int n_entries,
                                    const cfg_port_ref *ports,
                                    int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_ingress_rate_limit_ports(
    cfg_ingress_rate_limit_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_egress_rate_limit_ports(
    cfg_egress_rate_limit_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_qos_interface_ports(cfg_qos_interface_intent *entries,
                                    int n_entries,
                                    const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_qos_pfc_ports(cfg_qos_pfc_intent *entries, int n_entries,
                              const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_qos_scheduler_tc_map_ports(
    cfg_qos_scheduler_tc_map_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_qos_scheduler_group_ports(
    cfg_qos_scheduler_group_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_qos_scheduler_group_shaping_ports(
    cfg_qos_scheduler_group_shaping_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_qos_scheduler_port_ports(
    cfg_qos_scheduler_port_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

void l2_resolve_qos_watermark_ports(
    cfg_qos_watermark_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports) {
    for (int i = 0; i < n_entries; i++) {
        if (entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
            entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
            entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG)
            continue;
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (port)
            entries[i].port = *port;
    }
}

int l2_find_static_mac_by_key(const cfg_static_mac_intent *entries,
                                  int n_entries,
                                  const char *mac, int vid) {
    for (int i = 0; i < n_entries; i++) {
        if (entries[i].vid == vid && strcmp(entries[i].mac, mac) == 0)
            return i;
    }
    return -1;
}

bool l2_static_mac_same_target(const cfg_static_mac_intent *a,
                                   const cfg_static_mac_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->port.is_aggregate == b->port.is_aggregate &&
           a->port.ae_id == b->port.ae_id;
}

int l2_find_storm_control_by_ifname(const cfg_storm_control_intent *entries,
                                    int n_entries, const char *ifname,
                                    nl_storm_kind kind) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (entries[i].kind == kind && strcmp(entries[i].ifname, ifname) == 0)
            return i;
    return -1;
}

bool l2_storm_control_same(const cfg_storm_control_intent *a,
                           const cfg_storm_control_intent *b) {
    return a && b &&
           a->kind == b->kind &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->rate_kbps == b->rate_kbps &&
           a->burst_bytes == b->burst_bytes;
}

int l2_find_ingress_rate_limit_by_ifname(
    const cfg_ingress_rate_limit_intent *entries, int n_entries,
    const char *ifname) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0)
            return i;
    return -1;
}

bool l2_ingress_rate_limit_same(const cfg_ingress_rate_limit_intent *a,
                                const cfg_ingress_rate_limit_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->rate_kbps == b->rate_kbps &&
           a->burst_bytes == b->burst_bytes;
}

int l2_find_egress_rate_limit_by_ifname(
    const cfg_egress_rate_limit_intent *entries, int n_entries,
    const char *ifname) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0)
            return i;
    return -1;
}

bool l2_egress_rate_limit_same(const cfg_egress_rate_limit_intent *a,
                               const cfg_egress_rate_limit_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->rate_kbps == b->rate_kbps &&
           a->burst_bytes == b->burst_bytes;
}

int l2_find_qos_interface_by_ifname(
    const cfg_qos_interface_intent *entries, int n_entries,
    const char *ifname) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0)
            return i;
    return -1;
}

bool l2_qos_interface_same(const cfg_qos_interface_intent *a,
                           const cfg_qos_interface_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->trust_mode == b->trust_mode &&
           a->default_priority == b->default_priority;
}

int l2_find_qos_pfc_by_ifname(
    const cfg_qos_pfc_intent *entries, int n_entries,
    const char *ifname) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0)
            return i;
    return -1;
}

bool l2_qos_pfc_same(const cfg_qos_pfc_intent *a,
                     const cfg_qos_pfc_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->rx_class_mask == b->rx_class_mask &&
           a->tx_class_mask == b->tx_class_mask &&
           a->lossless_smp_mask == b->lossless_smp_mask &&
           a->shared_pause_mask == b->shared_pause_mask &&
           fm10k_pfc_wd_policy_equal(&a->watchdog, &b->watchdog);
}

int l2_find_qos_priority_map(
    const cfg_qos_priority_map_intent *entries, int n_entries,
    int switch_priority) {
    if (!entries)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (entries[i].switch_priority == switch_priority)
            return i;
    return -1;
}

bool l2_qos_priority_map_same(const cfg_qos_priority_map_intent *a,
                              const cfg_qos_priority_map_intent *b) {
    return a && b &&
           a->switch_priority == b->switch_priority &&
           a->traffic_class == b->traffic_class;
}

int l2_find_qos_scheduler_tc_map(
    const cfg_qos_scheduler_tc_map_intent *entries, int n_entries,
    const char *ifname, int traffic_class) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0 &&
            entries[i].traffic_class == traffic_class)
            return i;
    return -1;
}

bool l2_qos_scheduler_tc_map_same(
    const cfg_qos_scheduler_tc_map_intent *a,
    const cfg_qos_scheduler_tc_map_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->traffic_class == b->traffic_class &&
           a->shaping_group == b->shaping_group;
}

int l2_find_qos_scheduler_group(
    const cfg_qos_scheduler_group_intent *entries, int n_entries,
    const char *ifname, int group) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0 &&
            entries[i].group == group)
            return i;
    return -1;
}

bool l2_qos_scheduler_group_same(
    const cfg_qos_scheduler_group_intent *a,
    const cfg_qos_scheduler_group_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->group == b->group &&
           a->strict_priority == b->strict_priority &&
           a->weight == b->weight;
}

int l2_find_qos_scheduler_group_shaping(
    const cfg_qos_scheduler_group_shaping_intent *entries, int n_entries,
    const char *ifname, int group) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0 &&
            entries[i].group == group)
            return i;
    return -1;
}

bool l2_qos_scheduler_group_shaping_same(
    const cfg_qos_scheduler_group_shaping_intent *a,
    const cfg_qos_scheduler_group_shaping_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->group == b->group &&
           a->rate_bps == b->rate_bps &&
           a->burst_bits == b->burst_bits;
}

int l2_find_qos_scheduler_port_by_ifname(
    const cfg_qos_scheduler_port_intent *entries, int n_entries,
    const char *ifname) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0)
            return i;
    return -1;
}

bool l2_qos_scheduler_port_same(
    const cfg_qos_scheduler_port_intent *a,
    const cfg_qos_scheduler_port_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->traffic_class_enable_mask == b->traffic_class_enable_mask;
}

int l2_find_qos_watermark(
    const cfg_qos_watermark_intent *entries, int n_entries,
    const char *ifname, int traffic_class, int attr) {
    if (!entries || !ifname)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].ifname, ifname) == 0 &&
            entries[i].traffic_class == traffic_class &&
            entries[i].attr == attr)
            return i;
    return -1;
}

bool l2_qos_watermark_same(const cfg_qos_watermark_intent *a,
                           const cfg_qos_watermark_intent *b) {
    return a && b &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->traffic_class == b->traffic_class &&
           a->attr == b->attr &&
           a->value == b->value;
}

int l2_find_l2_security_rule(const cfg_l2_security_rule_intent *entries,
                             int n_entries, cfg_l2_security_kind kind,
                             int vid, int port) {
    if (!entries)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (entries[i].kind == kind &&
            entries[i].vid == vid &&
            entries[i].port.hw_port == port)
            return i;
    return -1;
}

int l2_find_dhcp_binding(const cfg_dhcp_binding_intent *entries,
                         int n_entries, const char *mac, int vid) {
    if (!entries || !mac)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (entries[i].vid == vid && strcmp(entries[i].mac, mac) == 0)
            return i;
    return -1;
}

bool l2_dhcp_binding_same_target(const cfg_dhcp_binding_intent *a,
                                 const cfg_dhcp_binding_intent *b) {
    return a && b &&
           strcmp(a->mac, b->mac) == 0 &&
           a->vid == b->vid &&
           strcmp(a->ifname, b->ifname) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           strcmp(a->ip, b->ip) == 0 &&
           a->ip_addr == b->ip_addr;
}

int l2_find_user_filter_by_name(const cfg_user_filter_intent *entries,
                                int n_entries, const char *name) {
    if (!entries || !name)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].name, name) == 0)
            return i;
    return -1;
}

bool l2_user_filter_same(const cfg_user_filter_intent *a,
                         const cfg_user_filter_intent *b) {
    return a && b &&
           strcmp(a->name, b->name) == 0 &&
           a->vid == b->vid &&
           a->port.hw_port == b->port.hw_port &&
           strcmp(a->mac_kind, b->mac_kind) == 0 &&
           strcmp(a->mac, b->mac) == 0 &&
           strcmp(a->action, b->action) == 0;
}

int l2_find_ingress_ipv4_acl_by_name(
    const cfg_ingress_ipv4_acl_intent *entries, int n_entries,
    const char *name) {
    if (!entries || !name)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].name, name) == 0)
            return i;
    return -1;
}

bool l2_ingress_ipv4_acl_same(
    const cfg_ingress_ipv4_acl_intent *a,
    const cfg_ingress_ipv4_acl_intent *b) {
    const hal_ingress_ipv4_acl_match *ma;
    const hal_ingress_ipv4_acl_match *mb;

    if (!a || !b)
        return false;
    ma = &a->match;
    mb = &b->match;
    return strcmp(a->name, b->name) == 0 &&
           a->vid == b->vid &&
           a->port.hw_port == b->port.hw_port &&
           ma->has_src_ip == mb->has_src_ip &&
           ma->has_dst_ip == mb->has_dst_ip &&
           ma->has_src_ip_mask == mb->has_src_ip_mask &&
           ma->has_dst_ip_mask == mb->has_dst_ip_mask &&
           ma->has_dscp == mb->has_dscp &&
           ma->has_ecn == mb->has_ecn &&
           ma->has_protocol == mb->has_protocol &&
           ma->has_src_port == mb->has_src_port &&
           ma->has_dst_port == mb->has_dst_port &&
           ma->has_src_port_range == mb->has_src_port_range &&
           ma->has_dst_port_range == mb->has_dst_port_range &&
           ma->has_tcp_flags == mb->has_tcp_flags &&
           ma->has_tcp_flags_mask == mb->has_tcp_flags_mask &&
           ma->count_only == mb->count_only &&
           ma->src_ip == mb->src_ip &&
           ma->dst_ip == mb->dst_ip &&
           ma->src_ip_mask == mb->src_ip_mask &&
           ma->dst_ip_mask == mb->dst_ip_mask &&
           ma->dscp == mb->dscp &&
           ma->ecn == mb->ecn &&
           ma->protocol == mb->protocol &&
           ma->src_port == mb->src_port &&
           ma->dst_port == mb->dst_port &&
           ma->src_port_start == mb->src_port_start &&
           ma->src_port_end == mb->src_port_end &&
           ma->dst_port_start == mb->dst_port_start &&
           ma->dst_port_end == mb->dst_port_end &&
           ma->tcp_flags == mb->tcp_flags &&
           ma->tcp_flags_mask == mb->tcp_flags_mask &&
           strcmp(a->action, b->action) == 0;
}

int l2_find_acl_policer_by_name(
    const cfg_acl_policer_intent *entries, int n_entries,
    const char *name) {
    if (!entries || !name)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].name, name) == 0)
            return i;
    return -1;
}

bool l2_acl_policer_same(const cfg_acl_policer_intent *a,
                         const cfg_acl_policer_intent *b) {
    return a && b &&
           strcmp(a->name, b->name) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->dst_mac == b->dst_mac &&
           a->rate_kbps == b->rate_kbps &&
           a->burst_bytes == b->burst_bytes;
}

int l2_find_egress_acl_by_name(
    const cfg_egress_acl_intent *entries, int n_entries,
    const char *name) {
    if (!entries || !name)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].name, name) == 0)
            return i;
    return -1;
}

bool l2_egress_acl_same(const cfg_egress_acl_intent *a,
                        const cfg_egress_acl_intent *b) {
    return a && b &&
           strcmp(a->name, b->name) == 0 &&
           a->port.hw_port == b->port.hw_port &&
           a->has_src_mac == b->has_src_mac &&
           a->has_dst_mac == b->has_dst_mac &&
           a->src_mac == b->src_mac &&
           a->dst_mac == b->dst_mac &&
           strcmp(a->action, b->action) == 0;
}

int l2_find_acl_independent_by_key(
    const cfg_acl_independent_intent *entries, int n_entries,
    const char *group, const char *term, const char *family) {
    if (!entries || !group || !term || !family)
        return -1;
    for (int i = 0; i < n_entries; i++)
        if (strcmp(entries[i].group, group) == 0 &&
            strcmp(entries[i].term, term) == 0 &&
            strcmp(entries[i].family, family) == 0)
            return i;
    return -1;
}

bool l2_acl_independent_same(
    const cfg_acl_independent_intent *a,
    const cfg_acl_independent_intent *b) {
    const hal_ingress_ipv4_acl_match *ma;
    const hal_ingress_ipv4_acl_match *mb;

    if (!a || !b)
        return false;
    ma = &a->inet_match;
    mb = &b->inet_match;
    return strcmp(a->group, b->group) == 0 &&
           strcmp(a->term, b->term) == 0 &&
           strcmp(a->family, b->family) == 0 &&
           a->slot == b->slot &&
           a->vid == b->vid &&
           a->port.hw_port == b->port.hw_port &&
           strcmp(a->action, b->action) == 0 &&
           a->has_src_mac == b->has_src_mac &&
           a->has_dst_mac == b->has_dst_mac &&
           a->src_mac == b->src_mac &&
           a->dst_mac == b->dst_mac &&
           ma->has_src_ip == mb->has_src_ip &&
           ma->has_dst_ip == mb->has_dst_ip &&
           ma->has_src_ip_mask == mb->has_src_ip_mask &&
           ma->has_dst_ip_mask == mb->has_dst_ip_mask &&
           ma->has_dscp == mb->has_dscp &&
           ma->has_ecn == mb->has_ecn &&
           ma->has_protocol == mb->has_protocol &&
           ma->has_src_port == mb->has_src_port &&
           ma->has_dst_port == mb->has_dst_port &&
           ma->has_src_port_range == mb->has_src_port_range &&
           ma->has_dst_port_range == mb->has_dst_port_range &&
           ma->has_tcp_flags == mb->has_tcp_flags &&
           ma->has_tcp_flags_mask == mb->has_tcp_flags_mask &&
           ma->count_only == mb->count_only &&
           ma->src_ip == mb->src_ip &&
           ma->dst_ip == mb->dst_ip &&
           ma->src_ip_mask == mb->src_ip_mask &&
           ma->dst_ip_mask == mb->dst_ip_mask &&
           ma->dscp == mb->dscp &&
           ma->ecn == mb->ecn &&
           ma->protocol == mb->protocol &&
           ma->src_port == mb->src_port &&
           ma->dst_port == mb->dst_port &&
           ma->src_port_start == mb->src_port_start &&
           ma->src_port_end == mb->src_port_end &&
           ma->dst_port_start == mb->dst_port_start &&
           ma->dst_port_end == mb->dst_port_end &&
           ma->tcp_flags == mb->tcp_flags &&
           ma->tcp_flags_mask == mb->tcp_flags_mask &&
           a->rate_kbps == b->rate_kbps &&
           a->burst_bytes == b->burst_bytes;
}

int l2_find_copp_class(const cfg_copp_class_intent *entries, int n_entries,
                       const char *class_name) {
    if (!entries || !class_name)
        return -1;
    for (int i = 0; i < n_entries; i++) {
        if (strcmp(entries[i].class_name, class_name) == 0)
            return i;
    }
    return -1;
}

const cfg_port_ref *l2_find_port_ref(const cfg_port_ref *ports,
                                         int n_ports, const char *name) {
    for (int i = 0; i < n_ports; i++)
        if (strcmp(ports[i].name, name) == 0)
            return &ports[i];
    return NULL;
}

bool l2_is_ae_name(const char *name) {
    const char *p;

    if (!name || name[0] != 'a' || name[1] != 'e' ||
        !isdigit((unsigned char)name[2]))
        return false;
    p = name + 2;
    while (*p) {
        if (!isdigit((unsigned char)*p))
            return false;
        p++;
    }
    return true;
}

int l2_ae_id(const char *name) {
    return l2_is_ae_name(name) ? atoi(name + 2) : -1;
}

bool l2_supported_ae_name(const char *name) {
    int id = l2_ae_id(name);
    return id >= 0 && id < l2_cfg_max_ae();
}

bool l2_aggregate_configured(nl_yang_session *ys, const char *ifname) {
    cfg_if_intent intent;
    const char *lacp;

    if (!ys || !ifname || !l2_supported_ae_name(ifname))
        return false;

    lacp = l2_get_lacp_mode(ys, ifname);
    l2_read_interface_intent(ys, ifname, &intent);
    return (lacp && lacp[0]) || intent.has_l2;
}
