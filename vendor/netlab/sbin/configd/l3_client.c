/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "l3_client.h"
#include "netlab/error.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include "netlab/l3_capacity.h"
#include "netlab/fm10k_board_types.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define RPD_SOCKET "/var/run/netlab/rpd.sock"
#define L3_RIB_STATIC_MAX_NEXTHOPS NL_L3_DYNAMIC_MAX_NEXTHOPS
#define L3_AUTO_NH_ID_BASE 60000
#define L3_AUTO_ECMP_ID_BASE 60000
#define L3_VRF_V1_VRID 1
#define L3_VRF_V1_KERNEL_TABLE 1001

static const char *L3_PUBLIC_GATE_REASON =
    "L3 public commit requires an active L3 chassis mode with route slices and ROUTE-capable external ports";

static bool env_truthy(const char *name) {
    const char *v = getenv(name);

    return v && (strcmp(v, "1") == 0 ||
                 strcmp(v, "true") == 0 ||
                 strcmp(v, "TRUE") == 0 ||
                 strcmp(v, "yes") == 0 ||
                 strcmp(v, "YES") == 0);
}

static bool socket_path_safe(const char *path) {
    if (!path || !path[0] || strlen(path) >= 108)
        return false;
    for (; *path; path++) {
        unsigned char c = (unsigned char)*path;

        if (!(isalnum(c) || c == '/' || c == '.' || c == '_' ||
              c == '-' || c == ':'))
            return false;
    }
    return true;
}

static const char *rpd_socket_path(void) {
    const char *env = getenv("NETLAB_RPD_SOCKET");

    if (socket_path_safe(env))
        return env;
    return RPD_SOCKET;
}

static bool ffu_slice_enabled(int first, int last) {
    return first >= 0 && last >= first;
}

static bool platform_has_route_slices(void) {
    nl_ffu_slice_allocation ffu;

    if (!nl_platform_ffu_slices(&ffu))
        return false;
    return ffu_slice_enabled(ffu.ipv4_uc_first, ffu.ipv4_uc_last) ||
           ffu_slice_enabled(ffu.ipv4_mc_first, ffu.ipv4_mc_last) ||
           ffu_slice_enabled(ffu.ipv6_uc_first, ffu.ipv6_uc_last) ||
           ffu_slice_enabled(ffu.ipv6_mc_first, ffu.ipv6_mc_last);
}

static bool port_capability_contains(const nl_port_entry *port,
                                     const char *wanted) {
    char tmp[sizeof(port->capabilities)];
    char *save = NULL;
    char *tok;

    if (!port || !wanted || !port->capabilities[0])
        return false;
    snprintf(tmp, sizeof(tmp), "%s", port->capabilities);
    tok = strtok_r(tmp, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (strcasecmp(tok, wanted) == 0)
            return true;
        tok = strtok_r(NULL, ",", &save);
    }
    return false;
}

static bool platform_has_route_capable_external_port(void) {
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);

    for (int i = 0; i < n; i++) {
        if (!(ports[i].flags & NL_PORT_FLAG_EXTERNAL) &&
            strcmp(ports[i].role, "external") != 0)
            continue;
        if (port_capability_contains(&ports[i], "ROUTE"))
            return true;
    }
    return false;
}

static bool platform_l3_profile_ready(void) {
    return platform_has_route_slices() &&
           platform_has_route_capable_external_port();
}

static const char *bounded_strstr(const char *start, const char *end,
                                  const char *needle) {
    size_t nlen;

    if (!start || !end || !needle || start > end)
        return NULL;
    nlen = strlen(needle);
    if (nlen == 0)
        return start;
    for (const char *p = start; p + nlen <= end; p++) {
        if (memcmp(p, needle, nlen) == 0)
            return p;
    }
    return NULL;
}

static const char *find_open_tag(const char *start, const char *end,
                                 const char *tag) {
    char needle[96];
    size_t nlen;

    snprintf(needle, sizeof(needle), "<%s", tag);
    nlen = strlen(needle);
    for (const char *p = start; p && p + nlen <= end;
         p = bounded_strstr(p + 1, end, needle)) {
        if (memcmp(p, needle, nlen) != 0)
            continue;
        if (p + nlen >= end)
            return NULL;
        if (p[nlen] == '>' || p[nlen] == ' ' || p[nlen] == '\t' ||
            p[nlen] == '\r' || p[nlen] == '\n')
            return p;
    }
    return NULL;
}

static int tag_body(const char *open, const char *end, const char *tag,
                    const char **body_start, const char **body_end) {
    char close_needle[96];
    const char *gt;
    const char *close;

    if (!open || !end || !tag || !body_start || !body_end)
        return -1;
    gt = memchr(open, '>', (size_t)(end - open));
    if (!gt)
        return -1;
    if (gt > open && gt[-1] == '/') {
        *body_start = gt + 1;
        *body_end = gt + 1;
        return 0;
    }
    snprintf(close_needle, sizeof(close_needle), "</%s>", tag);
    close = bounded_strstr(gt + 1, end, close_needle);
    if (!close)
        return -1;
    *body_start = gt + 1;
    *body_end = close;
    return 0;
}

static int next_entry(const char **cursor, const char *end, const char *tag,
                      const char **body_start, const char **body_end) {
    const char *open;
    char close_needle[96];
    const char *close;

    if (!cursor || !*cursor)
        return 0;
    open = find_open_tag(*cursor, end, tag);
    if (!open)
        return 0;
    if (tag_body(open, end, tag, body_start, body_end) != 0)
        return -1;
    snprintf(close_needle, sizeof(close_needle), "</%s>", tag);
    close = bounded_strstr(*body_end, end, close_needle);
    *cursor = close ? close + strlen(close_needle) : *body_end;
    return 1;
}

static int child_text(const char *start, const char *end, const char *tag,
                      char *out, size_t out_size) {
    const char *open;
    const char *body_start;
    const char *body_end;
    size_t len;

    if (!out || out_size == 0)
        return 0;
    out[0] = '\0';
    open = find_open_tag(start, end, tag);
    if (!open)
        return 0;
    if (tag_body(open, end, tag, &body_start, &body_end) != 0)
        return -1;
    while (body_start < body_end &&
           (*body_start == ' ' || *body_start == '\t' ||
            *body_start == '\r' || *body_start == '\n'))
        body_start++;
    while (body_end > body_start &&
           (body_end[-1] == ' ' || body_end[-1] == '\t' ||
            body_end[-1] == '\r' || body_end[-1] == '\n'))
        body_end--;
    len = (size_t)(body_end - body_start);
    if (len >= out_size)
        len = out_size - 1;
    memcpy(out, body_start, len);
    out[len] = '\0';
    return 1;
}

static int next_child_text(const char **cursor, const char *end,
                           const char *tag, char *out, size_t out_size) {
    const char *open;
    const char *body_start;
    const char *body_end;
    char close_needle[96];
    const char *close;
    size_t len;

    if (!cursor || !*cursor || !out || out_size == 0)
        return 0;
    out[0] = '\0';
    open = find_open_tag(*cursor, end, tag);
    if (!open)
        return 0;
    if (tag_body(open, end, tag, &body_start, &body_end) != 0)
        return -1;
    while (body_start < body_end &&
           (*body_start == ' ' || *body_start == '\t' ||
            *body_start == '\r' || *body_start == '\n'))
        body_start++;
    while (body_end > body_start &&
           (body_end[-1] == ' ' || body_end[-1] == '\t' ||
            body_end[-1] == '\r' || body_end[-1] == '\n'))
        body_end--;
    len = (size_t)(body_end - body_start);
    if (len >= out_size)
        len = out_size - 1;
    memcpy(out, body_start, len);
    out[len] = '\0';

    snprintf(close_needle, sizeof(close_needle), "</%s>", tag);
    close = bounded_strstr(body_end, end, close_needle);
    *cursor = close ? close + strlen(close_needle) : body_end;
    return 1;
}

static int append_line(char *plan, size_t plan_size, int *off,
                       const char *fmt, ...) {
    va_list ap;
    int remain;
    int n;

    if (!plan || !off || *off < 0 || (size_t)*off >= plan_size)
        return -1;
    remain = (int)(plan_size - (size_t)*off);
    va_start(ap, fmt);
    n = vsnprintf(plan + *off, (size_t)remain, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= remain)
        return -1;
    *off += n;
    return 0;
}

static int append_token(char *buf, size_t buf_size, const char *token) {
    size_t used;
    size_t len;

    if (!buf || !token || buf_size == 0)
        return -1;
    used = strlen(buf);
    len = strlen(token);
    if (used + len >= buf_size)
        return -1;
    memcpy(buf + used, token, len + 1);
    return 0;
}

static int append_platform_router_mac(char *plan, size_t plan_size, int *off) {
    u8 mac[NL_MAC_ADDR_LEN];

    if (!nl_platform_system_mac(mac))
        return 0;
    return append_line(plan, plan_size, off,
                       "router-mac %02x:%02x:%02x:%02x:%02x:%02x\n",
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

typedef struct {
    char ip[64];
    char rif[128];
} l3_static_arp_ref;

typedef struct {
    char id[32];
    char arp[64];
    char rif[128];
} l3_static_nh_ref;

typedef struct {
    char name[128];
    char address[64];
} l3_rif_ref;

typedef struct {
    bool enabled;
    char name[32];
    char table[64];
    char interfaces[8][128];
    int n_interfaces;
} l3_vrf_context;

static bool vrf_has_interface(const l3_vrf_context *vrf,
                              const char *name) {
    if (!vrf || !vrf->enabled || !name)
        return false;
    for (int i = 0; i < vrf->n_interfaces; i++)
        if (strcmp(vrf->interfaces[i], name) == 0)
            return true;
    return false;
}

static bool parse_int_range(const char *s, int min, int max, int *out) {
    char *end = NULL;
    long v;

    if (!s || !*s)
        return false;
    v = strtol(s, &end, 10);
    if (!end || *end || v < min || v > max)
        return false;
    if (out)
        *out = (int)v;
    return true;
}

static bool parse_ipv4_host(const char *s, unsigned int *host_order) {
    struct in_addr addr;

    if (!s || inet_pton(AF_INET, s, &addr) != 1)
        return false;
    if (host_order)
        *host_order = ntohl(addr.s_addr);
    return true;
}

static unsigned int ipv4_prefix_mask(int plen) {
    if (plen <= 0)
        return 0;
    if (plen >= 32)
        return 0xffffffffu;
    return 0xffffffffu << (32 - plen);
}

static bool parse_ipv4_cidr(const char *cidr, unsigned int *addr,
                            int *plen) {
    char tmp[64];
    char *slash;
    int p = 0;
    unsigned int a = 0;

    if (!cidr || strlen(cidr) >= sizeof(tmp))
        return false;
    snprintf(tmp, sizeof(tmp), "%s", cidr);
    slash = strchr(tmp, '/');
    if (!slash)
        return false;
    *slash++ = '\0';
    if (!parse_ipv4_host(tmp, &a) || !parse_int_range(slash, 0, 32, &p))
        return false;
    if (addr)
        *addr = a;
    if (plen)
        *plen = p;
    return true;
}

static bool ipv4_in_cidr(const char *ip, const char *cidr) {
    unsigned int host;
    unsigned int net;
    int plen;

    if (!parse_ipv4_host(ip, &host) || !parse_ipv4_cidr(cidr, &net, &plen))
        return false;
    return (host & ipv4_prefix_mask(plen)) == (net & ipv4_prefix_mask(plen));
}

static bool infer_vlan_from_rif_name(const char *name,
                                     char *vlan, size_t vlan_size) {
    const char *cursor;
    char *end = NULL;
    unsigned long value;

    if (!name || !vlan || vlan_size == 0)
        return false;
    if (strncmp(name, "vlan", 4) == 0)
        cursor = name + 4;
    else if (strncmp(name, "irb.", 4) == 0)
        cursor = name + 4;
    else
        return false;
    if (!*cursor)
        return false;
    value = strtoul(cursor, &end, 10);
    if (!end || *end != '\0' || value == 0 || value > 4094)
        return false;
    snprintf(vlan, vlan_size, "%lu", value);
    return true;
}

static bool physical_rif_port(const char *name, char *port,
                              size_t port_size, nl_port_entry *entry,
                              int *hidden_vlan) {
    size_t len;

    if (!name || !port || port_size == 0 || !entry || !hidden_vlan)
        return false;
    len = strlen(name);
    if (len <= 2 || strcmp(name + len - 2, ".0") != 0 ||
        len - 2 >= port_size)
        return false;
    memcpy(port, name, len - 2);
    port[len - 2] = '\0';
    if (!nl_ifid_get_by_name(port, entry) ||
        (!(entry->flags & NL_PORT_FLAG_EXTERNAL) &&
         strcmp(entry->role, "external") != 0) ||
        !port_capability_contains(entry, "ROUTE") ||
        entry->logical_port <= 0 || entry->logical_port >= 4095)
        return false;
    *hidden_vlan = 4095 - entry->logical_port;
    return *hidden_vlan >= 1 && *hidden_vlan <= 4094;
}

static bool configured_vlan_id_exists(const char *xml, const char *xml_end,
                                      int wanted) {
    const char *section = find_open_tag(xml, xml_end, "vlans");
    const char *section_start;
    const char *section_end;
    const char *cursor;
    const char *entry_start;
    const char *entry_end;
    char value[32];
    int rc;

    if (!section || tag_body(section, xml_end, "vlans",
                             &section_start, &section_end) != 0)
        return false;
    cursor = section_start;
    while ((rc = next_entry(&cursor, section_end, "vlan",
                            &entry_start, &entry_end)) > 0) {
        int vlan = 0;

        if (child_text(entry_start, entry_end, "vlan-id",
                       value, sizeof(value)) > 0 &&
            parse_int_range(value, 1, 4094, &vlan) && vlan == wanted)
            return true;
    }
    return false;
}

static bool physical_port_has_l2_intent(const char *xml,
                                        const char *xml_end,
                                        const char *port) {
    const char *section = find_open_tag(xml, xml_end, "interfaces");
    const char *section_start;
    const char *section_end;
    const char *cursor;
    const char *entry_start;
    const char *entry_end;
    char name[128];
    int rc;

    if (!section || tag_body(section, xml_end, "interfaces",
                             &section_start, &section_end) != 0)
        return false;
    cursor = section_start;
    while ((rc = next_entry(&cursor, section_end, "interface",
                            &entry_start, &entry_end)) > 0) {
        if (child_text(entry_start, entry_end, "name",
                       name, sizeof(name)) <= 0 || strcmp(name, port) != 0)
            continue;
        return find_open_tag(entry_start, entry_end, "native-vlan-id") ||
               find_open_tag(entry_start, entry_end, "ether-options") ||
               find_open_tag(entry_start, entry_end,
                             "aggregated-ether-options") ||
               find_open_tag(entry_start, entry_end,
                             "ethernet-switching");
    }
    return false;
}

static int add_arp_ref(l3_static_arp_ref *refs, int *count,
                       const char *ip, const char *rif,
                       char *err, size_t err_size) {
    if (*count >= NL_L3_PERSISTENT_MAX_ARP) {
        snprintf(err, err_size,
                 "too many static ARP entries for public next-hop resolution");
        return -1;
    }
    snprintf(refs[*count].ip, sizeof(refs[*count].ip), "%s", ip);
    snprintf(refs[*count].rif, sizeof(refs[*count].rif), "%s", rif);
    (*count)++;
    return 0;
}

static int add_nh_ref(l3_static_nh_ref *refs, int *count,
                      const char *id, const char *arp, const char *rif,
                      char *err, size_t err_size) {
    if (*count >= NL_L3_PERSISTENT_MAX_NEXTHOPS) {
        snprintf(err, err_size,
                 "too many static next-hop entries for public route resolution");
        return -1;
    }
    snprintf(refs[*count].id, sizeof(refs[*count].id), "%s", id);
    snprintf(refs[*count].arp, sizeof(refs[*count].arp), "%s", arp);
    snprintf(refs[*count].rif, sizeof(refs[*count].rif), "%s", rif);
    (*count)++;
    return 0;
}

static int find_nh_by_arp(const l3_static_nh_ref *refs, int count,
                          const char *arp) {
    for (int i = 0; i < count; i++) {
        if (strcmp(refs[i].arp, arp) == 0)
            return i;
    }
    return -1;
}

static int find_arp_ref(const l3_static_arp_ref *refs, int count,
                        const char *ip) {
    for (int i = 0; i < count; i++) {
        if (strcmp(refs[i].ip, ip) == 0)
            return i;
    }
    return -1;
}

static int find_rif_ref_for_ip(const l3_rif_ref *refs, int count,
                               const char *ip) {
    for (int i = 0; i < count; i++) {
        if (ipv4_in_cidr(ip, refs[i].address))
            return i;
    }
    return -1;
}

static int infer_rif_ref_for_ip(const l3_rif_ref *refs, int count,
                                const char *ip, char *rif,
                                size_t rif_size, char *err,
                                size_t err_size) {
    int match = -1;

    if (!rif || rif_size == 0)
        return -1;
    rif[0] = '\0';
    for (int i = 0; i < count; i++) {
        if (!ipv4_in_cidr(ip, refs[i].address))
            continue;
        if (match >= 0) {
            snprintf(err, err_size,
                     "static ARP %s matches multiple routed interfaces; "
                     "configure interface explicitly",
                     ip);
            return -1;
        }
        match = i;
    }
    if (match < 0) {
        snprintf(err, err_size,
                 "static ARP %s has no connected routed interface",
                 ip);
        return -1;
    }
    snprintf(rif, rif_size, "%s", refs[match].name);
    return 0;
}

static bool nh_id_used(const l3_static_nh_ref *refs, int count,
                       const char *id) {
    for (int i = 0; i < count; i++) {
        if (strcmp(refs[i].id, id) == 0)
            return true;
    }
    return false;
}

static bool string_id_used(char ids[][32], int count, const char *id) {
    for (int i = 0; i < count; i++) {
        if (strcmp(ids[i], id) == 0)
            return true;
    }
    return false;
}

static int add_string_id(char ids[][32], int *count, const char *id,
                         int max_count,
                         char *err, size_t err_size,
                         const char *family) {
    if (*count >= max_count) {
        snprintf(err, err_size, "too many static %s ids", family);
        return -1;
    }
    snprintf(ids[*count], 32, "%s", id);
    (*count)++;
    return 0;
}

static int allocate_auto_nh_id(const l3_static_nh_ref *refs, int count,
                               char *id, size_t id_size) {
    for (int candidate = L3_AUTO_NH_ID_BASE; candidate <= 65535;
         candidate++) {
        snprintf(id, id_size, "%d", candidate);
        if (!nh_id_used(refs, count, id))
            return 0;
    }
    return -1;
}

static int allocate_auto_ecmp_id(char ids[][32], int count,
                                 char *id, size_t id_size) {
    for (int candidate = L3_AUTO_ECMP_ID_BASE; candidate <= 65535;
         candidate++) {
        snprintf(id, id_size, "%d", candidate);
        if (!string_id_used(ids, count, id))
            return 0;
    }
    return -1;
}

static int collect_rif_refs(const char *xml, const char *xml_end,
                            l3_rif_ref *refs, int *count,
                            const l3_vrf_context *vrf, bool vrf_scope,
                            char *err, size_t err_size) {
    const char *section;
    const char *section_start;
    const char *section_end;
    const char *entry_start;
    const char *entry_end;
    const char *cursor;
    int rc;

    if (!refs || !count)
        return -1;
    *count = 0;
    section = find_open_tag(xml, xml_end, "interfaces-routing");
    if (!section)
        return 0;
    if (tag_body(section, xml_end, "interfaces-routing",
                 &section_start, &section_end) != 0) {
        snprintf(err, err_size, "malformed interfaces-routing XML");
        return -1;
    }
    cursor = section_start;
    while ((rc = next_entry(&cursor, section_end, "interface",
                            &entry_start, &entry_end)) != 0) {
        if (rc < 0) {
            snprintf(err, err_size,
                     "malformed interfaces-routing interface XML");
            return -1;
        }
        if (*count >= NL_L3_PERSISTENT_MAX_RIFS) {
            snprintf(err, err_size,
                     "too many routed interfaces for static route resolution");
            return -1;
        }
        if (child_text(entry_start, entry_end, "name",
                       refs[*count].name, sizeof(refs[*count].name)) <= 0 ||
            child_text(entry_start, entry_end, "address",
                       refs[*count].address,
                       sizeof(refs[*count].address)) <= 0) {
            snprintf(err, err_size,
                     "incomplete L3 routed interface; name and address are required");
            return -1;
        }
        if (vrf_has_interface(vrf, refs[*count].name) != vrf_scope)
            continue;
        (*count)++;
    }
    return 0;
}

static int collect_vrf_context(const char *xml, const char *xml_end,
                               l3_vrf_context *vrf,
                               char *err, size_t err_size) {
    const char *section;
    const char *section_start;
    const char *section_end;
    const char *entry_start;
    const char *entry_end;
    const char *cursor;
    const char *if_cursor;
    const char *if_end;
    char type[16];
    char interface[128];
    int rc;

    if (!vrf)
        return -1;
    memset(vrf, 0, sizeof(*vrf));
    section = find_open_tag(xml, xml_end, "routing-instances");
    if (!section)
        return 0;
    if (tag_body(section, xml_end, "routing-instances",
                 &section_start, &section_end) != 0) {
        snprintf(err, err_size, "malformed routing-instances XML");
        return -1;
    }
    cursor = section_start;
    rc = next_entry(&cursor, section_end, "instance",
                    &entry_start, &entry_end);
    if (rc <= 0) {
        snprintf(err, err_size, "routing-instances requires one instance");
        return -1;
    }
    if (child_text(entry_start, entry_end, "name",
                   vrf->name, sizeof(vrf->name)) <= 0 ||
        child_text(entry_start, entry_end, "instance-type",
                   type, sizeof(type)) <= 0 || strcmp(type, "vrf") != 0) {
        snprintf(err, err_size,
                 "VRF V1 requires instance-type vrf and a valid name");
        return -1;
    }
    if (next_entry(&cursor, section_end, "instance",
                   &section_start, &section_end) != 0) {
        snprintf(err, err_size,
                 "VRF V1 supports one additional routing instance");
        return -1;
    }
    snprintf(vrf->table, sizeof(vrf->table), "%s.inet.0", vrf->name);
    if_cursor = entry_start;
    if_end = find_open_tag(entry_start, entry_end, "routing-options");
    if (!if_end)
        if_end = entry_end;
    while ((rc = next_child_text(&if_cursor, if_end, "interface",
                                 interface, sizeof(interface))) != 0) {
        if (rc < 0 || vrf->n_interfaces >= 8) {
            snprintf(err, err_size,
                     "VRF V1 interface assignment exceeds capacity");
            return -1;
        }
        for (int i = 0; i < vrf->n_interfaces; i++) {
            if (strcmp(vrf->interfaces[i], interface) == 0) {
                snprintf(err, err_size,
                         "duplicate VRF interface assignment: %s",
                         interface);
                return -1;
            }
        }
        snprintf(vrf->interfaces[vrf->n_interfaces],
                 sizeof(vrf->interfaces[0]), "%s", interface);
        vrf->n_interfaces++;
    }
    if (vrf->n_interfaces == 0) {
        snprintf(err, err_size,
                 "VRF V1 requires at least one routed interface");
        return -1;
    }
    vrf->enabled = true;
    return 0;
}

static int build_interfaces_routing(const char *xml, const char *xml_end,
                                    char *plan, size_t plan_size, int *off,
                                    bool *has_l3,
                                    const l3_vrf_context *vrf, char *err,
                                    size_t err_size) {
    const char *section;
    const char *section_start;
    const char *section_end;
    const char *cursor;
    bool used_vlan[4095] = {false};
    int rif_count = 0;
    int rc;

    section = find_open_tag(xml, xml_end, "interfaces-routing");
    if (!section)
        return 0;
    *has_l3 = true;
    if (tag_body(section, xml_end, "interfaces-routing",
                 &section_start, &section_end) != 0) {
        snprintf(err, err_size, "malformed interfaces-routing XML");
        return -1;
    }
    cursor = section_start;
    while (1) {
        const char *entry_start;
        const char *entry_end;
        char name[128];
        char vlan[32];
        char address[64];
        char port[128] = {0};
        nl_port_entry port_entry;
        int vlan_id = 0;
        int hidden_vlan = 0;
        bool physical;
        const char *table;

        rc = next_entry(&cursor, section_end, "interface",
                        &entry_start, &entry_end);
        if (rc == 0)
            break;
        if (rc < 0) {
            snprintf(err, err_size, "malformed interfaces-routing interface XML");
            return -1;
        }
        if (rif_count >= NL_L3_PERSISTENT_MAX_RIFS) {
            snprintf(err, err_size,
                     "persistent routed interface capacity exceeded");
            return -1;
        }
        rif_count++;
        if (child_text(entry_start, entry_end, "name",
                       name, sizeof(name)) <= 0 ||
            child_text(entry_start, entry_end, "address",
                       address, sizeof(address)) <= 0) {
            snprintf(err, err_size,
                     "incomplete L3 routed interface; name and address are required");
            return -1;
        }
        memset(&port_entry, 0, sizeof(port_entry));
        physical = physical_rif_port(name, port, sizeof(port),
                                     &port_entry, &hidden_vlan);
        if (physical) {
            if (child_text(entry_start, entry_end, "vlan",
                           vlan, sizeof(vlan)) > 0) {
                snprintf(err, err_size,
                         "physical routed interface %s must use its compiler-owned internal VLAN",
                         name);
                return -1;
            }
            vlan_id = hidden_vlan;
            snprintf(vlan, sizeof(vlan), "%d", vlan_id);
            if (configured_vlan_id_exists(xml, xml_end, vlan_id)) {
                snprintf(err, err_size,
                         "physical routed interface %s internal VLAN %d conflicts with configured VLAN",
                         name, vlan_id);
                return -1;
            }
            if (physical_port_has_l2_intent(xml, xml_end, port)) {
                snprintf(err, err_size,
                         "physical routed interface %s conflicts with Layer-2 intent on %s",
                         name, port);
                return -1;
            }
        } else {
            if (strstr(name, "/")) {
                snprintf(err, err_size,
                         "physical routed interface %s is not an external ROUTE-capable unit 0 port",
                         name);
                return -1;
            }
            if (child_text(entry_start, entry_end, "vlan",
                           vlan, sizeof(vlan)) <= 0 &&
                !infer_vlan_from_rif_name(name, vlan, sizeof(vlan))) {
                snprintf(err, err_size,
                         "incomplete L3 routed interface; use irb.<vlan> or a ROUTE-capable physical unit 0 interface");
                return -1;
            }
            if (!parse_int_range(vlan, 1, 4094, &vlan_id)) {
                snprintf(err, err_size, "invalid routed interface VLAN");
                return -1;
            }
        }
        if (used_vlan[vlan_id]) {
            snprintf(err, err_size,
                     "duplicate routed interface VLAN: %d", vlan_id);
            return -1;
        }
        used_vlan[vlan_id] = true;
        table = vrf_has_interface(vrf, name) ? vrf->table : "inet.0";
        rc = physical ?
            append_line(plan, plan_size, off,
                        "rif name %s vlan %s port %s address %s table %s\n",
                        name, vlan, port, address, table) :
            append_line(plan, plan_size, off,
                        "rif name %s vlan %s address %s table %s\n",
                        name, vlan, address, table);
        if (rc != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
    }
    if (vrf && vrf->enabled) {
        l3_rif_ref refs[NL_L3_PERSISTENT_MAX_RIFS];
        int ref_count = 0;

        if (collect_rif_refs(xml, xml_end, refs, &ref_count, vrf, true,
                             err, err_size) != 0)
            return -1;
        if (ref_count != vrf->n_interfaces) {
            snprintf(err, err_size,
                     "VRF interface assignment references an incomplete routed interface");
            return -1;
        }
    }
    return 0;
}

static bool xml_has_l3_config(const char *xml) {
    const char *end;
    const char *protocols;
    const char *body_start;
    const char *body_end;

    if (!xml)
        return false;
    end = xml + strlen(xml);
    if (find_open_tag(xml, end, "interfaces-routing") ||
        find_open_tag(xml, end, "routing-options") ||
        find_open_tag(xml, end, "routing-instances") ||
        find_open_tag(xml, end, "policy-options"))
        return true;
    protocols = find_open_tag(xml, end, "protocols");
    if (!protocols || tag_body(protocols, end, "protocols",
                               &body_start, &body_end) != 0)
        return false;
    return find_open_tag(body_start, body_end, "ospf") ||
           find_open_tag(body_start, body_end, "bgp");
}

static int build_dynamic_l3_protocols(const char *xml, const char *xml_end,
                                      char *plan, size_t plan_size, int *off,
                                      bool *has_l3, char *err,
                                      size_t err_size) {
    const char *protocols;
    const char *protocols_start;
    const char *protocols_end;
    const char *ospf;
    const char *ospf_start;
    const char *ospf_end;
    const char *bgp;
    const char *bgp_start;
    const char *bgp_end;
    const char *cursor;
    int rc;

    protocols = find_open_tag(xml, xml_end, "protocols");
    if (!protocols)
        return 0;
    if (tag_body(protocols, xml_end, "protocols",
                 &protocols_start, &protocols_end) != 0) {
        snprintf(err, err_size, "malformed protocols XML");
        return -1;
    }
    ospf = find_open_tag(protocols_start, protocols_end, "ospf");
    if (ospf) {
        *has_l3 = true;
        if (tag_body(ospf, protocols_end, "ospf",
                     &ospf_start, &ospf_end) != 0) {
            snprintf(err, err_size, "malformed protocols ospf XML");
            return -1;
        }
        if (append_line(plan, plan_size, off,
                        "protocol ospf table inet.0\n") != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
        cursor = ospf_start;
        while ((rc = next_entry(&cursor, ospf_end, "area",
                                &bgp_start, &bgp_end)) != 0) {
            char area[32];
            const char *if_cursor;
            const char *area_start = bgp_start;
            const char *area_end = bgp_end;

            if (rc < 0) {
                snprintf(err, err_size, "malformed OSPF area XML");
                return -1;
            }
            if (child_text(area_start, area_end, "name",
                           area, sizeof(area)) <= 0) {
                snprintf(err, err_size, "incomplete OSPF area; name is required");
                return -1;
            }
            if (append_line(plan, plan_size, off,
                            "protocol ospf area %s table inet.0\n",
                            area) != 0) {
                snprintf(err, err_size, "L3 plan exceeds buffer");
                return -1;
            }
            if_cursor = area_start;
            while ((rc = next_entry(&if_cursor, area_end, "interface",
                                    &bgp_start, &bgp_end)) != 0) {
                char ifname[128];
                const char *if_start = bgp_start;
                const char *if_end = bgp_end;

                if (rc < 0) {
                    snprintf(err, err_size,
                             "malformed OSPF area interface XML");
                    return -1;
                }
                if (child_text(if_start, if_end, "name",
                               ifname, sizeof(ifname)) <= 0) {
                    snprintf(err, err_size,
                             "incomplete OSPF interface; name is required");
                    return -1;
                }
                if (append_line(plan, plan_size, off,
                                "protocol ospf area %s interface %s "
                                "table inet.0\n",
                                area, ifname) != 0) {
                    snprintf(err, err_size, "L3 plan exceeds buffer");
                    return -1;
                }
            }
        }
    }
    bgp = find_open_tag(protocols_start, protocols_end, "bgp");
    if (bgp) {
        *has_l3 = true;
        if (tag_body(bgp, protocols_end, "bgp", &bgp_start, &bgp_end) != 0) {
            snprintf(err, err_size, "malformed protocols bgp XML");
            return -1;
        }
        if (append_line(plan, plan_size, off,
                        "protocol bgp table inet.0\n") != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
        cursor = bgp_start;
        while ((rc = next_entry(&cursor, bgp_end, "group",
                                &ospf_start, &ospf_end)) != 0) {
            char group[128];
            char type[32];
            char export_policy[128];
            char hold_time[32];
            const char *nbr_cursor;
            const char *group_start = ospf_start;
            const char *group_end = ospf_end;

            if (rc < 0) {
                snprintf(err, err_size, "malformed BGP group XML");
                return -1;
            }
            if (child_text(group_start, group_end, "name",
                           group, sizeof(group)) <= 0 ||
                child_text(group_start, group_end, "type",
                           type, sizeof(type)) <= 0) {
                snprintf(err, err_size,
                         "incomplete BGP group; name and type are required");
                return -1;
            }
            if (append_line(plan, plan_size, off,
                            "protocol bgp group %s type %s table inet.0\n",
                            group, type) != 0) {
                snprintf(err, err_size, "L3 plan exceeds buffer");
                return -1;
            }
            if (child_text(group_start, group_end, "export",
                           export_policy, sizeof(export_policy)) > 0 &&
                append_line(plan, plan_size, off,
                            "protocol bgp group %s export %s table inet.0\n",
                            group, export_policy) != 0) {
                snprintf(err, err_size, "L3 plan exceeds buffer");
                return -1;
            }
            if (child_text(group_start, group_end, "hold-time",
                           hold_time, sizeof(hold_time)) > 0 &&
                append_line(plan, plan_size, off,
                            "protocol bgp group %s hold-time %s "
                            "table inet.0\n",
                            group, hold_time) != 0) {
                snprintf(err, err_size, "L3 plan exceeds buffer");
                return -1;
            }
            nbr_cursor = group_start;
            while ((rc = next_entry(&nbr_cursor, group_end, "neighbor",
                                    &ospf_start, &ospf_end)) != 0) {
                char address[64];
                char peer_as[32];
                const char *nbr_start = ospf_start;
                const char *nbr_end = ospf_end;

                if (rc < 0) {
                    snprintf(err, err_size, "malformed BGP neighbor XML");
                    return -1;
                }
                if (child_text(nbr_start, nbr_end, "address",
                               address, sizeof(address)) <= 0 ||
                    child_text(nbr_start, nbr_end, "peer-as",
                               peer_as, sizeof(peer_as)) <= 0) {
                    snprintf(err, err_size,
                             "incomplete BGP neighbor; address and peer-as are required");
                    return -1;
                }
                if (append_line(plan, plan_size, off,
                                "protocol bgp group %s neighbor %s "
                                "peer-as %s table inet.0\n",
                                group, address, peer_as) != 0) {
                    snprintf(err, err_size, "L3 plan exceeds buffer");
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int build_policy_options(const char *xml, const char *xml_end,
                                char *plan, size_t plan_size, int *off,
                                bool *has_l3, char *err,
                                size_t err_size) {
    const char *policy_options;
    const char *policies_start;
    const char *policies_end;
    const char *cursor;
    int rc;

    policy_options = find_open_tag(xml, xml_end, "policy-options");
    if (!policy_options)
        return 0;
    *has_l3 = true;
    if (tag_body(policy_options, xml_end, "policy-options",
                 &policies_start, &policies_end) != 0) {
        snprintf(err, err_size, "malformed policy-options XML");
        return -1;
    }
    cursor = policies_start;
    const char *policy_start;
    const char *policy_end;
    while ((rc = next_entry(&cursor, policies_end, "policy-statement",
                            &policy_start, &policy_end)) != 0) {
        char policy[128];
        const char *term_cursor;

        if (rc < 0) {
            snprintf(err, err_size, "malformed policy-statement XML");
            return -1;
        }
        if (child_text(policy_start, policy_end, "name",
                       policy, sizeof(policy)) <= 0) {
            snprintf(err, err_size,
                     "incomplete policy-statement; name is required");
            return -1;
        }
        term_cursor = policy_start;
        const char *term_start;
        const char *term_end;
        while ((rc = next_entry(&term_cursor, policy_end, "term",
                                &term_start, &term_end)) != 0) {
            char term[128];
            const char *from;
            const char *from_start;
            const char *from_end;
            const char *then;
            const char *then_start;
            const char *then_end;
            const char *rf_cursor;
            char action[32];

            if (rc < 0) {
                snprintf(err, err_size, "malformed policy term XML");
                return -1;
            }
            if (child_text(term_start, term_end, "name",
                           term, sizeof(term)) <= 0) {
                snprintf(err, err_size,
                         "incomplete policy term; name is required");
                return -1;
            }
            then = find_open_tag(term_start, term_end, "then");
            if (!then || tag_body(then, term_end, "then",
                                  &then_start, &then_end) != 0 ||
                child_text(then_start, then_end, "action",
                           action, sizeof(action)) <= 0) {
                snprintf(err, err_size,
                         "incomplete policy term; then action is required");
                return -1;
            }
            if (strcmp(action, "accept") != 0 &&
                strcmp(action, "reject") != 0) {
                snprintf(err, err_size,
                         "unsupported policy action: %s", action);
                return -1;
            }
            from = find_open_tag(term_start, term_end, "from");
            if (!from || tag_body(from, term_end, "from",
                                  &from_start, &from_end) != 0) {
                snprintf(err, err_size,
                         "incomplete policy term; from route-filter is required");
                return -1;
            }
            rf_cursor = from_start;
            const char *rf_start;
            const char *rf_end;
            int route_filters = 0;
            while ((rc = next_entry(&rf_cursor, from_end, "route-filter",
                                    &rf_start, &rf_end)) != 0) {
                char prefix[64];
                char match_type[32];

                if (rc < 0) {
                    snprintf(err, err_size,
                             "malformed policy route-filter XML");
                    return -1;
                }
                if (child_text(rf_start, rf_end, "prefix",
                               prefix, sizeof(prefix)) <= 0) {
                    snprintf(err, err_size,
                             "incomplete policy route-filter; prefix is required");
                    return -1;
                }
                if (child_text(rf_start, rf_end, "match-type",
                               match_type, sizeof(match_type)) <= 0)
                    snprintf(match_type, sizeof(match_type), "exact");
                if (strcmp(match_type, "exact") != 0) {
                    snprintf(err, err_size,
                             "unsupported policy route-filter match-type: %s",
                             match_type);
                    return -1;
                }
                if (append_line(plan, plan_size, off,
                                "policy statement %s term %s "
                                "route-filter %s %s then %s\n",
                                policy, term, prefix, match_type,
                                action) != 0) {
                    snprintf(err, err_size, "L3 plan exceeds buffer");
                    return -1;
                }
                route_filters++;
            }
            if (route_filters == 0) {
                snprintf(err, err_size,
                         "incomplete policy term; from route-filter is required");
                return -1;
            }
        }
    }
    return 0;
}

static int build_routing_options_global(const char *xml, const char *xml_end,
                                        char *plan, size_t plan_size,
                                        int *off, bool *has_l3,
                                        char *err, size_t err_size) {
    const char *routing;
    const char *routing_start;
    const char *routing_end;
    const char *routing_instances;
    char asn[32];

    routing = find_open_tag(xml, xml_end, "routing-options");
    routing_instances = find_open_tag(xml, xml_end, "routing-instances");
    if (routing && routing_instances && routing > routing_instances)
        routing = NULL;
    if (!routing)
        return 0;
    if (tag_body(routing, xml_end, "routing-options",
                 &routing_start, &routing_end) != 0) {
        snprintf(err, err_size, "malformed routing-options XML");
        return -1;
    }
    if (child_text(routing_start, routing_end, "autonomous-system",
                   asn, sizeof(asn)) > 0) {
        *has_l3 = true;
        if (append_line(plan, plan_size, off,
                        "protocol bgp local-as %s table inet.0\n",
                        asn) != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
    }
    return 0;
}

static int build_static_l3_scope(const char *xml, const char *xml_end,
                                 const char *scope_start,
                                 const char *scope_end,
                                 const char *table,
                                 const l3_vrf_context *vrf,
                                 bool vrf_scope,
                                 char *plan, size_t plan_size, int *off,
                                 bool *has_l3, char *err,
                                 size_t err_size) {
    const char *routing_start = scope_start;
    const char *routing_end = scope_end;
    const char *static_node;
    const char *static_start;
    const char *static_end;
    const char *cursor;
    l3_static_arp_ref arp_refs[NL_L3_PERSISTENT_MAX_ARP];
    l3_static_nh_ref nh_refs[NL_L3_PERSISTENT_MAX_NEXTHOPS];
    l3_rif_ref rif_refs[NL_L3_PERSISTENT_MAX_RIFS];
    char ecmp_ids[NL_L3_PERSISTENT_MAX_ECMP][32];
    int arp_ref_count = 0;
    int nh_ref_count = 0;
    int rif_ref_count = 0;
    int ecmp_id_count = 0;
    int route_count = 0;
    int rc;

    if (!routing_start || !routing_end || !table)
        return 0;
    *has_l3 = true;
    static_node = find_open_tag(routing_start, routing_end, "static");
    if (!static_node)
        return 0;
    if (tag_body(static_node, routing_end, "static",
                 &static_start, &static_end) != 0) {
        snprintf(err, err_size, "malformed routing-options static XML");
        return -1;
    }
    if (collect_rif_refs(xml, xml_end, rif_refs, &rif_ref_count,
                         vrf, vrf_scope,
                         err, err_size) != 0)
        return -1;

    cursor = static_start;
    while ((rc = next_entry(&cursor, static_end, "arp",
                            &routing_start, &routing_end)) != 0) {
        char ip[64], mac[64], rif[128], egress[128];

        if (rc < 0) {
            snprintf(err, err_size, "malformed static ARP XML");
            return -1;
        }
        if (child_text(routing_start, routing_end, "ip", ip, sizeof(ip)) <= 0 ||
            child_text(routing_start, routing_end, "mac", mac, sizeof(mac)) <= 0) {
            snprintf(err, err_size,
                     "incomplete static ARP entry; ip and mac are required");
            return -1;
        }
        {
            int rif_rc = child_text(routing_start, routing_end, "interface",
                                    rif, sizeof(rif));
            if (rif_rc < 0) {
                snprintf(err, err_size, "malformed static ARP interface XML");
                return -1;
            }
            if (rif_rc == 0 &&
                infer_rif_ref_for_ip(rif_refs, rif_ref_count, ip, rif,
                                     sizeof(rif), err, err_size) != 0)
                return -1;
        }
        if (child_text(routing_start, routing_end, "egress-interface",
                       egress, sizeof(egress)) > 0) {
            if (append_line(plan, plan_size, off,
                            "arp ip %s mac %s interface %s egress-port %s table %s\n",
                            ip, mac, rif, egress, table) != 0) {
                snprintf(err, err_size, "L3 plan exceeds buffer");
                return -1;
            }
        } else if (append_line(plan, plan_size, off,
                               "arp ip %s mac %s interface %s table %s\n",
                               ip, mac, rif, table) != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
        if (add_arp_ref(arp_refs, &arp_ref_count, ip, rif,
                        err, err_size) != 0)
            return -1;
    }

    cursor = static_start;
    while ((rc = next_entry(&cursor, static_end, "next-hop",
                            &routing_start, &routing_end)) != 0) {
        char id[32], arp[64], rif[128];

        if (rc < 0) {
            snprintf(err, err_size, "malformed static next-hop XML");
            return -1;
        }
        if (child_text(routing_start, routing_end, "id", id, sizeof(id)) <= 0 ||
            child_text(routing_start, routing_end, "arp-ip", arp, sizeof(arp)) <= 0 ||
            child_text(routing_start, routing_end, "interface",
                       rif, sizeof(rif)) <= 0) {
            snprintf(err, err_size,
                     "incomplete static next-hop; id, arp and interface are required");
            return -1;
        }
        if (append_line(plan, plan_size, off,
                        "next-hop id %s arp %s interface %s table %s\n",
                        id, arp, rif, table) != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
        if (add_nh_ref(nh_refs, &nh_ref_count, id, arp, rif,
                       err, err_size) != 0)
            return -1;
    }

    cursor = static_start;
    while ((rc = next_entry(&cursor, static_end, "ecmp",
                            &routing_start, &routing_end)) != 0) {
        char id[32], member[32], members[512] = {0};
        const char *member_cursor;
        int member_count = 0;

        if (rc < 0) {
            snprintf(err, err_size, "malformed static ECMP XML");
            return -1;
        }
        if (child_text(routing_start, routing_end, "id", id, sizeof(id)) <= 0) {
            snprintf(err, err_size, "incomplete static ECMP group; id is required");
            return -1;
        }
        member_cursor = routing_start;
        while ((rc = next_child_text(&member_cursor, routing_end, "member",
                                     member, sizeof(member))) != 0) {
            if (rc < 0) {
                snprintf(err, err_size, "malformed static ECMP member XML");
                return -1;
            }
            if (member_count >= NL_L3_PERSISTENT_MAX_ECMP_MEMBERS) {
                snprintf(err, err_size,
                         "static ECMP member capacity exceeded");
                return -1;
            }
            if (member_count > 0 &&
                append_token(members, sizeof(members), ",") != 0) {
                snprintf(err, err_size, "static ECMP member list too long");
                return -1;
            }
            if (append_token(members, sizeof(members), member) != 0) {
                snprintf(err, err_size, "static ECMP member list too long");
                return -1;
            }
            member_count++;
        }
        if (member_count == 0) {
            snprintf(err, err_size,
                     "incomplete static ECMP group; at least one member is required");
            return -1;
        }
        if (append_line(plan, plan_size, off,
                        "ecmp id %s members %s table %s\n", id, members,
                        table) != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
        if (add_string_id(ecmp_ids, &ecmp_id_count, id,
                          NL_L3_PERSISTENT_MAX_ECMP, err, err_size,
                          "ECMP") != 0)
            return -1;
    }

    cursor = static_start;
    while ((rc = next_entry(&cursor, static_end, "route",
                            &routing_start, &routing_end)) != 0) {
        char prefix[64], nexthop[32], nexthop_ip_tmp[64], ecmp[32];
        char nexthop_ips[L3_RIB_STATIC_MAX_NEXTHOPS][64];
        char ecmp_members[512] = {0};
        char rib_nexthops[1024] = {0};
        const char *nh_cursor;
        int has_nh_id;
        int nh_ip_count = 0;
        int has_ecmp;
        int target_count;
        bool rib_only = false;

        if (rc < 0) {
            snprintf(err, err_size, "malformed static route XML");
            return -1;
        }
        if (route_count >= NL_L3_PERSISTENT_MAX_ROUTES) {
            snprintf(err, err_size,
                     "persistent route capacity exceeded");
            return -1;
        }
        route_count++;
        has_nh_id = child_text(routing_start, routing_end, "next-hop-id",
                               nexthop, sizeof(nexthop));
        nh_cursor = routing_start;
        while ((rc = next_child_text(&nh_cursor, routing_end,
                                     "next-hop-address",
                                     nexthop_ip_tmp,
                                     sizeof(nexthop_ip_tmp))) != 0) {
            if (rc < 0) {
                snprintf(err, err_size,
                         "malformed static route next-hop XML");
                return -1;
            }
            if (nh_ip_count >= L3_RIB_STATIC_MAX_NEXTHOPS) {
                snprintf(err, err_size,
                         "too many static route next-hop addresses");
                return -1;
            }
            snprintf(nexthop_ips[nh_ip_count], sizeof(nexthop_ips[0]),
                     "%s", nexthop_ip_tmp);
            nh_ip_count++;
        }
        has_ecmp = child_text(routing_start, routing_end, "ecmp-id",
                              ecmp, sizeof(ecmp));
        target_count = (has_nh_id > 0) + (nh_ip_count > 0) + (has_ecmp > 0);
        if (child_text(routing_start, routing_end, "prefix",
                       prefix, sizeof(prefix)) <= 0 ||
            target_count != 1) {
            snprintf(err, err_size,
                     "incomplete static route; prefix and exactly one next-hop or ecmp target are required");
            return -1;
        }
        if (nh_ip_count > 0) {
            for (int i = 0; i < nh_ip_count; i++) {
                const char *nexthop_ip = nexthop_ips[i];
                int nh_idx = find_nh_by_arp(nh_refs, nh_ref_count,
                                            nexthop_ip);
                char member_nh[32];
                char member_rif[128];

                member_nh[0] = '\0';
                member_rif[0] = '\0';
                if (nh_idx >= 0) {
                    snprintf(member_nh, sizeof(member_nh), "%s",
                             nh_refs[nh_idx].id);
                    snprintf(member_rif, sizeof(member_rif), "%s",
                             nh_refs[nh_idx].rif);
                } else {
                    int arp_idx = find_arp_ref(arp_refs, arp_ref_count,
                                               nexthop_ip);
                    if (arp_idx < 0) {
                        int rif_idx = find_rif_ref_for_ip(
                            rif_refs, rif_ref_count, nexthop_ip);
                        if (rif_idx < 0) {
                            snprintf(err, err_size,
                                     "static route next-hop %s has no connected routed interface",
                                     nexthop_ip);
                            return -1;
                        }
                        snprintf(member_rif, sizeof(member_rif), "%s",
                                 rif_refs[rif_idx].name);
                        rib_only = true;
                    } else {
                        snprintf(member_rif, sizeof(member_rif), "%s",
                                 arp_refs[arp_idx].rif);
                        if (allocate_auto_nh_id(nh_refs, nh_ref_count,
                                                member_nh,
                                                sizeof(member_nh)) != 0) {
                            snprintf(err, err_size,
                                     "unable to allocate internal next-hop id for %s",
                                     nexthop_ip);
                            return -1;
                        }
                        if (append_line(plan, plan_size, off,
                                        "next-hop id %s arp %s interface %s table %s\n",
                                        member_nh, nexthop_ip,
                                        arp_refs[arp_idx].rif, table) != 0) {
                            snprintf(err, err_size, "L3 plan exceeds buffer");
                            return -1;
                        }
                        if (add_nh_ref(nh_refs, &nh_ref_count, member_nh,
                                       nexthop_ip, arp_refs[arp_idx].rif,
                                       err, err_size) != 0)
                            return -1;
                    }
                }
                if (i > 0 && append_token(rib_nexthops,
                                          sizeof(rib_nexthops), ",") != 0) {
                    snprintf(err, err_size,
                             "static route RIB nexthop list too long");
                    return -1;
                }
                if (append_token(rib_nexthops, sizeof(rib_nexthops),
                                 nexthop_ip) != 0 ||
                    append_token(rib_nexthops, sizeof(rib_nexthops),
                                 "@") != 0 ||
                    append_token(rib_nexthops, sizeof(rib_nexthops),
                                 member_rif) != 0) {
                    snprintf(err, err_size,
                             "static route RIB nexthop list too long");
                    return -1;
                }
                if (nh_ip_count == 1) {
                    snprintf(nexthop, sizeof(nexthop), "%s", member_nh);
                    has_nh_id = 1;
                    continue;
                }
                if (i > 0 && append_token(ecmp_members,
                                          sizeof(ecmp_members), ",") != 0) {
                    snprintf(err, err_size,
                             "static route ECMP member list too long");
                    return -1;
                }
                if (append_token(ecmp_members, sizeof(ecmp_members),
                                 member_nh) != 0) {
                    snprintf(err, err_size,
                             "static route ECMP member list too long");
                    return -1;
                }
            }
            if (nh_ip_count > 1) {
                if (rib_only)
                    goto emit_rib_static_route;
                if (allocate_auto_ecmp_id(ecmp_ids, ecmp_id_count,
                                          ecmp, sizeof(ecmp)) != 0) {
                    snprintf(err, err_size,
                             "unable to allocate internal ECMP id for %s",
                             prefix);
                    return -1;
                }
                if (append_line(plan, plan_size, off,
                                "ecmp id %s members %s table %s\n", ecmp,
                                ecmp_members, table) != 0) {
                    snprintf(err, err_size, "L3 plan exceeds buffer");
                    return -1;
                }
                if (add_string_id(ecmp_ids, &ecmp_id_count, ecmp,
                                  NL_L3_PERSISTENT_MAX_ECMP, err,
                                  err_size, "ECMP") != 0)
                    return -1;
                has_ecmp = 1;
                has_nh_id = 0;
            }
            if (rib_only)
                goto emit_rib_static_route;
        }
        if (has_nh_id > 0 && !nh_id_used(nh_refs, nh_ref_count, nexthop)) {
            snprintf(err, err_size,
                     "static route references unknown next-hop id %s",
                     nexthop);
            return -1;
        }
        if (has_ecmp > 0 && !string_id_used(ecmp_ids, ecmp_id_count, ecmp)) {
            snprintf(err, err_size,
                     "static route references unknown ECMP id %s", ecmp);
            return -1;
        }
        if (append_line(plan, plan_size, off,
                        has_nh_id > 0 ?
                        "route prefix %s next-hop %s table %s\n" :
                        "route prefix %s ecmp %s table %s\n",
                        prefix, has_nh_id > 0 ? nexthop : ecmp,
                        table) != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
        continue;

emit_rib_static_route:
        if (append_line(plan, plan_size, off,
                        "rib-static-route prefix %s nexthops %s table %s\n",
                        prefix, rib_nexthops, table) != 0) {
            snprintf(err, err_size, "L3 plan exceeds buffer");
            return -1;
        }
    }
    return 0;
}

static int build_static_l3(const char *xml, const char *xml_end,
                           const l3_vrf_context *vrf,
                           char *plan, size_t plan_size, int *off,
                           bool *has_l3, char *err, size_t err_size) {
    const char *routing;
    const char *routing_start;
    const char *routing_end;
    const char *routing_instances;

    routing = find_open_tag(xml, xml_end, "routing-options");
    routing_instances = find_open_tag(xml, xml_end, "routing-instances");
    if (routing && routing_instances && routing > routing_instances)
        routing = NULL;
    if (!routing)
        return 0;
    if (tag_body(routing, xml_end, "routing-options",
                 &routing_start, &routing_end) != 0) {
        snprintf(err, err_size, "malformed routing-options XML");
        return -1;
    }
    return build_static_l3_scope(xml, xml_end, routing_start, routing_end,
                                 "inet.0", vrf, false,
                                 plan, plan_size, off, has_l3,
                                 err, err_size);
}

static int build_vrf_l3(const char *xml, const char *xml_end,
                        const l3_vrf_context *vrf,
                        char *plan, size_t plan_size, int *off,
                        bool *has_l3, char *err, size_t err_size) {
    const char *section;
    const char *section_start;
    const char *section_end;
    const char *instance_start;
    const char *instance_end;
    const char *routing;
    const char *routing_start;
    const char *routing_end;
    const char *cursor;

    if (!vrf || !vrf->enabled)
        return 0;
    *has_l3 = true;
    section = find_open_tag(xml, xml_end, "routing-instances");
    if (!section || tag_body(section, xml_end, "routing-instances",
                             &section_start, &section_end) != 0) {
        snprintf(err, err_size, "malformed routing-instances XML");
        return -1;
    }
    cursor = section_start;
    if (next_entry(&cursor, section_end, "instance",
                   &instance_start, &instance_end) <= 0) {
        snprintf(err, err_size, "missing VRF V1 instance");
        return -1;
    }
    routing = find_open_tag(instance_start, instance_end, "routing-options");
    if (!routing)
        return 0;
    if (tag_body(routing, instance_end, "routing-options",
                 &routing_start, &routing_end) != 0) {
        snprintf(err, err_size, "malformed VRF routing-options XML");
        return -1;
    }
    return build_static_l3_scope(xml, xml_end, routing_start, routing_end,
                                 vrf->table, vrf, true,
                                 plan, plan_size, off, has_l3,
                                 err, err_size);
}

static int build_vrf_owner(const l3_vrf_context *vrf,
                           char *plan, size_t plan_size, int *off,
                           bool *has_l3, char *err, size_t err_size) {
    if (!vrf || !vrf->enabled)
        return 0;
    *has_l3 = true;
    if (append_line(plan, plan_size, off,
                    "virtual-router name %s table %s vrid %d kernel-table %d\n",
                    vrf->name, vrf->table, L3_VRF_V1_VRID,
                    L3_VRF_V1_KERNEL_TABLE) != 0) {
        snprintf(err, err_size, "L3 plan exceeds buffer");
        return -1;
    }
    return 0;
}

int configd_l3_build_plan(nl_yang_session *active,
                          nl_yang_session *candidate,
                          char *plan, size_t plan_size,
                          int *plan_len, bool *has_l3,
                          char *err, size_t err_size) {
    char *active_xml = NULL;
    char *xml = NULL;
    const char *xml_end;
    l3_vrf_context vrf;
    int off = 0;
    int ret = -1;

    if (err && err_size > 0)
        err[0] = '\0';
    if (plan && plan_size > 0)
        plan[0] = '\0';
    if (plan_len)
        *plan_len = 0;
    if (has_l3)
        *has_l3 = false;
    if (!active || !candidate || !plan || plan_size == 0 ||
        !plan_len || !has_l3) {
        snprintf(err, err_size, "invalid L3 plan request");
        return -1;
    }

    active_xml = nl_yang_to_xml(active);
    xml = nl_yang_to_xml(candidate);
    if (!active_xml || !xml) {
        snprintf(err, err_size, "failed to serialize config for rpd");
        goto out;
    }
    if (xml_has_l3_config(active_xml))
        *has_l3 = true;
    xml_end = xml + strlen(xml);
    if (collect_vrf_context(xml, xml_end, &vrf, err, err_size) != 0)
        goto out;
    if (append_line(plan, plan_size, &off,
                    "l3-plan version=%d\n", vrf.enabled ? 2 : 1) != 0) {
        snprintf(err, err_size, "L3 plan exceeds buffer");
        goto out;
    }
    if (build_vrf_owner(&vrf, plan, plan_size, &off,
                        has_l3, err, err_size) != 0)
        goto out;
    if (build_interfaces_routing(xml, xml_end, plan, plan_size, &off,
                                 has_l3, &vrf, err, err_size) != 0)
        goto out;
    if (build_routing_options_global(xml, xml_end, plan, plan_size, &off,
                                     has_l3, err, err_size) != 0)
        goto out;
    if (build_static_l3(xml, xml_end, &vrf, plan, plan_size, &off,
                        has_l3, err, err_size) != 0)
        goto out;
    if (build_vrf_l3(xml, xml_end, &vrf, plan, plan_size, &off,
                     has_l3, err, err_size) != 0)
        goto out;
    if (build_policy_options(xml, xml_end, plan, plan_size, &off,
                             has_l3, err, err_size) != 0)
        goto out;
    if (build_dynamic_l3_protocols(xml, xml_end, plan, plan_size, &off,
                                   has_l3, err, err_size) != 0)
        goto out;
    if (*has_l3 && append_platform_router_mac(plan, plan_size, &off) != 0) {
        snprintf(err, err_size, "L3 plan exceeds buffer");
        goto out;
    }

    *plan_len = off;
    ret = 0;

out:
    free(active_xml);
    free(xml);
    return ret;
}

int configd_l3_validate_plan(const char *plan, int plan_len, bool has_l3,
                             char *err, size_t err_size) {
    char resp[4096] = {0};
    s32 ec = 0;
    int rn;

    if (err && err_size > 0)
        err[0] = '\0';
    if (!has_l3 || plan_len <= 0)
        return 0;

    rn = nl_rpc_call_ex(rpd_socket_path(), NL_DAEMON_CONFIGD,
                        NL_DAEMON_RPD, NL_RPD_VALIDATE_PLAN, 0,
                        (const u8 *)plan, plan_len,
                        (u8 *)resp, sizeof(resp) - 1, 5000, &ec);
    if (rn >= 0 && ec == 0)
        return 0;

    if (err && err_size > 0)
        snprintf(err, err_size, "%s",
                 resp[0] ? resp : "rpd resource validation failed");
    return -1;
}

bool configd_l3_public_apply_enabled(void) {
    nl_platform_identity identity;
    nl_board_profile board;
    /* This release reserves L3 as an entry point only. Advertising route
     * slices or setting an environment variable cannot open that contract. */
    if ((nl_platform_identity_get(&identity) &&
         nl_fm10k_profile_known(identity.chassis_name)) ||
        (nl_platform_board_get(&board) && !strcmp(board.asic, "FM10840")))
        return false;
    if (env_truthy("NETLAB_DISABLE_L3_PUBLIC_COMMIT"))
        return false;
    return platform_l3_profile_ready();
}

bool configd_l3_full_replay_required(bool has_l3) {
    nl_platform_identity identity;
    nl_board_profile board;
    /* A recognized, fixed L2-only installation has no rpd owner to clear.
     * Retain empty-owner replay on other platforms, and never ignore L3
     * intent in either the source or the durable target configuration. */
    if (has_l3)
        return true;
    return !nl_platform_identity_get(&identity) ||
           !nl_fm10k_profile_known(identity.chassis_name) ||
           !nl_platform_board_get(&board) || strcmp(board.asic, "FM10840");
}

const char *configd_l3_public_apply_gate_reason(void) {
    nl_platform_identity identity;
    nl_board_profile board;
    if ((nl_platform_identity_get(&identity) &&
         nl_fm10k_profile_known(identity.chassis_name)) ||
        (nl_platform_board_get(&board) && !strcmp(board.asic, "FM10840")))
        return "FM10840 control-panel L3 writes are disabled in this L2-only release";
    return L3_PUBLIC_GATE_REASON;
}

static int l3_rpc_call(nl_rpc_method method, unsigned long long tx_id,
                       const char *payload, int payload_len,
                       char *resp, size_t resp_size, int *daemon_ec) {
    s32 ec = 0;
    int rn;

    if (resp && resp_size > 0)
        resp[0] = '\0';
    if (daemon_ec)
        *daemon_ec = 0;
    if (!resp || resp_size == 0)
        return -1;
    if (payload_len < 0)
        payload_len = payload ? (int)strlen(payload) : 0;
    rn = nl_rpc_call_ex(rpd_socket_path(), NL_DAEMON_CONFIGD, NL_DAEMON_RPD,
                        method, tx_id,
                        payload ? (const u8 *)payload : NULL,
                        payload_len, (u8 *)resp, resp_size - 1,
                        10000, &ec);
    if (rn >= 0)
        resp[rn] = '\0';
    if (daemon_ec)
        *daemon_ec = (int)ec;
    return rn;
}

typedef struct {
    int rifs;
    int arp;
    int next_hops;
    int routes;
    int ecmp_groups;
} l3_plan_counts;

static void l3_plan_count_objects(const char *plan, int plan_len,
                                  l3_plan_counts *counts) {
    const char *end;
    const char *p;

    if (!counts)
        return;
    memset(counts, 0, sizeof(*counts));
    if (!plan || plan_len <= 0)
        return;
    end = plan + plan_len;
    p = plan;
    while (p < end) {
        const char *line;

        while (p < end && (*p == '\n' || *p == '\r'))
            p++;
        if (p >= end)
            break;
        line = p;
        if (strncmp(line, "rif ", 4) == 0)
            counts->rifs++;
        else if (strncmp(line, "arp ", 4) == 0)
            counts->arp++;
        else if (strncmp(line, "next-hop ", 9) == 0)
            counts->next_hops++;
        else if (strncmp(line, "ecmp ", 5) == 0)
            counts->ecmp_groups++;
        else if (strncmp(line, "route ", 6) == 0)
            counts->routes++;
        while (p < end && *p != '\n')
            p++;
    }
}

static bool l3_plan_counts_empty(const l3_plan_counts *counts) {
    return !counts || (counts->rifs == 0 && counts->arp == 0 &&
                       counts->next_hops == 0 && counts->routes == 0 &&
                       counts->ecmp_groups == 0);
}

static int xml_attr_int(const char *tag, const char *end,
                        const char *attr, int *out) {
    char needle[96];
    const char *limit;
    const char *p;
    char *num_end = NULL;
    long v;

    if (!tag || !end || !attr || !out || tag >= end)
        return -1;
    limit = memchr(tag, '>', (size_t)(end - tag));
    if (!limit)
        return -1;
    snprintf(needle, sizeof(needle), "%s=\"", attr);
    p = bounded_strstr(tag, limit, needle);
    if (!p)
        return -1;
    p += strlen(needle);
    v = strtol(p, &num_end, 10);
    if (!num_end || num_end == p || *num_end != '"' ||
        v < 0 || v > 1000000L)
        return -1;
    *out = (int)v;
    return 0;
}

static bool xml_open_tag_attr_equals(const char *tag, const char *end,
                                     const char *attr,
                                     const char *expected) {
    char needle[160];
    const char *limit;
    const char *match;
    int n;

    if (!tag || !end || !attr || !expected || tag >= end)
        return false;
    limit = memchr(tag, '>', (size_t)(end - tag));
    if (!limit)
        return false;
    n = snprintf(needle, sizeof(needle), "%s=\"%s\"", attr, expected);
    if (n <= 0 || (size_t)n >= sizeof(needle))
        return false;
    match = bounded_strstr(tag, limit, needle);
    while (match) {
        if (match > tag && isspace((unsigned char)match[-1]))
            return true;
        match = bounded_strstr(match + 1, limit, needle);
    }
    return false;
}

static bool l3_persistent_result_has_common_evidence(
    const char *resp, const char *tag_name, unsigned long long tx_id,
    const char **open_out, const char **end_out) {
    char tx_text[32];
    const char *end;
    const char *open;

    if (!resp || !tag_name)
        return false;
    end = resp + strlen(resp);
    open = find_open_tag(resp, end, tag_name);
    if (!open)
        return false;
    snprintf(tx_text, sizeof(tx_text), "%llu", tx_id);
    if (!xml_open_tag_attr_equals(open, end, "tx-id", tx_text) ||
        !xml_open_tag_attr_equals(open, end, "hardware-apply",
                                  "persistent") ||
        !xml_open_tag_attr_equals(open, end, "sdk-readback", "live") ||
        !xml_open_tag_attr_equals(open, end, "hw-sync", "in-sync") ||
        !xml_open_tag_attr_equals(open, end, "persistent-hw-out-of-sync",
                                  "false"))
        return false;
    if (open_out)
        *open_out = open;
    if (end_out)
        *end_out = end;
    return true;
}

static int owner_usage_attr(const char *usage, const char *end,
                            const char *primary, const char *fallback) {
    int value = -1;

    if (xml_attr_int(usage, end, primary, &value) == 0)
        return value;
    if (fallback && xml_attr_int(usage, end, fallback, &value) == 0)
        return value;
    return -1;
}

static bool l3_readback_usage_covers_plan(const char *resp,
                                          const l3_plan_counts *counts) {
    const char *end;
    const char *owner;
    const char *body_start;
    const char *body_end;
    const char *usage;
    int rifs;
    int arp;
    int next_hops;
    int routes;
    int ecmp_groups;

    if (!resp || !counts)
        return false;
    end = resp + strlen(resp);
    owner = find_open_tag(resp, end, "l3-persistent-owner-readback");
    if (!owner || tag_body(owner, end, "l3-persistent-owner-readback",
                           &body_start, &body_end) != 0)
        return false;
    usage = find_open_tag(body_start, body_end, "usage");
    if (!usage)
        return false;
    rifs = owner_usage_attr(usage, body_end, "rifs", NULL);
    arp = owner_usage_attr(usage, body_end, "arp", NULL);
    next_hops = owner_usage_attr(usage, body_end, "next-hops", NULL);
    routes = owner_usage_attr(usage, body_end, "routes", "fib-routes");
    ecmp_groups = owner_usage_attr(usage, body_end, "ecmp-groups", NULL);
    return rifs >= counts->rifs &&
           arp >= counts->arp &&
           next_hops >= counts->next_hops &&
           routes >= counts->routes &&
           ecmp_groups >= counts->ecmp_groups;
}

int configd_l3_apply_plan(const char *plan, int plan_len, bool has_l3,
                          unsigned long long tx_id, char *resp,
                          size_t resp_size, int *daemon_ec) {
    if (!has_l3 || plan_len <= 0)
        return 0;
    return l3_rpc_call(NL_RPD_APPLY_PLAN, tx_id, plan, plan_len,
                       resp, resp_size,
                       daemon_ec);
}

int configd_l3_verify_readback(const char *plan, int plan_len, bool has_l3,
                               char *resp, size_t resp_size,
                               int *daemon_ec) {
    int rn;
    l3_plan_counts counts;
    bool expects_objects;

    if (!has_l3)
        return 0;
    l3_plan_count_objects(plan, plan_len, &counts);
    expects_objects = !l3_plan_counts_empty(&counts);
    rn = l3_rpc_call(NL_RPD_READBACK, 0, NULL, 0,
                     resp, resp_size, daemon_ec);
    if (rn < 0 || (daemon_ec && *daemon_ec != 0))
        return rn < 0 ? rn : -1;
    if (!strstr(resp, "<persistent-l3-owner-readback")) {
        if (daemon_ec)
            *daemon_ec = NL_ERR_INVALID_VALUE;
        return -1;
    }
    if (expects_objects &&
        (!strstr(resp, "owner-mode=\"persistent\"") ||
         !strstr(resp, "hardware-apply=\"persistent\"") ||
         !strstr(resp, "sdk-readback=\"live\"") ||
         !strstr(resp, "<l3-persistent-owner-readback status=\"ok\"") ||
         !l3_readback_usage_covers_plan(resp, &counts))) {
        if (daemon_ec)
            *daemon_ec = NL_ERR_INVALID_VALUE;
        return -1;
    }
    if (!expects_objects &&
        (!strstr(resp, "owner-mode=\"none\"") ||
         !strstr(resp, "hardware-apply=\"disabled\"") ||
         !strstr(resp, "<usage rifs=\"0\" arp=\"0\" next-hops=\"0\" "
                 "routes=\"0\" ecmp-groups=\"0\""))) {
        if (daemon_ec)
            *daemon_ec = NL_ERR_INVALID_VALUE;
        return -1;
    }
    return rn;
}

int configd_l3_rollback(unsigned long long tx_id, char *resp,
                        size_t resp_size, int *daemon_ec) {
    return l3_rpc_call(NL_RPD_ROLLBACK, tx_id, NULL, 0,
                       resp, resp_size, daemon_ec);
}

configd_l3_apply_failure_evidence configd_l3_apply_failure_classify(
    unsigned long long tx_id, int rpc_result, int daemon_ec,
    const char *resp) {
    const char *open;
    const char *end;

    if (rpc_result < 0 || daemon_ec == 0 ||
        !l3_persistent_result_has_common_evidence(
            resp, "l3-persistent-apply", tx_id, &open, &end))
        return CONFIGD_L3_APPLY_FAILURE_UNKNOWN;
    if (xml_open_tag_attr_equals(open, end, "status",
                                 "apply-failed-restored"))
        return CONFIGD_L3_APPLY_FAILURE_RESTORED;
    if (xml_open_tag_attr_equals(open, end, "status", "invalid"))
        return CONFIGD_L3_APPLY_FAILURE_NO_MUTATION;
    if (xml_open_tag_attr_equals(open, end, "status", "rollback-failed") &&
        xml_open_tag_attr_equals(
            open, end, "reason",
            "previous persistent L3 owner removal was blocked before hardware mutation"))
        return CONFIGD_L3_APPLY_FAILURE_NO_MUTATION;
    return CONFIGD_L3_APPLY_FAILURE_UNKNOWN;
}

bool configd_l3_rollback_verified(unsigned long long tx_id,
                                  int rpc_result, int daemon_ec,
                                  const char *resp) {
    const char *open;
    const char *end;

    return rpc_result >= 0 && daemon_ec == 0 &&
           l3_persistent_result_has_common_evidence(
               resp, "l3-persistent-rollback", tx_id, &open, &end) &&
           xml_open_tag_attr_equals(open, end, "status", "ok");
}
