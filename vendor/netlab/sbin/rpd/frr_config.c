#include "frr_config.h"
#include "fpm.h"
#include "rib.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RPD_FRR_DEFAULT_TAP_IFNAME "netlab-l3"

static void str_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0)
        return;
    snprintf(dst, dst_size, "%s", src ? src : "");
}

static char *trim(char *s) {
    char *end;

    while (*s && isspace((unsigned char)*s))
        s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

static bool token_safe(const char *s) {
    if (!s || !*s)
        return false;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (isspace(c) || c == '<' || c == '>' || c == '"' ||
            c == '\'' || c == '&')
            return false;
    }
    return true;
}

static bool ifname_safe(const char *s) {
    if (!token_safe(s) || strlen(s) >= 64)
        return false;
    return true;
}

static u32 fnv1a(const char *s) {
    u32 h = 2166136261u;

    if (!s)
        return h;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

static int appendf(char *buf, size_t buf_size, size_t *off,
                   const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !off || *off >= buf_size)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_size - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}

static int split_words(char *line, char **argv, int max_argc) {
    char *save = NULL;
    char *tok;
    int argc = 0;

    tok = strtok_r(line, " \t", &save);
    while (tok && argc < max_argc) {
        argv[argc++] = tok;
        tok = strtok_r(NULL, " \t", &save);
    }
    return argc;
}

static bool argv_safe(char **argv, int argc) {
    for (int i = 0; i < argc; i++) {
        if (!token_safe(argv[i]))
            return false;
    }
    return true;
}

static bool parse_u32_range(const char *s, u32 min, u32 max, u32 *out) {
    char *end = NULL;
    unsigned long n;

    if (!s || !*s)
        return false;
    n = strtoul(s, &end, 10);
    if (!end || *end || n < min || n > max)
        return false;
    if (out)
        *out = (u32)n;
    return true;
}

static bool parse_ipv4_host(const char *s, u32 *host_order) {
    struct in_addr addr;

    if (!s || inet_pton(AF_INET, s, &addr) != 1)
        return false;
    if (host_order)
        *host_order = ntohl(addr.s_addr);
    return true;
}

static int fpm_target(char *address, size_t address_size, u32 *port,
                      char *err, size_t err_size) {
    const char *env_addr = getenv("NETLAB_RPD_FPM_ADDRESS");
    const char *env_port = getenv("NETLAB_RPD_FPM_PORT");
    u32 parsed_port = RPD_FPM_DEFAULT_PORT;

    if (!address || address_size == 0 || !port) {
        snprintf(err, err_size, "invalid FPM target buffer");
        return -1;
    }
    if (!env_addr || !env_addr[0])
        env_addr = "127.0.0.1";
    if (!parse_ipv4_host(env_addr, NULL)) {
        snprintf(err, err_size, "invalid FPM address: %s", env_addr);
        return -1;
    }
    if (env_port && env_port[0] &&
        !parse_u32_range(env_port, 1, 65535, &parsed_port)) {
        snprintf(err, err_size, "invalid FPM port: %s", env_port);
        return -1;
    }
    str_copy(address, address_size, env_addr);
    *port = parsed_port;
    return 0;
}

static int emit_fpm_config(rpd_frr_config *cfg, size_t *off,
                           char *err, size_t err_size) {
    if (!cfg->ospf_enabled && !cfg->bgp_enabled)
        return 0;
    if (fpm_target(cfg->fpm_address, sizeof(cfg->fpm_address),
                   &cfg->fpm_port, err, err_size) != 0)
        return -1;
    if (appendf(cfg->config, sizeof(cfg->config), off,
                "fpm address %s port %u\n!\n",
                cfg->fpm_address, cfg->fpm_port) != 0) {
        snprintf(err, err_size, "FRR FPM config buffer exhausted");
        return -1;
    }
    cfg->fpm_enabled = true;
    cfg->config_lines += 2;
    return 0;
}

static u32 prefix_mask(int plen) {
    if (plen <= 0)
        return 0;
    if (plen >= 32)
        return 0xffffffffu;
    return 0xffffffffu << (32 - plen);
}

static bool parse_ipv4_prefix(const char *cidr, u32 *addr, int *plen) {
    char tmp[64];
    char *slash;
    u32 a;
    u32 p;

    if (!cidr || strlen(cidr) >= sizeof(tmp))
        return false;
    snprintf(tmp, sizeof(tmp), "%s", cidr);
    slash = strchr(tmp, '/');
    if (!slash)
        return false;
    *slash++ = '\0';
    if (!parse_ipv4_host(tmp, &a) || !parse_u32_range(slash, 0, 32, &p))
        return false;
    if (addr)
        *addr = a;
    if (plen)
        *plen = (int)p;
    return true;
}

static bool canonical_ipv4_prefix(const char *cidr) {
    u32 addr;
    int plen;

    if (!parse_ipv4_prefix(cidr, &addr, &plen))
        return false;
    return (addr & prefix_mask(plen)) == addr;
}

static bool ipv4_prefix_network_string(const char *cidr,
                                       char *out, size_t out_size) {
    u32 addr;
    int plen;
    struct in_addr ia;

    if (!out || out_size == 0 || !parse_ipv4_prefix(cidr, &addr, &plen))
        return false;
    addr &= prefix_mask(plen);
    ia.s_addr = htonl(addr);
    if (!inet_ntop(AF_INET, &ia, out, out_size))
        return false;
    if (strlen(out) + 4 >= out_size)
        return false;
    snprintf(out + strlen(out), out_size - strlen(out), "/%d", plen);
    return true;
}

static bool parse_ospf_area(const char *area) {
    u32 unused;

    return parse_ipv4_host(area, NULL) ||
           parse_u32_range(area, 0, 4294967295u, &unused);
}

static const char *default_frr_ifname(void) {
    const char *env = getenv("NETLAB_RPD_FRR_DEFAULT_IFNAME");

    if (env && env[0])
        return env;
    env = getenv("NETLAB_RPD_LINUX_ARP_DEV");
    if (env && env[0])
        return env;
    env = getenv("NETLAB_PACKETD_L3_TAP_IFNAME");
    if (env && env[0])
        return env;
    return RPD_FRR_DEFAULT_TAP_IFNAME;
}

static int explicit_frr_ifname_map_lookup(const char *rif,
                                          char *out, size_t out_size,
                                          bool *found,
                                          char *err, size_t err_size) {
    const char *env = getenv("NETLAB_RPD_FRR_RIF_IFNAME_MAP");
    char map[1024];
    char *save = NULL;
    char *entry;

    if (found)
        *found = false;
    if (!env || !env[0])
        return 0;
    if (strlen(env) >= sizeof(map)) {
        snprintf(err, err_size,
                 "NETLAB_RPD_FRR_RIF_IFNAME_MAP is too long");
        return -1;
    }
    str_copy(map, sizeof(map), env);
    entry = strtok_r(map, ",", &save);
    while (entry) {
        char *clean = trim(entry);
        char *eq = strchr(clean, '=');
        char *key;
        char *value;

        if (!eq) {
            snprintf(err, err_size,
                     "invalid NETLAB_RPD_FRR_RIF_IFNAME_MAP entry: %s",
                     clean);
            return -1;
        }
        *eq++ = '\0';
        key = trim(clean);
        value = trim(eq);
        if (!ifname_safe(key) || !ifname_safe(value)) {
            snprintf(err, err_size,
                     "invalid NETLAB_RPD_FRR_RIF_IFNAME_MAP entry: %s=%s",
                     key, value);
            return -1;
        }
        if (strcmp(key, rif) == 0) {
            str_copy(out, out_size, value);
            if (found)
                *found = true;
            return 0;
        }
        entry = strtok_r(NULL, ",", &save);
    }
    return 0;
}

static int resolve_ospf_linux_ifnames(rpd_frr_config *cfg,
                                      char *err, size_t err_size) {
    int implicit = 0;

    if (!cfg || !cfg->ospf_enabled)
        return 0;
    cfg->ospf_ifname_maps = 0;
    for (int i = 0; i < cfg->n_ospf_interface_state; i++) {
        rpd_frr_ospf_interface *iface =
            &cfg->ospf_interface_state[i];
        bool explicit = false;

        if (explicit_frr_ifname_map_lookup(iface->name,
                                           iface->linux_ifname,
                                           sizeof(iface->linux_ifname),
                                           &explicit,
                                           err, err_size) != 0)
            return -1;
        if (!explicit) {
            const char *fallback = default_frr_ifname();

            if (!ifname_safe(fallback)) {
                snprintf(err, err_size,
                         "invalid default FRR interface name: %s",
                         fallback ? fallback : "");
                return -1;
            }
            str_copy(iface->linux_ifname, sizeof(iface->linux_ifname),
                     fallback);
            implicit++;
        }
        if (strcmp(iface->linux_ifname, iface->name) != 0)
            cfg->ospf_ifname_maps++;
    }
    if (cfg->n_ospf_interface_state > 1 && implicit > 0) {
        snprintf(err, err_size,
                 "multiple OSPF interfaces require "
                 "NETLAB_RPD_FRR_RIF_IFNAME_MAP");
        return -1;
    }
    for (int i = 0; i < cfg->n_ospf_interface_state; i++) {
        for (int j = i + 1; j < cfg->n_ospf_interface_state; j++) {
            if (strcmp(cfg->ospf_interface_state[i].linux_ifname,
                       cfg->ospf_interface_state[j].linux_ifname) == 0) {
                snprintf(err, err_size,
                         "multiple OSPF interfaces map to Linux interface %s",
                         cfg->ospf_interface_state[i].linux_ifname);
                return -1;
            }
        }
    }
    return 0;
}

static bool rif_exists(const rpd_frr_config *cfg, const char *name) {
    if (!cfg || !name || !*name)
        return false;
    for (int i = 0; i < cfg->n_rif_state; i++)
        if (strcmp(cfg->rif_state[i].name, name) == 0)
            return true;
    return false;
}

static int add_rif(rpd_frr_config *cfg, const char *name,
                   char *err, size_t err_size) {
    rpd_frr_rif *rif;

    if (!cfg || !name || !*name) {
        snprintf(err, err_size, "invalid routed interface intent");
        return -1;
    }
    if (rif_exists(cfg, name))
        return 0;
    if (cfg->n_rif_state >= RPD_FRR_MAX_RIFS) {
        snprintf(err, err_size, "too many routed interfaces for FRR intent");
        return -1;
    }
    rif = &cfg->rif_state[cfg->n_rif_state++];
    memset(rif, 0, sizeof(*rif));
    str_copy(rif->name, sizeof(rif->name), name);
    cfg->routed_interfaces++;
    return 0;
}

static int add_ospf_interface(rpd_frr_config *cfg, const char *area,
                              const char *name, char *err,
                              size_t err_size) {
    rpd_frr_ospf_interface *iface;

    if (!cfg || !area || !*area || !name || !*name) {
        snprintf(err, err_size, "invalid OSPF interface intent");
        return -1;
    }
    for (int i = 0; i < cfg->n_ospf_interface_state; i++) {
        if (strcmp(cfg->ospf_interface_state[i].name, name) != 0)
            continue;
        if (strcmp(cfg->ospf_interface_state[i].area, area) == 0)
            return 0;
        snprintf(err, err_size,
                 "conflicting OSPF area for interface %s", name);
        return -1;
    }
    if (cfg->n_ospf_interface_state >= RPD_FRR_MAX_OSPF_INTERFACES) {
        snprintf(err, err_size, "too many OSPF interfaces");
        return -1;
    }
    iface = &cfg->ospf_interface_state[cfg->n_ospf_interface_state++];
    memset(iface, 0, sizeof(*iface));
    str_copy(iface->name, sizeof(iface->name), name);
    str_copy(iface->area, sizeof(iface->area), area);
    cfg->ospf_interfaces++;
    return 1;
}

static rpd_frr_bgp_group *bgp_group_get(rpd_frr_config *cfg,
                                        const char *name, bool create) {
    if (!cfg || !name || !*name)
        return NULL;
    for (int i = 0; i < cfg->n_bgp_group_state; i++)
        if (strcmp(cfg->bgp_group_state[i].name, name) == 0)
            return &cfg->bgp_group_state[i];
    if (!create || cfg->n_bgp_group_state >= RPD_FRR_MAX_BGP_GROUPS)
        return NULL;
    rpd_frr_bgp_group *group =
        &cfg->bgp_group_state[cfg->n_bgp_group_state++];
    memset(group, 0, sizeof(*group));
    str_copy(group->name, sizeof(group->name), name);
    return group;
}

static const rpd_frr_bgp_group *bgp_group_find_const(
    const rpd_frr_config *cfg, const char *name) {
    if (!cfg || !name || !*name)
        return NULL;
    for (int i = 0; i < cfg->n_bgp_group_state; i++)
        if (strcmp(cfg->bgp_group_state[i].name, name) == 0)
            return &cfg->bgp_group_state[i];
    return NULL;
}

static int add_bgp_neighbor(rpd_frr_config *cfg, const char *group,
                            const char *address, const char *peer_as,
                            char *err, size_t err_size) {
    rpd_frr_bgp_neighbor *neighbor;
    u32 asn;

    if (cfg->n_bgp_neighbor_state >= RPD_FRR_MAX_BGP_NEIGHBORS) {
        snprintf(err, err_size, "too many BGP neighbors");
        return -1;
    }
    if (!parse_u32_range(peer_as, 1, 4294967295u, &asn)) {
        snprintf(err, err_size, "invalid BGP peer-as: %s", peer_as);
        return -1;
    }
    if (!parse_ipv4_host(address, NULL)) {
        snprintf(err, err_size, "invalid BGP neighbor address: %s",
                 address);
        return -1;
    }
    for (int i = 0; i < cfg->n_bgp_neighbor_state; i++) {
        if (strcmp(cfg->bgp_neighbor_state[i].address, address) == 0) {
            snprintf(err, err_size, "duplicate BGP neighbor: %s", address);
            return -1;
        }
    }
    (void)asn;
    neighbor = &cfg->bgp_neighbor_state[cfg->n_bgp_neighbor_state++];
    memset(neighbor, 0, sizeof(*neighbor));
    str_copy(neighbor->group, sizeof(neighbor->group), group);
    str_copy(neighbor->address, sizeof(neighbor->address), address);
    str_copy(neighbor->peer_as, sizeof(neighbor->peer_as), peer_as);
    return 0;
}

static int add_policy_term(rpd_frr_config *cfg, const char *policy,
                           const char *term, const char *prefix,
                           const char *action,
                           char *err, size_t err_size) {
    rpd_frr_policy_term *entry;

    if (!canonical_ipv4_prefix(prefix)) {
        snprintf(err, err_size,
                 "invalid policy route-filter prefix: %s", prefix);
        return -1;
    }
    if (cfg->n_policy_term_state >= RPD_FRR_MAX_POLICY_TERMS) {
        snprintf(err, err_size, "too many policy terms");
        return -1;
    }
    entry = &cfg->policy_term_state[cfg->n_policy_term_state++];
    memset(entry, 0, sizeof(*entry));
    str_copy(entry->policy, sizeof(entry->policy), policy);
    str_copy(entry->term, sizeof(entry->term), term);
    str_copy(entry->prefix, sizeof(entry->prefix), prefix);
    str_copy(entry->action, sizeof(entry->action), action);
    return 0;
}

static int add_local_route(rpd_frr_config *cfg, const char *prefix,
                           const char *protocol,
                           char *err, size_t err_size);

static bool policy_exists(const rpd_frr_config *cfg, const char *policy) {
    if (!cfg || !policy || !policy[0])
        return false;
    for (int i = 0; i < cfg->n_policy_term_state; i++) {
        if (strcmp(cfg->policy_term_state[i].policy, policy) == 0)
            return true;
    }
    return false;
}

static int validate_bgp_references(const rpd_frr_config *cfg,
                                   char *err, size_t err_size) {
    if (!cfg || !cfg->bgp_enabled)
        return 0;
    for (int i = 0; i < cfg->n_bgp_group_state; i++) {
        const rpd_frr_bgp_group *group = &cfg->bgp_group_state[i];

        if (!group->type[0]) {
            snprintf(err, err_size,
                     "BGP group %s type is required", group->name);
            return -1;
        }
        if (group->export_policy[0] &&
            !policy_exists(cfg, group->export_policy)) {
            snprintf(err, err_size,
                     "BGP export policy %s is not defined",
                     group->export_policy);
            return -1;
        }
    }
    for (int i = 0; i < cfg->n_bgp_neighbor_state; i++) {
        const rpd_frr_bgp_neighbor *neighbor = &cfg->bgp_neighbor_state[i];
        const rpd_frr_bgp_group *group =
            bgp_group_find_const(cfg, neighbor->group);
        u32 peer_as = 0;

        if (!group || !group->type[0]) {
            snprintf(err, err_size,
                     "BGP group %s type is required", neighbor->group);
            return -1;
        }
        if (!parse_u32_range(neighbor->peer_as, 1, 4294967295u, &peer_as)) {
            snprintf(err, err_size,
                     "invalid BGP peer-as: %s", neighbor->peer_as);
            return -1;
        }
        if (cfg->bgp_local_as_set && strcmp(group->type, "internal") == 0 &&
            peer_as != cfg->bgp_local_as) {
            snprintf(err, err_size,
                     "BGP internal group %s neighbor %s peer-as %u "
                     "must match local-as %u",
                     neighbor->group, neighbor->address, peer_as,
                     cfg->bgp_local_as);
            return -1;
        }
        if (cfg->bgp_local_as_set && strcmp(group->type, "external") == 0 &&
            peer_as == cfg->bgp_local_as) {
            snprintf(err, err_size,
                     "BGP external group %s neighbor %s peer-as %u "
                     "must differ from local-as %u",
                     neighbor->group, neighbor->address, peer_as,
                     cfg->bgp_local_as);
            return -1;
        }
    }
    return 0;
}

static int validate_ospf_references(const rpd_frr_config *cfg,
                                    char *err, size_t err_size) {
    if (!cfg || !cfg->ospf_enabled)
        return 0;
    for (int i = 0; i < cfg->n_ospf_interface_state; i++) {
        const rpd_frr_ospf_interface *iface =
            &cfg->ospf_interface_state[i];

        if (!rif_exists(cfg, iface->name)) {
            snprintf(err, err_size,
                     "OSPF interface %s is not a configured routed interface",
                     iface->name);
            return -1;
        }
    }
    return 0;
}

static bool policy_accepts_prefix(const rpd_frr_config *cfg,
                                  const char *policy,
                                  const char *prefix) {
    if (!cfg || !policy || !prefix)
        return false;
    for (int i = 0; i < cfg->n_policy_term_state; i++) {
        const rpd_frr_policy_term *term = &cfg->policy_term_state[i];

        if (strcmp(term->policy, policy) != 0 ||
            strcmp(term->prefix, prefix) != 0)
            continue;
        return strcmp(term->action, "accept") == 0;
    }
    return false;
}

static bool bgp_originates_prefix(const rpd_frr_config *cfg,
                                  const char *prefix) {
    if (!cfg || !prefix)
        return false;
    for (int i = 0; i < cfg->n_bgp_group_state; i++) {
        const rpd_frr_bgp_group *group = &cfg->bgp_group_state[i];

        if (group->export_policy[0] &&
            policy_accepts_prefix(cfg, group->export_policy, prefix))
            return true;
    }
    return false;
}

static int bgp_origin_network_count(const rpd_frr_config *cfg) {
    int count = 0;

    if (!cfg || !cfg->bgp_enabled)
        return 0;
    for (int i = 0; i < cfg->n_local_route_state; i++)
        if (bgp_originates_prefix(cfg, cfg->local_route_state[i].prefix))
            count++;
    return count;
}

static bool bgp_has_neighbor_without_export(const rpd_frr_config *cfg) {
    if (!cfg)
        return false;
    for (int i = 0; i < cfg->n_bgp_neighbor_state; i++) {
        const rpd_frr_bgp_neighbor *neighbor = &cfg->bgp_neighbor_state[i];
        const rpd_frr_bgp_group *group =
            bgp_group_find_const(cfg, neighbor->group);

        if (!group || !group->export_policy[0])
            return true;
    }
    return false;
}

static int emit_policy_config(rpd_frr_config *cfg, size_t *off,
                              char *err, size_t err_size) {
    for (int i = 0; i < cfg->n_policy_term_state; i++) {
        rpd_frr_policy_term *term = &cfg->policy_term_state[i];
        char prefix_list[32];
        int seq = (i + 1) * 10;
        const char *action =
            strcmp(term->action, "accept") == 0 ? "permit" : "deny";

        snprintf(prefix_list, sizeof(prefix_list), "PFX_%08x",
                 fnv1a(term->policy) ^ fnv1a(term->term));
        if (appendf(cfg->config, sizeof(cfg->config), off,
                    "ip prefix-list %s seq %d permit %s\n"
                    "route-map %s %s %d\n"
                    " match ip address prefix-list %s\n"
                    "!\n",
                    prefix_list, seq, term->prefix,
                    term->policy, action, seq, prefix_list) != 0) {
            snprintf(err, err_size, "FRR policy config buffer exhausted");
            return -1;
        }
        cfg->config_lines += 4;
    }
    if (bgp_has_neighbor_without_export(cfg)) {
        if (appendf(cfg->config, sizeof(cfg->config), off,
                    "route-map NETLAB_DEFAULT_EXPORT_DENY deny 65535\n"
                    "!\n") != 0) {
            snprintf(err, err_size,
                     "FRR default export policy buffer exhausted");
            return -1;
        }
        cfg->config_lines += 2;
    }
    return 0;
}

static int emit_bgp_config(rpd_frr_config *cfg, size_t *off,
                           char *err, size_t err_size) {
    int network_count;

    if (!cfg->bgp_enabled)
        return 0;
    if (cfg->n_bgp_neighbor_state == 0 && cfg->bgp_groups == 0)
        return 0;
    if (!cfg->bgp_local_as_set) {
        snprintf(err, err_size,
                 "BGP local-as is required; set routing-options autonomous-system");
        return -1;
    }
    if (appendf(cfg->config, sizeof(cfg->config), off,
                "router bgp %u\n"
                " bgp log-neighbor-changes\n"
                " no bgp ebgp-requires-policy\n",
                cfg->bgp_local_as) != 0) {
        snprintf(err, err_size, "FRR BGP config buffer exhausted");
        return -1;
    }
    cfg->config_lines += 3;
    network_count = bgp_origin_network_count(cfg);
    if (network_count > 0) {
        if (appendf(cfg->config, sizeof(cfg->config), off,
                    " no bgp network import-check\n") != 0) {
            snprintf(err, err_size, "FRR BGP network config exhausted");
            return -1;
        }
        cfg->config_lines++;
    }
    for (int i = 0; i < cfg->n_bgp_neighbor_state; i++) {
        rpd_frr_bgp_neighbor *neighbor = &cfg->bgp_neighbor_state[i];
        rpd_frr_bgp_group *group =
            bgp_group_get(cfg, neighbor->group, false);

        if (appendf(cfg->config, sizeof(cfg->config), off,
                    " neighbor %s remote-as %s\n",
                    neighbor->address, neighbor->peer_as) != 0) {
            snprintf(err, err_size, "FRR BGP neighbor config exhausted");
            return -1;
        }
        cfg->config_lines++;
        if (group && group->hold_time_set) {
            if (appendf(cfg->config, sizeof(cfg->config), off,
                        " neighbor %s timers %u %u\n",
                        neighbor->address, group->hold_time / 3,
                        group->hold_time) != 0) {
                snprintf(err, err_size,
                         "FRR BGP timer config exhausted");
                return -1;
            }
            cfg->config_lines++;
        }
        if (group && strcmp(group->type, "external") == 0) {
            if (appendf(cfg->config, sizeof(cfg->config), off,
                        " neighbor %s disable-connected-check\n",
                        neighbor->address) != 0) {
                snprintf(err, err_size,
                         "FRR BGP connected-check config exhausted");
                return -1;
            }
            cfg->config_lines++;
        }
        if (group && group->export_policy[0]) {
            if (appendf(cfg->config, sizeof(cfg->config), off,
                        " neighbor %s route-map %s out\n",
                        neighbor->address, group->export_policy) != 0) {
                snprintf(err, err_size, "FRR BGP export config exhausted");
                return -1;
            }
            cfg->config_lines++;
        } else {
            if (appendf(cfg->config, sizeof(cfg->config), off,
                        " neighbor %s route-map "
                        "NETLAB_DEFAULT_EXPORT_DENY out\n",
                        neighbor->address) != 0) {
                snprintf(err, err_size,
                         "FRR BGP default export config exhausted");
                return -1;
            }
            cfg->config_lines++;
        }
    }
    for (int i = 0; i < cfg->n_local_route_state; i++) {
        const rpd_frr_local_route *route = &cfg->local_route_state[i];

        if (!bgp_originates_prefix(cfg, route->prefix))
            continue;
        if (appendf(cfg->config, sizeof(cfg->config), off,
                    " network %s\n", route->prefix) != 0) {
            snprintf(err, err_size, "FRR BGP network config exhausted");
            return -1;
        }
        cfg->bgp_networks++;
        cfg->config_lines++;
    }
    if (appendf(cfg->config, sizeof(cfg->config), off,
                " address-family ipv4 unicast\n") != 0) {
        snprintf(err, err_size, "FRR BGP address-family config exhausted");
        return -1;
    }
    cfg->config_lines++;
    for (int i = 0; i < cfg->n_bgp_neighbor_state; i++) {
        const rpd_frr_bgp_neighbor *neighbor =
            &cfg->bgp_neighbor_state[i];

        if (appendf(cfg->config, sizeof(cfg->config), off,
                    "  neighbor %s activate\n",
                    neighbor->address) != 0) {
            snprintf(err, err_size,
                     "FRR BGP neighbor address-family config exhausted");
            return -1;
        }
        cfg->config_lines++;
    }
    if (appendf(cfg->config, sizeof(cfg->config), off,
                " exit-address-family\n") != 0) {
        snprintf(err, err_size, "FRR BGP address-family config exhausted");
        return -1;
    }
    cfg->config_lines++;
    if (appendf(cfg->config, sizeof(cfg->config), off, "!\n") != 0) {
        snprintf(err, err_size, "FRR BGP config buffer exhausted");
        return -1;
    }
    cfg->config_lines++;
    return 0;
}

static int emit_ospf_config(rpd_frr_config *cfg, size_t *off,
                            char *err, size_t err_size) {
    if (!cfg->ospf_enabled)
        return 0;
    if (resolve_ospf_linux_ifnames(cfg, err, err_size) != 0)
        return -1;
    for (int i = 0; i < cfg->n_ospf_interface_state; i++) {
        rpd_frr_ospf_interface *iface = &cfg->ospf_interface_state[i];

        if (appendf(cfg->config, sizeof(cfg->config), off,
                    "interface %s\n ip ospf area %s\n!\n",
                    iface->linux_ifname, iface->area) != 0) {
            snprintf(err, err_size,
                     "FRR OSPF interface config buffer exhausted");
            return -1;
        }
        cfg->config_lines += 3;
    }
    if (appendf(cfg->config, sizeof(cfg->config), off,
                "router ospf\n!\n") != 0) {
        snprintf(err, err_size, "FRR OSPF config buffer exhausted");
        return -1;
    }
    cfg->config_lines += 2;
    return 0;
}

static int compile_protocol_line(rpd_frr_config *cfg, char **argv, int argc,
                                 size_t *off, char *err, size_t err_size) {
    if (argc < 3 || strcmp(argv[0], "protocol") != 0) {
        snprintf(err, err_size, "invalid protocol intent line");
        return -1;
    }
    if (strcmp(argv[1], "ospf") == 0) {
        cfg->ospf_enabled = true;
        if (argc == 4 && strcmp(argv[2], "table") == 0 &&
            strcmp(argv[3], RPD_RIB_TABLE) == 0) {
            return 0;
        }
        if (argc == 6 && strcmp(argv[2], "area") == 0 &&
            strcmp(argv[4], "table") == 0 &&
            strcmp(argv[5], RPD_RIB_TABLE) == 0) {
            if (!parse_ospf_area(argv[3])) {
                snprintf(err, err_size, "invalid OSPF area: %s",
                         argv[3]);
                return -1;
            }
            if (cfg->ospf_areas >= RPD_FRR_MAX_OSPF_AREAS) {
                snprintf(err, err_size, "too many OSPF areas");
                return -1;
            }
            cfg->ospf_areas++;
            return 0;
        }
        if (argc == 8 && strcmp(argv[2], "area") == 0 &&
            strcmp(argv[4], "interface") == 0 &&
            strcmp(argv[6], "table") == 0 &&
            strcmp(argv[7], RPD_RIB_TABLE) == 0) {
            if (!parse_ospf_area(argv[3])) {
                snprintf(err, err_size, "invalid OSPF area: %s",
                         argv[3]);
                return -1;
            }
            int add_rc = add_ospf_interface(cfg, argv[3], argv[5],
                                            err, err_size);
            if (add_rc < 0)
                return -1;
            (void)off;
            return 0;
        }
        snprintf(err, err_size, "unsupported OSPF intent shape");
        return -1;
    }
    if (strcmp(argv[1], "bgp") == 0) {
        cfg->bgp_enabled = true;
        if (argc == 6 && strcmp(argv[2], "local-as") == 0 &&
            strcmp(argv[4], "table") == 0 &&
            strcmp(argv[5], RPD_RIB_TABLE) == 0) {
            if (!parse_u32_range(argv[3], 1, 4294967295u,
                                 &cfg->bgp_local_as)) {
                snprintf(err, err_size, "invalid BGP local-as: %s",
                         argv[3]);
                return -1;
            }
            cfg->bgp_local_as_set = true;
            return 0;
        }
        if (argc == 4 && strcmp(argv[2], "table") == 0 &&
            strcmp(argv[3], RPD_RIB_TABLE) == 0) {
            return 0;
        }
        if (argc == 8 && strcmp(argv[2], "group") == 0 &&
            strcmp(argv[4], "type") == 0 &&
            strcmp(argv[6], "table") == 0 &&
            strcmp(argv[7], RPD_RIB_TABLE) == 0) {
            rpd_frr_bgp_group *group =
                bgp_group_get(cfg, argv[3], true);
            if (!group) {
                snprintf(err, err_size, "too many BGP groups");
                return -1;
            }
            if (strcmp(argv[5], "external") != 0 &&
                strcmp(argv[5], "internal") != 0) {
                snprintf(err, err_size, "unsupported BGP group type: %s",
                         argv[5]);
                return -1;
            }
            if (group->type[0] && strcmp(group->type, argv[5]) != 0) {
                snprintf(err, err_size,
                         "conflicting BGP group type for %s", argv[3]);
                return -1;
            }
            if (!group->type[0])
                cfg->bgp_groups++;
            str_copy(group->type, sizeof(group->type), argv[5]);
            return 0;
        }
        if (argc == 8 && strcmp(argv[2], "group") == 0 &&
            strcmp(argv[4], "export") == 0 &&
            strcmp(argv[6], "table") == 0 &&
            strcmp(argv[7], RPD_RIB_TABLE) == 0) {
            rpd_frr_bgp_group *group =
                bgp_group_get(cfg, argv[3], true);
            if (!group) {
                snprintf(err, err_size, "too many BGP groups");
                return -1;
            }
            if (group->export_policy[0] &&
                strcmp(group->export_policy, argv[5]) != 0) {
                snprintf(err, err_size,
                         "conflicting BGP export policy for %s", argv[3]);
                return -1;
            }
            if (!group->export_policy[0])
                cfg->bgp_exports++;
            str_copy(group->export_policy, sizeof(group->export_policy),
                     argv[5]);
            return 0;
        }
        if (argc == 8 && strcmp(argv[2], "group") == 0 &&
            strcmp(argv[4], "hold-time") == 0 &&
            strcmp(argv[6], "table") == 0 &&
            strcmp(argv[7], RPD_RIB_TABLE) == 0) {
            rpd_frr_bgp_group *group =
                bgp_group_get(cfg, argv[3], true);
            u32 hold_time;
            if (!group) {
                snprintf(err, err_size, "too many BGP groups");
                return -1;
            }
            if (!parse_u32_range(argv[5], 3, 3600, &hold_time) ||
                hold_time % 3 != 0) {
                snprintf(err, err_size,
                         "BGP hold-time must be divisible by 3 and in "
                         "[3, 3600]: %s", argv[5]);
                return -1;
            }
            if (group->hold_time_set && group->hold_time != hold_time) {
                snprintf(err, err_size,
                         "conflicting BGP hold-time for %s", argv[3]);
                return -1;
            }
            group->hold_time_set = true;
            group->hold_time = hold_time;
            return 0;
        }
        if (argc == 10 && strcmp(argv[2], "group") == 0 &&
            strcmp(argv[4], "neighbor") == 0 &&
            strcmp(argv[6], "peer-as") == 0 &&
            strcmp(argv[8], "table") == 0 &&
            strcmp(argv[9], RPD_RIB_TABLE) == 0) {
            if (!bgp_group_get(cfg, argv[3], true)) {
                snprintf(err, err_size, "too many BGP groups");
                return -1;
            }
            if (add_bgp_neighbor(cfg, argv[3], argv[5], argv[7],
                                 err, err_size) != 0)
                return -1;
            cfg->bgp_neighbors++;
            return 0;
        }
        snprintf(err, err_size, "unsupported BGP intent shape");
        return -1;
    }
    snprintf(err, err_size, "unsupported dynamic protocol: %s", argv[1]);
    return -1;
}

static int compile_rif_line(rpd_frr_config *cfg, char **argv, int argc,
                            char *err, size_t err_size) {
    char prefix[64];

    if (argc < 3 || strcmp(argv[0], "rif") != 0 ||
        strcmp(argv[1], "name") != 0) {
        snprintf(err, err_size, "unsupported RIF intent shape");
        return -1;
    }
    for (int i = 3; i + 1 < argc; i++) {
        if (strcmp(argv[i], "address") != 0)
            continue;
        if (!ipv4_prefix_network_string(argv[i + 1], prefix,
                                        sizeof(prefix))) {
            snprintf(err, err_size, "invalid RIF address: %s",
                     argv[i + 1]);
            return -1;
        }
        if (add_local_route(cfg, prefix, "connected",
                            err, err_size) != 0)
            return -1;
        break;
    }
    return add_rif(cfg, argv[2], err, err_size);
}

static int compile_policy_line(rpd_frr_config *cfg, char **argv, int argc,
                               size_t *off, char *err, size_t err_size) {
    bool new_policy;

    if (argc != 10 || strcmp(argv[0], "policy") != 0 ||
        strcmp(argv[1], "statement") != 0 ||
        strcmp(argv[3], "term") != 0 ||
        strcmp(argv[5], "route-filter") != 0 ||
        strcmp(argv[7], "exact") != 0 ||
        strcmp(argv[8], "then") != 0 ||
        (strcmp(argv[9], "accept") != 0 &&
         strcmp(argv[9], "reject") != 0)) {
        snprintf(err, err_size, "unsupported policy intent shape");
        return -1;
    }
    (void)off;
    new_policy = !policy_exists(cfg, argv[2]);
    if (add_policy_term(cfg, argv[2], argv[4], argv[6], argv[9],
                        err, err_size) != 0)
        return -1;
    if (new_policy)
        cfg->policies++;
    cfg->policy_terms++;
    return 0;
}

static int add_local_route(rpd_frr_config *cfg, const char *prefix,
                           const char *protocol,
                           char *err, size_t err_size) {
    rpd_frr_local_route *route;

    if (!cfg || !prefix || !protocol || !canonical_ipv4_prefix(prefix)) {
        snprintf(err, err_size, "invalid FRR local route prefix: %s",
                 prefix ? prefix : "");
        return -1;
    }
    for (int i = 0; i < cfg->n_local_route_state; i++) {
        if (strcmp(cfg->local_route_state[i].prefix, prefix) == 0)
            return 0;
    }
    if (cfg->n_local_route_state >= RPD_FRR_MAX_LOCAL_ROUTES) {
        snprintf(err, err_size, "too many FRR local routes");
        return -1;
    }
    route = &cfg->local_route_state[cfg->n_local_route_state++];
    memset(route, 0, sizeof(*route));
    str_copy(route->prefix, sizeof(route->prefix), prefix);
    str_copy(route->protocol, sizeof(route->protocol), protocol);
    return 0;
}

static int compile_non_frr_line(rpd_frr_config *cfg, char **argv, int argc,
                                bool *ignored, char *err, size_t err_size) {
    if (ignored)
        *ignored = false;
    if (argc <= 0)
        return 0;
    if (strcmp(argv[0], "l3-plan") == 0) {
        if (ignored)
            *ignored = true;
        if (argc != 2 ||
            (strcmp(argv[1], "version=1") != 0 &&
             strcmp(argv[1], "version=2") != 0)) {
            snprintf(err, err_size,
                     "unsupported L3 plan version for FRR intent");
            return -1;
        }
        return 0;
    }
    if ((strcmp(argv[0], "route") == 0 ||
         strcmp(argv[0], "rib-static-route") == 0) &&
        argc >= 3 && strcmp(argv[1], "prefix") == 0) {
        if (add_local_route(cfg, argv[2], "static", err, err_size) != 0)
            return -1;
        if (ignored)
            *ignored = true;
        return 0;
    }
    if (strcmp(argv[0], "virtual-router") == 0 ||
        strcmp(argv[0], "router-mac") == 0 ||
        strcmp(argv[0], "arp") == 0 ||
        strcmp(argv[0], "next-hop") == 0 ||
        strcmp(argv[0], "ecmp") == 0 ||
        strcmp(argv[0], "route") == 0 ||
        strcmp(argv[0], "rib-static-route") == 0) {
        if (ignored)
            *ignored = true;
        return 0;
    }
    return 0;
}

void rpd_frr_config_init(rpd_frr_config *cfg) {
    if (!cfg)
        return;
    memset(cfg, 0, sizeof(*cfg));
    str_copy(cfg->status, sizeof(cfg->status), "idle");
    str_copy(cfg->reason, sizeof(cfg->reason), "no dynamic protocol intent");
}

int rpd_frr_config_compile_plan(rpd_frr_config *cfg, const char *payload,
                                int payload_len, u64 generation,
                                char *err, size_t err_size) {
    rpd_frr_config next;
    const char *p;
    const char *end;
    size_t off = 0;

    if (!cfg) {
        snprintf(err, err_size, "invalid FRR config context");
        return -1;
    }
    rpd_frr_config_init(&next);
    next.generation = generation;
    next.last_update = time(NULL);
    if (appendf(next.config, sizeof(next.config), &off,
                "frr version netlab\n"
                "service integrated-vtysh-config\n"
                "no zebra nexthop kernel enable\n"
                "!\n") != 0) {
        snprintf(err, err_size, "FRR config buffer exhausted");
        return -1;
    }
    next.config_lines = 4;
    p = payload;
    end = payload ? payload + payload_len : payload;
    while (p && p < end) {
        char linebuf[1024];
        char *argv[16];
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char *clean;
        int argc;

        if (len >= sizeof(linebuf)) {
            snprintf(err, err_size, "FRR intent line too long");
            return -1;
        }
        memcpy(linebuf, line, len);
        linebuf[len] = '\0';
        clean = trim(linebuf);
        if (*clean && *clean != '#') {
            bool ignored = false;

            argc = split_words(clean, argv, 16);
            if (argc > 0 && !argv_safe(argv, argc)) {
                snprintf(err, err_size, "FRR intent contains unsafe token");
                return -1;
            }
            if (argc > 0 && strcmp(argv[0], "protocol") == 0) {
                if (compile_protocol_line(&next, argv, argc, &off,
                                          err, err_size) != 0)
                    return -1;
            } else if (argc > 0 && strcmp(argv[0], "rif") == 0) {
                if (compile_rif_line(&next, argv, argc, err,
                                     err_size) != 0)
                    return -1;
            } else if (argc > 0 && strcmp(argv[0], "policy") == 0) {
                if (compile_policy_line(&next, argv, argc, &off,
                                        err, err_size) != 0)
                    return -1;
            } else if (compile_non_frr_line(&next, argv, argc, &ignored,
                                            err, err_size) != 0) {
                return -1;
            } else if (!ignored && argc > 0) {
                snprintf(err, err_size,
                         "unsupported FRR intent record: %s", argv[0]);
                return -1;
            }
        }
        p = nl ? nl + 1 : end;
    }
    if (validate_ospf_references(&next, err, err_size) != 0)
        return -1;
    if (validate_bgp_references(&next, err, err_size) != 0)
        return -1;
    if (emit_fpm_config(&next, &off, err, err_size) != 0)
        return -1;
    if (emit_ospf_config(&next, &off, err, err_size) != 0)
        return -1;
    if (emit_policy_config(&next, &off, err, err_size) != 0)
        return -1;
    if (emit_bgp_config(&next, &off, err, err_size) != 0)
        return -1;
    if (next.ospf_enabled || next.bgp_enabled || next.policies) {
        str_copy(next.status, sizeof(next.status), "compiled");
        str_copy(next.reason, sizeof(next.reason),
                 "FRR intent compiled for runtime config writer");
    }
    next.config_hash = fnv1a(next.config);
    *cfg = next;
    return 0;
}

int rpd_frr_config_validate_plan(const char *payload, int payload_len,
                                 char *err, size_t err_size) {
    rpd_frr_config tmp;

    return rpd_frr_config_compile_plan(&tmp, payload, payload_len, 0,
                                       err, err_size);
}

int rpd_frr_config_append_xml(const rpd_frr_config *cfg, char *buf,
                              size_t buf_size, size_t *off) {
    int n;

    if (!cfg || !buf || !off || *off >= buf_size)
        return -1;
    n = snprintf(buf + *off, buf_size - *off,
                 "  <frr-intent status=\"%s\" reason=\"%s\" "
                 "generation=\"%llu\" config-hash=\"%08x\" "
                 "config-lines=\"%d\" ospf-enabled=\"%s\" "
                 "ospf-areas=\"%d\" ospf-interfaces=\"%d\" "
                 "ospf-ifname-maps=\"%d\" "
                 "routed-interfaces=\"%d\" "
                 "fpm-enabled=\"%s\" fpm-address=\"%s\" "
                 "fpm-port=\"%u\" "
                 "bgp-enabled=\"%s\" bgp-local-as=\"%u\" "
                 "bgp-local-as-set=\"%s\" bgp-groups=\"%d\" "
                 "bgp-neighbors=\"%d\" bgp-exports=\"%d\" "
                 "bgp-networks=\"%d\" "
                 "policies=\"%d\" policy-terms=\"%d\"/>\n",
                 cfg->status, cfg->reason,
                 (unsigned long long)cfg->generation,
                 cfg->config_hash, cfg->config_lines,
                 cfg->ospf_enabled ? "true" : "false",
                 cfg->ospf_areas, cfg->ospf_interfaces,
                 cfg->ospf_ifname_maps,
                 cfg->routed_interfaces,
                 cfg->fpm_enabled ? "true" : "false",
                 cfg->fpm_address, cfg->fpm_port,
                 cfg->bgp_enabled ? "true" : "false",
                 cfg->bgp_local_as,
                 cfg->bgp_local_as_set ? "true" : "false",
                 cfg->bgp_groups, cfg->bgp_neighbors,
                 cfg->bgp_exports, cfg->bgp_networks,
                 cfg->policies, cfg->policy_terms);
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}
