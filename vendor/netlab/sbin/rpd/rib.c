#include "rib.h"
#include "netlab/error.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RPD_STATIC_RIFS 64
#define RPD_STATIC_ARP RPD_RIB_MAX_ARP
#define RPD_STATIC_NEXTHOPS 256
#define RPD_STATIC_ECMP 128
#define RPD_STATIC_ECMP_MEMBERS 32

typedef struct {
    char name[32];
    char address[40];
    char prefix[40];
} static_rif;

typedef struct {
    char ip[40];
    char mac[32];
    char rif[32];
    char egress_port[64];
} static_arp;

typedef struct {
    int id;
    char arp_ip[40];
    char rif[32];
} static_nexthop;

typedef struct {
    int id;
    int members[RPD_STATIC_ECMP_MEMBERS];
    int n_members;
} static_ecmp;

typedef struct {
    static_rif rifs[RPD_STATIC_RIFS];
    int n_rifs;
    static_arp arps[RPD_STATIC_ARP];
    int n_arps;
    static_nexthop nexthops[RPD_STATIC_NEXTHOPS];
    int n_nexthops;
    static_ecmp ecmp[RPD_STATIC_ECMP];
    int n_ecmp;
} static_plan_index;

typedef struct {
    char op[16];
    char protocol[16];
    char prefix[40];
    int preference;
    bool has_preference;
    int metric;
    bool has_metric;
    rpd_rib_nexthop nexthops[RPD_RIB_MAX_NEXTHOPS];
    int n_nexthops;
    char egress_rif[64];
    char installed_state[32];
    char idempotency[96];
    char table[RPD_RIB_TABLE_LEN];
    u32 kernel_table;
    bool has_table;
    bool has_kernel_table;
    u32 fingerprint;
} rib_update;

static void str_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0)
        return;
    if (!src)
        src = "";
    snprintf(dst, dst_size, "%s", src);
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

static bool xml_safe_token(const char *s) {
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

static bool parse_ipv4_host(const char *s, u32 *host_order) {
    struct in_addr addr;

    if (!s || inet_pton(AF_INET, s, &addr) != 1)
        return false;
    if (host_order)
        *host_order = ntohl(addr.s_addr);
    return true;
}

static bool parse_mac(const char *s) {
    if (!s || strlen(s) != 17)
        return false;
    for (int i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (s[i] != ':')
                return false;
        } else if (!isxdigit((unsigned char)s[i])) {
            return false;
        }
    }
    return true;
}

static u32 prefix_mask(int plen) {
    if (plen <= 0)
        return 0;
    if (plen >= 32)
        return 0xffffffffu;
    return 0xffffffffu << (32 - plen);
}

static bool parse_ipv4_cidr(const char *cidr, u32 *addr, int *plen) {
    char tmp[64];
    char *slash;
    int p = 0;
    u32 a = 0;

    if (!cidr || strlen(cidr) >= sizeof(tmp))
        return false;
    str_copy(tmp, sizeof(tmp), cidr);
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

static bool canonical_prefix(const char *cidr) {
    u32 addr;
    int plen;

    if (!parse_ipv4_cidr(cidr, &addr, &plen))
        return false;
    return (addr & prefix_mask(plen)) == addr;
}

static bool ipv4_v1_unicast_prefix(const char *cidr, bool allow_default) {
    u32 addr;
    int plen;

    if (!parse_ipv4_cidr(cidr, &addr, &plen))
        return false;
    if (allow_default && plen == 0)
        return true;
    return (addr >> 28) < 14;
}

static bool cidr_network_string(const char *cidr, char *out, size_t out_size) {
    struct in_addr net_addr;
    char ip[INET_ADDRSTRLEN];
    u32 addr;
    u32 net;
    int plen;

    if (!parse_ipv4_cidr(cidr, &addr, &plen) || !out || out_size == 0)
        return false;
    net = addr & prefix_mask(plen);
    net_addr.s_addr = htonl(net);
    if (!inet_ntop(AF_INET, &net_addr, ip, sizeof(ip)))
        return false;
    snprintf(out, out_size, "%s/%d", ip, plen);
    return true;
}

static bool ipv4_in_cidr(const char *ip, const char *cidr) {
    u32 host;
    u32 net;
    int plen;

    if (!parse_ipv4_host(ip, &host) || !parse_ipv4_cidr(cidr, &net, &plen))
        return false;
    return (host & prefix_mask(plen)) == (net & prefix_mask(plen));
}

static bool ipv4_equals_cidr_address(const char *ip, const char *cidr) {
    u32 host;
    u32 local;
    int plen;

    if (!parse_ipv4_host(ip, &host) || !parse_ipv4_cidr(cidr, &local, &plen))
        return false;
    (void)plen;
    return host == local;
}

static int protocol_preference(const char *protocol) {
    if (strcmp(protocol, "connected") == 0)
        return 0;
    if (strcmp(protocol, "static") == 0)
        return 5;
    if (strcmp(protocol, "ospf") == 0)
        return 10;
    if (strcmp(protocol, "bgp") == 0)
        return 170;
    return -1;
}

static bool protocol_valid(const char *protocol) {
    return protocol_preference(protocol) >= 0;
}

static bool fpm_protocol_valid(const char *protocol) {
    return strcmp(protocol, "ospf") == 0 || strcmp(protocol, "bgp") == 0;
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

static int route_find(const rpd_rib *rib, const char *prefix,
                      const char *protocol) {
    if (!rib || !prefix || !protocol)
        return -1;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        if (!rib->routes[i].active)
            continue;
        if (strcmp(rib->routes[i].prefix, prefix) == 0 &&
            strcmp(rib->routes[i].protocol, protocol) == 0)
            return i;
    }
    return -1;
}

static int route_alloc(rpd_rib *rib) {
    if (!rib)
        return -1;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        if (!rib->routes[i].active)
            return i;
    }
    return -1;
}

static bool route_nexthops_resolved(const rpd_rib *rib,
                                    const rpd_rib_route *route);

typedef struct {
    int route_index[RPD_RIB_MAX_ROUTES];
    int count;
} rib_best_index;

static bool route_preferred(const rpd_rib_route *candidate,
                            const rpd_rib_route *current) {
    if (!candidate || !current)
        return false;
    if (candidate->preference != current->preference)
        return candidate->preference < current->preference;
    if (candidate->metric != current->metric)
        return candidate->metric < current->metric;
    return strcmp(candidate->protocol, current->protocol) < 0;
}

static int route_selection_compare(const rpd_rib *rib, int left_index,
                                   int right_index) {
    const rpd_rib_route *left;
    const rpd_rib_route *right;
    int cmp;

    left = &rib->routes[left_index];
    right = &rib->routes[right_index];
    cmp = strcmp(left->prefix, right->prefix);
    if (cmp != 0)
        return cmp;
    if (route_preferred(left, right))
        return -1;
    if (route_preferred(right, left))
        return 1;
    return left_index < right_index ? -1 : left_index > right_index;
}

/*
 * Build one deterministic prefix -> best-route index for a RIB snapshot.
 * The bottom-up merge sort keeps the upper bound at O(routes log routes),
 * including adversarial prefix distributions, and the compacted array gives
 * delta compilation an O(log prefixes) lookup instead of another RIB scan.
 */
static int route_best_index_build(const rpd_rib *rib,
                                  rib_best_index *index) {
    int scratch[RPD_RIB_MAX_ROUTES];
    int count = 0;

    if (!rib || !index)
        return -1;
    memset(index, 0, sizeof(*index));
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++)
        if (rib->routes[i].active)
            index->route_index[count++] = i;

    for (int width = 1; width < count; width *= 2) {
        for (int left = 0; left < count; left += width * 2) {
            int middle = left + width;
            int right = left + width * 2;
            int first = left;
            int second;
            int out = left;

            if (middle > count)
                middle = count;
            if (right > count)
                right = count;
            second = middle;
            while (first < middle && second < right) {
                if (route_selection_compare(
                        rib, index->route_index[first],
                        index->route_index[second]) <= 0)
                    scratch[out++] = index->route_index[first++];
                else
                    scratch[out++] = index->route_index[second++];
            }
            while (first < middle)
                scratch[out++] = index->route_index[first++];
            while (second < right)
                scratch[out++] = index->route_index[second++];
        }
        memcpy(index->route_index, scratch,
               (size_t)count * sizeof(index->route_index[0]));
    }

    index->count = 0;
    for (int i = 0; i < count; i++) {
        int route_index = index->route_index[i];

        if (index->count > 0 &&
            strcmp(rib->routes[index->route_index[index->count - 1]].prefix,
                   rib->routes[route_index].prefix) == 0)
            continue;
        index->route_index[index->count++] = route_index;
    }
    return 0;
}

static int route_best_flags(const rpd_rib *rib, bool *best,
                            size_t best_count) {
    rib_best_index index;

    if (!rib || !best || best_count < RPD_RIB_MAX_ROUTES)
        return -1;
    memset(best, 0, best_count * sizeof(*best));
    if (route_best_index_build(rib, &index) != 0)
        return -1;
    for (int i = 0; i < index.count; i++)
        best[index.route_index[i]] = true;
    return 0;
}

static int fib_best_route_find(const rpd_rib *rib,
                               const rib_best_index *index,
                               const char *prefix) {
    int left = 0;
    int right;

    if (!rib || !index || !prefix)
        return -1;
    right = index->count;
    while (left < right) {
        int middle = left + (right - left) / 2;
        int route_index = index->route_index[middle];
        const rpd_rib_route *route = &rib->routes[route_index];
        int cmp = strcmp(route->prefix, prefix);

        if (cmp < 0)
            left = middle + 1;
        else if (cmp > 0)
            right = middle;
        else
            return route_nexthops_resolved(rib, route) ? route_index : -1;
    }
    return -1;
}

static void result_add_affected_prefix(rpd_rib_update_result *result,
                                       const char *prefix) {
    if (!result || !prefix || !prefix[0])
        return;
    for (int i = 0; i < result->affected_prefix_count; i++)
        if (strcmp(result->affected_prefixes[i], prefix) == 0)
            return;
    if (result->affected_prefix_count >= RPD_RIB_UPDATE_AFFECTED_MAX) {
        result->affected_prefix_overflow = true;
        return;
    }
    str_copy(result->affected_prefixes[result->affected_prefix_count],
             sizeof(result->affected_prefixes[0]), prefix);
    result->affected_prefix_count++;
}

static void nexthops_sort(rpd_rib_nexthop *nexthops, int n) {
    for (int i = 1; i < n; i++) {
        rpd_rib_nexthop cur = nexthops[i];
        int j = i - 1;
        while (j >= 0) {
            int cmp = strcmp(nexthops[j].address, cur.address);
            if (cmp == 0)
                cmp = strcmp(nexthops[j].egress_rif, cur.egress_rif);
            if (cmp <= 0)
                break;
            nexthops[j + 1] = nexthops[j];
            j--;
        }
        nexthops[j + 1] = cur;
    }
}

static bool nexthops_have_duplicate(const rpd_rib_nexthop *nexthops, int n) {
    for (int i = 1; i < n; i++) {
        if (strcmp(nexthops[i - 1].address, nexthops[i].address) == 0 &&
            strcmp(nexthops[i - 1].egress_rif,
                   nexthops[i].egress_rif) == 0)
            return true;
    }
    return false;
}

static bool route_equal_update(const rpd_rib_route *route,
                               const rib_update *update) {
    if (!route || !update || !route->active)
        return false;
    if (strcmp(route->prefix, update->prefix) != 0 ||
        strcmp(route->protocol, update->protocol) != 0 ||
        route->preference != update->preference ||
        route->metric != update->metric ||
        route->n_nexthops != update->n_nexthops ||
        strcmp(route->egress_rif, update->egress_rif) != 0)
        return false;
    for (int i = 0; i < route->n_nexthops; i++) {
        if (strcmp(route->nexthops[i].address,
                   update->nexthops[i].address) != 0 ||
            strcmp(route->nexthops[i].egress_rif,
                   update->nexthops[i].egress_rif) != 0)
            return false;
    }
    return true;
}

static int idempotency_lookup(const rpd_rib *rib, const char *key) {
    if (!rib || !key || !*key)
        return -1;
    for (int i = 0; i < RPD_RIB_MAX_IDEMPOTENCY; i++) {
        if (rib->idempotency[i].used &&
            strcmp(rib->idempotency[i].key, key) == 0)
            return i;
    }
    return -1;
}

static void idempotency_record(rpd_rib *rib, const char *key, u32 fingerprint,
                               u64 generation, u64 fib_update_id) {
    rpd_rib_idempotency *entry;
    int idx;

    if (!rib || !key || !*key)
        return;
    idx = idempotency_lookup(rib, key);
    if (idx < 0) {
        idx = rib->idempotency_head;
        rib->idempotency_head =
            (rib->idempotency_head + 1) % RPD_RIB_MAX_IDEMPOTENCY;
    }
    entry = &rib->idempotency[idx];
    memset(entry, 0, sizeof(*entry));
    entry->used = true;
    str_copy(entry->key, sizeof(entry->key), key);
    entry->fingerprint = fingerprint;
    entry->generation = generation;
    entry->fib_update_id = fib_update_id;
}

static void idempotency_clear(rpd_rib *rib) {
    if (!rib)
        return;
    memset(rib->idempotency, 0, sizeof(rib->idempotency));
    rib->idempotency_head = 0;
}

static bool idempotency_state_matches(const rpd_rib *rib,
                                      const rib_update *update) {
    int idx;

    if (!rib || !update)
        return false;
    idx = route_find(rib, update->prefix, update->protocol);
    if (strcmp(update->op, "delete") == 0)
        return idx < 0;
    if (idx < 0)
        return false;
    return route_equal_update(&rib->routes[idx], update);
}

static int apply_replace(rpd_rib *rib, const rib_update *update,
                         u64 generation, u64 fib_update_id,
                         rpd_rib_update_result *result,
                         char *err, size_t err_size) {
    int idx = route_find(rib, update->prefix, update->protocol);
    rpd_rib_route *route;

    if (idx >= 0 && route_equal_update(&rib->routes[idx], update)) {
        result->routes_unchanged++;
        result->generation = rib->routes[idx].generation;
        result->fib_update_id = rib->routes[idx].fib_update_id;
        idempotency_record(rib, update->idempotency, update->fingerprint,
                           rib->routes[idx].generation,
                           rib->routes[idx].fib_update_id);
        return 0;
    }
    if (idx < 0) {
        idx = route_alloc(rib);
        if (idx < 0) {
            snprintf(err, err_size, "RIB route capacity exceeded");
            return -1;
        }
    }
    route = &rib->routes[idx];
    memset(route, 0, sizeof(*route));
    route->active = true;
    str_copy(route->prefix, sizeof(route->prefix), update->prefix);
    str_copy(route->protocol, sizeof(route->protocol), update->protocol);
    route->preference = update->preference;
    route->metric = update->metric;
    route->n_nexthops = update->n_nexthops;
    for (int i = 0; i < update->n_nexthops; i++)
        route->nexthops[i] = update->nexthops[i];
    str_copy(route->egress_rif, sizeof(route->egress_rif),
             update->egress_rif[0] ? update->egress_rif : "-");
    str_copy(route->installed_state, sizeof(route->installed_state),
             update->installed_state[0] ? update->installed_state :
             "pending-fib");
    route->generation = generation;
    route->fib_update_id = fib_update_id;
    result->changed = true;
    result->routes_changed++;
    if (route->n_nexthops > 1) {
        result->ecmp_routes++;
        result->ecmp_members += route->n_nexthops;
    }
    idempotency_record(rib, update->idempotency, update->fingerprint,
                       generation, fib_update_id);
    return 0;
}

static int apply_delete(rpd_rib *rib, const rib_update *update,
                        u64 current_generation, u64 current_fib_update_id,
                        rpd_rib_update_result *result) {
    int idx = route_find(rib, update->prefix, update->protocol);

    if (idx < 0) {
        result->routes_unchanged++;
        result->generation = current_generation;
        result->fib_update_id = current_fib_update_id;
        idempotency_record(rib, update->idempotency, update->fingerprint,
                           result->generation, result->fib_update_id);
        return 0;
    }
    memset(&rib->routes[idx], 0, sizeof(rib->routes[idx]));
    result->changed = true;
    result->routes_deleted++;
    idempotency_record(rib, update->idempotency, update->fingerprint,
                       result->generation, result->fib_update_id);
    return 0;
}

static int add_update_nexthop(rib_update *update, const char *address,
                              const char *rif, char *err, size_t err_size) {
    if (update->n_nexthops >= RPD_RIB_MAX_NEXTHOPS) {
        snprintf(err, err_size, "too many nexthops");
        return -1;
    }
    if (!parse_ipv4_host(address, NULL)) {
        snprintf(err, err_size, "invalid nexthop address: %s", address);
        return -1;
    }
    if (rif && *rif && !xml_safe_token(rif)) {
        snprintf(err, err_size, "invalid nexthop rif: %s", rif);
        return -1;
    }
    str_copy(update->nexthops[update->n_nexthops].address,
             sizeof(update->nexthops[update->n_nexthops].address),
             address);
    str_copy(update->nexthops[update->n_nexthops].egress_rif,
             sizeof(update->nexthops[update->n_nexthops].egress_rif),
             rif && *rif ? rif : "-");
    update->n_nexthops++;
    return 0;
}

static int add_update_nexthop_list(rib_update *update, const char *value,
                                   const char *rif, char *err,
                                   size_t err_size) {
    char list[512];
    char *save = NULL;
    char *tok;

    if (!value || strlen(value) >= sizeof(list)) {
        snprintf(err, err_size, "invalid nexthop list");
        return -1;
    }
    str_copy(list, sizeof(list), value);
    tok = strtok_r(list, ",", &save);
    while (tok) {
        char *nh = trim(tok);
        char *rif_sep = strchr(nh, '@');
        const char *nh_rif = rif;
        if (!*nh) {
            snprintf(err, err_size, "empty nexthop in list");
            return -1;
        }
        if (rif_sep) {
            *rif_sep++ = '\0';
            nh_rif = rif_sep;
        }
        if (add_update_nexthop(update, nh, nh_rif, err, err_size) != 0)
            return -1;
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}

static int parse_update_line(const char *line, rib_update *update,
                             char *err, size_t err_size) {
    char tmp[1024];
    char *save = NULL;
    char *tok;
    char pending_nexthops[512] = {0};

    memset(update, 0, sizeof(*update));
    update->metric = 0;
    str_copy(update->table, sizeof(update->table), RPD_RIB_TABLE);
    str_copy(update->installed_state, sizeof(update->installed_state),
             "pending-fib");
    if (!line || strlen(line) >= sizeof(tmp)) {
        snprintf(err, err_size, "route update line is too long");
        return -1;
    }
    str_copy(tmp, sizeof(tmp), line);
    update->fingerprint = fnv1a(tmp);

    tok = strtok_r(tmp, " \t", &save);
    while (tok) {
        char *eq = strchr(tok, '=');
        char *key;
        char *value;

        if (!eq) {
            snprintf(err, err_size, "route update token must be key=value: %s",
                     tok);
            return -1;
        }
        *eq = '\0';
        key = tok;
        value = eq + 1;
        if (!xml_safe_token(value)) {
            snprintf(err, err_size, "invalid value for %s", key);
            return -1;
        }
        if (strcmp(key, "op") == 0) {
            str_copy(update->op, sizeof(update->op), value);
        } else if (strcmp(key, "protocol") == 0) {
            str_copy(update->protocol, sizeof(update->protocol), value);
        } else if (strcmp(key, "prefix") == 0) {
            str_copy(update->prefix, sizeof(update->prefix), value);
        } else if (strcmp(key, "preference") == 0) {
            if (!parse_int_range(value, 0, 255, &update->preference)) {
                snprintf(err, err_size, "invalid route preference: %s",
                         value);
                return -1;
            }
            update->has_preference = true;
        } else if (strcmp(key, "metric") == 0) {
            if (!parse_int_range(value, 0, 2147483647, &update->metric)) {
                snprintf(err, err_size, "invalid route metric: %s", value);
                return -1;
            }
            update->has_metric = true;
        } else if (strcmp(key, "nexthop") == 0 ||
                   strcmp(key, "nexthops") == 0) {
            if (pending_nexthops[0]) {
                if (strlen(pending_nexthops) + strlen(value) + 2 >=
                    sizeof(pending_nexthops)) {
                    snprintf(err, err_size, "nexthop list is too long");
                    return -1;
                }
                strcat(pending_nexthops, ",");
                strcat(pending_nexthops, value);
            } else {
                str_copy(pending_nexthops, sizeof(pending_nexthops), value);
            }
        } else if (strcmp(key, "rif") == 0 ||
                   strcmp(key, "egress-rif") == 0) {
            str_copy(update->egress_rif, sizeof(update->egress_rif), value);
        } else if (strcmp(key, "installed-state") == 0 ||
                   strcmp(key, "state") == 0) {
            str_copy(update->installed_state,
                     sizeof(update->installed_state), value);
        } else if (strcmp(key, "idempotency") == 0 ||
                   strcmp(key, "idempotency-key") == 0 ||
                   strcmp(key, "key") == 0) {
            str_copy(update->idempotency, sizeof(update->idempotency), value);
        } else if (strcmp(key, "table") == 0) {
            if (strlen(value) >= sizeof(update->table)) {
                snprintf(err, err_size, "route table name is too long");
                return -1;
            }
            str_copy(update->table, sizeof(update->table), value);
            update->has_table = true;
        } else if (strcmp(key, "table-id") == 0) {
            int table_id = 0;

            if (!parse_int_range(value, 1, 2147483647, &table_id)) {
                snprintf(err, err_size, "invalid route table id: %s", value);
                return -1;
            }
            update->kernel_table = (u32)table_id;
            update->has_kernel_table = true;
        } else {
            snprintf(err, err_size, "unknown route update key: %s", key);
            return -1;
        }
        tok = strtok_r(NULL, " \t", &save);
    }

    if (!update->op[0])
        str_copy(update->op, sizeof(update->op), "replace");
    if (strcmp(update->op, "add") == 0)
        str_copy(update->op, sizeof(update->op), "replace");
    if (strcmp(update->op, "withdraw") == 0)
        str_copy(update->op, sizeof(update->op), "delete");
    if (strcmp(update->op, "replace") != 0 &&
        strcmp(update->op, "delete") != 0) {
        snprintf(err, err_size, "unsupported route update op: %s",
                 update->op);
        return -1;
    }
    if (!protocol_valid(update->protocol)) {
        snprintf(err, err_size, "unsupported route protocol: %s",
                 update->protocol);
        return -1;
    }
    if (!fpm_protocol_valid(update->protocol)) {
        snprintf(err, err_size,
                 "dynamic route update protocol must be ospf or bgp: %s",
                 update->protocol);
        return -1;
    }
    if (!canonical_prefix(update->prefix) ||
        !ipv4_v1_unicast_prefix(update->prefix, true)) {
        snprintf(err, err_size,
                 "invalid route prefix: prefix must be a network address and IPv4 unicast");
        return -1;
    }
    if (!update->has_preference)
        update->preference = protocol_preference(update->protocol);
    if (pending_nexthops[0] &&
        add_update_nexthop_list(update, pending_nexthops,
                                update->egress_rif, err, err_size) != 0)
        return -1;
    nexthops_sort(update->nexthops, update->n_nexthops);
    if (nexthops_have_duplicate(update->nexthops, update->n_nexthops)) {
        snprintf(err, err_size, "duplicate route nexthop");
        return -1;
    }
    if (strcmp(update->op, "replace") == 0 &&
        strcmp(update->protocol, "connected") != 0 &&
        update->n_nexthops == 0) {
        snprintf(err, err_size, "route update requires at least one nexthop");
        return -1;
    }
    if (!update->egress_rif[0])
        str_copy(update->egress_rif, sizeof(update->egress_rif), "-");
    return 0;
}

static int apply_update(rpd_rib *rib, const rib_update *update,
                        u64 generation, u64 fib_update_id,
                        rpd_rib_update_result *result,
                        char *err, size_t err_size) {
    u64 current_generation = generation > 0 ? generation - 1 : 0;
    u64 current_fib_update_id = fib_update_id > 0 ? fib_update_id - 1 : 0;
    int idem;

    result->generation = generation;
    result->fib_update_id = fib_update_id;
    str_copy(result->idempotency_key, sizeof(result->idempotency_key),
             update->idempotency[0] ? update->idempotency : "-");
    if (update->idempotency[0]) {
        idem = idempotency_lookup(rib, update->idempotency);
        if (idem >= 0) {
            if (rib->idempotency[idem].fingerprint != update->fingerprint) {
                result->idempotency_conflict = true;
                snprintf(err, err_size,
                         "idempotency key conflict: %s",
                         update->idempotency);
                return -1;
            }
            if (idempotency_state_matches(rib, update)) {
                result->idempotent = true;
                result->routes_unchanged++;
                result->generation = rib->idempotency[idem].generation;
                result->fib_update_id = rib->idempotency[idem].fib_update_id;
                return 0;
            }
        }
    }
    result_add_affected_prefix(result, update->prefix);
    if (strcmp(update->op, "delete") == 0)
        return apply_delete(rib, update, current_generation,
                            current_fib_update_id, result);
    return apply_replace(rib, update, generation, fib_update_id,
                         result, err, err_size);
}

static int update_scope_matches(const rpd_rib *rib,
                                const rib_update *update,
                                char *err, size_t err_size) {
    if (!rib || !update)
        return -1;
    if (!update->has_table && !update->has_kernel_table) {
        if (strcmp(rib->table, RPD_RIB_TABLE) == 0)
            return 0;
        snprintf(err, err_size,
                 "unscoped route update is restricted to %s",
                 RPD_RIB_TABLE);
        return -1;
    }
    if (update->has_table && strcmp(update->table, rib->table) != 0) {
        snprintf(err, err_size,
                 "route table %s does not match RIB %s",
                 update->table, rib->table);
        return -1;
    }
    if (update->has_kernel_table &&
        update->kernel_table != rib->kernel_table) {
        snprintf(err, err_size,
                 "route table id %u does not match RIB %u",
                 update->kernel_table, rib->kernel_table);
        return -1;
    }
    return 0;
}

static int extract_single_update_line(const char *payload, int payload_len,
                                      char *linebuf, size_t linebuf_size,
                                      char *err, size_t err_size) {
    const char *p;
    const char *end;
    int effective = 0;

    if (!payload || payload_len <= 0)
        return 0;
    p = payload;
    end = payload + payload_len;
    while (p && p < end) {
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char tmp[1024];
        char *clean;

        if (len >= sizeof(tmp) || len >= linebuf_size) {
            snprintf(err, err_size, "route update line is too long");
            return -1;
        }
        memcpy(tmp, line, len);
        tmp[len] = '\0';
        clean = trim(tmp);
        if (*clean && *clean != '#') {
            effective++;
            if (effective > 1)
                return 0;
            str_copy(linebuf, linebuf_size, clean);
        }
        p = nl ? nl + 1 : end;
    }
    return effective == 1 ? 1 : 0;
}

static int split_words(char *line, char **argv, int max_argc) {
    int argc = 0;
    char *save = NULL;
    char *tok = strtok_r(line, " \t", &save);

    while (tok && argc < max_argc) {
        argv[argc++] = tok;
        tok = strtok_r(NULL, " \t", &save);
    }
    return argc;
}

static int static_find_nexthop(const static_plan_index *idx, int id) {
    for (int i = 0; i < idx->n_nexthops; i++)
        if (idx->nexthops[i].id == id)
            return i;
    return -1;
}

static int static_find_rif(const static_plan_index *idx, const char *name) {
    for (int i = 0; i < idx->n_rifs; i++)
        if (strcmp(idx->rifs[i].name, name) == 0)
            return i;
    return -1;
}

static int static_find_arp(const static_plan_index *idx, const char *ip,
                           const char *rif) {
    for (int i = 0; i < idx->n_arps; i++)
        if (strcmp(idx->arps[i].ip, ip) == 0 &&
            strcmp(idx->arps[i].rif, rif) == 0)
            return i;
    return -1;
}

static int static_find_ecmp(const static_plan_index *idx, int id) {
    for (int i = 0; i < idx->n_ecmp; i++)
        if (idx->ecmp[i].id == id)
            return i;
    return -1;
}

static int static_add_rif(static_plan_index *idx, char **argv, int argc,
                          char *err, size_t err_size) {
    static_rif *rif;
    int address_arg;

    if ((argc != 7 && argc != 9) || strcmp(argv[1], "name") != 0 ||
        strcmp(argv[3], "vlan") != 0)
        return 0;
    if (argc == 9) {
        if (strcmp(argv[5], "port") != 0 ||
            !xml_safe_token(argv[6]) || strcmp(argv[7], "address") != 0)
            return 0;
        address_arg = 8;
    } else {
        if (strcmp(argv[5], "address") != 0)
            return 0;
        address_arg = 6;
    }
    if (idx->n_rifs >= RPD_STATIC_RIFS) {
        snprintf(err, err_size, "too many static RIFs for RIB sync");
        return -1;
    }
    if (!xml_safe_token(argv[2]) ||
        !ipv4_v1_unicast_prefix(argv[address_arg], false) ||
        !cidr_network_string(argv[address_arg],
                             idx->rifs[idx->n_rifs].prefix,
                             sizeof(idx->rifs[idx->n_rifs].prefix))) {
        snprintf(err, err_size, "invalid static RIF for RIB sync");
        return -1;
    }
    rif = &idx->rifs[idx->n_rifs++];
    str_copy(rif->name, sizeof(rif->name), argv[2]);
    str_copy(rif->address, sizeof(rif->address), argv[address_arg]);
    return 0;
}

static int static_add_arp(static_plan_index *idx, char **argv, int argc,
                          char *err, size_t err_size) {
    static_arp *arp;
    int rif_idx;

    if ((argc != 7 && argc != 9) || strcmp(argv[1], "ip") != 0 ||
        strcmp(argv[3], "mac") != 0 || strcmp(argv[5], "interface") != 0 ||
        (argc == 9 && strcmp(argv[7], "egress-port") != 0)) {
        snprintf(err, err_size, "invalid static ARP syntax for RIB sync");
        return -1;
    }
    if (idx->n_arps >= RPD_STATIC_ARP) {
        snprintf(err, err_size, "too many static ARP entries for RIB sync");
        return -1;
    }
    rif_idx = static_find_rif(idx, argv[6]);
    if (!parse_ipv4_host(argv[2], NULL) || !parse_mac(argv[4]) ||
        !xml_safe_token(argv[6]) ||
        (argc == 9 && !xml_safe_token(argv[8])) || rif_idx < 0) {
        snprintf(err, err_size, "invalid static ARP for RIB sync");
        return -1;
    }
    if (!ipv4_in_cidr(argv[2], idx->rifs[rif_idx].address)) {
        snprintf(err, err_size, "static ARP outside RIF subnet");
        return -1;
    }
    if (ipv4_equals_cidr_address(argv[2], idx->rifs[rif_idx].address)) {
        snprintf(err, err_size, "static ARP is RIF local address");
        return -1;
    }
    if (static_find_arp(idx, argv[2], argv[6]) >= 0) {
        snprintf(err, err_size, "duplicate static ARP for RIB sync");
        return -1;
    }
    arp = &idx->arps[idx->n_arps++];
    str_copy(arp->ip, sizeof(arp->ip), argv[2]);
    str_copy(arp->mac, sizeof(arp->mac), argv[4]);
    str_copy(arp->rif, sizeof(arp->rif), argv[6]);
    str_copy(arp->egress_port, sizeof(arp->egress_port),
             argc == 9 ? argv[8] : "-");
    return 0;
}

static int static_add_nexthop(static_plan_index *idx, char **argv, int argc,
                              char *err, size_t err_size) {
    static_nexthop *nh;
    int id;

    if (argc != 7 || strcmp(argv[1], "id") != 0 ||
        strcmp(argv[3], "arp") != 0 || strcmp(argv[5], "interface") != 0)
        return 0;
    if (idx->n_nexthops >= RPD_STATIC_NEXTHOPS) {
        snprintf(err, err_size, "too many static next-hops for RIB sync");
        return -1;
    }
    if (!parse_int_range(argv[2], 1, 65535, &id) ||
        !parse_ipv4_host(argv[4], NULL) || !xml_safe_token(argv[6]) ||
        static_find_rif(idx, argv[6]) < 0 ||
        static_find_arp(idx, argv[4], argv[6]) < 0) {
        snprintf(err, err_size, "invalid static next-hop for RIB sync");
        return -1;
    }
    nh = &idx->nexthops[idx->n_nexthops++];
    nh->id = id;
    str_copy(nh->arp_ip, sizeof(nh->arp_ip), argv[4]);
    str_copy(nh->rif, sizeof(nh->rif), argv[6]);
    return 0;
}

static int static_add_ecmp(static_plan_index *idx, char **argv, int argc,
                           char *err, size_t err_size) {
    char members[256];
    char *save = NULL;
    char *tok;
    static_ecmp *ecmp;
    int id;

    if (argc != 5 || strcmp(argv[1], "id") != 0 ||
        strcmp(argv[3], "members") != 0)
        return 0;
    if (idx->n_ecmp >= RPD_STATIC_ECMP) {
        snprintf(err, err_size, "too many static ECMP groups for RIB sync");
        return -1;
    }
    if (!parse_int_range(argv[2], 1, 65535, &id)) {
        snprintf(err, err_size, "invalid static ECMP id for RIB sync");
        return -1;
    }
    ecmp = &idx->ecmp[idx->n_ecmp++];
    memset(ecmp, 0, sizeof(*ecmp));
    ecmp->id = id;
    str_copy(members, sizeof(members), argv[4]);
    tok = strtok_r(members, ",", &save);
    while (tok) {
        int nh_id = 0;
        if (ecmp->n_members >= RPD_STATIC_ECMP_MEMBERS ||
            !parse_int_range(tok, 1, 65535, &nh_id)) {
            snprintf(err, err_size, "invalid static ECMP member");
            return -1;
        }
        ecmp->members[ecmp->n_members++] = nh_id;
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}

static void remove_protocol(rpd_rib *rib, const char *protocol,
                            rpd_rib_update_result *result) {
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        if (!rib->routes[i].active ||
            strcmp(rib->routes[i].protocol, protocol) != 0)
            continue;
        result_add_affected_prefix(result, rib->routes[i].prefix);
        memset(&rib->routes[i], 0, sizeof(rib->routes[i]));
        result->changed = true;
        result->routes_deleted++;
    }
}

static void remove_arp_source(rpd_rib *rib, const char *source,
                              rpd_rib_update_result *result) {
    for (int i = 0; i < RPD_RIB_MAX_ARP; i++) {
        if (!rib->arps[i].active ||
            strcmp(rib->arps[i].source, source) != 0)
            continue;
        memset(&rib->arps[i], 0, sizeof(rib->arps[i]));
        result->changed = true;
    }
}

static int rib_arp_find(const rpd_rib *rib, const char *ip,
                        const char *rif, const char *source) {
    for (int i = 0; i < RPD_RIB_MAX_ARP; i++) {
        const rpd_rib_arp *arp = &rib->arps[i];

        if (!arp->active)
            continue;
        if (strcmp(arp->ip, ip) == 0 && strcmp(arp->rif, rif) == 0 &&
            (!source || strcmp(arp->source, source) == 0))
            return i;
    }
    return -1;
}

static int rib_arp_alloc(rpd_rib *rib) {
    for (int i = 0; i < RPD_RIB_MAX_ARP; i++)
        if (!rib->arps[i].active)
            return i;
    return -1;
}

static bool route_nexthops_resolved(const rpd_rib *rib,
                                    const rpd_rib_route *route) {
    if (!rib || !route || !route->active)
        return false;
    if (route->n_nexthops == 0)
        return true;
    for (int i = 0; i < route->n_nexthops; i++) {
        const rpd_rib_nexthop *nh = &route->nexthops[i];

        if (rib_arp_find(rib, nh->address, nh->egress_rif, NULL) < 0)
            return false;
    }
    return true;
}

static bool refresh_route_resolution(rpd_rib *rib) {
    bool changed = false;

    if (!rib)
        return false;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        rpd_rib_route *route = &rib->routes[i];
        char old_state[sizeof(route->installed_state)];

        if (!route->active)
            continue;
        str_copy(old_state, sizeof(old_state), route->installed_state);
        if (strcmp(route->protocol, "connected") == 0) {
            str_copy(route->installed_state,
                     sizeof(route->installed_state), "owner-applied");
        } else if (!route_nexthops_resolved(rib, route)) {
            str_copy(route->installed_state,
                     sizeof(route->installed_state), "pending-arp");
        } else if (strcmp(route->protocol, "static") == 0) {
            if (strcmp(old_state, "owner-applied") != 0)
                str_copy(route->installed_state,
                         sizeof(route->installed_state), "pending-owner");
        } else if (strcmp(route->installed_state, "pending-arp") == 0 ||
                   !route->installed_state[0]) {
            str_copy(route->installed_state,
                     sizeof(route->installed_state), "pending-fib");
        }
        if (strcmp(old_state, route->installed_state) != 0)
            changed = true;
    }
    return changed;
}

static bool prefix_is_affected(const rpd_rib_update_result *result,
                               const char *prefix) {
    if (!result || !prefix || !prefix[0])
        return false;
    if (result->affected_prefix_overflow)
        return true;
    for (int i = 0; i < result->affected_prefix_count; i++)
        if (strcmp(result->affected_prefixes[i], prefix) == 0)
            return true;
    return false;
}

static bool refresh_affected_route_resolution(
        rpd_rib *rib, const rpd_rib_update_result *result) {
    bool changed = false;

    if (!rib || !result)
        return false;
    if (result->affected_prefix_overflow)
        return refresh_route_resolution(rib);
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        rpd_rib_route *route = &rib->routes[i];
        char old_state[sizeof(route->installed_state)];

        if (!route->active || !prefix_is_affected(result, route->prefix))
            continue;
        str_copy(old_state, sizeof(old_state), route->installed_state);
        if (strcmp(route->protocol, "connected") == 0) {
            str_copy(route->installed_state,
                     sizeof(route->installed_state), "owner-applied");
        } else if (!route_nexthops_resolved(rib, route)) {
            str_copy(route->installed_state,
                     sizeof(route->installed_state), "pending-arp");
        } else if (strcmp(route->protocol, "static") == 0) {
            if (strcmp(old_state, "owner-applied") != 0)
                str_copy(route->installed_state,
                         sizeof(route->installed_state), "pending-owner");
        } else if (strcmp(route->installed_state, "pending-arp") == 0 ||
                   !route->installed_state[0]) {
            str_copy(route->installed_state,
                     sizeof(route->installed_state), "pending-fib");
        }
        if (strcmp(old_state, route->installed_state) != 0)
            changed = true;
    }
    return changed;
}

static bool rib_arp_equal_static(const rpd_rib_arp *arp,
                                 const static_arp *entry) {
    return arp && entry &&
           strcmp(arp->ip, entry->ip) == 0 &&
           strcmp(arp->mac, entry->mac) == 0 &&
           strcmp(arp->rif, entry->rif) == 0 &&
           strcmp(arp->egress_port, entry->egress_port) == 0 &&
           strcmp(arp->source, "static") == 0 &&
           strcmp(arp->installed_state, "owner-applied") == 0;
}

static int static_arp_to_rib(rpd_rib *rib, const static_arp *entry,
                             u64 generation, u64 fib_update_id,
                             rpd_rib_update_result *result,
                             char *err, size_t err_size) {
    rpd_rib_arp *arp;
    int idx;

    idx = rib_arp_find(rib, entry->ip, entry->rif, "static");
    if (idx < 0) {
        idx = rib_arp_alloc(rib);
        if (idx < 0) {
            snprintf(err, err_size, "RIB ARP table is full");
            return -1;
        }
        result->changed = true;
    } else if (!rib_arp_equal_static(&rib->arps[idx], entry)) {
        result->changed = true;
    }

    arp = &rib->arps[idx];
    memset(arp, 0, sizeof(*arp));
    arp->active = true;
    str_copy(arp->ip, sizeof(arp->ip), entry->ip);
    str_copy(arp->mac, sizeof(arp->mac), entry->mac);
    str_copy(arp->rif, sizeof(arp->rif), entry->rif);
    str_copy(arp->egress_port, sizeof(arp->egress_port), entry->egress_port);
    str_copy(arp->source, sizeof(arp->source), "static");
    str_copy(arp->installed_state, sizeof(arp->installed_state),
             "owner-applied");
    arp->generation = generation;
    arp->fib_update_id = fib_update_id;
    return 0;
}

static int dynamic_arp_to_rib(rpd_rib *rib, const static_arp *entry,
                              u64 generation, u64 fib_update_id,
                              rpd_rib_update_result *result,
                              char *err, size_t err_size) {
    rpd_rib_arp *arp;
    int idx;

    idx = rib_arp_find(rib, entry->ip, entry->rif, "linux");
    if (idx < 0) {
        idx = rib_arp_alloc(rib);
        if (idx < 0) {
            snprintf(err, err_size, "RIB ARP table is full");
            return -1;
        }
        result->changed = true;
    } else if (strcmp(rib->arps[idx].mac, entry->mac) != 0 ||
               strcmp(rib->arps[idx].egress_port,
                      entry->egress_port) != 0 ||
               strcmp(rib->arps[idx].installed_state, "learned") != 0) {
        result->changed = true;
    }

    arp = &rib->arps[idx];
    memset(arp, 0, sizeof(*arp));
    arp->active = true;
    str_copy(arp->ip, sizeof(arp->ip), entry->ip);
    str_copy(arp->mac, sizeof(arp->mac), entry->mac);
    str_copy(arp->rif, sizeof(arp->rif), entry->rif);
    str_copy(arp->egress_port, sizeof(arp->egress_port), entry->egress_port);
    str_copy(arp->source, sizeof(arp->source), "linux");
    str_copy(arp->installed_state, sizeof(arp->installed_state), "learned");
    arp->generation = generation;
    arp->fib_update_id = fib_update_id;
    return 0;
}

static int static_connected_to_rib(rpd_rib *rib, const static_rif *rif,
                                   u64 generation, u64 fib_update_id,
                                   rpd_rib_update_result *result,
                                   char *err, size_t err_size) {
    rib_update update;

    memset(&update, 0, sizeof(update));
    str_copy(update.op, sizeof(update.op), "replace");
    str_copy(update.protocol, sizeof(update.protocol), "connected");
    str_copy(update.prefix, sizeof(update.prefix), rif->prefix);
    update.preference = protocol_preference("connected");
    update.metric = 0;
    str_copy(update.egress_rif, sizeof(update.egress_rif), rif->name);
    str_copy(update.installed_state, sizeof(update.installed_state),
             "owner-applied");
    update.fingerprint = fnv1a(update.prefix);
    return apply_replace(rib, &update, generation, fib_update_id,
                         result, err, err_size);
}

static int static_route_to_rib(rpd_rib *rib, const static_plan_index *idx,
                               char **argv, int argc, u64 generation,
                               u64 fib_update_id,
                               rpd_rib_update_result *result,
                               char *err, size_t err_size) {
    rib_update update;
    int id;

    if (argc != 5 || strcmp(argv[1], "prefix") != 0 ||
        (strcmp(argv[3], "next-hop") != 0 && strcmp(argv[3], "ecmp") != 0))
        return 0;
    if (!canonical_prefix(argv[2]) ||
        !ipv4_v1_unicast_prefix(argv[2], true) ||
        !parse_int_range(argv[4], 1, 65535, &id)) {
        snprintf(err, err_size, "invalid static route for RIB sync");
        return -1;
    }
    memset(&update, 0, sizeof(update));
    str_copy(update.op, sizeof(update.op), "replace");
    str_copy(update.protocol, sizeof(update.protocol), "static");
    str_copy(update.prefix, sizeof(update.prefix), argv[2]);
    update.preference = protocol_preference("static");
    update.metric = 0;
    str_copy(update.installed_state, sizeof(update.installed_state),
             "owner-applied");
    if (strcmp(argv[3], "next-hop") == 0) {
        int nh_idx = static_find_nexthop(idx, id);
        if (nh_idx < 0) {
            snprintf(err, err_size, "static route references missing nexthop");
            return -1;
        }
        str_copy(update.egress_rif, sizeof(update.egress_rif),
                 idx->nexthops[nh_idx].rif);
        if (add_update_nexthop(&update, idx->nexthops[nh_idx].arp_ip,
                               idx->nexthops[nh_idx].rif,
                               err, err_size) != 0)
            return -1;
    } else {
        int ecmp_idx = static_find_ecmp(idx, id);
        if (ecmp_idx < 0) {
            snprintf(err, err_size, "static route references missing ECMP");
            return -1;
        }
        for (int i = 0; i < idx->ecmp[ecmp_idx].n_members; i++) {
            int nh_idx = static_find_nexthop(idx,
                                             idx->ecmp[ecmp_idx].members[i]);
            if (nh_idx < 0) {
                snprintf(err, err_size,
                         "static ECMP route references missing nexthop");
                return -1;
            }
            if (!update.egress_rif[0])
                str_copy(update.egress_rif, sizeof(update.egress_rif),
                         idx->nexthops[nh_idx].rif);
            if (add_update_nexthop(&update, idx->nexthops[nh_idx].arp_ip,
                                   idx->nexthops[nh_idx].rif,
                                   err, err_size) != 0)
                return -1;
        }
    }
    nexthops_sort(update.nexthops, update.n_nexthops);
    if (nexthops_have_duplicate(update.nexthops, update.n_nexthops)) {
        snprintf(err, err_size, "duplicate static route nexthop");
        return -1;
    }
    update.fingerprint = fnv1a(update.prefix);
    return apply_replace(rib, &update, generation, fib_update_id,
                         result, err, err_size);
}

static int rib_static_route_to_rib(rpd_rib *rib, char **argv, int argc,
                                   u64 generation, u64 fib_update_id,
                                   rpd_rib_update_result *result,
                                   char *err, size_t err_size) {
    rib_update update;

    (void)rib;
    if (argc != 5 || strcmp(argv[1], "prefix") != 0 ||
        strcmp(argv[3], "nexthops") != 0)
        return 0;
    if (!canonical_prefix(argv[2]) ||
        !ipv4_v1_unicast_prefix(argv[2], true)) {
        snprintf(err, err_size, "invalid static RIB route prefix");
        return -1;
    }
    memset(&update, 0, sizeof(update));
    str_copy(update.op, sizeof(update.op), "replace");
    str_copy(update.protocol, sizeof(update.protocol), "static");
    str_copy(update.prefix, sizeof(update.prefix), argv[2]);
    update.preference = protocol_preference("static");
    update.metric = 0;
    str_copy(update.installed_state, sizeof(update.installed_state),
             "pending-arp");
    if (add_update_nexthop_list(&update, argv[4], NULL,
                                err, err_size) != 0)
        return -1;
    if (update.n_nexthops <= 0) {
        snprintf(err, err_size, "static RIB route requires nexthop");
        return -1;
    }
    if (update.nexthops[0].egress_rif[0])
        str_copy(update.egress_rif, sizeof(update.egress_rif),
                 update.nexthops[0].egress_rif);
    nexthops_sort(update.nexthops, update.n_nexthops);
    if (nexthops_have_duplicate(update.nexthops, update.n_nexthops)) {
        snprintf(err, err_size, "duplicate static RIB route nexthop");
        return -1;
    }
    update.fingerprint = fnv1a(update.prefix);
    return apply_replace(rib, &update, generation, fib_update_id,
                         result, err, err_size);
}

int rpd_rib_init_scope(rpd_rib *rib, const char *table, u32 kernel_table) {
    if (!rib || !table || !xml_safe_token(table) ||
        strlen(table) >= sizeof(rib->table) || kernel_table == 0)
        return -1;
    memset(rib, 0, sizeof(*rib));
    str_copy(rib->table, sizeof(rib->table), table);
    rib->kernel_table = kernel_table;
    return 0;
}

int rpd_rib_init_table(rpd_rib *rib, const char *table) {
    return rpd_rib_init_scope(rib, table, RPD_RIB_MAIN_KERNEL_TABLE);
}

void rpd_rib_init(rpd_rib *rib) {
    (void)rpd_rib_init_table(rib, RPD_RIB_TABLE);
}

void rpd_rib_get_stats(const rpd_rib *rib, rpd_rib_stats *stats) {
    bool best[RPD_RIB_MAX_ROUTES];

    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (!rib)
        return;
    if (route_best_flags(rib, best, RPD_RIB_MAX_ROUTES) != 0)
        return;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        const rpd_rib_route *route = &rib->routes[i];
        if (!route->active)
            continue;
        stats->candidates++;
        if (strcmp(route->protocol, "connected") == 0)
            stats->connected++;
        else if (strcmp(route->protocol, "static") == 0)
            stats->static_routes++;
        else if (strcmp(route->protocol, "ospf") == 0)
            stats->ospf++;
        else if (strcmp(route->protocol, "bgp") == 0)
            stats->bgp++;
        if (route->n_nexthops > 1) {
            stats->ecmp_routes++;
            stats->ecmp_members += route->n_nexthops;
        }
        if (best[i])
            stats->best_routes++;
    }
    for (int i = 0; i < RPD_RIB_MAX_ARP; i++)
        if (rib->arps[i].active)
            stats->arp_entries++;
}

int rpd_rib_apply_fpm_text(rpd_rib *rib, const char *payload,
                           int payload_len, u64 generation,
                           u64 fib_update_id,
                           rpd_rib_update_result *result,
                           char *err, size_t err_size) {
    rpd_rib *tmp;
    const char *p;
    const char *end;
    char single_line[1024];
    int single;

    if (!rib || !result) {
        snprintf(err, err_size, "invalid RIB update context");
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->generation = generation;
    result->fib_update_id = fib_update_id;
    if (payload_len <= 0) {
        snprintf(err, err_size, "empty RIB update");
        return -1;
    }
    single_line[0] = '\0';
    single = extract_single_update_line(payload, payload_len,
                                        single_line, sizeof(single_line),
                                        err, err_size);
    if (single < 0)
        return -1;
    if (single > 0) {
        rib_update update;

        if (parse_update_line(single_line, &update, err, err_size) != 0)
            return -1;
        if (update_scope_matches(rib, &update, err, err_size) != 0)
            return -1;
        if (apply_update(rib, &update, generation, fib_update_id,
                         result, err, err_size) != 0)
            return -1;
        if (refresh_affected_route_resolution(rib, result))
            result->changed = true;
        snprintf(result->detail, sizeof(result->detail), "%s",
                 result->idempotent ? "idempotent duplicate" :
                 (result->changed ? "RIB updated" : "no RIB change"));
        return 0;
    }
    tmp = malloc(sizeof(*tmp));
    if (!tmp) {
        snprintf(err, err_size, "RIB update allocation failed");
        return -1;
    }
    memcpy(tmp, rib, sizeof(*tmp));
    p = payload;
    end = payload + payload_len;
    while (p && p < end) {
        char linebuf[1024];
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char *clean;
        rib_update update;

        if (len >= sizeof(linebuf)) {
            snprintf(err, err_size, "route update line is too long");
            free(tmp);
            return -1;
        }
        memcpy(linebuf, line, len);
        linebuf[len] = '\0';
        clean = trim(linebuf);
        if (*clean && *clean != '#') {
            if (parse_update_line(clean, &update, err, err_size) != 0) {
                free(tmp);
                return -1;
            }
            if (update_scope_matches(rib, &update, err, err_size) != 0) {
                free(tmp);
                return -1;
            }
            if (apply_update(tmp, &update, generation, fib_update_id,
                             result, err, err_size) != 0) {
                free(tmp);
                return -1;
            }
        }
        p = nl ? nl + 1 : end;
    }
    if (refresh_affected_route_resolution(tmp, result))
        result->changed = true;
    memcpy(rib, tmp, sizeof(*rib));
    free(tmp);
    snprintf(result->detail, sizeof(result->detail), "%s",
             result->idempotent ? "idempotent duplicate" :
             (result->changed ? "RIB updated" : "no RIB change"));
    return 0;
}

static int static_record_for_rib(const rpd_rib *rib, char **argv,
                                 int *argc, bool *matches,
                                 char *err, size_t err_size) {
    const char *table = RPD_RIB_TABLE;

    if (!rib || !argv || !argc || !matches || *argc <= 0)
        return -1;
    if (*argc >= 2 && strcmp(argv[*argc - 2], "table") == 0) {
        table = argv[*argc - 1];
        *argc -= 2;
    }
    if (!xml_safe_token(table) || strlen(table) >= RPD_RIB_TABLE_LEN) {
        snprintf(err, err_size, "invalid static plan table");
        return -1;
    }
    *matches = strcmp(table, rib->table) == 0;
    return 0;
}

int rpd_rib_sync_static_plan(rpd_rib *rib, const char *payload,
                             int payload_len, u64 generation,
                             u64 fib_update_id,
                             rpd_rib_update_result *result,
                             char *err, size_t err_size) {
    rpd_rib *tmp;
    static_plan_index idx;
    const char *p;
    const char *end;

    if (!rib || !result) {
        snprintf(err, err_size, "invalid static RIB sync context");
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->generation = generation;
    result->fib_update_id = fib_update_id;
    tmp = malloc(sizeof(*tmp));
    if (!tmp) {
        snprintf(err, err_size, "static RIB sync allocation failed");
        return -1;
    }
    memcpy(tmp, rib, sizeof(*tmp));
    memset(&idx, 0, sizeof(idx));
    remove_protocol(tmp, "connected", result);
    remove_protocol(tmp, "static", result);
    remove_arp_source(tmp, "static", result);

    p = payload;
    end = payload + payload_len;
    while (p && p < end) {
        char linebuf[512];
        char *argv[16];
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char *clean;
        int argc;
        bool matches = false;

        if (len >= sizeof(linebuf)) {
            snprintf(err, err_size, "static plan line too long for RIB sync");
            free(tmp);
            return -1;
        }
        memcpy(linebuf, line, len);
        linebuf[len] = '\0';
        clean = trim(linebuf);
        if (*clean && *clean != '#') {
            argc = split_words(clean, argv, 16);
            if (static_record_for_rib(rib, argv, &argc, &matches,
                                      err, err_size) != 0) {
                free(tmp);
                return -1;
            }
            if (matches && argc > 0 && strcmp(argv[0], "rif") == 0 &&
                static_add_rif(&idx, argv, argc, err, err_size) != 0) {
                free(tmp);
                return -1;
            }
        }
        p = nl ? nl + 1 : end;
    }

    p = payload;
    while (p && p < end) {
        char linebuf[512];
        char *argv[16];
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char *clean;
        int argc;
        bool matches = false;

        if (len >= sizeof(linebuf)) {
            snprintf(err, err_size, "static plan line too long for RIB sync");
            free(tmp);
            return -1;
        }
        memcpy(linebuf, line, len);
        linebuf[len] = '\0';
        clean = trim(linebuf);
        if (*clean && *clean != '#') {
            argc = split_words(clean, argv, 16);
            if (static_record_for_rib(rib, argv, &argc, &matches,
                                      err, err_size) != 0) {
                free(tmp);
                return -1;
            }
            if (matches && argc > 0 && strcmp(argv[0], "arp") == 0 &&
                static_add_arp(&idx, argv, argc, err, err_size) != 0) {
                free(tmp);
                return -1;
            }
        }
        p = nl ? nl + 1 : end;
    }

    p = payload;
    while (p && p < end) {
        char linebuf[512];
        char *argv[16];
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char *clean;
        int argc;
        bool matches = false;

        if (len >= sizeof(linebuf)) {
            snprintf(err, err_size, "static plan line too long for RIB sync");
            free(tmp);
            return -1;
        }
        memcpy(linebuf, line, len);
        linebuf[len] = '\0';
        clean = trim(linebuf);
        if (*clean && *clean != '#') {
            argc = split_words(clean, argv, 16);
            if (static_record_for_rib(rib, argv, &argc, &matches,
                                      err, err_size) != 0) {
                free(tmp);
                return -1;
            }
            if (matches && argc > 0 && strcmp(argv[0], "next-hop") == 0 &&
                static_add_nexthop(&idx, argv, argc, err, err_size) != 0) {
                free(tmp);
                return -1;
            }
        }
        p = nl ? nl + 1 : end;
    }

    p = payload;
    while (p && p < end) {
        char linebuf[512];
        char *argv[16];
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char *clean;
        int argc;
        bool matches = false;

        if (len >= sizeof(linebuf)) {
            snprintf(err, err_size, "static plan line too long for RIB sync");
            free(tmp);
            return -1;
        }
        memcpy(linebuf, line, len);
        linebuf[len] = '\0';
        clean = trim(linebuf);
        if (*clean && *clean != '#') {
            argc = split_words(clean, argv, 16);
            if (static_record_for_rib(rib, argv, &argc, &matches,
                                      err, err_size) != 0) {
                free(tmp);
                return -1;
            }
            if (matches && argc > 0 && strcmp(argv[0], "ecmp") == 0 &&
                static_add_ecmp(&idx, argv, argc, err, err_size) != 0) {
                free(tmp);
                return -1;
            }
        }
        p = nl ? nl + 1 : end;
    }

    for (int i = 0; i < idx.n_rifs; i++) {
        if (static_connected_to_rib(tmp, &idx.rifs[i], generation,
                                    fib_update_id, result,
                                    err, err_size) != 0) {
            free(tmp);
            return -1;
        }
    }

    for (int i = 0; i < idx.n_arps; i++) {
        if (static_arp_to_rib(tmp, &idx.arps[i], generation,
                              fib_update_id, result,
                              err, err_size) != 0) {
            free(tmp);
            return -1;
        }
    }

    p = payload;
    while (p && p < end) {
        char linebuf[512];
        char *argv[16];
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char *clean;
        int argc;
        bool matches = false;

        if (len >= sizeof(linebuf)) {
            snprintf(err, err_size, "static plan line too long for RIB sync");
            free(tmp);
            return -1;
        }
        memcpy(linebuf, line, len);
        linebuf[len] = '\0';
        clean = trim(linebuf);
        if (*clean && *clean != '#') {
            argc = split_words(clean, argv, 16);
            if (static_record_for_rib(rib, argv, &argc, &matches,
                                      err, err_size) != 0) {
                free(tmp);
                return -1;
            }
            if (matches && argc > 0 && strcmp(argv[0], "route") == 0 &&
                static_route_to_rib(tmp, &idx, argv, argc, generation,
                                    fib_update_id, result,
                                    err, err_size) != 0) {
                free(tmp);
                return -1;
            }
            if (matches && argc > 0 &&
                strcmp(argv[0], "rib-static-route") == 0 &&
                rib_static_route_to_rib(tmp, argv, argc, generation,
                                        fib_update_id, result,
                                        err, err_size) != 0) {
                free(tmp);
                return -1;
            }
        }
        p = nl ? nl + 1 : end;
    }
    if (refresh_route_resolution(tmp))
        result->changed = true;
    memcpy(rib, tmp, sizeof(*rib));
    free(tmp);
    snprintf(result->detail, sizeof(result->detail), "%s",
             result->changed ? "static plan synced" : "no static RIB change");
    return 0;
}

int rpd_rib_purge_dynamic_protocols(rpd_rib *rib, u64 generation,
                                    u64 fib_update_id,
                                    rpd_rib_update_result *result,
                                    char *err, size_t err_size) {
    rpd_rib *tmp;

    if (!rib || !result) {
        snprintf(err, err_size, "invalid dynamic RIB purge context");
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->generation = generation;
    result->fib_update_id = fib_update_id;
    tmp = malloc(sizeof(*tmp));
    if (!tmp) {
        snprintf(err, err_size, "dynamic RIB purge allocation failed");
        return -1;
    }
    memcpy(tmp, rib, sizeof(*tmp));
    remove_protocol(tmp, "ospf", result);
    remove_protocol(tmp, "bgp", result);
    if (result->changed) {
        idempotency_clear(tmp);
        (void)refresh_route_resolution(tmp);
    }
    memcpy(rib, tmp, sizeof(*rib));
    free(tmp);
    snprintf(result->detail, sizeof(result->detail), "%s",
             result->changed ? "dynamic protocols purged" :
             "no dynamic RIB routes to purge");
    return 0;
}

static int dynamic_add_arp(static_plan_index *idx, char **argv, int argc,
                           char *err, size_t err_size) {
    static_arp *arp;

    if ((argc != 7 && argc != 9) || strcmp(argv[0], "arp") != 0 ||
        strcmp(argv[1], "ip") != 0 || strcmp(argv[3], "mac") != 0 ||
        strcmp(argv[5], "interface") != 0 ||
        (argc == 9 && strcmp(argv[7], "egress-port") != 0)) {
        snprintf(err, err_size, "invalid dynamic ARP syntax");
        return -1;
    }
    if (idx->n_arps >= RPD_STATIC_ARP) {
        snprintf(err, err_size, "too many dynamic ARP entries");
        return -1;
    }
    if (!parse_ipv4_host(argv[2], NULL) || !parse_mac(argv[4]) ||
        !xml_safe_token(argv[6]) ||
        (argc == 9 && !xml_safe_token(argv[8]))) {
        snprintf(err, err_size, "invalid dynamic ARP entry");
        return -1;
    }
    if (static_find_arp(idx, argv[2], argv[6]) >= 0) {
        snprintf(err, err_size, "duplicate dynamic ARP entry");
        return -1;
    }
    arp = &idx->arps[idx->n_arps++];
    str_copy(arp->ip, sizeof(arp->ip), argv[2]);
    str_copy(arp->mac, sizeof(arp->mac), argv[4]);
    str_copy(arp->rif, sizeof(arp->rif), argv[6]);
    str_copy(arp->egress_port, sizeof(arp->egress_port),
             argc == 9 ? argv[8] : "-");
    return 0;
}

int rpd_rib_sync_dynamic_arp_text(rpd_rib *rib, const char *payload,
                                  int payload_len, u64 generation,
                                  u64 fib_update_id,
                                  rpd_rib_update_result *result,
                                  char *err, size_t err_size) {
    rpd_rib *tmp;
    static_plan_index idx;
    const char *p;
    const char *end;

    if (!rib || !result) {
        snprintf(err, err_size, "invalid dynamic ARP sync context");
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->generation = generation;
    result->fib_update_id = fib_update_id;
    tmp = malloc(sizeof(*tmp));
    if (!tmp) {
        snprintf(err, err_size, "dynamic ARP sync allocation failed");
        return -1;
    }
    memcpy(tmp, rib, sizeof(*tmp));
    memset(&idx, 0, sizeof(idx));
    remove_arp_source(tmp, "linux", result);

    p = payload;
    end = payload ? payload + payload_len : payload;
    while (p && p < end) {
        char linebuf[512];
        char *argv[16];
        const char *line = p;
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
        char *clean;
        int argc;

        if (len >= sizeof(linebuf)) {
            snprintf(err, err_size, "dynamic ARP line too long");
            free(tmp);
            return -1;
        }
        memcpy(linebuf, line, len);
        linebuf[len] = '\0';
        clean = trim(linebuf);
        if (*clean && *clean != '#') {
            argc = split_words(clean, argv, 16);
            if (dynamic_add_arp(&idx, argv, argc, err, err_size) != 0) {
                free(tmp);
                return -1;
            }
        }
        p = nl ? nl + 1 : end;
    }
    for (int i = 0; i < idx.n_arps; i++) {
        if (dynamic_arp_to_rib(tmp, &idx.arps[i], generation,
                               fib_update_id, result,
                               err, err_size) != 0) {
            free(tmp);
            return -1;
        }
    }
    if (refresh_route_resolution(tmp))
        result->changed = true;
    memcpy(rib, tmp, sizeof(*rib));
    free(tmp);
    snprintf(result->detail, sizeof(result->detail), "%s",
             result->changed ? "dynamic ARP synced" :
             "no dynamic ARP change");
    return 0;
}

#define RPD_RIB_FIB_NEXTHOPS_TEXT_MAX 2048
#define RPD_RIB_FIB_ROUTE_TEXT_MAX 2304

static int route_nexthops_attr(const rpd_rib_route *route, char *out,
                               size_t out_size) {
    size_t off = 0;

    if (!route || !out || out_size == 0)
        return -1;
    out[0] = '\0';
    for (int i = 0; i < route->n_nexthops; i++) {
        int n = snprintf(out + off, out_size - off, "%s%s@%s",
                         i == 0 ? "" : ",",
                         route->nexthops[i].address,
                         route->nexthops[i].egress_rif);
        if (n < 0)
            return -1;
        if ((size_t)n >= out_size - off)
            return -1;
        off += (size_t)n;
    }
    if (off == 0)
        str_copy(out, out_size, "-");
    return 0;
}

static int batch_appendf(char *buf, size_t buf_size, size_t *off,
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

static const char *route_owner_role(const rpd_rib_route *route) {
    if (route && (strcmp(route->protocol, "connected") == 0 ||
                  strcmp(route->protocol, "static") == 0))
        return "persistent-owner";
    return "dynamic-fib";
}

static int append_fib_route(char *buf, size_t buf_size, size_t *off,
                            const rpd_rib_route *route,
                            const char *op) {
    char nh_attr[RPD_RIB_FIB_NEXTHOPS_TEXT_MAX];

    if (!route)
        return -1;
    if (route_nexthops_attr(route, nh_attr, sizeof(nh_attr)) != 0)
        return -1;
    return batch_appendf(buf, buf_size, off,
                         "fib-route op=%s prefix=%s protocol=%s "
                         "preference=%d metric=%d nexthops=%s "
                         "egress-rif=%s installed-state=%s "
                         "route-generation=%llu fib-update-id=%llu "
                         "owner-role=%s\n",
                         op && op[0] ? op : "replace",
                         route->prefix, route->protocol,
                         route->preference, route->metric, nh_attr,
                         route->egress_rif[0] ? route->egress_rif : "-",
                         route->installed_state[0] ?
                            route->installed_state : "pending-fib",
                         (unsigned long long)route->generation,
                         (unsigned long long)route->fib_update_id,
                         route_owner_role(route));
}

static bool route_is_fib_candidate_eligible(const rpd_rib *rib, int index) {
    const rpd_rib_route *route;

    if (!rib || index < 0 || index >= RPD_RIB_MAX_ROUTES)
        return false;
    route = &rib->routes[index];
    if (!route->active)
        return false;
    if (strcmp(route->protocol, "static") == 0 &&
        strcmp(route->installed_state, "owner-applied") != 0)
        return false;
    return route_nexthops_resolved(rib, route);
}

int rpd_rib_fib_route_count(const rpd_rib *rib) {
    bool best[RPD_RIB_MAX_ROUTES];
    int routes = 0;

    if (!rib || route_best_flags(rib, best,
                                 RPD_RIB_MAX_ROUTES) != 0)
        return -1;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++)
        if (best[i] && route_is_fib_candidate_eligible(rib, i))
            routes++;
    return routes;
}

int rpd_rib_compile_fib_batch(const rpd_rib *rib, u64 generation,
                              u64 fib_update_id, char *buf,
                              size_t buf_size, int *routes_out) {
    bool best[RPD_RIB_MAX_ROUTES];
    size_t off = 0;
    int routes = 0;

    if (!rib || !buf || buf_size == 0)
        return -1;
    if (route_best_flags(rib, best, RPD_RIB_MAX_ROUTES) != 0)
        return -1;
    buf[0] = '\0';
    if (batch_appendf(buf, buf_size, &off,
                      "fib-batch table=%s generation=%llu "
                      "fib-update-id=%llu\n",
                      rib->table[0] ? rib->table : RPD_RIB_TABLE,
                      (unsigned long long)generation,
                      (unsigned long long)fib_update_id) != 0)
        return -1;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        const rpd_rib_route *route = &rib->routes[i];

        if (!best[i] || !route_is_fib_candidate_eligible(rib, i))
            continue;
        if (append_fib_route(buf, buf_size, &off, route, "replace") != 0)
            return -1;
        routes++;
    }
    if (routes_out)
        *routes_out = routes;
    return (int)off;
}

int rpd_rib_compile_fib_batch_alloc(const rpd_rib *rib, u64 generation,
                                    u64 fib_update_id, char **buf_out,
                                    size_t *len_out, int *routes_out) {
    char *buf;
    size_t capacity;
    int routes;
    int length;

    if (!rib || !buf_out || !len_out)
        return -1;
    *buf_out = NULL;
    *len_out = 0;
    routes = rpd_rib_fib_route_count(rib);
    if (routes < 0 || routes > RPD_RIB_MAX_ROUTES)
        return -1;
    capacity = 4096u + (size_t)routes * RPD_RIB_FIB_ROUTE_TEXT_MAX;
    buf = malloc(capacity);
    if (!buf)
        return -1;
    length = rpd_rib_compile_fib_batch(rib, generation, fib_update_id,
                                       buf, capacity, &routes);
    if (length < 0) {
        free(buf);
        return -1;
    }
    *buf_out = buf;
    *len_out = (size_t)length;
    if (routes_out)
        *routes_out = routes;
    return 0;
}

void rpd_rib_mark_dynamic_fib_installed(rpd_rib *rib) {
    bool best[RPD_RIB_MAX_ROUTES];

    if (!rib)
        return;
    if (route_best_flags(rib, best, RPD_RIB_MAX_ROUTES) != 0)
        return;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        rpd_rib_route *route = &rib->routes[i];

        if (!route->active ||
            !best[i] ||
            strcmp(route->protocol, "connected") == 0 ||
            strcmp(route->protocol, "static") == 0 ||
            !route_nexthops_resolved(rib, route))
            continue;
        str_copy(route->installed_state, sizeof(route->installed_state),
                 "owner-applied");
    }
}

void rpd_rib_mark_dynamic_fib_installed_through(rpd_rib *rib,
                                                u64 generation,
                                                u64 fib_update_id) {
    bool best[RPD_RIB_MAX_ROUTES];

    if (!rib)
        return;
    if (route_best_flags(rib, best, RPD_RIB_MAX_ROUTES) != 0)
        return;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        rpd_rib_route *route = &rib->routes[i];

        if (!route->active ||
            !best[i] ||
            strcmp(route->protocol, "connected") == 0 ||
            strcmp(route->protocol, "static") == 0 ||
            !route_nexthops_resolved(rib, route) ||
            route->generation > generation ||
            route->fib_update_id > fib_update_id)
            continue;
        str_copy(route->installed_state, sizeof(route->installed_state),
                 "owner-applied");
    }
}

int rpd_rib_compile_fib_delta(const rpd_rib *rib,
                              const rpd_rib_update_result *result,
                              u64 generation, u64 fib_update_id,
                              char *buf, size_t buf_size, int *routes_out) {
    rib_best_index index;
    size_t off = 0;
    int routes = 0;

    if (!rib || !result || !buf || buf_size == 0)
        return -1;
    if (route_best_index_build(rib, &index) != 0)
        return -1;
    buf[0] = '\0';
    if (batch_appendf(buf, buf_size, &off,
                      "fib-batch table=%s generation=%llu "
                      "fib-update-id=%llu mode=delta\n",
                      rib->table[0] ? rib->table : RPD_RIB_TABLE,
                      (unsigned long long)generation,
                      (unsigned long long)fib_update_id) != 0)
        return -1;
    for (int i = 0; i < result->affected_prefix_count; i++) {
        const char *prefix = result->affected_prefixes[i];
        int idx = fib_best_route_find(rib, &index, prefix);

        if (idx >= 0) {
            if (append_fib_route(buf, buf_size, &off,
                                 &rib->routes[idx], "replace") != 0)
                return -1;
        } else if (batch_appendf(buf, buf_size, &off,
                                 "fib-route op=delete prefix=%s\n",
                                 prefix) != 0) {
            return -1;
        }
        routes++;
    }
    if (routes_out)
        *routes_out = routes;
    return (int)off;
}

int rpd_rib_append_xml(const rpd_rib *rib, char *buf, size_t buf_size,
                       size_t *off) {
    bool best[RPD_RIB_MAX_ROUTES];
    rpd_rib_stats stats;
    int emitted = 0;
    int emitted_arp = 0;
    int total = 0;
    int total_arp = 0;
    int n;

    if (!rib || !buf || !off || *off >= buf_size)
        return -1;
    if (route_best_flags(rib, best, RPD_RIB_MAX_ROUTES) != 0)
        return -1;
    rpd_rib_get_stats(rib, &stats);
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++)
        if (rib->routes[i].active)
            total++;
    for (int i = 0; i < RPD_RIB_MAX_ARP; i++)
        if (rib->arps[i].active)
            total_arp++;
    n = snprintf(buf + *off, buf_size - *off,
                 "  <rib table=\"%s\" candidates=\"%d\" best=\"%d\" "
                 "connected=\"%d\" static=\"%d\" ospf=\"%d\" bgp=\"%d\" "
                 "ecmp-routes=\"%d\" ecmp-members=\"%d\" arp=\"%d\" "
                 "emitted-limit=\"%d\" truncated=\"%s\">\n",
                 rib->table[0] ? rib->table : RPD_RIB_TABLE,
                 stats.candidates, stats.best_routes,
                 stats.connected, stats.static_routes, stats.ospf, stats.bgp,
                 stats.ecmp_routes, stats.ecmp_members, stats.arp_entries,
                 RPD_RIB_XML_ROUTE_LIMIT,
                 total > RPD_RIB_XML_ROUTE_LIMIT ? "true" : "false");
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    for (int i = 0; i < RPD_RIB_MAX_ROUTES; i++) {
        const rpd_rib_route *route = &rib->routes[i];
        char nh_attr[RPD_RIB_FIB_NEXTHOPS_TEXT_MAX];

        if (!route->active)
            continue;
        if (emitted++ >= RPD_RIB_XML_ROUTE_LIMIT)
            break;
        if (route_nexthops_attr(route, nh_attr, sizeof(nh_attr)) != 0)
            return -1;
        n = snprintf(buf + *off, buf_size - *off,
                     "    <route prefix=\"%s\" protocol=\"%s\" "
                     "preference=\"%d\" metric=\"%d\" selected=\"%s\" "
                     "nexthops=\"%d\" ecmp-key=\"%s\" "
                     "egress-rif=\"%s\" installed-state=\"%s\" "
                     "generation=\"%llu\" fib-update-id=\"%llu\">\n",
                     route->prefix, route->protocol, route->preference,
                     route->metric, best[i] ? "true" : "false",
                     route->n_nexthops, nh_attr, route->egress_rif,
                     route->installed_state,
                     (unsigned long long)route->generation,
                     (unsigned long long)route->fib_update_id);
        if (n < 0 || (size_t)n >= buf_size - *off)
            return -1;
        *off += (size_t)n;
        for (int nh = 0; nh < route->n_nexthops; nh++) {
            n = snprintf(buf + *off, buf_size - *off,
                         "      <nexthop index=\"%d\" address=\"%s\" "
                         "egress-rif=\"%s\"/>\n",
                         nh, route->nexthops[nh].address,
                         route->nexthops[nh].egress_rif);
            if (n < 0 || (size_t)n >= buf_size - *off)
                return -1;
            *off += (size_t)n;
        }
        n = snprintf(buf + *off, buf_size - *off, "    </route>\n");
        if (n < 0 || (size_t)n >= buf_size - *off)
            return -1;
        *off += (size_t)n;
    }
    n = snprintf(buf + *off, buf_size - *off,
                 "    <arp-table entries=\"%d\" emit-limit=\"%d\" "
                 "truncated=\"%s\">\n",
                 total_arp, RPD_RIB_XML_ARP_LIMIT,
                 total_arp > RPD_RIB_XML_ARP_LIMIT ? "true" : "false");
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    for (int i = 0; i < RPD_RIB_MAX_ARP; i++) {
        const rpd_rib_arp *arp = &rib->arps[i];

        if (!arp->active)
            continue;
        if (emitted_arp++ >= RPD_RIB_XML_ARP_LIMIT)
            break;
        n = snprintf(buf + *off, buf_size - *off,
                     "      <arp ip=\"%s\" mac=\"%s\" rif=\"%s\" "
                     "egress-port=\"%s\" source=\"%s\" "
                     "installed-state=\"%s\" generation=\"%llu\" "
                     "fib-update-id=\"%llu\"/>\n",
                     arp->ip, arp->mac, arp->rif, arp->egress_port,
                     arp->source, arp->installed_state,
                     (unsigned long long)arp->generation,
                     (unsigned long long)arp->fib_update_id);
        if (n < 0 || (size_t)n >= buf_size - *off)
            return -1;
        *off += (size_t)n;
    }
    n = snprintf(buf + *off, buf_size - *off, "    </arp-table>\n");
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    n = snprintf(buf + *off, buf_size - *off, "  </rib>\n");
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}
