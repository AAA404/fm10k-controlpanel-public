#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/l3_capacity.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define L3_SHADOW_EMIT_LIMIT 8
#define L3_FIB_MAX_ROUTES NL_L3_DYNAMIC_MAX_ROUTES
#define L3_FIB_MAX_NEXTHOPS NL_L3_DYNAMIC_MAX_NEXTHOPS
#define L3_FIB_NEXTHOPS_TEXT_MAX 2048
#define L3_FIB_SHADOW_EMIT_LIMIT 16
#define L3_FIB_SNAPSHOT_PREFIX_SLOTS (L3_FIB_MAX_ROUTES * 2)
#define L3_FIB_SNAPSHOT_MAX_BYTES \
    ((size_t)L3_FIB_MAX_ROUTES * 2304u + 4096u)
#define L3_FIB_SNAPSHOT_MAX_PARTS 512
#define L3_FIB_SNAPSHOT_PART_MAX_BYTES 60000u
#define L3_FIB_SNAPSHOT_TTL_NS (30ULL * 1000ULL * 1000ULL * 1000ULL)
#define L3_FIB_SNAPSHOT_DIGEST_INIT UINT64_C(14695981039346656037)
#define L3_FIB_SNAPSHOT_DIGEST_PRIME UINT64_C(1099511628211)

typedef hal_l3_intent_rif l3_tx_rif;
typedef hal_l3_intent_arp l3_tx_arp;
typedef hal_l3_intent_next_hop l3_tx_nexthop;
typedef hal_l3_intent_ecmp l3_tx_ecmp;
typedef hal_l3_intent_route l3_tx_route;

typedef struct {
    bool has_router_mac;
    char router_mac[HAL_L3_INTENT_MAC_LEN];
    bool has_virtual_router;
    char virtual_router_name[HAL_L3_INTENT_NAME_LEN];
    char virtual_router_table[HAL_L3_INTENT_TABLE_LEN];
    int virtual_router_id;
    int virtual_router_kernel_table;
    l3_tx_rif rifs[NL_L3_PERSISTENT_MAX_RIFS];
    int n_rifs;
    l3_tx_arp arps[NL_L3_PERSISTENT_MAX_ARP];
    int n_arps;
    l3_tx_nexthop nexthops[NL_L3_PERSISTENT_MAX_NEXTHOPS];
    int n_nexthops;
    l3_tx_ecmp ecmp[NL_L3_PERSISTENT_MAX_ECMP];
    int n_ecmp;
    l3_tx_route routes[NL_L3_PERSISTENT_MAX_ROUTES];
    int n_routes;
} l3_tx_state;

typedef enum {
    L3_OWNER_IDLE = 0,
    L3_OWNER_APPLIED,
    L3_OWNER_ROLLED_BACK,
} l3_owner_state;

typedef struct {
    l3_tx_state *current;
    l3_tx_state *pre;
    bool rollback_available;
    l3_owner_state state;
    u64 last_tx_id;
    u64 next_tx_id;
} l3_tx_owner;

static l3_tx_owner g_l3_tx_owner;
static pthread_mutex_t g_l3_tx_owner_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char address[40];
    char egress_rif[64];
} l3_fib_nexthop;

typedef struct {
    char op[16];
    char prefix[40];
    char protocol[16];
    int preference;
    int metric;
    l3_fib_nexthop nexthops[L3_FIB_MAX_NEXTHOPS];
    int n_nexthops;
    char egress_rif[64];
    char installed_state[32];
    char owner_role[32];
    u64 route_generation;
    u64 fib_update_id;
} l3_fib_route;

typedef struct {
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    char mode[16];
    u64 generation;
    u64 fib_update_id;
    l3_fib_route routes[L3_FIB_MAX_ROUTES];
    int n_routes;
} l3_fib_state;

typedef struct {
    l3_fib_state *current;
    l3_fib_state *pre;
    bool rollback_available;
    l3_owner_state state;
    u64 last_tx_id;
    u64 next_tx_id;
} l3_fib_owner;

typedef struct {
    int dynamic_routes;
    int ecmp_routes;
    int dynamic_nexthops;
    int mapped_nexthops;
    int unmapped_nexthops;
    bool owner_applied;
} l3_fib_handle_map_stats;

typedef struct {
    hal_l3_dynamic_fib_plan plan;
    hal_l3_dynamic_fib_route *routes;
    hal_l3_dynamic_fib_nexthop *nexthops;
} l3_fib_live_plan;

#define L3_FIB_OWNER_SLOTS 2
static l3_fib_owner g_l3_fib_owner[L3_FIB_OWNER_SLOTS];

typedef struct {
    bool active;
    bool header_received;
    u64 tx_id;
    u64 generation;
    u64 fib_update_id;
    u64 expected_digest;
    u64 rolling_digest;
    u64 started_ns;
    u64 deadline_ns;
    size_t expected_bytes;
    size_t received_bytes;
    int expected_routes;
    int expected_parts;
    int next_part;
    int vrid;
    char table[HAL_L3_INTENT_TABLE_LEN];
    l3_fib_state *state;
    int *prefix_slots;
} l3_fib_snapshot_stage;

static l3_fib_snapshot_stage g_l3_fib_snapshot[L3_FIB_OWNER_SLOTS];
static pthread_mutex_t g_l3_fib_owner_lock = PTHREAD_MUTEX_INITIALIZER;

static l3_fib_owner *fib_owner_for_vrid(int vrid) {
    if (vrid < 0 || vrid >= L3_FIB_OWNER_SLOTS)
        return NULL;
    return &g_l3_fib_owner[vrid];
}

static const char *owner_state_name(l3_owner_state state) {
    switch (state) {
    case L3_OWNER_IDLE:        return "idle";
    case L3_OWNER_APPLIED:     return "applied";
    case L3_OWNER_ROLLED_BACK: return "rolled-back";
    }
    return "unknown";
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

static int ecmp_member_count(const l3_tx_state *st) {
    int n = 0;

    if (!st)
        return 0;
    for (int i = 0; i < st->n_ecmp; i++)
        n += st->ecmp[i].n_members;
    return n;
}

static int op_count(const l3_tx_state *st) {
    if (!st)
        return 0;
    return st->n_rifs + st->n_arps + st->n_nexthops +
           st->n_ecmp + st->n_routes;
}

static int shadow_emit_count(int count) {
    if (count <= 0)
        return 0;
    return count > L3_SHADOW_EMIT_LIMIT ? L3_SHADOW_EMIT_LIMIT : count;
}

static int shadow_truncated(const l3_tx_state *st) {
    if (!st)
        return 0;
    return st->n_rifs > L3_SHADOW_EMIT_LIMIT ||
           st->n_arps > L3_SHADOW_EMIT_LIMIT ||
           st->n_nexthops > L3_SHADOW_EMIT_LIMIT ||
           st->n_ecmp > L3_SHADOW_EMIT_LIMIT ||
           st->n_routes > L3_SHADOW_EMIT_LIMIT;
}

static int shadow_inventory_xml(const l3_tx_state *st, char *buf,
                                size_t buf_size) {
    size_t off = 0;
    int truncated = shadow_truncated(st);
    int n_rifs = st ? st->n_rifs : 0;
    int n_arps = st ? st->n_arps : 0;
    int n_nexthops = st ? st->n_nexthops : 0;
    int n_ecmp = st ? st->n_ecmp : 0;
    int n_routes = st ? st->n_routes : 0;

    if (!buf || buf_size == 0)
        return -1;
    buf[0] = '\0';
    if (appendf(buf, buf_size, &off,
                "<shadow-readback source=\"switchd-owner\" "
                "mode=\"synthetic\" sdk-write=\"disabled\" "
                "sdk-readback=\"disabled\" complete=\"%s\" "
                "emit-limit=\"%d\">"
                "<traffic-owner router-mac=\"%s\" enabled=\"%s\"/>"
                "<family name=\"rif\" count=\"%d\" emitted=\"%d\"/>"
                "<family name=\"arp\" count=\"%d\" emitted=\"%d\"/>"
                "<family name=\"next-hop\" count=\"%d\" emitted=\"%d\"/>"
                "<family name=\"ecmp\" count=\"%d\" emitted=\"%d\" "
                "members=\"%d\"/>"
                "<family name=\"route\" count=\"%d\" emitted=\"%d\"/>",
                truncated ? "false" : "true", L3_SHADOW_EMIT_LIMIT,
                st && st->has_router_mac ? st->router_mac : "-",
                st && st->has_router_mac ? "true" : "false",
                n_rifs, shadow_emit_count(n_rifs),
                n_arps, shadow_emit_count(n_arps),
                n_nexthops, shadow_emit_count(n_nexthops),
                n_ecmp, shadow_emit_count(n_ecmp),
                ecmp_member_count(st),
                n_routes, shadow_emit_count(n_routes)) != 0)
        return -1;

    for (int i = 0; i < shadow_emit_count(n_rifs); i++) {
        if (st->rifs[i].port[0]) {
            if (appendf(buf, buf_size, &off,
                        "<object family=\"rif\" key=\"%s\" vlan=\"%d\" "
                        "port=\"%s\" address=\"%s\" state=\"shadow\"/>",
                        st->rifs[i].name, st->rifs[i].vlan,
                        st->rifs[i].port, st->rifs[i].address) != 0)
                return -1;
        } else if (appendf(buf, buf_size, &off,
                           "<object family=\"rif\" key=\"%s\" vlan=\"%d\" "
                           "address=\"%s\" state=\"shadow\"/>",
                           st->rifs[i].name, st->rifs[i].vlan,
                           st->rifs[i].address) != 0) {
            return -1;
        }
    }
    for (int i = 0; i < shadow_emit_count(n_arps); i++)
        if (appendf(buf, buf_size, &off,
                    "<object family=\"arp\" key=\"%s/%s\" ip=\"%s\" "
                    "mac=\"%s\" rif=\"%s\" egress-port=\"%s\" "
                    "state=\"shadow\"/>",
                    st->arps[i].rif, st->arps[i].ip, st->arps[i].ip,
                    st->arps[i].mac, st->arps[i].rif,
                    st->arps[i].egress_port[0] ?
                    st->arps[i].egress_port : "-") != 0)
            return -1;
    for (int i = 0; i < shadow_emit_count(n_nexthops); i++)
        if (appendf(buf, buf_size, &off,
                    "<object family=\"next-hop\" key=\"%d\" arp=\"%s\" "
                    "rif=\"%s\" depends-on=\"arp:%s/%s\" "
                    "state=\"shadow\"/>",
                    st->nexthops[i].id, st->nexthops[i].arp,
                    st->nexthops[i].rif, st->nexthops[i].rif,
                    st->nexthops[i].arp) != 0)
            return -1;
    for (int i = 0; i < shadow_emit_count(n_ecmp); i++) {
        if (appendf(buf, buf_size, &off,
                    "<object family=\"ecmp\" key=\"%d\" members=\"",
                    st->ecmp[i].id) != 0)
            return -1;
        for (int j = 0; j < st->ecmp[i].n_members; j++)
            if (appendf(buf, buf_size, &off, "%s%d",
                        j == 0 ? "" : ",", st->ecmp[i].members[j]) != 0)
                return -1;
        if (appendf(buf, buf_size, &off, "\" state=\"shadow\"/>") != 0)
            return -1;
    }
    for (int i = 0; i < shadow_emit_count(n_routes); i++) {
        const char *target_name = "next-hop";
        char target_value[64];

        if (st->routes[i].target_type == HAL_L3_ROUTE_TARGET_ECMP)
            target_name = "ecmp";
        else if (st->routes[i].target_type == HAL_L3_ROUTE_TARGET_RIF)
            target_name = "rif";
        if (st->routes[i].target_type == HAL_L3_ROUTE_TARGET_RIF)
            snprintf(target_value, sizeof(target_value), "%s",
                     st->routes[i].target_name);
        else
            snprintf(target_value, sizeof(target_value), "%d",
                     st->routes[i].target_id);

        if (appendf(buf, buf_size, &off,
                    "<object family=\"route\" key=\"%s\" target=\"%s:%s\" "
                    "state=\"shadow\"/>",
                    st->routes[i].prefix, target_name,
                    target_value) != 0)
            return -1;
    }
    if (truncated &&
        appendf(buf, buf_size, &off,
                "<truncated reason=\"emit-limit\"/>") != 0)
        return -1;
    if (appendf(buf, buf_size, &off, "</shadow-readback>") != 0)
        return -1;
    return 0;
}

static int compare_rifs(const l3_tx_state *expected,
                        const l3_tx_state *actual) {
    int expected_count = expected ? expected->n_rifs : 0;
    int actual_count = actual ? actual->n_rifs : 0;
    int mismatches = expected_count == actual_count ? 0 : 1;
    int n = expected_count < actual_count ? expected_count : actual_count;

    for (int i = 0; i < n; i++) {
        if (expected->rifs[i].vlan != actual->rifs[i].vlan ||
            strcmp(expected->rifs[i].name, actual->rifs[i].name) != 0 ||
            strcmp(expected->rifs[i].port, actual->rifs[i].port) != 0 ||
            strcmp(expected->rifs[i].address, actual->rifs[i].address) != 0)
            mismatches++;
    }
    return mismatches;
}

static int compare_arps(const l3_tx_state *expected,
                        const l3_tx_state *actual) {
    int expected_count = expected ? expected->n_arps : 0;
    int actual_count = actual ? actual->n_arps : 0;
    int mismatches = expected_count == actual_count ? 0 : 1;
    int n = expected_count < actual_count ? expected_count : actual_count;

    for (int i = 0; i < n; i++) {
        if (strcmp(expected->arps[i].ip, actual->arps[i].ip) != 0 ||
            strcmp(expected->arps[i].mac, actual->arps[i].mac) != 0 ||
            strcmp(expected->arps[i].rif, actual->arps[i].rif) != 0 ||
            strcmp(expected->arps[i].egress_port,
                   actual->arps[i].egress_port) != 0)
            mismatches++;
    }
    return mismatches;
}

static int compare_nexthops(const l3_tx_state *expected,
                            const l3_tx_state *actual) {
    int expected_count = expected ? expected->n_nexthops : 0;
    int actual_count = actual ? actual->n_nexthops : 0;
    int mismatches = expected_count == actual_count ? 0 : 1;
    int n = expected_count < actual_count ? expected_count : actual_count;

    for (int i = 0; i < n; i++) {
        if (expected->nexthops[i].id != actual->nexthops[i].id ||
            strcmp(expected->nexthops[i].arp,
                   actual->nexthops[i].arp) != 0 ||
            strcmp(expected->nexthops[i].rif,
                   actual->nexthops[i].rif) != 0)
            mismatches++;
    }
    return mismatches;
}

static int compare_ecmp(const l3_tx_state *expected,
                        const l3_tx_state *actual) {
    int expected_count = expected ? expected->n_ecmp : 0;
    int actual_count = actual ? actual->n_ecmp : 0;
    int mismatches = expected_count == actual_count ? 0 : 1;
    int n = expected_count < actual_count ? expected_count : actual_count;

    for (int i = 0; i < n; i++) {
        if (expected->ecmp[i].id != actual->ecmp[i].id ||
            expected->ecmp[i].n_members != actual->ecmp[i].n_members) {
            mismatches++;
            continue;
        }
        for (int j = 0; j < expected->ecmp[i].n_members; j++) {
            if (expected->ecmp[i].members[j] !=
                actual->ecmp[i].members[j]) {
                mismatches++;
                break;
            }
        }
    }
    return mismatches;
}

static int compare_routes(const l3_tx_state *expected,
                          const l3_tx_state *actual) {
    int expected_count = expected ? expected->n_routes : 0;
    int actual_count = actual ? actual->n_routes : 0;
    int mismatches = expected_count == actual_count ? 0 : 1;
    int n = expected_count < actual_count ? expected_count : actual_count;

    for (int i = 0; i < n; i++) {
        if (expected->routes[i].target_type != actual->routes[i].target_type ||
            expected->routes[i].target_id != actual->routes[i].target_id ||
            strcmp(expected->routes[i].target_name,
                   actual->routes[i].target_name) != 0 ||
            strcmp(expected->routes[i].prefix,
                   actual->routes[i].prefix) != 0)
            mismatches++;
    }
    return mismatches;
}

static int compare_traffic_owner(const l3_tx_state *expected,
                                 const l3_tx_state *actual) {
    bool expected_has_router_mac = expected && expected->has_router_mac;
    bool actual_has_router_mac = actual && actual->has_router_mac;

    if (expected_has_router_mac != actual_has_router_mac)
        return 1;
    if (expected_has_router_mac &&
        strcmp(expected->router_mac, actual->router_mac) != 0)
        return 1;
    return 0;
}

static int shadow_verify_xml(const l3_tx_state *expected,
                             const l3_tx_state *actual,
                             char *buf, size_t buf_size) {
    size_t off = 0;
    int rif_mismatches;
    int arp_mismatches;
    int nexthop_mismatches;
    int ecmp_mismatches;
    int route_mismatches;
    int traffic_mismatches;
    int total_mismatches;
    int compared;

    if (!buf || buf_size == 0)
        return -1;
    buf[0] = '\0';

    rif_mismatches = compare_rifs(expected, actual);
    arp_mismatches = compare_arps(expected, actual);
    nexthop_mismatches = compare_nexthops(expected, actual);
    ecmp_mismatches = compare_ecmp(expected, actual);
    route_mismatches = compare_routes(expected, actual);
    traffic_mismatches = compare_traffic_owner(expected, actual);
    total_mismatches = rif_mismatches + arp_mismatches +
        nexthop_mismatches + ecmp_mismatches + route_mismatches +
        traffic_mismatches;
    compared = op_count(expected) +
        (expected && expected->has_router_mac ? 1 : 0);

    return appendf(buf, buf_size, &off,
                   "<shadow-verify source=\"switchd-owner\" "
                   "mode=\"synthetic\" sdk-write=\"disabled\" "
                   "sdk-readback=\"disabled\" status=\"%s\" "
                   "compared=\"%d\" mismatches=\"%d\">"
                   "<family name=\"rif\" expected=\"%d\" actual=\"%d\" "
                   "mismatches=\"%d\"/>"
                   "<family name=\"arp\" expected=\"%d\" actual=\"%d\" "
                   "mismatches=\"%d\"/>"
                   "<family name=\"next-hop\" expected=\"%d\" "
                   "actual=\"%d\" mismatches=\"%d\"/>"
                   "<family name=\"ecmp\" expected=\"%d\" actual=\"%d\" "
                   "members-expected=\"%d\" members-actual=\"%d\" "
                   "mismatches=\"%d\"/>"
                   "<family name=\"route\" expected=\"%d\" actual=\"%d\" "
                   "mismatches=\"%d\"/>"
                   "<family name=\"traffic-owner\" expected=\"%d\" "
                   "actual=\"%d\" mismatches=\"%d\"/>"
                   "</shadow-verify>",
                   total_mismatches == 0 ? "ok" : "mismatch",
                   compared, total_mismatches,
                   expected ? expected->n_rifs : 0,
                   actual ? actual->n_rifs : 0, rif_mismatches,
                   expected ? expected->n_arps : 0,
                   actual ? actual->n_arps : 0, arp_mismatches,
                   expected ? expected->n_nexthops : 0,
                   actual ? actual->n_nexthops : 0,
                   nexthop_mismatches,
                   expected ? expected->n_ecmp : 0,
                   actual ? actual->n_ecmp : 0,
                   ecmp_member_count(expected), ecmp_member_count(actual),
                   ecmp_mismatches,
                   expected ? expected->n_routes : 0,
                   actual ? actual->n_routes : 0,
                   route_mismatches,
                   expected && expected->has_router_mac ? 1 : 0,
                   actual && actual->has_router_mac ? 1 : 0,
                   traffic_mismatches);
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

static const char *kv_value(const char *text, const char *key) {
    size_t key_len;
    const char *p = text;

    if (!text || !key)
        return NULL;
    key_len = strlen(key);
    while ((p = strstr(p, key))) {
        if ((p == text || isspace((unsigned char)p[-1])) &&
            p[key_len] == '=')
            return p + key_len + 1;
        p += key_len;
    }
    return NULL;
}

static bool kv_str(const char *text, const char *key,
                   char *out, size_t out_size) {
    const char *p = kv_value(text, key);
    size_t n = 0;

    if (!p || !out || out_size == 0)
        return false;
    while (p[n] && !isspace((unsigned char)p[n]))
        n++;
    if (n == 0 || n >= out_size)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool kv_int(const char *text, const char *key, int min, int max,
                   int *out) {
    char buf[32];
    char *end = NULL;
    long value;

    if (!kv_str(text, key, buf, sizeof(buf)) || !out)
        return false;
    value = strtol(buf, &end, 10);
    if (!end || *end != '\0' || value < min || value > max)
        return false;
    *out = (int)value;
    return true;
}

static bool valid_name(const char *s) {
    if (!s || !s[0] || strlen(s) >= 32)
        return false;
    for (const char *p = s; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' &&
            *p != '.')
            return false;
    }
    return true;
}

static bool valid_ifname(const char *s) {
    if (!s || !s[0] || strlen(s) >= HAL_L3_INTENT_IFNAME_LEN)
        return false;
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p) || iscntrl((unsigned char)*p))
            return false;
    }
    return true;
}

static bool valid_ipv4(const char *s) {
    struct in_addr addr;
    return s && inet_pton(AF_INET, s, &addr) == 1;
}

static bool parse_ipv4_u32(const char *s, u32 *out) {
    struct in_addr addr;

    if (!s || inet_pton(AF_INET, s, &addr) != 1)
        return false;
    if (out)
        *out = ntohl(addr.s_addr);
    return true;
}

static bool parse_ipv4_cidr_parts(const char *s, u32 *addr, int *prefix) {
    char ip[40];
    int prefix_len = -1;
    char tail;
    u32 value;

    if (!s || sscanf(s, "%39[^/]/%d%c", ip, &prefix_len, &tail) != 2 ||
        prefix_len < 0 || prefix_len > 32 || !parse_ipv4_u32(ip, &value))
        return false;
    if (addr)
        *addr = value;
    if (prefix)
        *prefix = prefix_len;
    return true;
}

static u32 ipv4_prefix_mask(int prefix) {
    return prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
}

static bool valid_ipv4_cidr(const char *s) {
    return parse_ipv4_cidr_parts(s, NULL, NULL);
}

static bool valid_ipv4_network_cidr(const char *s) {
    u32 addr;
    int prefix;

    if (!parse_ipv4_cidr_parts(s, &addr, &prefix))
        return false;
    return (addr & ~ipv4_prefix_mask(prefix)) == 0;
}

static bool ipv4_v1_unicast_cidr(const char *s, bool allow_default) {
    u32 addr;
    int prefix;

    if (!parse_ipv4_cidr_parts(s, &addr, &prefix))
        return false;
    if (allow_default && prefix == 0)
        return true;
    return (addr >> 28) < 14;
}

static bool ipv4_cidr_local_address_is_reserved(const char *s) {
    u32 addr;
    u32 mask;
    u32 host;
    int prefix;

    if (!parse_ipv4_cidr_parts(s, &addr, &prefix))
        return true;
    if (prefix >= 31)
        return false;
    mask = ipv4_prefix_mask(prefix);
    host = addr & ~mask;
    return host == 0 || host == ~mask;
}

static bool ipv4_in_cidr(const char *ip, const char *cidr) {
    u32 value;
    u32 cidr_addr;
    u32 mask;
    int prefix;

    if (!parse_ipv4_u32(ip, &value) ||
        !parse_ipv4_cidr_parts(cidr, &cidr_addr, &prefix))
        return false;
    mask = ipv4_prefix_mask(prefix);
    return (value & mask) == (cidr_addr & mask);
}

static bool ipv4_equals_cidr_address(const char *ip, const char *cidr) {
    u32 value;
    u32 cidr_addr;

    if (!parse_ipv4_u32(ip, &value) ||
        !parse_ipv4_cidr_parts(cidr, &cidr_addr, NULL))
        return false;
    return value == cidr_addr;
}

static bool ipv4_cidr_overlap(const char *a, const char *b) {
    u32 addr_a;
    u32 addr_b;
    u32 mask;
    int prefix_a;
    int prefix_b;
    int common_prefix;

    if (!parse_ipv4_cidr_parts(a, &addr_a, &prefix_a) ||
        !parse_ipv4_cidr_parts(b, &addr_b, &prefix_b))
        return false;
    common_prefix = prefix_a < prefix_b ? prefix_a : prefix_b;
    mask = ipv4_prefix_mask(common_prefix);
    return (addr_a & mask) == (addr_b & mask);
}

static bool valid_mac(const char *s) {
    unsigned int b[6];
    char tail;

    return s && sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c",
                       &b[0], &b[1], &b[2], &b[3], &b[4], &b[5],
                       &tail) == 6 &&
           b[0] <= 255 && b[1] <= 255 && b[2] <= 255 &&
           b[3] <= 255 && b[4] <= 255 && b[5] <= 255;
}

static bool fib_valid_protocol(const char *protocol) {
    return protocol &&
           (strcmp(protocol, "connected") == 0 ||
            strcmp(protocol, "static") == 0 ||
            strcmp(protocol, "ospf") == 0 ||
            strcmp(protocol, "bgp") == 0);
}

static bool fib_xml_safe_token(const char *s) {
    if (!s || !s[0])
        return false;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;

        if (isspace(c) || iscntrl(c) || c == '<' || c == '>' ||
            c == '"' || c == '\'' || c == '&')
            return false;
    }
    return true;
}

static bool fib_csv_has_empty_member(const char *s) {
    size_t len;

    if (!s || !s[0])
        return true;
    len = strlen(s);
    if (s[0] == ',' || s[len - 1] == ',')
        return true;
    for (const char *p = s; *p; p++)
        if (*p == ',' && p[1] == ',')
            return true;
    return false;
}

static bool fib_kv_u64(const char *text, const char *key, u64 *out) {
    char buf[32];
    char *end = NULL;
    unsigned long long value;

    if (!kv_str(text, key, buf, sizeof(buf)) || !out)
        return false;
    value = strtoull(buf, &end, 10);
    if (!end || *end != '\0')
        return false;
    *out = (u64)value;
    return true;
}

static int fib_fail(char *resp, size_t resp_size, int line_no,
                    const char *detail) {
    snprintf(resp, resp_size,
             "<fib-batch status=\"invalid\" line=\"%d\" "
             "error=\"%s\" owner=\"rpd\" table=\"inet.0\" "
             "hardware-apply=\"disabled\"/>",
             line_no, detail ? detail : "invalid");
    return -1;
}

static int fib_find_route(const l3_fib_state *st, const char *prefix) {
    if (!st || !prefix)
        return -1;
    for (int i = 0; i < st->n_routes; i++)
        if (strcmp(st->routes[i].prefix, prefix) == 0)
            return i;
    return -1;
}

static int fib_ecmp_route_count(const l3_fib_state *st) {
    int n = 0;

    if (!st)
        return 0;
    for (int i = 0; i < st->n_routes; i++)
        if (st->routes[i].n_nexthops > 1)
            n++;
    return n;
}

static int fib_nexthop_count(const l3_fib_state *st) {
    int n = 0;

    if (!st)
        return 0;
    for (int i = 0; i < st->n_routes; i++)
        n += st->routes[i].n_nexthops;
    return n;
}

static int fib_shadow_emit_count(int count) {
    if (count <= 0)
        return 0;
    return count > L3_FIB_SHADOW_EMIT_LIMIT ?
        L3_FIB_SHADOW_EMIT_LIMIT : count;
}

static int fib_parse_nexthops(l3_fib_route *route, const char *value,
                              const char *default_rif, int line_no,
                              char *resp, size_t resp_size) {
    char list[L3_FIB_NEXTHOPS_TEXT_MAX];
    char *save = NULL;
    char *tok;

    if (!route || !value || !value[0])
        return fib_fail(resp, resp_size, line_no, "invalid fib nexthop list");
    if (strcmp(value, "-") == 0)
        return 0;
    if (strlen(value) >= sizeof(list))
        return fib_fail(resp, resp_size, line_no, "fib nexthop list too long");
    snprintf(list, sizeof(list), "%s", value);
    if (fib_csv_has_empty_member(list))
        return fib_fail(resp, resp_size, line_no, "empty fib nexthop");
    tok = strtok_r(list, ",", &save);
    while (tok) {
        char *rif;
        char *nh = trim(tok);
        const char *egress_rif = default_rif && default_rif[0] ?
            default_rif : "-";

        if (route->n_nexthops >= L3_FIB_MAX_NEXTHOPS)
            return fib_fail(resp, resp_size, line_no,
                            "too many fib nexthops");
        if (!nh[0])
            return fib_fail(resp, resp_size, line_no, "empty fib nexthop");
        rif = strchr(nh, '@');
        if (rif) {
            *rif++ = '\0';
            egress_rif = rif;
        }
        if (!valid_ipv4(nh) ||
            !egress_rif || !egress_rif[0] ||
            !fib_xml_safe_token(egress_rif))
            return fib_fail(resp, resp_size, line_no,
                            "invalid fib nexthop");
        for (int i = 0; i < route->n_nexthops; i++)
            if (strcmp(route->nexthops[i].address, nh) == 0 &&
                strcmp(route->nexthops[i].egress_rif, egress_rif) == 0)
                return fib_fail(resp, resp_size, line_no,
                                "duplicate fib nexthop");
        snprintf(route->nexthops[route->n_nexthops].address,
                 sizeof(route->nexthops[route->n_nexthops].address),
                 "%s", nh);
        snprintf(route->nexthops[route->n_nexthops].egress_rif,
                 sizeof(route->nexthops[route->n_nexthops].egress_rif),
                 "%s", egress_rif);
        route->n_nexthops++;
        tok = strtok_r(NULL, ",", &save);
    }
    return 0;
}

static int fib_parse_batch_header(l3_fib_state *st, const char *line,
                                  int line_no, char *resp,
                                  size_t resp_size) {
    char table[HAL_L3_INTENT_TABLE_LEN];
    char mode[16] = "full-state";
    int vrid = 0;

    if (!kv_str(line, "table", table, sizeof(table)) ||
        hal_l3_persistent_owner_lookup_table(table, &vrid) != 0)
        return fib_fail(resp, resp_size, line_no,
                        "unsupported fib table");
    if (kv_value(line, "mode") &&
        (!kv_str(line, "mode", mode, sizeof(mode)) ||
         (strcmp(mode, "full-state") != 0 &&
          strcmp(mode, "delta") != 0)))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib batch mode");
    if (!fib_kv_u64(line, "generation", &st->generation))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib generation");
    if (!fib_kv_u64(line, "fib-update-id", &st->fib_update_id))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib update id");
    snprintf(st->table, sizeof(st->table), "%s", table);
    st->vrid = vrid;
    snprintf(st->mode, sizeof(st->mode), "%s", mode);
    return 0;
}

static const char *fib_default_owner_role(const char *protocol);
static bool fib_valid_owner_role(const char *role);

static int fib_parse_route(l3_fib_state *st, const char *line, int line_no,
                           bool reject_duplicate,
                           char *resp, size_t resp_size) {
    l3_fib_route *route;
    char prefix[40];
    char protocol[16];
    char egress_rif[64] = "-";
    char installed_state[32] = "pending-fib";
    char owner_role[32] = "";
    char nexthops[L3_FIB_NEXTHOPS_TEXT_MAX] = "-";
    char op[16] = "replace";
    int preference;
    int metric;

    if (st->n_routes >= L3_FIB_MAX_ROUTES)
        return fib_fail(resp, resp_size, line_no, "too many fib routes");
    if (kv_value(line, "op") &&
        (!kv_str(line, "op", op, sizeof(op)) ||
         (strcmp(op, "replace") != 0 && strcmp(op, "delete") != 0)))
        return fib_fail(resp, resp_size, line_no, "invalid fib route op");
    if (!kv_str(line, "prefix", prefix, sizeof(prefix)) ||
        !valid_ipv4_network_cidr(prefix) ||
        !ipv4_v1_unicast_cidr(prefix, true))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib prefix: prefix must be a network address and IPv4 unicast");
    if (reject_duplicate && fib_find_route(st, prefix) >= 0)
        return fib_fail(resp, resp_size, line_no, "duplicate fib prefix");
    if (strcmp(op, "delete") == 0) {
        if (strcmp(st->mode, "delta") != 0)
            return fib_fail(resp, resp_size, line_no,
                            "delete op requires delta fib batch");
        route = &st->routes[st->n_routes];
        memset(route, 0, sizeof(*route));
        snprintf(route->op, sizeof(route->op), "%s", op);
        snprintf(route->prefix, sizeof(route->prefix), "%s", prefix);
        st->n_routes++;
        return 0;
    }
    if (!kv_str(line, "protocol", protocol, sizeof(protocol)) ||
        !fib_valid_protocol(protocol))
        return fib_fail(resp, resp_size, line_no, "invalid fib protocol");
    if (!kv_int(line, "preference", 0, 255, &preference))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib preference");
    if (!kv_int(line, "metric", 0, 2147483647, &metric))
        return fib_fail(resp, resp_size, line_no, "invalid fib metric");
    if (kv_value(line, "egress-rif") &&
        (!kv_str(line, "egress-rif", egress_rif, sizeof(egress_rif)) ||
         !fib_xml_safe_token(egress_rif)))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib egress rif");
    if (kv_value(line, "installed-state") &&
        (!kv_str(line, "installed-state", installed_state,
                 sizeof(installed_state)) || !valid_name(installed_state)))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib installed state");
    if (kv_value(line, "owner-role") &&
        (!kv_str(line, "owner-role", owner_role, sizeof(owner_role)) ||
         !fib_valid_owner_role(owner_role)))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib owner role");
    if (kv_value(line, "nexthops") &&
        !kv_str(line, "nexthops", nexthops, sizeof(nexthops)))
        return fib_fail(resp, resp_size, line_no,
                        "invalid fib nexthops");

    route = &st->routes[st->n_routes];
    memset(route, 0, sizeof(*route));
    snprintf(route->op, sizeof(route->op), "%s", op);
    snprintf(route->prefix, sizeof(route->prefix), "%s", prefix);
    snprintf(route->protocol, sizeof(route->protocol), "%s", protocol);
    route->preference = preference;
    route->metric = metric;
    snprintf(route->egress_rif, sizeof(route->egress_rif), "%s", egress_rif);
    snprintf(route->installed_state, sizeof(route->installed_state), "%s",
             installed_state);
    snprintf(route->owner_role, sizeof(route->owner_role), "%s",
             owner_role[0] ? owner_role : fib_default_owner_role(protocol));
    if (kv_value(line, "route-generation") &&
        !fib_kv_u64(line, "route-generation", &route->route_generation))
        return fib_fail(resp, resp_size, line_no,
                        "invalid route generation");
    if (kv_value(line, "fib-update-id") &&
        !fib_kv_u64(line, "fib-update-id", &route->fib_update_id))
        return fib_fail(resp, resp_size, line_no,
                        "invalid route fib update id");
    if (fib_parse_nexthops(route, nexthops, route->egress_rif,
                           line_no, resp, resp_size) != 0)
        return -1;
    if (strcmp(protocol, "connected") != 0 && route->n_nexthops == 0)
        return fib_fail(resp, resp_size, line_no,
                        "fib route requires nexthop");
    st->n_routes++;
    return 0;
}

static int fib_batch_parse(const char *text, l3_fib_state *st,
                           char *resp, size_t resp_size) {
    char *copy;
    char *save = NULL;
    char *line;
    int line_no = 0;
    bool have_header = false;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!text || !text[0])
        return fib_fail(resp, resp_size, 0, "empty fib batch");
    if (!st)
        return fib_fail(resp, resp_size, 0, "missing fib batch state");
    memset(st, 0, sizeof(*st));
    snprintf(st->table, sizeof(st->table), "inet.0");
    copy = strdup(text);
    if (!copy)
        return fib_fail(resp, resp_size, 0, "out of memory");

    line = strtok_r(copy, "\n", &save);
    while (line) {
        char *t = trim(line);
        int rc = 0;

        line_no++;
        if (!t[0] || t[0] == '#') {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }
        if (strncmp(t, "fib-batch ", 10) == 0) {
            if (have_header) {
                rc = fib_fail(resp, resp_size, line_no,
                              "duplicate fib batch header");
            } else {
                rc = fib_parse_batch_header(st, t, line_no,
                                            resp, resp_size);
                have_header = rc == 0;
            }
        } else if (strncmp(t, "fib-route ", 10) == 0) {
            if (!have_header)
                rc = fib_fail(resp, resp_size, line_no,
                              "missing fib batch header");
            else
                rc = fib_parse_route(st, t, line_no, true,
                                     resp, resp_size);
        } else {
            rc = fib_fail(resp, resp_size, line_no,
                          "unknown fib batch op");
        }
        if (rc != 0) {
            free(copy);
            return -1;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    if (!have_header)
        return fib_fail(resp, resp_size, 0, "missing fib batch header");
    return 0;
}

static int fib_shadow_inventory_xml(const l3_fib_state *st, char *buf,
                                    size_t buf_size) {
    size_t off = 0;
    int emit;
    int n_routes = st ? st->n_routes : 0;
    bool truncated;

    if (!buf || buf_size == 0)
        return -1;
    buf[0] = '\0';
    emit = fib_shadow_emit_count(n_routes);
    truncated = n_routes > emit;
    if (appendf(buf, buf_size, &off,
                "<fib-shadow-readback source=\"switchd-rpd-fib-owner\" "
                "mode=\"synthetic\" table=\"%s\" generation=\"%llu\" "
                "fib-update-id=\"%llu\" sdk-write=\"disabled\" "
                "sdk-readback=\"disabled\" complete=\"%s\" "
                "routes=\"%d\" emitted=\"%d\" ecmp-routes=\"%d\" "
                "nexthops=\"%d\">",
                st && st->table[0] ? st->table : "inet.0",
                (unsigned long long)(st ? st->generation : 0),
                (unsigned long long)(st ? st->fib_update_id : 0),
                truncated ? "false" : "true",
                n_routes, emit, fib_ecmp_route_count(st),
                fib_nexthop_count(st)) != 0)
        return -1;
    for (int i = 0; i < emit; i++) {
        const l3_fib_route *route = &st->routes[i];

        if (appendf(buf, buf_size, &off,
                    "<route prefix=\"%s\" protocol=\"%s\" "
                    "preference=\"%d\" metric=\"%d\" egress-rif=\"%s\" "
                    "installed-state=\"%s\" owner-role=\"%s\" "
                    "route-generation=\"%llu\" "
                    "fib-update-id=\"%llu\" nexthops=\"",
                    route->prefix, route->protocol, route->preference,
                    route->metric, route->egress_rif,
                    route->installed_state, route->owner_role,
                    (unsigned long long)route->route_generation,
                    (unsigned long long)route->fib_update_id) != 0)
            return -1;
        if (route->n_nexthops == 0) {
            if (appendf(buf, buf_size, &off, "-") != 0)
                return -1;
        }
        for (int j = 0; j < route->n_nexthops; j++) {
            const l3_fib_nexthop *nh = &route->nexthops[j];

            if (appendf(buf, buf_size, &off, "%s%s@%s",
                        j == 0 ? "" : ",", nh->address,
                        nh->egress_rif) != 0)
                return -1;
        }
        if (appendf(buf, buf_size, &off, "\"/>") != 0)
            return -1;
    }
    if (truncated &&
        appendf(buf, buf_size, &off,
                "<truncated reason=\"emit-limit\"/>") != 0)
        return -1;
    return appendf(buf, buf_size, &off, "</fib-shadow-readback>");
}

static bool fib_route_equal(const l3_fib_route *a, const l3_fib_route *b) {
    if (!a || !b)
        return false;
    if (strcmp(a->prefix, b->prefix) != 0 ||
        strcmp(a->protocol, b->protocol) != 0 ||
        a->preference != b->preference ||
        a->metric != b->metric ||
        strcmp(a->egress_rif, b->egress_rif) != 0 ||
        strcmp(a->installed_state, b->installed_state) != 0 ||
        strcmp(a->owner_role, b->owner_role) != 0 ||
        a->route_generation != b->route_generation ||
        a->fib_update_id != b->fib_update_id ||
        a->n_nexthops != b->n_nexthops)
        return false;
    for (int i = 0; i < a->n_nexthops; i++)
        if (strcmp(a->nexthops[i].address, b->nexthops[i].address) != 0 ||
            strcmp(a->nexthops[i].egress_rif,
                   b->nexthops[i].egress_rif) != 0)
            return false;
    return true;
}

static int fib_compare(const l3_fib_state *expected,
                       const l3_fib_state *actual) {
    int mismatches = 0;

    if (!expected && !actual)
        return 0;
    if (!expected || !actual)
        return 1;
    if (strcmp(expected->table, actual->table) != 0 ||
        expected->generation != actual->generation ||
        expected->fib_update_id != actual->fib_update_id ||
        expected->n_routes != actual->n_routes)
        mismatches++;
    for (int i = 0; i < expected->n_routes && i < actual->n_routes; i++)
        if (!fib_route_equal(&expected->routes[i], &actual->routes[i]))
            mismatches++;
    return mismatches;
}

static void fib_state_remove_route(l3_fib_state *st, int idx) {
    if (!st || idx < 0 || idx >= st->n_routes)
        return;
    for (int i = idx; i + 1 < st->n_routes; i++)
        st->routes[i] = st->routes[i + 1];
    memset(&st->routes[st->n_routes - 1], 0,
           sizeof(st->routes[st->n_routes - 1]));
    st->n_routes--;
}

static int fib_state_apply_delta(const l3_fib_state *base,
                                 const l3_fib_state *delta,
                                 l3_fib_state *out,
                                 char *resp, size_t resp_size) {
    if (!base || !delta || !out)
        return fib_fail(resp, resp_size, 0, "invalid fib delta context");
    *out = *base;
    snprintf(out->table, sizeof(out->table), "%s",
             delta->table[0] ? delta->table : "inet.0");
    snprintf(out->mode, sizeof(out->mode), "full-state");
    out->generation = delta->generation;
    out->fib_update_id = delta->fib_update_id;
    for (int i = 0; i < delta->n_routes; i++) {
        const l3_fib_route *route = &delta->routes[i];
        int idx = fib_find_route(out, route->prefix);

        if (strcmp(route->op, "delete") == 0) {
            if (idx >= 0)
                fib_state_remove_route(out, idx);
            continue;
        }
        if (idx >= 0) {
            out->routes[idx] = *route;
            snprintf(out->routes[idx].op, sizeof(out->routes[idx].op),
                     "replace");
            continue;
        }
        if (out->n_routes >= L3_FIB_MAX_ROUTES)
            return fib_fail(resp, resp_size, 0,
                            "too many fib routes after delta");
        out->routes[out->n_routes] = *route;
        snprintf(out->routes[out->n_routes].op,
                 sizeof(out->routes[out->n_routes].op), "replace");
        out->n_routes++;
    }
    return 0;
}

static int fib_shadow_verify_xml(const l3_fib_state *expected,
                                 const l3_fib_state *actual,
                                 char *buf, size_t buf_size) {
    int mismatches = fib_compare(expected, actual);
    int n;

    n = snprintf(buf, buf_size,
                 "<fib-shadow-verify source=\"switchd-rpd-fib-owner\" "
                 "mode=\"synthetic\" status=\"%s\" compared=\"%d\" "
                 "mismatches=\"%d\" sdk-write=\"disabled\" "
                 "sdk-readback=\"disabled\"/>",
                 mismatches ? "mismatch" : "ok",
                 expected ? expected->n_routes : 0,
                 mismatches);
    return n < 0 || (size_t)n >= buf_size ? -1 : 0;
}

static bool fib_live_gate_open(void) {
    const char *v = getenv("NETLAB_ENABLE_RPD_FIB_LIVE_APPLY");

    return v && (strcmp(v, "1") == 0 ||
                 strcmp(v, "true") == 0 ||
                 strcmp(v, "TRUE") == 0 ||
                 strcmp(v, "yes") == 0 ||
                 strcmp(v, "YES") == 0);
}

static void fib_missing_add(char *buf, size_t size, const char *name) {
    if (!buf || size == 0 || !name || !name[0])
        return;
    if (buf[0] && strlen(buf) + strlen(name) + 1 < size)
        strncat(buf, ",", size - strlen(buf) - 1);
    if (strlen(buf) + strlen(name) < size)
        strncat(buf, name, size - strlen(buf) - 1);
}

static int fib_protocol_count(const l3_fib_state *st, const char *protocol) {
    int count = 0;

    if (!st || !protocol)
        return 0;
    for (int i = 0; i < st->n_routes; i++)
        if (strcmp(st->routes[i].protocol, protocol) == 0)
            count++;
    return count;
}

static int fib_ifindex_rif_count(const l3_fib_state *st) {
    int count = 0;

    if (!st)
        return 0;
    for (int i = 0; i < st->n_routes; i++) {
        if (strncmp(st->routes[i].egress_rif, "ifindex", 7) == 0) {
            count++;
            continue;
        }
        for (int j = 0; j < st->routes[i].n_nexthops; j++) {
            if (strncmp(st->routes[i].nexthops[j].egress_rif,
                        "ifindex", 7) == 0) {
                count++;
                break;
            }
        }
    }
    return count;
}

static const char *fib_default_owner_role(const char *protocol) {
    if (protocol &&
        (strcmp(protocol, "connected") == 0 ||
         strcmp(protocol, "static") == 0))
        return "persistent-owner";
    return "dynamic-fib";
}

static bool fib_valid_owner_role(const char *role) {
    return role &&
        (strcmp(role, "persistent-owner") == 0 ||
         strcmp(role, "dynamic-fib") == 0);
}

static bool fib_route_owner_role_ok(const l3_fib_route *route) {
    if (!route)
        return false;
    if (strcmp(route->protocol, "connected") == 0 ||
        strcmp(route->protocol, "static") == 0)
        return strcmp(route->owner_role, "persistent-owner") == 0;
    if (strcmp(route->protocol, "ospf") == 0 ||
        strcmp(route->protocol, "bgp") == 0)
        return strcmp(route->owner_role, "dynamic-fib") == 0;
    return false;
}

static int fib_owner_role_mismatch_count(const l3_fib_state *st) {
    int count = 0;

    if (!st)
        return 0;
    for (int i = 0; i < st->n_routes; i++)
        if (!fib_route_owner_role_ok(&st->routes[i]))
            count++;
    return count;
}

static bool fib_route_is_dynamic_owner(const l3_fib_route *route) {
    return route && strcmp(route->owner_role, "dynamic-fib") == 0;
}

static void fib_handle_map_collect(const l3_fib_state *st,
                                   l3_fib_handle_map_stats *stats) {
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (!st)
        return;
    for (int i = 0; i < st->n_routes; i++) {
        const l3_fib_route *route = &st->routes[i];

        if (!fib_route_is_dynamic_owner(route))
            continue;
        stats->dynamic_routes++;
        if (route->n_nexthops > 1)
            stats->ecmp_routes++;
        for (int j = 0; j < route->n_nexthops; j++) {
            hal_l3_persistent_next_hop_ref ref;
            const l3_fib_nexthop *nh = &route->nexthops[j];

            stats->dynamic_nexthops++;
            if (hal_l3_persistent_owner_lookup_next_hop(
                    st->table, nh->address, nh->egress_rif, &ref) == 0) {
                if (ref.owner_applied)
                    stats->owner_applied = true;
                if (ref.found)
                    stats->mapped_nexthops++;
                else
                    stats->unmapped_nexthops++;
            } else {
                stats->unmapped_nexthops++;
            }
        }
    }
}

static const char *fib_handle_map_status(
        const l3_fib_handle_map_stats *stats) {
    if (!stats || stats->dynamic_routes == 0)
        return "empty";
    if (stats->unmapped_nexthops == 0)
        return "ready";
    if (stats->mapped_nexthops > 0)
        return "partial";
    return "missing";
}

static int fib_handle_map_xml(const l3_fib_state *st, char *buf,
                              size_t buf_size) {
    l3_fib_handle_map_stats stats;
    size_t off = 0;
    int emitted = 0;
    bool truncated = false;

    if (!buf || buf_size == 0)
        return -1;
    buf[0] = '\0';
    fib_handle_map_collect(st, &stats);
    if (appendf(buf, buf_size, &off,
                "<fib-handle-map source=\"switchd-rpd-fib-owner\" "
                "owner=\"persistent\" status=\"%s\" "
                "owner-applied=\"%s\" sdk-write=\"disabled\" "
                "dynamic-routes=\"%d\" ecmp-routes=\"%d\" "
                "dynamic-nexthops=\"%d\" mapped-nexthops=\"%d\" "
                "unmapped-nexthops=\"%d\">",
                fib_handle_map_status(&stats),
                stats.owner_applied ? "true" : "false",
                stats.dynamic_routes, stats.ecmp_routes,
                stats.dynamic_nexthops, stats.mapped_nexthops,
                stats.unmapped_nexthops) != 0)
        return -1;
    if (st) {
        for (int i = 0; i < st->n_routes; i++) {
            const l3_fib_route *route = &st->routes[i];

            if (!fib_route_is_dynamic_owner(route))
                continue;
            for (int j = 0; j < route->n_nexthops; j++) {
                hal_l3_persistent_next_hop_ref ref;
                const l3_fib_nexthop *nh = &route->nexthops[j];
                const char *nh_status = "unmapped";

                if (emitted >= L3_FIB_SHADOW_EMIT_LIMIT) {
                    truncated = true;
                    continue;
                }
                memset(&ref, 0, sizeof(ref));
                ref.next_hop_id = -1;
                ref.rif_index = -1;
                (void)hal_l3_persistent_owner_lookup_next_hop(
                    st->table, nh->address, nh->egress_rif, &ref);
                if (!ref.owner_applied)
                    nh_status = "owner-empty";
                else if (ref.found)
                    nh_status = "mapped";
                if (appendf(buf, buf_size, &off,
                            "<nexthop prefix=\"%s\" ip=\"%s\" "
                            "rif=\"%s\" status=\"%s\" "
                            "persistent-next-hop-id=\"%d\" "
                            "persistent-rif-index=\"%d\" vlan=\"%d\" "
                            "interface-address=\"%s\"/>",
                            route->prefix, nh->address, nh->egress_rif,
                            nh_status, ref.next_hop_id, ref.rif_index,
                            ref.vlan,
                            ref.interface_addr[0] ?
                                ref.interface_addr : "-") != 0)
                    return -1;
                emitted++;
            }
        }
    }
    if (truncated &&
        appendf(buf, buf_size, &off,
                "<truncated reason=\"emit-limit\"/>") != 0)
        return -1;
    return appendf(buf, buf_size, &off, "</fib-handle-map>");
}

static int fib_live_eligibility_xml(const l3_fib_state *st, char *buf,
                                    size_t buf_size) {
    char missing[256] = "";
    const char *reason;
    l3_fib_handle_map_stats handle_map;
    bool gate_open = fib_live_gate_open();
    bool ready;
    int connected = fib_protocol_count(st, "connected");
    int statics = fib_protocol_count(st, "static");
    int ospf = fib_protocol_count(st, "ospf");
    int bgp = fib_protocol_count(st, "bgp");
    int owner_routes = connected + statics;
    int dynamic_routes = ospf + bgp;
    int ifindex_rifs = fib_ifindex_rif_count(st);
    int owner_role_mismatches = fib_owner_role_mismatch_count(st);
    int nexthops = fib_nexthop_count(st);
    int n;

    fib_handle_map_collect(st, &handle_map);
    if (!gate_open)
        fib_missing_add(missing, sizeof(missing), "operator-gate");
    if (owner_role_mismatches > 0)
        fib_missing_add(missing, sizeof(missing), "persistent-owner-merge");
    if (handle_map.unmapped_nexthops > 0)
        fib_missing_add(missing, sizeof(missing), "next-hop-handle-map");
    if (ifindex_rifs > 0)
        fib_missing_add(missing, sizeof(missing), "stable-rif-map");
    if (!missing[0])
        snprintf(missing, sizeof(missing), "none");
    ready = gate_open && owner_role_mismatches == 0 &&
        handle_map.unmapped_nexthops == 0 && ifindex_rifs == 0;

    if (!gate_open)
        reason = "NETLAB_ENABLE_RPD_FIB_LIVE_APPLY is not set";
    else if (owner_role_mismatches > 0)
        reason = "batch route owner roles do not separate persistent and dynamic FIB owners";
    else if (handle_map.unmapped_nexthops > 0 && !handle_map.owner_applied)
        reason = "persistent owner next-hop handles are not installed";
    else if (handle_map.unmapped_nexthops > 0)
        reason = "some dynamic nexthops are not mapped to persistent owner handles";
    else if (ifindex_rifs > 0)
        reason = "dynamic route nexthops still use transient ifindex RIF names";
    else
        reason = "switchd rpd FIB live apply prerequisites are satisfied";

    n = snprintf(buf, buf_size,
                 "<live-eligibility source=\"switchd-rpd-fib-owner\" "
                 "family=\"ipv4-unicast\" table=\"inet.0\" "
                 "gate-env=\"NETLAB_ENABLE_RPD_FIB_LIVE_APPLY\" "
                 "gate=\"%s\" status=\"%s\" live-ready=\"%s\" "
                 "hardware-apply=\"%s\" sdk-write=\"available\" "
                 "sdk-readback=\"available\" routes=\"%d\" "
                 "dynamic-routes=\"%d\" owner-routes=\"%d\" "
                 "owner-role-mismatches=\"%d\" "
                 "connected=\"%d\" static=\"%d\" ospf=\"%d\" bgp=\"%d\" "
                 "ifindex-rifs=\"%d\" nexthops=\"%d\" "
                 "dynamic-nexthops=\"%d\" mapped-nexthops=\"%d\" "
                 "unmapped-nexthops=\"%d\" handle-map=\"%s\" "
                 "missing=\"%s\" "
                 "reason=\"%s\"/>",
                 gate_open ? "open" : "closed",
                 ready ? "ready" : "blocked",
                 ready ? "true" : "false",
                 ready ? "enabled" : "disabled",
                 st ? st->n_routes : 0, dynamic_routes, owner_routes,
                 owner_role_mismatches, connected, statics, ospf, bgp,
                 ifindex_rifs, nexthops, handle_map.dynamic_nexthops,
                 handle_map.mapped_nexthops, handle_map.unmapped_nexthops,
                 fib_handle_map_status(&handle_map), missing, reason);
    return n < 0 || (size_t)n >= buf_size ? -1 : 0;
}

static bool fib_live_prereqs_ready(const l3_fib_state *st) {
    l3_fib_handle_map_stats handle_map;

    fib_handle_map_collect(st, &handle_map);
    return fib_owner_role_mismatch_count(st) == 0 &&
           handle_map.unmapped_nexthops == 0 &&
           fib_ifindex_rif_count(st) == 0;
}

static int fib_dynamic_owner_route_count(const l3_fib_state *st) {
    int count = 0;

    if (!st)
        return 0;
    for (int i = 0; i < st->n_routes; i++)
        if (fib_route_is_dynamic_owner(&st->routes[i]))
            count++;
    return count;
}

static int fib_dynamic_owner_nexthop_count(const l3_fib_state *st) {
    int count = 0;

    if (!st)
        return 0;
    for (int i = 0; i < st->n_routes; i++)
        if (fib_route_is_dynamic_owner(&st->routes[i]))
            count += st->routes[i].n_nexthops;
    return count;
}

static void fib_live_plan_free(l3_fib_live_plan *live) {
    if (!live)
        return;
    free(live->routes);
    free(live->nexthops);
    memset(live, 0, sizeof(*live));
}

static void fib_live_plan_init_empty(const l3_fib_state *st,
                                     l3_fib_live_plan *live) {
    if (!live)
        return;
    memset(live, 0, sizeof(*live));
    snprintf(live->plan.table, sizeof(live->plan.table), "%s",
             st && st->table[0] ? st->table : "inet.0");
    live->plan.generation = st ? st->generation : 0;
    live->plan.fib_update_id = st ? st->fib_update_id : 0;
    live->plan.vrid = st ? st->vrid : 0;
}

static int fib_live_plan_build(const l3_fib_state *st,
                               l3_fib_live_plan *live,
                               char *err, size_t err_size) {
    int route_count = fib_dynamic_owner_route_count(st);
    int nh_count = fib_dynamic_owner_nexthop_count(st);
    int route_index = 0;
    int nh_index = 0;

    if (!live) {
        snprintf(err, err_size, "missing live plan");
        return -1;
    }
    fib_live_plan_init_empty(st, live);
    if (!st)
        return 0;
    if (route_count == 0)
        return 0;
    live->routes = calloc((size_t)route_count, sizeof(*live->routes));
    live->nexthops = calloc((size_t)nh_count, sizeof(*live->nexthops));
    if (!live->routes || (nh_count > 0 && !live->nexthops)) {
        snprintf(err, err_size, "out of memory");
        fib_live_plan_free(live);
        return -1;
    }
    for (int i = 0; i < st->n_routes; i++) {
        const l3_fib_route *route = &st->routes[i];
        hal_l3_dynamic_fib_route *out;

        if (!fib_route_is_dynamic_owner(route))
            continue;
        if (route->n_nexthops <= 0) {
            snprintf(err, err_size, "dynamic route %s has no nexthop",
                     route->prefix);
            fib_live_plan_free(live);
            return -1;
        }
        out = &live->routes[route_index];
        snprintf(out->prefix, sizeof(out->prefix), "%s", route->prefix);
        snprintf(out->protocol, sizeof(out->protocol), "%s",
                 route->protocol[0] ? route->protocol : "dynamic");
        out->preference = route->preference;
        out->metric = route->metric;
        out->route_generation = route->route_generation;
        out->fib_update_id = route->fib_update_id;
        out->nexthops = &live->nexthops[nh_index];
        out->n_nexthops = route->n_nexthops;
        for (int j = 0; j < route->n_nexthops; j++) {
            const l3_fib_nexthop *nh = &route->nexthops[j];
            hal_l3_persistent_next_hop_ref ref;
            hal_l3_dynamic_fib_nexthop *out_nh =
                &live->nexthops[nh_index + j];

            memset(&ref, 0, sizeof(ref));
            if (hal_l3_persistent_owner_lookup_next_hop(
                    st->table, nh->address, nh->egress_rif, &ref) != 0 ||
                !ref.owner_applied || !ref.found) {
                snprintf(err, err_size,
                         "dynamic nexthop %s@%s has no persistent owner handle",
                         nh->address, nh->egress_rif);
                fib_live_plan_free(live);
                return -1;
            }
            snprintf(out_nh->address, sizeof(out_nh->address), "%s",
                     nh->address);
            snprintf(out_nh->rif, sizeof(out_nh->rif), "%s",
                     nh->egress_rif);
            snprintf(out_nh->table, sizeof(out_nh->table), "%s",
                     st->table);
            out_nh->vrid = st->vrid;
            snprintf(out_nh->interface_addr,
                     sizeof(out_nh->interface_addr), "%s",
                     ref.interface_addr);
            out_nh->persistent_next_hop_id = ref.next_hop_id;
            out_nh->persistent_rif_index = ref.rif_index;
            out_nh->vlan = ref.vlan;
        }
        nh_index += route->n_nexthops;
        route_index++;
    }
    live->plan.routes = live->routes;
    live->plan.n_routes = route_index;
    return 0;
}

static int fib_live_owner_sync(int sw, const l3_fib_state *st,
                               u64 tx_id, char *resp,
                               size_t resp_size) {
    l3_fib_live_plan live;
    char err[192] = "";
    int rc;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!fib_live_gate_open())
        return hal_l3_dynamic_fib_owner_readback(sw, resp, resp_size);

    if (!fib_live_prereqs_ready(st)) {
        fib_live_plan_init_empty(st, &live);
        return hal_l3_dynamic_fib_owner_apply(sw, &live.plan, true,
                                              tx_id, resp, resp_size);
    }

    if (fib_live_plan_build(st, &live, err, sizeof(err)) != 0) {
        snprintf(resp, resp_size,
                 "<fib-live-owner status=\"invalid\" source=\"switchd\" "
                 "owner=\"rpd\" hardware-apply=\"disabled\" "
                 "sdk-write=\"available\" sdk-readback=\"available\" "
                 "tx-id=\"%llu\" reason=\"%s\"/>",
                 (unsigned long long)tx_id,
                 err[0] ? err : "live plan build failed");
        return -1;
    }
    rc = hal_l3_dynamic_fib_owner_apply(sw, &live.plan, true, tx_id,
                                        resp, resp_size);
    fib_live_plan_free(&live);
    return rc;
}

static int fib_owner_xml(const char *tag, const char *status, u64 tx_id,
                         const l3_fib_state *pre,
                         const l3_fib_state *post,
                         const char *apply_mode,
                         const char *reason,
                         const char *live_owner,
                         char *resp, size_t resp_size) {
    char shadow[8192];
    char verify[1024];
    char live[1024];
    char handle_map[4096];

    if (fib_shadow_inventory_xml(post, shadow, sizeof(shadow)) != 0)
        snprintf(shadow, sizeof(shadow),
                 "<fib-shadow-readback status=\"invalid\" "
                 "source=\"switchd-rpd-fib-owner\" mode=\"synthetic\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");
    if (fib_shadow_verify_xml(post, post, verify, sizeof(verify)) < 0)
        snprintf(verify, sizeof(verify),
                 "<fib-shadow-verify status=\"invalid\" "
                 "source=\"switchd-rpd-fib-owner\" mode=\"synthetic\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");
    if (fib_live_eligibility_xml(post, live, sizeof(live)) != 0)
        snprintf(live, sizeof(live),
                 "<live-eligibility status=\"invalid\" "
                 "source=\"switchd-rpd-fib-owner\" "
                 "hardware-apply=\"disabled\" sdk-write=\"disabled\"/>");
    if (fib_handle_map_xml(post, handle_map, sizeof(handle_map)) != 0)
        snprintf(handle_map, sizeof(handle_map),
                 "<fib-handle-map status=\"invalid\" "
                 "source=\"switchd-rpd-fib-owner\" "
                 "owner=\"persistent\" sdk-write=\"disabled\"/>");
    return snprintf(resp, resp_size,
                    "<%s status=\"%s\" tx-id=\"%llu\" owner=\"rpd\" "
                    "table=\"%s\" mode=\"shadow\" "
                    "hardware-apply=\"disabled\" read-back=\"synthetic\" "
                    "rollback=\"%s\" generation=\"%llu\" "
                    "fib-update-id=\"%llu\" routes=\"%d\" "
                    "ecmp-routes=\"%d\" nexthops=\"%d\" reason=\"%s\">"
                    "<pre-state routes=\"%d\" ecmp-routes=\"%d\" "
                    "nexthops=\"%d\" generation=\"%llu\" "
                    "fib-update-id=\"%llu\"/>"
                    "<post-state routes=\"%d\" ecmp-routes=\"%d\" "
                    "nexthops=\"%d\" generation=\"%llu\" "
                    "fib-update-id=\"%llu\"/>"
                    "<apply-intent owner=\"switchd\" source=\"rpd\" "
                    "family=\"ipv4-unicast\" table=\"%s\" "
                    "mode=\"%s\" sdk-write=\"disabled\" "
                    "total-ops=\"%d\"/>"
                    "<rollback-intent owner=\"switchd\" source=\"rpd\" "
                    "mode=\"restore-pre-state\" sdk-write=\"disabled\" "
                    "restore-ops=\"%d\"/>"
                    "%s"
                    "%s"
                    "%s"
                    "%s"
                    "%s"
                    "<boundary reason=\"dynamic FIB batch owner is shadow by "
                    "default; live SDK apply requires "
                    "NETLAB_ENABLE_RPD_FIB_LIVE_APPLY and a persistent owner "
                    "next-hop handle map\"/>"
                    "</%s>",
                    tag ? tag : "fib-batch",
                    status ? status : "invalid",
                    (unsigned long long)tx_id,
                    post && post->table[0] ? post->table : "inet.0",
                    status && strcmp(status, "ok") == 0 ?
                        "available" : "unavailable",
                    (unsigned long long)(post ? post->generation : 0),
                    (unsigned long long)(post ? post->fib_update_id : 0),
                    post ? post->n_routes : 0,
                    fib_ecmp_route_count(post),
                    fib_nexthop_count(post),
                    reason ? reason : "",
                    pre ? pre->n_routes : 0,
                    fib_ecmp_route_count(pre),
                    fib_nexthop_count(pre),
                    (unsigned long long)(pre ? pre->generation : 0),
                    (unsigned long long)(pre ? pre->fib_update_id : 0),
                    post ? post->n_routes : 0,
                    fib_ecmp_route_count(post),
                    fib_nexthop_count(post),
                    (unsigned long long)(post ? post->generation : 0),
                    (unsigned long long)(post ? post->fib_update_id : 0),
                    post && post->table[0] ? post->table : "inet.0",
                    apply_mode ? apply_mode : "full-replace",
                    post ? post->n_routes : 0,
                    pre ? pre->n_routes : 0,
                    shadow,
                    verify,
                    live,
                    handle_map,
                    live_owner ? live_owner : "",
                    tag ? tag : "fib-batch");
}

static int fib_owner_commit_locked(int sw, l3_fib_state **post_io,
                                   u64 tx_id, const char *tag,
                                   const char *apply_mode,
                                   char *resp, size_t resp_size) {
    l3_fib_owner *owner;
    l3_fib_state *pre;
    l3_fib_state *post;
    char live_owner[8192];
    int live_rc;
    int n;

    if (!post_io || !*post_io || !resp || resp_size == 0)
        return -1;
    post = *post_io;
    owner = fib_owner_for_vrid(post->vrid);
    if (!owner)
        return fib_fail(resp, resp_size, 0,
                        "unsupported fib virtual router id");
    pre = owner->current;
    if (owner->state == L3_OWNER_APPLIED && owner->current &&
        owner->last_tx_id == tx_id) {
        bool identical = fib_compare(owner->current, post) == 0;

        n = fib_owner_xml(
            tag, identical ? "ok" : "transaction-conflict", tx_id,
            owner->pre, owner->current, apply_mode,
            identical ?
                "idempotent switchd rpd FIB retry acknowledged without replacing rollback authority" :
                "FIB transaction identity or version was reused with divergent content",
            "", resp, resp_size);
        if (n < 0 || (size_t)n >= resp_size)
            return fib_fail(resp, resp_size, 0,
                            "fib owner retry response overflow");
        return identical ? 0 : -1;
    }
    live_rc = fib_live_owner_sync(sw, post, tx_id, live_owner,
                                  sizeof(live_owner));
    if (live_rc == 0) {
        free(owner->pre);
        owner->pre = owner->current;
        owner->current = post;
        *post_io = NULL;
        owner->rollback_available = true;
        owner->state = L3_OWNER_APPLIED;
        owner->last_tx_id = tx_id;
    }
    n = fib_owner_xml(
        tag, live_rc == 0 ? "ok" : "fib-sync-error", tx_id,
        pre, live_rc == 0 ? owner->current : post, apply_mode,
        live_rc == 0 ?
            "switchd rpd FIB owner accepted state" :
            "switchd rpd FIB owner rejected staged state because live dynamic FIB sync failed",
        live_owner, resp, resp_size);
    if (n < 0 || (size_t)n >= resp_size)
        return fib_fail(resp, resp_size, 0,
                        "fib owner apply response overflow");
    return live_rc == 0 ? 0 : -1;
}

static u64 fib_snapshot_digest_update(u64 digest, const char *data,
                                      size_t length) {
    for (size_t i = 0; data && i < length; i++) {
        digest ^= (u8)data[i];
        digest *= L3_FIB_SNAPSHOT_DIGEST_PRIME;
    }
    return digest;
}

static u32 fib_snapshot_prefix_hash(const char *prefix) {
    u32 hash = 2166136261u;

    while (prefix && *prefix) {
        hash ^= (u8)*prefix++;
        hash *= 16777619u;
    }
    return hash;
}

static void fib_snapshot_stage_reset(l3_fib_snapshot_stage *stage) {
    if (!stage)
        return;
    free(stage->state);
    free(stage->prefix_slots);
    memset(stage, 0, sizeof(*stage));
}

static u64 fib_snapshot_monotonic_ns(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (u64)now.tv_sec * 1000000000ULL + (u64)now.tv_nsec;
}

static bool fib_snapshot_stage_expired(
        const l3_fib_snapshot_stage *stage, u64 now_ns) {
    return stage && stage->active && stage->deadline_ns != 0 &&
        now_ns >= stage->deadline_ns;
}

int l3_fib_snapshot_sweep(u64 now_ns) {
    int expired = 0;

    if (now_ns == 0)
        now_ns = fib_snapshot_monotonic_ns();
    pthread_mutex_lock(&g_l3_fib_owner_lock);
    for (int slot = 0; slot < L3_FIB_OWNER_SLOTS; slot++) {
        if (!fib_snapshot_stage_expired(&g_l3_fib_snapshot[slot], now_ns))
            continue;
        fib_snapshot_stage_reset(&g_l3_fib_snapshot[slot]);
        expired++;
    }
    pthread_mutex_unlock(&g_l3_fib_owner_lock);
    return expired;
}

static int fib_snapshot_fail(char *resp, size_t resp_size,
                             const char *operation,
                             const char *reason) {
    if (resp && resp_size > 0)
        snprintf(resp, resp_size,
                 "<fib-snapshot-%s status=\"invalid\" "
                 "reason=\"%s\"/>",
                 operation ? operation : "request",
                 reason ? reason : "invalid snapshot request");
    return -1;
}

static int fib_snapshot_prefix_add(l3_fib_snapshot_stage *stage,
                                   int route_index) {
    const char *prefix;
    u32 hash;

    if (!stage || !stage->state || !stage->prefix_slots ||
        route_index < 0 || route_index >= stage->state->n_routes)
        return -1;
    prefix = stage->state->routes[route_index].prefix;
    hash = fib_snapshot_prefix_hash(prefix);
    for (int probe = 0; probe < L3_FIB_SNAPSHOT_PREFIX_SLOTS; probe++) {
        int slot_index = (int)((hash + (u32)probe) %
                               L3_FIB_SNAPSHOT_PREFIX_SLOTS);
        int stored = stage->prefix_slots[slot_index];

        if (stored == 0) {
            stage->prefix_slots[slot_index] = route_index + 1;
            return 0;
        }
        if (strcmp(stage->state->routes[stored - 1].prefix, prefix) == 0)
            return -1;
    }
    return -1;
}

static int fib_snapshot_parse_part_locked(l3_fib_snapshot_stage *stage,
                                          const char *data,
                                          int expected_routes,
                                          char *resp,
                                          size_t resp_size) {
    char *copy;
    char *save = NULL;
    char *line;
    int first_route = stage && stage->state ? stage->state->n_routes : 0;
    int line_no = 0;

    if (!stage || !stage->state || !data)
        return fib_snapshot_fail(resp, resp_size, "part",
                                 "missing snapshot part state");
    copy = strdup(data);
    if (!copy)
        return fib_snapshot_fail(resp, resp_size, "part", "out of memory");
    line = strtok_r(copy, "\n", &save);
    while (line) {
        char *text = trim(line);

        line_no++;
        if (!text[0]) {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }
        if (strncmp(text, "fib-batch ", 10) == 0) {
            char table[sizeof(stage->table)];
            u64 generation;
            u64 update_id;

            if (stage->header_received || stage->received_bytes != 0 ||
                fib_parse_batch_header(stage->state, text, line_no,
                                       resp, resp_size) != 0) {
                free(copy);
                return fib_snapshot_fail(resp, resp_size, "part",
                                         "unexpected snapshot header");
            }
            snprintf(table, sizeof(table), "%s", stage->state->table);
            generation = stage->state->generation;
            update_id = stage->state->fib_update_id;
            if (strcmp(stage->state->mode, "full-state") != 0 ||
                strcmp(table, stage->table) != 0 ||
                generation != stage->generation ||
                update_id != stage->fib_update_id) {
                free(copy);
                return fib_snapshot_fail(resp, resp_size, "part",
                                         "snapshot header mismatch");
            }
            stage->header_received = true;
        } else if (strncmp(text, "fib-route ", 10) == 0) {
            int route_index;

            if (!stage->header_received ||
                fib_parse_route(stage->state, text, line_no, false,
                                resp, resp_size) != 0) {
                free(copy);
                return fib_snapshot_fail(resp, resp_size, "part",
                                         "invalid snapshot route");
            }
            route_index = stage->state->n_routes - 1;
            if (fib_snapshot_prefix_add(stage, route_index) != 0) {
                free(copy);
                return fib_snapshot_fail(resp, resp_size, "part",
                                         "duplicate snapshot prefix");
            }
        } else {
            free(copy);
            return fib_snapshot_fail(resp, resp_size, "part",
                                     "unknown snapshot record");
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    if (stage->state->n_routes - first_route != expected_routes)
        return fib_snapshot_fail(resp, resp_size, "part",
                                 "snapshot part route count mismatch");
    return 0;
}

typedef struct {
    char table[HAL_L3_INTENT_TABLE_LEN];
    u64 generation;
    u64 fib_update_id;
    u64 bytes;
    u64 digest;
    int routes;
    int parts;
    int part;
    u64 offset;
    u64 part_bytes;
    int part_routes;
    int vrid;
} l3_fib_snapshot_meta;

static int fib_snapshot_meta_parse(const char *text, const char *operation,
                                   bool parse_part,
                                   l3_fib_snapshot_meta *meta,
                                   char *resp, size_t resp_size) {
    char prefix[64];
    int n;

    if (!text || !operation || !meta)
        return fib_snapshot_fail(resp, resp_size, operation,
                                 "missing snapshot metadata");
    n = snprintf(prefix, sizeof(prefix), "fib-snapshot-%s ", operation);
    if (n < 0 || (size_t)n >= sizeof(prefix) ||
        strncmp(text, prefix, (size_t)n) != 0)
        return fib_snapshot_fail(resp, resp_size, operation,
                                 "invalid snapshot operation");
    memset(meta, 0, sizeof(*meta));
    if (!kv_str(text, "table", meta->table, sizeof(meta->table)) ||
        hal_l3_persistent_owner_lookup_table(meta->table, &meta->vrid) != 0 ||
        !fib_kv_u64(text, "generation", &meta->generation) ||
        !fib_kv_u64(text, "fib-update-id", &meta->fib_update_id) ||
        !kv_int(text, "routes", 0, L3_FIB_MAX_ROUTES, &meta->routes) ||
        !kv_int(text, "parts", 1, L3_FIB_SNAPSHOT_MAX_PARTS,
                &meta->parts) ||
        !fib_kv_u64(text, "bytes", &meta->bytes) ||
        meta->bytes == 0 || meta->bytes > L3_FIB_SNAPSHOT_MAX_BYTES ||
        !fib_kv_u64(text, "digest", &meta->digest))
        return fib_snapshot_fail(resp, resp_size, operation,
                                 "invalid snapshot metadata");
    if (parse_part &&
        (!kv_int(text, "part", 0, L3_FIB_SNAPSHOT_MAX_PARTS - 1,
                 &meta->part) ||
         !fib_kv_u64(text, "offset", &meta->offset) ||
         !fib_kv_u64(text, "part-bytes", &meta->part_bytes) ||
         meta->part_bytes == 0 ||
         meta->part_bytes > L3_FIB_SNAPSHOT_PART_MAX_BYTES ||
         !kv_int(text, "part-routes", 0, L3_FIB_MAX_ROUTES,
                 &meta->part_routes)))
        return fib_snapshot_fail(resp, resp_size, operation,
                                 "invalid snapshot part metadata");
    return 0;
}

static bool fib_snapshot_meta_matches(
        const l3_fib_snapshot_stage *stage,
        const l3_fib_snapshot_meta *meta, u64 tx_id) {
    return stage && meta && stage->active && stage->tx_id == tx_id &&
        stage->vrid == meta->vrid &&
        strcmp(stage->table, meta->table) == 0 &&
        stage->generation == meta->generation &&
        stage->fib_update_id == meta->fib_update_id &&
        stage->expected_routes == meta->routes &&
        stage->expected_parts == meta->parts &&
        stage->expected_bytes == (size_t)meta->bytes &&
        stage->expected_digest == meta->digest;
}

int l3_fib_snapshot_begin(const char *text, u64 tx_id, char *resp,
                          size_t resp_size) {
    l3_fib_snapshot_meta meta;
    l3_fib_state *state = NULL;
    int *prefix_slots = NULL;
    l3_fib_snapshot_stage *stage;
    l3_fib_owner *owner;
    u64 started_ns;
    int n;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (tx_id == 0)
        return fib_snapshot_fail(resp, resp_size, "begin",
                                 "snapshot transaction id is required");
    if (fib_snapshot_meta_parse(text, "begin", false, &meta,
                                resp, resp_size) != 0)
        return -1;
    started_ns = fib_snapshot_monotonic_ns();
    if (started_ns == 0 ||
        UINT64_MAX - started_ns < L3_FIB_SNAPSHOT_TTL_NS)
        return fib_snapshot_fail(resp, resp_size, "begin",
                                 "monotonic snapshot deadline unavailable");
    state = calloc(1, sizeof(*state));
    prefix_slots = calloc(L3_FIB_SNAPSHOT_PREFIX_SLOTS,
                          sizeof(*prefix_slots));
    if (!state || !prefix_slots) {
        free(state);
        free(prefix_slots);
        return fib_snapshot_fail(resp, resp_size, "begin", "out of memory");
    }

    pthread_mutex_lock(&g_l3_fib_owner_lock);
    stage = &g_l3_fib_snapshot[meta.vrid];
    owner = fib_owner_for_vrid(meta.vrid);
    if (!owner || (owner->current &&
        (meta.generation < owner->current->generation ||
         (meta.generation == owner->current->generation &&
          meta.fib_update_id < owner->current->fib_update_id)))) {
        pthread_mutex_unlock(&g_l3_fib_owner_lock);
        free(state);
        free(prefix_slots);
        return fib_snapshot_fail(resp, resp_size, "begin",
                                 "stale snapshot generation");
    }
    fib_snapshot_stage_reset(stage);
    stage->active = true;
    stage->tx_id = tx_id;
    stage->generation = meta.generation;
    stage->fib_update_id = meta.fib_update_id;
    stage->expected_digest = meta.digest;
    stage->rolling_digest = L3_FIB_SNAPSHOT_DIGEST_INIT;
    stage->started_ns = started_ns;
    stage->deadline_ns = started_ns + L3_FIB_SNAPSHOT_TTL_NS;
    stage->expected_bytes = (size_t)meta.bytes;
    stage->expected_routes = meta.routes;
    stage->expected_parts = meta.parts;
    stage->vrid = meta.vrid;
    snprintf(stage->table, sizeof(stage->table), "%s", meta.table);
    stage->state = state;
    stage->prefix_slots = prefix_slots;
    n = snprintf(resp, resp_size,
                 "<fib-snapshot-begin status=\"ok\" tx-id=\"%llu\" "
                 "table=\"%s\" generation=\"%llu\" "
                 "fib-update-id=\"%llu\" routes=\"%d\" parts=\"%d\" "
                 "bytes=\"%llu\" digest=\"%llu\" next-part=\"0\"/>",
                 (unsigned long long)tx_id, stage->table,
                 (unsigned long long)stage->generation,
                 (unsigned long long)stage->fib_update_id,
                 stage->expected_routes, stage->expected_parts,
                 (unsigned long long)stage->expected_bytes,
                 (unsigned long long)stage->expected_digest);
    pthread_mutex_unlock(&g_l3_fib_owner_lock);
    if (n < 0 || (size_t)n >= resp_size)
        return fib_snapshot_fail(resp, resp_size, "begin",
                                 "snapshot begin response overflow");
    return 0;
}

int l3_fib_snapshot_part(const char *text, u64 tx_id, char *resp,
                         size_t resp_size) {
    l3_fib_snapshot_meta meta;
    l3_fib_snapshot_stage *stage;
    const char *data;
    const char *line_end;
    char header[1024];
    size_t header_len;
    size_t data_len;
    int n;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    line_end = text ? strchr(text, '\n') : NULL;
    if (!line_end)
        return fib_snapshot_fail(resp, resp_size, "part",
                                 "missing snapshot part data");
    header_len = (size_t)(line_end - text);
    if (header_len == 0 || header_len >= sizeof(header))
        return fib_snapshot_fail(resp, resp_size, "part",
                                 "invalid snapshot part header");
    memcpy(header, text, header_len);
    header[header_len] = '\0';
    if (fib_snapshot_meta_parse(header, "part", true, &meta,
                                resp, resp_size) != 0)
        return -1;
    data = line_end + 1;
    data_len = strlen(data);

    pthread_mutex_lock(&g_l3_fib_owner_lock);
    stage = &g_l3_fib_snapshot[meta.vrid];
    if (fib_snapshot_stage_expired(stage, fib_snapshot_monotonic_ns()))
        fib_snapshot_stage_reset(stage);
    if (!fib_snapshot_meta_matches(stage, &meta, tx_id) ||
        meta.part != stage->next_part ||
        meta.offset != stage->received_bytes ||
        meta.part_bytes != data_len ||
        data_len == 0 || data[data_len - 1] != '\n' ||
        stage->received_bytes + data_len > stage->expected_bytes ||
        stage->state->n_routes + meta.part_routes >
            stage->expected_routes) {
        fib_snapshot_stage_reset(stage);
        pthread_mutex_unlock(&g_l3_fib_owner_lock);
        return fib_snapshot_fail(resp, resp_size, "part",
                                 "snapshot part sequence mismatch");
    }
    if (fib_snapshot_parse_part_locked(stage, data, meta.part_routes,
                                       resp, resp_size) != 0) {
        fib_snapshot_stage_reset(stage);
        pthread_mutex_unlock(&g_l3_fib_owner_lock);
        return -1;
    }
    stage->rolling_digest = fib_snapshot_digest_update(
        stage->rolling_digest, data, data_len);
    stage->received_bytes += data_len;
    stage->next_part++;
    n = snprintf(resp, resp_size,
                 "<fib-snapshot-part status=\"ok\" tx-id=\"%llu\" "
                 "table=\"%s\" part=\"%d\" next-part=\"%d\" "
                 "received-bytes=\"%llu\" received-routes=\"%d\"/>",
                 (unsigned long long)tx_id, stage->table, meta.part,
                 stage->next_part,
                 (unsigned long long)stage->received_bytes,
                 stage->state->n_routes);
    pthread_mutex_unlock(&g_l3_fib_owner_lock);
    if (n < 0 || (size_t)n >= resp_size)
        return fib_snapshot_fail(resp, resp_size, "part",
                                 "snapshot part response overflow");
    return 0;
}

int l3_fib_snapshot_commit(int sw, const char *text, u64 tx_id, char *resp,
                           size_t resp_size) {
    l3_fib_snapshot_meta meta;
    l3_fib_snapshot_stage *stage;
    l3_fib_state *post;
    int rc;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (fib_snapshot_meta_parse(text, "commit", false, &meta,
                                resp, resp_size) != 0)
        return -1;

    pthread_mutex_lock(&g_l3_fib_owner_lock);
    stage = &g_l3_fib_snapshot[meta.vrid];
    if (fib_snapshot_stage_expired(stage, fib_snapshot_monotonic_ns()))
        fib_snapshot_stage_reset(stage);
    if (!fib_snapshot_meta_matches(stage, &meta, tx_id) ||
        !stage->header_received ||
        stage->next_part != stage->expected_parts ||
        stage->received_bytes != stage->expected_bytes ||
        !stage->state ||
        stage->state->n_routes != stage->expected_routes ||
        stage->rolling_digest != stage->expected_digest) {
        fib_snapshot_stage_reset(stage);
        pthread_mutex_unlock(&g_l3_fib_owner_lock);
        return fib_snapshot_fail(resp, resp_size, "commit",
                                 "incomplete or corrupt snapshot");
    }
    post = stage->state;
    stage->state = NULL;
    rc = fib_owner_commit_locked(sw, &post, tx_id,
                                 "fib-snapshot-commit", "full-snapshot",
                                 resp, resp_size);
    fib_snapshot_stage_reset(stage);
    pthread_mutex_unlock(&g_l3_fib_owner_lock);
    free(post);
    return rc;
}

int l3_fib_snapshot_abort(const char *text, u64 tx_id, char *resp,
                          size_t resp_size) {
    l3_fib_snapshot_meta meta;
    l3_fib_snapshot_stage *stage;
    int n;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (fib_snapshot_meta_parse(text, "abort", false, &meta,
                                resp, resp_size) != 0)
        return -1;
    pthread_mutex_lock(&g_l3_fib_owner_lock);
    stage = &g_l3_fib_snapshot[meta.vrid];
    if (fib_snapshot_stage_expired(stage, fib_snapshot_monotonic_ns()))
        fib_snapshot_stage_reset(stage);
    if (stage->active && !fib_snapshot_meta_matches(stage, &meta, tx_id)) {
        pthread_mutex_unlock(&g_l3_fib_owner_lock);
        return fib_snapshot_fail(resp, resp_size, "abort",
                                 "snapshot abort owner mismatch");
    }
    fib_snapshot_stage_reset(stage);
    n = snprintf(resp, resp_size,
                 "<fib-snapshot-abort status=\"ok\" tx-id=\"%llu\" "
                 "table=\"%s\"/>",
                 (unsigned long long)tx_id, meta.table);
    pthread_mutex_unlock(&g_l3_fib_owner_lock);
    if (n < 0 || (size_t)n >= resp_size)
        return fib_snapshot_fail(resp, resp_size, "abort",
                                 "snapshot abort response overflow");
    return 0;
}

static int find_rif(const l3_tx_state *st, const char *name) {
    for (int i = 0; i < st->n_rifs; i++)
        if (strcmp(st->rifs[i].name, name) == 0)
            return i;
    return -1;
}

static int find_rif_vlan(const l3_tx_state *st, int vlan) {
    for (int i = 0; i < st->n_rifs; i++)
        if (st->rifs[i].vlan == vlan)
            return i;
    return -1;
}

static int find_overlapping_rif_subnet(const l3_tx_state *st,
                                       const char *address,
                                       const char *table) {
    for (int i = 0; i < st->n_rifs; i++)
        if (strcmp(st->rifs[i].table, table) == 0 &&
            ipv4_cidr_overlap(st->rifs[i].address, address))
            return i;
    return -1;
}

static int find_arp(const l3_tx_state *st, const char *ip, const char *rif) {
    for (int i = 0; i < st->n_arps; i++)
        if (strcmp(st->arps[i].ip, ip) == 0 &&
            strcmp(st->arps[i].rif, rif) == 0)
            return i;
    return -1;
}

static int find_nexthop(const l3_tx_state *st, int id) {
    for (int i = 0; i < st->n_nexthops; i++)
        if (st->nexthops[i].id == id)
            return i;
    return -1;
}

static l3_tx_nexthop *get_nexthop(l3_tx_state *st, int id) {
    int idx = find_nexthop(st, id);
    return idx >= 0 ? &st->nexthops[idx] : NULL;
}

static int find_ecmp(const l3_tx_state *st, int id) {
    for (int i = 0; i < st->n_ecmp; i++)
        if (st->ecmp[i].id == id)
            return i;
    return -1;
}

static int find_route(const l3_tx_state *st, const char *prefix,
                      const char *table) {
    for (int i = 0; i < st->n_routes; i++)
        if (strcmp(st->routes[i].prefix, prefix) == 0 &&
            strcmp(st->routes[i].table, table) == 0)
            return i;
    return -1;
}

static bool ecmp_has_member(const l3_tx_ecmp *ecmp, int member) {
    if (!ecmp)
        return false;
    for (int i = 0; i < ecmp->n_members; i++)
        if (ecmp->members[i] == member)
            return true;
    return false;
}

static bool csv_has_empty_member(const char *s) {
    size_t len;

    if (!s || !s[0])
        return true;
    len = strlen(s);
    if (s[0] == ',' || s[len - 1] == ',')
        return true;
    for (const char *p = s; *p; p++)
        if (*p == ',' && p[1] == ',')
            return true;
    return false;
}

static int route_target_count(const char *line) {
    int count = 0;

    if (kv_value(line, "next-hop"))
        count++;
    if (kv_value(line, "ecmp"))
        count++;
    if (kv_value(line, "rif"))
        count++;
    return count;
}

static int fail(char *resp, size_t resp_size, int line_no,
                const char *detail);

static void build_hal_plan(const l3_tx_state *st, hal_l3_intent_plan *plan) {
    memset(plan, 0, sizeof(*plan));
    if (!st)
        return;
    plan->has_router_mac = st->has_router_mac;
    snprintf(plan->router_mac, sizeof(plan->router_mac), "%s",
             st->router_mac);
    plan->has_virtual_router = st->has_virtual_router;
    snprintf(plan->virtual_router_name, sizeof(plan->virtual_router_name),
             "%s", st->virtual_router_name);
    snprintf(plan->virtual_router_table, sizeof(plan->virtual_router_table),
             "%s", st->virtual_router_table);
    plan->virtual_router_id = st->virtual_router_id;
    plan->virtual_router_kernel_table = st->virtual_router_kernel_table;
    plan->rifs = st->rifs;
    plan->n_rifs = st->n_rifs;
    plan->arps = st->arps;
    plan->n_arps = st->n_arps;
    plan->nexthops = st->nexthops;
    plan->n_nexthops = st->n_nexthops;
    plan->ecmp = st->ecmp;
    plan->n_ecmp = st->n_ecmp;
    plan->routes = st->routes;
    plan->n_routes = st->n_routes;
}

static int parse_scope(const l3_tx_state *st, const char *line,
                       char *table, size_t table_size, int *vrid,
                       int line_no, char *resp, size_t resp_size) {
    int parsed_vrid = 0;

    snprintf(table, table_size, "inet.0");
    if (kv_value(line, "table") &&
        !kv_str(line, "table", table, table_size))
        return fail(resp, resp_size, line_no, "invalid routing table");
    if (kv_value(line, "vrid") &&
        !kv_int(line, "vrid", 0, 255, &parsed_vrid))
        return fail(resp, resp_size, line_no, "invalid route vrid");
    if (strcmp(table, "inet.0") == 0) {
        if (parsed_vrid != 0)
            return fail(resp, resp_size, line_no,
                        "inet.0 requires physical router vrid 0");
    } else if (!st->has_virtual_router ||
               strcmp(table, st->virtual_router_table) != 0 ||
               parsed_vrid != st->virtual_router_id) {
        return fail(resp, resp_size, line_no,
                    "routing table does not match virtual router owner");
    }
    *vrid = parsed_vrid;
    return 0;
}

static int parse_virtual_router(l3_tx_state *st, const char *line,
                                int line_no, char *resp,
                                size_t resp_size) {
    char name[HAL_L3_INTENT_NAME_LEN];
    char table[HAL_L3_INTENT_TABLE_LEN];
    char expected[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    int kernel_table;

    if (st->has_virtual_router ||
        !kv_str(line, "name", name, sizeof(name)) || !valid_name(name) ||
        !kv_str(line, "table", table, sizeof(table)) ||
        !kv_int(line, "vrid", HAL_L3_VRF_V1_VRID,
                HAL_L3_VRF_V1_VRID, &vrid) ||
        !kv_int(line, "kernel-table", HAL_L3_VRF_V1_KERNEL_TABLE,
                HAL_L3_VRF_V1_KERNEL_TABLE, &kernel_table))
        return fail(resp, resp_size, line_no,
                    "invalid virtual router V1 owner");
    snprintf(expected, sizeof(expected), "%s.inet.0", name);
    if (strcmp(table, expected) != 0)
        return fail(resp, resp_size, line_no,
                    "virtual router table/name mismatch");
    st->has_virtual_router = true;
    snprintf(st->virtual_router_name, sizeof(st->virtual_router_name),
             "%s", name);
    snprintf(st->virtual_router_table, sizeof(st->virtual_router_table),
             "%s", table);
    st->virtual_router_id = vrid;
    st->virtual_router_kernel_table = kernel_table;
    return 0;
}

static int parse_router(l3_tx_state *st, const char *line, int line_no,
                        char *resp, size_t resp_size) {
    char mac[HAL_L3_INTENT_MAC_LEN];

    if (!kv_str(line, "mac", mac, sizeof(mac)) || !valid_mac(mac))
        return fail(resp, resp_size, line_no, "invalid router mac");
    if (st->has_router_mac)
        return fail(resp, resp_size, line_no, "duplicate router owner");
    st->has_router_mac = true;
    snprintf(st->router_mac, sizeof(st->router_mac), "%s", mac);
    return 0;
}

static int fail(char *resp, size_t resp_size, int line_no,
                const char *detail) {
    snprintf(resp, resp_size,
             "<l3-transaction status=\"invalid\" line=\"%d\" "
             "error=\"%s\" hardware-apply=\"disabled\"/>",
             line_no, detail ? detail : "invalid");
    return -1;
}

static int transaction_xml(const char *tag, const char *status, u64 tx_id,
                           const l3_tx_state *pre, const l3_tx_state *post,
                           const char *reason, char *resp, size_t resp_size) {
    hal_l3_intent_plan hal_plan;
    char hal_probe[1536];
    char sdk_preflight[2048];
    char shadow[2048];
    char verify[1536];

    build_hal_plan(post, &hal_plan);
    if (hal_l3_intent_probe(&hal_plan, hal_probe, sizeof(hal_probe)) != 0)
        snprintf(hal_probe, sizeof(hal_probe),
                 "<hal-l3-intent-probe status=\"invalid\" "
                 "sdk-write=\"disabled\"/>");
    if (hal_l3_intent_sdk_preflight(&hal_plan, sdk_preflight,
                                    sizeof(sdk_preflight)) != 0)
        snprintf(sdk_preflight, sizeof(sdk_preflight),
                 "<hal-l3-sdk-preflight status=\"invalid\" "
                 "hardware-apply=\"disabled\" sdk-write=\"disabled\"/>");
    if (shadow_inventory_xml(post, shadow, sizeof(shadow)) != 0)
        snprintf(shadow, sizeof(shadow),
                 "<shadow-readback source=\"switchd-owner\" "
                 "status=\"invalid\" mode=\"synthetic\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");
    if (shadow_verify_xml(post, post, verify, sizeof(verify)) != 0)
        snprintf(verify, sizeof(verify),
                 "<shadow-verify source=\"switchd-owner\" "
                 "mode=\"synthetic\" status=\"invalid\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");
    return snprintf(resp, resp_size,
                    "<%s status=\"%s\" tx-id=\"%llu\" mode=\"hidden\" "
                    "hardware-apply=\"disabled\" read-back=\"synthetic\" "
                    "rollback=\"%s\" reason=\"%s\">"
                    "<pre-state rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                    "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                    "<post-state rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                    "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                    "<apply-intent owner=\"switchd\" sdk-write=\"disabled\" "
                    "order=\"rif,arp,next-hop,ecmp,route\" total-ops=\"%d\">"
                    "<op name=\"rif\" count=\"%d\"/>"
                    "<op name=\"arp\" count=\"%d\"/>"
                    "<op name=\"next-hop\" count=\"%d\"/>"
                    "<op name=\"ecmp\" count=\"%d\" members=\"%d\"/>"
                    "<op name=\"route\" count=\"%d\"/>"
                    "</apply-intent>"
                    "<rollback-intent owner=\"switchd\" sdk-write=\"disabled\" "
                    "order=\"route,ecmp,next-hop,arp,rif\" total-ops=\"%d\" "
                    "restore-ops=\"%d\">"
                    "<op name=\"route\" count=\"%d\"/>"
                    "<op name=\"ecmp\" count=\"%d\" members=\"%d\"/>"
                    "<op name=\"next-hop\" count=\"%d\"/>"
                    "<op name=\"arp\" count=\"%d\"/>"
                    "<op name=\"rif\" count=\"%d\"/>"
                    "</rollback-intent>"
                    "%s"
                    "%s"
                    "%s"
                    "%s"
                    "<boundary user-config=\"rejected\" "
                    "reason=\"SDK L3 apply/read-back/rollback not enabled\"/>"
                    "</%s>",
                    tag ? tag : "l3-transaction",
                    status ? status : "invalid",
                    (unsigned long long)tx_id,
                    status && strcmp(status, "ok") == 0 ?
                        "available" : "unavailable",
                    reason ? reason : "",
                    pre ? pre->n_rifs : 0,
                    pre ? pre->n_arps : 0,
                    pre ? pre->n_nexthops : 0,
                    pre ? pre->n_routes : 0,
                    pre ? pre->n_ecmp : 0,
                    ecmp_member_count(pre),
                    post ? post->n_rifs : 0,
                    post ? post->n_arps : 0,
                    post ? post->n_nexthops : 0,
                    post ? post->n_routes : 0,
                    post ? post->n_ecmp : 0,
                    ecmp_member_count(post),
                    op_count(post),
                    post ? post->n_rifs : 0,
                    post ? post->n_arps : 0,
                    post ? post->n_nexthops : 0,
                    post ? post->n_ecmp : 0,
                    ecmp_member_count(post),
                    post ? post->n_routes : 0,
                    op_count(post),
                    op_count(pre),
                    post ? post->n_routes : 0,
                    post ? post->n_ecmp : 0,
                    ecmp_member_count(post),
                    post ? post->n_nexthops : 0,
                    post ? post->n_arps : 0,
                    post ? post->n_rifs : 0,
                    shadow,
                    verify,
                    hal_probe,
                    sdk_preflight,
                    tag ? tag : "l3-transaction");
}

static int parse_rif(l3_tx_state *st, const char *line, int line_no,
                     char *resp, size_t resp_size) {
    char name[32];
    char table[HAL_L3_INTENT_TABLE_LEN];
    char port[HAL_L3_INTENT_IFNAME_LEN] = {0};
    char address[40];
    int vrid;
    int vlan;

    if (st->n_rifs >= NL_L3_PERSISTENT_MAX_RIFS)
        return fail(resp, resp_size, line_no, "too many rifs");
    if (parse_scope(st, line, table, sizeof(table), &vrid,
                    line_no, resp, resp_size) != 0)
        return -1;
    if (!kv_str(line, "name", name, sizeof(name)) || !valid_ifname(name) ||
        find_rif(st, name) >= 0)
        return fail(resp, resp_size, line_no, "invalid or duplicate rif");
    if (kv_value(line, "port")) {
        char expected[HAL_L3_INTENT_IFNAME_LEN + 4];

        if (!kv_str(line, "port", port, sizeof(port)) ||
            !valid_ifname(port) || !nl_ifid_name_is_user_port(port))
            return fail(resp, resp_size, line_no,
                        "invalid physical rif port");
        snprintf(expected, sizeof(expected), "%s.0", port);
        if (strcmp(name, expected) != 0)
            return fail(resp, resp_size, line_no,
                        "physical rif name must match port unit 0");
    } else if (strchr(name, '/')) {
        return fail(resp, resp_size, line_no,
                    "physical rif requires port intent");
    }
    if (!kv_int(line, "vlan", 1, 4094, &vlan))
        return fail(resp, resp_size, line_no, "invalid rif vlan");
    if (!kv_str(line, "address", address, sizeof(address)) ||
        !valid_ipv4_cidr(address) ||
        !ipv4_v1_unicast_cidr(address, false))
        return fail(resp, resp_size, line_no,
                    "invalid rif address: IPv4 unicast required");
    if (ipv4_cidr_local_address_is_reserved(address))
        return fail(resp, resp_size, line_no, "invalid RIF local address");
    if (find_rif_vlan(st, vlan) >= 0)
        return fail(resp, resp_size, line_no, "duplicate RIF vlan");
    if (find_overlapping_rif_subnet(st, address, table) >= 0)
        return fail(resp, resp_size, line_no, "overlapping RIF subnet");
    snprintf(st->rifs[st->n_rifs].name, sizeof(st->rifs[st->n_rifs].name),
             "%s", name);
    snprintf(st->rifs[st->n_rifs].table,
             sizeof(st->rifs[st->n_rifs].table), "%s", table);
    st->rifs[st->n_rifs].vrid = vrid;
    snprintf(st->rifs[st->n_rifs].address,
             sizeof(st->rifs[st->n_rifs].address), "%s", address);
    snprintf(st->rifs[st->n_rifs].port,
             sizeof(st->rifs[st->n_rifs].port), "%s", port);
    st->rifs[st->n_rifs].vlan = vlan;
    st->n_rifs++;
    return 0;
}

static int parse_arp(l3_tx_state *st, const char *line, int line_no,
                     char *resp, size_t resp_size) {
    char ip[40];
    char table[HAL_L3_INTENT_TABLE_LEN];
    char mac[18];
    char rif[32];
    char egress_port[HAL_L3_INTENT_IFNAME_LEN] = {0};
    int rif_index;
    int vrid;

    if (st->n_arps >= NL_L3_PERSISTENT_MAX_ARP)
        return fail(resp, resp_size, line_no, "too many arp entries");
    if (parse_scope(st, line, table, sizeof(table), &vrid,
                    line_no, resp, resp_size) != 0)
        return -1;
    if (!kv_str(line, "ip", ip, sizeof(ip)) || !valid_ipv4(ip) ||
        !kv_str(line, "mac", mac, sizeof(mac)) || !valid_mac(mac) ||
        !kv_str(line, "rif", rif, sizeof(rif)))
        return fail(resp, resp_size, line_no, "invalid arp entry");
    if (kv_value(line, "egress-port") &&
        (!kv_str(line, "egress-port", egress_port, sizeof(egress_port)) ||
         !valid_ifname(egress_port)))
        return fail(resp, resp_size, line_no, "invalid arp egress-port");
    rif_index = find_rif(st, rif);
    if (rif_index < 0 || strcmp(st->rifs[rif_index].table, table) != 0)
        return fail(resp, resp_size, line_no, "invalid arp entry");
    if (!ipv4_in_cidr(ip, st->rifs[rif_index].address))
        return fail(resp, resp_size, line_no, "ARP ip outside RIF subnet");
    if (ipv4_equals_cidr_address(ip, st->rifs[rif_index].address))
        return fail(resp, resp_size, line_no, "ARP ip is RIF local address");
    if (find_arp(st, ip, rif) >= 0)
        return fail(resp, resp_size, line_no, "duplicate arp entry");
    snprintf(st->arps[st->n_arps].ip, sizeof(st->arps[st->n_arps].ip),
             "%s", ip);
    snprintf(st->arps[st->n_arps].table,
             sizeof(st->arps[st->n_arps].table), "%s", table);
    st->arps[st->n_arps].vrid = vrid;
    snprintf(st->arps[st->n_arps].mac, sizeof(st->arps[st->n_arps].mac),
             "%s", mac);
    snprintf(st->arps[st->n_arps].rif, sizeof(st->arps[st->n_arps].rif),
             "%s", rif);
    snprintf(st->arps[st->n_arps].egress_port,
             sizeof(st->arps[st->n_arps].egress_port), "%s", egress_port);
    st->n_arps++;
    return 0;
}

static int parse_next_hop(l3_tx_state *st, const char *line, int line_no,
                          char *resp, size_t resp_size) {
    char arp[40];
    char table[HAL_L3_INTENT_TABLE_LEN];
    char rif[32];
    int arp_index;
    int id;
    int rif_index;
    int vrid;

    if (st->n_nexthops >= NL_L3_PERSISTENT_MAX_NEXTHOPS)
        return fail(resp, resp_size, line_no, "too many next-hops");
    if (parse_scope(st, line, table, sizeof(table), &vrid,
                    line_no, resp, resp_size) != 0)
        return -1;
    if (!kv_int(line, "id", 1, 65535, &id) || find_nexthop(st, id) >= 0 ||
        !kv_str(line, "arp", arp, sizeof(arp)) || !valid_ipv4(arp) ||
        !kv_str(line, "rif", rif, sizeof(rif)))
        return fail(resp, resp_size, line_no, "invalid next-hop");
    rif_index = find_rif(st, rif);
    arp_index = find_arp(st, arp, rif);
    if (rif_index < 0 || arp_index < 0 ||
        strcmp(st->rifs[rif_index].table, table) != 0 ||
        strcmp(st->arps[arp_index].table, table) != 0)
        return fail(resp, resp_size, line_no,
                    "next-hop crosses routing table owner");
    st->nexthops[st->n_nexthops].id = id;
    snprintf(st->nexthops[st->n_nexthops].table,
             sizeof(st->nexthops[st->n_nexthops].table), "%s", table);
    st->nexthops[st->n_nexthops].vrid = vrid;
    snprintf(st->nexthops[st->n_nexthops].arp,
             sizeof(st->nexthops[st->n_nexthops].arp), "%s", arp);
    snprintf(st->nexthops[st->n_nexthops].rif,
             sizeof(st->nexthops[st->n_nexthops].rif), "%s", rif);
    st->n_nexthops++;
    return 0;
}

static int parse_ecmp(l3_tx_state *st, const char *line, int line_no,
                      char *resp, size_t resp_size) {
    char members[256];
    char table[HAL_L3_INTENT_TABLE_LEN];
    char *save = NULL;
    char *tok;
    int id;
    int vrid;
    l3_tx_ecmp *ecmp;

    if (st->n_ecmp >= NL_L3_PERSISTENT_MAX_ECMP)
        return fail(resp, resp_size, line_no, "too many ecmp groups");
    if (parse_scope(st, line, table, sizeof(table), &vrid,
                    line_no, resp, resp_size) != 0)
        return -1;
    if (!kv_int(line, "id", 1, 65535, &id) || find_ecmp(st, id) >= 0 ||
        !kv_str(line, "members", members, sizeof(members)))
        return fail(resp, resp_size, line_no, "invalid ecmp group");
    if (csv_has_empty_member(members))
        return fail(resp, resp_size, line_no,
                    "invalid ecmp member list: empty member");
    ecmp = &st->ecmp[st->n_ecmp];
    memset(ecmp, 0, sizeof(*ecmp));
    ecmp->id = id;
    snprintf(ecmp->table, sizeof(ecmp->table), "%s", table);
    ecmp->vrid = vrid;
    tok = strtok_r(members, ",", &save);
    while (tok) {
        char *end = NULL;
        long member = strtol(tok, &end, 10);

        if (!end || *end != '\0' || member < 1 || member > 65535 ||
            ecmp->n_members >= NL_L3_PERSISTENT_MAX_ECMP_MEMBERS ||
            find_nexthop(st, (int)member) < 0 ||
            strcmp(st->nexthops[find_nexthop(st, (int)member)].table,
                   table) != 0)
            return fail(resp, resp_size, line_no, "invalid ecmp member");
        if (ecmp_has_member(ecmp, (int)member))
            return fail(resp, resp_size, line_no, "duplicate ecmp member");
        ecmp->members[ecmp->n_members++] = (int)member;
        tok = strtok_r(NULL, ",", &save);
    }
    if (ecmp->n_members == 0)
        return fail(resp, resp_size, line_no, "empty ecmp group");
    st->n_ecmp++;
    return 0;
}

static int parse_route(l3_tx_state *st, const char *line, int line_no,
                       char *resp, size_t resp_size) {
    char prefix[40];
    char table[HAL_L3_INTENT_TABLE_LEN];
    char rif[32];
    int target;
    int targets;
    int vrid;
    l3_tx_route *route = NULL;

    if (st->n_routes >= NL_L3_PERSISTENT_MAX_ROUTES)
        return fail(resp, resp_size, line_no, "too many routes");
    if (parse_scope(st, line, table, sizeof(table), &vrid,
                    line_no, resp, resp_size) != 0)
        return -1;
    if (!kv_str(line, "prefix", prefix, sizeof(prefix)) ||
        !valid_ipv4_network_cidr(prefix) ||
        !ipv4_v1_unicast_cidr(prefix, true))
        return fail(resp, resp_size, line_no,
                    "invalid route prefix: prefix must be a network address and IPv4 unicast");
    if (find_route(st, prefix, table) >= 0)
        return fail(resp, resp_size, line_no, "duplicate route prefix");
    targets = route_target_count(line);
    if (targets == 0)
        return fail(resp, resp_size, line_no, "missing route target");
    if (targets > 1)
        return fail(resp, resp_size, line_no, "multiple route targets");
    if (kv_value(line, "next-hop")) {
        if (!kv_int(line, "next-hop", 1, 65535, &target) ||
            !get_nexthop(st, target) ||
            strcmp(get_nexthop(st, target)->table, table) != 0)
            return fail(resp, resp_size, line_no, "unknown route next-hop");
        route = &st->routes[st->n_routes];
        route->target_type = HAL_L3_ROUTE_TARGET_NEXTHOP;
        route->target_id = target;
    } else if (kv_value(line, "ecmp")) {
        if (!kv_int(line, "ecmp", 1, 65535, &target) ||
            find_ecmp(st, target) < 0 ||
            strcmp(st->ecmp[find_ecmp(st, target)].table, table) != 0)
            return fail(resp, resp_size, line_no, "unknown route ecmp");
        route = &st->routes[st->n_routes];
        route->target_type = HAL_L3_ROUTE_TARGET_ECMP;
        route->target_id = target;
    } else if (kv_value(line, "rif")) {
        int rif_index;

        if (!kv_str(line, "rif", rif, sizeof(rif)))
            return fail(resp, resp_size, line_no, "unknown route rif");
        rif_index = find_rif(st, rif);
        if (rif_index < 0 || strcmp(st->rifs[rif_index].table, table) != 0)
            return fail(resp, resp_size, line_no, "unknown route rif");
        route = &st->routes[st->n_routes];
        route->target_type = HAL_L3_ROUTE_TARGET_RIF;
        route->target_id = rif_index + 1;
        snprintf(route->target_name, sizeof(route->target_name), "%s", rif);
    } else {
        return fail(resp, resp_size, line_no, "missing route target");
    }
    if (!route)
        return fail(resp, resp_size, line_no, "missing route target");
    snprintf(route->prefix, sizeof(route->prefix), "%s", prefix);
    snprintf(route->table, sizeof(route->table), "%s", table);
    route->vrid = vrid;
    st->n_routes++;
    return 0;
}

static int l3_transaction_parse(const char *text, l3_tx_state *st,
                                char *resp, size_t resp_size) {
    char *copy;
    char *save = NULL;
    char *line;
    int line_no = 0;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!text || !text[0])
        return fail(resp, resp_size, 0, "empty transaction");
    if (!st)
        return fail(resp, resp_size, 0, "missing transaction state");
    memset(st, 0, sizeof(*st));
    copy = strdup(text);
    if (!copy)
        return fail(resp, resp_size, 0, "out of memory");

    line = strtok_r(copy, "\n", &save);
    while (line) {
        char *t = trim(line);
        int rc = 0;

        line_no++;
        if (!t[0] || t[0] == '#') {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }
        if (strncmp(t, "l3-router-set ", 14) == 0)
            rc = parse_router(st, t, line_no, resp, resp_size);
        else if (strncmp(t, "l3-virtual-router-set ", 22) == 0)
            rc = parse_virtual_router(st, t, line_no, resp, resp_size);
        else if (strncmp(t, "l3-rif-set ", 11) == 0)
            rc = parse_rif(st, t, line_no, resp, resp_size);
        else if (strncmp(t, "l3-arp-set ", 11) == 0)
            rc = parse_arp(st, t, line_no, resp, resp_size);
        else if (strncmp(t, "l3-next-hop-set ", 16) == 0)
            rc = parse_next_hop(st, t, line_no, resp, resp_size);
        else if (strncmp(t, "l3-ecmp-set ", 12) == 0)
            rc = parse_ecmp(st, t, line_no, resp, resp_size);
        else if (strncmp(t, "l3-route-set ", 13) == 0)
            rc = parse_route(st, t, line_no, resp, resp_size);
        else
            rc = fail(resp, resp_size, line_no, "unknown l3 transaction op");
        if (rc != 0) {
            free(copy);
            return -1;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    return 0;
}

int l3_transaction_dry_run_parse(const char *text, char *resp,
                                 size_t resp_size) {
    l3_tx_state *st;
    int n;

    st = malloc(sizeof(*st));
    if (!st)
        return fail(resp, resp_size, 0, "out of memory");
    if (l3_transaction_parse(text, st, resp, resp_size) != 0) {
        free(st);
        return -1;
    }

    n = snprintf(resp, resp_size,
                 "<l3-transaction status=\"ok\" hardware-apply=\"disabled\" "
                 "rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" routes=\"%d\" "
                 "ecmp-groups=\"%d\"/>",
                 st->n_rifs, st->n_arps, st->n_nexthops, st->n_routes,
                 st->n_ecmp);
    free(st);
    if (n < 0 || (size_t)n >= resp_size)
        return fail(resp, resp_size, 0,
                    "transaction dry-run response overflow");
    return 0;
}

int l3_transaction_hidden_apply(const char *text, u64 tx_id, char *resp,
                                size_t resp_size) {
    l3_tx_state *parsed = NULL;
    l3_tx_state *empty = NULL;
    u64 owner_tx_id;
    int n;

    parsed = malloc(sizeof(*parsed));
    empty = calloc(1, sizeof(*empty));
    if (!parsed || !empty) {
        free(parsed);
        free(empty);
        return fail(resp, resp_size, 0, "out of memory");
    }
    if (l3_transaction_parse(text, parsed, resp, resp_size) != 0) {
        free(parsed);
        free(empty);
        return -1;
    }

    pthread_mutex_lock(&g_l3_tx_owner_lock);
    owner_tx_id = tx_id ? tx_id : ++g_l3_tx_owner.next_tx_id;
    free(g_l3_tx_owner.pre);
    g_l3_tx_owner.pre = g_l3_tx_owner.current ?
        g_l3_tx_owner.current : empty;
    if (!g_l3_tx_owner.current)
        empty = NULL;
    g_l3_tx_owner.current = parsed;
    parsed = NULL;
    g_l3_tx_owner.rollback_available = true;
    g_l3_tx_owner.state = L3_OWNER_APPLIED;
    g_l3_tx_owner.last_tx_id = owner_tx_id;

    n = transaction_xml("l3-transaction-apply", "ok", owner_tx_id,
                        g_l3_tx_owner.pre, g_l3_tx_owner.current,
                        "switchd hidden L3 transaction owner accepted state",
                        resp, resp_size);
    pthread_mutex_unlock(&g_l3_tx_owner_lock);
    free(parsed);
    free(empty);
    if (n < 0 || (size_t)n >= resp_size)
        return fail(resp, resp_size, 0, "transaction apply response overflow");
    return 0;
}

int l3_transaction_hidden_rollback(u64 tx_id, char *resp, size_t resp_size) {
    l3_tx_state *removed;
    u64 owner_tx_id;
    int n;

    pthread_mutex_lock(&g_l3_tx_owner_lock);
    if (!g_l3_tx_owner.rollback_available) {
        n = transaction_xml("l3-transaction-rollback", "invalid",
                            g_l3_tx_owner.last_tx_id,
                            g_l3_tx_owner.current, g_l3_tx_owner.current,
                            "no switchd L3 pre-state available",
                            resp, resp_size);
        pthread_mutex_unlock(&g_l3_tx_owner_lock);
        if (n < 0 || (size_t)n >= resp_size)
            return fail(resp, resp_size, 0,
                        "transaction rollback response overflow");
        return -1;
    }

    owner_tx_id = tx_id ? tx_id : g_l3_tx_owner.last_tx_id;
    removed = g_l3_tx_owner.current;
    g_l3_tx_owner.current = g_l3_tx_owner.pre;
    g_l3_tx_owner.pre = NULL;
    g_l3_tx_owner.rollback_available = false;
    g_l3_tx_owner.state = L3_OWNER_ROLLED_BACK;
    g_l3_tx_owner.last_tx_id = owner_tx_id;

    n = transaction_xml("l3-transaction-rollback", "ok", owner_tx_id,
                        removed, g_l3_tx_owner.current,
                        "switchd hidden L3 transaction owner restored pre-state",
                        resp, resp_size);
    pthread_mutex_unlock(&g_l3_tx_owner_lock);
    free(removed);
    if (n < 0 || (size_t)n >= resp_size)
        return fail(resp, resp_size, 0,
                    "transaction rollback response overflow");
    return 0;
}

int l3_transaction_hidden_rif_live_probe(int sw, const char *text,
                                         bool acknowledged, u64 tx_id,
                                         char *resp, size_t resp_size) {
    l3_tx_state *parsed;
    hal_l3_intent_plan hal_plan;
    int rc;

    if (!acknowledged)
        return hal_l3_rif_live_probe(sw, NULL, false, tx_id, resp,
                                     resp_size);
    parsed = malloc(sizeof(*parsed));
    if (!parsed)
        return fail(resp, resp_size, 0, "out of memory");
    if (l3_transaction_parse(text, parsed, resp, resp_size) != 0) {
        free(parsed);
        return -1;
    }
    build_hal_plan(parsed, &hal_plan);
    rc = hal_l3_rif_live_probe(sw, &hal_plan, true, tx_id, resp, resp_size);
    free(parsed);
    return rc;
}

int l3_transaction_hidden_arp_live_probe(int sw, const char *text,
                                         bool acknowledged, u64 tx_id,
                                         char *resp, size_t resp_size) {
    l3_tx_state *parsed;
    hal_l3_intent_plan hal_plan;
    int rc;

    if (!acknowledged)
        return hal_l3_arp_live_probe(sw, NULL, false, tx_id, resp,
                                     resp_size);
    parsed = malloc(sizeof(*parsed));
    if (!parsed)
        return fail(resp, resp_size, 0, "out of memory");
    if (l3_transaction_parse(text, parsed, resp, resp_size) != 0) {
        free(parsed);
        return -1;
    }
    build_hal_plan(parsed, &hal_plan);
    rc = hal_l3_arp_live_probe(sw, &hal_plan, true, tx_id, resp, resp_size);
    free(parsed);
    return rc;
}

int l3_transaction_hidden_ecmp_live_probe(int sw, const char *text,
                                          bool acknowledged, u64 tx_id,
                                          char *resp, size_t resp_size) {
    l3_tx_state *parsed;
    hal_l3_intent_plan hal_plan;
    int rc;

    if (!acknowledged)
        return hal_l3_ecmp_live_probe(sw, NULL, false, tx_id, resp,
                                      resp_size);
    parsed = malloc(sizeof(*parsed));
    if (!parsed)
        return fail(resp, resp_size, 0, "out of memory");
    if (l3_transaction_parse(text, parsed, resp, resp_size) != 0) {
        free(parsed);
        return -1;
    }
    build_hal_plan(parsed, &hal_plan);
    rc = hal_l3_ecmp_live_probe(sw, &hal_plan, true, tx_id, resp, resp_size);
    free(parsed);
    return rc;
}

int l3_transaction_hidden_route_live_probe(int sw, const char *text,
                                           bool acknowledged, u64 tx_id,
                                           int hold_sec,
                                           const char *router_mac_text,
                                           char *resp,
                                           size_t resp_size) {
    l3_tx_state *parsed;
    hal_l3_intent_plan hal_plan;
    int rc;

    if (!acknowledged)
        return hal_l3_route_live_probe(sw, NULL, false, tx_id, hold_sec,
                                       router_mac_text, resp, resp_size);
    parsed = malloc(sizeof(*parsed));
    if (!parsed)
        return fail(resp, resp_size, 0, "out of memory");
    if (l3_transaction_parse(text, parsed, resp, resp_size) != 0) {
        free(parsed);
        return -1;
    }
    build_hal_plan(parsed, &hal_plan);
    rc = hal_l3_route_live_probe(sw, &hal_plan, true, tx_id, hold_sec,
                                 router_mac_text, resp, resp_size);
    free(parsed);
    return rc;
}

int l3_transaction_hidden_persistent_apply(int sw, const char *text,
                                           bool acknowledged, u64 tx_id,
                                           char *resp, size_t resp_size) {
    l3_tx_state *parsed;
    hal_l3_intent_plan hal_plan;
    int rc;

    if (!acknowledged)
        return hal_l3_persistent_owner_apply(sw, NULL, false, tx_id,
                                             resp, resp_size);
    parsed = malloc(sizeof(*parsed));
    if (!parsed)
        return fail(resp, resp_size, 0, "out of memory");
    if (l3_transaction_parse(text, parsed, resp, resp_size) != 0) {
        free(parsed);
        return -1;
    }
    build_hal_plan(parsed, &hal_plan);
    rc = hal_l3_persistent_owner_apply(sw, &hal_plan, true, tx_id,
                                       resp, resp_size);
    free(parsed);
    return rc;
}

int l3_transaction_hidden_persistent_readback(int sw, char *resp,
                                              size_t resp_size) {
    return hal_l3_persistent_owner_readback(sw, resp, resp_size);
}

int l3_transaction_hidden_persistent_rollback(int sw, bool acknowledged,
                                              u64 tx_id, char *resp,
                                              size_t resp_size) {
    return hal_l3_persistent_owner_rollback(sw, acknowledged, tx_id,
                                            resp, resp_size);
}

int l3_transaction_shadow_mismatch_probe(const char *text, char *resp,
                                         size_t resp_size) {
    l3_tx_state *expected = NULL;
    l3_tx_state *actual = NULL;
    char verify[1536];
    const char *fault = "none";
    int n;
    int rc = -1;

    expected = malloc(sizeof(*expected));
    actual = malloc(sizeof(*actual));
    if (!expected || !actual) {
        fail(resp, resp_size, 0, "out of memory");
        goto out;
    }
    if (l3_transaction_parse(text, expected, resp, resp_size) != 0)
        goto out;
    if (op_count(expected) == 0) {
        fail(resp, resp_size, 0, "empty mismatch probe");
        goto out;
    }

    *actual = *expected;
    if (actual->n_routes > 0) {
        actual->n_routes--;
        fault = "drop-route";
    } else if (actual->n_ecmp > 0) {
        actual->n_ecmp--;
        fault = "drop-ecmp";
    } else if (actual->n_nexthops > 0) {
        actual->n_nexthops--;
        fault = "drop-next-hop";
    } else if (actual->n_arps > 0) {
        actual->n_arps--;
        fault = "drop-arp";
    } else if (actual->n_rifs > 0) {
        actual->n_rifs--;
        fault = "drop-rif";
    }

    if (shadow_verify_xml(expected, actual, verify, sizeof(verify)) != 0)
        snprintf(verify, sizeof(verify),
                 "<shadow-verify source=\"switchd-owner\" "
                 "mode=\"synthetic\" status=\"invalid\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");

    n = snprintf(resp, resp_size,
                 "<l3-shadow-mismatch-probe status=\"ok\" "
                 "mode=\"hidden\" hardware-apply=\"disabled\" "
                 "fault=\"%s\">"
                 "<expected rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                 "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                 "<actual rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                 "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                 "%s"
                 "<boundary user-config=\"rejected\" "
                 "reason=\"synthetic L3 read-back mismatch probe only\"/>"
                 "</l3-shadow-mismatch-probe>",
                 fault,
                 expected->n_rifs, expected->n_arps,
                 expected->n_nexthops, expected->n_routes,
                 expected->n_ecmp, ecmp_member_count(expected),
                 actual->n_rifs, actual->n_arps, actual->n_nexthops,
                 actual->n_routes, actual->n_ecmp,
                 ecmp_member_count(actual),
                 verify);
    if (n < 0 || (size_t)n >= resp_size) {
        fail(resp, resp_size, 0, "mismatch probe response overflow");
        goto out;
    }
    rc = 0;
out:
    free(expected);
    free(actual);
    return rc;
}

static int parse_failure_probe_payload(const char *text, char *fault,
                                       size_t fault_size,
                                       const char **tx_text,
                                       char *resp, size_t resp_size) {
    const char *line_end;
    size_t n;

    if (!text || strncmp(text, "fault=", 6) != 0)
        return fail(resp, resp_size, 0, "missing failure probe fault");
    line_end = strchr(text, '\n');
    if (!line_end)
        return fail(resp, resp_size, 0, "missing failure probe transaction");
    n = (size_t)(line_end - (text + 6));
    if (n == 0 || n >= fault_size)
        return fail(resp, resp_size, 0, "invalid failure probe fault");
    memcpy(fault, text + 6, n);
    fault[n] = '\0';
    *tx_text = line_end + 1;
    return 0;
}

int l3_transaction_failure_probe(const char *text, char *resp,
                                 size_t resp_size) {
    l3_tx_state *expected = NULL;
    l3_tx_state *actual = NULL;
    char fault[64];
    char verify[1536];
    const char *tx_text = NULL;
    const char *stage = "apply";
    const char *failed_family = "route";
    const char *failed_op = "add";
    const char *policy = "rollback";
    const char *persistent_hw_out_of_sync = "false";
    int rollback_required = 1;
    int n;
    int rc = -1;

    if (parse_failure_probe_payload(text, fault, sizeof(fault), &tx_text,
                                    resp, resp_size) != 0)
        return -1;
    expected = malloc(sizeof(*expected));
    actual = malloc(sizeof(*actual));
    if (!expected || !actual) {
        fail(resp, resp_size, 0, "out of memory");
        goto out;
    }
    if (l3_transaction_parse(tx_text, expected, resp, resp_size) != 0)
        goto out;
    if (op_count(expected) == 0) {
        fail(resp, resp_size, 0, "empty failure probe");
        goto out;
    }

    *actual = *expected;
    if (strcmp(fault, "route-add") == 0) {
        if (expected->n_routes <= 0) {
            fail(resp, resp_size, 0, "route-add probe needs route");
            goto out;
        }
        stage = "apply";
        failed_family = "route";
        failed_op = "add";
    } else if (strcmp(fault, "next-hop-add") == 0) {
        if (expected->n_nexthops <= 0) {
            fail(resp, resp_size, 0,
                 "next-hop-add probe needs next-hop");
            goto out;
        }
        stage = "apply";
        failed_family = "next-hop";
        failed_op = "add";
    } else if (strcmp(fault, "read-back-mismatch") == 0) {
        if (actual->n_routes > 0) {
            actual->n_routes--;
            failed_family = "route";
        } else if (actual->n_nexthops > 0) {
            actual->n_nexthops--;
            failed_family = "next-hop";
        } else if (actual->n_arps > 0) {
            actual->n_arps--;
            failed_family = "arp";
        } else if (actual->n_rifs > 0) {
            actual->n_rifs--;
            failed_family = "rif";
        }
        stage = "read-back";
        failed_op = "verify";
        policy = "rollback";
    } else if (strcmp(fault, "rollback-mismatch") == 0) {
        if (actual->n_routes > 0) {
            actual->n_routes--;
            failed_family = "route";
        } else if (actual->n_ecmp > 0) {
            actual->n_ecmp--;
            failed_family = "ecmp";
        } else if (actual->n_nexthops > 0) {
            actual->n_nexthops--;
            failed_family = "next-hop";
        } else if (actual->n_arps > 0) {
            actual->n_arps--;
            failed_family = "arp";
        } else if (actual->n_rifs > 0) {
            actual->n_rifs--;
            failed_family = "rif";
        }
        stage = "rollback";
        failed_op = "verify";
        policy = "mark-hw-out-of-sync";
        persistent_hw_out_of_sync = "true";
        rollback_required = 0;
    } else {
        fail(resp, resp_size, 0, "unsupported failure probe fault");
        goto out;
    }

    if (shadow_verify_xml(expected, actual, verify, sizeof(verify)) != 0)
        snprintf(verify, sizeof(verify),
                 "<shadow-verify source=\"switchd-owner\" "
                 "mode=\"synthetic\" status=\"invalid\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");

    n = snprintf(resp, resp_size,
                 "<l3-failure-probe status=\"ok\" mode=\"hidden\" "
                 "hardware-apply=\"disabled\" fault=\"%s\" stage=\"%s\" "
                 "failed-family=\"%s\" failed-op=\"%s\" "
                 "owner-mutated=\"false\">"
                 "<expected rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                 "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                 "%s"
                 "<failure-policy action=\"%s\" rollback-required=\"%s\" "
                 "persistent-hw-out-of-sync=\"%s\" "
                 "block-future-commits=\"%s\"/>"
                 "<boundary user-config=\"rejected\" "
                 "reason=\"synthetic L3 SDK failure injection only\"/>"
                 "</l3-failure-probe>",
                 fault, stage, failed_family, failed_op,
                 expected->n_rifs, expected->n_arps,
                 expected->n_nexthops, expected->n_routes,
                 expected->n_ecmp, ecmp_member_count(expected),
                 verify,
                 policy,
                 rollback_required ? "true" : "false",
                 persistent_hw_out_of_sync,
                 strcmp(persistent_hw_out_of_sync, "true") == 0 ?
                    "true" : "false");
    if (n < 0 || (size_t)n >= resp_size) {
        fail(resp, resp_size, 0, "failure probe response overflow");
        goto out;
    }
    rc = 0;
out:
    free(expected);
    free(actual);
    return rc;
}

int l3_transaction_hidden_readback(int sw, bool sdk_live_readback,
                                   char *resp, size_t resp_size) {
    const l3_tx_state *current;
    const l3_tx_state *pre;
    hal_l3_intent_plan hal_plan;
    char hal_probe[1536];
    char sdk_preflight[2048];
    char sdk_readback[8192];
    char sdk_owner_verify[4096];
    char shadow[2048];
    char verify[1536];
    int n;

    if (!resp || resp_size == 0)
        return -1;
    pthread_mutex_lock(&g_l3_tx_owner_lock);
    current = g_l3_tx_owner.current;
    pre = g_l3_tx_owner.pre;
    build_hal_plan(current, &hal_plan);
    if (hal_l3_intent_probe(&hal_plan, hal_probe, sizeof(hal_probe)) != 0)
        snprintf(hal_probe, sizeof(hal_probe),
                 "<hal-l3-intent-probe status=\"invalid\" "
                 "sdk-write=\"disabled\"/>");
    if (hal_l3_intent_sdk_preflight(&hal_plan, sdk_preflight,
                                    sizeof(sdk_preflight)) != 0)
        snprintf(sdk_preflight, sizeof(sdk_preflight),
                 "<hal-l3-sdk-preflight status=\"invalid\" "
                 "hardware-apply=\"disabled\" sdk-write=\"disabled\"/>");
    if (sdk_live_readback) {
        if (hal_l3_sdk_readback_probe(sw, sdk_readback,
                                      sizeof(sdk_readback)) != 0)
            snprintf(sdk_readback, sizeof(sdk_readback),
                     "<l3-sdk-readback-probe status=\"invalid\" "
                     "source=\"switchd\" hardware-apply=\"disabled\" "
                     "sdk-write=\"disabled\" sdk-readback=\"live\"/>");
        if (hal_l3_sdk_owner_verify(sw, &hal_plan, sdk_owner_verify,
                                    sizeof(sdk_owner_verify)) != 0)
            snprintf(sdk_owner_verify, sizeof(sdk_owner_verify),
                     "<l3-sdk-owner-verify status=\"invalid\" "
                     "source=\"switchd\" hardware-apply=\"disabled\" "
                     "sdk-write=\"disabled\" sdk-readback=\"live\"/>");
    } else {
        snprintf(sdk_readback, sizeof(sdk_readback),
                 "<l3-sdk-readback-probe status=\"unavailable\" "
                 "source=\"switchd\" hardware-apply=\"disabled\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                 "mode=\"canary\" reason=\"PFE not UP\"/>");
        snprintf(sdk_owner_verify, sizeof(sdk_owner_verify),
                 "<l3-sdk-owner-verify status=\"unavailable\" "
                 "source=\"switchd\" hardware-apply=\"disabled\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                 "mode=\"persistent-owner-readiness\" "
                 "reason=\"PFE not UP\"/>");
    }
    if (shadow_inventory_xml(current, shadow,
                             sizeof(shadow)) != 0)
        snprintf(shadow, sizeof(shadow),
                 "<shadow-readback source=\"switchd-owner\" "
                 "status=\"invalid\" mode=\"synthetic\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");
    if (shadow_verify_xml(current, current,
                          verify, sizeof(verify)) != 0)
        snprintf(verify, sizeof(verify),
                 "<shadow-verify source=\"switchd-owner\" "
                 "mode=\"synthetic\" status=\"invalid\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");
    n = snprintf(resp, resp_size,
                 "<l3-transaction-readback status=\"ok\" mode=\"hidden\" "
                 "hardware-apply=\"disabled\" read-back=\"synthetic\" "
                 "transaction-state=\"%s\" rollback-available=\"%s\" "
                 "tx-id=\"%llu\">"
                 "<usage rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                 "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                 "<pre-state rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                 "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                 "<apply-intent owner=\"switchd\" sdk-write=\"disabled\" "
                 "order=\"rif,arp,next-hop,ecmp,route\" total-ops=\"%d\"/>"
                 "<rollback-intent owner=\"switchd\" sdk-write=\"disabled\" "
                 "order=\"route,ecmp,next-hop,arp,rif\" total-ops=\"%d\" "
                 "restore-ops=\"%d\"/>"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "<boundary user-config=\"rejected\" "
                 "reason=\"SDK L3 hardware read-back not enabled\"/>"
                 "</l3-transaction-readback>",
                 owner_state_name(g_l3_tx_owner.state),
                 g_l3_tx_owner.rollback_available ? "true" : "false",
                 (unsigned long long)g_l3_tx_owner.last_tx_id,
                 current ? current->n_rifs : 0,
                 current ? current->n_arps : 0,
                 current ? current->n_nexthops : 0,
                 current ? current->n_routes : 0,
                 current ? current->n_ecmp : 0,
                 ecmp_member_count(current),
                 pre ? pre->n_rifs : 0,
                 pre ? pre->n_arps : 0,
                 pre ? pre->n_nexthops : 0,
                 pre ? pre->n_routes : 0,
                 pre ? pre->n_ecmp : 0,
                 ecmp_member_count(pre),
                 op_count(current),
                 op_count(current),
                 op_count(pre),
                 shadow,
                 verify,
                 hal_probe,
                 sdk_preflight,
                 sdk_owner_verify,
                 sdk_readback);
    pthread_mutex_unlock(&g_l3_tx_owner_lock);
    if (n < 0 || (size_t)n >= resp_size)
        return -1;
    return 0;
}

int l3_fib_batch_apply(int sw, const char *text, u64 tx_id, char *resp,
                       size_t resp_size) {
    l3_fib_state *parsed = NULL;
    l3_fib_state *post;
    l3_fib_state *empty = NULL;
    const char *apply_mode;
    u64 owner_tx_id;
    int rc;
    l3_fib_owner *owner;

    parsed = malloc(sizeof(*parsed));
    if (!parsed)
        return fib_fail(resp, resp_size, 0, "out of memory");
    if (fib_batch_parse(text, parsed, resp, resp_size) != 0) {
        free(parsed);
        return -1;
    }
    owner = fib_owner_for_vrid(parsed->vrid);
    if (!owner) {
        free(parsed);
        return fib_fail(resp, resp_size, 0,
                        "unsupported fib virtual router id");
    }
    post = malloc(sizeof(*post));
    if (!post) {
        free(parsed);
        return fib_fail(resp, resp_size, 0, "out of memory");
    }

    pthread_mutex_lock(&g_l3_fib_owner_lock);
    if (strcmp(parsed->mode, "delta") == 0) {
        if (!owner->current) {
            empty = calloc(1, sizeof(*empty));
            if (!empty) {
                pthread_mutex_unlock(&g_l3_fib_owner_lock);
                free(parsed);
                free(post);
                return fib_fail(resp, resp_size, 0, "out of memory");
            }
            snprintf(empty->table, sizeof(empty->table), "%s",
                     parsed->table);
            empty->vrid = parsed->vrid;
            snprintf(empty->mode, sizeof(empty->mode), "full-state");
        }
        if (fib_state_apply_delta(owner->current ? owner->current : empty,
                                  parsed, post,
                                  resp, resp_size) != 0) {
            pthread_mutex_unlock(&g_l3_fib_owner_lock);
            free(parsed);
            free(post);
            free(empty);
            return -1;
        }
        apply_mode = "delta-merge";
    } else {
        free(post);
        post = parsed;
        parsed = NULL;
        snprintf(post->mode, sizeof(post->mode), "full-state");
        apply_mode = "full-replace";
    }
    free(parsed);
    free(empty);
    owner_tx_id = tx_id ? tx_id : ++owner->next_tx_id;
    rc = fib_owner_commit_locked(sw, &post, owner_tx_id,
                                 "fib-batch-apply", apply_mode,
                                 resp, resp_size);
    pthread_mutex_unlock(&g_l3_fib_owner_lock);
    free(post);
    return rc;
}

int l3_fib_batch_readback(int sw, char *resp, size_t resp_size) {
    char shadow[8192];
    char verify[1024];
    char live[1024];
    char handle_map[4096];
    char live_owner[8192];
    char vrf_summary[512] = "";
    l3_fib_owner *owner = &g_l3_fib_owner[0];
    l3_fib_owner *vrf_owner = &g_l3_fib_owner[1];
    const l3_fib_state *current;
    const l3_fib_state *vrf_current;
    int n;

    if (!resp || resp_size == 0)
        return -1;
    pthread_mutex_lock(&g_l3_fib_owner_lock);
    current = owner->current;
    vrf_current = vrf_owner->current;
    if (fib_shadow_inventory_xml(current, shadow,
                                 sizeof(shadow)) != 0)
        snprintf(shadow, sizeof(shadow),
                 "<fib-shadow-readback status=\"invalid\" "
                 "source=\"switchd-rpd-fib-owner\" mode=\"synthetic\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");
    if (fib_shadow_verify_xml(current, current,
                              verify, sizeof(verify)) < 0)
        snprintf(verify, sizeof(verify),
                 "<fib-shadow-verify status=\"invalid\" "
                 "source=\"switchd-rpd-fib-owner\" mode=\"synthetic\" "
                 "sdk-write=\"disabled\" sdk-readback=\"disabled\"/>");
    if (fib_live_eligibility_xml(current,
                                 live, sizeof(live)) != 0)
        snprintf(live, sizeof(live),
                 "<live-eligibility status=\"invalid\" "
                 "source=\"switchd-rpd-fib-owner\" "
                 "hardware-apply=\"disabled\" sdk-write=\"disabled\"/>");
    if (fib_handle_map_xml(current, handle_map,
                           sizeof(handle_map)) != 0)
        snprintf(handle_map, sizeof(handle_map),
                 "<fib-handle-map status=\"invalid\" "
                 "source=\"switchd-rpd-fib-owner\" "
                 "owner=\"persistent\" sdk-write=\"disabled\"/>");
    if (hal_l3_dynamic_fib_owner_readback(sw, live_owner,
                                          sizeof(live_owner)) != 0)
        snprintf(live_owner, sizeof(live_owner),
                 "<fib-live-owner-readback status=\"invalid\" "
                 "source=\"switchd\" owner=\"rpd\" "
                 "hardware-apply=\"dynamic\" sdk-readback=\"live\"/>");
    if (vrf_current && vrf_current->table[0])
        snprintf(vrf_summary, sizeof(vrf_summary),
                 "<fib-table table=\"%s\" vrid=\"%d\" state=\"%s\" "
                 "rollback-available=\"%s\" tx-id=\"%llu\" "
                 "generation=\"%llu\" fib-update-id=\"%llu\" "
                 "routes=\"%d\" ecmp-routes=\"%d\" nexthops=\"%d\"/>",
                 vrf_current->table, vrf_current->vrid,
                 owner_state_name(vrf_owner->state),
                 vrf_owner->rollback_available ? "true" : "false",
                 (unsigned long long)vrf_owner->last_tx_id,
                 (unsigned long long)vrf_current->generation,
                 (unsigned long long)vrf_current->fib_update_id,
                 vrf_current->n_routes,
                 fib_ecmp_route_count(vrf_current),
                 fib_nexthop_count(vrf_current));
    n = snprintf(resp, resp_size,
                 "<fib-readback status=\"ok\" owner=\"rpd\" table=\"%s\" "
                 "mode=\"shadow\" hardware-apply=\"disabled\" "
                 "read-back=\"synthetic\" transaction-state=\"%s\" "
                 "rollback-available=\"%s\" tx-id=\"%llu\" "
                 "generation=\"%llu\" fib-update-id=\"%llu\" "
                 "routes=\"%d\" ecmp-routes=\"%d\" nexthops=\"%d\">"
                 "<usage routes=\"%d\" ecmp-routes=\"%d\" "
                 "nexthops=\"%d\"/>"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "%s"
                 "<boundary reason=\"dynamic FIB batch owner is shadow by "
                 "default; live SDK apply requires "
                 "NETLAB_ENABLE_RPD_FIB_LIVE_APPLY and a persistent owner "
                 "next-hop handle map\"/>"
                 "</fib-readback>",
                 current && current->table[0] ? current->table : "inet.0",
                 owner_state_name(owner->state),
                 owner->rollback_available ? "true" : "false",
                 (unsigned long long)owner->last_tx_id,
                 (unsigned long long)(current ? current->generation : 0),
                 (unsigned long long)(current ? current->fib_update_id : 0),
                 current ? current->n_routes : 0,
                 fib_ecmp_route_count(current),
                 fib_nexthop_count(current),
                 current ? current->n_routes : 0,
                 fib_ecmp_route_count(current),
                 fib_nexthop_count(current),
                 shadow,
                 verify,
                 live,
                 handle_map,
                 live_owner,
                 vrf_summary);
    pthread_mutex_unlock(&g_l3_fib_owner_lock);
    if (n < 0 || (size_t)n >= resp_size)
        return -1;
    return 0;
}

int l3_fib_batch_reconcile(int sw, char *resp, size_t resp_size) {
    char readback[32768];
    int n;

    if (l3_fib_batch_readback(sw, readback, sizeof(readback)) != 0)
        return -1;
    n = snprintf(resp, resp_size,
                 "<fib-reconcile status=\"ok\" owner=\"rpd\" "
                 "mode=\"shadow\" hardware-apply=\"disabled\" "
                 "drift=\"false\" reason=\"synthetic shadow owner matches "
                 "current switchd state\">%s</fib-reconcile>",
                 readback);
    if (n < 0 || (size_t)n >= resp_size)
        return -1;
    return 0;
}

int l3_fib_batch_rollback(int sw, u64 tx_id, char *resp, size_t resp_size) {
    const l3_fib_state *removed = NULL;
    const l3_fib_state *restored = NULL;
    l3_fib_state *original[L3_FIB_OWNER_SLOTS] = {0};
    l3_fib_state *restore[L3_FIB_OWNER_SLOTS] = {0};
    bool restore_allocated[L3_FIB_OWNER_SLOTS] = {false};
    int selected[L3_FIB_OWNER_SLOTS] = {0};
    char live_owner[8192];
    u64 owner_tx_id = tx_id;
    int live_rc = 0;
    int compensation_failures = 0;
    int selected_count = 0;
    int n;

    pthread_mutex_lock(&g_l3_fib_owner_lock);
    for (int slot = 0; slot < L3_FIB_OWNER_SLOTS; slot++) {
        l3_fib_owner *owner = &g_l3_fib_owner[slot];

        if (owner->rollback_available &&
            (!tx_id || owner->last_tx_id == tx_id))
            selected[selected_count++] = slot;
    }
    if (selected_count == 0) {
        if (hal_l3_dynamic_fib_owner_readback(sw, live_owner,
                                              sizeof(live_owner)) != 0)
            snprintf(live_owner, sizeof(live_owner),
                     "<fib-live-owner-readback status=\"invalid\" "
                     "source=\"switchd\" owner=\"rpd\" "
                     "hardware-apply=\"dynamic\" sdk-readback=\"live\"/>");
        n = fib_owner_xml("fib-rollback-tx", "invalid",
                          tx_id,
                          g_l3_fib_owner[0].current,
                          g_l3_fib_owner[0].current,
                          "restore-pre-state",
                          "no switchd rpd FIB pre-state available",
                          live_owner,
                          resp, resp_size);
        pthread_mutex_unlock(&g_l3_fib_owner_lock);
        if (n < 0 || (size_t)n >= resp_size)
            return fib_fail(resp, resp_size, 0,
                            "fib rollback response overflow");
        return -1;
    }

    for (int index = 0; index < selected_count; index++) {
        int slot = selected[index];
        l3_fib_owner *owner = &g_l3_fib_owner[slot];

        if (!owner->current) {
            live_rc = -1;
            break;
        }
        original[index] = owner->current;
        restore[index] = owner->pre;
        if (!restore[index]) {
            restore[index] = calloc(1, sizeof(*restore[index]));
            if (!restore[index]) {
                live_rc = -1;
                break;
            }
            restore_allocated[index] = true;
            snprintf(restore[index]->table, sizeof(restore[index]->table),
                     "%s", owner->current->table[0] ?
                     owner->current->table :
                     (slot == 0 ? "inet.0" : "vrf-1"));
            restore[index]->vrid = slot;
            snprintf(restore[index]->mode, sizeof(restore[index]->mode),
                     "full-state");
        }
    }
    if (live_rc != 0) {
        for (int index = 0; index < selected_count; index++)
            if (restore_allocated[index])
                free(restore[index]);
        pthread_mutex_unlock(&g_l3_fib_owner_lock);
        return fib_fail(resp, resp_size, 0,
                        "invalid fib owner state or out of memory");
    }
    removed = original[0];
    restored = restore[0];
    owner_tx_id = tx_id ? tx_id :
        g_l3_fib_owner[selected[0]].last_tx_id;

    for (int index = 0; index < selected_count; index++) {
        int slot = selected[index];
        l3_fib_owner *owner = &g_l3_fib_owner[slot];
        char slot_live[8192];
        u64 slot_tx_id;

        slot_tx_id = tx_id ? tx_id : owner->last_tx_id;
        if (fib_live_owner_sync(sw, restore[index], slot_tx_id,
                                slot_live, sizeof(slot_live)) != 0) {
            snprintf(live_owner, sizeof(live_owner), "%s", slot_live);
            live_rc = -1;
            for (int previous = index - 1; previous >= 0; previous--) {
                char compensate_live[8192];
                l3_fib_owner *previous_owner =
                    &g_l3_fib_owner[selected[previous]];
                u64 compensate_tx_id = tx_id ? tx_id :
                    previous_owner->last_tx_id;

                if (fib_live_owner_sync(sw, original[previous],
                                        compensate_tx_id, compensate_live,
                                        sizeof(compensate_live)) != 0)
                    compensation_failures++;
            }
            break;
        }
        snprintf(live_owner, sizeof(live_owner), "%s", slot_live);
    }
    if (live_rc == 0) {
        for (int index = 0; index < selected_count; index++) {
            l3_fib_owner *owner = &g_l3_fib_owner[selected[index]];

            owner->current = restore[index];
            owner->pre = NULL;
            owner->rollback_available = false;
            owner->state = L3_OWNER_ROLLED_BACK;
            owner->last_tx_id = tx_id ? tx_id : owner->last_tx_id;
        }
    }
    n = fib_owner_xml("fib-rollback-tx",
                      live_rc == 0 ? "ok" :
                        (compensation_failures ? "out-of-sync" :
                         "fib-sync-error"),
                      owner_tx_id,
                      removed,
                      live_rc == 0 ? restored : removed,
                      "restore-pre-state",
                      live_rc == 0 ?
                        "switchd rpd FIB owner restored table-scoped pre-state" :
                        (compensation_failures ?
                         "switchd rpd FIB owner rollback compensation failed" :
                         "switchd rpd FIB owner rejected and compensated staged rollback because live dynamic FIB sync failed"),
                      live_owner,
                      resp, resp_size);
    for (int index = 0; index < selected_count; index++) {
        if (live_rc == 0)
            free(original[index]);
        else if (restore_allocated[index])
            free(restore[index]);
    }
    pthread_mutex_unlock(&g_l3_fib_owner_lock);
    if (n < 0 || (size_t)n >= resp_size)
        return fib_fail(resp, resp_size, 0,
                        "fib rollback response overflow");
    return live_rc == 0 ? 0 : -1;
}
