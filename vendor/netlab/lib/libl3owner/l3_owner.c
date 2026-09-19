#include "netlab/l3_owner.h"
#include "netlab/error.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
#define L3_OWNER_TX_MAX_BYTES 65536
#define L3_OWNER_MAX_RIFS 64
#define L3_OWNER_MAX_ARP 256
#define L3_OWNER_MAX_NEXTHOPS 256
#define L3_OWNER_MAX_ROUTES 2048
#define L3_OWNER_MAX_ECMP 128
#define L3_OWNER_MAX_ECMP_MEMBERS 32
#define L3_OWNER_TABLE_LEN 64
#define L3_OWNER_NAME_LEN 32
#define L3_OWNER_VRF_V1_VRID 1
#define L3_OWNER_VRF_V1_KERNEL_TABLE 1001
#define L3_OWNER_INVENTORY_EMIT_LIMIT 8
#define L3_OWNER_PROFILE_ROUTE_ENTRIES_PER_SLICE 1024
#define L3_OWNER_PROFILE_RIF_CAPACITY 4094
#define L3_OWNER_PROFILE_ARP_CAPACITY 4096
#define L3_OWNER_PROFILE_NEXTHOP_CAPACITY 4096
#define L3_OWNER_PROFILE_ECMP_CAPACITY 1024
#define L3_OWNER_PROFILE_ECMP_MEMBER_CAPACITY 8192
#define L3_OWNER_SOCKET_PATH_MAX 100
#define L3_OWNER_RESOURCE_PROFILE_KEY_LEN 1024

static bool l3_owner_socket_path_safe(const char *path) {
    if (!path || !path[0] || strlen(path) >= L3_OWNER_SOCKET_PATH_MAX)
        return false;
    for (; *path; path++) {
        unsigned char c = (unsigned char)*path;

        if (!(isalnum(c) || c == '/' || c == '.' || c == '_' ||
              c == '-' || c == ':'))
            return false;
    }
    return true;
}

typedef struct {
    char name[32];
    char table[L3_OWNER_TABLE_LEN];
    int vrid;
    int vlan;
    char port[64];
    char address[32];
} l3_rif;

typedef struct {
    char ip[40];
    char table[L3_OWNER_TABLE_LEN];
    int vrid;
    char mac[18];
    char rif[32];
    char egress_port[64];
} l3_arp;

typedef struct {
    int id;
    char table[L3_OWNER_TABLE_LEN];
    int vrid;
    char arp_ip[40];
    char rif[32];
} l3_nexthop;

typedef struct {
    int id;
    char table[L3_OWNER_TABLE_LEN];
    int vrid;
    int members[L3_OWNER_MAX_ECMP_MEMBERS];
    int n_members;
} l3_ecmp;

typedef struct {
    char prefix[40];
    char table[L3_OWNER_TABLE_LEN];
    int vrid;
    int next_hop;
    int ecmp;
} l3_route;

typedef struct {
    int version;
    bool has_router_mac;
    char router_mac[18];
    bool has_virtual_router;
    char virtual_router_name[L3_OWNER_NAME_LEN];
    char virtual_router_table[L3_OWNER_TABLE_LEN];
    int virtual_router_id;
    int virtual_router_kernel_table;
    l3_rif rifs[L3_OWNER_MAX_RIFS];
    int n_rifs;
    l3_arp arps[L3_OWNER_MAX_ARP];
    int n_arps;
    l3_nexthop nexthops[L3_OWNER_MAX_NEXTHOPS];
    int n_nexthops;
    l3_ecmp ecmp[L3_OWNER_MAX_ECMP];
    int n_ecmp;
    l3_route routes[L3_OWNER_MAX_ROUTES];
    int n_routes;
} l3_plan;

typedef enum {
    L3_TX_IDLE = 0,
    L3_TX_LOADED,
    L3_TX_APPLIED,
    L3_TX_ROLLED_BACK,
    L3_TX_HW_OUT_OF_SYNC,
} l3_tx_state;

typedef enum {
    L3_OWNER_NONE = 0,
    L3_OWNER_SYNTHETIC,
    L3_OWNER_PERSISTENT,
} l3_owner_mode;

typedef struct {
    l3_plan plan;
    l3_plan pre_plan;
    l3_tx_state tx_state;
    l3_owner_mode owner_mode;
    bool rollback_available;
    bool hw_out_of_sync;
    char hw_out_of_sync_reason[192];
    u64 last_tx_id;
    u64 next_tx_id;
    int generation;
    time_t last_load;
    time_t last_apply;
    time_t last_rollback;
} l3_owner_ctx;

typedef struct {
    bool profile_loaded;
    bool l3_ready;
    char profile_path[256];
    char reason[192];
    int external_ports;
    int route_capable_ports;
    int route_slice_count;
    int route_capacity;
    int rif_capacity;
    int arp_capacity;
    int nexthop_capacity;
    int ecmp_capacity;
    int ecmp_member_capacity;
} l3_resource_model;

struct nl_l3_owner {
    l3_owner_ctx state;
    pthread_mutex_t lock;
    pthread_mutex_t resource_model_lock;
    bool resource_model_cached;
    char resource_profile_key[L3_OWNER_RESOURCE_PROFILE_KEY_LEN];
    l3_resource_model resource_model_cache;
    char switchd_socket_path[L3_OWNER_SOCKET_PATH_MAX];
    char authority_name[L3_OWNER_NAME_LEN];
    char public_reason[192];
    u16 switchd_caller_daemon;
};

/* The platform resolver is process-global, so serialize profile snapshots. */
static pthread_mutex_t g_platform_profile_lock = PTHREAD_MUTEX_INITIALIZER;

static int switchd_l3_transaction_call(nl_l3_owner *owner,
                                       nl_rpc_method method,
                                       u64 tx_id,
                                       const char *payload,
                                       char *resp, size_t resp_size,
                                       s32 *switchd_ec);

static const char *l3_tx_state_name(l3_tx_state state) {
    switch (state) {
    case L3_TX_IDLE:        return "idle";
    case L3_TX_LOADED:      return "loaded";
    case L3_TX_APPLIED:     return "applied";
    case L3_TX_ROLLED_BACK: return "rolled-back";
    case L3_TX_HW_OUT_OF_SYNC: return "hw-out-of-sync";
    }
    return "unknown";
}

static const char *l3_owner_mode_name(l3_owner_mode mode) {
    switch (mode) {
    case L3_OWNER_NONE:       return "none";
    case L3_OWNER_SYNTHETIC:  return "synthetic";
    case L3_OWNER_PERSISTENT: return "persistent";
    }
    return "unknown";
}

static const char *l3_owner_hardware_apply(l3_owner_mode mode) {
    return mode == L3_OWNER_PERSISTENT ? "persistent" : "disabled";
}

static const char *l3_owner_sdk_readback(l3_owner_mode mode) {
    return mode == L3_OWNER_PERSISTENT ? "live" : "disabled";
}

static void str_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0)
        return;
    snprintf(dst, dst_size, "%s", src ? src : "");
}

static void l3_owner_mark_hw_out_of_sync(nl_l3_owner *owner,
                                         const char *reason) {
    if (!owner)
        return;
    owner->state.hw_out_of_sync = true;
    owner->state.tx_state = L3_TX_HW_OUT_OF_SYNC;
    str_copy(owner->state.hw_out_of_sync_reason,
             sizeof(owner->state.hw_out_of_sync_reason),
             reason ? reason : "persistent L3 hardware state is unknown");
}

static void l3_owner_clear_hw_out_of_sync(nl_l3_owner *owner) {
    if (!owner)
        return;
    owner->state.hw_out_of_sync = false;
    owner->state.hw_out_of_sync_reason[0] = '\0';
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

static int split_tokens(char *line, char **argv, int max_argv) {
    int argc = 0;
    char *save = NULL;
    char *tok = strtok_r(line, " \t\r\n", &save);

    while (tok && argc < max_argv) {
        argv[argc++] = tok;
        tok = strtok_r(NULL, " \t\r\n", &save);
    }
    return argc;
}

static bool valid_ifname(const char *s) {
    if (!s || !s[0] || strlen(s) >= 64)
        return false;
    for (const char *p = s; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '/' && *p != '.' &&
            *p != '_' && *p != '-' && *p != ':')
            return false;
    }
    return true;
}

static bool parse_int_range(const char *s, int min, int max, int *out) {
    char *end = NULL;
    long v;

    if (!s || !out)
        return false;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v < min || v > max)
        return false;
    *out = (int)v;
    return true;
}

static bool parse_ipv4(const char *s) {
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
    char tail;
    int p = -1;
    u32 value;

    if (!s || sscanf(s, "%39[^/]/%d%c", ip, &p, &tail) != 2)
        return false;
    if (p < 0 || p > 32 || !parse_ipv4_u32(ip, &value))
        return false;
    if (addr)
        *addr = value;
    if (prefix)
        *prefix = p;
    return true;
}

static u32 ipv4_prefix_mask(int prefix) {
    return prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
}

static bool parse_ipv4_cidr(const char *s) {
    return parse_ipv4_cidr_parts(s, NULL, NULL);
}

static bool parse_ipv4_network_cidr(const char *s) {
    u32 value;
    int prefix = -1;

    if (!parse_ipv4_cidr_parts(s, &value, &prefix))
        return false;
    return (value & ~ipv4_prefix_mask(prefix)) == 0;
}

static bool ipv4_v1_unicast_cidr(const char *s, bool allow_default) {
    u32 value;
    int prefix = -1;

    if (!parse_ipv4_cidr_parts(s, &value, &prefix))
        return false;
    if (allow_default && prefix == 0)
        return true;
    return (value >> 28) < 14;
}

static bool ipv4_cidr_network_string(const char *s, char *buf,
                                     size_t buf_size) {
    u32 value;
    u32 network;
    int prefix = -1;
    struct in_addr addr;
    char ip[INET_ADDRSTRLEN];
    int n;

    if (!buf || buf_size == 0 ||
        !parse_ipv4_cidr_parts(s, &value, &prefix))
        return false;
    network = value & ipv4_prefix_mask(prefix);
    addr.s_addr = htonl(network);
    if (!inet_ntop(AF_INET, &addr, ip, sizeof(ip)))
        return false;
    n = snprintf(buf, buf_size, "%s/%d", ip, prefix);
    return n > 0 && (size_t)n < buf_size;
}

static bool ipv4_cidr_local_address_is_reserved(const char *s) {
    u32 value;
    u32 host;
    u32 mask;
    int prefix = -1;

    if (!parse_ipv4_cidr_parts(s, &value, &prefix))
        return true;
    if (prefix >= 31)
        return false;
    mask = ipv4_prefix_mask(prefix);
    host = value & ~mask;
    return host == 0 || host == ~mask;
}

static bool ipv4_in_cidr(const char *ip, const char *cidr) {
    u32 value;
    u32 cidr_addr;
    u32 mask;
    int prefix = -1;

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
    int prefix_a = -1;
    int prefix_b = -1;
    int common_prefix;

    if (!parse_ipv4_cidr_parts(a, &addr_a, &prefix_a) ||
        !parse_ipv4_cidr_parts(b, &addr_b, &prefix_b))
        return false;
    common_prefix = prefix_a < prefix_b ? prefix_a : prefix_b;
    mask = ipv4_prefix_mask(common_prefix);
    return (addr_a & mask) == (addr_b & mask);
}

static bool parse_mac(const char *s) {
    unsigned int b[6];
    char tail;

    if (!s)
        return false;
    return sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c",
                  &b[0], &b[1], &b[2], &b[3], &b[4], &b[5],
                  &tail) == 6 &&
           b[0] <= 255 && b[1] <= 255 && b[2] <= 255 &&
           b[3] <= 255 && b[4] <= 255 && b[5] <= 255;
}

static int find_rif(const l3_plan *plan, const char *name) {
    for (int i = 0; i < plan->n_rifs; i++)
        if (strcmp(plan->rifs[i].name, name) == 0)
            return i;
    return -1;
}

static int find_rif_vlan(const l3_plan *plan, int vlan) {
    for (int i = 0; i < plan->n_rifs; i++)
        if (plan->rifs[i].vlan == vlan)
            return i;
    return -1;
}

static int find_overlapping_rif_subnet(const l3_plan *plan,
                                       const char *address,
                                       const char *table) {
    for (int i = 0; i < plan->n_rifs; i++)
        if (strcmp(plan->rifs[i].table, table) == 0 &&
            ipv4_cidr_overlap(plan->rifs[i].address, address))
            return i;
    return -1;
}

static int find_arp(const l3_plan *plan, const char *ip, const char *rif) {
    for (int i = 0; i < plan->n_arps; i++)
        if (strcmp(plan->arps[i].ip, ip) == 0 &&
            strcmp(plan->arps[i].rif, rif) == 0)
            return i;
    return -1;
}

static int find_nexthop(const l3_plan *plan, int id) {
    for (int i = 0; i < plan->n_nexthops; i++)
        if (plan->nexthops[i].id == id)
            return i;
    return -1;
}

static int find_ecmp(const l3_plan *plan, int id) {
    for (int i = 0; i < plan->n_ecmp; i++)
        if (plan->ecmp[i].id == id)
            return i;
    return -1;
}

static bool ecmp_has_member(const l3_ecmp *ecmp, int member) {
    for (int i = 0; i < ecmp->n_members; i++)
        if (ecmp->members[i] == member)
            return true;
    return false;
}

static bool ecmp_member_list_has_empty(const char *members) {
    size_t len;

    if (!members || !members[0])
        return true;
    len = strlen(members);
    if (members[0] == ',' || members[len - 1] == ',')
        return true;
    for (const char *p = members; *p; p++)
        if (*p == ',' && p[1] == ',')
            return true;
    return false;
}

static int find_route(const l3_plan *plan, const char *prefix,
                      const char *table) {
    for (int i = 0; i < plan->n_routes; i++)
        if (strcmp(plan->routes[i].prefix, prefix) == 0 &&
            strcmp(plan->routes[i].table, table) == 0)
            return i;
    return -1;
}

static int find_connected_route_prefix(const l3_plan *plan,
                                       const char *prefix,
                                       const char *table) {
    char connected[40];

    for (int i = 0; i < plan->n_rifs; i++)
        if (strcmp(plan->rifs[i].table, table) == 0 &&
            ipv4_cidr_network_string(plan->rifs[i].address,
                                     connected, sizeof(connected)) &&
            strcmp(connected, prefix) == 0)
            return i;
    return -1;
}

static bool valid_vrf_name(const char *name) {
    if (!name || !name[0] || strlen(name) >= L3_OWNER_NAME_LEN)
        return false;
    for (const char *p = name; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_')
            return false;
    return strcmp(name, "inet") != 0;
}

static int plan_scope(const l3_plan *plan, const char *table, int *vrid,
                      char *err, size_t err_size) {
    if (!table || !table[0] || strcmp(table, "inet.0") == 0) {
        if (vrid)
            *vrid = 0;
        return 0;
    }
    if (!plan || !plan->has_virtual_router ||
        strcmp(table, plan->virtual_router_table) != 0) {
        snprintf(err, err_size, "unknown routing table: %s",
                 table ? table : "-");
        return -1;
    }
    if (vrid)
        *vrid = plan->virtual_router_id;
    return 0;
}

static int add_virtual_router(l3_plan *plan, char **argv, int argc,
                              char *err, size_t err_size) {
    int vrid;
    int kernel_table;
    char expected[L3_OWNER_TABLE_LEN];

    if (argc != 9 || strcmp(argv[1], "name") != 0 ||
        strcmp(argv[3], "table") != 0 || strcmp(argv[5], "vrid") != 0 ||
        strcmp(argv[7], "kernel-table") != 0 ||
        !valid_vrf_name(argv[2]) ||
        !parse_int_range(argv[6], L3_OWNER_VRF_V1_VRID,
                         L3_OWNER_VRF_V1_VRID, &vrid) ||
        !parse_int_range(argv[8], L3_OWNER_VRF_V1_KERNEL_TABLE,
                         L3_OWNER_VRF_V1_KERNEL_TABLE, &kernel_table)) {
        snprintf(err, err_size,
                 "virtual-router syntax: virtual-router name <name> table <name>.inet.0 vrid 1 kernel-table 1001");
        return -1;
    }
    snprintf(expected, sizeof(expected), "%s.inet.0", argv[2]);
    if (strcmp(argv[4], expected) != 0) {
        snprintf(err, err_size, "virtual-router table must be %s", expected);
        return -1;
    }
    if (plan->has_virtual_router) {
        snprintf(err, err_size, "VRF V1 supports one additional virtual router");
        return -1;
    }
    plan->has_virtual_router = true;
    str_copy(plan->virtual_router_name, sizeof(plan->virtual_router_name),
             argv[2]);
    str_copy(plan->virtual_router_table, sizeof(plan->virtual_router_table),
             argv[4]);
    plan->virtual_router_id = vrid;
    plan->virtual_router_kernel_table = kernel_table;
    return 0;
}

static int add_rif(l3_plan *plan, char **argv, int argc,
                   char *err, size_t err_size) {
    int address_arg = 6;
    int syntax_argc = argc;
    const char *port = "";
    const char *table = "inet.0";
    int vrid = 0;
    int vlan;
    int overlap;

    if (argc >= 3 && strcmp(argv[argc - 2], "table") == 0) {
        table = argv[argc - 1];
        syntax_argc -= 2;
    }
    if (plan_scope(plan, table, &vrid, err, err_size) != 0)
        return -1;
    if ((syntax_argc != 7 && syntax_argc != 9) ||
        strcmp(argv[1], "name") != 0 ||
        strcmp(argv[3], "vlan") != 0) {
        snprintf(err, err_size,
                 "rif syntax: rif name <name> vlan <vid> [port <ifname>] address <ipv4/prefix> [table <table>]");
        return -1;
    }
    if (syntax_argc == 9) {
        if (strcmp(argv[5], "port") != 0 ||
            strcmp(argv[7], "address") != 0) {
            snprintf(err, err_size,
                     "rif syntax: rif name <name> vlan <vid> [port <ifname>] address <ipv4/prefix>");
            return -1;
        }
        port = argv[6];
        address_arg = 8;
    } else if (strcmp(argv[5], "address") != 0) {
        snprintf(err, err_size,
                 "rif syntax: rif name <name> vlan <vid> [port <ifname>] address <ipv4/prefix>");
        return -1;
    }
    if (plan->n_rifs >= L3_OWNER_MAX_RIFS) {
        snprintf(err, err_size, "too many RIFs");
        return -1;
    }
    if (!valid_ifname(argv[2]) || find_rif(plan, argv[2]) >= 0) {
        snprintf(err, err_size, "invalid or duplicate RIF name: %s", argv[2]);
        return -1;
    }
    if (port[0]) {
        char expected[72];

        snprintf(expected, sizeof(expected), "%s.0", port);
        if (!valid_ifname(port) || !nl_ifid_name_is_user_port(port) ||
            strcmp(argv[2], expected) != 0) {
            snprintf(err, err_size,
                     "physical RIF name/port must reference a user port unit 0");
            return -1;
        }
    } else if (strchr(argv[2], '/')) {
        snprintf(err, err_size, "physical RIF requires port intent");
        return -1;
    }
    if (!parse_int_range(argv[4], 1, 4094, &vlan) ||
        !parse_ipv4_cidr(argv[address_arg]) ||
        !ipv4_v1_unicast_cidr(argv[address_arg], false)) {
        snprintf(err, err_size, "invalid RIF vlan or address");
        return -1;
    }
    if (ipv4_cidr_local_address_is_reserved(argv[address_arg])) {
        snprintf(err, err_size, "invalid RIF local address: %s",
                 argv[address_arg]);
        return -1;
    }
    if (find_rif_vlan(plan, vlan) >= 0) {
        snprintf(err, err_size, "duplicate RIF vlan: %d", vlan);
        return -1;
    }
    overlap = find_overlapping_rif_subnet(plan, argv[address_arg], table);
    if (overlap >= 0) {
        snprintf(err, err_size, "overlapping RIF subnet: %s overlaps %s",
                 argv[address_arg], plan->rifs[overlap].name);
        return -1;
    }
    str_copy(plan->rifs[plan->n_rifs].name,
             sizeof(plan->rifs[plan->n_rifs].name), argv[2]);
    str_copy(plan->rifs[plan->n_rifs].table,
             sizeof(plan->rifs[plan->n_rifs].table), table);
    plan->rifs[plan->n_rifs].vrid = vrid;
    plan->rifs[plan->n_rifs].vlan = vlan;
    str_copy(plan->rifs[plan->n_rifs].port,
             sizeof(plan->rifs[plan->n_rifs].port), port);
    str_copy(plan->rifs[plan->n_rifs].address,
             sizeof(plan->rifs[plan->n_rifs].address), argv[address_arg]);
    plan->n_rifs++;
    return 0;
}

static int add_arp(l3_plan *plan, char **argv, int argc,
                   char *err, size_t err_size) {
    int syntax_argc = argc;
    const char *table = "inet.0";
    int vrid = 0;
    int rif_idx;

    if (argc >= 3 && strcmp(argv[argc - 2], "table") == 0) {
        table = argv[argc - 1];
        syntax_argc -= 2;
    }
    if (plan_scope(plan, table, &vrid, err, err_size) != 0)
        return -1;
    if ((syntax_argc != 7 && syntax_argc != 9) ||
        strcmp(argv[1], "ip") != 0 ||
        strcmp(argv[3], "mac") != 0 || strcmp(argv[5], "interface") != 0) {
        snprintf(err, err_size,
                 "arp syntax: arp ip <ipv4> mac <mac> interface <rif> "
                 "[egress-port <ifname>]");
        return -1;
    }
    if (syntax_argc == 9 &&
        (strcmp(argv[7], "egress-port") != 0 || !valid_ifname(argv[8]))) {
        snprintf(err, err_size, "invalid ARP egress-port");
        return -1;
    }
    if (plan->n_arps >= L3_OWNER_MAX_ARP) {
        snprintf(err, err_size, "too many ARP entries");
        return -1;
    }
    rif_idx = find_rif(plan, argv[6]);
    if (!parse_ipv4(argv[2]) || !parse_mac(argv[4]) ||
        rif_idx < 0 || strcmp(plan->rifs[rif_idx].table, table) != 0) {
        snprintf(err, err_size, "invalid ARP ip/mac/interface");
        return -1;
    }
    if (!ipv4_in_cidr(argv[2], plan->rifs[rif_idx].address)) {
        snprintf(err, err_size, "ARP ip outside RIF subnet: %s %s",
                 argv[2], argv[6]);
        return -1;
    }
    if (ipv4_equals_cidr_address(argv[2], plan->rifs[rif_idx].address)) {
        snprintf(err, err_size, "ARP ip is RIF local address: %s %s",
                 argv[2], argv[6]);
        return -1;
    }
    if (find_arp(plan, argv[2], argv[6]) >= 0) {
        snprintf(err, err_size, "duplicate ARP entry: %s %s", argv[2],
                 argv[6]);
        return -1;
    }
    str_copy(plan->arps[plan->n_arps].ip,
             sizeof(plan->arps[plan->n_arps].ip), argv[2]);
    str_copy(plan->arps[plan->n_arps].table,
             sizeof(plan->arps[plan->n_arps].table), table);
    plan->arps[plan->n_arps].vrid = vrid;
    str_copy(plan->arps[plan->n_arps].mac,
             sizeof(plan->arps[plan->n_arps].mac), argv[4]);
    str_copy(plan->arps[plan->n_arps].rif,
             sizeof(plan->arps[plan->n_arps].rif), argv[6]);
    if (syntax_argc == 9)
        str_copy(plan->arps[plan->n_arps].egress_port,
                 sizeof(plan->arps[plan->n_arps].egress_port), argv[8]);
    plan->n_arps++;
    return 0;
}

static int add_nexthop(l3_plan *plan, char **argv, int argc,
                       char *err, size_t err_size) {
    int syntax_argc = argc;
    const char *table = "inet.0";
    int vrid = 0;
    int rif_idx;
    int arp_idx;
    int id;

    if (argc >= 3 && strcmp(argv[argc - 2], "table") == 0) {
        table = argv[argc - 1];
        syntax_argc -= 2;
    }
    if (plan_scope(plan, table, &vrid, err, err_size) != 0)
        return -1;
    if (syntax_argc != 7 || strcmp(argv[1], "id") != 0 ||
        strcmp(argv[3], "arp") != 0 || strcmp(argv[5], "interface") != 0) {
        snprintf(err, err_size,
                 "next-hop syntax: next-hop id <id> arp <ipv4> interface <rif>");
        return -1;
    }
    if (plan->n_nexthops >= L3_OWNER_MAX_NEXTHOPS) {
        snprintf(err, err_size, "too many next-hops");
        return -1;
    }
    rif_idx = find_rif(plan, argv[6]);
    arp_idx = find_arp(plan, argv[4], argv[6]);
    if (!parse_int_range(argv[2], 1, 65535, &id) ||
        !parse_ipv4(argv[4]) || rif_idx < 0 || arp_idx < 0 ||
        strcmp(plan->rifs[rif_idx].table, table) != 0 ||
        strcmp(plan->arps[arp_idx].table, table) != 0) {
        snprintf(err, err_size, "invalid next-hop id/arp/interface");
        return -1;
    }
    if (find_nexthop(plan, id) >= 0) {
        snprintf(err, err_size, "duplicate next-hop id: %d", id);
        return -1;
    }
    plan->nexthops[plan->n_nexthops].id = id;
    str_copy(plan->nexthops[plan->n_nexthops].table,
             sizeof(plan->nexthops[plan->n_nexthops].table), table);
    plan->nexthops[plan->n_nexthops].vrid = vrid;
    str_copy(plan->nexthops[plan->n_nexthops].arp_ip,
             sizeof(plan->nexthops[plan->n_nexthops].arp_ip), argv[4]);
    str_copy(plan->nexthops[plan->n_nexthops].rif,
             sizeof(plan->nexthops[plan->n_nexthops].rif), argv[6]);
    plan->n_nexthops++;
    return 0;
}

static int add_ecmp(l3_plan *plan, char **argv, int argc,
                    char *err, size_t err_size) {
    char members[256];
    char *save = NULL;
    char *tok;
    int id;
    int syntax_argc = argc;
    const char *table = "inet.0";
    int vrid = 0;
    l3_ecmp *ecmp;

    if (argc >= 3 && strcmp(argv[argc - 2], "table") == 0) {
        table = argv[argc - 1];
        syntax_argc -= 2;
    }
    if (plan_scope(plan, table, &vrid, err, err_size) != 0)
        return -1;
    if (syntax_argc != 5 || strcmp(argv[1], "id") != 0 ||
        strcmp(argv[3], "members") != 0) {
        snprintf(err, err_size,
                 "ecmp syntax: ecmp id <id> members <next-hop-id,...>");
        return -1;
    }
    if (plan->n_ecmp >= L3_OWNER_MAX_ECMP) {
        snprintf(err, err_size, "too many ECMP groups");
        return -1;
    }
    if (!parse_int_range(argv[2], 1, 65535, &id) ||
        find_ecmp(plan, id) >= 0) {
        snprintf(err, err_size, "invalid or duplicate ECMP id");
        return -1;
    }
    if (ecmp_member_list_has_empty(argv[4])) {
        snprintf(err, err_size, "invalid ECMP member list: empty member");
        return -1;
    }
    ecmp = &plan->ecmp[plan->n_ecmp];
    memset(ecmp, 0, sizeof(*ecmp));
    ecmp->id = id;
    str_copy(ecmp->table, sizeof(ecmp->table), table);
    ecmp->vrid = vrid;
    str_copy(members, sizeof(members), argv[4]);
    tok = strtok_r(members, ",", &save);
    while (tok) {
        int nh = 0;
        if (ecmp->n_members >= L3_OWNER_MAX_ECMP_MEMBERS ||
            !parse_int_range(tok, 1, 65535, &nh) ||
            find_nexthop(plan, nh) < 0 ||
            strcmp(plan->nexthops[find_nexthop(plan, nh)].table,
                   table) != 0) {
            snprintf(err, err_size, "invalid ECMP member: %s", tok);
            return -1;
        }
        if (ecmp_has_member(ecmp, nh)) {
            snprintf(err, err_size, "duplicate ECMP member: %d", nh);
            return -1;
        }
        ecmp->members[ecmp->n_members++] = nh;
        tok = strtok_r(NULL, ",", &save);
    }
    if (ecmp->n_members == 0) {
        snprintf(err, err_size, "empty ECMP member list");
        return -1;
    }
    plan->n_ecmp++;
    return 0;
}

static int add_route(l3_plan *plan, char **argv, int argc,
                     char *err, size_t err_size) {
    int syntax_argc = argc;
    const char *table = "inet.0";
    int vrid = 0;
    int id;
    l3_route *route;

    if (argc >= 3 && strcmp(argv[argc - 2], "table") == 0) {
        table = argv[argc - 1];
        syntax_argc -= 2;
    }
    if (plan_scope(plan, table, &vrid, err, err_size) != 0)
        return -1;
    if (syntax_argc != 5 || strcmp(argv[1], "prefix") != 0 ||
        (strcmp(argv[3], "next-hop") != 0 && strcmp(argv[3], "ecmp") != 0)) {
        snprintf(err, err_size,
                 "route syntax: route prefix <ipv4/prefix> next-hop <id>|ecmp <id>");
        return -1;
    }
    if (plan->n_routes >= L3_OWNER_MAX_ROUTES) {
        snprintf(err, err_size, "too many routes");
        return -1;
    }
    if (!parse_ipv4_network_cidr(argv[2]) ||
        !ipv4_v1_unicast_cidr(argv[2], true) ||
        !parse_int_range(argv[4], 1, 65535, &id)) {
        snprintf(err, err_size,
                 "invalid route prefix or target: prefix must be a network address and IPv4 unicast");
        return -1;
    }
    if (find_route(plan, argv[2], table) >= 0) {
        snprintf(err, err_size, "duplicate route prefix: %s", argv[2]);
        return -1;
    }
    if (find_connected_route_prefix(plan, argv[2], table) >= 0) {
        snprintf(err, err_size,
                 "route prefix conflicts with connected RIF route: %s",
                 argv[2]);
        return -1;
    }
    if (strcmp(argv[3], "next-hop") == 0 &&
        (find_nexthop(plan, id) < 0 ||
         strcmp(plan->nexthops[find_nexthop(plan, id)].table, table) != 0)) {
        snprintf(err, err_size, "route references unknown next-hop: %d", id);
        return -1;
    }
    if (strcmp(argv[3], "ecmp") == 0 &&
        (find_ecmp(plan, id) < 0 ||
         strcmp(plan->ecmp[find_ecmp(plan, id)].table, table) != 0)) {
        snprintf(err, err_size, "route references unknown ECMP group: %d", id);
        return -1;
    }
    route = &plan->routes[plan->n_routes++];
    memset(route, 0, sizeof(*route));
    str_copy(route->prefix, sizeof(route->prefix), argv[2]);
    str_copy(route->table, sizeof(route->table), table);
    route->vrid = vrid;
    if (strcmp(argv[3], "next-hop") == 0)
        route->next_hop = id;
    else
        route->ecmp = id;
    return 0;
}

static int set_router_mac(l3_plan *plan, char **argv, int argc,
                          char *err, size_t err_size) {
    u8 mac[NL_MAC_ADDR_LEN];

    if (argc != 2) {
        snprintf(err, err_size, "router-mac syntax: router-mac <mac>");
        return -1;
    }
    if (!nl_platform_parse_mac(argv[1], mac)) {
        snprintf(err, err_size, "invalid router-mac: %s", argv[1]);
        return -1;
    }
    plan->has_router_mac = true;
    str_copy(plan->router_mac, sizeof(plan->router_mac), argv[1]);
    return 0;
}

static int l3_plan_parse(const char *text, l3_plan *plan,
                         char *err, size_t err_size) {
    char *copy;
    char *save = NULL;
    char *line;
    int line_no = 0;

    if (!text || !plan) {
        snprintf(err, err_size, "empty L3 plan");
        return -1;
    }
    memset(plan, 0, sizeof(*plan));
    plan->version = 1;
    copy = strdup(text);
    if (!copy) {
        snprintf(err, err_size, "out of memory");
        return -1;
    }

    line = strtok_r(copy, "\n", &save);
    while (line) {
        char *argv[16];
        int argc;
        char *t = trim(line);
        int rc = 0;

        line_no++;
        if (!t[0] || t[0] == '#') {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }
        argc = split_tokens(t, argv, 16);
        if (argc == 0) {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }
        if (strcmp(argv[0], "l3-plan") == 0) {
            if (argc != 2 ||
                (strcmp(argv[1], "version=1") != 0 &&
                 strcmp(argv[1], "version=2") != 0)) {
                snprintf(err, err_size, "line %d: unsupported plan version",
                         line_no);
                free(copy);
                return -1;
            }
            plan->version = strcmp(argv[1], "version=2") == 0 ? 2 : 1;
            line = strtok_r(NULL, "\n", &save);
            continue;
        } else if (strcmp(argv[0], "virtual-router") == 0) {
            if (plan->version != 2)
                rc = -1;
            else
                rc = add_virtual_router(plan, argv, argc, err, err_size);
            if (rc != 0 && !err[0])
                snprintf(err, err_size,
                         "virtual-router requires l3-plan version=2");
        } else if (strcmp(argv[0], "router-mac") == 0) {
            rc = set_router_mac(plan, argv, argc, err, err_size);
        } else if (strcmp(argv[0], "rif") == 0) {
            rc = add_rif(plan, argv, argc, err, err_size);
        } else if (strcmp(argv[0], "arp") == 0) {
            rc = add_arp(plan, argv, argc, err, err_size);
        } else if (strcmp(argv[0], "next-hop") == 0) {
            rc = add_nexthop(plan, argv, argc, err, err_size);
        } else if (strcmp(argv[0], "ecmp") == 0) {
            rc = add_ecmp(plan, argv, argc, err, err_size);
        } else if (strcmp(argv[0], "route") == 0) {
            rc = add_route(plan, argv, argc, err, err_size);
        } else {
            snprintf(err, err_size, "line %d: unknown L3 plan record: %s",
                     line_no, argv[0]);
            free(copy);
            return -1;
        }
        if (rc != 0) {
            char detail[256];
            snprintf(detail, sizeof(detail), "line %d: %s", line_no, err);
            str_copy(err, err_size, detail);
            free(copy);
            return -1;
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    if (plan->version == 1 && plan->has_virtual_router) {
        snprintf(err, err_size, "virtual-router requires plan version 2");
        return -1;
    }
    if (plan->n_rifs == 0 && plan->n_routes > 0) {
        snprintf(err, err_size, "routes require at least one RIF");
        return -1;
    }
    return 0;
}

static int send_text(nl_conn *conn, nl_msg_hdr *msg, s32 error_code,
                     const char *text) {
    size_t len = text ? strlen(text) : 0;
    nl_msg_hdr *resp = nl_msg_alloc((u32)len);

    if (!resp)
        return -1;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)len;
    if (len > 0)
        memcpy(resp->payload, text, len);
    nl_send(conn, resp);
    nl_msg_free(resp);
    return 0;
}

static void plan_summary(const l3_plan *plan, char *buf, size_t buf_size) {
    snprintf(buf, buf_size,
             "rifs=%d arp=%d next-hops=%d routes=%d ecmp-groups=%d",
             plan->n_rifs, plan->n_arps, plan->n_nexthops, plan->n_routes,
             plan->n_ecmp);
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

static int slice_len(int first, int last) {
    return first >= 0 && last >= first ? last - first + 1 : 0;
}

static int l3_plan_ecmp_member_count(const l3_plan *plan) {
    int total = 0;

    if (!plan)
        return 0;
    for (int i = 0; i < plan->n_ecmp; i++)
        total += plan->ecmp[i].n_members;
    return total;
}

static int l3_plan_connected_route_count(const l3_plan *plan) {
    return plan ? plan->n_rifs : 0;
}

static int l3_plan_hidden_route_count(const l3_plan *plan) {
    if (!plan)
        return 0;
    return plan->n_routes + l3_plan_connected_route_count(plan);
}

static bool capability_token_present(const char *capabilities,
                                     const char *wanted) {
    char tmp[128];
    char *save = NULL;
    char *tok;

    if (!capabilities || !wanted || !capabilities[0])
        return false;
    snprintf(tmp, sizeof(tmp), "%s", capabilities);
    tok = strtok_r(tmp, ",", &save);
    while (tok) {
        char *t = trim(tok);
        if (strcasecmp(t, wanted) == 0)
            return true;
        tok = strtok_r(NULL, ",", &save);
    }
    return false;
}

static void l3_resource_model_build_uncached(l3_resource_model *model,
                                             const char *profile_path) {
    nl_ffu_slice_allocation ffu;
    nl_port_entry *ports;
    int n_ports;

    memset(model, 0, sizeof(*model));
    model->rif_capacity = L3_OWNER_PROFILE_RIF_CAPACITY;
    model->arp_capacity = L3_OWNER_PROFILE_ARP_CAPACITY;
    model->nexthop_capacity = L3_OWNER_PROFILE_NEXTHOP_CAPACITY;
    model->ecmp_capacity = L3_OWNER_PROFILE_ECMP_CAPACITY;
    model->ecmp_member_capacity = L3_OWNER_PROFILE_ECMP_MEMBER_CAPACITY;

    if (nl_ifid_resolver_init(profile_path) != NL_OK) {
        snprintf(model->reason, sizeof(model->reason),
                 "platform profile failed to load");
        return;
    }
    model->profile_loaded = true;
    str_copy(model->profile_path, sizeof(model->profile_path),
             nl_platform_loaded_profile());

    if (!nl_platform_ffu_slices(&ffu)) {
        snprintf(model->reason, sizeof(model->reason),
                 "platform profile has no FFU slice allocation");
        return;
    }
    model->route_slice_count =
        slice_len(ffu.ipv4_uc_first, ffu.ipv4_uc_last) +
        slice_len(ffu.ipv4_mc_first, ffu.ipv4_mc_last) +
        slice_len(ffu.ipv6_uc_first, ffu.ipv6_uc_last) +
        slice_len(ffu.ipv6_mc_first, ffu.ipv6_mc_last);
    model->route_capacity =
        model->route_slice_count * L3_OWNER_PROFILE_ROUTE_ENTRIES_PER_SLICE;

    ports = calloc(NL_MAX_PORTS_PER_PROFILE, sizeof(*ports));
    if (!ports) {
        snprintf(model->reason, sizeof(model->reason),
                 "platform profile port inventory allocation failed");
        return;
    }
    n_ports = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_ports; i++) {
        if (!(ports[i].flags & NL_PORT_FLAG_EXTERNAL))
            continue;
        model->external_ports++;
        if (capability_token_present(ports[i].capabilities, "ROUTE"))
            model->route_capable_ports++;
    }
    free(ports);

    if (model->route_slice_count <= 0) {
        snprintf(model->reason, sizeof(model->reason),
                 "platform profile has no enabled route slices");
        return;
    }
    if (model->route_capable_ports <= 0) {
        snprintf(model->reason, sizeof(model->reason),
                 "platform profile has no external ROUTE capability");
        return;
    }

    model->l3_ready = true;
    snprintf(model->reason, sizeof(model->reason),
             "profile route resources available");
}

static void l3_resource_model_build(nl_l3_owner *owner,
                                    l3_resource_model *model,
                                    const char *profile_path) {
    const char *profile_key = profile_path && profile_path[0] ?
        profile_path : "<default>";
    bool cacheable = strlen(profile_key) <
        sizeof(owner->resource_profile_key);

    pthread_mutex_lock(&owner->resource_model_lock);
    if (cacheable && owner->resource_model_cached &&
        strcmp(owner->resource_profile_key, profile_key) == 0) {
        *model = owner->resource_model_cache;
        pthread_mutex_unlock(&owner->resource_model_lock);
        return;
    }

    pthread_mutex_lock(&g_platform_profile_lock);
    l3_resource_model_build_uncached(model, profile_path);
    pthread_mutex_unlock(&g_platform_profile_lock);
    if (cacheable && model->profile_loaded) {
        owner->resource_model_cache = *model;
        str_copy(owner->resource_profile_key,
                 sizeof(owner->resource_profile_key), profile_key);
        owner->resource_model_cached = true;
    }
    pthread_mutex_unlock(&owner->resource_model_lock);
}

static int l3_resource_model_validate_plan(const l3_resource_model *model,
                                           const l3_plan *plan,
                                           char *err, size_t err_size) {
    int ecmp_members = l3_plan_ecmp_member_count(plan);
    int route_count = l3_plan_hidden_route_count(plan);

    if (!model->l3_ready) {
        snprintf(err, err_size, "%s", model->reason[0] ?
                 model->reason : "platform profile is not L3-ready");
        return -1;
    }
    if (plan->n_rifs > model->rif_capacity) {
        snprintf(err, err_size, "RIF capacity exceeded: required=%d capacity=%d",
                 plan->n_rifs, model->rif_capacity);
        return -1;
    }
    if (plan->n_arps > model->arp_capacity) {
        snprintf(err, err_size, "ARP capacity exceeded: required=%d capacity=%d",
                 plan->n_arps, model->arp_capacity);
        return -1;
    }
    if (plan->n_nexthops > model->nexthop_capacity) {
        snprintf(err, err_size,
                 "next-hop capacity exceeded: required=%d capacity=%d",
                 plan->n_nexthops, model->nexthop_capacity);
        return -1;
    }
    if (route_count > model->route_capacity) {
        snprintf(err, err_size,
                 "FIB route capacity exceeded: required=%d capacity=%d",
                 route_count, model->route_capacity);
        return -1;
    }
    if (plan->n_ecmp > model->ecmp_capacity) {
        snprintf(err, err_size,
                 "ECMP group capacity exceeded: required=%d capacity=%d",
                 plan->n_ecmp, model->ecmp_capacity);
        return -1;
    }
    if (ecmp_members > model->ecmp_member_capacity) {
        snprintf(err, err_size,
                 "ECMP member capacity exceeded: required=%d capacity=%d",
                 ecmp_members, model->ecmp_member_capacity);
        return -1;
    }
    return 0;
}

static int l3_resource_free(int capacity, int used) {
    return capacity > used ? capacity - used : 0;
}

static int l3_resource_delta_xml(const l3_plan *pre,
                                 const l3_plan *post,
                                 const l3_resource_model *model,
                                 char *buf, size_t buf_size) {
    int pre_rifs = pre ? pre->n_rifs : 0;
    int pre_arps = pre ? pre->n_arps : 0;
    int pre_nexthops = pre ? pre->n_nexthops : 0;
    int pre_routes = l3_plan_hidden_route_count(pre);
    int pre_ecmp = pre ? pre->n_ecmp : 0;
    int pre_ecmp_members = l3_plan_ecmp_member_count(pre);
    int post_rifs = post ? post->n_rifs : 0;
    int post_arps = post ? post->n_arps : 0;
    int post_nexthops = post ? post->n_nexthops : 0;
    int post_routes = l3_plan_hidden_route_count(post);
    int post_ecmp = post ? post->n_ecmp : 0;
    int post_ecmp_members = l3_plan_ecmp_member_count(post);

    return snprintf(buf, buf_size,
                    "<l3-resource-delta mode=\"hidden\" "
                    "hardware-apply=\"disabled\" sdk-readback=\"disabled\">"
                    "<resource name=\"rif\" pre=\"%d\" used=\"%d\" "
                    "delta=\"%d\" capacity=\"%d\" free=\"%d\"/>"
                    "<resource name=\"arp\" pre=\"%d\" used=\"%d\" "
                    "delta=\"%d\" capacity=\"%d\" free=\"%d\"/>"
                    "<resource name=\"next-hop\" pre=\"%d\" used=\"%d\" "
                    "delta=\"%d\" capacity=\"%d\" free=\"%d\"/>"
                    "<resource name=\"route\" pre=\"%d\" used=\"%d\" "
                    "delta=\"%d\" capacity=\"%d\" free=\"%d\" "
                    "route-slices=\"%d\"/>"
                    "<resource name=\"ecmp-group\" pre=\"%d\" used=\"%d\" "
                    "delta=\"%d\" capacity=\"%d\" free=\"%d\"/>"
                    "<resource name=\"ecmp-member\" pre=\"%d\" used=\"%d\" "
                    "delta=\"%d\" capacity=\"%d\" free=\"%d\"/>"
                    "</l3-resource-delta>",
                    pre_rifs, post_rifs, post_rifs - pre_rifs,
                    model->rif_capacity,
                    l3_resource_free(model->rif_capacity, post_rifs),
                    pre_arps, post_arps, post_arps - pre_arps,
                    model->arp_capacity,
                    l3_resource_free(model->arp_capacity, post_arps),
                    pre_nexthops, post_nexthops,
                    post_nexthops - pre_nexthops,
                    model->nexthop_capacity,
                    l3_resource_free(model->nexthop_capacity, post_nexthops),
                    pre_routes, post_routes, post_routes - pre_routes,
                    model->route_capacity,
                    l3_resource_free(model->route_capacity, post_routes),
                    model->route_slice_count,
                    pre_ecmp, post_ecmp, post_ecmp - pre_ecmp,
                    model->ecmp_capacity,
                    l3_resource_free(model->ecmp_capacity, post_ecmp),
                    pre_ecmp_members, post_ecmp_members,
                    post_ecmp_members - pre_ecmp_members,
                    model->ecmp_member_capacity,
                    l3_resource_free(model->ecmp_member_capacity,
                                     post_ecmp_members));
}

static int l3_plan_inventory_emit_count(int count) {
    if (count <= 0)
        return 0;
    return count > L3_OWNER_INVENTORY_EMIT_LIMIT ? L3_OWNER_INVENTORY_EMIT_LIMIT : count;
}

static bool l3_plan_inventory_truncated(const l3_plan *plan) {
    if (!plan)
        return false;
    return plan->n_rifs > L3_OWNER_INVENTORY_EMIT_LIMIT ||
           plan->n_arps > L3_OWNER_INVENTORY_EMIT_LIMIT ||
           plan->n_nexthops > L3_OWNER_INVENTORY_EMIT_LIMIT ||
           plan->n_ecmp > L3_OWNER_INVENTORY_EMIT_LIMIT ||
           l3_plan_hidden_route_count(plan) > L3_OWNER_INVENTORY_EMIT_LIMIT;
}

static int l3_plan_inventory_xml(const nl_l3_owner *owner,
                                 const l3_plan *plan, char *buf,
                                 size_t buf_size) {
    size_t off = 0;
    bool truncated = l3_plan_inventory_truncated(plan);
    int route_count;
    int routes_remaining;

    if (!plan || !buf || buf_size == 0)
        return -1;
    buf[0] = '\0';
    route_count = l3_plan_hidden_route_count(plan);
    routes_remaining = l3_plan_inventory_emit_count(route_count);
    if (appendf(buf, buf_size, &off,
                "<inventory source=\"%s\" mode=\"production\" "
                "hardware-apply=\"persistent\" sdk-readback=\"live\" "
                "complete=\"%s\" emit-limit=\"%d\">"
                "<family name=\"rif\" count=\"%d\" emitted=\"%d\"/>"
                "<family name=\"arp\" count=\"%d\" emitted=\"%d\"/>"
                "<family name=\"next-hop\" count=\"%d\" emitted=\"%d\"/>"
                "<family name=\"ecmp\" count=\"%d\" emitted=\"%d\" "
                "members=\"%d\"/>"
                "<family name=\"route\" count=\"%d\" emitted=\"%d\"/>",
                owner->authority_name,
                truncated ? "false" : "true", L3_OWNER_INVENTORY_EMIT_LIMIT,
                plan->n_rifs, l3_plan_inventory_emit_count(plan->n_rifs),
                plan->n_arps, l3_plan_inventory_emit_count(plan->n_arps),
                plan->n_nexthops,
                l3_plan_inventory_emit_count(plan->n_nexthops),
                plan->n_ecmp, l3_plan_inventory_emit_count(plan->n_ecmp),
                l3_plan_ecmp_member_count(plan),
                route_count,
                l3_plan_inventory_emit_count(route_count)) != 0)
        return -1;
    for (int i = 0; i < l3_plan_inventory_emit_count(plan->n_rifs); i++)
        if (appendf(buf, buf_size, &off,
                    "<object family=\"rif\" key=\"%s\" vlan=\"%d\" "
                    "port=\"%s\" address=\"%s\" state=\"hidden\"/>",
                    plan->rifs[i].name, plan->rifs[i].vlan,
                    plan->rifs[i].port[0] ? plan->rifs[i].port : "-",
                    plan->rifs[i].address) != 0)
            return -1;
    for (int i = 0; i < l3_plan_inventory_emit_count(plan->n_arps); i++)
        if (appendf(buf, buf_size, &off,
                    "<object family=\"arp\" key=\"%s/%s\" ip=\"%s\" "
                    "mac=\"%s\" rif=\"%s\" egress-port=\"%s\" "
                    "state=\"hidden\"/>",
                    plan->arps[i].rif, plan->arps[i].ip,
                    plan->arps[i].ip, plan->arps[i].mac,
                    plan->arps[i].rif,
                    plan->arps[i].egress_port[0] ?
                    plan->arps[i].egress_port : "-") != 0)
            return -1;
    for (int i = 0; i < l3_plan_inventory_emit_count(plan->n_nexthops); i++)
        if (appendf(buf, buf_size, &off,
                    "<object family=\"next-hop\" key=\"%d\" arp=\"%s\" "
                    "rif=\"%s\" depends-on=\"arp:%s/%s\" "
                    "state=\"hidden\"/>",
                    plan->nexthops[i].id, plan->nexthops[i].arp_ip,
                    plan->nexthops[i].rif, plan->nexthops[i].rif,
                    plan->nexthops[i].arp_ip) != 0)
            return -1;
    for (int i = 0; i < l3_plan_inventory_emit_count(plan->n_ecmp); i++) {
        if (appendf(buf, buf_size, &off,
                    "<object family=\"ecmp\" key=\"%d\" members=\"",
                    plan->ecmp[i].id) != 0)
            return -1;
        for (int j = 0; j < plan->ecmp[i].n_members; j++)
            if (appendf(buf, buf_size, &off, "%s%d",
                        j == 0 ? "" : ",", plan->ecmp[i].members[j]) != 0)
                return -1;
        if (appendf(buf, buf_size, &off, "\" state=\"hidden\"/>") != 0)
            return -1;
    }
    for (int i = 0; i < plan->n_rifs && routes_remaining > 0; i++) {
        char prefix[40];

        if (!ipv4_cidr_network_string(plan->rifs[i].address,
                                      prefix, sizeof(prefix)))
            return -1;
        if (appendf(buf, buf_size, &off,
                    "<object family=\"route\" key=\"%s\" prefix=\"%s\" "
                    "protocol=\"connected\" target-type=\"rif\" "
                    "target-id=\"%s\" rif=\"%s\" state=\"hidden\"/>",
                    prefix, prefix, plan->rifs[i].name,
                    plan->rifs[i].name) != 0)
            return -1;
        routes_remaining--;
    }
    for (int i = 0; i < plan->n_routes && routes_remaining > 0; i++) {
        const char *target_type = plan->routes[i].ecmp > 0 ?
            "ecmp" : "next-hop";
        int target_id = plan->routes[i].ecmp > 0 ?
            plan->routes[i].ecmp : plan->routes[i].next_hop;

        if (appendf(buf, buf_size, &off,
                    "<object family=\"route\" key=\"%s\" prefix=\"%s\" "
                    "protocol=\"static\" target-type=\"%s\" "
                    "target-id=\"%d\" state=\"hidden\"/>",
                    plan->routes[i].prefix, plan->routes[i].prefix,
                    target_type, target_id) != 0)
            return -1;
        routes_remaining--;
    }
    if (truncated &&
        appendf(buf, buf_size, &off,
                "<truncated reason=\"emit-limit\"/>") != 0)
        return -1;
    if (appendf(buf, buf_size, &off, "</inventory>") != 0)
        return -1;
    return 0;
}

static int l3_resource_xml(const l3_plan *plan,
                           const l3_resource_model *model,
                           const char *status,
                           const char *reason,
                           char *buf, size_t buf_size) {
    int ecmp_members = l3_plan_ecmp_member_count(plan);
    int route_count = l3_plan_hidden_route_count(plan);
    char delta[2048];
    int dn;

    dn = l3_resource_delta_xml(NULL, plan, model, delta, sizeof(delta));
    if (dn < 0 || (size_t)dn >= sizeof(delta))
        return -1;

    return snprintf(buf, buf_size,
                    "<l3-resource-check status=\"%s\" "
                    "profile=\"%s\" profile-l3-ready=\"%s\" "
                    "hardware-apply=\"disabled\" config-open=\"false\" "
                    "reason=\"%s\">"
                    "<usage rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                    "routes=\"%d\" ecmp-groups=\"%d\" "
                    "ecmp-members=\"%d\"/>"
                    "<capacity rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                    "routes=\"%d\" route-slices=\"%d\" "
                    "ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                    "<parser-limit rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                    "routes=\"%d\" ecmp-groups=\"%d\" "
                    "ecmp-members-per-group=\"%d\"/>"
                    "%s"
                    "<ports external=\"%d\" route-capable=\"%d\"/>"
                    "</l3-resource-check>",
                    status,
                    model->profile_path[0] ? model->profile_path : "unloaded",
                    model->l3_ready ? "true" : "false",
                    reason ? reason : "",
                    plan->n_rifs, plan->n_arps, plan->n_nexthops,
                    route_count, plan->n_ecmp, ecmp_members,
                    model->rif_capacity, model->arp_capacity,
                    model->nexthop_capacity, model->route_capacity,
                    model->route_slice_count, model->ecmp_capacity,
                    model->ecmp_member_capacity,
                    L3_OWNER_MAX_RIFS, L3_OWNER_MAX_ARP, L3_OWNER_MAX_NEXTHOPS,
                    L3_OWNER_MAX_ROUTES, L3_OWNER_MAX_ECMP, L3_OWNER_MAX_ECMP_MEMBERS,
                    delta,
                    model->external_ports, model->route_capable_ports);
}

static int l3_resource_check_plan(nl_l3_owner *owner,
                                  const l3_plan *plan,
                                  const char *profile_path,
                                  char *xml, size_t xml_size,
                                  char *err, size_t err_size) {
    l3_resource_model model;
    char reason[256] = {0};
    int n;

    l3_resource_model_build(owner, &model, profile_path);
    if (l3_resource_model_validate_plan(&model, plan,
                                        reason, sizeof(reason)) != 0) {
        n = l3_resource_xml(plan, &model, "invalid", reason, xml, xml_size);
        if (n < 0 || (size_t)n >= xml_size)
            snprintf(err, err_size, "resource XML exceeds buffer");
        else
            snprintf(err, err_size, "%s", reason);
        return -1;
    }

    n = l3_resource_xml(plan, &model, "ok", model.reason, xml, xml_size);
    if (n < 0 || (size_t)n >= xml_size) {
        snprintf(err, err_size, "resource XML exceeds buffer");
        return -1;
    }
    return 0;
}

static int l3_plan_compile_transaction(const l3_plan *plan, char *buf,
                                       size_t buf_size,
                                       char *err, size_t err_size) {
    size_t off = 0;

    if (!plan || !buf || buf_size == 0) {
        snprintf(err, err_size, "invalid compile buffer");
        return -1;
    }
    buf[0] = '\0';
    if (appendf(buf, buf_size, &off,
                "# netlab-l3-transaction version=%d hardware-apply=disabled\n",
                plan->has_virtual_router ? 2 : 1) != 0)
        goto overflow;
    if (plan->has_router_mac &&
        (plan->n_rifs || plan->n_arps || plan->n_nexthops ||
         plan->n_routes || plan->n_ecmp)) {
        if (appendf(buf, buf_size, &off,
                    "l3-router-set mac=%s\n", plan->router_mac) != 0)
            goto overflow;
    }
    if (plan->has_virtual_router &&
        appendf(buf, buf_size, &off,
                "l3-virtual-router-set name=%s table=%s vrid=%d kernel-table=%d\n",
                plan->virtual_router_name, plan->virtual_router_table,
                plan->virtual_router_id,
                plan->virtual_router_kernel_table) != 0)
        goto overflow;
    for (int i = 0; i < plan->n_rifs; i++) {
        if (appendf(buf, buf_size, &off,
                    "l3-rif-set name=%s vlan=%d",
                    plan->rifs[i].name, plan->rifs[i].vlan) != 0)
            goto overflow;
        if (plan->rifs[i].port[0] &&
            appendf(buf, buf_size, &off, " port=%s",
                    plan->rifs[i].port) != 0)
            goto overflow;
        if (appendf(buf, buf_size, &off, " address=%s table=%s vrid=%d\n",
                    plan->rifs[i].address, plan->rifs[i].table,
                    plan->rifs[i].vrid) != 0)
            goto overflow;
    }
    for (int i = 0; i < plan->n_arps; i++) {
        if (appendf(buf, buf_size, &off,
                    "l3-arp-set ip=%s mac=%s rif=%s",
                    plan->arps[i].ip, plan->arps[i].mac,
                    plan->arps[i].rif) != 0)
            goto overflow;
        if (plan->arps[i].egress_port[0] &&
            appendf(buf, buf_size, &off, " egress-port=%s",
                    plan->arps[i].egress_port) != 0)
            goto overflow;
        if (appendf(buf, buf_size, &off, " table=%s vrid=%d\n",
                    plan->arps[i].table, plan->arps[i].vrid) != 0)
            goto overflow;
    }
    for (int i = 0; i < plan->n_nexthops; i++) {
        if (appendf(buf, buf_size, &off,
                    "l3-next-hop-set id=%d arp=%s rif=%s table=%s vrid=%d\n",
                    plan->nexthops[i].id, plan->nexthops[i].arp_ip,
                    plan->nexthops[i].rif, plan->nexthops[i].table,
                    plan->nexthops[i].vrid) != 0)
            goto overflow;
    }
    for (int i = 0; i < plan->n_ecmp; i++) {
        if (appendf(buf, buf_size, &off, "l3-ecmp-set id=%d members=",
                    plan->ecmp[i].id) != 0)
            goto overflow;
        for (int j = 0; j < plan->ecmp[i].n_members; j++) {
            if (appendf(buf, buf_size, &off, "%s%d",
                        j == 0 ? "" : ",", plan->ecmp[i].members[j]) != 0)
                goto overflow;
        }
        if (appendf(buf, buf_size, &off, " table=%s vrid=%d\n",
                    plan->ecmp[i].table, plan->ecmp[i].vrid) != 0)
            goto overflow;
    }
    for (int i = 0; i < plan->n_rifs; i++) {
        char prefix[40];

        if (!ipv4_cidr_network_string(plan->rifs[i].address,
                                      prefix, sizeof(prefix))) {
            snprintf(err, err_size, "invalid connected RIF prefix: %s",
                     plan->rifs[i].address);
            return -1;
        }
        if (appendf(buf, buf_size, &off,
                    "l3-route-set prefix=%s rif=%s table=%s vrid=%d\n",
                    prefix, plan->rifs[i].name, plan->rifs[i].table,
                    plan->rifs[i].vrid) != 0)
            goto overflow;
    }
    for (int i = 0; i < plan->n_routes; i++) {
        if (plan->routes[i].next_hop > 0) {
            if (appendf(buf, buf_size, &off,
                        "l3-route-set prefix=%s next-hop=%d table=%s vrid=%d\n",
                        plan->routes[i].prefix,
                        plan->routes[i].next_hop, plan->routes[i].table,
                        plan->routes[i].vrid) != 0)
                goto overflow;
        } else {
            if (appendf(buf, buf_size, &off,
                        "l3-route-set prefix=%s ecmp=%d table=%s vrid=%d\n",
                        plan->routes[i].prefix,
                        plan->routes[i].ecmp, plan->routes[i].table,
                        plan->routes[i].vrid) != 0)
                goto overflow;
        }
    }
    return 0;

overflow:
    snprintf(err, err_size, "compiled transaction exceeds %zu bytes",
             buf_size);
    return -1;
}

static int handle_show(nl_l3_owner *owner, nl_conn *conn,
                       nl_msg_hdr *msg) {
    l3_resource_model model;
    const char *user_config;
    const char *boundary_reason;
    char xml[2048];

    l3_resource_model_build(owner, &model, NULL);
    user_config = model.l3_ready ? "open" : "chassis-mode-gated";
    boundary_reason = model.l3_ready ?
        owner->public_reason :
        (model.reason[0] ? model.reason :
         "active L3 chassis mode is not ready");
    snprintf(xml, sizeof(xml),
             "<l3-owner state=\"ready\" mode=\"production\" authority=\"%s\" "
             "config-open=\"%s\" "
             "owner-mode=\"%s\" hardware-apply=\"%s\" "
             "sdk-readback=\"%s\" generation=\"%d\" "
             "last-load=\"%ld\" transaction-state=\"%s\" "
             "rollback-available=\"%s\" hw-sync=\"%s\" "
             "persistent-hw-out-of-sync=\"%s\" "
             "block-future-commits=\"%s\" tx-id=\"%llu\">"
             "<plan rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
             "routes=\"%d\" ecmp-groups=\"%d\"/>"
             "<hardware-state sync=\"%s\" reason=\"%s\"/>"
             "<boundary user-config=\"%s\" reason=\"%s\"/>"
             "</l3-owner>",
             owner->authority_name,
             model.l3_ready ? "true" : "false",
             l3_owner_mode_name(owner->state.owner_mode),
             l3_owner_hardware_apply(owner->state.owner_mode),
             l3_owner_sdk_readback(owner->state.owner_mode),
             owner->state.generation, (long)owner->state.last_load,
             l3_tx_state_name(owner->state.tx_state),
             owner->state.rollback_available ? "true" : "false",
             owner->state.hw_out_of_sync ? "out-of-sync" : "in-sync",
             owner->state.hw_out_of_sync ? "true" : "false",
             owner->state.hw_out_of_sync ? "true" : "false",
             (unsigned long long)owner->state.last_tx_id,
             owner->state.plan.n_rifs, owner->state.plan.n_arps,
             owner->state.plan.n_nexthops, owner->state.plan.n_routes,
             owner->state.plan.n_ecmp,
             owner->state.hw_out_of_sync ? "out-of-sync" : "in-sync",
             owner->state.hw_out_of_sync_reason[0] ?
                 owner->state.hw_out_of_sync_reason : "none",
             user_config, boundary_reason);
    return send_text(conn, msg, 0, xml);
}

static int handle_readback(nl_l3_owner *owner, nl_conn *conn,
                           nl_msg_hdr *msg) {
    l3_resource_model model;
    const char *user_config;
    const char *boundary_reason;
    int ecmp_members = l3_plan_ecmp_member_count(&owner->state.plan);
    int routes = l3_plan_hidden_route_count(&owner->state.plan);
    int pre_routes = l3_plan_hidden_route_count(&owner->state.pre_plan);
    char switchd_resp[32768];
    char switchd_owner[33280];
    char delta[2048];
    char inventory[8192];
    char xml[L3_OWNER_TX_MAX_BYTES];
    s32 switchd_ec = 0;
    int dn;

    l3_resource_model_build(owner, &model, NULL);
    user_config = model.l3_ready ? "open" : "chassis-mode-gated";
    boundary_reason = model.l3_ready ?
        owner->public_reason :
        (model.reason[0] ? model.reason :
         "active L3 chassis mode is not ready");
    dn = l3_resource_delta_xml(&owner->state.pre_plan, &owner->state.plan, &model,
                               delta, sizeof(delta));
    if (dn < 0 || (size_t)dn >= sizeof(delta))
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: l3-owner resource delta response overflow");
    if (l3_plan_inventory_xml(owner, &owner->state.plan, inventory,
                              sizeof(inventory)) != 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: l3-owner inventory response overflow");
    if (switchd_l3_transaction_call(owner,
            (owner->state.owner_mode == L3_OWNER_PERSISTENT ||
             owner->state.hw_out_of_sync) ?
                NL_SWITCHD_L3_PERSISTENT_READBACK :
                NL_SWITCHD_L3_TX_READBACK,
            owner->state.last_tx_id, NULL,
                                    switchd_resp, sizeof(switchd_resp),
                                    &switchd_ec) == 0) {
        snprintf(switchd_owner, sizeof(switchd_owner),
                 "<switchd-owner status=\"%s\" ec=\"%d\">%s</switchd-owner>",
                 switchd_ec == 0 ? "ok" : "error",
                 switchd_ec, switchd_resp);
    } else {
        snprintf(switchd_owner, sizeof(switchd_owner),
                 "<switchd-owner status=\"unavailable\"/>");
    }
    snprintf(xml, sizeof(xml),
             "<persistent-l3-owner-readback state=\"ready\" "
             "mode=\"production\" authority=\"%s\" "
             "config-open=\"%s\" owner-mode=\"%s\" "
             "hardware-apply=\"%s\" sdk-readback=\"%s\" "
             "generation=\"%d\" last-load=\"%ld\" last-apply=\"%ld\" "
             "last-rollback=\"%ld\" transaction-state=\"%s\" "
             "rollback-available=\"%s\" hw-sync=\"%s\" "
             "persistent-hw-out-of-sync=\"%s\" "
             "block-future-commits=\"%s\" tx-id=\"%llu\">"
             "<profile path=\"%s\" l3-ready=\"%s\" reason=\"%s\" "
             "external-ports=\"%d\" route-capable-ports=\"%d\"/>"
             "<usage rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
             "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
             "<capacity rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
             "routes=\"%d\" route-slices=\"%d\" ecmp-groups=\"%d\" "
             "ecmp-members=\"%d\"/>"
             "<pre-state rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
             "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
             "%s"
             "%s"
             "%s"
             "<hardware-state sync=\"%s\" reason=\"%s\"/>"
             "<boundary user-config=\"%s\" reason=\"%s\"/>"
             "</persistent-l3-owner-readback>",
             owner->authority_name,
             model.l3_ready ? "true" : "false",
             l3_owner_mode_name(owner->state.owner_mode),
             l3_owner_hardware_apply(owner->state.owner_mode),
             l3_owner_sdk_readback(owner->state.owner_mode),
             owner->state.generation, (long)owner->state.last_load,
             (long)owner->state.last_apply, (long)owner->state.last_rollback,
             l3_tx_state_name(owner->state.tx_state),
             owner->state.rollback_available ? "true" : "false",
             owner->state.hw_out_of_sync ? "out-of-sync" : "in-sync",
             owner->state.hw_out_of_sync ? "true" : "false",
             owner->state.hw_out_of_sync ? "true" : "false",
             (unsigned long long)owner->state.last_tx_id,
             model.profile_path[0] ? model.profile_path : "unloaded",
             model.l3_ready ? "true" : "false",
             model.reason[0] ? model.reason : "unknown",
             model.external_ports, model.route_capable_ports,
             owner->state.plan.n_rifs, owner->state.plan.n_arps,
             owner->state.plan.n_nexthops, routes,
             owner->state.plan.n_ecmp, ecmp_members,
             model.rif_capacity, model.arp_capacity,
             model.nexthop_capacity, model.route_capacity,
             model.route_slice_count, model.ecmp_capacity,
             model.ecmp_member_capacity,
             owner->state.pre_plan.n_rifs, owner->state.pre_plan.n_arps,
             owner->state.pre_plan.n_nexthops, pre_routes,
             owner->state.pre_plan.n_ecmp,
             l3_plan_ecmp_member_count(&owner->state.pre_plan),
             delta,
             inventory,
             switchd_owner,
             owner->state.hw_out_of_sync ? "out-of-sync" : "in-sync",
             owner->state.hw_out_of_sync_reason[0] ?
                 owner->state.hw_out_of_sync_reason : "none",
             user_config, boundary_reason);
    return send_text(conn, msg, 0, xml);
}

static int switchd_l3_transaction_call(nl_l3_owner *owner,
                                       nl_rpc_method method,
                                       u64 tx_id,
                                       const char *payload,
                                       char *resp, size_t resp_size,
                                       s32 *switchd_ec) {
    int payload_len = payload ? (int)strlen(payload) : 0;
    int rn;

    if (!resp || resp_size == 0 || !switchd_ec)
        return -1;
    resp[0] = '\0';
    *switchd_ec = 0;
    rn = nl_rpc_call_ex(owner->switchd_socket_path,
                        owner->switchd_caller_daemon,
                        NL_DAEMON_SWITCHD, method, tx_id,
                        payload ? (const u8 *)payload : NULL,
                        payload_len, (u8 *)resp, resp_size - 1,
                        5000, switchd_ec);
    if (rn < 0)
        return -1;
    resp[rn] = '\0';
    return 0;
}

static int handle_resource_check(nl_l3_owner *owner, nl_conn *conn,
                                 nl_msg_hdr *msg) {
    char *text;
    l3_plan *plan;
    char err[256] = {0};
    char xml[4096];
    int rc;

    plan = calloc(1, sizeof(*plan));
    if (!plan)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: l3-owner plan allocation failed");
    text = calloc(1, (size_t)msg->payload_len + 1);
    if (!text) {
        free(plan);
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: l3-owner out of memory");
    }
    if (msg->payload_len > 0)
        memcpy(text, msg->payload, msg->payload_len);
    if (l3_plan_parse(text, plan, err, sizeof(err)) != 0) {
        char detail[320];
        snprintf(detail, sizeof(detail), "error: l3-owner plan invalid: %s",
                 err[0] ? err : "invalid plan");
        free(text);
        free(plan);
        return send_text(conn, msg, NL_ERR_INVALID_VALUE, detail);
    }
    free(text);
    rc = l3_resource_check_plan(owner, plan, NULL, xml, sizeof(xml),
                                err, sizeof(err));
    free(plan);
    return send_text(conn, msg, rc == 0 ? 0 : NL_ERR_INVALID_VALUE, xml);
}

static bool l3_plan_is_empty(const l3_plan *plan) {
    return !plan || (plan->n_rifs == 0 && plan->n_arps == 0 &&
                     plan->n_nexthops == 0 && plan->n_routes == 0 &&
                     plan->n_ecmp == 0);
}

static int l3_owner_rollback_current_owner(nl_l3_owner *owner, char *resp,
                                           size_t resp_size,
                                           s32 *switchd_ec) {
    const char *ack = "ack=NETLAB_ENABLE_L3_PERSISTENT_OWNER\n";

    if (!resp || resp_size == 0 || !switchd_ec)
        return -1;
    resp[0] = '\0';
    *switchd_ec = 0;
    if (owner->state.owner_mode == L3_OWNER_PERSISTENT) {
        return switchd_l3_transaction_call(
            owner, NL_SWITCHD_L3_PERSISTENT_ROLLBACK,
                                           owner->state.last_tx_id, ack,
                                           resp, resp_size, switchd_ec);
    }
    if (owner->state.owner_mode == L3_OWNER_SYNTHETIC) {
        return switchd_l3_transaction_call(owner, NL_SWITCHD_L3_TX_ROLLBACK,
                                           owner->state.last_tx_id, NULL,
                                           resp, resp_size, switchd_ec);
    }
    return 0;
}

static int l3_owner_apply_persistent_to_switchd(nl_l3_owner *owner,
                                                u64 tx_id, const char *tx,
                                                char *resp, size_t resp_size,
                                                s32 *switchd_ec) {
    char *payload;
    int n;
    int rc;

    if (!tx || !resp || resp_size == 0 || !switchd_ec)
        return -1;
    payload = calloc(1, strlen(tx) + 64);
    if (!payload)
        return -1;
    n = snprintf(payload, strlen(tx) + 64,
                 "ack=NETLAB_ENABLE_L3_PERSISTENT_OWNER\n%s", tx);
    if (n < 0 || (size_t)n >= strlen(tx) + 64) {
        free(payload);
        return -1;
    }
    rc = switchd_l3_transaction_call(
        owner, NL_SWITCHD_L3_PERSISTENT_APPLY, tx_id, payload,
                                     resp, resp_size, switchd_ec);
    free(payload);
    return rc;
}

static bool l3_owner_switchd_readback_matches_plan(const l3_plan *plan,
                                                   const char *resp) {
    const char *usage;
    int rifs = -1;
    int arps = -1;
    int nexthops = -1;
    int ecmp = -1;
    int fib_routes = -1;
    int connected = -1;

    if (!plan || !resp)
        return false;
    if (l3_plan_is_empty(plan)) {
        if (!strstr(resp, "<l3-persistent-owner-readback status=\"empty\"") ||
            !strstr(resp, "applied=\"false\""))
            return false;
    } else if (!strstr(
                   resp, "<l3-persistent-owner-readback status=\"ok\"") ||
               !strstr(resp, "applied=\"true\"")) {
        return false;
    }
    usage = strstr(resp, "<usage ");
    if (!usage || sscanf(
            usage, "<usage rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
            "ecmp-groups=\"%d\" fib-routes=\"%d\" "
            "connected-route-intent=\"%d\"",
            &rifs, &arps, &nexthops, &ecmp, &fib_routes, &connected) != 6)
        return false;
    return rifs == plan->n_rifs && arps == plan->n_arps &&
           nexthops == plan->n_nexthops && ecmp == plan->n_ecmp &&
           fib_routes == plan->n_routes && connected == plan->n_rifs;
}

static int l3_owner_verify_persistent_plan(nl_l3_owner *owner,
                                           const l3_plan *plan, u64 tx_id,
                                           char *resp, size_t resp_size,
                                           s32 *verify_ec) {
    if (!resp || resp_size == 0 || !verify_ec)
        return -1;
    if (switchd_l3_transaction_call(
            owner, NL_SWITCHD_L3_PERSISTENT_READBACK, tx_id, NULL,
            resp, resp_size, verify_ec) != 0) {
        *verify_ec = NL_ERR_DAEMON_UNREACHABLE;
        return -1;
    }
    if (*verify_ec != 0)
        return -1;
    if (!l3_owner_switchd_readback_matches_plan(plan, resp)) {
        *verify_ec = NL_ERR_VERIFY_AFTER_ROLLBACK_FAILED;
        return -1;
    }
    return 0;
}

static int l3_owner_install_and_verify_plan(
        nl_l3_owner *owner, const l3_plan *plan, u64 tx_id,
        char *apply_resp, size_t apply_resp_size,
        char *readback_resp, size_t readback_resp_size,
        s32 *restore_ec) {
    char tx[L3_OWNER_TX_MAX_BYTES];
    char err[256] = {0};

    if (!owner || !plan || !apply_resp || apply_resp_size == 0 ||
        !readback_resp || readback_resp_size == 0 || !restore_ec)
        return -1;
    apply_resp[0] = '\0';
    readback_resp[0] = '\0';
    *restore_ec = 0;
    if (l3_plan_is_empty(plan))
        return l3_owner_verify_persistent_plan(
            owner, plan, tx_id, readback_resp, readback_resp_size,
            restore_ec);
    if (l3_plan_compile_transaction(plan, tx, sizeof(tx), err,
                                    sizeof(err)) != 0) {
        *restore_ec = NL_ERR_INVALID_VALUE;
        snprintf(apply_resp, apply_resp_size,
                 "<l3-persistent-owner-restore status=\"invalid\" "
                 "reason=\"stored pre-plan did not compile\"/>");
        return -1;
    }
    if (l3_owner_apply_persistent_to_switchd(
            owner, tx_id, tx, apply_resp, apply_resp_size, restore_ec) != 0) {
        *restore_ec = NL_ERR_DAEMON_UNREACHABLE;
        return -1;
    }
    if (*restore_ec != 0)
        return -1;
    return l3_owner_verify_persistent_plan(
        owner, plan, tx_id, readback_resp, readback_resp_size, restore_ec);
}

static bool l3_owner_switchd_response_out_of_sync(const char *resp) {
    return resp &&
        (strstr(resp, "status=\"out-of-sync\"") ||
         strstr(resp, "status=\"mismatch\"") ||
         strstr(resp,
                "<l3-persistent-owner-rollback status=\"empty\"") ||
         strstr(resp, "persistent-hw-out-of-sync=\"true\"") ||
         (strstr(resp, "rollback-failures=\"0\"") == NULL &&
          strstr(resp, "rollback-failures=\"") != NULL));
}

static bool l3_owner_switchd_rollback_known_unchanged(const char *resp) {
    return resp && strstr(resp,
                          "<l3-persistent-owner-rollback status=\"blocked\"");
}

static int l3_persistent_result_xml(nl_l3_owner *owner,
                                    const char *tag, const char *status,
                                    u64 tx_id, const l3_plan *pre,
                                    const l3_plan *post,
                                    const char *reason,
                                    const char *switchd_xml,
                                    char *buf, size_t buf_size) {
    l3_resource_model model;
    const char *user_config;
    const char *boundary_reason;

    l3_resource_model_build(owner, &model, NULL);
    user_config = model.l3_ready ? "open" : "chassis-mode-gated";
    boundary_reason = model.l3_ready ?
        owner->public_reason :
        (model.reason[0] ? model.reason :
         "active L3 chassis mode is not ready");
    return snprintf(buf, buf_size,
                    "<%s status=\"%s\" tx-id=\"%llu\" "
                    "mode=\"production\" authority=\"%s\" "
                    "owner-mode=\"persistent\" config-open=\"%s\" "
                    "hardware-apply=\"persistent\" sdk-readback=\"live\" "
                    "rollback=\"%s\" hw-sync=\"%s\" "
                    "persistent-hw-out-of-sync=\"%s\" "
                    "block-future-commits=\"%s\" reason=\"%s\">"
                    "<pre-state rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                    "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                    "<post-state rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                    "routes=\"%d\" ecmp-groups=\"%d\" ecmp-members=\"%d\"/>"
                    "<switchd-owner>%s</switchd-owner>"
                    "<boundary user-config=\"%s\" reason=\"%s\"/>"
                    "</%s>",
                    tag, status, (unsigned long long)tx_id,
                    owner->authority_name,
                    model.l3_ready ? "true" : "false",
                    owner->state.rollback_available ?
                        "available" : "unavailable",
                    owner->state.hw_out_of_sync ? "out-of-sync" : "in-sync",
                    owner->state.hw_out_of_sync ? "true" : "false",
                    owner->state.hw_out_of_sync ? "true" : "false",
                    reason ? reason : "",
                    pre ? pre->n_rifs : 0,
                    pre ? pre->n_arps : 0,
                    pre ? pre->n_nexthops : 0,
                    l3_plan_hidden_route_count(pre),
                    pre ? pre->n_ecmp : 0,
                    pre ? l3_plan_ecmp_member_count(pre) : 0,
                    post ? post->n_rifs : 0,
                    post ? post->n_arps : 0,
                    post ? post->n_nexthops : 0,
                    l3_plan_hidden_route_count(post),
                    post ? post->n_ecmp : 0,
                    post ? l3_plan_ecmp_member_count(post) : 0,
                    switchd_xml ? switchd_xml : "",
                    user_config, boundary_reason,
                    tag);
}

static int send_l3_persistent_result(
        nl_l3_owner *owner, nl_conn *conn, nl_msg_hdr *msg, s32 error_code,
        const char *tag, const char *status, u64 tx_id,
        const l3_plan *pre, const l3_plan *post, const char *reason,
        const char *switchd_xml) {
    char *xml;
    int n;
    int rc;

    xml = malloc(L3_OWNER_TX_MAX_BYTES);
    if (!xml)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: l3-owner response allocation failed");
    n = l3_persistent_result_xml(owner, tag, status, tx_id, pre, post,
                                 reason, switchd_xml, xml,
                                 L3_OWNER_TX_MAX_BYTES);
    if (n < 0 || n >= L3_OWNER_TX_MAX_BYTES) {
        free(xml);
        return send_text(conn, msg,
                         error_code ? error_code : NL_ERR_INVALID_VALUE,
                         "error: l3-owner persistent response overflow");
    }
    rc = send_text(conn, msg, error_code, xml);
    free(xml);
    return rc;
}

static void l3_owner_commit_state(nl_l3_owner *owner,
                                  const l3_plan *plan,
                                  const l3_plan *pre_plan,
                                  bool rollback_available,
                                  l3_tx_state tx_state,
                                  l3_owner_mode owner_mode,
                                  u64 tx_id, bool applied,
                                  bool rolled_back) {
    owner->state.plan = *plan;
    if (pre_plan)
        owner->state.pre_plan = *pre_plan;
    else
        memset(&owner->state.pre_plan, 0, sizeof(owner->state.pre_plan));
    owner->state.rollback_available = rollback_available;
    owner->state.tx_state = tx_state;
    owner->state.owner_mode = owner_mode;
    owner->state.last_tx_id = tx_id;
    if (applied)
        owner->state.last_apply = time(NULL);
    if (rolled_back)
        owner->state.last_rollback = time(NULL);
    owner->state.generation++;
    l3_owner_clear_hw_out_of_sync(owner);
}

typedef struct {
    l3_plan plan;
    l3_plan previous;
    char err[256];
    char resource_xml[4096];
    char tx[L3_OWNER_TX_MAX_BYTES];
    char switchd_resp[32768];
    char rollback_resp[16384];
    char restore_resp[32768];
    char restore_readback[32768];
} l3_persistent_apply_work;

static int handle_apply_persistent_work(nl_l3_owner *owner, nl_conn *conn,
                                        nl_msg_hdr *msg,
                                        l3_persistent_apply_work *work) {
    char *text;
    l3_plan *plan = &work->plan;
    l3_plan *previous = &work->previous;
    char *err = work->err;
    char *resource_xml = work->resource_xml;
    char *tx = work->tx;
    char *switchd_resp = work->switchd_resp;
    char *rollback_resp = work->rollback_resp;
    char *restore_resp = work->restore_resp;
    char *restore_readback = work->restore_readback;
    s32 switchd_ec = 0;
    s32 rollback_ec = 0;
    s32 restore_ec = 0;
    u64 tx_id;
    bool current_owner;
    bool same_plan = false;
    bool same_tx;
    int apply_rc;

    text = calloc(1, (size_t)msg->payload_len + 1);
    if (!text)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: l3-owner out of memory");
    if (msg->payload_len > 0)
        memcpy(text, msg->payload, msg->payload_len);
    if (l3_plan_parse(text, plan, err, sizeof(work->err)) != 0) {
        char detail[320];
        snprintf(detail, sizeof(detail), "error: l3-owner plan invalid: %s",
                 err[0] ? err : "invalid plan");
        free(text);
        return send_text(conn, msg, NL_ERR_INVALID_VALUE, detail);
    }
    free(text);

    if (l3_resource_check_plan(owner, plan, NULL, resource_xml,
                               sizeof(work->resource_xml), err,
                               sizeof(work->err)) != 0) {
        return send_l3_persistent_result(
            owner, conn, msg, NL_ERR_INVALID_VALUE,
            "l3-persistent-apply", "invalid", msg->tx_id,
            &owner->state.plan, plan, err, resource_xml);
    }
    if (l3_plan_compile_transaction(plan, tx, sizeof(work->tx), err,
                                    sizeof(work->err)) != 0)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE, err);

    if (owner->state.hw_out_of_sync) {
        return send_l3_persistent_result(
            owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
            "l3-persistent-apply", "blocked", msg->tx_id,
            &owner->state.plan, plan,
            owner->state.hw_out_of_sync_reason[0] ?
                owner->state.hw_out_of_sync_reason :
                "persistent L3 hardware state is out of sync",
            "<failure-policy action=\"block\" "
            "persistent-hw-out-of-sync=\"true\" "
            "block-future-commits=\"true\"/>");
    }

    tx_id = msg->tx_id ? msg->tx_id : ++owner->state.next_tx_id;
    *previous = owner->state.plan;
    current_owner = !l3_plan_is_empty(previous) &&
                    (owner->state.owner_mode == L3_OWNER_PERSISTENT ||
                     owner->state.owner_mode == L3_OWNER_SYNTHETIC);
    if (memcmp(previous, plan, sizeof(*plan)) == 0)
        same_plan = true;
    same_tx = tx_id == owner->state.last_tx_id;

    if (same_tx) {
        if (owner->state.tx_state != L3_TX_APPLIED || !same_plan) {
            return send_l3_persistent_result(
                owner, conn, msg, NL_ERR_INVALID_VALUE,
                "l3-persistent-apply", "invalid", tx_id,
                &owner->state.pre_plan, &owner->state.plan,
                owner->state.tx_state != L3_TX_APPLIED ?
                    "persistent L3 transaction is already terminal" :
                    "persistent L3 transaction retry changed the plan",
                "");
        }
        apply_rc = l3_owner_verify_persistent_plan(
            owner, &owner->state.plan, tx_id, switchd_resp,
            sizeof(work->switchd_resp), &switchd_ec);
        if (apply_rc != 0 || switchd_ec != 0) {
            l3_owner_mark_hw_out_of_sync(
                owner,
                "same-transaction persistent L3 replay failed live readback");
            return send_l3_persistent_result(
                owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
                "l3-persistent-apply", "out-of-sync", tx_id,
                &owner->state.pre_plan, &owner->state.plan,
                "same-transaction persistent L3 replay failed live readback",
                switchd_resp);
        }
        return send_l3_persistent_result(
            owner, conn, msg, 0, "l3-persistent-apply", "ok", tx_id,
            &owner->state.pre_plan, &owner->state.plan,
            "same persistent L3 transaction verified idempotently",
            switchd_resp);
    }

    if (same_plan) {
        if (l3_plan_is_empty(plan)) {
            apply_rc = l3_owner_verify_persistent_plan(
                owner, plan, tx_id, switchd_resp,
                sizeof(work->switchd_resp),
                &switchd_ec);
        } else {
            apply_rc = l3_owner_apply_persistent_to_switchd(
                owner, tx_id, tx, switchd_resp,
                sizeof(work->switchd_resp),
                &switchd_ec);
        }
        if (apply_rc != 0 || switchd_ec != 0) {
            if (apply_rc != 0 ||
                l3_owner_switchd_response_out_of_sync(switchd_resp)) {
                l3_owner_mark_hw_out_of_sync(
                    owner, "idempotent persistent L3 replay status is unknown");
                return send_l3_persistent_result(
                    owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
                    "l3-persistent-apply", "out-of-sync", tx_id,
                    previous, plan,
                    "idempotent persistent L3 replay status is unknown",
                    switchd_resp);
            }
            return send_text(conn, msg, switchd_ec, switchd_resp);
        }
        l3_owner_commit_state(
            owner, plan, previous, true, L3_TX_APPLIED,
            l3_plan_is_empty(plan) ? L3_OWNER_NONE : L3_OWNER_PERSISTENT,
            tx_id, true, false);
        return send_l3_persistent_result(
            owner, conn, msg, 0, "l3-persistent-apply", "ok", tx_id,
            previous, &owner->state.plan,
            "persistent L3 owner rebound to a new transaction and verified",
            switchd_resp);
    }

    if (current_owner) {
        int rollback_rc = l3_owner_rollback_current_owner(
            owner, rollback_resp, sizeof(work->rollback_resp), &rollback_ec);

        if (rollback_rc != 0 || rollback_ec != 0) {
            bool known_unchanged = rollback_rc == 0 &&
                l3_owner_switchd_rollback_known_unchanged(rollback_resp);

            if (!known_unchanged)
                l3_owner_mark_hw_out_of_sync(
                    owner,
                    "previous persistent L3 owner removal status is unknown");
            return send_l3_persistent_result(
                owner, conn, msg,
                known_unchanged ? rollback_ec : NL_ERR_HW_STATE_OUT_OF_SYNC,
                "l3-persistent-apply", "rollback-failed", tx_id,
                previous, plan,
                known_unchanged ?
                    "previous persistent L3 owner removal was blocked before hardware mutation" :
                    "previous persistent L3 owner removal status is unknown",
                rollback_resp);
        }
    }
    if (l3_plan_is_empty(plan)) {
        if (l3_owner_verify_persistent_plan(
                owner, plan, tx_id, restore_readback,
                sizeof(work->restore_readback), &restore_ec) != 0) {
            l3_owner_commit_state(owner, plan, previous, false,
                                  L3_TX_HW_OUT_OF_SYNC, L3_OWNER_NONE,
                                  tx_id, true, false);
            l3_owner_mark_hw_out_of_sync(
                owner, "cleared persistent L3 owner failed empty live readback");
            return send_l3_persistent_result(
                owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
                "l3-persistent-apply", "rollback-failed", tx_id,
                previous, &owner->state.plan,
                "cleared persistent L3 owner failed empty live readback",
                restore_readback);
        }
        l3_owner_commit_state(
            owner, plan, previous, !l3_plan_is_empty(previous),
            L3_TX_APPLIED, L3_OWNER_NONE, tx_id, true, false);
        return send_l3_persistent_result(
            owner, conn, msg, 0, "l3-persistent-apply", "ok", tx_id,
            previous, &owner->state.plan,
            "persistent L3 owner cleared and verified", restore_readback);
    }

    apply_rc = l3_owner_apply_persistent_to_switchd(
        owner, tx_id, tx, switchd_resp, sizeof(work->switchd_resp),
        &switchd_ec);
    if (apply_rc != 0 || switchd_ec != 0) {
        s32 failure_ec = apply_rc != 0 ?
            NL_ERR_DAEMON_UNREACHABLE : switchd_ec;

        if (!l3_plan_is_empty(previous)) {
            if (l3_owner_install_and_verify_plan(
                    owner, previous, tx_id,
                    restore_resp, sizeof(work->restore_resp),
                    restore_readback, sizeof(work->restore_readback),
                    &restore_ec) != 0) {
                l3_owner_commit_state(
                    owner, previous, NULL, false, L3_TX_HW_OUT_OF_SYNC,
                    L3_OWNER_PERSISTENT, tx_id, false, true);
                l3_owner_mark_hw_out_of_sync(
                    owner, "failed persistent L3 apply could not restore pre-plan");
                return send_l3_persistent_result(
                    owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
                    "l3-persistent-apply", "rollback-failed", tx_id,
                    previous, plan,
                    "failed persistent L3 apply could not restore pre-plan",
                    restore_readback[0] ? restore_readback : restore_resp);
            }

            l3_owner_commit_state(
                owner, previous, NULL, false, L3_TX_ROLLED_BACK,
                L3_OWNER_PERSISTENT, tx_id, true, true);
            return send_l3_persistent_result(
                owner, conn, msg, failure_ec,
                "l3-persistent-apply", "apply-failed-restored", tx_id,
                previous, &owner->state.plan,
                "persistent L3 apply failed and pre-plan was restored and verified",
                restore_readback);
        }

        if (apply_rc != 0 ||
            l3_owner_switchd_response_out_of_sync(switchd_resp)) {
            l3_owner_mark_hw_out_of_sync(
                owner, "failed initial persistent L3 apply status is unknown");
            return send_l3_persistent_result(
                owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
                "l3-persistent-apply", "out-of-sync", tx_id,
                previous, plan,
                "failed initial persistent L3 apply status is unknown",
                switchd_resp);
        }
        return send_text(conn, msg, failure_ec, switchd_resp);
    }

    l3_owner_commit_state(owner, plan, previous, true, L3_TX_APPLIED,
                          L3_OWNER_PERSISTENT, tx_id, true, false);
    return send_l3_persistent_result(
        owner, conn, msg, 0, "l3-persistent-apply", "ok", tx_id,
        &owner->state.pre_plan, &owner->state.plan,
        "persistent L3 owner applied and verified", switchd_resp);
}

static int handle_apply_persistent(nl_l3_owner *owner, nl_conn *conn,
                                   nl_msg_hdr *msg) {
    l3_persistent_apply_work *work;
    int rc;

    work = calloc(1, sizeof(*work));
    if (!work)
        return send_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: l3-owner apply workspace allocation failed");
    rc = handle_apply_persistent_work(owner, conn, msg, work);
    free(work);
    return rc;
}

typedef struct {
    l3_plan removed;
    l3_plan restored;
    char switchd_resp[16384];
    char restore_resp[32768];
    char restore_readback[32768];
} l3_persistent_rollback_work;

static int handle_rollback_persistent_work(
        nl_l3_owner *owner, nl_conn *conn, nl_msg_hdr *msg,
        l3_persistent_rollback_work *work) {
    l3_plan *removed = &work->removed;
    l3_plan *restored = &work->restored;
    char *switchd_resp = work->switchd_resp;
    char *restore_resp = work->restore_resp;
    char *restore_readback = work->restore_readback;
    s32 switchd_ec = 0;
    s32 restore_ec = 0;
    u64 tx_id;
    bool current_owner;

    tx_id = msg->tx_id;
    if (tx_id == 0 || tx_id != owner->state.last_tx_id) {
        return send_l3_persistent_result(
            owner, conn, msg, NL_ERR_INVALID_VALUE,
            "l3-persistent-rollback", "invalid", tx_id,
            &owner->state.plan, &owner->state.plan,
            !owner->state.rollback_available &&
                    owner->state.tx_state != L3_TX_ROLLED_BACK ?
                "no persistent owner rollback available for requested transaction" :
                "persistent L3 rollback transaction does not match current transaction",
            "");
    }
    if (owner->state.hw_out_of_sync) {
        return send_l3_persistent_result(
            owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
            "l3-persistent-rollback", "blocked",
            tx_id, &owner->state.plan,
            &owner->state.pre_plan,
            owner->state.hw_out_of_sync_reason[0] ?
                owner->state.hw_out_of_sync_reason :
                "persistent L3 hardware state is out of sync",
            "<failure-policy action=\"block\" "
            "persistent-hw-out-of-sync=\"true\" "
            "block-future-commits=\"true\"/>");
    }
    if (owner->state.tx_state == L3_TX_ROLLED_BACK) {
        if (l3_owner_verify_persistent_plan(
                owner, &owner->state.plan, tx_id,
                restore_readback, sizeof(work->restore_readback),
                &restore_ec) != 0) {
            l3_owner_mark_hw_out_of_sync(
                owner,
                "idempotent persistent L3 rollback failed live readback");
            return send_l3_persistent_result(
                owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
                "l3-persistent-rollback", "out-of-sync", tx_id,
                &owner->state.plan, &owner->state.plan,
                "idempotent persistent L3 rollback failed live readback",
                restore_readback);
        }
        return send_l3_persistent_result(
            owner, conn, msg, 0,
            "l3-persistent-rollback", "ok", tx_id,
            &owner->state.plan, &owner->state.plan,
            "persistent L3 transaction was already rolled back and verified",
            restore_readback);
    }
    if (owner->state.tx_state != L3_TX_APPLIED ||
        !owner->state.rollback_available) {
        return send_l3_persistent_result(
            owner, conn, msg, NL_ERR_INVALID_VALUE,
            "l3-persistent-rollback", "invalid", tx_id,
            &owner->state.plan, &owner->state.plan,
            "no persistent owner rollback available",
            "");
    }

    *removed = owner->state.plan;
    *restored = owner->state.pre_plan;
    current_owner = !l3_plan_is_empty(removed) &&
                    owner->state.owner_mode == L3_OWNER_PERSISTENT;
    if (current_owner) {
        int rollback_rc = l3_owner_rollback_current_owner(
            owner, switchd_resp, sizeof(work->switchd_resp), &switchd_ec);

        if (rollback_rc != 0 || switchd_ec != 0) {
            bool known_unchanged = rollback_rc == 0 &&
                l3_owner_switchd_rollback_known_unchanged(switchd_resp);

            if (!known_unchanged) {
                owner->state.last_tx_id = tx_id;
                owner->state.last_rollback = time(NULL);
                owner->state.generation++;
                l3_owner_mark_hw_out_of_sync(
                    owner,
                    "persistent L3 rollback could not remove current owner");
            }
            return send_l3_persistent_result(
                owner, conn, msg,
                known_unchanged ? switchd_ec : NL_ERR_HW_STATE_OUT_OF_SYNC,
                "l3-persistent-rollback", "rollback-failed", tx_id,
                removed, restored,
                known_unchanged ?
                    "persistent L3 rollback was blocked before hardware mutation" :
                    "persistent L3 rollback could not remove current owner",
                switchd_resp);
        }
    }

    if (l3_owner_install_and_verify_plan(
            owner, restored, tx_id,
            restore_resp, sizeof(work->restore_resp),
            restore_readback, sizeof(work->restore_readback),
            &restore_ec) != 0) {
        l3_owner_commit_state(
            owner, restored, removed, false, L3_TX_HW_OUT_OF_SYNC,
            l3_plan_is_empty(restored) ?
                L3_OWNER_NONE : L3_OWNER_PERSISTENT,
            tx_id, false, true);
        l3_owner_mark_hw_out_of_sync(
            owner, "persistent L3 rollback could not restore pre-plan");
        return send_l3_persistent_result(
            owner, conn, msg, NL_ERR_HW_STATE_OUT_OF_SYNC,
            "l3-persistent-rollback", "rollback-failed", tx_id,
            removed, restored,
            "persistent L3 rollback could not restore pre-plan",
            restore_readback[0] ? restore_readback : restore_resp);
    }

    l3_owner_commit_state(
        owner, restored, NULL, false, L3_TX_ROLLED_BACK,
        l3_plan_is_empty(restored) ? L3_OWNER_NONE : L3_OWNER_PERSISTENT,
        tx_id, false, true);
    return send_l3_persistent_result(
        owner, conn, msg, 0, "l3-persistent-rollback", "ok", tx_id,
        removed, &owner->state.plan,
        l3_plan_is_empty(restored) ?
            "persistent L3 owner rolled back to empty state and verified" :
            "persistent L3 owner pre-plan restored and verified",
        restore_readback);
}

static int handle_rollback_persistent(nl_l3_owner *owner, nl_conn *conn,
                                      nl_msg_hdr *msg) {
    l3_persistent_rollback_work *work;
    int rc;

    work = calloc(1, sizeof(*work));
    if (!work)
        return send_text(
            conn, msg, NL_ERR_INVALID_VALUE,
            "error: l3-owner rollback workspace allocation failed");
    rc = handle_rollback_persistent_work(owner, conn, msg, work);
    free(work);
    return rc;
}

static bool xml_text_safe(const char *text) {
    if (!text || !text[0])
        return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p < 0x20 || *p == '<' || *p == '>' || *p == '&' ||
            *p == '\'' || *p == '"')
            return false;
    }
    return true;
}

nl_l3_owner *nl_l3_owner_create(const nl_l3_owner_options *options) {
    const char *socket_path = options && options->switchd_socket_path ?
        options->switchd_socket_path : getenv("NETLAB_SWITCHD_SOCKET");
    const char *authority = options && options->authority_name ?
        options->authority_name : "rpd";
    const char *reason = options && options->public_reason ?
        options->public_reason :
        "public routing config commits through configd and rpd persistent owner";
    u16 caller = options && options->switchd_caller_daemon ?
        options->switchd_caller_daemon : NL_DAEMON_RPD;
    nl_l3_owner *owner;

    if (!l3_owner_socket_path_safe(socket_path))
        socket_path = SWITCHD_SOCKET;
    if (!valid_vrf_name(authority) || !xml_text_safe(reason))
        return NULL;
    if (caller != NL_DAEMON_RPD)
        return NULL;

    owner = calloc(1, sizeof(*owner));
    if (!owner)
        return NULL;
    if (pthread_mutex_init(&owner->lock, NULL) != 0) {
        free(owner);
        return NULL;
    }
    if (pthread_mutex_init(&owner->resource_model_lock, NULL) != 0) {
        pthread_mutex_destroy(&owner->lock);
        free(owner);
        return NULL;
    }
    str_copy(owner->switchd_socket_path,
             sizeof(owner->switchd_socket_path), socket_path);
    str_copy(owner->authority_name, sizeof(owner->authority_name), authority);
    str_copy(owner->public_reason, sizeof(owner->public_reason), reason);
    owner->switchd_caller_daemon = caller;
    return owner;
}

void nl_l3_owner_destroy(nl_l3_owner *owner) {
    if (!owner)
        return;
    pthread_mutex_destroy(&owner->resource_model_lock);
    pthread_mutex_destroy(&owner->lock);
    free(owner);
}

int nl_l3_owner_handle(nl_l3_owner *owner, nl_l3_owner_method method,
                       nl_conn *conn, nl_msg_hdr *msg) {
    int rc;

    if (!owner || !conn || !msg)
        return -1;
    pthread_mutex_lock(&owner->lock);
    switch (method) {
    case NL_L3_OWNER_SHOW:
        rc = handle_show(owner, conn, msg);
        break;
    case NL_L3_OWNER_READBACK:
        rc = handle_readback(owner, conn, msg);
        break;
    case NL_L3_OWNER_RESOURCE_CHECK:
        rc = handle_resource_check(owner, conn, msg);
        break;
    case NL_L3_OWNER_APPLY:
        rc = handle_apply_persistent(owner, conn, msg);
        break;
    case NL_L3_OWNER_ROLLBACK:
        rc = handle_rollback_persistent(owner, conn, msg);
        break;
    default:
        rc = send_text(conn, msg, NL_ERR_INVALID_VALUE,
                       "error: unknown persistent L3 owner method");
        break;
    }
    pthread_mutex_unlock(&owner->lock);
    return rc;
}

int nl_l3_owner_plan_validate(const char *text, char *summary,
                              size_t summary_size, char *error,
                              size_t error_size) {
    l3_plan *plan;
    int rc = -1;

    if (!text || !summary || summary_size == 0 || !error || error_size == 0)
        return -1;
    error[0] = '\0';
    plan = calloc(1, sizeof(*plan));
    if (!plan) {
        snprintf(error, error_size, "l3-owner plan allocation failed");
        return -1;
    }
    if (l3_plan_parse(text, plan, error, error_size) == 0) {
        plan_summary(plan, summary, summary_size);
        rc = 0;
    }
    free(plan);
    return rc;
}

int nl_l3_owner_plan_compile(const char *text, char *transaction,
                             size_t transaction_size, char *error,
                             size_t error_size) {
    l3_plan *plan;
    int rc = -1;

    if (!text || !transaction || transaction_size == 0 ||
        !error || error_size == 0)
        return -1;
    error[0] = '\0';
    plan = calloc(1, sizeof(*plan));
    if (!plan) {
        snprintf(error, error_size, "l3-owner plan allocation failed");
        return -1;
    }
    if (l3_plan_parse(text, plan, error, error_size) == 0)
        rc = l3_plan_compile_transaction(plan, transaction,
                                         transaction_size, error, error_size);
    free(plan);
    return rc;
}

int nl_l3_owner_plan_resource_check(nl_l3_owner *owner, const char *text,
                                    const char *profile_path, char *xml,
                                    size_t xml_size, char *error,
                                    size_t error_size) {
    l3_plan *plan;
    int rc;

    if (!owner || !text || !xml || xml_size == 0 ||
        !error || error_size == 0)
        return -1;
    error[0] = '\0';
    plan = calloc(1, sizeof(*plan));
    if (!plan) {
        snprintf(error, error_size, "l3-owner plan allocation failed");
        return -1;
    }
    if (l3_plan_parse(text, plan, error, error_size) != 0) {
        free(plan);
        return -1;
    }
    pthread_mutex_lock(&owner->lock);
    rc = l3_resource_check_plan(owner, plan, profile_path, xml, xml_size,
                                error, error_size);
    pthread_mutex_unlock(&owner->lock);
    free(plan);
    return rc;
}
