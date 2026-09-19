/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static nl_port_entry g_ports[NL_MAX_PORTS_PER_PROFILE];
static nl_switch_entry g_switches[NL_MAX_SWITCHES_PER_PROFILE];
static nl_lane_entry g_lanes[NL_MAX_LANES_PER_PROFILE];
static nl_xcvr_entry g_xcvrs[NL_MAX_XCVRS_PER_PROFILE];
static int g_num_ports = 0;
static int g_num_switches = 0;
static int g_num_lanes = 0;
static int g_num_xcvrs = 0;
static bool g_loaded = false;
static char g_loaded_profile[256];
static nl_platform_identity g_identity;
static nl_board_profile g_board;
static nl_ffu_slice_allocation g_ffu;

static void trim(char *s) {
    char *p;
    size_t n;

    if (!s)
        return;
    while (isspace((unsigned char)*s))
        memmove(s, s + 1, strlen(s));
    n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    p = strchr(s, '#');
    if (p) {
        *p = '\0';
        trim(s);
    }
}

static char *next_token(char **cursor, char *buf, size_t buf_size) {
    char *p;
    size_t off = 0;
    bool quoted = false;

    if (!cursor || !*cursor || !buf || buf_size == 0)
        return NULL;
    p = *cursor;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (!*p || *p == '#') {
        *cursor = p;
        return NULL;
    }

    while (*p) {
        if (*p == '"') {
            quoted = !quoted;
            p++;
            continue;
        }
        if (!quoted && isspace((unsigned char)*p))
            break;
        if (!quoted && *p == '#')
            break;
        if (off + 1 < buf_size)
            buf[off++] = *p;
        p++;
    }
    buf[off] = '\0';
    while (*p && isspace((unsigned char)*p))
        p++;
    *cursor = p;
    return buf[0] ? buf : NULL;
}

static bool kv_split(char *token, char **key, char **value) {
    char *eq;

    if (!token || !key || !value)
        return false;
    eq = strchr(token, '=');
    if (!eq)
        return false;
    *eq = '\0';
    *key = token;
    *value = eq + 1;
    return **key != '\0';
}

bool nl_platform_parse_mac(const char *text, u8 mac[NL_MAC_ADDR_LEN]) {
    unsigned int m[NL_MAC_ADDR_LEN];

    if (!text || !mac)
        return false;
    if (sscanf(text, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return false;
    for (int i = 0; i < NL_MAC_ADDR_LEN; i++) {
        if (m[i] > 0xff)
            return false;
        mac[i] = (u8)m[i];
    }
    return !(mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
             mac[3] == 0 && mac[4] == 0 && mac[5] == 0);
}

static u64 parse_u64(const char *value, u64 fallback) {
    char *end = NULL;
    unsigned long long v;

    if (!value || !*value)
        return fallback;
    errno = 0;
    v = strtoull(value, &end, 0);
    if (errno != 0 || !end || *end)
        return fallback;
    return (u64)v;
}

static int parse_int(const char *value, int fallback) {
    char *end = NULL;
    long v;

    if (!value || !*value)
        return fallback;
    errno = 0;
    v = strtol(value, &end, 0);
    if (errno != 0 || !end || *end || v < -2147483647L || v > 2147483647L)
        return fallback;
    return (int)v;
}

static void parse_supported_speeds(nl_port_entry *e, const char *value) {
    char tmp[128];
    char *save = NULL;
    char *tok;

    if (!e || !value)
        return;
    snprintf(tmp, sizeof(tmp), "%s", value);
    e->num_speeds = 0;
    tok = strtok_r(tmp, ",", &save);
    while (tok && e->num_speeds < (int)(sizeof(e->supported_speeds) /
                                        sizeof(e->supported_speeds[0]))) {
        trim(tok);
        e->supported_speeds[e->num_speeds++] = parse_u64(tok, 0);
        tok = strtok_r(NULL, ",", &save);
    }
}

static void parse_flags(nl_port_entry *e, const char *value) {
    char tmp[128];
    char *save = NULL;
    char *tok;

    if (!e || !value)
        return;
    snprintf(tmp, sizeof(tmp), "%s", value);
    tok = strtok_r(tmp, ",", &save);
    while (tok) {
        trim(tok);
        if (strcasecmp(tok, "external") == 0)
            e->flags |= NL_PORT_FLAG_EXTERNAL;
        else if (strcasecmp(tok, "trunk") == 0 ||
                 strcasecmp(tok, "tagged-trunk") == 0)
            e->flags |= NL_PORT_FLAG_TAGGED_TRUNK;
        else if (strcasecmp(tok, "lldp") == 0 ||
                 strcasecmp(tok, "lldp-capable") == 0)
            e->flags |= NL_PORT_FLAG_LLDP_CAPABLE;
        else if (strcasecmp(tok, "lldp-default") == 0) {
            e->flags |= NL_PORT_FLAG_LLDP_DEFAULT |
                        NL_PORT_FLAG_LLDP_CAPABLE;
        }
        else if (strcasecmp(tok, "rstp") == 0)
            e->flags |= NL_PORT_FLAG_RSTP_CAPABLE;
        else if (strcasecmp(tok, "lacp") == 0)
            e->flags |= NL_PORT_FLAG_LACP_CAPABLE;
        else if (strcasecmp(tok, "hidden") == 0)
            e->flags |= NL_PORT_FLAG_HIDDEN;
        else if (strcasecmp(tok, "cpu") == 0 ||
                 strcasecmp(tok, "control") == 0 ||
                 strcasecmp(tok, "cpu-control") == 0) {
            e->flags |= NL_PORT_FLAG_CPU_CONTROL |
                        NL_PORT_FLAG_HIDDEN;
        }
        tok = strtok_r(NULL, ",", &save);
    }
}

static void derive_name_fields(nl_port_entry *e) {
    char media[8] = {0};
    int fpc = 0;
    int pic = 0;
    int port = -1;

    if (!e || !e->canonical_name[0])
        return;
    if (sscanf(e->canonical_name, "%7[^-]-%d/%d/%d",
               media, &fpc, &pic, &port) == 4) {
        if (!e->media_type[0])
            snprintf(e->media_type, sizeof(e->media_type), "%s", media);
        if (e->fpc < 0)
            e->fpc = fpc;
        if (e->pic < 0)
            e->pic = pic;
        if (e->port < 0)
            e->port = port;
    }
}

static int add_switch_from_line(char *cursor) {
    nl_switch_entry e;
    char token[256];
    char *tok;

    if (g_num_switches >= NL_MAX_SWITCHES_PER_PROFILE)
        return -1;

    memset(&e, 0, sizeof(e));
    e.index = -1;
    e.number = -1;
    e.cpu_port = -1;
    e.management_pep = -1;

    while ((tok = next_token(&cursor, token, sizeof(token))) != NULL) {
        char *key = NULL;
        char *value = NULL;
        if (!kv_split(tok, &key, &value))
            continue;

        if (strcmp(key, "index") == 0 || strcmp(key, "switch-index") == 0)
            e.index = parse_int(value, e.index);
        else if (strcmp(key, "number") == 0 ||
                 strcmp(key, "switch-number") == 0)
            e.number = parse_int(value, e.number);
        else if (strcmp(key, "uio-dev") == 0 ||
                 strcmp(key, "uio-dev-name") == 0)
            snprintf(e.uio_dev, sizeof(e.uio_dev), "%s", value);
        else if (strcmp(key, "cpu-port") == 0)
            e.cpu_port = parse_int(value, e.cpu_port);
        else if (strcmp(key, "management-pep") == 0 ||
                 strcmp(key, "mgmt-pep") == 0)
            e.management_pep = parse_int(value, e.management_pep);
    }

    if (e.index < 0)
        return -1;
    if (e.number < 0)
        e.number = e.index;
    g_switches[g_num_switches++] = e;
    return 0;
}

static int add_port_from_line(char *cursor) {
    nl_port_entry e;
    char token[256];
    char *tok;

    if (g_num_ports >= NL_MAX_PORTS_PER_PROFILE)
        return -1;

    memset(&e, 0, sizeof(e));
    e.interface_id = 0;
    e.fpc = -1;
    e.pic = -1;
    e.port = -1;
    e.switch_id = 0;
    e.switch_number = -1;
    e.port_index = -1;
    e.logical_port = 0;
    e.front_panel_port = 0;
    e.pcie_port = -1;
    e.epl_port = -1;
    e.lane = -1;
    e.sdk_lane = -1;
    e.hw_resource_id = -1;

    while ((tok = next_token(&cursor, token, sizeof(token))) != NULL) {
        char *key = NULL;
        char *value = NULL;
        if (!kv_split(tok, &key, &value))
            continue;

        if (strcmp(key, "name") == 0)
            snprintf(e.canonical_name, sizeof(e.canonical_name), "%s", value);
        else if (strcmp(key, "interface-id") == 0)
            e.interface_id = parse_u64(value, e.interface_id);
        else if (strcmp(key, "media") == 0)
            snprintf(e.media_type, sizeof(e.media_type), "%s", value);
        else if (strcmp(key, "role") == 0)
            snprintf(e.role, sizeof(e.role), "%s", value);
        else if (strcmp(key, "interface-type") == 0)
            snprintf(e.interface_type, sizeof(e.interface_type), "%s", value);
        else if (strcmp(key, "ethernet-mode") == 0)
            snprintf(e.ethernet_mode, sizeof(e.ethernet_mode), "%s", value);
        else if (strcmp(key, "capabilities") == 0 ||
                 strcmp(key, "capability") == 0)
            snprintf(e.capabilities, sizeof(e.capabilities), "%s", value);
        else if (strcmp(key, "flags") == 0)
            parse_flags(&e, value);
        else if (strcmp(key, "fpc") == 0)
            e.fpc = parse_int(value, e.fpc);
        else if (strcmp(key, "pic") == 0)
            e.pic = parse_int(value, e.pic);
        else if (strcmp(key, "port") == 0)
            e.port = parse_int(value, e.port);
        else if (strcmp(key, "switch-id") == 0 ||
                 strcmp(key, "switch-index") == 0)
            e.switch_id = parse_int(value, e.switch_id);
        else if (strcmp(key, "switch-number") == 0)
            e.switch_number = parse_int(value, e.switch_number);
        else if (strcmp(key, "port-index") == 0)
            e.port_index = parse_int(value, e.port_index);
        else if (strcmp(key, "logical-port") == 0)
            e.logical_port = parse_int(value, e.logical_port);
        else if (strcmp(key, "front-panel-port") == 0)
            e.front_panel_port = parse_int(value, e.front_panel_port);
        else if (strcmp(key, "pcie-port") == 0 ||
                 strcmp(key, "pcie") == 0)
            e.pcie_port = parse_int(value, e.pcie_port);
        else if (strcmp(key, "epl-port") == 0 ||
                 strcmp(key, "epl") == 0)
            e.epl_port = parse_int(value, e.epl_port);
        else if (strcmp(key, "lane") == 0)
            e.lane = parse_int(value, e.lane);
        else if (strcmp(key, "sdk-lane") == 0)
            e.sdk_lane = parse_int(value, e.sdk_lane);
        else if (strcmp(key, "hw-resource-id") == 0)
            e.hw_resource_id = parse_int(value, e.hw_resource_id);
        else if (strcmp(key, "default-speed") == 0)
            e.default_speed = parse_u64(value, e.default_speed);
        else if (strcmp(key, "line-rate") == 0)
            e.line_rate = parse_u64(value, e.line_rate);
        else if (strcmp(key, "scheduler-speed") == 0)
            e.scheduler_speed = parse_u64(value, e.scheduler_speed);
        else if (strcmp(key, "supported-speeds") == 0)
            parse_supported_speeds(&e, value);
        else if (strcmp(key, "rstp-cost") == 0)
            e.rstp_cost = parse_int(value, e.rstp_cost);
    }

    derive_name_fields(&e);
    if (!e.canonical_name[0] || e.logical_port <= 0)
        return -1;
    if (e.interface_id == 0)
        e.interface_id = 1000 + (u64)e.logical_port;
    if (e.front_panel_port <= 0)
        e.front_panel_port = e.port >= 0 ? e.port + 1 : e.logical_port;
    if (!e.media_type[0])
        snprintf(e.media_type, sizeof(e.media_type), "et");
    if (!e.role[0])
        snprintf(e.role, sizeof(e.role), "unknown");
    if (strcasecmp(e.role, "external") == 0)
        e.flags |= NL_PORT_FLAG_EXTERNAL;
    if (strcasecmp(e.role, "cpu") == 0 ||
        strcasecmp(e.role, "control") == 0 ||
        strcasecmp(e.role, "cpu-control") == 0)
        e.flags |= NL_PORT_FLAG_CPU_CONTROL |
                   NL_PORT_FLAG_HIDDEN;
    if (e.port_index < 0)
        e.port_index = e.logical_port;
    if (e.default_speed == 0 && e.num_speeds > 0 &&
        strcasecmp(e.ethernet_mode, "DISABLED") != 0)
        e.default_speed = e.supported_speeds[0];
    if (e.default_speed == 0 && e.line_rate != 0)
        e.default_speed = e.line_rate;
    if (e.line_rate == 0 && e.default_speed != 0)
        e.line_rate = e.default_speed;
    if (e.scheduler_speed == 0 && e.default_speed != 0)
        e.scheduler_speed = e.default_speed;
    if (e.default_speed != 0 && e.num_speeds == 0) {
        e.supported_speeds[0] = e.default_speed;
        e.num_speeds = 1;
    }

    g_ports[g_num_ports++] = e;
    return 0;
}

static int add_lane_from_line(char *cursor) {
    nl_lane_entry e;
    char token[256];
    char *tok;

    if (g_num_lanes >= NL_MAX_LANES_PER_PROFILE)
        return -1;

    memset(&e, 0, sizeof(e));
    e.switch_id = 0;
    e.port_index = -1;
    e.index = -1;
    e.epl_port = -1;
    e.pcie_port = -1;
    e.sdk_lane = -1;

    while ((tok = next_token(&cursor, token, sizeof(token))) != NULL) {
        char *key = NULL;
        char *value = NULL;
        if (!kv_split(tok, &key, &value))
            continue;

        if (strcmp(key, "ifname") == 0 || strcmp(key, "name") == 0 ||
            strcmp(key, "interface") == 0)
            snprintf(e.ifname, sizeof(e.ifname), "%s", value);
        else if (strcmp(key, "switch-id") == 0 ||
                 strcmp(key, "switch-index") == 0)
            e.switch_id = parse_int(value, e.switch_id);
        else if (strcmp(key, "port-index") == 0)
            e.port_index = parse_int(value, e.port_index);
        else if (strcmp(key, "logical-port") == 0)
            e.logical_port = parse_int(value, e.logical_port);
        else if (strcmp(key, "index") == 0 || strcmp(key, "lane-index") == 0)
            e.index = parse_int(value, e.index);
        else if (strcmp(key, "epl") == 0 || strcmp(key, "epl-port") == 0)
            e.epl_port = parse_int(value, e.epl_port);
        else if (strcmp(key, "pcie") == 0 || strcmp(key, "pcie-port") == 0)
            e.pcie_port = parse_int(value, e.pcie_port);
        else if (strcmp(key, "sdk-lane") == 0)
            e.sdk_lane = parse_int(value, e.sdk_lane);
        else if (strcmp(key, "polarity") == 0 ||
                 strcmp(key, "lane-polarity") == 0)
            snprintf(e.polarity, sizeof(e.polarity), "%s", value);
    }

    if (!e.ifname[0] || e.index < 0)
        return -1;
    if (e.sdk_lane < 0)
        e.sdk_lane = e.index;
    g_lanes[g_num_lanes++] = e;
    return 0;
}

static int add_xcvr_from_line(char *cursor) {
    nl_xcvr_entry e;
    char token[256];
    char *tok;

    if (g_num_xcvrs >= NL_MAX_XCVRS_PER_PROFILE)
        return -1;

    memset(&e, 0, sizeof(e));
    e.resource_id = -1;
    e.mux_index = -1;
    e.mux_value = -1;
    e.state_gpio_index = -1;
    e.state_gpio_base = -1;

    while ((tok = next_token(&cursor, token, sizeof(token))) != NULL) {
        char *key = NULL;
        char *value = NULL;
        if (!kv_split(tok, &key, &value))
            continue;

        if (strcmp(key, "resource-id") == 0 ||
            strcmp(key, "hw-resource-id") == 0 || strcmp(key, "id") == 0)
            e.resource_id = parse_int(value, e.resource_id);
        else if (strcmp(key, "type") == 0 ||
                 strcmp(key, "interface-type") == 0)
            snprintf(e.type, sizeof(e.type), "%s", value);
        else if (strcmp(key, "i2c-bus") == 0)
            snprintf(e.i2c_bus, sizeof(e.i2c_bus), "%s", value);
        else if (strcmp(key, "mux-index") == 0 ||
                 strcmp(key, "mux") == 0)
            e.mux_index = parse_int(value, e.mux_index);
        else if (strcmp(key, "mux-value") == 0)
            e.mux_value = parse_int(value, e.mux_value);
        else if (strcmp(key, "state-gpio-index") == 0)
            e.state_gpio_index = parse_int(value, e.state_gpio_index);
        else if (strcmp(key, "state-gpio-base") == 0)
            e.state_gpio_base = parse_int(value, e.state_gpio_base);
    }

    if (e.resource_id < 0)
        return -1;
    g_xcvrs[g_num_xcvrs++] = e;
    return 0;
}

static int parse_ffu_line(char *cursor) {
    char token[256];
    char *tok;

    g_ffu.configured = true;
    while ((tok = next_token(&cursor, token, sizeof(token))) != NULL) {
        char *key = NULL;
        char *value = NULL;
        if (!kv_split(tok, &key, &value))
            continue;

        if (strcmp(key, "ipv4-uc-first") == 0)
            g_ffu.ipv4_uc_first = parse_int(value, g_ffu.ipv4_uc_first);
        else if (strcmp(key, "ipv4-uc-last") == 0)
            g_ffu.ipv4_uc_last = parse_int(value, g_ffu.ipv4_uc_last);
        else if (strcmp(key, "ipv4-mc-first") == 0)
            g_ffu.ipv4_mc_first = parse_int(value, g_ffu.ipv4_mc_first);
        else if (strcmp(key, "ipv4-mc-last") == 0)
            g_ffu.ipv4_mc_last = parse_int(value, g_ffu.ipv4_mc_last);
        else if (strcmp(key, "ipv6-uc-first") == 0)
            g_ffu.ipv6_uc_first = parse_int(value, g_ffu.ipv6_uc_first);
        else if (strcmp(key, "ipv6-uc-last") == 0)
            g_ffu.ipv6_uc_last = parse_int(value, g_ffu.ipv6_uc_last);
        else if (strcmp(key, "ipv6-mc-first") == 0)
            g_ffu.ipv6_mc_first = parse_int(value, g_ffu.ipv6_mc_first);
        else if (strcmp(key, "ipv6-mc-last") == 0)
            g_ffu.ipv6_mc_last = parse_int(value, g_ffu.ipv6_mc_last);
        else if (strcmp(key, "acl-first") == 0)
            g_ffu.acl_first = parse_int(value, g_ffu.acl_first);
        else if (strcmp(key, "acl-last") == 0)
            g_ffu.acl_last = parse_int(value, g_ffu.acl_last);
        else if (strcmp(key, "cvlan-first") == 0)
            g_ffu.cvlan_first = parse_int(value, g_ffu.cvlan_first);
        else if (strcmp(key, "cvlan-last") == 0)
            g_ffu.cvlan_last = parse_int(value, g_ffu.cvlan_last);
        else if (strcmp(key, "bst-routing-first") == 0)
            g_ffu.bst_routing_first =
                parse_int(value, g_ffu.bst_routing_first);
        else if (strcmp(key, "bst-routing-last") == 0)
            g_ffu.bst_routing_last =
                parse_int(value, g_ffu.bst_routing_last);
    }

    return 0;
}

static void parse_platform_line(char *cursor) {
    char token[256];
    char *tok;

    while ((tok = next_token(&cursor, token, sizeof(token))) != NULL) {
        char *key = NULL;
        char *value = NULL;
        if (!kv_split(tok, &key, &value))
            continue;

        if (strcmp(key, "model") == 0)
            snprintf(g_identity.model, sizeof(g_identity.model), "%s", value);
        else if (strcmp(key, "chassis-name") == 0)
            snprintf(g_identity.chassis_name, sizeof(g_identity.chassis_name),
                     "%s", value);
        else if (strcmp(key, "serial") == 0)
            snprintf(g_identity.serial, sizeof(g_identity.serial), "%s", value);
        else if (strcmp(key, "system-name") == 0)
            snprintf(g_identity.system_name, sizeof(g_identity.system_name),
                     "%s", value);
        else if (strcmp(key, "system-description") == 0)
            snprintf(g_identity.system_description,
                     sizeof(g_identity.system_description), "%s", value);
        else if (strcmp(key, "system-mac") == 0)
            g_identity.has_system_mac =
                nl_platform_parse_mac(value, g_identity.system_mac);
        else if (strcmp(key, "max-ae") == 0)
            g_identity.max_ae = parse_int(value, g_identity.max_ae);
        else if (strcmp(key, "rstp-bridge-priority") == 0)
            g_identity.rstp_bridge_priority =
                parse_int(value, g_identity.rstp_bridge_priority);
        else if (strcmp(key, "rstp-hello-sec") == 0)
            g_identity.rstp_hello_sec =
                parse_int(value, g_identity.rstp_hello_sec);
        else if (strcmp(key, "rstp-bpdu-stale-sec") == 0)
            g_identity.rstp_bpdu_stale_sec =
                parse_int(value, g_identity.rstp_bpdu_stale_sec);
        else if (strcmp(key, "lacp-system-priority") == 0)
            g_identity.lacp_system_priority =
                parse_int(value, g_identity.lacp_system_priority);
        else if (strcmp(key, "lacp-port-priority") == 0)
            g_identity.lacp_port_priority =
                parse_int(value, g_identity.lacp_port_priority);
        else if (strcmp(key, "lacp-ttl-sec") == 0)
            g_identity.lacp_ttl_sec =
                parse_int(value, g_identity.lacp_ttl_sec);
    }
}

static int parse_board_line(char *cursor) {
    char token[256];
    char *tok;

    if (g_board.configured)
        return -1;
    g_board.configured = true;
    while ((tok = next_token(&cursor, token, sizeof(token))) != NULL) {
        char *key = NULL;
        char *value = NULL;

        if (!kv_split(tok, &key, &value))
            continue;
        if (strcmp(key, "model") == 0)
            snprintf(g_board.model, sizeof(g_board.model), "%s", value);
        else if (strcmp(key, "asic") == 0)
            snprintf(g_board.asic, sizeof(g_board.asic), "%s", value);
        else if (strcmp(key, "fci-count") == 0)
            g_board.fci_count = parse_int(value, g_board.fci_count);
        else if (strcmp(key, "i2c-bus") == 0)
            g_board.i2c_bus = parse_int(value, g_board.i2c_bus);
        else if (strcmp(key, "mux-address") == 0)
            g_board.mux_addr = parse_int(value, g_board.mux_addr);
        else if (strcmp(key, "cpld-ram-address") == 0)
            g_board.cpld_ram_addr = parse_int(value, g_board.cpld_ram_addr);
        else if (strcmp(key, "reset-gpio-address") == 0)
            g_board.reset_gpio_addr = parse_int(value, g_board.reset_gpio_addr);
        else if (strcmp(key, "fci0-mux") == 0)
            g_board.fci_mux[0] = parse_int(value, g_board.fci_mux[0]);
        else if (strcmp(key, "fci1-mux") == 0)
            g_board.fci_mux[1] = parse_int(value, g_board.fci_mux[1]);
        else if (strcmp(key, "environment-mux") == 0)
            g_board.environment_mux =
                parse_int(value, g_board.environment_mux);
        else if (strcmp(key, "power-mux") == 0)
            g_board.power_mux = parse_int(value, g_board.power_mux);
        else if (strcmp(key, "shared-memory-bytes") == 0)
            g_board.shared_memory_bytes =
                parse_int(value, g_board.shared_memory_bytes);
        else if (strcmp(key, "tcam-entries") == 0)
            g_board.tcam_entries = parse_int(value, g_board.tcam_entries);
        else if (strcmp(key, "mac-nexthop-entries") == 0)
            g_board.mac_nexthop_entries =
                parse_int(value, g_board.mac_nexthop_entries);
    }
    return 0;
}

static void reset_profile(void) {
    memset(g_ports, 0, sizeof(g_ports));
    memset(g_switches, 0, sizeof(g_switches));
    memset(g_lanes, 0, sizeof(g_lanes));
    memset(g_xcvrs, 0, sizeof(g_xcvrs));
    memset(&g_identity, 0, sizeof(g_identity));
    memset(&g_board, 0, sizeof(g_board));
    memset(&g_ffu, 0, sizeof(g_ffu));
    g_num_ports = 0;
    g_num_switches = 0;
    g_num_lanes = 0;
    g_num_xcvrs = 0;
    g_identity.max_ae = 0;
    g_board.i2c_bus = -1;
    g_board.mux_addr = -1;
    g_board.cpld_ram_addr = -1;
    g_board.reset_gpio_addr = -1;
    g_board.fci_mux[0] = -1;
    g_board.fci_mux[1] = -1;
    g_board.environment_mux = -1;
    g_board.power_mux = -1;
    g_ffu.ipv4_uc_first = -1;
    g_ffu.ipv4_uc_last = -1;
    g_ffu.ipv4_mc_first = -1;
    g_ffu.ipv4_mc_last = -1;
    g_ffu.ipv6_uc_first = -1;
    g_ffu.ipv6_uc_last = -1;
    g_ffu.ipv6_mc_first = -1;
    g_ffu.ipv6_mc_last = -1;
    g_ffu.acl_first = -1;
    g_ffu.acl_last = -1;
    g_ffu.cvlan_first = -1;
    g_ffu.cvlan_last = -1;
    g_ffu.bst_routing_first = -1;
    g_ffu.bst_routing_last = -1;
    g_loaded_profile[0] = '\0';
}

static bool slice_pair_valid(int first, int last) {
    if (first == -1 && last == -1)
        return true;
    if (first < 0 || last < 0)
        return false;
    return first <= last && last <= 31;
}

static bool slice_pair_enabled(int first, int last) {
    return first >= 0 && last >= 0;
}

static bool slice_pair_overlap(int a_first, int a_last,
                               int b_first, int b_last) {
    if (!slice_pair_enabled(a_first, a_last) ||
        !slice_pair_enabled(b_first, b_last))
        return false;
    return a_first <= b_last && b_first <= a_last;
}

static bool profile_route_slices_enabled(void) {
    return slice_pair_enabled(g_ffu.ipv4_uc_first, g_ffu.ipv4_uc_last) ||
           slice_pair_enabled(g_ffu.ipv4_mc_first, g_ffu.ipv4_mc_last) ||
           slice_pair_enabled(g_ffu.ipv6_uc_first, g_ffu.ipv6_uc_last) ||
           slice_pair_enabled(g_ffu.ipv6_mc_first, g_ffu.ipv6_mc_last);
}

static bool port_has_capability(const nl_port_entry *p, const char *wanted) {
    char tmp[sizeof(p->capabilities)];
    char *save = NULL;
    char *tok;

    if (!p || !wanted || !p->capabilities[0])
        return false;
    snprintf(tmp, sizeof(tmp), "%s", p->capabilities);
    tok = strtok_r(tmp, ",", &save);
    while (tok) {
        trim(tok);
        if (strcasecmp(tok, wanted) == 0)
            return true;
        tok = strtok_r(NULL, ",", &save);
    }
    return false;
}

static bool profile_has_route_capable_external_port(void) {
    for (int i = 0; i < g_num_ports; i++) {
        if ((g_ports[i].flags & NL_PORT_FLAG_EXTERNAL) &&
            port_has_capability(&g_ports[i], "ROUTE"))
            return true;
    }
    return false;
}

static bool ffu_ranges_non_overlapping(const char *path) {
    struct range {
        const char *name;
        int first;
        int last;
    } ranges[] = {
        {"ipv4-unicast", g_ffu.ipv4_uc_first, g_ffu.ipv4_uc_last},
        {"ipv4-multicast", g_ffu.ipv4_mc_first, g_ffu.ipv4_mc_last},
        {"ipv6-unicast", g_ffu.ipv6_uc_first, g_ffu.ipv6_uc_last},
        {"ipv6-multicast", g_ffu.ipv6_mc_first, g_ffu.ipv6_mc_last},
        {"acl", g_ffu.acl_first, g_ffu.acl_last},
        {"cvlan", g_ffu.cvlan_first, g_ffu.cvlan_last},
        {"bst-routing", g_ffu.bst_routing_first, g_ffu.bst_routing_last},
    };
    int n_ranges = (int)(sizeof(ranges) / sizeof(ranges[0]));

    for (int i = 0; i < n_ranges; i++) {
        for (int j = i + 1; j < n_ranges; j++) {
            if (!slice_pair_overlap(ranges[i].first, ranges[i].last,
                                    ranges[j].first, ranges[j].last))
                continue;
            NL_LOG_ERR("platform profile %s FFU %s range %d-%d overlaps "
                       "%s range %d-%d", path,
                       ranges[i].name, ranges[i].first, ranges[i].last,
                       ranges[j].name, ranges[j].first, ranges[j].last);
            return false;
        }
    }
    return true;
}

static bool switch_index_exists(int index) {
    if (g_num_switches == 0)
        return true;
    for (int i = 0; i < g_num_switches; i++)
        if (g_switches[i].index == index)
            return true;
    return false;
}

static bool xcvr_exists(int resource_id) {
    if (resource_id < 0)
        return true;
    for (int i = 0; i < g_num_xcvrs; i++)
        if (g_xcvrs[i].resource_id == resource_id)
            return true;
    return false;
}

static nl_port_entry *find_loaded_port_by_name(const char *name) {
    if (!name || !name[0])
        return NULL;
    for (int i = 0; i < g_num_ports; i++)
        if (strcmp(g_ports[i].canonical_name, name) == 0)
            return &g_ports[i];
    return NULL;
}

static bool profile_has_duplicate_ports(const char *path) {
    for (int i = 0; i < g_num_ports; i++) {
        for (int j = i + 1; j < g_num_ports; j++) {
            if (strcmp(g_ports[i].canonical_name,
                       g_ports[j].canonical_name) == 0) {
                NL_LOG_ERR("platform profile %s duplicate interface %s",
                           path, g_ports[i].canonical_name);
                return true;
            }
            if (g_ports[i].logical_port == g_ports[j].logical_port) {
                NL_LOG_ERR("platform profile %s duplicate logical-port %d",
                           path, g_ports[i].logical_port);
                return true;
            }
            if (g_ports[i].switch_id == g_ports[j].switch_id &&
                g_ports[i].port_index >= 0 && g_ports[j].port_index >= 0 &&
                g_ports[i].port_index == g_ports[j].port_index) {
                NL_LOG_ERR("platform profile %s duplicate switch %d "
                           "port-index %d", path, g_ports[i].switch_id,
                           g_ports[i].port_index);
                return true;
            }
        }
    }
    return false;
}

static bool profile_switches_valid(const char *path) {
    for (int i = 0; i < g_num_switches; i++) {
        if (g_switches[i].index < 0) {
            NL_LOG_ERR("platform profile %s invalid switch index", path);
            return false;
        }
        for (int j = i + 1; j < g_num_switches; j++) {
            if (g_switches[i].index == g_switches[j].index) {
                NL_LOG_ERR("platform profile %s duplicate switch index %d",
                           path, g_switches[i].index);
                return false;
            }
            if (g_switches[i].number == g_switches[j].number) {
                NL_LOG_ERR("platform profile %s duplicate switch number %d",
                           path, g_switches[i].number);
                return false;
            }
        }
    }
    return true;
}

static bool profile_xcvrs_valid(const char *path) {
    for (int i = 0; i < g_num_xcvrs; i++) {
        if (g_xcvrs[i].resource_id < 0) {
            NL_LOG_ERR("platform profile %s invalid xcvr resource-id", path);
            return false;
        }
        for (int j = i + 1; j < g_num_xcvrs; j++) {
            if (g_xcvrs[i].resource_id == g_xcvrs[j].resource_id) {
                NL_LOG_ERR("platform profile %s duplicate xcvr resource-id %d",
                           path, g_xcvrs[i].resource_id);
                return false;
            }
        }
    }
    return true;
}

static bool profile_refs_valid(const char *path) {
    for (int i = 0; i < g_num_ports; i++) {
        if (!switch_index_exists(g_ports[i].switch_id)) {
            NL_LOG_ERR("platform profile %s port %s references missing "
                       "switch-index %d", path, g_ports[i].canonical_name,
                       g_ports[i].switch_id);
            return false;
        }
        if (!xcvr_exists(g_ports[i].hw_resource_id)) {
            NL_LOG_ERR("platform profile %s port %s references missing "
                       "xcvr resource-id %d", path, g_ports[i].canonical_name,
                       g_ports[i].hw_resource_id);
            return false;
        }
    }

    for (int i = 0; i < g_num_lanes; i++) {
        nl_port_entry *p = find_loaded_port_by_name(g_lanes[i].ifname);
        if (!p) {
            NL_LOG_ERR("platform profile %s lane references missing "
                       "interface %s", path, g_lanes[i].ifname);
            return false;
        }
        if (!switch_index_exists(g_lanes[i].switch_id)) {
            NL_LOG_ERR("platform profile %s lane %s/%d references missing "
                       "switch-index %d", path, g_lanes[i].ifname,
                       g_lanes[i].index, g_lanes[i].switch_id);
            return false;
        }
        if (g_lanes[i].logical_port <= 0)
            g_lanes[i].logical_port = p->logical_port;
        if (g_lanes[i].port_index < 0)
            g_lanes[i].port_index = p->port_index;
    }

    for (int i = 0; i < g_num_lanes; i++) {
        for (int j = i + 1; j < g_num_lanes; j++) {
            if (g_lanes[i].switch_id == g_lanes[j].switch_id &&
                g_lanes[i].port_index == g_lanes[j].port_index &&
                g_lanes[i].index == g_lanes[j].index) {
                NL_LOG_ERR("platform profile %s duplicate switch %d "
                           "port-index %d lane %d", path,
                           g_lanes[i].switch_id, g_lanes[i].port_index,
                           g_lanes[i].index);
                return false;
            }
        }
    }
    return true;
}

static bool profile_identity_valid(const char *path) {
    if (!g_identity.model[0]) {
        NL_LOG_ERR("platform profile %s missing platform model", path);
        return false;
    }
    if (!g_identity.system_name[0]) {
        NL_LOG_ERR("platform profile %s missing platform system-name", path);
        return false;
    }
    if (!g_identity.has_system_mac) {
        NL_LOG_ERR("platform profile %s missing or invalid platform system-mac",
                   path);
        return false;
    }
    return true;
}

static bool board_i2c_addr_valid(int addr) {
    return addr >= 0x03 && addr <= 0x77;
}

static bool board_mux_value_valid(int value) {
    return value == 0x01 || value == 0x02 ||
           value == 0x04 || value == 0x08;
}

static bool profile_board_valid(const char *path) {
    int mux_values[4];

    if (!g_board.configured)
        return true;
    if (strcmp(g_board.model, "PE31625G24DiRA-MPS") != 0 ||
        strcmp(g_board.asic, "FM10840") != 0 ||
        strcasecmp(g_identity.model, g_board.asic) != 0 ||
        g_board.fci_count != 2 || g_board.i2c_bus < 0 ||
        !board_i2c_addr_valid(g_board.mux_addr) ||
        !board_i2c_addr_valid(g_board.cpld_ram_addr) ||
        !board_i2c_addr_valid(g_board.reset_gpio_addr) ||
        g_board.mux_addr != 0x58 ||
        g_board.cpld_ram_addr != 0x59 ||
        g_board.reset_gpio_addr != 0x64 ||
        g_board.fci_mux[0] != 0x01 ||
        g_board.fci_mux[1] != 0x02 ||
        g_board.environment_mux != 0x04 ||
        g_board.power_mux != 0x08 ||
        g_board.shared_memory_bytes != 4 * 1024 * 1024 ||
        g_board.tcam_entries != 32768 ||
        g_board.mac_nexthop_entries != 16384) {
        NL_LOG_ERR("platform profile %s invalid PE31625G24DiRA-MPS "
                   "board contract", path);
        return false;
    }
    mux_values[0] = g_board.fci_mux[0];
    mux_values[1] = g_board.fci_mux[1];
    mux_values[2] = g_board.environment_mux;
    mux_values[3] = g_board.power_mux;
    for (int i = 0; i < 4; i++) {
        if (!board_mux_value_valid(mux_values[i])) {
            NL_LOG_ERR("platform profile %s invalid board mux branch 0x%x",
                       path, mux_values[i]);
            return false;
        }
        for (int j = i + 1; j < 4; j++) {
            if (mux_values[i] == mux_values[j]) {
                NL_LOG_ERR("platform profile %s duplicate board mux branch "
                           "0x%x", path, mux_values[i]);
                return false;
            }
        }
    }
    return true;
}

static u64 profile_port_budget_speed(const nl_port_entry *p) {
    u64 speed = 0;

    if (!p)
        return 0;
    if (p->scheduler_speed > speed)
        speed = p->scheduler_speed;
    if (p->line_rate > speed)
        speed = p->line_rate;
    if (p->default_speed > speed)
        speed = p->default_speed;
    return speed;
}

static u64 profile_external_bandwidth_limit(void) {
    if (strcasecmp(g_identity.model, "FM10840") == 0)
        return 600000000000ULL;
    if (strcasecmp(g_identity.model, "FM10420") == 0)
        return 400000000000ULL;
    return 0;
}

static bool profile_bandwidth_valid(const char *path) {
    u64 limit = profile_external_bandwidth_limit();
    u64 used = 0;

    if (limit == 0)
        return true;
    for (int i = 0; i < g_num_ports; i++) {
        if (!(g_ports[i].flags & NL_PORT_FLAG_EXTERNAL))
            continue;
        used += profile_port_budget_speed(&g_ports[i]);
    }
    if (used <= limit)
        return true;

    NL_LOG_ERR("platform profile %s external Ethernet bandwidth %llu "
               "exceeds %s limit %llu",
               path, (unsigned long long)used, g_identity.model,
               (unsigned long long)limit);
    return false;
}

static bool profile_ffu_valid(const char *path) {
    bool route_slices;
    bool route_ports;

    if (!g_ffu.configured)
        return true;

    if (!slice_pair_valid(g_ffu.ipv4_uc_first, g_ffu.ipv4_uc_last) ||
        !slice_pair_valid(g_ffu.ipv4_mc_first, g_ffu.ipv4_mc_last) ||
        !slice_pair_valid(g_ffu.ipv6_uc_first, g_ffu.ipv6_uc_last) ||
        !slice_pair_valid(g_ffu.ipv6_mc_first, g_ffu.ipv6_mc_last) ||
        !slice_pair_valid(g_ffu.acl_first, g_ffu.acl_last) ||
        !slice_pair_valid(g_ffu.cvlan_first, g_ffu.cvlan_last) ||
        !slice_pair_valid(g_ffu.bst_routing_first,
                          g_ffu.bst_routing_last)) {
        NL_LOG_ERR("platform profile %s invalid FFU slice allocation", path);
        return false;
    }

    if (g_ffu.acl_first < 0 || g_ffu.acl_last < 0) {
        NL_LOG_ERR("platform profile %s FFU allocation must declare ACL range",
                   path);
        return false;
    }
    if (!ffu_ranges_non_overlapping(path))
        return false;

    route_slices = profile_route_slices_enabled();
    route_ports = profile_has_route_capable_external_port();
    if (route_ports && !route_slices) {
        NL_LOG_ERR("platform profile %s advertises ROUTE capability but "
                   "disables all L3 FFU route slices", path);
        return false;
    }
    if (route_slices && !route_ports) {
        NL_LOG_ERR("platform profile %s enables L3 FFU route slices but has "
                   "no external ROUTE-capable ports", path);
        return false;
    }
    return true;
}

static nl_status load_profile_file(const char *path) {
    FILE *f;
    char line[2048];
    int line_no = 0;
    int invalid_lines = 0;

    if (!path || !*path)
        return NL_ERR;
    f = fopen(path, "r");
    if (!f)
        return NL_ERR;

    reset_profile();
    while (fgets(line, sizeof(line), f)) {
        char *cursor = line;
        char kind[64];
        line_no++;
        trim(line);
        if (!line[0])
            continue;
        if (!next_token(&cursor, kind, sizeof(kind)))
            continue;
        if (strcmp(kind, "platform") == 0) {
            parse_platform_line(cursor);
        } else if (strcmp(kind, "board") == 0) {
            if (parse_board_line(cursor) != 0) {
                NL_LOG_WARN("platform profile %s:%d invalid board line",
                            path, line_no);
                invalid_lines++;
            }
        } else if (strcmp(kind, "switch") == 0) {
            if (add_switch_from_line(cursor) != 0) {
                NL_LOG_WARN("platform profile %s:%d invalid switch line",
                            path, line_no);
                invalid_lines++;
            }
        } else if (strcmp(kind, "port") == 0) {
            if (add_port_from_line(cursor) != 0) {
                NL_LOG_WARN("platform profile %s:%d invalid port line",
                            path, line_no);
                invalid_lines++;
            }
        } else if (strcmp(kind, "lane") == 0) {
            if (add_lane_from_line(cursor) != 0) {
                NL_LOG_WARN("platform profile %s:%d invalid lane line",
                            path, line_no);
                invalid_lines++;
            }
        } else if (strcmp(kind, "xcvr") == 0) {
            if (add_xcvr_from_line(cursor) != 0) {
                NL_LOG_WARN("platform profile %s:%d invalid xcvr line",
                            path, line_no);
                invalid_lines++;
            }
        } else if (strcmp(kind, "ffu") == 0) {
            if (parse_ffu_line(cursor) != 0) {
                NL_LOG_WARN("platform profile %s:%d invalid ffu line",
                            path, line_no);
                invalid_lines++;
            }
        } else {
            NL_LOG_WARN("platform profile %s:%d unknown record %s",
                        path, line_no, kind);
        }
    }
    fclose(f);

    if (invalid_lines > 0 || g_num_ports <= 0 || g_identity.max_ae < 0 ||
        !profile_identity_valid(path) || profile_has_duplicate_ports(path) ||
        !profile_switches_valid(path) || !profile_xcvrs_valid(path) ||
        !profile_refs_valid(path) || !profile_board_valid(path) ||
        !profile_bandwidth_valid(path) ||
        !profile_ffu_valid(path)) {
        reset_profile();
        return NL_ERR;
    }
    snprintf(g_loaded_profile, sizeof(g_loaded_profile), "%s", path);
    g_loaded = true;
    NL_LOG_INFO("ifid resolver loaded %d ports, %d switches, %d lanes, "
                "%d xcvrs from %s", g_num_ports, g_num_switches,
                g_num_lanes, g_num_xcvrs, path);
    return NL_OK;
}

static nl_status load_default_profile(void) {
    const char *env = getenv("NETLAB_PLATFORM_PROFILE");
    const char *root = getenv("NETLAB_ROOT");
    char root_profile[256] = {0};
    if (root && root[0]) {
        snprintf(root_profile, sizeof(root_profile),
                 "%s/config/platform/default.profile", root);
    }
    const char *paths[] = {
        "/var/lib/netlab/platform.profile",
        "/etc/netlab/platform.profile",
        root_profile,
        "config/platform/default.profile",
        NL_PLATFORM_DEFAULT_PROFILE,
        NULL
    };

    if (env && env[0]) {
        nl_status st = load_profile_file(env);
        if (st != NL_OK)
            NL_LOG_ERR("NETLAB_PLATFORM_PROFILE=%s failed to load", env);
        return st;
    }
    for (int i = 0; paths[i]; i++) {
        if (paths[i][0] && load_profile_file(paths[i]) == NL_OK)
            return NL_OK;
    }
    return NL_ERR;
}

static bool ensure_loaded(void) {
    if (g_loaded)
        return true;
    return nl_ifid_resolver_init(NULL) == NL_OK;
}

nl_status nl_ifid_resolver_init(const char *profile_path) {
    g_loaded = false;
    reset_profile();

    if (profile_path && profile_path[0] &&
        strcmp(profile_path, "default") != 0) {
        return load_profile_file(profile_path);
    }
    return load_default_profile();
}

void nl_ifid_resolver_destroy(void) {
    reset_profile();
    g_loaded = false;
}

u64 nl_ifid_resolve(const char *canonical_name) {
    nl_port_entry e;
    if (!canonical_name || !ensure_loaded())
        return 0;
    return nl_ifid_get_by_name(canonical_name, &e) ? e.interface_id : 0;
}

const char *nl_ifid_reverse(u64 interface_id) {
    if (!ensure_loaded())
        return NULL;
    for (int i = 0; i < g_num_ports; i++) {
        if (g_ports[i].interface_id == interface_id)
            return g_ports[i].canonical_name;
    }
    return NULL;
}

int nl_ifid_get_all(nl_port_entry *entries, int max) {
    int n;

    if (!ensure_loaded() || !entries || max <= 0)
        return 0;
    n = g_num_ports < max ? g_num_ports : max;
    for (int i = 0; i < n; i++)
        entries[i] = g_ports[i];
    return n;
}

bool nl_ifid_get_by_name(const char *canonical_name, nl_port_entry *out) {
    if (!canonical_name || !ensure_loaded())
        return false;
    for (int i = 0; i < g_num_ports; i++) {
        if (strcmp(g_ports[i].canonical_name, canonical_name) == 0) {
            if (out)
                *out = g_ports[i];
            return true;
        }
    }
    return false;
}

bool nl_ifid_get_by_logical_port(int logical_port, nl_port_entry *out) {
    if (logical_port <= 0 || !ensure_loaded())
        return false;
    for (int i = 0; i < g_num_ports; i++) {
        if (g_ports[i].logical_port == logical_port) {
            if (out)
                *out = g_ports[i];
            return true;
        }
    }
    return false;
}

int nl_ifid_name_to_logical_port(const char *canonical_name) {
    nl_port_entry e;
    return nl_ifid_get_by_name(canonical_name, &e) ? e.logical_port : 0;
}

bool nl_ifid_logical_port_to_name(int logical_port,
                                  char *out, size_t out_size) {
    nl_port_entry e;

    if (!out || out_size == 0)
        return false;
    out[0] = '\0';
    if (!nl_ifid_get_by_logical_port(logical_port, &e))
        return false;
    snprintf(out, out_size, "%s", e.canonical_name);
    return true;
}

bool nl_ifid_supports_tagged_trunk(const char *canonical_name) {
    nl_port_entry e;
    if (!nl_ifid_get_by_name(canonical_name, &e))
        return false;
    return (e.flags & NL_PORT_FLAG_TAGGED_TRUNK) != 0;
}

bool nl_ifid_lldp_default_enabled(int logical_port) {
    nl_port_entry e;
    if (!nl_ifid_get_by_logical_port(logical_port, &e))
        return false;
    return (e.flags & NL_PORT_FLAG_LLDP_DEFAULT) != 0;
}

bool nl_ifid_is_external(int logical_port) {
    nl_port_entry e;
    if (!nl_ifid_get_by_logical_port(logical_port, &e))
        return false;
    return (e.flags & NL_PORT_FLAG_EXTERNAL) != 0;
}

bool nl_ifid_is_cpu_port(int logical_port) {
    nl_port_entry e;

    if (logical_port <= 0 || !ensure_loaded())
        return false;

    for (int i = 0; i < g_num_switches; i++) {
        if (g_switches[i].cpu_port == logical_port)
            return true;
    }

    if (nl_ifid_get_by_logical_port(logical_port, &e))
        return (e.flags & NL_PORT_FLAG_CPU_CONTROL) != 0;
    return false;
}

bool nl_ifid_is_user_port(int logical_port) {
    nl_port_entry e;

    if (logical_port <= 0 || !ensure_loaded())
        return false;
    if (nl_ifid_is_cpu_port(logical_port))
        return false;
    if (!nl_ifid_get_by_logical_port(logical_port, &e))
        return false;
    return (e.flags & (NL_PORT_FLAG_HIDDEN |
                       NL_PORT_FLAG_CPU_CONTROL)) == 0;
}

bool nl_ifid_name_is_user_port(const char *canonical_name) {
    nl_port_entry e;

    if (!canonical_name || !ensure_loaded())
        return false;
    if (!nl_ifid_get_by_name(canonical_name, &e))
        return false;
    return nl_ifid_is_user_port(e.logical_port);
}

bool nl_platform_identity_get(nl_platform_identity *out) {
    if (!out || !ensure_loaded())
        return false;
    *out = g_identity;
    return true;
}

bool nl_platform_board_get(nl_board_profile *out) {
    if (!out || !ensure_loaded() || !g_board.configured)
        return false;
    *out = g_board;
    return true;
}

int nl_platform_get_switches(nl_switch_entry *entries, int max) {
    int n;

    if (!ensure_loaded() || !entries || max <= 0)
        return 0;
    n = g_num_switches < max ? g_num_switches : max;
    for (int i = 0; i < n; i++)
        entries[i] = g_switches[i];
    return n;
}

int nl_platform_get_lanes(nl_lane_entry *entries, int max) {
    int n;

    if (!ensure_loaded() || !entries || max <= 0)
        return 0;
    n = g_num_lanes < max ? g_num_lanes : max;
    for (int i = 0; i < n; i++)
        entries[i] = g_lanes[i];
    return n;
}

int nl_platform_get_xcvrs(nl_xcvr_entry *entries, int max) {
    int n;

    if (!ensure_loaded() || !entries || max <= 0)
        return 0;
    n = g_num_xcvrs < max ? g_num_xcvrs : max;
    for (int i = 0; i < n; i++)
        entries[i] = g_xcvrs[i];
    return n;
}

bool nl_platform_ffu_slices(nl_ffu_slice_allocation *out) {
    if (!out || !ensure_loaded() || !g_ffu.configured)
        return false;
    *out = g_ffu;
    return true;
}

int nl_platform_max_ae(void) {
    if (!ensure_loaded())
        return 0;
    return g_identity.max_ae;
}

bool nl_platform_system_mac(u8 mac[NL_MAC_ADDR_LEN]) {
    if (!mac || !ensure_loaded() || !g_identity.has_system_mac)
        return false;
    memcpy(mac, g_identity.system_mac, NL_MAC_ADDR_LEN);
    return true;
}

const char *nl_platform_loaded_profile(void) {
    return ensure_loaded() ? g_loaded_profile : NULL;
}
