/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "l2_plan_text.h"

#include "netlab/hal.h"
#include "netlab/hal_qos.h"
#include "netlab/fm10k_plan_codec.h"
#include "netlab/interface_id.h"
#include "netlab/l2_plan.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define L2D_INTERFACE_MIN_MTU 1514
#define L2D_INTERFACE_MAX_MTU 9216

static int plan_text_get_int(const char *text, const char *key, int def) {
    char value[32];
    char *end = NULL;
    long parsed;

    if (!l2_plan_text_get_str(text, key, value, sizeof(value)))
        return def;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed < INT_MIN ||
        parsed > INT_MAX)
        return def;
    return (int)parsed;
}

static u64 plan_text_get_u64(const char *text, const char *key, u64 def) {
    char value[32];
    char *end = NULL;
    unsigned long long parsed;

    if (!l2_plan_text_get_str(text, key, value, sizeof(value)))
        return def;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || !end || *end != '\0')
        return def;
    return (u64)parsed;
}

bool l2_plan_text_get_str(const char *text, const char *key,
                          char *out, size_t out_size) {
    const char *p = text;
    size_t key_len;
    size_t len = 0;

    if (!text || !key || !out || out_size == 0)
        return false;
    out[0] = '\0';
    key_len = strlen(key);
    while ((p = strstr(p, key))) {
        if ((p == text || isspace((unsigned char)p[-1])) &&
            p[key_len] == '=') {
            p += key_len + 1;
            while (p[len] && !isspace((unsigned char)p[len]))
                len++;
            if (len >= out_size)
                len = out_size - 1;
            memcpy(out, p, len);
            out[len] = '\0';
            return true;
        }
        p += key_len;
    }
    return false;
}

static bool valid_plan_mac(const char *text) {
    unsigned int b[6];

    if (!text)
        return false;
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return false;
    if (b[0] & 0x01)
        return false;
    for (int i = 0; i < 6; i++)
        if (b[i] > 0xff)
            return false;
    return b[0] || b[1] || b[2] || b[3] || b[4] || b[5];
}

static bool valid_plan_ipv4(const char *text) {
    struct in_addr addr;
    u32 host;

    if (!text || inet_pton(AF_INET, text, &addr) != 1)
        return false;
    host = ntohl(addr.s_addr);
    return host != 0 && host != 0xffffffffU;
}

static bool valid_igmp_group(const char *text) {
    struct in_addr addr;
    u32 host;

    if (!text || inet_pton(AF_INET, text, &addr) != 1)
        return false;
    host = ntohl(addr.s_addr);
    return host >= 0xe0000100U && host <= 0xefffffffU;
}

static bool valid_user_filter_field(const char *text) {
    return !text || !text[0] ||
           strcmp(text, "source") == 0 ||
           strcmp(text, "source-mac") == 0 ||
           strcmp(text, "destination") == 0 ||
           strcmp(text, "destination-mac") == 0;
}

static bool valid_single_port_range_text(const char *text) {
    int start = -1;
    int end = -1;
    char extra = '\0';

    if (!text || sscanf(text, "%d-%d%c", &start, &end, &extra) != 2)
        return false;
    return start == end && start >= 0 && end <= 65535;
}

static bool known_logical_port(int port) {
    nl_port_entry entry;

    if (port <= 0)
        return false;
    if (!nl_ifid_get_by_logical_port(port, &entry))
        return false;
    return nl_ifid_is_user_port(port);
}

static bool valid_copp_class(const char *name) {
    return name && (strcmp(name, "rstp") == 0 ||
                    strcmp(name, "lldp") == 0 ||
                    strcmp(name, "lacp") == 0 ||
                    strcmp(name, "igmp") == 0 ||
                    strcmp(name, "arp") == 0 ||
                    strcmp(name, "icmp") == 0 ||
                    strcmp(name, "ospf") == 0 ||
                    strcmp(name, "bgp") == 0);
}

static bool valid_plan_ae(int ae_id) {
    int max_ae = nl_platform_max_ae();

    return ae_id >= 0 && ae_id < max_ae;
}

static bool valid_plan_target(int port, int ae_id) {
    if (port > 0)
        return known_logical_port(port);
    return valid_plan_ae(ae_id);
}

static bool valid_vid(int vid) {
    return vid >= 1 && vid <= 4094;
}

static bool valid_mirror_sources(const char *text, int destination) {
    char buf[512];
    char *save = NULL;
    char *token;
    int ports[NETLAB_MIRROR_MAX_SOURCES];
    int n_ports = 0;

    if (!text || !text[0] || strlen(text) >= sizeof(buf))
        return false;
    snprintf(buf, sizeof(buf), "%s", text);
    token = strtok_r(buf, ",", &save);
    while (token) {
        char *colon = strchr(token, ':');
        char extra = '\0';
        int port = 0;
        int direction = 0;

        if (!colon || sscanf(token, "%d:%d%c", &port, &direction,
                             &extra) != 2 ||
            !known_logical_port(port) || port == destination ||
            direction < HAL_MIRROR_DIRECTION_INGRESS ||
            direction > HAL_MIRROR_DIRECTION_BOTH ||
            n_ports >= NETLAB_MIRROR_MAX_SOURCES)
            return false;
        for (int i = 0; i < n_ports; i++)
            if (ports[i] == port)
                return false;
        ports[n_ports++] = port;
        token = strtok_r(NULL, ",", &save);
    }
    return n_ports > 0;
}

static bool op_is(const char *op, const char *name) {
    return op && strcmp(op, name) == 0;
}

static int validate_plan_line(const char *op, const char *kv,
                              char *err, size_t err_size) {
    int vid = plan_text_get_int(kv, "vid", 0);
    int port = plan_text_get_int(kv, "port", 0);
    int ae_id = plan_text_get_int(kv, "ae", -1);
    int tagged = plan_text_get_int(kv, "tagged", -1);
    int mode = plan_text_get_int(kv, "mode", -1);
    int state = plan_text_get_int(kv, "state", -1);
    int seconds = plan_text_get_int(kv, "seconds", -1);
    int rate = plan_text_get_int(kv, "rate", -1);
    int burst = plan_text_get_int(kv, "burst", -1);
    int mtu = plan_text_get_int(kv, "mtu", -1);
    int speed = plan_text_get_int(kv, "speed", -1);
    int rotation = plan_text_get_int(kv, "rotation", -1);
    int rate_pps = plan_text_get_int(kv, "rate-pps", -1);
    int burst_pkts = plan_text_get_int(kv, "burst-pkts", -1);
    int trust = plan_text_get_int(kv, "trust", -1);
    int default_priority = plan_text_get_int(kv, "default-priority", -1);
    int priority = plan_text_get_int(kv, "priority", -1);
    int traffic_class = plan_text_get_int(kv, "traffic-class", -1);
    int shaping_group = plan_text_get_int(kv, "shaping-group", -1);
    int tc_enable_mask = plan_text_get_int(kv, "traffic-class-enable-mask", -1);
    int scheduler_group = plan_text_get_int(kv, "group", -1);
    int strict = plan_text_get_int(kv, "strict", -1);
    int weight = plan_text_get_int(kv, "weight", -1);
    u64 group_rate_bps = plan_text_get_u64(kv, "rate-bps", 0);
    u64 group_burst_bits = plan_text_get_u64(kv, "burst-bits", 0);
    int rx_class_mask = plan_text_get_int(kv, "rx-class-mask", -1);
    int tx_class_mask = plan_text_get_int(kv, "tx-class-mask", -1);
    int lossless_smp_mask = plan_text_get_int(kv, "lossless-smp-mask", -1);
    int shared_pause_mask = plan_text_get_int(kv, "shared-pause-mask", -1);

    if (op_is(op, "fm10k-group-set")) {
        fm10k_group group;
        if (!nl_fm10k_parse_group(kv, &group)) goto invalid;
        return 0;
    }
    if (op_is(op, "fm10k-fan-set")) {
        fm10k_fan_curve curve;
        if (!nl_fm10k_parse_fan(kv, &curve)) goto invalid;
        return 0;
    }

    if (op_is(op, "vlan-create") || op_is(op, "vlan-delete")) {
        if (!valid_vid(vid))
            goto invalid;
        return 0;
    }
    if (op_is(op, "vlan-add-port") || op_is(op, "vlan-rem-port")) {
        if (!valid_vid(vid) || !valid_plan_target(port, ae_id) ||
            (tagged != 0 && tagged != 1))
            goto invalid;
        return 0;
    }
    if (op_is(op, "pvid-set")) {
        if (!valid_vid(vid) || !valid_plan_target(port, ae_id))
            goto invalid;
        return 0;
    }
    if (op_is(op, "stp-set")) {
        if (!valid_vid(vid) || !valid_plan_target(port, ae_id) ||
            state < 0 || state > 4)
            goto invalid;
        return 0;
    }
    if (op_is(op, "port-set-admin")) {
        if (!known_logical_port(port) || mode < 0 || mode > 2)
            goto invalid;
        return 0;
    }
    if (op_is(op, "port-set-mtu")) {
        if (!valid_plan_target(port, ae_id) ||
            mtu < L2D_INTERFACE_MIN_MTU ||
            mtu > L2D_INTERFACE_MAX_MTU)
            goto invalid;
        return 0;
    }
    if (op_is(op, "port-set-speed")) {
        if (!known_logical_port(port) ||
            (speed != NL_PORT_SPEED_10G_MBPS &&
             speed != NL_PORT_SPEED_25G_MBPS))
            goto invalid;
        return 0;
    }
    if (op_is(op, "port-parser-set")) {
        if (!valid_plan_target(port, ae_id) || mode < 0 || mode > 2)
            goto invalid;
        return 0;
    }
    if (op_is(op, "port-ingress-filter-set")) {
        int enabled = plan_text_get_int(kv, "enabled", -1);
        if (!valid_plan_target(port, ae_id) || (enabled != 0 && enabled != 1))
            goto invalid;
        return 0;
    }
    if (op_is(op, "mac-aging-set")) {
        if (seconds < 0 || seconds > 1000000)
            goto invalid;
        return 0;
    }
    if (op_is(op, "static-mac-add") || op_is(op, "static-mac-del")) {
        char mac[32];
        if (!valid_vid(vid) ||
            !l2_plan_text_get_str(kv, "mac", mac, sizeof(mac)) ||
            !valid_plan_mac(mac))
            goto invalid;
        if (op_is(op, "static-mac-add") &&
            !valid_plan_target(port, ae_id))
            goto invalid;
        return 0;
    }
    if (op_is(op, "igmp-listener-set") ||
        op_is(op, "igmp-listener-del")) {
        char group[32];

        if (!valid_vid(vid) || !known_logical_port(port) ||
            !l2_plan_text_get_str(kv, "group", group, sizeof(group)) ||
            !valid_igmp_group(group))
            goto invalid;
        return 0;
    }
    if (op_is(op, "lag-create") || op_is(op, "lag-delete")) {
        if (!valid_plan_ae(ae_id))
            goto invalid;
        return 0;
    }
    if (op_is(op, "lag-add-port") || op_is(op, "lag-del-port")) {
        if (!valid_plan_ae(ae_id) || !known_logical_port(port))
            goto invalid;
        return 0;
    }
    if (op_is(op, "lag-hash-rotation-set")) {
        if (!valid_plan_ae(ae_id) || (rotation != 0 && rotation != 1))
            goto invalid;
        return 0;
    }
    if (op_is(op, "storm-control-set")) {
        char kind[32] = "combined";
        if (!l2_plan_text_get_str(kv, "kind", kind, sizeof(kind)))
            strcpy(kind, "combined");
        if (!known_logical_port(port) ||
            nl_storm_kind_parse(kind) == NL_STORM_INVALID ||
            rate < 22000 || rate > 100000000 ||
            burst <= 0 || burst > 104857600)
            goto invalid;
        return 0;
    }
    if (op_is(op, "storm-control-del")) {
        char kind[32] = "combined";
        if (!l2_plan_text_get_str(kv, "kind", kind, sizeof(kind)))
            strcpy(kind, "combined");
        if (!known_logical_port(port) || nl_storm_kind_parse(kind) == NL_STORM_INVALID)
            goto invalid;
        return 0;
    }
    if (op_is(op, "ingress-rate-limit-set")) {
        if (!known_logical_port(port) ||
            rate < 22000 || rate > 100000000 ||
            burst <= 0 || burst > 104857600)
            goto invalid;
        return 0;
    }
    if (op_is(op, "ingress-rate-limit-del")) {
        if (!known_logical_port(port))
            goto invalid;
        return 0;
    }
    if (op_is(op, "egress-rate-limit-set")) {
        if (!known_logical_port(port) ||
            rate < 22000 || rate > 100000000 ||
            burst <= 0 || burst > 8387584)
            goto invalid;
        return 0;
    }
    if (op_is(op, "egress-rate-limit-del")) {
        if (!known_logical_port(port))
            goto invalid;
        return 0;
    }
    if (op_is(op, "acl-policer-set") || op_is(op, "acl-policer-del")) {
        char mac[32];
        if (!known_logical_port(port) ||
            !l2_plan_text_get_str(kv, "dst-mac", mac, sizeof(mac)) ||
            !valid_plan_mac(mac))
            goto invalid;
        if (op_is(op, "acl-policer-set") &&
            (rate < 1 || rate > 100000000 ||
             burst < 1024 || burst > 268435456))
            goto invalid;
        return 0;
    }
    if (op_is(op, "egress-acl-set") || op_is(op, "egress-acl-del")) {
        char src_mac[32];
        char dst_mac[32];
        char action[16] = "drop";
        bool has_src = l2_plan_text_get_str(kv, "src-mac", src_mac,
                                            sizeof(src_mac));
        bool has_dst = l2_plan_text_get_str(kv, "dst-mac", dst_mac,
                                            sizeof(dst_mac));
        if (!known_logical_port(port) || (!has_src && !has_dst))
            goto invalid;
        if ((has_src && !valid_plan_mac(src_mac)) ||
            (has_dst && !valid_plan_mac(dst_mac)))
            goto invalid;
        if (l2_plan_text_get_str(kv, "action", action, sizeof(action)) &&
            strcmp(action, "drop") != 0)
            goto invalid;
        return 0;
    }
    if (op_is(op, "acl-independent-set") ||
        op_is(op, "acl-independent-del")) {
        char group[64];
        char term[64];
        char family[32];
        char src_mac[32];
        char dst_mac[32];
        char src_ip[32];
        char dst_ip[32];
        char src_mask[32];
        char dst_mask[32];
        char src_range[32];
        char dst_range[32];
        char action[16] = "drop";
        bool has_src_mac;
        bool has_dst_mac;
        bool has_src_ip;
        bool has_dst_ip;
        bool has_src_mask;
        bool has_dst_mask;
        bool has_src_range;
        bool has_dst_range;
        bool has_mac;
        bool has_inet;
        int slot = plan_text_get_int(kv, "slot", -1);
        int dscp = plan_text_get_int(kv, "dscp", -1);
        int ecn = plan_text_get_int(kv, "ecn", -1);
        int proto = plan_text_get_int(kv, "proto", -1);
        int src_port = plan_text_get_int(kv, "src-port", -1);
        int dst_port = plan_text_get_int(kv, "dst-port", -1);
        int tcp_flags = plan_text_get_int(kv, "tcp-flags", -1);
        int tcp_flags_mask = plan_text_get_int(kv, "tcp-flags-mask", -1);

        if (!l2_plan_text_get_str(kv, "group", group, sizeof(group)) ||
            !l2_plan_text_get_str(kv, "term", term, sizeof(term)) ||
            !l2_plan_text_get_str(kv, "family", family, sizeof(family)) ||
            group[0] == '\0' || term[0] == '\0' ||
            slot < 0 || slot >= 32)
            goto invalid;
        if (!valid_vid(vid) || !known_logical_port(port))
            goto invalid;

        has_src_mac = l2_plan_text_get_str(kv, "src-mac", src_mac,
                                           sizeof(src_mac));
        has_dst_mac = l2_plan_text_get_str(kv, "dst-mac", dst_mac,
                                           sizeof(dst_mac));
        has_src_ip = l2_plan_text_get_str(kv, "src-ip", src_ip,
                                          sizeof(src_ip));
        has_dst_ip = l2_plan_text_get_str(kv, "dst-ip", dst_ip,
                                          sizeof(dst_ip));
        has_src_mask = l2_plan_text_get_str(kv, "src-mask", src_mask,
                                            sizeof(src_mask));
        has_dst_mask = l2_plan_text_get_str(kv, "dst-mask", dst_mask,
                                            sizeof(dst_mask));
        has_src_range = l2_plan_text_get_str(kv, "src-port-range",
                                             src_range, sizeof(src_range));
        has_dst_range = l2_plan_text_get_str(kv, "dst-port-range",
                                             dst_range, sizeof(dst_range));
        has_mac = has_src_mac || has_dst_mac;
        has_inet = has_src_ip || has_dst_ip || dscp >= 0 || proto >= 0 ||
                   src_port >= 0 || dst_port >= 0 ||
                   has_src_range || has_dst_range || tcp_flags >= 0;
        if ((has_src_mac && !valid_plan_mac(src_mac)) ||
            (has_dst_mac && !valid_plan_mac(dst_mac)))
            goto invalid;
        if ((has_src_ip && !valid_plan_ipv4(src_ip)) ||
            (has_dst_ip && !valid_plan_ipv4(dst_ip)) ||
            (has_src_mask && (!has_src_ip || !valid_plan_ipv4(src_mask))) ||
            (has_dst_mask && (!has_dst_ip || !valid_plan_ipv4(dst_mask))))
            goto invalid;
        if (dscp > 63 || ecn >= 0 || proto > 255 ||
            src_port > 65535 || dst_port > 65535 ||
            tcp_flags > 63 || tcp_flags_mask > 63 || tcp_flags_mask == 0)
            goto invalid;
        if ((has_src_range && !valid_single_port_range_text(src_range)) ||
            (has_dst_range && !valid_single_port_range_text(dst_range)))
            goto invalid;
        if ((src_port >= 0 || dst_port >= 0 ||
             has_src_range || has_dst_range) &&
            (proto != 6 && proto != 17))
            goto invalid;
        if (tcp_flags >= 0 &&
            (proto != 6 || (tcp_flags_mask >= 0 &&
             (tcp_flags & ~tcp_flags_mask) != 0)))
            goto invalid;
        if (l2_plan_text_get_str(kv, "action", action, sizeof(action)) &&
            strcmp(action, "drop") != 0 &&
            strcmp(action, "count") != 0 &&
            strcmp(action, "policer") != 0)
            goto invalid;
        if (strcmp(family, "ethernet") == 0) {
            if (!has_mac || has_inet)
                goto invalid;
        } else if (strcmp(family, "inet") == 0) {
            if (has_mac || !has_inet)
                goto invalid;
        } else if (strcmp(family, "policer") == 0) {
            if (has_mac == has_inet)
                goto invalid;
        } else {
            goto invalid;
        }
        if ((strcmp(family, "policer") == 0 ||
             strcmp(action, "policer") == 0) &&
            (rate < 1 || rate > 100000000 ||
             burst < 1024 || burst > 268435456))
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-interface-set")) {
        if (!valid_plan_target(port, ae_id) ||
            trust < 0 || trust > 2 ||
            default_priority < 0 || default_priority > 7)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-interface-del")) {
        if (!valid_plan_target(port, ae_id))
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-tc-smp-set")) {
        int smp = plan_text_get_int(kv, "smp", -1);
        if (traffic_class < 0 || traffic_class > 7 || smp < 0 || smp > 1)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-dscp-set")) {
        int dscp = plan_text_get_int(kv, "dscp", -1);
        if (dscp < 0 || dscp > 63 || priority < 0 || priority > 15)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-pfc-set")) {
        fm10k_pfc_wd_policy watchdog = {
            (uint32_t)plan_text_get_int(kv, "watchdog-detect-ms", 0),
            (uint32_t)plan_text_get_int(kv, "watchdog-recovery-ms", 100),
            (uint32_t)plan_text_get_int(kv, "watchdog-cooldown-ms", 30000)};
        if (!known_logical_port(port) ||
            rx_class_mask < 0 || rx_class_mask > 255 ||
            tx_class_mask < 0 || tx_class_mask > 255 ||
            lossless_smp_mask < 0 || lossless_smp_mask > 3 ||
            shared_pause_mask < 0 || shared_pause_mask > 3 ||
            !fm10k_pfc_wd_policy_valid(&watchdog) ||
            (watchdog.detect_ms && (rx_class_mask != 8 || tx_class_mask != 8 ||
                                   lossless_smp_mask != 2 || shared_pause_mask != 2)))
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-pfc-del")) {
        if (!known_logical_port(port))
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-priority-map-set")) {
        if (priority < 0 || priority > 15 ||
            traffic_class < 0 || traffic_class > 7)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-priority-map-del")) {
        if (priority < 0 || priority > 15)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-scheduler-tc-map-set")) {
        if (!known_logical_port(port) ||
            traffic_class < 0 || traffic_class > 7 ||
            shaping_group < 0 || shaping_group > 7)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-scheduler-tc-map-del")) {
        if (!known_logical_port(port) ||
            traffic_class < 0 || traffic_class > 7)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-scheduler-group-set")) {
        if (!known_logical_port(port) ||
            scheduler_group < 0 || scheduler_group > 7 ||
            (strict != 0 && strict != 1) ||
            weight < 0 || weight > 16777215)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-scheduler-group-del")) {
        if (!known_logical_port(port) ||
            scheduler_group < 0 || scheduler_group > 7)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-scheduler-group-shaping-set")) {
        if (!known_logical_port(port) ||
            scheduler_group < 0 || scheduler_group > 7 ||
            group_rate_bps < 1 || group_rate_bps > 100000000000ULL ||
            group_burst_bits < 1 || group_burst_bits > 67100672ULL)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-scheduler-group-shaping-del")) {
        if (!known_logical_port(port) ||
            scheduler_group < 0 || scheduler_group > 7)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-scheduler-port-set")) {
        if (!known_logical_port(port) ||
            tc_enable_mask < 1 || tc_enable_mask > 255)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-scheduler-port-del")) {
        if (!known_logical_port(port))
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-watermark-set")) {
        int attr = plan_text_get_int(kv, "attr", -1);
        int index = plan_text_get_int(kv, "index", -1);
        int value = plan_text_get_int(kv, "value", -1);
        int owner_create = plan_text_get_int(kv, "owner-create", 0);
        int reconcile = plan_text_get_int(kv, "reconcile", 0);
        bool closed_bit_attr =
            attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
            attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE;
        bool port_attr = attr == HAL_QOS_WATERMARK_ATTR_TX_HOG ||
                         attr == HAL_QOS_WATERMARK_ATTR_TX_PRIVATE;
        bool switch_attr =
            attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
            attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
            attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;

        if (closed_bit_attr) {
            snprintf(err, err_size,
                     "qos watermark attrs 11/12 are per-port priorities "
                     "but are not open in the L2 product model");
            return -1;
        }
        if ((!port_attr && !switch_attr) ||
            (port_attr && !known_logical_port(port)) ||
            (switch_attr && port != 0) ||
            index < 0 || index > 7 ||
            (owner_create != 0 && owner_create != 1) ||
            (reconcile != 0 && reconcile != 1) ||
            (attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER &&
             value > 7) ||
            value < 0 || value > 6291264)
            goto invalid;
        return 0;
    }
    if (op_is(op, "qos-watermark-del")) {
        int attr = plan_text_get_int(kv, "attr", -1);
        int index = plan_text_get_int(kv, "index", -1);
        int reconcile = plan_text_get_int(kv, "reconcile", 0);
        bool closed_bit_attr =
            attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
            attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE;
        bool port_attr = attr == HAL_QOS_WATERMARK_ATTR_TX_HOG ||
                         attr == HAL_QOS_WATERMARK_ATTR_TX_PRIVATE;
        bool switch_attr =
            attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
            attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
            attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;

        if (closed_bit_attr) {
            snprintf(err, err_size,
                     "qos watermark attrs 11/12 are per-port priorities "
                     "but are not open in the L2 product model");
            return -1;
        }
        if ((!port_attr && !switch_attr) ||
            (port_attr && !known_logical_port(port)) ||
            (switch_attr && port != 0) ||
            index < 0 || index > 7 ||
            (reconcile != 0 && reconcile != 1))
            goto invalid;
        return 0;
    }
    if (op_is(op, "mirror-session-set")) {
        char sources[512];
        int group = plan_text_get_int(kv, "group", -1);
        int destination = plan_text_get_int(kv, "destination", 0);

        if (group != NETLAB_MIRROR_V1_GROUP ||
            !known_logical_port(destination) ||
            !l2_plan_text_get_str(kv, "sources", sources,
                                  sizeof(sources)) ||
            !valid_mirror_sources(sources, destination))
            goto invalid;
        return 0;
    }
    if (op_is(op, "mirror-session-del")) {
        if (plan_text_get_int(kv, "group", -1) !=
            NETLAB_MIRROR_V1_GROUP)
            goto invalid;
        return 0;
    }
    if (op_is(op, "dhcp-snooping-set") ||
        op_is(op, "dhcp-snooping-del") ||
        op_is(op, "arp-inspection-set") ||
        op_is(op, "arp-inspection-del")) {
        if (!valid_vid(vid) || !known_logical_port(port))
            goto invalid;
        return 0;
    }
    if (op_is(op, "arp-inspection-binding-set") ||
        op_is(op, "arp-inspection-binding-del")) {
        char mac[32];
        char ip[32];
        if (!valid_vid(vid) || !known_logical_port(port) ||
            !l2_plan_text_get_str(kv, "mac", mac, sizeof(mac)) ||
            !valid_plan_mac(mac) ||
            !l2_plan_text_get_str(kv, "ip", ip, sizeof(ip)) ||
            !valid_plan_ipv4(ip))
            goto invalid;
        return 0;
    }
    if (op_is(op, "user-filter-set") ||
        op_is(op, "user-filter-del")) {
        char mac[32];
        char field[32] = "";
        if (!valid_vid(vid) || !known_logical_port(port) ||
            !l2_plan_text_get_str(kv, "mac", mac, sizeof(mac)) ||
            !valid_plan_mac(mac))
            goto invalid;
        (void)l2_plan_text_get_str(kv, "field", field, sizeof(field));
        if (!valid_user_filter_field(field))
            goto invalid;
        return 0;
    }
    if (op_is(op, "ingress-ipv4-acl-set") ||
        op_is(op, "ingress-ipv4-acl-del")) {
        char src_ip[32];
        char dst_ip[32];
        char src_mask[32];
        char dst_mask[32];
        bool has_src_ip = l2_plan_text_get_str(kv, "src-ip", src_ip,
                                               sizeof(src_ip));
        bool has_dst_ip = l2_plan_text_get_str(kv, "dst-ip", dst_ip,
                                               sizeof(dst_ip));
        bool has_src_mask = l2_plan_text_get_str(kv, "src-mask", src_mask,
                                                 sizeof(src_mask));
        bool has_dst_mask = l2_plan_text_get_str(kv, "dst-mask", dst_mask,
                                                 sizeof(dst_mask));
        int dscp = plan_text_get_int(kv, "dscp", -1);
        int ecn = plan_text_get_int(kv, "ecn", -1);
        int proto = plan_text_get_int(kv, "proto", -1);
        int src_port = plan_text_get_int(kv, "src-port", -1);
        int dst_port = plan_text_get_int(kv, "dst-port", -1);
        int tcp_flags = plan_text_get_int(kv, "tcp-flags", -1);
        int tcp_flags_mask = plan_text_get_int(kv, "tcp-flags-mask", -1);
        char action[16] = "";

        if (!valid_vid(vid) || !known_logical_port(port))
            goto invalid;
        if (!has_src_ip && !has_dst_ip && dscp < 0 && ecn < 0 && proto < 0 &&
            src_port < 0 && dst_port < 0 && tcp_flags < 0)
            goto invalid;
        if (has_src_ip && !valid_plan_ipv4(src_ip))
            goto invalid;
        if (has_dst_ip && !valid_plan_ipv4(dst_ip))
            goto invalid;
        if ((has_src_mask && (!has_src_ip || !valid_plan_ipv4(src_mask))) ||
            (has_dst_mask && (!has_dst_ip || !valid_plan_ipv4(dst_mask))))
            goto invalid;
        if (dscp > 63 || ecn > 3 ||
            proto > 255 || src_port > 65535 || dst_port > 65535 ||
            tcp_flags > 63 || tcp_flags_mask > 63 || tcp_flags_mask == 0)
            goto invalid;
        if ((src_port >= 0 || dst_port >= 0) &&
            (proto != 6 && proto != 17))
            goto invalid;
        if ((tcp_flags >= 0 && proto != 6) ||
            (tcp_flags_mask >= 0 && tcp_flags < 0) ||
            (tcp_flags >= 0 && tcp_flags_mask >= 0 &&
             (tcp_flags & ~tcp_flags_mask) != 0))
            goto invalid;
        if (l2_plan_text_get_str(kv, "action", action, sizeof(action)) &&
            strcmp(action, "drop") != 0 && strcmp(action, "count") != 0)
            goto invalid;
        return 0;
    }
    if (op_is(op, "copp-class-set")) {
        char class_name[16];
        if (!l2_plan_text_get_str(kv, "class", class_name,
                                  sizeof(class_name)) ||
            !valid_copp_class(class_name) ||
            rate_pps < 1 || rate_pps > 1000000 ||
            burst_pkts < 1 || burst_pkts > 1000000)
            goto invalid;
        return 0;
    }

    snprintf(err, err_size, "unknown operation %s", op ? op : "-");
    return -1;

invalid:
    snprintf(err, err_size, "invalid %s parameters", op ? op : "-");
    return -1;
}

int l2_plan_text_validate(const char *text, int *steps,
                          char *err, size_t err_size) {
    const char *p = text;
    int n = 0;
    int line_no = 0;

    if (steps)
        *steps = 0;
    if (err && err_size > 0)
        err[0] = '\0';
    if (!text || !text[0])
        return 0;
    bool scope_present;
    uint32_t scope_mask;
    if (!nl_fm10k_parse_scope_header(text, strlen(text), &scope_present, &scope_mask)) {
        if (err && err_size) snprintf(err, err_size, "invalid FM10840 plan scope header");
        return -1;
    }

    while (p && *p) {
        const char *line_end;
        const char *sp;
        char op[64];
        char kv[512];
        int op_len;
        int kv_len;

        while (*p == '\n' || *p == '\r')
            p++;
        if (!*p)
            break;
        line_no++;
        while (*p == ' ' || *p == '\t')
            p++;
        line_end = strchr(p, '\n');
        if (!line_end)
            line_end = p + strlen(p);
        if (*p == '#') {
            p = line_end;
            continue;
        }
        sp = p;
        while (sp < line_end && *sp != ' ' && *sp != '\t')
            sp++;
        op_len = (int)(sp - p);
        if (op_len <= 0) {
            p = line_end;
            continue;
        }
        if (n >= NL_L2_PLAN_MAX_STEPS) {
            snprintf(err, err_size, "line %d: too many operations: max %d",
                     line_no, NL_L2_PLAN_MAX_STEPS);
            return -1;
        }
        if (op_len >= (int)sizeof(op))
            op_len = (int)sizeof(op) - 1;
        memcpy(op, p, (size_t)op_len);
        op[op_len] = '\0';
        while (sp < line_end && (*sp == ' ' || *sp == '\t'))
            sp++;
        kv_len = (int)(line_end - sp);
        if (kv_len >= (int)sizeof(kv)) {
            snprintf(err, err_size, "line %d: oversized operation arguments", line_no);
            return -1;
        }
        memcpy(kv, sp, (size_t)kv_len);
        kv[kv_len] = '\0';

        if (validate_plan_line(op, kv, err, err_size) != 0) {
            char detail[256];
            snprintf(detail, sizeof(detail), "line %d: %s", line_no,
                     err && err[0] ? err : "invalid operation");
            snprintf(err, err_size, "%s", detail);
            return -1;
        }
        n++;
        p = line_end;
    }
    if (steps)
        *steps = n;
    return 0;
}
