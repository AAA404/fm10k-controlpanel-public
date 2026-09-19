/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/fm10k_plan_codec.h"
#include <ctype.h>
#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    l2_step_type type;
} step_name_map;

static const step_name_map L2_STEP_NAMES[] = {
    {"fm10k-group-set",   L2_STEP_FM10K_GROUP_SET},
    {"fm10k-fan-set",     L2_STEP_FM10K_FAN_SET},
    {"vlan-create",       L2_STEP_VLAN_CREATE},
    {"vlan-delete",       L2_STEP_VLAN_DELETE},
    {"vlan-add-port",     L2_STEP_VLAN_ADD_PORT},
    {"vlan-rem-port",     L2_STEP_VLAN_REM_PORT},
    {"pvid-set",          L2_STEP_PVID_SET},
    {"stp-set",           L2_STEP_VLAN_STP_SET},
    {"port-set-admin",    L2_STEP_PORT_SET_ADMIN},
    {"port-set-mtu",      L2_STEP_PORT_SET_MTU},
    {"port-set-speed",    L2_STEP_PORT_SET_SPEED},
    {"port-parser-set",   L2_STEP_PORT_PARSER_SET},
    {"port-ingress-filter-set", L2_STEP_PORT_INGRESS_FILTER_SET},
    {"mac-aging-set",     L2_STEP_MAC_AGING_SET},
    {"static-mac-add",    L2_STEP_STATIC_MAC_ADD},
    {"static-mac-del",    L2_STEP_STATIC_MAC_DEL},
    {"lag-create",        L2_STEP_LAG_CREATE},
    {"lag-delete",        L2_STEP_LAG_DELETE},
    {"lag-add-port",      L2_STEP_LAG_ADD_PORT},
    {"lag-del-port",      L2_STEP_LAG_DEL_PORT},
    {"lag-hash-rotation-set", L2_STEP_LAG_HASH_ROTATION_SET},
    {"dhcp-snooping-set", L2_STEP_DHCP_SNOOPING_SET},
    {"dhcp-snooping-del", L2_STEP_DHCP_SNOOPING_DEL},
    {"arp-inspection-set", L2_STEP_ARP_INSPECTION_SET},
    {"arp-inspection-del", L2_STEP_ARP_INSPECTION_DEL},
    {"arp-inspection-binding-set", L2_STEP_ARP_INSPECTION_BINDING_SET},
    {"arp-inspection-binding-del", L2_STEP_ARP_INSPECTION_BINDING_DEL},
    {"user-filter-set", L2_STEP_USER_FILTER_SET},
    {"user-filter-del", L2_STEP_USER_FILTER_DEL},
    {"ingress-ipv4-acl-set", L2_STEP_INGRESS_IPV4_ACL_SET},
    {"ingress-ipv4-acl-del", L2_STEP_INGRESS_IPV4_ACL_DEL},
    {"acl-policer-set", L2_STEP_ACL_POLICER_SET},
    {"acl-policer-del", L2_STEP_ACL_POLICER_DEL},
    {"egress-acl-set", L2_STEP_EGRESS_ACL_SET},
    {"egress-acl-del", L2_STEP_EGRESS_ACL_DEL},
    {"acl-independent-set", L2_STEP_ACL_INDEPENDENT_SET},
    {"acl-independent-del", L2_STEP_ACL_INDEPENDENT_DEL},
    {"copp-class-set", L2_STEP_COPP_CLASS_SET},
    {"storm-control-set", L2_STEP_STORM_CONTROL_SET},
    {"storm-control-del", L2_STEP_STORM_CONTROL_DEL},
    {"ingress-rate-limit-set", L2_STEP_INGRESS_RATE_LIMIT_SET},
    {"ingress-rate-limit-del", L2_STEP_INGRESS_RATE_LIMIT_DEL},
    {"egress-rate-limit-set", L2_STEP_EGRESS_RATE_LIMIT_SET},
    {"egress-rate-limit-del", L2_STEP_EGRESS_RATE_LIMIT_DEL},
    {"qos-interface-set", L2_STEP_QOS_INTERFACE_SET},
    {"qos-interface-del", L2_STEP_QOS_INTERFACE_DEL},
    {"qos-tc-smp-set", L2_STEP_QOS_TC_SMP_SET},
    {"qos-dscp-set", L2_STEP_QOS_DSCP_SET},
    {"qos-pfc-set", L2_STEP_QOS_PFC_SET},
    {"qos-pfc-del", L2_STEP_QOS_PFC_DEL},
    {"qos-priority-map-set", L2_STEP_QOS_PRIORITY_MAP_SET},
    {"qos-priority-map-del", L2_STEP_QOS_PRIORITY_MAP_DEL},
    {"qos-scheduler-tc-map-set", L2_STEP_QOS_SCHEDULER_TC_MAP_SET},
    {"qos-scheduler-tc-map-del", L2_STEP_QOS_SCHEDULER_TC_MAP_DEL},
    {"qos-scheduler-group-set", L2_STEP_QOS_SCHEDULER_GROUP_SET},
    {"qos-scheduler-group-del", L2_STEP_QOS_SCHEDULER_GROUP_DEL},
    {"qos-scheduler-group-shaping-set",
     L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET},
    {"qos-scheduler-group-shaping-del",
     L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL},
    {"qos-scheduler-port-set", L2_STEP_QOS_SCHEDULER_PORT_SET},
    {"qos-scheduler-port-del", L2_STEP_QOS_SCHEDULER_PORT_DEL},
    {"qos-watermark-set", L2_STEP_QOS_WATERMARK_SET},
    {"qos-watermark-del", L2_STEP_QOS_WATERMARK_DEL},
    {"mirror-session-set", L2_STEP_MIRROR_SESSION_SET},
    {"mirror-session-del", L2_STEP_MIRROR_SESSION_DEL},
    {"igmp-listener-set", L2_STEP_IGMP_LISTENER_SET},
    {"igmp-listener-del", L2_STEP_IGMP_LISTENER_DEL},
    {NULL, L2_STEP_NONE}
};

static l2_step_type name_to_type(const char *name) {
    for (int i = 0; L2_STEP_NAMES[i].name; i++)
        if (strcmp(name, L2_STEP_NAMES[i].name) == 0)
            return L2_STEP_NAMES[i].type;
    return L2_STEP_NONE;
}


static const char *parse_kv_value(const char *text, const char *key) {
    const char *p = text;
    size_t key_len;

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

static int parse_kv_int(const char *text, const char *key, int def) {
    const char *p = parse_kv_value(text, key);

    if (!p)
        return def;
    return atoi(p);
}

static u64 parse_kv_u64(const char *text, const char *key, u64 def) {
    const char *p = parse_kv_value(text, key);

    if (!p)
        return def;
    return (u64)strtoull(p, NULL, 0);
}

static bool parse_kv_str(const char *text, const char *key,
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

static bool parse_mac_text(const char *text, u8 mac[6]) {
    unsigned int b[6];

    if (!text || !mac)
        return false;
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xff)
            return false;
        mac[i] = (u8)b[i];
    }
    return true;
}

static u64 mac_bytes_to_u64(const u8 mac[6]) {
    u64 value = 0;

    for (int i = 0; i < 6; i++)
        value = (value << 8) | mac[i];
    return value;
}

static bool mac_is_unicast_nonzero(const u8 mac[6]) {
    bool any = false;

    if (!mac || (mac[0] & 0x01))
        return false;
    for (int i = 0; i < 6; i++)
        any = any || mac[i] != 0;
    return any;
}

static int parse_security_mac_kind(const char *kv_buf) {
    char field[32];

    if (!parse_kv_str(kv_buf, "field", field, sizeof(field)))
        return L2_SECURITY_MAC_SOURCE;
    if (strcmp(field, "source") == 0 ||
        strcmp(field, "source-mac") == 0)
        return L2_SECURITY_MAC_SOURCE;
    if (strcmp(field, "destination") == 0 ||
        strcmp(field, "destination-mac") == 0)
        return L2_SECURITY_MAC_DESTINATION;
    return 0;
}

static bool parse_ipv4_text(const char *text, u32 *ip) {
    struct in_addr addr;

    if (!text || !ip || inet_pton(AF_INET, text, &addr) != 1)
        return false;
    *ip = ntohl(addr.s_addr);
    return true;
}

static bool parse_igmp_group(const char *text, u32 *ip, u8 mac[6]) {
    u32 group;

    if (!parse_ipv4_text(text, &group) || group < 0xe0000100U ||
        group > 0xefffffffU)
        return false;
    if (ip)
        *ip = group;
    mac[0] = 0x01;
    mac[1] = 0x00;
    mac[2] = 0x5e;
    mac[3] = (u8)((group >> 16) & 0x7f);
    mac[4] = (u8)((group >> 8) & 0xff);
    mac[5] = (u8)(group & 0xff);
    return true;
}

static bool parse_port_range_text(const char *text, int *start, int *end) {
    char buf[32];
    char *dash;
    char *endp;
    long lo;
    long hi;

    if (!text || !start || !end || strlen(text) >= sizeof(buf))
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

static bool valid_ae_id(int ae_id) {
    return ae_id >= 0 && ae_id < NETLAB_MAX_AE;
}

static bool acl_independent_family_valid(const char *family) {
    return family &&
           (strcmp(family, "ethernet") == 0 ||
            strcmp(family, "inet") == 0 ||
            strcmp(family, "policer") == 0 ||
            strcmp(family, "egress") == 0);
}

static bool acl_independent_action_valid(const char *family,
                                         const char *action) {
    if (!family || !action || !action[0])
        return false;
    if (strcmp(family, "egress") == 0)
        return strcmp(action, "drop") == 0 ||
               strcmp(action, "count") == 0;
    return strcmp(action, "drop") == 0 ||
           strcmp(action, "count") == 0 ||
           strcmp(action, "policer") == 0;
}

static bool acl_independent_has_inet_selector(
    const hal_ingress_ipv4_acl_match *m) {
    return m &&
           (m->has_src_ip || m->has_dst_ip || m->has_dscp ||
            m->has_ecn || m->has_protocol || m->has_src_port ||
            m->has_dst_port || m->has_src_port_range ||
            m->has_dst_port_range || m->has_tcp_flags);
}

static bool valid_port_target(const l2_apply_step *step) {
    if (!step)
        return false;
    if (step->port > 0)
        return true;
    return valid_ae_id(step->ae_id);
}

static bool parse_mirror_sources(const char *text, hal_mirror_state *state) {
    char buf[512];
    char *save = NULL;
    char *token;

    if (!text || !text[0] || !state || strlen(text) >= sizeof(buf))
        return false;
    snprintf(buf, sizeof(buf), "%s", text);
    token = strtok_r(buf, ",", &save);
    while (token) {
        char *colon = strchr(token, ':');
        char *end = NULL;
        long port;
        long direction;

        if (!colon || colon == token || colon[1] == '\0' ||
            strchr(colon + 1, ':') ||
            state->n_sources >= NETLAB_MIRROR_MAX_SOURCES)
            return false;
        *colon++ = '\0';
        port = strtol(token, &end, 10);
        if (!end || *end != '\0' || port <= 0 || port > INT_MAX)
            return false;
        direction = strtol(colon, &end, 10);
        if (!end || *end != '\0' ||
            direction < HAL_MIRROR_DIRECTION_INGRESS ||
            direction > HAL_MIRROR_DIRECTION_BOTH)
            return false;
        state->source_ports[state->n_sources] = (int)port;
        state->source_directions[state->n_sources] = (int)direction;
        state->n_sources++;
        token = strtok_r(NULL, ",", &save);
    }
    return state->n_sources > 0;
}

static int l2_plan_count_steps(const char *text) {
    const char *p = text;
    int count = 0;

    while (p && *p) {
        const char *line_end;

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
        if (!*p)
            break;
        line_end = strchr(p, '\n');
        if (!line_end)
            line_end = p + strlen(p);
        if (*p != '#') {
            count++;
            if (count > L2_PLAN_MAX_STEPS)
                return -1;
        }
        p = line_end;
    }
    return count;
}

int l2_plan_parse(const char *text, l2_apply_plan *plan) {
    const char *p;
    int expected;
    int n = 0;

    if (!text || !plan)
        return -1;
    expected = l2_plan_count_steps(text);
    if (expected <= 0) {
        NL_LOG_ERR("l2_plan_parse: empty or oversized plan");
        return -1;
    }
    l2_apply_plan_reset(plan);
    if (l2_apply_plan_allocate_steps(plan, expected) != 0) {
        NL_LOG_ERR("l2_plan_parse: cannot allocate %d operations", expected);
        return -1;
    }
    if (!nl_fm10k_parse_scope_header(text, strlen(text), &plan->fm10k_scope_present,
                                    &plan->fm10k_scope_mask)) return -1;

    p = text;
    while (p && *p) {
        const char *line_end;
        const char *sp;
        const char *kv;
        int name_len;
        int kv_len;
        char name[64];
        char kv_buf[768];
        l2_step_type type;
        l2_apply_step *step;

        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            p++;
        if (!*p)
            break;

        line_end = strchr(p, '\n');
        if (!line_end)
            line_end = p + strlen(p);

        if (*p == '#') {
            p = line_end;
            continue;
        }

        if (n >= plan->step_capacity) {
            NL_LOG_ERR("l2_plan_parse: operation count changed while parsing");
            return -1;
        }

        sp = p;
        while (sp < line_end && *sp != ' ' && *sp != '\t')
            sp++;
        name_len = (int)(sp - p);
        if (name_len == 0) {
            p = line_end;
            continue;
        }

        if (name_len > 63)
            name_len = 63;
        memcpy(name, p, (size_t)name_len);
        name[name_len] = 0;

        type = name_to_type(name);
        if (type == L2_STEP_NONE) {
            NL_LOG_ERR("l2_plan_parse: unknown operation '%s'", name);
            return -1;
        }

        step = &plan->steps[n];
        step->type = type;
        step->ae_id = -1;

        kv = sp;
        while (kv < line_end && (*kv == ' ' || *kv == '\t'))
            kv++;
        kv_len = (int)(line_end - kv);
        if ((size_t)kv_len >= sizeof(kv_buf)) {
            NL_LOG_ERR("l2_plan_parse: oversized operation arguments");
            return -1;
        }
        memcpy(kv_buf, kv, (size_t)kv_len);
        kv_buf[kv_len] = 0;

        switch (type) {
        case L2_STEP_FM10K_GROUP_SET:
            if (!nl_fm10k_parse_group(kv_buf, &step->fm10k_group)) return -1;
            break;
        case L2_STEP_FM10K_FAN_SET:
            if (!nl_fm10k_parse_fan(kv_buf, &step->fm10k_fan)) return -1;
            break;
        case L2_STEP_VLAN_CREATE:
        case L2_STEP_VLAN_DELETE:
            step->vid = (u16)parse_kv_int(kv_buf, "vid", 0);
            break;
        case L2_STEP_VLAN_ADD_PORT:
        case L2_STEP_VLAN_REM_PORT:
            step->vid = (u16)parse_kv_int(kv_buf, "vid", 0);
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            step->tagged = parse_kv_int(kv_buf, "tagged", 0) != 0;
            break;
        case L2_STEP_PVID_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            step->vid = (u16)parse_kv_int(kv_buf, "vid", 0);
            break;
        case L2_STEP_VLAN_STP_SET:
            step->vid = (u16)parse_kv_int(kv_buf, "vid", 0);
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            step->stp_state = parse_kv_int(kv_buf, "state", 3);
            break;
        case L2_STEP_PORT_SET_ADMIN:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->admin_mode = parse_kv_int(kv_buf, "mode", 0);
            break;
        case L2_STEP_PORT_SET_MTU:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            step->mtu = parse_kv_int(kv_buf, "mtu", 0);
            break;
        case L2_STEP_PORT_SET_SPEED:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->speed = parse_kv_int(kv_buf, "speed", 0);
            break;
        case L2_STEP_PORT_PARSER_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            step->parser_mode = parse_kv_int(kv_buf, "mode", 2);
            break;
        case L2_STEP_PORT_INGRESS_FILTER_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            step->ingress_filtering = parse_kv_int(kv_buf, "enabled", -1);
            break;
        case L2_STEP_MAC_AGING_SET:
            step->aging_time = parse_kv_int(kv_buf, "seconds", -1);
            break;
        case L2_STEP_STATIC_MAC_ADD:
        case L2_STEP_STATIC_MAC_DEL: {
            char mac_text[32];
            step->vid = (u16)parse_kv_int(kv_buf, "vid", 0);
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            if (!parse_kv_str(kv_buf, "mac", mac_text, sizeof(mac_text)) ||
                !parse_mac_text(mac_text, step->mac)) {
                NL_LOG_ERR("l2_plan_parse: invalid static MAC operation");
                return -1;
            }
            break;
        }
        case L2_STEP_LAG_CREATE:
        case L2_STEP_LAG_DELETE:
            step->ae_id = parse_kv_int(kv_buf, "ae", 0);
            break;
        case L2_STEP_LAG_ADD_PORT:
        case L2_STEP_LAG_DEL_PORT:
            step->ae_id = parse_kv_int(kv_buf, "ae", 0);
            step->port = parse_kv_int(kv_buf, "port", 0);
            break;
        case L2_STEP_LAG_HASH_ROTATION_SET:
            step->ae_id = parse_kv_int(kv_buf, "ae", 0);
            step->lag_hash_rotation = parse_kv_int(kv_buf, "rotation", -1);
            break;
        case L2_STEP_DHCP_SNOOPING_SET:
        case L2_STEP_DHCP_SNOOPING_DEL:
        case L2_STEP_ARP_INSPECTION_SET:
        case L2_STEP_ARP_INSPECTION_DEL:
            step->security_vid = parse_kv_int(kv_buf, "vid", 0);
            step->security_port = parse_kv_int(kv_buf, "port", 0);
            break;
        case L2_STEP_ARP_INSPECTION_BINDING_SET:
        case L2_STEP_ARP_INSPECTION_BINDING_DEL: {
            char mac_text[32];
            char ip_text[32];
            step->security_vid = parse_kv_int(kv_buf, "vid", 0);
            step->security_port = parse_kv_int(kv_buf, "port", 0);
            if (!parse_kv_str(kv_buf, "mac", mac_text, sizeof(mac_text)) ||
                !parse_mac_text(mac_text, step->security_mac) ||
                !parse_kv_str(kv_buf, "ip", ip_text, sizeof(ip_text)) ||
                !parse_ipv4_text(ip_text, &step->security_ip)) {
                NL_LOG_ERR("l2_plan_parse: invalid ARP inspection binding");
                return -1;
            }
            break;
        }
        case L2_STEP_USER_FILTER_SET:
        case L2_STEP_USER_FILTER_DEL: {
            char mac_text[32];
            step->security_vid = parse_kv_int(kv_buf, "vid", 0);
            step->security_port = parse_kv_int(kv_buf, "port", 0);
            step->security_mac_kind = parse_security_mac_kind(kv_buf);
            if (!parse_kv_str(kv_buf, "mac", mac_text, sizeof(mac_text)) ||
                !parse_mac_text(mac_text, step->security_mac)) {
                NL_LOG_ERR("l2_plan_parse: invalid user filter");
                return -1;
            }
            break;
        }
        case L2_STEP_INGRESS_IPV4_ACL_SET:
        case L2_STEP_INGRESS_IPV4_ACL_DEL: {
            char src_ip[32];
            char dst_ip[32];
            char src_mask[32];
            char dst_mask[32];
            char src_port_range[32];
            char dst_port_range[32];
            char action[16] = "";
            hal_ingress_ipv4_acl_match *m = &step->ingress_ipv4_acl;

            memset(m, 0, sizeof(*m));
            m->vid = parse_kv_int(kv_buf, "vid", 0);
            m->port = parse_kv_int(kv_buf, "port", 0);
            if (parse_kv_str(kv_buf, "src-ip", src_ip, sizeof(src_ip))) {
                if (!parse_ipv4_text(src_ip, &m->src_ip)) {
                    NL_LOG_ERR("l2_plan_parse: invalid ingress IPv4 ACL source IP");
                    return -1;
                }
                m->has_src_ip = true;
                if (parse_kv_str(kv_buf, "src-mask", src_mask,
                                 sizeof(src_mask))) {
                    if (!parse_ipv4_text(src_mask, &m->src_ip_mask)) {
                        NL_LOG_ERR("l2_plan_parse: invalid ingress IPv4 ACL source mask");
                        return -1;
                    }
                } else {
                    m->src_ip_mask = 0xffffffffU;
                }
                m->has_src_ip_mask = true;
            }
            if (parse_kv_str(kv_buf, "dst-ip", dst_ip, sizeof(dst_ip))) {
                if (!parse_ipv4_text(dst_ip, &m->dst_ip)) {
                    NL_LOG_ERR("l2_plan_parse: invalid ingress IPv4 ACL destination IP");
                    return -1;
                }
                m->has_dst_ip = true;
                if (parse_kv_str(kv_buf, "dst-mask", dst_mask,
                                 sizeof(dst_mask))) {
                    if (!parse_ipv4_text(dst_mask, &m->dst_ip_mask)) {
                        NL_LOG_ERR("l2_plan_parse: invalid ingress IPv4 ACL destination mask");
                        return -1;
                    }
                } else {
                    m->dst_ip_mask = 0xffffffffU;
                }
                m->has_dst_ip_mask = true;
            }
            m->protocol = parse_kv_int(kv_buf, "proto", -1);
            if (m->protocol >= 0)
                m->has_protocol = true;
            m->dscp = parse_kv_int(kv_buf, "dscp", -1);
            if (m->dscp >= 0)
                m->has_dscp = true;
            m->ecn = parse_kv_int(kv_buf, "ecn", -1);
            if (m->ecn >= 0)
                m->has_ecn = true;
            m->src_port = parse_kv_int(kv_buf, "src-port", -1);
            if (m->src_port >= 0)
                m->has_src_port = true;
            m->dst_port = parse_kv_int(kv_buf, "dst-port", -1);
            if (m->dst_port >= 0)
                m->has_dst_port = true;
            if (parse_kv_str(kv_buf, "src-port-range",
                             src_port_range,
                             sizeof(src_port_range))) {
                if (!parse_port_range_text(src_port_range,
                                           &m->src_port_start,
                                           &m->src_port_end)) {
                    NL_LOG_ERR("l2_plan_parse: invalid ingress IPv4 ACL source port range");
                    return -1;
                }
                m->has_src_port_range = true;
            }
            if (parse_kv_str(kv_buf, "dst-port-range",
                             dst_port_range,
                             sizeof(dst_port_range))) {
                if (!parse_port_range_text(dst_port_range,
                                           &m->dst_port_start,
                                           &m->dst_port_end)) {
                    NL_LOG_ERR("l2_plan_parse: invalid ingress IPv4 ACL destination port range");
                    return -1;
                }
                m->has_dst_port_range = true;
            }
            m->tcp_flags = parse_kv_int(kv_buf, "tcp-flags", -1);
            if (m->tcp_flags >= 0) {
                m->has_tcp_flags = true;
                m->tcp_flags_mask = 63;
                m->has_tcp_flags_mask = true;
            }
            {
                int parsed_tcp_flags_mask =
                    parse_kv_int(kv_buf, "tcp-flags-mask", -1);
                if (parsed_tcp_flags_mask >= 0) {
                    m->tcp_flags_mask = parsed_tcp_flags_mask;
                    m->has_tcp_flags_mask = true;
                }
            }
            if (parse_kv_str(kv_buf, "action", action, sizeof(action))) {
                if (strcmp(action, "count") == 0)
                    m->count_only = true;
                else if (strcmp(action, "drop") != 0) {
                    NL_LOG_ERR("l2_plan_parse: invalid ingress IPv4 ACL action");
                    return -1;
                }
            }
            break;
        }
        case L2_STEP_ACL_POLICER_SET:
        case L2_STEP_ACL_POLICER_DEL: {
            char mac_text[32];
            u8 mac[6];

            memset(&step->acl_policer, 0, sizeof(step->acl_policer));
            step->acl_policer.port = parse_kv_int(kv_buf, "port", 0);
            step->acl_policer.rate_kbps =
                parse_kv_int(kv_buf, "rate", 0);
            step->acl_policer.burst_bytes =
                parse_kv_int(kv_buf, "burst", 0);
            if (!parse_kv_str(kv_buf, "dst-mac", mac_text,
                              sizeof(mac_text)) ||
                !parse_mac_text(mac_text, mac)) {
                NL_LOG_ERR("l2_plan_parse: invalid ACL policer destination MAC");
                return -1;
            }
            if ((mac[0] & 0x01) ||
                (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
                 mac[3] == 0 && mac[4] == 0 && mac[5] == 0)) {
                NL_LOG_ERR("l2_plan_parse: ACL policer destination MAC must be unicast non-zero");
                return -1;
            }
            step->acl_policer.dst_mac = mac_bytes_to_u64(mac);
            break;
        }
        case L2_STEP_EGRESS_ACL_SET:
        case L2_STEP_EGRESS_ACL_DEL: {
            char mac_text[32];
            char action[16];
            u8 mac[6];
            bool has_src = false;
            bool has_dst = false;

            memset(&step->egress_acl, 0, sizeof(step->egress_acl));
            step->egress_acl.port = parse_kv_int(kv_buf, "port", 0);
            if (parse_kv_str(kv_buf, "src-mac", mac_text,
                             sizeof(mac_text))) {
                if (!parse_mac_text(mac_text, mac)) {
                    NL_LOG_ERR("l2_plan_parse: invalid egress ACL source MAC");
                    return -1;
                }
                if ((mac[0] & 0x01) ||
                    (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
                     mac[3] == 0 && mac[4] == 0 && mac[5] == 0)) {
                    NL_LOG_ERR("l2_plan_parse: egress ACL source MAC must be unicast non-zero");
                    return -1;
                }
                step->egress_acl.src_mac = mac_bytes_to_u64(mac);
                has_src = true;
            }
            if (parse_kv_str(kv_buf, "dst-mac", mac_text,
                             sizeof(mac_text))) {
                if (!parse_mac_text(mac_text, mac)) {
                    NL_LOG_ERR("l2_plan_parse: invalid egress ACL destination MAC");
                    return -1;
                }
                if ((mac[0] & 0x01) ||
                    (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
                     mac[3] == 0 && mac[4] == 0 && mac[5] == 0)) {
                    NL_LOG_ERR("l2_plan_parse: egress ACL destination MAC must be unicast non-zero");
                    return -1;
                }
                step->egress_acl.dst_mac = mac_bytes_to_u64(mac);
                has_dst = true;
            }
            if (!has_src && !has_dst) {
                NL_LOG_ERR("l2_plan_parse: egress ACL requires source or destination MAC");
                return -1;
            }
            if (parse_kv_str(kv_buf, "action", action, sizeof(action)) &&
                strcmp(action, "drop") != 0) {
                NL_LOG_ERR("l2_plan_parse: invalid egress ACL action");
                return -1;
            }
            break;
        }
        case L2_STEP_ACL_INDEPENDENT_SET:
        case L2_STEP_ACL_INDEPENDENT_DEL: {
            char mac_text[32];
            char src_ip[32];
            char dst_ip[32];
            char src_mask[32];
            char dst_mask[32];
            char src_port_range[32];
            char dst_port_range[32];
            u8 mac[6];
            hal_acl_independent_args *a = &step->acl_independent;
            hal_ingress_ipv4_acl_match *m = &a->inet_match;

            memset(a, 0, sizeof(*a));
            if (!parse_kv_str(kv_buf, "group", a->group,
                              sizeof(a->group)) ||
                !parse_kv_str(kv_buf, "term", a->term,
                              sizeof(a->term)) ||
                !parse_kv_str(kv_buf, "family", a->family,
                              sizeof(a->family))) {
                NL_LOG_ERR("l2_plan_parse: invalid independent ACL identity");
                return -1;
            }
            if (!parse_kv_str(kv_buf, "action", a->action,
                              sizeof(a->action)))
                snprintf(a->action, sizeof(a->action), "%s",
                         strcmp(a->family, "policer") == 0 ?
                         "policer" : "drop");
            a->vid = parse_kv_int(kv_buf, "vid", 0);
            a->port = parse_kv_int(kv_buf, "port", 0);
            a->slot = parse_kv_int(kv_buf, "slot", -1);
            m->vid = a->vid;
            m->port = a->port;
            if (parse_kv_str(kv_buf, "src-mac", mac_text,
                             sizeof(mac_text))) {
                if (!parse_mac_text(mac_text, mac) ||
                    !mac_is_unicast_nonzero(mac)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent ACL source MAC");
                    return -1;
                }
                a->src_mac = mac_bytes_to_u64(mac);
                a->has_src_mac = true;
            }
            if (parse_kv_str(kv_buf, "dst-mac", mac_text,
                             sizeof(mac_text))) {
                if (!parse_mac_text(mac_text, mac) ||
                    !mac_is_unicast_nonzero(mac)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent ACL destination MAC");
                    return -1;
                }
                a->dst_mac = mac_bytes_to_u64(mac);
                a->has_dst_mac = true;
            }
            if (parse_kv_str(kv_buf, "src-ip", src_ip, sizeof(src_ip))) {
                if (!parse_ipv4_text(src_ip, &m->src_ip)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent ACL source IP");
                    return -1;
                }
                m->has_src_ip = true;
                if (parse_kv_str(kv_buf, "src-mask", src_mask,
                                 sizeof(src_mask))) {
                    if (!parse_ipv4_text(src_mask, &m->src_ip_mask)) {
                        NL_LOG_ERR("l2_plan_parse: invalid independent ACL source mask");
                        return -1;
                    }
                } else {
                    m->src_ip_mask = 0xffffffffU;
                }
                m->has_src_ip_mask = true;
            }
            if (parse_kv_str(kv_buf, "dst-ip", dst_ip, sizeof(dst_ip))) {
                if (!parse_ipv4_text(dst_ip, &m->dst_ip)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent ACL destination IP");
                    return -1;
                }
                m->has_dst_ip = true;
                if (parse_kv_str(kv_buf, "dst-mask", dst_mask,
                                 sizeof(dst_mask))) {
                    if (!parse_ipv4_text(dst_mask, &m->dst_ip_mask)) {
                        NL_LOG_ERR("l2_plan_parse: invalid independent ACL destination mask");
                        return -1;
                    }
                } else {
                    m->dst_ip_mask = 0xffffffffU;
                }
                m->has_dst_ip_mask = true;
            }
            m->protocol = parse_kv_int(kv_buf, "proto", -1);
            if (m->protocol >= 0)
                m->has_protocol = true;
            m->dscp = parse_kv_int(kv_buf, "dscp", -1);
            if (m->dscp >= 0)
                m->has_dscp = true;
            m->ecn = parse_kv_int(kv_buf, "ecn", -1);
            if (m->ecn >= 0)
                m->has_ecn = true;
            m->src_port = parse_kv_int(kv_buf, "src-port", -1);
            if (m->src_port >= 0)
                m->has_src_port = true;
            m->dst_port = parse_kv_int(kv_buf, "dst-port", -1);
            if (m->dst_port >= 0)
                m->has_dst_port = true;
            if (parse_kv_str(kv_buf, "src-port-range",
                             src_port_range, sizeof(src_port_range))) {
                if (!parse_port_range_text(src_port_range,
                                           &m->src_port_start,
                                           &m->src_port_end)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent ACL source port range");
                    return -1;
                }
                m->has_src_port_range = true;
            }
            if (parse_kv_str(kv_buf, "dst-port-range",
                             dst_port_range, sizeof(dst_port_range))) {
                if (!parse_port_range_text(dst_port_range,
                                           &m->dst_port_start,
                                           &m->dst_port_end)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent ACL destination port range");
                    return -1;
                }
                m->has_dst_port_range = true;
            }
            m->tcp_flags = parse_kv_int(kv_buf, "tcp-flags", -1);
            if (m->tcp_flags >= 0) {
                m->has_tcp_flags = true;
                m->tcp_flags_mask = 63;
                m->has_tcp_flags_mask = true;
            }
            {
                int tcp_flags_mask =
                    parse_kv_int(kv_buf, "tcp-flags-mask", -1);
                if (tcp_flags_mask >= 0) {
                    m->tcp_flags_mask = tcp_flags_mask;
                    m->has_tcp_flags_mask = true;
                }
            }
            if (strcmp(a->action, "count") == 0)
                m->count_only = true;
            a->rate_kbps = parse_kv_int(kv_buf, "rate", 0);
            a->burst_bytes = parse_kv_int(kv_buf, "burst", 0);
            break;
        }
        case L2_STEP_COPP_CLASS_SET:
            (void)parse_kv_str(kv_buf, "class", step->copp_class,
                               sizeof(step->copp_class));
            step->copp_rate_pps = parse_kv_int(kv_buf, "rate-pps", -1);
            step->copp_burst_pkts = parse_kv_int(kv_buf, "burst-pkts", -1);
            break;
        case L2_STEP_STORM_CONTROL_SET:
            step->storm_rate_kbps = parse_kv_int(kv_buf, "rate", 0);
            step->storm_burst_bytes = parse_kv_int(kv_buf, "burst", 0);
            /* fall through */
        case L2_STEP_STORM_CONTROL_DEL: {
            char kind[32] = "combined";
            if (!parse_kv_str(kv_buf, "kind", kind, sizeof(kind)))
                strcpy(kind, "combined");
            step->storm_kind = nl_storm_kind_parse(kind);
            step->port = parse_kv_int(kv_buf, "port", 0);
            break;
        }
        case L2_STEP_INGRESS_RATE_LIMIT_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ingress_rate_limit_rate_kbps = parse_kv_int(kv_buf, "rate", 0);
            step->ingress_rate_limit_burst_bytes = parse_kv_int(kv_buf, "burst", 0);
            break;
        case L2_STEP_INGRESS_RATE_LIMIT_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            break;
        case L2_STEP_EGRESS_RATE_LIMIT_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->egress_rate_limit_rate_kbps =
                parse_kv_int(kv_buf, "rate", 0);
            step->egress_rate_limit_burst_bytes =
                parse_kv_int(kv_buf, "burst", 0);
            break;
        case L2_STEP_EGRESS_RATE_LIMIT_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            break;
        case L2_STEP_QOS_INTERFACE_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            step->qos_trust_mode = parse_kv_int(kv_buf, "trust", -1);
            step->qos_default_priority =
                parse_kv_int(kv_buf, "default-priority", -1);
            break;
        case L2_STEP_QOS_INTERFACE_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->ae_id = parse_kv_int(kv_buf, "ae", -1);
            break;
        case L2_STEP_QOS_TC_SMP_SET:
            step->qos_traffic_class = parse_kv_int(kv_buf, "traffic-class", -1);
            step->qos_smp = parse_kv_int(kv_buf, "smp", -1);
            break;
        case L2_STEP_QOS_DSCP_SET:
            step->qos_dscp = parse_kv_int(kv_buf, "dscp", -1);
            step->qos_dscp_priority = parse_kv_int(kv_buf, "priority", -1);
            break;
        case L2_STEP_QOS_PFC_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_pfc_rx_class_mask =
                parse_kv_int(kv_buf, "rx-class-mask", -1);
            step->qos_pfc_tx_class_mask =
                parse_kv_int(kv_buf, "tx-class-mask", -1);
            step->qos_pfc_tx_pause_mode =
                step->qos_pfc_tx_class_mask ? 1 : 0;
            step->qos_pfc_lossless_smp_mask =
                parse_kv_int(kv_buf, "lossless-smp-mask", -1);
            step->qos_pfc_shared_pause_mask =
                parse_kv_int(kv_buf, "shared-pause-mask", -1);
            step->qos_pfc_watchdog = (fm10k_pfc_wd_policy){
                (uint32_t)parse_kv_int(kv_buf, "watchdog-detect-ms", 0),
                (uint32_t)parse_kv_int(kv_buf, "watchdog-recovery-ms", 100),
                (uint32_t)parse_kv_int(kv_buf, "watchdog-cooldown-ms", 30000)};
            break;
        case L2_STEP_QOS_PFC_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_pfc_rx_class_mask = 0;
            step->qos_pfc_tx_pause_mode = 0;
            step->qos_pfc_tx_class_mask = 0xff;
            step->qos_pfc_lossless_smp_mask = 0;
            step->qos_pfc_shared_pause_mask = 0;
            step->qos_pfc_watchdog = fm10k_pfc_wd_default_policy();
            break;
        case L2_STEP_QOS_PRIORITY_MAP_SET:
            step->qos_switch_priority =
                parse_kv_int(kv_buf, "priority", -1);
            step->qos_traffic_class =
                parse_kv_int(kv_buf, "traffic-class", -1);
            break;
        case L2_STEP_QOS_PRIORITY_MAP_DEL:
            step->qos_switch_priority =
                parse_kv_int(kv_buf, "priority", -1);
            break;
        case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_scheduler_traffic_class =
                parse_kv_int(kv_buf, "traffic-class", -1);
            step->qos_scheduler_shaping_group =
                parse_kv_int(kv_buf, "shaping-group", -1);
            break;
        case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_scheduler_traffic_class =
                parse_kv_int(kv_buf, "traffic-class", -1);
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_scheduler_group =
                parse_kv_int(kv_buf, "group", -1);
            step->qos_scheduler_strict_priority =
                parse_kv_int(kv_buf, "strict", -1);
            step->qos_scheduler_weight =
                parse_kv_int(kv_buf, "weight", -1);
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_scheduler_group =
                parse_kv_int(kv_buf, "group", -1);
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_scheduler_group =
                parse_kv_int(kv_buf, "group", -1);
            step->qos_scheduler_group_rate_bps =
                parse_kv_u64(kv_buf, "rate-bps", 0);
            step->qos_scheduler_group_burst_bits =
                parse_kv_u64(kv_buf, "burst-bits", 0);
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_scheduler_group =
                parse_kv_int(kv_buf, "group", -1);
            break;
        case L2_STEP_QOS_SCHEDULER_PORT_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_scheduler_traffic_class_enable_mask =
                parse_kv_int(kv_buf, "traffic-class-enable-mask", -1);
            break;
        case L2_STEP_QOS_SCHEDULER_PORT_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            break;
        case L2_STEP_QOS_WATERMARK_SET:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_watermark_attr = parse_kv_int(kv_buf, "attr", 0);
            step->qos_watermark_index = parse_kv_int(kv_buf, "index", -1);
            step->qos_watermark_value = parse_kv_int(kv_buf, "value", -1);
            step->qos_watermark_owner_create =
                parse_kv_int(kv_buf, "owner-create", 0);
            step->qos_watermark_reconcile =
                parse_kv_int(kv_buf, "reconcile", 0);
            break;
        case L2_STEP_QOS_WATERMARK_DEL:
            step->port = parse_kv_int(kv_buf, "port", 0);
            step->qos_watermark_attr = parse_kv_int(kv_buf, "attr", 0);
            step->qos_watermark_index = parse_kv_int(kv_buf, "index", -1);
            step->qos_watermark_reconcile =
                parse_kv_int(kv_buf, "reconcile", 0);
            break;
        case L2_STEP_MIRROR_SESSION_SET: {
            char sources[512];

            memset(&step->mirror, 0, sizeof(step->mirror));
            step->mirror.exists = true;
            step->mirror.attributes_valid = true;
            step->mirror.sample_rate = -1;
            step->mirror.encapsulation_vlan = -1;
            step->mirror.group = parse_kv_int(kv_buf, "group", -1);
            step->mirror.destination_port =
                parse_kv_int(kv_buf, "destination", 0);
            if (!parse_kv_str(kv_buf, "sources", sources,
                              sizeof(sources)) ||
                !parse_mirror_sources(sources, &step->mirror)) {
                NL_LOG_ERR("l2_plan_parse: invalid mirror source list");
                return -1;
            }
            step->mirror.direction =
                step->mirror.source_directions[0];
            for (int i = 1; i < step->mirror.n_sources; i++) {
                if (step->mirror.source_directions[i] !=
                    step->mirror.direction) {
                    step->mirror.direction = HAL_MIRROR_DIRECTION_BOTH;
                    break;
                }
            }
            break;
        }
        case L2_STEP_MIRROR_SESSION_DEL:
            memset(&step->mirror, 0, sizeof(step->mirror));
            step->mirror.group = parse_kv_int(kv_buf, "group", -1);
            break;
        case L2_STEP_IGMP_LISTENER_SET:
        case L2_STEP_IGMP_LISTENER_DEL: {
            char group[32];

            step->vid = (u16)parse_kv_int(kv_buf, "vid", 0);
            step->port = parse_kv_int(kv_buf, "port", 0);
            if (!parse_kv_str(kv_buf, "group", group, sizeof(group)) ||
                !parse_igmp_group(group, &step->igmp_group_ip,
                                  step->mac)) {
                NL_LOG_ERR("l2_plan_parse: invalid IGMP group");
                return -1;
            }
            break;
        }
        default:
            break;
        }

        switch (type) {
        case L2_STEP_VLAN_CREATE:
        case L2_STEP_VLAN_DELETE:
            if (step->vid < 1 || step->vid > 4094) {
                NL_LOG_ERR("l2_plan_parse: invalid VLAN ID %d", step->vid);
                return -1;
            }
            break;
        case L2_STEP_VLAN_ADD_PORT:
        case L2_STEP_VLAN_REM_PORT:
        case L2_STEP_PVID_SET:
        case L2_STEP_VLAN_STP_SET:
            if (step->vid < 1 || step->vid > 4094 ||
                !valid_port_target(step)) {
                NL_LOG_ERR("l2_plan_parse: invalid vid=%d port=%d ae=%d",
                           step->vid, step->port, step->ae_id);
                return -1;
            }
            break;
        case L2_STEP_PORT_SET_ADMIN:
            if (step->port <= 0) {
                NL_LOG_ERR("l2_plan_parse: invalid port=%d", step->port);
                return -1;
            }
            break;
        case L2_STEP_PORT_SET_MTU:
            if (!valid_port_target(step) ||
                step->mtu < 1514 || step->mtu > 9216) {
                NL_LOG_ERR("l2_plan_parse: invalid mtu target port=%d ae=%d mtu=%d",
                           step->port, step->ae_id, step->mtu);
                return -1;
            }
            break;
        case L2_STEP_PORT_SET_SPEED:
            if (step->port <= 0 ||
                (step->speed != 10000 && step->speed != 25000)) {
                NL_LOG_ERR("l2_plan_parse: invalid speed target port=%d speed=%d",
                           step->port, step->speed);
                return -1;
            }
            break;
        case L2_STEP_PORT_PARSER_SET:
            if (!valid_port_target(step)) {
                NL_LOG_ERR("l2_plan_parse: invalid parser target port=%d ae=%d",
                           step->port, step->ae_id);
                return -1;
            }
            break;
        case L2_STEP_MAC_AGING_SET:
            if (step->aging_time < 0 || step->aging_time > 1000000) {
                NL_LOG_ERR("l2_plan_parse: invalid MAC aging time %d",
                           step->aging_time);
                return -1;
            }
            break;
        case L2_STEP_PORT_INGRESS_FILTER_SET:
            if (!valid_port_target(step) ||
                (step->ingress_filtering != 0 && step->ingress_filtering != 1)) {
                NL_LOG_ERR("l2_plan_parse: invalid ingress-filter target or enabled value");
                return -1;
            }
            break;
        case L2_STEP_STATIC_MAC_ADD:
            if (step->vid < 1 || step->vid > 4094 ||
                !valid_port_target(step) ||
                !mac_is_unicast_nonzero(step->mac)) {
                NL_LOG_ERR("l2_plan_parse: invalid static-mac-add vid=%d port=%d ae=%d",
                           step->vid, step->port, step->ae_id);
                return -1;
            }
            break;
        case L2_STEP_STATIC_MAC_DEL:
            if (step->vid < 1 || step->vid > 4094 ||
                !mac_is_unicast_nonzero(step->mac)) {
                NL_LOG_ERR("l2_plan_parse: invalid static-mac-del vid=%d",
                           step->vid);
                return -1;
            }
            break;
        case L2_STEP_LAG_CREATE:
        case L2_STEP_LAG_DELETE:
            if (!valid_ae_id(step->ae_id)) {
                NL_LOG_ERR("l2_plan_parse: invalid ae=%d", step->ae_id);
                return -1;
            }
            break;
        case L2_STEP_LAG_ADD_PORT:
        case L2_STEP_LAG_DEL_PORT:
            if (!valid_ae_id(step->ae_id) || step->port <= 0) {
                NL_LOG_ERR("l2_plan_parse: invalid ae=%d port=%d",
                           step->ae_id, step->port);
                return -1;
            }
            break;
        case L2_STEP_LAG_HASH_ROTATION_SET:
            if (!valid_ae_id(step->ae_id) ||
                (step->lag_hash_rotation != 0 &&
                 step->lag_hash_rotation != 1)) {
                NL_LOG_ERR("l2_plan_parse: invalid ae=%d rotation=%d",
                           step->ae_id, step->lag_hash_rotation);
                return -1;
            }
            break;
        case L2_STEP_DHCP_SNOOPING_SET:
        case L2_STEP_DHCP_SNOOPING_DEL:
        case L2_STEP_ARP_INSPECTION_SET:
        case L2_STEP_ARP_INSPECTION_DEL:
            if (step->security_vid < 1 || step->security_vid > 4094 ||
                step->security_port <= 0) {
                NL_LOG_ERR("l2_plan_parse: invalid L2 security vid=%d port=%d",
                           step->security_vid, step->security_port);
                return -1;
            }
            break;
        case L2_STEP_ARP_INSPECTION_BINDING_SET:
        case L2_STEP_ARP_INSPECTION_BINDING_DEL:
            if (step->security_vid < 1 || step->security_vid > 4094 ||
                step->security_port <= 0 ||
                !mac_is_unicast_nonzero(step->security_mac) ||
                step->security_ip == 0 ||
                step->security_ip == 0xffffffffU) {
                NL_LOG_ERR("l2_plan_parse: invalid DAI binding vid=%d port=%d",
                           step->security_vid, step->security_port);
                return -1;
            }
            break;
        case L2_STEP_USER_FILTER_SET:
        case L2_STEP_USER_FILTER_DEL:
            if (step->security_vid < 1 || step->security_vid > 4094 ||
                step->security_port <= 0 ||
                (step->security_mac_kind != L2_SECURITY_MAC_SOURCE &&
                 step->security_mac_kind != L2_SECURITY_MAC_DESTINATION) ||
                !mac_is_unicast_nonzero(step->security_mac)) {
                NL_LOG_ERR("l2_plan_parse: invalid user filter vid=%d port=%d",
                           step->security_vid, step->security_port);
                return -1;
            }
            break;
        case L2_STEP_INGRESS_IPV4_ACL_SET:
        case L2_STEP_INGRESS_IPV4_ACL_DEL: {
            const hal_ingress_ipv4_acl_match *m = &step->ingress_ipv4_acl;
            if (m->vid < 1 || m->vid > 4094 || m->port <= 0 ||
                (!m->has_src_ip && !m->has_dst_ip && !m->has_protocol &&
                 !m->has_dscp && !m->has_ecn &&
                 !m->has_src_port && !m->has_dst_port &&
                 !m->has_src_port_range && !m->has_dst_port_range &&
                 !m->has_tcp_flags) ||
                (m->has_src_ip &&
                 (!m->has_src_ip_mask ||
                  (m->src_ip_mask == 0xffffffffU &&
                   (m->src_ip == 0 || m->src_ip == 0xffffffffU)))) ||
                (m->has_dst_ip &&
                 (!m->has_dst_ip_mask ||
                  (m->dst_ip_mask == 0xffffffffU &&
                   (m->dst_ip == 0 || m->dst_ip == 0xffffffffU)))) ||
                (m->has_protocol &&
                 (m->protocol < 0 || m->protocol > 255)) ||
                (m->has_dscp && (m->dscp < 0 || m->dscp > 63)) ||
                (m->has_ecn && (m->ecn < 0 || m->ecn > 3)) ||
                (m->has_src_port &&
                 (m->src_port < 0 || m->src_port > 65535)) ||
                (m->has_dst_port &&
                 (m->dst_port < 0 || m->dst_port > 65535)) ||
                (m->has_src_port_range &&
                 (m->src_port_start < 0 ||
                  m->src_port_start > m->src_port_end ||
                  m->src_port_end > 65535)) ||
                (m->has_dst_port_range &&
                 (m->dst_port_start < 0 ||
                  m->dst_port_start > m->dst_port_end ||
                  m->dst_port_end > 65535)) ||
                (m->has_src_port && m->has_src_port_range) ||
                (m->has_dst_port && m->has_dst_port_range) ||
                ((m->has_src_port || m->has_dst_port ||
                  m->has_src_port_range || m->has_dst_port_range) &&
                 (!m->has_protocol ||
                  (m->protocol != 6 && m->protocol != 17))) ||
                (m->has_tcp_flags &&
                 (m->tcp_flags < 0 || m->tcp_flags > 63 ||
                  !m->has_protocol || m->protocol != 6)) ||
                (m->has_tcp_flags_mask &&
                 (m->tcp_flags_mask < 1 || m->tcp_flags_mask > 63)) ||
                (m->has_tcp_flags_mask && !m->has_tcp_flags) ||
                (m->has_tcp_flags && m->has_tcp_flags_mask &&
                 ((m->tcp_flags & ~m->tcp_flags_mask) != 0))) {
                NL_LOG_ERR("l2_plan_parse: invalid ingress-ipv4-acl vid=%d port=%d",
                           m->vid, m->port);
                return -1;
            }
            break;
        }
        case L2_STEP_ACL_POLICER_SET:
            if (step->acl_policer.port <= 0 ||
                step->acl_policer.dst_mac == 0 ||
                step->acl_policer.rate_kbps < 1 ||
                step->acl_policer.rate_kbps > 100000000 ||
                step->acl_policer.burst_bytes < 1024 ||
                step->acl_policer.burst_bytes > 268435456) {
                NL_LOG_ERR("l2_plan_parse: invalid ACL policer set");
                return -1;
            }
            break;
        case L2_STEP_ACL_POLICER_DEL:
            if (step->acl_policer.port <= 0 ||
                step->acl_policer.dst_mac == 0) {
                NL_LOG_ERR("l2_plan_parse: invalid ACL policer delete");
                return -1;
            }
            break;
        case L2_STEP_EGRESS_ACL_SET:
        case L2_STEP_EGRESS_ACL_DEL:
            if (step->egress_acl.port <= 0 ||
                (step->egress_acl.src_mac == 0 &&
                 step->egress_acl.dst_mac == 0)) {
                NL_LOG_ERR("l2_plan_parse: invalid egress ACL step");
                return -1;
            }
            break;
        case L2_STEP_ACL_INDEPENDENT_SET:
        case L2_STEP_ACL_INDEPENDENT_DEL: {
            const hal_acl_independent_args *a = &step->acl_independent;
            const hal_ingress_ipv4_acl_match *m = &a->inet_match;
            bool has_mac = a->has_src_mac || a->has_dst_mac;
            bool has_inet = acl_independent_has_inet_selector(m);
            bool is_del = step->type == L2_STEP_ACL_INDEPENDENT_DEL;
            bool wants_policer = strcmp(a->action, "policer") == 0 ||
                                 strcmp(a->family, "policer") == 0;

            if (!a->group[0] || !a->term[0] ||
                a->slot < 0 || a->slot >= 32 ||
                !acl_independent_family_valid(a->family) ||
                !acl_independent_action_valid(a->family, a->action)) {
                NL_LOG_ERR("l2_plan_parse: invalid independent ACL identity/action");
                return -1;
            }
            if (strcmp(a->family, "egress") == 0) {
                NL_LOG_ERR("l2_plan_parse: independent egress ACL owner is deferred");
                return -1;
            } else {
                if (a->vid < 1 || a->vid > 4094 || a->port <= 0) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent ingress ACL target");
                    return -1;
                }
                if (strcmp(a->family, "ethernet") == 0 &&
                    (!has_mac || has_inet)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent ethernet ACL selectors");
                    return -1;
                }
                if (strcmp(a->family, "inet") == 0 &&
                    (has_mac || !has_inet)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent inet ACL selectors");
                    return -1;
                }
                if (strcmp(a->family, "policer") == 0 &&
                    (has_mac == has_inet)) {
                    NL_LOG_ERR("l2_plan_parse: invalid independent policer ACL selectors");
                    return -1;
                }
            }
            if (has_inet &&
                ((!m->has_src_ip && !m->has_dst_ip && !m->has_protocol &&
                  !m->has_dscp && !m->has_ecn &&
                  !m->has_src_port && !m->has_dst_port &&
                  !m->has_src_port_range && !m->has_dst_port_range &&
                  !m->has_tcp_flags) ||
                 (m->has_src_ip &&
                  (!m->has_src_ip_mask ||
                   (m->src_ip_mask == 0xffffffffU &&
                    (m->src_ip == 0 || m->src_ip == 0xffffffffU)))) ||
                 (m->has_dst_ip &&
                  (!m->has_dst_ip_mask ||
                   (m->dst_ip_mask == 0xffffffffU &&
                    (m->dst_ip == 0 || m->dst_ip == 0xffffffffU)))) ||
                 (m->has_protocol &&
                  (m->protocol < 0 || m->protocol > 255)) ||
                 (m->has_dscp && (m->dscp < 0 || m->dscp > 63)) ||
                 m->has_ecn ||
                 (m->has_src_port &&
                  (m->src_port < 0 || m->src_port > 65535)) ||
                 (m->has_dst_port &&
                  (m->dst_port < 0 || m->dst_port > 65535)) ||
                 (m->has_src_port_range &&
                  (m->src_port_start < 0 ||
                   m->src_port_start > m->src_port_end ||
                   m->src_port_end > 65535 ||
                   m->src_port_start != m->src_port_end)) ||
                 (m->has_dst_port_range &&
                  (m->dst_port_start < 0 ||
                   m->dst_port_start > m->dst_port_end ||
                   m->dst_port_end > 65535 ||
                   m->dst_port_start != m->dst_port_end)) ||
                 (m->has_src_port && m->has_src_port_range) ||
                 (m->has_dst_port && m->has_dst_port_range) ||
                 ((m->has_src_port || m->has_dst_port ||
                   m->has_src_port_range || m->has_dst_port_range) &&
                  (!m->has_protocol ||
                   (m->protocol != 6 && m->protocol != 17))) ||
                 (m->has_tcp_flags &&
                  (m->tcp_flags < 0 || m->tcp_flags > 63 ||
                   !m->has_protocol || m->protocol != 6)) ||
                 (m->has_tcp_flags_mask &&
                  (m->tcp_flags_mask < 1 || m->tcp_flags_mask > 63)) ||
                 (m->has_tcp_flags_mask && !m->has_tcp_flags) ||
                 (m->has_tcp_flags && m->has_tcp_flags_mask &&
                  ((m->tcp_flags & ~m->tcp_flags_mask) != 0)))) {
                NL_LOG_ERR("l2_plan_parse: invalid independent inet ACL selectors");
                return -1;
            }
            if (wants_policer && !is_del &&
                (a->rate_kbps < 1 || a->rate_kbps > 100000000 ||
                 a->burst_bytes < 1024 ||
                 a->burst_bytes > 268435456)) {
                NL_LOG_ERR("l2_plan_parse: invalid independent ACL policer");
                return -1;
            }
            break;
        }
        case L2_STEP_COPP_CLASS_SET:
            if ((strcmp(step->copp_class, "rstp") != 0 &&
                 strcmp(step->copp_class, "lldp") != 0 &&
                 strcmp(step->copp_class, "lacp") != 0) ||
                step->copp_rate_pps < 1 ||
                step->copp_rate_pps > 1000000 ||
                step->copp_burst_pkts < 1 ||
                step->copp_burst_pkts > 1000000) {
                NL_LOG_ERR("l2_plan_parse: invalid CoPP class=%s rate=%d burst=%d",
                           step->copp_class, step->copp_rate_pps,
                           step->copp_burst_pkts);
                return -1;
            }
            break;
        case L2_STEP_STORM_CONTROL_SET:
            if (step->port <= 0 || step->storm_kind == NL_STORM_INVALID ||
                step->storm_rate_kbps < NL_STORM_MIN_RATE_KBPS ||
                step->storm_rate_kbps > 100000000 ||
                step->storm_burst_bytes < 0 ||
                step->storm_burst_bytes > 104857600) {
                NL_LOG_ERR("l2_plan_parse: invalid storm-control port=%d rate=%d burst=%d",
                           step->port, step->storm_rate_kbps,
                           step->storm_burst_bytes);
                return -1;
            }
            break;
        case L2_STEP_STORM_CONTROL_DEL:
            if (step->port <= 0 || step->storm_kind == NL_STORM_INVALID) {
                NL_LOG_ERR("l2_plan_parse: invalid storm-control port=%d",
                           step->port);
                return -1;
            }
            break;
        case L2_STEP_INGRESS_RATE_LIMIT_SET:
            if (step->port <= 0 || step->ingress_rate_limit_rate_kbps <= 0 ||
                step->ingress_rate_limit_rate_kbps > 100000000 ||
                step->ingress_rate_limit_burst_bytes < 0 ||
                step->ingress_rate_limit_burst_bytes > 104857600) {
                NL_LOG_ERR("l2_plan_parse: invalid ingress-rate-limit port=%d rate=%d burst=%d",
                           step->port, step->ingress_rate_limit_rate_kbps,
                           step->ingress_rate_limit_burst_bytes);
                return -1;
            }
            break;
        case L2_STEP_INGRESS_RATE_LIMIT_DEL:
            if (step->port <= 0) {
                NL_LOG_ERR("l2_plan_parse: invalid ingress-rate-limit port=%d",
                           step->port);
                return -1;
            }
            break;
        case L2_STEP_EGRESS_RATE_LIMIT_SET:
            if (step->port <= 0 ||
                step->egress_rate_limit_rate_kbps <= 0 ||
                step->egress_rate_limit_rate_kbps > 100000000 ||
                step->egress_rate_limit_burst_bytes < 0 ||
                step->egress_rate_limit_burst_bytes > 8387584) {
                NL_LOG_ERR("l2_plan_parse: invalid egress-rate-limit port=%d rate=%d burst=%d",
                           step->port,
                           step->egress_rate_limit_rate_kbps,
                           step->egress_rate_limit_burst_bytes);
                return -1;
            }
            break;
        case L2_STEP_EGRESS_RATE_LIMIT_DEL:
            if (step->port <= 0) {
                NL_LOG_ERR("l2_plan_parse: invalid egress-rate-limit port=%d",
                           step->port);
                return -1;
            }
            break;
        case L2_STEP_QOS_INTERFACE_SET:
            if (!valid_port_target(step) ||
                step->qos_trust_mode < HAL_QOS_TRUST_NONE ||
                step->qos_trust_mode > HAL_QOS_TRUST_DSCP ||
                step->qos_default_priority < 0 ||
                step->qos_default_priority > 7) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-interface port=%d trust=%d default-priority=%d",
                           step->port, step->qos_trust_mode,
                           step->qos_default_priority);
                return -1;
            }
            break;
        case L2_STEP_QOS_INTERFACE_DEL:
            if (!valid_port_target(step)) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-interface port=%d",
                           step->port);
                return -1;
            }
            break;
        case L2_STEP_QOS_TC_SMP_SET:
            if (step->qos_traffic_class < 0 || step->qos_traffic_class > 7 ||
                step->qos_smp < 0 || step->qos_smp > 1) return -1;
            break;
        case L2_STEP_QOS_DSCP_SET:
            if (step->qos_dscp < 0 || step->qos_dscp > 63 ||
                step->qos_dscp_priority < 0 || step->qos_dscp_priority > 15) return -1;
            break;
        case L2_STEP_QOS_PFC_SET:
            if (step->port <= 0 ||
                step->qos_pfc_rx_class_mask < 0 ||
                step->qos_pfc_rx_class_mask > 255 ||
                step->qos_pfc_tx_class_mask < 0 ||
                step->qos_pfc_tx_class_mask > 255 ||
                step->qos_pfc_lossless_smp_mask < 0 ||
                step->qos_pfc_lossless_smp_mask > 3 ||
                step->qos_pfc_shared_pause_mask < 0 ||
                step->qos_pfc_shared_pause_mask > 3 ||
                !fm10k_pfc_wd_policy_valid(&step->qos_pfc_watchdog) ||
                (step->qos_pfc_watchdog.detect_ms && (step->qos_pfc_rx_class_mask != 8 ||
                 step->qos_pfc_tx_class_mask != 8 || step->qos_pfc_lossless_smp_mask != 2 ||
                 step->qos_pfc_shared_pause_mask != 2))) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-pfc port=%d",
                           step->port);
                return -1;
            }
            break;
        case L2_STEP_QOS_PFC_DEL:
            if (step->port <= 0) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-pfc port=%d",
                           step->port);
                return -1;
            }
            break;
        case L2_STEP_QOS_PRIORITY_MAP_SET:
            if (step->qos_switch_priority < 0 ||
                step->qos_switch_priority > 15 ||
                step->qos_traffic_class < 0 ||
                step->qos_traffic_class > 7) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-priority-map priority=%d tc=%d",
                           step->qos_switch_priority,
                           step->qos_traffic_class);
                return -1;
            }
            break;
        case L2_STEP_QOS_PRIORITY_MAP_DEL:
            if (step->qos_switch_priority < 0 ||
                step->qos_switch_priority > 15) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-priority-map priority=%d",
                           step->qos_switch_priority);
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
            if (step->port <= 0 ||
                step->qos_scheduler_traffic_class < 0 ||
                step->qos_scheduler_traffic_class > 7 ||
                step->qos_scheduler_shaping_group < 0 ||
                step->qos_scheduler_shaping_group > 7) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-scheduler-tc-map port=%d tc=%d group=%d",
                           step->port,
                           step->qos_scheduler_traffic_class,
                           step->qos_scheduler_shaping_group);
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL:
            if (step->port <= 0 ||
                step->qos_scheduler_traffic_class < 0 ||
                step->qos_scheduler_traffic_class > 7) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-scheduler-tc-map port=%d tc=%d",
                           step->port,
                           step->qos_scheduler_traffic_class);
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_SET:
            if (step->port <= 0 ||
                step->qos_scheduler_group < 0 ||
                step->qos_scheduler_group > 7 ||
                (step->qos_scheduler_strict_priority != 0 &&
                 step->qos_scheduler_strict_priority != 1) ||
                step->qos_scheduler_weight < 0 ||
                step->qos_scheduler_weight > 16777215) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-scheduler-group port=%d group=%d strict=%d weight=%d",
                           step->port,
                           step->qos_scheduler_group,
                           step->qos_scheduler_strict_priority,
                           step->qos_scheduler_weight);
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
            if (step->port <= 0 ||
                step->qos_scheduler_group < 0 ||
                step->qos_scheduler_group > 7) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-scheduler-group port=%d group=%d",
                           step->port,
                           step->qos_scheduler_group);
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET:
            if (step->port <= 0 ||
                step->qos_scheduler_group < 0 ||
                step->qos_scheduler_group > 7 ||
                step->qos_scheduler_group_rate_bps < 1 ||
                step->qos_scheduler_group_rate_bps > 100000000000ULL ||
                step->qos_scheduler_group_burst_bits < 1 ||
                step->qos_scheduler_group_burst_bits > 67100672ULL) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-scheduler-group-shaping port=%d group=%d",
                           step->port, step->qos_scheduler_group);
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
            if (step->port <= 0 ||
                step->qos_scheduler_group < 0 ||
                step->qos_scheduler_group > 7) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-scheduler-group-shaping port=%d group=%d",
                           step->port, step->qos_scheduler_group);
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_PORT_SET:
            if (step->port <= 0 ||
                step->qos_scheduler_traffic_class_enable_mask < 1 ||
                step->qos_scheduler_traffic_class_enable_mask > 255) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-scheduler-port port=%d tc-enable-mask=%d",
                           step->port,
                           step->qos_scheduler_traffic_class_enable_mask);
                return -1;
            }
            break;
        case L2_STEP_QOS_SCHEDULER_PORT_DEL:
            if (step->port <= 0) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-scheduler-port port=%d",
                           step->port);
                return -1;
            }
            break;
        case L2_STEP_QOS_WATERMARK_SET:
        {
            bool closed_bit_attr =
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE;
            bool port_attr =
                step->qos_watermark_attr == HAL_QOS_WATERMARK_ATTR_TX_HOG ||
                step->qos_watermark_attr == HAL_QOS_WATERMARK_ATTR_TX_PRIVATE;
            bool switch_attr =
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
            if (closed_bit_attr) {
                NL_LOG_ERR(
                    "l2_plan_parse: qos-watermark attrs 11/12 are "
                    "per-port priorities but are not open in the L2 "
                    "product model");
                return -1;
            }
            if ((!port_attr && !switch_attr) ||
                (port_attr && step->port <= 0) ||
                (switch_attr && step->port != 0) ||
                step->qos_watermark_index < 0 ||
                step->qos_watermark_index > 7 ||
                (step->qos_watermark_owner_create != 0 &&
                 step->qos_watermark_owner_create != 1) ||
                (step->qos_watermark_reconcile != 0 &&
                 step->qos_watermark_reconcile != 1) ||
                (step->qos_watermark_attr ==
                     HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER &&
                 step->qos_watermark_value > 7) ||
                step->qos_watermark_value < 0 ||
                step->qos_watermark_value > 6291264) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-watermark port=%d attr=%d index=%d value=%d",
                           step->port, step->qos_watermark_attr,
                           step->qos_watermark_index,
                           step->qos_watermark_value);
                return -1;
            }
            break;
        }
        case L2_STEP_QOS_WATERMARK_DEL:
        {
            bool closed_bit_attr =
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE;
            bool port_attr =
                step->qos_watermark_attr == HAL_QOS_WATERMARK_ATTR_TX_HOG ||
                step->qos_watermark_attr == HAL_QOS_WATERMARK_ATTR_TX_PRIVATE;
            bool switch_attr =
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
                step->qos_watermark_attr ==
                    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
            if (closed_bit_attr) {
                NL_LOG_ERR(
                    "l2_plan_parse: qos-watermark attrs 11/12 are "
                    "per-port priorities but are not open in the L2 "
                    "product model");
                return -1;
            }
            if ((!port_attr && !switch_attr) ||
                (port_attr && step->port <= 0) ||
                (switch_attr && step->port != 0) ||
                step->qos_watermark_index < 0 ||
                step->qos_watermark_index > 7 ||
                (step->qos_watermark_reconcile != 0 &&
                 step->qos_watermark_reconcile != 1)) {
                NL_LOG_ERR("l2_plan_parse: invalid qos-watermark port=%d attr=%d index=%d",
                           step->port, step->qos_watermark_attr,
                           step->qos_watermark_index);
                return -1;
            }
            break;
        }
        case L2_STEP_MIRROR_SESSION_SET:
            if (step->mirror.group != NETLAB_MIRROR_V1_GROUP ||
                step->mirror.destination_port <= 0 ||
                step->mirror.n_sources <= 0) {
                NL_LOG_ERR("l2_plan_parse: invalid mirror session");
                return -1;
            }
            for (int i = 0; i < step->mirror.n_sources; i++) {
                if (step->mirror.source_ports[i] <= 0 ||
                    step->mirror.source_ports[i] ==
                        step->mirror.destination_port) {
                    NL_LOG_ERR("l2_plan_parse: invalid mirror source port=%d",
                               step->mirror.source_ports[i]);
                    return -1;
                }
                for (int j = i + 1; j < step->mirror.n_sources; j++) {
                    if (step->mirror.source_ports[i] ==
                        step->mirror.source_ports[j]) {
                        NL_LOG_ERR("l2_plan_parse: duplicate mirror source port=%d",
                                   step->mirror.source_ports[i]);
                        return -1;
                    }
                }
            }
            break;
        case L2_STEP_MIRROR_SESSION_DEL:
            if (step->mirror.group != NETLAB_MIRROR_V1_GROUP) {
                NL_LOG_ERR("l2_plan_parse: invalid mirror delete group=%d",
                           step->mirror.group);
                return -1;
            }
            break;
        case L2_STEP_IGMP_LISTENER_SET:
        case L2_STEP_IGMP_LISTENER_DEL:
            if (step->vid < 1 || step->vid > 4094 || step->port <= 0 ||
                step->igmp_group_ip < 0xe0000100U ||
                step->igmp_group_ip > 0xefffffffU) {
                NL_LOG_ERR("l2_plan_parse: invalid IGMP listener vid=%d port=%d",
                           step->vid, step->port);
                return -1;
            }
            break;
        default:
            break;
        }

        n++;
        p = line_end;
    }

    if (n != expected) {
        NL_LOG_ERR("l2_plan_parse: expected %d operations, parsed %d",
                   expected, n);
        return -1;
    }
    plan->n_steps = n;
    NL_LOG_INFO("l2_plan_parse: %d steps parsed", n);
    return n;
}
