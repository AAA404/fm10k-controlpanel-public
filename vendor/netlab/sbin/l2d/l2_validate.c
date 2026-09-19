/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "l2_plan_internal.h"
#include "l2_fm10k.h"
#include <errno.h>
#include <limits.h>

static bool l2_parse_long_range(const char *text, long min, long max,
                                long *out) {
    char *end = NULL;
    long value;

    if (!text || !text[0])
        return false;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value < min || value > max)
        return false;
    if (out)
        *out = value;
    return true;
}

static bool l2_parse_int_range(const char *text, int min, int max, int *out) {
    long value;

    if (!l2_parse_long_range(text, min, max, &value))
        return false;
    if (out)
        *out = (int)value;
    return true;
}

static bool l2_parse_xml_int_value(const char *start, const char *close_tag,
                                   int min, int max, int *out) {
    char value[32];
    const char *end;
    size_t len;

    if (!start || !close_tag)
        return false;
    end = strstr(start, close_tag);
    if (!end)
        return false;
    len = (size_t)(end - start);
    if (len == 0 || len >= sizeof(value))
        return false;
    memcpy(value, start, len);
    value[len] = '\0';
    return l2_parse_int_range(value, min, max, out);
}

static bool port_supports_tagged_trunk(const cfg_port_ref *port) {
    if (!port)
        return false;
    if (port->is_aggregate)
        return true;
    return (port->flags & NL_PORT_FLAG_TAGGED_TRUNK) != 0;
}

static bool port_supports_speed(const cfg_port_ref *port, int speed_mbps) {
    u64 wanted_bps;

    if (!port || speed_mbps <= 0)
        return false;
    wanted_bps = (u64)speed_mbps * 1000000ULL;
    for (int i = 0; i < port->num_speeds && i < 8; i++) {
        if (port->supported_speeds_bps[i] == wanted_bps)
            return true;
    }
    return false;
}

static int port_effective_speed_mbps(const cfg_port_ref *port,
                                     const cfg_if_intent *intent) {
    if (!port || !intent)
        return 0;
    if (intent->has_speed)
        return intent->speed_mbps;
    if (port->default_speed_bps == 0 ||
        port->default_speed_bps % 1000000ULL != 0)
        return 0;
    return (int)(port->default_speed_bps / 1000000ULL);
}

static bool lacp_system_id_valid(const char *system_id) {
    u8 mac[NL_MAC_ADDR_LEN];

    if (!nl_platform_parse_mac(system_id, mac))
        return false;
    return (mac[0] & 0x01) == 0;
}

int l2_validate_interface_intent(const cfg_port_ref *port,
                                     const cfg_if_intent *intent,
                                     char *err, size_t err_size) {
    if (!intent->members_complete)
        return l2_plan_set_error(
            err, err_size,
            "interface %s has more than 64 ethernet-switching VLAN members",
            port->name, NULL);

    if (intent->has_speed) {
        u64 wanted_bps = (u64)intent->speed_mbps * 1000000ULL;

        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "interface %s cannot configure speed on an aggregate",
                             port->name, NULL);
        if ((intent->speed_mbps != NL_PORT_SPEED_10G_MBPS &&
             intent->speed_mbps != NL_PORT_SPEED_25G_MBPS) ||
            !port_supports_speed(port, intent->speed_mbps)) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "interface %s speed %dg is not supported by the active platform profile",
                         port->name, intent->speed_mbps / 1000);
            return -1;
        }
        if (port->scheduler_speed_bps < wanted_bps) {
            if (err && err_size > 0)
                snprintf(
                    err, err_size,
                    "interface %s speed %dg exceeds the active platform "
                    "scheduler budget %llug",
                    port->name, intent->speed_mbps / 1000,
                    (unsigned long long)(
                        port->scheduler_speed_bps / 1000000000ULL));
            return -1;
        }
    }

    if (!intent->has_l2)
        return 0;

    if (!intent->mode[0])
        return l2_plan_set_error(err, err_size,
                         "interface %s has ethernet-switching VLAN data but no interface-mode",
                         port->name, NULL);

    if (intent->n_members == 0)
        return l2_plan_set_error(err, err_size,
                         "interface %s has no ethernet-switching vlan members",
                         port->name, NULL);

    for (int i = 0; i < intent->n_members; i++) {
        if (intent->member_vids[i] <= 0 || intent->member_vids[i] > 4094)
            return l2_plan_set_error(err, err_size,
                             "VLAN %s is referenced but not defined",
                             intent->members[i], NULL);
    }

    if (strcmp(intent->mode, "access") == 0) {
        if (intent->n_members != 1)
            return l2_plan_set_error(err, err_size,
                             "interface %s access mode requires exactly one VLAN member",
                             port->name, NULL);
        if (intent->has_native)
            return l2_plan_set_error(err, err_size,
                             "interface %s access mode cannot set native-vlan-id",
                             port->name, NULL);
        return 0;
    }

    if (strcmp(intent->mode, "trunk") == 0) {
        if (!port_supports_tagged_trunk(port))
            return l2_plan_set_error(err, err_size,
                             "interface %s is not tagged-trunk capable in the active chassis mode",
                             port->name, NULL);
        if (intent->has_native && !l2_intent_has_vid(intent, intent->native_vid))
            return l2_plan_set_error(err, err_size,
                             "native-vlan-id must be included in trunk vlan members",
                             NULL, NULL);
        return 0;
    }

    return l2_plan_set_error(err, err_size, "unsupported interface-mode %s",
                     intent->mode, NULL);
}

int l2_validate_duplicate_vlan_ids(nl_yang_session *ys,
                                       char *err, size_t err_size) {
    char *xml = nl_yang_to_xml(ys);
    bool seen[4095] = {0};
    char *vlans;
    char *vlans_end;
    char *p;

    if (!xml)
        return 0;

    vlans = strstr(xml, "<vlans>");
    vlans_end = vlans ? strstr(vlans, "</vlans>") : NULL;
    if (!vlans || !vlans_end) {
        free(xml);
        return 0;
    }

    p = vlans;
    while ((p = strstr(p, "<vlan-id>")) && p < vlans_end) {
        int vid;
        p += strlen("<vlan-id>");
        if (!l2_parse_xml_int_value(p, "</vlan-id>", 1, 4094, &vid)) {
            p++;
            continue;
        }
        if (vid >= 1 && vid <= 4094) {
            if (seen[vid]) {
                free(xml);
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "vlan-id %d is configured more than once", vid);
                return -1;
            }
            seen[vid] = true;
        }
    }

    free(xml);
    return 0;
}

int l2_validate_mac_aging_time(nl_yang_session *ys,
                                   char *err, size_t err_size) {
    bool configured = false;
    int seconds = l2_get_mac_aging_time(ys, &configured);

    if (!configured)
        return 0;
    if (seconds < 0 || seconds > CFG_MAC_AGING_MAX_SECONDS) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "mac-table-aging-time must be 0..%d seconds",
                     CFG_MAC_AGING_MAX_SECONDS);
        return -1;
    }
    return 0;
}

static bool known_port_name(const cfg_port_ref *ports, int n_ports,
                            const char *name) {
    for (int i = 0; i < n_ports; i++) {
        if (strcmp(ports[i].name, name) == 0)
            return true;
    }
    return false;
}

static bool l2_xml_ptr_inside_tag(const char *container,
                                  const char *container_end,
                                  const char *open_tag,
                                  const char *close_tag,
                                  const char *ptr) {
    const char *p = container;

    if (!container || !container_end || !open_tag || !close_tag || !ptr)
        return false;
    while ((p = strstr(p, open_tag)) && p < container_end && p < ptr) {
        const char *end = strstr(p, close_tag);

        if (!end || end > container_end)
            return false;
        if (ptr > p && ptr < end)
            return true;
        p = end + strlen(close_tag);
    }
    return false;
}

static int l2_validate_stp_interface_entry(nl_yang_session *ys,
                                           const cfg_port_ref *ports,
                                           int n_ports,
                                           const char *scope,
                                           const char *p,
                                           const char *end,
                                           bool allow_guards,
                                           char *err,
                                           size_t err_size) {
    char name[64] = {0};
    char edge[16] = {0};
    char guard[16] = {0};
    char root_protection[16] = {0};
    char loop_protection[16] = {0};
    char path_cost_s[32] = {0};
    char port_priority_s[32] = {0};

    if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) != 0 ||
        !name[0])
        return 1;

    const cfg_port_ref *port = l2_find_port_ref(ports, n_ports, name);
    if (!port) {
        return l2_plan_set_error(err, err_size,
                         "%s %s not found", scope, name);
    }
    if ((port->flags & NL_PORT_FLAG_RSTP_CAPABLE) == 0) {
        return l2_plan_set_error(err, err_size,
                         "%s %s is not RSTP-capable in the active chassis mode",
                         scope, name);
    }
    {
        const char *lag = l2_get_lag_member(ys, name);
        if (lag && lag[0]) {
            return l2_plan_set_error(err, err_size,
                             "%s %s cannot be configured on aggregate member",
                             scope, name);
        }
    }

    l2_extract_xml_leaf(p, end, "edge", edge, sizeof(edge));
    l2_extract_xml_leaf(p, end, "bpdu-block-on-edge", guard, sizeof(guard));
    l2_extract_xml_leaf(p, end, "root-protection", root_protection,
                        sizeof(root_protection));
    l2_extract_xml_leaf(p, end, "loop-protection", loop_protection,
                        sizeof(loop_protection));
    l2_extract_xml_leaf(p, end, "path-cost", path_cost_s,
                        sizeof(path_cost_s));
    l2_extract_xml_leaf(p, end, "port-priority", port_priority_s,
                        sizeof(port_priority_s));

    if (!allow_guards &&
        (edge[0] || guard[0] || root_protection[0] || loop_protection[0])) {
        return l2_plan_set_error(err, err_size,
                         "%s %s supports only path-cost and port-priority",
                         scope, name);
    }
    if (allow_guards &&
        strcmp(guard, "true") == 0 && strcmp(edge, "true") != 0) {
        return l2_plan_set_error(err, err_size,
                         "%s %s bpdu-block-on-edge requires edge",
                         scope, name);
    }
    if (path_cost_s[0]) {
        long path_cost = 0;
        if (!l2_parse_long_range(path_cost_s, 1, 200000000,
                                 &path_cost)) {
            return l2_plan_set_error(err, err_size,
                         "%s %s path-cost must be 1..200000000",
                         scope, name);
        }
    }
    if (port_priority_s[0]) {
        int port_priority = 0;
        if (!l2_parse_int_range(port_priority_s, 0, 240,
                                &port_priority) ||
            port_priority % 16 != 0) {
            return l2_plan_set_error(err, err_size,
                         "%s %s port-priority must be 0..240 in steps of 16",
                         scope, name);
        }
    }
    if (allow_guards &&
        root_protection[0] &&
        strcmp(root_protection, "true") != 0 &&
        strcmp(root_protection, "false") != 0) {
        return l2_plan_set_error(err, err_size,
                         "%s %s root-protection must be boolean",
                         scope, name);
    }
    if (allow_guards &&
        loop_protection[0] &&
        strcmp(loop_protection, "true") != 0 &&
        strcmp(loop_protection, "false") != 0) {
        return l2_plan_set_error(err, err_size,
                         "%s %s loop-protection must be boolean",
                         scope, name);
    }
    return 0;
}

int l2_validate_configured_interfaces(nl_yang_session *ys,
                                          const cfg_port_ref *ports,
                                          int n_ports,
                                          char *err, size_t err_size) {
    char *xml = nl_yang_to_xml(ys);
    char *interfaces;
    char *interfaces_end;
    char *next_top;
    char *p;

    if (!xml)
        return 0;

    interfaces = strstr(xml, "<interfaces>");
    next_top = strstr(xml, "<interfaces-routing>");
    if (!next_top)
        next_top = strstr(xml, "<routing-options>");
    if (!next_top)
        next_top = strstr(xml, "<protocols>");
    if (!next_top)
        next_top = strstr(xml, "<control-plane>");
    if (!next_top)
        next_top = strstr(xml, "<class-of-service>");
    if (!next_top)
        next_top = strstr(xml, "<ethernet-switching-options>");
    if (interfaces && next_top && interfaces > next_top)
        interfaces = NULL;
    interfaces_end = interfaces ? strstr(interfaces, "</interfaces>") : NULL;
    if (!interfaces || !interfaces_end) {
        free(xml);
        return 0;
    }

    p = interfaces;
    while ((p = strstr(p, "<interface>")) && p < interfaces_end) {
        char *end = strstr(p, "</interface>");
        char *name_start;
        char *name_end;
        char name[64] = {0};
        size_t nlen;

        if (!end || end > interfaces_end)
            break;
        name_start = strstr(p, "<name>");
        if (!name_start || name_start > end) {
            p = end + strlen("</interface>");
            continue;
        }
        name_start += strlen("<name>");
        name_end = strstr(name_start, "</name>");
        if (!name_end || name_end > end) {
            p = end + strlen("</interface>");
            continue;
        }
        nlen = (size_t)(name_end - name_start);
        if (nlen >= sizeof(name))
            nlen = sizeof(name) - 1;
        memcpy(name, name_start, nlen);

        bool is_ae = l2_is_ae_name(name);
        char *agg_opts = strstr(p, "<aggregated-ether-options>");

        if (is_ae) {
            if (!l2_supported_ae_name(name)) {
                int max_ae = l2_cfg_max_ae();
                free(xml);
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "aggregate interface %s is outside supported range ae0-ae%d",
                             name, max_ae > 0 ? max_ae - 1 : 0);
                return -1;
            }
        } else if (!known_port_name(ports, n_ports, name)) {
            free(xml);
            return l2_plan_set_error(err, err_size, "interface %s not found",
                             name, NULL);
        }
        if (!is_ae && agg_opts && agg_opts < end) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "interface %s aggregated-ether-options require an ae interface",
                             name, NULL);
        }
        {
            char value[64];
            if (l2_extract_xml_leaf(p, end, "mtu", value, sizeof(value)) == 0 &&
                value[0]) {
                int mtu = 0;
                if (!l2_parse_int_range(value, CFG_INTERFACE_MIN_MTU,
                                        CFG_INTERFACE_MAX_MTU, &mtu)) {
                    free(xml);
                    if (err && err_size > 0)
                        snprintf(err, err_size,
                                 "interface %s mtu must be %d..%d",
                                 name, CFG_INTERFACE_MIN_MTU,
                                 CFG_INTERFACE_MAX_MTU);
                    return -1;
                }
            }
            if (l2_extract_xml_leaf(p, end, "speed", value, sizeof(value)) == 0 &&
                value[0] && strcmp(value, "10g") != 0 &&
                strcmp(value, "25g") != 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "interface %s speed must be 10g or 25g",
                                 name, NULL);
            }
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return 0;
}

static int l2_validate_stp_container(nl_yang_session *ys,
                                     const cfg_port_ref *ports, int n_ports,
                                     const char *proto,
                                     char *container,
                                     char *container_end,
                                     char *err, size_t err_size) {
    char *p;

    {
        char value[32] = {0};
        int bridge_priority = 32768;
        int hello_time = 2;
        int max_age = 20;
        int forward_delay = 15;

        if (l2_extract_xml_leaf(container, container_end, "bridge-priority",
                             value, sizeof(value)) == 0) {
            if (!l2_parse_int_range(value, 0, 61440, &bridge_priority) ||
                bridge_priority % 4096 != 0) {
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "protocols %s bridge-priority must be 0..61440 in steps of 4096",
                             proto);
                return -1;
            }
        }
        if (l2_extract_xml_leaf(container, container_end, "hello-time",
                             value, sizeof(value)) == 0 &&
            !l2_parse_int_range(value, 0, INT_MAX, &hello_time))
            return l2_plan_set_error(err, err_size,
                             "protocols %s hello-time must be an integer",
                             proto, NULL);
        if (l2_extract_xml_leaf(container, container_end, "max-age",
                             value, sizeof(value)) == 0 &&
            !l2_parse_int_range(value, 0, INT_MAX, &max_age))
            return l2_plan_set_error(err, err_size,
                             "protocols %s max-age must be an integer",
                             proto, NULL);
        if (l2_extract_xml_leaf(container, container_end, "forward-delay",
                             value, sizeof(value)) == 0 &&
            !l2_parse_int_range(value, 0, INT_MAX, &forward_delay))
            return l2_plan_set_error(err, err_size,
                             "protocols %s forward-delay must be an integer",
                             proto, NULL);

        if (max_age < 2 * (hello_time + 1)) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "protocols %s max-age must be at least 2 * (hello-time + 1)",
                         proto);
            return -1;
        }
        if (2 * (forward_delay - 1) < max_age) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "protocols %s forward-delay must satisfy 2 * (forward-delay - 1) >= max-age",
                         proto);
            return -1;
        }
    }

    if (strcmp(proto, "mstp") == 0) {
        bool vlan_seen[4095] = {0};
        char value[64] = {0};

        if (l2_extract_xml_leaf(container, container_end,
                                "configuration-name", value,
                                sizeof(value)) == 0 &&
                (strlen(value) < 1 || strlen(value) > 32)) {
            return l2_plan_set_error(err, err_size,
                             "protocols mstp configuration-name must be 1..32 characters",
                             NULL, NULL);
        }
        memset(value, 0, sizeof(value));
        if (l2_extract_xml_leaf(container, container_end, "revision-level",
                                value, sizeof(value)) == 0) {
            int revision = 0;
            if (!l2_parse_int_range(value, 0, 65535, &revision))
                return l2_plan_set_error(err, err_size,
                                 "protocols mstp revision-level must be 0..65535",
                                 NULL, NULL);
        }
        memset(value, 0, sizeof(value));
        if (l2_extract_xml_leaf(container, container_end, "max-hops",
                                value, sizeof(value)) == 0) {
            int max_hops = 0;
            if (!l2_parse_int_range(value, 6, 40, &max_hops))
                return l2_plan_set_error(err, err_size,
                                 "protocols mstp max-hops must be 6..40",
                                 NULL, NULL);
        }

        p = container;
        while ((p = strstr(p, "<instance>")) && p < container_end) {
            char *end = strstr(p, "</instance>");
            char id_s[32] = {0};
            char priority_s[32] = {0};
            char *vlan_p;
            char *iface_p;
            int inst_id;

            if (!end || end > container_end)
                break;
            if (l2_extract_xml_leaf(p, end, "id", id_s, sizeof(id_s)) != 0 ||
                !id_s[0])
                return l2_plan_set_error(err, err_size,
                                 "protocols mstp instance requires an id",
                                 NULL, NULL);
            if (!l2_parse_int_range(id_s, 1, 4094, &inst_id))
                return l2_plan_set_error(err, err_size,
                                 "protocols mstp instance %s must be 1..4094",
                                 id_s, NULL);
            if (l2_extract_xml_leaf(p, end, "bridge-priority",
                                    priority_s, sizeof(priority_s)) == 0) {
                int priority = 0;
                if (!l2_parse_int_range(priority_s, 0, 61440,
                                        &priority) ||
                    priority % 4096 != 0)
                    return l2_plan_set_error(err, err_size,
                                     "protocols mstp instance %s bridge-priority must be 0..61440 in steps of 4096",
                                     id_s, NULL);
            }
            vlan_p = p;
            while ((vlan_p = strstr(vlan_p, "<vlan>")) && vlan_p < end) {
                char *vlan_end = strstr(vlan_p, "</vlan>");
                char vlan_s[32] = {0};
                int vlan;

                if (!vlan_end || vlan_end > end)
                    break;
                if (l2_extract_xml_leaf(vlan_p, vlan_end, "vlan-id",
                                        vlan_s, sizeof(vlan_s)) != 0 ||
                    !vlan_s[0])
                    return l2_plan_set_error(err, err_size,
                                     "protocols mstp instance %s vlan requires a vlan-id",
                                     id_s, NULL);
                if (!l2_parse_int_range(vlan_s, 1, 4094, &vlan))
                    return l2_plan_set_error(err, err_size,
                                     "protocols mstp instance %s vlan %s must be 1..4094",
                                     id_s, vlan_s);
                if (vlan_seen[vlan])
                    return l2_plan_set_error(err, err_size,
                                     "protocols mstp vlan %s is mapped to more than one instance",
                                     vlan_s, NULL);
                vlan_seen[vlan] = true;
                vlan_p = vlan_end + strlen("</vlan>");
            }
            iface_p = p;
            while ((iface_p = strstr(iface_p, "<interface>")) &&
                   iface_p < end) {
                char *iface_end = strstr(iface_p, "</interface>");
                char scope[96];
                int rc;

                if (!iface_end || iface_end > end)
                    break;
                snprintf(scope, sizeof(scope),
                         "protocols mstp instance %s interface", id_s);
                rc = l2_validate_stp_interface_entry(ys, ports, n_ports,
                                                     scope, iface_p,
                                                     iface_end, false,
                                                     err, err_size);
                if (rc < 0)
                    return rc;
                iface_p = iface_end + strlen("</interface>");
            }
            p = end + strlen("</instance>");
        }
    }

    p = container;
    while ((p = strstr(p, "<interface>")) && p < container_end) {
        char *end = strstr(p, "</interface>");
        char scope[64];
        int rc;

        if (!end || end > container_end)
            break;
        if (strcmp(proto, "mstp") == 0 &&
            l2_xml_ptr_inside_tag(container, container_end,
                                  "<instance>", "</instance>", p)) {
            p = end + strlen("</interface>");
            continue;
        }
        snprintf(scope, sizeof(scope), "protocols %s interface", proto);
        rc = l2_validate_stp_interface_entry(ys, ports, n_ports, scope,
                                             p, end, true, err, err_size);
        if (rc < 0)
            return rc;
        p = end + strlen("</interface>");
    }

    return 0;
}

int l2_validate_rstp_intents(nl_yang_session *ys,
                                 const cfg_port_ref *ports, int n_ports,
                                 char *err, size_t err_size) {
    char *xml = nl_yang_to_xml(ys);
    char *rstp;
    char *rstp_end;
    char *mstp;
    char *mstp_end;
    int ret = 0;

    if (!xml)
        return 0;

    rstp = strstr(xml, "<rstp>");
    rstp_end = rstp ? strstr(rstp, "</rstp>") : NULL;
    mstp = strstr(xml, "<mstp>");
    mstp_end = mstp ? strstr(mstp, "</mstp>") : NULL;

    if (rstp && mstp) {
        ret = l2_plan_set_error(err, err_size,
                         "protocols rstp and protocols mstp cannot be configured at the same time",
                         NULL, NULL);
        free(xml);
        return ret;
    }

    if (rstp && rstp_end)
        ret = l2_validate_stp_container(ys, ports, n_ports, "rstp",
                                        rstp, rstp_end, err, err_size);
    else if (mstp && mstp_end)
        ret = l2_validate_stp_container(ys, ports, n_ports, "mstp",
                                        mstp, mstp_end, err, err_size);

    free(xml);
    return ret;
}

int l2_validate_lldp_intents(nl_yang_session *ys,
                                 const cfg_port_ref *ports, int n_ports,
                                 char *err, size_t err_size) {
    char *xml = nl_yang_to_xml(ys);
    char *lldp;
    char *lldp_end;
    char *global_end;
    char *p;
    char value[256];

    if (!xml)
        return 0;

    lldp = strstr(xml, "<lldp>");
    if (!lldp) {
        free(xml);
        return 0;
    }
    lldp_end = strstr(lldp, "</lldp>");
    if (!lldp_end) {
        free(xml);
        return l2_plan_set_error(err, err_size,
                         "protocols lldp configuration is malformed",
                         NULL, NULL);
    }

    global_end = strstr(lldp, "<interface>");
    if (!global_end || global_end > lldp_end)
        global_end = lldp_end;

    if (l2_extract_xml_leaf(lldp, global_end, "transmit-interval", value,
                         sizeof(value)) == 0) {
        long v = 0;
        if (!l2_parse_long_range(value, 5, 3600, &v)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "protocols lldp transmit-interval must be 5..3600",
                             NULL, NULL);
        }
    }
    if (l2_extract_xml_leaf(lldp, global_end, "hold-multiplier", value,
                         sizeof(value)) == 0) {
        long v = 0;
        if (!l2_parse_long_range(value, 2, 10, &v)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "protocols lldp hold-multiplier must be 2..10",
                             NULL, NULL);
        }
    }
    if (l2_extract_xml_leaf(lldp, global_end, "management-address", value,
                         sizeof(value)) == 0) {
        unsigned char addr[16];
        if (inet_pton(AF_INET, value, addr) != 1 &&
            inet_pton(AF_INET6, value, addr) != 1) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "protocols lldp management-address %s is not a valid IP address",
                             value, NULL);
        }
    }

    p = lldp;
    while ((p = strstr(p, "<interface>")) && p < lldp_end) {
        char *end = strstr(p, "</interface>");
        char name[64] = {0};

        if (!end || end > lldp_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) != 0 ||
            !name[0]) {
            p = end + strlen("</interface>");
            continue;
        }
        if (l2_is_ae_name(name)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "protocols lldp interface %s: aggregate LLDP is not supported yet",
                             name, NULL);
        }
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports, name);
        if (!port) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "protocols lldp interface %s not found",
                             name, NULL);
        }
        if ((port->flags & NL_PORT_FLAG_LLDP_CAPABLE) == 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "protocols lldp interface %s is not LLDP-capable in the active chassis mode",
                             name, NULL);
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return 0;
}

int l2_validate_secure_access_intents(nl_yang_session *ys,
                                          const cfg_port_ref *ports,
                                          int n_ports,
                                          char *err, size_t err_size) {
    char *xml = nl_yang_to_xml(ys);
    char *eso;
    char *eso_end;
    char *secure;
    char *secure_end;
    char *p;

    if (!xml)
        return 0;

    eso = strstr(xml, "<ethernet-switching-options>");
    if (!eso) {
        free(xml);
        return 0;
    }
    eso_end = strstr(eso, "</ethernet-switching-options>");
    if (!eso_end) {
        free(xml);
        return l2_plan_set_error(err, err_size,
                         "ethernet-switching-options configuration is malformed",
                         NULL, NULL);
    }
    secure = strstr(eso, "<secure-access-port>");
    if (!secure || secure > eso_end) {
        free(xml);
        return 0;
    }
    secure_end = strstr(secure, "</secure-access-port>");
    if (!secure_end || secure_end > eso_end) {
        free(xml);
        return l2_plan_set_error(err, err_size,
                         "secure-access-port configuration is malformed",
                         NULL, NULL);
    }

    p = secure;
    while ((p = strstr(p, "<interface>")) && p < secure_end) {
        char *end = strstr(p, "</interface>");
        char name[64] = {0};
        char limit_s[32] = {0};
        char action[32] = {0};
        int limit;
        const cfg_port_ref *port;

        if (!end || end > secure_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) != 0 ||
            !name[0]) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "secure-access-port interface requires a name",
                             NULL, NULL);
        }
        if (l2_extract_xml_leaf(p, end, "mac-limit", limit_s,
                             sizeof(limit_s)) != 0 || !limit_s[0]) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "secure-access-port interface %s requires mac-limit",
                             name, NULL);
        }
        if (!l2_parse_int_range(limit_s, 1, 65535, &limit)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "secure-access-port interface %s mac-limit must be 1..65535",
                             name, NULL);
        }
        if (l2_extract_xml_leaf(p, end, "violation-action", action,
                                sizeof(action)) == 0 && action[0]) {
            if (strcmp(action, "alarm") != 0 &&
                strcmp(action, "drop") != 0 &&
                strcmp(action, "restrict") != 0 &&
                strcmp(action, "shutdown") != 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                             "secure-access-port interface %s action must be alarm, drop, restrict, or shutdown",
                             name, NULL);
            }
        }
        port = l2_find_port_ref(ports, n_ports, name);
        if (!port) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "secure-access-port interface %s not found",
                             name, NULL);
        }
        if (port->is_aggregate && !l2_aggregate_configured(ys, port->name)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "secure-access-port interface %s references an unconfigured aggregate",
                             name, NULL);
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return 0;
}

int l2_validate_mac_move_intents(nl_yang_session *ys,
                                 char *err, size_t err_size) {
    const char *base =
        "/netlab:netlab-config/ethernet-switching-options/mac-move/dampening";
    char path[256];
    const char *threshold_s;
    const char *window_s;
    const char *action;
    int threshold;
    int window;

    if (!ys)
        return 0;

    snprintf(path, sizeof(path), "%s/threshold", base);
    threshold_s = nl_yang_get(ys, path);
    snprintf(path, sizeof(path), "%s/window", base);
    window_s = nl_yang_get(ys, path);
    snprintf(path, sizeof(path), "%s/action", base);
    action = nl_yang_get(ys, path);

    if ((!threshold_s || !threshold_s[0]) &&
        (!window_s || !window_s[0]) &&
        (!action || !action[0]))
        return 0;

    if (!threshold_s || !threshold_s[0])
        return l2_plan_set_error(err, err_size,
                         "mac-move dampening requires threshold",
                         NULL, NULL);
    if (!window_s || !window_s[0])
        return l2_plan_set_error(err, err_size,
                         "mac-move dampening requires window",
                         NULL, NULL);

    if (!l2_parse_int_range(threshold_s, 1, 1000, &threshold))
        return l2_plan_set_error(err, err_size,
                         "mac-move dampening threshold must be 1..1000",
                         NULL, NULL);
    if (!l2_parse_int_range(window_s, 1, 3600, &window))
        return l2_plan_set_error(err, err_size,
                         "mac-move dampening window must be 1..3600 seconds",
                         NULL, NULL);
    if (action && action[0] &&
        strcmp(action, "alarm") != 0 &&
        strcmp(action, "shutdown") != 0)
        return l2_plan_set_error(err, err_size,
                         "mac-move dampening action must be alarm or shutdown",
                         NULL, NULL);

    return 0;
}

static bool security_vlan_enabled(nl_yang_session *ys, const char *feature,
                                  const char *vlan) {
    char path[256];

    if (!ys || !feature || !vlan || !vlan[0])
        return false;
    snprintf(path, sizeof(path),
             "/netlab:netlab-config/ethernet-switching-options"
             "/%s/vlan[name='%s']/name", feature, vlan);
    return nl_yang_get(ys, path) != NULL;
}

static bool security_interface_trusted(nl_yang_session *ys,
                                       const char *feature,
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

static int validate_security_feature(nl_yang_session *ys,
                                     const cfg_port_ref *ports, int n_ports,
                                     const char *feature,
                                     char *err, size_t err_size) {
    char *xml;
    char open_tag[64];
    char close_tag[64];
    char *feature_xml;
    char *feature_end;
    char *p;

    if (!ys || !feature)
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
        return l2_plan_set_error(err, err_size,
                                 "malformed %s configuration",
                                 feature, NULL);
    }

    p = feature_xml;
    while ((p = strstr(p, "<vlan>")) && p < feature_end) {
        char *end = strstr(p, "</vlan>");
        char vlan[64];
        if (!end || end > feature_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", vlan, sizeof(vlan)) == 0) {
            if (l2_get_vlan_id(ys, vlan) <= 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "%s references undefined VLAN %s",
                                 feature, vlan);
            }
            if (strcmp(feature, "arp-inspection") == 0 &&
                !security_vlan_enabled(ys, "dhcp-snooping", vlan)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "arp-inspection vlan %s requires DHCP snooping",
                                 vlan, NULL);
            }
        }
        p = end + strlen("</vlan>");
    }

    p = feature_xml;
    while ((p = strstr(p, "<interface>")) && p < feature_end) {
        char *end = strstr(p, "</interface>");
        char ifname[64];
        char trusted[16];
        const cfg_port_ref *port;

        if (!end || end > feature_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", ifname, sizeof(ifname)) != 0) {
            p = end + strlen("</interface>");
            continue;
        }
        port = l2_find_port_ref(ports, n_ports, ifname);
        if (!port) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                                     "%s interface %s not found",
                                     feature, ifname);
        }
        if (l2_extract_xml_leaf(p, end, "trusted", trusted,
                                sizeof(trusted)) == 0 &&
            trusted[0] && strcmp(trusted, "true") != 0 &&
            strcmp(trusted, "false") != 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                                     "%s interface %s trusted must be boolean",
                                     feature, ifname);
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return 0;
}

int l2_validate_l2_security_intents(nl_yang_session *ys,
                                    const cfg_port_ref *ports, int n_ports,
                                    char *err, size_t err_size) {
    if (validate_security_feature(ys, ports, n_ports, "dhcp-snooping",
                                  err, err_size) != 0)
        return -1;
    if (validate_security_feature(ys, ports, n_ports, "arp-inspection",
                                  err, err_size) != 0)
        return -1;
    return 0;
}

int l2_validate_dhcp_binding_intents(nl_yang_session *ys,
                                     const cfg_port_ref *ports, int n_ports,
                                     char *err, size_t err_size) {
    cfg_dhcp_binding_intent entries[CFG_DHCP_BINDING_MAX_ENTRIES];
    int configured;
    int n;
    char *xml;
    char *dhcp;
    char *dhcp_end;
    char *p;

    if (!ys)
        return 0;
    configured = nl_yang_count(
        ys,
        "/netlab:netlab-config/ethernet-switching-options/"
        "dhcp-snooping/binding");
    if (configured < 0)
        return l2_plan_set_error(err, err_size,
                                 "cannot count dhcp-snooping bindings",
                                 NULL, NULL);
    if (configured > CFG_DHCP_BINDING_MAX_ENTRIES) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "dhcp-snooping uses %d bindings; maximum is %d",
                     configured, CFG_DHCP_BINDING_MAX_ENTRIES);
        return -1;
    }
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;
    dhcp = strstr(xml, "<dhcp-snooping>");
    dhcp_end = dhcp ? strstr(dhcp, "</dhcp-snooping>") : NULL;
    p = dhcp;
    while (dhcp && dhcp_end && (p = strstr(p, "<binding>")) &&
           p < dhcp_end) {
        char *end = strstr(p, "</binding>");
        char mac[18];
        char vlan[64];
        char ifname[64];
        char ip[16];
        char normalized[18];
        const cfg_port_ref *port;
        struct in_addr addr;
        u32 ip_host;

        if (!end || end > dhcp_end) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "malformed dhcp-snooping binding",
                             NULL, NULL);
        }
        if (l2_extract_xml_leaf(p, end, "mac-address", mac,
                                sizeof(mac)) != 0 ||
            l2_extract_xml_leaf(p, end, "vlan", vlan,
                                sizeof(vlan)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0 ||
            l2_extract_xml_leaf(p, end, "ip-address", ip,
                                sizeof(ip)) != 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding requires mac-address, vlan, interface, and ip-address",
                             NULL, NULL);
        }
        if (!l2_normalize_mac_text(mac, normalized, sizeof(normalized)) ||
            !l2_static_mac_is_unicast_nonzero(normalized)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding %s must be a non-zero unicast MAC",
                             mac, NULL);
        }
        if (inet_pton(AF_INET, ip, &addr) != 1) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding %s has invalid IPv4 address",
                             normalized, NULL);
        }
        ip_host = ntohl(addr.s_addr);
        if (ip_host == 0 || ip_host == 0xffffffffU) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding %s has unusable IPv4 address",
                             normalized, NULL);
        }
        if (l2_get_vlan_id(ys, vlan) <= 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding references undefined VLAN %s",
                             vlan, NULL);
        }
        port = l2_find_port_ref(ports, n_ports, ifname);
        if (!port) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding interface %s not found",
                             ifname, NULL);
        }
        p = end + strlen("</binding>");
    }
    free(xml);

    n = l2_collect_dhcp_binding_intents(ys, entries,
                                        CFG_DHCP_BINDING_MAX_ENTRIES,
                                        ports, n_ports);
    for (int i = 0; i < n; i++) {
        cfg_if_intent intent;

        if (!l2_static_mac_is_unicast_nonzero(entries[i].mac))
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding %s must be a non-zero unicast MAC",
                             entries[i].mac, NULL);
        if (entries[i].port.is_aggregate || entries[i].port.hw_port <= 0)
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding interface %s must be a physical hardware port",
                             entries[i].ifname, NULL);
        if (security_interface_trusted(ys, "dhcp-snooping",
                                       entries[i].ifname))
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding interface %s cannot be trusted",
                             entries[i].ifname, NULL);
        l2_read_interface_intent(ys, entries[i].ifname, &intent);
        if (!intent.has_l2 || !l2_intent_has_vid(&intent, entries[i].vid))
            return l2_plan_set_error(err, err_size,
                             "dhcp-snooping binding interface %s is not a member of VLAN %s",
                             entries[i].ifname, entries[i].vlan);
        for (int j = i + 1; j < n; j++) {
            if (entries[i].vid == entries[j].vid &&
                strcmp(entries[i].mac, entries[j].mac) == 0)
                return l2_plan_set_error(err, err_size,
                             "duplicate dhcp-snooping binding for %s vlan %s",
                             entries[i].mac, entries[i].vlan);
            if (entries[i].vid == entries[j].vid &&
                strcmp(entries[i].ip, entries[j].ip) == 0)
                return l2_plan_set_error(err, err_size,
                             "duplicate dhcp-snooping IP binding for %s vlan %s",
                             entries[i].ip, entries[i].vlan);
        }
    }
    return 0;
}

static bool user_filter_name_valid(const char *name) {
    if (!name || !isalpha((unsigned char)name[0]))
        return false;
    for (int i = 1; name[i]; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '_' && c != '.' && c != '-')
            return false;
    }
    return strlen(name) <= 64;
}

int l2_validate_user_filter_intents(nl_yang_session *ys,
                                    const cfg_port_ref *ports, int n_ports,
                                    char *err, size_t err_size) {
    cfg_user_filter_intent entries[CFG_USER_FILTER_MAX_ENTRIES];
    const char *feature_names[] = { "user-filter", "ingress-acl" };
    int n;
    char *xml;
    int term_count = 0;

    if (!ys)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;
    for (size_t i = 0; i < sizeof(feature_names) / sizeof(feature_names[0]);
         i++) {
        char open_tag[64];
        char close_tag[64];
        char *feature;
        char *feature_end;
        char *p;

        snprintf(open_tag, sizeof(open_tag), "<%s>", feature_names[i]);
        snprintf(close_tag, sizeof(close_tag), "</%s>", feature_names[i]);
        feature = strstr(xml, open_tag);
        feature_end = feature ? strstr(feature, close_tag) : NULL;
        p = feature;
        while (feature && feature_end && (p = strstr(p, "<term>")) &&
               p < feature_end) {
            char *end = strstr(p, "</term>");
            char name[64];
            char vlan[64];
            char ifname[64];
            char src_mac[18];
            char dst_mac[18];
            char normalized[18];
            char action[16] = "drop";
            bool has_src;
            bool has_dst;

            if (!end || end > feature_end) {
                char msg[96];
                snprintf(msg, sizeof(msg), "malformed %s term",
                         feature_names[i]);
                free(xml);
                return l2_plan_set_error(err, err_size, msg, NULL, NULL);
            }
            term_count++;
            if (term_count > CFG_USER_FILTER_MAX_ENTRIES) {
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "L2 filter uses %d terms, hardware capacity is %d",
                             term_count, CFG_USER_FILTER_MAX_ENTRIES);
                free(xml);
                return -1;
            }
            has_src = l2_extract_xml_leaf(p, end, "source-mac", src_mac,
                                          sizeof(src_mac)) == 0;
            has_dst = l2_extract_xml_leaf(p, end, "destination-mac", dst_mac,
                                          sizeof(dst_mac)) == 0;
            if (l2_extract_xml_leaf(p, end, "name", name,
                                    sizeof(name)) != 0 ||
                l2_extract_xml_leaf(p, end, "vlan", vlan,
                                    sizeof(vlan)) != 0 ||
                l2_extract_xml_leaf(p, end, "interface", ifname,
                                    sizeof(ifname)) != 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "%s term requires name, vlan, and interface",
                                 feature_names[i], NULL);
            }
            if (has_src == has_dst) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "%s term %s requires exactly one of source-mac or destination-mac",
                                 feature_names[i], name);
            }
            if (!user_filter_name_valid(name)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "%s term %s has invalid name",
                                 feature_names[i], name);
            }
            if (l2_extract_xml_leaf(p, end, "action", action,
                                    sizeof(action)) == 0 &&
                strcmp(action, "drop") != 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "%s term %s action must be drop",
                                 feature_names[i], name);
            }
            if (!l2_normalize_mac_text(has_src ? src_mac : dst_mac,
                                       normalized, sizeof(normalized)) ||
                !l2_static_mac_is_unicast_nonzero(normalized)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "%s term %s MAC must be a non-zero unicast MAC",
                                 feature_names[i], name);
            }
            if (l2_get_vlan_id(ys, vlan) <= 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "%s term %s references undefined VLAN",
                                 feature_names[i], name);
            }
            if (!l2_find_port_ref(ports, n_ports, ifname)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "%s term %s interface not found",
                                 feature_names[i], name);
            }
            p = end + strlen("</term>");
        }
    }
    free(xml);

    n = l2_collect_user_filter_intents(ys, entries,
                                       CFG_USER_FILTER_MAX_ENTRIES,
                                       ports, n_ports);
    for (int i = 0; i < n; i++) {
        cfg_if_intent intent;
        const char *feature = entries[i].feature[0] ?
                              entries[i].feature : "user-filter";

        if (entries[i].port.is_aggregate || entries[i].port.hw_port <= 0)
            return l2_plan_set_error(err, err_size,
                             "%s term %s interface must be a physical hardware port",
                             feature, entries[i].name);
        l2_read_interface_intent(ys, entries[i].ifname, &intent);
        if (!intent.has_l2 || !l2_intent_has_vid(&intent, entries[i].vid))
            return l2_plan_set_error(err, err_size,
                             "%s term %s interface is not a member of VLAN",
                             feature, entries[i].name);
        for (int j = i + 1; j < n; j++) {
            if (strcmp(entries[i].name, entries[j].name) == 0)
                return l2_plan_set_error(err, err_size,
                             "duplicate L2 filter term name %s",
                             entries[i].name, NULL);
            if (entries[i].vid == entries[j].vid &&
                entries[i].port.hw_port == entries[j].port.hw_port &&
                strcmp(entries[i].mac_kind, entries[j].mac_kind) == 0 &&
                strcmp(entries[i].mac, entries[j].mac) == 0)
                return l2_plan_set_error(err, err_size,
                             "duplicate L2 filter match for %s",
                             entries[i].mac, NULL);
        }
    }
    return 0;
}

int l2_validate_ingress_ipv4_acl_intents(nl_yang_session *ys,
                                         const cfg_port_ref *ports,
                                         int n_ports,
                                         char *err, size_t err_size) {
    cfg_ingress_ipv4_acl_intent entries[CFG_INGRESS_IPV4_ACL_MAX_ENTRIES];
    char *xml;
    char *feature;
    char *feature_end;
    char *p;
    int term_count = 0;
    int n;

    if (!ys)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    feature = strstr(xml, "<ingress-ipv4-acl>");
    feature_end = feature ? strstr(feature, "</ingress-ipv4-acl>") : NULL;
    p = feature;
    while (feature && feature_end &&
           (p = strstr(p, "<term>")) && p < feature_end) {
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
        int proto = -1;
        int dscp = -1;
        int ecn = -1;
        int src_port = -1;
        int dst_port = -1;
        int src_port_start = -1;
        int src_port_end = -1;
        int dst_port_start = -1;
        int dst_port_end = -1;
        int tcp_flags = -1;
        int tcp_flags_mask = -1;
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

        if (!end || end > feature_end) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "malformed ingress-ipv4-acl term", NULL, NULL);
        }
        term_count++;
        if (term_count > CFG_INGRESS_IPV4_ACL_MAX_ENTRIES) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "ingress-ipv4-acl uses %d terms, hardware capacity is %d",
                         term_count, CFG_INGRESS_IPV4_ACL_MAX_ENTRIES);
            free(xml);
            return -1;
        }
        if (l2_extract_xml_leaf(p, end, "name", name,
                                sizeof(name)) != 0 ||
            l2_extract_xml_leaf(p, end, "vlan", vlan,
                                sizeof(vlan)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term requires name, vlan, and interface",
                             NULL, NULL);
        }
        if (!user_filter_name_valid(name)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s has invalid name",
                             name, NULL);
        }
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
        if (has_src_ip && has_src_prefix) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s cannot set both source-ip and source-prefix",
                             name, NULL);
        }
        if (has_dst_ip && has_dst_prefix) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s cannot set both destination-ip and destination-prefix",
                             name, NULL);
        }
        if (!has_src_ip && !has_src_prefix &&
            !has_dst_ip && !has_dst_prefix && !has_dscp &&
            !has_ecn && !has_proto &&
            !has_src_port && !has_dst_port &&
            !has_src_port_range && !has_dst_port_range &&
            !has_tcp_flags) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s requires at least one IPv4/L4 match",
                             name, NULL);
        }
        if (has_src_port && has_src_port_range) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s cannot set both source-port and source-port-range",
                             name, NULL);
        }
        if (has_dst_port && has_dst_port_range) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s cannot set both destination-port and destination-port-range",
                             name, NULL);
        }
        if (has_src_ip &&
            (inet_pton(AF_INET, src_ip, &addr) != 1 ||
             ntohl(addr.s_addr) == 0 || ntohl(addr.s_addr) == 0xffffffffU)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s source-ip is invalid",
                             name, NULL);
        }
        if (has_src_prefix &&
            !l2_parse_ipv4_prefix_text(src_prefix, &prefix_ip,
                                       &prefix_mask, &prefix_len)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s source-prefix is invalid",
                             name, NULL);
        }
        if (has_dst_ip &&
            (inet_pton(AF_INET, dst_ip, &addr) != 1 ||
             ntohl(addr.s_addr) == 0 || ntohl(addr.s_addr) == 0xffffffffU)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s destination-ip is invalid",
                             name, NULL);
        }
        if (has_dst_prefix &&
            !l2_parse_ipv4_prefix_text(dst_prefix, &prefix_ip,
                                       &prefix_mask, &prefix_len)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s destination-prefix is invalid",
                             name, NULL);
        }
        if (has_dscp) {
            if (!l2_parse_int_range(dscp_text, 0, 63, &dscp)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s dscp must be 0..63",
                             name, NULL);
            }
        }
        if (has_ecn) {
            if (!l2_parse_int_range(ecn_text, 0, 3, &ecn)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s ecn must be 0..3",
                             name, NULL);
            }
        }
        if (has_proto) {
            if (!l2_parse_int_range(proto_text, 0, 255, &proto)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s protocol must be 0..255",
                             name, NULL);
            }
        }
        if (has_src_port) {
            if (!l2_parse_int_range(src_port_text, 0, 65535, &src_port)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s source-port must be 0..65535",
                             name, NULL);
            }
        }
        if (has_dst_port) {
            if (!l2_parse_int_range(dst_port_text, 0, 65535, &dst_port)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s destination-port must be 0..65535",
                             name, NULL);
            }
        }
        if (has_src_port_range &&
            !l2_parse_port_range_text(src_port_range_text,
                                      &src_port_start, &src_port_end)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s source-port-range must be start-end within 0..65535",
                             name, NULL);
        }
        if (has_dst_port_range &&
            !l2_parse_port_range_text(dst_port_range_text,
                                      &dst_port_start, &dst_port_end)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s destination-port-range must be start-end within 0..65535",
                             name, NULL);
        }
        if ((has_src_port || has_dst_port ||
             has_src_port_range || has_dst_port_range) &&
            (!has_proto || (proto != 6 && proto != 17))) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s ports require protocol 6 or 17",
                             name, NULL);
        }
        if (has_tcp_flags) {
            if (!l2_parse_int_range(tcp_flags_text, 0, 63, &tcp_flags)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s tcp-flags must be 0..63",
                             name, NULL);
            }
        }
        if (has_tcp_flags_mask) {
            if (!l2_parse_int_range(tcp_flags_mask_text, 1, 63,
                                    &tcp_flags_mask)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s tcp-flags-mask must be 1..63",
                             name, NULL);
            }
        }
        if (has_tcp_flags_mask && !has_tcp_flags) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s tcp-flags-mask requires tcp-flags",
                             name, NULL);
        }
        if (has_tcp_flags && (!has_proto || proto != 6)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s tcp-flags require protocol 6",
                             name, NULL);
        }
        if (has_tcp_flags && has_tcp_flags_mask &&
            (tcp_flags & ~tcp_flags_mask) != 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s tcp-flags bits must be covered by tcp-flags-mask",
                             name, NULL);
        }
        if (l2_extract_xml_leaf(p, end, "action", action,
                                sizeof(action)) == 0 &&
            strcmp(action, "drop") != 0 &&
            strcmp(action, "count") != 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s action must be drop or count",
                             name, NULL);
        }
        if (l2_get_vlan_id(ys, vlan) <= 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s references undefined VLAN",
                             name, NULL);
        }
        if (!l2_find_port_ref(ports, n_ports, ifname)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s interface not found",
                             name, NULL);
        }
        p = end + strlen("</term>");
    }
    free(xml);

    n = l2_collect_ingress_ipv4_acl_intents(
        ys, entries, CFG_INGRESS_IPV4_ACL_MAX_ENTRIES, ports, n_ports);
    term_count = 0;
    for (int i = 0; i < n; i++) {
        cfg_if_intent intent;
        int hw_entries = l2_ingress_ipv4_acl_hw_entry_count(&entries[i]);

        if (hw_entries <= 0)
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s has invalid hardware expansion",
                             entries[i].name, NULL);
        term_count += hw_entries;
        if (term_count > CFG_INGRESS_IPV4_ACL_MAX_ENTRIES) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "ingress-ipv4-acl uses %d hardware entries, hardware capacity is %d",
                         term_count, CFG_INGRESS_IPV4_ACL_MAX_ENTRIES);
            return -1;
        }
        if (entries[i].port.is_aggregate || entries[i].port.hw_port <= 0)
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s interface must be a physical hardware port",
                             entries[i].name, NULL);
        l2_read_interface_intent(ys, entries[i].ifname, &intent);
        if (!intent.has_l2 || !l2_intent_has_vid(&intent, entries[i].vid))
            return l2_plan_set_error(err, err_size,
                             "ingress-ipv4-acl term %s interface is not a member of VLAN",
                             entries[i].name, NULL);
        for (int j = i + 1; j < n; j++) {
            if (strcmp(entries[i].name, entries[j].name) == 0)
                return l2_plan_set_error(err, err_size,
                             "duplicate ingress-ipv4-acl term name %s",
                             entries[i].name, NULL);
            if (entries[i].vid == entries[j].vid &&
                entries[i].port.hw_port == entries[j].port.hw_port &&
                entries[i].match.has_src_ip ==
                    entries[j].match.has_src_ip &&
                entries[i].match.has_dst_ip ==
                    entries[j].match.has_dst_ip &&
                entries[i].match.has_src_ip_mask ==
                    entries[j].match.has_src_ip_mask &&
                entries[i].match.has_dst_ip_mask ==
                    entries[j].match.has_dst_ip_mask &&
                entries[i].match.has_dscp ==
                    entries[j].match.has_dscp &&
                entries[i].match.has_ecn ==
                    entries[j].match.has_ecn &&
                entries[i].match.has_protocol ==
                    entries[j].match.has_protocol &&
                entries[i].match.has_src_port ==
                    entries[j].match.has_src_port &&
                entries[i].match.has_dst_port ==
                    entries[j].match.has_dst_port &&
                entries[i].match.has_src_port_range ==
                    entries[j].match.has_src_port_range &&
                entries[i].match.has_dst_port_range ==
                    entries[j].match.has_dst_port_range &&
                entries[i].match.has_tcp_flags ==
                    entries[j].match.has_tcp_flags &&
                entries[i].match.has_tcp_flags_mask ==
                    entries[j].match.has_tcp_flags_mask &&
                entries[i].match.src_ip == entries[j].match.src_ip &&
                entries[i].match.dst_ip == entries[j].match.dst_ip &&
                entries[i].match.src_ip_mask ==
                    entries[j].match.src_ip_mask &&
                entries[i].match.dst_ip_mask ==
                    entries[j].match.dst_ip_mask &&
                entries[i].match.dscp == entries[j].match.dscp &&
                entries[i].match.ecn == entries[j].match.ecn &&
                entries[i].match.protocol == entries[j].match.protocol &&
                entries[i].match.src_port == entries[j].match.src_port &&
                entries[i].match.dst_port == entries[j].match.dst_port &&
                entries[i].match.src_port_start ==
                    entries[j].match.src_port_start &&
                entries[i].match.src_port_end ==
                    entries[j].match.src_port_end &&
                entries[i].match.dst_port_start ==
                    entries[j].match.dst_port_start &&
                entries[i].match.dst_port_end ==
                    entries[j].match.dst_port_end &&
                entries[i].match.tcp_flags == entries[j].match.tcp_flags &&
                entries[i].match.tcp_flags_mask ==
                    entries[j].match.tcp_flags_mask)
                return l2_plan_set_error(err, err_size,
                             "duplicate ingress-ipv4-acl match for %s",
                             entries[i].name, NULL);
        }
    }
    return 0;
}

static bool acl_policer_mac_valid(const char *text) {
    unsigned int values[6];
    bool nonzero = false;

    if (!text ||
        sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6)
        return false;
    if (values[0] & 0x01)
        return false;
    for (int i = 0; i < 6; i++) {
        if (values[i] > 255)
            return false;
        if (values[i] != 0)
            nonzero = true;
    }
    return nonzero;
}

int l2_validate_acl_policer_intents(nl_yang_session *ys,
                                    const cfg_port_ref *ports,
                                    int n_ports,
                                    char *err, size_t err_size) {
    cfg_acl_policer_intent entries[CFG_ACL_POLICER_MAX_ENTRIES];
    char *xml;
    char *feature;
    char *feature_end;
    char *p;
    int term_count = 0;
    int n;

    if (!ys)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    feature = strstr(xml, "<acl-policer>");
    feature_end = feature ? strstr(feature, "</acl-policer>") : NULL;
    p = feature;
    while (feature && feature_end &&
           (p = strstr(p, "<term>")) && p < feature_end) {
        char *end = strstr(p, "</term>");
        char name[64];
        char ifname[64];
        char mac_text[32];
        char rate_text[32];
        char burst_text[32];
        const cfg_port_ref *port;
        int rate;
        int burst = CFG_ACL_POLICER_DEFAULT_BURST_BYTES;

        if (!end || end > feature_end) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "malformed acl-policer term", NULL, NULL);
        }
        term_count++;
        if (term_count > CFG_ACL_POLICER_MAX_ENTRIES) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "acl-policer uses %d terms, hardware capacity is %d",
                         term_count, CFG_ACL_POLICER_MAX_ENTRIES);
            free(xml);
            return -1;
        }
        if (l2_extract_xml_leaf(p, end, "name", name,
                                sizeof(name)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0 ||
            l2_extract_xml_leaf(p, end, "destination-mac", mac_text,
                                sizeof(mac_text)) != 0 ||
            l2_extract_xml_leaf(p, end, "bandwidth", rate_text,
                                sizeof(rate_text)) != 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "acl-policer term requires name, interface, destination-mac, and bandwidth",
                             NULL, NULL);
        }
        if (!user_filter_name_valid(name)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "acl-policer term %s has invalid name",
                             name, NULL);
        }
        port = l2_find_port_ref(ports, n_ports, ifname);
        if (!port) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "acl-policer term %s interface not found",
                             name, NULL);
        }
        if (port->is_aggregate || port->hw_port <= 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "acl-policer term %s interface must be a physical hardware port",
                             name, NULL);
        }
        if (!acl_policer_mac_valid(mac_text)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "acl-policer term %s destination-mac is invalid",
                             name, NULL);
        }
        if (!l2_parse_int_range(rate_text, CFG_ACL_POLICER_MIN_RATE_KBPS,
                                CFG_ACL_POLICER_MAX_RATE_KBPS, &rate)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "acl-policer term %s bandwidth must be 1..100000000",
                             name, NULL);
        }
        if (l2_extract_xml_leaf(p, end, "burst-size", burst_text,
                                sizeof(burst_text)) == 0 &&
            !l2_parse_int_range(burst_text, CFG_ACL_POLICER_MIN_BURST_BYTES,
                                CFG_ACL_POLICER_MAX_BURST_BYTES, &burst)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "acl-policer term %s burst-size must be 1024..268435456",
                             name, NULL);
        }
        if (burst < CFG_ACL_POLICER_MIN_BURST_BYTES ||
            burst > CFG_ACL_POLICER_MAX_BURST_BYTES) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "acl-policer term %s burst-size must be 1024..268435456",
                             name, NULL);
        }
        p = end + strlen("</term>");
    }
    free(xml);

    n = l2_collect_acl_policer_intents(
        ys, entries, CFG_ACL_POLICER_MAX_ENTRIES, ports, n_ports);
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (strcmp(entries[i].name, entries[j].name) == 0)
                return l2_plan_set_error(err, err_size,
                             "duplicate acl-policer term name %s",
                             entries[i].name, NULL);
            if (entries[i].port.hw_port == entries[j].port.hw_port &&
                entries[i].dst_mac == entries[j].dst_mac)
                return l2_plan_set_error(err, err_size,
                             "duplicate acl-policer match for %s",
                             entries[i].name, NULL);
        }
    }
    return 0;
}

int l2_validate_egress_acl_intents(nl_yang_session *ys,
                                   const cfg_port_ref *ports,
                                   int n_ports,
                                   char *err, size_t err_size) {
    cfg_egress_acl_intent entries[CFG_EGRESS_ACL_MAX_ENTRIES];
    char *xml;
    char *feature;
    char *feature_end;
    char *p;
    int term_count = 0;
    int n;

    if (!ys)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    feature = strstr(xml, "<egress-acl>");
    feature_end = feature ? strstr(feature, "</egress-acl>") : NULL;
    p = feature;
    while (feature && feature_end &&
           (p = strstr(p, "<term>")) && p < feature_end) {
        char *end = strstr(p, "</term>");
        char name[64];
        char ifname[64];
        char src_mac_text[32] = {0};
        char dst_mac_text[32] = {0};
        char action[16] = "drop";
        bool has_src;
        bool has_dst;
        const cfg_port_ref *port;

        if (!end || end > feature_end) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "malformed egress-acl term", NULL, NULL);
        }
        term_count++;
        if (term_count > CFG_EGRESS_ACL_MAX_ENTRIES) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "egress-acl uses %d terms, hardware capacity is %d",
                         term_count, CFG_EGRESS_ACL_MAX_ENTRIES);
            free(xml);
            return -1;
        }
        if (l2_extract_xml_leaf(p, end, "name", name,
                                sizeof(name)) != 0 ||
            l2_extract_xml_leaf(p, end, "interface", ifname,
                                sizeof(ifname)) != 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "egress-acl term requires name and interface",
                             NULL, NULL);
        }
        has_src = l2_extract_xml_leaf(p, end, "source-mac", src_mac_text,
                                      sizeof(src_mac_text)) == 0 &&
                  src_mac_text[0] != '\0';
        has_dst = l2_extract_xml_leaf(p, end, "destination-mac", dst_mac_text,
                                      sizeof(dst_mac_text)) == 0 &&
                  dst_mac_text[0] != '\0';
        if (!has_src && !has_dst) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "egress-acl term %s requires source-mac or destination-mac",
                             name, NULL);
        }
        if (!user_filter_name_valid(name)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "egress-acl term %s has invalid name",
                             name, NULL);
        }
        port = l2_find_port_ref(ports, n_ports, ifname);
        if (!port) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "egress-acl term %s interface not found",
                             name, NULL);
        }
        if (port->is_aggregate || port->hw_port <= 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "egress-acl term %s interface must be a physical hardware port",
                             name, NULL);
        }
        if (has_src && !acl_policer_mac_valid(src_mac_text)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "egress-acl term %s source-mac is invalid",
                             name, NULL);
        }
        if (has_dst && !acl_policer_mac_valid(dst_mac_text)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "egress-acl term %s destination-mac is invalid",
                             name, NULL);
        }
        if (l2_extract_xml_leaf(p, end, "action", action,
                                sizeof(action)) == 0 &&
            action[0] && strcmp(action, "drop") != 0) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "egress-acl term %s action must be drop",
                             name, NULL);
        }
        p = end + strlen("</term>");
    }
    free(xml);

    n = l2_collect_egress_acl_intents(
        ys, entries, CFG_EGRESS_ACL_MAX_ENTRIES, ports, n_ports);
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (strcmp(entries[i].name, entries[j].name) == 0)
                return l2_plan_set_error(err, err_size,
                             "duplicate egress-acl term name %s",
                             entries[i].name, NULL);
            if (entries[i].port.hw_port == entries[j].port.hw_port)
                return l2_plan_set_error(err, err_size,
                             "duplicate egress-acl egress interface %s",
                             entries[i].ifname, NULL);
        }
    }
    return 0;
}

static bool acl_independent_family_valid(const char *family) {
    return family &&
           (strcmp(family, "ethernet") == 0 ||
            strcmp(family, "inet") == 0 ||
            strcmp(family, "policer") == 0 ||
            strcmp(family, "egress") == 0);
}

static bool acl_independent_has_inet_selector(
    bool has_src_ip, bool has_dst_ip, bool has_src_prefix,
    bool has_dst_prefix, bool has_dscp, bool has_ecn, bool has_proto,
    bool has_src_port, bool has_dst_port, bool has_src_port_range,
    bool has_dst_port_range, bool has_tcp_flags) {
    return has_src_ip || has_dst_ip || has_src_prefix || has_dst_prefix ||
           has_dscp || has_ecn || has_proto || has_src_port ||
           has_dst_port || has_src_port_range || has_dst_port_range ||
           has_tcp_flags;
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

int l2_validate_acl_independent_intents(nl_yang_session *ys,
                                        const cfg_port_ref *ports,
                                        int n_ports,
                                        char *err, size_t err_size) {
    cfg_acl_independent_intent entries[CFG_ACL_INDEPENDENT_MAX_TERMS];
    char *xml;
    char *feature;
    char *feature_end;
    char *g;
    int term_count = 0;
    int n;

    if (!ys)
        return 0;
    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    feature = strstr(xml, "<acl-independent>");
    feature_end = feature ? strstr(feature, "</acl-independent>") : NULL;
    g = feature;
    while (feature && feature_end &&
           (g = strstr(g, "<group>")) && g < feature_end) {
        char *g_end = strstr(g, "</group>");
        char *first_term;
        char *group_leaf_end;
        char group_name[64] = {0};
        char *p;

        if (!g_end || g_end > feature_end) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "malformed independent ACL group", NULL, NULL);
        }
        first_term = strstr(g, "<term>");
        group_leaf_end = (first_term && first_term < g_end) ? first_term : g_end;
        if (l2_extract_xml_leaf(g, group_leaf_end, "name", group_name,
                                sizeof(group_name)) != 0 ||
            !group_name[0]) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "independent ACL group requires name",
                             NULL, NULL);
        }
        if (!user_filter_name_valid(group_name)) {
            free(xml);
            return l2_plan_set_error(err, err_size,
                             "independent ACL group %s has invalid name",
                             group_name, NULL);
        }

        p = g;
        while ((p = strstr(p, "<term>")) && p < g_end) {
            char *end = strstr(p, "</term>");
            char term_name[64] = {0};
            char family[16] = {0};
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
            struct in_addr addr;
            u32 prefix_ip;
            u32 prefix_mask;
            int prefix_len;
            int proto = -1;
            int dscp = -1;
            int ecn = -1;
            int src_port = -1;
            int dst_port = -1;
            int src_port_start = -1;
            int src_port_end = -1;
            int dst_port_start = -1;
            int dst_port_end = -1;
            int tcp_flags = -1;
            int tcp_flags_mask = -1;
            int rate = 0;
            int burst = CFG_ACL_POLICER_DEFAULT_BURST_BYTES;
            bool has_vlan;
            bool has_interface;
            bool has_src_mac;
            bool has_dst_mac;
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
            bool has_inet_selector;
            bool has_mac_selector;
            bool action_is_policer;
            const cfg_port_ref *port = NULL;

            if (!end || end > g_end) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "malformed independent ACL term",
                                 NULL, NULL);
            }
            term_count++;
            if (term_count > CFG_ACL_INDEPENDENT_MAX_TERMS) {
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "independent ACL uses %d terms, current public-independent capacity is %d",
                             term_count, CFG_ACL_INDEPENDENT_MAX_TERMS);
                free(xml);
                return -1;
            }
            if (l2_extract_xml_leaf(p, end, "name", term_name,
                                    sizeof(term_name)) != 0 ||
                l2_extract_xml_leaf(p, end, "family", family,
                                    sizeof(family)) != 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term requires name and family",
                                 NULL, NULL);
            }
            if (!user_filter_name_valid(term_name)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s has invalid name",
                                 term_name, NULL);
            }
            if (!acl_independent_family_valid(family)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s family is unsupported",
                                 term_name, NULL);
            }
            if (strcmp(family, "egress") == 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL egress term %s requires the future egress owner",
                                 term_name, NULL);
            }

            has_vlan = l2_extract_xml_leaf(p, end, "vlan", vlan,
                                           sizeof(vlan)) == 0 && vlan[0];
            has_interface = l2_extract_xml_leaf(p, end, "interface", ifname,
                                                sizeof(ifname)) == 0 &&
                            ifname[0];
            has_src_mac = l2_extract_xml_leaf(p, end, "source-mac",
                                              src_mac_text,
                                              sizeof(src_mac_text)) == 0 &&
                          src_mac_text[0] != '\0';
            has_dst_mac = l2_extract_xml_leaf(p, end, "destination-mac",
                                              dst_mac_text,
                                              sizeof(dst_mac_text)) == 0 &&
                          dst_mac_text[0] != '\0';
            has_src_ip = l2_extract_xml_leaf(p, end, "source-ip", src_ip,
                                             sizeof(src_ip)) == 0;
            has_dst_ip = l2_extract_xml_leaf(p, end, "destination-ip", dst_ip,
                                             sizeof(dst_ip)) == 0;
            has_src_prefix = l2_extract_xml_leaf(p, end, "source-prefix",
                                                 src_prefix,
                                                 sizeof(src_prefix)) == 0;
            has_dst_prefix =
                l2_extract_xml_leaf(p, end, "destination-prefix",
                                    dst_prefix, sizeof(dst_prefix)) == 0;
            has_dscp = l2_extract_xml_leaf(p, end, "dscp", dscp_text,
                                           sizeof(dscp_text)) == 0;
            has_ecn = l2_extract_xml_leaf(p, end, "ecn", ecn_text,
                                          sizeof(ecn_text)) == 0;
            has_proto = l2_extract_xml_leaf(p, end, "protocol", proto_text,
                                            sizeof(proto_text)) == 0;
            has_src_port = l2_extract_xml_leaf(p, end, "source-port",
                                               src_port_text,
                                               sizeof(src_port_text)) == 0;
            has_dst_port =
                l2_extract_xml_leaf(p, end, "destination-port",
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
            has_tcp_flags_mask =
                l2_extract_xml_leaf(p, end, "tcp-flags-mask",
                                    tcp_flags_mask_text,
                                    sizeof(tcp_flags_mask_text)) == 0;
            has_inet_selector = acl_independent_has_inet_selector(
                has_src_ip, has_dst_ip, has_src_prefix, has_dst_prefix,
                has_dscp, has_ecn, has_proto, has_src_port, has_dst_port,
                has_src_port_range, has_dst_port_range, has_tcp_flags);
            has_mac_selector = has_src_mac || has_dst_mac;

            if (l2_extract_xml_leaf(p, end, "action", action,
                                    sizeof(action)) != 0 || !action[0])
                snprintf(action, sizeof(action), "%s",
                         strcmp(family, "policer") == 0 ? "policer" :
                         "drop");
            if (!acl_independent_action_valid(family, action)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s action is unsupported for family",
                                 term_name, NULL);
            }
            action_is_policer = strcmp(action, "policer") == 0;

            if (has_src_ip && has_src_prefix) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s cannot set both source-ip and source-prefix",
                                 term_name, NULL);
            }
            if (has_dst_ip && has_dst_prefix) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s cannot set both destination-ip and destination-prefix",
                                 term_name, NULL);
            }
            if (has_src_port && has_src_port_range) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s cannot set both source-port and source-port-range",
                                 term_name, NULL);
            }
            if (has_dst_port && has_dst_port_range) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s cannot set both destination-port and destination-port-range",
                                 term_name, NULL);
            }
            if (has_src_mac && !acl_policer_mac_valid(src_mac_text)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s source-mac is invalid",
                                 term_name, NULL);
            }
            if (has_dst_mac && !acl_policer_mac_valid(dst_mac_text)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s destination-mac is invalid",
                                 term_name, NULL);
            }
            if (has_src_ip &&
                (inet_pton(AF_INET, src_ip, &addr) != 1 ||
                 ntohl(addr.s_addr) == 0 ||
                 ntohl(addr.s_addr) == 0xffffffffU)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s source-ip is invalid",
                                 term_name, NULL);
            }
            if (has_dst_ip &&
                (inet_pton(AF_INET, dst_ip, &addr) != 1 ||
                 ntohl(addr.s_addr) == 0 ||
                 ntohl(addr.s_addr) == 0xffffffffU)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s destination-ip is invalid",
                                 term_name, NULL);
            }
            if (has_src_prefix &&
                !l2_parse_ipv4_prefix_text(src_prefix, &prefix_ip,
                                           &prefix_mask, &prefix_len)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s source-prefix is invalid",
                                 term_name, NULL);
            }
            if (has_dst_prefix &&
                !l2_parse_ipv4_prefix_text(dst_prefix, &prefix_ip,
                                           &prefix_mask, &prefix_len)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s destination-prefix is invalid",
                                 term_name, NULL);
            }
            if (has_dscp) {
                if (!l2_parse_int_range(dscp_text, 0, 63, &dscp)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s dscp must be 0..63",
                                     term_name, NULL);
                }
            }
            if (has_ecn) {
                if (!l2_parse_int_range(ecn_text, 0, 3, &ecn)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s ecn must be 0..3",
                                     term_name, NULL);
                }
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s ecn is not yet supported by the hardware ACL owner",
                                 term_name, NULL);
            }
            if (has_proto) {
                if (!l2_parse_int_range(proto_text, 0, 255, &proto)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s protocol must be 0..255",
                                     term_name, NULL);
                }
            }
            if (has_src_port) {
                if (!l2_parse_int_range(src_port_text, 0, 65535,
                                        &src_port)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s source-port must be 0..65535",
                                     term_name, NULL);
                }
            }
            if (has_dst_port) {
                if (!l2_parse_int_range(dst_port_text, 0, 65535,
                                        &dst_port)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s destination-port must be 0..65535",
                                     term_name, NULL);
                }
            }
            if (has_src_port_range &&
                !l2_parse_port_range_text(src_port_range_text,
                                          &src_port_start, &src_port_end)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s source-port-range must be start-end within 0..65535",
                                 term_name, NULL);
            }
            if (has_src_port_range && src_port_start != src_port_end) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s source-port-range requires future multi-rule expansion",
                                 term_name, NULL);
            }
            if (has_dst_port_range &&
                !l2_parse_port_range_text(dst_port_range_text,
                                          &dst_port_start, &dst_port_end)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s destination-port-range must be start-end within 0..65535",
                                 term_name, NULL);
            }
            if (has_dst_port_range && dst_port_start != dst_port_end) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s destination-port-range requires future multi-rule expansion",
                                 term_name, NULL);
            }
            if ((has_src_port || has_dst_port ||
                 has_src_port_range || has_dst_port_range) &&
                (!has_proto || (proto != 6 && proto != 17))) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s ports require protocol 6 or 17",
                                 term_name, NULL);
            }
            if (has_tcp_flags) {
                if (!l2_parse_int_range(tcp_flags_text, 0, 63,
                                        &tcp_flags)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s tcp-flags must be 0..63",
                                     term_name, NULL);
                }
            }
            if (has_tcp_flags_mask) {
                if (!l2_parse_int_range(tcp_flags_mask_text, 1, 63,
                                        &tcp_flags_mask)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s tcp-flags-mask must be 1..63",
                                     term_name, NULL);
                }
            }
            if (has_tcp_flags_mask && !has_tcp_flags) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s tcp-flags-mask requires tcp-flags",
                                 term_name, NULL);
            }
            if (has_tcp_flags && (!has_proto || proto != 6)) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s tcp-flags require protocol 6",
                                 term_name, NULL);
            }
            if (has_tcp_flags && has_tcp_flags_mask &&
                (tcp_flags & ~tcp_flags_mask) != 0) {
                free(xml);
                return l2_plan_set_error(err, err_size,
                                 "independent ACL term %s tcp-flags bits must be covered by tcp-flags-mask",
                                 term_name, NULL);
            }

            if (strcmp(family, "egress") == 0) {
                if (has_vlan || has_inet_selector) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL egress term %s cannot set vlan or IPv4/L4 selectors",
                                     term_name, NULL);
                }
                if (!has_interface || !has_mac_selector) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL egress term %s requires interface and source-mac or destination-mac",
                                     term_name, NULL);
                }
            } else {
                cfg_if_intent if_intent;
                int vid;

                if (!has_vlan || !has_interface) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL %s term %s requires vlan and interface",
                                     family, term_name);
                }
                vid = l2_get_vlan_id(ys, vlan);
                if (vid <= 0) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s references undefined VLAN",
                                     term_name, NULL);
                }
                port = l2_find_port_ref(ports, n_ports, ifname);
                if (!port) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s interface not found",
                                     term_name, NULL);
                }
                if (port->is_aggregate || port->hw_port <= 0) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s interface must be a physical hardware port",
                                     term_name, NULL);
                }
                l2_read_interface_intent(ys, ifname, &if_intent);
                if (!if_intent.has_l2 || !l2_intent_has_vid(&if_intent, vid)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s interface is not a member of VLAN",
                                     term_name, NULL);
                }
            }

            if (has_interface && strcmp(family, "egress") == 0) {
                port = l2_find_port_ref(ports, n_ports, ifname);
                if (!port) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s interface not found",
                                     term_name, NULL);
                }
                if (port->is_aggregate || port->hw_port <= 0) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s interface must be a physical hardware port",
                                     term_name, NULL);
                }
            }

            if (strcmp(family, "ethernet") == 0) {
                if (!has_mac_selector || has_inet_selector) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL ethernet term %s requires MAC selector and no IPv4/L4 selector",
                                     term_name, NULL);
                }
            } else if (strcmp(family, "inet") == 0) {
                if (has_mac_selector || !has_inet_selector) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL inet term %s requires IPv4/L4 selector and no MAC selector",
                                     term_name, NULL);
                }
            } else if (strcmp(family, "policer") == 0) {
                if (has_mac_selector == has_inet_selector) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL policer term %s requires exactly one ethernet or inet selector class",
                                     term_name, NULL);
                }
            }

            if (action_is_policer || strcmp(family, "policer") == 0) {
                if (strcmp(family, "egress") == 0) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL egress term %s does not support policer action",
                                     term_name, NULL);
                }
                if (l2_extract_xml_leaf(p, end, "bandwidth", rate_text,
                                        sizeof(rate_text)) != 0) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL policer term %s requires bandwidth",
                                     term_name, NULL);
                }
                if (!l2_parse_int_range(rate_text,
                                        CFG_ACL_POLICER_MIN_RATE_KBPS,
                                        CFG_ACL_POLICER_MAX_RATE_KBPS,
                                        &rate)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s bandwidth must be 1..100000000",
                                     term_name, NULL);
                }
                if (l2_extract_xml_leaf(p, end, "burst-size", burst_text,
                                        sizeof(burst_text)) == 0 &&
                    !l2_parse_int_range(burst_text,
                                        CFG_ACL_POLICER_MIN_BURST_BYTES,
                                        CFG_ACL_POLICER_MAX_BURST_BYTES,
                                        &burst)) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s burst-size must be 1024..268435456",
                                     term_name, NULL);
                }
                if (burst < CFG_ACL_POLICER_MIN_BURST_BYTES ||
                    burst > CFG_ACL_POLICER_MAX_BURST_BYTES) {
                    free(xml);
                    return l2_plan_set_error(err, err_size,
                                     "independent ACL term %s burst-size must be 1024..268435456",
                                     term_name, NULL);
                }
            }

            p = end + strlen("</term>");
        }
        g = g_end + strlen("</group>");
    }
    free(xml);

    n = l2_collect_acl_independent_intents(
        ys, entries, CFG_ACL_INDEPENDENT_MAX_TERMS, ports, n_ports);
    if (n != term_count)
        return l2_plan_set_error(err, err_size,
                         "independent ACL normalization did not cover every validated term",
                         NULL, NULL);
    for (int i = 0; i < n; i++) {
        if (l2_find_acl_independent_by_key(
                entries, i, entries[i].group, entries[i].term,
                entries[i].family) >= 0)
            return l2_plan_set_error(err, err_size,
                             "duplicate independent ACL term key %s/%s",
                             entries[i].group, entries[i].term);
    }

    return 0;
}

typedef struct {
    cfg_l2_security_rule_intent rules[CFG_L2_SECURITY_MAX_RULES];
    cfg_dhcp_binding_intent bindings[CFG_DHCP_BINDING_MAX_ENTRIES];
    cfg_user_filter_intent filters[CFG_USER_FILTER_MAX_ENTRIES];
    cfg_ingress_ipv4_acl_intent ipv4_acl[CFG_INGRESS_IPV4_ACL_MAX_ENTRIES];
} l2_security_capacity_work;

static int l2_validate_l2_security_capacity_work(
        nl_yang_session *ys, const cfg_port_ref *ports, int n_ports,
        char *err, size_t err_size, l2_security_capacity_work *work) {
    cfg_l2_security_rule_intent *rules = work->rules;
    cfg_dhcp_binding_intent *bindings = work->bindings;
    cfg_user_filter_intent *filters = work->filters;
    cfg_ingress_ipv4_acl_intent *ipv4_acl = work->ipv4_acl;
    int n_rules = 0;
    int n_bindings;
    int n_filters;
    int n_ipv4_acl;
    int required;
    int capacity = CFG_L2_SECURITY_FLOW_CAPACITY;

    if (!ys || !ports || n_ports <= 0)
        return 0;

    n_rules += l2_collect_l2_security_rule_intents(
        ys, "dhcp-snooping", rules + n_rules,
        CFG_L2_SECURITY_MAX_RULES - n_rules, ports, n_ports);
    n_rules += l2_collect_l2_security_rule_intents(
        ys, "arp-inspection", rules + n_rules,
        CFG_L2_SECURITY_MAX_RULES - n_rules, ports, n_ports);

    n_bindings = l2_collect_dhcp_binding_intents(
        ys, bindings, CFG_DHCP_BINDING_MAX_ENTRIES, ports, n_ports);
    n_filters = l2_collect_user_filter_intents(
        ys, filters, CFG_USER_FILTER_MAX_ENTRIES, ports, n_ports);
    n_ipv4_acl = l2_collect_ingress_ipv4_acl_intents(
        ys, ipv4_acl, CFG_INGRESS_IPV4_ACL_MAX_ENTRIES, ports, n_ports);

    required = n_rules + n_filters;
    for (int i = 0; i < n_ipv4_acl; i++) {
        int hw_entries = l2_ingress_ipv4_acl_hw_entry_count(&ipv4_acl[i]);
        if (hw_entries <= 0)
            hw_entries = 1;
        required += hw_entries;
    }
    for (int i = 0; i < n_bindings; i++) {
        if (bindings[i].port.hw_port <= 0)
            continue;
        if (security_vlan_enabled(ys, "arp-inspection", bindings[i].vlan))
            required++;
    }

    if (required > capacity) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "l2-security flow rules require %d entries, hardware capacity is %d",
                     required, capacity);
        return -1;
    }
    return 0;
}

int l2_validate_l2_security_capacity(nl_yang_session *ys,
                                     const cfg_port_ref *ports, int n_ports,
                                     char *err, size_t err_size) {
    l2_security_capacity_work *work;
    int rc;

    work = calloc(1, sizeof(*work));
    if (!work)
        return l2_plan_set_error(
            err, err_size,
            "l2-security validation workspace allocation failed",
            NULL, NULL);
    rc = l2_validate_l2_security_capacity_work(
        ys, ports, n_ports, err, err_size, work);
    free(work);
    return rc;
}

int l2_validate_storm_control_intents(nl_yang_session *ys,
                                      const cfg_port_ref *ports,
                                      int n_ports,
                                      char *err, size_t err_size) {
    cfg_storm_control_intent entries[CFG_STORM_CONTROL_MAX_ENTRIES];
    int n_entries = l2_collect_storm_control_intents(ys, entries,
                                                     CFG_STORM_CONTROL_MAX_ENTRIES);

    if (n_entries < 0)
        return l2_plan_set_error(err, err_size, "cannot read all storm-control policies", NULL, NULL);

    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "storm-control interface %s not found",
                             entries[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "storm-control interface %s must be a physical user port",
                             entries[i].ifname, NULL);
        if (entries[i].rate_kbps < CFG_STORM_CONTROL_MIN_RATE_KBPS ||
            entries[i].rate_kbps > CFG_STORM_CONTROL_MAX_RATE_KBPS)
            return l2_plan_set_error(err, err_size,
                             "storm-control interface %s bandwidth must be 22000..100000000 Kbps",
                             entries[i].ifname, NULL);
        if (entries[i].burst_bytes <= 0 ||
            entries[i].burst_bytes > CFG_STORM_CONTROL_MAX_BURST_BYTES)
            return l2_plan_set_error(err, err_size,
                             "storm-control interface %s burst-size must be 1..104857600 bytes",
                             entries[i].ifname, NULL);
        for (int j = i + 1; j < n_entries; j++) {
            if (strcmp(entries[i].ifname, entries[j].ifname) == 0 &&
                (entries[i].kind == entries[j].kind ||
                 entries[i].kind == NL_STORM_COMBINED || entries[j].kind == NL_STORM_COMBINED))
                return l2_plan_set_error(err, err_size,
                                 "duplicate or overlapping storm-control policy on interface %s",
                                 entries[i].ifname, NULL);
        }
    }
    return 0;
}

int l2_validate_ingress_rate_limit_intents(nl_yang_session *ys,
                                           const cfg_port_ref *ports,
                                           int n_ports,
                                           char *err, size_t err_size) {
    cfg_ingress_rate_limit_intent entries[CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES];
    int n_entries = l2_collect_ingress_rate_limit_intents(
        ys, entries, CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES);

    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "ingress-rate-limit interface %s not found",
                             entries[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "ingress-rate-limit interface %s must be a physical user port",
                             entries[i].ifname, NULL);
        if (entries[i].rate_kbps < CFG_INGRESS_RATE_LIMIT_MIN_RATE_KBPS ||
            entries[i].rate_kbps > CFG_INGRESS_RATE_LIMIT_MAX_RATE_KBPS)
            return l2_plan_set_error(err, err_size,
                             "ingress-rate-limit interface %s bandwidth must be 22000..100000000 Kbps",
                             entries[i].ifname, NULL);
        if (entries[i].burst_bytes <= 0 ||
            entries[i].burst_bytes > CFG_INGRESS_RATE_LIMIT_MAX_BURST_BYTES)
            return l2_plan_set_error(err, err_size,
                             "ingress-rate-limit interface %s burst-size must be 1..104857600 bytes",
                             entries[i].ifname, NULL);
        for (int j = i + 1; j < n_entries; j++) {
            if (strcmp(entries[i].ifname, entries[j].ifname) == 0)
                return l2_plan_set_error(err, err_size,
                                 "duplicate ingress-rate-limit interface %s",
                                 entries[i].ifname, NULL);
        }
    }
    return 0;
}

int l2_validate_rate_controller_capacity(nl_yang_session *ys,
                                         char *err, size_t err_size) {
    cfg_storm_control_intent storm[CFG_STORM_CONTROL_MAX_ENTRIES];
    cfg_ingress_rate_limit_intent ingress[CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES];
    int n_storm = l2_collect_storm_control_intents(
        ys, storm, CFG_STORM_CONTROL_MAX_ENTRIES);
    int n_ingress = l2_collect_ingress_rate_limit_intents(
        ys, ingress, CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES);
    int required = n_storm + n_ingress;
    int capacity = l2_hw_storm_controller_capacity();

    if (n_storm < 0 || n_ingress < 0)
        return l2_plan_set_error(err, err_size, "cannot count rate controllers", NULL, NULL);
    if (capacity <= 0)
        capacity = CFG_STORM_CONTROLLER_DEFAULT_CAPACITY;
    if (required > capacity) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "storm-control plus ingress-rate-limit use %d controllers, hardware capacity is %d",
                     required, capacity);
        return -1;
    }
    return 0;
}

int l2_validate_egress_rate_limit_intents(nl_yang_session *ys,
                                          const cfg_port_ref *ports,
                                          int n_ports,
                                          char *err, size_t err_size) {
    cfg_egress_rate_limit_intent entries[CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES];
    int n_entries = l2_collect_egress_rate_limit_intents(
        ys, entries, CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES);

    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    entries[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "egress-rate-limit interface %s not found",
                             entries[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "egress-rate-limit interface %s must be a physical user port",
                             entries[i].ifname, NULL);
        if (entries[i].rate_kbps < CFG_EGRESS_RATE_LIMIT_MIN_RATE_KBPS ||
            entries[i].rate_kbps > CFG_EGRESS_RATE_LIMIT_MAX_RATE_KBPS)
            return l2_plan_set_error(err, err_size,
                             "egress-rate-limit interface %s bandwidth must be 22000..100000000 Kbps",
                             entries[i].ifname, NULL);
        if (entries[i].burst_bytes <= 0 ||
            entries[i].burst_bytes > CFG_EGRESS_RATE_LIMIT_MAX_BURST_BYTES)
            return l2_plan_set_error(err, err_size,
                             "egress-rate-limit interface %s burst-size must be 1..8387584 bytes",
                             entries[i].ifname, NULL);
        for (int j = i + 1; j < n_entries; j++) {
            if (strcmp(entries[i].ifname, entries[j].ifname) == 0)
                return l2_plan_set_error(err, err_size,
                                 "duplicate egress-rate-limit interface %s",
                                 entries[i].ifname, NULL);
        }
    }
    return 0;
}

static int validate_qos_scheduler_strict_order(
    const cfg_qos_scheduler_group_intent *groups, int n_groups,
    char *err, size_t err_size) {
    char ifnames[CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES][64];
    int n_ifnames = 0;

    for (int i = 0; i < n_groups; i++) {
        bool seen = false;
        for (int j = 0; j < n_ifnames; j++) {
            if (strcmp(ifnames[j], groups[i].ifname) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen && n_ifnames < CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES) {
            snprintf(ifnames[n_ifnames], sizeof(ifnames[n_ifnames]),
                     "%s", groups[i].ifname);
            n_ifnames++;
        }
    }

    for (int i = 0; i < n_ifnames; i++) {
        int strict[HAL_QOS_MAX_SCHED_GROUPS];
        int on2off = 0;
        int off2on = 0;

        for (int g = 0; g < HAL_QOS_MAX_SCHED_GROUPS; g++)
            strict[g] = 1;
        for (int j = 0; j < n_groups; j++)
            if (strcmp(groups[j].ifname, ifnames[i]) == 0 &&
                groups[j].group >= 0 &&
                groups[j].group < HAL_QOS_MAX_SCHED_GROUPS)
                strict[groups[j].group] = groups[j].strict_priority;

        for (int g = 0; g < HAL_QOS_MAX_SCHED_GROUPS - 1; g++) {
            if (strict[g] > strict[g + 1]) {
                if (off2on != 0)
                    return l2_plan_set_error(
                        err, err_size,
                        "class-of-service scheduler interface %s has non-contiguous DRR groups",
                        ifnames[i], NULL);
                on2off++;
            } else if (strict[g] < strict[g + 1]) {
                off2on++;
            }
        }
        if (on2off > 1 || off2on > 1)
            return l2_plan_set_error(
                err, err_size,
                "class-of-service scheduler interface %s has non-contiguous DRR groups",
                ifnames[i], NULL);
    }
    return 0;
}

static int validate_qos_scheduler_template_refs(nl_yang_session *ys,
                                                char *err,
                                                size_t err_size) {
    char *xml;
    char *cos;
    char *scheduler;
    char *scheduler_end;
    char *interfaces;
    char *interfaces_end;
    char *p;

    if (!ys)
        return 0;

    xml = nl_yang_to_xml(ys);
    if (!xml)
        return 0;

    cos = strstr(xml, "<class-of-service>");
    scheduler = cos ? strstr(cos, "<scheduler>") : NULL;
    scheduler_end = scheduler ? strstr(scheduler, "</scheduler>") : NULL;
    interfaces = scheduler ? strstr(scheduler, "<interfaces>") : NULL;
    interfaces_end = interfaces ? strstr(interfaces, "</interfaces>") : NULL;
    if (!cos || !scheduler || !scheduler_end || !interfaces ||
        !interfaces_end || interfaces_end > scheduler_end) {
        free(xml);
        return 0;
    }

    p = interfaces;
    while ((p = strstr(p, "<interface>")) && p < interfaces_end) {
        char *end = strstr(p, "</interface>");
        char ifname[64] = {0};
        char tmpl[64] = {0};

        if (!end || end > interfaces_end)
            break;
        if (l2_extract_xml_leaf(p, end, "template", tmpl,
                                sizeof(tmpl)) == 0 && tmpl[0]) {
            char path[384];
            snprintf(path, sizeof(path),
                     "/netlab:netlab-config/class-of-service/scheduler"
                     "/template[name='%s']/name",
                     tmpl);
            if (!nl_yang_get(ys, path)) {
                (void)l2_extract_xml_leaf(p, end, "name", ifname,
                                          sizeof(ifname));
                free(xml);
                if (ifname[0])
                    return l2_plan_set_error(
                        err, err_size,
                        "class-of-service scheduler interface %s references undefined template",
                        ifname, NULL);
                return l2_plan_set_error(
                    err, err_size,
                    "class-of-service scheduler references undefined template %s",
                    tmpl, NULL);
            }
        }
        p = end + strlen("</interface>");
    }

    free(xml);
    return 0;
}

typedef struct {
    cfg_qos_interface_intent ifaces[CFG_QOS_INTERFACE_MAX_ENTRIES];
    cfg_qos_pfc_intent pfc[CFG_QOS_PFC_MAX_ENTRIES];
    cfg_qos_priority_map_intent maps[CFG_QOS_PRIORITY_MAP_MAX_ENTRIES];
    cfg_qos_scheduler_tc_map_intent
        scheduler[CFG_QOS_SCHEDULER_TC_MAP_MAX_ENTRIES];
    cfg_qos_scheduler_group_intent
        scheduler_groups[CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES];
    cfg_qos_scheduler_group_shaping_intent
        scheduler_group_shaping[CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES];
    cfg_qos_scheduler_port_intent
        scheduler_ports[CFG_QOS_SCHEDULER_PORT_MAX_ENTRIES];
    cfg_qos_watermark_intent
        watermarks[CFG_QOS_WATERMARK_MAX_ENTRIES];
    cfg_egress_rate_limit_intent
        egress[CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES];
} l2_qos_validation_work;

static int l2_validate_qos_intents_work(
        nl_yang_session *ys, const cfg_port_ref *ports, int n_ports,
        char *err, size_t err_size, l2_qos_validation_work *work) {
    cfg_qos_interface_intent *ifaces = work->ifaces;
    cfg_qos_pfc_intent *pfc = work->pfc;
    cfg_qos_priority_map_intent *maps = work->maps;
    cfg_qos_scheduler_tc_map_intent *scheduler = work->scheduler;
    cfg_qos_scheduler_group_intent *scheduler_groups =
        work->scheduler_groups;
    cfg_qos_scheduler_group_shaping_intent *scheduler_group_shaping =
        work->scheduler_group_shaping;
    cfg_qos_scheduler_port_intent *scheduler_ports = work->scheduler_ports;
    cfg_qos_watermark_intent *watermarks = work->watermarks;
    cfg_egress_rate_limit_intent *egress = work->egress;
    int n_ifaces = l2_collect_qos_interface_intents(
        ys, ifaces, CFG_QOS_INTERFACE_MAX_ENTRIES);
    int n_pfc = l2_collect_qos_pfc_intents(
        ys, pfc, CFG_QOS_PFC_MAX_ENTRIES);
    int n_maps = l2_collect_qos_priority_map_intents(
        ys, maps, CFG_QOS_PRIORITY_MAP_MAX_ENTRIES);
    int n_scheduler = l2_collect_qos_scheduler_tc_map_intents(
        ys, scheduler, CFG_QOS_SCHEDULER_TC_MAP_MAX_ENTRIES);
    int n_scheduler_groups = l2_collect_qos_scheduler_group_intents(
        ys, scheduler_groups, CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES);
    int n_scheduler_group_shaping =
        l2_collect_qos_scheduler_group_shaping_intents(
            ys, scheduler_group_shaping,
            CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES);
    int n_scheduler_ports = l2_collect_qos_scheduler_port_intents(
        ys, scheduler_ports, CFG_QOS_SCHEDULER_PORT_MAX_ENTRIES);
    int n_watermarks = l2_collect_qos_watermark_intents(
        ys, watermarks, CFG_QOS_WATERMARK_MAX_ENTRIES);
    int n_egress = l2_collect_egress_rate_limit_intents(
        ys, egress, CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES);

    if (validate_qos_scheduler_template_refs(ys, err, err_size) != 0)
        return -1;

    for (int i = 0; i < n_ifaces; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    ifaces[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "class-of-service interface %s not found",
                             ifaces[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "class-of-service interface %s must be a physical user port",
                             ifaces[i].ifname, NULL);
        if (ifaces[i].trust_mode < HAL_QOS_TRUST_NONE ||
            ifaces[i].trust_mode > HAL_QOS_TRUST_DSCP)
            return l2_plan_set_error(err, err_size,
                             "class-of-service interface %s trust must be none, ieee-802.1p, or dscp",
                             ifaces[i].ifname, NULL);
        if (ifaces[i].default_priority < 0 ||
            ifaces[i].default_priority > 7)
            return l2_plan_set_error(err, err_size,
                             "class-of-service interface %s default-priority must be 0..7",
                             ifaces[i].ifname, NULL);
        for (int j = i + 1; j < n_ifaces; j++) {
            if (strcmp(ifaces[i].ifname, ifaces[j].ifname) == 0)
                return l2_plan_set_error(err, err_size,
                                 "duplicate class-of-service interface %s",
                                 ifaces[i].ifname, NULL);
        }
    }

    for (int i = 0; i < n_pfc; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    pfc[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "class-of-service priority-flow-control interface %s not found",
                             pfc[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "class-of-service priority-flow-control interface %s must be a physical user port",
                             pfc[i].ifname, NULL);
        if (pfc[i].rx_class_mask < 0 || pfc[i].rx_class_mask > 255)
            return l2_plan_set_error(err, err_size,
                             "class-of-service priority-flow-control interface %s rx-class-mask must be 0..255",
                             pfc[i].ifname, NULL);
        if (pfc[i].tx_class_mask < 0 || pfc[i].tx_class_mask > 255)
            return l2_plan_set_error(err, err_size,
                             "class-of-service priority-flow-control interface %s tx-class-mask must be 0..255",
                             pfc[i].ifname, NULL);
        if (pfc[i].lossless_smp_mask < 0 || pfc[i].lossless_smp_mask > 3)
            return l2_plan_set_error(err, err_size,
                             "class-of-service priority-flow-control interface %s lossless-smp-mask must be 0..3",
                             pfc[i].ifname, NULL);
        if (pfc[i].shared_pause_mask < 0 || pfc[i].shared_pause_mask > 3)
            return l2_plan_set_error(err, err_size,
                             "class-of-service priority-flow-control interface %s shared-pause-mask must be 0..3",
                             pfc[i].ifname, NULL);
        if (!fm10k_pfc_wd_policy_valid(&pfc[i].watchdog) ||
            (pfc[i].watchdog.detect_ms && (pfc[i].rx_class_mask != 8 ||
             pfc[i].tx_class_mask != 8 || pfc[i].lossless_smp_mask != 2 || pfc[i].shared_pause_mask != 2)))
            return l2_plan_set_error(err, err_size,
                             "PFC watchdog interface %s requires TC3 PFC and valid detection/recovery/cooldown intervals",
                             pfc[i].ifname, NULL);
        for (int j = i + 1; j < n_pfc; j++) {
            if (strcmp(pfc[i].ifname, pfc[j].ifname) == 0)
                return l2_plan_set_error(err, err_size,
                                 "duplicate class-of-service priority-flow-control interface %s",
                                 pfc[i].ifname, NULL);
        }
    }

    for (int i = 0; i < n_maps; i++) {
        if (maps[i].switch_priority < 0 ||
            maps[i].switch_priority > 15) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "class-of-service switch-priority must be 0..15");
            return -1;
        }
        if (maps[i].traffic_class < 0 || maps[i].traffic_class > 7) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "class-of-service traffic-class must be 0..7");
            return -1;
        }
        for (int j = i + 1; j < n_maps; j++) {
            if (maps[i].switch_priority == maps[j].switch_priority) {
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "duplicate class-of-service switch-priority %d",
                             maps[i].switch_priority);
                return -1;
            }
        }
    }

    for (int i = 0; i < n_scheduler; i++) {
        const cfg_port_ref *port = l2_find_port_ref(ports, n_ports,
                                                    scheduler[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s not found",
                             scheduler[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s must be a physical user port",
                             scheduler[i].ifname, NULL);
        if (scheduler[i].traffic_class < 0 ||
            scheduler[i].traffic_class > 7)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s traffic-class must be 0..7",
                             scheduler[i].ifname, NULL);
        if (scheduler[i].shaping_group < 0 ||
            scheduler[i].shaping_group > 7)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s shaping-group must be 0..7",
                             scheduler[i].ifname, NULL);
        for (int j = i + 1; j < n_scheduler; j++) {
            if (strcmp(scheduler[i].ifname, scheduler[j].ifname) == 0 &&
                scheduler[i].traffic_class == scheduler[j].traffic_class)
                return l2_plan_set_error(err, err_size,
                                 "duplicate class-of-service scheduler interface %s traffic-class",
                                 scheduler[i].ifname, NULL);
        }
        for (int j = 0; j < n_egress; j++) {
            if (strcmp(scheduler[i].ifname, egress[j].ifname) == 0)
                return l2_plan_set_error(err, err_size,
                                 "class-of-service scheduler interface %s conflicts with egress-rate-limit",
                                 scheduler[i].ifname, NULL);
        }
    }

    for (int i = 0; i < n_scheduler_groups; i++) {
        const cfg_port_ref *port = l2_find_port_ref(
            ports, n_ports, scheduler_groups[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s not found",
                             scheduler_groups[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s must be a physical user port",
                             scheduler_groups[i].ifname, NULL);
        if (scheduler_groups[i].group < 0 ||
            scheduler_groups[i].group > 7)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s group must be 0..7",
                             scheduler_groups[i].ifname, NULL);
        if (scheduler_groups[i].strict_priority != 0 &&
            scheduler_groups[i].strict_priority != 1)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s strict-priority must be true or false",
                             scheduler_groups[i].ifname, NULL);
        if (scheduler_groups[i].weight < 0 ||
            scheduler_groups[i].weight > CFG_QOS_SCHEDULER_GROUP_MAX_WEIGHT)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s weight must be 0..16777215",
                             scheduler_groups[i].ifname, NULL);
        for (int j = i + 1; j < n_scheduler_groups; j++) {
            if (strcmp(scheduler_groups[i].ifname,
                       scheduler_groups[j].ifname) == 0 &&
                scheduler_groups[i].group == scheduler_groups[j].group)
                return l2_plan_set_error(err, err_size,
                                 "duplicate class-of-service scheduler interface %s group",
                                 scheduler_groups[i].ifname, NULL);
        }
    }
    if (validate_qos_scheduler_strict_order(
            scheduler_groups, n_scheduler_groups, err, err_size) != 0)
        return -1;

    for (int i = 0; i < n_scheduler_group_shaping; i++) {
        const cfg_port_ref *port = l2_find_port_ref(
            ports, n_ports, scheduler_group_shaping[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s not found",
                             scheduler_group_shaping[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s must be a physical user port",
                             scheduler_group_shaping[i].ifname, NULL);
        if (scheduler_group_shaping[i].group < 0 ||
            scheduler_group_shaping[i].group > 7)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s group must be 0..7",
                             scheduler_group_shaping[i].ifname, NULL);
        if (scheduler_group_shaping[i].rate_bps < 1 ||
            scheduler_group_shaping[i].rate_bps >
                CFG_QOS_SCHEDULER_GROUP_MAX_RATE_BPS)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s group rate-bps must be 1..100000000000",
                             scheduler_group_shaping[i].ifname, NULL);
        if (scheduler_group_shaping[i].burst_bits < 1 ||
            scheduler_group_shaping[i].burst_bits >
                CFG_QOS_SCHEDULER_GROUP_MAX_BURST_BITS)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s group burst-bits must be 1..67100672",
                             scheduler_group_shaping[i].ifname, NULL);
        for (int j = i + 1; j < n_scheduler_group_shaping; j++) {
            if (strcmp(scheduler_group_shaping[i].ifname,
                       scheduler_group_shaping[j].ifname) == 0 &&
                scheduler_group_shaping[i].group ==
                    scheduler_group_shaping[j].group)
                return l2_plan_set_error(err, err_size,
                                 "duplicate class-of-service scheduler interface %s group shaping",
                                 scheduler_group_shaping[i].ifname, NULL);
        }
        for (int j = 0; j < n_egress; j++) {
            if (strcmp(scheduler_group_shaping[i].ifname,
                       egress[j].ifname) == 0)
                return l2_plan_set_error(err, err_size,
                                 "class-of-service scheduler interface %s group shaping conflicts with egress-rate-limit",
                                 scheduler_group_shaping[i].ifname, NULL);
        }
    }

    for (int i = 0; i < n_scheduler_ports; i++) {
        const cfg_port_ref *port = l2_find_port_ref(
            ports, n_ports, scheduler_ports[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s not found",
                             scheduler_ports[i].ifname, NULL);
        if (port->is_aggregate)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s must be a physical user port",
                             scheduler_ports[i].ifname, NULL);
        if (scheduler_ports[i].traffic_class_enable_mask < 1 ||
            scheduler_ports[i].traffic_class_enable_mask > 255)
            return l2_plan_set_error(err, err_size,
                             "class-of-service scheduler interface %s traffic-class-enable-mask must be 1..255",
                             scheduler_ports[i].ifname, NULL);
        for (int j = i + 1; j < n_scheduler_ports; j++) {
            if (strcmp(scheduler_ports[i].ifname,
                       scheduler_ports[j].ifname) == 0)
                return l2_plan_set_error(err, err_size,
                                 "duplicate class-of-service scheduler interface %s traffic-class-enable-mask",
                                 scheduler_ports[i].ifname, NULL);
        }
    }
    for (int i = 0; i < n_watermarks; i++) {
        bool switch_attr =
            watermarks[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
            watermarks[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
            watermarks[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
        if (!switch_attr) {
            const cfg_port_ref *port = l2_find_port_ref(
                ports, n_ports, watermarks[i].ifname);
            if (!port)
                return l2_plan_set_error(err, err_size,
                                 "class-of-service watermarks interface %s not found",
                                 watermarks[i].ifname, NULL);
            if (port->is_aggregate)
                return l2_plan_set_error(err, err_size,
                                 "class-of-service watermarks interface %s must be a physical user port",
                                 watermarks[i].ifname, NULL);
        }
        if (watermarks[i].traffic_class < 0 ||
            watermarks[i].traffic_class > 7)
            return l2_plan_set_error(err, err_size,
                             switch_attr ?
                             "class-of-service watermarks switch-priority must be 0..7" :
                             "class-of-service watermarks interface %s traffic-class must be 0..7",
                             watermarks[i].ifname, NULL);
        if (!switch_attr &&
            watermarks[i].attr != HAL_QOS_WATERMARK_ATTR_TX_HOG &&
            watermarks[i].attr != HAL_QOS_WATERMARK_ATTR_TX_PRIVATE)
            return l2_plan_set_error(err, err_size,
                             "class-of-service watermarks interface %s supports only tx-hog and tx-private",
                             watermarks[i].ifname, NULL);
        if (switch_attr &&
            watermarks[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER &&
            (watermarks[i].value < 0 || watermarks[i].value > 7))
            return l2_plan_set_error(err, err_size,
                             "class-of-service watermarks switch-priority soft-drop-jitter value must be 0..7",
                             NULL, NULL);
        if (watermarks[i].value < 0 ||
            watermarks[i].value > CFG_QOS_WATERMARK_MAX_VALUE)
            return l2_plan_set_error(err, err_size,
                             switch_attr ?
                             "class-of-service watermarks switch-priority value must be 0..6291264" :
                             "class-of-service watermarks interface %s value must be 0..6291264",
                             watermarks[i].ifname, NULL);
        for (int j = i + 1; j < n_watermarks; j++) {
            if (strcmp(watermarks[i].ifname, watermarks[j].ifname) == 0 &&
                watermarks[i].traffic_class == watermarks[j].traffic_class &&
                watermarks[i].attr == watermarks[j].attr)
                return l2_plan_set_error(err, err_size,
                                 switch_attr ?
                                 "duplicate class-of-service watermarks switch-priority" :
                                 "duplicate class-of-service watermarks interface %s traffic-class",
                                 watermarks[i].ifname, NULL);
        }
    }
    return 0;
}

int l2_validate_qos_intents(nl_yang_session *ys,
                            const cfg_port_ref *ports, int n_ports,
                            char *err, size_t err_size) {
    l2_qos_validation_work *work;
    int rc;

    work = calloc(1, sizeof(*work));
    if (!work)
        return l2_plan_set_error(
            err, err_size,
            "class-of-service validation workspace allocation failed",
            NULL, NULL);
    rc = l2_validate_qos_intents_work(
        ys, ports, n_ports, err, err_size, work);
    free(work);
    return rc;
}

int l2_validate_lag_intents(nl_yang_session *ys,
                                const cfg_port_ref *ports, int n_ports,
                                char *err, size_t err_size) {
    const char *system_id = nl_yang_get(ys,
        "/netlab:netlab-config/protocols/lacp/system-id");
    int aggregate_speed[CFG_AE_LIMIT] = {0};
    char aggregate_first_member[CFG_AE_LIMIT][64] = {{0}};

    if (system_id && system_id[0] && !lacp_system_id_valid(system_id))
        return l2_plan_set_error(err, err_size,
                         "protocols lacp system-id must be a non-zero unicast MAC address",
                         NULL, NULL);

    for (int i = 0; i < n_ports; i++) {
        const char *member = l2_get_lag_member(ys, ports[i].name);
        const char *member_prio =
            l2_get_lacp_member_port_priority(ys, ports[i].name);
        cfg_if_intent intent;
        const char *lacp;
        int ae;
        int speed_mbps;

        if (member_prio && member_prio[0] && (!member || !member[0]))
            return l2_plan_set_error(err, err_size,
                             "interface %s ether-options lacp port-priority requires 802.3ad aggregate membership",
                             ports[i].name, NULL);
        if (!member || !member[0])
            continue;
        l2_read_interface_intent(ys, ports[i].name, &intent);
        if (intent.has_l2)
            return l2_plan_set_error(err, err_size,
                             "interface %s cannot be both an aggregate member and an ethernet-switching interface",
                             ports[i].name, NULL);
        if ((ports[i].flags & NL_PORT_FLAG_LACP_CAPABLE) == 0)
            return l2_plan_set_error(err, err_size,
                             "interface %s is not LACP-capable in the active chassis mode",
                             ports[i].name, NULL);
        if (!l2_supported_ae_name(member))
            return l2_plan_set_error(err, err_size,
                             "interface %s references unsupported aggregate %s",
                             ports[i].name, member);
        lacp = l2_get_lacp_mode(ys, member);
        if (!l2_aggregate_configured(ys, member) || !lacp || !lacp[0])
            return l2_plan_set_error(err, err_size,
                             "interface %s references %s but LACP is not configured",
                             ports[i].name, member);

        if (nl_yang_exists(ys, L2_FM10K_ROOT) &&
            l2_get_ingress_filtering(ys, ports[i].name) != l2_get_ingress_filtering(ys, member))
            return l2_plan_set_error(err, err_size,
                             "interface %s ingress-filtering must match aggregate %s",
                             ports[i].name, member);

        ae = l2_ae_id(member);
        speed_mbps = port_effective_speed_mbps(&ports[i], &intent);
        if (speed_mbps <= 0) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "interface %s has no valid effective speed for aggregate %s",
                         ports[i].name, member);
            return -1;
        }
        if (aggregate_speed[ae] != 0 && aggregate_speed[ae] != speed_mbps) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "aggregate %s members %s (%dg) and %s (%dg) must use the same speed",
                         member, aggregate_first_member[ae],
                         aggregate_speed[ae] / 1000, ports[i].name,
                         speed_mbps / 1000);
            return -1;
        }
        if (aggregate_speed[ae] == 0) {
            aggregate_speed[ae] = speed_mbps;
            snprintf(aggregate_first_member[ae],
                     sizeof(aggregate_first_member[ae]), "%s",
                     ports[i].name);
        }
    }

    for (int ae = 0; ae < l2_cfg_max_ae(); ae++) {
        char ifname[16];
        const char *lacp;
        const char *periodic;
        const char *actor_key;
        const char *hash_rotation;
        bool min_links_configured = false;
        bool min_links_valid = true;
        cfg_if_intent intent;

        snprintf(ifname, sizeof(ifname), "ae%d", ae);
        lacp = l2_get_lacp_mode(ys, ifname);
        periodic = l2_get_lacp_periodic(ys, ifname);
        actor_key = l2_get_lacp_actor_key(ys, ifname);
        hash_rotation = l2_get_lag_hash_rotation(ys, ifname);
        l2_read_interface_intent(ys, ifname, &intent);
        if (intent.has_l2 && (!lacp || !lacp[0]))
            return l2_plan_set_error(err, err_size,
                             "interfaces %s ethernet-switching requires aggregated-ether-options lacp",
                             ifname, NULL);
        if (lacp && lacp[0]) {
            if (strcmp(lacp, "active") != 0 &&
                strcmp(lacp, "passive") != 0 && strcmp(lacp, "static") != 0)
                return l2_plan_set_error(err, err_size, "unsupported lacp mode %s",
                                 lacp, NULL);
        }
        if (periodic && periodic[0] &&
            strcmp(periodic, "fast") != 0 &&
            strcmp(periodic, "slow") != 0)
            return l2_plan_set_error(err, err_size, "unsupported lacp periodic %s",
                             periodic, NULL);
        if (periodic && periodic[0] && (!lacp || !lacp[0])) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "interfaces %s aggregated-ether-options lacp periodic requires lacp active or passive",
                         ifname);
            return -1;
        }
        if (actor_key && actor_key[0]) {
            long value = 0;
            if (!l2_parse_long_range(actor_key, 1, 65535, &value)) {
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "interfaces %s aggregated-ether-options lacp actor-key must be 1..65535",
                             ifname);
                return -1;
            }
            if (!lacp || !lacp[0]) {
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "interfaces %s aggregated-ether-options lacp actor-key requires lacp active or passive",
                             ifname);
                return -1;
            }
        }
        if (hash_rotation && hash_rotation[0]) {
            if (strcmp(hash_rotation, "a") != 0 &&
                strcmp(hash_rotation, "b") != 0)
                return l2_plan_set_error(err, err_size,
                                 "unsupported LAG hash rotation %s",
                                 hash_rotation, NULL);
            if (!lacp || !lacp[0]) {
                if (err && err_size > 0)
                    snprintf(err, err_size,
                             "interfaces %s aggregated-ether-options hash-policy requires lacp active or passive",
                             ifname);
                return -1;
            }
        }

        (void)l2_get_lacp_min_links(ys, ifname, &min_links_configured,
                                 &min_links_valid);
        if (!min_links_valid) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "interfaces %s aggregated-ether-options minimum-links must be 1..16",
                         ifname);
            return -1;
        }
        if (min_links_configured && (!lacp || !lacp[0])) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "interfaces %s aggregated-ether-options minimum-links requires lacp active or passive",
                         ifname);
            return -1;
        }
    }

    return 0;
}

int l2_validate_static_mac_intents(nl_yang_session *ys,
                                       const cfg_port_ref *ports, int n_ports,
                                       char *err, size_t err_size) {
    cfg_static_mac_intent entries[CFG_STATIC_MAC_MAX_ENTRIES];
    int configured = nl_yang_count(
        ys,
        "/netlab:netlab-config/ethernet-switching-options/static/"
        "mac-table-entry");
    int n_entries = l2_collect_static_mac_intents(ys, entries,
                                               CFG_STATIC_MAC_MAX_ENTRIES);

    if (configured < 0)
        return l2_plan_set_error(err, err_size,
                                 "cannot count static MAC entries",
                                 NULL, NULL);
    if (configured > CFG_STATIC_MAC_MAX_ENTRIES) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "static MAC table uses %d entries; maximum is %d",
                     configured, CFG_STATIC_MAC_MAX_ENTRIES);
        return -1;
    }

    for (int i = 0; i < n_entries; i++) {
        const cfg_port_ref *port;
        cfg_if_intent intent;

        if (!l2_static_mac_is_unicast_nonzero(entries[i].mac))
            return l2_plan_set_error(err, err_size,
                             "static MAC %s must be a unicast non-zero address",
                             entries[i].mac, NULL);

        if (entries[i].vid <= 0 || entries[i].vid > 4094)
            return l2_plan_set_error(err, err_size,
                             "static MAC %s references undefined VLAN %s",
                             entries[i].mac, entries[i].vlan);

        for (int j = i + 1; j < n_entries; j++) {
            if (strcmp(entries[i].mac, entries[j].mac) == 0 &&
                entries[i].vid == entries[j].vid)
                return l2_plan_set_error(err, err_size,
                                 "static MAC %s is configured more than once in VLAN %s",
                                 entries[i].mac, entries[i].vlan);
        }

        port = l2_find_port_ref(ports, n_ports, entries[i].ifname);
        if (!port)
            return l2_plan_set_error(err, err_size,
                             "static MAC %s references unknown interface %s",
                             entries[i].mac, entries[i].ifname);
        if (port->is_aggregate && !l2_aggregate_configured(ys, port->name))
            return l2_plan_set_error(err, err_size,
                             "static MAC %s references unconfigured aggregate %s",
                             entries[i].mac, entries[i].ifname);
        if (!port->is_aggregate) {
            const char *lag = l2_get_lag_member(ys, port->name);
            if (lag && lag[0])
                return l2_plan_set_error(err, err_size,
                                 "static MAC %s must use aggregate %s instead of member interface",
                                 entries[i].mac, lag);
        }

        l2_read_interface_intent(ys, port->name, &intent);
        if (!l2_intent_has_vid(&intent, entries[i].vid)) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "static MAC %s interface %s is not a member of VLAN %d",
                         entries[i].mac, entries[i].ifname, entries[i].vid);
            return -1;
        }
    }

    return 0;
}

int l2_validate_igmp_snooping_intents(nl_yang_session *ys,
                                      const cfg_port_ref *ports,
                                      int n_ports,
                                      char *err, size_t err_size) {
    int configured_vlans = nl_yang_count(
        ys,
        "/netlab:netlab-config/protocols/igmp-snooping/vlan");
    int configured_scopes = nl_yang_count(
        ys,
        "/netlab:netlab-config/protocols/igmp-snooping/vlan/interface");
    cfg_igmp_listener_intent
        entries[CFG_IGMP_STATIC_MAX_MEMBERS + 1];
    int n_entries = l2_collect_igmp_listener_intents(
        ys, entries, CFG_IGMP_STATIC_MAX_MEMBERS + 1, ports, n_ports);

    if (configured_vlans < 0 || configured_scopes < 0)
        return l2_plan_set_error(err, err_size,
                                 "cannot count igmp-snooping scopes",
                                 NULL, NULL);
    if (configured_vlans > 256 || configured_scopes > 1024) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "igmp-snooping uses %d VLANs and %d interface scopes; maximum is 256 VLANs and 1024 scopes",
                     configured_vlans, configured_scopes);
        return -1;
    }
    if (n_entries < 0)
        return l2_plan_set_error(err, err_size, "cannot collect igmp-snooping memberships", NULL, NULL);
    if (n_entries > CFG_IGMP_STATIC_MAX_MEMBERS) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "igmp-snooping uses more than %d static memberships including router ports",
                     CFG_IGMP_STATIC_MAX_MEMBERS);
        return -1;
    }
    cfg_igmp_scope_intent *scopes = calloc(CFG_IGMP_MAX_SCOPES, sizeof(*scopes));
    if (!scopes)
        return l2_plan_set_error(err, err_size, "cannot allocate igmp-snooping scopes", NULL, NULL);
    int ns = l2_collect_igmp_scope_intents(ys, scopes, CFG_IGMP_MAX_SCOPES, ports, n_ports);
    if (ns < 0 || ns > CFG_IGMP_MAX_SCOPES) {
        free(scopes);
        return l2_plan_set_error(err, err_size, "cannot collect igmp-snooping scopes", NULL, NULL);
    }
    for (int i = 0; i < ns; ++i) {
        cfg_if_intent iface;
        const cfg_igmp_scope_intent *scope = &scopes[i];
        l2_read_interface_intent(ys, scope->ifname, &iface);
        if (scope->vid < 1 || scope->vid > 4094 || scope->port.is_aggregate ||
            !nl_ifid_is_user_port(scope->port.hw_port) ||
            !l2_intent_has_vid(&iface, scope->vid) ||
            (scope->fast_leave && !scope->direct_receiver)) {
            if (err && err_size)
                snprintf(err, err_size, "igmp-snooping VLAN %s interface %s requires a physical VLAN member; fast-leave requires a direct receiver",
                         scope->vlan, scope->ifname);
            free(scopes);
            return -1;
        }
    }
    free(scopes);
    for (int i = 0; i < n_entries; i++) {
        cfg_if_intent iface;

        if (!l2_parse_igmp_group(entries[i].group,
                                 &entries[i].group_ip, entries[i].mac))
            return l2_plan_set_error(
                err, err_size,
                "igmp-snooping group %s must be 224.0.1.0..239.255.255.255",
                entries[i].group, NULL);
        if (entries[i].vid <= 0 || entries[i].vid > 4094)
            return l2_plan_set_error(
                err, err_size,
                "igmp-snooping group %s references undefined VLAN %s",
                entries[i].group, entries[i].vlan);
        if (entries[i].port.hw_port <= 0)
            return l2_plan_set_error(
                err, err_size,
                "igmp-snooping group %s references unknown interface %s",
                entries[i].group, entries[i].ifname);
        if (entries[i].port.is_aggregate ||
            !nl_ifid_is_user_port(entries[i].port.hw_port))
            return l2_plan_set_error(
                err, err_size,
                "igmp-snooping group %s interface must be a physical user port",
                entries[i].group, NULL);
        l2_read_interface_intent(ys, entries[i].ifname, &iface);
        if (!l2_intent_has_vid(&iface, entries[i].vid)) {
            if (err && err_size > 0)
                snprintf(err, err_size,
                         "igmp-snooping interface %s is not a member of VLAN %d",
                         entries[i].ifname, entries[i].vid);
            return -1;
        }
        for (int j = i + 1; j < n_entries; j++) {
            if (entries[i].vid == entries[j].vid &&
                memcmp(entries[i].mac, entries[j].mac, 6) == 0 &&
                entries[i].group_ip != entries[j].group_ip)
                return l2_plan_set_error(
                    err, err_size,
                    "igmp-snooping group %s aliases another IPv4 group MAC in VLAN %s",
                    entries[j].group, entries[j].vlan);
        }
    }
    return 0;
}

int l2_validate_port_mirror_intent(nl_yang_session *ys,
                                   const cfg_port_ref *ports, int n_ports,
                                   char *err, size_t err_size) {
    cfg_port_mirror_intent intent;

    if (l2_collect_port_mirror_intent(ys, &intent, ports, n_ports) == 0)
        return 0;
    if (!intent.name[0])
        return l2_plan_set_error(err, err_size,
                                 "port-mirroring instance %s has no name",
                                 "", NULL);
    if (!intent.destination_ifname[0] ||
        intent.destination.hw_port <= 0)
        return l2_plan_set_error(
            err, err_size,
            "port-mirroring instance %s references unknown output interface %s",
            intent.name, intent.destination_ifname);
    if (intent.destination.is_aggregate ||
        !nl_ifid_is_user_port(intent.destination.hw_port))
        return l2_plan_set_error(
            err, err_size,
            "port-mirroring instance %s output must be a physical user interface, not %s",
            intent.name, intent.destination_ifname);
    if (intent.n_sources <= 0)
        return l2_plan_set_error(
            err, err_size,
            "port-mirroring instance %s requires at least one input interface",
            intent.name, NULL);
    for (int i = 0; i < intent.n_sources; i++) {
        const cfg_port_mirror_source *source = &intent.sources[i];

        if (!source->ifname[0] || source->port.hw_port <= 0)
            return l2_plan_set_error(
                err, err_size,
                "port-mirroring instance %s references unknown input interface %s",
                intent.name, source->ifname);
        if (source->port.is_aggregate ||
            !nl_ifid_is_user_port(source->port.hw_port))
            return l2_plan_set_error(
                err, err_size,
                "port-mirroring instance %s input must be a physical user interface, not %s",
                intent.name, source->ifname);
        if (source->port.hw_port == intent.destination.hw_port)
            return l2_plan_set_error(
                err, err_size,
                "port-mirroring instance %s cannot use output interface as input %s",
                intent.name, source->ifname);
        if (source->direction < HAL_MIRROR_DIRECTION_INGRESS ||
            source->direction > HAL_MIRROR_DIRECTION_BOTH)
            return l2_plan_set_error(
                err, err_size,
                "port-mirroring instance %s has invalid direction on %s",
                intent.name, source->ifname);
        for (int j = i + 1; j < intent.n_sources; j++) {
            if (source->port.hw_port == intent.sources[j].port.hw_port)
                return l2_plan_set_error(
                    err, err_size,
                    "port-mirroring instance %s repeats input interface %s",
                    intent.name, source->ifname);
        }
    }
    return 0;
}
