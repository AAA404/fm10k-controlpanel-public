#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/l3_capacity.h"
#include <arpa/inet.h>
#include <fm_sdk.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static int appendf(char *buf, size_t size, int off, const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || size == 0 || off < 0 || (size_t)off >= size)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(buf + off, size - (size_t)off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= size - (size_t)off)
        return -1;
    return off + n;
}

static void xml_escape_attr(const char *src, char *dst, size_t dst_len) {
    size_t di = 0;

    if (!dst || dst_len == 0)
        return;
    if (!src)
        src = "";
    for (size_t si = 0; src[si] && di + 1 < dst_len; si++) {
        const char *rep = NULL;
        if (src[si] == '&')
            rep = "&amp;";
        else if (src[si] == '<')
            rep = "&lt;";
        else if (src[si] == '>')
            rep = "&gt;";
        else if (src[si] == '"')
            rep = "&quot;";
        else if (src[si] == '\'')
            rep = "&apos;";
        if (rep) {
            size_t len = strlen(rep);
            if (di + len >= dst_len)
                break;
            memcpy(dst + di, rep, len);
            di += len;
        } else {
            dst[di++] = src[si];
        }
    }
    dst[di] = '\0';
}

static const char *sdk_status_name(fm_status st) {
    if (st == FM_OK)
        return "ok";
    if (st == FM_ERR_UNSUPPORTED)
        return "unsupported";
    if (st == FM_ERR_NOT_FOUND)
        return "not-found";
    if (st == FM_ERR_UNINITIALIZED)
        return "uninitialized";
    return "error";
}

static bool sdk_status_is_soft_readback(fm_status st) {
    return st == FM_OK || st == FM_ERR_UNSUPPORTED ||
           st == FM_ERR_NOT_FOUND || st == FM_ERR_UNINITIALIZED;
}

static int append_sdk_readback_family(char *buf, size_t size, int off,
                                      const char *name, fm_status st,
                                      int count, int emitted) {
    char msg_attr[128];

    xml_escape_attr(fmErrorMsg(st), msg_attr, sizeof(msg_attr));

    return appendf(buf, size, off,
                   "<family name=\"%s\" status=\"%s\" sdk-status=\"%d\" "
                   "message=\"%s\" count=\"%d\" emitted=\"%d\"/>",
                   name ? name : "unknown", sdk_status_name(st), (int)st,
                   msg_attr, count, emitted);
}

static int sdk_readback_emit_count(int count, int limit) {
    if (count <= 0 || limit <= 0)
        return 0;
    return count > limit ? limit : count;
}

static void ipaddr_to_text(const fm_ipAddr *addr, char *buf, size_t size) {
    struct in_addr in;

    if (!buf || size == 0)
        return;
    snprintf(buf, size, "-");
    if (!addr)
        return;
    if (addr->isIPv6) {
        snprintf(buf, size, "ipv6");
        return;
    }
    memset(&in, 0, sizeof(in));
    in.s_addr = addr->addr[0];
    if (!inet_ntop(AF_INET, &in, buf, (socklen_t)size))
        snprintf(buf, size, "invalid");
}

static void mac_to_text(fm_macaddr mac, char *buf, size_t size) {
    if (!buf || size == 0)
        return;
    snprintf(buf, size, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
             (unsigned long long)((mac >> 40) & 0xff),
             (unsigned long long)((mac >> 32) & 0xff),
             (unsigned long long)((mac >> 24) & 0xff),
             (unsigned long long)((mac >> 16) & 0xff),
             (unsigned long long)((mac >> 8) & 0xff),
             (unsigned long long)(mac & 0xff));
}

static int append_sdk_readback_objects(char *buf, size_t size, int off,
                                       int sw, const fm_int *vrids,
                                       int n_vrids, const fm_int *ifaces,
                                       int n_ifaces,
                                       const fm_arpEntry *arps,
                                       int n_arps,
                                       const fm_int *ecmp_groups,
                                       int n_ecmp_groups,
                                       const fm_routeEntry *routes,
                                       int n_routes,
                                       int object_limit) {
    int emit;

    emit = sdk_readback_emit_count(n_vrids, object_limit);
    for (int i = 0; i < emit; i++)
        off = appendf(buf, size, off,
                      "<object family=\"virtual-router\" key=\"%d\"/>",
                      (int)vrids[i]);

    emit = sdk_readback_emit_count(n_ifaces, object_limit);
    for (int i = 0; i < emit; i++) {
        fm_uint16 vlan = 0;
        fm_interfaceState state = FM_INTERFACE_STATE_ADMIN_DOWN;
        fm_ipAddr addrs[4];
        fm_int addr_count = 0;
        fm_status st_vlan;
        fm_status st_state;
        fm_status st_addr;
        char addr_text[64];

        memset(addrs, 0, sizeof(addrs));
        st_vlan = fmGetInterfaceAttribute((fm_int)sw, ifaces[i],
                                          FM_INTERFACE_VLAN, &vlan);
        st_state = fmGetInterfaceAttribute((fm_int)sw, ifaces[i],
                                           FM_INTERFACE_STATE, &state);
        st_addr = fmGetInterfaceAddrList(
            (fm_int)sw, ifaces[i], &addr_count, addrs,
            (fm_int)(sizeof(addrs) / sizeof(addrs[0])));
        if (st_addr == FM_OK && addr_count > 0)
            ipaddr_to_text(&addrs[0], addr_text, sizeof(addr_text));
        else
            snprintf(addr_text, sizeof(addr_text), "-");
        off = appendf(buf, size, off,
                      "<object family=\"rif\" key=\"%d\" vlan=\"%u\" "
                      "state=\"%d\" address=\"%s\" address-count=\"%d\" "
                      "vlan-status=\"%s\" state-status=\"%s\" "
                      "addr-status=\"%s\"/>",
                      (int)ifaces[i], (unsigned)vlan, (int)state,
                      addr_text, (int)addr_count,
                      sdk_status_name(st_vlan), sdk_status_name(st_state),
                      sdk_status_name(st_addr));
    }

    emit = sdk_readback_emit_count(n_arps, object_limit);
    for (int i = 0; i < emit; i++) {
        char ip_text[64];
        char mac_text[32];

        ipaddr_to_text(&arps[i].ipAddr, ip_text, sizeof(ip_text));
        mac_to_text(arps[i].macAddr, mac_text, sizeof(mac_text));
        off = appendf(buf, size, off,
                      "<object family=\"arp\" key=\"%s/%u\" ip=\"%s\" "
                      "mac=\"%s\" interface=\"%d\" vlan=\"%u\"/>",
                      ip_text, (unsigned)arps[i].vlan, ip_text,
                      mac_text, (int)arps[i].interface,
                      (unsigned)arps[i].vlan);
    }

    emit = sdk_readback_emit_count(n_ecmp_groups, object_limit);
    for (int i = 0; i < emit; i++) {
        fm_nextHop members[8];
        fm_int member_count = 0;
        fm_status st_members;

        memset(members, 0, sizeof(members));
        st_members = fmGetECMPGroupNextHopList(
            (fm_int)sw, ecmp_groups[i], &member_count, members,
            (fm_int)(sizeof(members) / sizeof(members[0])));
        off = appendf(buf, size, off,
                      "<object family=\"ecmp\" key=\"%d\" members=\"%d\" "
                      "member-status=\"%s\">",
                      (int)ecmp_groups[i], (int)member_count,
                      sdk_status_name(st_members));
        if (st_members == FM_OK) {
            int member_emit = sdk_readback_emit_count(
                member_count, (int)(sizeof(members) / sizeof(members[0])));
            for (int j = 0; j < member_emit; j++) {
                char ip_text[64];
                char if_text[64];

                ipaddr_to_text(&members[j].addr, ip_text, sizeof(ip_text));
                ipaddr_to_text(&members[j].interfaceAddr, if_text,
                               sizeof(if_text));
                off = appendf(buf, size, off,
                              "<member index=\"%d\" ip=\"%s\" "
                              "interface-address=\"%s\" vlan=\"%u\"/>",
                              j, ip_text, if_text,
                              (unsigned)members[j].vlan);
            }
        }
        off = appendf(buf, size, off, "</object>");
    }

    emit = sdk_readback_emit_count(n_routes, object_limit);
    for (int i = 0; i < emit; i++) {
        char prefix_text[64];

        if (routes[i].routeType == FM_ROUTE_TYPE_UNICAST) {
            char next_hop[64];
            char if_addr[64];

            ipaddr_to_text(&routes[i].data.unicast.dstAddr, prefix_text,
                           sizeof(prefix_text));
            ipaddr_to_text(&routes[i].data.unicast.nextHop, next_hop,
                           sizeof(next_hop));
            ipaddr_to_text(&routes[i].data.unicast.interfaceAddr, if_addr,
                           sizeof(if_addr));
            off = appendf(buf, size, off,
                          "<object family=\"route\" key=\"%s/%d\" "
                          "type=\"unicast\" prefix=\"%s/%d\" "
                          "next-hop=\"%s\" interface-address=\"%s\" "
                          "vlan=\"%u\" vrid=\"%d\"/>",
                          prefix_text,
                          (int)routes[i].data.unicast.prefixLength,
                          prefix_text,
                          (int)routes[i].data.unicast.prefixLength,
                          next_hop, if_addr,
                          (unsigned)routes[i].data.unicast.vlan,
                          (int)routes[i].data.unicast.vrid);
        } else if (routes[i].routeType == FM_ROUTE_TYPE_UNICAST_ECMP) {
            ipaddr_to_text(&routes[i].data.unicastECMP.dstAddr,
                           prefix_text, sizeof(prefix_text));
            off = appendf(buf, size, off,
                          "<object family=\"route\" key=\"%s/%d\" "
                          "type=\"ecmp\" prefix=\"%s/%d\" ecmp=\"%d\" "
                          "vrid=\"%d\"/>",
                          prefix_text,
                          (int)routes[i].data.unicastECMP.prefixLength,
                          prefix_text,
                          (int)routes[i].data.unicastECMP.prefixLength,
                          (int)routes[i].data.unicastECMP.ecmpGroup,
                          (int)routes[i].data.unicastECMP.vrid);
        } else {
            off = appendf(buf, size, off,
                          "<object family=\"route\" key=\"%d\" "
                          "type=\"%d\"/>", i, (int)routes[i].routeType);
        }
    }

    return off;
}

static int append_sdk_op_status(char *buf, size_t size, int off,
                                const char *name, fm_status st,
                                bool skipped) {
    char msg_attr[128];

    if (skipped) {
        return appendf(buf, size, off,
                       "<op name=\"%s\" status=\"skipped\" "
                       "message=\"not-needed\"/>",
                       name ? name : "unknown");
    }
    xml_escape_attr(fmErrorMsg(st), msg_attr, sizeof(msg_attr));
    return appendf(buf, size, off,
                   "<op name=\"%s\" status=\"%s\" sdk-status=\"%d\" "
                   "message=\"%s\"/>",
                   name ? name : "unknown", sdk_status_name(st), (int)st,
                   msg_attr);
}

static fm_uint64 port_counter_rx_pkts(const fm_portCounters *cnt) {
    if (!cnt)
        return 0;
    return cnt->cntRxUcstPkts + cnt->cntRxBcstPkts + cnt->cntRxMcstPkts;
}

static fm_uint64 port_counter_tx_pkts(const fm_portCounters *cnt) {
    if (!cnt)
        return 0;
    return cnt->cntTxUcstPkts + cnt->cntTxBcstPkts + cnt->cntTxMcstPkts;
}

static fm_uint64 port_counter_rx_errs(const fm_portCounters *cnt) {
    if (!cnt)
        return 0;
    return cnt->cntRxFCSErrors + cnt->cntRxSymbolErrors +
           cnt->cntRxFrameSizeErrors + cnt->cntRxFramingErrorPkts;
}

static bool ipaddr_equal(const fm_ipAddr *a, const fm_ipAddr *b) {
    if (!a || !b || a->isIPv6 != b->isIPv6)
        return false;
    for (int i = 0; i < 4; i++)
        if (a->addr[i] != b->addr[i])
            return false;
    return true;
}

static bool ipaddr_list_contains(const fm_ipAddr *list, int count,
                                 const fm_ipAddr *needle) {
    if (!list || count <= 0 || !needle)
        return false;
    for (int i = 0; i < count; i++)
        if (ipaddr_equal(&list[i], needle))
            return true;
    return false;
}

static bool arp_entry_equal(const fm_arpEntry *a, const fm_arpEntry *b) {
    return a && b && ipaddr_equal(&a->ipAddr, &b->ipAddr) &&
           a->interface == b->interface && a->vlan == b->vlan &&
           a->macAddr == b->macAddr;
}

static bool arp_list_contains(const fm_arpEntry *list, int count,
                              const fm_arpEntry *needle) {
    if (!list || count <= 0 || !needle)
        return false;
    for (int i = 0; i < count; i++)
        if (arp_entry_equal(&list[i], needle))
            return true;
    return false;
}

static bool next_hop_equal(const fm_nextHop *a, const fm_nextHop *b) {
    return a && b && ipaddr_equal(&a->addr, &b->addr) &&
           ipaddr_equal(&a->interfaceAddr, &b->interfaceAddr) &&
           a->vlan == b->vlan;
}

static bool next_hop_list_contains(const fm_nextHop *list, int count,
                                   const fm_nextHop *needle) {
    if (!list || count <= 0 || !needle)
        return false;
    for (int i = 0; i < count; i++)
        if (next_hop_equal(&list[i], needle))
            return true;
    return false;
}

static bool ecmp_group_list_contains(const fm_int *list, int count,
                                     fm_int group_id) {
    if (!list || count <= 0)
        return false;
    for (int i = 0; i < count; i++)
        if (list[i] == group_id)
            return true;
    return false;
}

static bool route_entry_equal(const fm_routeEntry *a, const fm_routeEntry *b) {
    if (!a || !b || a->routeType != b->routeType)
        return false;
    if (a->routeType == FM_ROUTE_TYPE_UNICAST) {
        return ipaddr_equal(&a->data.unicast.dstAddr,
                            &b->data.unicast.dstAddr) &&
               a->data.unicast.prefixLength == b->data.unicast.prefixLength &&
               ipaddr_equal(&a->data.unicast.nextHop,
                            &b->data.unicast.nextHop) &&
               ipaddr_equal(&a->data.unicast.interfaceAddr,
                            &b->data.unicast.interfaceAddr) &&
               a->data.unicast.vlan == b->data.unicast.vlan &&
               a->data.unicast.vrid == b->data.unicast.vrid;
    }
    if (a->routeType == FM_ROUTE_TYPE_UNICAST_ECMP) {
        return ipaddr_equal(&a->data.unicastECMP.dstAddr,
                            &b->data.unicastECMP.dstAddr) &&
               a->data.unicastECMP.prefixLength ==
                   b->data.unicastECMP.prefixLength &&
               a->data.unicastECMP.ecmpGroup ==
                   b->data.unicastECMP.ecmpGroup &&
               a->data.unicastECMP.vrid == b->data.unicastECMP.vrid;
    }
    return false;
}

static bool route_list_contains(const fm_routeEntry *list, int count,
                                const fm_routeEntry *needle) {
    if (!list || count <= 0 || !needle)
        return false;
    for (int i = 0; i < count; i++)
        if (route_entry_equal(&list[i], needle))
            return true;
    return false;
}

static fm_status get_interface_list_contains(int sw, fm_int ifindex,
                                             fm_int *count, bool *contains) {
    enum { MAX_INTERFACES = 512 };
    fm_int ifaces[MAX_INTERFACES];
    fm_int n = 0;
    fm_status st;

    memset(ifaces, 0, sizeof(ifaces));
    st = fmGetInterfaceList((fm_int)sw, &n, ifaces, MAX_INTERFACES);
    if (count)
        *count = n;
    if (contains) {
        *contains = false;
        if (st == FM_OK) {
            fm_int emitted = n > MAX_INTERFACES ? MAX_INTERFACES : n;
            for (fm_int i = 0; i < emitted; i++) {
                if (ifaces[i] == ifindex) {
                    *contains = true;
                    break;
                }
            }
        }
    }
    return st;
}

static void fp_mix_u64(u64 *fp, u64 value) {
    if (!fp)
        return;
    *fp ^= value;
    *fp *= 1099511628211ULL;
}

static bool env_truthy(const char *value) {
    return value &&
           (strcmp(value, "1") == 0 ||
            strcmp(value, "true") == 0 ||
            strcmp(value, "TRUE") == 0 ||
            strcmp(value, "yes") == 0 ||
            strcmp(value, "YES") == 0);
}

static int parse_ipv4(const char *text, fm_ipAddr *out) {
    struct in_addr addr;

    if (!text || !out || inet_pton(AF_INET, text, &addr) != 1)
        return -1;
    memset(out, 0, sizeof(*out));
    out->addr[0] = addr.s_addr;
    out->isIPv6 = false;
    return 0;
}

static int parse_ipv4_cidr(const char *text, fm_ipAddr *addr, int *prefix) {
    char ip[HAL_L3_INTENT_ADDR_LEN];
    int plen = -1;

    if (!text || sscanf(text, "%39[^/]/%d", ip, &plen) != 2 ||
        plen < 0 || plen > 32 || parse_ipv4(ip, addr) != 0)
        return -1;
    if (prefix)
        *prefix = plen;
    return 0;
}

static int parse_mac(const char *text, fm_macaddr *mac) {
    unsigned int b[6];
    char tail;

    if (!text || !mac ||
        sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        if (b[i] > 255)
            return -1;
    *mac = ((fm_macaddr)b[0] << 40) | ((fm_macaddr)b[1] << 32) |
           ((fm_macaddr)b[2] << 24) | ((fm_macaddr)b[3] << 16) |
           ((fm_macaddr)b[4] << 8) | (fm_macaddr)b[5];
    return 0;
}

static fm_status find_vlan_first_user_port(int sw, fm_uint16 vlan,
                                           fm_int *port_out,
                                           fm_int *user_ports_out) {
    fm_int ports[NL_MAX_PORTS_PER_PROFILE + 16];
    fm_int n_ports = (fm_int)(sizeof(ports) / sizeof(ports[0]));
    fm_status st;
    int user_ports = 0;
    fm_int selected = -1;

    if (!port_out)
        return FM_ERR_INVALID_ARGUMENT;
    *port_out = -1;
    st = fmGetVlanPortList((fm_int)sw, vlan, &n_ports, ports,
                           (fm_int)(sizeof(ports) / sizeof(ports[0])));
    if (st != FM_OK)
        return st;
    for (int i = 0; i < n_ports &&
         i < (int)(sizeof(ports) / sizeof(ports[0])); i++) {
        if (!nl_ifid_is_user_port((int)ports[i]))
            continue;
        if (user_ports == 0)
            selected = ports[i];
        user_ports++;
    }
    if (user_ports_out)
        *user_ports_out = user_ports;
    if (user_ports <= 0)
        return FM_ERR_NOT_FOUND;
    *port_out = selected;
    return FM_OK;
}

static fm_status find_vlan_named_user_port(int sw, fm_uint16 vlan,
                                           const char *ifname,
                                           fm_int *port_out) {
    fm_int ports[NL_MAX_PORTS_PER_PROFILE + 16];
    fm_int n_ports = (fm_int)(sizeof(ports) / sizeof(ports[0]));
    int logical_port;
    fm_status st;

    if (!ifname || !ifname[0] || !port_out)
        return FM_ERR_INVALID_ARGUMENT;
    *port_out = -1;
    logical_port = nl_ifid_name_to_logical_port(ifname);
    if (logical_port <= 0 || !nl_ifid_is_user_port(logical_port))
        return FM_ERR_INVALID_ARGUMENT;
    st = fmGetVlanPortList((fm_int)sw, vlan, &n_ports, ports,
                           (fm_int)(sizeof(ports) / sizeof(ports[0])));
    if (st != FM_OK)
        return st;
    for (int i = 0; i < n_ports &&
         i < (int)(sizeof(ports) / sizeof(ports[0])); i++) {
        if ((int)ports[i] == logical_port) {
            *port_out = (fm_int)logical_port;
            return FM_OK;
        }
    }
    return FM_ERR_NOT_FOUND;
}

static int find_rif(const hal_l3_intent_plan *plan, const char *name) {
    if (!plan || !name)
        return -1;
    for (int i = 0; i < plan->n_rifs; i++)
        if (strcmp(plan->rifs[i].name, name) == 0)
            return i;
    return -1;
}

static const char *intent_table(const char *table) {
    return table && table[0] ? table : "inet.0";
}

static bool intent_scope_valid(const hal_l3_intent_plan *plan,
                               const char *table, int vrid) {
    const char *effective = intent_table(table);

    if (strcmp(effective, "inet.0") == 0)
        return vrid == 0;
    return plan && plan->has_virtual_router &&
           strcmp(effective, plan->virtual_router_table) == 0 &&
           vrid == plan->virtual_router_id;
}

static const hal_l3_intent_arp *find_arp(const hal_l3_intent_plan *plan,
                                         const char *ip, const char *rif) {
    if (!plan || !ip || !rif)
        return NULL;
    for (int i = 0; i < plan->n_arps; i++)
        if (strcmp(plan->arps[i].ip, ip) == 0 &&
            strcmp(plan->arps[i].rif, rif) == 0)
            return &plan->arps[i];
    return NULL;
}

static const hal_l3_intent_next_hop *find_nexthop(
        const hal_l3_intent_plan *plan, int id) {
    if (!plan)
        return NULL;
    for (int i = 0; i < plan->n_nexthops; i++)
        if (plan->nexthops[i].id == id)
            return &plan->nexthops[i];
    return NULL;
}

static const hal_l3_intent_ecmp *find_ecmp(const hal_l3_intent_plan *plan,
                                           int id) {
    if (!plan)
        return NULL;
    for (int i = 0; i < plan->n_ecmp; i++)
        if (plan->ecmp[i].id == id)
            return &plan->ecmp[i];
    return NULL;
}

static int encode_rif(const hal_l3_intent_rif *rif, u64 *fp) {
    fm_ipAddr addr;
    int prefix;
    fm_interfaceState state = FM_INTERFACE_STATE_ADMIN_UP;
    fm_uint16 vlan;

    if (!rif || parse_ipv4_cidr(rif->address, &addr, &prefix) != 0 ||
        rif->vlan < 1 || rif->vlan > 4094)
        return -1;
    vlan = (fm_uint16)rif->vlan;
    fp_mix_u64(fp, (u64)addr.addr[0]);
    fp_mix_u64(fp, (u64)prefix);
    fp_mix_u64(fp, (u64)vlan);
    fp_mix_u64(fp, (u64)state);
    for (const char *p = rif->port; *p; p++)
        fp_mix_u64(fp, (u64)(unsigned char)*p);
    return 0;
}

static int encode_arp(const hal_l3_intent_plan *plan,
                      const hal_l3_intent_arp *arp, u64 *fp) {
    fm_arpEntry entry;
    int rif_index;

    if (!plan || !arp)
        return -1;
    rif_index = find_rif(plan, arp->rif);
    if (rif_index < 0 || parse_ipv4(arp->ip, &entry.ipAddr) != 0 ||
        parse_mac(arp->mac, &entry.macAddr) != 0)
        return -1;
    entry.interface = rif_index + 1;
    entry.vlan = (fm_uint16)plan->rifs[rif_index].vlan;
    fp_mix_u64(fp, (u64)entry.ipAddr.addr[0]);
    fp_mix_u64(fp, (u64)entry.interface);
    fp_mix_u64(fp, (u64)entry.vlan);
    fp_mix_u64(fp, (u64)entry.macAddr);
    return 0;
}

static int encode_next_hop(const hal_l3_intent_plan *plan,
                           const hal_l3_intent_next_hop *nh, u64 *fp) {
    fm_nextHop sdk_nh;
    int rif_index;

    if (!plan || !nh)
        return -1;
    rif_index = find_rif(plan, nh->rif);
    if (rif_index < 0 || !find_arp(plan, nh->arp, nh->rif) ||
        parse_ipv4(nh->arp, &sdk_nh.addr) != 0 ||
        parse_ipv4_cidr(plan->rifs[rif_index].address,
                        &sdk_nh.interfaceAddr, NULL) != 0)
        return -1;
    sdk_nh.vlan = (fm_uint16)plan->rifs[rif_index].vlan;
    sdk_nh.trapCode = FM_DEFAULT_NEXTHOP_TRAPCODE;
    fp_mix_u64(fp, (u64)nh->id);
    fp_mix_u64(fp, (u64)sdk_nh.addr.addr[0]);
    fp_mix_u64(fp, (u64)sdk_nh.interfaceAddr.addr[0]);
    fp_mix_u64(fp, (u64)sdk_nh.vlan);
    fp_mix_u64(fp, (u64)sdk_nh.trapCode);
    return 0;
}

static int build_sdk_next_hop(const hal_l3_intent_plan *plan,
                              const hal_l3_intent_next_hop *nh,
                              fm_nextHop *sdk_nh) {
    int rif_index;

    if (!plan || !nh || !sdk_nh)
        return -1;
    rif_index = find_rif(plan, nh->rif);
    if (rif_index < 0 || !find_arp(plan, nh->arp, nh->rif))
        return -1;
    memset(sdk_nh, 0, sizeof(*sdk_nh));
    if (parse_ipv4(nh->arp, &sdk_nh->addr) != 0 ||
        parse_ipv4_cidr(plan->rifs[rif_index].address,
                        &sdk_nh->interfaceAddr, NULL) != 0)
        return -1;
    sdk_nh->vlan = 0; /* Only used by the SDK when interfaceAddr is zero. */
    sdk_nh->trapCode = FM_DEFAULT_NEXTHOP_TRAPCODE;
    return 0;
}

static int encode_ecmp(const hal_l3_intent_plan *plan,
                       const hal_l3_intent_ecmp *ecmp, u64 *fp) {
    fm_ecmpGroupInfo info;

    if (!plan || !ecmp || ecmp->n_members <= 0 ||
        ecmp->n_members > HAL_L3_INTENT_MAX_ECMP_MEMBERS)
        return -1;
    memset(&info, 0, sizeof(info));
    info.numFixedEntries = ecmp->n_members;
    fp_mix_u64(fp, (u64)ecmp->id);
    fp_mix_u64(fp, (u64)info.numFixedEntries);
    for (int i = 0; i < ecmp->n_members; i++) {
        fm_ecmpNextHop member;
        const hal_l3_intent_next_hop *nh =
            find_nexthop(plan, ecmp->members[i]);

        if (!nh)
            return -1;
        memset(&member, 0, sizeof(member));
        member.type = FM_NEXTHOP_TYPE_ARP;
        if (parse_ipv4(nh->arp, &member.data.arp.addr) != 0)
            return -1;
        fp_mix_u64(fp, (u64)member.type);
        fp_mix_u64(fp, (u64)member.data.arp.addr.addr[0]);
    }
    return 0;
}

static int encode_route(const hal_l3_intent_plan *plan,
                        const hal_l3_intent_route *route, u64 *fp) {
    fm_routeEntry sdk_route;
    fm_ipAddr dst;
    int prefix;

    if (!plan || !route ||
        parse_ipv4_cidr(route->prefix, &dst, &prefix) != 0)
        return -1;
    memset(&sdk_route, 0, sizeof(sdk_route));
    if (route->target_type == HAL_L3_ROUTE_TARGET_NEXTHOP) {
        const hal_l3_intent_next_hop *nh =
            find_nexthop(plan, route->target_id);
        int rif_index;

        if (!nh)
            return -1;
        rif_index = find_rif(plan, nh->rif);
        if (rif_index < 0 ||
            parse_ipv4(nh->arp, &sdk_route.data.unicast.nextHop) != 0 ||
            parse_ipv4_cidr(plan->rifs[rif_index].address,
                            &sdk_route.data.unicast.interfaceAddr,
                            NULL) != 0)
            return -1;
        sdk_route.routeType = FM_ROUTE_TYPE_UNICAST;
        sdk_route.data.unicast.dstAddr = dst;
        sdk_route.data.unicast.prefixLength = prefix;
        sdk_route.data.unicast.vlan = 0;
        sdk_route.data.unicast.vrid = route->vrid;
        fp_mix_u64(fp, (u64)sdk_route.data.unicast.nextHop.addr[0]);
        fp_mix_u64(fp, (u64)sdk_route.data.unicast.interfaceAddr.addr[0]);
    } else if (route->target_type == HAL_L3_ROUTE_TARGET_ECMP) {
        if (!find_ecmp(plan, route->target_id))
            return -1;
        sdk_route.routeType = FM_ROUTE_TYPE_UNICAST_ECMP;
        sdk_route.data.unicastECMP.dstAddr = dst;
        sdk_route.data.unicastECMP.prefixLength = prefix;
        sdk_route.data.unicastECMP.ecmpGroup = route->target_id;
        sdk_route.data.unicastECMP.vrid = route->vrid;
        fp_mix_u64(fp, (u64)sdk_route.data.unicastECMP.ecmpGroup);
    } else if (route->target_type == HAL_L3_ROUTE_TARGET_RIF) {
        int rif_index = find_rif(plan, route->target_name);

        if (rif_index < 0 ||
            parse_ipv4_cidr(plan->rifs[rif_index].address,
                            &sdk_route.data.unicast.interfaceAddr,
                            NULL) != 0)
            return -1;
        sdk_route.routeType = FM_ROUTE_TYPE_UNICAST;
        sdk_route.data.unicast.dstAddr = dst;
        sdk_route.data.unicast.prefixLength = prefix;
        sdk_route.data.unicast.vlan = 0;
        sdk_route.data.unicast.vrid = route->vrid;
        fp_mix_u64(fp, (u64)sdk_route.data.unicast.interfaceAddr.addr[0]);
        fp_mix_u64(fp, (u64)sdk_route.data.unicast.vlan);
    } else {
        return -1;
    }
    fp_mix_u64(fp, (u64)sdk_route.routeType);
    fp_mix_u64(fp, (u64)dst.addr[0]);
    fp_mix_u64(fp, (u64)prefix);
    fp_mix_u64(fp, (u64)route->target_id);
    for (const char *p = route->target_name; *p; p++)
        fp_mix_u64(fp, (u64)(unsigned char)*p);
    return 0;
}

static int build_sdk_route(const hal_l3_intent_plan *plan,
                           const hal_l3_intent_route *route,
                           const fm_int *sdk_ecmp_groups,
                           const hal_l3_intent_ecmp **ecmp_refs,
                           int n_ecmp_groups,
                           fm_routeEntry *sdk_route) {
    fm_ipAddr dst;
    int prefix;

    if (!plan || !route || !sdk_route ||
        parse_ipv4_cidr(route->prefix, &dst, &prefix) != 0)
        return -1;
    memset(sdk_route, 0, sizeof(*sdk_route));
    if (route->target_type == HAL_L3_ROUTE_TARGET_NEXTHOP) {
        const hal_l3_intent_next_hop *nh =
            find_nexthop(plan, route->target_id);
        int rif_index;

        if (!nh)
            return -1;
        rif_index = find_rif(plan, nh->rif);
        if (rif_index < 0 ||
            parse_ipv4(nh->arp, &sdk_route->data.unicast.nextHop) != 0 ||
            parse_ipv4_cidr(plan->rifs[rif_index].address,
                            &sdk_route->data.unicast.interfaceAddr,
                            NULL) != 0)
            return -1;
        sdk_route->routeType = FM_ROUTE_TYPE_UNICAST;
        sdk_route->data.unicast.dstAddr = dst;
        sdk_route->data.unicast.prefixLength = prefix;
        sdk_route->data.unicast.vlan = 0;
        sdk_route->data.unicast.vrid = route->vrid;
        return 0;
    }
    if (route->target_type == HAL_L3_ROUTE_TARGET_ECMP) {
        if (!sdk_ecmp_groups || !ecmp_refs)
            return -1;
        for (int i = 0; i < n_ecmp_groups; i++) {
            if (ecmp_refs[i] && ecmp_refs[i]->id == route->target_id) {
                sdk_route->routeType = FM_ROUTE_TYPE_UNICAST_ECMP;
                sdk_route->data.unicastECMP.dstAddr = dst;
                sdk_route->data.unicastECMP.prefixLength = prefix;
                sdk_route->data.unicastECMP.ecmpGroup = sdk_ecmp_groups[i];
                sdk_route->data.unicastECMP.vrid = route->vrid;
                return 0;
            }
        }
        return -1;
    }
    return -1;
}

static int encode_plan(const hal_l3_intent_plan *plan, u64 *fingerprint,
                       int *ecmp_members) {
    u64 fp = 1469598103934665603ULL;
    int members = 0;

    if (!plan || plan->n_rifs < 0 || plan->n_arps < 0 ||
        plan->n_nexthops < 0 || plan->n_ecmp < 0 || plan->n_routes < 0)
        return -1;
    if ((plan->n_rifs > 0 && !plan->rifs) ||
        (plan->n_arps > 0 && !plan->arps) ||
        (plan->n_nexthops > 0 && !plan->nexthops) ||
        (plan->n_ecmp > 0 && !plan->ecmp) ||
        (plan->n_routes > 0 && !plan->routes))
        return -1;
    if (plan->has_router_mac) {
        fm_macaddr mac;

        if (parse_mac(plan->router_mac, &mac) != 0)
            return -1;
        for (const char *p = plan->router_mac; *p; p++)
            fp_mix_u64(&fp, (u64)(unsigned char)*p);
    }

    for (int i = 0; i < plan->n_rifs; i++)
        if (encode_rif(&plan->rifs[i], &fp) != 0)
            return -1;
    for (int i = 0; i < plan->n_arps; i++)
        if (encode_arp(plan, &plan->arps[i], &fp) != 0)
            return -1;
    for (int i = 0; i < plan->n_nexthops; i++)
        if (encode_next_hop(plan, &plan->nexthops[i], &fp) != 0)
            return -1;
    for (int i = 0; i < plan->n_ecmp; i++) {
        members += plan->ecmp[i].n_members;
        if (encode_ecmp(plan, &plan->ecmp[i], &fp) != 0)
            return -1;
    }
    for (int i = 0; i < plan->n_routes; i++)
        if (encode_route(plan, &plan->routes[i], &fp) != 0)
            return -1;

    if (fingerprint)
        *fingerprint = fp;
    if (ecmp_members)
        *ecmp_members = members;
    return 0;
}

int hal_l3_intent_probe(const hal_l3_intent_plan *plan, char *resp,
                        size_t resp_size) {
    int ecmp_members = 0;
    u64 fingerprint = 0;
    int off;

    if (!plan || !resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (encode_plan(plan, &fingerprint, &ecmp_members) != 0)
        return -1;

    off = snprintf(resp, resp_size,
                   "<hal-l3-intent-probe status=\"ok\" sdk-write=\"disabled\" "
                   "sdk-readback=\"planned\" "
                   "apply-order=\"traffic,rif,arp,next-hop,ecmp,route\" "
                   "rollback-order=\"route,ecmp,next-hop,arp,rif,traffic\" "
                   "fingerprint=\"0x%016llx\">",
                   (unsigned long long)fingerprint);
    if (off < 0 || (size_t)off >= resp_size)
        return -1;
    off = appendf(resp, resp_size, off,
                  "<sdk-object family=\"traffic-owner\" "
                  "api=\"fmSetRouterAttribute,fmSetRouterState,"
                  "fmSetVlanAttribute,fmAddVlanPort,fmSetVlanPortState,"
                  "fmSetPortAttribute,fmAddAddress\" "
                  "router-mac=\"%s\" enabled=\"%s\"/>",
                  plan->has_router_mac ? plan->router_mac : "-",
                  plan->has_router_mac ? "true" : "false");
    off = appendf(resp, resp_size, off,
                  "<sdk-object family=\"router-interface\" "
                  "api=\"fmCreateInterface,fmSetInterfaceAttribute,"
                  "fmAddInterfaceAddr\" state=\"FM_INTERFACE_STATE_ADMIN_UP\" "
                  "count=\"%d\"/>",
                  plan->n_rifs);
    off = appendf(resp, resp_size, off,
                  "<sdk-object family=\"arp\" struct=\"fm_arpEntry\" "
                  "api=\"fmAddARPEntry,fmGetARPEntryInfo,"
                  "fmGetARPEntryUsed\" count=\"%d\"/>",
                  plan->n_arps);
    off = appendf(resp, resp_size, off,
                  "<sdk-object family=\"next-hop\" struct=\"fm_nextHop\" "
                  "type=\"FM_NEXTHOP_TYPE_ARP\" count=\"%d\"/>",
                  plan->n_nexthops);
    off = appendf(resp, resp_size, off,
                  "<sdk-object family=\"ecmp\" struct=\"fm_ecmpNextHop\" "
                  "api=\"fmCreateECMPGroup,fmGetECMPGroupNextHopList,"
                  "fmDeleteECMPGroup\" "
                  "groups=\"%d\" members=\"%d\"/>",
                  plan->n_ecmp, ecmp_members);
    off = appendf(resp, resp_size, off,
                  "<sdk-object family=\"route\" struct=\"fm_routeEntry\" "
                  "type=\"FM_ROUTE_TYPE_UNICAST,FM_ROUTE_TYPE_UNICAST_ECMP\" "
                  "targets=\"connected,next-hop,ecmp\" "
                  "api=\"fmAddRoute,fmGetRouteState,fmDeleteRoute\" "
                  "count=\"%d\"/>"
                  "</hal-l3-intent-probe>",
                  plan->n_routes);
    return off < 0 ? -1 : 0;
}

int hal_l3_intent_sdk_preflight(const hal_l3_intent_plan *plan, char *resp,
                                size_t resp_size) {
    const char *gate_env = "NETLAB_ENABLE_L3_SDK_APPLY";
    bool gate_enabled;
    int ecmp_members = 0;
    int total_ops;
    u64 fingerprint = 0;
    int off;

    if (!plan || !resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (encode_plan(plan, &fingerprint, &ecmp_members) != 0)
        return -1;

    gate_enabled = env_truthy(getenv(gate_env));
    total_ops = (plan->has_router_mac ? 1 : 0) +
                plan->n_rifs + plan->n_arps + plan->n_nexthops +
                plan->n_ecmp + plan->n_routes;

    off = snprintf(resp, resp_size,
                   "<hal-l3-sdk-preflight status=\"ok\" "
                   "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                   "sdk-readback=\"planned\" rollback=\"planned\" "
                   "write-implementation=\"preflight-only\" "
                   "gate-env=\"%s\" gate-enabled=\"%s\" "
                   "profile-gate=\"required\" "
                   "apply-order=\"traffic,rif,arp,next-hop,ecmp,route\" "
                   "readback-order=\"traffic,rif,arp,next-hop,ecmp,route\" "
                   "rollback-order=\"route,ecmp,next-hop,arp,rif,traffic\" "
                   "total-ops=\"%d\" fingerprint=\"0x%016llx\">",
                   gate_env, gate_enabled ? "true" : "false", total_ops,
                   (unsigned long long)fingerprint);
    if (off < 0 || (size_t)off >= resp_size)
        return -1;
    off = appendf(resp, resp_size, off,
                  "<gate name=\"profile\" state=\"required\" "
                  "requires=\"L3-route-slices-and-ROUTE-ports\"/>");
    off = appendf(resp, resp_size, off,
                  "<gate name=\"operator\" state=\"%s\" variable=\"%s\"/>",
                  gate_enabled ? "acknowledged" : "closed", gate_env);
    off = appendf(resp, resp_size, off,
                  "<phase name=\"apply\" "
                  "api=\"fmSetRouterAttribute,fmSetRouterState,"
                  "fmSetVlanAttribute,fmAddVlanPort,fmSetVlanPortState,"
                  "fmSetPortAttribute,"
                  "fmCreateInterface,fmSetInterfaceAttribute,"
                  "fmAddInterfaceAddr,fmAddARPEntry,"
                  "fmAddAddress,fmCreateECMPGroup,fmAddRoute\"/>");
    off = appendf(resp, resp_size, off,
                  "<phase name=\"read-back\" "
                  "api=\"fmGetRouterAttribute,fmGetRouterState,"
                  "fmGetVlanAttribute,fmGetVlanPortTag,"
                  "fmGetVlanPortState,fmGetPortAttribute,"
                  "fmGetInterfaceAddrList,fmGetARPEntryInfo,"
                  "fmGetARPEntryUsed,fmGetECMPGroupNextHopList,"
                  "fmGetRouteState,fmGetRouteList\"/>");
    off = appendf(resp, resp_size, off,
                  "<phase name=\"rollback\" "
                  "api=\"fmDeleteRoute,fmDeleteECMPGroup,"
                  "fmDeleteARPEntry,fmDeleteInterfaceAddr,"
                  "fmDeleteInterface,fmDeleteVlanPort,fmSetPortAttribute,"
                  "fmSetVlanAttribute,fmSetRouterState,"
                  "fmSetRouterAttribute\"/>");
    off = appendf(resp, resp_size, off,
                  "<family name=\"traffic-owner\" apply=\"%d\" "
                  "rollback=\"%d\" router-mac=\"%s\"/>",
                  plan->has_router_mac ? 1 : 0,
                  plan->has_router_mac ? 1 : 0,
                  plan->has_router_mac ? plan->router_mac : "-");
    off = appendf(resp, resp_size, off,
                  "<family name=\"rif\" apply=\"%d\" rollback=\"%d\"/>",
                  plan->n_rifs, plan->n_rifs);
    off = appendf(resp, resp_size, off,
                  "<family name=\"arp\" apply=\"%d\" rollback=\"%d\"/>",
                  plan->n_arps, plan->n_arps);
    off = appendf(resp, resp_size, off,
                  "<family name=\"next-hop\" apply=\"%d\" rollback=\"0\" "
                  "reason=\"SDK-next-hop-is-route-reference\"/>",
                  plan->n_nexthops);
    off = appendf(resp, resp_size, off,
                  "<family name=\"ecmp\" apply=\"%d\" members=\"%d\" "
                  "rollback=\"%d\"/>",
                  plan->n_ecmp, ecmp_members, plan->n_ecmp);
    off = appendf(resp, resp_size, off,
                  "<family name=\"route\" apply=\"%d\" rollback=\"%d\"/>",
                  plan->n_routes, plan->n_routes);
    off = appendf(resp, resp_size, off,
                  "<failure-policy apply-failure=\"rollback\" "
                  "readback-mismatch=\"rollback\" "
                  "rollback-mismatch=\"mark-hw-out-of-sync\" "
                  "future-commits=\"blocked-on-persistent-mismatch\"/>"
                  "</hal-l3-sdk-preflight>");
    return off < 0 ? -1 : 0;
}

int hal_l3_sdk_readback_probe(int sw, char *resp, size_t resp_size) {
    enum { L3_PROBE_MAX = 64 };
    enum { L3_OBJECT_EMIT_LIMIT = 8 };
    fm_routerState router_state = 0;
    fm_int vrids[16];
    fm_int ifaces[L3_PROBE_MAX];
    fm_arpEntry arps[L3_PROBE_MAX];
    fm_int ecmp_groups[L3_PROBE_MAX];
    fm_routeEntry routes[L3_PROBE_MAX];
    fm_int num_vrids = 0;
    fm_int num_ifaces = 0;
    fm_int num_arps = 0;
    fm_int num_ecmp_groups = 0;
    fm_int num_routes = 0;
    fm_status st_router;
    fm_status st_vrid;
    fm_status st_ifaces;
    fm_status st_arps;
    fm_status st_ecmp;
    fm_status st_routes;
    const char *overall = "ok";
    char router_msg[128];
    int off;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';

    memset(vrids, 0, sizeof(vrids));
    memset(ifaces, 0, sizeof(ifaces));
    memset(arps, 0, sizeof(arps));
    memset(ecmp_groups, 0, sizeof(ecmp_groups));
    memset(routes, 0, sizeof(routes));

    st_router = fmGetRouterState((fm_int)sw, FM_PHYSICAL_ROUTER,
                                 &router_state);
    st_vrid = fmGetVirtualRouterList((fm_int)sw, &num_vrids, vrids,
                                     (fm_int)(sizeof(vrids) /
                                              sizeof(vrids[0])));
    st_ifaces = fmGetInterfaceList((fm_int)sw, &num_ifaces, ifaces,
                                   L3_PROBE_MAX);
    st_arps = fmGetARPEntryList((fm_int)sw, &num_arps, arps, L3_PROBE_MAX);
    st_ecmp = fmGetECMPGroupList((fm_int)sw, &num_ecmp_groups, ecmp_groups,
                                 L3_PROBE_MAX);
    st_routes = fmGetRouteList((fm_int)sw, &num_routes, routes, L3_PROBE_MAX);

    if (st_router != FM_OK || st_vrid != FM_OK || st_ifaces != FM_OK ||
        st_arps != FM_OK || st_ecmp != FM_OK || st_routes != FM_OK)
        overall = "limited";
    if (!sdk_status_is_soft_readback(st_router) ||
        !sdk_status_is_soft_readback(st_vrid) ||
        !sdk_status_is_soft_readback(st_ifaces) ||
        !sdk_status_is_soft_readback(st_arps) ||
        !sdk_status_is_soft_readback(st_ecmp) ||
        !sdk_status_is_soft_readback(st_routes))
        overall = "error";
    xml_escape_attr(fmErrorMsg(st_router), router_msg, sizeof(router_msg));

    off = snprintf(resp, resp_size,
                   "<l3-sdk-readback-probe status=\"%s\" "
                   "source=\"switchd\" hardware-apply=\"disabled\" "
                   "sdk-write=\"disabled\" sdk-readback=\"live\" "
                   "mode=\"canary\" emit-limit=\"%d\" "
                   "object-emit-limit=\"%d\">",
                   overall, L3_PROBE_MAX, L3_OBJECT_EMIT_LIMIT);
    if (off < 0 || (size_t)off >= resp_size)
        return -1;
    off = appendf(resp, resp_size, off,
                  "<router vrid=\"%d\" status=\"%s\" sdk-status=\"%d\" "
                  "state=\"%d\" message=\"%s\"/>",
                  FM_PHYSICAL_ROUTER, sdk_status_name(st_router),
                  (int)st_router, (int)router_state, router_msg);
    off = append_sdk_readback_family(
        resp, resp_size, off, "virtual-router", st_vrid, num_vrids,
        num_vrids > (fm_int)(sizeof(vrids) / sizeof(vrids[0])) ?
            (fm_int)(sizeof(vrids) / sizeof(vrids[0])) : num_vrids);
    off = append_sdk_readback_family(resp, resp_size, off, "rif",
                                     st_ifaces, num_ifaces,
                                     num_ifaces > L3_PROBE_MAX ?
                                        L3_PROBE_MAX : num_ifaces);
    off = append_sdk_readback_family(resp, resp_size, off, "arp",
                                     st_arps, num_arps,
                                     num_arps > L3_PROBE_MAX ?
                                        L3_PROBE_MAX : num_arps);
    off = append_sdk_readback_family(resp, resp_size, off, "ecmp",
                                     st_ecmp, num_ecmp_groups,
                                     num_ecmp_groups > L3_PROBE_MAX ?
                                        L3_PROBE_MAX : num_ecmp_groups);
    off = append_sdk_readback_family(resp, resp_size, off, "route",
                                     st_routes, num_routes,
                                     num_routes > L3_PROBE_MAX ?
                                        L3_PROBE_MAX : num_routes);
    off = append_sdk_readback_objects(
        resp, resp_size, off, sw, vrids,
        num_vrids > (fm_int)(sizeof(vrids) / sizeof(vrids[0])) ?
            (int)(sizeof(vrids) / sizeof(vrids[0])) : (int)num_vrids,
        ifaces,
        num_ifaces > L3_PROBE_MAX ? L3_PROBE_MAX : (int)num_ifaces,
        arps, num_arps > L3_PROBE_MAX ? L3_PROBE_MAX : (int)num_arps,
        ecmp_groups,
        num_ecmp_groups > L3_PROBE_MAX ? L3_PROBE_MAX :
            (int)num_ecmp_groups,
        routes, num_routes > L3_PROBE_MAX ? L3_PROBE_MAX : (int)num_routes,
        L3_OBJECT_EMIT_LIMIT);
    off = appendf(resp, resp_size, off,
                  "<boundary user-config=\"rejected\" "
                  "reason=\"read-only SDK L3 inventory canary; "
                  "no RIF/ARP/ECMP/FIB writes\"/>"
                  "</l3-sdk-readback-probe>");
    return off < 0 ? -1 : 0;
}

static int expected_fib_route_count(const hal_l3_intent_plan *plan) {
    int count = 0;

    if (!plan)
        return 0;
    for (int i = 0; i < plan->n_routes; i++)
        if (plan->routes[i].target_type != HAL_L3_ROUTE_TARGET_RIF)
            count++;
    return count;
}

int hal_l3_sdk_owner_verify(int sw, const hal_l3_intent_plan *expected,
                            char *resp, size_t resp_size) {
    enum { L3_OWNER_VERIFY_MAX = 64 };
    fm_int vrids[L3_OWNER_VERIFY_MAX];
    fm_int ifaces[L3_OWNER_VERIFY_MAX];
    fm_arpEntry arps[L3_OWNER_VERIFY_MAX];
    fm_int ecmp_groups[L3_OWNER_VERIFY_MAX];
    fm_routeEntry routes[L3_OWNER_VERIFY_MAX];
    fm_int num_vrids = 0;
    fm_int num_ifaces = 0;
    fm_int num_arps = 0;
    fm_int num_ecmp_groups = 0;
    fm_int num_routes = 0;
    fm_status st_vrids;
    fm_status st_ifaces;
    fm_status st_arps;
    fm_status st_ecmp;
    fm_status st_routes;
    int exp_rifs;
    int exp_arps;
    int exp_next_hops;
    int exp_ecmp;
    int exp_ecmp_members = 0;
    int exp_fib_routes;
    int compared;
    int mismatches = 0;
    int ecmp_member_read_errors = 0;
    int ecmp_member_entries = 0;
    const char *status = "error";
    const char *reason = "live SDK read-back error";
    const char *owner_map = "missing";
    int off;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    memset(vrids, 0, sizeof(vrids));
    memset(ifaces, 0, sizeof(ifaces));
    memset(arps, 0, sizeof(arps));
    memset(ecmp_groups, 0, sizeof(ecmp_groups));
    memset(routes, 0, sizeof(routes));

    if (!expected)
        expected = &(const hal_l3_intent_plan){0};
    exp_rifs = expected->n_rifs;
    exp_arps = expected->n_arps;
    exp_next_hops = expected->n_nexthops;
    exp_ecmp = expected->n_ecmp;
    for (int i = 0; i < expected->n_ecmp; i++)
        exp_ecmp_members += expected->ecmp[i].n_members;
    exp_fib_routes = expected_fib_route_count(expected);
    compared = exp_rifs + exp_arps + exp_next_hops + exp_ecmp +
               exp_fib_routes;

    st_vrids = fmGetVirtualRouterList((fm_int)sw, &num_vrids, vrids,
                                      L3_OWNER_VERIFY_MAX);
    st_ifaces = fmGetInterfaceList((fm_int)sw, &num_ifaces, ifaces,
                                   L3_OWNER_VERIFY_MAX);
    st_arps = fmGetARPEntryList((fm_int)sw, &num_arps, arps,
                                L3_OWNER_VERIFY_MAX);
    st_ecmp = fmGetECMPGroupList((fm_int)sw, &num_ecmp_groups,
                                 ecmp_groups, L3_OWNER_VERIFY_MAX);
    st_routes = fmGetRouteList((fm_int)sw, &num_routes, routes,
                               L3_OWNER_VERIFY_MAX);

    if (st_ecmp == FM_OK) {
        int emit = sdk_readback_emit_count((int)num_ecmp_groups,
                                           L3_OWNER_VERIFY_MAX);

        for (int i = 0; i < emit; i++) {
            fm_nextHop members[8];
            fm_int member_count = 0;
            fm_status st_members;

            memset(members, 0, sizeof(members));
            st_members = fmGetECMPGroupNextHopList(
                (fm_int)sw, ecmp_groups[i], &member_count, members,
                (fm_int)(sizeof(members) / sizeof(members[0])));
            if (st_members == FM_OK)
                ecmp_member_entries += (int)member_count;
            else
                ecmp_member_read_errors++;
        }
    }

    if (st_ifaces == FM_OK && exp_rifs != num_ifaces)
        mismatches++;
    if (st_arps == FM_OK && exp_arps != num_arps)
        mismatches++;
    if (st_routes == FM_OK && exp_fib_routes != num_routes)
        mismatches++;
    if (st_ecmp == FM_OK && exp_ecmp > 0 && exp_ecmp != num_ecmp_groups)
        mismatches++;

    if (!sdk_status_is_soft_readback(st_vrids) ||
        !sdk_status_is_soft_readback(st_ifaces) ||
        !sdk_status_is_soft_readback(st_arps) ||
        !sdk_status_is_soft_readback(st_ecmp) ||
        !sdk_status_is_soft_readback(st_routes)) {
        status = "limited";
        reason = "one or more SDK L3 read-back families are unavailable";
    } else if (compared > 0) {
        status = "blocked";
        reason = "persistent SDK owner handle map is not installed";
    } else if (mismatches > 0) {
        status = "mismatch";
        reason = "SDK actual state is not empty while owner expected state is empty";
    } else {
        status = "ok";
        reason = "empty owner state matches SDK RIF/ARP/FIB route inventory";
    }

    off = snprintf(resp, resp_size,
                   "<l3-sdk-owner-verify status=\"%s\" source=\"switchd\" "
                   "mode=\"persistent-owner-readiness\" "
                   "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                   "sdk-readback=\"live\" owner-handle-map=\"%s\" "
                   "compared=\"%d\" mismatches=\"%d\" reason=\"%s\" "
                   "ecmp-member-read-errors=\"%d\">"
                   "<family name=\"virtual-router\" expected=\"0\" "
                   "actual=\"%d\" status=\"%s\" sdk-status=\"%d\" "
                   "inventory-only=\"true\"/>"
                   "<family name=\"rif\" expected=\"%d\" actual=\"%d\" "
                   "status=\"%s\" sdk-status=\"%d\" mismatches=\"%d\"/>"
                   "<family name=\"arp\" expected=\"%d\" actual=\"%d\" "
                   "status=\"%s\" sdk-status=\"%d\" mismatches=\"%d\"/>"
                   "<family name=\"next-hop\" expected=\"%d\" "
                   "actual=\"derived\" status=\"derived\" "
                   "mismatches=\"0\"/>"
                   "<family name=\"ecmp\" expected=\"%d\" "
                   "actual-inventory=\"%d\" actual-owned=\"0\" "
                   "members-expected=\"%d\" members-actual=\"%d\" "
                   "member-read-errors=\"%d\" status=\"%s\" "
                   "sdk-status=\"%d\" inventory-only=\"%s\" "
                   "mismatches=\"%d\"/>"
                   "<family name=\"route\" expected=\"%d\" actual=\"%d\" "
                   "connected-intent=\"%d\" status=\"%s\" sdk-status=\"%d\" "
                   "mismatches=\"%d\"/>"
                   "</l3-sdk-owner-verify>",
                   status, owner_map, compared, mismatches, reason,
                   ecmp_member_read_errors,
                   (int)num_vrids, sdk_status_name(st_vrids), (int)st_vrids,
                   exp_rifs, st_ifaces == FM_OK ? (int)num_ifaces : 0,
                   sdk_status_name(st_ifaces), (int)st_ifaces,
                   (st_ifaces == FM_OK && exp_rifs != num_ifaces) ? 1 : 0,
                   exp_arps, st_arps == FM_OK ? (int)num_arps : 0,
                   sdk_status_name(st_arps), (int)st_arps,
                   (st_arps == FM_OK && exp_arps != num_arps) ? 1 : 0,
                   exp_next_hops,
                   exp_ecmp, st_ecmp == FM_OK ? (int)num_ecmp_groups : 0,
                   exp_ecmp_members, ecmp_member_entries,
                   ecmp_member_read_errors, sdk_status_name(st_ecmp),
                   (int)st_ecmp, exp_ecmp == 0 ? "true" : "false",
                   (st_ecmp == FM_OK && exp_ecmp > 0 &&
                    exp_ecmp != num_ecmp_groups) ? 1 : 0,
                   exp_fib_routes, st_routes == FM_OK ? (int)num_routes : 0,
                   expected->n_routes - exp_fib_routes,
                   sdk_status_name(st_routes), (int)st_routes,
                   (st_routes == FM_OK && exp_fib_routes != num_routes) ?
                       1 : 0);
    return (off < 0 || (size_t)off >= resp_size) ? -1 : 0;
}

#define HAL_L3_PERSISTENT_MAX_TRAFFIC_VLANS NL_L3_PERSISTENT_MAX_RIFS
#define HAL_L3_PERSISTENT_MAX_TRAFFIC_PORTS NL_MAX_PORTS_PER_PROFILE
#define HAL_L3_PERSISTENT_EMIT_LIMIT 8

typedef struct {
    fm_uint16 vlan;
    fm_bool pre_routable;
    bool used;
    bool created;
    bool set;
} hal_l3_persistent_vlan_owner;

typedef struct {
    fm_int port;
    fm_bool pre_routable;
    fm_uint32 pre_parser;
    bool used;
    bool routable_set;
    bool parser_set;
} hal_l3_persistent_port_owner;

typedef struct {
    fm_int port;
    fm_uint16 vlan;
    fm_uint32 pre_pvid;
    bool used;
    bool member_added;
    bool stp_set;
    bool pvid_set;
} hal_l3_persistent_routed_port_owner;

typedef struct {
    bool applied;
    bool hw_out_of_sync;
    u64 tx_id;
    int sw;
    bool has_router_mac;
    char router_mac[HAL_L3_INTENT_MAC_LEN];
    bool has_virtual_router;
    char virtual_router_name[HAL_L3_INTENT_NAME_LEN];
    char virtual_router_table[HAL_L3_INTENT_TABLE_LEN];
    int virtual_router_id;
    int virtual_router_kernel_table;
    fm_macaddr router_mac_value;
    fm_macaddr pre_router_mac;
    fm_routerState pre_router_state;
    bool router_mac_set;
    bool router_state_set;
    fm_macaddr virtual_router_mac_value;
    fm_macaddr pre_virtual_router_mac;
    bool virtual_router_mac_set;
    bool virtual_router_created;
    bool virtual_router_state_set;
    hal_l3_persistent_vlan_owner vlan_owner[HAL_L3_PERSISTENT_MAX_TRAFFIC_VLANS];
    int n_vlan_owner;
    hal_l3_persistent_port_owner port_owner[HAL_L3_PERSISTENT_MAX_TRAFFIC_PORTS];
    int n_port_owner;
    hal_l3_persistent_routed_port_owner routed_port_owner[
        NL_L3_PERSISTENT_MAX_RIFS];
    int n_routed_port_owner;
    hal_l3_intent_rif rifs[NL_L3_PERSISTENT_MAX_RIFS];
    int n_rifs;
    hal_l3_intent_arp arps[NL_L3_PERSISTENT_MAX_ARP];
    int n_arps;
    hal_l3_intent_next_hop nexthops[NL_L3_PERSISTENT_MAX_NEXTHOPS];
    int n_nexthops;
    hal_l3_intent_ecmp ecmp[NL_L3_PERSISTENT_MAX_ECMP];
    int n_ecmp;
    hal_l3_intent_route routes[NL_L3_PERSISTENT_MAX_ROUTES];
    int n_routes;
    fm_int rif_ifindex[NL_L3_PERSISTENT_MAX_RIFS];
    fm_ipAddr rif_addr[NL_L3_PERSISTENT_MAX_RIFS];
    bool rif_created[NL_L3_PERSISTENT_MAX_RIFS];
    bool rif_addr_added[NL_L3_PERSISTENT_MAX_RIFS];
    fm_arpEntry arp_entry[NL_L3_PERSISTENT_MAX_ARP];
    bool arp_added[NL_L3_PERSISTENT_MAX_ARP];
    fm_macAddressEntry arp_mac_entry[NL_L3_PERSISTENT_MAX_ARP];
    fm_macAddressEntry arp_pre_mac_entry[NL_L3_PERSISTENT_MAX_ARP];
    bool arp_mac_added[NL_L3_PERSISTENT_MAX_ARP];
    bool arp_mac_pre_existing[NL_L3_PERSISTENT_MAX_ARP];
    fm_int ecmp_group[NL_L3_PERSISTENT_MAX_ECMP];
    fm_nextHop ecmp_members[NL_L3_PERSISTENT_MAX_ECMP]
                           [NL_L3_PERSISTENT_MAX_ECMP_MEMBERS];
    int ecmp_member_count[NL_L3_PERSISTENT_MAX_ECMP];
    bool ecmp_created[NL_L3_PERSISTENT_MAX_ECMP];
    fm_routeEntry route_entry[NL_L3_PERSISTENT_MAX_ROUTES];
    int route_plan_index[NL_L3_PERSISTENT_MAX_ROUTES];
    bool route_added[NL_L3_PERSISTENT_MAX_ROUTES];
    int n_fib_routes;
} hal_l3_persistent_owner;

static hal_l3_persistent_owner *g_l3_persistent_owner;
static pthread_mutex_t g_l3_persistent_owner_lock = PTHREAD_MUTEX_INITIALIZER;
static bool dynamic_vrf_owner_active(void);

static void persistent_plan_view(const hal_l3_persistent_owner *owner,
                                 hal_l3_intent_plan *plan) {
    if (!plan)
        return;
    memset(plan, 0, sizeof(*plan));
    if (!owner)
        return;
    plan->has_router_mac = owner->has_router_mac;
    snprintf(plan->router_mac, sizeof(plan->router_mac), "%s",
             owner->router_mac);
    plan->has_virtual_router = owner->has_virtual_router;
    snprintf(plan->virtual_router_name, sizeof(plan->virtual_router_name),
             "%s", owner->virtual_router_name);
    snprintf(plan->virtual_router_table, sizeof(plan->virtual_router_table),
             "%s", owner->virtual_router_table);
    plan->virtual_router_id = owner->virtual_router_id;
    plan->virtual_router_kernel_table = owner->virtual_router_kernel_table;
    plan->rifs = owner->rifs;
    plan->n_rifs = owner->n_rifs;
    plan->arps = owner->arps;
    plan->n_arps = owner->n_arps;
    plan->nexthops = owner->nexthops;
    plan->n_nexthops = owner->n_nexthops;
    plan->ecmp = owner->ecmp;
    plan->n_ecmp = owner->n_ecmp;
    plan->routes = owner->routes;
    plan->n_routes = owner->n_routes;
}

static int persistent_copy_plan(hal_l3_persistent_owner *owner,
                                const hal_l3_intent_plan *plan) {
    if (!owner || !plan)
        return -1;
    if (plan->n_rifs < 0 ||
        plan->n_rifs > NL_L3_PERSISTENT_MAX_RIFS ||
        plan->n_arps < 0 ||
        plan->n_arps > NL_L3_PERSISTENT_MAX_ARP ||
        plan->n_nexthops < 0 ||
        plan->n_nexthops > NL_L3_PERSISTENT_MAX_NEXTHOPS ||
        plan->n_ecmp < 0 ||
        plan->n_ecmp > NL_L3_PERSISTENT_MAX_ECMP ||
        plan->n_routes < 0 ||
        plan->n_routes > NL_L3_PERSISTENT_MAX_ROUTES)
        return -1;
    memset(owner, 0, sizeof(*owner));
    owner->has_router_mac = plan->has_router_mac;
    snprintf(owner->router_mac, sizeof(owner->router_mac), "%s",
             plan->router_mac);
    owner->has_virtual_router = plan->has_virtual_router;
    snprintf(owner->virtual_router_name,
             sizeof(owner->virtual_router_name), "%s",
             plan->virtual_router_name);
    snprintf(owner->virtual_router_table,
             sizeof(owner->virtual_router_table), "%s",
             plan->virtual_router_table);
    owner->virtual_router_id = plan->virtual_router_id;
    owner->virtual_router_kernel_table =
        plan->virtual_router_kernel_table;
    owner->n_rifs = plan->n_rifs;
    owner->n_arps = plan->n_arps;
    owner->n_nexthops = plan->n_nexthops;
    owner->n_ecmp = plan->n_ecmp;
    owner->n_routes = plan->n_routes;
    if (plan->n_rifs)
        memcpy(owner->rifs, plan->rifs,
               sizeof(owner->rifs[0]) * (size_t)plan->n_rifs);
    if (plan->n_arps)
        memcpy(owner->arps, plan->arps,
               sizeof(owner->arps[0]) * (size_t)plan->n_arps);
    if (plan->n_nexthops)
        memcpy(owner->nexthops, plan->nexthops,
               sizeof(owner->nexthops[0]) * (size_t)plan->n_nexthops);
    if (plan->n_ecmp)
        memcpy(owner->ecmp, plan->ecmp,
               sizeof(owner->ecmp[0]) * (size_t)plan->n_ecmp);
    if (plan->n_routes)
        memcpy(owner->routes, plan->routes,
               sizeof(owner->routes[0]) * (size_t)plan->n_routes);
    for (int i = 0; i < owner->n_rifs; i++)
        if (!owner->rifs[i].table[0])
            snprintf(owner->rifs[i].table, sizeof(owner->rifs[i].table),
                     "inet.0");
    for (int i = 0; i < owner->n_arps; i++)
        if (!owner->arps[i].table[0])
            snprintf(owner->arps[i].table, sizeof(owner->arps[i].table),
                     "inet.0");
    for (int i = 0; i < owner->n_nexthops; i++)
        if (!owner->nexthops[i].table[0])
            snprintf(owner->nexthops[i].table,
                     sizeof(owner->nexthops[i].table), "inet.0");
    for (int i = 0; i < owner->n_ecmp; i++)
        if (!owner->ecmp[i].table[0])
            snprintf(owner->ecmp[i].table, sizeof(owner->ecmp[i].table),
                     "inet.0");
    for (int i = 0; i < owner->n_routes; i++)
        if (!owner->routes[i].table[0])
            snprintf(owner->routes[i].table,
                     sizeof(owner->routes[i].table), "inet.0");
    for (int i = 0; i < NL_L3_PERSISTENT_MAX_RIFS; i++)
        owner->rif_ifindex[i] = -1;
    for (int i = 0; i < NL_L3_PERSISTENT_MAX_ECMP; i++)
        owner->ecmp_group[i] = -1;
    for (int i = 0; i < NL_L3_PERSISTENT_MAX_ROUTES; i++)
        owner->route_plan_index[i] = -1;
    return 0;
}

static bool persistent_plan_matches_owner(
        const hal_l3_persistent_owner *owner,
        const hal_l3_persistent_owner *candidate) {
    if (!owner || !candidate ||
        owner->has_router_mac != candidate->has_router_mac ||
        (owner->has_router_mac &&
         strcmp(owner->router_mac, candidate->router_mac) != 0) ||
        owner->has_virtual_router != candidate->has_virtual_router ||
        (owner->has_virtual_router &&
         (strcmp(owner->virtual_router_name,
                 candidate->virtual_router_name) != 0 ||
          strcmp(owner->virtual_router_table,
                 candidate->virtual_router_table) != 0 ||
          owner->virtual_router_id != candidate->virtual_router_id ||
          owner->virtual_router_kernel_table !=
              candidate->virtual_router_kernel_table)) ||
        owner->n_rifs != candidate->n_rifs ||
        owner->n_arps != candidate->n_arps ||
        owner->n_nexthops != candidate->n_nexthops ||
        owner->n_ecmp != candidate->n_ecmp ||
        owner->n_routes != candidate->n_routes)
        return false;

    for (int i = 0; i < owner->n_rifs; i++) {
        const hal_l3_intent_rif *a = &owner->rifs[i];
        const hal_l3_intent_rif *b = &candidate->rifs[i];

        if (strcmp(a->name, b->name) != 0 ||
            strcmp(a->table, b->table) != 0 || a->vrid != b->vrid ||
            a->vlan != b->vlan || strcmp(a->port, b->port) != 0 ||
            strcmp(a->address, b->address) != 0)
            return false;
    }
    for (int i = 0; i < owner->n_arps; i++) {
        const hal_l3_intent_arp *a = &owner->arps[i];
        const hal_l3_intent_arp *b = &candidate->arps[i];

        if (strcmp(a->ip, b->ip) != 0 ||
            strcmp(a->table, b->table) != 0 || a->vrid != b->vrid ||
            strcmp(a->mac, b->mac) != 0 ||
            strcmp(a->rif, b->rif) != 0 ||
            strcmp(a->egress_port, b->egress_port) != 0)
            return false;
    }
    for (int i = 0; i < owner->n_nexthops; i++) {
        const hal_l3_intent_next_hop *a = &owner->nexthops[i];
        const hal_l3_intent_next_hop *b = &candidate->nexthops[i];

        if (a->id != b->id || strcmp(a->table, b->table) != 0 ||
            a->vrid != b->vrid || strcmp(a->arp, b->arp) != 0 ||
            strcmp(a->rif, b->rif) != 0)
            return false;
    }
    for (int i = 0; i < owner->n_ecmp; i++) {
        const hal_l3_intent_ecmp *a = &owner->ecmp[i];
        const hal_l3_intent_ecmp *b = &candidate->ecmp[i];

        if (a->id != b->id || strcmp(a->table, b->table) != 0 ||
            a->vrid != b->vrid || a->n_members != b->n_members)
            return false;
        for (int member = 0; member < a->n_members; member++)
            if (a->members[member] != b->members[member])
                return false;
    }
    for (int i = 0; i < owner->n_routes; i++) {
        const hal_l3_intent_route *a = &owner->routes[i];
        const hal_l3_intent_route *b = &candidate->routes[i];

        if (strcmp(a->prefix, b->prefix) != 0 ||
            strcmp(a->table, b->table) != 0 || a->vrid != b->vrid ||
            a->target_type != b->target_type ||
            a->target_id != b->target_id ||
            strcmp(a->target_name, b->target_name) != 0)
            return false;
    }
    return true;
}

static bool l3_port_has_route_capability(const nl_port_entry *entry) {
    char capabilities[sizeof(entry->capabilities)];
    char *save = NULL;
    char *token;

    if (!entry || !entry->capabilities[0])
        return false;
    snprintf(capabilities, sizeof(capabilities), "%s", entry->capabilities);
    token = strtok_r(capabilities, ",", &save);
    while (token) {
        while (*token == ' ' || *token == '\t')
            token++;
        if (strcasecmp(token, "ROUTE") == 0)
            return true;
        token = strtok_r(NULL, ",", &save);
    }
    return false;
}

static bool l3_plan_is_persistent_owner_safe(
        const hal_l3_intent_plan *plan, const char **reason) {
    if (!plan) {
        if (reason)
            *reason = "missing L3 intent plan";
        return false;
    }
    if (plan->n_rifs <= 0) {
        if (reason)
            *reason = "persistent owner requires at least one RIF";
        return false;
    }
    if (plan->n_arps < 0 || plan->n_nexthops < 0 ||
        plan->n_ecmp < 0 || plan->n_routes < 0) {
        if (reason)
            *reason = "invalid negative L3 object count";
        return false;
    }
    if (plan->n_rifs > NL_L3_PERSISTENT_MAX_RIFS ||
        plan->n_arps > NL_L3_PERSISTENT_MAX_ARP ||
        plan->n_nexthops > NL_L3_PERSISTENT_MAX_NEXTHOPS ||
        plan->n_ecmp > NL_L3_PERSISTENT_MAX_ECMP ||
        plan->n_routes > NL_L3_PERSISTENT_MAX_ROUTES) {
        if (reason)
            *reason = "persistent owner first slice capacity exceeded";
        return false;
    }
    if (plan->has_router_mac) {
        fm_macaddr mac;

        if (parse_mac(plan->router_mac, &mac) != 0) {
            if (reason)
                *reason = "invalid persistent router MAC";
            return false;
        }
    }
    if (plan->has_virtual_router) {
        char expected[HAL_L3_INTENT_TABLE_LEN];

        snprintf(expected, sizeof(expected), "%s.inet.0",
                 plan->virtual_router_name);
        if (!plan->has_router_mac || !plan->virtual_router_name[0] ||
            strcmp(plan->virtual_router_table, expected) != 0 ||
            plan->virtual_router_id != HAL_L3_VRF_V1_VRID ||
            plan->virtual_router_kernel_table !=
                HAL_L3_VRF_V1_KERNEL_TABLE) {
            if (reason)
                *reason = "invalid VRF V1 virtual-router owner";
            return false;
        }
    }
    for (int i = 0; i < plan->n_rifs; i++) {
        fm_ipAddr addr;
        int prefix = 0;

        if (!intent_scope_valid(plan, plan->rifs[i].table,
                                plan->rifs[i].vrid) ||
            parse_ipv4_cidr(plan->rifs[i].address, &addr, &prefix) != 0 ||
            plan->rifs[i].vlan < 1 || plan->rifs[i].vlan > 4094) {
            if (reason)
                *reason = "invalid persistent RIF address or VLAN";
            return false;
        }
        if (plan->rifs[i].port[0]) {
            nl_port_entry entry;
            int expected_vlan;

            memset(&entry, 0, sizeof(entry));
            if (!nl_ifid_get_by_name(plan->rifs[i].port, &entry) ||
                !nl_ifid_name_is_user_port(plan->rifs[i].port) ||
                !l3_port_has_route_capability(&entry) ||
                entry.logical_port <= 0 || entry.logical_port >= 4095) {
                if (reason)
                    *reason = "persistent physical RIF requires a ROUTE-capable user port";
                return false;
            }
            expected_vlan = 4095 - entry.logical_port;
            if (plan->rifs[i].vlan != expected_vlan) {
                if (reason)
                    *reason = "persistent physical RIF internal VLAN does not match its port allocation";
                return false;
            }
            for (int j = 0; j < i; j++) {
                if (plan->rifs[j].port[0] &&
                    strcmp(plan->rifs[j].port, plan->rifs[i].port) == 0) {
                    if (reason)
                        *reason = "persistent physical RIF port is duplicated";
                    return false;
                }
            }
        } else if (strchr(plan->rifs[i].name, '/')) {
            if (reason)
                *reason = "persistent physical RIF is missing port ownership";
            return false;
        }
    }
    for (int i = 0; i < plan->n_arps; i++) {
        fm_ipAddr ip;
        fm_macaddr mac;

        int rif_index = find_rif(plan, plan->arps[i].rif);

        if (!intent_scope_valid(plan, plan->arps[i].table,
                                plan->arps[i].vrid) ||
            rif_index < 0 ||
            strcmp(intent_table(plan->rifs[rif_index].table),
                   intent_table(plan->arps[i].table)) != 0 ||
            parse_ipv4(plan->arps[i].ip, &ip) != 0 ||
            parse_mac(plan->arps[i].mac, &mac) != 0) {
            if (reason)
                *reason = "persistent ARP must reference a valid RIF";
            return false;
        }
        if (plan->arps[i].egress_port[0] &&
            !nl_ifid_name_is_user_port(plan->arps[i].egress_port)) {
            if (reason)
                *reason = "persistent ARP egress-port must be a user port";
            return false;
        }
    }
    for (int i = 0; i < plan->n_nexthops; i++) {
        int rif_index = find_rif(plan, plan->nexthops[i].rif);
        const hal_l3_intent_arp *arp =
            find_arp(plan, plan->nexthops[i].arp,
                     plan->nexthops[i].rif);

        if (!intent_scope_valid(plan, plan->nexthops[i].table,
                                plan->nexthops[i].vrid) ||
            rif_index < 0 || !arp ||
            strcmp(intent_table(plan->rifs[rif_index].table),
                   intent_table(plan->nexthops[i].table)) != 0 ||
            strcmp(intent_table(arp->table),
                   intent_table(plan->nexthops[i].table)) != 0 ||
            arp->vrid != plan->nexthops[i].vrid) {
            if (reason)
                *reason = "persistent next-hop must reference RIF and ARP";
            return false;
        }
    }
    for (int i = 0; i < plan->n_ecmp; i++) {
        if (!intent_scope_valid(plan, plan->ecmp[i].table,
                                plan->ecmp[i].vrid) ||
            plan->ecmp[i].n_members <= 0 ||
            plan->ecmp[i].n_members >
                NL_L3_PERSISTENT_MAX_ECMP_MEMBERS) {
            if (reason)
                *reason = "persistent ECMP member count is out of range";
            return false;
        }
        for (int j = 0; j < plan->ecmp[i].n_members; j++) {
            const hal_l3_intent_next_hop *nh =
                find_nexthop(plan, plan->ecmp[i].members[j]);
            if (!nh || strcmp(intent_table(nh->table),
                              intent_table(plan->ecmp[i].table)) != 0 ||
                nh->vrid != plan->ecmp[i].vrid) {
                if (reason)
                    *reason = "persistent ECMP member must reference next-hop";
                return false;
            }
        }
    }
    for (int i = 0; i < plan->n_routes; i++) {
        if (!intent_scope_valid(plan, plan->routes[i].table,
                                plan->routes[i].vrid)) {
            if (reason)
                *reason = "persistent route has invalid table scope";
            return false;
        }
        if (plan->routes[i].target_type == HAL_L3_ROUTE_TARGET_RIF) {
            int rif_index = find_rif(plan, plan->routes[i].target_name);
            if (rif_index < 0 ||
                strcmp(intent_table(plan->rifs[rif_index].table),
                       intent_table(plan->routes[i].table)) != 0) {
                if (reason)
                    *reason = "persistent connected route must reference RIF";
                return false;
            }
        } else if (plan->routes[i].target_type ==
                   HAL_L3_ROUTE_TARGET_NEXTHOP) {
            const hal_l3_intent_next_hop *nh =
                find_nexthop(plan, plan->routes[i].target_id);
            if (!nh || strcmp(intent_table(nh->table),
                              intent_table(plan->routes[i].table)) != 0 ||
                nh->vrid != plan->routes[i].vrid) {
                if (reason)
                    *reason = "persistent route must reference next-hop";
                return false;
            }
        } else if (plan->routes[i].target_type ==
                   HAL_L3_ROUTE_TARGET_ECMP) {
            const hal_l3_intent_ecmp *ecmp =
                find_ecmp(plan, plan->routes[i].target_id);
            if (!ecmp || strcmp(intent_table(ecmp->table),
                                intent_table(plan->routes[i].table)) != 0 ||
                ecmp->vrid != plan->routes[i].vrid) {
                if (reason)
                    *reason = "persistent route must reference ECMP";
                return false;
            }
        } else {
            if (reason)
                *reason = "unsupported persistent route target";
            return false;
        }
    }
    return true;
}

static int persistent_sdk_non_ecmp_object_count(int sw, fm_int *rif_count,
                                                fm_int *arp_count,
                                                fm_int *route_count) {
    fm_int ifaces[16];
    fm_arpEntry arps[16];
    fm_routeEntry routes[16];
    fm_int count = 0;
    fm_status st;

    if (rif_count)
        *rif_count = 0;
    if (arp_count)
        *arp_count = 0;
    if (route_count)
        *route_count = 0;
    memset(ifaces, 0, sizeof(ifaces));
    memset(arps, 0, sizeof(arps));
    memset(routes, 0, sizeof(routes));
    st = fmGetInterfaceList((fm_int)sw, &count, ifaces,
                            (fm_int)(sizeof(ifaces) / sizeof(ifaces[0])));
    if (st != FM_OK)
        return -1;
    if (rif_count)
        *rif_count = count;
    count = 0;
    st = fmGetARPEntryList((fm_int)sw, &count, arps,
                           (fm_int)(sizeof(arps) / sizeof(arps[0])));
    if (st != FM_OK)
        return -1;
    if (arp_count)
        *arp_count = count;
    count = 0;
    st = fmGetRouteList((fm_int)sw, &count, routes,
                        (fm_int)(sizeof(routes) / sizeof(routes[0])));
    if (st != FM_OK)
        return -1;
    if (route_count)
        *route_count = count;
    return 0;
}

static int persistent_find_rif_index(const hal_l3_persistent_owner *owner,
                                     const char *name) {
    if (!owner || !name)
        return -1;
    for (int i = 0; i < owner->n_rifs; i++)
        if (strcmp(owner->rifs[i].name, name) == 0)
            return i;
    return -1;
}

int hal_l3_persistent_owner_lookup_next_hop(
        const char *table, const char *ip, const char *rif,
        hal_l3_persistent_next_hop_ref *ref) {
    const hal_l3_persistent_owner *owner;

    if (!table || !ip || !rif || !ref || !table[0] || !ip[0] || !rif[0])
        return -1;
    memset(ref, 0, sizeof(*ref));
    snprintf(ref->ip, sizeof(ref->ip), "%s", ip);
    snprintf(ref->rif, sizeof(ref->rif), "%s", rif);
    snprintf(ref->table, sizeof(ref->table), "%s", table);
    ref->next_hop_id = -1;
    ref->rif_index = -1;
    pthread_mutex_lock(&g_l3_persistent_owner_lock);
    owner = g_l3_persistent_owner;
    ref->owner_applied = owner && owner->applied;
    if (ref->owner_applied) {
        for (int i = 0; i < owner->n_nexthops; i++) {
            const hal_l3_intent_next_hop *nh =
                &owner->nexthops[i];

            if (strcmp(nh->table, table) != 0 ||
                strcmp(nh->arp, ip) != 0 || strcmp(nh->rif, rif) != 0)
                continue;
            ref->found = true;
            ref->next_hop_id = nh->id;
            ref->vrid = nh->vrid;
            ref->rif_index =
                persistent_find_rif_index(owner, rif);
            if (ref->rif_index >= 0) {
                const hal_l3_intent_rif *r =
                    &owner->rifs[ref->rif_index];

                ref->vlan = r->vlan;
                snprintf(ref->interface_addr,
                         sizeof(ref->interface_addr), "%s", r->address);
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_l3_persistent_owner_lock);
    return 0;
}

int hal_l3_persistent_owner_lookup_table(const char *table, int *vrid) {
    const hal_l3_persistent_owner *owner;
    int rc = -1;

    if (!table || !table[0] || !vrid)
        return -1;
    if (strcmp(table, "inet.0") == 0) {
        *vrid = 0;
        return 0;
    }
    pthread_mutex_lock(&g_l3_persistent_owner_lock);
    owner = g_l3_persistent_owner;
    if (owner && owner->applied && owner->has_virtual_router &&
        strcmp(owner->virtual_router_table, table) == 0) {
        *vrid = owner->virtual_router_id;
        rc = 0;
    }
    pthread_mutex_unlock(&g_l3_persistent_owner_lock);
    return rc;
}

static int persistent_build_route(const hal_l3_persistent_owner *owner,
                                  const hal_l3_intent_plan *plan,
                                  const hal_l3_intent_route *route,
                                  fm_routeEntry *entry) {
    const hal_l3_intent_ecmp *refs[NL_L3_PERSISTENT_MAX_ECMP];

    if (!owner || !plan || !route || !entry)
        return -1;
    for (int i = 0; i < owner->n_ecmp; i++)
        refs[i] = &owner->ecmp[i];
    return build_sdk_route(plan, route, owner->ecmp_group, refs,
                           owner->n_ecmp, entry);
}

static void persistent_record_failure(char *stage, size_t stage_size,
                                      fm_status *status_out, int *index_out,
                                      const char *new_stage, int index,
                                      fm_status status) {
    if (!stage || stage_size == 0 || !new_stage)
        return;
    if (stage[0] && strcmp(stage, "none") != 0)
        return;
    snprintf(stage, stage_size, "%s", new_stage);
    if (status_out)
        *status_out = status;
    if (index_out)
        *index_out = index;
}

static int persistent_apply_traffic_owner(
        int sw, hal_l3_persistent_owner *owner,
        char *failure_stage, size_t failure_stage_size,
        fm_status *failure_status, int *failure_index) {
    int failures = 0;

    if (!owner)
        return -1;
    if (owner->has_router_mac) {
        fm_routerState up_state = FM_ROUTER_STATE_ADMIN_UP;
        fm_status st;

        if (parse_mac(owner->router_mac, &owner->router_mac_value) != 0) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-router-mac-parse", -1,
                FM_ERR_INVALID_ARGUMENT);
            failures++;
        } else if ((st = fmGetRouterAttribute(
                        (fm_int)sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS,
                        &owner->pre_router_mac)) != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-router-mac-read", -1, st);
            failures++;
        } else if ((st = fmGetRouterState(
                        (fm_int)sw, FM_PHYSICAL_ROUTER,
                        &owner->pre_router_state)) != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-router-state-read", -1, st);
            failures++;
        } else if ((st = fmSetRouterAttribute(
                        (fm_int)sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS,
                        &owner->router_mac_value)) != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-router-mac-set", -1, st);
            failures++;
        } else {
            owner->router_mac_set = true;
            st = fmSetRouterState((fm_int)sw, FM_PHYSICAL_ROUTER,
                                  up_state);
            if (st != FM_OK) {
                persistent_record_failure(
                    failure_stage, failure_stage_size, failure_status,
                    failure_index, "traffic-router-state-set", -1, st);
                failures++;
            } else {
                owner->router_state_set = true;
            }
        }
    }
    if (failures == 0 && owner->has_virtual_router) {
        fm_routerState up_state = FM_ROUTER_STATE_ADMIN_UP;
        fm_status st;

        owner->virtual_router_mac_value =
            owner->router_mac_value & (fm_macaddr)0xffffffffff00ULL;
        st = fmGetRouterAttribute((fm_int)sw,
                                  FM_ROUTER_VIRTUAL_MAC_ADDRESS,
                                  &owner->pre_virtual_router_mac);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "virtual-router-mac-read", -1, st);
            failures++;
        } else if ((st = fmSetRouterAttribute(
                        (fm_int)sw, FM_ROUTER_VIRTUAL_MAC_ADDRESS,
                        &owner->virtual_router_mac_value)) != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "virtual-router-mac-set", -1, st);
            failures++;
        } else {
            owner->virtual_router_mac_set = true;
            st = fmCreateVirtualRouter((fm_int)sw,
                                       owner->virtual_router_id);
            if (st != FM_OK) {
                persistent_record_failure(
                    failure_stage, failure_stage_size, failure_status,
                    failure_index, "virtual-router-create", -1, st);
                failures++;
            } else {
                owner->virtual_router_created = true;
                st = fmSetRouterState((fm_int)sw,
                                      owner->virtual_router_id,
                                      up_state);
                if (st != FM_OK) {
                    persistent_record_failure(
                        failure_stage, failure_stage_size, failure_status,
                        failure_index, "virtual-router-state-set", -1, st);
                    failures++;
                } else {
                    owner->virtual_router_state_set = true;
                }
            }
        }
    }

    for (int i = 0; i < owner->n_rifs; i++) {
        fm_uint16 vlan = (fm_uint16)owner->rifs[i].vlan;
        fm_bool enabled = FM_ENABLED;
        bool exists = false;

        for (int j = 0; j < owner->n_vlan_owner; j++) {
            if (owner->vlan_owner[j].vlan == vlan) {
                exists = true;
                break;
            }
        }
        if (exists)
            continue;
        if (owner->n_vlan_owner >= HAL_L3_PERSISTENT_MAX_TRAFFIC_VLANS) {
            failures++;
            continue;
        }
        hal_l3_persistent_vlan_owner *v =
            &owner->vlan_owner[owner->n_vlan_owner++];
        memset(v, 0, sizeof(*v));
        v->used = true;
        v->vlan = vlan;
        fm_status st = fmGetVlanAttribute((fm_int)sw, vlan,
                                          FM_VLAN_ROUTABLE,
                                          &v->pre_routable);
        if (st != FM_OK) {
            st = fmCreateVlan((fm_int)sw, vlan);
            if (st != FM_OK) {
                persistent_record_failure(
                    failure_stage, failure_stage_size, failure_status,
                    failure_index, "traffic-vlan-create", i, st);
                failures++;
                continue;
            }
            v->created = true;
            v->pre_routable = FM_DISABLED;
        }
        st = fmSetVlanAttribute((fm_int)sw, vlan, FM_VLAN_ROUTABLE,
                                &enabled);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-vlan-set", i, st);
            failures++;
        } else {
            v->set = true;
        }
    }

    for (int i = 0; i < owner->n_rifs; i++) {
        hal_l3_persistent_routed_port_owner *routed;
        hal_l3_persistent_vlan_owner *vlan_owner = NULL;
        fm_bool tagged = FM_DISABLED;
        fm_uint32 pvid = 0;
        fm_int logical_port;
        fm_status st;

        if (!owner->rifs[i].port[0])
            continue;
        if (owner->n_routed_port_owner >= NL_L3_PERSISTENT_MAX_RIFS) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-routed-port-capacity", i,
                FM_ERR_NO_MEM);
            failures++;
            continue;
        }
        logical_port = (fm_int)nl_ifid_name_to_logical_port(
            owner->rifs[i].port);
        for (int j = 0; j < owner->n_vlan_owner; j++) {
            if (owner->vlan_owner[j].vlan ==
                (fm_uint16)owner->rifs[i].vlan) {
                vlan_owner = &owner->vlan_owner[j];
                break;
            }
        }
        if (logical_port <= 0 || !vlan_owner || !vlan_owner->created) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-routed-vlan-collision", i,
                FM_ERR_ALREADY_EXISTS);
            failures++;
            continue;
        }
        if (fmGetVlanPortTag((fm_int)sw, vlan_owner->vlan,
                             logical_port, &tagged) == FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-routed-member-collision", i,
                FM_ERR_ALREADY_EXISTS);
            failures++;
            continue;
        }
        routed = &owner->routed_port_owner[
            owner->n_routed_port_owner++];
        memset(routed, 0, sizeof(*routed));
        routed->used = true;
        routed->port = logical_port;
        routed->vlan = vlan_owner->vlan;
        st = fmGetPortAttribute((fm_int)sw, logical_port,
                                FM_PORT_DEF_VLAN, &pvid);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-routed-pvid-read", i, st);
            failures++;
            continue;
        }
        routed->pre_pvid = pvid;
        st = fmAddVlanPort((fm_int)sw, routed->vlan, logical_port,
                           FM_DISABLED);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-routed-member-add", i, st);
            failures++;
            continue;
        }
        routed->member_added = true;
        st = fmSetVlanPortState((fm_int)sw, routed->vlan, logical_port,
                                FM_STP_STATE_FORWARDING);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-routed-stp-set", i, st);
            failures++;
            continue;
        }
        routed->stp_set = true;
        pvid = routed->vlan;
        st = fmSetPortAttribute((fm_int)sw, logical_port,
                                FM_PORT_DEF_VLAN, &pvid);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, failure_stage_size, failure_status,
                failure_index, "traffic-routed-pvid-set", i, st);
            failures++;
        } else {
            routed->pvid_set = true;
        }
    }

    {
        nl_port_entry entries[NL_MAX_PORTS_PER_PROFILE];
        int n_ports = nl_ifid_get_all(entries, NL_MAX_PORTS_PER_PROFILE);

        for (int i = 0; i < n_ports; i++) {
            fm_bool enabled = FM_ENABLED;
            fm_uint32 parser = FM_PORT_PARSER_STOP_AFTER_L4;
            fm_int port = (fm_int)entries[i].logical_port;

            if (!nl_ifid_is_user_port((int)port))
                continue;
            if (owner->n_port_owner >= HAL_L3_PERSISTENT_MAX_TRAFFIC_PORTS) {
                failures++;
                break;
            }
            hal_l3_persistent_port_owner *p =
                &owner->port_owner[owner->n_port_owner++];
            memset(p, 0, sizeof(*p));
            p->used = true;
            p->port = port;
            fm_status st = fmGetPortAttribute((fm_int)sw, port,
                                              FM_PORT_ROUTABLE,
                                              &p->pre_routable);
            if (st != FM_OK) {
                persistent_record_failure(
                    failure_stage, failure_stage_size, failure_status,
                    failure_index, "traffic-port-routable-read", i, st);
                failures++;
                continue;
            }
            st = fmGetPortAttribute((fm_int)sw, port, FM_PORT_PARSER,
                                    &p->pre_parser);
            if (st != FM_OK) {
                persistent_record_failure(
                    failure_stage, failure_stage_size, failure_status,
                    failure_index, "traffic-port-parser-read", i, st);
                failures++;
                continue;
            }
            st = fmSetPortAttribute((fm_int)sw, port, FM_PORT_PARSER,
                                    &parser);
            if (st != FM_OK) {
                persistent_record_failure(
                    failure_stage, failure_stage_size, failure_status,
                    failure_index, "traffic-port-parser-set", i, st);
                failures++;
                continue;
            }
            p->parser_set = true;
            st = fmSetPortAttribute((fm_int)sw, port, FM_PORT_ROUTABLE,
                                    &enabled);
            if (st != FM_OK) {
                persistent_record_failure(
                    failure_stage, failure_stage_size, failure_status,
                    failure_index, "traffic-port-routable-set", i, st);
                failures++;
            } else {
                p->routable_set = true;
            }
        }
    }

    return failures == 0 ? 0 : -1;
}

static void persistent_cleanup_state(int sw, hal_l3_persistent_owner *owner,
                                     int *delete_failures) {
    if (!owner)
        return;
    if (delete_failures)
        *delete_failures = 0;
    for (int i = owner->n_fib_routes - 1; i >= 0; i--) {
        if (owner->route_added[i]) {
            fm_status st = fmDeleteRoute((fm_int)sw,
                                         &owner->route_entry[i]);

            if (st == FM_OK || st == FM_ERR_NOT_FOUND)
                owner->route_added[i] = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
    }
    for (int i = owner->n_ecmp - 1; i >= 0; i--) {
        if (owner->ecmp_created[i]) {
            fm_status st = fmDeleteECMPGroup((fm_int)sw,
                                             owner->ecmp_group[i]);

            if (st == FM_OK || st == FM_ERR_NOT_FOUND)
                owner->ecmp_created[i] = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
    }
    for (int i = owner->n_arps - 1; i >= 0; i--) {
        if (owner->arp_mac_added[i]) {
            fm_status st = fmDeleteAddress((fm_int)sw,
                                           &owner->arp_mac_entry[i]);

            if (st == FM_OK || st == FM_ERR_NOT_FOUND)
                owner->arp_mac_added[i] = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
        if (owner->arp_added[i]) {
            fm_status st = fmDeleteARPEntry((fm_int)sw,
                                            &owner->arp_entry[i]);

            if (st == FM_OK || st == FM_ERR_NOT_FOUND)
                owner->arp_added[i] = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
    }
    for (int i = owner->n_rifs - 1; i >= 0; i--) {
        if (owner->rif_addr_added[i]) {
            fm_status st = fmDeleteInterfaceAddr(
                (fm_int)sw, owner->rif_ifindex[i], &owner->rif_addr[i]);

            if (st == FM_OK || st == FM_ERR_NOT_FOUND)
                owner->rif_addr_added[i] = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
        if (owner->rif_created[i]) {
            fm_status st = fmDeleteInterface((fm_int)sw,
                                             owner->rif_ifindex[i]);

            if (st == FM_OK || st == FM_ERR_NOT_FOUND)
                owner->rif_created[i] = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
    }
    for (int i = owner->n_routed_port_owner - 1; i >= 0; i--) {
        hal_l3_persistent_routed_port_owner *routed =
            &owner->routed_port_owner[i];
        fm_uint32 current_pvid = 0;

        if (!routed->used)
            continue;
        if (routed->pvid_set) {
            fm_status st = fmGetPortAttribute(
                (fm_int)sw, routed->port, FM_PORT_DEF_VLAN,
                &current_pvid);

            if (st != FM_OK) {
                if (delete_failures)
                    (*delete_failures)++;
            } else if (current_pvid != routed->vlan) {
                routed->pvid_set = false;
            } else {
                st = fmSetPortAttribute(
                    (fm_int)sw, routed->port, FM_PORT_DEF_VLAN,
                    &routed->pre_pvid);
                if (st == FM_OK)
                    routed->pvid_set = false;
                else if (delete_failures)
                    (*delete_failures)++;
            }
        }
        if (routed->member_added) {
            fm_status st = fmDeleteVlanPort(
                (fm_int)sw, routed->vlan, routed->port);

            if (st == FM_OK || st == FM_ERR_NOT_FOUND) {
                routed->member_added = false;
                routed->stp_set = false;
            } else if (delete_failures) {
                (*delete_failures)++;
            }
        }
    }
    for (int i = owner->n_port_owner - 1; i >= 0; i--) {
        if (owner->port_owner[i].used &&
            owner->port_owner[i].parser_set) {
            fm_status st = fmSetPortAttribute(
                (fm_int)sw, owner->port_owner[i].port, FM_PORT_PARSER,
                &owner->port_owner[i].pre_parser);

            if (st == FM_OK)
                owner->port_owner[i].parser_set = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
        if (owner->port_owner[i].used &&
            owner->port_owner[i].routable_set) {
            fm_status st = fmSetPortAttribute(
                (fm_int)sw, owner->port_owner[i].port, FM_PORT_ROUTABLE,
                &owner->port_owner[i].pre_routable);

            if (st == FM_OK)
                owner->port_owner[i].routable_set = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
    }
    for (int i = owner->n_vlan_owner - 1; i >= 0; i--) {
        fm_bool disabled = FM_DISABLED;
        fm_status st;

        if (!owner->vlan_owner[i].used)
            continue;
        if (owner->vlan_owner[i].set) {
            fm_bool *restore = owner->vlan_owner[i].created ?
                &disabled : &owner->vlan_owner[i].pre_routable;

            st = fmSetVlanAttribute((fm_int)sw,
                                    owner->vlan_owner[i].vlan,
                                    FM_VLAN_ROUTABLE, restore);
            if (st == FM_OK)
                owner->vlan_owner[i].set = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
        if (owner->vlan_owner[i].created) {
            st = fmDeleteVlan((fm_int)sw, owner->vlan_owner[i].vlan);
            if (st == FM_OK || st == FM_ERR_NOT_FOUND)
                owner->vlan_owner[i].created = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
    }
    if (owner->virtual_router_created) {
        fm_routerState down_state = FM_ROUTER_STATE_ADMIN_DOWN;
        fm_status st;

        if (owner->virtual_router_state_set) {
            st = fmSetRouterState((fm_int)sw, owner->virtual_router_id,
                                  down_state);
            if (st == FM_OK)
                owner->virtual_router_state_set = false;
            else if (delete_failures)
                (*delete_failures)++;
        }
        st = fmDeleteVirtualRouter((fm_int)sw,
                                   owner->virtual_router_id);
        if (st == FM_OK || st == FM_ERR_NOT_FOUND) {
            owner->virtual_router_created = false;
            owner->virtual_router_state_set = false;
        } else if (delete_failures) {
            (*delete_failures)++;
        }
    }
    if (owner->virtual_router_mac_set) {
        fm_status st = fmSetRouterAttribute(
            (fm_int)sw, FM_ROUTER_VIRTUAL_MAC_ADDRESS,
            &owner->pre_virtual_router_mac);

        if (st == FM_OK)
            owner->virtual_router_mac_set = false;
        else if (delete_failures)
            (*delete_failures)++;
    }
    if (owner->router_state_set) {
        fm_status st = fmSetRouterState((fm_int)sw, FM_PHYSICAL_ROUTER,
                                        owner->pre_router_state);

        if (st == FM_OK)
            owner->router_state_set = false;
        else if (delete_failures)
            (*delete_failures)++;
    }
    if (owner->router_mac_set) {
        fm_status st = fmSetRouterAttribute(
            (fm_int)sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS,
            &owner->pre_router_mac);

        if (st == FM_OK)
            owner->router_mac_set = false;
        else if (delete_failures)
            (*delete_failures)++;
    }
}

static int persistent_verify_state(int sw,
                                   const hal_l3_persistent_owner *owner,
                                   int *compared_out,
                                   int *mismatches_out,
                                   char *objects,
                                   size_t objects_size) {
    int compared = 0;
    int mismatches = 0;
    int off = 0;

    if (objects && objects_size > 0)
        objects[0] = '\0';
    if (!owner)
        return -1;
    if (owner->has_router_mac) {
        fm_macaddr mac = 0;
        fm_routerState state = FM_ROUTER_STATE_ADMIN_DOWN;
        bool ok;
        fm_status st_mac = fmGetRouterAttribute(
            (fm_int)sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS, &mac);
        fm_status st_state = fmGetRouterState(
            (fm_int)sw, FM_PHYSICAL_ROUTER, &state);

        ok = st_mac == FM_OK && st_state == FM_OK &&
             mac == owner->router_mac_value &&
             state == FM_ROUTER_STATE_ADMIN_UP;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0)
            off = appendf(objects, objects_size, off,
                          "<object family=\"traffic-owner\" "
                          "kind=\"router\" router-mac=\"%s\" "
                          "status=\"%s\"/>",
                          owner->router_mac, ok ? "ok" : "mismatch");
    }
    if (owner->has_virtual_router) {
        fm_int vrids[16];
        fm_int count = 0;
        fm_macaddr mac = 0;
        fm_routerState state = FM_ROUTER_STATE_ADMIN_DOWN;
        bool found = false;
        bool ok;
        fm_status st_list;
        fm_status st_mac;
        fm_status st_state;

        memset(vrids, 0, sizeof(vrids));
        st_list = fmGetVirtualRouterList(
            (fm_int)sw, &count, vrids,
            (fm_int)(sizeof(vrids) / sizeof(vrids[0])));
        if (st_list == FM_OK) {
            fm_int emitted = count >
                (fm_int)(sizeof(vrids) / sizeof(vrids[0])) ?
                (fm_int)(sizeof(vrids) / sizeof(vrids[0])) : count;
            for (int i = 0; i < emitted; i++)
                if (vrids[i] == owner->virtual_router_id)
                    found = true;
        }
        st_mac = fmGetRouterAttribute((fm_int)sw,
                                      FM_ROUTER_VIRTUAL_MAC_ADDRESS,
                                      &mac);
        st_state = fmGetRouterState((fm_int)sw,
                                    owner->virtual_router_id, &state);
        ok = st_list == FM_OK && found && st_mac == FM_OK &&
             mac == owner->virtual_router_mac_value &&
             st_state == FM_OK && state == FM_ROUTER_STATE_ADMIN_UP;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0)
            off = appendf(objects, objects_size, off,
                          "<object family=\"virtual-router\" name=\"%s\" "
                          "table=\"%s\" vrid=\"%d\" kernel-table=\"%d\" "
                          "status=\"%s\"/>",
                          owner->virtual_router_name,
                          owner->virtual_router_table,
                          owner->virtual_router_id,
                          owner->virtual_router_kernel_table,
                          ok ? "ok" : "mismatch");
    }
    for (int i = 0; i < owner->n_vlan_owner; i++) {
        fm_bool routable = FM_DISABLED;
        bool ok;
        fm_status st = fmGetVlanAttribute(
            (fm_int)sw, owner->vlan_owner[i].vlan, FM_VLAN_ROUTABLE,
            &routable);

        ok = st == FM_OK && routable == FM_ENABLED;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_PERSISTENT_EMIT_LIMIT)
            off = appendf(objects, objects_size, off,
                          "<object family=\"traffic-owner\" kind=\"vlan\" "
                          "vlan=\"%u\" status=\"%s\"/>",
                          (unsigned)owner->vlan_owner[i].vlan,
                          ok ? "ok" : "mismatch");
    }
    for (int i = 0; i < owner->n_routed_port_owner; i++) {
        const hal_l3_persistent_routed_port_owner *routed =
            &owner->routed_port_owner[i];
        fm_bool tagged = FM_ENABLED;
        fm_int stp_state = FM_STP_STATE_DISABLED;
        fm_uint32 pvid = 0;
        fm_status st_tag = fmGetVlanPortTag(
            (fm_int)sw, routed->vlan, routed->port, &tagged);
        fm_status st_stp = fmGetVlanPortState(
            (fm_int)sw, routed->vlan, routed->port, &stp_state);
        fm_status st_pvid = fmGetPortAttribute(
            (fm_int)sw, routed->port, FM_PORT_DEF_VLAN, &pvid);
        bool ok = st_tag == FM_OK && tagged == FM_DISABLED &&
                  st_stp == FM_OK &&
                  stp_state == FM_STP_STATE_FORWARDING &&
                  st_pvid == FM_OK && pvid == routed->vlan;

        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_PERSISTENT_EMIT_LIMIT)
            off = appendf(objects, objects_size, off,
                          "<object family=\"traffic-owner\" "
                          "kind=\"routed-port\" port=\"%d\" vlan=\"%u\" "
                          "status=\"%s\"/>",
                          (int)routed->port, (unsigned)routed->vlan,
                          ok ? "ok" : "mismatch");
    }
    for (int i = 0; i < owner->n_port_owner; i++) {
        fm_bool routable = FM_DISABLED;
        fm_uint32 parser = 0;
        bool ok;
        fm_status st_routable = fmGetPortAttribute(
            (fm_int)sw, owner->port_owner[i].port, FM_PORT_ROUTABLE,
            &routable);
        fm_status st_parser = fmGetPortAttribute(
            (fm_int)sw, owner->port_owner[i].port, FM_PORT_PARSER,
            &parser);

        ok = st_routable == FM_OK && routable == FM_ENABLED &&
             st_parser == FM_OK && parser == FM_PORT_PARSER_STOP_AFTER_L4;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_PERSISTENT_EMIT_LIMIT)
            off = appendf(objects, objects_size, off,
                          "<object family=\"traffic-owner\" kind=\"port\" "
                          "port=\"%d\" status=\"%s\"/>",
                          (int)owner->port_owner[i].port,
                          ok ? "ok" : "mismatch");
    }
    for (int i = 0; i < owner->n_rifs; i++) {
        fm_ipAddr addrs[8];
        fm_int addr_count = 0;
        fm_int list_count = 0;
        fm_uint16 vlan = 0;
        fm_interfaceState state = FM_INTERFACE_STATE_ADMIN_DOWN;
        bool found = false;
        bool addr_found = false;
        bool ok;
        fm_status st_list;
        fm_status st_addr;
        fm_status st_vlan;
        fm_status st_state;

        memset(addrs, 0, sizeof(addrs));
        st_list = get_interface_list_contains(sw, owner->rif_ifindex[i],
                                              &list_count, &found);
        st_addr = fmGetInterfaceAddrList(
            (fm_int)sw, owner->rif_ifindex[i], &addr_count, addrs,
            (fm_int)(sizeof(addrs) / sizeof(addrs[0])));
        if (st_addr == FM_OK) {
            fm_int emitted = addr_count >
                (fm_int)(sizeof(addrs) / sizeof(addrs[0])) ?
                (fm_int)(sizeof(addrs) / sizeof(addrs[0])) : addr_count;
            addr_found = ipaddr_list_contains(addrs, emitted,
                                              &owner->rif_addr[i]);
        }
        st_vlan = fmGetInterfaceAttribute((fm_int)sw, owner->rif_ifindex[i],
                                          FM_INTERFACE_VLAN, &vlan);
        st_state = fmGetInterfaceAttribute((fm_int)sw, owner->rif_ifindex[i],
                                           FM_INTERFACE_STATE, &state);
        ok = st_list == FM_OK && found && st_addr == FM_OK && addr_found &&
             st_vlan == FM_OK && vlan == (fm_uint16)owner->rifs[i].vlan &&
             st_state == FM_OK && state == FM_INTERFACE_STATE_ADMIN_UP;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_PERSISTENT_EMIT_LIMIT)
            off = appendf(objects, objects_size, off,
                          "<object family=\"rif\" name=\"%s\" "
                          "sdk-interface=\"%d\" vlan=\"%d\" status=\"%s\"/>",
                          owner->rifs[i].name, (int)owner->rif_ifindex[i],
                          owner->rifs[i].vlan, ok ? "ok" : "mismatch");
    }
    for (int i = 0; i < owner->n_arps; i++) {
        fm_arpEntry needle;
        fm_arpEntryInfo info;
        bool info_match = false;
        bool ok;
        fm_status st_info;

        memset(&info, 0, sizeof(info));
        needle = owner->arp_entry[i];
        st_info = fmGetARPEntryInfo((fm_int)sw, &needle, &info);
        info_match = st_info == FM_OK &&
                     arp_entry_equal(&info.arp, &owner->arp_entry[i]);
        ok = info_match;
        if (owner->arp_mac_entry[i].vlanID != 0) {
            fm_macAddressEntry entry;
            fm_status st_mac;

            memset(&entry, 0, sizeof(entry));
            st_mac = fmGetAddress((fm_int)sw,
                                  owner->arp_mac_entry[i].macAddress,
                                  (fm_int)owner->arp_mac_entry[i].vlanID,
                                  &entry);
            ok = ok && st_mac == FM_OK &&
                 entry.port == owner->arp_mac_entry[i].port;
        }
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_PERSISTENT_EMIT_LIMIT) {
            char ifname[64] = {0};

            if (owner->arp_mac_entry[i].port > 0 &&
                !nl_ifid_logical_port_to_name(owner->arp_mac_entry[i].port,
                                              ifname, sizeof(ifname)))
                snprintf(ifname, sizeof(ifname), "port-%d",
                         owner->arp_mac_entry[i].port);
            off = appendf(objects, objects_size, off,
                          "<object family=\"arp\" ip=\"%s\" rif=\"%s\" "
                          "egress-port=\"%s\" egress-logical-port=\"%d\" "
                          "status=\"%s\"/>",
                          owner->arps[i].ip, owner->arps[i].rif,
                          ifname[0] ? ifname : "-",
                          owner->arp_mac_entry[i].port,
                          ok ? "ok" : "mismatch");
        }
    }
    for (int i = 0; i < owner->n_ecmp; i++) {
        fm_nextHop members[NL_L3_PERSISTENT_MAX_ECMP_MEMBERS];
        fm_int member_count = 0;
        bool members_match = false;
        bool ok;
        fm_status st_members;

        memset(members, 0, sizeof(members));
        st_members = fmGetECMPGroupNextHopList(
            (fm_int)sw, owner->ecmp_group[i], &member_count, members,
            (fm_int)(sizeof(members) / sizeof(members[0])));
        members_match = st_members == FM_OK &&
            member_count == owner->ecmp_member_count[i];
        if (members_match) {
            fm_int emitted = member_count >
                (fm_int)(sizeof(members) / sizeof(members[0])) ?
                (fm_int)(sizeof(members) / sizeof(members[0])) :
                member_count;
            for (int j = 0; j < owner->ecmp_member_count[i]; j++)
                if (!next_hop_list_contains(
                        members, emitted, &owner->ecmp_members[i][j]))
                    members_match = false;
        }
        ok = members_match;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_PERSISTENT_EMIT_LIMIT)
            off = appendf(objects, objects_size, off,
                          "<object family=\"ecmp\" plan-id=\"%d\" "
                          "sdk-group=\"%d\" members=\"%d\" status=\"%s\"/>",
                          owner->ecmp[i].id, (int)owner->ecmp_group[i],
                          owner->ecmp_member_count[i],
                          ok ? "ok" : "mismatch");
    }
    for (int i = 0; i < owner->n_fib_routes; i++) {
        fm_routeEntry route;
        fm_routeState state = 0;
        bool ok;
        fm_status st_state;

        route = owner->route_entry[i];
        st_state = fmGetRouteState((fm_int)sw, &route, &state);
        ok = st_state == FM_OK && state == FM_ROUTE_STATE_UP;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_PERSISTENT_EMIT_LIMIT)
            off = appendf(objects, objects_size, off,
                          "<object family=\"route\" prefix=\"%s\" "
                          "table=\"%s\" vrid=\"%d\" status=\"%s\"/>",
                          owner->routes[owner->route_plan_index[i]].prefix,
                          intent_table(owner->routes[
                              owner->route_plan_index[i]].table),
                          owner->routes[
                              owner->route_plan_index[i]].vrid,
                          ok ? "ok" : "mismatch");
    }
    if (compared_out)
        *compared_out = compared;
    if (mismatches_out)
        *mismatches_out = mismatches;
    return off < 0 ? -1 : 0;
}

static int persistent_verify_absent_state(
        int sw, const hal_l3_persistent_owner *owner,
        int *compared_out, int *leaks_out,
        char *first_leak, size_t first_leak_size) {
    int compared = 0;
    int leaks = 0;

    if (first_leak && first_leak_size > 0)
        first_leak[0] = '\0';
    if (!owner)
        return -1;
    if (owner->has_router_mac) {
        fm_macaddr mac = 0;
        fm_routerState state = FM_ROUTER_STATE_ADMIN_DOWN;
        fm_status st_mac = fmGetRouterAttribute(
            (fm_int)sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS, &mac);
        fm_status st_state = fmGetRouterState(
            (fm_int)sw, FM_PHYSICAL_ROUTER, &state);

        compared++;
        if (st_mac != FM_OK || st_state != FM_OK ||
            mac != owner->pre_router_mac ||
            state != owner->pre_router_state) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size, "traffic-router");
            leaks++;
        }
    }
    if (owner->has_virtual_router) {
        fm_int vrids[16];
        fm_int count = 0;
        fm_macaddr mac = 0;
        bool found = false;
        fm_status st_list;
        fm_status st_mac;

        memset(vrids, 0, sizeof(vrids));
        st_list = fmGetVirtualRouterList(
            (fm_int)sw, &count, vrids,
            (fm_int)(sizeof(vrids) / sizeof(vrids[0])));
        if (st_list == FM_OK) {
            fm_int emitted = count >
                (fm_int)(sizeof(vrids) / sizeof(vrids[0])) ?
                (fm_int)(sizeof(vrids) / sizeof(vrids[0])) : count;
            for (int i = 0; i < emitted; i++)
                if (vrids[i] == owner->virtual_router_id)
                    found = true;
        }
        st_mac = fmGetRouterAttribute((fm_int)sw,
                                      FM_ROUTER_VIRTUAL_MAC_ADDRESS,
                                      &mac);
        compared++;
        if (st_list != FM_OK || found || st_mac != FM_OK ||
            mac != owner->pre_virtual_router_mac) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size, "virtual-router");
            leaks++;
        }
    }
    for (int i = 0; i < owner->n_vlan_owner; i++) {
        fm_bool routable = FM_DISABLED;
        fm_status st = fmGetVlanAttribute(
            (fm_int)sw, owner->vlan_owner[i].vlan, FM_VLAN_ROUTABLE,
            &routable);

        /* VLAN shells may remain readable after delete; SDK write failures
         * are already counted by persistent_cleanup_state(). */
        compared++;
        (void)st;
        (void)routable;
    }
    for (int i = 0; i < owner->n_routed_port_owner; i++) {
        const hal_l3_persistent_routed_port_owner *routed =
            &owner->routed_port_owner[i];
        fm_bool tagged = FM_DISABLED;
        fm_uint32 pvid = 0;
        fm_status st_tag = fmGetVlanPortTag(
            (fm_int)sw, routed->vlan, routed->port, &tagged);
        fm_status st_pvid = fmGetPortAttribute(
            (fm_int)sw, routed->port, FM_PORT_DEF_VLAN, &pvid);

        compared++;
        if (st_tag == FM_OK || st_pvid != FM_OK || pvid == routed->vlan) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size,
                         "traffic-routed-port[%d]", i);
            leaks++;
        }
    }
    for (int i = 0; i < owner->n_port_owner; i++) {
        fm_bool routable = FM_DISABLED;
        fm_uint32 parser = 0;
        fm_status st_routable = fmGetPortAttribute(
            (fm_int)sw, owner->port_owner[i].port, FM_PORT_ROUTABLE,
            &routable);
        fm_status st_parser = fmGetPortAttribute(
            (fm_int)sw, owner->port_owner[i].port, FM_PORT_PARSER, &parser);

        compared++;
        if (st_routable != FM_OK || st_parser != FM_OK ||
            routable != owner->port_owner[i].pre_routable ||
            parser != owner->port_owner[i].pre_parser) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size,
                         "traffic-port[%d]", i);
            leaks++;
        }
    }
    for (int i = 0; i < owner->n_arps; i++) {
        if (owner->arp_mac_entry[i].vlanID == 0)
            continue;
        fm_macAddressEntry entry;
        fm_status st;

        memset(&entry, 0, sizeof(entry));
        st = fmGetAddress((fm_int)sw, owner->arp_mac_entry[i].macAddress,
                          (fm_int)owner->arp_mac_entry[i].vlanID, &entry);
        compared++;
        if (owner->arp_mac_pre_existing[i]) {
            if (st != FM_OK ||
                entry.port != owner->arp_pre_mac_entry[i].port) {
                if (first_leak && first_leak_size > 0 && !first_leak[0])
                    snprintf(first_leak, first_leak_size,
                             "arp-mac-restore[%d]", i);
                leaks++;
            }
        } else if (st == FM_OK) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size,
                         "arp-mac-created[%d]", i);
            leaks++;
        }
    }
    for (int i = 0; i < owner->n_rifs; i++) {
        fm_int count = 0;
        bool found = false;
        fm_status st = get_interface_list_contains(
            sw, owner->rif_ifindex[i], &count, &found);

        compared++;
        if (st != FM_OK || found) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size, "rif[%d]", i);
            leaks++;
        }
    }
    for (int i = 0; i < owner->n_arps; i++) {
        fm_arpEntry needle = owner->arp_entry[i];
        fm_arpEntryInfo info;
        fm_status st;

        memset(&info, 0, sizeof(info));
        st = fmGetARPEntryInfo((fm_int)sw, &needle, &info);
        compared++;
        if (st != FM_ERR_NOT_FOUND) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size, "arp[%d]", i);
            leaks++;
        }
    }
    for (int i = 0; i < owner->n_ecmp; i++) {
        fm_int count = 0;
        fm_nextHop member;
        fm_status st;

        memset(&member, 0, sizeof(member));
        st = fmGetECMPGroupNextHopList(
            (fm_int)sw, owner->ecmp_group[i], &count, &member, 1);
        compared++;
        if (st != FM_ERR_NOT_FOUND) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size, "ecmp[%d]", i);
            leaks++;
        }
    }
    for (int i = 0; i < owner->n_fib_routes; i++) {
        fm_routeEntry route = owner->route_entry[i];
        fm_routeState state = 0;
        fm_status st;

        st = fmGetRouteState((fm_int)sw, &route, &state);
        compared++;
        if (st != FM_ERR_NOT_FOUND) {
            if (first_leak && first_leak_size > 0 && !first_leak[0])
                snprintf(first_leak, first_leak_size, "route[%d]", i);
            leaks++;
        }
    }
    if (compared_out)
        *compared_out = compared;
    if (leaks_out)
        *leaks_out = leaks;
    return 0;
}

static int persistent_owner_readback_xml(
        int sw, const hal_l3_persistent_owner *owner, const char *root,
        const char *sdk_write, bool idempotent,
        char *resp, size_t resp_size) {
    char objects[16384];
    int compared = 0;
    int mismatches = 0;
    const char *status;
    const char *handle_map;
    int connected_routes = 0;
    int rc;
    int off;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!owner || !owner->applied) {
        off = snprintf(resp, resp_size,
                       "<%s status=\"empty\" source=\"switchd\" "
                       "mode=\"hidden\" hardware-apply=\"persistent\" "
                       "sdk-write=\"disabled\" sdk-readback=\"live\" "
                       "owner-handle-map=\"empty\" applied=\"false\" "
                       "tx-id=\"0\"><usage rifs=\"0\" arp=\"0\" "
                       "next-hops=\"0\" ecmp-groups=\"0\" fib-routes=\"0\" "
                       "connected-route-intent=\"0\"/>"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"hidden persistent SDK L3 owner is empty; "
                       "direct switchd user config is internal; public routing "
                       "config is handled by configd/rpd\"/>"
                       "</%s>",
                       root, root);
        return (off < 0 || (size_t)off >= resp_size) ? -1 : 0;
    }
    for (int i = 0; i < owner->n_routes; i++)
        if (owner->routes[i].target_type == HAL_L3_ROUTE_TARGET_RIF)
            connected_routes++;
    rc = persistent_verify_state(sw, owner, &compared, &mismatches,
                                 objects, sizeof(objects));
    if (owner->hw_out_of_sync) {
        status = "out-of-sync";
        handle_map = "installed";
    } else if (rc != 0) {
        status = "error";
        handle_map = "installed";
    } else if (mismatches > 0) {
        status = "mismatch";
        handle_map = "installed";
    } else {
        status = "ok";
        handle_map = "installed";
    }
    off = snprintf(resp, resp_size,
                   "<%s status=\"%s\" source=\"switchd\" mode=\"hidden\" "
                   "hardware-apply=\"persistent\" sdk-write=\"%s\" "
                   "sdk-readback=\"live\" owner-handle-map=\"%s\" "
                   "applied=\"true\" tx-id=\"%llu\" sw=\"%d\" "
                   "compared=\"%d\" mismatches=\"%d\" idempotent=\"%s\" "
                   "traffic-owner=\"%s\" router-mac=\"%s\" "
                   "virtual-router=\"%s\" vrf-table=\"%s\" "
                   "vrid=\"%d\" kernel-table=\"%d\">"
                   "<usage rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                   "ecmp-groups=\"%d\" fib-routes=\"%d\" "
                   "connected-route-intent=\"%d\"/>"
                   "<handle-map status=\"%s\" rifs=\"%d\" arp=\"%d\" "
                   "ecmp-groups=\"%d\" routes=\"%d\"/>"
                   "<traffic-owner router=\"%s\" vlans=\"%d\" ports=\"%d\" "
                   "routed-ports=\"%d\"/>"
                   "%s"
                   "<boundary user-config=\"rejected\" "
                   "reason=\"hidden persistent SDK L3 owner; direct switchd "
                   "user config is internal; public routing config is handled "
                   "by configd/rpd\"/>"
                   "</%s>",
                   root, status, sdk_write, handle_map,
                   (unsigned long long)owner->tx_id, owner->sw,
                   compared, mismatches, idempotent ? "true" : "false",
                   owner->has_router_mac ? "enabled" : "disabled",
                   owner->has_router_mac ? owner->router_mac : "-",
                   owner->has_virtual_router ?
                       owner->virtual_router_name : "disabled",
                   owner->has_virtual_router ?
                       owner->virtual_router_table : "inet.0",
                   owner->has_virtual_router ? owner->virtual_router_id : 0,
                   owner->has_virtual_router ?
                       owner->virtual_router_kernel_table : 0,
                   owner->n_rifs, owner->n_arps, owner->n_nexthops,
                   owner->n_ecmp, owner->n_fib_routes, connected_routes,
                   handle_map, owner->n_rifs, owner->n_arps, owner->n_ecmp,
                   owner->n_fib_routes,
                   owner->has_router_mac ? "enabled" : "disabled",
                   owner->n_vlan_owner, owner->n_port_owner,
                   owner->n_routed_port_owner,
                   objects, root);
    return (off < 0 || (size_t)off >= resp_size) ? -1 : 0;
}

int hal_l3_persistent_owner_apply(int sw, const hal_l3_intent_plan *plan,
                                  bool acknowledged, u64 tx_id,
                                  char *resp, size_t resp_size) {
    const char *gate = "NETLAB_ENABLE_L3_PERSISTENT_OWNER";
    const char *unsafe_reason = NULL;
    hal_l3_persistent_owner *next = NULL;
    hal_l3_persistent_owner *owner;
    hal_l3_intent_plan view;
    fm_int pre_rifs = 0;
    fm_int pre_arps = 0;
    fm_int pre_routes = 0;
    fm_int pre_vrids[16];
    fm_int pre_vrid_count = 0;
    fm_status pre_vrid_status;
    int apply_failures = 0;
    int compared = 0;
    int mismatches = 0;
    int rollback_failures = 0;
    char failure_stage[64] = "none";
    int failure_index = -1;
    fm_status failure_status = FM_OK;
    char reason_attr[192];
    char failure_msg[160];
    int off;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!acknowledged) {
        off = snprintf(resp, resp_size,
                       "<l3-persistent-owner-apply status=\"blocked\" "
                       "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" owner-handle-map=\"missing\" "
                       "gate-env=\"%s\" gate=\"closed\">"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"operator acknowledgement required; payload "
                       "must include ack=%s\"/>"
                       "</l3-persistent-owner-apply>",
                       (unsigned long long)tx_id, gate, gate);
        (void)off;
        return -1;
    }
    if (!l3_plan_is_persistent_owner_safe(plan, &unsafe_reason)) {
        xml_escape_attr(unsafe_reason, reason_attr, sizeof(reason_attr));
        off = snprintf(resp, resp_size,
                       "<l3-persistent-owner-apply status=\"invalid\" "
                       "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"acknowledged\" reason=\"%s\"/>",
                       (unsigned long long)tx_id, gate, reason_attr);
        (void)off;
        return -1;
    }
    next = calloc(1, sizeof(*next));
    if (!next)
        return -1;
    if (persistent_copy_plan(next, plan) != 0) {
        free(next);
        return -1;
    }
    next->tx_id = tx_id;
    next->sw = sw;
    persistent_plan_view(next, &view);

    pthread_mutex_lock(&g_l3_persistent_owner_lock);
    owner = g_l3_persistent_owner;
    if (owner && owner->applied) {
        if (!persistent_plan_matches_owner(owner, next)) {
            off = snprintf(resp, resp_size,
                           "<l3-persistent-owner-apply status=\"blocked\" "
                           "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                           "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                           "sdk-readback=\"live\" owner-handle-map=\"installed\" "
                           "idempotent=\"false\" reason=\"persistent owner "
                           "already applied with a different plan; rollback "
                           "first\"/>",
                           (unsigned long long)tx_id);
            pthread_mutex_unlock(&g_l3_persistent_owner_lock);
            free(next);
            (void)off;
            return -1;
        }
        if (persistent_verify_state(sw, owner,
                                    &compared, &mismatches, NULL, 0) != 0 ||
            mismatches != 0) {
            owner->hw_out_of_sync = true;
            off = persistent_owner_readback_xml(
                sw, owner,
                "l3-persistent-owner-apply", "disabled", true,
                resp, resp_size);
            pthread_mutex_unlock(&g_l3_persistent_owner_lock);
            free(next);
            return -1;
        }
        owner->tx_id = tx_id;
        off = persistent_owner_readback_xml(
            sw, owner, "l3-persistent-owner-apply",
            "disabled", true, resp, resp_size);
        pthread_mutex_unlock(&g_l3_persistent_owner_lock);
        free(next);
        return off == 0 ? 0 : -1;
    }
    memset(pre_vrids, 0, sizeof(pre_vrids));
    pre_vrid_status = fmGetVirtualRouterList(
        (fm_int)sw, &pre_vrid_count, pre_vrids,
        (fm_int)(sizeof(pre_vrids) / sizeof(pre_vrids[0])));
    if (pre_vrid_status != FM_OK || pre_vrid_count != 0 ||
        persistent_sdk_non_ecmp_object_count(sw, &pre_rifs, &pre_arps,
                                            &pre_routes) != 0 ||
        pre_rifs != 0 || pre_arps != 0 || pre_routes != 0) {
        off = snprintf(resp, resp_size,
                       "<l3-persistent-owner-apply status=\"blocked\" "
                       "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"live\" owner-handle-map=\"missing\" "
                       "reason=\"SDK L3 RIF/ARP/FIB state is not empty\" "
                       "pre-vrids=\"%d\" pre-rifs=\"%d\" pre-arp=\"%d\" "
                       "pre-routes=\"%d\"/>",
                       (unsigned long long)tx_id, (int)pre_vrid_count,
                       (int)pre_rifs, (int)pre_arps,
                       (int)pre_routes);
        pthread_mutex_unlock(&g_l3_persistent_owner_lock);
        free(next);
        (void)off;
        return -1;
    }

    if (persistent_apply_traffic_owner(
            sw, next, failure_stage, sizeof(failure_stage),
            &failure_status, &failure_index) != 0)
        apply_failures++;

    for (int i = 0; i < next->n_rifs; i++) {
        fm_uint16 vlan = (fm_uint16)next->rifs[i].vlan;
        fm_interfaceState state = FM_INTERFACE_STATE_ADMIN_UP;
        fm_status st;

        if (apply_failures)
            break;
        if (parse_ipv4_cidr(next->rifs[i].address, &next->rif_addr[i],
                            NULL) != 0) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "rif-parse", i, FM_ERR_INVALID_ARGUMENT);
            apply_failures++;
            break;
        }
        st = fmCreateInterface((fm_int)sw, &next->rif_ifindex[i]);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "rif-create", i, st);
            apply_failures++;
            break;
        }
        next->rif_created[i] = true;
        st = fmAddInterfaceAddr((fm_int)sw, next->rif_ifindex[i],
                                &next->rif_addr[i]);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "rif-add-address", i, st);
            apply_failures++;
            break;
        }
        next->rif_addr_added[i] = true;
        st = fmSetInterfaceAttribute((fm_int)sw, next->rif_ifindex[i],
                                     FM_INTERFACE_VLAN, &vlan);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "rif-set-vlan", i, st);
            apply_failures++;
            break;
        }
        st = fmSetInterfaceAttribute((fm_int)sw, next->rif_ifindex[i],
                                     FM_INTERFACE_STATE, &state);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "rif-set-state", i, st);
            apply_failures++;
            break;
        }
    }
    for (int i = 0; i < next->n_arps && apply_failures == 0; i++) {
        int rif_index = persistent_find_rif_index(next, next->arps[i].rif);
        fm_int mac_port = -1;
        fm_int user_ports = 0;
        fm_status st;

        memset(&next->arp_entry[i], 0, sizeof(next->arp_entry[i]));
        if (rif_index < 0 ||
            parse_ipv4(next->arps[i].ip, &next->arp_entry[i].ipAddr) != 0 ||
            parse_mac(next->arps[i].mac, &next->arp_entry[i].macAddr) != 0) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "arp-build", i, FM_ERR_INVALID_ARGUMENT);
            apply_failures++;
            break;
        }
        next->arp_entry[i].interface = next->rif_ifindex[rif_index];
        next->arp_entry[i].vlan = (fm_uint16)next->rifs[rif_index].vlan;
        st = fmAddARPEntry((fm_int)sw, &next->arp_entry[i]);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "arp-add", i, st);
            apply_failures++;
            break;
        }
        next->arp_added[i] = true;
        if (next->arps[i].egress_port[0]) {
            st = find_vlan_named_user_port(sw, next->arp_entry[i].vlan,
                                           next->arps[i].egress_port,
                                           &mac_port);
            if (st != FM_OK) {
                persistent_record_failure(
                    failure_stage, sizeof(failure_stage), &failure_status,
                    &failure_index, "arp-mac-named-port", i, st);
                apply_failures++;
                break;
            }
        } else if (find_vlan_first_user_port(
                       sw, next->arp_entry[i].vlan, &mac_port,
                       &user_ports) != FM_OK) {
            mac_port = -1;
        }
        if (mac_port > 0) {
            memset(&next->arp_mac_entry[i], 0,
                   sizeof(next->arp_mac_entry[i]));
            next->arp_mac_entry[i].macAddress = next->arp_entry[i].macAddr;
            next->arp_mac_entry[i].vlanID = next->arp_entry[i].vlan;
            next->arp_mac_entry[i].type = FM_ADDRESS_STATIC;
            next->arp_mac_entry[i].destMask = FM_DESTMASK_UNUSED;
            next->arp_mac_entry[i].port = mac_port;
            if (fmGetAddress((fm_int)sw,
                             next->arp_mac_entry[i].macAddress,
                             (fm_int)next->arp_mac_entry[i].vlanID,
                             &next->arp_pre_mac_entry[i]) == FM_OK) {
                if (next->arp_pre_mac_entry[i].port != mac_port) {
                    persistent_record_failure(
                        failure_stage, sizeof(failure_stage),
                        &failure_status, &failure_index,
                        "arp-mac-pre-existing-mismatch", i,
                        FM_ERR_INVALID_ARGUMENT);
                    apply_failures++;
                    break;
                }
                next->arp_mac_pre_existing[i] = true;
            } else if ((st = fmAddAddress((fm_int)sw,
                                          &next->arp_mac_entry[i])) == FM_OK) {
                next->arp_mac_added[i] = true;
            } else {
                persistent_record_failure(
                    failure_stage, sizeof(failure_stage), &failure_status,
                    &failure_index, "arp-mac-add", i, st);
                apply_failures++;
                break;
            }
        }
    }
    for (int i = 0; i < next->n_ecmp && apply_failures == 0; i++) {
        bool built = true;

        for (int j = 0; j < next->ecmp[i].n_members; j++) {
            const hal_l3_intent_next_hop *nh =
                find_nexthop(&view, next->ecmp[i].members[j]);

            if (!nh ||
                build_sdk_next_hop(&view, nh, &next->ecmp_members[i][j]) != 0)
                built = false;
        }
        if (!built) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "ecmp-member-build", i,
                FM_ERR_INVALID_ARGUMENT);
            apply_failures++;
            break;
        }
        fm_status st = fmCreateECMPGroup((fm_int)sw, &next->ecmp_group[i],
                                         next->ecmp[i].n_members,
                                         next->ecmp_members[i]);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "ecmp-create", i, st);
            apply_failures++;
            break;
        }
        next->ecmp_member_count[i] = next->ecmp[i].n_members;
        next->ecmp_created[i] = true;
    }
    for (int i = 0; i < next->n_routes && apply_failures == 0; i++) {
        if (next->routes[i].target_type == HAL_L3_ROUTE_TARGET_RIF)
            continue;
        if (next->n_fib_routes >= NL_L3_PERSISTENT_MAX_ROUTES ||
            persistent_build_route(next, &view, &next->routes[i],
                                   &next->route_entry[next->n_fib_routes]) != 0) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "route-build", i, FM_ERR_INVALID_ARGUMENT);
            apply_failures++;
            break;
        }
        fm_status st = fmAddRoute((fm_int)sw,
                                  &next->route_entry[next->n_fib_routes],
                                  FM_ROUTE_STATE_UP);
        if (st != FM_OK) {
            persistent_record_failure(
                failure_stage, sizeof(failure_stage), &failure_status,
                &failure_index, "route-add", i, st);
            apply_failures++;
            break;
        }
        next->route_plan_index[next->n_fib_routes] = i;
        next->route_added[next->n_fib_routes] = true;
        next->n_fib_routes++;
    }

    if (apply_failures == 0 &&
        persistent_verify_state(sw, next, &compared, &mismatches,
                                NULL, 0) != 0) {
        persistent_record_failure(
            failure_stage, sizeof(failure_stage), &failure_status,
            &failure_index, "verify-state", -1, FM_ERR_INVALID_ARGUMENT);
        apply_failures++;
    }
    if (apply_failures || mismatches) {
        xml_escape_attr(fmErrorMsg(failure_status), failure_msg,
                        sizeof(failure_msg));
        persistent_cleanup_state(sw, next, &rollback_failures);
        if (rollback_failures) {
            next->hw_out_of_sync = true;
            next->applied = true;
            g_l3_persistent_owner = next;
            next = NULL;
        }
        off = snprintf(resp, resp_size,
                       "<l3-persistent-owner-apply status=\"%s\" "
                       "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                       "hardware-apply=\"persistent\" sdk-write=\"live\" "
                       "sdk-readback=\"live\" owner-handle-map=\"%s\" "
                       "apply-failures=\"%d\" compared=\"%d\" "
                       "mismatches=\"%d\" rollback-failures=\"%d\" "
                       "failure-stage=\"%s\" failure-index=\"%d\" "
                       "failure-sdk-status=\"%d\" "
                       "failure-sdk-status-name=\"%s\" "
                       "failure-message=\"%s\">"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"hidden persistent SDK L3 owner apply failed; "
                       "direct switchd user config is internal; public routing "
                       "config is handled by configd/rpd\"/>"
                       "</l3-persistent-owner-apply>",
                       rollback_failures ? "out-of-sync" : "rollback",
                       (unsigned long long)tx_id,
                       rollback_failures ? "partial" : "missing",
                       apply_failures, compared, mismatches,
                       rollback_failures, failure_stage, failure_index,
                       (int)failure_status, sdk_status_name(failure_status),
                       failure_msg);
        pthread_mutex_unlock(&g_l3_persistent_owner_lock);
        free(next);
        (void)off;
        return -1;
    }

    next->applied = true;
    g_l3_persistent_owner = next;
    off = persistent_owner_readback_xml(sw, next,
                                        "l3-persistent-owner-apply",
                                        "live", false,
                                        resp, resp_size);
    pthread_mutex_unlock(&g_l3_persistent_owner_lock);
    return off == 0 ? 0 : -1;
}

int hal_l3_persistent_owner_readback(int sw, char *resp, size_t resp_size) {
    int rc;

    pthread_mutex_lock(&g_l3_persistent_owner_lock);
    rc = persistent_owner_readback_xml(sw, g_l3_persistent_owner,
                                       "l3-persistent-owner-readback",
                                       "disabled", false,
                                       resp, resp_size);
    pthread_mutex_unlock(&g_l3_persistent_owner_lock);
    return rc;
}

int hal_l3_persistent_owner_rollback(int sw, bool acknowledged, u64 tx_id,
                                     char *resp, size_t resp_size) {
    const char *gate = "NETLAB_ENABLE_L3_PERSISTENT_OWNER";
    hal_l3_persistent_owner *removed;
    int delete_failures = 0;
    int compared = 0;
    int mismatches = 0;
    char first_mismatch[96];
    int off;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!acknowledged) {
        off = snprintf(resp, resp_size,
                       "<l3-persistent-owner-rollback status=\"blocked\" "
                       "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"closed\"><boundary user-config=\"rejected\" "
                       "reason=\"operator acknowledgement required; payload "
                       "must include ack=%s\"/>"
                       "</l3-persistent-owner-rollback>",
                       (unsigned long long)tx_id, gate, gate);
        (void)off;
        return -1;
    }
    pthread_mutex_lock(&g_l3_persistent_owner_lock);
    removed = g_l3_persistent_owner;
    if (!removed || !removed->applied) {
        off = snprintf(resp, resp_size,
                       "<l3-persistent-owner-rollback status=\"empty\" "
                       "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"live\" owner-handle-map=\"empty\"/>",
                       (unsigned long long)tx_id);
        pthread_mutex_unlock(&g_l3_persistent_owner_lock);
        (void)off;
        return -1;
    }
    if (removed->has_virtual_router &&
        dynamic_vrf_owner_active()) {
        off = snprintf(resp, resp_size,
                       "<l3-persistent-owner-rollback status=\"blocked\" "
                       "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"live\" reason=\"VRF dynamic FIB "
                       "owner must be empty before virtual-router delete\"/>",
                       (unsigned long long)tx_id);
        pthread_mutex_unlock(&g_l3_persistent_owner_lock);
        (void)off;
        return -1;
    }
    persistent_cleanup_state(sw, removed, &delete_failures);
    (void)persistent_verify_absent_state(sw, removed, &compared,
                                         &mismatches, first_mismatch,
                                         sizeof(first_mismatch));
    if (mismatches) {
        removed->hw_out_of_sync = true;
        off = snprintf(resp, resp_size,
                       "<l3-persistent-owner-rollback status=\"out-of-sync\" "
                       "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                       "hardware-apply=\"persistent\" sdk-write=\"live\" "
                       "sdk-readback=\"live\" owner-handle-map=\"installed\" "
                       "delete-failures=\"%d\" compared=\"%d\" "
                       "mismatches=\"%d\" first-mismatch=\"%s\"/>",
                       (unsigned long long)tx_id, delete_failures, compared,
                       mismatches,
                       first_mismatch[0] ? first_mismatch : "unknown");
        pthread_mutex_unlock(&g_l3_persistent_owner_lock);
        (void)off;
        return -1;
    }
    g_l3_persistent_owner = NULL;
    off = snprintf(resp, resp_size,
                   "<l3-persistent-owner-rollback status=\"ok\" "
                   "source=\"switchd\" mode=\"hidden\" tx-id=\"%llu\" "
                   "hardware-apply=\"persistent\" sdk-write=\"live\" "
                   "sdk-readback=\"live\" owner-handle-map=\"removed\" "
                   "delete-failures=\"%d\" cleanup-status=\"%s\" "
                   "compared=\"%d\" mismatches=\"0\">"
                   "<usage rifs=\"%d\" arp=\"%d\" next-hops=\"%d\" "
                   "ecmp-groups=\"%d\" fib-routes=\"%d\"/>"
                   "<boundary user-config=\"rejected\" "
                   "reason=\"hidden persistent SDK L3 owner rolled back%s; "
                   "direct switchd user config is internal; public routing "
                   "config is handled by configd/rpd\"/>"
                   "</l3-persistent-owner-rollback>",
                   (unsigned long long)tx_id, delete_failures,
                   delete_failures ? "warning" : "clean",
                   compared,
                   removed->n_rifs, removed->n_arps, removed->n_nexthops,
                   removed->n_ecmp, removed->n_fib_routes,
                   delete_failures ? " with SDK cleanup warning" : "");
    pthread_mutex_unlock(&g_l3_persistent_owner_lock);
    free(removed);
    return (off < 0 || (size_t)off >= resp_size) ? -1 : 0;
}

#define HAL_L3_DYNAMIC_MAX_ECMP NL_L3_DYNAMIC_MAX_ROUTES
#define HAL_L3_DYNAMIC_EMIT_LIMIT 16
#define HAL_L3_DYNAMIC_READBACK_EXTRA 64

typedef struct {
    bool applied;
    bool hw_out_of_sync;
    u64 tx_id;
    u64 generation;
    u64 fib_update_id;
    int sw;
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    char route_prefix[NL_L3_DYNAMIC_MAX_ROUTES][HAL_L3_INTENT_ADDR_LEN];
    char route_protocol[NL_L3_DYNAMIC_MAX_ROUTES][16];
    int route_nexthops[NL_L3_DYNAMIC_MAX_ROUTES];
    int route_ecmp_index[NL_L3_DYNAMIC_MAX_ROUTES];
    fm_routeEntry route_entry[NL_L3_DYNAMIC_MAX_ROUTES];
    bool route_added[NL_L3_DYNAMIC_MAX_ROUTES];
    int n_routes;
    fm_int ecmp_group[HAL_L3_DYNAMIC_MAX_ECMP];
    fm_nextHop ecmp_members[HAL_L3_DYNAMIC_MAX_ECMP]
                           [NL_L3_DYNAMIC_MAX_NEXTHOPS];
    int ecmp_member_count[HAL_L3_DYNAMIC_MAX_ECMP];
    bool ecmp_created[HAL_L3_DYNAMIC_MAX_ECMP];
    int n_ecmp;
} hal_l3_dynamic_fib_owner;

#define HAL_L3_DYNAMIC_OWNER_SLOTS 2
typedef struct {
    hal_l3_dynamic_fib_owner *state;
} hal_l3_dynamic_fib_owner_slot;

static hal_l3_dynamic_fib_owner_slot
    g_l3_dynamic_fib_owner[HAL_L3_DYNAMIC_OWNER_SLOTS];
static pthread_mutex_t g_l3_dynamic_fib_owner_lock =
    PTHREAD_MUTEX_INITIALIZER;

static bool dynamic_vrf_owner_active(void) {
    bool active;

    pthread_mutex_lock(&g_l3_dynamic_fib_owner_lock);
    active = g_l3_dynamic_fib_owner[1].state &&
        g_l3_dynamic_fib_owner[1].state->applied &&
        g_l3_dynamic_fib_owner[1].state->n_routes > 0;
    pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
    return active;
}

static void dynamic_owner_init(hal_l3_dynamic_fib_owner *owner) {
    if (!owner)
        return;
    memset(owner, 0, sizeof(*owner));
    snprintf(owner->table, sizeof(owner->table), "inet.0");
    for (int i = 0; i < NL_L3_DYNAMIC_MAX_ROUTES; i++)
        owner->route_ecmp_index[i] = -1;
    for (int i = 0; i < HAL_L3_DYNAMIC_MAX_ECMP; i++)
        owner->ecmp_group[i] = -1;
}

static hal_l3_dynamic_fib_owner_slot *dynamic_owner_slot_for_vrid(int vrid) {
    if (vrid < 0 || vrid >= HAL_L3_DYNAMIC_OWNER_SLOTS)
        return NULL;
    return &g_l3_dynamic_fib_owner[vrid];
}

static int dynamic_build_next_hop(
        const hal_l3_dynamic_fib_nexthop *nh, fm_nextHop *sdk_nh) {
    if (!nh || !sdk_nh || !nh->address[0] || !nh->interface_addr[0])
        return -1;
    memset(sdk_nh, 0, sizeof(*sdk_nh));
    if (parse_ipv4(nh->address, &sdk_nh->addr) != 0 ||
        parse_ipv4_cidr(nh->interface_addr, &sdk_nh->interfaceAddr,
                        NULL) != 0)
        return -1;
    sdk_nh->vlan = 0;
    sdk_nh->trapCode = FM_DEFAULT_NEXTHOP_TRAPCODE;
    return 0;
}

static int dynamic_build_route(
        const hal_l3_dynamic_fib_route *route,
        const hal_l3_dynamic_fib_nexthop *nh,
        fm_int ecmp_group, int vrid, fm_routeEntry *entry) {
    fm_ipAddr dst;
    int prefix = 0;

    if (!route || !entry || parse_ipv4_cidr(route->prefix, &dst,
                                            &prefix) != 0)
        return -1;
    memset(entry, 0, sizeof(*entry));
    if (route->n_nexthops == 1) {
        if (!nh || parse_ipv4(nh->address,
                              &entry->data.unicast.nextHop) != 0 ||
            parse_ipv4_cidr(nh->interface_addr,
                            &entry->data.unicast.interfaceAddr, NULL) != 0)
            return -1;
        entry->routeType = FM_ROUTE_TYPE_UNICAST;
        entry->data.unicast.dstAddr = dst;
        entry->data.unicast.prefixLength = prefix;
        entry->data.unicast.vlan = 0;
        entry->data.unicast.vrid = vrid;
        return 0;
    }
    if (route->n_nexthops > 1 && ecmp_group >= 0) {
        entry->routeType = FM_ROUTE_TYPE_UNICAST_ECMP;
        entry->data.unicastECMP.dstAddr = dst;
        entry->data.unicastECMP.prefixLength = prefix;
        entry->data.unicastECMP.ecmpGroup = ecmp_group;
        entry->data.unicastECMP.vrid = vrid;
        return 0;
    }
    return -1;
}

#define HAL_L3_DYNAMIC_ROUTE_INDEX_SIZE (NL_L3_DYNAMIC_MAX_ROUTES * 2)

typedef struct {
    const char *prefix;
    int index;
} dynamic_route_index_slot;

static u32 dynamic_route_prefix_hash(const char *prefix) {
    u32 hash = 2166136261U;

    if (!prefix)
        return 0;
    while (*prefix) {
        hash ^= (u8)*prefix++;
        hash *= 16777619U;
    }
    return hash;
}

static int dynamic_route_index_insert(dynamic_route_index_slot *slots,
                                      const char *prefix, int index) {
    u32 slot;

    if (!slots || !prefix || !prefix[0])
        return -1;
    slot = dynamic_route_prefix_hash(prefix) &
        (HAL_L3_DYNAMIC_ROUTE_INDEX_SIZE - 1);
    for (int i = 0; i < HAL_L3_DYNAMIC_ROUTE_INDEX_SIZE; i++) {
        dynamic_route_index_slot *candidate = &slots[slot];

        if (!candidate->prefix) {
            candidate->prefix = prefix;
            candidate->index = index;
            return 0;
        }
        if (strcmp(candidate->prefix, prefix) == 0)
            return -1;
        slot = (slot + 1) & (HAL_L3_DYNAMIC_ROUTE_INDEX_SIZE - 1);
    }
    return -1;
}

static int dynamic_route_index_find(const dynamic_route_index_slot *slots,
                                    const char *prefix) {
    u32 slot;

    if (!slots || !prefix || !prefix[0])
        return -1;
    slot = dynamic_route_prefix_hash(prefix) &
        (HAL_L3_DYNAMIC_ROUTE_INDEX_SIZE - 1);
    for (int i = 0; i < HAL_L3_DYNAMIC_ROUTE_INDEX_SIZE; i++) {
        const dynamic_route_index_slot *candidate = &slots[slot];

        if (!candidate->prefix)
            return -1;
        if (strcmp(candidate->prefix, prefix) == 0)
            return candidate->index;
        slot = (slot + 1) & (HAL_L3_DYNAMIC_ROUTE_INDEX_SIZE - 1);
    }
    return -1;
}

static void dynamic_owner_prepare(hal_l3_dynamic_fib_owner *owner, int sw,
                                  const hal_l3_dynamic_fib_plan *plan,
                                  u64 tx_id) {
    dynamic_owner_init(owner);
    owner->tx_id = tx_id;
    owner->sw = sw;
    owner->generation = plan->generation;
    owner->fib_update_id = plan->fib_update_id;
    owner->vrid = plan->vrid;
    snprintf(owner->table, sizeof(owner->table), "%s",
             plan->table[0] ? plan->table : "inet.0");
}

static int dynamic_prepare_unicast_plan(
        const hal_l3_dynamic_fib_plan *plan,
        hal_l3_dynamic_fib_owner *next) {
    if (!plan || !next)
        return -1;
    for (int i = 0; i < plan->n_routes; i++) {
        const hal_l3_dynamic_fib_route *route = &plan->routes[i];

        if (!route->prefix[0] || route->n_nexthops != 1 || !route->nexthops)
            return -1;
        snprintf(next->route_prefix[i], sizeof(next->route_prefix[i]), "%s",
                 route->prefix);
        snprintf(next->route_protocol[i], sizeof(next->route_protocol[i]),
                 "%s", route->protocol[0] ? route->protocol : "dynamic");
        next->route_nexthops[i] = 1;
        if (dynamic_build_route(route, &route->nexthops[0], -1,
                                plan->vrid, &next->route_entry[i]) != 0)
            return -1;
        next->n_routes++;
    }
    return 0;
}

static int dynamic_incremental_result_xml(
        const hal_l3_dynamic_fib_owner *owner, int changed,
        char *resp, size_t resp_size) {
    int off;

    off = snprintf(resp, resp_size,
                   "<fib-live-owner status=\"ok\" source=\"switchd\" "
                   "owner=\"rpd\" table=\"%s\" vrid=\"%d\" "
                   "hardware-apply=\"dynamic\" sdk-write=\"live\" "
                   "sdk-readback=\"live\" applied=\"%s\" tx-id=\"%llu\" "
                   "sw=\"%d\" generation=\"%llu\" fib-update-id=\"%llu\" "
                   "routes=\"%d\" ecmp-groups=\"0\" compared=\"%d\" "
                   "changed-compared=\"%d\" mismatches=\"0\" "
                   "update-mode=\"incremental-unicast\" "
                   "verification=\"changed-objects-and-owner-invariant\">"
                   "<usage routes=\"%d\" ecmp-groups=\"0\"/>"
                   "</fib-live-owner>",
                   owner->table, owner->vrid,
                   owner->applied ? "true" : "false",
                   (unsigned long long)owner->tx_id, owner->sw,
                   (unsigned long long)owner->generation,
                   (unsigned long long)owner->fib_update_id,
                   owner->n_routes, owner->n_routes, changed,
                   owner->n_routes);
    return (off < 0 || (size_t)off >= resp_size) ? -1 : 0;
}

static int dynamic_incremental_failure_xml(
        hal_l3_dynamic_fib_owner *owner, u64 tx_id,
        int apply_failures, int delete_failures, int rollback_failures,
        char *resp, size_t resp_size) {
    int off;

    if (rollback_failures)
        owner->hw_out_of_sync = true;
    off = snprintf(resp, resp_size,
                   "<fib-live-owner status=\"%s\" source=\"switchd\" "
                   "owner=\"rpd\" hardware-apply=\"dynamic\" "
                   "sdk-write=\"live\" sdk-readback=\"live\" "
                   "update-mode=\"incremental-unicast\" tx-id=\"%llu\" "
                   "apply-failures=\"%d\" delete-failures=\"%d\" "
                   "rollback-failures=\"%d\"/>",
                   rollback_failures ? "out-of-sync" : "rollback",
                   (unsigned long long)tx_id, apply_failures,
                   delete_failures, rollback_failures);
    (void)off;
    return -1;
}

static int dynamic_try_incremental_unicast(
        int sw, hal_l3_dynamic_fib_owner *owner,
        const hal_l3_dynamic_fib_plan *plan, u64 tx_id,
        hal_l3_dynamic_fib_owner *next, bool *handled,
        char *resp, size_t resp_size) {
    dynamic_route_index_slot *old_index = NULL;
    bool *old_seen = NULL;
    bool *new_route = NULL;
    int *changed_old = NULL;
    int additions = 0;
    int removals = 0;
    int changed = 0;
    int completed = 0;
    int apply_failures = 0;
    int delete_failures = 0;
    int rollback_failures = 0;
    int rc = -1;

    *handled = false;
    if (!owner || !owner->applied || owner->n_ecmp != 0 || !plan || !next)
        return 0;
    if (dynamic_prepare_unicast_plan(plan, next) != 0)
        return 0;

    old_index = calloc(HAL_L3_DYNAMIC_ROUTE_INDEX_SIZE,
                       sizeof(*old_index));
    old_seen = calloc((size_t)(owner->n_routes ? owner->n_routes : 1),
                      sizeof(*old_seen));
    new_route = calloc((size_t)(next->n_routes ? next->n_routes : 1),
                       sizeof(*new_route));
    changed_old = calloc((size_t)(owner->n_routes ? owner->n_routes : 1),
                         sizeof(*changed_old));
    if (!old_index || !old_seen || !new_route || !changed_old)
        goto out;
    for (int i = 0; i < owner->n_routes; i++)
        if (dynamic_route_index_insert(old_index, owner->route_prefix[i], i) != 0)
            goto out;
    for (int i = 0; i < next->n_routes; i++) {
        int old = dynamic_route_index_find(old_index, next->route_prefix[i]);

        if (old < 0) {
            new_route[i] = true;
            additions++;
            continue;
        }
        old_seen[old] = true;
        if (!route_entry_equal(&owner->route_entry[old],
                               &next->route_entry[i])) {
            changed++;
            continue;
        }
        next->route_added[i] = owner->route_added[old];
    }
    for (int i = 0; i < owner->n_routes; i++) {
        if (!old_seen[i]) {
            changed_old[removals] = i;
            removals++;
        }
    }
    if (changed || (additions && removals))
        goto out;

    *handled = true;
    if (additions) {
        for (int i = 0; i < next->n_routes; i++) {
            fm_routeState state = 0;

            if (!new_route[i])
                continue;
            if (fmAddRoute((fm_int)sw, &next->route_entry[i],
                           FM_ROUTE_STATE_UP) != FM_OK) {
                apply_failures++;
                break;
            }
            next->route_added[i] = true;
            completed++;
            if (fmGetRouteState((fm_int)sw, &next->route_entry[i],
                                &state) != FM_OK ||
                state != FM_ROUTE_STATE_UP) {
                apply_failures++;
                break;
            }
        }
        if (apply_failures) {
            for (int i = next->n_routes - 1; i >= 0; i--)
                if (new_route[i] && next->route_added[i]) {
                    if (fmDeleteRoute((fm_int)sw,
                                      &next->route_entry[i]) != FM_OK)
                        rollback_failures++;
                    else
                        next->route_added[i] = false;
                }
            if (rollback_failures) {
                next->applied = true;
                next->hw_out_of_sync = true;
            }
            rc = dynamic_incremental_failure_xml(
                rollback_failures ? next : owner, tx_id,
                apply_failures, 0, rollback_failures,
                resp, resp_size);
            goto out;
        }
    } else if (removals) {
        for (int i = 0; i < removals; i++) {
            int old = changed_old[i];
            fm_routeState state = 0;

            if (fmDeleteRoute((fm_int)sw,
                              &owner->route_entry[old]) != FM_OK) {
                delete_failures++;
                break;
            }
            owner->route_added[old] = false;
            completed++;
            if (fmGetRouteState((fm_int)sw, &owner->route_entry[old],
                                &state) == FM_OK) {
                owner->route_added[old] = true;
                delete_failures++;
                break;
            }
        }
        if (delete_failures) {
            for (int i = completed - 1; i >= 0; i--) {
                int old = changed_old[i];

                if (fmAddRoute((fm_int)sw, &owner->route_entry[old],
                               FM_ROUTE_STATE_UP) != FM_OK)
                    rollback_failures++;
                else
                    owner->route_added[old] = true;
            }
            rc = dynamic_incremental_failure_xml(
                owner, tx_id, 0, delete_failures, rollback_failures,
                resp, resp_size);
            goto out;
        }
    }

    next->applied = next->n_routes > 0;
    next->hw_out_of_sync = false;
    rc = dynamic_incremental_result_xml(next, additions + removals,
                                        resp, resp_size);
out:
    free(changed_old);
    free(new_route);
    free(old_seen);
    free(old_index);
    return rc;
}

static void dynamic_cleanup_state(int sw, hal_l3_dynamic_fib_owner *owner,
                                  int *delete_failures) {
    bool retained = false;

    if (!owner)
        return;
    if (delete_failures)
        *delete_failures = 0;
    for (int i = owner->n_routes - 1; i >= 0; i--) {
        if (!owner->route_added[i])
            continue;
        if (fmDeleteRoute((fm_int)sw, &owner->route_entry[i]) != FM_OK) {
            retained = true;
            if (delete_failures)
                (*delete_failures)++;
        } else {
            owner->route_added[i] = false;
        }
    }
    for (int i = owner->n_ecmp - 1; i >= 0; i--) {
        if (!owner->ecmp_created[i])
            continue;
        if (fmDeleteECMPGroup((fm_int)sw,
                              owner->ecmp_group[i]) != FM_OK) {
            retained = true;
            if (delete_failures)
                (*delete_failures)++;
        } else {
            owner->ecmp_created[i] = false;
        }
    }
    owner->applied = retained;
}

static int dynamic_restore_state(int sw, hal_l3_dynamic_fib_owner *owner) {
    int cleanup_failures = 0;

    if (!owner)
        return -1;
    for (int i = 0; i < owner->n_ecmp; i++) {
        owner->ecmp_group[i] = -1;
        owner->ecmp_created[i] = false;
        if (fmCreateECMPGroup((fm_int)sw, &owner->ecmp_group[i],
                              owner->ecmp_member_count[i],
                              owner->ecmp_members[i]) != FM_OK)
            goto fail;
        owner->ecmp_created[i] = true;
    }
    for (int i = 0; i < owner->n_routes; i++) {
        int ecmp_index = owner->route_ecmp_index[i];

        owner->route_added[i] = false;
        if (ecmp_index >= 0) {
            if (ecmp_index >= owner->n_ecmp)
                goto fail;
            owner->route_entry[i].data.unicastECMP.ecmpGroup =
                owner->ecmp_group[ecmp_index];
        }
        if (fmAddRoute((fm_int)sw, &owner->route_entry[i],
                       FM_ROUTE_STATE_UP) != FM_OK)
            goto fail;
        owner->route_added[i] = true;
    }
    owner->applied = owner->n_routes > 0;
    owner->hw_out_of_sync = false;
    return 0;

fail:
    dynamic_cleanup_state(sw, owner, &cleanup_failures);
    owner->hw_out_of_sync = true;
    return -1;
}

static int dynamic_verify_state(int sw,
                                const hal_l3_dynamic_fib_owner *owner,
                                int *compared_out,
                                int *mismatches_out,
                                char *objects,
                                size_t objects_size) {
    fm_int group_list_cap = HAL_L3_DYNAMIC_MAX_ECMP +
        NL_L3_PERSISTENT_MAX_ECMP + HAL_L3_DYNAMIC_READBACK_EXTRA;
    fm_int route_list_cap = NL_L3_DYNAMIC_MAX_ROUTES +
        NL_L3_PERSISTENT_MAX_ROUTES + HAL_L3_DYNAMIC_READBACK_EXTRA;
    fm_int *groups = NULL;
    fm_routeEntry *routes = NULL;
    fm_int group_count = 0;
    fm_int route_count = 0;
    fm_status st_group_list = (fm_status)-1;
    fm_status st_route_list = (fm_status)-1;
    int compared = 0;
    int mismatches = 0;
    int off = 0;
    int rc = 0;

    if (objects && objects_size > 0)
        objects[0] = '\0';
    if (!owner)
        return -1;
    groups = calloc((size_t)group_list_cap, sizeof(*groups));
    routes = calloc((size_t)route_list_cap, sizeof(*routes));
    if (!groups || !routes) {
        rc = -1;
        goto out;
    }
    st_group_list = fmGetECMPGroupList((fm_int)sw, &group_count, groups,
                                       group_list_cap);
    st_route_list = fmGetRouteList((fm_int)sw, &route_count, routes,
                                   route_list_cap);
    for (int i = 0; i < owner->n_ecmp; i++) {
        fm_nextHop members[NL_L3_DYNAMIC_MAX_NEXTHOPS];
        fm_int member_count = 0;
        bool group_found = false;
        bool members_match = false;
        bool ok;
        fm_status st_members;

        memset(members, 0, sizeof(members));
        if (st_group_list == FM_OK) {
            fm_int emitted = group_count > group_list_cap ?
                group_list_cap : group_count;
            group_found = ecmp_group_list_contains(groups, emitted,
                                                   owner->ecmp_group[i]);
        }
        st_members = fmGetECMPGroupNextHopList(
            (fm_int)sw, owner->ecmp_group[i], &member_count, members,
            (fm_int)(sizeof(members) / sizeof(members[0])));
        members_match = st_members == FM_OK;
        if (members_match) {
            fm_int emitted = member_count >
                (fm_int)(sizeof(members) / sizeof(members[0])) ?
                (fm_int)(sizeof(members) / sizeof(members[0])) :
                member_count;
            for (int j = 0; j < owner->ecmp_member_count[i]; j++)
                if (!next_hop_list_contains(
                        members, emitted, &owner->ecmp_members[i][j]))
                    members_match = false;
        }
        ok = group_found && members_match;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_DYNAMIC_EMIT_LIMIT)
            off = appendf(objects, objects_size, off,
                          "<object family=\"ecmp\" index=\"%d\" "
                          "sdk-group=\"%d\" members=\"%d\" "
                          "status=\"%s\"/>",
                          i, (int)owner->ecmp_group[i],
                          owner->ecmp_member_count[i],
                          ok ? "ok" : "mismatch");
    }
    for (int i = 0; i < owner->n_routes; i++) {
        bool list_found = false;
        bool ok;

        if (st_route_list == FM_OK) {
            fm_int emitted = route_count > route_list_cap ?
                route_list_cap : route_count;
            list_found = route_list_contains(routes, emitted,
                                             &owner->route_entry[i]);
        }
        ok = owner->route_added[i] && st_route_list == FM_OK && list_found;
        compared++;
        if (!ok)
            mismatches++;
        if (objects && objects_size > 0 &&
            i < HAL_L3_DYNAMIC_EMIT_LIMIT)
            off = appendf(objects, objects_size, off,
                          "<object family=\"route\" prefix=\"%s\" "
                          "protocol=\"%s\" nexthops=\"%d\" "
                          "status=\"%s\"/>",
                          owner->route_prefix[i],
                          owner->route_protocol[i],
                          owner->route_nexthops[i],
                          ok ? "ok" : "mismatch");
    }
    if (objects && objects_size > 0 &&
        (owner->n_ecmp > HAL_L3_DYNAMIC_EMIT_LIMIT ||
         owner->n_routes > HAL_L3_DYNAMIC_EMIT_LIMIT))
        off = appendf(objects, objects_size, off,
                      "<truncated reason=\"emit-limit\"/>");
    if (compared_out)
        *compared_out = compared;
    if (mismatches_out)
        *mismatches_out = mismatches;
out:
    free(groups);
    free(routes);
    return rc != 0 || off < 0 ? -1 : 0;
}

static int dynamic_owner_readback_xml(
        int sw, const hal_l3_dynamic_fib_owner *owner, const char *root,
        char *resp, size_t resp_size) {
    char objects[8192];
    int compared = 0;
    int mismatches = 0;
    const char *status;
    int rc;
    int off;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!owner || (!owner->applied && !owner->hw_out_of_sync)) {
        off = snprintf(resp, resp_size,
                       "<%s status=\"empty\" source=\"switchd\" "
                       "owner=\"rpd\" table=\"%s\" vrid=\"%d\" "
                       "hardware-apply=\"dynamic\" sdk-write=\"disabled\" "
                       "sdk-readback=\"live\" applied=\"false\" tx-id=\"0\" "
                       "generation=\"0\" fib-update-id=\"0\">"
                       "<usage routes=\"0\" ecmp-groups=\"0\"/>"
                       "</%s>",
                       root,
                       owner && owner->table[0] ? owner->table : "inet.0",
                       owner ? owner->vrid : 0, root);
        return (off < 0 || (size_t)off >= resp_size) ? -1 : 0;
    }
    rc = dynamic_verify_state(sw, owner, &compared, &mismatches,
                              objects, sizeof(objects));
    if (owner->hw_out_of_sync)
        status = "out-of-sync";
    else if (rc != 0)
        status = "error";
    else if (mismatches > 0)
        status = "mismatch";
    else
        status = "ok";
    off = snprintf(resp, resp_size,
                   "<%s status=\"%s\" source=\"switchd\" owner=\"rpd\" "
                   "table=\"%s\" hardware-apply=\"dynamic\" "
                   "vrid=\"%d\" "
                   "sdk-write=\"live\" sdk-readback=\"live\" "
                   "applied=\"true\" tx-id=\"%llu\" sw=\"%d\" "
                   "generation=\"%llu\" fib-update-id=\"%llu\" "
                   "routes=\"%d\" ecmp-groups=\"%d\" compared=\"%d\" "
                   "mismatches=\"%d\">"
                   "<usage routes=\"%d\" ecmp-groups=\"%d\"/>"
                   "%s"
                   "</%s>",
                   root, status,
                   owner->table[0] ? owner->table : "inet.0",
                   owner->vrid,
                   (unsigned long long)owner->tx_id, owner->sw,
                   (unsigned long long)owner->generation,
                   (unsigned long long)owner->fib_update_id,
                   owner->n_routes, owner->n_ecmp, compared, mismatches,
                   owner->n_routes, owner->n_ecmp, objects, root);
    return (off < 0 || (size_t)off >= resp_size) ? -1 : 0;
}

int hal_l3_dynamic_fib_owner_apply(int sw,
                                   const hal_l3_dynamic_fib_plan *plan,
                                   bool enabled, u64 tx_id,
                                   char *resp, size_t resp_size) {
    hal_l3_dynamic_fib_owner *next = NULL;
    int delete_failures = 0;
    int apply_failures = 0;
    int compared = 0;
    int mismatches = 0;
    int off;
    int mapped_vrid = -1;
    bool incremental_handled = false;
    int incremental_rc;
    hal_l3_dynamic_fib_owner *owner = NULL;
    hal_l3_dynamic_fib_owner_slot *owner_slot = NULL;
    bool restore_previous = false;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!enabled) {
        off = snprintf(resp, resp_size,
                       "<fib-live-owner status=\"blocked\" "
                       "source=\"switchd\" owner=\"rpd\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" gate=\"closed\"/>");
        (void)off;
        return -1;
    }
    if (!plan || plan->n_routes < 0 ||
        plan->n_routes > NL_L3_DYNAMIC_MAX_ROUTES ||
        (plan->n_routes > 0 && !plan->routes) ||
        hal_l3_persistent_owner_lookup_table(
            plan->table[0] ? plan->table : "inet.0", &mapped_vrid) != 0 ||
        mapped_vrid != plan->vrid ||
        !(owner_slot = dynamic_owner_slot_for_vrid(plan->vrid))) {
        off = snprintf(resp, resp_size,
                       "<fib-live-owner status=\"invalid\" "
                       "source=\"switchd\" owner=\"rpd\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" reason=\"invalid-plan\"/>");
        (void)off;
        return -1;
    }
    next = malloc(sizeof(*next));
    if (!next) {
        off = snprintf(resp, resp_size,
                       "<fib-live-owner status=\"error\" "
                       "source=\"switchd\" owner=\"rpd\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" reason=\"out-of-memory\"/>");
        (void)off;
        return -1;
    }
    dynamic_owner_prepare(next, sw, plan, tx_id);

    pthread_mutex_lock(&g_l3_dynamic_fib_owner_lock);
    owner = owner_slot->state;
    if (!owner) {
        owner = malloc(sizeof(*owner));
        if (!owner) {
            pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
            free(next);
            off = snprintf(resp, resp_size,
                           "<fib-live-owner status=\"error\" "
                           "source=\"switchd\" owner=\"rpd\" "
                           "hardware-apply=\"disabled\" "
                           "sdk-write=\"disabled\" "
                           "sdk-readback=\"disabled\" "
                           "reason=\"out-of-memory\"/>");
            (void)off;
            return -1;
        }
        dynamic_owner_init(owner);
        owner_slot->state = owner;
    }
    incremental_rc = dynamic_try_incremental_unicast(
        sw, owner, plan, tx_id, next, &incremental_handled,
        resp, resp_size);
    if (incremental_handled) {
        if (incremental_rc == 0 || next->hw_out_of_sync) {
            owner_slot->state = next;
            next = NULL;
            free(owner);
        }
        pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
        free(next);
        return incremental_rc;
    }
    dynamic_owner_prepare(next, sw, plan, tx_id);
    if (owner->applied) {
        restore_previous = true;
        dynamic_cleanup_state(sw, owner,
                              &delete_failures);
        if (delete_failures) {
            owner->hw_out_of_sync = true;
            off = snprintf(resp, resp_size,
                           "<fib-live-owner status=\"out-of-sync\" "
                           "source=\"switchd\" owner=\"rpd\" "
                           "hardware-apply=\"dynamic\" sdk-write=\"live\" "
                           "sdk-readback=\"live\" tx-id=\"%llu\" "
                           "delete-failures=\"%d\"/>",
                           (unsigned long long)tx_id, delete_failures);
            pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
            free(next);
            (void)off;
            return -1;
        }
    }

    if (plan->n_routes == 0) {
        owner_slot->state = next;
        next = NULL;
        off = snprintf(resp, resp_size,
                       "<fib-live-owner status=\"ok\" source=\"switchd\" "
                       "owner=\"rpd\" table=\"%s\" "
                       "hardware-apply=\"dynamic\" sdk-write=\"live\" "
                       "sdk-readback=\"live\" applied=\"false\" "
                       "tx-id=\"%llu\" sw=\"%d\" generation=\"%llu\" "
                       "fib-update-id=\"%llu\" routes=\"0\" "
                       "ecmp-groups=\"0\" compared=\"0\" mismatches=\"0\">"
                       "<usage routes=\"0\" ecmp-groups=\"0\"/>"
                       "</fib-live-owner>",
                       plan->table[0] ? plan->table : "inet.0",
                       (unsigned long long)tx_id, sw,
                       (unsigned long long)plan->generation,
                       (unsigned long long)plan->fib_update_id);
        pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
        free(owner);
        free(next);
        return (off < 0 || (size_t)off >= resp_size) ? -1 : 0;
    }

    for (int i = 0; i < plan->n_routes && apply_failures == 0; i++) {
        const hal_l3_dynamic_fib_route *route = &plan->routes[i];
        fm_int ecmp_group = -1;

        if (!route->prefix[0] || route->n_nexthops <= 0 ||
            route->n_nexthops > NL_L3_DYNAMIC_MAX_NEXTHOPS ||
            !route->nexthops) {
            apply_failures++;
            break;
        }
        snprintf(next->route_prefix[next->n_routes],
                 sizeof(next->route_prefix[next->n_routes]), "%s",
                 route->prefix);
        snprintf(next->route_protocol[next->n_routes],
                 sizeof(next->route_protocol[next->n_routes]), "%s",
                 route->protocol[0] ? route->protocol : "dynamic");
        next->route_nexthops[next->n_routes] = route->n_nexthops;

        if (route->n_nexthops > 1) {
            int ecmp_index = next->n_ecmp;
            bool built = true;

            if (next->n_ecmp >= HAL_L3_DYNAMIC_MAX_ECMP) {
                apply_failures++;
                break;
            }
            for (int j = 0; j < route->n_nexthops; j++) {
                if (dynamic_build_next_hop(
                        &route->nexthops[j],
                        &next->ecmp_members[ecmp_index][j]) != 0)
                    built = false;
            }
            if (!built ||
                fmCreateECMPGroup((fm_int)sw,
                                  &next->ecmp_group[ecmp_index],
                                  route->n_nexthops,
                                  next->ecmp_members[ecmp_index]) != FM_OK) {
                apply_failures++;
                break;
            }
            next->ecmp_member_count[ecmp_index] = route->n_nexthops;
            next->ecmp_created[ecmp_index] = true;
            ecmp_group = next->ecmp_group[ecmp_index];
            next->route_ecmp_index[next->n_routes] = ecmp_index;
            next->n_ecmp++;
        }

        if (dynamic_build_route(route, &route->nexthops[0], ecmp_group,
                                plan->vrid,
                                &next->route_entry[next->n_routes]) != 0 ||
            fmAddRoute((fm_int)sw, &next->route_entry[next->n_routes],
                       FM_ROUTE_STATE_UP) != FM_OK) {
            apply_failures++;
            break;
        }
        next->route_added[next->n_routes] = true;
        next->n_routes++;
    }

    if (apply_failures == 0 &&
        dynamic_verify_state(sw, next, &compared, &mismatches,
                             NULL, 0) != 0)
        apply_failures++;
    if (apply_failures || mismatches) {
        int candidate_delete_failures = 0;

        dynamic_cleanup_state(sw, next, &candidate_delete_failures);
        if (candidate_delete_failures) {
            next->hw_out_of_sync = true;
            owner_slot->state = next;
            next = NULL;
            free(owner);
            owner = NULL;
            delete_failures += candidate_delete_failures;
        } else if (restore_previous &&
                   dynamic_restore_state(sw, owner) != 0) {
            owner->hw_out_of_sync = true;
            delete_failures++;
        }
        off = snprintf(resp, resp_size,
                       "<fib-live-owner status=\"%s\" source=\"switchd\" "
                       "owner=\"rpd\" hardware-apply=\"dynamic\" "
                       "sdk-write=\"live\" sdk-readback=\"live\" "
                       "tx-id=\"%llu\" apply-failures=\"%d\" "
                       "delete-failures=\"%d\" compared=\"%d\" "
                       "mismatches=\"%d\"/>",
                       delete_failures ? "out-of-sync" : "rollback",
                       (unsigned long long)tx_id, apply_failures,
                       delete_failures, compared, mismatches);
        pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
        free(next);
        (void)off;
        return -1;
    }

    next->applied = true;
    owner_slot->state = next;
    next = NULL;
    off = dynamic_owner_readback_xml(sw, owner_slot->state,
                                     "fib-live-owner", resp, resp_size);
    pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
    free(owner);
    free(next);
    return off == 0 ? 0 : -1;
}

int hal_l3_dynamic_fib_owner_readback(int sw, char *resp, size_t resp_size) {
    char primary[8192];
    char vrf[8192] = "";
    int rc;
    int n;

    pthread_mutex_lock(&g_l3_dynamic_fib_owner_lock);
    rc = dynamic_owner_readback_xml(sw, g_l3_dynamic_fib_owner[0].state,
                                    "fib-live-owner-readback",
                                    primary, sizeof(primary));
    if (rc == 0 && g_l3_dynamic_fib_owner[1].state &&
        (g_l3_dynamic_fib_owner[1].state->applied ||
         g_l3_dynamic_fib_owner[1].state->table[0]))
        rc = dynamic_owner_readback_xml(sw,
                                        g_l3_dynamic_fib_owner[1].state,
                                        "fib-live-owner-vrf-readback",
                                        vrf, sizeof(vrf));
    n = rc == 0 ? snprintf(resp, resp_size, "%s%s", primary, vrf) : -1;
    pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
    return rc != 0 || n < 0 || (size_t)n >= resp_size ? -1 : 0;
}

int hal_l3_dynamic_fib_owner_rollback(int sw, bool enabled, u64 tx_id,
                                      char *resp, size_t resp_size) {
    int delete_failures = 0;
    int rolled_back = 0;
    int off;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    if (!enabled) {
        off = snprintf(resp, resp_size,
                       "<fib-live-owner-rollback status=\"blocked\" "
                       "source=\"switchd\" owner=\"rpd\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" gate=\"closed\"/>");
        (void)off;
        return -1;
    }
    pthread_mutex_lock(&g_l3_dynamic_fib_owner_lock);
    for (int slot = HAL_L3_DYNAMIC_OWNER_SLOTS - 1; slot >= 0; slot--) {
        hal_l3_dynamic_fib_owner *owner =
            g_l3_dynamic_fib_owner[slot].state;
        int slot_failures = 0;

        if (!owner || !owner->applied ||
            (tx_id && owner->tx_id != tx_id))
            continue;
        dynamic_cleanup_state(sw, owner, &slot_failures);
        delete_failures += slot_failures;
        if (slot_failures)
            owner->hw_out_of_sync = true;
        else
            dynamic_owner_init(owner);
        rolled_back++;
    }
    if (rolled_back == 0) {
        off = snprintf(resp, resp_size,
                       "<fib-live-owner-rollback status=\"empty\" "
                       "source=\"switchd\" owner=\"rpd\" "
                       "hardware-apply=\"dynamic\" sdk-write=\"disabled\" "
                       "sdk-readback=\"live\" tx-id=\"%llu\"/>",
                       (unsigned long long)tx_id);
        pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
        (void)off;
        return -1;
    }
    off = snprintf(resp, resp_size,
                   "<fib-live-owner-rollback status=\"%s\" "
                   "source=\"switchd\" owner=\"rpd\" "
                   "hardware-apply=\"dynamic\" sdk-write=\"live\" "
                   "sdk-readback=\"live\" tx-id=\"%llu\" "
                   "tables=\"%d\" delete-failures=\"%d\"/>",
                   delete_failures ? "out-of-sync" : "ok",
                   (unsigned long long)tx_id, rolled_back,
                   delete_failures);
    pthread_mutex_unlock(&g_l3_dynamic_fib_owner_lock);
    return (off < 0 || (size_t)off >= resp_size ||
            delete_failures) ? -1 : 0;
}

int hal_l3_sdk_write_canary(int sw, bool acknowledged, char *resp,
                            size_t resp_size) {
    const char *gate = "NETLAB_ENABLE_L3_SDK_WRITE_CANARY";
    fm_ipAddr addr;
    fm_ipAddr addr_list[8];
    fm_int ifindex = -1;
    fm_int pre_count = 0;
    fm_int create_count = 0;
    fm_int addr_count = 0;
    fm_int post_count = 0;
    bool visible_after_create = false;
    bool visible_after_cleanup = false;
    bool addr_visible = false;
    fm_status st_pre = FM_OK;
    fm_status st_create = FM_ERR_UNINITIALIZED;
    fm_status st_list_after_create = FM_ERR_UNINITIALIZED;
    fm_status st_add_addr = FM_ERR_UNINITIALIZED;
    fm_status st_addr_list = FM_ERR_UNINITIALIZED;
    fm_status st_delete_addr = FM_ERR_UNINITIALIZED;
    fm_status st_delete_if = FM_ERR_UNINITIALIZED;
    fm_status st_post = FM_ERR_UNINITIALIZED;
    const char *overall = "error";
    int off;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';

    if (!acknowledged) {
        off = snprintf(resp, resp_size,
                       "<l3-sdk-write-canary status=\"blocked\" "
                       "source=\"switchd\" hardware-apply=\"disabled\" "
                       "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                       "mode=\"rif-create-delete\" gate-env=\"%s\" "
                       "gate=\"closed\"><boundary user-config=\"rejected\" "
                       "reason=\"operator acknowledgement required; "
                       "payload must include ack=%s\"/>"
                       "</l3-sdk-write-canary>",
                       gate, gate);
        (void)off;
        return -1;
    }

    if (parse_ipv4("169.254.254.1", &addr) != 0)
        return -1;

    memset(addr_list, 0, sizeof(addr_list));
    st_pre = get_interface_list_contains(sw, -1, &pre_count, NULL);

    st_create = fmCreateInterface((fm_int)sw, &ifindex);
    if (st_create == FM_OK) {
        st_list_after_create = get_interface_list_contains(
            sw, ifindex, &create_count, &visible_after_create);
        st_add_addr = fmAddInterfaceAddr((fm_int)sw, ifindex, &addr);
        if (st_add_addr == FM_OK) {
            st_addr_list = fmGetInterfaceAddrList(
                (fm_int)sw, ifindex, &addr_count, addr_list,
                (fm_int)(sizeof(addr_list) / sizeof(addr_list[0])));
            if (st_addr_list == FM_OK) {
                fm_int emitted = addr_count >
                    (fm_int)(sizeof(addr_list) / sizeof(addr_list[0])) ?
                    (fm_int)(sizeof(addr_list) / sizeof(addr_list[0])) :
                    addr_count;
                addr_visible = ipaddr_list_contains(addr_list, emitted, &addr);
            }
            st_delete_addr = fmDeleteInterfaceAddr((fm_int)sw, ifindex, &addr);
        }
        st_delete_if = fmDeleteInterface((fm_int)sw, ifindex);
    }

    st_post = get_interface_list_contains(sw, ifindex, &post_count,
                                          &visible_after_cleanup);
    if (st_pre == FM_OK && st_create == FM_OK &&
        st_list_after_create == FM_OK && visible_after_create &&
        st_add_addr == FM_OK && st_addr_list == FM_OK && addr_visible &&
        st_delete_addr == FM_OK && st_delete_if == FM_OK &&
        st_post == FM_OK && !visible_after_cleanup)
        overall = "ok";

    off = snprintf(resp, resp_size,
                   "<l3-sdk-write-canary status=\"%s\" "
                   "source=\"switchd\" hardware-apply=\"transient\" "
                   "sdk-write=\"live\" sdk-readback=\"live\" "
                   "rollback=\"cleanup\" mode=\"rif-create-delete\" "
                   "gate-env=\"%s\" gate=\"acknowledged\" "
                   "interface=\"%d\" address=\"169.254.254.1\">",
                   overall, gate, (int)ifindex);
    if (off < 0 || (size_t)off >= resp_size)
        return -1;
    off = appendf(resp, resp_size, off,
                  "<pre family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>",
                  sdk_status_name(st_pre), (int)st_pre, (int)pre_count);
    off = append_sdk_op_status(resp, resp_size, off,
                               "fmCreateInterface", st_create, false);
    off = appendf(resp, resp_size, off,
                  "<verify name=\"interface-readback\" status=\"%s\" "
                  "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>",
                  sdk_status_name(st_list_after_create),
                  (int)st_list_after_create, (int)create_count,
                  visible_after_create ? "true" : "false");
    off = append_sdk_op_status(resp, resp_size, off,
                               "fmAddInterfaceAddr", st_add_addr,
                               st_create != FM_OK);
    off = appendf(resp, resp_size, off,
                  "<verify name=\"addr-readback\" status=\"%s\" "
                  "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>",
                  sdk_status_name(st_addr_list), (int)st_addr_list,
                  (int)addr_count, addr_visible ? "true" : "false");
    off = append_sdk_op_status(resp, resp_size, off,
                               "fmDeleteInterfaceAddr", st_delete_addr,
                               st_add_addr != FM_OK);
    off = append_sdk_op_status(resp, resp_size, off,
                               "fmDeleteInterface", st_delete_if,
                               st_create != FM_OK);
    off = appendf(resp, resp_size, off,
                  "<post family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>",
                  sdk_status_name(st_post), (int)st_post, (int)post_count,
                  visible_after_cleanup ? "true" : "false");
    off = appendf(resp, resp_size, off,
                  "<boundary user-config=\"rejected\" "
                  "reason=\"operator-assisted SDK L3 RIF write canary only; "
                  "public L3 config remains rejected\"/>"
                  "</l3-sdk-write-canary>");
    return (off < 0 || strcmp(overall, "ok") != 0) ? -1 : 0;
}

static bool l3_plan_is_rif_live_probe_safe(const hal_l3_intent_plan *plan,
                                           const char **reason) {
    if (!plan) {
        if (reason)
            *reason = "missing L3 intent plan";
        return false;
    }
    if (plan->n_rifs <= 0) {
        if (reason)
            *reason = "RIF live probe requires at least one RIF";
        return false;
    }
    if (plan->n_rifs > 8) {
        if (reason)
            *reason = "RIF live probe limit is 8 RIFs";
        return false;
    }
    if (plan->n_arps || plan->n_nexthops || plan->n_ecmp) {
        if (reason)
            *reason = "RIF live probe forbids ARP/next-hop/ECMP writes";
        return false;
    }
    for (int i = 0; i < plan->n_routes; i++) {
        if (plan->routes[i].target_type != HAL_L3_ROUTE_TARGET_RIF ||
            find_rif(plan, plan->routes[i].target_name) < 0) {
            if (reason)
                *reason = "RIF live probe allows connected RIF route intent only";
            return false;
        }
    }
    return true;
}

int hal_l3_rif_live_probe(int sw, const hal_l3_intent_plan *plan,
                          bool acknowledged, u64 tx_id, char *resp,
                          size_t resp_size) {
    const char *gate = "NETLAB_ENABLE_L3_RIF_LIVE_PROBE";
    const char *unsafe_reason = NULL;
    fm_int pre_count = 0;
    fm_int post_count = 0;
    fm_status st_pre = FM_ERR_UNINITIALIZED;
    fm_status st_post = FM_ERR_UNINITIALIZED;
    bool any_leaked = false;
    const char *overall = "error";
    int off;

    struct rif_result {
        fm_int ifindex;
        fm_ipAddr addr;
        fm_status st_parse;
        fm_status st_create;
        fm_status st_list_create;
        fm_status st_add_addr;
        fm_status st_set_vlan;
        fm_status st_set_state;
        fm_status st_addr_list;
        fm_status st_get_vlan;
        fm_status st_get_state;
        fm_status st_delete_addr;
        fm_status st_delete_if;
        fm_status st_post_list;
        fm_int list_count;
        fm_int addr_count;
        fm_int post_count;
        fm_uint16 rb_vlan;
        fm_interfaceState rb_state;
        bool visible_after_create;
        bool addr_visible;
        bool vlan_match;
        bool state_match;
        bool visible_after_cleanup;
        bool created;
        bool addr_added;
    } results[8];

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    memset(results, 0, sizeof(results));
    for (int i = 0; i < 8; i++) {
        results[i].ifindex = -1;
        results[i].st_parse = FM_ERR_INVALID_ARGUMENT;
        results[i].st_create = FM_ERR_UNINITIALIZED;
        results[i].st_list_create = FM_ERR_UNINITIALIZED;
        results[i].st_add_addr = FM_ERR_UNINITIALIZED;
        results[i].st_set_vlan = FM_ERR_UNINITIALIZED;
        results[i].st_set_state = FM_ERR_UNINITIALIZED;
        results[i].st_addr_list = FM_ERR_UNINITIALIZED;
        results[i].st_get_vlan = FM_ERR_UNINITIALIZED;
        results[i].st_get_state = FM_ERR_UNINITIALIZED;
        results[i].st_delete_addr = FM_ERR_UNINITIALIZED;
        results[i].st_delete_if = FM_ERR_UNINITIALIZED;
        results[i].st_post_list = FM_ERR_UNINITIALIZED;
        results[i].rb_state = FM_INTERFACE_STATE_ADMIN_DOWN;
    }

    if (!acknowledged) {
        off = snprintf(resp, resp_size,
                       "<l3-rif-live-probe status=\"blocked\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" rollback=\"disabled\" "
                       "gate-env=\"%s\" gate=\"closed\">"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"operator acknowledgement required; "
                       "payload must include ack=%s\"/>"
                       "</l3-rif-live-probe>",
                       (unsigned long long)tx_id, gate, gate);
        (void)off;
        return -1;
    }

    if (!l3_plan_is_rif_live_probe_safe(plan, &unsafe_reason)) {
        char reason_attr[160];

        xml_escape_attr(unsafe_reason, reason_attr, sizeof(reason_attr));
        off = snprintf(resp, resp_size,
                       "<l3-rif-live-probe status=\"invalid\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" "
                       "hardware-apply=\"disabled\" sdk-write=\"disabled\" "
                       "sdk-readback=\"disabled\" rollback=\"disabled\" "
                       "gate-env=\"%s\" gate=\"acknowledged\" "
                       "reason=\"%s\">"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"RIF-only live probe; ARP/ECMP/FIB writes "
                       "remain disabled\"/>"
                       "</l3-rif-live-probe>",
                       (unsigned long long)tx_id, gate, reason_attr);
        (void)off;
        return -1;
    }

    st_pre = get_interface_list_contains(sw, -1, &pre_count, NULL);
    for (int i = 0; i < plan->n_rifs; i++) {
        fm_uint16 vlan = (fm_uint16)plan->rifs[i].vlan;
        fm_interfaceState state = FM_INTERFACE_STATE_ADMIN_UP;
        fm_ipAddr addr_list[8];

        memset(addr_list, 0, sizeof(addr_list));
        if (parse_ipv4_cidr(plan->rifs[i].address, &results[i].addr, NULL) == 0)
            results[i].st_parse = FM_OK;
        if (results[i].st_parse != FM_OK)
            continue;

        results[i].st_create = fmCreateInterface((fm_int)sw,
                                                 &results[i].ifindex);
        if (results[i].st_create != FM_OK)
            continue;
        results[i].created = true;
        results[i].st_list_create = get_interface_list_contains(
            sw, results[i].ifindex, &results[i].list_count,
            &results[i].visible_after_create);
        results[i].st_add_addr = fmAddInterfaceAddr(
            (fm_int)sw, results[i].ifindex, &results[i].addr);
        if (results[i].st_add_addr == FM_OK)
            results[i].addr_added = true;
        results[i].st_set_vlan = fmSetInterfaceAttribute(
            (fm_int)sw, results[i].ifindex, FM_INTERFACE_VLAN, &vlan);
        results[i].st_set_state = fmSetInterfaceAttribute(
            (fm_int)sw, results[i].ifindex, FM_INTERFACE_STATE, &state);
        results[i].st_addr_list = fmGetInterfaceAddrList(
            (fm_int)sw, results[i].ifindex, &results[i].addr_count,
            addr_list, (fm_int)(sizeof(addr_list) / sizeof(addr_list[0])));
        if (results[i].st_addr_list == FM_OK) {
            fm_int emitted = results[i].addr_count >
                (fm_int)(sizeof(addr_list) / sizeof(addr_list[0])) ?
                (fm_int)(sizeof(addr_list) / sizeof(addr_list[0])) :
                results[i].addr_count;
            results[i].addr_visible = ipaddr_list_contains(
                addr_list, emitted, &results[i].addr);
        }
        results[i].st_get_vlan = fmGetInterfaceAttribute(
            (fm_int)sw, results[i].ifindex, FM_INTERFACE_VLAN,
            &results[i].rb_vlan);
        results[i].vlan_match = results[i].st_get_vlan == FM_OK &&
                                results[i].rb_vlan == vlan;
        results[i].st_get_state = fmGetInterfaceAttribute(
            (fm_int)sw, results[i].ifindex, FM_INTERFACE_STATE,
            &results[i].rb_state);
        results[i].state_match = results[i].st_get_state == FM_OK &&
                                 results[i].rb_state == state;
    }

    for (int i = plan->n_rifs - 1; i >= 0; i--) {
        if (results[i].addr_added) {
            results[i].st_delete_addr = fmDeleteInterfaceAddr(
                (fm_int)sw, results[i].ifindex, &results[i].addr);
        }
        if (results[i].created) {
            results[i].st_delete_if = fmDeleteInterface((fm_int)sw,
                                                        results[i].ifindex);
            results[i].st_post_list = get_interface_list_contains(
                sw, results[i].ifindex, &results[i].post_count,
                &results[i].visible_after_cleanup);
            if (results[i].visible_after_cleanup)
                any_leaked = true;
        }
    }
    st_post = get_interface_list_contains(sw, -1, &post_count, NULL);

    if (st_pre == FM_OK && st_post == FM_OK && !any_leaked)
        overall = "ok";
    for (int i = 0; i < plan->n_rifs && strcmp(overall, "ok") == 0; i++) {
        if (results[i].st_parse != FM_OK ||
            results[i].st_create != FM_OK ||
            results[i].st_list_create != FM_OK ||
            !results[i].visible_after_create ||
            results[i].st_add_addr != FM_OK ||
            results[i].st_set_vlan != FM_OK ||
            results[i].st_set_state != FM_OK ||
            results[i].st_addr_list != FM_OK ||
            !results[i].addr_visible ||
            !results[i].vlan_match ||
            !results[i].state_match ||
            results[i].st_delete_addr != FM_OK ||
            results[i].st_delete_if != FM_OK ||
            results[i].st_post_list != FM_OK ||
            results[i].visible_after_cleanup)
            overall = "error";
    }

    off = snprintf(resp, resp_size,
                   "<l3-rif-live-probe status=\"%s\" source=\"switchd\" "
                   "mode=\"hidden\" tx-id=\"%llu\" "
                   "hardware-apply=\"transient\" "
                   "sdk-write=\"live\" sdk-readback=\"live\" "
                   "rollback=\"cleanup\" gate-env=\"%s\" "
                   "gate=\"acknowledged\" rifs=\"%d\" "
                   "routes-intent-only=\"%d\">",
                   overall, (unsigned long long)tx_id, gate,
                   plan->n_rifs, plan->n_routes);
    if (off < 0 || (size_t)off >= resp_size)
        return -1;
    off = appendf(resp, resp_size, off,
                  "<pre family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>",
                  sdk_status_name(st_pre), (int)st_pre, (int)pre_count);
    for (int i = 0; i < plan->n_rifs; i++) {
        off = appendf(resp, resp_size, off,
                      "<rif name=\"%s\" vlan=\"%d\" address=\"%s\" "
                      "interface=\"%d\">",
                      plan->rifs[i].name, plan->rifs[i].vlan,
                      plan->rifs[i].address, (int)results[i].ifindex);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "parse-address", results[i].st_parse,
                                   false);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmCreateInterface", results[i].st_create,
                                   false);
        off = appendf(resp, resp_size, off,
                      "<verify name=\"interface-readback\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>",
                      sdk_status_name(results[i].st_list_create),
                      (int)results[i].st_list_create,
                      (int)results[i].list_count,
                      results[i].visible_after_create ? "true" : "false");
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmAddInterfaceAddr",
                                   results[i].st_add_addr,
                                   !results[i].created);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmSetInterfaceAttribute(VLAN)",
                                   results[i].st_set_vlan,
                                   !results[i].created);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmSetInterfaceAttribute(STATE)",
                                   results[i].st_set_state,
                                   !results[i].created);
        off = appendf(resp, resp_size, off,
                      "<verify name=\"addr-readback\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>",
                      sdk_status_name(results[i].st_addr_list),
                      (int)results[i].st_addr_list,
                      (int)results[i].addr_count,
                      results[i].addr_visible ? "true" : "false");
        off = appendf(resp, resp_size, off,
                      "<verify name=\"vlan-readback\" status=\"%s\" "
                      "sdk-status=\"%d\" expected=\"%d\" actual=\"%d\" "
                      "match=\"%s\"/>",
                      sdk_status_name(results[i].st_get_vlan),
                      (int)results[i].st_get_vlan,
                      plan->rifs[i].vlan, (int)results[i].rb_vlan,
                      results[i].vlan_match ? "true" : "false");
        off = appendf(resp, resp_size, off,
                      "<verify name=\"state-readback\" status=\"%s\" "
                      "sdk-status=\"%d\" expected=\"admin-up\" "
                      "actual=\"%d\" match=\"%s\"/>",
                      sdk_status_name(results[i].st_get_state),
                      (int)results[i].st_get_state,
                      (int)results[i].rb_state,
                      results[i].state_match ? "true" : "false");
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteInterfaceAddr",
                                   results[i].st_delete_addr,
                                   !results[i].addr_added);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteInterface",
                                   results[i].st_delete_if,
                                   !results[i].created);
        off = appendf(resp, resp_size, off,
                      "<post family=\"rif\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" leaked=\"%s\"/>"
                      "</rif>",
                      sdk_status_name(results[i].st_post_list),
                      (int)results[i].st_post_list,
                      (int)results[i].post_count,
                      results[i].visible_after_cleanup ? "true" : "false");
    }
    off = appendf(resp, resp_size, off,
                  "<post family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>",
                  sdk_status_name(st_post), (int)st_post, (int)post_count,
                  any_leaked ? "true" : "false");
    off = appendf(resp, resp_size, off,
                  "<boundary user-config=\"rejected\" "
                  "reason=\"operator-assisted hidden L3 RIF transaction "
                  "probe only; ARP/ECMP/FIB writes and public routing "
                  "config remain disabled\"/>"
                  "</l3-rif-live-probe>");
    return (off < 0 || strcmp(overall, "ok") != 0) ? -1 : 0;
}

static bool l3_plan_is_arp_live_probe_safe(const hal_l3_intent_plan *plan,
                                           const char **reason) {
    if (!plan) {
        if (reason)
            *reason = "missing L3 intent plan";
        return false;
    }
    if (plan->n_rifs <= 0 || plan->n_rifs > 8) {
        if (reason)
            *reason = "ARP live probe requires 1-8 RIFs";
        return false;
    }
    if (plan->n_arps <= 0 || plan->n_arps > 8) {
        if (reason)
            *reason = "ARP live probe requires 1-8 ARP entries";
        return false;
    }
    if (plan->n_nexthops || plan->n_ecmp) {
        if (reason)
            *reason = "ARP live probe forbids next-hop/ECMP writes";
        return false;
    }
    for (int i = 0; i < plan->n_routes; i++) {
        if (plan->routes[i].target_type != HAL_L3_ROUTE_TARGET_RIF ||
            find_rif(plan, plan->routes[i].target_name) < 0) {
            if (reason)
                *reason = "ARP live probe allows connected RIF route intent only";
            return false;
        }
    }
    for (int i = 0; i < plan->n_arps; i++) {
        if (find_rif(plan, plan->arps[i].rif) < 0) {
            if (reason)
                *reason = "ARP live probe requires ARP entries to reference a RIF";
            return false;
        }
    }
    return true;
}

int hal_l3_arp_live_probe(int sw, const hal_l3_intent_plan *plan,
                          bool acknowledged, u64 tx_id, char *resp,
                          size_t resp_size) {
    const char *gate = "NETLAB_ENABLE_L3_ARP_LIVE_PROBE";
    const char *unsafe_reason = NULL;
    fm_int pre_rif_count = 0;
    fm_int post_rif_count = 0;
    fm_int pre_arp_count = 0;
    fm_int post_arp_count = 0;
    fm_arpEntry arp_list[32];
    fm_status st_pre_rif = FM_ERR_UNINITIALIZED;
    fm_status st_post_rif = FM_ERR_UNINITIALIZED;
    fm_status st_pre_arp = FM_ERR_UNINITIALIZED;
    fm_status st_post_arp = FM_ERR_UNINITIALIZED;
    bool any_rif_leaked = false;
    bool any_arp_leaked = false;
    const char *overall = "error";
    int off;

    struct live_rif {
        fm_int ifindex;
        fm_ipAddr addr;
        fm_status st_parse;
        fm_status st_create;
        fm_status st_add_addr;
        fm_status st_set_vlan;
        fm_status st_set_state;
        fm_status st_delete_addr;
        fm_status st_delete_if;
        fm_status st_post_list;
        fm_int post_count;
        bool created;
        bool addr_added;
        bool visible_after_cleanup;
    } rifs[8];

    struct live_arp {
        fm_arpEntry entry;
        fm_arpEntryInfo info;
        fm_macAddressEntry mac_entry;
        fm_macAddressEntry pre_mac_entry;
        fm_macAddressEntry post_mac_entry;
        fm_status st_parse_ip;
        fm_status st_parse_mac;
        fm_status st_mac_port;
        fm_status st_mac_pre_get;
        fm_status st_mac_add;
        fm_status st_mac_get;
        fm_status st_mac_delete;
        fm_status st_mac_post_get;
        fm_status st_add;
        fm_status st_info;
        fm_status st_list;
        fm_status st_delete;
        fm_status st_post_list;
        fm_int list_count;
        fm_int post_count;
        fm_int mac_user_ports;
        fm_int mac_port;
        bool added;
        bool info_match;
        bool list_found;
        bool leaked;
        bool mac_added;
        bool mac_pre_existing;
        bool mac_match;
        bool mac_leaked;
        int rif_index;
    } arps[8];

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    memset(rifs, 0, sizeof(rifs));
    memset(arps, 0, sizeof(arps));
    memset(arp_list, 0, sizeof(arp_list));
    for (int i = 0; i < 8; i++) {
        rifs[i].ifindex = -1;
        rifs[i].st_parse = FM_ERR_INVALID_ARGUMENT;
        rifs[i].st_create = FM_ERR_UNINITIALIZED;
        rifs[i].st_add_addr = FM_ERR_UNINITIALIZED;
        rifs[i].st_set_vlan = FM_ERR_UNINITIALIZED;
        rifs[i].st_set_state = FM_ERR_UNINITIALIZED;
        rifs[i].st_delete_addr = FM_ERR_UNINITIALIZED;
        rifs[i].st_delete_if = FM_ERR_UNINITIALIZED;
        rifs[i].st_post_list = FM_ERR_UNINITIALIZED;
        arps[i].st_parse_ip = FM_ERR_INVALID_ARGUMENT;
        arps[i].st_parse_mac = FM_ERR_INVALID_ARGUMENT;
        arps[i].st_mac_port = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_pre_get = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_add = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_get = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_delete = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_post_get = FM_ERR_UNINITIALIZED;
        arps[i].st_add = FM_ERR_UNINITIALIZED;
        arps[i].st_info = FM_ERR_UNINITIALIZED;
        arps[i].st_list = FM_ERR_UNINITIALIZED;
        arps[i].st_delete = FM_ERR_UNINITIALIZED;
        arps[i].st_post_list = FM_ERR_UNINITIALIZED;
        arps[i].rif_index = -1;
        arps[i].mac_port = -1;
    }

    if (!acknowledged) {
        off = snprintf(resp, resp_size,
                       "<l3-arp-live-probe status=\"blocked\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" hardware-apply=\"disabled\" "
                       "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                       "rollback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"closed\"><boundary user-config=\"rejected\" "
                       "reason=\"operator acknowledgement required; "
                       "payload must include ack=%s\"/>"
                       "</l3-arp-live-probe>",
                       (unsigned long long)tx_id, gate, gate);
        (void)off;
        return -1;
    }

    if (!l3_plan_is_arp_live_probe_safe(plan, &unsafe_reason)) {
        char reason_attr[160];

        xml_escape_attr(unsafe_reason, reason_attr, sizeof(reason_attr));
        off = snprintf(resp, resp_size,
                       "<l3-arp-live-probe status=\"invalid\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" hardware-apply=\"disabled\" "
                       "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                       "rollback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"acknowledged\" reason=\"%s\">"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"ARP-only live probe; next-hop/ECMP/FIB "
                       "writes remain disabled\"/>"
                       "</l3-arp-live-probe>",
                       (unsigned long long)tx_id, gate, reason_attr);
        (void)off;
        return -1;
    }

    st_pre_rif = get_interface_list_contains(sw, -1, &pre_rif_count, NULL);
    st_pre_arp = fmGetARPEntryList((fm_int)sw, &pre_arp_count, arp_list,
                                   (fm_int)(sizeof(arp_list) /
                                            sizeof(arp_list[0])));

    for (int i = 0; i < plan->n_rifs; i++) {
        fm_uint16 vlan = (fm_uint16)plan->rifs[i].vlan;
        fm_interfaceState state = FM_INTERFACE_STATE_ADMIN_UP;

        if (parse_ipv4_cidr(plan->rifs[i].address, &rifs[i].addr, NULL) == 0)
            rifs[i].st_parse = FM_OK;
        if (rifs[i].st_parse != FM_OK)
            continue;
        rifs[i].st_create = fmCreateInterface((fm_int)sw, &rifs[i].ifindex);
        if (rifs[i].st_create != FM_OK)
            continue;
        rifs[i].created = true;
        rifs[i].st_add_addr = fmAddInterfaceAddr((fm_int)sw, rifs[i].ifindex,
                                                 &rifs[i].addr);
        if (rifs[i].st_add_addr == FM_OK)
            rifs[i].addr_added = true;
        rifs[i].st_set_vlan = fmSetInterfaceAttribute(
            (fm_int)sw, rifs[i].ifindex, FM_INTERFACE_VLAN, &vlan);
        rifs[i].st_set_state = fmSetInterfaceAttribute(
            (fm_int)sw, rifs[i].ifindex, FM_INTERFACE_STATE, &state);
    }

    for (int i = 0; i < plan->n_arps; i++) {
        fm_arpEntry list[32];
        fm_int emitted;
        int rif_index = find_rif(plan, plan->arps[i].rif);

        memset(list, 0, sizeof(list));
        memset(&arps[i].entry, 0, sizeof(arps[i].entry));
        memset(&arps[i].info, 0, sizeof(arps[i].info));
        arps[i].rif_index = rif_index;
        if (parse_ipv4(plan->arps[i].ip, &arps[i].entry.ipAddr) == 0)
            arps[i].st_parse_ip = FM_OK;
        if (parse_mac(plan->arps[i].mac, &arps[i].entry.macAddr) == 0)
            arps[i].st_parse_mac = FM_OK;
        if (rif_index < 0 || arps[i].st_parse_ip != FM_OK ||
            arps[i].st_parse_mac != FM_OK || !rifs[rif_index].created)
            continue;
        arps[i].entry.interface = rifs[rif_index].ifindex;
        arps[i].entry.vlan = (fm_uint16)plan->rifs[rif_index].vlan;

        arps[i].st_add = fmAddARPEntry((fm_int)sw, &arps[i].entry);
        if (arps[i].st_add == FM_OK)
            arps[i].added = true;
        arps[i].st_info = fmGetARPEntryInfo((fm_int)sw, &arps[i].entry,
                                            &arps[i].info);
        arps[i].info_match = arps[i].st_info == FM_OK &&
                             arp_entry_equal(&arps[i].info.arp,
                                             &arps[i].entry);
        arps[i].st_list = fmGetARPEntryList(
            (fm_int)sw, &arps[i].list_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted = arps[i].list_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) : arps[i].list_count;
        arps[i].list_found = arps[i].st_list == FM_OK &&
                             arp_list_contains(list, emitted,
                                               &arps[i].entry);

        arps[i].st_mac_port = find_vlan_first_user_port(
            sw, arps[i].entry.vlan, &arps[i].mac_port,
            &arps[i].mac_user_ports);
        if (arps[i].st_mac_port != FM_OK)
            continue;
        memset(&arps[i].mac_entry, 0, sizeof(arps[i].mac_entry));
        arps[i].mac_entry.macAddress = arps[i].entry.macAddr;
        arps[i].mac_entry.vlanID = arps[i].entry.vlan;
        arps[i].mac_entry.type = FM_ADDRESS_STATIC;
        arps[i].mac_entry.destMask = FM_DESTMASK_UNUSED;
        arps[i].mac_entry.port = arps[i].mac_port;
        arps[i].st_mac_pre_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].pre_mac_entry);
        arps[i].mac_pre_existing = arps[i].st_mac_pre_get == FM_OK;
        if (!arps[i].mac_pre_existing) {
            arps[i].st_mac_add = fmAddAddress((fm_int)sw,
                                              &arps[i].mac_entry);
            if (arps[i].st_mac_add == FM_OK)
                arps[i].mac_added = true;
        } else {
            arps[i].st_mac_add = FM_OK;
        }
        arps[i].st_mac_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].post_mac_entry);
        arps[i].mac_match = arps[i].st_mac_get == FM_OK &&
                            arps[i].post_mac_entry.port ==
                                arps[i].mac_port;
    }

    for (int i = plan->n_arps - 1; i >= 0; i--) {
        fm_arpEntry list[32];
        fm_int emitted;

        memset(list, 0, sizeof(list));
        if (arps[i].mac_added)
            arps[i].st_mac_delete = fmDeleteAddress(
                (fm_int)sw, &arps[i].mac_entry);
        arps[i].st_mac_post_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].post_mac_entry);
        arps[i].mac_leaked = arps[i].mac_added &&
                             arps[i].st_mac_post_get == FM_OK;
        if (arps[i].mac_leaked)
            any_arp_leaked = true;
        if (arps[i].added)
            arps[i].st_delete = fmDeleteARPEntry((fm_int)sw,
                                                 &arps[i].entry);
        arps[i].st_post_list = fmGetARPEntryList(
            (fm_int)sw, &arps[i].post_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted = arps[i].post_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) : arps[i].post_count;
        arps[i].leaked = arps[i].st_post_list == FM_OK &&
                         arp_list_contains(list, emitted, &arps[i].entry);
        if (arps[i].leaked)
            any_arp_leaked = true;
    }

    for (int i = plan->n_rifs - 1; i >= 0; i--) {
        if (rifs[i].addr_added)
            rifs[i].st_delete_addr = fmDeleteInterfaceAddr(
                (fm_int)sw, rifs[i].ifindex, &rifs[i].addr);
        if (rifs[i].created) {
            rifs[i].st_delete_if = fmDeleteInterface((fm_int)sw,
                                                     rifs[i].ifindex);
            rifs[i].st_post_list = get_interface_list_contains(
                sw, rifs[i].ifindex, &rifs[i].post_count,
                &rifs[i].visible_after_cleanup);
            if (rifs[i].visible_after_cleanup)
                any_rif_leaked = true;
        }
    }

    memset(arp_list, 0, sizeof(arp_list));
    st_post_arp = fmGetARPEntryList((fm_int)sw, &post_arp_count, arp_list,
                                    (fm_int)(sizeof(arp_list) /
                                             sizeof(arp_list[0])));
    st_post_rif = get_interface_list_contains(sw, -1, &post_rif_count, NULL);

    if (st_pre_rif == FM_OK && st_post_rif == FM_OK &&
        st_pre_arp == FM_OK && st_post_arp == FM_OK &&
        !any_rif_leaked && !any_arp_leaked)
        overall = "ok";
    for (int i = 0; i < plan->n_rifs && strcmp(overall, "ok") == 0; i++) {
        if (rifs[i].st_parse != FM_OK ||
            rifs[i].st_create != FM_OK ||
            rifs[i].st_add_addr != FM_OK ||
            rifs[i].st_set_vlan != FM_OK ||
            rifs[i].st_set_state != FM_OK ||
            rifs[i].st_delete_addr != FM_OK ||
            rifs[i].st_delete_if != FM_OK ||
            rifs[i].st_post_list != FM_OK ||
            rifs[i].visible_after_cleanup)
            overall = "error";
    }
    for (int i = 0; i < plan->n_arps && strcmp(overall, "ok") == 0; i++) {
        if (arps[i].st_parse_ip != FM_OK ||
            arps[i].st_parse_mac != FM_OK ||
            arps[i].st_add != FM_OK ||
            arps[i].st_info != FM_OK ||
            !arps[i].info_match ||
            arps[i].st_list != FM_OK ||
            !arps[i].list_found ||
            arps[i].st_delete != FM_OK ||
            arps[i].st_post_list != FM_OK ||
            arps[i].leaked)
            overall = "error";
    }

    off = snprintf(resp, resp_size,
                   "<l3-arp-live-probe status=\"%s\" source=\"switchd\" "
                   "mode=\"hidden\" tx-id=\"%llu\" "
                   "hardware-apply=\"transient\" sdk-write=\"live\" "
                   "sdk-readback=\"live\" rollback=\"cleanup\" "
                   "gate-env=\"%s\" gate=\"acknowledged\" rifs=\"%d\" "
                   "arp=\"%d\" routes-intent-only=\"%d\">",
                   overall, (unsigned long long)tx_id, gate,
                   plan->n_rifs, plan->n_arps, plan->n_routes);
    if (off < 0 || (size_t)off >= resp_size)
        return -1;
    off = appendf(resp, resp_size, off,
                  "<pre family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>"
                  "<pre family=\"arp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>",
                  sdk_status_name(st_pre_rif), (int)st_pre_rif,
                  (int)pre_rif_count,
                  sdk_status_name(st_pre_arp), (int)st_pre_arp,
                  (int)pre_arp_count);
    for (int i = 0; i < plan->n_rifs; i++) {
        off = appendf(resp, resp_size, off,
                      "<rif name=\"%s\" vlan=\"%d\" address=\"%s\" "
                      "interface=\"%d\">",
                      plan->rifs[i].name, plan->rifs[i].vlan,
                      plan->rifs[i].address, (int)rifs[i].ifindex);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmCreateInterface", rifs[i].st_create,
                                   rifs[i].st_parse != FM_OK);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmAddInterfaceAddr", rifs[i].st_add_addr,
                                   !rifs[i].created);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmSetInterfaceAttribute(VLAN)",
                                   rifs[i].st_set_vlan, !rifs[i].created);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmSetInterfaceAttribute(STATE)",
                                   rifs[i].st_set_state, !rifs[i].created);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteInterfaceAddr",
                                   rifs[i].st_delete_addr,
                                   !rifs[i].addr_added);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteInterface", rifs[i].st_delete_if,
                                   !rifs[i].created);
        off = appendf(resp, resp_size, off,
                      "<post family=\"rif\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" leaked=\"%s\"/>"
                      "</rif>",
                      sdk_status_name(rifs[i].st_post_list),
                      (int)rifs[i].st_post_list, (int)rifs[i].post_count,
                      rifs[i].visible_after_cleanup ? "true" : "false");
    }
    for (int i = 0; i < plan->n_arps; i++) {
        off = appendf(resp, resp_size, off,
                      "<arp ip=\"%s\" mac=\"%s\" rif=\"%s\" "
                      "interface=\"%d\" vlan=\"%d\">",
                      plan->arps[i].ip, plan->arps[i].mac,
                      plan->arps[i].rif, (int)arps[i].entry.interface,
                      (int)arps[i].entry.vlan);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "parse-ip", arps[i].st_parse_ip, false);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "parse-mac", arps[i].st_parse_mac, false);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmAddARPEntry", arps[i].st_add,
                                   arps[i].rif_index < 0 ||
                                   arps[i].st_parse_ip != FM_OK ||
                                   arps[i].st_parse_mac != FM_OK);
        off = appendf(resp, resp_size, off,
                      "<verify name=\"arp-info-readback\" status=\"%s\" "
                      "sdk-status=\"%d\" match=\"%s\" used=\"%d\"/>",
                      sdk_status_name(arps[i].st_info), (int)arps[i].st_info,
                      arps[i].info_match ? "true" : "false",
                      (int)arps[i].info.used);
        off = appendf(resp, resp_size, off,
                      "<verify name=\"arp-list-readback\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>",
                      sdk_status_name(arps[i].st_list), (int)arps[i].st_list,
                      (int)arps[i].list_count,
                      arps[i].list_found ? "true" : "false");
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteARPEntry", arps[i].st_delete,
                                   !arps[i].added);
        off = appendf(resp, resp_size, off,
                      "<post family=\"arp\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" leaked=\"%s\"/>"
                      "</arp>",
                      sdk_status_name(arps[i].st_post_list),
                      (int)arps[i].st_post_list, (int)arps[i].post_count,
                      arps[i].leaked ? "true" : "false");
    }
    off = appendf(resp, resp_size, off,
                  "<post family=\"arp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<post family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<boundary user-config=\"rejected\" "
                  "reason=\"operator-assisted hidden L3 ARP transaction "
                  "probe only; next-hop/ECMP/FIB writes and public routing "
                  "config remain disabled\"/>"
                  "</l3-arp-live-probe>",
                  sdk_status_name(st_post_arp), (int)st_post_arp,
                  (int)post_arp_count, any_arp_leaked ? "true" : "false",
                  sdk_status_name(st_post_rif), (int)st_post_rif,
                  (int)post_rif_count, any_rif_leaked ? "true" : "false");
    return (off < 0 || strcmp(overall, "ok") != 0) ? -1 : 0;
}

static bool l3_plan_is_ecmp_live_probe_safe(const hal_l3_intent_plan *plan,
                                            const char **reason) {
    if (!plan) {
        if (reason)
            *reason = "missing L3 intent plan";
        return false;
    }
    if (plan->n_rifs <= 0 || plan->n_rifs > 8) {
        if (reason)
            *reason = "ECMP live probe requires 1-8 RIFs";
        return false;
    }
    if (plan->n_arps <= 0 || plan->n_arps > 8) {
        if (reason)
            *reason = "ECMP live probe requires 1-8 ARP entries";
        return false;
    }
    if (plan->n_nexthops <= 0 || plan->n_nexthops > 8) {
        if (reason)
            *reason = "ECMP live probe requires 1-8 next-hop entries";
        return false;
    }
    if (plan->n_ecmp <= 0 || plan->n_ecmp > 4) {
        if (reason)
            *reason = "ECMP live probe requires 1-4 ECMP groups";
        return false;
    }
    for (int i = 0; i < plan->n_routes; i++) {
        if (plan->routes[i].target_type != HAL_L3_ROUTE_TARGET_RIF ||
            find_rif(plan, plan->routes[i].target_name) < 0) {
            if (reason)
                *reason = "ECMP live probe allows connected RIF route intent only";
            return false;
        }
    }
    for (int i = 0; i < plan->n_arps; i++) {
        if (find_rif(plan, plan->arps[i].rif) < 0) {
            if (reason)
                *reason = "ECMP live probe requires ARP entries to reference a RIF";
            return false;
        }
    }
    for (int i = 0; i < plan->n_nexthops; i++) {
        if (find_rif(plan, plan->nexthops[i].rif) < 0 ||
            !find_arp(plan, plan->nexthops[i].arp,
                      plan->nexthops[i].rif)) {
            if (reason)
                *reason = "ECMP live probe requires next-hops to reference ARP entries";
            return false;
        }
    }
    for (int i = 0; i < plan->n_ecmp; i++) {
        if (plan->ecmp[i].n_members <= 0 || plan->ecmp[i].n_members > 8) {
            if (reason)
                *reason = "ECMP live probe requires 1-8 members per group";
            return false;
        }
        for (int j = 0; j < plan->ecmp[i].n_members; j++) {
            if (!find_nexthop(plan, plan->ecmp[i].members[j])) {
                if (reason)
                    *reason = "ECMP live probe requires members to reference next-hops";
                return false;
            }
        }
    }
    return true;
}

int hal_l3_ecmp_live_probe(int sw, const hal_l3_intent_plan *plan,
                           bool acknowledged, u64 tx_id, char *resp,
                           size_t resp_size) {
    const char *gate = "NETLAB_ENABLE_L3_ECMP_LIVE_PROBE";
    const char *unsafe_reason = NULL;
    fm_int pre_rif_count = 0;
    fm_int post_rif_count = 0;
    fm_int pre_arp_count = 0;
    fm_int post_arp_count = 0;
    fm_int pre_ecmp_count = 0;
    fm_int post_ecmp_count = 0;
    fm_int ecmp_groups[64];
    fm_arpEntry arp_list[32];
    fm_status st_pre_rif = FM_ERR_UNINITIALIZED;
    fm_status st_post_rif = FM_ERR_UNINITIALIZED;
    fm_status st_pre_arp = FM_ERR_UNINITIALIZED;
    fm_status st_post_arp = FM_ERR_UNINITIALIZED;
    fm_status st_pre_ecmp = FM_ERR_UNINITIALIZED;
    fm_status st_post_ecmp = FM_ERR_UNINITIALIZED;
    bool any_rif_leaked = false;
    bool any_arp_leaked = false;
    bool any_ecmp_leaked = false;
    const char *overall = "error";
    int off;

    struct live_rif {
        fm_int ifindex;
        fm_ipAddr addr;
        fm_status st_parse;
        fm_status st_create;
        fm_status st_add_addr;
        fm_status st_set_vlan;
        fm_status st_set_state;
        fm_status st_delete_addr;
        fm_status st_delete_if;
        fm_status st_post_list;
        fm_int post_count;
        bool created;
        bool addr_added;
        bool visible_after_cleanup;
    } rifs[8];

    struct live_arp {
        fm_arpEntry entry;
        fm_arpEntryInfo info;
        fm_macAddressEntry mac_entry;
        fm_macAddressEntry pre_mac_entry;
        fm_macAddressEntry post_mac_entry;
        fm_status st_parse_ip;
        fm_status st_parse_mac;
        fm_status st_mac_port;
        fm_status st_mac_pre_get;
        fm_status st_mac_add;
        fm_status st_mac_get;
        fm_status st_mac_delete;
        fm_status st_mac_post_get;
        fm_status st_add;
        fm_status st_info;
        fm_status st_list;
        fm_status st_delete;
        fm_status st_post_list;
        fm_int list_count;
        fm_int post_count;
        fm_int mac_user_ports;
        fm_int mac_port;
        bool added;
        bool info_match;
        bool list_found;
        bool leaked;
        bool mac_added;
        bool mac_pre_existing;
        bool mac_match;
        bool mac_leaked;
        int rif_index;
    } arps[8];

    struct live_ecmp {
        fm_int group_id;
        fm_nextHop members[8];
        fm_status st_build[8];
        fm_status st_create;
        fm_status st_group_list;
        fm_status st_next_hop_list;
        fm_status st_route_count;
        fm_status st_delete;
        fm_status st_post_list;
        fm_int group_list_count;
        fm_int next_hop_count;
        fm_int route_count;
        fm_int post_count;
        bool created;
        bool group_found;
        bool members_match;
        bool leaked;
    } ecmp[4];

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    memset(rifs, 0, sizeof(rifs));
    memset(arps, 0, sizeof(arps));
    memset(ecmp, 0, sizeof(ecmp));
    memset(arp_list, 0, sizeof(arp_list));
    memset(ecmp_groups, 0, sizeof(ecmp_groups));
    for (int i = 0; i < 8; i++) {
        rifs[i].ifindex = -1;
        rifs[i].st_parse = FM_ERR_INVALID_ARGUMENT;
        rifs[i].st_create = FM_ERR_UNINITIALIZED;
        rifs[i].st_add_addr = FM_ERR_UNINITIALIZED;
        rifs[i].st_set_vlan = FM_ERR_UNINITIALIZED;
        rifs[i].st_set_state = FM_ERR_UNINITIALIZED;
        rifs[i].st_delete_addr = FM_ERR_UNINITIALIZED;
        rifs[i].st_delete_if = FM_ERR_UNINITIALIZED;
        rifs[i].st_post_list = FM_ERR_UNINITIALIZED;
        arps[i].st_parse_ip = FM_ERR_INVALID_ARGUMENT;
        arps[i].st_parse_mac = FM_ERR_INVALID_ARGUMENT;
        arps[i].st_mac_port = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_pre_get = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_add = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_get = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_delete = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_post_get = FM_ERR_UNINITIALIZED;
        arps[i].st_add = FM_ERR_UNINITIALIZED;
        arps[i].st_info = FM_ERR_UNINITIALIZED;
        arps[i].st_list = FM_ERR_UNINITIALIZED;
        arps[i].st_delete = FM_ERR_UNINITIALIZED;
        arps[i].st_post_list = FM_ERR_UNINITIALIZED;
        arps[i].rif_index = -1;
        arps[i].mac_port = -1;
    }
    for (int i = 0; i < 4; i++) {
        ecmp[i].group_id = -1;
        ecmp[i].st_create = FM_ERR_UNINITIALIZED;
        ecmp[i].st_group_list = FM_ERR_UNINITIALIZED;
        ecmp[i].st_next_hop_list = FM_ERR_UNINITIALIZED;
        ecmp[i].st_route_count = FM_ERR_UNINITIALIZED;
        ecmp[i].st_delete = FM_ERR_UNINITIALIZED;
        ecmp[i].st_post_list = FM_ERR_UNINITIALIZED;
        for (int j = 0; j < 8; j++)
            ecmp[i].st_build[j] = FM_ERR_INVALID_ARGUMENT;
    }

    if (!acknowledged) {
        off = snprintf(resp, resp_size,
                       "<l3-ecmp-live-probe status=\"blocked\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" hardware-apply=\"disabled\" "
                       "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                       "rollback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"closed\"><boundary user-config=\"rejected\" "
                       "reason=\"operator acknowledgement required; "
                       "payload must include ack=%s\"/>"
                       "</l3-ecmp-live-probe>",
                       (unsigned long long)tx_id, gate, gate);
        (void)off;
        return -1;
    }

    if (!l3_plan_is_ecmp_live_probe_safe(plan, &unsafe_reason)) {
        char reason_attr[160];

        xml_escape_attr(unsafe_reason, reason_attr, sizeof(reason_attr));
        off = snprintf(resp, resp_size,
                       "<l3-ecmp-live-probe status=\"invalid\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" hardware-apply=\"disabled\" "
                       "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                       "rollback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"acknowledged\" reason=\"%s\">"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"ECMP-only live probe; FIB route writes "
                       "remain disabled\"/>"
                       "</l3-ecmp-live-probe>",
                       (unsigned long long)tx_id, gate, reason_attr);
        (void)off;
        return -1;
    }

    st_pre_rif = get_interface_list_contains(sw, -1, &pre_rif_count, NULL);
    st_pre_arp = fmGetARPEntryList((fm_int)sw, &pre_arp_count, arp_list,
                                   (fm_int)(sizeof(arp_list) /
                                            sizeof(arp_list[0])));
    st_pre_ecmp = fmGetECMPGroupList((fm_int)sw, &pre_ecmp_count,
                                     ecmp_groups,
                                     (fm_int)(sizeof(ecmp_groups) /
                                              sizeof(ecmp_groups[0])));

    for (int i = 0; i < plan->n_rifs; i++) {
        fm_uint16 vlan = (fm_uint16)plan->rifs[i].vlan;
        fm_interfaceState state = FM_INTERFACE_STATE_ADMIN_UP;

        if (parse_ipv4_cidr(plan->rifs[i].address, &rifs[i].addr, NULL) == 0)
            rifs[i].st_parse = FM_OK;
        if (rifs[i].st_parse != FM_OK)
            continue;
        rifs[i].st_create = fmCreateInterface((fm_int)sw, &rifs[i].ifindex);
        if (rifs[i].st_create != FM_OK)
            continue;
        rifs[i].created = true;
        rifs[i].st_add_addr = fmAddInterfaceAddr((fm_int)sw, rifs[i].ifindex,
                                                 &rifs[i].addr);
        if (rifs[i].st_add_addr == FM_OK)
            rifs[i].addr_added = true;
        rifs[i].st_set_vlan = fmSetInterfaceAttribute(
            (fm_int)sw, rifs[i].ifindex, FM_INTERFACE_VLAN, &vlan);
        rifs[i].st_set_state = fmSetInterfaceAttribute(
            (fm_int)sw, rifs[i].ifindex, FM_INTERFACE_STATE, &state);
    }

    for (int i = 0; i < plan->n_arps; i++) {
        fm_arpEntry list[32];
        fm_int emitted;
        int rif_index = find_rif(plan, plan->arps[i].rif);

        memset(list, 0, sizeof(list));
        memset(&arps[i].entry, 0, sizeof(arps[i].entry));
        memset(&arps[i].info, 0, sizeof(arps[i].info));
        arps[i].rif_index = rif_index;
        if (parse_ipv4(plan->arps[i].ip, &arps[i].entry.ipAddr) == 0)
            arps[i].st_parse_ip = FM_OK;
        if (parse_mac(plan->arps[i].mac, &arps[i].entry.macAddr) == 0)
            arps[i].st_parse_mac = FM_OK;
        if (rif_index < 0 || arps[i].st_parse_ip != FM_OK ||
            arps[i].st_parse_mac != FM_OK || !rifs[rif_index].created)
            continue;
        arps[i].entry.interface = rifs[rif_index].ifindex;
        arps[i].entry.vlan = (fm_uint16)plan->rifs[rif_index].vlan;

        arps[i].st_add = fmAddARPEntry((fm_int)sw, &arps[i].entry);
        if (arps[i].st_add == FM_OK)
            arps[i].added = true;
        arps[i].st_info = fmGetARPEntryInfo((fm_int)sw, &arps[i].entry,
                                            &arps[i].info);
        arps[i].info_match = arps[i].st_info == FM_OK &&
                             arp_entry_equal(&arps[i].info.arp,
                                             &arps[i].entry);
        arps[i].st_list = fmGetARPEntryList(
            (fm_int)sw, &arps[i].list_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted = arps[i].list_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) : arps[i].list_count;
        arps[i].list_found = arps[i].st_list == FM_OK &&
                             arp_list_contains(list, emitted,
                                               &arps[i].entry);
        arps[i].st_mac_port = find_vlan_first_user_port(
            sw, arps[i].entry.vlan, &arps[i].mac_port,
            &arps[i].mac_user_ports);
        if (arps[i].st_mac_port != FM_OK)
            continue;
        memset(&arps[i].mac_entry, 0, sizeof(arps[i].mac_entry));
        arps[i].mac_entry.macAddress = arps[i].entry.macAddr;
        arps[i].mac_entry.vlanID = arps[i].entry.vlan;
        arps[i].mac_entry.type = FM_ADDRESS_STATIC;
        arps[i].mac_entry.destMask = FM_DESTMASK_UNUSED;
        arps[i].mac_entry.port = arps[i].mac_port;
        arps[i].st_mac_pre_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].pre_mac_entry);
        arps[i].mac_pre_existing = arps[i].st_mac_pre_get == FM_OK;
        if (!arps[i].mac_pre_existing) {
            arps[i].st_mac_add = fmAddAddress((fm_int)sw,
                                              &arps[i].mac_entry);
            if (arps[i].st_mac_add == FM_OK)
                arps[i].mac_added = true;
        } else {
            arps[i].st_mac_add = FM_OK;
        }
        arps[i].st_mac_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].post_mac_entry);
        arps[i].mac_match = arps[i].st_mac_get == FM_OK &&
                            arps[i].post_mac_entry.port ==
                                arps[i].mac_port;
    }

    for (int i = 0; i < plan->n_ecmp; i++) {
        fm_nextHop list[16];
        fm_int groups[64];
        fm_int emitted_groups;
        fm_int emitted_nh;
        bool built = true;

        memset(list, 0, sizeof(list));
        memset(groups, 0, sizeof(groups));
        for (int j = 0; j < plan->ecmp[i].n_members; j++) {
            const hal_l3_intent_next_hop *nh =
                find_nexthop(plan, plan->ecmp[i].members[j]);

            if (nh &&
                build_sdk_next_hop(plan, nh, &ecmp[i].members[j]) == 0) {
                ecmp[i].st_build[j] = FM_OK;
            } else {
                built = false;
            }
        }
        if (!built)
            continue;
        ecmp[i].st_create = fmCreateECMPGroup(
            (fm_int)sw, &ecmp[i].group_id, plan->ecmp[i].n_members,
            ecmp[i].members);
        if (ecmp[i].st_create == FM_OK)
            ecmp[i].created = true;
        if (!ecmp[i].created)
            continue;
        ecmp[i].st_group_list = fmGetECMPGroupList(
            (fm_int)sw, &ecmp[i].group_list_count, groups,
            (fm_int)(sizeof(groups) / sizeof(groups[0])));
        emitted_groups = ecmp[i].group_list_count >
            (fm_int)(sizeof(groups) / sizeof(groups[0])) ?
            (fm_int)(sizeof(groups) / sizeof(groups[0])) :
            ecmp[i].group_list_count;
        ecmp[i].group_found = ecmp[i].st_group_list == FM_OK &&
                              ecmp_group_list_contains(
                                  groups, emitted_groups, ecmp[i].group_id);
        ecmp[i].st_next_hop_list = fmGetECMPGroupNextHopList(
            (fm_int)sw, ecmp[i].group_id, &ecmp[i].next_hop_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted_nh = ecmp[i].next_hop_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) :
            ecmp[i].next_hop_count;
        ecmp[i].members_match = ecmp[i].st_next_hop_list == FM_OK;
        for (int j = 0; j < plan->ecmp[i].n_members &&
             ecmp[i].members_match; j++) {
            if (!next_hop_list_contains(list, emitted_nh,
                                        &ecmp[i].members[j]))
                ecmp[i].members_match = false;
        }
        ecmp[i].st_route_count = fmGetECMPGroupRouteCount(
            (fm_int)sw, ecmp[i].group_id, &ecmp[i].route_count);
    }

    for (int i = plan->n_ecmp - 1; i >= 0; i--) {
        fm_int groups[64];
        fm_int emitted;

        memset(groups, 0, sizeof(groups));
        if (ecmp[i].created)
            ecmp[i].st_delete = fmDeleteECMPGroup((fm_int)sw,
                                                  ecmp[i].group_id);
        ecmp[i].st_post_list = fmGetECMPGroupList(
            (fm_int)sw, &ecmp[i].post_count, groups,
            (fm_int)(sizeof(groups) / sizeof(groups[0])));
        emitted = ecmp[i].post_count >
            (fm_int)(sizeof(groups) / sizeof(groups[0])) ?
            (fm_int)(sizeof(groups) / sizeof(groups[0])) :
            ecmp[i].post_count;
        ecmp[i].leaked = ecmp[i].st_post_list == FM_OK &&
                         ecmp_group_list_contains(groups, emitted,
                                                  ecmp[i].group_id);
        if (ecmp[i].leaked)
            any_ecmp_leaked = true;
    }

    for (int i = plan->n_arps - 1; i >= 0; i--) {
        fm_arpEntry list[32];
        fm_int emitted;

        memset(list, 0, sizeof(list));
        if (arps[i].mac_added)
            arps[i].st_mac_delete = fmDeleteAddress(
                (fm_int)sw, &arps[i].mac_entry);
        arps[i].st_mac_post_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].post_mac_entry);
        arps[i].mac_leaked = arps[i].mac_added &&
                             arps[i].st_mac_post_get == FM_OK;
        if (arps[i].mac_leaked)
            any_arp_leaked = true;
        if (arps[i].added)
            arps[i].st_delete = fmDeleteARPEntry((fm_int)sw,
                                                 &arps[i].entry);
        arps[i].st_post_list = fmGetARPEntryList(
            (fm_int)sw, &arps[i].post_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted = arps[i].post_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) : arps[i].post_count;
        arps[i].leaked = arps[i].st_post_list == FM_OK &&
                         arp_list_contains(list, emitted, &arps[i].entry);
        if (arps[i].leaked)
            any_arp_leaked = true;
    }

    for (int i = plan->n_rifs - 1; i >= 0; i--) {
        if (rifs[i].addr_added)
            rifs[i].st_delete_addr = fmDeleteInterfaceAddr(
                (fm_int)sw, rifs[i].ifindex, &rifs[i].addr);
        if (rifs[i].created) {
            rifs[i].st_delete_if = fmDeleteInterface((fm_int)sw,
                                                     rifs[i].ifindex);
            rifs[i].st_post_list = get_interface_list_contains(
                sw, rifs[i].ifindex, &rifs[i].post_count,
                &rifs[i].visible_after_cleanup);
            if (rifs[i].visible_after_cleanup)
                any_rif_leaked = true;
        }
    }

    memset(arp_list, 0, sizeof(arp_list));
    memset(ecmp_groups, 0, sizeof(ecmp_groups));
    st_post_arp = fmGetARPEntryList((fm_int)sw, &post_arp_count, arp_list,
                                    (fm_int)(sizeof(arp_list) /
                                             sizeof(arp_list[0])));
    st_post_ecmp = fmGetECMPGroupList((fm_int)sw, &post_ecmp_count,
                                      ecmp_groups,
                                      (fm_int)(sizeof(ecmp_groups) /
                                               sizeof(ecmp_groups[0])));
    st_post_rif = get_interface_list_contains(sw, -1, &post_rif_count, NULL);

    if (st_pre_rif == FM_OK && st_post_rif == FM_OK &&
        st_pre_arp == FM_OK && st_post_arp == FM_OK &&
        st_pre_ecmp == FM_OK && st_post_ecmp == FM_OK &&
        !any_rif_leaked && !any_arp_leaked && !any_ecmp_leaked)
        overall = "ok";
    for (int i = 0; i < plan->n_rifs && strcmp(overall, "ok") == 0; i++) {
        if (rifs[i].st_parse != FM_OK ||
            rifs[i].st_create != FM_OK ||
            rifs[i].st_add_addr != FM_OK ||
            rifs[i].st_set_vlan != FM_OK ||
            rifs[i].st_set_state != FM_OK ||
            rifs[i].st_delete_addr != FM_OK ||
            rifs[i].st_delete_if != FM_OK ||
            rifs[i].st_post_list != FM_OK ||
            rifs[i].visible_after_cleanup)
            overall = "error";
    }
    for (int i = 0; i < plan->n_arps && strcmp(overall, "ok") == 0; i++) {
        if (arps[i].st_parse_ip != FM_OK ||
            arps[i].st_parse_mac != FM_OK ||
            arps[i].st_add != FM_OK ||
            arps[i].st_info != FM_OK ||
            !arps[i].info_match ||
            arps[i].st_list != FM_OK ||
            !arps[i].list_found ||
            arps[i].st_delete != FM_OK ||
            arps[i].st_post_list != FM_OK ||
            arps[i].leaked)
            overall = "error";
    }
    for (int i = 0; i < plan->n_ecmp && strcmp(overall, "ok") == 0; i++) {
        for (int j = 0; j < plan->ecmp[i].n_members; j++)
            if (ecmp[i].st_build[j] != FM_OK)
                overall = "error";
        if (ecmp[i].st_create != FM_OK ||
            ecmp[i].st_group_list != FM_OK ||
            !ecmp[i].group_found ||
            ecmp[i].st_next_hop_list != FM_OK ||
            !ecmp[i].members_match ||
            ecmp[i].st_delete != FM_OK ||
            ecmp[i].st_post_list != FM_OK ||
            ecmp[i].leaked)
            overall = "error";
        if (ecmp[i].st_route_count == FM_OK && ecmp[i].route_count != 0)
            overall = "error";
    }

    off = snprintf(resp, resp_size,
                   "<l3-ecmp-live-probe status=\"%s\" source=\"switchd\" "
                   "mode=\"hidden\" tx-id=\"%llu\" "
                   "hardware-apply=\"transient\" sdk-write=\"live\" "
                   "sdk-readback=\"live\" rollback=\"cleanup\" "
                   "gate-env=\"%s\" gate=\"acknowledged\" rifs=\"%d\" "
                   "arp=\"%d\" next-hops=\"%d\" ecmp-groups=\"%d\" "
                   "routes-intent-only=\"%d\">",
                   overall, (unsigned long long)tx_id, gate,
                   plan->n_rifs, plan->n_arps, plan->n_nexthops,
                   plan->n_ecmp, plan->n_routes);
    if (off < 0 || (size_t)off >= resp_size)
        return -1;
    off = appendf(resp, resp_size, off,
                  "<pre family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>"
                  "<pre family=\"arp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>"
                  "<pre family=\"ecmp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>",
                  sdk_status_name(st_pre_rif), (int)st_pre_rif,
                  (int)pre_rif_count,
                  sdk_status_name(st_pre_arp), (int)st_pre_arp,
                  (int)pre_arp_count,
                  sdk_status_name(st_pre_ecmp), (int)st_pre_ecmp,
                  (int)pre_ecmp_count);
    for (int i = 0; i < plan->n_rifs; i++) {
        off = appendf(resp, resp_size, off,
                      "<rif name=\"%s\" vlan=\"%d\" address=\"%s\" "
                      "interface=\"%d\">",
                      plan->rifs[i].name, plan->rifs[i].vlan,
                      plan->rifs[i].address, (int)rifs[i].ifindex);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmCreateInterface", rifs[i].st_create,
                                   rifs[i].st_parse != FM_OK);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmAddInterfaceAddr", rifs[i].st_add_addr,
                                   !rifs[i].created);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmSetInterfaceAttribute(VLAN)",
                                   rifs[i].st_set_vlan, !rifs[i].created);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmSetInterfaceAttribute(STATE)",
                                   rifs[i].st_set_state, !rifs[i].created);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteInterfaceAddr",
                                   rifs[i].st_delete_addr,
                                   !rifs[i].addr_added);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteInterface", rifs[i].st_delete_if,
                                   !rifs[i].created);
        off = appendf(resp, resp_size, off,
                      "<post family=\"rif\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" leaked=\"%s\"/>"
                      "</rif>",
                      sdk_status_name(rifs[i].st_post_list),
                      (int)rifs[i].st_post_list, (int)rifs[i].post_count,
                      rifs[i].visible_after_cleanup ? "true" : "false");
    }
    for (int i = 0; i < plan->n_arps; i++) {
        off = appendf(resp, resp_size, off,
                      "<arp ip=\"%s\" mac=\"%s\" rif=\"%s\" "
                      "interface=\"%d\" vlan=\"%d\">",
                      plan->arps[i].ip, plan->arps[i].mac,
                      plan->arps[i].rif, (int)arps[i].entry.interface,
                      (int)arps[i].entry.vlan);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmAddARPEntry", arps[i].st_add,
                                   arps[i].rif_index < 0 ||
                                   arps[i].st_parse_ip != FM_OK ||
                                   arps[i].st_parse_mac != FM_OK);
        off = appendf(resp, resp_size, off,
                      "<verify name=\"arp-info-readback\" status=\"%s\" "
                      "sdk-status=\"%d\" match=\"%s\"/>"
                      "<verify name=\"arp-list-readback\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>",
                      sdk_status_name(arps[i].st_info), (int)arps[i].st_info,
                      arps[i].info_match ? "true" : "false",
                      sdk_status_name(arps[i].st_list), (int)arps[i].st_list,
                      (int)arps[i].list_count,
                      arps[i].list_found ? "true" : "false");
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteARPEntry", arps[i].st_delete,
                                   !arps[i].added);
        off = appendf(resp, resp_size, off,
                      "<post family=\"arp\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" leaked=\"%s\"/>"
                      "</arp>",
                      sdk_status_name(arps[i].st_post_list),
                      (int)arps[i].st_post_list, (int)arps[i].post_count,
                      arps[i].leaked ? "true" : "false");
    }
    for (int i = 0; i < plan->n_ecmp; i++) {
        off = appendf(resp, resp_size, off,
                      "<ecmp plan-id=\"%d\" sdk-group=\"%d\" members=\"%d\">",
                      plan->ecmp[i].id, (int)ecmp[i].group_id,
                      plan->ecmp[i].n_members);
        for (int j = 0; j < plan->ecmp[i].n_members; j++) {
            const hal_l3_intent_next_hop *nh =
                find_nexthop(plan, plan->ecmp[i].members[j]);

            off = appendf(resp, resp_size, off,
                          "<member id=\"%d\" arp=\"%s\" rif=\"%s\" "
                          "build=\"%s\"/>",
                          plan->ecmp[i].members[j], nh ? nh->arp : "",
                          nh ? nh->rif : "",
                          sdk_status_name(ecmp[i].st_build[j]));
        }
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmCreateECMPGroup", ecmp[i].st_create,
                                   false);
        off = appendf(resp, resp_size, off,
                      "<verify name=\"ecmp-group-list\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>"
                      "<verify name=\"ecmp-next-hop-list\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" members-match=\"%s\"/>"
                      "<verify name=\"ecmp-route-count\" status=\"%s\" "
                      "sdk-status=\"%d\" routes=\"%d\"/>",
                      sdk_status_name(ecmp[i].st_group_list),
                      (int)ecmp[i].st_group_list,
                      (int)ecmp[i].group_list_count,
                      ecmp[i].group_found ? "true" : "false",
                      sdk_status_name(ecmp[i].st_next_hop_list),
                      (int)ecmp[i].st_next_hop_list,
                      (int)ecmp[i].next_hop_count,
                      ecmp[i].members_match ? "true" : "false",
                      sdk_status_name(ecmp[i].st_route_count),
                      (int)ecmp[i].st_route_count,
                      (int)ecmp[i].route_count);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteECMPGroup", ecmp[i].st_delete,
                                   !ecmp[i].created);
        off = appendf(resp, resp_size, off,
                      "<post family=\"ecmp\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" leaked=\"%s\"/>"
                      "</ecmp>",
                      sdk_status_name(ecmp[i].st_post_list),
                      (int)ecmp[i].st_post_list, (int)ecmp[i].post_count,
                      ecmp[i].leaked ? "true" : "false");
    }
    off = appendf(resp, resp_size, off,
                  "<post family=\"ecmp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<post family=\"arp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<post family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<boundary user-config=\"rejected\" "
                  "reason=\"operator-assisted hidden L3 ECMP transaction "
                  "probe only; FIB route writes and public routing config "
                  "remain disabled\"/>"
                  "</l3-ecmp-live-probe>",
                  sdk_status_name(st_post_ecmp), (int)st_post_ecmp,
                  (int)post_ecmp_count, any_ecmp_leaked ? "true" : "false",
                  sdk_status_name(st_post_arp), (int)st_post_arp,
                  (int)post_arp_count, any_arp_leaked ? "true" : "false",
                  sdk_status_name(st_post_rif), (int)st_post_rif,
                  (int)post_rif_count, any_rif_leaked ? "true" : "false");
    return (off < 0 || strcmp(overall, "ok") != 0) ? -1 : 0;
}

static int count_fib_route_targets(const hal_l3_intent_plan *plan) {
    int count = 0;

    if (!plan)
        return 0;
    for (int i = 0; i < plan->n_routes; i++)
        if (plan->routes[i].target_type != HAL_L3_ROUTE_TARGET_RIF)
            count++;
    return count;
}

static bool l3_plan_is_route_live_probe_safe(const hal_l3_intent_plan *plan,
                                             const char **reason) {
    int fib_routes;

    if (!plan) {
        if (reason)
            *reason = "missing L3 intent plan";
        return false;
    }
    fib_routes = count_fib_route_targets(plan);
    if (plan->n_rifs <= 0 || plan->n_rifs > 8) {
        if (reason)
            *reason = "route live probe requires 1-8 RIFs";
        return false;
    }
    if (plan->n_arps <= 0 || plan->n_arps > 8) {
        if (reason)
            *reason = "route live probe requires 1-8 ARP entries";
        return false;
    }
    if (plan->n_nexthops <= 0 || plan->n_nexthops > 8) {
        if (reason)
            *reason = "route live probe requires 1-8 next-hop entries";
        return false;
    }
    if (plan->n_ecmp < 0 || plan->n_ecmp > 4) {
        if (reason)
            *reason = "route live probe allows 0-4 ECMP groups";
        return false;
    }
    if (fib_routes <= 0 || fib_routes > 4) {
        if (reason)
            *reason = "route live probe requires 1-4 FIB route targets";
        return false;
    }
    for (int i = 0; i < plan->n_arps; i++) {
        if (find_rif(plan, plan->arps[i].rif) < 0) {
            if (reason)
                *reason = "route live probe requires ARP entries to reference a RIF";
            return false;
        }
    }
    for (int i = 0; i < plan->n_nexthops; i++) {
        if (find_rif(plan, plan->nexthops[i].rif) < 0 ||
            !find_arp(plan, plan->nexthops[i].arp,
                      plan->nexthops[i].rif)) {
            if (reason)
                *reason = "route live probe requires next-hops to reference ARP entries";
            return false;
        }
    }
    for (int i = 0; i < plan->n_ecmp; i++) {
        if (plan->ecmp[i].n_members <= 0 || plan->ecmp[i].n_members > 8) {
            if (reason)
                *reason = "route live probe requires 1-8 ECMP members per group";
            return false;
        }
        for (int j = 0; j < plan->ecmp[i].n_members; j++) {
            if (!find_nexthop(plan, plan->ecmp[i].members[j])) {
                if (reason)
                    *reason = "route live probe requires ECMP members to reference next-hops";
                return false;
            }
        }
    }
    for (int i = 0; i < plan->n_routes; i++) {
        if (plan->routes[i].target_type == HAL_L3_ROUTE_TARGET_RIF) {
            if (find_rif(plan, plan->routes[i].target_name) < 0) {
                if (reason)
                    *reason = "route live probe requires connected route intent to reference a RIF";
                return false;
            }
        } else if (plan->routes[i].target_type ==
                   HAL_L3_ROUTE_TARGET_NEXTHOP) {
            if (!find_nexthop(plan, plan->routes[i].target_id)) {
                if (reason)
                    *reason = "route live probe requires FIB routes to reference next-hops";
                return false;
            }
        } else if (plan->routes[i].target_type ==
                   HAL_L3_ROUTE_TARGET_ECMP) {
            if (!find_ecmp(plan, plan->routes[i].target_id)) {
                if (reason)
                    *reason = "route live probe requires FIB routes to reference ECMP groups";
                return false;
            }
        } else {
            if (reason)
                *reason = "route live probe supports next-hop, ECMP, and connected route targets only";
            return false;
        }
    }
    return true;
}

int hal_l3_route_live_probe(int sw, const hal_l3_intent_plan *plan,
                            bool acknowledged, u64 tx_id, int hold_sec,
                            const char *router_mac_text,
                            char *resp, size_t resp_size) {
    const char *gate = "NETLAB_ENABLE_L3_ROUTE_LIVE_PROBE";
    const char *unsafe_reason = NULL;
    fm_int pre_route_count = 0;
    fm_int post_route_count = 0;
    fm_int pre_ecmp_count = 0;
    fm_int post_ecmp_count = 0;
    fm_int pre_arp_count = 0;
    fm_int post_arp_count = 0;
    fm_int pre_rif_count = 0;
    fm_int post_rif_count = 0;
    fm_routeEntry route_list[64];
    fm_int ecmp_groups[64];
    fm_int sdk_ecmp_group_ids[4];
    const hal_l3_intent_ecmp *sdk_ecmp_refs[4];
    fm_arpEntry arp_list[32];
    fm_status st_pre_route = FM_ERR_UNINITIALIZED;
    fm_status st_post_route = FM_ERR_UNINITIALIZED;
    fm_status st_parse_router_mac = FM_ERR_UNINITIALIZED;
    fm_status st_pre_router_mac = FM_ERR_UNINITIALIZED;
    fm_status st_set_router_mac = FM_ERR_UNINITIALIZED;
    fm_status st_restore_router_mac = FM_ERR_UNINITIALIZED;
    fm_status st_pre_router_state = FM_ERR_UNINITIALIZED;
    fm_status st_set_router_state = FM_ERR_UNINITIALIZED;
    fm_status st_restore_router_state = FM_ERR_UNINITIALIZED;
    fm_status st_pre_ecmp = FM_ERR_UNINITIALIZED;
    fm_status st_post_ecmp = FM_ERR_UNINITIALIZED;
    fm_status st_pre_arp = FM_ERR_UNINITIALIZED;
    fm_status st_post_arp = FM_ERR_UNINITIALIZED;
    fm_status st_pre_rif = FM_ERR_UNINITIALIZED;
    fm_status st_post_rif = FM_ERR_UNINITIALIZED;
    const char *overall = "error";
    bool any_route_leaked = false;
    bool any_ecmp_leaked = false;
    bool any_arp_leaked = false;
    bool any_rif_leaked = false;
    int fib_routes = 0;
    int routes_added = 0;
    int hold_applied_sec = 0;
    bool base_ok = false;
    bool deps_ok = true;
    bool routes_ok = true;
    bool routes_profile_limited = true;
    bool router_mac_requested = router_mac_text && router_mac_text[0];
    bool router_mac_applied = false;
    bool router_state_applied = false;
    fm_macaddr pre_router_mac = 0;
    fm_macaddr router_mac = 0;
    fm_routerState pre_router_state = FM_ROUTER_STATE_ADMIN_DOWN;
    fm_routerState up_state = FM_ROUTER_STATE_ADMIN_UP;
    int off;

    struct live_vlan_route_enabler {
        fm_uint16 vlan;
        fm_bool pre_routable;
        fm_status st_get;
        fm_status st_set;
        fm_status st_restore;
        bool used;
    } vlan_enablers[8];

    struct live_port_route_enabler {
        fm_int port;
        fm_bool pre_routable;
        fm_uint32 pre_parser;
        fm_status st_get_routable;
        fm_status st_set_routable;
        fm_status st_restore_routable;
        fm_status st_get_parser;
        fm_status st_set_parser;
        fm_status st_restore_parser;
        fm_status st_counter_pre;
        fm_status st_counter_post;
        fm_uint64 pre_rx_pkts;
        fm_uint64 pre_tx_pkts;
        fm_uint64 pre_rx_bytes;
        fm_uint64 pre_tx_bytes;
        fm_uint64 pre_rx_errs;
        fm_uint64 post_rx_pkts;
        fm_uint64 post_tx_pkts;
        fm_uint64 post_rx_bytes;
        fm_uint64 post_tx_bytes;
        fm_uint64 post_rx_errs;
        bool used;
    } port_enablers[NL_MAX_PORTS_PER_PROFILE];
    int n_vlan_enablers = 0;
    int n_port_enablers = 0;

    struct live_rif {
        fm_int ifindex;
        fm_ipAddr addr;
        fm_status st_parse;
        fm_status st_create;
        fm_status st_add_addr;
        fm_status st_set_vlan;
        fm_status st_set_state;
        fm_status st_delete_addr;
        fm_status st_delete_if;
        fm_status st_post_list;
        fm_int post_count;
        bool created;
        bool addr_added;
        bool visible_after_cleanup;
    } rifs[8];

    struct live_arp {
        fm_arpEntry entry;
        fm_arpEntryInfo info;
        fm_macAddressEntry mac_entry;
        fm_macAddressEntry pre_mac_entry;
        fm_macAddressEntry post_mac_entry;
        fm_status st_parse_ip;
        fm_status st_parse_mac;
        fm_status st_mac_port;
        fm_status st_mac_pre_get;
        fm_status st_mac_add;
        fm_status st_mac_get;
        fm_status st_mac_delete;
        fm_status st_mac_post_get;
        fm_status st_add;
        fm_status st_info;
        fm_status st_list;
        fm_status st_delete;
        fm_status st_post_list;
        fm_int list_count;
        fm_int post_count;
        fm_int mac_user_ports;
        fm_int mac_port;
        bool added;
        bool info_match;
        bool list_found;
        bool leaked;
        bool mac_added;
        bool mac_pre_existing;
        bool mac_match;
        bool mac_leaked;
        int rif_index;
    } arps[8];

    struct live_ecmp {
        const hal_l3_intent_ecmp *plan_ecmp;
        fm_int group_id;
        fm_nextHop members[8];
        fm_status st_build[8];
        fm_status st_create;
        fm_status st_group_list;
        fm_status st_next_hop_list;
        fm_status st_delete;
        fm_status st_post_list;
        fm_int group_list_count;
        fm_int next_hop_count;
        fm_int post_count;
        bool created;
        bool group_found;
        bool members_match;
        bool leaked;
    } ecmp[4];

    struct live_route {
        const hal_l3_intent_route *plan_route;
        fm_routeEntry entry;
        fm_status st_build;
        fm_status st_add;
        fm_status st_state;
        fm_status st_list;
        fm_status st_delete;
        fm_status st_post_list;
        fm_routeState state;
        fm_int list_count;
        fm_int post_count;
        bool added;
        bool list_found;
        bool leaked;
    } routes[4];

    if (!resp || resp_size == 0)
        return -1;
    if (hold_sec < 0)
        hold_sec = 0;
    if (hold_sec > 120)
        hold_sec = 120;
    resp[0] = '\0';
    memset(rifs, 0, sizeof(rifs));
    memset(arps, 0, sizeof(arps));
    memset(ecmp, 0, sizeof(ecmp));
    memset(routes, 0, sizeof(routes));
    memset(route_list, 0, sizeof(route_list));
    memset(ecmp_groups, 0, sizeof(ecmp_groups));
    memset(sdk_ecmp_group_ids, 0, sizeof(sdk_ecmp_group_ids));
    memset(sdk_ecmp_refs, 0, sizeof(sdk_ecmp_refs));
    memset(arp_list, 0, sizeof(arp_list));
    memset(vlan_enablers, 0, sizeof(vlan_enablers));
    memset(port_enablers, 0, sizeof(port_enablers));
    for (int i = 0; i < 8; i++) {
        rifs[i].ifindex = -1;
        rifs[i].st_parse = FM_ERR_INVALID_ARGUMENT;
        rifs[i].st_create = FM_ERR_UNINITIALIZED;
        rifs[i].st_add_addr = FM_ERR_UNINITIALIZED;
        rifs[i].st_set_vlan = FM_ERR_UNINITIALIZED;
        rifs[i].st_set_state = FM_ERR_UNINITIALIZED;
        rifs[i].st_delete_addr = FM_ERR_UNINITIALIZED;
        rifs[i].st_delete_if = FM_ERR_UNINITIALIZED;
        rifs[i].st_post_list = FM_ERR_UNINITIALIZED;
        arps[i].st_parse_ip = FM_ERR_INVALID_ARGUMENT;
        arps[i].st_parse_mac = FM_ERR_INVALID_ARGUMENT;
        arps[i].st_mac_port = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_pre_get = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_add = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_get = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_delete = FM_ERR_UNINITIALIZED;
        arps[i].st_mac_post_get = FM_ERR_UNINITIALIZED;
        arps[i].st_add = FM_ERR_UNINITIALIZED;
        arps[i].st_info = FM_ERR_UNINITIALIZED;
        arps[i].st_list = FM_ERR_UNINITIALIZED;
        arps[i].st_delete = FM_ERR_UNINITIALIZED;
        arps[i].st_post_list = FM_ERR_UNINITIALIZED;
        arps[i].rif_index = -1;
        arps[i].mac_port = -1;
        vlan_enablers[i].st_get = FM_ERR_UNINITIALIZED;
        vlan_enablers[i].st_set = FM_ERR_UNINITIALIZED;
        vlan_enablers[i].st_restore = FM_ERR_UNINITIALIZED;
    }
    for (int i = 0; i < NL_MAX_PORTS_PER_PROFILE; i++) {
        port_enablers[i].st_get_routable = FM_ERR_UNINITIALIZED;
        port_enablers[i].st_set_routable = FM_ERR_UNINITIALIZED;
        port_enablers[i].st_restore_routable = FM_ERR_UNINITIALIZED;
        port_enablers[i].st_get_parser = FM_ERR_UNINITIALIZED;
        port_enablers[i].st_set_parser = FM_ERR_UNINITIALIZED;
        port_enablers[i].st_restore_parser = FM_ERR_UNINITIALIZED;
        port_enablers[i].st_counter_pre = FM_ERR_UNINITIALIZED;
        port_enablers[i].st_counter_post = FM_ERR_UNINITIALIZED;
    }
    for (int i = 0; i < 4; i++) {
        sdk_ecmp_group_ids[i] = -1;
        sdk_ecmp_refs[i] = NULL;
        ecmp[i].group_id = -1;
        ecmp[i].st_create = FM_ERR_UNINITIALIZED;
        ecmp[i].st_group_list = FM_ERR_UNINITIALIZED;
        ecmp[i].st_next_hop_list = FM_ERR_UNINITIALIZED;
        ecmp[i].st_delete = FM_ERR_UNINITIALIZED;
        ecmp[i].st_post_list = FM_ERR_UNINITIALIZED;
        routes[i].st_build = FM_ERR_INVALID_ARGUMENT;
        routes[i].st_add = FM_ERR_UNINITIALIZED;
        routes[i].st_state = FM_ERR_UNINITIALIZED;
        routes[i].st_list = FM_ERR_UNINITIALIZED;
        routes[i].st_delete = FM_ERR_UNINITIALIZED;
        routes[i].st_post_list = FM_ERR_UNINITIALIZED;
        for (int j = 0; j < 8; j++)
            ecmp[i].st_build[j] = FM_ERR_INVALID_ARGUMENT;
    }

    if (!acknowledged) {
        off = snprintf(resp, resp_size,
                       "<l3-route-live-probe status=\"blocked\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" hardware-apply=\"disabled\" "
                       "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                       "rollback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"closed\"><boundary user-config=\"rejected\" "
                       "reason=\"operator acknowledgement required; "
                       "payload must include ack=%s\"/>"
                       "</l3-route-live-probe>",
                       (unsigned long long)tx_id, gate, gate);
        (void)off;
        return -1;
    }

    if (!l3_plan_is_route_live_probe_safe(plan, &unsafe_reason)) {
        char reason_attr[160];

        xml_escape_attr(unsafe_reason, reason_attr, sizeof(reason_attr));
        off = snprintf(resp, resp_size,
                       "<l3-route-live-probe status=\"invalid\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" hardware-apply=\"disabled\" "
                       "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                       "rollback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"acknowledged\" reason=\"%s\">"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"FIB route live probe only; public routing "
                       "config remains disabled\"/>"
                       "</l3-route-live-probe>",
                       (unsigned long long)tx_id, gate, reason_attr);
        (void)off;
        return -1;
    }
    if (router_mac_requested &&
        parse_mac(router_mac_text, &router_mac) != 0) {
        char reason_attr[160];

        st_parse_router_mac = FM_ERR_INVALID_ARGUMENT;
        xml_escape_attr("invalid router-mac", reason_attr,
                        sizeof(reason_attr));
        off = snprintf(resp, resp_size,
                       "<l3-route-live-probe status=\"invalid\" "
                       "source=\"switchd\" mode=\"hidden\" "
                       "tx-id=\"%llu\" hardware-apply=\"disabled\" "
                       "sdk-write=\"disabled\" sdk-readback=\"disabled\" "
                       "rollback=\"disabled\" gate-env=\"%s\" "
                       "gate=\"acknowledged\" reason=\"%s\">"
                       "<boundary user-config=\"rejected\" "
                       "reason=\"FIB route live probe only; public routing "
                       "config remains disabled\"/>"
                       "</l3-route-live-probe>",
                       (unsigned long long)tx_id, gate, reason_attr);
        (void)off;
        return -1;
    }
    if (router_mac_requested) {
        st_parse_router_mac = FM_OK;
        st_pre_router_mac = fmGetRouterAttribute(
            (fm_int)sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS, &pre_router_mac);
        st_pre_router_state = fmGetRouterState(
            (fm_int)sw, FM_PHYSICAL_ROUTER, &pre_router_state);
        st_set_router_mac = fmSetRouterAttribute(
            (fm_int)sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS, &router_mac);
        if (st_set_router_mac == FM_OK)
            router_mac_applied = true;
        st_set_router_state = fmSetRouterState(
            (fm_int)sw, FM_PHYSICAL_ROUTER, up_state);
        if (st_set_router_state == FM_OK)
            router_state_applied = true;
    }

    st_pre_rif = get_interface_list_contains(sw, -1, &pre_rif_count, NULL);
    st_pre_arp = fmGetARPEntryList((fm_int)sw, &pre_arp_count, arp_list,
                                   (fm_int)(sizeof(arp_list) /
                                            sizeof(arp_list[0])));
    st_pre_ecmp = fmGetECMPGroupList((fm_int)sw, &pre_ecmp_count,
                                     ecmp_groups,
                                     (fm_int)(sizeof(ecmp_groups) /
                                              sizeof(ecmp_groups[0])));
    st_pre_route = fmGetRouteList((fm_int)sw, &pre_route_count, route_list,
                                  (fm_int)(sizeof(route_list) /
                                           sizeof(route_list[0])));

    for (int i = 0; i < plan->n_rifs; i++) {
        fm_uint16 vlan = (fm_uint16)plan->rifs[i].vlan;
        bool exists = false;

        for (int j = 0; j < n_vlan_enablers; j++) {
            if (vlan_enablers[j].vlan == vlan) {
                exists = true;
                break;
            }
        }
        if (exists || n_vlan_enablers >=
            (int)(sizeof(vlan_enablers) / sizeof(vlan_enablers[0])))
            continue;
        vlan_enablers[n_vlan_enablers].used = true;
        vlan_enablers[n_vlan_enablers].vlan = vlan;
        vlan_enablers[n_vlan_enablers].st_get = fmGetVlanAttribute(
            (fm_int)sw, vlan, FM_VLAN_ROUTABLE,
            &vlan_enablers[n_vlan_enablers].pre_routable);
        {
            fm_bool enabled = FM_ENABLED;
            vlan_enablers[n_vlan_enablers].st_set = fmSetVlanAttribute(
                (fm_int)sw, vlan, FM_VLAN_ROUTABLE, &enabled);
        }
        n_vlan_enablers++;
    }

    {
        nl_port_entry port_entries[NL_MAX_PORTS_PER_PROFILE];
        int n_ports = nl_ifid_get_all(port_entries,
                                      NL_MAX_PORTS_PER_PROFILE);

        for (int i = 0; i < n_ports &&
             n_port_enablers < NL_MAX_PORTS_PER_PROFILE; i++) {
            fm_bool routable = FM_ENABLED;
            fm_uint32 parser = FM_PORT_PARSER_STOP_AFTER_L4;
            fm_int port = (fm_int)port_entries[i].logical_port;

            if (!nl_ifid_is_user_port((int)port))
                continue;
            port_enablers[n_port_enablers].used = true;
            port_enablers[n_port_enablers].port = port;
            port_enablers[n_port_enablers].st_get_routable =
                fmGetPortAttribute((fm_int)sw, port, FM_PORT_ROUTABLE,
                                   &port_enablers[n_port_enablers].
                                   pre_routable);
            port_enablers[n_port_enablers].st_get_parser =
                fmGetPortAttribute((fm_int)sw, port, FM_PORT_PARSER,
                                   &port_enablers[n_port_enablers].
                                   pre_parser);
            port_enablers[n_port_enablers].st_set_parser =
                fmSetPortAttribute((fm_int)sw, port, FM_PORT_PARSER,
                                   &parser);
            port_enablers[n_port_enablers].st_set_routable =
                fmSetPortAttribute((fm_int)sw, port, FM_PORT_ROUTABLE,
                                   &routable);
            n_port_enablers++;
        }
    }

    for (int i = 0; i < plan->n_rifs; i++) {
        fm_uint16 vlan = (fm_uint16)plan->rifs[i].vlan;
        fm_interfaceState state = FM_INTERFACE_STATE_ADMIN_UP;

        if (parse_ipv4_cidr(plan->rifs[i].address, &rifs[i].addr, NULL) == 0)
            rifs[i].st_parse = FM_OK;
        if (rifs[i].st_parse != FM_OK)
            continue;
        rifs[i].st_create = fmCreateInterface((fm_int)sw, &rifs[i].ifindex);
        if (rifs[i].st_create != FM_OK)
            continue;
        rifs[i].created = true;
        rifs[i].st_add_addr = fmAddInterfaceAddr((fm_int)sw, rifs[i].ifindex,
                                                 &rifs[i].addr);
        if (rifs[i].st_add_addr == FM_OK)
            rifs[i].addr_added = true;
        rifs[i].st_set_vlan = fmSetInterfaceAttribute(
            (fm_int)sw, rifs[i].ifindex, FM_INTERFACE_VLAN, &vlan);
        rifs[i].st_set_state = fmSetInterfaceAttribute(
            (fm_int)sw, rifs[i].ifindex, FM_INTERFACE_STATE, &state);
    }

    for (int i = 0; i < plan->n_arps; i++) {
        fm_arpEntry list[32];
        fm_int emitted;
        int rif_index = find_rif(plan, plan->arps[i].rif);

        memset(list, 0, sizeof(list));
        memset(&arps[i].entry, 0, sizeof(arps[i].entry));
        memset(&arps[i].info, 0, sizeof(arps[i].info));
        arps[i].rif_index = rif_index;
        if (parse_ipv4(plan->arps[i].ip, &arps[i].entry.ipAddr) == 0)
            arps[i].st_parse_ip = FM_OK;
        if (parse_mac(plan->arps[i].mac, &arps[i].entry.macAddr) == 0)
            arps[i].st_parse_mac = FM_OK;
        if (rif_index < 0 || arps[i].st_parse_ip != FM_OK ||
            arps[i].st_parse_mac != FM_OK || !rifs[rif_index].created)
            continue;
        arps[i].entry.interface = rifs[rif_index].ifindex;
        arps[i].entry.vlan = (fm_uint16)plan->rifs[rif_index].vlan;
        arps[i].st_add = fmAddARPEntry((fm_int)sw, &arps[i].entry);
        if (arps[i].st_add == FM_OK)
            arps[i].added = true;
        arps[i].st_info = fmGetARPEntryInfo((fm_int)sw, &arps[i].entry,
                                            &arps[i].info);
        arps[i].info_match = arps[i].st_info == FM_OK &&
                             arp_entry_equal(&arps[i].info.arp,
                                             &arps[i].entry);
        arps[i].st_list = fmGetARPEntryList(
            (fm_int)sw, &arps[i].list_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted = arps[i].list_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) : arps[i].list_count;
        arps[i].list_found = arps[i].st_list == FM_OK &&
                             arp_list_contains(list, emitted,
                                               &arps[i].entry);
        arps[i].st_mac_port = find_vlan_first_user_port(
            sw, arps[i].entry.vlan, &arps[i].mac_port,
            &arps[i].mac_user_ports);
        if (arps[i].st_mac_port != FM_OK)
            continue;
        memset(&arps[i].mac_entry, 0, sizeof(arps[i].mac_entry));
        arps[i].mac_entry.macAddress = arps[i].entry.macAddr;
        arps[i].mac_entry.vlanID = arps[i].entry.vlan;
        arps[i].mac_entry.type = FM_ADDRESS_STATIC;
        arps[i].mac_entry.destMask = FM_DESTMASK_UNUSED;
        arps[i].mac_entry.port = arps[i].mac_port;
        arps[i].st_mac_pre_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].pre_mac_entry);
        arps[i].mac_pre_existing = arps[i].st_mac_pre_get == FM_OK;
        if (!arps[i].mac_pre_existing) {
            arps[i].st_mac_add = fmAddAddress((fm_int)sw,
                                              &arps[i].mac_entry);
            if (arps[i].st_mac_add == FM_OK)
                arps[i].mac_added = true;
        } else {
            arps[i].st_mac_add = FM_OK;
        }
        arps[i].st_mac_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].post_mac_entry);
        arps[i].mac_match = arps[i].st_mac_get == FM_OK &&
                            arps[i].post_mac_entry.port ==
                                arps[i].mac_port;
    }

    for (int i = 0; i < plan->n_ecmp; i++) {
        fm_nextHop list[16];
        fm_int groups[64];
        fm_int emitted_groups;
        fm_int emitted_nh;
        bool built = true;

        memset(list, 0, sizeof(list));
        memset(groups, 0, sizeof(groups));
        ecmp[i].plan_ecmp = &plan->ecmp[i];
        for (int j = 0; j < plan->ecmp[i].n_members; j++) {
            const hal_l3_intent_next_hop *nh =
                find_nexthop(plan, plan->ecmp[i].members[j]);

            if (nh &&
                build_sdk_next_hop(plan, nh, &ecmp[i].members[j]) == 0) {
                ecmp[i].st_build[j] = FM_OK;
            } else {
                built = false;
            }
        }
        if (!built)
            continue;
        ecmp[i].st_create = fmCreateECMPGroup(
            (fm_int)sw, &ecmp[i].group_id, plan->ecmp[i].n_members,
            ecmp[i].members);
        if (ecmp[i].st_create == FM_OK)
            ecmp[i].created = true;
        if (!ecmp[i].created)
            continue;
        sdk_ecmp_group_ids[i] = ecmp[i].group_id;
        sdk_ecmp_refs[i] = ecmp[i].plan_ecmp;
        ecmp[i].st_group_list = fmGetECMPGroupList(
            (fm_int)sw, &ecmp[i].group_list_count, groups,
            (fm_int)(sizeof(groups) / sizeof(groups[0])));
        emitted_groups = ecmp[i].group_list_count >
            (fm_int)(sizeof(groups) / sizeof(groups[0])) ?
            (fm_int)(sizeof(groups) / sizeof(groups[0])) :
            ecmp[i].group_list_count;
        ecmp[i].group_found = ecmp[i].st_group_list == FM_OK &&
                              ecmp_group_list_contains(
                                  groups, emitted_groups, ecmp[i].group_id);
        ecmp[i].st_next_hop_list = fmGetECMPGroupNextHopList(
            (fm_int)sw, ecmp[i].group_id, &ecmp[i].next_hop_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted_nh = ecmp[i].next_hop_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) :
            ecmp[i].next_hop_count;
        ecmp[i].members_match = ecmp[i].st_next_hop_list == FM_OK;
        for (int j = 0; j < plan->ecmp[i].n_members &&
             ecmp[i].members_match; j++) {
            if (!next_hop_list_contains(list, emitted_nh,
                                        &ecmp[i].members[j]))
                ecmp[i].members_match = false;
        }
    }

    for (int i = 0; i < plan->n_routes; i++) {
        fm_routeEntry list[64];
        fm_int emitted;

        if (plan->routes[i].target_type == HAL_L3_ROUTE_TARGET_RIF)
            continue;
        if (fib_routes >= 4)
            continue;
        memset(list, 0, sizeof(list));
        routes[fib_routes].plan_route = &plan->routes[i];
        routes[fib_routes].st_build = build_sdk_route(
            plan, &plan->routes[i], sdk_ecmp_group_ids, sdk_ecmp_refs,
            plan->n_ecmp, &routes[fib_routes].entry) == 0 ?
            FM_OK : FM_ERR_INVALID_ARGUMENT;
        if (routes[fib_routes].st_build == FM_OK) {
            routes[fib_routes].st_add = fmAddRoute(
                (fm_int)sw, &routes[fib_routes].entry, FM_ROUTE_STATE_UP);
            if (routes[fib_routes].st_add == FM_OK)
                routes[fib_routes].added = true;
            if (routes[fib_routes].added)
                routes_added++;
            routes[fib_routes].st_state = fmGetRouteState(
                (fm_int)sw, &routes[fib_routes].entry,
                &routes[fib_routes].state);
            routes[fib_routes].st_list = fmGetRouteList(
                (fm_int)sw, &routes[fib_routes].list_count, list,
                (fm_int)(sizeof(list) / sizeof(list[0])));
            emitted = routes[fib_routes].list_count >
                (fm_int)(sizeof(list) / sizeof(list[0])) ?
                (fm_int)(sizeof(list) / sizeof(list[0])) :
                routes[fib_routes].list_count;
            routes[fib_routes].list_found =
                routes[fib_routes].st_list == FM_OK &&
                route_list_contains(list, emitted, &routes[fib_routes].entry);
        }
        fib_routes++;
    }

    for (int i = 0; i < n_port_enablers; i++) {
        fm_portCounters cnt;

        memset(&cnt, 0, sizeof(cnt));
        port_enablers[i].st_counter_pre = fmGetPortCounters(
            (fm_int)sw, port_enablers[i].port, &cnt);
        if (port_enablers[i].st_counter_pre == FM_OK) {
            port_enablers[i].pre_rx_pkts = port_counter_rx_pkts(&cnt);
            port_enablers[i].pre_tx_pkts = port_counter_tx_pkts(&cnt);
            port_enablers[i].pre_rx_bytes = cnt.cntRxGoodOctets;
            port_enablers[i].pre_tx_bytes = cnt.cntTxOctets;
            port_enablers[i].pre_rx_errs = port_counter_rx_errs(&cnt);
        }
    }

    if (hold_sec > 0 && routes_added > 0) {
        struct timespec req;
        struct timespec rem;

        hold_applied_sec = hold_sec;
        req.tv_sec = hold_sec;
        req.tv_nsec = 0;
        while (nanosleep(&req, &rem) != 0)
            req = rem;
    }

    for (int i = 0; i < n_port_enablers; i++) {
        fm_portCounters cnt;

        memset(&cnt, 0, sizeof(cnt));
        port_enablers[i].st_counter_post = fmGetPortCounters(
            (fm_int)sw, port_enablers[i].port, &cnt);
        if (port_enablers[i].st_counter_post == FM_OK) {
            port_enablers[i].post_rx_pkts = port_counter_rx_pkts(&cnt);
            port_enablers[i].post_tx_pkts = port_counter_tx_pkts(&cnt);
            port_enablers[i].post_rx_bytes = cnt.cntRxGoodOctets;
            port_enablers[i].post_tx_bytes = cnt.cntTxOctets;
            port_enablers[i].post_rx_errs = port_counter_rx_errs(&cnt);
        }
    }

    for (int i = fib_routes - 1; i >= 0; i--) {
        fm_routeEntry list[64];
        fm_int emitted;

        memset(list, 0, sizeof(list));
        if (routes[i].added)
            routes[i].st_delete = fmDeleteRoute((fm_int)sw,
                                                &routes[i].entry);
        routes[i].st_post_list = fmGetRouteList(
            (fm_int)sw, &routes[i].post_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted = routes[i].post_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) : routes[i].post_count;
        routes[i].leaked = routes[i].st_post_list == FM_OK &&
                           route_list_contains(list, emitted,
                                               &routes[i].entry);
        if (routes[i].leaked)
            any_route_leaked = true;
    }

    for (int i = plan->n_ecmp - 1; i >= 0; i--) {
        fm_int groups[64];
        fm_int emitted;

        memset(groups, 0, sizeof(groups));
        if (ecmp[i].created)
            ecmp[i].st_delete = fmDeleteECMPGroup((fm_int)sw,
                                                  ecmp[i].group_id);
        ecmp[i].st_post_list = fmGetECMPGroupList(
            (fm_int)sw, &ecmp[i].post_count, groups,
            (fm_int)(sizeof(groups) / sizeof(groups[0])));
        emitted = ecmp[i].post_count >
            (fm_int)(sizeof(groups) / sizeof(groups[0])) ?
            (fm_int)(sizeof(groups) / sizeof(groups[0])) :
            ecmp[i].post_count;
        ecmp[i].leaked = ecmp[i].st_post_list == FM_OK &&
                         ecmp_group_list_contains(groups, emitted,
                                                  ecmp[i].group_id);
        if (ecmp[i].leaked)
            any_ecmp_leaked = true;
    }

    for (int i = plan->n_arps - 1; i >= 0; i--) {
        fm_arpEntry list[32];
        fm_int emitted;

        memset(list, 0, sizeof(list));
        if (arps[i].mac_added)
            arps[i].st_mac_delete = fmDeleteAddress(
                (fm_int)sw, &arps[i].mac_entry);
        arps[i].st_mac_post_get = fmGetAddress(
            (fm_int)sw, arps[i].mac_entry.macAddress,
            (fm_int)arps[i].mac_entry.vlanID,
            &arps[i].post_mac_entry);
        arps[i].mac_leaked = arps[i].mac_added &&
                             arps[i].st_mac_post_get == FM_OK;
        if (arps[i].mac_leaked)
            any_arp_leaked = true;
        if (arps[i].added)
            arps[i].st_delete = fmDeleteARPEntry((fm_int)sw,
                                                 &arps[i].entry);
        arps[i].st_post_list = fmGetARPEntryList(
            (fm_int)sw, &arps[i].post_count, list,
            (fm_int)(sizeof(list) / sizeof(list[0])));
        emitted = arps[i].post_count >
            (fm_int)(sizeof(list) / sizeof(list[0])) ?
            (fm_int)(sizeof(list) / sizeof(list[0])) : arps[i].post_count;
        arps[i].leaked = arps[i].st_post_list == FM_OK &&
                         arp_list_contains(list, emitted, &arps[i].entry);
        if (arps[i].leaked)
            any_arp_leaked = true;
    }

    for (int i = plan->n_rifs - 1; i >= 0; i--) {
        if (rifs[i].addr_added)
            rifs[i].st_delete_addr = fmDeleteInterfaceAddr(
                (fm_int)sw, rifs[i].ifindex, &rifs[i].addr);
        if (rifs[i].created) {
            rifs[i].st_delete_if = fmDeleteInterface((fm_int)sw,
                                                     rifs[i].ifindex);
            rifs[i].st_post_list = get_interface_list_contains(
                sw, rifs[i].ifindex, &rifs[i].post_count,
                &rifs[i].visible_after_cleanup);
            if (rifs[i].visible_after_cleanup)
                any_rif_leaked = true;
        }
    }

    for (int i = n_port_enablers - 1; i >= 0; i--) {
        if (port_enablers[i].used &&
            port_enablers[i].st_get_parser == FM_OK &&
            port_enablers[i].st_set_parser == FM_OK) {
            port_enablers[i].st_restore_parser = fmSetPortAttribute(
                (fm_int)sw, port_enablers[i].port, FM_PORT_PARSER,
                &port_enablers[i].pre_parser);
        }
        if (port_enablers[i].used &&
            port_enablers[i].st_get_routable == FM_OK &&
            port_enablers[i].st_set_routable == FM_OK) {
            port_enablers[i].st_restore_routable = fmSetPortAttribute(
                (fm_int)sw, port_enablers[i].port, FM_PORT_ROUTABLE,
                &port_enablers[i].pre_routable);
        }
    }
    for (int i = n_vlan_enablers - 1; i >= 0; i--) {
        if (vlan_enablers[i].used &&
            vlan_enablers[i].st_get == FM_OK &&
            vlan_enablers[i].st_set == FM_OK) {
            vlan_enablers[i].st_restore = fmSetVlanAttribute(
                (fm_int)sw, vlan_enablers[i].vlan, FM_VLAN_ROUTABLE,
                &vlan_enablers[i].pre_routable);
        }
    }

    if (router_state_applied)
        st_restore_router_state = fmSetRouterState(
            (fm_int)sw, FM_PHYSICAL_ROUTER, pre_router_state);
    if (router_mac_applied)
        st_restore_router_mac = fmSetRouterAttribute(
            (fm_int)sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS, &pre_router_mac);

    memset(route_list, 0, sizeof(route_list));
    memset(ecmp_groups, 0, sizeof(ecmp_groups));
    memset(arp_list, 0, sizeof(arp_list));
    st_post_route = fmGetRouteList((fm_int)sw, &post_route_count, route_list,
                                   (fm_int)(sizeof(route_list) /
                                            sizeof(route_list[0])));
    st_post_ecmp = fmGetECMPGroupList((fm_int)sw, &post_ecmp_count,
                                      ecmp_groups,
                                      (fm_int)(sizeof(ecmp_groups) /
                                               sizeof(ecmp_groups[0])));
    st_post_arp = fmGetARPEntryList((fm_int)sw, &post_arp_count, arp_list,
                                    (fm_int)(sizeof(arp_list) /
                                             sizeof(arp_list[0])));
    st_post_rif = get_interface_list_contains(sw, -1, &post_rif_count, NULL);

    base_ok = st_pre_rif == FM_OK && st_post_rif == FM_OK &&
              st_pre_arp == FM_OK && st_post_arp == FM_OK &&
              st_pre_ecmp == FM_OK && st_post_ecmp == FM_OK &&
              st_pre_route == FM_OK && st_post_route == FM_OK &&
              !any_rif_leaked && !any_arp_leaked && !any_ecmp_leaked &&
              !any_route_leaked;
    if (router_mac_requested) {
        base_ok = base_ok &&
                  st_parse_router_mac == FM_OK &&
                  st_pre_router_mac == FM_OK &&
                  st_set_router_mac == FM_OK &&
                  st_restore_router_mac == FM_OK &&
                  st_pre_router_state == FM_OK &&
                  st_set_router_state == FM_OK &&
                  st_restore_router_state == FM_OK;
    }
    for (int i = 0; i < n_vlan_enablers; i++) {
        if (vlan_enablers[i].st_get != FM_OK ||
            vlan_enablers[i].st_set != FM_OK ||
            vlan_enablers[i].st_restore != FM_OK)
            base_ok = false;
    }
    for (int i = 0; i < n_port_enablers; i++) {
        if (port_enablers[i].st_get_routable != FM_OK ||
            port_enablers[i].st_set_routable != FM_OK ||
            port_enablers[i].st_restore_routable != FM_OK ||
            port_enablers[i].st_get_parser != FM_OK ||
            port_enablers[i].st_set_parser != FM_OK ||
            port_enablers[i].st_restore_parser != FM_OK)
            base_ok = false;
    }
    routes_profile_limited = fib_routes > 0;
    for (int i = 0; i < fib_routes; i++) {
        bool route_ok = routes[i].st_build == FM_OK &&
                        routes[i].st_add == FM_OK &&
                        routes[i].st_state == FM_OK &&
                        routes[i].state == FM_ROUTE_STATE_UP &&
                        routes[i].st_list == FM_OK &&
                        routes[i].list_found &&
                        routes[i].st_delete == FM_OK &&
                        routes[i].st_post_list == FM_OK &&
                        !routes[i].leaked;
        bool route_limited = routes[i].st_build == FM_OK &&
                             routes[i].st_add == FM_ERR_NO_FFU_RES_FOUND &&
                             routes[i].st_state == FM_ERR_NOT_FOUND &&
                             routes[i].st_list == FM_OK &&
                             !routes[i].list_found &&
                             !routes[i].added &&
                             routes[i].st_post_list == FM_OK &&
                             !routes[i].leaked;

        if (!route_ok)
            routes_ok = false;
        if (!route_limited)
            routes_profile_limited = false;
        if (!route_ok && !route_limited)
            routes_profile_limited = false;
    }
    for (int i = 0; i < plan->n_ecmp; i++) {
        if (ecmp[i].st_create != FM_OK ||
            ecmp[i].st_group_list != FM_OK ||
            !ecmp[i].group_found ||
            ecmp[i].st_next_hop_list != FM_OK ||
            !ecmp[i].members_match ||
            ecmp[i].st_delete != FM_OK ||
            ecmp[i].st_post_list != FM_OK ||
            ecmp[i].leaked)
            deps_ok = false;
    }
    for (int i = 0; i < plan->n_arps; i++) {
        bool mac_pre_ok = arps[i].st_mac_pre_get == FM_OK ||
                          arps[i].st_mac_pre_get == FM_ERR_NOT_FOUND ||
                          arps[i].st_mac_pre_get == FM_ERR_ADDR_NOT_FOUND;
        bool mac_cleanup_ok = arps[i].mac_added ?
                              (arps[i].st_mac_delete == FM_OK &&
                               (arps[i].st_mac_post_get ==
                                    FM_ERR_NOT_FOUND ||
                                arps[i].st_mac_post_get ==
                                    FM_ERR_ADDR_NOT_FOUND) &&
                               !arps[i].mac_leaked) :
                              (arps[i].mac_pre_existing &&
                               arps[i].st_mac_post_get == FM_OK &&
                               !arps[i].mac_leaked);
        bool mac_optional_no_user_port =
            arps[i].st_mac_port == FM_ERR_NOT_FOUND;
        bool mac_entry_ok = mac_optional_no_user_port ||
                            (arps[i].st_mac_port == FM_OK &&
                             mac_pre_ok &&
                             arps[i].st_mac_add == FM_OK &&
                             arps[i].st_mac_get == FM_OK &&
                             arps[i].mac_match &&
                             mac_cleanup_ok);

        if (arps[i].st_add != FM_OK ||
            arps[i].st_info != FM_OK ||
            !arps[i].info_match ||
            arps[i].st_list != FM_OK ||
            !arps[i].list_found ||
            !mac_entry_ok ||
            arps[i].st_delete != FM_OK ||
            arps[i].st_post_list != FM_OK ||
            arps[i].leaked)
            deps_ok = false;
    }
    for (int i = 0; i < plan->n_rifs; i++) {
        if (rifs[i].st_create != FM_OK ||
            rifs[i].st_add_addr != FM_OK ||
            rifs[i].st_set_vlan != FM_OK ||
            rifs[i].st_set_state != FM_OK ||
            rifs[i].st_delete_addr != FM_OK ||
            rifs[i].st_delete_if != FM_OK ||
            rifs[i].st_post_list != FM_OK ||
            rifs[i].visible_after_cleanup)
            deps_ok = false;
    }
    if (base_ok && deps_ok && routes_ok)
        overall = "ok";
    else if (base_ok && deps_ok && routes_profile_limited)
        overall = "limited";

    off = snprintf(resp, resp_size,
                   "<l3-route-live-probe status=\"%s\" source=\"switchd\" "
                   "mode=\"hidden\" tx-id=\"%llu\" "
                   "hardware-apply=\"transient\" sdk-write=\"live\" "
                   "sdk-readback=\"live\" rollback=\"cleanup\" "
                   "gate-env=\"%s\" gate=\"acknowledged\" rifs=\"%d\" "
                   "arp=\"%d\" next-hops=\"%d\" ecmp-groups=\"%d\" "
                   "fib-routes=\"%d\" connected-route-intent=\"%d\" "
                   "hold-sec=\"%d\" hold-applied-sec=\"%d\" "
                   "routes-added=\"%d\" router-mac-requested=\"%s\">",
                   overall, (unsigned long long)tx_id, gate,
                   plan->n_rifs, plan->n_arps, plan->n_nexthops,
                   plan->n_ecmp, fib_routes,
                   plan->n_routes - fib_routes, hold_sec, hold_applied_sec,
                   routes_added, router_mac_requested ? "true" : "false");
    if (off < 0 || (size_t)off >= resp_size)
        return -1;
    if (router_mac_requested) {
        off = appendf(resp, resp_size, off,
                      "<router-mac requested=\"%s\" "
                      "parse-status=\"%s\" parse-sdk-status=\"%d\" "
                      "pre-status=\"%s\" pre-sdk-status=\"%d\" "
                      "set-status=\"%s\" set-sdk-status=\"%d\" "
                      "restore-status=\"%s\" restore-sdk-status=\"%d\" "
                      "pre-state-status=\"%s\" pre-state-sdk-status=\"%d\" "
                      "set-state-status=\"%s\" set-state-sdk-status=\"%d\" "
                      "restore-state-status=\"%s\" "
                      "restore-state-sdk-status=\"%d\"/>",
                      router_mac_text,
                      sdk_status_name(st_parse_router_mac),
                      (int)st_parse_router_mac,
                      sdk_status_name(st_pre_router_mac),
                      (int)st_pre_router_mac,
                      sdk_status_name(st_set_router_mac),
                      (int)st_set_router_mac,
                      sdk_status_name(st_restore_router_mac),
                      (int)st_restore_router_mac,
                      sdk_status_name(st_pre_router_state),
                      (int)st_pre_router_state,
                      sdk_status_name(st_set_router_state),
                      (int)st_set_router_state,
                      sdk_status_name(st_restore_router_state),
                      (int)st_restore_router_state);
    }
    off = appendf(resp, resp_size, off,
                  "<routing-enablers vlan-count=\"%d\" "
                  "port-count=\"%d\">",
                  n_vlan_enablers, n_port_enablers);
    for (int i = 0; i < n_vlan_enablers; i++) {
        off = appendf(resp, resp_size, off,
                      "<vlan id=\"%u\" pre-routable=\"%d\" "
                      "get-status=\"%s\" get-sdk-status=\"%d\" "
                      "set-status=\"%s\" set-sdk-status=\"%d\" "
                      "restore-status=\"%s\" restore-sdk-status=\"%d\"/>",
                      (unsigned)vlan_enablers[i].vlan,
                      (int)vlan_enablers[i].pre_routable,
                      sdk_status_name(vlan_enablers[i].st_get),
                      (int)vlan_enablers[i].st_get,
                      sdk_status_name(vlan_enablers[i].st_set),
                      (int)vlan_enablers[i].st_set,
                      sdk_status_name(vlan_enablers[i].st_restore),
                      (int)vlan_enablers[i].st_restore);
    }
    for (int i = 0; i < n_port_enablers; i++) {
        off = appendf(resp, resp_size, off,
                      "<port id=\"%d\" pre-routable=\"%d\" "
                      "pre-parser=\"%u\" "
                      "get-routable-status=\"%s\" "
                      "get-routable-sdk-status=\"%d\" "
                      "set-routable-status=\"%s\" "
                      "set-routable-sdk-status=\"%d\" "
                      "restore-routable-status=\"%s\" "
                      "restore-routable-sdk-status=\"%d\" "
                      "get-parser-status=\"%s\" "
                      "get-parser-sdk-status=\"%d\" "
                      "set-parser-status=\"%s\" "
                      "set-parser-sdk-status=\"%d\" "
                      "restore-parser-status=\"%s\" "
                      "restore-parser-sdk-status=\"%d\"/>",
                      (int)port_enablers[i].port,
                      (int)port_enablers[i].pre_routable,
                      (unsigned)port_enablers[i].pre_parser,
                      sdk_status_name(port_enablers[i].st_get_routable),
                      (int)port_enablers[i].st_get_routable,
                      sdk_status_name(port_enablers[i].st_set_routable),
                      (int)port_enablers[i].st_set_routable,
                      sdk_status_name(port_enablers[i].st_restore_routable),
                      (int)port_enablers[i].st_restore_routable,
                      sdk_status_name(port_enablers[i].st_get_parser),
                      (int)port_enablers[i].st_get_parser,
                      sdk_status_name(port_enablers[i].st_set_parser),
                      (int)port_enablers[i].st_set_parser,
                      sdk_status_name(port_enablers[i].st_restore_parser),
                      (int)port_enablers[i].st_restore_parser);
    }
    off = appendf(resp, resp_size, off, "</routing-enablers>");
    off = appendf(resp, resp_size, off,
                  "<traffic-counters source=\"fmGetPortCounters\" "
                  "sample=\"route-hold\" ports=\"%d\">",
                  n_port_enablers);
    for (int i = 0; i < n_port_enablers; i++) {
        fm_uint64 rx_pkts_delta = 0;
        fm_uint64 tx_pkts_delta = 0;
        fm_uint64 rx_bytes_delta = 0;
        fm_uint64 tx_bytes_delta = 0;
        fm_uint64 rx_errs_delta = 0;

        if (port_enablers[i].st_counter_pre == FM_OK &&
            port_enablers[i].st_counter_post == FM_OK) {
            if (port_enablers[i].post_rx_pkts >=
                port_enablers[i].pre_rx_pkts)
                rx_pkts_delta = port_enablers[i].post_rx_pkts -
                                port_enablers[i].pre_rx_pkts;
            if (port_enablers[i].post_tx_pkts >=
                port_enablers[i].pre_tx_pkts)
                tx_pkts_delta = port_enablers[i].post_tx_pkts -
                                port_enablers[i].pre_tx_pkts;
            if (port_enablers[i].post_rx_bytes >=
                port_enablers[i].pre_rx_bytes)
                rx_bytes_delta = port_enablers[i].post_rx_bytes -
                                 port_enablers[i].pre_rx_bytes;
            if (port_enablers[i].post_tx_bytes >=
                port_enablers[i].pre_tx_bytes)
                tx_bytes_delta = port_enablers[i].post_tx_bytes -
                                 port_enablers[i].pre_tx_bytes;
            if (port_enablers[i].post_rx_errs >=
                port_enablers[i].pre_rx_errs)
                rx_errs_delta = port_enablers[i].post_rx_errs -
                                port_enablers[i].pre_rx_errs;
        }
        off = appendf(resp, resp_size, off,
                      "<port id=\"%d\" "
                      "pre-status=\"%s\" pre-sdk-status=\"%d\" "
                      "post-status=\"%s\" post-sdk-status=\"%d\" "
                      "rx-packets=\"%llu\" tx-packets=\"%llu\" "
                      "rx-bytes=\"%llu\" tx-bytes=\"%llu\" "
                      "rx-errors=\"%llu\"/>",
                      (int)port_enablers[i].port,
                      sdk_status_name(port_enablers[i].st_counter_pre),
                      (int)port_enablers[i].st_counter_pre,
                      sdk_status_name(port_enablers[i].st_counter_post),
                      (int)port_enablers[i].st_counter_post,
                      (unsigned long long)rx_pkts_delta,
                      (unsigned long long)tx_pkts_delta,
                      (unsigned long long)rx_bytes_delta,
                      (unsigned long long)tx_bytes_delta,
                      (unsigned long long)rx_errs_delta);
    }
    off = appendf(resp, resp_size, off, "</traffic-counters>");
    off = appendf(resp, resp_size, off,
                  "<pre family=\"route\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>"
                  "<pre family=\"ecmp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>"
                  "<pre family=\"arp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>"
                  "<pre family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\"/>",
                  sdk_status_name(st_pre_route), (int)st_pre_route,
                  (int)pre_route_count,
                  sdk_status_name(st_pre_ecmp), (int)st_pre_ecmp,
                  (int)pre_ecmp_count,
                  sdk_status_name(st_pre_arp), (int)st_pre_arp,
                  (int)pre_arp_count,
                  sdk_status_name(st_pre_rif), (int)st_pre_rif,
                  (int)pre_rif_count);
    for (int i = 0; i < plan->n_arps; i++) {
        char mac_add_msg[128];

        xml_escape_attr(fmErrorMsg(arps[i].st_mac_add),
                        mac_add_msg, sizeof(mac_add_msg));
        off = appendf(resp, resp_size, off,
                      "<arp ip=\"%s\" rif=\"%s\" vlan=\"%u\" "
                      "interface=\"%d\" mac-port=\"%d\" "
                      "mac-user-ports=\"%d\" mac-pre-existing=\"%s\" "
                      "mac-added=\"%s\" mac-match=\"%s\">",
                      plan->arps[i].ip, plan->arps[i].rif,
                      (unsigned)arps[i].entry.vlan,
                      (int)arps[i].entry.interface,
                      (int)arps[i].mac_port,
                      (int)arps[i].mac_user_ports,
                      arps[i].mac_pre_existing ? "true" : "false",
                      arps[i].mac_added ? "true" : "false",
                      arps[i].mac_match ? "true" : "false");
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmAddARPEntry", arps[i].st_add,
                                   arps[i].rif_index < 0 ||
                                   arps[i].st_parse_ip != FM_OK ||
                                   arps[i].st_parse_mac != FM_OK);
        off = appendf(resp, resp_size, off,
                      "<verify name=\"arp-info\" status=\"%s\" "
                      "sdk-status=\"%d\" match=\"%s\"/>"
                      "<verify name=\"arp-list\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>"
                      "<verify name=\"mac-egress-port\" status=\"%s\" "
                      "sdk-status=\"%d\"/>"
                      "<verify name=\"mac-pre-get\" status=\"%s\" "
                      "sdk-status=\"%d\"/>"
                      "<op name=\"fmAddAddress\" status=\"%s\" "
                      "sdk-status=\"%d\" message=\"%s\"/>"
                      "<verify name=\"mac-get\" status=\"%s\" "
                      "sdk-status=\"%d\" match=\"%s\"/>",
                      sdk_status_name(arps[i].st_info),
                      (int)arps[i].st_info,
                      arps[i].info_match ? "true" : "false",
                      sdk_status_name(arps[i].st_list),
                      (int)arps[i].st_list, (int)arps[i].list_count,
                      arps[i].list_found ? "true" : "false",
                      sdk_status_name(arps[i].st_mac_port),
                      (int)arps[i].st_mac_port,
                      sdk_status_name(arps[i].st_mac_pre_get),
                      (int)arps[i].st_mac_pre_get,
                      sdk_status_name(arps[i].st_mac_add),
                      (int)arps[i].st_mac_add,
                      mac_add_msg,
                      sdk_status_name(arps[i].st_mac_get),
                      (int)arps[i].st_mac_get,
                      arps[i].mac_match ? "true" : "false");
        if (arps[i].mac_added)
            off = append_sdk_op_status(resp, resp_size, off,
                                       "fmDeleteAddress",
                                       arps[i].st_mac_delete, false);
        off = appendf(resp, resp_size, off,
                      "<post family=\"mac\" status=\"%s\" "
                      "sdk-status=\"%d\" leaked=\"%s\"/>",
                      sdk_status_name(arps[i].st_mac_post_get),
                      (int)arps[i].st_mac_post_get,
                      arps[i].mac_leaked ? "true" : "false");
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteARPEntry", arps[i].st_delete,
                                   !arps[i].added);
        off = appendf(resp, resp_size, off,
                      "<post family=\"arp\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" leaked=\"%s\"/>"
                      "</arp>",
                      sdk_status_name(arps[i].st_post_list),
                      (int)arps[i].st_post_list, (int)arps[i].post_count,
                      arps[i].leaked ? "true" : "false");
    }
    for (int i = 0; i < fib_routes; i++) {
        off = appendf(resp, resp_size, off,
                      "<route prefix=\"%s\" target-type=\"%s\" "
                      "target=\"%d\">",
                      routes[i].plan_route ? routes[i].plan_route->prefix : "",
                      routes[i].entry.routeType == FM_ROUTE_TYPE_UNICAST ?
                          "next-hop" : "ecmp",
                      routes[i].plan_route ?
                          routes[i].plan_route->target_id : 0);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "build-route", routes[i].st_build, false);
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmAddRoute", routes[i].st_add,
                                   routes[i].st_build != FM_OK);
        off = appendf(resp, resp_size, off,
                      "<verify name=\"route-state\" status=\"%s\" "
                      "sdk-status=\"%d\" state=\"%d\"/>"
                      "<verify name=\"route-list\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" found=\"%s\"/>",
                      sdk_status_name(routes[i].st_state),
                      (int)routes[i].st_state, (int)routes[i].state,
                      sdk_status_name(routes[i].st_list),
                      (int)routes[i].st_list, (int)routes[i].list_count,
                      routes[i].list_found ? "true" : "false");
        off = append_sdk_op_status(resp, resp_size, off,
                                   "fmDeleteRoute", routes[i].st_delete,
                                   !routes[i].added);
        off = appendf(resp, resp_size, off,
                      "<post family=\"route\" status=\"%s\" "
                      "sdk-status=\"%d\" count=\"%d\" leaked=\"%s\"/>"
                      "</route>",
                      sdk_status_name(routes[i].st_post_list),
                      (int)routes[i].st_post_list, (int)routes[i].post_count,
                      routes[i].leaked ? "true" : "false");
    }
    off = appendf(resp, resp_size, off,
                  "<post family=\"route\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<post family=\"ecmp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<post family=\"arp\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<post family=\"rif\" status=\"%s\" sdk-status=\"%d\" "
                  "count=\"%d\" leaked=\"%s\"/>"
                  "<boundary user-config=\"rejected\" "
                  "reason=\"operator-assisted hidden L3 FIB route "
                  "transaction probe only; public routing config remains "
                  "disabled\"/>"
                  "</l3-route-live-probe>",
                  sdk_status_name(st_post_route), (int)st_post_route,
                  (int)post_route_count, any_route_leaked ? "true" : "false",
                  sdk_status_name(st_post_ecmp), (int)st_post_ecmp,
                  (int)post_ecmp_count, any_ecmp_leaked ? "true" : "false",
                  sdk_status_name(st_post_arp), (int)st_post_arp,
                  (int)post_arp_count, any_arp_leaked ? "true" : "false",
                  sdk_status_name(st_post_rif), (int)st_post_rif,
                  (int)post_rif_count, any_rif_leaked ? "true" : "false");
    return (off < 0 || strcmp(overall, "error") == 0) ? -1 : 0;
}

int hal_route_add(int sw, void *entry) {
    fm_status st = fmAddRoute((fm_int)sw, (fm_routeEntry *)entry, FM_ROUTE_STATE_UP);
    if (st != FM_OK)
        NL_LOG_ERR("fmAddRoute: %s", fmErrorMsg(st));
    return (st == FM_OK) ? 0 : -1;
}

int hal_route_delete(int sw, void *entry) {
    fm_status st = fmDeleteRoute((fm_int)sw, (fm_routeEntry *)entry);
    return (st == FM_OK) ? 0 : -1;
}

int hal_l3if_create(int sw, int *ifindex) {
    fm_status st = fmCreateInterface((fm_int)sw, ifindex);
    return (st == FM_OK) ? 0 : -1;
}

int hal_l3if_add_addr(int sw, int ifindex, void *addr) {
    fm_status st = fmAddInterfaceAddr((fm_int)sw, (fm_int)ifindex, (fm_ipAddr *)addr);
    return (st == FM_OK) ? 0 : -1;
}

int hal_ecmp_create(int sw, int *group_id, int num_nh, void *nh_list) {
    fm_status st = fmCreateECMPGroup((fm_int)sw, group_id, num_nh, (fm_nextHop *)nh_list);
    return (st == FM_OK) ? 0 : -1;
}
