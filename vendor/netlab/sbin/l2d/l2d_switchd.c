/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "l2d_switchd.h"
#include "netlab/mcast_readback.h"
#include "netlab/ipc.h"
#include "netlab/pfe_capability.h"
#include "netlab/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int switchd_call(const char *socket_path, nl_rpc_method method,
                        const u8 *payload, int payload_len,
                        u8 *resp, int resp_max, int timeout_ms,
                        s32 *ec_out) {
    s32 ec = 0;
    u8 scratch[64];
    int rn;

    if (!socket_path)
        return -1;
    if (!resp || resp_max <= 0) {
        resp = scratch;
        resp_max = (int)sizeof(scratch);
    }

    rn = nl_rpc_call_ex(socket_path, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        method, 0,
                        payload, payload_len, resp, resp_max,
                        timeout_ms, &ec);
    if (ec_out)
        *ec_out = ec;
    if (rn < 0 || ec != 0)
        return -1;
    return rn;
}

static bool xml_attr_value(const char *xml, const char *attr,
                           char *out, size_t out_size) {
    char needle[64];
    const char *p;
    size_t n = 0;

    if (!xml || !attr || !out || out_size == 0)
        return false;
    out[0] = '\0';
    snprintf(needle, sizeof(needle), "%s=\"", attr);
    p = strstr(xml, needle);
    if (!p)
        return false;
    p += strlen(needle);
    while (p[n] && p[n] != '"')
        n++;
    if (n >= out_size)
        n = out_size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return n > 0;
}

static u64 parse_u64_or_zero(const char *text) {
    unsigned long long v = 0;

    if (!text || sscanf(text, "%llu", &v) != 1)
        return 0;
    return (u64)v;
}

int l2d_switchd_get_acl_counter_snapshot(
    const char *socket_path, const nl_acl_counter_query *query,
    nl_acl_counter_snapshot *snapshot) {
    u8 *request = NULL;
    u8 *response = NULL;
    size_t request_size;
    size_t response_size;
    nl_acl_counter_snapshot decoded;
    s32 ec = 0;
    int request_len;
    int response_len;
    int rc = -1;

    if (!socket_path || !query || !snapshot ||
        nl_acl_counter_query_validate(query) != 0)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    request_size = nl_acl_counter_query_wire_size(query->n_entries);
    response_size = nl_acl_counter_snapshot_wire_size(query->n_entries);
    if (request_size == 0 || response_size == 0)
        return -1;
    request = malloc(request_size);
    response = malloc(response_size);
    if (!request || !response)
        goto out;
    request_len = nl_acl_counter_query_encode(
        query, request, request_size);
    if (request_len <= 0)
        goto out;
    response_len = switchd_call(
        socket_path, NL_SWITCHD_ACL_COUNTER_SNAPSHOT_GET,
        request, request_len, response, (int)response_size, 10000, &ec);
    if (response_len <= 0 || ec != 0 ||
        nl_acl_counter_snapshot_decode(
            response, (size_t)response_len, &decoded) != 0 ||
        !decoded.complete || decoded.n_entries != query->n_entries)
        goto out;
    for (u16 i = 0; i < decoded.n_entries; i++)
        if (decoded.entries[i].id != query->entries[i].id ||
            decoded.entries[i].kind != query->entries[i].kind)
            goto out;
    *snapshot = decoded;
    rc = 0;
out:
    if (rc != 0)
        memset(snapshot, 0, sizeof(*snapshot));
    free(response);
    free(request);
    return rc;
}

bool l2d_switchd_reachable(const char *socket_path) {
    char buf[NETLAB_PFE_STATUS_JSON_BYTES + 1] = {0};
    s32 ec = 0;
    int rn = switchd_call(socket_path, NL_SWITCHD_PFE_STATUS_GET,
                          (const u8 *)"pfe", 3,
                          (u8 *)buf, sizeof(buf) - 1, 2000, &ec);
    if (rn <= 0 || ec != 0)
        return false;
    return strstr(buf, "\"status\": \"UP\"") != NULL ||
           strstr(buf, "\"status\":\"UP\"") != NULL;
}

bool l2d_switchd_vlan_exists(const char *socket_path, int vid) {
    char payload[32];
    char resp[64] = {0};
    s32 ec = 0;
    int rvid = 0;
    int exists = 0;
    int n;
    int rn;

    n = snprintf(payload, sizeof(payload), "vid=%d", vid);
    if (n <= 0 || n >= (int)sizeof(payload))
        return false;

    rn = switchd_call(socket_path, NL_SWITCHD_VLAN_GET_STATE,
                      (const u8 *)payload, n,
                      (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    if (rn <= 0 || ec != 0)
        return false;
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';
    if (sscanf(resp, "vlan=%d exists=%d", &rvid, &exists) != 2)
        return false;
    return rvid == vid && exists != 0;
}

int l2d_switchd_set_runtime_admin(const char *socket_path, int port,
                                  int mode) {
    char payload[64];
    char resp[64] = {0};
    s32 ec = 0;
    int n;
    int rn;

    if (port <= 0 || mode < 0 || mode > 1)
        return -1;

    n = snprintf(payload, sizeof(payload), "port=%d mode=%d", port, mode);
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_PORT_ADMIN_OVERRIDE,
                      (const u8 *)payload, n,
                      (u8 *)resp, sizeof(resp) - 1, 10000, &ec);
    return (rn >= 0 && ec == 0) ? 0 : -1;
}

int l2d_switchd_clear_dynamic_macs(const char *socket_path, int port) {
    char payload[64];
    char resp[64] = {0};
    s32 ec = 0;
    int n;
    int rn;

    if (port <= 0)
        return -1;

    n = snprintf(payload, sizeof(payload), "port=%d vid=0", port);
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_DYNAMIC_MAC_CLEAR,
                      (const u8 *)payload, n,
                      (u8 *)resp, sizeof(resp) - 1, 10000, &ec);
    return (rn >= 0 && ec == 0) ? 0 : -1;
}

int l2d_switchd_set_port_security(const char *socket_path, int port,
                                  bool enable, const char *action) {
    char payload[96];
    char resp[64] = {0};
    s32 ec = 0;
    int n;
    int rn;

    if (port <= 0)
        return -1;

    n = snprintf(payload, sizeof(payload),
                 "port=%d enable=%d strict=%d action=%s",
                 port, enable ? 1 : 0,
                 0,
                 action && action[0] ? action : "drop");
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_PORT_SECURITY_ACTION,
                      (const u8 *)payload, n,
                      (u8 *)resp, sizeof(resp) - 1, 10000, &ec);
    return (rn >= 0 && ec == 0) ? 0 : -1;
}

int l2d_switchd_get_mac_snapshot(const char *socket_path, void *resp,
                                 int resp_max) {
    s32 ec = 0;
    int rn;

    if (!resp || resp_max <= 0)
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_MAC_SNAPSHOT_GET,
                      (const u8 *)"", 0,
                      (u8 *)resp, resp_max - 1, 10000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    return rn;
}

int l2d_switchd_get_mac_update_events(const char *socket_path, char *resp,
                                      int resp_max) {
    s32 ec = 0;
    int rn;

    if (!resp || resp_max <= 0)
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_MAC_EVENTS_GET,
                      (const u8 *)"", 0,
                      (u8 *)resp, resp_max - 1, 10000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    resp[rn < resp_max ? rn : resp_max - 1] = '\0';
    return rn;
}

int l2d_switchd_get_lag_table(const char *socket_path, char *resp,
                              int resp_max) {
    s32 ec = 0;
    int rn;

    if (!resp || resp_max <= 0)
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_LAG_GET_ALL,
                      (const u8 *)"", 0,
                      (u8 *)resp, resp_max - 1, 2000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    resp[rn < resp_max ? rn : resp_max - 1] = '\0';
    return rn;
}

int l2d_switchd_get_stp_snapshot(const char *socket_path,
                                 nl_stp_snapshot *snapshot) {
    return nl_stp_snapshot_fetch(socket_path, NL_DAEMON_L2D, 10000,
                                 snapshot);
}

int l2d_switchd_get_port_mirroring(const char *socket_path, char *resp,
                                   int resp_max) {
    s32 ec = 0;
    int rn;

    if (!resp || resp_max <= 0)
        return -1;
    rn = switchd_call(socket_path, NL_SWITCHD_PORT_MIRRORING_GET,
                      (const u8 *)"", 0, (u8 *)resp, resp_max - 1,
                      3000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    resp[rn < resp_max ? rn : resp_max - 1] = '\0';
    return rn;
}

int l2d_switchd_get_user_filter_counters(const char *socket_path, int vid,
                                         int port, const char *mac_kind,
                                         const char *mac, u64 *packets,
                                         u64 *octets, char *state,
                                         int state_max) {
    char payload[128];
    char resp[256] = {0};
    char value[32];
    s32 ec = 0;
    int n;
    int rn;

    if (packets)
        *packets = 0;
    if (octets)
        *octets = 0;
    if (state && state_max > 0) {
        snprintf(state, (size_t)state_max, "unavailable");
    }
    if (vid < 1 || vid > 4094 || port <= 0 || !mac || !mac[0])
        return -1;

    n = snprintf(payload, sizeof(payload), "vid=%d port=%d field=%s mac=%s",
                 vid, port,
                 mac_kind && mac_kind[0] ? mac_kind : "source",
                 mac);
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_L2_SECURITY_COUNTERS_GET,
                      (const u8 *)payload, n,
                      (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    if (state && state_max > 0 &&
        xml_attr_value(resp, "state", value, sizeof(value)))
        snprintf(state, (size_t)state_max, "%s", value);
    if (xml_attr_value(resp, "packets", value, sizeof(value)) && packets)
        *packets = parse_u64_or_zero(value);
    if (xml_attr_value(resp, "octets", value, sizeof(value)) && octets)
        *octets = parse_u64_or_zero(value);
    return 0;
}

int l2d_switchd_get_ingress_ipv4_acl_counters(
    const char *socket_path, int vid, int port,
    bool has_src_ip, const char *src_ip,
    bool has_src_ip_mask, const char *src_mask,
    bool has_dst_ip, const char *dst_ip,
    bool has_dst_ip_mask, const char *dst_mask,
    bool has_dscp, int dscp,
    bool has_ecn, int ecn,
    bool has_protocol, int protocol,
    bool has_src_port, int src_port,
    bool has_src_port_range, const char *src_port_range,
    bool has_dst_port, int dst_port,
    bool has_dst_port_range, const char *dst_port_range,
    bool has_tcp_flags, int tcp_flags,
    bool has_tcp_flags_mask, int tcp_flags_mask,
    bool count_only,
    u64 *packets, u64 *octets, char *state, int state_max) {
    char payload[384];
    char resp[256] = {0};
    char value[32];
    s32 ec = 0;
    int off;
    int rn;

    if (packets)
        *packets = 0;
    if (octets)
        *octets = 0;
    if (state && state_max > 0)
        snprintf(state, (size_t)state_max, "unavailable");
    if (vid < 1 || vid > 4094 || port <= 0)
        return -1;

    off = snprintf(payload, sizeof(payload), "vid=%d port=%d", vid, port);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_src_ip && src_ip && src_ip[0])
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " src-ip=%s", src_ip);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_src_ip_mask && src_mask && src_mask[0])
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " src-mask=%s", src_mask);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_dst_ip && dst_ip && dst_ip[0])
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " dst-ip=%s", dst_ip);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_dst_ip_mask && dst_mask && dst_mask[0])
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " dst-mask=%s", dst_mask);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_dscp)
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " dscp=%d", dscp);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_ecn)
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " ecn=%d", ecn);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_protocol)
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " proto=%d", protocol);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_src_port)
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " src-port=%d", src_port);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_src_port_range && src_port_range && src_port_range[0])
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " src-port-range=%s", src_port_range);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_dst_port)
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " dst-port=%d", dst_port);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_dst_port_range && dst_port_range && dst_port_range[0])
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " dst-port-range=%s", dst_port_range);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_tcp_flags)
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " tcp-flags=%d", tcp_flags);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (has_tcp_flags_mask)
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " tcp-flags-mask=%d", tcp_flags_mask);
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
    if (count_only)
        off += snprintf(payload + off, sizeof(payload) - (size_t)off,
                        " action=count");
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_IPV4_ACL_COUNTERS_GET,
                      (const u8 *)payload, off,
                      (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    if (state && state_max > 0 &&
        xml_attr_value(resp, "state", value, sizeof(value)))
        snprintf(state, (size_t)state_max, "%s", value);
    if (xml_attr_value(resp, "packets", value, sizeof(value)) && packets)
        *packets = parse_u64_or_zero(value);
    if (xml_attr_value(resp, "octets", value, sizeof(value)) && octets)
        *octets = parse_u64_or_zero(value);
    return 0;
}

int l2d_switchd_get_egress_acl_counters(const char *socket_path, int port,
                                        u64 *packets, u64 *octets,
                                        char *state, int state_max) {
    char payload[32];
    char resp[192] = {0};
    char value[32];
    s32 ec = 0;
    int n;
    int rn;

    if (packets)
        *packets = 0;
    if (octets)
        *octets = 0;
    if (state && state_max > 0)
        snprintf(state, (size_t)state_max, "unavailable");
    if (port <= 0)
        return -1;

    n = snprintf(payload, sizeof(payload), "port=%d", port);
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_EGRESS_ACL_COUNTERS_GET,
                      (const u8 *)payload, n,
                      (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    if (state && state_max > 0 &&
        xml_attr_value(resp, "state", value, sizeof(value)))
        snprintf(state, (size_t)state_max, "%s", value);
    if (xml_attr_value(resp, "packets", value, sizeof(value)) && packets)
        *packets = parse_u64_or_zero(value);
    if (xml_attr_value(resp, "octets", value, sizeof(value)) && octets)
        *octets = parse_u64_or_zero(value);
    return 0;
}

int l2d_switchd_get_acl_policer_counters(
    const char *socket_path, int port, const char *dst_mac,
    int rate_kbps, int burst_bytes, u64 *packets, u64 *octets,
    char *state, int state_max) {
    char payload[160];
    char resp[320] = {0};
    char value[32];
    s32 ec = 0;
    int n;
    int rn;

    if (packets)
        *packets = 0;
    if (octets)
        *octets = 0;
    if (state && state_max > 0)
        snprintf(state, (size_t)state_max, "unavailable");
    if (port <= 0 || !dst_mac || !dst_mac[0] ||
        rate_kbps <= 0 || burst_bytes <= 0)
        return -1;

    n = snprintf(payload, sizeof(payload),
                 "port=%d dst-mac=%s rate-kbps=%d burst-bytes=%d",
                 port, dst_mac, rate_kbps, burst_bytes);
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;

    rn = switchd_call(socket_path, NL_SWITCHD_ACL_POLICER_COUNTERS_GET,
                      (const u8 *)payload, n,
                      (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    if (state && state_max > 0 &&
        xml_attr_value(resp, "state", value, sizeof(value)))
        snprintf(state, (size_t)state_max, "%s", value);
    if (xml_attr_value(resp, "packets", value, sizeof(value)) && packets)
        *packets = parse_u64_or_zero(value);
    if (xml_attr_value(resp, "octets", value, sizeof(value)) && octets)
        *octets = parse_u64_or_zero(value);
    return 0;
}

int l2d_switchd_get_acl_independent_counters(
    const char *socket_path, const l2_acl_independent *entry, int port,
    u64 *packets, u64 *octets, char *state, int state_max) {
    char payload[512];
    char resp[512] = {0};
    char value[32];
    s32 ec = 0;
    int off;
    int rn;

    if (packets)
        *packets = 0;
    if (octets)
        *octets = 0;
    if (state && state_max > 0)
        snprintf(state, (size_t)state_max, "unavailable");
    if (!entry || port <= 0 || entry->slot < 0 || entry->vid <= 0 ||
        !entry->group[0] || !entry->term[0] || !entry->family[0])
        return -1;

    off = snprintf(payload, sizeof(payload),
                   "slot=%d group=%s term=%s family=%s vid=%d port=%d "
                   "action=%s",
                   entry->slot, entry->group, entry->term, entry->family,
                   entry->vid, port,
                   entry->action[0] ? entry->action : "drop");
    if (off <= 0 || off >= (int)sizeof(payload))
        return -1;
#define ACL_IND_APPEND(fmt, value_arg) do { \
        int n__ = snprintf(payload + off, sizeof(payload) - (size_t)off, \
                           fmt, value_arg); \
        if (n__ < 0 || (size_t)n__ >= sizeof(payload) - (size_t)off) \
            return -1; \
        off += n__; \
    } while (0)
    if (entry->has_src_mac)
        ACL_IND_APPEND(" src-mac=%s", entry->src_mac);
    if (entry->has_dst_mac)
        ACL_IND_APPEND(" dst-mac=%s", entry->dst_mac);
    if (entry->has_src_ip) {
        ACL_IND_APPEND(" src-ip=%s", entry->src_ip);
        if (entry->has_src_ip_mask)
            ACL_IND_APPEND(" src-mask=%s", entry->src_mask);
    }
    if (entry->has_dst_ip) {
        ACL_IND_APPEND(" dst-ip=%s", entry->dst_ip);
        if (entry->has_dst_ip_mask)
            ACL_IND_APPEND(" dst-mask=%s", entry->dst_mask);
    }
    if (entry->has_dscp)
        ACL_IND_APPEND(" dscp=%d", entry->dscp);
    if (entry->has_protocol)
        ACL_IND_APPEND(" proto=%d", entry->protocol);
    if (entry->has_src_port)
        ACL_IND_APPEND(" src-port=%d", entry->src_port);
    if (entry->has_dst_port)
        ACL_IND_APPEND(" dst-port=%d", entry->dst_port);
    if (entry->has_src_port_range)
        ACL_IND_APPEND(" src-port-range=%s", entry->src_port_range);
    if (entry->has_dst_port_range)
        ACL_IND_APPEND(" dst-port-range=%s", entry->dst_port_range);
    if (entry->has_tcp_flags)
        ACL_IND_APPEND(" tcp-flags=%d", entry->tcp_flags);
    if (entry->has_tcp_flags_mask)
        ACL_IND_APPEND(" tcp-flags-mask=%d", entry->tcp_flags_mask);
    if (entry->rate_kbps > 0)
        ACL_IND_APPEND(" rate-kbps=%d", entry->rate_kbps);
    if (entry->burst_bytes > 0)
        ACL_IND_APPEND(" burst-bytes=%d", entry->burst_bytes);
#undef ACL_IND_APPEND

    rn = switchd_call(socket_path, NL_SWITCHD_ACL_INDEPENDENT_COUNTERS_GET,
                      (const u8 *)payload, off,
                      (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    if (rn <= 0 || ec != 0)
        return -1;
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    if (state && state_max > 0 &&
        xml_attr_value(resp, "state", value, sizeof(value)))
        snprintf(state, (size_t)state_max, "%s", value);
    if (xml_attr_value(resp, "packets", value, sizeof(value)) && packets)
        *packets = parse_u64_or_zero(value);
    if (xml_attr_value(resp, "octets", value, sizeof(value)) && octets)
        *octets = parse_u64_or_zero(value);
    return 0;
}

int l2d_switchd_apply_igmp_listener(const char *socket_path, bool add,
                                    int vid, int port, const char *group,
                                    u64 txid) {
    char payload[160];
    char resp[256] = {0};
    s32 ec = 0;
    int n;
    int rn;

    if (!socket_path || !group || txid == 0 || vid < 1 || vid > 4094 ||
        port <= 0)
        return -1;
    n = snprintf(payload, sizeof(payload),
                 "igmp-listener-%s vid=%d port=%d group=%s\n",
                 add ? "set" : "del", vid, port, group);
    if (n <= 0 || n >= (int)sizeof(payload))
        return -1;
    rn = nl_rpc_call_ex(socket_path, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_L2_PLAN_APPLY, txid,
                        (const u8 *)payload, n,
                        (u8 *)resp, sizeof(resp) - 1, 10000, &ec);
    return rn >= 0 && ec == 0 ? 0 : -1;
}

int l2d_switchd_get_multicast_owner(const char *socket_path, char *resp,
                                    int resp_max) {
    s32 ec = 0;
    int rn;

    if (!socket_path || !resp || resp_max <= 0)
        return -1;
    rn = switchd_call(socket_path, NL_SWITCHD_L2_MULTICAST_OWNER_GET,
                      NULL, 0,
                      (u8 *)resp, resp_max - 1, 10000, &ec);
    if (rn <= 0 || rn >= resp_max || ec != 0 || !nl_mcast_readback_valid(resp, (size_t)rn)) {
        resp[0] = '\0';
        return -1;
    }
    resp[rn] = '\0';
    return rn;
}
