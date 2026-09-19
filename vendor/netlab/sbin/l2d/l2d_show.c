#include "l2d_show.h"

#include "l2d_switchd.h"
#include "l2d_state.h"
#include "l2_plan_internal.h"
#include "netlab/error.h"
#include "netlab/journal.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    bool queried;
    u64 packets;
    u64 octets;
    char state[24];
} l2_user_filter_counter_snapshot;

typedef l2_user_filter_counter_snapshot l2_acl_counter_snapshot;

#define L2D_SHOW_CONFIG_XML_BYTES (256U * 1024U)

static const char *acl_counter_state_name(u8 state) {
    if (state == NL_ACL_COUNTER_STATE_INSTALLED)
        return "installed";
    if (state == NL_ACL_COUNTER_STATE_ABSENT)
        return "absent";
    if (state == NL_ACL_COUNTER_STATE_MISMATCH)
        return "mismatch";
    return "unavailable";
}

static void publish_acl_counter(
    l2_acl_counter_snapshot *dst,
    const nl_acl_counter_snapshot_entry *src) {
    if (!dst || !src)
        return;
    dst->queried = true;
    dst->packets = src->packets;
    dst->octets = src->octets;
    snprintf(dst->state, sizeof(dst->state), "%s",
             acl_counter_state_name(src->state));
}

static bool ipv4_text_to_host(const char *text, u32 *out) {
    struct in_addr addr;

    if (!text || !out || inet_pton(AF_INET, text, &addr) != 1)
        return false;
    *out = ntohl(addr.s_addr);
    return true;
}

static bool mac_text_to_u64(const char *text, u64 *out) {
    u8 mac[NL_MAC_ADDR_LEN];
    u64 value = 0;

    if (!text || !out || !nl_platform_parse_mac(text, mac))
        return false;
    for (int i = 0; i < NL_MAC_ADDR_LEN; i++)
        value = (value << 8) | mac[i];
    *out = value;
    return true;
}

static bool fill_ingress_counter_match(
    const l2_ingress_ipv4_acl *src, int port,
    nl_acl_counter_ipv4_match *dst) {
    memset(dst, 0, sizeof(*dst));
    if (!src || port <= 0)
        return false;
    dst->vid = (u16)src->vid;
    dst->port = (u16)port;
    if (src->has_src_ip) {
        if (!ipv4_text_to_host(src->src_ip, &dst->src_ip))
            return false;
        dst->flags |= NL_ACL_COUNTER_MATCH_SRC_IP;
    }
    if (src->has_src_ip_mask) {
        if (!ipv4_text_to_host(src->src_mask, &dst->src_ip_mask))
            return false;
        dst->flags |= NL_ACL_COUNTER_MATCH_SRC_IP_MASK;
    }
    if (src->has_dst_ip) {
        if (!ipv4_text_to_host(src->dst_ip, &dst->dst_ip))
            return false;
        dst->flags |= NL_ACL_COUNTER_MATCH_DST_IP;
    }
    if (src->has_dst_ip_mask) {
        if (!ipv4_text_to_host(src->dst_mask, &dst->dst_ip_mask))
            return false;
        dst->flags |= NL_ACL_COUNTER_MATCH_DST_IP_MASK;
    }
#define COPY_INGRESS_FLAG(member, flag_name) do { \
        if (src->has_##member) { \
            dst->flags |= flag_name; \
            dst->member = src->member; \
        } \
    } while (0)
    COPY_INGRESS_FLAG(dscp, NL_ACL_COUNTER_MATCH_DSCP);
    COPY_INGRESS_FLAG(ecn, NL_ACL_COUNTER_MATCH_ECN);
    COPY_INGRESS_FLAG(protocol, NL_ACL_COUNTER_MATCH_PROTOCOL);
    COPY_INGRESS_FLAG(src_port, NL_ACL_COUNTER_MATCH_SRC_PORT);
    COPY_INGRESS_FLAG(dst_port, NL_ACL_COUNTER_MATCH_DST_PORT);
    COPY_INGRESS_FLAG(tcp_flags, NL_ACL_COUNTER_MATCH_TCP_FLAGS);
    COPY_INGRESS_FLAG(tcp_flags_mask,
                      NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK);
#undef COPY_INGRESS_FLAG
    if (src->has_tcp_flags && !src->has_tcp_flags_mask) {
        dst->flags |= NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK;
        dst->tcp_flags_mask = src->tcp_flags_mask;
    }
    if (src->has_src_port_range) {
        dst->flags |= NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE;
        dst->src_port_start = src->src_port_start;
        dst->src_port_end = src->src_port_end;
    }
    if (src->has_dst_port_range) {
        dst->flags |= NL_ACL_COUNTER_MATCH_DST_PORT_RANGE;
        dst->dst_port_start = src->dst_port_start;
        dst->dst_port_end = src->dst_port_end;
    }
    if (strcmp(src->action, "count") == 0)
        dst->flags |= NL_ACL_COUNTER_MATCH_COUNT_ONLY;
    return true;
}

static bool fill_independent_counter_query(
    const l2_acl_independent *src, int port,
    nl_acl_counter_query_entry *dst) {
    nl_acl_counter_ipv4_match *m;

    if (!src || !dst || port <= 0)
        return false;
    m = &dst->match;
    m->vid = (u16)src->vid;
    m->port = (u16)port;
    dst->slot = src->slot;
    dst->rate_kbps = src->rate_kbps;
    dst->burst_bytes = src->burst_bytes;
    if (strcmp(src->family, "ethernet") == 0)
        dst->family = NL_ACL_COUNTER_FAMILY_ETHERNET;
    else if (strcmp(src->family, "inet") == 0)
        dst->family = NL_ACL_COUNTER_FAMILY_INET;
    else if (strcmp(src->family, "policer") == 0)
        dst->family = NL_ACL_COUNTER_FAMILY_POLICER;
    else
        return false;
    if (strcmp(src->action, "drop") == 0)
        dst->action = NL_ACL_COUNTER_ACTION_DROP;
    else if (strcmp(src->action, "count") == 0)
        dst->action = NL_ACL_COUNTER_ACTION_COUNT;
    else if (strcmp(src->action, "policer") == 0)
        dst->action = NL_ACL_COUNTER_ACTION_POLICER;
    else
        return false;
    if (src->has_src_mac) {
        if (!mac_text_to_u64(src->src_mac, &dst->src_mac))
            return false;
        m->flags |= NL_ACL_COUNTER_MATCH_SRC_MAC;
    }
    if (src->has_dst_mac) {
        if (!mac_text_to_u64(src->dst_mac, &dst->dst_mac))
            return false;
        m->flags |= NL_ACL_COUNTER_MATCH_DST_MAC;
    }
    if (src->has_src_ip) {
        if (!ipv4_text_to_host(src->src_ip, &m->src_ip))
            return false;
        m->flags |= NL_ACL_COUNTER_MATCH_SRC_IP;
    }
    if (src->has_src_ip_mask) {
        if (!ipv4_text_to_host(src->src_mask, &m->src_ip_mask))
            return false;
        m->flags |= NL_ACL_COUNTER_MATCH_SRC_IP_MASK;
    }
    if (src->has_dst_ip) {
        if (!ipv4_text_to_host(src->dst_ip, &m->dst_ip))
            return false;
        m->flags |= NL_ACL_COUNTER_MATCH_DST_IP;
    }
    if (src->has_dst_ip_mask) {
        if (!ipv4_text_to_host(src->dst_mask, &m->dst_ip_mask))
            return false;
        m->flags |= NL_ACL_COUNTER_MATCH_DST_IP_MASK;
    }
#define COPY_INDEPENDENT_FLAG(member, flag_name) do { \
        if (src->has_##member) { \
            m->flags |= flag_name; \
            m->member = src->member; \
        } \
    } while (0)
    COPY_INDEPENDENT_FLAG(dscp, NL_ACL_COUNTER_MATCH_DSCP);
    COPY_INDEPENDENT_FLAG(protocol, NL_ACL_COUNTER_MATCH_PROTOCOL);
    COPY_INDEPENDENT_FLAG(src_port, NL_ACL_COUNTER_MATCH_SRC_PORT);
    COPY_INDEPENDENT_FLAG(dst_port, NL_ACL_COUNTER_MATCH_DST_PORT);
    COPY_INDEPENDENT_FLAG(tcp_flags, NL_ACL_COUNTER_MATCH_TCP_FLAGS);
    COPY_INDEPENDENT_FLAG(tcp_flags_mask,
                          NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK);
#undef COPY_INDEPENDENT_FLAG
    if (src->has_tcp_flags && !src->has_tcp_flags_mask) {
        m->flags |= NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK;
        m->tcp_flags_mask = src->tcp_flags_mask;
    }
    if (src->has_src_port_range) {
        m->flags |= NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE;
        m->src_port_start = src->src_port_start;
        m->src_port_end = src->src_port_end;
    }
    if (src->has_dst_port_range) {
        m->flags |= NL_ACL_COUNTER_MATCH_DST_PORT_RANGE;
        m->dst_port_start = src->dst_port_start;
        m->dst_port_end = src->dst_port_end;
    }
    if (strcmp(src->action, "count") == 0)
        m->flags |= NL_ACL_COUNTER_MATCH_COUNT_ONLY;
    return true;
}

static int append_show_text(char *buf, size_t buf_size, int off,
                            const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !fmt || off < 0 || (size_t)off >= buf_size)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(buf + off, buf_size - (size_t)off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - (size_t)off)
        return -1;
    return off + n;
}

static bool user_filter_matches_feature(const l2_user_filter *filter,
                                        const char *feature) {
    const char *filter_feature;

    if (!filter || !feature)
        return false;
    filter_feature = filter->feature[0] ? filter->feature : "user-filter";
    return strcmp(filter_feature, feature) == 0;
}

static int emit_user_filter_container(
    char *buf, size_t buf_size, int off, const char *container_name,
    const char *feature, const l2_user_filter *user_filters,
    const l2_user_filter_counter_snapshot *counters, int n_user_filters) {
    off = append_show_text(buf, buf_size, off,
                    "  <%s>\n", container_name);
    for (int i = 0; i < n_user_filters; i++) {
        char counter_attrs[128];
        const char *counter_state;

        if (!user_filter_matches_feature(&user_filters[i], feature))
            continue;
        counter_state = counters[i].state[0] ?
                        counters[i].state : "unavailable";
        if (counters[i].queried && strcmp(counter_state, "installed") == 0) {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\" packets=\"%llu\" "
                     "octets=\"%llu\"",
                     counter_state,
                     (unsigned long long)counters[i].packets,
                     (unsigned long long)counters[i].octets);
        } else {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\"", counter_state);
        }
        off = append_show_text(buf, buf_size, off,
                        "    <term name=\"%s\" vlan=\"%s\" vid=\"%d\" "
                        "interface=\"%s\" match=\"%s-mac\" %s-mac=\"%s\" "
                        "action=\"%s\" "
                        "enforcement=\"hardware-flow-tcam\" %s/>\n",
                        user_filters[i].name,
                        user_filters[i].vlan,
                        user_filters[i].vid,
                        user_filters[i].ifname,
                        user_filters[i].mac_kind[0] ?
                        user_filters[i].mac_kind : "source",
                        user_filters[i].mac_kind[0] ?
                        user_filters[i].mac_kind : "source",
                        user_filters[i].mac,
                        user_filters[i].action[0] ?
                        user_filters[i].action : "drop",
                        counter_attrs);
    }
    off = append_show_text(buf, buf_size, off,
                    "  </%s>\n", container_name);
    return off;
}

static int emit_ingress_ipv4_acl_container(
    char *buf, size_t buf_size, int off,
    const l2_ingress_ipv4_acl *entries,
    const l2_acl_counter_snapshot *counters, int n_entries) {
    off = append_show_text(buf, buf_size, off,
                    "  <ingress-ipv4-acl>\n");
    for (int i = 0; i < n_entries; i++) {
        char match_attrs[384] = "";
        char counter_attrs[128];
        int moff = 0;
        const char *counter_state;

        if (entries[i].has_src_prefix)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-prefix=\"%s\"",
                             entries[i].src_prefix);
        else if (entries[i].has_src_ip)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-ip=\"%s\"", entries[i].src_ip);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dst_prefix)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-prefix=\"%s\"",
                             entries[i].dst_prefix);
        else if (entries[i].has_dst_ip)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-ip=\"%s\"", entries[i].dst_ip);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_protocol)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " protocol=\"%d\"", entries[i].protocol);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_src_port)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-port=\"%d\"", entries[i].src_port);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_src_port_range)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-port-range=\"%s\"",
                             entries[i].src_port_range);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dst_port)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-port=\"%d\"", entries[i].dst_port);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dst_port_range)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-port-range=\"%s\"",
                             entries[i].dst_port_range);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dscp)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " dscp=\"%d\"", entries[i].dscp);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_ecn)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " ecn=\"%d\"", entries[i].ecn);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_tcp_flags)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " tcp-flags=\"%d\"", entries[i].tcp_flags);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_tcp_flags_mask)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " tcp-flags-mask=\"%d\"",
                             entries[i].tcp_flags_mask);

        counter_state = counters[i].state[0] ?
                        counters[i].state : "unavailable";
        if (counters[i].queried && strcmp(counter_state, "installed") == 0) {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\" packets=\"%llu\" "
                     "octets=\"%llu\"",
                     counter_state,
                     (unsigned long long)counters[i].packets,
                     (unsigned long long)counters[i].octets);
        } else {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\"", counter_state);
        }
        off = append_show_text(buf, buf_size, off,
                        "    <term name=\"%s\" vlan=\"%s\" vid=\"%d\" "
                        "interface=\"%s\"%s action=\"%s\" "
                        "enforcement=\"hardware-flow-tcam\" %s/>\n",
                        entries[i].name, entries[i].vlan, entries[i].vid,
                        entries[i].ifname, match_attrs,
                        entries[i].action[0] ? entries[i].action : "drop",
                        counter_attrs);
    }
    off = append_show_text(buf, buf_size, off,
                    "  </ingress-ipv4-acl>\n");
    return off;
}

static int emit_egress_acl_container(char *buf, size_t buf_size, int off,
                                     const l2_egress_acl *entries,
                                     const l2_acl_counter_snapshot *counters,
                                     int n_entries) {
    off = append_show_text(buf, buf_size, off,
                    "  <egress-acl>\n");
    for (int i = 0; i < n_entries; i++) {
        char counter_attrs[128];
        const char *counter_state = counters[i].state[0] ?
                                    counters[i].state : "unavailable";

        if (counters[i].queried && strcmp(counter_state, "installed") == 0) {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\" packets=\"%llu\" "
                     "octets=\"%llu\"",
                     counter_state,
                     (unsigned long long)counters[i].packets,
                     (unsigned long long)counters[i].octets);
        } else {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\"", counter_state);
        }
        off = append_show_text(buf, buf_size, off,
                        "    <term name=\"%s\" interface=\"%s\" "
                        "source-mac=\"%s\" destination-mac=\"%s\" "
                        "action=\"%s\" "
                        "enforcement=\"hardware-egress-acl\" %s/>\n",
                        entries[i].name,
                        entries[i].ifname,
                        entries[i].src_mac,
                        entries[i].dst_mac,
                        entries[i].action[0] ? entries[i].action : "drop",
                        counter_attrs);
    }
    off = append_show_text(buf, buf_size, off,
                    "  </egress-acl>\n");
    return off;
}

static int emit_acl_policer_container(char *buf, size_t buf_size, int off,
                                      const l2_acl_policer *entries,
                                      const l2_acl_counter_snapshot *counters,
                                      int n_entries) {
    off = append_show_text(buf, buf_size, off,
                    "  <acl-policer>\n");
    for (int i = 0; i < n_entries; i++) {
        char counter_attrs[128];
        const char *counter_state = counters[i].state[0] ?
                                    counters[i].state : "unavailable";

        if (counters[i].queried && strcmp(counter_state, "installed") == 0) {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\" packets=\"%llu\" "
                     "octets=\"%llu\"",
                     counter_state,
                     (unsigned long long)counters[i].packets,
                     (unsigned long long)counters[i].octets);
        } else {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\"", counter_state);
        }
        off = append_show_text(buf, buf_size, off,
                        "    <term name=\"%s\" interface=\"%s\" "
                        "destination-mac=\"%s\" bandwidth=\"%d\" "
                        "burst-size=\"%d\" action=\"police\" "
                        "enforcement=\"hardware-acl-compiler\" %s/>\n",
                        entries[i].name,
                        entries[i].ifname,
                        entries[i].dst_mac,
                        entries[i].rate_kbps,
                        entries[i].burst_bytes,
                        counter_attrs);
    }
    off = append_show_text(buf, buf_size, off,
                    "  </acl-policer>\n");
    return off;
}

static int emit_acl_independent_container(
    char *buf, size_t buf_size, int off,
    const l2_acl_independent *entries,
    const l2_acl_counter_snapshot *counters, int n_entries) {
    off = append_show_text(buf, buf_size, off,
                    "  <acl-independent>\n");
    for (int i = 0; i < n_entries; i++) {
        char match_attrs[768] = "";
        char counter_attrs[128];
        const char *counter_state;
        int moff = 0;

        if (entries[i].has_src_mac)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-mac=\"%s\"", entries[i].src_mac);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dst_mac)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-mac=\"%s\"", entries[i].dst_mac);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_src_prefix)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-prefix=\"%s\"",
                             entries[i].src_prefix);
        else if (entries[i].has_src_ip)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-ip=\"%s\"", entries[i].src_ip);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dst_prefix)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-prefix=\"%s\"",
                             entries[i].dst_prefix);
        else if (entries[i].has_dst_ip)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-ip=\"%s\"", entries[i].dst_ip);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dscp)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " dscp=\"%d\"", entries[i].dscp);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_protocol)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " protocol=\"%d\"", entries[i].protocol);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_src_port)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-port=\"%d\"", entries[i].src_port);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_src_port_range)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " source-port-range=\"%s\"",
                             entries[i].src_port_range);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dst_port)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-port=\"%d\"", entries[i].dst_port);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_dst_port_range)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " destination-port-range=\"%s\"",
                             entries[i].dst_port_range);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_tcp_flags)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " tcp-flags=\"%d\"", entries[i].tcp_flags);
        if (moff < 0 || (size_t)moff >= sizeof(match_attrs))
            moff = (int)sizeof(match_attrs) - 1;
        if (entries[i].has_tcp_flags_mask)
            moff = append_show_text(match_attrs, sizeof(match_attrs), moff,
                             " tcp-flags-mask=\"%d\"",
                             entries[i].tcp_flags_mask);

        counter_state = counters[i].state[0] ?
                        counters[i].state : "unavailable";
        if (counters[i].queried && strcmp(counter_state, "installed") == 0) {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\" packets=\"%llu\" "
                     "octets=\"%llu\"",
                     counter_state,
                     (unsigned long long)counters[i].packets,
                     (unsigned long long)counters[i].octets);
        } else {
            snprintf(counter_attrs, sizeof(counter_attrs),
                     "counter-state=\"%s\"", counter_state);
        }
        off = append_show_text(buf, buf_size, off,
                        "    <term group=\"%s\" name=\"%s\" family=\"%s\" "
                        "slot=\"%d\" vlan=\"%s\" vid=\"%d\" "
                        "interface=\"%s\"%s action=\"%s\" "
                        "bandwidth=\"%d\" burst-size=\"%d\" "
                        "enforcement=\"hardware-general-acl-independent\" "
                        "%s/>\n",
                        entries[i].group, entries[i].term,
                        entries[i].family, entries[i].slot,
                        entries[i].vlan, entries[i].vid,
                        entries[i].ifname, match_attrs,
                        entries[i].action[0] ? entries[i].action : "drop",
                        entries[i].rate_kbps, entries[i].burst_bytes,
                        counter_attrs);
    }
    off = append_show_text(buf, buf_size, off,
                    "  </acl-independent>\n");
    return off;
}

static int send_show_response(nl_conn *conn, const nl_msg_hdr *msg,
                              const char *buf, int len) {
    static const char capacity_error[] =
        "L2 state response exceeds the IPC message capacity";
    const char *payload = buf;
    s32 error_code = 0;
    nl_msg_hdr *resp;

    if (len < 0 || len > NETLAB_MAX_MSG) {
        payload = capacity_error;
        len = (int)sizeof(capacity_error) - 1;
        error_code = NL_ERR_CAPABILITY_INSUFFICIENT;
    }
    resp = nl_msg_alloc((u32)len);

    if (!resp)
        return -1;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)len;
    memcpy(resp->payload, payload, (size_t)len);
    nl_send(conn, resp);
    nl_msg_free(resp);
    return 0;
}

static const char *mirror_direction_name(int direction) {
    if (direction == HAL_MIRROR_DIRECTION_EGRESS)
        return "egress";
    if (direction == HAL_MIRROR_DIRECTION_BOTH)
        return "both";
    return "ingress";
}

static int show_collect_ports(cfg_port_ref *ports, int max_ports) {
    nl_port_entry entries[NL_MAX_PORTS_PER_PROFILE];
    int n_entries = nl_ifid_get_all(entries, NL_MAX_PORTS_PER_PROFILE);
    int n = 0;

    for (int i = 0; i < n_entries && n < max_ports; i++) {
        if (!nl_ifid_is_user_port(entries[i].logical_port))
            continue;
        snprintf(ports[n].name, sizeof(ports[n].name), "%s",
                 entries[i].canonical_name);
        ports[n].hw_port = entries[i].logical_port;
        ports[n].flags = entries[i].flags;
        n++;
    }
    return n;
}

static bool mirror_readback_matches(const cfg_port_mirror_intent *intent,
                                    const char *hardware) {
    const char *session = hardware ? strstr(hardware, "<session ") : NULL;
    char needle[128];

    if (!intent || !hardware || !strstr(hardware, "<port-mirroring ") ||
        !strstr(hardware, "</port-mirroring>"))
        return false;
    if (!intent->exists)
        return session == NULL;
    if (!session)
        return false;
    snprintf(needle, sizeof(needle), "destination-port=\"%d\"",
             intent->destination.hw_port);
    if (!strstr(session, needle))
        return false;
    snprintf(needle, sizeof(needle), "source-count=\"%d\"",
             intent->n_sources);
    if (!strstr(session, needle))
        return false;
    for (int i = 0; i < intent->n_sources; i++) {
        snprintf(needle, sizeof(needle),
                 "<source port=\"%d\" direction=\"%s\"/>",
                 intent->sources[i].port.hw_port,
                 mirror_direction_name(intent->sources[i].direction));
        if (!strstr(session, needle))
            return false;
    }
    return true;
}

int l2d_show_port_mirroring(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    char *xml = calloc(1, L2D_SHOW_CONFIG_XML_BYTES);
    char hardware[4096] = {0};
    cfg_port_ref ports[NL_MAX_PORTS_PER_PROFILE];
    cfg_port_mirror_intent intent;
    nl_yang_session *ys = NULL;
    FILE *f = NULL;
    bool config_ok = false;
    bool hardware_ok = false;
    const char *state = "unavailable";
    int off = 0;
    int n_ports;

    if (!buf || !xml) {
        free(xml);
        free(buf);
        return send_show_response(conn, msg, NULL, -1);
    }
    memset(&intent, 0, sizeof(intent));
    ys = nl_yang_session_create(NULL);
    if (ys) {
        char active_path[512];

        nl_config_file_path(active_path, sizeof(active_path), "active.conf");
        f = fopen(active_path, "r");
        if (f) {
            size_t n = fread(xml, 1, L2D_SHOW_CONFIG_XML_BYTES - 1, f);
            fclose(f);
            f = NULL;
            if (n > 0) {
                struct lyd_node *tree;
                xml[n] = '\0';
                tree = nl_yang_from_xml(ys, xml);
                if (tree) {
                    nl_yang_data_set(ys, tree);
                    n_ports = show_collect_ports(
                        ports, NL_MAX_PORTS_PER_PROFILE);
                    (void)l2_collect_port_mirror_intent(
                        ys, &intent, ports, n_ports);
                    config_ok = true;
                }
            }
        }
    }
    hardware_ok = l2d_switchd_get_port_mirroring(
        SW_SOCKET, hardware, sizeof(hardware)) > 0;
    if (config_ok && hardware_ok)
        state = mirror_readback_matches(&intent, hardware) ?
                "in-sync" : "out-of-sync";

    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "<span state=\"%s\" capacity=\"1\">\n", state);
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "  <desired present=\"%s\">\n",
                    intent.exists ? "true" : "false");
    if (intent.exists) {
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
            "    <session name=\"%s\" group=\"%d\" destination-interface=\"%s\" destination-port=\"%d\">\n",
            intent.name, NETLAB_MIRROR_V1_GROUP,
            intent.destination_ifname, intent.destination.hw_port);
        for (int i = 0; i < intent.n_sources; i++)
            off = append_show_text(buf, NETLAB_MAX_MSG, off,
                "      <source interface=\"%s\" port=\"%d\" direction=\"%s\"/>\n",
                intent.sources[i].ifname,
                intent.sources[i].port.hw_port,
                mirror_direction_name(intent.sources[i].direction));
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
                        "    </session>\n");
    }
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "  </desired>\n  <hardware available=\"%s\">\n%s",
                    hardware_ok ? "true" : "false",
                    hardware_ok ? hardware : "");
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "  </hardware>\n</span>\n");
    nl_yang_session_destroy(ys);
    int rc = send_show_response(conn, msg, buf, off);
    free(xml);
    free(buf);
    return rc;
}

int l2d_show_vlans(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    int off = 0;

    if (!buf)
        return send_show_response(conn, msg, NULL, -1);
    pthread_mutex_lock(&g_l2d.lock);
    off = append_show_text(
        buf, NETLAB_MAX_MSG, off,
        "<vlans complete=\"%s\" generation=\"%llu\" last-update=\"%ld\">\n",
        g_l2d.config_complete ? "true" : "false",
        (unsigned long long)g_l2d.cache_generation,
        (long)g_l2d.last_update);
    for (int i = 0; i < g_l2d.n_vlans; i++) {
        const char *state = (!g_l2d.config_complete ||
                             !g_l2d.switchd_up) ? "unknown" :
                            g_l2d.vlans[i].hw_exists ? "up" : "missing";
        char members[512] = {0};
        int moff = 0;

        for (int j = 0; j < g_l2d.n_ifs; j++) {
            for (int k = 0; k < g_l2d.ifs[j].n_members; k++) {
                int n;

                if (g_l2d.ifs[j].member_vids[k] != g_l2d.vlans[i].vid)
                    continue;
                n = snprintf(members + moff,
                             sizeof(members) - (size_t)moff,
                             "%s%s", moff > 0 ? "," : "",
                             g_l2d.ifs[j].name);
                if (n < 0 || (size_t)n >= sizeof(members) - (size_t)moff)
                    break;
                moff += n;
            }
        }
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
            "  <vlan><name>%s</name><vlan-id>%d</vlan-id>"
            "<state>%s</state><interfaces>%s</interfaces></vlan>\n",
            g_l2d.vlans[i].name, g_l2d.vlans[i].vid, state, members);
    }
    pthread_mutex_unlock(&g_l2d.lock);
    off = append_show_text(buf, NETLAB_MAX_MSG, off, "</vlans>\n");

    int rc = send_show_response(conn, msg, buf, off);
    free(buf);
    return rc;
}

int l2d_show_ethernet_switching(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    int off = 0;

    if (!buf)
        return send_show_response(conn, msg, NULL, -1);
    pthread_mutex_lock(&g_l2d.lock);
    off = append_show_text(
        buf, NETLAB_MAX_MSG, off,
        "<ethernet-switching-interfaces complete=\"%s\" "
        "generation=\"%llu\" last-update=\"%ld\">\n",
        g_l2d.config_complete ? "true" : "false",
        (unsigned long long)g_l2d.cache_generation,
        (long)g_l2d.last_update);
    for (int i = 0; i < g_l2d.n_ifs; i++) {
        l2_if_state *st = &g_l2d.ifs[i];
        const char *hwsync = "not-applicable";
        const char *state = "inactive";

        if (!g_l2d.config_complete || !g_l2d.switchd_up) {
            hwsync = "unknown";
            state = "unknown";
        } else if (st->n_members > 0) {
            hwsync = st->hw_member ? "in-sync" : "out-of-sync";
            state = (st->hw_member && !st->disabled) ? "up" : "down";
        }
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
            "  <interface><name>%s</name><mode>%s</mode>"
            "<state>%s</state><vlan-member>%s</vlan-member>"
            "<hw-sync>%s</hw-sync></interface>\n",
            st->name, st->mode, state,
            st->members[0] ? st->members : "-", hwsync);
    }
    pthread_mutex_unlock(&g_l2d.lock);
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "</ethernet-switching-interfaces>\n");

    int rc = send_show_response(conn, msg, buf, off);
    free(buf);
    return rc;
}

int l2d_show_mac_security(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    int off = 0;
    time_t now = time(NULL);
    l2_user_filter user_filters[L2D_MAX_USER_FILTERS];
    l2_user_filter_counter_snapshot counters[L2D_MAX_USER_FILTERS];
    l2_ingress_ipv4_acl ingress_ipv4_acl[L2D_MAX_INGRESS_IPV4_ACL];
    l2_acl_counter_snapshot ipv4_acl_counters[L2D_MAX_INGRESS_IPV4_ACL];
    l2_acl_counter_snapshot acl_policer_counters[L2D_MAX_ACL_POLICER];
    l2_acl_counter_snapshot egress_acl_counters[L2D_MAX_EGRESS_ACL];
    l2_acl_counter_snapshot acl_independent_counters[L2D_MAX_ACL_INDEPENDENT];
    l2_acl_policer acl_policer[L2D_MAX_ACL_POLICER];
    l2_egress_acl egress_acl[L2D_MAX_EGRESS_ACL];
    l2_acl_independent acl_independent[L2D_MAX_ACL_INDEPENDENT];
    int n_user_filters = 0;
    int n_ingress_ipv4_acl = 0;
    int n_acl_policer = 0;
    int n_egress_acl = 0;
    int n_acl_independent = 0;
    bool switchd_up = false;
    bool acl_counter_snapshot_complete = false;
    u64 acl_counter_generation = 0;
    long long acl_counter_age_ms = -1;

    if (!buf)
        return send_show_response(conn, msg, NULL, -1);
    memset(user_filters, 0, sizeof(user_filters));
    memset(counters, 0, sizeof(counters));
    memset(ingress_ipv4_acl, 0, sizeof(ingress_ipv4_acl));
    memset(ipv4_acl_counters, 0, sizeof(ipv4_acl_counters));
    memset(acl_policer_counters, 0, sizeof(acl_policer_counters));
    memset(egress_acl_counters, 0, sizeof(egress_acl_counters));
    memset(acl_independent_counters, 0, sizeof(acl_independent_counters));
    memset(acl_policer, 0, sizeof(acl_policer));
    memset(egress_acl, 0, sizeof(egress_acl));
    memset(acl_independent, 0, sizeof(acl_independent));
    pthread_mutex_lock(&g_l2d.lock);
    n_user_filters = g_l2d.n_user_filters;
    if (n_user_filters > L2D_MAX_USER_FILTERS)
        n_user_filters = L2D_MAX_USER_FILTERS;
    if (n_user_filters > 0)
        memcpy(user_filters, g_l2d.user_filters,
               sizeof(user_filters[0]) * (size_t)n_user_filters);
    n_ingress_ipv4_acl = g_l2d.n_ingress_ipv4_acl;
    if (n_ingress_ipv4_acl > L2D_MAX_INGRESS_IPV4_ACL)
        n_ingress_ipv4_acl = L2D_MAX_INGRESS_IPV4_ACL;
    if (n_ingress_ipv4_acl > 0)
        memcpy(ingress_ipv4_acl, g_l2d.ingress_ipv4_acl,
               sizeof(ingress_ipv4_acl[0]) *
               (size_t)n_ingress_ipv4_acl);
    n_acl_policer = g_l2d.n_acl_policer;
    if (n_acl_policer > L2D_MAX_ACL_POLICER)
        n_acl_policer = L2D_MAX_ACL_POLICER;
    if (n_acl_policer > 0)
        memcpy(acl_policer, g_l2d.acl_policer,
               sizeof(acl_policer[0]) * (size_t)n_acl_policer);
    n_egress_acl = g_l2d.n_egress_acl;
    if (n_egress_acl > L2D_MAX_EGRESS_ACL)
        n_egress_acl = L2D_MAX_EGRESS_ACL;
    if (n_egress_acl > 0)
        memcpy(egress_acl, g_l2d.egress_acl,
               sizeof(egress_acl[0]) * (size_t)n_egress_acl);
    n_acl_independent = g_l2d.n_acl_independent;
    if (n_acl_independent > L2D_MAX_ACL_INDEPENDENT)
        n_acl_independent = L2D_MAX_ACL_INDEPENDENT;
    if (n_acl_independent > 0)
        memcpy(acl_independent, g_l2d.acl_independent,
               sizeof(acl_independent[0]) * (size_t)n_acl_independent);
    switchd_up = g_l2d.switchd_up;
    pthread_mutex_unlock(&g_l2d.lock);

    if (switchd_up) {
        nl_acl_counter_query *query = calloc(1, sizeof(*query));
        nl_acl_counter_snapshot *snapshot = calloc(1, sizeof(*snapshot));
        bool query_ok = query != NULL && snapshot != NULL;
        u16 ingress_offset;
        u16 egress_offset;
        u16 policer_offset;
        u16 independent_offset;

        if (query_ok) {
            for (int i = 0; i < n_user_filters && query_ok; i++) {
                nl_acl_counter_query_entry *entry =
                    &query->entries[query->n_entries];
                int port = nl_ifid_name_to_logical_port(
                    user_filters[i].ifname);

                entry->id = query->n_entries;
                entry->kind = NL_ACL_COUNTER_KIND_USER_FILTER;
                entry->match.vid = (u16)user_filters[i].vid;
                entry->match.port = (u16)port;
                entry->mac_kind =
                    strcmp(user_filters[i].mac_kind, "destination") == 0 ?
                        NL_ACL_COUNTER_MAC_DESTINATION :
                        NL_ACL_COUNTER_MAC_SOURCE;
                query_ok = port > 0 && nl_platform_parse_mac(
                    user_filters[i].mac, entry->mac);
                if (query_ok)
                    query->n_entries++;
            }
        }
        ingress_offset = query ? query->n_entries : 0;
        if (query_ok) {
            for (int i = 0; i < n_ingress_ipv4_acl && query_ok; i++) {
                nl_acl_counter_query_entry *entry =
                    &query->entries[query->n_entries];
                int port = nl_ifid_name_to_logical_port(
                    ingress_ipv4_acl[i].ifname);

                entry->id = query->n_entries;
                entry->kind = NL_ACL_COUNTER_KIND_INGRESS_IPV4;
                query_ok = fill_ingress_counter_match(
                    &ingress_ipv4_acl[i], port, &entry->match);
                if (query_ok)
                    query->n_entries++;
            }
        }
        egress_offset = query ? query->n_entries : 0;
        if (query_ok) {
            for (int i = 0; i < n_egress_acl && query_ok; i++) {
                nl_acl_counter_query_entry *entry =
                    &query->entries[query->n_entries];
                int port = nl_ifid_name_to_logical_port(
                    egress_acl[i].ifname);

                entry->id = query->n_entries;
                entry->kind = NL_ACL_COUNTER_KIND_EGRESS;
                entry->match.port = (u16)port;
                query_ok = port > 0;
                if (query_ok)
                    query->n_entries++;
            }
        }
        policer_offset = query ? query->n_entries : 0;
        if (query_ok) {
            for (int i = 0; i < n_acl_policer && query_ok; i++) {
                nl_acl_counter_query_entry *entry =
                    &query->entries[query->n_entries];
                int port = nl_ifid_name_to_logical_port(
                    acl_policer[i].ifname);

                entry->id = query->n_entries;
                entry->kind = NL_ACL_COUNTER_KIND_POLICER;
                entry->match.port = (u16)port;
                entry->rate_kbps = acl_policer[i].rate_kbps;
                entry->burst_bytes = acl_policer[i].burst_bytes;
                query_ok = port > 0 && mac_text_to_u64(
                    acl_policer[i].dst_mac, &entry->dst_mac);
                if (query_ok)
                    query->n_entries++;
            }
        }
        independent_offset = query ? query->n_entries : 0;
        if (query_ok) {
            for (int i = 0; i < n_acl_independent && query_ok; i++) {
                nl_acl_counter_query_entry *entry =
                    &query->entries[query->n_entries];
                int port = nl_ifid_name_to_logical_port(
                    acl_independent[i].ifname);

                entry->id = query->n_entries;
                entry->kind = NL_ACL_COUNTER_KIND_INDEPENDENT;
                query_ok = fill_independent_counter_query(
                    &acl_independent[i], port, entry);
                if (query_ok)
                    query->n_entries++;
            }
        }

        if (query_ok && query->n_entries ==
                (u16)(n_user_filters + n_ingress_ipv4_acl +
                      n_egress_acl + n_acl_policer + n_acl_independent) &&
            l2d_switchd_get_acl_counter_snapshot(
                SW_SOCKET, query, snapshot) == 0) {
            struct timespec sampled_now;

            acl_counter_snapshot_complete = true;
            acl_counter_generation = snapshot->generation;
            if (clock_gettime(CLOCK_MONOTONIC, &sampled_now) == 0) {
                u64 now_ms = (u64)sampled_now.tv_sec * 1000ULL +
                             (u64)sampled_now.tv_nsec / 1000000ULL;
                if (now_ms >= snapshot->sampled_monotonic_ms)
                    acl_counter_age_ms = (long long)(
                        now_ms - snapshot->sampled_monotonic_ms);
            }
            for (int i = 0; i < n_user_filters; i++)
                publish_acl_counter(
                    &counters[i], &snapshot->entries[i]);
            for (int i = 0; i < n_ingress_ipv4_acl; i++)
                publish_acl_counter(
                    &ipv4_acl_counters[i],
                    &snapshot->entries[ingress_offset + (u16)i]);
            for (int i = 0; i < n_egress_acl; i++)
                publish_acl_counter(
                    &egress_acl_counters[i],
                    &snapshot->entries[egress_offset + (u16)i]);
            for (int i = 0; i < n_acl_policer; i++)
                publish_acl_counter(
                    &acl_policer_counters[i],
                    &snapshot->entries[policer_offset + (u16)i]);
            for (int i = 0; i < n_acl_independent; i++)
                publish_acl_counter(
                    &acl_independent_counters[i],
                    &snapshot->entries[independent_offset + (u16)i]);
        }
        free(snapshot);
        free(query);
    }

    pthread_mutex_lock(&g_l2d.lock);
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "<mac-security switchd=\"%s\" "
                    "config-complete=\"%s\" mac-snapshot-complete=\"%s\" "
                    "stp-snapshot-complete=\"%s\" "
                    "acl-counter-snapshot-complete=\"%s\" "
                    "acl-counter-generation=\"%llu\" "
                    "acl-counter-age-ms=\"%lld\" generation=\"%llu\" "
                    "last-update=\"%ld\" mac-snapshot-update=\"%ld\" "
                    "total-moves=\"%lu\" total-move-dampens=\"%lu\">\n",
                    g_l2d.switchd_up ? "up" : "down",
                    g_l2d.config_complete ? "true" : "false",
                    g_l2d.mac_snapshot_complete ? "true" : "false",
                    g_l2d.stp_snapshot_complete ? "true" : "false",
                    acl_counter_snapshot_complete ? "true" : "false",
                    (unsigned long long)acl_counter_generation,
                    acl_counter_age_ms,
                    (unsigned long long)g_l2d.cache_generation,
                    (long)g_l2d.last_update,
                    (long)g_l2d.mac_snapshot_last_update,
                    g_l2d.total_moves,
                    g_l2d.total_move_dampens);
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "  <mac-move-policy configured=\"%s\" "
                    "threshold=\"%d\" window=\"%d\" action=\"%s\"/>\n",
                    g_l2d.move_dampening_configured ? "true" : "false",
                    g_l2d.move_dampening_threshold,
                    g_l2d.move_dampening_window,
                    g_l2d.move_dampening_action[0] ?
                    g_l2d.move_dampening_action : "alarm");
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "  <dhcp-snooping>\n");
    for (int i = 0; i < g_l2d.n_dhcp_snooping_vlans; i++)
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
                        "    <vlan name=\"%s\"/>\n",
                        g_l2d.dhcp_snooping_vlans[i]);
    for (int i = 0; i < g_l2d.n_ifs; i++)
        if (g_l2d.ifs[i].dhcp_snooping_trusted)
            off = append_show_text(buf, NETLAB_MAX_MSG, off,
                            "    <interface name=\"%s\" trusted=\"true\"/>\n",
                            g_l2d.ifs[i].name);
    for (int i = 0; i < g_l2d.n_dhcp_bindings; i++)
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
                        "    <binding mac=\"%s\" vlan=\"%s\" vid=\"%d\" "
                        "interface=\"%s\" ip=\"%s\" source=\"static\" "
                        "active-dai=\"%s\"/>\n",
                        g_l2d.dhcp_bindings[i].mac,
                        g_l2d.dhcp_bindings[i].vlan,
                        g_l2d.dhcp_bindings[i].vid,
                        g_l2d.dhcp_bindings[i].ifname,
                        g_l2d.dhcp_bindings[i].ip,
                        g_l2d.dhcp_bindings[i].active_dai ?
                        "true" : "false");
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "  </dhcp-snooping>\n"
                    "  <arp-inspection>\n");
    for (int i = 0; i < g_l2d.n_arp_inspection_vlans; i++)
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
                        "    <vlan name=\"%s\"/>\n",
                        g_l2d.arp_inspection_vlans[i]);
    for (int i = 0; i < g_l2d.n_ifs; i++)
        if (g_l2d.ifs[i].arp_inspection_trusted)
            off = append_show_text(buf, NETLAB_MAX_MSG, off,
                            "    <interface name=\"%s\" trusted=\"true\"/>\n",
                            g_l2d.ifs[i].name);
    for (int i = 0; i < g_l2d.n_dhcp_bindings; i++)
        if (g_l2d.dhcp_bindings[i].active_dai)
            off = append_show_text(buf, NETLAB_MAX_MSG, off,
                            "    <binding mac=\"%s\" vlan=\"%s\" vid=\"%d\" "
                            "interface=\"%s\" ip=\"%s\" source=\"static\"/>\n",
                            g_l2d.dhcp_bindings[i].mac,
                            g_l2d.dhcp_bindings[i].vlan,
                            g_l2d.dhcp_bindings[i].vid,
                            g_l2d.dhcp_bindings[i].ifname,
                            g_l2d.dhcp_bindings[i].ip);
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "  </arp-inspection>\n");
    off = emit_user_filter_container(buf, NETLAB_MAX_MSG, off, "user-filter",
                                     "user-filter", user_filters, counters,
                                     n_user_filters);
    off = emit_user_filter_container(buf, NETLAB_MAX_MSG, off, "ingress-acl",
                                     "ingress-acl", user_filters, counters,
                                     n_user_filters);
    off = emit_ingress_ipv4_acl_container(
        buf, NETLAB_MAX_MSG, off, ingress_ipv4_acl, ipv4_acl_counters,
        n_ingress_ipv4_acl);
    off = emit_acl_policer_container(buf, NETLAB_MAX_MSG, off,
                                     acl_policer, acl_policer_counters,
                                     n_acl_policer);
    off = emit_egress_acl_container(buf, NETLAB_MAX_MSG, off,
                                    egress_acl, egress_acl_counters,
                                    n_egress_acl);
    off = emit_acl_independent_container(
        buf, NETLAB_MAX_MSG, off, acl_independent, acl_independent_counters,
        n_acl_independent);
    for (int i = 0; i < g_l2d.n_ifs; i++) {
        l2_if_state *st = &g_l2d.ifs[i];
        const char *status = "ok";
        char limit_text[16];
        long shutdown_age = st->mac_shutdown_time > 0 ?
                            (long)(now - st->mac_shutdown_time) : -1;
        long drop_age = st->mac_drop_time > 0 ?
                        (long)(now - st->mac_drop_time) : -1;

        if (st->mac_limit_configured &&
            st->mac_limit > 0 &&
            st->dynamic_macs > st->mac_limit)
            status = "limit-exceeded";
        if (st->mac_drop_active)
            status = strcmp(st->mac_action, "restrict") == 0 ?
                     "restricted" : "dropping";
        if (st->mac_shutdown)
            status = "shutdown";
        if (st->mac_limit_configured)
            snprintf(limit_text, sizeof(limit_text), "%d", st->mac_limit);
        else
            snprintf(limit_text, sizeof(limit_text), "-");
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
            "  <interface name=\"%s\" dynamic=\"%d\" limit=\"%s\" "
            "configured=\"%s\" action=\"%s\" status=\"%s\" "
            "enforced=\"%s\" last-shutdown-age=\"%ld\" "
            "last-drop-age=\"%ld\" reason=\"%s\"/>\n",
            st->name, st->dynamic_macs, limit_text,
            st->mac_limit_configured ? "true" : "false",
            st->mac_action[0] ? st->mac_action : "alarm",
            status, (st->mac_shutdown || st->mac_drop_active) ?
            "true" : "false",
            shutdown_age, drop_age, st->mac_shutdown_reason);
    }
    for (int i = 0; i < g_l2d.n_moves; i++) {
        long age = g_l2d.moves[i].last_seen > 0 ?
                   (long)(now - g_l2d.moves[i].last_seen) : -1;
        long dampened_age = g_l2d.moves[i].dampened_time > 0 ?
                   (long)(now - g_l2d.moves[i].dampened_time) : -1;
        off = append_show_text(buf, NETLAB_MAX_MSG, off,
            "  <move vlan=\"%d\" mac=\"%s\" from=\"%s\" to=\"%s\" "
            "count=\"%lu\" window-count=\"%lu\" last-age=\"%ld\" "
            "dampened=\"%s\" dampened-age=\"%ld\" dampened-if=\"%s\"/>\n",
            g_l2d.moves[i].vlan, g_l2d.moves[i].mac,
            g_l2d.moves[i].from_if, g_l2d.moves[i].to_if,
            g_l2d.moves[i].count, g_l2d.moves[i].window_count, age,
            g_l2d.moves[i].dampened ? "true" : "false",
            dampened_age, g_l2d.moves[i].dampened_if);
    }
    off = append_show_text(buf, NETLAB_MAX_MSG, off,
                    "</mac-security>\n");
    pthread_mutex_unlock(&g_l2d.lock);

    int rc = send_show_response(conn, msg, buf, off);
    free(buf);
    return rc;
}
