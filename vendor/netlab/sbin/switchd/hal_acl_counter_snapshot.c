#include "netlab/hal.h"
#include "netlab/interface_id.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Called only by switchd's single SDK executor thread. */
static u64 counter_snapshot_generation;

static void convert_ipv4_match(const nl_acl_counter_ipv4_match *src,
                               hal_ingress_ipv4_acl_match *dst) {
    u32 f = src->flags;

    memset(dst, 0, sizeof(*dst));
    dst->vid = src->vid;
    dst->port = src->port;
    dst->has_src_ip = (f & NL_ACL_COUNTER_MATCH_SRC_IP) != 0;
    dst->has_dst_ip = (f & NL_ACL_COUNTER_MATCH_DST_IP) != 0;
    dst->has_src_ip_mask = (f & NL_ACL_COUNTER_MATCH_SRC_IP_MASK) != 0;
    dst->has_dst_ip_mask = (f & NL_ACL_COUNTER_MATCH_DST_IP_MASK) != 0;
    dst->has_dscp = (f & NL_ACL_COUNTER_MATCH_DSCP) != 0;
    dst->has_ecn = (f & NL_ACL_COUNTER_MATCH_ECN) != 0;
    dst->has_protocol = (f & NL_ACL_COUNTER_MATCH_PROTOCOL) != 0;
    dst->has_src_port = (f & NL_ACL_COUNTER_MATCH_SRC_PORT) != 0;
    dst->has_dst_port = (f & NL_ACL_COUNTER_MATCH_DST_PORT) != 0;
    dst->has_src_port_range =
        (f & NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE) != 0;
    dst->has_dst_port_range =
        (f & NL_ACL_COUNTER_MATCH_DST_PORT_RANGE) != 0;
    dst->has_tcp_flags = (f & NL_ACL_COUNTER_MATCH_TCP_FLAGS) != 0;
    dst->has_tcp_flags_mask =
        (f & NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK) != 0;
    dst->count_only = (f & NL_ACL_COUNTER_MATCH_COUNT_ONLY) != 0;
    dst->src_ip = src->src_ip;
    dst->dst_ip = src->dst_ip;
    dst->src_ip_mask = src->src_ip_mask;
    dst->dst_ip_mask = src->dst_ip_mask;
    dst->dscp = src->dscp;
    dst->ecn = src->ecn;
    dst->protocol = src->protocol;
    dst->src_port = src->src_port;
    dst->dst_port = src->dst_port;
    dst->src_port_start = src->src_port_start;
    dst->src_port_end = src->src_port_end;
    dst->dst_port_start = src->dst_port_start;
    dst->dst_port_end = src->dst_port_end;
    dst->tcp_flags = src->tcp_flags;
    dst->tcp_flags_mask = src->tcp_flags_mask;
}

static const char *family_name(u8 family) {
    if (family == NL_ACL_COUNTER_FAMILY_ETHERNET)
        return "ethernet";
    if (family == NL_ACL_COUNTER_FAMILY_INET)
        return "inet";
    if (family == NL_ACL_COUNTER_FAMILY_POLICER)
        return "policer";
    return "";
}

static const char *action_name(u8 action) {
    if (action == NL_ACL_COUNTER_ACTION_DROP)
        return "drop";
    if (action == NL_ACL_COUNTER_ACTION_COUNT)
        return "count";
    if (action == NL_ACL_COUNTER_ACTION_POLICER)
        return "policer";
    return "";
}

static void convert_independent(const nl_acl_counter_query_entry *src,
                                hal_acl_independent_args *dst) {
    memset(dst, 0, sizeof(*dst));
    snprintf(dst->group, sizeof(dst->group), "snapshot");
    snprintf(dst->term, sizeof(dst->term), "entry-%u", src->id);
    snprintf(dst->family, sizeof(dst->family), "%s",
             family_name(src->family));
    snprintf(dst->action, sizeof(dst->action), "%s",
             action_name(src->action));
    dst->slot = src->slot;
    dst->vid = src->match.vid;
    dst->port = src->match.port;
    dst->has_src_mac =
        (src->match.flags & NL_ACL_COUNTER_MATCH_SRC_MAC) != 0;
    dst->has_dst_mac =
        (src->match.flags & NL_ACL_COUNTER_MATCH_DST_MAC) != 0;
    dst->src_mac = src->src_mac;
    dst->dst_mac = src->dst_mac;
    dst->rate_kbps = src->rate_kbps;
    dst->burst_bytes = src->burst_bytes;
    convert_ipv4_match(&src->match, &dst->inet_match);
}

static int validate_ports(const nl_acl_counter_query *query) {
    for (u16 i = 0; i < query->n_entries; i++)
        if (!nl_ifid_is_user_port(query->entries[i].match.port))
            return -1;
    return 0;
}

int hal_acl_counter_snapshot_get(int sw,
                                 const nl_acl_counter_query *query,
                                 nl_acl_counter_snapshot *snapshot) {
    struct timespec sampled;

    if (!snapshot || nl_acl_counter_query_validate(query) != 0 ||
        validate_ports(query) != 0)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->n_entries = query->n_entries;
    for (u16 i = 0; i < query->n_entries; i++) {
        snapshot->entries[i].id = query->entries[i].id;
        snapshot->entries[i].kind = query->entries[i].kind;
        snapshot->entries[i].state = NL_ACL_COUNTER_STATE_ABSENT;
    }

    /* The shared flow table is traversed once for every user-filter query. */
    if (hal_l2_security_user_filter_counter_snapshot(
            sw, query, snapshot) != 0)
        return -1;
    if (hal_ingress_ipv4_acl_counter_snapshot(
            sw, query, snapshot) != 0)
        return -1;
    if (hal_acl_policer_counter_snapshot(sw, query, snapshot) != 0)
        return -1;

    for (u16 i = 0; i < query->n_entries; i++) {
        const nl_acl_counter_query_entry *entry = &query->entries[i];
        nl_acl_counter_snapshot_entry *out = &snapshot->entries[i];

        if (entry->kind == NL_ACL_COUNTER_KIND_USER_FILTER)
            continue;
        if (entry->kind == NL_ACL_COUNTER_KIND_INGRESS_IPV4) {
            continue;
        }
        if (entry->kind == NL_ACL_COUNTER_KIND_EGRESS) {
            int rc = hal_acl_egress_counters(
                sw, entry->match.port, &out->packets, &out->octets);
            out->sdk_status = rc;
            if (rc != 0)
                return rc;
            out->state = NL_ACL_COUNTER_STATE_INSTALLED;
            continue;
        }
        if (entry->kind == NL_ACL_COUNTER_KIND_POLICER) {
            continue;
        }
        if (entry->kind == NL_ACL_COUNTER_KIND_INDEPENDENT) {
            hal_acl_independent_args args;
            hal_acl_independent_result owner;
            int rc;

            convert_independent(entry, &args);
            rc = hal_acl_independent_readback_match(sw, &args, &owner);
            out->sdk_status = owner.read_status;
            out->packets = owner.packets;
            out->octets = owner.octets;
            if (rc == 0 && owner.ok) {
                out->state = owner.active ?
                    NL_ACL_COUNTER_STATE_INSTALLED :
                    NL_ACL_COUNTER_STATE_ABSENT;
            } else if (owner.active && owner.mismatches > 0) {
                out->state = NL_ACL_COUNTER_STATE_MISMATCH;
            } else {
                return rc != 0 ? rc : -1;
            }
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &sampled) != 0)
        return -1;
    snapshot->sampled_monotonic_ms =
        (u64)sampled.tv_sec * 1000ULL + (u64)sampled.tv_nsec / 1000000ULL;
    counter_snapshot_generation++;
    if (counter_snapshot_generation == 0)
        counter_snapshot_generation++;
    snapshot->generation = counter_snapshot_generation;
    snapshot->complete = true;
    return 0;
}
