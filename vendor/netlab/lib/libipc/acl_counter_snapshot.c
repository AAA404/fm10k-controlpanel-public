#include "netlab/acl_counter_snapshot.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#define QUERY_HEADER_SIZE 16U
#define QUERY_ENTRY_SIZE 128U
#define SNAPSHOT_HEADER_SIZE 32U
#define SNAPSHOT_ENTRY_SIZE 24U
#define SNAPSHOT_COMPLETE (1U << 0)

_Static_assert(QUERY_HEADER_SIZE +
               QUERY_ENTRY_SIZE * NL_ACL_COUNTER_MAX_ENTRIES ==
               NL_ACL_COUNTER_QUERY_WIRE_MAX,
               "ACL counter query wire bound changed");
_Static_assert(SNAPSHOT_HEADER_SIZE +
               SNAPSHOT_ENTRY_SIZE * NL_ACL_COUNTER_MAX_ENTRIES ==
               NL_ACL_COUNTER_SNAPSHOT_WIRE_MAX,
               "ACL counter snapshot wire bound changed");

static u64 hton64(u64 value) {
    u32 high = htonl((u32)(value >> 32));
    u32 low = htonl((u32)value);
    return ((u64)low << 32) | high;
}

static u64 ntoh64(u64 value) {
    u32 high = ntohl((u32)value);
    u32 low = ntohl((u32)(value >> 32));
    return ((u64)high << 32) | low;
}

static void put16(u8 *p, u16 value) {
    value = htons(value);
    memcpy(p, &value, sizeof(value));
}

static void put32(u8 *p, u32 value) {
    value = htonl(value);
    memcpy(p, &value, sizeof(value));
}

static void put64(u8 *p, u64 value) {
    value = hton64(value);
    memcpy(p, &value, sizeof(value));
}

static u16 get16(const u8 *p) {
    u16 value;
    memcpy(&value, p, sizeof(value));
    return ntohs(value);
}

static u32 get32(const u8 *p) {
    u32 value;
    memcpy(&value, p, sizeof(value));
    return ntohl(value);
}

static u64 get64(const u8 *p) {
    u64 value;
    memcpy(&value, p, sizeof(value));
    return ntoh64(value);
}

size_t nl_acl_counter_query_wire_size(u16 n_entries) {
    if (n_entries > NL_ACL_COUNTER_MAX_ENTRIES)
        return 0;
    return QUERY_HEADER_SIZE + QUERY_ENTRY_SIZE * (size_t)n_entries;
}

size_t nl_acl_counter_snapshot_wire_size(u16 n_entries) {
    if (n_entries > NL_ACL_COUNTER_MAX_ENTRIES)
        return 0;
    return SNAPSHOT_HEADER_SIZE + SNAPSHOT_ENTRY_SIZE * (size_t)n_entries;
}

static bool ipv4_match_valid(const nl_acl_counter_ipv4_match *m,
                             bool independent) {
    u32 f;

    if (!m || m->vid < 1 || m->vid > 4094 || m->port == 0)
        return false;
    f = m->flags;
    if (f & ~NL_ACL_COUNTER_MATCH_ALL)
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_SRC_IP) != 0 &&
        (f & NL_ACL_COUNTER_MATCH_SRC_IP_MASK) == 0)
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_DST_IP) != 0 &&
        (f & NL_ACL_COUNTER_MATCH_DST_IP_MASK) == 0)
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_SRC_IP_MASK) != 0 &&
        (f & NL_ACL_COUNTER_MATCH_SRC_IP) == 0)
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_DST_IP_MASK) != 0 &&
        (f & NL_ACL_COUNTER_MATCH_DST_IP) == 0)
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_DSCP) && (m->dscp < 0 || m->dscp > 63))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_ECN) && (m->ecn < 0 || m->ecn > 3))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_PROTOCOL) &&
        (m->protocol < 0 || m->protocol > 255))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_SRC_PORT) &&
        (m->src_port < 0 || m->src_port > 65535))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_DST_PORT) &&
        (m->dst_port < 0 || m->dst_port > 65535))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE) &&
        (m->src_port_start < 0 || m->src_port_start > m->src_port_end ||
         m->src_port_end > 65535))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_DST_PORT_RANGE) &&
        (m->dst_port_start < 0 || m->dst_port_start > m->dst_port_end ||
         m->dst_port_end > 65535))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_SRC_PORT) &&
        (f & NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_DST_PORT) &&
        (f & NL_ACL_COUNTER_MATCH_DST_PORT_RANGE))
        return false;
    if ((f & (NL_ACL_COUNTER_MATCH_SRC_PORT |
              NL_ACL_COUNTER_MATCH_DST_PORT |
              NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE |
              NL_ACL_COUNTER_MATCH_DST_PORT_RANGE)) &&
        (!(f & NL_ACL_COUNTER_MATCH_PROTOCOL) ||
         (m->protocol != 6 && m->protocol != 17)))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_TCP_FLAGS) &&
        (m->tcp_flags < 0 || m->tcp_flags > 63 ||
         !(f & NL_ACL_COUNTER_MATCH_PROTOCOL) || m->protocol != 6))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK) &&
        (!(f & NL_ACL_COUNTER_MATCH_TCP_FLAGS) ||
         m->tcp_flags_mask < 1 || m->tcp_flags_mask > 63 ||
         (m->tcp_flags & ~m->tcp_flags_mask) != 0))
        return false;
    if ((f & NL_ACL_COUNTER_MATCH_TCP_FLAGS) &&
        !(f & NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK))
        return false;
    if (!independent &&
        (f & (NL_ACL_COUNTER_MATCH_SRC_MAC |
              NL_ACL_COUNTER_MATCH_DST_MAC)))
        return false;
    if (!(f & NL_ACL_COUNTER_MATCH_SRC_IP) && m->src_ip != 0)
        return false;
    if (!(f & NL_ACL_COUNTER_MATCH_DST_IP) && m->dst_ip != 0)
        return false;
    if (!(f & NL_ACL_COUNTER_MATCH_SRC_IP_MASK) && m->src_ip_mask != 0)
        return false;
    if (!(f & NL_ACL_COUNTER_MATCH_DST_IP_MASK) && m->dst_ip_mask != 0)
        return false;
#define UNUSED_VALUE_MUST_BE_ZERO(flag_name, member) do { \
        if (!(f & flag_name) && m->member != 0) \
            return false; \
    } while (0)
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_DSCP, dscp);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_ECN, ecn);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_PROTOCOL, protocol);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_SRC_PORT, src_port);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_DST_PORT, dst_port);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE,
                              src_port_start);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE,
                              src_port_end);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_DST_PORT_RANGE,
                              dst_port_start);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_DST_PORT_RANGE,
                              dst_port_end);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_TCP_FLAGS, tcp_flags);
    UNUSED_VALUE_MUST_BE_ZERO(NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK,
                              tcp_flags_mask);
#undef UNUSED_VALUE_MUST_BE_ZERO
    return true;
}

static bool bytes_zero(const u8 *value, size_t length) {
    if (!value)
        return false;
    for (size_t i = 0; i < length; i++)
        if (value[i] != 0)
            return false;
    return true;
}

static bool match_payload_empty(const nl_acl_counter_ipv4_match *m) {
    return m && m->flags == 0 && m->src_ip == 0 && m->dst_ip == 0 &&
           m->src_ip_mask == 0 && m->dst_ip_mask == 0 && m->dscp == 0 &&
           m->ecn == 0 && m->protocol == 0 && m->src_port == 0 &&
           m->dst_port == 0 && m->src_port_start == 0 &&
           m->src_port_end == 0 && m->dst_port_start == 0 &&
           m->dst_port_end == 0 && m->tcp_flags == 0 &&
           m->tcp_flags_mask == 0;
}

static bool query_entry_valid(const nl_acl_counter_query_entry *e) {
    u32 f;

    if (!e || e->id >= NL_ACL_COUNTER_MAX_ENTRIES)
        return false;
    f = e->match.flags;
    switch (e->kind) {
        case NL_ACL_COUNTER_KIND_USER_FILTER:
            return e->match.vid >= 1 && e->match.vid <= 4094 &&
                   e->match.port > 0 &&
                   (e->mac_kind == NL_ACL_COUNTER_MAC_SOURCE ||
                    e->mac_kind == NL_ACL_COUNTER_MAC_DESTINATION) &&
                   e->family == 0 && e->action == 0 &&
                   e->slot == 0 && e->rate_kbps == 0 &&
                   e->burst_bytes == 0 && e->src_mac == 0 &&
                   e->dst_mac == 0 &&
                   match_payload_empty(&e->match);
        case NL_ACL_COUNTER_KIND_INGRESS_IPV4:
            return e->mac_kind == 0 && e->family == 0 && e->action == 0 &&
                   e->slot == 0 && e->rate_kbps == 0 &&
                   e->burst_bytes == 0 && e->src_mac == 0 &&
                   e->dst_mac == 0 && bytes_zero(e->mac, sizeof(e->mac)) &&
                   (f & ~(NL_ACL_COUNTER_MATCH_ALL &
                          ~(NL_ACL_COUNTER_MATCH_SRC_MAC |
                            NL_ACL_COUNTER_MATCH_DST_MAC))) == 0 &&
                   (f & ~(NL_ACL_COUNTER_MATCH_COUNT_ONLY)) != 0 &&
                   ipv4_match_valid(&e->match, false);
        case NL_ACL_COUNTER_KIND_EGRESS:
            return e->match.port > 0 && e->match.vid == 0 && f == 0 &&
                   e->mac_kind == 0 && e->family == 0 && e->action == 0 &&
                   e->slot == 0 && e->rate_kbps == 0 &&
                   e->burst_bytes == 0 && e->src_mac == 0 &&
                   e->dst_mac == 0 && bytes_zero(e->mac, sizeof(e->mac)) &&
                   match_payload_empty(&e->match);
        case NL_ACL_COUNTER_KIND_POLICER:
            return e->match.port > 0 && e->match.vid == 0 && f == 0 &&
                   e->rate_kbps > 0 && e->burst_bytes > 0 &&
                   e->mac_kind == 0 && e->family == 0 && e->action == 0 &&
                   e->slot == 0 && e->src_mac == 0 && e->dst_mac != 0 &&
                   bytes_zero(e->mac, sizeof(e->mac)) &&
                   match_payload_empty(&e->match) &&
                   (e->dst_mac & (1ULL << 40)) == 0;
        case NL_ACL_COUNTER_KIND_INDEPENDENT: {
            bool has_mac = (f & (NL_ACL_COUNTER_MATCH_SRC_MAC |
                                 NL_ACL_COUNTER_MATCH_DST_MAC)) != 0;
            bool has_inet = (f & ~(NL_ACL_COUNTER_MATCH_SRC_MAC |
                                   NL_ACL_COUNTER_MATCH_DST_MAC |
                                   NL_ACL_COUNTER_MATCH_COUNT_ONLY)) != 0;
            bool wants_policer =
                e->family == NL_ACL_COUNTER_FAMILY_POLICER ||
                e->action == NL_ACL_COUNTER_ACTION_POLICER;

            if (e->slot < 0 || e->slot >= 32 || e->mac_kind != 0 ||
                e->family < NL_ACL_COUNTER_FAMILY_ETHERNET ||
                e->family > NL_ACL_COUNTER_FAMILY_POLICER ||
                e->action < NL_ACL_COUNTER_ACTION_DROP ||
                e->action > NL_ACL_COUNTER_ACTION_POLICER ||
                !bytes_zero(e->mac, sizeof(e->mac)) ||
                !ipv4_match_valid(&e->match, true))
                return false;
            if (!(f & NL_ACL_COUNTER_MATCH_SRC_MAC) && e->src_mac != 0)
                return false;
            if (!(f & NL_ACL_COUNTER_MATCH_DST_MAC) && e->dst_mac != 0)
                return false;
            if (f & NL_ACL_COUNTER_MATCH_ECN)
                return false;
            if ((f & NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE) &&
                e->match.src_port_start != e->match.src_port_end)
                return false;
            if ((f & NL_ACL_COUNTER_MATCH_DST_PORT_RANGE) &&
                e->match.dst_port_start != e->match.dst_port_end)
                return false;
            if (((f & NL_ACL_COUNTER_MATCH_COUNT_ONLY) != 0) !=
                (e->action == NL_ACL_COUNTER_ACTION_COUNT))
                return false;
            if (e->family == NL_ACL_COUNTER_FAMILY_ETHERNET &&
                (!has_mac || has_inet))
                return false;
            if (e->family == NL_ACL_COUNTER_FAMILY_INET &&
                (has_mac || !has_inet))
                return false;
            if (e->family == NL_ACL_COUNTER_FAMILY_POLICER &&
                has_mac == has_inet)
                return false;
            if (wants_policer &&
                (e->rate_kbps <= 0 || e->burst_bytes <= 0))
                return false;
            if (!wants_policer &&
                (e->rate_kbps != 0 || e->burst_bytes != 0))
                return false;
            return true;
        }
        default:
            return false;
    }
}

int nl_acl_counter_query_validate(const nl_acl_counter_query *query) {
    u16 kind_count[6] = {0};

    if (!query || query->n_entries > NL_ACL_COUNTER_MAX_ENTRIES)
        return -1;
    for (u16 i = 0; i < query->n_entries; i++) {
        const nl_acl_counter_query_entry *e = &query->entries[i];
        if (!query_entry_valid(e) || e->id != i)
            return -1;
        kind_count[e->kind]++;
    }
    if (kind_count[NL_ACL_COUNTER_KIND_USER_FILTER] >
            NL_ACL_COUNTER_MAX_USER_FILTERS ||
        kind_count[NL_ACL_COUNTER_KIND_INGRESS_IPV4] >
            NL_ACL_COUNTER_MAX_INGRESS_IPV4 ||
        kind_count[NL_ACL_COUNTER_KIND_EGRESS] >
            NL_ACL_COUNTER_MAX_EGRESS ||
        kind_count[NL_ACL_COUNTER_KIND_POLICER] >
            NL_ACL_COUNTER_MAX_POLICERS ||
        kind_count[NL_ACL_COUNTER_KIND_INDEPENDENT] >
            NL_ACL_COUNTER_MAX_INDEPENDENT)
        return -1;
    return 0;
}

static void encode_query_entry(const nl_acl_counter_query_entry *e, u8 *p) {
    memset(p, 0, QUERY_ENTRY_SIZE);
    put16(p, e->id);
    p[2] = e->kind;
    p[3] = e->mac_kind;
    p[4] = e->family;
    p[5] = e->action;
    put32(p + 8, e->match.flags);
    put16(p + 12, e->match.vid);
    put16(p + 14, e->match.port);
    put32(p + 16, (u32)e->slot);
    put32(p + 20, (u32)e->rate_kbps);
    put32(p + 24, (u32)e->burst_bytes);
    memcpy(p + 28, e->mac, sizeof(e->mac));
    put64(p + 36, e->src_mac);
    put64(p + 44, e->dst_mac);
    put32(p + 52, e->match.src_ip);
    put32(p + 56, e->match.dst_ip);
    put32(p + 60, e->match.src_ip_mask);
    put32(p + 64, e->match.dst_ip_mask);
    put32(p + 68, (u32)e->match.dscp);
    put32(p + 72, (u32)e->match.ecn);
    put32(p + 76, (u32)e->match.protocol);
    put32(p + 80, (u32)e->match.src_port);
    put32(p + 84, (u32)e->match.dst_port);
    put32(p + 88, (u32)e->match.src_port_start);
    put32(p + 92, (u32)e->match.src_port_end);
    put32(p + 96, (u32)e->match.dst_port_start);
    put32(p + 100, (u32)e->match.dst_port_end);
    put32(p + 104, (u32)e->match.tcp_flags);
    put32(p + 108, (u32)e->match.tcp_flags_mask);
}

static int decode_query_entry(const u8 *p, nl_acl_counter_query_entry *e) {
    memset(e, 0, sizeof(*e));
    for (size_t i = 112; i < QUERY_ENTRY_SIZE; i++)
        if (p[i] != 0)
            return -1;
    if (p[6] != 0 || p[7] != 0 || p[34] != 0 || p[35] != 0)
        return -1;
    e->id = get16(p);
    e->kind = p[2];
    e->mac_kind = p[3];
    e->family = p[4];
    e->action = p[5];
    e->match.flags = get32(p + 8);
    e->match.vid = get16(p + 12);
    e->match.port = get16(p + 14);
    e->slot = (int)(int32_t)get32(p + 16);
    e->rate_kbps = (int)(int32_t)get32(p + 20);
    e->burst_bytes = (int)(int32_t)get32(p + 24);
    memcpy(e->mac, p + 28, sizeof(e->mac));
    e->src_mac = get64(p + 36);
    e->dst_mac = get64(p + 44);
    e->match.src_ip = get32(p + 52);
    e->match.dst_ip = get32(p + 56);
    e->match.src_ip_mask = get32(p + 60);
    e->match.dst_ip_mask = get32(p + 64);
    e->match.dscp = (int)(int32_t)get32(p + 68);
    e->match.ecn = (int)(int32_t)get32(p + 72);
    e->match.protocol = (int)(int32_t)get32(p + 76);
    e->match.src_port = (int)(int32_t)get32(p + 80);
    e->match.dst_port = (int)(int32_t)get32(p + 84);
    e->match.src_port_start = (int)(int32_t)get32(p + 88);
    e->match.src_port_end = (int)(int32_t)get32(p + 92);
    e->match.dst_port_start = (int)(int32_t)get32(p + 96);
    e->match.dst_port_end = (int)(int32_t)get32(p + 100);
    e->match.tcp_flags = (int)(int32_t)get32(p + 104);
    e->match.tcp_flags_mask = (int)(int32_t)get32(p + 108);
    return query_entry_valid(e) ? 0 : -1;
}

int nl_acl_counter_query_encode(const nl_acl_counter_query *query,
                                void *buffer, size_t capacity) {
    u8 *p = buffer;
    size_t length;

    if (!buffer || nl_acl_counter_query_validate(query) != 0)
        return -1;
    length = nl_acl_counter_query_wire_size(query->n_entries);
    if (length == 0 || length > capacity || length > INT_MAX)
        return -1;
    memset(p, 0, length);
    put32(p, NL_ACL_COUNTER_QUERY_MAGIC);
    put16(p + 4, NL_ACL_COUNTER_SNAPSHOT_VERSION);
    put16(p + 6, QUERY_HEADER_SIZE);
    put16(p + 8, QUERY_ENTRY_SIZE);
    put16(p + 10, query->n_entries);
    put32(p + 12, (u32)length);
    for (u16 i = 0; i < query->n_entries; i++)
        encode_query_entry(&query->entries[i],
                           p + QUERY_HEADER_SIZE + QUERY_ENTRY_SIZE * i);
    return (int)length;
}

int nl_acl_counter_query_decode(const void *buffer, size_t length,
                                nl_acl_counter_query *query) {
    const u8 *p = buffer;
    nl_acl_counter_query decoded;
    u16 count;
    size_t expected;

    if (!buffer || !query || length < QUERY_HEADER_SIZE ||
        get32(p) != NL_ACL_COUNTER_QUERY_MAGIC ||
        get16(p + 4) != NL_ACL_COUNTER_SNAPSHOT_VERSION ||
        get16(p + 6) != QUERY_HEADER_SIZE ||
        get16(p + 8) != QUERY_ENTRY_SIZE)
        return -1;
    count = get16(p + 10);
    expected = nl_acl_counter_query_wire_size(count);
    if (expected == 0 || length != expected || get32(p + 12) != length)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    decoded.n_entries = count;
    for (u16 i = 0; i < count; i++)
        if (decode_query_entry(
                p + QUERY_HEADER_SIZE + QUERY_ENTRY_SIZE * i,
                &decoded.entries[i]) != 0 || decoded.entries[i].id != i)
            return -1;
    if (nl_acl_counter_query_validate(&decoded) != 0)
        return -1;
    *query = decoded;
    return 0;
}

static bool snapshot_valid(const nl_acl_counter_snapshot *snapshot) {
    if (!snapshot || !snapshot->complete || snapshot->generation == 0 ||
        snapshot->sampled_monotonic_ms == 0 ||
        snapshot->n_entries > NL_ACL_COUNTER_MAX_ENTRIES)
        return false;
    for (u16 i = 0; i < snapshot->n_entries; i++) {
        const nl_acl_counter_snapshot_entry *e = &snapshot->entries[i];
        if (e->id != i || e->kind < NL_ACL_COUNTER_KIND_USER_FILTER ||
            e->kind > NL_ACL_COUNTER_KIND_INDEPENDENT ||
            e->state < NL_ACL_COUNTER_STATE_ABSENT ||
            e->state > NL_ACL_COUNTER_STATE_MISMATCH)
            return false;
    }
    return true;
}

int nl_acl_counter_snapshot_encode(const nl_acl_counter_snapshot *snapshot,
                                   void *buffer, size_t capacity) {
    u8 *p = buffer;
    size_t length;

    if (!buffer || !snapshot_valid(snapshot))
        return -1;
    length = nl_acl_counter_snapshot_wire_size(snapshot->n_entries);
    if (length == 0 || length > capacity || length > INT_MAX)
        return -1;
    memset(p, 0, length);
    put32(p, NL_ACL_COUNTER_SNAPSHOT_MAGIC);
    put16(p + 4, NL_ACL_COUNTER_SNAPSHOT_VERSION);
    put16(p + 6, SNAPSHOT_HEADER_SIZE);
    put16(p + 8, SNAPSHOT_ENTRY_SIZE);
    put16(p + 10, snapshot->n_entries);
    put32(p + 12, SNAPSHOT_COMPLETE);
    put64(p + 16, snapshot->generation);
    put64(p + 24, snapshot->sampled_monotonic_ms);
    for (u16 i = 0; i < snapshot->n_entries; i++) {
        const nl_acl_counter_snapshot_entry *e = &snapshot->entries[i];
        u8 *entry = p + SNAPSHOT_HEADER_SIZE + SNAPSHOT_ENTRY_SIZE * i;
        put16(entry, e->id);
        entry[2] = e->kind;
        entry[3] = e->state;
        put32(entry + 4, (u32)e->sdk_status);
        put64(entry + 8, e->packets);
        put64(entry + 16, e->octets);
    }
    return (int)length;
}

int nl_acl_counter_snapshot_decode(const void *buffer, size_t length,
                                   nl_acl_counter_snapshot *snapshot) {
    const u8 *p = buffer;
    nl_acl_counter_snapshot decoded;
    u16 count;
    u32 flags;
    size_t expected;

    if (!buffer || !snapshot || length < SNAPSHOT_HEADER_SIZE ||
        get32(p) != NL_ACL_COUNTER_SNAPSHOT_MAGIC ||
        get16(p + 4) != NL_ACL_COUNTER_SNAPSHOT_VERSION ||
        get16(p + 6) != SNAPSHOT_HEADER_SIZE ||
        get16(p + 8) != SNAPSHOT_ENTRY_SIZE)
        return -1;
    count = get16(p + 10);
    flags = get32(p + 12);
    expected = nl_acl_counter_snapshot_wire_size(count);
    if (expected == 0 || length != expected || flags != SNAPSHOT_COMPLETE)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    decoded.complete = true;
    decoded.generation = get64(p + 16);
    decoded.sampled_monotonic_ms = get64(p + 24);
    decoded.n_entries = count;
    for (u16 i = 0; i < count; i++) {
        const u8 *entry =
            p + SNAPSHOT_HEADER_SIZE + SNAPSHOT_ENTRY_SIZE * i;
        decoded.entries[i].id = get16(entry);
        decoded.entries[i].kind = entry[2];
        decoded.entries[i].state = entry[3];
        decoded.entries[i].sdk_status = (int)(int32_t)get32(entry + 4);
        decoded.entries[i].packets = get64(entry + 8);
        decoded.entries[i].octets = get64(entry + 16);
    }
    if (!snapshot_valid(&decoded))
        return -1;
    *snapshot = decoded;
    return 0;
}
