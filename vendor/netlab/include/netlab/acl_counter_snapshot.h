#ifndef NETLAB_ACL_COUNTER_SNAPSHOT_H
#define NETLAB_ACL_COUNTER_SNAPSHOT_H

#include "types.h"

#include <stdbool.h>
#include <stddef.h>

#define NL_ACL_COUNTER_QUERY_MAGIC 0x4e414351U
#define NL_ACL_COUNTER_SNAPSHOT_MAGIC 0x4e414353U
#define NL_ACL_COUNTER_SNAPSHOT_VERSION 1U

#define NL_ACL_COUNTER_MAX_USER_FILTERS 64U
#define NL_ACL_COUNTER_MAX_INGRESS_IPV4 64U
#define NL_ACL_COUNTER_MAX_EGRESS 8U
#define NL_ACL_COUNTER_MAX_POLICERS 8U
#define NL_ACL_COUNTER_MAX_INDEPENDENT 32U
#define NL_ACL_COUNTER_MAX_ENTRIES \
    (NL_ACL_COUNTER_MAX_USER_FILTERS + \
     NL_ACL_COUNTER_MAX_INGRESS_IPV4 + \
     NL_ACL_COUNTER_MAX_EGRESS + \
     NL_ACL_COUNTER_MAX_POLICERS + \
     NL_ACL_COUNTER_MAX_INDEPENDENT)
#define NL_ACL_COUNTER_QUERY_WIRE_MAX \
    (16U + 128U * NL_ACL_COUNTER_MAX_ENTRIES)
#define NL_ACL_COUNTER_SNAPSHOT_WIRE_MAX \
    (32U + 24U * NL_ACL_COUNTER_MAX_ENTRIES)

typedef enum {
    NL_ACL_COUNTER_KIND_USER_FILTER = 1,
    NL_ACL_COUNTER_KIND_INGRESS_IPV4 = 2,
    NL_ACL_COUNTER_KIND_EGRESS = 3,
    NL_ACL_COUNTER_KIND_POLICER = 4,
    NL_ACL_COUNTER_KIND_INDEPENDENT = 5,
} nl_acl_counter_kind;

typedef enum {
    NL_ACL_COUNTER_MAC_SOURCE = 1,
    NL_ACL_COUNTER_MAC_DESTINATION = 2,
} nl_acl_counter_mac_kind;

typedef enum {
    NL_ACL_COUNTER_FAMILY_NONE = 0,
    NL_ACL_COUNTER_FAMILY_ETHERNET = 1,
    NL_ACL_COUNTER_FAMILY_INET = 2,
    NL_ACL_COUNTER_FAMILY_POLICER = 3,
} nl_acl_counter_family;

typedef enum {
    NL_ACL_COUNTER_ACTION_NONE = 0,
    NL_ACL_COUNTER_ACTION_DROP = 1,
    NL_ACL_COUNTER_ACTION_COUNT = 2,
    NL_ACL_COUNTER_ACTION_POLICER = 3,
} nl_acl_counter_action;

typedef enum {
    NL_ACL_COUNTER_STATE_ABSENT = 1,
    NL_ACL_COUNTER_STATE_INSTALLED = 2,
    NL_ACL_COUNTER_STATE_MISMATCH = 3,
} nl_acl_counter_state;

#define NL_ACL_COUNTER_MATCH_SRC_IP          (1U << 0)
#define NL_ACL_COUNTER_MATCH_DST_IP          (1U << 1)
#define NL_ACL_COUNTER_MATCH_SRC_IP_MASK     (1U << 2)
#define NL_ACL_COUNTER_MATCH_DST_IP_MASK     (1U << 3)
#define NL_ACL_COUNTER_MATCH_DSCP            (1U << 4)
#define NL_ACL_COUNTER_MATCH_ECN             (1U << 5)
#define NL_ACL_COUNTER_MATCH_PROTOCOL        (1U << 6)
#define NL_ACL_COUNTER_MATCH_SRC_PORT        (1U << 7)
#define NL_ACL_COUNTER_MATCH_DST_PORT        (1U << 8)
#define NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE  (1U << 9)
#define NL_ACL_COUNTER_MATCH_DST_PORT_RANGE  (1U << 10)
#define NL_ACL_COUNTER_MATCH_TCP_FLAGS       (1U << 11)
#define NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK  (1U << 12)
#define NL_ACL_COUNTER_MATCH_COUNT_ONLY      (1U << 13)
#define NL_ACL_COUNTER_MATCH_SRC_MAC         (1U << 14)
#define NL_ACL_COUNTER_MATCH_DST_MAC         (1U << 15)
#define NL_ACL_COUNTER_MATCH_ALL             ((1U << 16) - 1U)

typedef struct {
    u16 vid;
    u16 port;
    u32 flags;
    u32 src_ip;
    u32 dst_ip;
    u32 src_ip_mask;
    u32 dst_ip_mask;
    int dscp;
    int ecn;
    int protocol;
    int src_port;
    int dst_port;
    int src_port_start;
    int src_port_end;
    int dst_port_start;
    int dst_port_end;
    int tcp_flags;
    int tcp_flags_mask;
} nl_acl_counter_ipv4_match;

typedef struct {
    u16 id;
    u8 kind;
    u8 mac_kind;
    u8 family;
    u8 action;
    int slot;
    int rate_kbps;
    int burst_bytes;
    u8 mac[6];
    u64 src_mac;
    u64 dst_mac;
    nl_acl_counter_ipv4_match match;
} nl_acl_counter_query_entry;

typedef struct {
    u16 n_entries;
    nl_acl_counter_query_entry entries[NL_ACL_COUNTER_MAX_ENTRIES];
} nl_acl_counter_query;

typedef struct {
    u16 id;
    u8 kind;
    u8 state;
    int sdk_status;
    u64 packets;
    u64 octets;
} nl_acl_counter_snapshot_entry;

typedef struct {
    u64 generation;
    u64 sampled_monotonic_ms;
    u16 n_entries;
    bool complete;
    nl_acl_counter_snapshot_entry entries[NL_ACL_COUNTER_MAX_ENTRIES];
} nl_acl_counter_snapshot;

size_t nl_acl_counter_query_wire_size(u16 n_entries);
size_t nl_acl_counter_snapshot_wire_size(u16 n_entries);
int nl_acl_counter_query_validate(const nl_acl_counter_query *query);
int nl_acl_counter_query_encode(const nl_acl_counter_query *query,
                                void *buffer, size_t capacity);
int nl_acl_counter_query_decode(const void *buffer, size_t length,
                                nl_acl_counter_query *query);
int nl_acl_counter_snapshot_encode(const nl_acl_counter_snapshot *snapshot,
                                   void *buffer, size_t capacity);
int nl_acl_counter_snapshot_decode(const void *buffer, size_t length,
                                   nl_acl_counter_snapshot *snapshot);

#endif
