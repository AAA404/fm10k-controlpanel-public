#ifndef L2D_STATE_H
#define L2D_STATE_H

#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "l2d_paths.h"

#include <pthread.h>
#include <stdbool.h>
#include <time.h>

#define SW_SOCKET l2d_switchd_socket_path()

#define L2_IF_MAX_MEMBERS 64
#define L2_IF_MEMBERS_TEXT_BYTES (L2_IF_MAX_MEMBERS * 65)
#define L2D_AE_LIMIT NETLAB_MAX_AE
#define L2D_MAX_IFS (NL_MAX_PORTS_PER_PROFILE + L2D_AE_LIMIT)
#define L2D_MAX_VLANS 4094
#define L2D_MAX_MAC_ENTRIES NL_MAC_SNAPSHOT_MAX_ENTRIES
#define L2D_MAX_MAC_SEEN NL_MAC_SNAPSHOT_MAX_ENTRIES
#define L2D_MAX_MAC_MOVES 256
#define L2D_MAX_SECURITY_VLANS L2D_MAX_VLANS
#define L2D_MAX_DHCP_BINDINGS 512
#define L2D_MAX_USER_FILTERS 64
#define L2D_MAX_INGRESS_IPV4_ACL 64
#define L2D_MAX_ACL_POLICER 8
#define L2D_MAX_EGRESS_ACL 8
#define L2D_MAX_ACL_INDEPENDENT 32

typedef struct {
    char name[64];
    int vid;
    bool hw_exists;
} l2_vlan_state;

typedef struct {
    char name[64];
    char mode[16];
    char member[64];
    int member_vid;
    char members[L2_IF_MEMBERS_TEXT_BYTES];
    int member_vids[L2_IF_MAX_MEMBERS];
    int n_members;
    bool disabled;
    bool hw_member;
    bool mac_limit_configured;
    int mac_limit;
    char mac_action[16];
    int dynamic_macs;
    bool mac_shutdown;
    time_t mac_shutdown_time;
    bool mac_drop_active;
    time_t mac_drop_time;
    int mac_enforced_ports[NL_MAX_PORTS];
    int n_mac_enforced_ports;
    char mac_enforced_action[16];
    char mac_shutdown_reason[128];
    bool mac_move_shutdown;
    time_t mac_move_shutdown_time;
    char mac_move_shutdown_reason[128];
    bool dhcp_snooping_trusted;
    bool arp_inspection_trusted;
} l2_if_state;

typedef struct {
    int vlan;
    char mac[18];
    char ifname[64];
} l2_mac_entry;

typedef struct {
    int vlan;
    char mac[18];
    char ifname[64];
    time_t last_seen;
} l2_mac_seen;

typedef struct {
    int vlan;
    char mac[18];
    char from_if[64];
    char to_if[64];
    unsigned long count;
    unsigned long window_count;
    time_t window_start;
    time_t last_seen;
    bool dampened;
    time_t dampened_time;
    char dampened_if[64];
} l2_mac_move;

typedef struct {
    char mac[18];
    char vlan[64];
    int vid;
    char ifname[64];
    char ip[16];
    bool active_dai;
} l2_dhcp_binding;

typedef struct {
    char feature[16];
    char name[64];
    char vlan[64];
    int vid;
    char ifname[64];
    char mac[18];
    char mac_kind[16];
    char action[16];
} l2_user_filter;

typedef struct {
    char name[64];
    char vlan[64];
    int vid;
    char ifname[64];
    char src_ip[16];
    char dst_ip[16];
    char src_mask[16];
    char dst_mask[16];
    char src_prefix[32];
    char dst_prefix[32];
    bool has_src_ip;
    bool has_dst_ip;
    bool has_src_ip_mask;
    bool has_dst_ip_mask;
    bool has_src_prefix;
    bool has_dst_prefix;
    bool has_dscp;
    bool has_ecn;
    bool has_protocol;
    bool has_src_port;
    bool has_dst_port;
    bool has_src_port_range;
    bool has_dst_port_range;
    bool has_tcp_flags;
    bool has_tcp_flags_mask;
    int protocol;
    int dscp;
    int ecn;
    int src_port;
    int dst_port;
    int src_port_start;
    int src_port_end;
    int dst_port_start;
    int dst_port_end;
    char src_port_range[16];
    char dst_port_range[16];
    int tcp_flags;
    int tcp_flags_mask;
    char action[16];
} l2_ingress_ipv4_acl;

typedef struct {
    char name[64];
    char ifname[64];
    char dst_mac[18];
    int rate_kbps;
    int burst_bytes;
} l2_acl_policer;

typedef struct {
    char name[64];
    char ifname[64];
    char src_mac[18];
    char dst_mac[18];
    char action[16];
} l2_egress_acl;

typedef struct {
    char group[64];
    char term[64];
    char family[16];
    int slot;
    char vlan[64];
    int vid;
    char ifname[64];
    char src_mac[18];
    char dst_mac[18];
    char src_ip[16];
    char dst_ip[16];
    char src_mask[16];
    char dst_mask[16];
    char src_prefix[32];
    char dst_prefix[32];
    char src_port_range[16];
    char dst_port_range[16];
    bool has_src_mac;
    bool has_dst_mac;
    bool has_src_ip;
    bool has_dst_ip;
    bool has_src_ip_mask;
    bool has_dst_ip_mask;
    bool has_src_prefix;
    bool has_dst_prefix;
    bool has_dscp;
    bool has_protocol;
    bool has_src_port;
    bool has_dst_port;
    bool has_src_port_range;
    bool has_dst_port_range;
    bool has_tcp_flags;
    bool has_tcp_flags_mask;
    int dscp;
    int protocol;
    int src_port;
    int dst_port;
    int src_port_start;
    int src_port_end;
    int dst_port_start;
    int dst_port_end;
    int tcp_flags;
    int tcp_flags_mask;
    char action[16];
    int rate_kbps;
    int burst_bytes;
} l2_acl_independent;

typedef struct {
    l2_vlan_state vlans[L2D_MAX_VLANS];
    int n_vlans;
    l2_if_state ifs[L2D_MAX_IFS];
    int n_ifs;
    l2_mac_seen seen[L2D_MAX_MAC_SEEN];
    int n_seen;
    l2_mac_move moves[L2D_MAX_MAC_MOVES];
    int n_moves;
    unsigned long mac_update_last_seq;
    bool mac_update_baseline_ready;
    unsigned long total_moves;
    unsigned long total_move_dampens;
    bool move_dampening_configured;
    int move_dampening_threshold;
    int move_dampening_window;
    char move_dampening_action[16];
    char dhcp_snooping_vlans[L2D_MAX_SECURITY_VLANS][64];
    int n_dhcp_snooping_vlans;
    char arp_inspection_vlans[L2D_MAX_SECURITY_VLANS][64];
    int n_arp_inspection_vlans;
    l2_dhcp_binding dhcp_bindings[L2D_MAX_DHCP_BINDINGS];
    int n_dhcp_bindings;
    l2_user_filter user_filters[L2D_MAX_USER_FILTERS];
    int n_user_filters;
    l2_ingress_ipv4_acl ingress_ipv4_acl[L2D_MAX_INGRESS_IPV4_ACL];
    int n_ingress_ipv4_acl;
    l2_acl_policer acl_policer[L2D_MAX_ACL_POLICER];
    int n_acl_policer;
    l2_egress_acl egress_acl[L2D_MAX_EGRESS_ACL];
    int n_egress_acl;
    l2_acl_independent acl_independent[L2D_MAX_ACL_INDEPENDENT];
    int n_acl_independent;
    bool switchd_up;
    bool config_complete;
    bool mac_snapshot_complete;
    bool stp_snapshot_complete;
    u64 cache_generation;
    time_t last_update;
    time_t mac_snapshot_last_update;
    time_t stp_snapshot_last_update;
    pthread_mutex_t lock;
} l2d_ctx;

typedef struct {
    bool present;
    char name[16];
    int ae_id;
    int logical_port;
    int members[NL_MAX_PORTS];
    int n_members;
} l2_lag_info;

extern l2d_ctx g_l2d;

#endif
