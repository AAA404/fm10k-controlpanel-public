/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_L2_PLAN_INTERNAL_H
#define NETLAB_L2_PLAN_INTERNAL_H

#include "netlab/l2_plan.h"
#include "netlab/yang_config.h"

#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include "l2d_paths.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SWITCHD_SOCKET l2d_switchd_socket_path()
#define CFG_IF_MAX_MEMBERS 64
#define CFG_AE_LIMIT NETLAB_MAX_AE
#define CFG_PORT_MODE_UP 0
#define CFG_PORT_MODE_ADMIN_PWRDOWN 2
#define CFG_MAC_AGING_DEFAULT_SECONDS 300
#define CFG_MAC_AGING_MAX_SECONDS 1000000
#define CFG_INTERFACE_DEFAULT_MTU 1514
#define CFG_INTERFACE_MIN_MTU 1514
#define CFG_INTERFACE_MAX_MTU 9216
#define CFG_STATIC_MAC_MAX_ENTRIES 512
#define CFG_STORM_CONTROL_MAX_ENTRIES 128
#define CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES 128
#define CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES 128
#define CFG_STORM_CONTROLLER_DEFAULT_CAPACITY 16
#define CFG_L2_SECURITY_MAX_RULES 256
#define CFG_L2_SECURITY_FLOW_CAPACITY 64
#define CFG_DHCP_BINDING_MAX_ENTRIES 512
#define CFG_USER_FILTER_MAX_ENTRIES 64
#define CFG_INGRESS_IPV4_ACL_MAX_ENTRIES 64
#define CFG_ACL_POLICER_MAX_ENTRIES 8
#define CFG_EGRESS_ACL_MAX_ENTRIES 8
#define CFG_ACL_INDEPENDENT_MAX_TERMS 32
#define CFG_COPP_CLASS_MAX 8
#define CFG_QOS_INTERFACE_MAX_ENTRIES 128
#define CFG_QOS_PFC_MAX_ENTRIES 128
#define CFG_QOS_PRIORITY_MAP_MAX_ENTRIES 16
#define CFG_QOS_SCHEDULER_TC_MAP_MAX_ENTRIES 256
#define CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES 256
#define CFG_QOS_SCHEDULER_GROUP_MAX_WEIGHT 0xffffff
#define CFG_QOS_SCHEDULER_GROUP_MAX_RATE_BPS 100000000000ULL
#define CFG_QOS_SCHEDULER_GROUP_MAX_BURST_BITS 67100672ULL
#define CFG_QOS_SCHEDULER_GROUP_DEFAULT_BURST_BITS 67100672ULL
#define CFG_QOS_SCHEDULER_PORT_MAX_ENTRIES 64
#define CFG_QOS_WATERMARK_MAX_ENTRIES 256
#define CFG_MIRROR_MAX_SESSIONS 1
#define CFG_IGMP_STATIC_MAX_MEMBERS 32
#define CFG_IGMP_MAX_SCOPES 1024
#define CFG_QOS_WATERMARK_MAX_VALUE 6291264
#define CFG_STORM_CONTROL_MIN_RATE_KBPS 22000
#define CFG_STORM_CONTROL_MAX_RATE_KBPS 100000000
#define CFG_STORM_CONTROL_DEFAULT_BURST_BYTES 65536
#define CFG_STORM_CONTROL_MAX_BURST_BYTES 104857600
#define CFG_INGRESS_RATE_LIMIT_MIN_RATE_KBPS CFG_STORM_CONTROL_MIN_RATE_KBPS
#define CFG_INGRESS_RATE_LIMIT_MAX_RATE_KBPS CFG_STORM_CONTROL_MAX_RATE_KBPS
#define CFG_INGRESS_RATE_LIMIT_DEFAULT_BURST_BYTES CFG_STORM_CONTROL_DEFAULT_BURST_BYTES
#define CFG_INGRESS_RATE_LIMIT_MAX_BURST_BYTES CFG_STORM_CONTROL_MAX_BURST_BYTES
#define CFG_EGRESS_RATE_LIMIT_MIN_RATE_KBPS CFG_STORM_CONTROL_MIN_RATE_KBPS
#define CFG_EGRESS_RATE_LIMIT_MAX_RATE_KBPS CFG_STORM_CONTROL_MAX_RATE_KBPS
#define CFG_EGRESS_RATE_LIMIT_DEFAULT_BURST_BYTES CFG_STORM_CONTROL_DEFAULT_BURST_BYTES
#define CFG_EGRESS_RATE_LIMIT_MAX_BURST_BYTES 8387584
#define CFG_ACL_POLICER_MIN_RATE_KBPS 1
#define CFG_ACL_POLICER_MAX_RATE_KBPS 100000000
#define CFG_ACL_POLICER_DEFAULT_BURST_BYTES 65536
#define CFG_ACL_POLICER_MIN_BURST_BYTES 1024
#define CFG_ACL_POLICER_MAX_BURST_BYTES 268435456

typedef struct {
    char name[64];
    int  hw_port;
    bool is_aggregate;
    int  ae_id;
    u32  flags;
    u64  default_speed_bps;
    u64  scheduler_speed_bps;
    u64  supported_speeds_bps[8];
    int  num_speeds;
} cfg_port_ref;

typedef struct {
    char name[64];
    int  vid;
} cfg_vlan_ref;

typedef struct {
    bool exists;
    bool disabled;
    bool has_l2;
    bool has_mtu;
    bool has_speed;
    bool has_native;
    bool rstp_managed;
    char mode[16];
    char member[64];
    int  member_vid;
    char members[CFG_IF_MAX_MEMBERS][64];
    int  member_vids[CFG_IF_MAX_MEMBERS];
    int  n_members;
    int  mtu;
    int  speed_mbps;
    int  native_vid;
    bool members_complete;
} cfg_if_intent;

typedef struct {
    char mac[18];
    char vlan[64];
    char ifname[64];
    int  vid;
    cfg_port_ref port;
} cfg_static_mac_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    nl_storm_kind kind;
    int rate_kbps;
    int burst_bytes;
} cfg_storm_control_intent;

typedef cfg_storm_control_intent cfg_ingress_rate_limit_intent;
typedef cfg_storm_control_intent cfg_egress_rate_limit_intent;

typedef enum {
    CFG_L2_SECURITY_DHCP_SNOOPING = 1,
    CFG_L2_SECURITY_ARP_INSPECTION = 2,
} cfg_l2_security_kind;

typedef struct {
    cfg_l2_security_kind kind;
    int vid;
    cfg_port_ref port;
} cfg_l2_security_rule_intent;

typedef struct {
    char mac[18];
    char vlan[64];
    int vid;
    char ifname[64];
    cfg_port_ref port;
    char ip[16];
    u32 ip_addr;
} cfg_dhcp_binding_intent;

typedef struct {
    char feature[16];
    char name[64];
    char vlan[64];
    char ifname[64];
    char mac[18];
    char mac_kind[16];
    char action[16];
    int vid;
    cfg_port_ref port;
} cfg_user_filter_intent;

typedef struct {
    char name[64];
    char vlan[64];
    char ifname[64];
    char action[16];
    char src_ip_text[16];
    char dst_ip_text[16];
    char src_prefix_text[32];
    char dst_prefix_text[32];
    char src_port_range_text[16];
    char dst_port_range_text[16];
    int vid;
    cfg_port_ref port;
    hal_ingress_ipv4_acl_match match;
} cfg_ingress_ipv4_acl_intent;

typedef struct {
    char name[64];
    char ifname[64];
    char dst_mac_text[18];
    cfg_port_ref port;
    u64 dst_mac;
    int rate_kbps;
    int burst_bytes;
} cfg_acl_policer_intent;

typedef struct {
    char name[64];
    char ifname[64];
    char src_mac_text[18];
    char dst_mac_text[18];
    char action[16];
    cfg_port_ref port;
    bool has_src_mac;
    bool has_dst_mac;
    u64 src_mac;
    u64 dst_mac;
} cfg_egress_acl_intent;

typedef struct {
    char group[64];
    char term[64];
    char family[16];
    int slot;
    char vlan[64];
    int vid;
    char ifname[64];
    cfg_port_ref port;
    char action[16];
    bool has_src_mac;
    bool has_dst_mac;
    char src_mac_text[18];
    char dst_mac_text[18];
    u64 src_mac;
    u64 dst_mac;
    char src_ip_text[16];
    char dst_ip_text[16];
    char src_prefix_text[32];
    char dst_prefix_text[32];
    char src_port_range_text[16];
    char dst_port_range_text[16];
    hal_ingress_ipv4_acl_match inet_match;
    int rate_kbps;
    int burst_bytes;
} cfg_acl_independent_intent;

typedef struct {
    char class_name[16];
    int rate_pps;
    int burst_pkts;
} cfg_copp_class_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    int trust_mode;
    int default_priority;
} cfg_qos_interface_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    int rx_class_mask;
    int tx_class_mask;
    int lossless_smp_mask;
    int shared_pause_mask;
    fm10k_pfc_wd_policy watchdog;
} cfg_qos_pfc_intent;

typedef struct {
    int switch_priority;
    int traffic_class;
} cfg_qos_priority_map_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    int traffic_class;
    int shaping_group;
} cfg_qos_scheduler_tc_map_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    int group;
    int strict_priority;
    int weight;
} cfg_qos_scheduler_group_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    int group;
    u64 rate_bps;
    u64 burst_bits;
} cfg_qos_scheduler_group_shaping_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    int traffic_class_enable_mask;
} cfg_qos_scheduler_port_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    int traffic_class;
    int attr;
    int value;
} cfg_qos_watermark_intent;

typedef struct {
    char ifname[64];
    cfg_port_ref port;
    int direction;
} cfg_port_mirror_source;

typedef struct {
    bool exists;
    char name[64];
    char destination_ifname[64];
    cfg_port_ref destination;
    int n_sources;
    cfg_port_mirror_source sources[NETLAB_MIRROR_MAX_SOURCES];
} cfg_port_mirror_intent;

typedef struct {
    char vlan[64];
    int vid;
    char ifname[64];
    cfg_port_ref port;
    char group[16];
    u32 group_ip;
    u8 mac[6];
    bool router;
} cfg_igmp_listener_intent;

typedef struct {
    char vlan[64];
    int vid;
    char ifname[64];
    cfg_port_ref port;
    bool mrouter;
    bool fast_leave;
    bool direct_receiver;
} cfg_igmp_scope_intent;

int l2_plan_set_error(char *err, size_t err_size, const char *fmt,
                      const char *a, const char *b);
int l2_plan_append(char *plan, size_t plan_size, int *off,
                   const char *fmt, int a, int b, int c);
int l2_plan_appendf(char *plan, size_t plan_size, int *off,
                    const char *fmt, ...);
bool l2_text_eq(const char *a, const char *b);
int l2_cfg_max_ae(void);
bool l2_bool_leaf_true(const char *value);
bool l2_normalize_mac_text(const char *in, char *out, size_t out_size);
u32 l2_ipv4_mask_from_prefix_len(int prefix_len);
bool l2_parse_ipv4_prefix_text(const char *text, u32 *ip, u32 *mask,
                               int *prefix_len);
bool l2_format_ipv4_text(u32 ip, char *out, size_t out_size);
bool l2_format_ipv4_prefix_text(u32 ip, int prefix_len, char *out,
                                size_t out_size);
bool l2_parse_port_range_text(const char *text, int *start, int *end);
int l2_port_range_entry_count(int start, int end);
int l2_ingress_ipv4_acl_hw_entry_count(
    const cfg_ingress_ipv4_acl_intent *entry);
bool l2_static_mac_is_unicast_nonzero(const char *mac);
int l2_extract_xml_leaf(const char *start, const char *end,
                        const char *leaf, char *out, size_t out_size);
int l2_extract_xml_attr(const char *start, const char *end,
                        const char *attr, char *out, size_t out_size);

int l2_collect_vlans(nl_yang_session *ys, cfg_vlan_ref *vlans, int max_vlans);
int l2_collect_static_mac_intents(nl_yang_session *ys,
                                  cfg_static_mac_intent *entries,
                                  int max_entries);
int l2_collect_storm_control_intents(nl_yang_session *ys,
                                     cfg_storm_control_intent *entries,
                                     int max_entries);
int l2_collect_ingress_rate_limit_intents(
    nl_yang_session *ys, cfg_ingress_rate_limit_intent *entries,
    int max_entries);
int l2_collect_egress_rate_limit_intents(
    nl_yang_session *ys, cfg_egress_rate_limit_intent *entries,
    int max_entries);
int l2_collect_l2_security_rule_intents(nl_yang_session *ys,
                                        const char *feature,
                                        cfg_l2_security_rule_intent *entries,
                                        int max_entries,
                                        const cfg_port_ref *ports,
                                        int n_ports);
int l2_collect_dhcp_binding_intents(nl_yang_session *ys,
                                    cfg_dhcp_binding_intent *entries,
                                    int max_entries,
                                    const cfg_port_ref *ports,
                                    int n_ports);
int l2_collect_user_filter_intents(nl_yang_session *ys,
                                   cfg_user_filter_intent *entries,
                                   int max_entries,
                                   const cfg_port_ref *ports,
                                   int n_ports);
int l2_collect_ingress_ipv4_acl_intents(
    nl_yang_session *ys, cfg_ingress_ipv4_acl_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports);
int l2_collect_acl_policer_intents(
    nl_yang_session *ys, cfg_acl_policer_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports);
int l2_collect_egress_acl_intents(
    nl_yang_session *ys, cfg_egress_acl_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports);
int l2_collect_acl_independent_intents(
    nl_yang_session *ys, cfg_acl_independent_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports);
int l2_collect_copp_class_intents(nl_yang_session *ys,
                                  cfg_copp_class_intent *entries,
                                  int max_entries);
int l2_collect_qos_interface_intents(nl_yang_session *ys,
                                     cfg_qos_interface_intent *entries,
                                     int max_entries);
int l2_collect_qos_pfc_intents(nl_yang_session *ys,
                               cfg_qos_pfc_intent *entries,
                               int max_entries);
int l2_collect_qos_priority_map_intents(
    nl_yang_session *ys, cfg_qos_priority_map_intent *entries,
    int max_entries);
int l2_collect_qos_scheduler_tc_map_intents(
    nl_yang_session *ys, cfg_qos_scheduler_tc_map_intent *entries,
    int max_entries);
int l2_collect_qos_scheduler_group_intents(
    nl_yang_session *ys, cfg_qos_scheduler_group_intent *entries,
    int max_entries);
int l2_collect_qos_scheduler_group_shaping_intents(
    nl_yang_session *ys, cfg_qos_scheduler_group_shaping_intent *entries,
    int max_entries);
int l2_collect_qos_scheduler_port_intents(
    nl_yang_session *ys, cfg_qos_scheduler_port_intent *entries,
    int max_entries);
int l2_collect_qos_watermark_intents(
    nl_yang_session *ys, cfg_qos_watermark_intent *entries,
    int max_entries);
int l2_collect_port_mirror_intent(nl_yang_session *ys,
                                  cfg_port_mirror_intent *intent,
                                  const cfg_port_ref *ports, int n_ports);
int l2_collect_igmp_scope_intents(nl_yang_session *ys,
    cfg_igmp_scope_intent *entries, int max_entries,
    const cfg_port_ref *ports, int n_ports);
int l2_collect_igmp_listener_intents(
    nl_yang_session *ys, cfg_igmp_listener_intent *entries,
    int max_entries, const cfg_port_ref *ports, int n_ports);
bool l2_parse_igmp_group(const char *text, u32 *group_ip, u8 mac[6]);
int l2_find_igmp_listener(const cfg_igmp_listener_intent *entries,
                          int n_entries, int vid, int port, u32 group_ip);
bool l2_port_mirror_same(const cfg_port_mirror_intent *a,
                         const cfg_port_mirror_intent *b);
bool l2_vlan_vid_present(const cfg_vlan_ref *vlans, int n_vlans, int vid);
bool l2_vlan_marked_missing(const bool *missing_by_vid, int vid);
void l2_read_interface_intent(nl_yang_session *ys, const char *ifname,
                              cfg_if_intent *intent);
bool l2_intent_is_trunk(const cfg_if_intent *intent);
bool l2_intent_vid_tagged(const cfg_if_intent *intent, int vid);
bool l2_intent_has_member_tagged(const cfg_if_intent *intent, int vid,
                                  bool tagged);
bool l2_intent_has_vid(const cfg_if_intent *intent, int vid);
bool l2_membership_changed(const cfg_if_intent *old_i,
                           const cfg_if_intent *new_i);

int l2_get_vlan_id(nl_yang_session *ys, const char *vlan_name);
const char *l2_get_interface_leaf(nl_yang_session *ys, const char *ifname,
                                  const char *leaf);
const char *l2_get_l2_leaf(nl_yang_session *ys, const char *ifname,
                           const char *leaf);
const char *l2_get_lag_member(nl_yang_session *ys, const char *ifname);
bool l2_get_ingress_filtering(nl_yang_session *ys, const char *ifname);
const char *l2_get_lacp_member_port_priority(nl_yang_session *ys,
                                             const char *ifname);
const char *l2_get_lacp_mode(nl_yang_session *ys, const char *ifname);
const char *l2_get_lacp_periodic(nl_yang_session *ys, const char *ifname);
const char *l2_get_lacp_actor_key(nl_yang_session *ys, const char *ifname);
const char *l2_get_lag_hash_rotation(nl_yang_session *ys,
                                     const char *ifname);
int l2_get_lacp_min_links(nl_yang_session *ys, const char *ifname,
                          bool *configured, bool *valid);
int l2_get_mac_aging_time(nl_yang_session *ys, bool *configured);

void l2_port_target_arg(const cfg_port_ref *port, char *buf, size_t buf_len);
void l2_resolve_static_mac_ports(cfg_static_mac_intent *entries, int n_entries,
                                 const cfg_port_ref *ports, int n_ports);
void l2_resolve_storm_control_ports(cfg_storm_control_intent *entries,
                                    int n_entries,
                                    const cfg_port_ref *ports, int n_ports);
void l2_resolve_ingress_rate_limit_ports(
    cfg_ingress_rate_limit_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports);
void l2_resolve_egress_rate_limit_ports(
    cfg_egress_rate_limit_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports);
void l2_resolve_qos_interface_ports(cfg_qos_interface_intent *entries,
                                    int n_entries,
                                    const cfg_port_ref *ports, int n_ports);
void l2_resolve_qos_pfc_ports(cfg_qos_pfc_intent *entries, int n_entries,
                              const cfg_port_ref *ports, int n_ports);
void l2_resolve_qos_scheduler_tc_map_ports(
    cfg_qos_scheduler_tc_map_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports);
void l2_resolve_qos_scheduler_group_ports(
    cfg_qos_scheduler_group_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports);
void l2_resolve_qos_scheduler_group_shaping_ports(
    cfg_qos_scheduler_group_shaping_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports);
void l2_resolve_qos_scheduler_port_ports(
    cfg_qos_scheduler_port_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports);
void l2_resolve_qos_watermark_ports(
    cfg_qos_watermark_intent *entries, int n_entries,
    const cfg_port_ref *ports, int n_ports);
int l2_find_static_mac_by_key(const cfg_static_mac_intent *entries,
                              int n_entries, const char *mac, int vid);
bool l2_static_mac_same_target(const cfg_static_mac_intent *a,
                               const cfg_static_mac_intent *b);
int l2_find_storm_control_by_ifname(const cfg_storm_control_intent *entries,
                                    int n_entries, const char *ifname,
                                    nl_storm_kind kind);
bool l2_storm_control_same(const cfg_storm_control_intent *a,
                           const cfg_storm_control_intent *b);
int l2_find_ingress_rate_limit_by_ifname(
    const cfg_ingress_rate_limit_intent *entries, int n_entries,
    const char *ifname);
bool l2_ingress_rate_limit_same(const cfg_ingress_rate_limit_intent *a,
                                const cfg_ingress_rate_limit_intent *b);
int l2_find_egress_rate_limit_by_ifname(
    const cfg_egress_rate_limit_intent *entries, int n_entries,
    const char *ifname);
bool l2_egress_rate_limit_same(const cfg_egress_rate_limit_intent *a,
                               const cfg_egress_rate_limit_intent *b);
int l2_find_l2_security_rule(const cfg_l2_security_rule_intent *entries,
                             int n_entries, cfg_l2_security_kind kind,
                             int vid, int port);
int l2_find_dhcp_binding(const cfg_dhcp_binding_intent *entries,
                         int n_entries, const char *mac, int vid);
bool l2_dhcp_binding_same_target(const cfg_dhcp_binding_intent *a,
                                 const cfg_dhcp_binding_intent *b);
int l2_find_user_filter_by_name(const cfg_user_filter_intent *entries,
                                int n_entries, const char *name);
bool l2_user_filter_same(const cfg_user_filter_intent *a,
                         const cfg_user_filter_intent *b);
int l2_find_ingress_ipv4_acl_by_name(
    const cfg_ingress_ipv4_acl_intent *entries, int n_entries,
    const char *name);
bool l2_ingress_ipv4_acl_same(
    const cfg_ingress_ipv4_acl_intent *a,
    const cfg_ingress_ipv4_acl_intent *b);
int l2_find_acl_policer_by_name(
    const cfg_acl_policer_intent *entries, int n_entries,
    const char *name);
bool l2_acl_policer_same(const cfg_acl_policer_intent *a,
                         const cfg_acl_policer_intent *b);
int l2_find_egress_acl_by_name(
    const cfg_egress_acl_intent *entries, int n_entries,
    const char *name);
bool l2_egress_acl_same(const cfg_egress_acl_intent *a,
                        const cfg_egress_acl_intent *b);
int l2_find_acl_independent_by_key(
    const cfg_acl_independent_intent *entries, int n_entries,
    const char *group, const char *term, const char *family);
bool l2_acl_independent_same(
    const cfg_acl_independent_intent *a,
    const cfg_acl_independent_intent *b);
int l2_find_copp_class(const cfg_copp_class_intent *entries, int n_entries,
                       const char *class_name);
int l2_find_qos_interface_by_ifname(
    const cfg_qos_interface_intent *entries, int n_entries,
    const char *ifname);
bool l2_qos_interface_same(const cfg_qos_interface_intent *a,
                           const cfg_qos_interface_intent *b);
int l2_find_qos_pfc_by_ifname(
    const cfg_qos_pfc_intent *entries, int n_entries,
    const char *ifname);
bool l2_qos_pfc_same(const cfg_qos_pfc_intent *a,
                     const cfg_qos_pfc_intent *b);
int l2_find_qos_priority_map(
    const cfg_qos_priority_map_intent *entries, int n_entries,
    int switch_priority);
bool l2_qos_priority_map_same(const cfg_qos_priority_map_intent *a,
                              const cfg_qos_priority_map_intent *b);
int l2_find_qos_scheduler_tc_map(
    const cfg_qos_scheduler_tc_map_intent *entries, int n_entries,
    const char *ifname, int traffic_class);
bool l2_qos_scheduler_tc_map_same(
    const cfg_qos_scheduler_tc_map_intent *a,
    const cfg_qos_scheduler_tc_map_intent *b);
int l2_find_qos_scheduler_group(
    const cfg_qos_scheduler_group_intent *entries, int n_entries,
    const char *ifname, int group);
bool l2_qos_scheduler_group_same(
    const cfg_qos_scheduler_group_intent *a,
    const cfg_qos_scheduler_group_intent *b);
int l2_find_qos_scheduler_group_shaping(
    const cfg_qos_scheduler_group_shaping_intent *entries, int n_entries,
    const char *ifname, int group);
bool l2_qos_scheduler_group_shaping_same(
    const cfg_qos_scheduler_group_shaping_intent *a,
    const cfg_qos_scheduler_group_shaping_intent *b);
int l2_find_qos_scheduler_port_by_ifname(
    const cfg_qos_scheduler_port_intent *entries, int n_entries,
    const char *ifname);
bool l2_qos_scheduler_port_same(
    const cfg_qos_scheduler_port_intent *a,
    const cfg_qos_scheduler_port_intent *b);
int l2_find_qos_watermark(
    const cfg_qos_watermark_intent *entries, int n_entries,
    const char *ifname, int traffic_class, int attr);
bool l2_qos_watermark_same(const cfg_qos_watermark_intent *a,
                           const cfg_qos_watermark_intent *b);
const cfg_port_ref *l2_find_port_ref(const cfg_port_ref *ports, int n_ports,
                                     const char *name);
bool l2_is_ae_name(const char *name);
int l2_ae_id(const char *name);
bool l2_supported_ae_name(const char *name);
bool l2_aggregate_configured(nl_yang_session *ys, const char *ifname);

void l2_hw_probe_begin(bool require_hw);
void l2_hw_force_ports(uint32_t mask);
bool l2_hw_probe_finish(char *err, size_t err_size);
int l2_hw_inventory_ports(int *ports, int max_ports);
int l2_hw_storm_controller_capacity(void);
bool l2_hw_vlan_missing(int vid);
bool l2_hw_lag_missing(int l2_ae_id);
int l2_hw_ae_logical_port(int l2_ae_id);
bool l2_hw_vlan_member_present(int vid, int port);
bool l2_hw_port_member_missing(const cfg_port_ref *port, int vid);
bool l2_hw_admin_mismatch(int port, bool want_disabled);
bool l2_hw_mac_aging_mismatch(int want_seconds);
bool l2_hw_static_mac_mismatch(const cfg_static_mac_intent *entry);
bool l2_hw_igmp_listener_missing(const cfg_igmp_listener_intent *entry);
bool l2_hw_storm_control_mismatch(const cfg_storm_control_intent *entry);
bool l2_hw_ingress_rate_limit_mismatch(const cfg_ingress_rate_limit_intent *entry);
bool l2_hw_egress_rate_limit_mismatch(
    const cfg_egress_rate_limit_intent *entry);
bool l2_hw_qos_interface_mismatch(const cfg_qos_interface_intent *entry);
bool l2_hw_qos_tc_smp_mismatch(int tc, int smp);
bool l2_hw_qos_pfc_mismatch(const cfg_qos_pfc_intent *entry);
bool l2_hw_qos_dscp_mismatch(int dscp, int priority);
bool l2_hw_qos_priority_map_mismatch(
    const cfg_qos_priority_map_intent *entry);
bool l2_hw_qos_scheduler_tc_map_mismatch(
    const cfg_qos_scheduler_tc_map_intent *entry);
bool l2_hw_qos_scheduler_group_mismatch(
    const cfg_qos_scheduler_group_intent *entry);
bool l2_hw_qos_scheduler_group_shaping_mismatch(
    const cfg_qos_scheduler_group_shaping_intent *entry);
bool l2_hw_qos_scheduler_port_mismatch(
    const cfg_qos_scheduler_port_intent *entry);
bool l2_hw_qos_watermark_mismatch(const cfg_qos_watermark_intent *entry);
bool l2_hw_port_mirror_mismatch(const cfg_port_mirror_intent *intent);
bool l2_hw_mtu_mismatch(const cfg_port_ref *port, int mtu);
bool l2_hw_speed_mismatch(const cfg_port_ref *port, int speed_mbps);
bool l2_hw_pvid_mismatch(const cfg_port_ref *port, int vid);

int l2_validate_interface_intent(const cfg_port_ref *port,
                                 const cfg_if_intent *intent,
                                 char *err, size_t err_size);
int l2_validate_duplicate_vlan_ids(nl_yang_session *ys,
                                   char *err, size_t err_size);
int l2_validate_mac_aging_time(nl_yang_session *ys,
                               char *err, size_t err_size);
int l2_validate_configured_interfaces(nl_yang_session *ys,
                                      const cfg_port_ref *ports,
                                      int n_ports,
                                      char *err, size_t err_size);
int l2_validate_rstp_intents(nl_yang_session *ys,
                             const cfg_port_ref *ports, int n_ports,
                             char *err, size_t err_size);
int l2_validate_lldp_intents(nl_yang_session *ys,
                             const cfg_port_ref *ports, int n_ports,
                             char *err, size_t err_size);
int l2_validate_secure_access_intents(nl_yang_session *ys,
                                      const cfg_port_ref *ports, int n_ports,
                                      char *err, size_t err_size);
int l2_validate_mac_move_intents(nl_yang_session *ys,
                                 char *err, size_t err_size);
int l2_validate_l2_security_intents(nl_yang_session *ys,
                                    const cfg_port_ref *ports, int n_ports,
                                    char *err, size_t err_size);
int l2_validate_dhcp_binding_intents(nl_yang_session *ys,
                                     const cfg_port_ref *ports, int n_ports,
                                     char *err, size_t err_size);
int l2_validate_user_filter_intents(nl_yang_session *ys,
                                    const cfg_port_ref *ports, int n_ports,
                                    char *err, size_t err_size);
int l2_validate_ingress_ipv4_acl_intents(nl_yang_session *ys,
                                         const cfg_port_ref *ports,
                                         int n_ports,
                                         char *err, size_t err_size);
int l2_validate_acl_policer_intents(nl_yang_session *ys,
                                    const cfg_port_ref *ports,
                                    int n_ports,
                                    char *err, size_t err_size);
int l2_validate_egress_acl_intents(nl_yang_session *ys,
                                   const cfg_port_ref *ports,
                                   int n_ports,
                                   char *err, size_t err_size);
int l2_validate_acl_independent_intents(nl_yang_session *ys,
                                        const cfg_port_ref *ports,
                                        int n_ports,
                                        char *err, size_t err_size);
int l2_validate_l2_security_capacity(nl_yang_session *ys,
                                     const cfg_port_ref *ports, int n_ports,
                                     char *err, size_t err_size);
int l2_validate_storm_control_intents(nl_yang_session *ys,
                                      const cfg_port_ref *ports, int n_ports,
                                      char *err, size_t err_size);
int l2_validate_ingress_rate_limit_intents(nl_yang_session *ys,
                                           const cfg_port_ref *ports,
                                           int n_ports,
                                           char *err, size_t err_size);
int l2_validate_rate_controller_capacity(nl_yang_session *ys,
                                         char *err, size_t err_size);
int l2_validate_egress_rate_limit_intents(nl_yang_session *ys,
                                          const cfg_port_ref *ports,
                                          int n_ports,
                                          char *err, size_t err_size);
int l2_validate_qos_intents(nl_yang_session *ys,
                            const cfg_port_ref *ports, int n_ports,
                            char *err, size_t err_size);
int l2_validate_lag_intents(nl_yang_session *ys,
                            const cfg_port_ref *ports, int n_ports,
                            char *err, size_t err_size);
int l2_validate_static_mac_intents(nl_yang_session *ys,
                                   const cfg_port_ref *ports, int n_ports,
                                   char *err, size_t err_size);
int l2_validate_port_mirror_intent(nl_yang_session *ys,
                                   const cfg_port_ref *ports, int n_ports,
                                   char *err, size_t err_size);
int l2_validate_igmp_snooping_intents(nl_yang_session *ys,
                                      const cfg_port_ref *ports,
                                      int n_ports,
                                      char *err, size_t err_size);

#endif
