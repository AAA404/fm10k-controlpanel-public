#ifndef L2D_SWITCHD_H
#define L2D_SWITCHD_H

#include <stdbool.h>
#include "l2d_state.h"
#include "netlab/acl_counter_snapshot.h"
#include "netlab/stp_snapshot.h"
#include "netlab/types.h"

bool l2d_switchd_reachable(const char *socket_path);
bool l2d_switchd_vlan_exists(const char *socket_path, int vid);
int l2d_switchd_set_runtime_admin(const char *socket_path, int port, int mode);
int l2d_switchd_clear_dynamic_macs(const char *socket_path, int port);
int l2d_switchd_set_port_security(const char *socket_path, int port,
                                  bool enable, const char *action);
int l2d_switchd_get_mac_snapshot(const char *socket_path, void *resp,
                                 int resp_max);
int l2d_switchd_get_mac_update_events(const char *socket_path, char *resp,
                                      int resp_max);
int l2d_switchd_get_lag_table(const char *socket_path, char *resp,
                              int resp_max);
int l2d_switchd_get_stp_snapshot(const char *socket_path,
                                 nl_stp_snapshot *snapshot);
int l2d_switchd_get_port_mirroring(const char *socket_path, char *resp,
                                   int resp_max);
int l2d_switchd_get_user_filter_counters(const char *socket_path, int vid,
                                         int port, const char *mac_kind,
                                         const char *mac, u64 *packets,
                                         u64 *octets, char *state,
                                         int state_max);
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
    u64 *packets, u64 *octets, char *state, int state_max);
int l2d_switchd_get_egress_acl_counters(const char *socket_path, int port,
                                        u64 *packets, u64 *octets,
                                        char *state, int state_max);
int l2d_switchd_get_acl_policer_counters(
    const char *socket_path, int port, const char *dst_mac,
    int rate_kbps, int burst_bytes, u64 *packets, u64 *octets,
    char *state, int state_max);
int l2d_switchd_get_acl_independent_counters(
    const char *socket_path, const l2_acl_independent *entry, int port,
    u64 *packets, u64 *octets, char *state, int state_max);
int l2d_switchd_get_acl_counter_snapshot(
    const char *socket_path, const nl_acl_counter_query *query,
    nl_acl_counter_snapshot *snapshot);
int l2d_switchd_apply_igmp_listener(const char *socket_path, bool add,
                                    int vid, int port, const char *group,
                                    u64 txid);
int l2d_switchd_get_multicast_owner(const char *socket_path, char *resp,
                                    int resp_max);

#endif
