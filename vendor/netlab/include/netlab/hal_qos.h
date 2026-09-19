/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_HAL_QOS_H
#define NETLAB_HAL_QOS_H

#include "types.h"
#include "storm_control.h"
#include "pfc_watchdog.h"

typedef enum {
    HAL_QOS_TRUST_NONE = 0,
    HAL_QOS_TRUST_IEEE8021P = 1,
    HAL_QOS_TRUST_DSCP = 2,
} hal_qos_trust_mode;

typedef struct {
    int port;
    int controller;
    nl_storm_kind kind;
    int rate_kbps;
    int burst_bytes;
    u64 packets;
} hal_storm_control_entry;

typedef struct {
    int port;
    int shaping_group;
    int rate_kbps;
    int burst_bytes;
} hal_egress_rate_limit_entry;

typedef struct {
    int port;
    int trust_mode;
    int default_priority;
} hal_qos_interface_entry;

typedef struct {
    int switch_priority;
    int traffic_class;
} hal_qos_priority_map_entry;

typedef struct {
    int auto_pause_mode;
    int drop_pause;
    int pause_smac_valid;
    u64 pause_smac;
    int tc_smp_map[8];
    int roce_buffer_status;
    int smp_usage[2];
} hal_qos_flow_control_global;

typedef struct {
    int port;
    int rx_pause;
    int rx_class_pause_mask;
    int tx_pause_mode;
    int tx_class_pause_mask;
    int smp_lossless_pause_mask;
    int shared_pause_enable_mask;
    int tx_pause_quanta;
    int tx_pause_resend_time_ns;
    int tc3_usage, rx_smp0_usage, rx_smp1_usage, tc3_pause_class;
    int pc3_smp; /* PFC generation: 0/1 = SMP, 2 = always pause OFF. */
    int pause_state_status, paused_class_mask, generated_smp_pause_mask;
    int rx_pause_quanta[8];
    int cnp_tc_usage;
    int rx_class_mask_hardware;
    hal_pfc_wd_status watchdog;
} hal_qos_flow_control_entry;

#define HAL_QOS_MAX_TRAFFIC_CLASSES 8
#define HAL_QOS_MAX_SCHED_GROUPS 8
#define HAL_QOS_MAX_SWITCH_PRIORITIES 16
#define HAL_QOS_MAX_MEMORY_PARTITIONS 2

typedef struct {
    int port;
    int num_sched_groups;
    int free_bandwidth_percent;
    int traffic_class_enable_mask;
    int traffic_class_zero_length_mask;
    int tc_shaping_group_map[HAL_QOS_MAX_TRAFFIC_CLASSES];
    int group_priset[HAL_QOS_MAX_SCHED_GROUPS];
    int group_strict[HAL_QOS_MAX_SCHED_GROUPS];
    int group_weight[HAL_QOS_MAX_SCHED_GROUPS];
    int group_tc_boundary_a[HAL_QOS_MAX_SCHED_GROUPS];
    int group_tc_boundary_b[HAL_QOS_MAX_SCHED_GROUPS];
    int group_rate_supported[HAL_QOS_MAX_SCHED_GROUPS];
    int group_rate_default[HAL_QOS_MAX_SCHED_GROUPS];
    u64 group_rate_bps[HAL_QOS_MAX_SCHED_GROUPS];
    int group_burst_supported[HAL_QOS_MAX_SCHED_GROUPS];
    u64 group_burst_bits[HAL_QOS_MAX_SCHED_GROUPS];
} hal_qos_scheduler_entry;

typedef struct {
    int port;
    int queue_id;
    int present;
    int sdk_status;
    int traffic_class;
    u64 min_bw_mbps;
    u64 max_bw_mbps;
    int max_bw_default;
} hal_qos_queue_entry;

typedef struct {
    int port;
    int queue_id;
    int traffic_class;
    u64 min_bw_mbps;
    u64 max_bw_mbps;
    int max_bw_default;
} hal_qos_queue_probe_args;

typedef struct {
    bool ok;
    int port;
    int queue_id;
    int traffic_class;
    u64 min_bw_mbps;
    u64 max_bw_mbps;
    int max_bw_default;
    int pre_status;
    int add_status;
    int set_tc_status;
    int set_min_status;
    int set_max_status;
    int read_status;
    int delete_status;
    int post_read_status;
    int cleanup_status;
    int post_present;
    char detail[160];
} hal_qos_queue_probe_result;

typedef hal_qos_queue_probe_args hal_qos_queue_owner_args;

typedef struct {
    bool ok;
    bool active;
    int port;
    int queue_id;
    int traffic_class;
    u64 min_bw_mbps;
    u64 max_bw_mbps;
    int max_bw_default;
    int pre_present;
    int pre_status;
    int add_status;
    int set_tc_status;
    int set_min_status;
    int set_max_status;
    int read_status;
    int rollback_status;
    int post_read_status;
    int post_present;
    int compared;
    int mismatches;
    char detail[160];
} hal_qos_queue_owner_result;

#define HAL_QOS_QUEUE_PROFILE_MAX_QUEUES 8

typedef struct {
    int queue_id;
    int traffic_class;
    u64 min_bw_mbps;
    u64 max_bw_mbps;
    int max_bw_default;
} hal_qos_queue_profile_item;

typedef struct {
    int port;
    int queue_count;
    hal_qos_queue_profile_item queue[HAL_QOS_QUEUE_PROFILE_MAX_QUEUES];
} hal_qos_queue_profile_owner_args;

typedef struct {
    int queue_id;
    int traffic_class;
    u64 min_bw_mbps;
    u64 max_bw_mbps;
    int max_bw_default;
    int pre_present;
    int pre_status;
    int add_status;
    int set_tc_status;
    int set_min_status;
    int set_max_status;
    int read_status;
    int rollback_status;
    int post_read_status;
    int post_present;
    int compared;
    int mismatches;
} hal_qos_queue_profile_item_result;

typedef struct {
    bool ok;
    bool active;
    int port;
    int queue_count;
    int applied_count;
    int compared;
    int mismatches;
    int cleanup_status;
    char detail[160];
    hal_qos_queue_profile_item_result
        queue[HAL_QOS_QUEUE_PROFILE_MAX_QUEUES];
} hal_qos_queue_profile_owner_result;

typedef struct {
    int auto_pause_mode;
    int cn_mode;
    int cn_frame_etype;
    int cn_frame_vpri;
    int cn_frame_vlan;
    int cn_frame_src_port;
    int cn_frame_smac_valid;
    u64 cn_frame_smac;
    int cn_frame_dmac_valid;
    u64 cn_frame_dmac;
    int priv_wm;
    int high_wm;
    int low_wm;
    int shared_pause_on_wm[HAL_QOS_MAX_MEMORY_PARTITIONS];
    int shared_pause_off_wm[HAL_QOS_MAX_MEMORY_PARTITIONS];
    int shared_pri_wm[HAL_QOS_MAX_SWITCH_PRIORITIES];
    int shared_soft_drop_wm[HAL_QOS_MAX_SWITCH_PRIORITIES];
    int shared_soft_drop_jitter[HAL_QOS_MAX_SWITCH_PRIORITIES];
    int shared_soft_drop_hog[HAL_QOS_MAX_SWITCH_PRIORITIES];
} hal_qos_watermark_global;

typedef struct {
    int port;
    int tx_hog_wm[HAL_QOS_MAX_TRAFFIC_CLASSES];
    int tx_tc_private_wm[HAL_QOS_MAX_TRAFFIC_CLASSES];
    int rx_hog_wm[HAL_QOS_MAX_MEMORY_PARTITIONS];
    int rx_private_wm[HAL_QOS_MAX_MEMORY_PARTITIONS];
    int private_pause_on_wm[HAL_QOS_MAX_MEMORY_PARTITIONS];
    int private_pause_off_wm[HAL_QOS_MAX_MEMORY_PARTITIONS];
    int tx_soft_drop_on_private[HAL_QOS_MAX_SWITCH_PRIORITIES];
    int tx_soft_drop_on_rxmp_free[HAL_QOS_MAX_SWITCH_PRIORITIES];
} hal_qos_watermark_entry;

typedef enum {
    HAL_QOS_WATERMARK_SCOPE_PORT = 1,
    HAL_QOS_WATERMARK_SCOPE_SWITCH = 2,
} hal_qos_watermark_scope;

typedef enum {
    HAL_QOS_WATERMARK_ATTR_TX_HOG = 1,
    HAL_QOS_WATERMARK_ATTR_TX_PRIVATE = 2,
    HAL_QOS_WATERMARK_ATTR_RX_HOG = 3,
    HAL_QOS_WATERMARK_ATTR_RX_PRIVATE = 4,
    HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_ON = 5,
    HAL_QOS_WATERMARK_ATTR_PRIVATE_PAUSE_OFF = 6,
    HAL_QOS_WATERMARK_ATTR_SHARED_PRI = 7,
    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP = 8,
    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER = 9,
    HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG = 10,
    HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE = 11,
    HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE = 12,
} hal_qos_watermark_attr;

typedef struct {
    int scope;
    int port;
    int attr;
    int index;
    int value;
} hal_qos_watermark_owner_args;

typedef struct {
    bool ok;
    bool active;
    int scope;
    int port;
    int attr;
    int index;
    int requested_value;
    int original_value;
    int applied_value;
    int current_value;
    int pre_read_status;
    int set_status;
    int read_status;
    int rollback_status;
    int post_read_status;
    int compared;
    int mismatches;
    char detail[160];
} hal_qos_watermark_owner_result;

int hal_storm_control_set(int sw, int port, int rate_kbps, int burst_bytes);
int hal_storm_control_set_kind(int sw, int port, nl_storm_kind kind,
                                int rate_kbps, int burst_bytes);
int hal_storm_control_delete_kind(int sw, int port, nl_storm_kind kind);
int hal_storm_control_get_kind(int sw, int port, nl_storm_kind kind,
                                hal_storm_control_entry *entry);
int hal_storm_control_delete(int sw, int port);
int hal_storm_control_get(int sw, int port,
                          hal_storm_control_entry *entry);
int hal_storm_control_list(int sw, hal_storm_control_entry *entries,
                           int max_entries);
int hal_ingress_rate_limit_set(int sw, int port, int rate_kbps,
                               int burst_bytes);
int hal_ingress_rate_limit_delete(int sw, int port);
int hal_ingress_rate_limit_get(int sw, int port,
                               hal_storm_control_entry *entry);
int hal_ingress_rate_limit_list(int sw, hal_storm_control_entry *entries,
                                int max_entries);
int hal_egress_rate_limit_set(int sw, int port, int rate_kbps,
                              int burst_bytes);
int hal_egress_rate_limit_delete(int sw, int port);
int hal_egress_rate_limit_get(int sw, int port,
                              hal_egress_rate_limit_entry *entry);
int hal_egress_rate_limit_snapshot(
    int sw, int port, bool *present,
    hal_egress_rate_limit_entry *entry);
int hal_egress_rate_limit_list(int sw,
                               hal_egress_rate_limit_entry *entries,
                               int max_entries);
int hal_qos_interface_set(int sw, int port, int trust_mode,
                          int default_priority);
int hal_qos_interface_delete(int sw, int port);
int hal_qos_interface_get(int sw, int port,
                          hal_qos_interface_entry *entry);
int hal_qos_interface_list(int sw, hal_qos_interface_entry *entries,
                           int max_entries);
int hal_qos_priority_map_set(int sw, int switch_priority,
                             int traffic_class);
int hal_qos_priority_map_delete(int sw, int switch_priority);
int hal_qos_priority_map_get(int sw, int switch_priority,
                             hal_qos_priority_map_entry *entry);
int hal_qos_priority_map_list(int sw,
                              hal_qos_priority_map_entry *entries,
                              int max_entries);
int hal_qos_flow_control_global_get(int sw,
                                    hal_qos_flow_control_global *global);
int hal_qos_flow_control_get(int sw, int port,
                             hal_qos_flow_control_entry *entry);
int hal_qos_flow_control_list(int sw,
                              hal_qos_flow_control_entry *entries,
                              int max_entries);
int hal_qos_pause_state_get(int sw, hal_qos_flow_control_entry *entry);
int hal_qos_scheduler_get(int sw, int port,
                          hal_qos_scheduler_entry *entry);
int hal_qos_scheduler_list(int sw,
                           hal_qos_scheduler_entry *entries,
                           int max_entries);
int hal_qos_scheduler_tc_map_set(int sw, int port, int traffic_class,
                                 int shaping_group);
int hal_qos_scheduler_tc_map_delete(int sw, int port, int traffic_class);
int hal_qos_scheduler_tc_map_get(int sw, int port, int traffic_class,
                                 int *shaping_group);
int hal_qos_scheduler_group_set(int sw, int port, int group,
                                int strict_priority, int weight);
int hal_qos_scheduler_group_delete(int sw, int port, int group);
int hal_qos_scheduler_group_get(int sw, int port, int group,
                                int *strict_priority, int *weight);
int hal_qos_scheduler_group_shaping_set(int sw, int port, int group,
                                        u64 rate_bps, u64 burst_bits);
int hal_qos_scheduler_group_shaping_delete(int sw, int port, int group);
int hal_qos_scheduler_group_shaping_get(int sw, int port, int group,
                                        u64 *rate_bps, u64 *burst_bits);
int hal_qos_scheduler_group_shaping_snapshot(
    int sw, int port, int group, bool *present,
    u64 *rate_bps, u64 *burst_bits);
int hal_qos_scheduler_port_set(int sw, int port,
                               int traffic_class_enable_mask);
int hal_qos_scheduler_port_delete(int sw, int port);
int hal_qos_scheduler_port_get(int sw, int port,
                               int *traffic_class_enable_mask);
int hal_qos_queue_get(int sw, int port, int queue_id,
                      hal_qos_queue_entry *entry);
int hal_qos_queue_list(int sw, hal_qos_queue_entry *entries,
                       int max_entries);
int hal_qos_queue_probe(int sw,
                        const hal_qos_queue_probe_args *args,
                        hal_qos_queue_probe_result *result);
int hal_qos_queue_owner_apply(int sw,
                              const hal_qos_queue_owner_args *args,
                              hal_qos_queue_owner_result *result);
int hal_qos_queue_owner_readback(int sw,
                                 hal_qos_queue_owner_result *result);
int hal_qos_queue_owner_rollback(int sw,
                                 hal_qos_queue_owner_result *result);
int hal_qos_queue_profile_owner_apply(
    int sw,
    const hal_qos_queue_profile_owner_args *args,
    hal_qos_queue_profile_owner_result *result);
int hal_qos_queue_profile_owner_readback(
    int sw,
    hal_qos_queue_profile_owner_result *result);
int hal_qos_queue_profile_owner_rollback(
    int sw,
    hal_qos_queue_profile_owner_result *result);
int hal_qos_watermark_global_get(int sw,
                                 hal_qos_watermark_global *global);
int hal_qos_watermark_get(int sw, int port,
                          hal_qos_watermark_entry *entry);
int hal_qos_watermark_list(int sw,
                           hal_qos_watermark_entry *entries,
                           int max_entries);
int hal_qos_watermark_set(int sw, int port, int attr, int index, int value);
int hal_qos_watermark_delete(int sw, int port, int attr, int index);
int hal_qos_watermark_read(int sw, int port, int attr, int index,
                           int *value);
int hal_qos_watermark_owner_apply(
    int sw,
    const hal_qos_watermark_owner_args *args,
    hal_qos_watermark_owner_result *result);
int hal_qos_watermark_owner_readback(
    int sw,
    hal_qos_watermark_owner_result *result);
int hal_qos_watermark_owner_rollback(
    int sw,
    hal_qos_watermark_owner_result *result);
int hal_qos_tc_smp_get(int sw, int tc, int *smp);
int hal_qos_tc_smp_set(int sw, int tc, int smp);
int hal_qos_dscp_get(int sw, int dscp, int *priority);
int hal_qos_dscp_set(int sw, int dscp, int priority);
int hal_qos_dscp_list(int sw, int priorities[64]);
int hal_qos_roce_buffer_ready(int sw);
int hal_qos_pfc_pc3_smp_set(int sw, int port, int smp);

int hal_qos_pfc_apply(int sw, int port, int rx_class_mask,
                      int tx_pause_mode, int tx_class_mask,
                      int lossless_smp_mask, int shared_pause_mask);
int hal_qos_pfc_delete(int sw, int port);

#endif
