/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_HAL_H
#define NETLAB_HAL_H

#include "types.h"
#include "error.h"
#include "ipc.h"
#include "l2_plan.h"
#include "pfe_capability.h"
#include "hal_qos.h"
#include "hal_fm10k.h"
#include "hal_transaction_snapshot.h"
#include "hal_acl_owner_transaction.h"
#include "hal_flow_table_token.h"
#include "mac_snapshot.h"
#include "stp_snapshot.h"
#include "acl_counter_snapshot.h"
#include "l3_capacity.h"
#include "sflow.h"

#define NETLAB_L2_MCAST_OWNER_MAX (128 * 1024)

// SDK operation types
typedef enum {
    SDK_OP_NONE,
    SDK_OP_PORT_SET_ADMIN,
    SDK_OP_PORT_SET_SPEED,
    SDK_OP_PORT_SET_MTU,
    SDK_OP_VLAN_CREATE,
    SDK_OP_VLAN_DELETE,
    SDK_OP_VLAN_ADD_PORT,
    SDK_OP_VLAN_REM_PORT,
    SDK_OP_PVID_SET,
    SDK_OP_ROUTE_ADD,
    SDK_OP_ROUTE_DELETE,
    SDK_OP_VLAN_STP_SET,
    SDK_OP_RUNTIME_STP_SET,
    SDK_OP_PORT_PARSER_SET,
    SDK_OP_GET_PORT_STATE,
    SDK_OP_GET_COUNTERS,
    SDK_OP_RESET_COUNTERS,
    SDK_OP_GET_XCVR,
    SDK_OP_GET_TEMPERATURE,
    SDK_OP_GET_MAC_TABLE,
    SDK_OP_CLEAR_DYNAMIC_MAC_TABLE,
    SDK_OP_GET_MAC_AGING_TIME,
    SDK_OP_GET_STP_TABLE,
    SDK_OP_GET_VLAN_STATE,
    SDK_OP_PACKET_TX,
    SDK_OP_PACKET_RX_POLL,
    SDK_OP_LAG_DELETE,
    SDK_OP_LAG_ADD_PORT,
    SDK_OP_LAG_DEL_PORT,
    SDK_OP_LAG_GET_ALL,
    SDK_OP_GET_PFE_RESOURCES,
    SDK_OP_GET_SWITCH_SENSORS,
    SDK_OP_GET_SWITCH_CONFIG,
    SDK_OP_GET_CONTROL_PLANE_PROTECTION,
    SDK_OP_PORT_SECURITY_SET,
    SDK_OP_GET_L2_SECURITY_USER_FILTER_COUNTERS,
    SDK_OP_GET_INGRESS_IPV4_ACL_COUNTERS,
    SDK_OP_GET_EGRESS_ACL_COUNTERS,
    SDK_OP_GET_ACL_POLICER_COUNTERS,
    SDK_OP_GET_ACL_INDEPENDENT_COUNTERS,
    SDK_OP_GET_ACL_COUNTER_SNAPSHOT,
    SDK_OP_ACL_POLICER_PROBE,
    SDK_OP_ACL_POLICER_OWNER_APPLY,
    SDK_OP_ACL_POLICER_OWNER_READBACK,
    SDK_OP_ACL_POLICER_OWNER_ROLLBACK,
    SDK_OP_ACL_EGRESS_PROBE,
    SDK_OP_ACL_GENERAL_ALLOCATOR_APPLY,
    SDK_OP_ACL_GENERAL_ALLOCATOR_READBACK,
    SDK_OP_ACL_GENERAL_ALLOCATOR_ROLLBACK,
    SDK_OP_QOS_QUEUE_PROBE,
    SDK_OP_QOS_QUEUE_OWNER_APPLY,
    SDK_OP_QOS_QUEUE_OWNER_READBACK,
    SDK_OP_QOS_QUEUE_OWNER_ROLLBACK,
    SDK_OP_QOS_QUEUE_PROFILE_OWNER_APPLY,
    SDK_OP_QOS_QUEUE_PROFILE_OWNER_READBACK,
    SDK_OP_QOS_QUEUE_PROFILE_OWNER_ROLLBACK,
    SDK_OP_QOS_WATERMARK_OWNER_APPLY,
    SDK_OP_QOS_WATERMARK_OWNER_READBACK,
    SDK_OP_QOS_WATERMARK_OWNER_ROLLBACK,
    SDK_OP_OPTICS_MUX_PROBE,
    SDK_OP_BOARD_ENV_GET,
    SDK_OP_L3_FIB_BATCH_APPLY,
    SDK_OP_L3_FIB_SNAPSHOT_BEGIN,
    SDK_OP_L3_FIB_SNAPSHOT_PART,
    SDK_OP_L3_FIB_SNAPSHOT_COMMIT,
    SDK_OP_L3_FIB_SNAPSHOT_ABORT,
    SDK_OP_PORT_RECOVERY_POLL,
    SDK_OP_GET_PORT_SNAPSHOT,
    SDK_OP_GET_QOS_READBACK,
    SDK_OP_L3_SDK_READBACK_PROBE,
    SDK_OP_L3_SDK_WRITE_CANARY,
    SDK_OP_L3_RUNTIME,
    SDK_OP_NOP,
    SDK_OP_GET_MIRROR_STATE,
    SDK_OP_GET_SFLOW_STATE,
    SDK_OP_SFLOW_LIVE_PROBE,
    SDK_OP_GET_L2_MCAST_OWNER,
    SDK_OP_APPLY_L2_PLAN,
    SDK_OP_ROLLBACK_L2_PLAN,
    SDK_OP_FM10K_BOARD_POLL,
    SDK_OP_FM10K_FAN_MANUAL,
    SDK_OP_FM10K_BOARD_SHUTDOWN,
    SDK_OP_FM10K_CONFIG_GET,
    /* Internal cold-start operation; never exposed as a management RPC. */
    SDK_OP_FM10K_BOOTSTRAP_CLOSED,
    SDK_OP_FM10K_PHY_GET,
    SDK_OP_FM10K_CONTROL_INIT,
    SDK_OP_COMMIT_MARK_SUCCESS,
    SDK_OP_COMMIT_MARK_FAILED,
    SDK_OP_FM10K_EYE_GET,
    SDK_OP_FM10K_EYE_CONTROL,
} sdk_op_type;
#define SDK_PRIO_CONTROL_PACKET 0
#define SDK_PRIO_CONFIG_CHANGE  1
#define SDK_PRIO_READBACK       2
#define SDK_PRIO_COUNTER        3
#define SDK_PRIO_PLATFORM_POLL  4
#define SDK_PRIO_COUNT          5

#define NETLAB_PACKET_IO_MAX    2048
#define NETLAB_XCVR_MAX_LANES   4
#define NETLAB_OPTICS_MUX_MAX_BRANCHES 2
#define NETLAB_OPTICS_MUX_MAX_ADDRS 41
#define NETLAB_OPTICS_MUX_DUMP_LEN 256
#define NETLAB_OPTICS_MUX_SCAN_MIN 0x03
#define NETLAB_OPTICS_MUX_SCAN_MAX 0x77
#define NETLAB_OPTICS_MUX_SCAN_COUNT \
    (NETLAB_OPTICS_MUX_SCAN_MAX - NETLAB_OPTICS_MUX_SCAN_MIN + 1)
#define NETLAB_MAX_AE           64
#define NETLAB_MAX_LAG_MEMBERS  64
#define NETLAB_MIRROR_V1_GROUP  0
#define NETLAB_MIRROR_MAX_SOURCES 32
#define NETLAB_SWITCH_SENSOR_MAX 17
#define NETLAB_SWITCH_CONFIG_MAX_FIELDS 96
#define NETLAB_BOARD_ENV_MAX_SENSORS 24
#define NETLAB_BOARD_ENV_MAX_RESPONDERS 12
#define NETLAB_BOARD_ENV_RAW_MAX 16
#define NETLAB_PORT_SNAPSHOT_MAX 64
#define NETLAB_QOS_READBACK_MAX_PORTS NETLAB_PORT_SNAPSHOT_MAX
#define NETLAB_QOS_READBACK_MAX_QUEUES \
    (NETLAB_QOS_READBACK_MAX_PORTS * HAL_QOS_MAX_TRAFFIC_CLASSES)
#define NETLAB_L3_SDK_READBACK_RESPONSE_MAX 16384
#define NETLAB_L3_SDK_CANARY_RESPONSE_MAX 4096
#define NETLAB_L3_RUNTIME_RESPONSE_MAX 65536
#define NETLAB_SFLOW_PROBE_RESPONSE_MAX NL_SFLOW_V1_PROBE_RESPONSE_MAX
// This SDK release implements fmGetPortState() with an eight-slot V3 buffer.
#define NETLAB_PORT_STATE_INFO_SLOTS 8
#define NETLAB_FLOW_TABLE_OWNER_MAX 16
#define NETLAB_FLOW_OWNER_NAME_MAX 32

/*
 * Non-idempotent LAG creation is authorized by the complete live handle set,
 * not by the SDK output argument.  A transaction may release its before-image
 * only after this global set is read back exactly.
 */
typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    int count;
    int lag_ids[NETLAB_MAX_AE];
} hal_lag_handle_set_snapshot;
#define NETLAB_ACL_RESOURCE_OWNER_MAX 8
#define NETLAB_CP_PROTECTION_CLASS_MAX 12
#define NETLAB_CP_PROTECTION_NAME_MAX 32
#define NETLAB_CP_PROTECTION_FIELD_MAX 64
#define NETLAB_MAC_UPDATE_RING_MAX 2048
#define NETLAB_ACL_GENERAL_PROFILE_MAX 32
#define NETLAB_ACL_INDEPENDENT_NAME_MAX 64
#define NETLAB_ACL_INDEPENDENT_FAMILY_MAX 16
#define NETLAB_ACL_INDEPENDENT_ACTION_MAX 16

struct sdk_pre_state {
    struct { int port; int mode; int speed; int mtu; } port;
};

typedef struct {
    int table;
    int owner;
    int capacity;
    int used;
    int free;
    int max_actions;
    int condition;
    char name[NETLAB_FLOW_OWNER_NAME_MAX];
} nl_flow_table_owner_resource;

typedef struct {
    int acl;
    int acl_count;
    int rules_per_acl;
    int owner;
    int first_policer;
    int policer_count;
    char name[NETLAB_FLOW_OWNER_NAME_MAX];
} nl_acl_resource_owner_resource;

typedef struct {
    int profile_ports, profile_switches, profile_lanes;
    int profile_xcvrs, profile_max_ae;
    int mac_capacity, mac_used, mac_static, mac_dynamic;
    int mac_multicast, mac_internal, mac_visible, mac_truncated;
    int mac_aging_time, mac_raw_bytes, mac_entry_size;
    int vlan_capacity, vlan_used, vlan_memberships;
    int lag_capacity, lag_used, lag_members, lag_member_capacity;
    int mcast_capacity, mcast_used, mcast_listeners;
    int mcast_listeners_free;
    int storm_capacity, storm_used;
    int policer_used;
    int flow_tables, flow_entries_capacity, flow_entries_used;
    int flow_entries_free;
    int control_plane_rules, control_plane_packets;
    int control_plane_octets;
    int control_plane_table, control_plane_capacity;
    int control_plane_free;
    int acl_count;
    int ffu_ipv4_uc_first, ffu_ipv4_uc_last;
    int ffu_ipv4_mc_first, ffu_ipv4_mc_last;
    int ffu_ipv6_uc_first, ffu_ipv6_uc_last;
    int ffu_ipv6_mc_first, ffu_ipv6_mc_last;
    int ffu_acl_first, ffu_acl_last;
    int route_count, arp_used, ecmp_groups;
    int event_queue_drops, event_total, event_port;
    int event_table_updates, event_table_entries;
    int event_table_learned, event_table_aged, event_table_errors;
    int event_security, event_platform, event_unsupported;
    int event_parity_errors, event_logical_port;
    int event_cable_mismatch, event_over_temp;
    int event_switch, event_frame, event_software, event_sflow;
    int event_fibm_threshold, event_crm, event_arp;
    int event_purge_scan_complete, event_egress_timestamp;
    int event_packet_enqueued;
    int event_last, event_last_unsupported;
    int event_last_port, event_last_vlan, event_last_lane;
    int event_last_mac, event_last_status;
    int event_last_temperature, event_last_crm_id;
    int event_last_fibm_retries;
    int event_last_parity_type, event_last_parity_severity;
    int event_last_parity_area, event_last_parity_status;
    int event_last_parity_sram;
    int event_last_logical_first, event_last_logical_count;
    int event_last_logical_pep_id, event_last_logical_pep_port;
    int event_last_logical_created;
    int event_last_platform_type, event_last_software_events;
    int event_last_switch_slot;
    int event_last_arp_sip, event_last_arp_dip, event_last_arp_ipv6;
    int event_last_egress_port;
    int event_tcn_interrupts, event_tcn_pending, event_tcn_overflow;
    int event_tcn_fifo_errors;
    int event_tcn_learned_events, event_tcn_moved_events;
    int event_mac_learned_debug, event_mac_aged_debug;
    int event_mac_port_changed, event_mac_learn_discarded;
    int event_mac_vlan_errors, event_mac_security;
    int event_mac_work_service_fifo, event_mac_work_fifo_events;
    int fm10000_epl_interrupts, fm10000_link_change_events;
    int fm10000_link_change_lost, fm10000_egress_timestamp_events;
    int fm10000_egress_timestamp_lost;
    int fm10000_parity_area_epl, fm10000_parity_area_policer;
    int fm10000_parity_area_policer_u_err;
    int fm10000_parity_area_policer_c_err;
    int fm10000_parity_severity_transient;
    int fm10000_parity_severity_repairable;
    int fm10000_parity_severity_cumulative;
    int fm10000_parity_severity_fatal;
    int fm10000_parity_status_fixed;
    int fm10000_parity_status_fix_failed;
    int fm10000_sram_c_err_interrupt, fm10000_sram_u_err_interrupt;
    int fm10000_parity_event_lost, fm10000_parity_repair_invalid;
    int fm10000_crm_ip0, fm10000_crm_ip1, fm10000_crm_ip2;
    int fm10000_crm_im0, fm10000_crm_im1, fm10000_crm_im2;
    int fm10000_fibm_ip, fm10000_fibm_im;
    int fm10000_pcie_clk_ip, fm10000_pcie_clk_im;
    int fm10000_sbus_pcie_ip, fm10000_sbus_pcie_im;
    int fm10000_sram_err_ip0, fm10000_sram_err_ip1;
    int fm10000_sram_err_im0, fm10000_sram_err_im1;
    int fm10000_trigger_ip0, fm10000_trigger_ip1;
    int fm10000_trigger_im0, fm10000_trigger_im1;
    int fm10000_epl_pending_count, fm10000_epl_pending_mask;
    int fm10000_epl_error_pending_count, fm10000_epl_error_pending_mask;
    int fm10000_epl_fifo_error_count, fm10000_epl_fifo_error_mask;
    int fm10000_pcie_clk_xref_high, fm10000_pcie_clk_xref_low;
    int fm10000_pcie_clk_xpll_high, fm10000_pcie_clk_xpll_low;
    int fm10000_sbus_pcie_detect_high, fm10000_sbus_pcie_detect_low;
    int fm10000_trigger_pending_count;
    int fm10000_epl_an_pending_low, fm10000_epl_an_pending_high;
    int fm10000_epl_link_pending_low, fm10000_epl_link_pending_high;
    int fm10000_epl_serdes_pending_low, fm10000_epl_serdes_pending_high;
    int fm10000_epl_error_interrupt_mask;
    int fm10000_epl_jitter_uerr_low, fm10000_epl_jitter_uerr_high;
    int fm10000_epl_jitter_cerr_low, fm10000_epl_jitter_cerr_high;
    int fm10000_epl_rs_saf_uerr_mask;
    int fm10000_epl_fifo_tx_error_low, fm10000_epl_fifo_tx_error_high;
    int fm10000_epl_fifo_rx_error_low, fm10000_epl_fifo_rx_error_high;
    int flow_owner_count;
    nl_flow_table_owner_resource flow_owner[NETLAB_FLOW_TABLE_OWNER_MAX];
    int acl_owner_count;
    nl_acl_resource_owner_resource acl_owner[NETLAB_ACL_RESOURCE_OWNER_MAX];
} nl_pfe_resources;

typedef struct {
    char name[NETLAB_CP_PROTECTION_NAME_MAX];
    char protocol[NETLAB_CP_PROTECTION_NAME_MAX];
    char match[NETLAB_CP_PROTECTION_FIELD_MAX];
    char action[NETLAB_CP_PROTECTION_NAME_MAX];
    char enforcement[NETLAB_CP_PROTECTION_FIELD_MAX];
    char state[NETLAB_CP_PROTECTION_NAME_MAX];
    int table;
    int flow;
    int policer;
    int rate_kbps;
    int burst_bytes;
    u64 packets;
    u64 octets;
} nl_control_plane_protection_class;

typedef struct {
    int vid;
    int port;
    bool has_src_ip;
    bool has_dst_ip;
    bool has_src_ip_mask;
    bool has_dst_ip_mask;
    bool has_dscp;
    bool has_ecn;
    bool has_protocol;
    bool has_src_port;
    bool has_dst_port;
    bool has_src_port_range;
    bool has_dst_port_range;
    bool has_tcp_flags;
    bool has_tcp_flags_mask;
    bool count_only;
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
} hal_ingress_ipv4_acl_match;

typedef struct {
    int port;
    u64 dst_mac;
    int rate_kbps;
    int burst_bytes;
} hal_acl_policer_probe_args;

typedef hal_acl_policer_probe_args hal_acl_policer_owner_args;

typedef struct {
    int port;
    u64 src_mac;
    u64 dst_mac;
} hal_acl_egress_probe_args;

typedef hal_acl_egress_probe_args hal_acl_egress_owner_args;

typedef struct {
    char profile[NETLAB_ACL_GENERAL_PROFILE_MAX];
} hal_acl_general_allocator_args;

typedef struct {
    char group[NETLAB_ACL_INDEPENDENT_NAME_MAX];
    char term[NETLAB_ACL_INDEPENDENT_NAME_MAX];
    char family[NETLAB_ACL_INDEPENDENT_FAMILY_MAX];
    char action[NETLAB_ACL_INDEPENDENT_ACTION_MAX];
    int slot;
    int vid;
    int port;
    bool has_src_mac;
    bool has_dst_mac;
    u64 src_mac;
    u64 dst_mac;
    hal_ingress_ipv4_acl_match inet_match;
    int rate_kbps;
    int burst_bytes;
} hal_acl_independent_args;

typedef struct {
    bool ok;
    bool active;
    bool unsupported;
    int slot;
    int port;
    int acl;
    int rule;
    int policer;
    int port_set;
    int vid;
    u64 src_mac;
    u64 dst_mac;
    int rate_kbps;
    int burst_bytes;
    int read_status;
    int cleanup_status;
    int rollback_status;
    int compared;
    int mismatches;
    u64 packets;
    u64 octets;
    char detail[128];
} hal_acl_independent_result;

typedef struct {
    bool ok;
    int port;
    int acl;
    int rule;
    int policer;
    int port_set;
    u64 dst_mac;
    int rate_kbps;
    int burst_bytes;
    int create_status;
    int rule_status;
    int compile_status;
    int apply_status;
    int read_status;
    int cleanup_status;
    u64 packets;
    u64 octets;
    char detail[128];
} hal_acl_policer_probe_result;

typedef struct {
    bool ok;
    bool active;
    int slot;
    int port;
    int acl;
    int rule;
    int policer;
    int port_set;
    u64 dst_mac;
    int rate_kbps;
    int burst_bytes;
    int create_status;
    int rule_status;
    int compile_status;
    int apply_status;
    int read_status;
    int cleanup_status;
    int policer_read_status;
    int rollback_status;
    int rate_readback;
    int burst_readback;
    int compared;
    int mismatches;
    u64 packets;
    u64 octets;
    char detail[128];
} hal_acl_policer_owner_result;

typedef struct {
    bool ok;
    bool unsupported;
    int port;
    int acl;
    int rule;
    u64 src_mac;
    u64 dst_mac;
    int create_status;
    int pre_rule_status;
    int port_status;
    int rule_status;
    int compile_status;
    int apply_status;
    int read_status;
    int cleanup_status;
    int delete_acl_status;
    u64 packets;
    u64 octets;
    char detail[128];
} hal_acl_egress_probe_result;

typedef struct {
    bool ok;
    bool active;
    bool unsupported;
    int slot;
    int port;
    int acl;
    int rule;
    u64 src_mac;
    u64 dst_mac;
    int create_status;
    int pre_rule_status;
    int port_status;
    int rule_status;
    int compile_status;
    int apply_status;
    int read_status;
    int cleanup_status;
    int rollback_status;
    int compared;
    int mismatches;
    u64 packets;
    u64 octets;
    char detail[128];
} hal_acl_egress_owner_result;

typedef struct {
    bool ok;
    bool active;
    int ingress_acl_start;
    int ingress_acl_count;
    int ingress_rules_per_acl;
    int ingress_policer_start;
    int ingress_policer_count;
    int egress_acl_start;
    int egress_acl_count;
    int egress_rules_per_acl;
    int reserve_ingress_status;
    int reserve_egress_status;
    int rollback_ingress_status;
    int rollback_egress_status;
    int compiler_acl;
    int compiler_rule;
    int compiler_port;
    int compiler_port_set;
    int compiler_policer_rule;
    int compiler_policer;
    int compiler_profile_id;
    int compiler_term_count;
    u64 compiler_condition;
    u64 compiler_action;
    int compiler_create_status;
    int compiler_rule_status;
    int compiler_policer_status;
    int compiler_policer_rule_status;
    int compiler_compile_status;
    int compiler_apply_status;
    int compiler_read_status;
    int compiler_policer_read_status;
    int compiler_cleanup_status;
    u64 compiler_packets;
    u64 compiler_octets;
    u64 compiler_policer_packets;
    u64 compiler_policer_octets;
    int owner_count;
    int compared;
    int mismatches;
    char compiler_profile[NETLAB_ACL_GENERAL_PROFILE_MAX];
    char detail[128];
} hal_acl_general_allocator_result;

typedef struct {
    int addr;
    int page;
    int offset;
    int status;
    int length;
    u8 bytes[NETLAB_OPTICS_MUX_DUMP_LEN];
} hal_optics_mux_addr_dump;

typedef struct {
    int mux_value;
    int select_status;
    int control_after;
    int addr_count;
    int scan_start;
    int scan_count;
    int scan_status[NETLAB_OPTICS_MUX_SCAN_COUNT];
    hal_optics_mux_addr_dump addr[NETLAB_OPTICS_MUX_MAX_ADDRS];
} hal_optics_mux_branch_dump;

typedef struct {
    int bus;
    int mux_addr;
    int control_before;
    int restore_status;
    int branch_count;
    u64 generation;
    u64 sampled_monotonic_ms;
    bool complete;
    hal_optics_mux_branch_dump branch[NETLAB_OPTICS_MUX_MAX_BRANCHES];
} hal_optics_mux_probe_result;

typedef struct {
    char name[48];
    char sensor_class[16];
    char unit[16];
    char status[16];
    char chip[24];
    int branch;
    int addr;
    int reg;
    int raw_len;
    u8 raw[NETLAB_BOARD_ENV_RAW_MAX];
    float value;
    bool valid;
} hal_board_env_sensor;

typedef struct {
    char role[32];
    int branch;
    int addr;
    int status;
} hal_board_env_responder;

typedef struct {
    char board_model[64];
    int bus;
    int mux_addr;
    int mux_before;
    int restore_status;
    int sample_count;
    int sample_failures;
    int sensor_count;
    int responder_count;
    hal_board_env_sensor sensor[NETLAB_BOARD_ENV_MAX_SENSORS];
    hal_board_env_responder responder[NETLAB_BOARD_ENV_MAX_RESPONDERS];
} hal_board_env_result;

typedef struct {
    int mode;
    int state;
    int info[NETLAB_PORT_STATE_INFO_SLOTS];
    int speed;
    int ethernet_mode;
    int mtu;
    int max_frame;
    int pvid;
} hal_port_state;

typedef struct {
    u64 rx_bytes, tx_bytes, rx_pkts, tx_pkts;
    u64 rx_ucast_pkts, rx_mcast_pkts, rx_bcast_pkts;
    u64 tx_ucast_pkts, tx_mcast_pkts, tx_bcast_pkts;
    u64 rx_errors, tx_errors, rx_drops, tx_drops;
    u64 rx_fcs_errors, rx_symbol_errors, rx_frame_size_errors;
    u64 rx_pause_pkts, tx_pause_pkts;
    u64 rx_pfc_pkts, tx_pfc_pkts, rx_congestion_drops, tx_congestion_drops;
    u64 stp_drops, vlan_tag_drops, security_violations;
    u64 flood_control_drops, policer_drops, ttl_drops;
} hal_port_counters;

typedef struct {
    int port;
    int state_status;
    int counters_status;
    hal_port_state state;
    hal_port_counters counters;
} hal_port_snapshot_entry;

typedef struct {
    u64 generation;
    u64 sampled_monotonic_ms;
    int n_ports;
    int state_failures;
    int counter_failures;
    bool counters_included;
    hal_port_snapshot_entry ports[NETLAB_PORT_SNAPSHOT_MAX];
} hal_port_snapshot;

typedef struct {
    int lag_id;
    int ae_id;
    int logical_port;
    int logical_port_status;
    int member_status;
    int qos_status;
    int qos_trust;
    int qos_default_priority;
    int n_members;
    int members[NETLAB_MAX_LAG_MEMBERS];
} hal_lag_readback_entry;

typedef struct {
    int n_lags;
    hal_lag_readback_entry lag[NETLAB_MAX_AE];
} hal_lag_readback;

typedef enum {
    HAL_QOS_READBACK_STORM_CONTROL = 1,
    HAL_QOS_READBACK_INGRESS_RATE_LIMIT,
    HAL_QOS_READBACK_EGRESS_RATE_LIMIT,
    HAL_QOS_READBACK_INTERFACES,
    HAL_QOS_READBACK_PRIORITY_MAP,
    HAL_QOS_READBACK_FLOW_CONTROL,
    HAL_QOS_READBACK_SCHEDULERS,
    HAL_QOS_READBACK_QUEUES,
    HAL_QOS_READBACK_WATERMARKS,
    HAL_QOS_READBACK_DSCP_MAP,
} hal_qos_readback_kind;

typedef struct {
    int kind;
    int global_status;
    int n_entries;
    hal_qos_flow_control_global flow_control_global;
    hal_qos_watermark_global watermark_global;
    union {
        int dscp_map[64];
        hal_storm_control_entry
            storm_control[NETLAB_QOS_READBACK_MAX_PORTS];
        hal_egress_rate_limit_entry
            egress_rate_limit[NETLAB_QOS_READBACK_MAX_PORTS];
        hal_qos_interface_entry
            interfaces[NETLAB_QOS_READBACK_MAX_PORTS];
        hal_qos_priority_map_entry
            priority_map[HAL_QOS_MAX_SWITCH_PRIORITIES];
        hal_qos_flow_control_entry
            flow_control[NETLAB_QOS_READBACK_MAX_PORTS];
        hal_qos_scheduler_entry
            schedulers[NETLAB_QOS_READBACK_MAX_PORTS];
        hal_qos_queue_entry queues[NETLAB_QOS_READBACK_MAX_QUEUES];
        hal_qos_watermark_entry
            watermarks[NETLAB_QOS_READBACK_MAX_PORTS];
    } entries;
} hal_qos_readback;

typedef struct {
    char response[NETLAB_L3_SDK_READBACK_RESPONSE_MAX];
} hal_l3_sdk_readback_result;

typedef struct {
    char response[NETLAB_L3_SDK_CANARY_RESPONSE_MAX];
} hal_l3_sdk_canary_result;

typedef struct {
    char response[NETLAB_SFLOW_PROBE_RESPONSE_MAX];
} hal_sflow_probe_result;

typedef enum {
    HAL_L3_RUNTIME_HIDDEN_READBACK = 1,
    HAL_L3_RUNTIME_RIF_LIVE_PROBE,
    HAL_L3_RUNTIME_ARP_LIVE_PROBE,
    HAL_L3_RUNTIME_ECMP_LIVE_PROBE,
    HAL_L3_RUNTIME_ROUTE_LIVE_PROBE,
    HAL_L3_RUNTIME_PERSISTENT_APPLY,
    HAL_L3_RUNTIME_PERSISTENT_READBACK,
    HAL_L3_RUNTIME_PERSISTENT_ROLLBACK,
    HAL_L3_RUNTIME_FIB_READBACK,
    HAL_L3_RUNTIME_FIB_RECONCILE,
    HAL_L3_RUNTIME_FIB_ROLLBACK,
} hal_l3_runtime_kind;

typedef struct {
    char response[NETLAB_L3_RUNTIME_RESPONSE_MAX];
} hal_l3_runtime_result;

typedef enum {
    HAL_MIRROR_DIRECTION_INGRESS = 1,
    HAL_MIRROR_DIRECTION_EGRESS = 2,
    HAL_MIRROR_DIRECTION_BOTH = 3,
} hal_mirror_direction;

typedef struct {
    bool exists;
    bool exact_snapshot;
    bool attributes_valid;
    bool truncate;
    bool acl_filter;
    int group;
    int destination_port;
    int direction;
    int sample_rate;
    int encapsulation_vlan;
    int vlan_priority;
    int trapcode_id;
    int n_sources;
    int source_ports[NETLAB_MIRROR_MAX_SOURCES];
    int source_directions[NETLAB_MIRROR_MAX_SOURCES];
    int n_vlan_sources;
    u16 source_vlans[NETLAB_MIRROR_MAX_SOURCES];
    int source_vlan_selectors[NETLAB_MIRROR_MAX_SOURCES];
    int source_vlan_directions[NETLAB_MIRROR_MAX_SOURCES];
} hal_mirror_state;

// Forward declarations for types used by sdk_op
typedef struct l2_apply_plan l2_apply_plan;
struct sdk_context;
struct hw_state_tracker;

struct sdk_op {
    sdk_op_type type;
    /* Runtime protocol work must not survive a scoped configuration epoch. */
    u64 issued_at;
    bool runtime;
    union {
        struct { int port; int mode; int speed; int mtu; bool configuration_only; } port;
        struct { int pwm; int seconds; } fm10k_fan;
        struct { char command[160]; } fm10k_eye;
        struct { struct hw_state_tracker *tracker; u64 tx_id; } commit;
        struct { int port; int enable; int action; int strict; } port_security;
        struct { u16 vid; int port; bool tagged; int stp_state; } vlan;
        struct {
            u16 vid;
            int port;
            int mac_kind;
            u8 mac[NL_MAC_ADDR_LEN];
        } l2_security_counter;
        hal_ingress_ipv4_acl_match ingress_ipv4_acl;
        hal_acl_policer_probe_args acl_policer_probe;
        hal_acl_policer_owner_args acl_policer_owner;
        hal_acl_independent_args acl_independent;
        const nl_acl_counter_query *acl_counter_query;
        hal_acl_egress_probe_args acl_egress_probe;
        hal_acl_general_allocator_args acl_general_allocator;
        struct { int port; } egress_acl_counter;
        hal_qos_queue_probe_args qos_queue_probe;
        hal_qos_queue_owner_args qos_queue_owner;
        hal_qos_queue_profile_owner_args qos_queue_profile_owner;
        hal_qos_watermark_owner_args qos_watermark_owner;
        struct {
            int bus;
            int mux_addr;
            int branch[NETLAB_OPTICS_MUX_MAX_BRANCHES];
        } optics_mux_probe;
        struct {
            int sample;
            int bus;
            int mux_addr;
            int branch;
            int cpld_ram_addr;
            int reset_gpio_addr;
        } board_env;
        struct { int first; int count; } switch_sensors;
        struct { void *entry; } route;
        l2_apply_plan *apply_plan;
        struct { int port; int len; u8 data[NETLAB_PACKET_IO_MAX]; } pkt_tx;
        struct {
            const char *text;
            u64 tx_id;
            char *resp;
            size_t resp_size;
        } l3_fib_batch;
        struct { struct sdk_context *ctx; } port_recovery;
        struct { struct sdk_context *ctx; char netdev[64]; } fm10k_control;
        struct {
            int n_ports;
            int ports[NETLAB_PORT_SNAPSHOT_MAX];
            bool include_counters;
        } port_snapshot;
        struct { int lag_id; int port; u64 native_generation; } lag;
        struct { int kind; } qos_readback;
        struct { bool acknowledged; } l3_sdk_canary;
        struct {
            int port;
            bool acknowledged;
            u64 tx_id;
        } sflow_probe;
        struct {
            int kind;
            const char *text;
            bool acknowledged;
            bool live_readback;
            u64 tx_id;
            int hold_sec;
            char router_mac[32];
        } l3_runtime;
        struct { char *buf; size_t buf_size; } l2_mcast_owner;
    } args;
    struct sdk_pre_state pre_state;
};

struct sdk_result {
    int status;
    int sdk_status;
    const char *error_msg;
    union {
        hal_port_state port_state;
        struct { double expires_at; } fm10k_fan;
        nl_fm10k_config_snapshot fm10k_config;
        struct { char response[8192]; } fm10k_phy;
        hal_port_counters counters;
        hal_port_snapshot port_snapshot;
        struct {
            u8 present;
            u8 type;
            u8 dom_valid;
            u8 lane_count;
            float temp;
            float voltage;
            float tx_bias;
            float tx_power;
            float rx_power;
            struct {
                float tx_bias;
                float tx_power;
                float rx_power;
            } lane[NETLAB_XCVR_MAX_LANES];
        } xcvr;
        nl_mac_snapshot mac_table;
        struct { int seconds; } mac_aging;
        nl_stp_snapshot stp_table;
        struct { bool exists; } vlan_state;
        hal_lag_readback lag_list;
        hal_qos_readback qos_readback;
        hal_l3_sdk_readback_result l3_sdk_readback;
        hal_l3_sdk_canary_result l3_sdk_canary;
        nl_sflow_hw_state_v1 sflow_state;
        hal_sflow_probe_result sflow_probe;
        hal_l3_runtime_result l3_runtime;
        nl_pfe_resources pfe_resources;
        struct {
            int n_sensors;
            struct {
                int index;
                char label[48];
                char sensor_class[16];
                char unit[16];
                float value;
                bool valid;
            } sensor[NETLAB_SWITCH_SENSOR_MAX];
        } switch_sensors;
        struct {
            int n_fields;
            struct {
                char name[48];
                char value[128];
                char status[16];
            } field[NETLAB_SWITCH_CONFIG_MAX_FIELDS];
        } switch_config;
        struct {
            int n_classes;
            int table;
            int capacity;
            int free;
            int policers;
            nl_control_plane_protection_class
                classes[NETLAB_CP_PROTECTION_CLASS_MAX];
        } cp_protection;
        struct {
            bool found;
            int table;
            int flow;
            u64 packets;
            u64 octets;
        } l2_security_counter;
        struct {
            bool found;
            int table;
            int flow;
            u64 packets;
            u64 octets;
        } ingress_ipv4_acl_counter;
        struct {
            bool found;
            int port;
            u64 packets;
            u64 octets;
        } egress_acl_counter;
        hal_acl_policer_probe_result acl_policer_probe;
        hal_acl_policer_owner_result acl_policer_owner;
        hal_acl_independent_result acl_independent;
        nl_acl_counter_snapshot acl_counter_snapshot;
        hal_acl_egress_probe_result acl_egress_probe;
        hal_acl_general_allocator_result acl_general_allocator;
        hal_qos_queue_probe_result qos_queue_probe;
        hal_qos_queue_owner_result qos_queue_owner;
        hal_qos_queue_profile_owner_result qos_queue_profile_owner;
        hal_qos_watermark_owner_result qos_watermark_owner;
        hal_optics_mux_probe_result optics_mux_probe;
        hal_board_env_result board_env;
        hal_mirror_state mirror_state;
        struct { float temp_c; } temperature;
    } data;
};

struct verify_result {
    int        op_index;
    int        sdk_status;
    bool       readback_ok;
    char       detail[256];
    bool       fatal;
};

struct hw_state_tracker;

struct sdk_context {
    int sw;
    bool initialized;
    bool capture_started;
    bool event_delivery_started;
    bool switch_state_touched;
    bool switch_up;
    bool raw_socket_started;
    bool cleanup_failed;
    struct sdk_executor *exec;
    struct hw_state_tracker *hw_tracker;
    nl_pfe_capability pfe_cap;
    int cardinal_ports[64];
    int num_cardinal_ports;
    int port_admin_state[64];  // -1 unknown, 0 down, 1 up
    int port_link_state[64];   // -1 unknown, 0 down, 1 up
    int port_speed[64];
};

struct sdk_executor;

typedef struct {
    u32 queue_depth;
    u32 queue_high_watermark;
    u64 enqueued;
    u64 completed;
    u64 failed;
    u64 cancelled;
    u64 queue_full;
    u64 timed_out;
    u64 wait_avg_us;
    u64 wait_p50_us;
    u64 wait_p95_us;
    u64 wait_max_us;
    u64 exec_avg_us;
    u64 exec_p50_us;
    u64 exec_p95_us;
    u64 exec_max_us;
} sdk_executor_priority_stats;

typedef struct {
    bool running;
    u64 snapshot_generation;
    sdk_executor_priority_stats priority[SDK_PRIO_COUNT];
} sdk_executor_stats;

typedef struct {
    int port;
    int attempts;
    int unknown_polls;
    long last_attempt_age;
    long episode_elapsed_seconds;
    bool window_expired;
    bool exhausted;
} sdk_port_recovery_entry;

typedef struct {
    bool enabled;
    int window_seconds;
    int max_attempts;
    long last_poll_age;
    int n_ports;
    sdk_port_recovery_entry ports[NETLAB_PORT_SNAPSHOT_MAX];
} sdk_port_recovery_stats;

typedef struct {
    int event;
    int sw;
    char port_event[128];
    int switch_event;
    int table_update_count;
    int table_update_learned;
    int table_update_aged;
    int table_update_errors;
    int detail_port;
    int detail_vlan;
    int detail_lane;
    int detail_mac;
    int detail_status;
    int detail_temperature;
    int detail_crm_id;
    int detail_fibm_retries;
    int detail_parity_type;
    int detail_parity_severity;
    int detail_parity_area;
    int detail_parity_status;
    int detail_parity_sram;
    int detail_logical_first;
    int detail_logical_count;
    int detail_logical_pep_id;
    int detail_logical_pep_port;
    int detail_logical_created;
    int detail_platform_type;
    int detail_software_events;
    int detail_switch_slot;
    int detail_arp_sip;
    int detail_arp_dip;
    int detail_arp_ipv6;
    int detail_egress_port;
} sdk_event_t;

typedef struct {
    unsigned long queue_drops;
    unsigned long total;
    unsigned long port;
    unsigned long table_updates;
    unsigned long table_entries;
    unsigned long table_learned;
    unsigned long table_aged;
    unsigned long table_errors;
    unsigned long security;
    unsigned long platform;
    unsigned long unsupported;
    unsigned long parity_errors;
    unsigned long logical_port;
    unsigned long cable_mismatch;
    unsigned long over_temp;
    unsigned long switch_events;
    unsigned long frame;
    unsigned long software;
    unsigned long sflow;
    unsigned long fibm_threshold;
    unsigned long crm;
    unsigned long arp;
    unsigned long purge_scan_complete;
    unsigned long egress_timestamp;
    unsigned long packet_enqueued;
    int last_event;
    int last_unsupported_event;
    int last_port;
    int last_vlan;
    int last_lane;
    int last_mac;
    int last_status;
    int last_temperature;
    int last_crm_id;
    int last_fibm_retries;
    int last_parity_type;
    int last_parity_severity;
    int last_parity_area;
    int last_parity_status;
    int last_parity_sram;
    int last_logical_first;
    int last_logical_count;
    int last_logical_pep_id;
    int last_logical_pep_port;
    int last_logical_created;
    int last_platform_type;
    int last_software_events;
    int last_switch_slot;
    int last_arp_sip;
    int last_arp_dip;
    int last_arp_ipv6;
    int last_egress_port;
} sdk_event_stats_t;

// SDK bringup
int sdk_bringup(struct sdk_context **ctx);
int sdk_fm10k_control_initialize(struct sdk_context *ctx, const char *netdev);
int sdk_shutdown(struct sdk_context *ctx);
void sdk_port_recovery_poll(struct sdk_context *ctx);
void sdk_port_recovery_stats_snapshot(struct sdk_context *ctx,
                                      sdk_port_recovery_stats *stats);

// Executor
int sdk_executor_init(struct sdk_executor **exec, int sw);
void sdk_executor_shutdown(struct sdk_executor **exec);
void sdk_executor_stats_snapshot(struct sdk_executor *exec,
                                 sdk_executor_stats *stats);
int sdk_exec(struct sdk_executor *exec, struct sdk_op *op,
             struct sdk_result *result);
int sdk_exec_with_prio(struct sdk_executor *exec, struct sdk_op *op,
                       struct sdk_result *result,
                       int priority, u32 timeout_ms);
int sdk_exec_staged(struct sdk_executor *exec,
                    struct sdk_op *ops, int n_ops,
                    struct sdk_result *results);
int  sdk_exec_op_dispatch(int sw, struct sdk_op *op,
                          struct sdk_result *result);
int sdk_exec_undo(struct sdk_op *op);

// Event handler
void     sdk_event_queue_push(sdk_event_t *evt);
int      sdk_event_publisher_start(struct sdk_context *ctx);
void     sdk_event_publisher_stop(void);
void     sdk_event_stats_snapshot(sdk_event_stats_t *out);
void     sdk_mac_update_ring_record(int sw, int event, int reason,
                                    int index, int vlan, int port,
                                    int age, int locked, int valid,
                                    int addr_type, u64 mac);
int      sdk_mac_update_ring_format(char *buf, size_t buf_size);
void     sdk_port_cache_reset(struct sdk_context *ctx);
void     sdk_port_cache_set(struct sdk_context *ctx, int port,
                            int admin_state, int link_state, int speed);
int      sdk_port_cache_get(struct sdk_context *ctx, int port,
                            int *admin_state, int *link_state, int *speed);

// HW state tracker
int hw_state_tracker_init(struct hw_state_tracker **out);
void hw_state_tracker_destroy(struct hw_state_tracker **tracker);
int hw_state_tracker_record_pre(struct sdk_op *op);
int hw_state_tracker_reserve_l2(struct hw_state_tracker *tracker, u64 tx_id,
                                const l2_apply_plan *plan,
                                l2_apply_plan **owned_plan);
int hw_state_tracker_finish_l2_apply(struct hw_state_tracker *tracker,
                                     u64 tx_id, int apply_status);
int hw_state_tracker_begin_l2_rollback(struct hw_state_tracker *tracker,
                                       u64 tx_id,
                                       l2_apply_plan **owned_plan,
                                       bool *already_rolled_back);
int hw_state_tracker_finish_l2_rollback(struct hw_state_tracker *tracker,
                                        u64 tx_id, int rollback_status);
int hw_state_tracker_begin_l2_mutation(struct hw_state_tracker *tracker);
void hw_state_tracker_end_l2_mutation(struct hw_state_tracker *tracker);

// Commit finalizer
int hal_commit_mark_success(struct hw_state_tracker *tracker,
                            u64 tx_id, const char *hash);
int hal_commit_mark_failed(struct hw_state_tracker *tracker, u64 tx_id);
int hal_commit_abort(struct hw_state_tracker *tracker, u64 tx_id);

// HAL port
int hal_port_effective_admin_mode(int mode);
int hal_port_set_admin_state(int sw, int port, int mode);
int hal_port_retrain(int sw, int port);
int hal_port_get_state(int sw, int port, int *mode);
int hal_port_set_speed(int sw, int port, int speed);
int hal_port_restore_speed(
    int sw, int port, int speed, int ethernet_mode,
    const hal_port_admin_transaction_snapshot *admin_snapshot);
int hal_port_set_ethernet_mode(int sw, int port, int ethernet_mode);
bool hal_port_ethernet_mode_restorable(int ethernet_mode);
int hal_port_get_speed_mode(int sw, int port, int *speed,
                            int *ethernet_mode);
const char *hal_port_ethernet_mode_name(int ethernet_mode);
int hal_port_mtu_to_max_frame(int mtu);
int hal_port_max_frame_to_mtu(int max_frame);
int hal_port_set_mtu(int sw, int port, int mtu);
int hal_port_get_mtu(int sw, int port, int *mtu, int *max_frame);

// HAL VLAN
int hal_vlan_create(int sw, u16 vid);
int hal_vlan_delete(int sw, u16 vid);
int hal_vlan_add_port(int sw, u16 vid, int port, bool tagged);
int hal_vlan_remove_port(int sw, u16 vid, int port);
int hal_pvid_set(int sw, int port, u16 vid);

// HAL L3
#define HAL_L3_INTENT_NAME_LEN 32
#define HAL_L3_INTENT_ADDR_LEN 40
#define HAL_L3_INTENT_MAC_LEN 18
#define HAL_L3_INTENT_IFNAME_LEN 64
#define HAL_L3_INTENT_TABLE_LEN 64
#define HAL_L3_INTENT_MAX_ECMP_MEMBERS \
    NL_L3_PERSISTENT_MAX_ECMP_MEMBERS
#define HAL_L3_VRF_V1_VRID 1
#define HAL_L3_VRF_V1_KERNEL_TABLE 1001

typedef enum {
    HAL_L3_ROUTE_TARGET_NEXTHOP = 1,
    HAL_L3_ROUTE_TARGET_ECMP = 2,
    HAL_L3_ROUTE_TARGET_RIF = 3,
} hal_l3_route_target_type;

typedef struct {
    char name[HAL_L3_INTENT_NAME_LEN];
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    int vlan;
    char port[HAL_L3_INTENT_IFNAME_LEN];
    char address[HAL_L3_INTENT_ADDR_LEN];
} hal_l3_intent_rif;

typedef struct {
    char ip[HAL_L3_INTENT_ADDR_LEN];
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    char mac[HAL_L3_INTENT_MAC_LEN];
    char rif[HAL_L3_INTENT_NAME_LEN];
    char egress_port[HAL_L3_INTENT_IFNAME_LEN];
} hal_l3_intent_arp;

typedef struct {
    int id;
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    char arp[HAL_L3_INTENT_ADDR_LEN];
    char rif[HAL_L3_INTENT_NAME_LEN];
} hal_l3_intent_next_hop;

typedef struct {
    int id;
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    int members[HAL_L3_INTENT_MAX_ECMP_MEMBERS];
    int n_members;
} hal_l3_intent_ecmp;

typedef struct {
    char prefix[HAL_L3_INTENT_ADDR_LEN];
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    hal_l3_route_target_type target_type;
    int target_id;
    char target_name[HAL_L3_INTENT_NAME_LEN];
} hal_l3_intent_route;

typedef struct {
    bool has_router_mac;
    char router_mac[HAL_L3_INTENT_MAC_LEN];
    bool has_virtual_router;
    char virtual_router_name[HAL_L3_INTENT_NAME_LEN];
    char virtual_router_table[HAL_L3_INTENT_TABLE_LEN];
    int virtual_router_id;
    int virtual_router_kernel_table;
    const hal_l3_intent_rif *rifs;
    int n_rifs;
    const hal_l3_intent_arp *arps;
    int n_arps;
    const hal_l3_intent_next_hop *nexthops;
    int n_nexthops;
    const hal_l3_intent_ecmp *ecmp;
    int n_ecmp;
    const hal_l3_intent_route *routes;
    int n_routes;
} hal_l3_intent_plan;

typedef struct {
    bool owner_applied;
    bool found;
    int next_hop_id;
    int rif_index;
    int vlan;
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    char ip[HAL_L3_INTENT_ADDR_LEN];
    char rif[HAL_L3_INTENT_NAME_LEN];
    char interface_addr[HAL_L3_INTENT_ADDR_LEN];
} hal_l3_persistent_next_hop_ref;

typedef struct {
    char address[HAL_L3_INTENT_ADDR_LEN];
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    char rif[HAL_L3_INTENT_IFNAME_LEN];
    char interface_addr[HAL_L3_INTENT_ADDR_LEN];
    int persistent_next_hop_id;
    int persistent_rif_index;
    int vlan;
} hal_l3_dynamic_fib_nexthop;

typedef struct {
    char prefix[HAL_L3_INTENT_ADDR_LEN];
    char protocol[16];
    int preference;
    int metric;
    const hal_l3_dynamic_fib_nexthop *nexthops;
    int n_nexthops;
    u64 route_generation;
    u64 fib_update_id;
} hal_l3_dynamic_fib_route;

typedef struct {
    char table[HAL_L3_INTENT_TABLE_LEN];
    int vrid;
    u64 generation;
    u64 fib_update_id;
    const hal_l3_dynamic_fib_route *routes;
    int n_routes;
} hal_l3_dynamic_fib_plan;

int hal_route_add(int sw, void *entry);
int hal_route_delete(int sw, void *entry);
int hal_l3if_create(int sw, int *ifindex);
int hal_l3if_add_addr(int sw, int ifindex, void *addr);
int hal_ecmp_create(int sw, int *group_id, int num_nh, void *nh_list);
int hal_l3_intent_probe(const hal_l3_intent_plan *plan, char *resp,
                        size_t resp_size);
int hal_l3_intent_sdk_preflight(const hal_l3_intent_plan *plan, char *resp,
                                 size_t resp_size);
int hal_l3_sdk_readback_probe(int sw, char *resp, size_t resp_size);
int hal_l3_sdk_owner_verify(int sw, const hal_l3_intent_plan *expected,
                            char *resp, size_t resp_size);
int hal_l3_sdk_write_canary(int sw, bool acknowledged, char *resp,
                             size_t resp_size);
int hal_l3_rif_live_probe(int sw, const hal_l3_intent_plan *plan,
                          bool acknowledged, u64 tx_id, char *resp,
                          size_t resp_size);
int hal_l3_arp_live_probe(int sw, const hal_l3_intent_plan *plan,
                          bool acknowledged, u64 tx_id, char *resp,
                          size_t resp_size);
int hal_l3_ecmp_live_probe(int sw, const hal_l3_intent_plan *plan,
                           bool acknowledged, u64 tx_id, char *resp,
                           size_t resp_size);
int hal_l3_route_live_probe(int sw, const hal_l3_intent_plan *plan,
                            bool acknowledged, u64 tx_id, int hold_sec,
                            const char *router_mac_text,
                            char *resp, size_t resp_size);
int hal_l3_persistent_owner_apply(int sw, const hal_l3_intent_plan *plan,
                                  bool acknowledged, u64 tx_id,
                                  char *resp, size_t resp_size);
int hal_l3_persistent_owner_readback(int sw, char *resp, size_t resp_size);
int hal_l3_persistent_owner_rollback(int sw, bool acknowledged, u64 tx_id,
                                     char *resp, size_t resp_size);
int hal_l3_persistent_owner_lookup_next_hop(
        const char *table, const char *ip, const char *rif,
        hal_l3_persistent_next_hop_ref *ref);
int hal_l3_persistent_owner_lookup_table(const char *table, int *vrid);
int hal_l3_dynamic_fib_owner_apply(int sw,
                                   const hal_l3_dynamic_fib_plan *plan,
                                   bool enabled, u64 tx_id,
                                   char *resp, size_t resp_size);
int hal_l3_dynamic_fib_owner_readback(int sw, char *resp, size_t resp_size);
int hal_l3_dynamic_fib_owner_rollback(int sw, bool enabled, u64 tx_id,
                                      char *resp, size_t resp_size);

// MAC table
int hal_get_mac_table(int sw, struct sdk_result *result);
int hal_clear_dynamic_mac_table(int sw, int port, int vid);
int hal_mac_aging_set(int sw, int seconds);
int hal_mac_aging_get(int sw, int *seconds);
int hal_static_mac_add(int sw, u16 vid, const u8 mac[6], int port);
int hal_static_mac_delete(int sw, u16 vid, const u8 mac[6]);
int hal_mac_entry_get(int sw, u16 vid, const u8 mac[6],
                      int *port, bool *is_static);
int hal_mac_entry_snapshot(int sw, u16 vid, const u8 mac[6],
                           bool *present, int *port, bool *is_static,
                           int *entry_type);
int hal_l2_mcast_listener_set(int sw, u16 vid, const u8 mac[6], int port);
int hal_l2_mcast_listener_delete(int sw, u16 vid, const u8 mac[6], int port);
int hal_l2_mcast_listener_present(int sw, u16 vid, const u8 mac[6], int port);
int hal_l2_mcast_owner_format(int sw, char *buf, size_t buf_size);
int hal_port_security_set(int sw, int port, bool enable, int action,
                          bool strict);
int hal_get_stp_table(int sw, struct sdk_result *result);

// Packet I/O
int hal_packet_tx(int sw, int port, const u8 *data, int len);
int hal_packet_rx_poll(int sw, u8 *buf, int buf_size);
int hal_packet_rx_poll_meta(int sw, u8 *buf, int buf_size,
                            int *src_port, int *vlan);
int hal_packet_rx_poll_stamped(int sw, u8 *buf, int buf_size,
                               int *src_port, int *vlan, u64 *captured_at);

// LAG management
hal_lag_handle_set_snapshot hal_lag_handle_set_snapshot_get(int sw);
bool hal_lag_handle_set_snapshot_equal(
    const hal_lag_handle_set_snapshot *left,
    const hal_lag_handle_set_snapshot *right);
int hal_lag_handle_set_single_addition(
    const hal_lag_handle_set_snapshot *before,
    const hal_lag_handle_set_snapshot *after,
    int *lag_id);
int hal_lag_handle_set_restore_after_create(
    int sw, const hal_lag_handle_set_snapshot *before);
int hal_lag_create_classified(
    int sw, const hal_lag_handle_set_snapshot *before,
    int *lag_id, bool *created, int *sdk_status);
int hal_lag_delete(int sw, int lag_id);
int hal_lag_add_port(int sw, int lag_id, int port);
int hal_lag_del_port(int sw, int lag_id, int port);
int hal_lag_restore_port(int sw, int lag_id, int port, u64 tx_id);
int hal_lag_del_port_transaction(int sw, int lag_id, int port, u64 tx_id);
int hal_lag_transaction_check(u64 tx_id, bool committed);
void hal_lag_transaction_retire(u64 tx_id);
int hal_lag_attributes_capture(int sw, int lag_id, fm10k_lag_attributes *out);
int hal_lag_attributes_restore(int sw, int lag_id, const fm10k_lag_attributes *before);
hal_qos_interface_transaction_snapshot hal_lag_qos_snapshot(int sw, int lag_id);
int hal_lag_qos_restore(int sw, int lag_id, const hal_qos_interface_transaction_snapshot *before);
int hal_lag_qos_set(int sw, int lag_id, int trust, int priority);
int hal_lag_qos_get(int sw, int lag_id, hal_qos_interface_entry *out);
int hal_lag_get_all(int sw, struct sdk_result *result);
int hal_lag_set_hash_rotation(int sw, int lag_id, int rotation);
int hal_lag_get_hash_rotation(int sw, int lag_id, int *rotation);
int hal_lag_ae_for_id(int lag_id);
int hal_lag_id_for_ae(int ae_id);
int hal_get_pfe_resources(int sw, struct sdk_result *result);
int hal_get_switch_digital_sensors(int sw, struct sdk_result *result);
int hal_get_switch_digital_sensors_range(int sw, int first, int count,
                                         struct sdk_result *result);
int hal_get_switch_config(int sw, struct sdk_result *result);
int hal_control_plane_init(int sw);
int hal_control_plane_copp_set(int sw, const char *class_name,
                               int rate_pps, int burst_pkts);
int hal_control_plane_copp_get(int sw, const char *class_name,
                               int *rate_pps, int *burst_pkts,
                               int *policer, int *acl, int *rule,
                               u64 *packets, u64 *octets);
int hal_control_plane_collect_stats(int sw, int *rules, int *pkts, int *octets,
                                    int *table, int *capacity,
                                    int *free_entries);
int hal_control_plane_collect_protection(int sw, struct sdk_result *result);

// Counters, transceiver, and chassis read-back.
int hal_get_port_counters(int sw, int port,
                          u64 *rx_bytes, u64 *tx_bytes,
                          u64 *rx_pkts, u64 *tx_pkts,
                          u64 *rx_errs);
int hal_get_xcvr_info(int sw, int port,
                      int *present, int *type,
                      float *temp, float *voltage,
                      float *tx_bias, float *tx_power,
                      float *rx_power);
int hal_get_temperature(int sw, float *temp_c);
int hal_get_switch_info(int sw, int *num_ports);

// ===== Typed L2 Apply Plan =====

typedef enum {
    L2_STEP_NONE,
    L2_STEP_VLAN_CREATE,
    L2_STEP_VLAN_DELETE,
    L2_STEP_VLAN_ADD_PORT,
    L2_STEP_VLAN_REM_PORT,
    L2_STEP_PVID_SET,
    L2_STEP_VLAN_STP_SET,
    L2_STEP_PORT_SET_ADMIN,
    L2_STEP_PORT_SET_MTU,
    L2_STEP_PORT_SET_SPEED,
    L2_STEP_PORT_PARSER_SET,
    L2_STEP_MAC_AGING_SET,
    L2_STEP_STATIC_MAC_ADD,
    L2_STEP_STATIC_MAC_DEL,
    L2_STEP_LAG_CREATE,
    L2_STEP_LAG_DELETE,
    L2_STEP_LAG_ADD_PORT,
    L2_STEP_LAG_DEL_PORT,
    L2_STEP_LAG_HASH_ROTATION_SET,
    L2_STEP_DHCP_SNOOPING_SET,
    L2_STEP_DHCP_SNOOPING_DEL,
    L2_STEP_ARP_INSPECTION_SET,
    L2_STEP_ARP_INSPECTION_DEL,
    L2_STEP_ARP_INSPECTION_BINDING_SET,
    L2_STEP_ARP_INSPECTION_BINDING_DEL,
    L2_STEP_USER_FILTER_SET,
    L2_STEP_USER_FILTER_DEL,
    L2_STEP_INGRESS_IPV4_ACL_SET,
    L2_STEP_INGRESS_IPV4_ACL_DEL,
    L2_STEP_ACL_POLICER_SET,
    L2_STEP_ACL_POLICER_DEL,
    L2_STEP_EGRESS_ACL_SET,
    L2_STEP_EGRESS_ACL_DEL,
    L2_STEP_ACL_INDEPENDENT_SET,
    L2_STEP_ACL_INDEPENDENT_DEL,
    L2_STEP_COPP_CLASS_SET,
    L2_STEP_STORM_CONTROL_SET,
    L2_STEP_STORM_CONTROL_DEL,
    L2_STEP_INGRESS_RATE_LIMIT_SET,
    L2_STEP_INGRESS_RATE_LIMIT_DEL,
    L2_STEP_EGRESS_RATE_LIMIT_SET,
    L2_STEP_EGRESS_RATE_LIMIT_DEL,
    L2_STEP_QOS_INTERFACE_SET,
    L2_STEP_QOS_INTERFACE_DEL,
    L2_STEP_QOS_PRIORITY_MAP_SET,
    L2_STEP_QOS_PRIORITY_MAP_DEL,
    L2_STEP_QOS_PFC_SET,
    L2_STEP_QOS_PFC_DEL,
    L2_STEP_QOS_SCHEDULER_TC_MAP_SET,
    L2_STEP_QOS_SCHEDULER_TC_MAP_DEL,
    L2_STEP_QOS_SCHEDULER_GROUP_SET,
    L2_STEP_QOS_SCHEDULER_GROUP_DEL,
    L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET,
    L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL,
    L2_STEP_QOS_SCHEDULER_PORT_SET,
    L2_STEP_QOS_SCHEDULER_PORT_DEL,
    L2_STEP_QOS_WATERMARK_SET,
    L2_STEP_QOS_WATERMARK_DEL,
    L2_STEP_MIRROR_SESSION_SET,
    L2_STEP_MIRROR_SESSION_DEL,
    L2_STEP_IGMP_LISTENER_SET,
    L2_STEP_IGMP_LISTENER_DEL,
    L2_STEP_FM10K_FAN_SET,
    L2_STEP_FM10K_GROUP_SET,
    L2_STEP_PORT_INGRESS_FILTER_SET,
    L2_STEP_QOS_TC_SMP_SET,
    L2_STEP_QOS_DSCP_SET,
} l2_step_type;

typedef enum {
    L2_SECURITY_MAC_SOURCE = 1,
    L2_SECURITY_MAC_DESTINATION = 2,
} l2_security_mac_kind;

#define L2_PRE_STATIC_MAC_MAX 512
#define L2_PRE_VLAN_MEMBER_MAX 64

typedef struct {
    u8  mac[6];
    int port;
    int ae_id;
    int entry_type;
} l2_pre_static_mac_entry;

typedef struct {
    int  port;
    int  ae_id;
    bool tagged;
    int  stp_state;
} l2_pre_vlan_member_entry;

typedef struct {
    l2_step_type type;
    u16 vid;
    int port;
    bool tagged;
    int stp_state;
    int admin_mode;
    int mtu;
    int speed;
    int parser_mode;
    int ingress_filtering;
    int aging_time;
    fm10k_fan_curve fm10k_fan;
    fm10k_group fm10k_group;
    u64 fm10k_tx_id;
    u8  mac[6];
    u32 igmp_group_ip;
    int ae_id;
    int lag_id;
    int lag_hash_rotation;
    int security_vid;
    int security_port;
    u8  security_mac[6];
    int security_mac_kind;
    u32 security_ip;
    hal_ingress_ipv4_acl_match ingress_ipv4_acl;
    hal_acl_policer_owner_args acl_policer;
    hal_acl_egress_owner_args egress_acl;
    hal_acl_independent_args acl_independent;
    char copp_class[16];
    int copp_rate_pps;
    int copp_burst_pkts;
    nl_storm_kind storm_kind;
    int storm_rate_kbps;
    int storm_burst_bytes;
    int ingress_rate_limit_rate_kbps;
    int ingress_rate_limit_burst_bytes;
    int egress_rate_limit_rate_kbps;
    int egress_rate_limit_burst_bytes;
    int qos_trust_mode;
    int qos_default_priority;
    int qos_switch_priority;
    int qos_traffic_class;
    int qos_smp;
    int qos_dscp;
    int qos_dscp_priority;
    int pre_qos_dscp_priority;
    bool pre_qos_dscp_valid;
    int pre_qos_smp;
    bool pre_qos_smp_valid;
    int qos_pfc_rx_class_mask;
    int qos_pfc_tx_pause_mode;
    int qos_pfc_tx_class_mask;
    int qos_pfc_lossless_smp_mask;
    int qos_pfc_shared_pause_mask;
    fm10k_pfc_wd_policy qos_pfc_watchdog;
    int qos_scheduler_traffic_class;
    int qos_scheduler_shaping_group;
    int qos_scheduler_group;
    int qos_scheduler_strict_priority;
    int qos_scheduler_weight;
    u64 qos_scheduler_group_rate_bps;
    u64 qos_scheduler_group_burst_bits;
    int qos_scheduler_traffic_class_enable_mask;
    int qos_watermark_attr;
    int qos_watermark_index;
    int qos_watermark_value;
    int qos_watermark_owner_create;
    int qos_watermark_reconcile;
    hal_mirror_state mirror;
    bool lag_delete_issued;
    int  restored_lag_id;
    hal_flow_table_creation_token security_table_creation_token;
    bool pre_vlan_existed;
    fm10k_fan_snapshot pre_fm10k_fan;
    bool pre_fm10k_group_valid;
    fm10k_group pre_fm10k_group;
    bool pre_member_existed;
    bool pre_member_tagged;
    bool pre_member_stp_valid;
    int  pre_member_stp_state;
    int  pre_static_mac_count;
    l2_pre_static_mac_entry *pre_static_macs;
    int  pre_vlan_member_count;
    l2_pre_vlan_member_entry *pre_vlan_members;
    bool pre_pvid_valid;
    u16  pre_pvid;
    bool pre_stp_valid;
    int  pre_stp_state;
    hal_port_admin_transaction_snapshot pre_admin;
    bool pre_mtu_valid;
    int  pre_mtu;
    bool pre_speed_valid;
    int  pre_speed;
    int  pre_ethernet_mode;
    bool pre_parser_valid;
    int  pre_parser_mode;
    bool pre_ingress_filter_valid;
    bool pre_ingress_filter;
    bool pre_aging_valid;
    int  pre_aging_time;
    bool pre_mac_valid;
    bool pre_mac_static;
    int  pre_mac_port;
    int  pre_mac_ae_id;
    int  pre_mac_type;
    bool pre_igmp_listener_present;
    bool pre_lag_existed;
    bool pre_lag_member_existed;
    int  pre_lag_id;
    hal_lag_handle_set_snapshot pre_lag_handles;
    int  pre_lag_member_count;
    int  pre_lag_members[NETLAB_MAX_LAG_MEMBERS];
    bool pre_lag_hash_rotation_valid;
    int  pre_lag_hash_rotation;
    bool pre_lag_lacp_disposition_valid;
    int  pre_lag_lacp_disposition;
    fm10k_lag_attributes pre_lag_attributes;
    bool pre_security_table_present;
    bool pre_security_present;
    bool pre_ingress_ipv4_acl_present;
    hal_acl_policer_owner_transaction_snapshot pre_acl_policer;
    hal_acl_egress_owner_transaction_snapshot pre_egress_acl;
    hal_acl_independent_transaction_snapshot pre_acl_independent;
    hal_copp_policer_transaction_snapshot pre_copp;
    hal_storm_rate_transaction_snapshot pre_storm;
    hal_storm_rate_transaction_snapshot pre_ingress_rate_limit;
    hal_egress_rate_transaction_snapshot pre_egress_rate_limit;
    hal_qos_interface_transaction_snapshot pre_qos_interface;
    bool pre_qos_priority_map_valid;
    int  pre_qos_traffic_class;
    bool pre_qos_pfc_valid;
    int  pre_qos_pfc_rx_class_mask;
    int  pre_qos_pfc_tx_pause_mode;
    int  pre_qos_pfc_tx_class_mask;
    int  pre_qos_pfc_lossless_smp_mask;
    int  pre_qos_pfc_shared_pause_mask;
    int  pre_qos_pfc_pc3_smp;
    fm10k_pfc_wd_policy pre_qos_pfc_watchdog;
    bool pre_qos_scheduler_tc_map_valid;
    int  pre_qos_scheduler_shaping_group;
    hal_qos_scheduler_topology_transaction_snapshot
        pre_qos_scheduler_topology;
    hal_qos_scheduler_group_shaping_transaction_snapshot
        pre_qos_scheduler_group_shaping;
    bool pre_qos_scheduler_port_valid;
    int  pre_qos_scheduler_traffic_class_enable_mask;
    hal_qos_watermark_transaction_snapshot pre_qos_watermark;
    hal_qos_watermark_transaction_snapshot qos_watermark_delete_target;
    hal_mirror_state pre_mirror;
} l2_apply_step;

#define L2_PLAN_MAX_STEPS NL_L2_PLAN_MAX_STEPS

struct l2_apply_plan {
    u32 storage_magic;
    u64 tx_id;
    bool fm10k_scope_present;
    u32 fm10k_scope_mask;
    int n_steps;
    int step_capacity;
    int rollback_last_idx;
    bool rollback_started;
    int rollback_next_idx;
    int original_n_steps;
    int original_capacity;
    l2_apply_step *steps;
    l2_apply_step *original_steps;
    bool qos_auto_pause_watermark_snapshot_required;
    hal_qos_auto_pause_watermark_transaction_snapshot
        pre_qos_auto_pause_watermark;
    /* Executor-owned, transient cooperative hook. Never serialized or copied
     * into a transaction snapshot. Invoked only between unlocked HAL steps. */
    void (*checkpoint)(void *context);
    void *checkpoint_context;
};

static inline void l2_apply_plan_checkpoint(const l2_apply_plan *plan) {
    if (plan && plan->checkpoint)
        plan->checkpoint(plan->checkpoint_context);
}

void l2_apply_plan_init(l2_apply_plan *plan);
void l2_apply_step_pre_state_reset(l2_apply_step *step);
void l2_apply_plan_reset(l2_apply_plan *plan);
int l2_apply_plan_allocate_steps(l2_apply_plan *plan, int n_steps);
int l2_apply_plan_allocate_original(l2_apply_plan *plan, int n_steps);
int l2_apply_plan_clone(l2_apply_plan *destination,
                        const l2_apply_plan *source);
void l2_apply_plan_move(l2_apply_plan *destination,
                        l2_apply_plan *source);

// Parse a text-format apply plan into structured plan.
// Text format: one step per line, e.g.:
//   vlan-create vid=100
//   vlan-add-port vid=100 port=2 tagged=0
// Returns number of steps parsed, or -1 on error.
int l2_plan_parse(const char *text, l2_apply_plan *plan);
int l3_transaction_dry_run_parse(const char *text, char *resp,
                                 size_t resp_size);
int l3_transaction_hidden_apply(const char *text, u64 tx_id, char *resp,
                                size_t resp_size);
int l3_transaction_hidden_readback(int sw, bool sdk_live_readback,
                                   char *resp, size_t resp_size);
int l3_transaction_hidden_rollback(u64 tx_id, char *resp, size_t resp_size);
int l3_transaction_hidden_rif_live_probe(int sw, const char *text,
                                         bool acknowledged, u64 tx_id,
                                         char *resp, size_t resp_size);
int l3_transaction_hidden_arp_live_probe(int sw, const char *text,
                                         bool acknowledged, u64 tx_id,
                                         char *resp, size_t resp_size);
int l3_transaction_hidden_ecmp_live_probe(int sw, const char *text,
                                          bool acknowledged, u64 tx_id,
                                          char *resp, size_t resp_size);
int l3_transaction_hidden_route_live_probe(int sw, const char *text,
                                           bool acknowledged, u64 tx_id,
                                           int hold_sec,
                                           const char *router_mac_text,
                                           char *resp,
                                           size_t resp_size);
int l3_transaction_hidden_persistent_apply(int sw, const char *text,
                                           bool acknowledged, u64 tx_id,
                                           char *resp, size_t resp_size);
int l3_transaction_hidden_persistent_readback(int sw, char *resp,
                                              size_t resp_size);
int l3_transaction_hidden_persistent_rollback(int sw, bool acknowledged,
                                              u64 tx_id, char *resp,
                                              size_t resp_size);
int l3_transaction_shadow_mismatch_probe(const char *text, char *resp,
                                          size_t resp_size);
int l3_transaction_failure_probe(const char *text, char *resp,
                                 size_t resp_size);
int l3_fib_batch_apply(int sw, const char *text, u64 tx_id, char *resp,
                       size_t resp_size);
int l3_fib_snapshot_begin(const char *text, u64 tx_id, char *resp,
                          size_t resp_size);
int l3_fib_snapshot_part(const char *text, u64 tx_id, char *resp,
                         size_t resp_size);
int l3_fib_snapshot_commit(int sw, const char *text, u64 tx_id, char *resp,
                           size_t resp_size);
int l3_fib_snapshot_abort(const char *text, u64 tx_id, char *resp,
                          size_t resp_size);
int l3_fib_snapshot_sweep(u64 now_ns);
int l3_fib_batch_readback(int sw, char *resp, size_t resp_size);
int l3_fib_batch_reconcile(int sw, char *resp, size_t resp_size);
int l3_fib_batch_rollback(int sw, u64 tx_id, char *resp, size_t resp_size);

// Apply a typed plan to hardware via executor.
int hal_apply_l2_plan(int sw, l2_apply_plan *plan, struct sdk_result *results, int max_results);
int hal_rollback_l2_plan(int sw, l2_apply_plan *plan);
int hal_mirror_state_get(int sw, int group, hal_mirror_state *state);
int hal_mirror_session_replace(int sw, const hal_mirror_state *state);
int hal_mirror_session_delete(int sw, int group);
bool hal_mirror_state_equal(const hal_mirror_state *a,
                            const hal_mirror_state *b);

// Read-back verifier
int verify_vlan_exists(int sw, u16 vlanId,
                       struct verify_result *result);
int verify_vlan_exists_with_ports(int sw, u16 vlanId,
                                   const int *expected_ports,
                                   int n_expected_ports,
                                   struct verify_result *result);
int verify_apply_plan(int sw, l2_apply_plan *plan,
                       struct verify_result *results, int max_results);
int verify_vlan_port_member(int sw, u16 vlanId, int port,
                            bool expect_tagged,
                            struct verify_result *result);
int verify_pvid(int sw, int port, u16 expected_vid,
                struct verify_result *result);
int verify_stp_state(int sw, u16 vlanId, int port, int expected_state,
                     struct verify_result *result);
int verify_port_state(int sw, int port, int expected_mode,
                      struct verify_result *result);
int verify_port_mtu(int sw, int port, int expected_mtu,
                    struct verify_result *result);
int verify_port_speed(int sw, int port, int expected_speed,
                      struct verify_result *result);
int verify_mac_aging_time(int sw, int expected_seconds,
                          struct verify_result *result);
int verify_static_mac_entry(int sw, u16 vlanId, const u8 mac[6],
                            int expected_port, bool expect_present,
                            struct verify_result *result);
int verify_lag_hash_rotation(int sw, int lag_id, int expected_rotation,
                             struct verify_result *result);
int verify_l2_security_rule(int sw, const char *kind, u16 vid, int port,
                            bool expect_present,
                            struct verify_result *result);
int verify_l2_security_binding(int sw, u16 vid, int port,
                               const u8 mac[6], u32 ip,
                               bool expect_present,
                               struct verify_result *result);
int verify_l2_security_user_filter(int sw, u16 vid, int port,
                                   const u8 mac[6], int mac_kind,
                                   bool expect_present,
                                   struct verify_result *result);
int verify_ingress_ipv4_acl(int sw,
                            const hal_ingress_ipv4_acl_match *match,
                            bool expect_present,
                            struct verify_result *result);
int verify_copp_class(int sw, const char *class_name, int rate_pps,
                      int burst_pkts, struct verify_result *result);
int verify_storm_control(int sw, int port, int expected_rate_kbps,
                         int expected_burst_bytes, bool expect_present,
                         struct verify_result *result);
int verify_storm_control_kind(int sw, int port, nl_storm_kind kind,
                               int expected_rate_kbps, int expected_burst_bytes,
                               bool expect_present, struct verify_result *result);
int verify_ingress_rate_limit(int sw, int port, int expected_rate_kbps,
                              int expected_burst_bytes, bool expect_present,
                              struct verify_result *result);
int verify_egress_rate_limit(int sw, int port, int expected_rate_kbps,
                             int expected_burst_bytes, bool expect_present,
                             struct verify_result *result);
int verify_qos_interface(int sw, int port, int expected_trust_mode,
                         int expected_default_priority,
                         struct verify_result *result);
int verify_qos_priority_map(int sw, int switch_priority,
                            int expected_traffic_class,
                            struct verify_result *result);
int verify_qos_pfc(int sw, int port, int expected_rx_class_mask,
                   int expected_tx_pause_mode,
                   int expected_tx_class_mask,
                   int expected_lossless_smp_mask,
                   int expected_shared_pause_mask,
                   const fm10k_pfc_wd_policy *expected_watchdog,
                   struct verify_result *result);
int verify_qos_scheduler_tc_map(int sw, int port, int traffic_class,
                                int expected_shaping_group,
                                struct verify_result *result);
int verify_qos_scheduler_group(int sw, int port, int group,
                               int expected_strict_priority,
                               int expected_weight,
                               struct verify_result *result);
int verify_qos_scheduler_group_shaping(int sw, int port, int group,
                                       u64 expected_rate_bps,
                                       u64 expected_burst_bits,
                                       bool expect_present,
                                       struct verify_result *result);
int verify_qos_scheduler_port(int sw, int port,
                              int expected_traffic_class_enable_mask,
                              struct verify_result *result);
int verify_qos_watermark(int sw, int port, int attr, int index,
                         int expected_value,
                         struct verify_result *result);

int hal_l2_security_dhcp_snooping_set(int sw, u16 vid, int port);
int hal_l2_security_dhcp_snooping_delete(int sw, u16 vid, int port);
int hal_l2_security_arp_inspection_set(int sw, u16 vid, int port);
int hal_l2_security_arp_inspection_delete(int sw, u16 vid, int port);
int hal_l2_security_rule_present(int sw, const char *kind, u16 vid, int port);
int hal_l2_security_arp_binding_set(int sw, u16 vid, int port,
                                    const u8 mac[6], u32 ip);
int hal_l2_security_arp_binding_delete(int sw, u16 vid, int port,
                                       const u8 mac[6], u32 ip);
int hal_l2_security_arp_binding_present(int sw, u16 vid, int port,
                                        const u8 mac[6], u32 ip);
int hal_l2_security_user_filter_set(int sw, u16 vid, int port,
                                    const u8 mac[6], int mac_kind);
int hal_l2_security_user_filter_delete(int sw, u16 vid, int port,
                                       const u8 mac[6], int mac_kind);
int hal_l2_security_user_filter_present(int sw, u16 vid, int port,
                                        const u8 mac[6], int mac_kind);
int hal_l2_security_user_filter_counters(int sw, u16 vid, int port,
                                         const u8 mac[6], int mac_kind,
                                         bool *found, int *table,
                                         int *flow, u64 *packets,
                                         u64 *octets);
int hal_l2_security_user_filter_counter_snapshot(
    int sw, const nl_acl_counter_query *query,
    nl_acl_counter_snapshot *snapshot);
int hal_acl_counter_snapshot_get(int sw,
                                 const nl_acl_counter_query *query,
                                 nl_acl_counter_snapshot *snapshot);
int hal_ingress_ipv4_acl_set(int sw,
                             const hal_ingress_ipv4_acl_match *match);
int hal_ingress_ipv4_acl_delete(int sw,
                                const hal_ingress_ipv4_acl_match *match);
int hal_ingress_ipv4_acl_present(int sw,
                                 const hal_ingress_ipv4_acl_match *match);
int hal_ingress_ipv4_acl_counters(int sw,
                                  const hal_ingress_ipv4_acl_match *match,
                                  bool *found, int *table, int *flow,
                                  u64 *packets, u64 *octets);
int hal_ingress_ipv4_acl_counter_snapshot(
    int sw, const nl_acl_counter_query *query,
    nl_acl_counter_snapshot *snapshot);
int hal_acl_policer_probe(int sw,
                          const hal_acl_policer_probe_args *args,
                          hal_acl_policer_probe_result *result);
int hal_acl_policer_owner_apply(int sw,
                                const hal_acl_policer_owner_args *args,
                                hal_acl_policer_owner_result *result);
int hal_acl_policer_owner_readback(int sw,
                                   hal_acl_policer_owner_result *result);
int hal_acl_policer_owner_rollback(int sw,
                                   hal_acl_policer_owner_result *result);
int hal_acl_policer_owner_readback_match(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_result *result);
int hal_acl_policer_counter_snapshot(
    int sw, const nl_acl_counter_query *query,
    nl_acl_counter_snapshot *snapshot);
int hal_acl_policer_owner_rollback_match(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_result *result);
int hal_acl_egress_probe(int sw,
                         const hal_acl_egress_probe_args *args,
                         hal_acl_egress_probe_result *result);
int hal_acl_egress_counters(int sw, int port, u64 *packets, u64 *octets);
int hal_acl_egress_owner_apply(int sw,
                               const hal_acl_egress_owner_args *args,
                               hal_acl_egress_owner_result *result);
int hal_acl_egress_owner_readback(int sw,
                                  hal_acl_egress_owner_result *result);
int hal_acl_egress_owner_readback_match(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_egress_owner_result *result);
int hal_acl_egress_owner_rollback(int sw,
                                  hal_acl_egress_owner_result *result);
int hal_acl_egress_owner_rollback_match(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_egress_owner_result *result);
int hal_acl_general_allocator_apply(
    int sw, const hal_acl_general_allocator_args *args,
    hal_acl_general_allocator_result *result);
int hal_acl_general_allocator_readback(
    int sw, hal_acl_general_allocator_result *result);
int hal_acl_general_allocator_rollback(
    int sw, hal_acl_general_allocator_result *result);
int hal_acl_independent_apply(int sw,
                              const hal_acl_independent_args *args,
                              hal_acl_independent_result *result);
int hal_acl_independent_readback_match(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_result *result);
int hal_acl_independent_rollback_match(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_result *result);

// PFE capability gate (global)
extern nl_pfe_capability g_pfe_cap;
void sdk_pfe_capability_register(nl_pfe_capability *cap);

// RPC dispatch
void hal_rpc_dispatch(struct sdk_context *ctx, nl_conn *conn, nl_msg_hdr *msg);

#endif
