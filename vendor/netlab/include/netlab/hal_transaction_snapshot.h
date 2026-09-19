/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_HAL_TRANSACTION_SNAPSHOT_H
#define NETLAB_HAL_TRANSACTION_SNAPSHOT_H

#include "types.h"
#include "storm_control.h"

/*
 * Transaction snapshots must never turn an SDK read failure into absence.
 * ABSENT is therefore reserved for a complete, successful enumeration that
 * proves no object owns the requested port.
 */
typedef enum {
    HAL_TRANSACTION_SNAPSHOT_READ_ERROR = -1,
    HAL_TRANSACTION_SNAPSHOT_ABSENT = 0,
    HAL_TRANSACTION_SNAPSHOT_PRESENT = 1,
} hal_transaction_snapshot_state;

/*
 * Port administrative mode and the QSFP module's complete lower-page byte 86
 * form one transaction boundary.  Bits 3..0 are Tx_Disable for lanes 0..3;
 * bits 7..4 are module-owned and must survive every lane update unchanged.
 *
 * module_owner_port maps every QSFP_LANE0..3 logical port to the lane-0 port
 * used for EEPROM access.  lane_mask is one bit for a split lane or 0x0f for
 * a single multi-lane logical port.  topology_fingerprint binds the snapshot
 * to the complete loaded profile mapping, preventing a stale before-image
 * from being replayed after a profile/topology change.
 *
 * A present QSFP snapshot is valid only with an exact full byte read-back.
 * An absent module has no byte to restore.  SFP is deliberately fail-closed
 * until its Tx_Disable pin can be captured and restored with the same exact
 * compare-and-swap contract.
 */
typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    int admin_mode;
    u64 xcvr_topology_fingerprint;
    u32 xcvr_module_hw_resource_id;
    int xcvr_module_owner_port;
    u8 xcvr_lane_mask;
    u8 xcvr_tx_disable_byte;
    bool xcvr_present;
    bool xcvr_tx_disable_valid;
} hal_port_admin_transaction_snapshot;

typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    int controller;
    u32 rate_kbps;
    u32 capacity_bytes;
} hal_storm_rate_transaction_snapshot;

/*
 * This is the raw FM10000 QoS-interface tuple.  The derived trust mode exposed
 * by hal_qos_interface_get() is intentionally insufficient for rollback:
 * distinct SOURCE/DSCP_PREF tuples can derive the same trust mode, and
 * DEF_PRI and DEF_SWPRI are independent hardware attributes.
 */
typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    u32 source;
    u32 dscp_preference;
    u32 default_priority;
    u32 default_switch_priority;
} hal_qos_interface_transaction_snapshot;

#define HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS 48
#define HAL_TRANSACTION_QOS_MEMORY_PARTITIONS 2
#define HAL_TRANSACTION_QOS_TRAFFIC_CLASSES 8
#define HAL_TRANSACTION_QOS_SWITCH_PRIORITIES 16

/*
 * With FM_AUTO_PAUSE_MODE enabled, changing either
 * FM_PORT_SMP_LOSSLESS_PAUSE or FM_QOS_SWPRI_TC_MAP runs the SDK's
 * SetAutoPauseMode()/SetWatermarks() path.  That path replaces the complete
 * congestion-management watermark image, including attributes on every
 * cardinal port, not only the requested port or priority.
 *
 * Keep this image at transaction/plan scope rather than in every apply step.
 * All triggering inputs must be rolled back before restoring and proving this
 * shared image.
 */
typedef struct {
    int port;
    u32 rx_private_wm[HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    u32 rx_hog_wm[HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    u32 private_pause_on_wm[HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    u32 private_pause_off_wm[HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    u32 tx_private_wm[HAL_TRANSACTION_QOS_TRAFFIC_CLASSES];
    u32 tx_hog_wm[HAL_TRANSACTION_QOS_TRAFFIC_CLASSES];
    u32 tx_soft_drop_on_private[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    u32 tx_soft_drop_on_rxmp_free[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
} hal_qos_auto_pause_port_watermark_transaction_state;

typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    u32 auto_pause_mode;
    u32 num_ports;
    u32 global_private_wm;
    u32 shared_pause_on_wm[HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    u32 shared_pause_off_wm[HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    u32 shared_priority_wm[HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    u32 shared_soft_drop_wm[HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    u32 shared_soft_drop_hog_wm[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    u32 shared_soft_drop_jitter[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    hal_qos_auto_pause_port_watermark_transaction_state
        ports[HAL_TRANSACTION_QOS_MAX_CARDINAL_PORTS];
} hal_qos_auto_pause_watermark_transaction_snapshot;

/*
 * Watermark attributes are persistent hardware fields, not presence-bearing
 * objects.  A direct SET/DEL rollback therefore preserves the exact raw
 * getter value; READ_ERROR must never be treated as a missing configuration.
 */
typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    u32 value;
    bool owner_present;
    bool owner_baseline_known;
    int owner_baseline;
    int owner_value;
} hal_qos_watermark_transaction_snapshot;

#define HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS 8
#define HAL_TRANSACTION_EGRESS_RATE_TC_COUNT 8

typedef struct {
    u32 strict_priority;
    u32 weight;
    u32 traffic_class_boundary_a;
    u32 traffic_class_boundary_b;
} hal_qos_scheduler_group_transaction_state;

/*
 * FM10000 applies scheduler-group changes as one topology.  A target-group
 * before-image is therefore insufficient: applying it also rewrites the group
 * count and every group's two boundaries, strict bit, and weight.
 */
typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    u32 num_groups;
    hal_qos_scheduler_group_transaction_state
        groups[HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS];
} hal_qos_scheduler_topology_transaction_snapshot;

/*
 * A disabled shaping rate does not make MAX_BURST disappear.  Preserve both
 * raw attributes so rollback can distinguish the SDK's complete default
 * tuple from a disabled rate paired with a non-default burst.
 */
typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    u64 raw_rate_bps;
    u64 raw_burst_bits;
} hal_qos_scheduler_group_shaping_transaction_snapshot;

/*
 * The rate-default sentinel is represented by ABSENT, but raw_rate_bps,
 * raw_burst_bits, and every TC mapping are still valid.  The setter changes
 * all of them even when the original limiter was absent.
 */
typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    u64 raw_rate_bps;
    u64 raw_burst_bits;
    u32 tc_shaping_group_map[HAL_TRANSACTION_EGRESS_RATE_TC_COUNT];
} hal_egress_rate_transaction_snapshot;

#define HAL_COPP_TRANSACTION_MAX_RULES 2

/*
 * CoPP updates are allowed only while the fixed shared ACL and every rule
 * owned by the selected class are already present and exactly match this
 * deterministic contract.  The live SDK getter is authoritative; process
 * cache state is not.  Capturing the contract alongside the four raw policer
 * attributes makes a PRESENT snapshot proof that the transaction can change
 * only the policer and leave ACL rules (and their counters) untouched.
 */
typedef struct {
    int rule;
    u64 condition;
    u64 action;
    u64 dst;
    u64 dst_mask;
    u16 eth_type;
    u16 eth_type_mask;
    u8 protocol;
    u8 protocol_mask;
    u16 l4_src_start;
    u16 l4_src_mask;
    u16 l4_dst_start;
    u16 l4_dst_mask;
    int port_set;
    int policer;
} hal_copp_acl_rule_transaction_state;

typedef struct {
    hal_transaction_snapshot_state state;
    int sdk_status;
    int acl;
    u32 acl_scenarios;
    int acl_precedence;
    int rule_count;
    hal_copp_acl_rule_transaction_state
        rules[HAL_COPP_TRANSACTION_MAX_RULES];
    int policer;
    int color_source;
    int cir_action;
    u32 cir_capacity;
    u32 cir_rate;
} hal_copp_policer_transaction_snapshot;

hal_port_admin_transaction_snapshot
hal_port_admin_transaction_snapshot_get(int sw, int port);

bool hal_port_admin_transaction_snapshot_equal(
    const hal_port_admin_transaction_snapshot *left,
    const hal_port_admin_transaction_snapshot *right);

/*
 * Apply checks that the retained before-image still matches live hardware
 * before making any write.  It changes only the selected Tx_Disable lane
 * bits, verifies the complete byte/admin tuple, and authoritatively classifies
 * every attempted non-idempotent write before safe compensation on failure.
 */
int hal_port_admin_transaction_apply(
    int sw, int port, int mode,
    const hal_port_admin_transaction_snapshot *before);

/*
 * Restore consumes the full raw byte before-image and proves the complete
 * tuple by exact live read-back.  Physical module insertion/removal and
 * profile topology are not writable; drift fails closed before any rollback
 * write.
 */
int hal_port_admin_transaction_restore(
    int sw, int port,
    const hal_port_admin_transaction_snapshot *snapshot);

hal_storm_rate_transaction_snapshot
hal_storm_control_transaction_snapshot(int sw, int port);

hal_storm_rate_transaction_snapshot
hal_storm_control_transaction_snapshot_kind(int sw, int port, nl_storm_kind kind);

hal_storm_rate_transaction_snapshot
hal_ingress_rate_limit_transaction_snapshot(int sw, int port);

hal_qos_interface_transaction_snapshot
hal_qos_interface_transaction_snapshot_get(int sw, int port);

/*
 * Restore the raw tuple and prove it by an exact post-write snapshot.  The
 * caller retains its transaction before-image when this returns non-zero.
 */
int hal_qos_interface_transaction_restore(
    int sw, int port,
    const hal_qos_interface_transaction_snapshot *snapshot);

hal_qos_auto_pause_watermark_transaction_snapshot
hal_qos_auto_pause_watermark_transaction_snapshot_get(int sw);

bool hal_qos_auto_pause_watermark_transaction_snapshot_equal(
    const hal_qos_auto_pause_watermark_transaction_snapshot *left,
    const hal_qos_auto_pause_watermark_transaction_snapshot *right);

/*
 * Call only after every PFC/priority-map trigger and direct watermark in the
 * transaction has been restored.  Auto-pause-owned fields are recalculated;
 * fields that the SDK permits applications to override are then replayed,
 * and the complete cardinal-port image is proved by exact read-back.
 */
int hal_qos_auto_pause_watermark_transaction_restore(
    int sw,
    const hal_qos_auto_pause_watermark_transaction_snapshot *snapshot);

hal_qos_watermark_transaction_snapshot
hal_qos_watermark_transaction_snapshot_get(
    int sw, int port, int attr, int index);

bool hal_qos_watermark_transaction_snapshot_equal(
    const hal_qos_watermark_transaction_snapshot *left,
    const hal_qos_watermark_transaction_snapshot *right);

/*
 * Capture the process owner's proven DEL reset target before mutation so the
 * independent read-back verifier can compare hardware against an explicit
 * value.  The owner cache is loaded from durable provenance before this read;
 * unknown/no-slot provenance is READ_ERROR/INVALID_STATE.
 */
hal_qos_watermark_transaction_snapshot
hal_qos_watermark_delete_target_get(
    int sw, int port, int attr, int index);

/*
 * Apply a candidate-owned override against the exact direct before-image.
 * owner_create is authority from the active/candidate diff, never an
 * inference from live != requested.  calculator_reconciled means a preceding
 * candidate priority-map/PFC replay just rebuilt the raw reset target, so
 * missing durable provenance may be reconstructed from snapshot->value.
 */
int hal_qos_watermark_transaction_apply(
    int sw, int port, int attr, int index, int value,
    bool owner_create, bool calculator_reconciled,
    const hal_qos_watermark_transaction_snapshot *snapshot);

/*
 * Delete either to the explicit durable reset target or, after a candidate
 * auto-pause reconciliation, by retaining the calculator-produced raw value.
 * The target is captured before owner-cache mutation and verified exactly.
 */
int hal_qos_watermark_transaction_delete(
    int sw, int port, int attr, int index,
    bool calculator_reconciled,
    const hal_qos_watermark_transaction_snapshot *snapshot,
    const hal_qos_watermark_transaction_snapshot *target);

int hal_qos_watermark_transaction_restore(
    int sw, int port, int attr, int index,
    const hal_qos_watermark_transaction_snapshot *snapshot);

hal_qos_scheduler_topology_transaction_snapshot
hal_qos_scheduler_topology_transaction_snapshot_get(int sw, int port);

int hal_qos_scheduler_topology_transaction_restore(
    int sw, int port,
    const hal_qos_scheduler_topology_transaction_snapshot *snapshot);

hal_qos_scheduler_group_shaping_transaction_snapshot
hal_qos_scheduler_group_shaping_transaction_snapshot_get(
    int sw, int port, int group);

int hal_qos_scheduler_group_shaping_transaction_restore(
    int sw, int port, int group,
    const hal_qos_scheduler_group_shaping_transaction_snapshot *snapshot);

/*
 * Transaction restore accepts every raw SDK mask, including zero.  The
 * ordinary user-facing setter keeps its stricter 1..0xff contract.
 */
int hal_qos_scheduler_port_transaction_restore(
    int sw, int port, u32 traffic_class_enable_mask);

hal_egress_rate_transaction_snapshot
hal_egress_rate_limit_transaction_snapshot(int sw, int port);

int hal_egress_rate_limit_transaction_restore(
    int sw, int port,
    const hal_egress_rate_transaction_snapshot *snapshot);

hal_copp_policer_transaction_snapshot
hal_control_plane_copp_transaction_snapshot(int sw, const char *class_name);

/*
 * Restore the raw policer or its proven absence.  PRESENT restoration calls
 * fmUpdatePolicer and then proves every saved attribute by exact read-back.
 * This does not restore the shared ACL owner rule described above.
 */
int hal_control_plane_copp_transaction_restore(
    int sw, const char *class_name,
    const hal_copp_policer_transaction_snapshot *snapshot);

#endif
