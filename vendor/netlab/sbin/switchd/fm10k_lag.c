#include "fm10k_lag.h"
#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/port_scope.h"
#include "netlab/log.h"
#include <fm_sdk_int.h>
#include <pthread.h>
#include <string.h>

/* These are the per-LAG attributes consumed by the first L2 profile. SDK
 * boolean values are one byte; using an int pointer silently breaks them. */
typedef enum { LAG_U32, LAG_INT, LAG_BOOL } lag_attr_type;
enum { LAG_QOS_DEF_PRI = 8, LAG_QOS_DEF_SWPRI, LAG_QOS_SOURCE, LAG_QOS_DSCP_PREF };
static const struct { fm_int id; lag_attr_type type; } lag_attributes[] = {
    {FM_PORT_DEF_VLAN, LAG_U32}, {FM_PORT_MAX_FRAME_SIZE, LAG_INT},
    {FM_PORT_PARSER, LAG_U32}, {FM_PORT_DROP_BV, LAG_BOOL},
    {FM_PORT_DROP_TAGGED, LAG_BOOL}, {FM_PORT_DROP_UNTAGGED, LAG_BOOL},
    {FM_PORT_LEARNING, LAG_BOOL}, {FM_PORT_SECURITY_ACTION, LAG_U32},
    [LAG_QOS_DEF_PRI] = {FM_PORT_DEF_PRI, LAG_U32},
    [LAG_QOS_DEF_SWPRI] = {FM_PORT_DEF_SWPRI, LAG_U32},
    [LAG_QOS_SOURCE] = {FM_PORT_SWPRI_SOURCE, LAG_U32},
    [LAG_QOS_DSCP_PREF] = {FM_PORT_SWPRI_DSCP_PREF, LAG_BOOL},
    {FM_PORT_BCAST_FLOODING, LAG_BOOL}, {FM_PORT_BCAST_PRUNING, LAG_BOOL},
    {FM_PORT_UCAST_FLOODING, LAG_INT}, {FM_PORT_UCAST_PRUNING, LAG_BOOL},
    {FM_PORT_MCAST_FLOODING, LAG_INT}, {FM_PORT_MCAST_PRUNING, LAG_BOOL},
    {FM_PORT_RX_PAUSE, LAG_BOOL}, {FM_PORT_RX_CLASS_PAUSE, LAG_U32},
    {FM_PORT_TX_CLASS_PAUSE, LAG_U32}, {FM_PORT_SMP_LOSSLESS_PAUSE, LAG_U32},
};
#define LAG_ATTR_COUNT (sizeof(lag_attributes) / sizeof(lag_attributes[0]))
_Static_assert(LAG_ATTR_COUNT == NL_FM10K_LAG_ATTRIBUTES, "LAG attribute snapshot order changed");
#define LAG_VLANS 4095
#define VLAN_PRESENT 1U
#define VLAN_TAGGED 2U
#define VLAN_STP_SHIFT 2

typedef struct {
    u32 attributes[LAG_ATTR_COUNT];
    u8 vlans[LAG_VLANS];
} lag_port_image;
typedef struct {
    int lag_id;
    bool valid, faulted;
    lag_port_image detached;
} lag_member_owner;

static lag_member_owner lag_owners[24];
/* A configuration transaction may restore a member's visible projected
 * attributes before reattaching it. Retain its independent detached image
 * separately, until configd finalizes the transaction. */
static struct {
    u64 tx_id;
    int ae_id;
    lag_port_image detached;
} lag_rollback_images[24];
static pthread_t lag_thread;
static bool lag_thread_set, lag_lock_fault;

_Static_assert(sizeof(fm_bool) == 1 && sizeof(fm_int) == 4 && sizeof(fm_uint32) == 4,
               "LAG adapter requires the pinned IES ABI");

static int lag_owner_thread(void) {
    if (!lag_thread_set) { lag_thread = pthread_self(); lag_thread_set = true; }
    return pthread_equal(lag_thread, pthread_self()) ? 0 : NL_ERR_HW_STATE_OUT_OF_SYNC;
}

static int per_lag_management(int sw) {
    fm_bool configured = FALSE;
    if (lag_lock_fault || sw != 0 || !fmRootApi || !fmRootPlatform ||
        fmRootPlatform->cfg.numSwitches != 1 || !fmRootApi->fmSwitchLockTable[sw] ||
        fmGetApiProperty(FM_AAK_API_PER_LAG_MANAGEMENT, FM_API_ATTR_BOOL, &configured) != FM_OK ||
        configured != TRUE) return NL_ERR_CAPABILITY_INSUFFICIENT;
    if (PROTECT_SWITCH(sw) != FM_OK) return NL_ERR_SDK_CALL_FAILED;
    fm_switch *state = GET_SWITCH_PTR(sw);
    bool enabled = state && state->perLagMgmt == TRUE;
    if (UNPROTECT_SWITCH(sw) != FM_OK) {
        lag_lock_fault = true;
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }
    return enabled ? 0 : NL_ERR_CAPABILITY_INSUFFICIENT;
}

static int read_attribute(int sw, int port, size_t index, u32 *out) {
    union { fm_uint32 u; fm_int i; fm_bool b; } value = {0};
    if (fmGetPortAttribute(sw, port, lag_attributes[index].id, &value) != FM_OK)
        return NL_ERR_PRE_STATE_MISSING;
    switch (lag_attributes[index].type) {
    case LAG_BOOL:
        if (value.b != TRUE && value.b != FALSE) return NL_ERR_PRE_STATE_MISSING;
        *out = value.b == TRUE; break;
    case LAG_INT: *out = (u32)value.i; break;
    default: *out = value.u; break;
    }
    return 0;
}

static int write_attribute(int sw, int port, size_t index, u32 value) {
    fm_bool b = value ? TRUE : FALSE;
    fm_int i = (fm_int)value;
    fm_uint32 u = value;
    void *data = lag_attributes[index].type == LAG_BOOL ? (void *)&b :
        lag_attributes[index].type == LAG_INT ? (void *)&i : (void *)&u;
    return fmSetPortAttribute(sw, port, lag_attributes[index].id, data) == FM_OK ?
        0 : NL_ERR_SDK_CALL_FAILED;
}

int hal_fm10k_lag_attributes_capture(int sw, int lag_id, fm10k_lag_attributes *out) {
    if (!out) return NL_ERR_INVALID_VALUE;
    memset(out, 0, sizeof(*out));
    if (sw != 0 || lag_id <= 0 || lag_owner_thread()) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    int status = per_lag_management(sw);
    if (status) return status;
    fm_int logical = 0;
    if (fmLAGNumberToLogicalPort(sw, lag_id, &logical) != FM_OK || logical <= 24)
        return NL_ERR_PRE_STATE_MISSING;
    for (size_t i = 0; i < LAG_ATTR_COUNT; ++i)
        if (read_attribute(sw, logical, i, &out->values[i])) return NL_ERR_PRE_STATE_MISSING;
    out->valid = true;
    return 0;
}

int hal_fm10k_lag_attributes_restore(int sw, int lag_id, const fm10k_lag_attributes *before) {
    if (!before || !before->valid) return NL_ERR_PRE_STATE_MISSING;
    fm10k_lag_attributes current;
    int status = hal_fm10k_lag_attributes_capture(sw, lag_id, &current);
    if (status) return status;
    fm_int logical = 0;
    if (fmLAGNumberToLogicalPort(sw, lag_id, &logical) != FM_OK || logical <= 24)
        return NL_ERR_PRE_STATE_MISSING;
    for (size_t i = 0; i < LAG_ATTR_COUNT; ++i) {
        if (lag_attributes[i].type == LAG_BOOL && before->values[i] > 1)
            return NL_ERR_INVALID_VALUE;
    }
    for (size_t i = 0; i < LAG_ATTR_COUNT; ++i)
        if (current.values[i] != before->values[i] && write_attribute(sw, logical, i, before->values[i]))
            return NL_ERR_SDK_CALL_FAILED;
    if (hal_fm10k_lag_attributes_capture(sw, lag_id, &current) ||
        memcmp(current.values, before->values, sizeof(current.values))) return NL_ERR_READBACK_MISMATCH;
    return 0;
}

static int lag_qos_logical_port(int sw, int lag_id, fm_int *logical) {
    if (sw != 0 || lag_id <= 0 || lag_owner_thread()) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    int ae = hal_lag_ae_for_id(lag_id);
    if (ae < 0 || hal_lag_id_for_ae(ae) != lag_id) return NL_ERR_PRE_STATE_MISSING;
    int status = per_lag_management(sw);
    if (status) return status;
    if (fmLAGNumberToLogicalPort(sw, lag_id, logical) != FM_OK || *logical <= 24)
        return NL_ERR_PRE_STATE_MISSING;
    return 0;
}

hal_qos_interface_transaction_snapshot hal_fm10k_lag_qos_snapshot(int sw, int lag_id) {
    hal_qos_interface_transaction_snapshot out = {.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR};
    fm_int logical = 0;
    out.sdk_status = lag_qos_logical_port(sw, lag_id, &logical);
    if (out.sdk_status) return out;
    if (read_attribute(sw, logical, LAG_QOS_DEF_PRI, &out.default_priority) ||
        read_attribute(sw, logical, LAG_QOS_DEF_SWPRI, &out.default_switch_priority) ||
        read_attribute(sw, logical, LAG_QOS_SOURCE, &out.source) ||
        read_attribute(sw, logical, LAG_QOS_DSCP_PREF, &out.dscp_preference)) {
        out.sdk_status = NL_ERR_PRE_STATE_MISSING;
        return out;
    }
    out.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    return out;
}

static bool lag_qos_equal(const hal_qos_interface_transaction_snapshot *a,
                          const hal_qos_interface_transaction_snapshot *b) {
    return a->state == HAL_TRANSACTION_SNAPSHOT_PRESENT && b->state == a->state &&
        a->default_priority == b->default_priority &&
        a->default_switch_priority == b->default_switch_priority &&
        a->source == b->source && a->dscp_preference == b->dscp_preference;
}

int hal_fm10k_lag_qos_restore(int sw, int lag_id, const hal_qos_interface_transaction_snapshot *before) {
    if (!before || before->state != HAL_TRANSACTION_SNAPSHOT_PRESENT || before->dscp_preference > 1)
        return NL_ERR_INVALID_VALUE;
    fm_int logical = 0;
    int status = lag_qos_logical_port(sw, lag_id, &logical);
    if (status) return status;
    hal_qos_interface_transaction_snapshot current = hal_fm10k_lag_qos_snapshot(sw, lag_id);
    if (current.state != HAL_TRANSACTION_SNAPSHOT_PRESENT) return current.sdk_status;
    /* Restore only the classifier tuple; VLAN/MTU and other steps have their
     * own before-images and must not be overwritten by a full LAG image. */
    if ((current.default_priority != before->default_priority &&
         write_attribute(sw, logical, LAG_QOS_DEF_PRI, before->default_priority)) ||
        (current.default_switch_priority != before->default_switch_priority &&
         write_attribute(sw, logical, LAG_QOS_DEF_SWPRI, before->default_switch_priority)) ||
        (current.dscp_preference != before->dscp_preference &&
         write_attribute(sw, logical, LAG_QOS_DSCP_PREF, before->dscp_preference)) ||
        (current.source != before->source && write_attribute(sw, logical, LAG_QOS_SOURCE, before->source)))
        return NL_ERR_SDK_CALL_FAILED;
    current = hal_fm10k_lag_qos_snapshot(sw, lag_id);
    return lag_qos_equal(before, &current) ? 0 : NL_ERR_READBACK_MISMATCH;
}

int hal_fm10k_lag_qos_set(int sw, int lag_id, int trust, int priority) {
    if (trust < HAL_QOS_TRUST_NONE || trust > HAL_QOS_TRUST_DSCP || priority < 0 || priority > 7)
        return NL_ERR_INVALID_VALUE;
    hal_qos_interface_transaction_snapshot target = {
        .state = HAL_TRANSACTION_SNAPSHOT_PRESENT,
        .default_priority = (u32)priority, .default_switch_priority = (u32)priority,
        .source = FM_PORT_SWPRI_ISL_TAG, .dscp_preference = trust == HAL_QOS_TRUST_DSCP,
    };
    if (trust != HAL_QOS_TRUST_NONE) target.source |= FM_PORT_SWPRI_VPRI1;
    if (trust == HAL_QOS_TRUST_DSCP) target.source |= FM_PORT_SWPRI_DSCP;
    return hal_fm10k_lag_qos_restore(sw, lag_id, &target);
}

int hal_fm10k_lag_qos_get(int sw, int lag_id, hal_qos_interface_entry *out) {
    if (!out) return NL_ERR_INVALID_VALUE;
    *out = (hal_qos_interface_entry){.trust_mode = -1, .default_priority = -1};
    hal_qos_interface_transaction_snapshot current = hal_fm10k_lag_qos_snapshot(sw, lag_id);
    if (current.state != HAL_TRANSACTION_SNAPSHOT_PRESENT) return current.sdk_status;
    fm_int logical = 0;
    int status = lag_qos_logical_port(sw, lag_id, &logical);
    if (status) return status;
    out->port = (int)logical;
    /* A complete but noncanonical tuple is a mismatch (-1), not a successful
     * projection which hides divergent DEF_PRI/DEF_SWPRI or extra sources. */
    if (current.default_priority <= 7 && current.default_priority == current.default_switch_priority)
        out->default_priority = (int)current.default_priority;
    if (!current.dscp_preference && current.source == FM_PORT_SWPRI_ISL_TAG)
        out->trust_mode = HAL_QOS_TRUST_NONE;
    else if (!current.dscp_preference && current.source == (FM_PORT_SWPRI_ISL_TAG | FM_PORT_SWPRI_VPRI1))
        out->trust_mode = HAL_QOS_TRUST_IEEE8021P;
    else if (current.dscp_preference &&
             current.source == (FM_PORT_SWPRI_ISL_TAG | FM_PORT_SWPRI_VPRI1 | FM_PORT_SWPRI_DSCP))
        out->trust_mode = HAL_QOS_TRUST_DSCP;
    return 0;
}

static int capture_image(int sw, int port, lag_port_image *out) {
    memset(out, 0, sizeof(*out));
    for (size_t index = 0; index < LAG_ATTR_COUNT; ++index)
        if (read_attribute(sw, port, index, &out->attributes[index])) return NL_ERR_PRE_STATE_MISSING;
    fm_int vid = -1, previous = 0;
    if (fmGetVlanFirst(sw, &vid) != FM_OK) return NL_ERR_PRE_STATE_MISSING;
    while (vid != -1) {
        if (vid <= previous || vid >= LAG_VLANS) return NL_ERR_PRE_STATE_MISSING;
        fm_bool tagged = FALSE;
        fm_status status = fmGetVlanPortTag(sw, vid, port, &tagged);
        if (status == FM_OK) {
            fm_int stp = -1;
            if ((tagged != FALSE && tagged != TRUE) ||
                fmGetVlanPortState(sw, (fm_uint16)vid, port, &stp) != FM_OK ||
                stp < FM_STP_STATE_DISABLED || stp > FM_STP_STATE_BLOCKING)
                return NL_ERR_PRE_STATE_MISSING;
            out->vlans[vid] = VLAN_PRESENT | (tagged ? VLAN_TAGGED : 0) | (u8)(stp << VLAN_STP_SHIFT);
        } else if (status != FM_ERR_INVALID_PORT) {
            /* The VLAN came from the live iterator: disappearing VLANs are
             * incomplete snapshots, not successful absent memberships. */
            return NL_ERR_PRE_STATE_MISSING;
        }
        previous = vid;
        if (fmGetVlanNext(sw, vid, &vid) != FM_OK) return NL_ERR_PRE_STATE_MISSING;
    }
    return 0;
}

static bool image_equal(const lag_port_image *a, const lag_port_image *b) {
    return !memcmp(a->attributes, b->attributes, sizeof(a->attributes)) &&
        !memcmp(a->vlans, b->vlans, sizeof(a->vlans));
}

/* Enumerate every LAG so a retry cannot steal a port from another owner. */
static int member_lag(int sw, int port, int *out) {
    fm_int lag = 0, seen[NETLAB_MAX_AE];
    int count_seen = 0;
    *out = 0;
    fm_status status = fmGetLAGFirst(sw, &lag);
    if (status == FM_ERR_NO_LAGS) return 0;
    if (status != FM_OK || lag <= 0) return NL_ERR_PRE_STATE_MISSING;
    for (;;) {
        if (count_seen == NETLAB_MAX_AE) return NL_ERR_PRE_STATE_MISSING;
        for (int i = 0; i < count_seen; ++i) if (seen[i] == lag) return NL_ERR_PRE_STATE_MISSING;
        seen[count_seen++] = lag;
        fm_int members[NETLAB_MAX_LAG_MEMBERS], count = 0;
        if (fmGetLAGPortList(sw, lag, &count, members, NETLAB_MAX_LAG_MEMBERS) != FM_OK ||
            count < 0 || count > NETLAB_MAX_LAG_MEMBERS) return NL_ERR_PRE_STATE_MISSING;
        for (int i = 0; i < count; ++i) {
            if (members[i] != port) continue;
            if (*out) return NL_ERR_PRE_STATE_MISSING;
            *out = lag;
        }
        status = fmGetLAGNext(sw, lag, &lag);
        if (status == FM_ERR_NO_LAGS) return 0;
        if (status != FM_OK || lag <= 0) return NL_ERR_PRE_STATE_MISSING;
    }
}

static int restore_detached(int sw, int port, const lag_port_image *target) {
    lag_port_image current;
    int lag = 0;
    if (member_lag(sw, port, &lag) || lag || capture_image(sw, port, &current))
        return NL_ERR_HW_STATE_OUT_OF_SYNC;
    /* Removing a LAG member in IES restores attributes, but leaves its VLAN
     * membership behind. Explicitly restore only this physical port. */
    for (int vid = 1; vid < LAG_VLANS; ++vid) {
        u8 before = current.vlans[vid], after = target->vlans[vid];
        if (before == after) continue;
        if (!(after & VLAN_PRESENT)) {
            if (fmDeleteVlanPort(sw, (fm_uint16)vid, port) != FM_OK) return NL_ERR_SDK_CALL_FAILED;
            continue;
        }
        fm_bool tag = after & VLAN_TAGGED ? TRUE : FALSE;
        fm_status status = before & VLAN_PRESENT ?
            fmChangeVlanPort(sw, (fm_uint16)vid, port, tag) : fmAddVlanPort(sw, (fm_uint16)vid, port, tag);
        if (status != FM_OK || fmSetVlanPortState(sw, (fm_uint16)vid, port, after >> VLAN_STP_SHIFT) != FM_OK)
            return NL_ERR_SDK_CALL_FAILED;
    }
    for (size_t index = 0; index < LAG_ATTR_COUNT; ++index)
        if (current.attributes[index] != target->attributes[index] &&
            write_attribute(sw, port, index, target->attributes[index])) return NL_ERR_SDK_CALL_FAILED;
    if (capture_image(sw, port, &current) || !image_equal(&current, target)) return NL_ERR_READBACK_MISMATCH;
    return 0;
}

static int member_fault(int sw, int port, int lag_id) {
    lag_member_owner *owner = &lag_owners[port - 1];
    owner->faulted = true;
    owner->lag_id = lag_id;
    /* This uses the FCI admin/TX transaction, never a whole-card reset. The
     * ownership fault remains latched even if closing also fails. */
    int closed = hal_port_set_admin_state(sw, port, FM_PORT_MODE_ADMIN_DOWN);
    NL_LOG_CRIT("LAG %d port %d requires reconciliation; close status=%d", lag_id, port, closed);
    return NL_ERR_HW_STATE_OUT_OF_SYNC;
}

int hal_fm10k_lag_members_status(int lag_id, const int *members, int count) {
    if (lag_owner_thread() || !members || count < 0 || count > 24) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    u32 mask = 0;
    for (int i = 0; i < count; ++i) {
        int port = members[i];
        if (port < 1 || port > 24 || (mask & (1U << (port - 1)))) return NL_ERR_HW_STATE_OUT_OF_SYNC;
        mask |= 1U << (port - 1);
        const lag_member_owner *owner = &lag_owners[port - 1];
        if (!owner->valid || owner->faulted || owner->lag_id != lag_id) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }
    for (int i = 0; i < 24; ++i) {
        const lag_member_owner *owner = &lag_owners[i];
        if (owner->lag_id == lag_id && (owner->faulted || (owner->valid && !(mask & (1U << i)))))
            return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }
    return 0;
}

static int lag_member_set(int sw, int lag_id, int port, bool attached, bool restoring) {
    nl_port_entry entry;
    if (sw != 0 || port < 1 || port > 24 || lag_id <= 0 || hal_lag_ae_for_id(lag_id) < 0 ||
        !nl_ifid_get_by_logical_port(port, &entry) || !(entry.flags & NL_PORT_FLAG_EXTERNAL))
        return NL_ERR_INVALID_VALUE;
    if (lag_owner_thread()) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    lag_member_owner *owner = &lag_owners[port - 1];
    if (owner->faulted) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    nl_port_scope_status scope = nl_port_scope_get();
    u32 bit = 1U << (port - 1);
    u64 held = lag_rollback_images[port - 1].tx_id;
    if (held && (scope.tx_id != held || !(scope.mask & bit) || (attached && !restoring)))
        return NL_ERR_COMMIT_LOCKED;
    int status = per_lag_management(sw);
    if (status) return !attached && owner->valid ? member_fault(sw, port, lag_id) : status;
    int current_lag = 0;
    if (member_lag(sw, port, &current_lag))
        return owner->valid ? member_fault(sw, port, lag_id) : NL_ERR_PRE_STATE_MISSING;
    if ((current_lag && current_lag != lag_id) || (owner->valid && owner->lag_id != lag_id))
        return NL_ERR_COMMIT_LOCKED;

    if (!attached) {
        if (!current_lag && !owner->valid) return 0;
        if (!owner->valid) return member_fault(sw, port, lag_id);
        fm_status removed = FM_OK;
        if (current_lag) removed = fmDeleteLAGPort(sw, lag_id, port);
        /* A runtime detach may be caused by loss of partner synchronization.
         * Never reattach to compensate it. Prove the safe detached state. */
        if (member_lag(sw, port, &current_lag) || current_lag ||
            restore_detached(sw, port, &owner->detached)) return member_fault(sw, port, lag_id);
        memset(owner, 0, sizeof(*owner));
        if (removed != FM_OK) NL_LOG_WARN("LAG %d port %d detached and restored after SDK error=%d", lag_id, port, removed);
        return 0;
    }

    fm_int logical = 0;
    lag_port_image target, before, after;
    if (fmLAGNumberToLogicalPort(sw, lag_id, &logical) != FM_OK || logical <= 24 ||
        capture_image(sw, logical, &target) || capture_image(sw, port, &before))
        return current_lag ? member_fault(sw, port, lag_id) : NL_ERR_PRE_STATE_MISSING;
    if (current_lag) {
        if (!owner->valid || !image_equal(&before, &target)) return member_fault(sw, port, lag_id);
        return 0;
    }
    if (owner->valid) return member_fault(sw, port, lag_id);
    owner->detached = before; owner->valid = true; owner->lag_id = lag_id;
    fm_status added = fmAddLAGPort(sw, lag_id, port);
    if (added == FM_OK && !member_lag(sw, port, &current_lag) && current_lag == lag_id &&
        !capture_image(sw, port, &after) && image_equal(&after, &target)) return 0;

    /* SDK add can return an error after its member list or attributes changed.
     * Compensate from our independent pre-image, not its return code. */
    if (member_lag(sw, port, &current_lag) || (current_lag && current_lag != lag_id))
        return member_fault(sw, port, lag_id);
    if (current_lag) (void)fmDeleteLAGPort(sw, lag_id, port);
    if (member_lag(sw, port, &current_lag) || current_lag || restore_detached(sw, port, &before))
        return member_fault(sw, port, lag_id);
    memset(owner, 0, sizeof(*owner));
    return added == FM_OK ? NL_ERR_READBACK_MISMATCH : NL_ERR_SDK_CALL_FAILED;
}

int hal_fm10k_lag_member_set(int sw, int lag_id, int port, bool attached) {
    return lag_member_set(sw, lag_id, port, attached, false);
}

int hal_fm10k_lag_del_port_transaction(int sw, int lag_id, int port, uint64_t tx_id) {
    if (!tx_id || sw != 0 || port < 1 || port > 24 || lag_owner_thread()) return NL_ERR_INVALID_VALUE;
    nl_port_scope_status scope = nl_port_scope_get();
    if (scope.tx_id != tx_id || !(scope.mask & (1U << (port - 1))) || scope.degraded)
        return NL_ERR_COMMIT_LOCKED;
    lag_member_owner *owner = &lag_owners[port - 1];
    u64 held = lag_rollback_images[port - 1].tx_id;
    int ae = hal_lag_ae_for_id(lag_id);
    if (ae < 0 || (held && (held != tx_id || lag_rollback_images[port - 1].ae_id != ae)))
        return NL_ERR_COMMIT_LOCKED;
    if (!held) {
        if (!owner->valid || owner->faulted || owner->lag_id != lag_id) return NL_ERR_PRE_STATE_MISSING;
        lag_rollback_images[port - 1].tx_id = tx_id;
        lag_rollback_images[port - 1].ae_id = ae;
        lag_rollback_images[port - 1].detached = owner->detached;
    }
    return lag_member_set(sw, lag_id, port, false, false);
}

int hal_fm10k_lag_restore_port(int sw, int lag_id, int port, uint64_t tx_id) {
    if (!tx_id || sw != 0 || port < 1 || port > 24 || lag_owner_thread()) return NL_ERR_INVALID_VALUE;
    nl_port_scope_status scope = nl_port_scope_get();
    if (scope.tx_id != tx_id || !(scope.mask & (1U << (port - 1))) || scope.degraded ||
        lag_rollback_images[port - 1].tx_id != tx_id ||
        lag_rollback_images[port - 1].ae_id != hal_lag_ae_for_id(lag_id)) return NL_ERR_COMMIT_LOCKED;
    int rc = lag_member_set(sw, lag_id, port, true, true);
    if (!rc) lag_owners[port - 1].detached = lag_rollback_images[port - 1].detached;
    return rc;
}

int hal_fm10k_lag_transaction_check(uint64_t tx_id, bool committed) {
    if (!tx_id || lag_owner_thread()) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    nl_port_scope_status scope = nl_port_scope_get();
    for (int i = 0; i < 24; ++i) {
        const lag_member_owner *owner = &lag_owners[i];
        if (scope.tx_id == tx_id && (scope.mask & (1U << i)) && owner->faulted)
            return NL_ERR_HW_STATE_OUT_OF_SYNC;
        if (lag_rollback_images[i].tx_id != tx_id) continue;
        if (scope.tx_id != tx_id || !(scope.mask & (1U << i)) || scope.degraded || owner->faulted)
            return NL_ERR_HW_STATE_OUT_OF_SYNC;
        int actual_lag = 0;
        if (member_lag(0, i + 1, &actual_lag)) return NL_ERR_HW_STATE_OUT_OF_SYNC;
        if (committed) {
            /* lacpd may attach the newly configured member only after the
             * configuration transaction has finalized and resumed it. */
            if (owner->valid || actual_lag) return NL_ERR_HW_STATE_OUT_OF_SYNC;
            continue;
        }
        if (!owner->valid ||
            actual_lag != owner->lag_id ||
            hal_lag_ae_for_id(owner->lag_id) != lag_rollback_images[i].ae_id ||
            !image_equal(&owner->detached, &lag_rollback_images[i].detached)) return NL_ERR_HW_STATE_OUT_OF_SYNC;
        fm_int logical = 0;
        lag_port_image target, actual;
        if (fmLAGNumberToLogicalPort(0, actual_lag, &logical) != FM_OK || logical <= 24 ||
            capture_image(0, logical, &target) || capture_image(0, i + 1, &actual) ||
            !image_equal(&target, &actual)) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }
    return 0;
}

void hal_fm10k_lag_transaction_retire(uint64_t tx_id) {
    if (!tx_id || lag_owner_thread()) return;
    /* Called after all finalizer checks on the same SDK thread. */
    for (int i = 0; i < 24; ++i)
        if (lag_rollback_images[i].tx_id == tx_id)
            memset(&lag_rollback_images[i], 0, sizeof(lag_rollback_images[i]));
}
