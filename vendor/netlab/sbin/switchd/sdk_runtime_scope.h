#ifndef NETLAB_SDK_RUNTIME_SCOPE_H
#define NETLAB_SDK_RUNTIME_SCOPE_H
#include "netlab/hal.h"
#include "netlab/port_scope.h"
#include <string.h>

typedef int (*sdk_scope_resolve_port)(int sw, int id, bool lag_handle, u32 *mask);
typedef int (*sdk_owned_dispatch)(int sw, struct sdk_op *op, struct sdk_result *result);

static inline void sdk_rpc_op_init(struct sdk_op *op, nl_daemon_id caller, u64 issued_at) {
    memset(op, 0, sizeof(*op));
    op->runtime = caller != NL_DAEMON_CONFIGD;
    op->issued_at = issued_at;
}

/* FM10840 has one persistent configuration authority. Legacy diagnostic
 * writers and direct configuration RPCs cannot coexist with it, even when
 * invoked by a privileged local client. This is a capability boundary; peer
 * authentication and method-specific caller permissions stay in libdaemon. */
static inline bool sdk_native_rpc_supported(nl_rpc_method method) {
    switch (method) {
    case NL_SWITCHD_PORT_GET_STATE:
    case NL_SWITCHD_PORT_GET_INVENTORY:
    case NL_SWITCHD_VLAN_GET_STATE:
    case NL_SWITCHD_COMMIT_MARK_SUCCESS:
    case NL_SWITCHD_COMMIT_MARK_FAILED:
    case NL_SWITCHD_PORT_COUNTERS_GET:
    case NL_SWITCHD_PORT_COUNTERS_RESET:
    case NL_SWITCHD_XCVR_INFO_GET:
    case NL_SWITCHD_PFE_STATUS_GET:
    case NL_SWITCHD_L2_PLAN_APPLY:
    case NL_SWITCHD_L2_PLAN_ROLLBACK:
    case NL_SWITCHD_STP_RUNTIME_SET:
    case NL_SWITCHD_DYNAMIC_MAC_CLEAR:
    case NL_SWITCHD_MAC_AGING_GET:
    case NL_SWITCHD_PFE_RESOURCES_GET:
    case NL_SWITCHD_L2_RATE_LIMIT_GET:
    case NL_SWITCHD_PORT_ADMIN_OVERRIDE:
    case NL_SWITCHD_PORT_MTU_GET:
    case NL_SWITCHD_PACKET_TX:
    case NL_SWITCHD_PACKET_RX_POLL:
    case NL_SWITCHD_PACKET_RX_POLL_META:
    case NL_SWITCHD_SWITCH_CONFIG_GET:
    case NL_SWITCHD_CONTROL_PLANE_PROTECTION_GET:
    case NL_SWITCHD_SDK_RUNTIME_GET:
    case NL_SWITCHD_COS_GET:
    case NL_SWITCHD_LAG_ADD_PORT:
    case NL_SWITCHD_LAG_DEL_PORT:
    case NL_SWITCHD_LAG_GET_ALL:
    case NL_SWITCHD_L2_SECURITY_COUNTERS_GET:
    case NL_SWITCHD_MAC_EVENTS_GET:
    case NL_SWITCHD_PORT_MIRRORING_GET:
    case NL_SWITCHD_L2_MULTICAST_OWNER_GET:
    case NL_SWITCHD_PORT_SNAPSHOT_GET:
    case NL_SWITCHD_PORT_SPEED_GET:
    case NL_SWITCHD_MAC_SNAPSHOT_GET:
    case NL_SWITCHD_STP_SNAPSHOT_PAGE_GET:
    case NL_SWITCHD_FM10K_BOARD_GET:
    case NL_SWITCHD_FM10K_FAN_MANUAL:
    case NL_SWITCHD_FM10K_CONFIG_GET:
    case NL_SWITCHD_FM10K_BIND:
    case NL_SWITCHD_FM10K_EYE_GET:
    case NL_SWITCHD_FM10K_EYE_CONTROL:
        return true;
    default:
        return false;
    }
}

static inline bool sdk_native_rpc_observable(nl_rpc_method method) {
    switch (method) {
    case NL_SWITCHD_PORT_GET_STATE:
    case NL_SWITCHD_PORT_GET_INVENTORY:
    case NL_SWITCHD_VLAN_GET_STATE:
    case NL_SWITCHD_PORT_COUNTERS_GET:
    case NL_SWITCHD_XCVR_INFO_GET:
    case NL_SWITCHD_PFE_STATUS_GET:
    case NL_SWITCHD_MAC_AGING_GET:
    case NL_SWITCHD_PFE_RESOURCES_GET:
    case NL_SWITCHD_L2_RATE_LIMIT_GET:
    case NL_SWITCHD_PORT_MTU_GET:
    case NL_SWITCHD_PACKET_RX_POLL:
    case NL_SWITCHD_PACKET_RX_POLL_META:
    case NL_SWITCHD_SWITCH_CONFIG_GET:
    case NL_SWITCHD_CONTROL_PLANE_PROTECTION_GET:
    case NL_SWITCHD_SDK_RUNTIME_GET:
    case NL_SWITCHD_COS_GET:
    case NL_SWITCHD_LAG_GET_ALL:
    case NL_SWITCHD_L2_SECURITY_COUNTERS_GET:
    case NL_SWITCHD_MAC_EVENTS_GET:
    case NL_SWITCHD_PORT_MIRRORING_GET:
    case NL_SWITCHD_L2_MULTICAST_OWNER_GET:
    case NL_SWITCHD_PORT_SNAPSHOT_GET:
    case NL_SWITCHD_PORT_SPEED_GET:
    case NL_SWITCHD_MAC_SNAPSHOT_GET:
    case NL_SWITCHD_STP_SNAPSHOT_PAGE_GET:
    case NL_SWITCHD_FM10K_BOARD_GET:
    case NL_SWITCHD_FM10K_EYE_GET:
    case NL_SWITCHD_FM10K_CONFIG_GET:
        return true;
    default:
        return false;
    }
}

static inline bool sdk_native_observation_readable(const struct sdk_context *ctx,
                                                   nl_rpc_method method) {
    return ctx && ctx->initialized && ctx->exec &&
        ctx->pfe_cap.sdk_initialized && ctx->pfe_cap.switch_enabled &&
        ctx->pfe_cap.port_inventory_ok && sdk_native_rpc_observable(method);
}

static inline bool sdk_native_op_supported(const struct sdk_op *op) {
    if (!op) return false;
    switch (op->type) {
    case SDK_OP_APPLY_L2_PLAN:
        return true; /* Runtime plans are separately restricted below. */
    case SDK_OP_ROLLBACK_L2_PLAN:
    case SDK_OP_FM10K_BOARD_POLL:
    case SDK_OP_FM10K_BOARD_SHUTDOWN:
    case SDK_OP_FM10K_BOOTSTRAP_CLOSED:
    case SDK_OP_FM10K_CONTROL_INIT:
    case SDK_OP_COMMIT_MARK_SUCCESS:
    case SDK_OP_COMMIT_MARK_FAILED:
        return !op->runtime;
    case SDK_OP_PORT_SET_ADMIN:
        return op->runtime && op->args.port.mode == 0; /* BPDU guard: close only. */
    case SDK_OP_RUNTIME_STP_SET:
    case SDK_OP_CLEAR_DYNAMIC_MAC_TABLE:
    case SDK_OP_RESET_COUNTERS:
    case SDK_OP_PACKET_TX:
    case SDK_OP_LAG_ADD_PORT:
    case SDK_OP_LAG_DEL_PORT:
    case SDK_OP_FM10K_FAN_MANUAL:
    case SDK_OP_GET_PORT_STATE:
    case SDK_OP_GET_COUNTERS:
    case SDK_OP_GET_XCVR:
    case SDK_OP_GET_MAC_TABLE:
    case SDK_OP_GET_MAC_AGING_TIME:
    case SDK_OP_GET_STP_TABLE:
    case SDK_OP_GET_VLAN_STATE:
    case SDK_OP_PACKET_RX_POLL:
    case SDK_OP_LAG_GET_ALL:
    case SDK_OP_GET_PFE_RESOURCES:
    case SDK_OP_GET_SWITCH_CONFIG:
    case SDK_OP_GET_CONTROL_PLANE_PROTECTION:
    case SDK_OP_GET_L2_SECURITY_USER_FILTER_COUNTERS:
    case SDK_OP_GET_PORT_SNAPSHOT:
    case SDK_OP_GET_QOS_READBACK:
    case SDK_OP_GET_MIRROR_STATE:
    case SDK_OP_GET_L2_MCAST_OWNER:
    case SDK_OP_FM10K_CONFIG_GET:
    case SDK_OP_FM10K_PHY_GET:
    case SDK_OP_FM10K_EYE_GET:
    case SDK_OP_FM10K_EYE_CONTROL:
    case SDK_OP_NOP:
        return true;
    default:
        return false;
    }
}

static inline bool sdk_native_protocol_runtime(nl_rpc_method method) {
    return method == NL_SWITCHD_STP_RUNTIME_SET ||
        method == NL_SWITCHD_LAG_ADD_PORT || method == NL_SWITCHD_LAG_DEL_PORT ||
        method == NL_SWITCHD_L2_PLAN_APPLY || method == NL_SWITCHD_PORT_ADMIN_OVERRIDE ||
        method == NL_SWITCHD_DYNAMIC_MAC_CLEAR || method == NL_SWITCHD_PORT_COUNTERS_RESET;
}

static inline int sdk_runtime_scope_mask(int sw, const struct sdk_op *op,
                                         sdk_scope_resolve_port resolve, u32 *mask) {
    *mask = 0;
    if (!op->runtime) return 0;
    int port = 0;
    switch (op->type) {
    case SDK_OP_RUNTIME_STP_SET:
    case SDK_OP_VLAN_STP_SET:
    case SDK_OP_VLAN_ADD_PORT:
    case SDK_OP_VLAN_REM_PORT:
    case SDK_OP_PVID_SET:
    case SDK_OP_CLEAR_DYNAMIC_MAC_TABLE: port = op->args.vlan.port; break;
    case SDK_OP_PORT_SET_ADMIN:
    case SDK_OP_PORT_SET_SPEED:
    case SDK_OP_PORT_SET_MTU:
    case SDK_OP_RESET_COUNTERS:
    case SDK_OP_PORT_PARSER_SET: port = op->args.port.port; break;
    case SDK_OP_PORT_SECURITY_SET: port = op->args.port_security.port; break;
    case SDK_OP_PACKET_TX: port = op->args.pkt_tx.port; break;
    case SDK_OP_LAG_ADD_PORT:
    case SDK_OP_LAG_DEL_PORT:
        if (op->args.lag.port < 1 || op->args.lag.port > 24 || op->args.lag.lag_id <= 0 || !resolve)
            return NL_ERR_INVALID_VALUE;
        *mask = 1U << (op->args.lag.port - 1);
        /* A member transition also changes the aggregate's distribution and
         * attribute projection. Fence every currently attached member. */
        return resolve(sw, op->args.lag.lag_id, true, mask);
    case SDK_OP_APPLY_L2_PLAN: {
        /* l2d's runtime namespace is limited to IGMP listeners. Arbitrary
         * L2 configuration belongs to configd's persistent transaction. */
        const l2_apply_plan *p = op->args.apply_plan;
        if (!p || !p->steps || p->n_steps <= 0 || p->n_steps > p->step_capacity) return NL_ERR_INVALID_VALUE;
        for (int i = 0; i < p->n_steps; ++i) {
            const l2_apply_step *s = &p->steps[i];
            if ((s->type != L2_STEP_IGMP_LISTENER_SET && s->type != L2_STEP_IGMP_LISTENER_DEL) ||
                s->port < 1 || s->port > 24 || s->ae_id >= 0) return NL_ERR_INVALID_VALUE;
            *mask |= 1U << (s->port - 1);
        }
        return 0;
    }
    default:
        return sdk_native_op_supported(op) ? 0 : NL_ERR_CAPABILITY_INSUFFICIENT;
    }
    if (!port) *mask = NL_PORT_SCOPE_MASK;
    else if (port >= 1 && port <= 24) *mask = 1U << (port - 1);
    else return resolve ? resolve(sw, port, false, mask) : NL_ERR_INTERFACE_NOT_FOUND;
    return 0;
}

static inline int sdk_runtime_dispatch(int sw, struct sdk_op *op, struct sdk_result *result,
                                       sdk_owned_dispatch dispatch,
                                       sdk_scope_resolve_port resolve, bool native) {
    if (!op || !dispatch) return NL_ERR_INVALID_VALUE;
    /* Other NetLab profiles may have physical ports above slot 24. */
    if (!native) return dispatch(sw, op, result);
    if (!sdk_native_op_supported(op)) return NL_ERR_CAPABILITY_INSUFFICIENT;
    if (!op->runtime && (op->type == SDK_OP_APPLY_L2_PLAN || op->type == SDK_OP_ROLLBACK_L2_PLAN)) {
        const l2_apply_plan *plan = op->args.apply_plan;
        if (!plan || !plan->tx_id || !plan->fm10k_scope_present ||
            (plan->fm10k_scope_mask & ~NL_PORT_SCOPE_MASK)) return NL_ERR_INVALID_VALUE;
        nl_port_scope_status scope = nl_port_scope_get();
        if (plan->fm10k_scope_mask && (!nl_port_scope_ready() || scope.tx_id != plan->tx_id ||
            scope.mask != plan->fm10k_scope_mask)) return NL_ERR_COMMIT_LOCKED;
    }
    u32 mask = 0;
    int rc = sdk_runtime_scope_mask(sw, op, resolve, &mask);
    if (rc) return rc;
    if (!nl_port_scope_enter_epoch_mask(mask, op->issued_at)) return NL_ERR_RPC_BUSY;
    rc = dispatch(sw, op, result);
    nl_port_scope_leave_mask(mask);
    return rc;
}
#endif
