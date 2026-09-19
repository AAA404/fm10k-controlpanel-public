#ifndef NETLAB_FM10K_PLAN_SCOPE_H
#define NETLAB_FM10K_PLAN_SCOPE_H
#include "hal.h"
#include "port_scope.h"

typedef enum { NL_FM10K_SCOPE_AE, NL_FM10K_SCOPE_VLAN } nl_fm10k_scope_target;
typedef int (*nl_fm10k_scope_resolver)(void *, nl_fm10k_scope_target, int, u32 *);

/* The planner resolves old AND new configuration membership. switchd resolves
 * actual membership independently before applying the plan, so a stale or
 * under-declared scope can never authorize an unpaused hardware mutation. */
static inline int nl_fm10k_plan_port_mask(const l2_apply_plan *plan,
                                         nl_fm10k_scope_resolver resolve,
                                         void *context, u32 *out) {
    if (!plan || !out || !plan->steps || plan->n_steps <= 0 ||
        plan->n_steps > plan->step_capacity) return NL_ERR_INVALID_VALUE;
    *out = 0;
    for (int i = 0; i < plan->n_steps; ++i) {
        const l2_apply_step *s = &plan->steps[i];
        u32 mask = 0;
        int rc = 0;
        switch (s->type) {
        case L2_STEP_FM10K_GROUP_SET: {
            int index = nl_fm10k_group_index(s->fm10k_group.epl);
            if (index < 0) return NL_ERR_INVALID_VALUE;
            /* Speed/mode changes can invoke the global watermark calculator. */
            mask = NL_PORT_SCOPE_MASK; break;
        }
        case L2_STEP_FM10K_FAN_SET:
        case L2_STEP_VLAN_CREATE:
        case L2_STEP_MAC_AGING_SET:
        case L2_STEP_STATIC_MAC_DEL:
            break;
        case L2_STEP_VLAN_DELETE:
            rc = resolve ? resolve(context, NL_FM10K_SCOPE_VLAN, s->vid, &mask) : NL_ERR_PRE_STATE_MISSING;
            break;
        case L2_STEP_LAG_ADD_PORT:
        case L2_STEP_LAG_DEL_PORT: {
            if (s->port < 1 || s->port > 24 || s->ae_id < 0) return NL_ERR_INVALID_VALUE;
            mask = 1U << (s->port - 1);
            u32 members = 0;
            rc = resolve ? resolve(context, NL_FM10K_SCOPE_AE, s->ae_id, &members) : NL_ERR_PRE_STATE_MISSING;
            mask |= members;
            break;
        }
        case L2_STEP_VLAN_ADD_PORT:
        case L2_STEP_VLAN_REM_PORT:
        case L2_STEP_VLAN_STP_SET:
        case L2_STEP_PVID_SET:
        case L2_STEP_PORT_SET_ADMIN:
        case L2_STEP_PORT_PARSER_SET:
        case L2_STEP_PORT_INGRESS_FILTER_SET:
        case L2_STEP_STATIC_MAC_ADD:
        case L2_STEP_LAG_CREATE:
        case L2_STEP_LAG_DELETE:
        case L2_STEP_LAG_HASH_ROTATION_SET:
        case L2_STEP_STORM_CONTROL_SET:
        case L2_STEP_STORM_CONTROL_DEL:
        case L2_STEP_INGRESS_RATE_LIMIT_SET:
        case L2_STEP_INGRESS_RATE_LIMIT_DEL:
        case L2_STEP_EGRESS_RATE_LIMIT_SET:
        case L2_STEP_EGRESS_RATE_LIMIT_DEL:
        case L2_STEP_QOS_INTERFACE_SET:
        case L2_STEP_QOS_INTERFACE_DEL:
        case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
        case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL:
        case L2_STEP_QOS_SCHEDULER_GROUP_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
        case L2_STEP_QOS_SCHEDULER_PORT_SET:
        case L2_STEP_QOS_SCHEDULER_PORT_DEL:
        case L2_STEP_IGMP_LISTENER_SET:
        case L2_STEP_IGMP_LISTENER_DEL:
            if (s->ae_id >= 0)
                rc = resolve ? resolve(context, NL_FM10K_SCOPE_AE, s->ae_id, &mask) : NL_ERR_PRE_STATE_MISSING;
            else if (s->port >= 1 && s->port <= 24) mask = 1U << (s->port - 1);
            else return NL_ERR_INVALID_VALUE;
            break;
        default:
            /* Shared switch policy and diagnostic extensions cannot claim a
             * narrower scope without an explicit mapping implementation. */
            mask = NL_PORT_SCOPE_MASK;
            break;
        }
        if (rc || (mask & ~NL_PORT_SCOPE_MASK)) return rc ? rc : NL_ERR_INVALID_VALUE;
        *out |= mask;
    }
    return 0;
}
#endif
