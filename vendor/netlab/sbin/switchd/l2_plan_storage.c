/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/hal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define L2_APPLY_PLAN_STORAGE_MAGIC UINT32_C(0x4e4c3250)

static bool valid_count(int count) {
    return count >= 0 && count <= L2_PLAN_MAX_STEPS;
}

void l2_apply_step_pre_state_reset(l2_apply_step *step) {
    size_t offset;

    if (!step)
        return;
    free(step->pre_static_macs);
    free(step->pre_vlan_members);
    offset = offsetof(l2_apply_step, pre_vlan_existed);
    memset((u8 *)step + offset, 0, sizeof(*step) - offset);
    step->pre_mac_ae_id = -1;
}

static void reset_steps(l2_apply_step *steps, int capacity) {
    if (!steps || capacity <= 0)
        return;
    for (int i = 0; i < capacity; i++)
        l2_apply_step_pre_state_reset(&steps[i]);
}

static int clone_step(l2_apply_step *destination,
                      const l2_apply_step *source) {
    if (!destination || !source ||
        source->pre_static_mac_count < 0 ||
        source->pre_static_mac_count > L2_PRE_STATIC_MAC_MAX ||
        source->pre_vlan_member_count < 0 ||
        source->pre_vlan_member_count > L2_PRE_VLAN_MEMBER_MAX ||
        (source->pre_static_mac_count > 0 &&
         !source->pre_static_macs) ||
        (source->pre_vlan_member_count > 0 &&
         !source->pre_vlan_members))
        return -1;
    *destination = *source;
    destination->pre_static_macs = NULL;
    destination->pre_vlan_members = NULL;
    if (source->pre_static_mac_count > 0) {
        destination->pre_static_macs = malloc(
            sizeof(*destination->pre_static_macs) *
            (size_t)source->pre_static_mac_count);
        if (!destination->pre_static_macs)
            return -1;
        memcpy(destination->pre_static_macs, source->pre_static_macs,
               sizeof(*destination->pre_static_macs) *
               (size_t)source->pre_static_mac_count);
    }
    if (source->pre_vlan_member_count > 0) {
        destination->pre_vlan_members = malloc(
            sizeof(*destination->pre_vlan_members) *
            (size_t)source->pre_vlan_member_count);
        if (!destination->pre_vlan_members) {
            l2_apply_step_pre_state_reset(destination);
            return -1;
        }
        memcpy(destination->pre_vlan_members, source->pre_vlan_members,
               sizeof(*destination->pre_vlan_members) *
               (size_t)source->pre_vlan_member_count);
    }
    return 0;
}

void l2_apply_plan_init(l2_apply_plan *plan) {
    if (!plan)
        return;
    memset(plan, 0, sizeof(*plan));
    plan->storage_magic = L2_APPLY_PLAN_STORAGE_MAGIC;
    plan->rollback_last_idx = -1;
    plan->rollback_next_idx = -1;
}

void l2_apply_plan_reset(l2_apply_plan *plan) {
    if (!plan)
        return;
    if (plan->storage_magic == L2_APPLY_PLAN_STORAGE_MAGIC) {
        reset_steps(plan->steps, plan->step_capacity);
        reset_steps(plan->original_steps, plan->original_capacity);
        free(plan->steps);
        free(plan->original_steps);
    }
    l2_apply_plan_init(plan);
}

int l2_apply_plan_allocate_steps(l2_apply_plan *plan, int n_steps) {
    l2_apply_step *steps = NULL;

    if (!plan || !valid_count(n_steps))
        return -1;
    if (n_steps > 0) {
        steps = calloc((size_t)n_steps, sizeof(*steps));
        if (!steps)
            return -1;
    }
    if (plan->storage_magic == L2_APPLY_PLAN_STORAGE_MAGIC) {
        reset_steps(plan->steps, plan->step_capacity);
        reset_steps(plan->original_steps, plan->original_capacity);
        free(plan->steps);
        free(plan->original_steps);
    }
    l2_apply_plan_init(plan);
    plan->steps = steps;
    plan->step_capacity = n_steps;
    return 0;
}

int l2_apply_plan_allocate_original(l2_apply_plan *plan, int n_steps) {
    l2_apply_step *original = NULL;

    if (!plan || plan->storage_magic != L2_APPLY_PLAN_STORAGE_MAGIC ||
        !valid_count(n_steps) || n_steps > plan->step_capacity)
        return -1;
    if (n_steps > 0) {
        original = calloc((size_t)n_steps, sizeof(*original));
        if (!original)
            return -1;
    }
    reset_steps(plan->original_steps, plan->original_capacity);
    free(plan->original_steps);
    plan->original_steps = original;
    plan->original_capacity = n_steps;
    plan->original_n_steps = 0;
    return 0;
}

int l2_apply_plan_clone(l2_apply_plan *destination,
                        const l2_apply_plan *source) {
    l2_apply_plan copy;

    if (!destination || !source || destination == source ||
        source->storage_magic != L2_APPLY_PLAN_STORAGE_MAGIC ||
        !valid_count(source->n_steps) ||
        source->n_steps > source->step_capacity ||
        (source->n_steps > 0 && !source->steps) ||
        !valid_count(source->original_n_steps) ||
        source->original_n_steps > source->original_capacity ||
        source->original_n_steps > source->n_steps ||
        (source->original_n_steps > 0 && !source->original_steps))
        return -1;

    l2_apply_plan_init(&copy);
    if (l2_apply_plan_allocate_steps(&copy, source->n_steps) != 0)
        return -1;
    for (int i = 0; i < source->n_steps; i++) {
        if (clone_step(&copy.steps[i], &source->steps[i]) != 0) {
            l2_apply_plan_reset(&copy);
            return -1;
        }
    }
    if (source->original_n_steps > 0) {
        if (l2_apply_plan_allocate_original(
                &copy, source->original_n_steps) != 0) {
            l2_apply_plan_reset(&copy);
            return -1;
        }
        for (int i = 0; i < source->original_n_steps; i++) {
            if (clone_step(&copy.original_steps[i],
                           &source->original_steps[i]) != 0) {
                l2_apply_plan_reset(&copy);
                return -1;
            }
        }
    }
    copy.tx_id = source->tx_id;
    copy.fm10k_scope_present = source->fm10k_scope_present;
    copy.fm10k_scope_mask = source->fm10k_scope_mask;
    copy.n_steps = source->n_steps;
    copy.rollback_last_idx = source->rollback_last_idx;
    copy.rollback_started = source->rollback_started;
    copy.rollback_next_idx = source->rollback_next_idx;
    copy.original_n_steps = source->original_n_steps;
    copy.qos_auto_pause_watermark_snapshot_required =
        source->qos_auto_pause_watermark_snapshot_required;
    copy.pre_qos_auto_pause_watermark =
        source->pre_qos_auto_pause_watermark;
    /* The stack-owned executor checkpoint must not leave its active request. */

    l2_apply_plan_reset(destination);
    *destination = copy;
    return 0;
}

void l2_apply_plan_move(l2_apply_plan *destination,
                        l2_apply_plan *source) {
    if (!destination || !source || destination == source ||
        source->storage_magic != L2_APPLY_PLAN_STORAGE_MAGIC)
        return;
    l2_apply_plan_reset(destination);
    *destination = *source;
    destination->checkpoint = NULL;
    destination->checkpoint_context = NULL;
    l2_apply_plan_init(source);
}
