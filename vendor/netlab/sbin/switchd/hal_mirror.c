#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"

#include <fm_sdk.h>
#include <api/fm_api_mirror.h>
#include <api/fm_api_vlan.h>
#include <common/fm_errno.h>
#include <string.h>

static bool mirror_absent_status(fm_status status) {
    return status == FM_ERR_INVALID_PORT_MIRROR_GROUP ||
           status == FM_ERR_NO_MIRROR_GROUPS_EXIST;
}

static int direction_from_sdk(fm_mirrorType type) {
    switch (type) {
    case FM_MIRROR_TYPE_INGRESS:
        return HAL_MIRROR_DIRECTION_INGRESS;
    case FM_MIRROR_TYPE_EGRESS:
        return HAL_MIRROR_DIRECTION_EGRESS;
    case FM_MIRROR_TYPE_BIDIRECTIONAL:
        return HAL_MIRROR_DIRECTION_BOTH;
    default:
        return 0;
    }
}

static bool direction_to_sdk(int direction, fm_mirrorType *type) {
    if (!type)
        return false;
    switch (direction) {
    case HAL_MIRROR_DIRECTION_INGRESS:
        *type = FM_MIRROR_TYPE_INGRESS;
        return true;
    case HAL_MIRROR_DIRECTION_EGRESS:
        *type = FM_MIRROR_TYPE_EGRESS;
        return true;
    case HAL_MIRROR_DIRECTION_BOTH:
        *type = FM_MIRROR_TYPE_BIDIRECTIONAL;
        return true;
    default:
        return false;
    }
}

static bool mirror_group_type(const hal_mirror_state *state,
                              fm_mirrorType *type) {
    int direction;

    if (!state || !type)
        return false;
    if (state->exact_snapshot)
        return direction_to_sdk(state->direction, type);
    if (state->n_sources <= 0)
        return false;
    direction = state->source_directions[0];
    for (int i = 1; i < state->n_sources; i++) {
        if (state->source_directions[i] != direction) {
            direction = HAL_MIRROR_DIRECTION_BOTH;
            break;
        }
    }
    return direction_to_sdk(direction, type);
}

static void sort_sources(hal_mirror_state *state) {
    if (!state)
        return;
    for (int i = 1; i < state->n_sources; i++) {
        int port = state->source_ports[i];
        int direction = state->source_directions[i];
        int j = i - 1;

        while (j >= 0 && state->source_ports[j] > port) {
            state->source_ports[j + 1] = state->source_ports[j];
            state->source_directions[j + 1] =
                state->source_directions[j];
            j--;
        }
        state->source_ports[j + 1] = port;
        state->source_directions[j + 1] = direction;
    }
}

static void sort_vlan_sources(hal_mirror_state *state) {
    if (!state)
        return;
    for (int i = 1; i < state->n_vlan_sources; i++) {
        u16 vlan = state->source_vlans[i];
        int selector = state->source_vlan_selectors[i];
        int direction = state->source_vlan_directions[i];
        int j = i - 1;

        while (j >= 0 &&
               (state->source_vlan_selectors[j] > selector ||
                (state->source_vlan_selectors[j] == selector &&
                 state->source_vlans[j] > vlan))) {
            state->source_vlans[j + 1] = state->source_vlans[j];
            state->source_vlan_selectors[j + 1] =
                state->source_vlan_selectors[j];
            state->source_vlan_directions[j + 1] =
                state->source_vlan_directions[j];
            j--;
        }
        state->source_vlans[j + 1] = vlan;
        state->source_vlan_selectors[j + 1] = selector;
        state->source_vlan_directions[j + 1] = direction;
    }
}

static int read_sources_v2(int sw, int group, hal_mirror_state *state) {
    fm_int port = 0;
    fm_mirrorType type = FM_MIRROR_TYPE_INGRESS;
    fm_status status;

    status = fmGetMirrorPortFirstV2((fm_int)sw, (fm_int)group,
                                    &port, &type);
    if (status == FM_ERR_NO_PORTS_IN_MIRROR_GROUP)
        return 0;
    if (status == FM_ERR_UNSUPPORTED)
        return 1;
    if (status != FM_OK)
        return -1;
    while (status == FM_OK) {
        fm_int next = 0;
        fm_mirrorType next_type = FM_MIRROR_TYPE_INGRESS;
        int direction = direction_from_sdk(type);

        if (port <= 0 || direction == 0 ||
            state->n_sources >= NETLAB_MIRROR_MAX_SOURCES)
            return -1;
        state->source_ports[state->n_sources] = (int)port;
        state->source_directions[state->n_sources] = direction;
        state->n_sources++;
        status = fmGetMirrorPortNextV2((fm_int)sw, (fm_int)group, port,
                                       &next, &next_type);
        if (status == FM_ERR_NO_PORTS_IN_MIRROR_GROUP)
            break;
        if (status != FM_OK)
            return -1;
        port = next;
        type = next_type;
    }
    return 0;
}

static int read_sources_legacy(int sw, int group, hal_mirror_state *state) {
    fm_int port = 0;
    fm_status status = fmGetMirrorPortFirst((fm_int)sw, (fm_int)group, &port);

    if (status == FM_ERR_NO_PORTS_IN_MIRROR_GROUP)
        return 0;
    if (status != FM_OK)
        return -1;
    while (status == FM_OK) {
        fm_int next = 0;

        if (port <= 0 || state->n_sources >= NETLAB_MIRROR_MAX_SOURCES)
            return -1;
        state->source_ports[state->n_sources] = (int)port;
        state->source_directions[state->n_sources] = state->direction;
        state->n_sources++;
        status = fmGetMirrorPortNext((fm_int)sw, (fm_int)group, port, &next);
        if (status == FM_ERR_NO_PORTS_IN_MIRROR_GROUP)
            break;
        if (status != FM_OK)
            return -1;
        port = next;
    }
    return 0;
}

static int read_vlan_sources(int sw, int group, fm_vlanSelect selector,
                             hal_mirror_state *state) {
    fm_uint16 vlan = 0;
    fm_mirrorVlanType direction = FM_MIRROR_VLAN_INGRESS;
    fm_status status;

    if (!state)
        return -1;
    status = fmGetMirrorVlanFirstExt(
        (fm_int)sw, (fm_int)group, selector, &vlan, &direction);
    if (status == FM_ERR_NO_VLANS_IN_MIRROR_GROUP)
        return 0;
    if (status != FM_OK)
        return -1;

    while (status == FM_OK) {
        fm_uint16 next = 0;
        fm_mirrorVlanType next_direction = FM_MIRROR_VLAN_INGRESS;

        if (vlan == 0 || vlan >= FM_MAX_VLAN ||
            direction < FM_MIRROR_VLAN_INGRESS ||
            direction > FM_MIRROR_VLAN_BIDIRECTIONAL ||
            state->n_vlan_sources >= NETLAB_MIRROR_MAX_SOURCES)
            return -1;
        state->source_vlans[state->n_vlan_sources] = (u16)vlan;
        state->source_vlan_selectors[state->n_vlan_sources] =
            (int)selector;
        state->source_vlan_directions[state->n_vlan_sources] =
            (int)direction;
        state->n_vlan_sources++;

        status = fmGetMirrorVlanNextExt(
            (fm_int)sw, (fm_int)group, selector, vlan,
            &next, &next_direction);
        if (status == FM_ERR_NO_VLANS_IN_MIRROR_GROUP)
            break;
        if (status != FM_OK || next <= vlan)
            return -1;
        vlan = next;
        direction = next_direction;
    }
    return 0;
}

static int read_mirror_attributes(int sw, int group,
                                  hal_mirror_state *state) {
    fm_bool truncate = FALSE;
    fm_bool acl_filter = FALSE;
    fm_int sample_rate = FM_MIRROR_SAMPLE_RATE_DISABLED;
    fm_int encapsulation_vlan = FM_MIRROR_NO_VLAN_ENCAP;
    fm_byte vlan_priority = 0;
    fm_int trapcode_id = 0;
    fm_status status;

    if (!state)
        return -1;
    status = fmGetMirrorAttribute(
        (fm_int)sw, (fm_int)group, FM_MIRROR_TRUNCATE, &truncate);
    if (status == FM_OK)
        status = fmGetMirrorAttribute(
            (fm_int)sw, (fm_int)group, FM_MIRROR_SAMPLE_RATE,
            &sample_rate);
    if (status == FM_OK)
        status = fmGetMirrorAttribute(
            (fm_int)sw, (fm_int)group, FM_MIRROR_ACL, &acl_filter);
    if (status == FM_OK)
        status = fmGetMirrorAttribute(
            (fm_int)sw, (fm_int)group, FM_MIRROR_VLAN,
            &encapsulation_vlan);
    if (status == FM_OK)
        status = fmGetMirrorAttribute(
            (fm_int)sw, (fm_int)group, FM_MIRROR_VLAN_PRI,
            &vlan_priority);
    if (status == FM_OK)
        status = fmGetMirrorAttribute(
            (fm_int)sw, (fm_int)group, FM_MIRROR_TRAPCODE_ID,
            &trapcode_id);
    if (status != FM_OK)
        return -1;

    state->attributes_valid = true;
    state->truncate = truncate != FALSE;
    state->acl_filter = acl_filter != FALSE;
    state->sample_rate = (int)sample_rate;
    state->encapsulation_vlan = (int)encapsulation_vlan;
    state->vlan_priority = (int)vlan_priority;
    state->trapcode_id = (int)trapcode_id;
    return 0;
}

int hal_mirror_state_get(int sw, int group, hal_mirror_state *state) {
    fm_int destination = 0;
    fm_mirrorType type = FM_MIRROR_TYPE_INGRESS;
    fm_status status;
    int rc;

    if (!state || group != NETLAB_MIRROR_V1_GROUP)
        return -1;
    memset(state, 0, sizeof(*state));
    state->group = group;
    state->sample_rate = FM_MIRROR_SAMPLE_RATE_DISABLED;
    state->encapsulation_vlan = FM_MIRROR_NO_VLAN_ENCAP;
    status = fmGetMirror((fm_int)sw, (fm_int)group, &destination, &type);
    if (mirror_absent_status(status))
        return 0;
    if (status != FM_OK) {
        NL_LOG_ERR("mirror read-back group=%d failed: %s",
                   group, fmErrorMsg(status));
        return -1;
    }

    state->exists = true;
    state->exact_snapshot = true;
    state->destination_port = (int)destination;
    state->direction = direction_from_sdk(type);
    if (state->destination_port <= 0 || state->direction == 0)
        return -1;
    rc = read_sources_v2(sw, group, state);
    if (rc == 1) {
        state->n_sources = 0;
        rc = read_sources_legacy(sw, group, state);
    }
    if (rc != 0)
        return -1;
    if (read_mirror_attributes(sw, group, state) != 0 ||
        read_vlan_sources(
            sw, group, FM_VLAN_SELECT_VLAN1, state) != 0 ||
        read_vlan_sources(
            sw, group, FM_VLAN_SELECT_VLAN2, state) != 0)
        return -1;
    /*
     * An ACL-bound mirror has dependencies outside the mirror object.  V1
     * cannot delete and later recreate that ACL graph from this snapshot, so
     * reject it before any transaction is allowed to mutate the group.
     */
    if (state->acl_filter) {
        NL_LOG_ERR("mirror group=%d is ACL-bound and not transaction-restorable",
                   group);
        return -1;
    }
    sort_sources(state);
    sort_vlan_sources(state);
    return 0;
}

static bool mirror_state_valid(const hal_mirror_state *state) {
    if (!state || !state->exists ||
        state->group != NETLAB_MIRROR_V1_GROUP ||
        !state->attributes_valid || state->acl_filter ||
        state->destination_port <= 0 ||
        state->direction < HAL_MIRROR_DIRECTION_INGRESS ||
        state->direction > HAL_MIRROR_DIRECTION_BOTH ||
        state->n_sources < 0 ||
        state->n_sources > NETLAB_MIRROR_MAX_SOURCES ||
        state->n_vlan_sources < 0 ||
        state->n_vlan_sources > NETLAB_MIRROR_MAX_SOURCES ||
        (!state->exact_snapshot && state->n_sources <= 0) ||
        (!state->exact_snapshot && state->n_vlan_sources != 0) ||
        state->sample_rate == 0 ||
        state->sample_rate < FM_MIRROR_SAMPLE_RATE_DISABLED ||
        state->sample_rate > 16777216 ||
        (state->encapsulation_vlan != FM_MIRROR_NO_VLAN_ENCAP &&
         (state->encapsulation_vlan <= 0 ||
          state->encapsulation_vlan >= FM_MAX_VLAN)) ||
        state->vlan_priority < 0 ||
        state->vlan_priority >= FM_MAX_VLAN_PRIORITIES ||
        state->trapcode_id < 0 || state->trapcode_id > 11 ||
        !nl_ifid_is_user_port(state->destination_port))
        return false;
    for (int i = 0; i < state->n_sources; i++) {
        if (!nl_ifid_is_user_port(state->source_ports[i]) ||
            state->source_ports[i] == state->destination_port ||
            state->source_directions[i] < HAL_MIRROR_DIRECTION_INGRESS ||
            state->source_directions[i] > HAL_MIRROR_DIRECTION_BOTH)
            return false;
        for (int j = i + 1; j < state->n_sources; j++)
            if (state->source_ports[i] == state->source_ports[j])
                return false;
    }
    for (int i = 0; i < state->n_vlan_sources; i++) {
        if (state->source_vlans[i] == 0 ||
            state->source_vlans[i] >= FM_MAX_VLAN ||
            (state->source_vlan_selectors[i] != FM_VLAN_SELECT_VLAN1 &&
             state->source_vlan_selectors[i] != FM_VLAN_SELECT_VLAN2) ||
            state->source_vlan_directions[i] <
                FM_MIRROR_VLAN_INGRESS ||
            state->source_vlan_directions[i] >
                FM_MIRROR_VLAN_BIDIRECTIONAL)
            return false;
        for (int j = i + 1; j < state->n_vlan_sources; j++) {
            if (state->source_vlans[i] == state->source_vlans[j] &&
                state->source_vlan_selectors[i] ==
                    state->source_vlan_selectors[j])
                return false;
        }
    }
    return true;
}

int hal_mirror_session_delete(int sw, int group) {
    hal_mirror_state before;
    hal_mirror_state after;
    fm_status status;

    if (group != NETLAB_MIRROR_V1_GROUP)
        return -1;
    if (hal_mirror_state_get(sw, group, &before) != 0)
        return -1;
    if (!before.exists)
        return 0;
    status = fmDeleteMirror((fm_int)sw, (fm_int)group);
    if (status != FM_OK && !mirror_absent_status(status)) {
        NL_LOG_ERR("mirror delete group=%d failed: %s",
                   group, fmErrorMsg(status));
    }
    if (hal_mirror_state_get(sw, group, &after) != 0 || after.exists)
        return status != FM_OK ? (int)status : -1;
    return 0;
}

static int restore_mirror_attributes(int sw,
                                     const hal_mirror_state *state) {
    fm_bool truncate;
    fm_bool acl_filter;
    fm_int sample_rate;
    fm_int encapsulation_vlan;
    fm_byte vlan_priority;
    fm_int trapcode_id;
    fm_status status;

    if (!state || !state->attributes_valid || state->acl_filter)
        return -1;
    truncate = state->truncate ? TRUE : FALSE;
    acl_filter = FALSE;
    sample_rate = (fm_int)state->sample_rate;
    encapsulation_vlan = (fm_int)state->encapsulation_vlan;
    vlan_priority = (fm_byte)state->vlan_priority;
    trapcode_id = (fm_int)state->trapcode_id;

    /* Encapsulation must be established before adding mirrored sources. */
    status = fmSetMirrorAttribute(
        (fm_int)sw, (fm_int)state->group, FM_MIRROR_VLAN,
        &encapsulation_vlan);
    if (status == FM_OK)
        status = fmSetMirrorAttribute(
            (fm_int)sw, (fm_int)state->group, FM_MIRROR_VLAN_PRI,
            &vlan_priority);
    if (status == FM_OK)
        status = fmSetMirrorAttribute(
            (fm_int)sw, (fm_int)state->group, FM_MIRROR_TRUNCATE,
            &truncate);
    if (status == FM_OK)
        status = fmSetMirrorAttribute(
            (fm_int)sw, (fm_int)state->group, FM_MIRROR_SAMPLE_RATE,
            &sample_rate);
    if (status == FM_OK)
        status = fmSetMirrorAttribute(
            (fm_int)sw, (fm_int)state->group, FM_MIRROR_TRAPCODE_ID,
            &trapcode_id);
    if (status == FM_OK)
        status = fmSetMirrorAttribute(
            (fm_int)sw, (fm_int)state->group, FM_MIRROR_ACL,
            &acl_filter);
    return status == FM_OK ? 0 : (int)status;
}

int hal_mirror_session_replace(int sw, const hal_mirror_state *state) {
    fm_mirrorType create_type;
    fm_status status;
    hal_mirror_state current;

    if (!mirror_state_valid(state) ||
        !mirror_group_type(state, &create_type))
        return -1;
    if (hal_mirror_state_get(sw, state->group, &current) != 0)
        return -1;
    if (hal_mirror_state_equal(&current, state))
        return 0;
    if (current.exists && hal_mirror_session_delete(sw, state->group) != 0)
        return -1;

    status = fmCreateMirror((fm_int)sw, (fm_int)state->group,
                            (fm_int)state->destination_port, create_type);
    if (status != FM_OK) {
        NL_LOG_ERR("mirror create group=%d destination=%d failed: %s",
                   state->group, state->destination_port,
                   fmErrorMsg(status));
        return (int)status;
    }
    if (restore_mirror_attributes(sw, state) != 0) {
        (void)fmDeleteMirror((fm_int)sw, (fm_int)state->group);
        return -1;
    }
    for (int i = 0; i < state->n_sources; i++) {
        fm_mirrorType source_type;

        if (!direction_to_sdk(state->source_directions[i], &source_type)) {
            (void)hal_mirror_session_delete(sw, state->group);
            return -1;
        }
        status = fmAddMirrorPortExt((fm_int)sw, (fm_int)state->group,
                                    (fm_int)state->source_ports[i],
                                    source_type);
        if (status != FM_OK) {
            NL_LOG_ERR("mirror add source group=%d port=%d failed: %s",
                       state->group, state->source_ports[i],
                       fmErrorMsg(status));
            (void)hal_mirror_session_delete(sw, state->group);
            return (int)status;
        }
    }
    for (int i = 0; i < state->n_vlan_sources; i++) {
        status = fmAddMirrorVlanExt(
            (fm_int)sw, (fm_int)state->group,
            (fm_vlanSelect)state->source_vlan_selectors[i],
            (fm_uint16)state->source_vlans[i],
            (fm_mirrorVlanType)state->source_vlan_directions[i]);
        if (status != FM_OK) {
            NL_LOG_ERR("mirror add VLAN source group=%d selector=%d vlan=%u failed: %s",
                       state->group, state->source_vlan_selectors[i],
                       state->source_vlans[i], fmErrorMsg(status));
            (void)fmDeleteMirror((fm_int)sw, (fm_int)state->group);
            return (int)status;
        }
    }
    if (hal_mirror_state_get(sw, state->group, &current) != 0 ||
        !hal_mirror_state_equal(&current, state)) {
        (void)fmDeleteMirror((fm_int)sw, (fm_int)state->group);
        return -1;
    }
    return 0;
}

bool hal_mirror_state_equal(const hal_mirror_state *a,
                            const hal_mirror_state *b) {
    hal_mirror_state left;
    hal_mirror_state right;

    if (!a || !b || a->exists != b->exists)
        return false;
    if (!a->exists)
        return true;
    left = *a;
    right = *b;
    sort_sources(&left);
    sort_sources(&right);
    sort_vlan_sources(&left);
    sort_vlan_sources(&right);
    if (left.group != right.group ||
        left.destination_port != right.destination_port ||
        left.direction != right.direction ||
        left.attributes_valid != right.attributes_valid ||
        left.n_sources != right.n_sources ||
        left.n_vlan_sources != right.n_vlan_sources)
        return false;
    if (left.attributes_valid &&
        (left.truncate != right.truncate ||
         left.acl_filter != right.acl_filter ||
         left.sample_rate != right.sample_rate ||
         left.encapsulation_vlan != right.encapsulation_vlan ||
         left.vlan_priority != right.vlan_priority ||
         left.trapcode_id != right.trapcode_id))
        return false;
    for (int i = 0; i < left.n_sources; i++) {
        if (left.source_ports[i] != right.source_ports[i] ||
            left.source_directions[i] != right.source_directions[i])
            return false;
    }
    for (int i = 0; i < left.n_vlan_sources; i++) {
        if (left.source_vlans[i] != right.source_vlans[i] ||
            left.source_vlan_selectors[i] !=
                right.source_vlan_selectors[i] ||
            left.source_vlan_directions[i] !=
                right.source_vlan_directions[i])
            return false;
    }
    return true;
}
