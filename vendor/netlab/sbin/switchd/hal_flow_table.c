#include "hal_flow_table.h"

#include "netlab/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HAL_FLOW_TABLE_CONTROL_PLANE 31
#define HAL_FLOW_TABLE_L2_SECURITY 30
#define HAL_FLOW_TABLE_MIN 1
#define HAL_FLOW_TABLE_MAX 31
#define HAL_FLOW_RESERVATION_MAX 16

typedef struct {
    bool used;
    bool locally_created;
    fm_int sw;
    fm_int table;
    hal_flow_owner owner;
    fm_uint64 generation;
    char name[32];
    fm_flowCondition condition;
    fm_uint32 max_entries;
    fm_uint32 max_actions;
    bool with_priority;
} hal_flow_reservation;

static hal_flow_reservation g_reservations[HAL_FLOW_RESERVATION_MAX];
static fm_uint64 g_next_creation_generation = 1;

const char *hal_flow_owner_name(hal_flow_owner owner) {
    switch (owner) {
    case HAL_FLOW_OWNER_CONTROL_PLANE:
        return "control-plane";
    case HAL_FLOW_OWNER_ACL:
        return "acl";
    case HAL_FLOW_OWNER_QOS:
        return "qos";
    case HAL_FLOW_OWNER_STORM_CONTROL:
        return "storm-control";
    case HAL_FLOW_OWNER_L2_SECURITY:
        return "l2-security";
    default:
        return "unknown";
    }
}

static fm_int default_table_for_owner(hal_flow_owner owner) {
    switch (owner) {
    case HAL_FLOW_OWNER_CONTROL_PLANE:
        return HAL_FLOW_TABLE_CONTROL_PLANE;
    case HAL_FLOW_OWNER_L2_SECURITY:
        return HAL_FLOW_TABLE_L2_SECURITY;
    case HAL_FLOW_OWNER_ACL:
    case HAL_FLOW_OWNER_QOS:
    case HAL_FLOW_OWNER_STORM_CONTROL:
    default:
        return 0;
    }
}

static bool valid_table_index(fm_int table) {
    return table >= HAL_FLOW_TABLE_MIN && table <= HAL_FLOW_TABLE_MAX;
}

static hal_flow_reservation *find_reservation(int sw, fm_int table) {
    for (int i = 0; i < HAL_FLOW_RESERVATION_MAX; i++) {
        if (g_reservations[i].used && g_reservations[i].sw == sw &&
            g_reservations[i].table == table)
            return &g_reservations[i];
    }
    return NULL;
}

static bool reservation_slot_available(void) {
    for (int i = 0; i < HAL_FLOW_RESERVATION_MAX; i++) {
        if (!g_reservations[i].used)
            return true;
    }
    return false;
}

static bool reservation_matches_spec(const hal_flow_reservation *r,
                                     const hal_flow_table_spec *spec) {
    return r && spec &&
           r->owner == spec->owner &&
           r->condition == spec->condition &&
           r->max_entries == spec->max_entries &&
           r->max_actions == spec->max_actions &&
           r->with_priority == spec->with_priority;
}

static void clear_creation_token(hal_flow_table_creation_token *token) {
    if (!token)
        return;
    memset(token, 0, sizeof(*token));
    token->sw = -1;
    token->table = -1;
}

static fm_uint64 next_creation_generation(void) {
    fm_uint64 generation = g_next_creation_generation++;

    if (generation == 0) {
        generation = 1;
        g_next_creation_generation = 2;
    }
    return generation;
}

static int remember_reservation(int sw, fm_int table,
                                const hal_flow_table_spec *spec,
                                bool locally_created,
                                fm_uint64 generation) {
    hal_flow_reservation *r = find_reservation(sw, table);

    if (!spec)
        return -1;
    if (r) {
        if (!reservation_matches_spec(r, spec)) {
            NL_LOG_ERR("flow table %d already reserved by %s, cannot reuse for %s",
                       table, hal_flow_owner_name(r->owner),
                       hal_flow_owner_name(spec->owner));
            return -1;
        }
        return 0;
    }

    for (int i = 0; i < HAL_FLOW_RESERVATION_MAX; i++) {
        if (!g_reservations[i].used) {
            g_reservations[i].used = true;
            g_reservations[i].locally_created = locally_created;
            g_reservations[i].sw = sw;
            g_reservations[i].table = table;
            g_reservations[i].owner = spec->owner;
            g_reservations[i].generation = generation;
            snprintf(g_reservations[i].name, sizeof(g_reservations[i].name),
                     "%s", spec->name ? spec->name :
                     hal_flow_owner_name(spec->owner));
            g_reservations[i].condition = spec->condition;
            g_reservations[i].max_entries = spec->max_entries;
            g_reservations[i].max_actions = spec->max_actions;
            g_reservations[i].with_priority = spec->with_priority;
            return 0;
        }
    }

    NL_LOG_ERR("flow table reservation registry is full");
    return -1;
}

static int get_int_table_attr(int sw, fm_int table, fm_int attr, fm_int *out) {
    if (!out)
        return -1;
    return fmGetFlowAttribute((fm_int)sw, table, attr, out) == FM_OK ? 0 : -1;
}

static int get_condition_table_attr(int sw, fm_int table,
                                    fm_flowCondition *out) {
    if (!out)
        return -1;
    return fmGetFlowAttribute((fm_int)sw, table, FM_FLOW_TABLE_CONDITION,
                              out) == FM_OK ? 0 : -1;
}

static int get_bool_table_attr(int sw, fm_int table, fm_int attr,
                               fm_bool *out) {
    if (!out)
        return -1;
    return fmGetFlowAttribute((fm_int)sw, table, attr, out) == FM_OK ? 0 : -1;
}

static int compare_owner_by_table(const void *a, const void *b) {
    const hal_flow_table_owner_info *oa = a;
    const hal_flow_table_owner_info *ob = b;

    if (oa->table < ob->table)
        return -1;
    if (oa->table > ob->table)
        return 1;
    return 0;
}

static int verify_existing_table(int sw, fm_int table,
                                 const hal_flow_table_spec *spec,
                                 hal_flow_table_reservation *out) {
    fm_flowTableType type;
    fm_flowCondition condition = 0;
    fm_int max_actions = 0;
    fm_int max_entries = 0;
    fm_int empty_entries = 0;
    fm_bool priority_enabled = FM_DISABLED;
    fm_status st;

    st = fmGetFlowTableType((fm_int)sw, table, &type);
    if (st != FM_OK)
        return -1;
    if (type != FM_FLOW_TCAM_TABLE) {
        NL_LOG_ERR("flow table %d exists but is not TCAM", table);
        return -1;
    }

    if (get_condition_table_attr(sw, table, &condition) != 0 ||
        get_int_table_attr(sw, table, FM_FLOW_TABLE_MAX_ACTIONS, &max_actions) != 0 ||
        get_int_table_attr(sw, table, FM_FLOW_TABLE_MAX_ENTRIES, &max_entries) != 0 ||
        get_int_table_attr(sw, table, FM_FLOW_TABLE_EMPTY_ENTRIES, &empty_entries) != 0 ||
        get_bool_table_attr(sw, table, FM_FLOW_TABLE_WITH_PRIORITY,
                            &priority_enabled) != 0) {
        NL_LOG_ERR("flow table %d exists but attributes are unreadable", table);
        return -1;
    }

    if ((condition & spec->condition) != spec->condition) {
        NL_LOG_ERR("flow table %d condition mismatch for %s",
                   table, spec->name ? spec->name :
                   hal_flow_owner_name(spec->owner));
        return -1;
    }
    if ((fm_uint32)max_actions < spec->max_actions ||
        (fm_uint32)max_entries < spec->max_entries) {
        NL_LOG_ERR("flow table %d capacity mismatch for %s",
                   table, spec->name ? spec->name :
                   hal_flow_owner_name(spec->owner));
        return -1;
    }
    if ((priority_enabled != FM_DISABLED) != spec->with_priority) {
        NL_LOG_ERR("flow table %d priority mode mismatch for %s",
                   table, spec->name ? spec->name :
                   hal_flow_owner_name(spec->owner));
        return -1;
    }

    if (out) {
        out->table = table;
        out->max_entries = (fm_uint32)max_entries;
        out->empty_entries = (fm_uint32)empty_entries;
        out->existed = true;
    }
    return remember_reservation(sw, table, spec, false, 0);
}

int hal_flow_table_reserve_with_token(
    int sw, const hal_flow_table_spec *spec,
    hal_flow_table_reservation *out,
    hal_flow_table_creation_token *creation_token) {
    fm_int table;
    fm_status st;

    clear_creation_token(creation_token);
    if (out) {
        memset(out, 0, sizeof(*out));
        out->table = -1;
    }
    if (!spec || spec->owner <= 0 || spec->condition == 0 ||
        spec->max_entries == 0 || spec->max_actions == 0)
        return -1;

    table = spec->preferred_table > 0 ?
            spec->preferred_table : default_table_for_owner(spec->owner);
    if (!valid_table_index(table)) {
        NL_LOG_ERR("flow table %d is outside managed range for %s",
                   table, hal_flow_owner_name(spec->owner));
        return -1;
    }

    if (find_reservation(sw, table))
        return verify_existing_table(sw, table, spec, out);
    if (!reservation_slot_available()) {
        NL_LOG_ERR("flow table reservation registry is full");
        return -1;
    }

    if (spec->with_priority) {
        fm_bool enabled = FM_ENABLED;
        st = fmSetFlowAttribute((fm_int)sw, table,
                                FM_FLOW_TABLE_WITH_PRIORITY, &enabled);
        if (st != FM_OK)
        {
            NL_LOG_ERR("flow table %d priority enable failed for %s: %s",
                       table, spec->name ? spec->name :
                       hal_flow_owner_name(spec->owner), fmErrorMsg(st));
            return -1;
        }
    }

    st = fmCreateFlowTCAMTable((fm_int)sw, table, spec->condition,
                               spec->max_entries, spec->max_actions);
    if (st == FM_OK) {
        fm_uint64 generation = next_creation_generation();
        fm_int empty_entries = 0;

        if (remember_reservation(sw, table, spec, true, generation) != 0) {
            NL_LOG_CRIT("created flow table %d but could not record ownership",
                        table);
            return -1;
        }
        if (out) {
            out->table = table;
            out->max_entries = spec->max_entries;
            out->empty_entries =
                get_int_table_attr(sw, table, FM_FLOW_TABLE_EMPTY_ENTRIES,
                                   &empty_entries) == 0 ?
                (fm_uint32)empty_entries : spec->max_entries;
            out->existed = false;
        }
        NL_LOG_INFO("reserved flow table %d for %s (%u entries, %u actions)",
                    table, spec->name ? spec->name :
                    hal_flow_owner_name(spec->owner),
                    spec->max_entries, spec->max_actions);
        if (creation_token) {
            creation_token->valid = true;
            creation_token->sw = sw;
            creation_token->table = table;
            creation_token->owner = spec->owner;
            creation_token->generation = generation;
            creation_token->condition = spec->condition;
            creation_token->max_entries = spec->max_entries;
            creation_token->max_actions = spec->max_actions;
            creation_token->with_priority = spec->with_priority;
        }
        return 0;
    }

    if (st == FM_ERR_ALREADY_EXISTS)
        return verify_existing_table(sw, table, spec, out);

    NL_LOG_ERR("flow table %d reserve failed for %s: %s",
               table, spec->name ? spec->name :
               hal_flow_owner_name(spec->owner), fmErrorMsg(st));
    return -1;
}

int hal_flow_table_reserve(int sw, const hal_flow_table_spec *spec,
                           hal_flow_table_reservation *out) {
    return hal_flow_table_reserve_with_token(sw, spec, out, NULL);
}

static int flow_table_presence_read(int sw, fm_int wanted,
                                    bool *present, int *sdk_status) {
    fm_int current = -1;
    fm_status st;

    if (present)
        *present = false;
    if (sdk_status)
        *sdk_status = FM_ERR_INVALID_ARGUMENT;
    if (!present)
        return -1;

    st = fmGetFlowFirst((fm_int)sw, &current);
    if (st == FM_ERR_NO_MORE) {
        if (sdk_status)
            *sdk_status = (int)st;
        return 0;
    }
    if (st != FM_OK) {
        if (sdk_status)
            *sdk_status = (int)st;
        return -1;
    }

    for (int scanned = 0; scanned < FM_FLOW_MAX_TABLE_TYPE; scanned++) {
        fm_int next = -1;

        if (current == wanted) {
            *present = true;
            if (sdk_status)
                *sdk_status = FM_OK;
            return 0;
        }
        st = fmGetFlowNext((fm_int)sw, current, &next);
        if (st == FM_ERR_NO_MORE) {
            if (sdk_status)
                *sdk_status = (int)st;
            return 0;
        }
        if (st != FM_OK || next <= current) {
            if (sdk_status)
                *sdk_status = st != FM_OK ?
                              (int)st : FM_ERR_MODIFIED_WHILE_ITERATING;
            return -1;
        }
        current = next;
    }

    if (sdk_status)
        *sdk_status = FM_ERR_MODIFIED_WHILE_ITERATING;
    return -1;
}

int hal_flow_table_release_created_empty(
    int sw, const hal_flow_table_spec *spec,
    const hal_flow_table_creation_token *creation_token) {
    hal_flow_reservation *reservation;
    fm_int first_rule = -1;
    fm_status st;
    bool present = true;
    int sdk_status = FM_ERR_INVALID_ARGUMENT;

    if (!spec || !creation_token || !creation_token->valid ||
        creation_token->sw != sw ||
        creation_token->owner != spec->owner ||
        creation_token->condition != spec->condition ||
        creation_token->max_entries != spec->max_entries ||
        creation_token->max_actions != spec->max_actions ||
        creation_token->with_priority != spec->with_priority)
        return -1;

    reservation = find_reservation(sw, creation_token->table);
    if (!reservation || !reservation->locally_created ||
        reservation->generation != creation_token->generation ||
        !reservation_matches_spec(reservation, spec)) {
        NL_LOG_ERR("flow table release token does not own table %d",
                   creation_token->table);
        return -1;
    }

    /*
     * A prior release attempt may have deleted the table and then failed its
     * absence read-back.  Keep the token/registry on that unknown outcome,
     * but let a later retry converge once the SDK can authoritatively prove
     * ABSENT.
     */
    if (flow_table_presence_read(sw, creation_token->table, &present,
                                 &sdk_status) != 0)
        return -1;
    if (!present) {
        memset(reservation, 0, sizeof(*reservation));
        NL_LOG_INFO(
            "reconciled absent flow table %d generation=%llu",
            creation_token->table,
            (unsigned long long)creation_token->generation);
        return 0;
    }
    if (verify_existing_table(sw, creation_token->table, spec, NULL) != 0)
        return -1;

    /*
     * The FM10000 delete API removes every unused rule; it does not require an
     * empty table.  A successful terminal first-rule read is therefore a
     * mandatory destructive-action guard.
     */
    st = fmGetFlowRuleFirst((fm_int)sw, creation_token->table, &first_rule);
    if (st == FM_OK) {
        NL_LOG_WARN("refusing to release non-empty flow table %d (flow=%d)",
                    creation_token->table, first_rule);
        return -1;
    }
    if (st != FM_ERR_NO_MORE)
        return -1;

    st = fmDeleteFlowTCAMTable((fm_int)sw, creation_token->table);
    if (st != FM_OK) {
        NL_LOG_ERR("flow table %d release failed: %s",
                   creation_token->table, fmErrorMsg(st));
        return -1;
    }

    if (flow_table_presence_read(sw, creation_token->table, &present,
                                 &sdk_status) != 0 ||
        present) {
        NL_LOG_ERR("flow table %d delete read-back failed (status=%d present=%d)",
                   creation_token->table, sdk_status, present ? 1 : 0);
        return -1;
    }

    memset(reservation, 0, sizeof(*reservation));
    NL_LOG_INFO("released empty flow table %d generation=%llu",
                creation_token->table,
                (unsigned long long)creation_token->generation);
    return 0;
}

int hal_flow_table_collect_owners(int sw, hal_flow_table_owner_info *owners,
                                  int max_owners) {
    int count = 0;

    if (!owners || max_owners <= 0)
        return 0;

    memset(owners, 0, (size_t)max_owners * sizeof(*owners));

    for (int i = 0; i < HAL_FLOW_RESERVATION_MAX && count < max_owners; i++) {
        hal_flow_reservation *r = &g_reservations[i];
        fm_int max_entries = -1;
        fm_int empty_entries = -1;
        fm_int max_actions = -1;
        fm_flowCondition condition = 0;

        if (!r->used || r->sw != sw)
            continue;

        owners[count].table = r->table;
        owners[count].owner = r->owner;
        snprintf(owners[count].name, sizeof(owners[count].name), "%s",
                 r->name[0] ? r->name : hal_flow_owner_name(r->owner));

        if (get_int_table_attr(sw, r->table, FM_FLOW_TABLE_MAX_ENTRIES,
                               &max_entries) == 0)
            owners[count].max_entries = (fm_uint32)max_entries;
        else
            owners[count].max_entries = r->max_entries;

        if (get_int_table_attr(sw, r->table, FM_FLOW_TABLE_EMPTY_ENTRIES,
                               &empty_entries) == 0)
            owners[count].empty_entries = (fm_uint32)empty_entries;
        else
            owners[count].empty_entries = 0;

        if (owners[count].max_entries >= owners[count].empty_entries)
            owners[count].used_entries =
                owners[count].max_entries - owners[count].empty_entries;
        else
            owners[count].used_entries = 0;

        if (get_int_table_attr(sw, r->table, FM_FLOW_TABLE_MAX_ACTIONS,
                               &max_actions) == 0)
            owners[count].max_actions = (fm_uint32)max_actions;
        else
            owners[count].max_actions = r->max_actions;

        if (get_condition_table_attr(sw, r->table, &condition) == 0)
            owners[count].condition = condition;
        else
            owners[count].condition = r->condition;

        count++;
    }

    qsort(owners, (size_t)count, sizeof(*owners), compare_owner_by_table);
    return count;
}
