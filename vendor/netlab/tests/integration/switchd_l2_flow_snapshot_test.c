#include "netlab/hal.h"
#include "netlab/hal_l2_flow_snapshot.h"
#include "netlab/log.h"
#include "hal_flow_table.h"

#include <api/fm_api_flow.h>
#include <fm_sdk.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_TABLE 28
#define MAX_TEST_FLOWS 128

typedef struct {
    bool used;
    fm_int id;
    fm_flowCondition condition;
    fm_flowValue value;
    fm_flowAction action;
    fm_flowParam param;
    fm_int priority;
    fm_int precedence;
    fm_aclEntryState state;
} test_flow;

static test_flow g_flows[MAX_TEST_FLOWS];
static bool g_table_exists;
static bool g_other_table_exists;
static fm_int g_next_flow_id = 1;
static fm_status g_table_first_error;
static fm_status g_table_first_delayed_error;
static int g_table_first_calls_before_delayed_error;
static fm_status g_table_next_error;
static fm_status g_table_type_error;
static fm_status g_table_attribute_error;
static fm_status g_rule_first_error;
static fm_status g_rule_next_error;
static fm_int g_get_flow_error_id = -1;
static fm_status g_get_flow_error = FM_FAIL;
static fm_int g_get_state_error_id = -1;
static fm_status g_get_state_error = FM_FAIL;
static fm_status g_create_table_error;
static fm_status g_delete_table_error;
static fm_status g_add_flow_error;
static bool g_ignore_table_delete;
static int g_create_table_calls;
static int g_delete_table_calls;
static int g_add_calls;
static int g_delete_calls;
static int g_rule_first_calls;
static int g_rule_next_calls;
static int g_get_flow_calls;
static int g_flow_count_calls;

static void fail_at(const char *file, int line, const char *expr) {
    fprintf(stderr, "%s:%d: check failed: %s\n", file, line, expr);
    exit(1);
}

#define CHECK(expr) \
    do { \
        if (!(expr)) \
            fail_at(__FILE__, __LINE__, #expr); \
    } while (0)

static void reset_injections(void) {
    g_table_first_error = FM_OK;
    g_table_first_delayed_error = FM_OK;
    g_table_first_calls_before_delayed_error = -1;
    g_table_next_error = FM_OK;
    g_table_type_error = FM_OK;
    g_table_attribute_error = FM_OK;
    g_rule_first_error = FM_OK;
    g_rule_next_error = FM_OK;
    g_get_flow_error_id = -1;
    g_get_flow_error = FM_FAIL;
    g_get_state_error_id = -1;
    g_get_state_error = FM_FAIL;
    g_create_table_error = FM_OK;
    g_delete_table_error = FM_OK;
    g_add_flow_error = FM_OK;
    g_ignore_table_delete = false;
}

static void reset_write_counts(void) {
    g_create_table_calls = 0;
    g_delete_table_calls = 0;
    g_add_calls = 0;
    g_delete_calls = 0;
}

static void reset_read_counts(void) {
    g_rule_first_calls = 0;
    g_rule_next_calls = 0;
    g_get_flow_calls = 0;
    g_flow_count_calls = 0;
}

static void reset_hardware(void) {
    memset(g_flows, 0, sizeof(g_flows));
    g_table_exists = false;
    g_other_table_exists = false;
    g_next_flow_id = 1;
    reset_injections();
    reset_write_counts();
    reset_read_counts();
}

static int active_flow_count(void) {
    int count = 0;

    for (int i = 0; i < MAX_TEST_FLOWS; i++) {
        if (g_flows[i].used)
            count++;
    }
    return count;
}

static test_flow *flow_by_ordinal(int ordinal) {
    int found = 0;

    for (int i = 0; i < MAX_TEST_FLOWS; i++) {
        if (!g_flows[i].used)
            continue;
        if (found == ordinal)
            return &g_flows[i];
        found++;
    }
    return NULL;
}

static test_flow *allocate_flow(void) {
    for (int i = 0; i < MAX_TEST_FLOWS; i++) {
        if (!g_flows[i].used) {
            memset(&g_flows[i], 0, sizeof(g_flows[i]));
            g_flows[i].used = true;
            g_flows[i].id = g_next_flow_id++;
            return &g_flows[i];
        }
    }
    return NULL;
}

static test_flow *clone_flow(const test_flow *source) {
    test_flow *copy = allocate_flow();
    fm_int id;

    if (!copy || !source)
        return NULL;
    id = copy->id;
    *copy = *source;
    copy->used = true;
    copy->id = id;
    return copy;
}

static void check_zero_writes(void) {
    CHECK(g_create_table_calls == 0);
    CHECK(g_delete_table_calls == 0);
    CHECK(g_add_calls == 0);
    CHECK(g_delete_calls == 0);
}

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

const char *fmErrorMsg(fm_int err) {
    (void)err;
    return "mock";
}

fm_status fmSetFlowAttribute(fm_int sw, fm_int table_index, fm_int attribute,
                             void *value) {
    (void)sw;
    CHECK(table_index == TEST_TABLE);
    CHECK(value != NULL);
    CHECK(attribute == FM_FLOW_TABLE_WITH_PRIORITY);
    CHECK(*(fm_bool *)value == FM_ENABLED);
    return FM_OK;
}

fm_status fmCreateFlowTCAMTable(fm_int sw, fm_int table_index,
                                fm_flowCondition condition,
                                fm_uint32 max_entries,
                                fm_uint32 max_actions) {
    (void)sw;
    CHECK(table_index == TEST_TABLE);
    CHECK(condition != 0);
    CHECK(max_entries == 64);
    CHECK(max_actions == 2);
    g_create_table_calls++;
    if (g_create_table_error != FM_OK)
        return g_create_table_error;
    if (g_table_exists)
        return FM_ERR_ALREADY_EXISTS;
    g_table_exists = true;
    return FM_OK;
}

fm_status fmDeleteFlowTCAMTable(fm_int sw, fm_int table_index) {
    (void)sw;
    CHECK(table_index == TEST_TABLE);
    g_delete_table_calls++;
    if (g_delete_table_error != FM_OK)
        return g_delete_table_error;
    CHECK(active_flow_count() == 0);
    if (!g_ignore_table_delete)
        g_table_exists = false;
    return FM_OK;
}

fm_status fmGetFlowFirst(fm_int sw, fm_int *table_index) {
    (void)sw;
    CHECK(table_index != NULL);
    if (g_table_first_delayed_error != FM_OK &&
        g_table_first_calls_before_delayed_error == 0)
        return g_table_first_delayed_error;
    if (g_table_first_calls_before_delayed_error > 0)
        g_table_first_calls_before_delayed_error--;
    if (g_table_first_error != FM_OK)
        return g_table_first_error;
    if (g_other_table_exists) {
        *table_index = 10;
        return FM_OK;
    }
    if (g_table_exists) {
        *table_index = TEST_TABLE;
        return FM_OK;
    }
    return FM_ERR_NO_MORE;
}

fm_status fmGetFlowNext(fm_int sw, fm_int current_table,
                        fm_int *table_index) {
    (void)sw;
    CHECK(table_index != NULL);
    if (g_table_next_error != FM_OK)
        return g_table_next_error;
    if (current_table == 10 && g_table_exists) {
        *table_index = TEST_TABLE;
        return FM_OK;
    }
    return FM_ERR_NO_MORE;
}

fm_status fmGetFlowTableType(fm_int sw, fm_int table_index,
                             fm_flowTableType *type) {
    (void)sw;
    CHECK(type != NULL);
    if (g_table_type_error != FM_OK)
        return g_table_type_error;
    if (table_index != TEST_TABLE || !g_table_exists)
        return FM_ERR_NOT_FOUND;
    *type = FM_FLOW_TCAM_TABLE;
    return FM_OK;
}

fm_status fmGetFlowAttribute(fm_int sw, fm_int table_index, fm_int attribute,
                             void *value) {
    (void)sw;
    CHECK(value != NULL);
    if (g_table_attribute_error != FM_OK)
        return g_table_attribute_error;
    if (table_index != TEST_TABLE || !g_table_exists)
        return FM_ERR_NOT_FOUND;
    if (attribute == FM_FLOW_TABLE_WITH_PRIORITY) {
        *(fm_bool *)value = FM_DISABLED;
        return FM_OK;
    }
    if (attribute == FM_FLOW_TABLE_CONDITION) {
        *(fm_flowCondition *)value =
            FM_FLOW_MATCH_VLAN |
            FM_FLOW_MATCH_LOGICAL_PORT |
            FM_FLOW_MATCH_PROTOCOL |
            FM_FLOW_MATCH_ETHERTYPE |
            FM_FLOW_MATCH_SRC_MAC |
            FM_FLOW_MATCH_DST_MAC |
            FM_FLOW_MATCH_SRC_IP |
            FM_FLOW_MATCH_DST_IP |
            FM_FLOW_MATCH_TOS |
            FM_FLOW_MATCH_TCP_FLAGS |
            FM_FLOW_MATCH_L4_SRC_PORT |
            FM_FLOW_MATCH_L4_DST_PORT |
            FM_FLOW_MATCH_L2_DEEP_INSPECTION;
        return FM_OK;
    }
    if (attribute == FM_FLOW_TABLE_MAX_ACTIONS) {
        *(fm_int *)value = 2;
        return FM_OK;
    }
    if (attribute == FM_FLOW_TABLE_MAX_ENTRIES) {
        *(fm_int *)value = 64;
        return FM_OK;
    }
    if (attribute == FM_FLOW_TABLE_EMPTY_ENTRIES) {
        *(fm_int *)value = 64 - active_flow_count();
        return FM_OK;
    }
    return FM_ERR_INVALID_ATTRIB;
}

fm_status fmGetFlowRuleFirst(fm_int sw, fm_int table_index,
                             fm_int *first_rule) {
    test_flow *first = NULL;

    (void)sw;
    g_rule_first_calls++;
    CHECK(first_rule != NULL);
    if (g_rule_first_error != FM_OK)
        return g_rule_first_error;
    if (table_index != TEST_TABLE || !g_table_exists)
        return FM_ERR_NO_MORE;
    for (int i = 0; i < MAX_TEST_FLOWS; i++) {
        if (g_flows[i].used &&
            (!first || g_flows[i].id < first->id))
            first = &g_flows[i];
    }
    if (!first)
        return FM_ERR_NO_MORE;
    *first_rule = first->id;
    return FM_OK;
}

fm_status fmGetFlowRuleNext(fm_int sw, fm_int table_index,
                            fm_int current_rule, fm_int *next_rule) {
    test_flow *next = NULL;

    (void)sw;
    g_rule_next_calls++;
    CHECK(next_rule != NULL);
    if (g_rule_next_error != FM_OK)
        return g_rule_next_error;
    if (table_index != TEST_TABLE || !g_table_exists)
        return FM_ERR_NO_MORE;
    for (int i = 0; i < MAX_TEST_FLOWS; i++) {
        if (g_flows[i].used && g_flows[i].id > current_rule &&
            (!next || g_flows[i].id < next->id))
            next = &g_flows[i];
    }
    if (!next)
        return FM_ERR_NO_MORE;
    *next_rule = next->id;
    return FM_OK;
}

fm_status fmGetFlow(fm_int sw, fm_int table_index, fm_int flow_id,
                    fm_flowCondition *condition, fm_flowValue *value,
                    fm_flowAction *action, fm_flowParam *param,
                    fm_int *priority, fm_int *precedence) {
    (void)sw;
    g_get_flow_calls++;
    if (flow_id == g_get_flow_error_id)
        return g_get_flow_error;
    if (table_index != TEST_TABLE)
        return FM_ERR_NOT_FOUND;
    for (int i = 0; i < MAX_TEST_FLOWS; i++) {
        if (!g_flows[i].used || g_flows[i].id != flow_id)
            continue;
        *condition = g_flows[i].condition;
        *value = g_flows[i].value;
        *action = g_flows[i].action;
        *param = g_flows[i].param;
        *priority = g_flows[i].priority;
        *precedence = g_flows[i].precedence;
        return FM_OK;
    }
    return FM_ERR_NOT_FOUND;
}

fm_status fmGetACLRuleState(fm_int sw, fm_int acl, fm_int rule,
                            fm_aclEntryState *state) {
    (void)sw;
    CHECK(acl == 21000000 + TEST_TABLE);
    CHECK(state != NULL);
    if (rule == g_get_state_error_id)
        return g_get_state_error;
    for (int i = 0; i < MAX_TEST_FLOWS; i++) {
        if (g_flows[i].used && g_flows[i].id == rule) {
            *state = g_flows[i].state;
            return FM_OK;
        }
    }
    return FM_ERR_NOT_FOUND;
}

fm_status fmAddFlow(fm_int sw, fm_int table_index, fm_uint16 priority,
                    fm_uint32 precedence, fm_flowCondition condition,
                    fm_flowValue *value, fm_flowAction action,
                    fm_flowParam *param, fm_flowState state,
                    fm_int *flow_id) {
    test_flow *flow;

    (void)sw;
    CHECK(table_index == TEST_TABLE);
    CHECK(value != NULL);
    CHECK(param != NULL);
    CHECK(state == FM_FLOW_STATE_ENABLED);
    if (g_add_flow_error != FM_OK)
        return g_add_flow_error;
    flow = allocate_flow();
    if (!flow)
        return FM_ERR_NO_MEM;
    flow->condition = condition;
    flow->value = *value;
    flow->action = action;
    flow->param = *param;
    /*
     * Table 28 is configured without priority.  The pinned FM10000 getter
     * leaves its caller-initialized priority at zero.
     */
    (void)priority;
    flow->priority = 0;
    flow->precedence = (fm_int)precedence;
    flow->state = FM_ACL_RULE_ENTRY_STATE_VALID;
    g_table_exists = true;
    g_add_calls++;
    if (flow_id)
        *flow_id = flow->id;
    return FM_OK;
}

fm_status fmDeleteFlow(fm_int sw, fm_int table_index, fm_int flow_id) {
    (void)sw;
    CHECK(table_index == TEST_TABLE);
    g_delete_calls++;
    for (int i = 0; i < MAX_TEST_FLOWS; i++) {
        if (g_flows[i].used && g_flows[i].id == flow_id) {
            g_flows[i].used = false;
            return FM_OK;
        }
    }
    return FM_ERR_NOT_FOUND;
}

fm_status fmGetFlowCount(fm_int sw, fm_int table_index, fm_int flow_id,
                         fm_flowCounters *counters) {
    (void)sw;
    (void)table_index;
    (void)flow_id;
    g_flow_count_calls++;
    if (counters)
        memset(counters, 0, sizeof(*counters));
    return FM_OK;
}

static void test_user_filter_counter_snapshot_single_scan(void) {
    nl_acl_counter_query query;
    nl_acl_counter_snapshot snapshot;

    reset_hardware();
    memset(&query, 0, sizeof(query));
    memset(&snapshot, 0, sizeof(snapshot));
    query.n_entries = NL_ACL_COUNTER_MAX_USER_FILTERS;
    snapshot.n_entries = query.n_entries;
    for (u16 i = 0; i < query.n_entries; i++) {
        nl_acl_counter_query_entry *entry = &query.entries[i];
        u8 mac[6] = {0x02, 0, 0, 0, 0, (u8)(i + 1)};

        CHECK(hal_l2_security_user_filter_set(
                  0, (u16)(100 + i), 4, mac,
                  L2_SECURITY_MAC_SOURCE) == 0);
        entry->id = i;
        entry->kind = NL_ACL_COUNTER_KIND_USER_FILTER;
        entry->mac_kind = NL_ACL_COUNTER_MAC_SOURCE;
        entry->match.vid = (u16)(100 + i);
        entry->match.port = 4;
        memcpy(entry->mac, mac, sizeof(entry->mac));
        snapshot.entries[i].id = i;
        snapshot.entries[i].kind = entry->kind;
        snapshot.entries[i].state = NL_ACL_COUNTER_STATE_ABSENT;
    }

    reset_read_counts();
    CHECK(hal_l2_security_user_filter_counter_snapshot(
              0, &query, &snapshot) == 0);
    CHECK(g_rule_first_calls == 1);
    CHECK(g_rule_next_calls == 64);
    CHECK(g_get_flow_calls == 64);
    CHECK(g_flow_count_calls == 64);
    for (u16 i = 0; i < snapshot.n_entries; i++)
        CHECK(snapshot.entries[i].state ==
              NL_ACL_COUNTER_STATE_INSTALLED);
}

static void test_ingress_counter_snapshot_single_scan(void) {
    nl_acl_counter_query query;
    nl_acl_counter_snapshot snapshot;

    reset_hardware();
    memset(&query, 0, sizeof(query));
    memset(&snapshot, 0, sizeof(snapshot));
    query.n_entries = NL_ACL_COUNTER_MAX_INGRESS_IPV4;
    snapshot.n_entries = query.n_entries;
    for (u16 i = 0; i < query.n_entries; i++) {
        hal_ingress_ipv4_acl_match match;
        nl_acl_counter_query_entry *entry = &query.entries[i];

        memset(&match, 0, sizeof(match));
        match.vid = 200 + i;
        match.port = 5;
        match.has_protocol = true;
        match.protocol = i + 1;
        CHECK(hal_ingress_ipv4_acl_set(0, &match) == 0);
        entry->id = i;
        entry->kind = NL_ACL_COUNTER_KIND_INGRESS_IPV4;
        entry->match.vid = (u16)match.vid;
        entry->match.port = (u16)match.port;
        entry->match.flags = NL_ACL_COUNTER_MATCH_PROTOCOL;
        entry->match.protocol = match.protocol;
        snapshot.entries[i].id = i;
        snapshot.entries[i].kind = entry->kind;
        snapshot.entries[i].state = NL_ACL_COUNTER_STATE_ABSENT;
    }

    reset_read_counts();
    CHECK(hal_ingress_ipv4_acl_counter_snapshot(
              0, &query, &snapshot) == 0);
    CHECK(g_rule_first_calls == 1);
    CHECK(g_rule_next_calls == 64);
    CHECK(g_get_flow_calls == 64);
    CHECK(g_flow_count_calls == 64);
    for (u16 i = 0; i < snapshot.n_entries; i++)
        CHECK(snapshot.entries[i].state ==
              NL_ACL_COUNTER_STATE_INSTALLED);
}

static hal_ingress_ipv4_acl_match test_acl_match(void) {
    hal_ingress_ipv4_acl_match match;

    memset(&match, 0, sizeof(match));
    match.vid = 200;
    match.port = 7;
    match.has_src_ip = true;
    match.has_src_ip_mask = true;
    match.src_ip = 0x0a000000U;
    match.src_ip_mask = 0xffffff00U;
    match.has_protocol = true;
    match.protocol = 6;
    match.has_src_port_range = true;
    match.src_port_start = 1000;
    match.src_port_end = 1005;
    match.has_dst_port = true;
    match.dst_port = 443;
    match.has_tcp_flags = true;
    match.has_tcp_flags_mask = true;
    match.tcp_flags = 0x02;
    match.tcp_flags_mask = 0x12;
    return match;
}

static void test_table_snapshot_error_fidelity(void) {
    hal_flow_presence_snapshot snapshot;

    reset_hardware();
    snapshot = hal_l2_security_table_snapshot(0);
    CHECK(snapshot.state == HAL_PRESENCE_ABSENT);
    CHECK(snapshot.sdk_status == FM_ERR_NO_MORE);
    check_zero_writes();

    g_table_first_error = FM_FAIL;
    snapshot = hal_l2_security_table_snapshot(0);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_FAIL);
    check_zero_writes();

    reset_hardware();
    g_other_table_exists = true;
    g_table_exists = true;
    g_table_next_error = FM_ERR_MODIFIED_WHILE_ITERATING;
    snapshot = hal_l2_security_table_snapshot(0);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_MODIFIED_WHILE_ITERATING);
    check_zero_writes();

    reset_hardware();
    g_table_exists = true;
    g_table_attribute_error = FM_ERR_UNINITIALIZED;
    snapshot = hal_l2_security_table_snapshot(0);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_UNINITIALIZED);
    check_zero_writes();
}

static void test_security_exact_snapshot(void) {
    hal_flow_presence_snapshot snapshot;
    test_flow saved;
    test_flow *flow;

    reset_hardware();
    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) == 0);
    CHECK(active_flow_count() == 1);
    flow = flow_by_ordinal(0);
    CHECK(flow != NULL);
    saved = *flow;

    reset_write_counts();
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(snapshot.exact);
    CHECK(snapshot.expected_rules == 1);
    CHECK(snapshot.observed_rules == 1);
    check_zero_writes();

    CHECK(hal_l2_security_rule_present(
              0, "dhcp-snooping", 100, 3) == 1);
    check_zero_writes();

    flow->priority++;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    *flow = saved;

    flow->precedence = 1;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    *flow = saved;

    flow->param.vlan = 100;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    *flow = saved;

    flow->action = FM_FLOW_ACTION_PERMIT | FM_FLOW_ACTION_COUNT;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    *flow = saved;

    flow->condition |= FM_FLOW_MATCH_TOS;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    *flow = saved;

    flow->state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    *flow = saved;

    g_get_flow_error_id = flow->id;
    g_get_flow_error = FM_ERR_UNINITIALIZED;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_UNINITIALIZED);
    reset_injections();

    g_get_state_error_id = flow->id;
    g_get_state_error = FM_ERR_UNINITIALIZED;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_UNINITIALIZED);
    reset_injections();

    g_rule_next_error = FM_ERR_MODIFIED_WHILE_ITERATING;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_MODIFIED_WHILE_ITERATING);
    reset_injections();

    g_rule_first_error = FM_FAIL;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_FAIL);
    reset_injections();

    g_table_exists = false;
    snapshot = hal_l2_security_rule_snapshot(
        0, "dhcp-snooping", 100, 3);
    CHECK(snapshot.state == HAL_PRESENCE_ABSENT);
    check_zero_writes();
}

static void test_security_binding_and_filter(void) {
    static const u8 binding_mac[6] = {0x02, 0, 0, 0, 0, 1};
    static const u8 filter_mac[6] = {0x02, 0, 0, 0, 0, 2};
    hal_flow_presence_snapshot snapshot;

    reset_hardware();
    CHECK(hal_l2_security_arp_binding_set(
              0, 101, 4, binding_mac, 0xc0000201U) == 0);
    CHECK(hal_l2_security_user_filter_set(
              0, 101, 4, filter_mac,
              L2_SECURITY_MAC_DESTINATION) == 0);

    reset_write_counts();
    snapshot = hal_l2_security_arp_binding_snapshot(
        0, 101, 4, binding_mac, 0xc0000201U);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(snapshot.exact);
    snapshot = hal_l2_security_user_filter_snapshot(
        0, 101, 4, filter_mac, L2_SECURITY_MAC_DESTINATION);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(snapshot.exact);
    check_zero_writes();
}

static void test_arp_deny_and_binding_coexist(void) {
    static const u8 binding_mac[6] = {0x02, 0, 0, 0, 0, 3};
    hal_flow_presence_snapshot deny;
    hal_flow_presence_snapshot binding;

    reset_hardware();
    CHECK(hal_l2_security_arp_inspection_set(0, 101, 4) == 0);
    CHECK(hal_l2_security_arp_binding_set(
              0, 101, 4, binding_mac, 0xc0000203U) == 0);
    CHECK(active_flow_count() == 2);

    reset_write_counts();
    deny = hal_l2_security_rule_snapshot(
        0, "arp-inspection", 101, 4);
    binding = hal_l2_security_arp_binding_snapshot(
        0, 101, 4, binding_mac, 0xc0000203U);
    CHECK(deny.state == HAL_PRESENCE_PRESENT);
    CHECK(deny.exact);
    CHECK(deny.observed_rules == 1);
    CHECK(binding.state == HAL_PRESENCE_PRESENT);
    CHECK(binding.exact);
    CHECK(binding.observed_rules == 1);
    check_zero_writes();

    CHECK(hal_l2_security_arp_binding_delete(
              0, 101, 4, binding_mac, 0xc0000203U) == 0);
    deny = hal_l2_security_rule_snapshot(
        0, "arp-inspection", 101, 4);
    CHECK(deny.state == HAL_PRESENCE_PRESENT);
    CHECK(deny.exact);
    CHECK(active_flow_count() == 1);
}

static void test_acl_group_snapshot(void) {
    hal_ingress_ipv4_acl_match match = test_acl_match();
    hal_flow_presence_snapshot snapshot;
    test_flow saved_first;
    test_flow *first;
    test_flow *second;
    test_flow *duplicate;

    reset_hardware();
    CHECK(hal_ingress_ipv4_acl_set(0, &match) == 0);
    CHECK(active_flow_count() == 2);
    first = flow_by_ordinal(0);
    second = flow_by_ordinal(1);
    CHECK(first != NULL);
    CHECK(second != NULL);
    saved_first = *first;

    reset_write_counts();
    snapshot = hal_ingress_ipv4_acl_snapshot(0, &match);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(snapshot.exact);
    CHECK(snapshot.expected_rules == 2);
    CHECK(snapshot.observed_rules == 2);
    check_zero_writes();

    CHECK(hal_ingress_ipv4_acl_present(0, &match) == 1);
    check_zero_writes();

    first->priority++;
    snapshot = hal_ingress_ipv4_acl_snapshot(0, &match);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    *first = saved_first;

    first->used = false;
    snapshot = hal_ingress_ipv4_acl_snapshot(0, &match);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    CHECK(snapshot.observed_rules == 1);
    second->used = false;
    snapshot = hal_ingress_ipv4_acl_snapshot(0, &match);
    CHECK(snapshot.state == HAL_PRESENCE_ABSENT);
    first->used = true;
    second->used = true;

    duplicate = clone_flow(first);
    CHECK(duplicate != NULL);
    snapshot = hal_ingress_ipv4_acl_snapshot(0, &match);
    CHECK(snapshot.state == HAL_PRESENCE_PRESENT);
    CHECK(!snapshot.exact);
    CHECK(snapshot.observed_rules == 3);
    duplicate->used = false;

    duplicate = allocate_flow();
    CHECK(duplicate != NULL);
    duplicate->condition = FM_FLOW_MATCH_VLAN;
    duplicate->value.vlanId = 4094;
    g_get_flow_error_id = duplicate->id;
    g_get_flow_error = FM_ERR_UNINITIALIZED;
    snapshot = hal_ingress_ipv4_acl_snapshot(0, &match);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_UNINITIALIZED);
    reset_injections();
    duplicate->used = false;

    g_rule_next_error = FM_ERR_MODIFIED_WHILE_ITERATING;
    snapshot = hal_ingress_ipv4_acl_snapshot(0, &match);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_MODIFIED_WHILE_ITERATING);
    reset_injections();
    check_zero_writes();
}

static void test_invalid_requests_are_unknown(void) {
    hal_ingress_ipv4_acl_match match;
    hal_flow_presence_snapshot snapshot;

    reset_hardware();
    snapshot = hal_l2_security_rule_snapshot(0, "unknown", 1, 1);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_INVALID_ARGUMENT);

    memset(&match, 0, sizeof(match));
    snapshot = hal_ingress_ipv4_acl_snapshot(0, &match);
    CHECK(snapshot.state == HAL_PRESENCE_READ_ERROR);
    CHECK(snapshot.sdk_status == FM_ERR_INVALID_ARGUMENT);
    check_zero_writes();
}

static void test_absent_delete_is_pure(void) {
    hal_ingress_ipv4_acl_match match = test_acl_match();
    hal_flow_table_creation_token token;

    reset_hardware();
    CHECK(hal_l2_security_dhcp_snooping_delete(0, 100, 3) == 0);
    CHECK(hal_l2_security_take_created_table_token(&token) == 0);
    CHECK(!token.valid);
    CHECK(hal_ingress_ipv4_acl_delete(0, &match) == 0);
    CHECK(hal_l2_security_take_created_table_token(&token) == 0);
    CHECK(!token.valid);
    CHECK(!g_table_exists);
    check_zero_writes();

    g_table_first_error = FM_ERR_UNINITIALIZED;
    CHECK(hal_l2_security_dhcp_snooping_delete(0, 100, 3) != 0);
    CHECK(hal_ingress_ipv4_acl_delete(0, &match) != 0);
    check_zero_writes();
}

static void test_creation_token_lifecycle(void) {
    hal_flow_table_creation_token creator;
    hal_flow_table_creation_token none;
    hal_flow_table_creation_token recreated;

    reset_hardware();
    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) == 0);
    CHECK(g_create_table_calls == 1);
    CHECK(hal_l2_security_take_created_table_token(&creator) == 1);
    CHECK(creator.valid);
    CHECK(creator.table == TEST_TABLE);
    CHECK(creator.owner == HAL_FLOW_OWNER_L2_SECURITY);
    CHECK(creator.generation != 0);

    CHECK(hal_l2_security_arp_inspection_set(0, 100, 3) == 0);
    CHECK(g_create_table_calls == 1);
    CHECK(hal_l2_security_take_created_table_token(&none) == 0);
    CHECK(!none.valid);
    CHECK(active_flow_count() == 2);

    CHECK(hal_l2_security_release_created_table_empty(&creator) != 0);
    CHECK(g_delete_table_calls == 0);
    CHECK(g_table_exists);

    CHECK(hal_l2_security_arp_inspection_delete(0, 100, 3) == 0);
    CHECK(hal_l2_security_dhcp_snooping_delete(0, 100, 3) == 0);
    CHECK(active_flow_count() == 0);
    CHECK(hal_l2_security_release_created_table_empty(&creator) == 0);
    CHECK(g_delete_table_calls == 1);
    CHECK(!g_table_exists);

    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) == 0);
    CHECK(g_create_table_calls == 2);
    CHECK(hal_l2_security_take_created_table_token(&recreated) == 1);
    CHECK(recreated.valid);
    CHECK(recreated.generation != creator.generation);
    CHECK(hal_l2_security_dhcp_snooping_delete(0, 100, 3) == 0);
    CHECK(hal_l2_security_release_created_table_empty(&recreated) == 0);
    CHECK(g_delete_table_calls == 2);
    CHECK(!g_table_exists);
}

static void test_shared_acl_creation_token(void) {
    hal_ingress_ipv4_acl_match match = test_acl_match();
    hal_flow_table_creation_token creator;
    hal_flow_table_creation_token none;

    reset_hardware();
    CHECK(hal_ingress_ipv4_acl_set(0, &match) == 0);
    CHECK(active_flow_count() == 2);
    CHECK(hal_l2_security_take_created_table_token(&creator) == 1);
    CHECK(creator.valid);

    CHECK(hal_l2_security_dhcp_snooping_set(0, 200, 7) == 0);
    CHECK(hal_l2_security_take_created_table_token(&none) == 0);
    CHECK(!none.valid);
    CHECK(g_create_table_calls == 1);
    CHECK(active_flow_count() == 3);

    CHECK(hal_l2_security_dhcp_snooping_delete(0, 200, 7) == 0);
    CHECK(hal_ingress_ipv4_acl_delete(0, &match) == 0);
    CHECK(active_flow_count() == 0);
    CHECK(hal_l2_security_release_created_table_empty(&creator) == 0);
    CHECK(!g_table_exists);
}

static void test_creation_token_survives_add_failure(void) {
    hal_flow_table_creation_token creator;

    reset_hardware();
    g_add_flow_error = FM_FAIL;
    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) != 0);
    CHECK(g_table_exists);
    CHECK(active_flow_count() == 0);
    CHECK(hal_l2_security_take_created_table_token(&creator) == 1);
    CHECK(creator.valid);
    g_add_flow_error = FM_OK;
    CHECK(hal_l2_security_release_created_table_empty(&creator) == 0);
    CHECK(!g_table_exists);
}

static void test_release_failure_retains_ownership(void) {
    hal_flow_table_creation_token creator;

    reset_hardware();
    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) == 0);
    CHECK(hal_l2_security_take_created_table_token(&creator) == 1);
    CHECK(hal_l2_security_dhcp_snooping_delete(0, 100, 3) == 0);

    g_delete_table_error = FM_FAIL;
    CHECK(hal_l2_security_release_created_table_empty(&creator) != 0);
    CHECK(g_table_exists);
    CHECK(g_delete_table_calls == 1);
    g_delete_table_error = FM_OK;
    CHECK(hal_l2_security_release_created_table_empty(&creator) == 0);
    CHECK(!g_table_exists);
    CHECK(g_delete_table_calls == 2);
}

static void test_release_readback_failure_retains_registry(void) {
    hal_flow_table_creation_token creator;

    reset_hardware();
    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) == 0);
    CHECK(hal_l2_security_take_created_table_token(&creator) == 1);
    CHECK(hal_l2_security_dhcp_snooping_delete(0, 100, 3) == 0);

    g_ignore_table_delete = true;
    CHECK(hal_l2_security_release_created_table_empty(&creator) != 0);
    CHECK(g_table_exists);
    g_ignore_table_delete = false;
    CHECK(hal_l2_security_release_created_table_empty(&creator) == 0);
    CHECK(!g_table_exists);
}

static void test_release_unknown_readback_is_not_cleared(void) {
    hal_flow_table_creation_token creator;
    hal_flow_table_creation_token none;
    hal_flow_table_creation_token recreated;

    reset_hardware();
    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) == 0);
    CHECK(hal_l2_security_take_created_table_token(&creator) == 1);
    CHECK(hal_l2_security_dhcp_snooping_delete(0, 100, 3) == 0);

    /*
     * Let the release preflight see PRESENT, then make only the post-delete
     * presence read unknown.
     */
    g_table_first_delayed_error = FM_ERR_UNINITIALIZED;
    g_table_first_calls_before_delayed_error = 1;
    CHECK(hal_l2_security_release_created_table_empty(&creator) != 0);
    CHECK(!g_table_exists);

    /*
     * The hardware may be gone, but the unverified release retained registry
     * ownership.  A new SET cannot silently create a fresh generation.
     */
    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) != 0);
    CHECK(hal_l2_security_take_created_table_token(&none) == 0);
    CHECK(!none.valid);
    CHECK(g_create_table_calls == 1);

    g_table_first_delayed_error = FM_OK;
    g_table_first_calls_before_delayed_error = -1;
    CHECK(hal_l2_security_release_created_table_empty(&creator) == 0);
    CHECK(hal_l2_security_dhcp_snooping_set(0, 100, 3) == 0);
    CHECK(hal_l2_security_take_created_table_token(&recreated) == 1);
    CHECK(recreated.valid);
    CHECK(recreated.generation != creator.generation);
    CHECK(g_create_table_calls == 2);
    CHECK(hal_l2_security_dhcp_snooping_delete(0, 100, 3) == 0);
    CHECK(hal_l2_security_release_created_table_empty(&recreated) == 0);
}

typedef void (*test_case_fn)(void);

typedef struct {
    const char *name;
    test_case_fn run;
} test_case;

int main(int argc, char **argv) {
    const test_case tests[] = {
        {"table-snapshot", test_table_snapshot_error_fidelity},
        {"security-snapshot", test_security_exact_snapshot},
        {"security-binding", test_security_binding_and_filter},
        {"arp-deny-binding", test_arp_deny_and_binding_coexist},
        {"acl-snapshot", test_acl_group_snapshot},
        {"invalid-request", test_invalid_requests_are_unknown},
        {"absent-delete", test_absent_delete_is_pure},
        {"token-lifecycle", test_creation_token_lifecycle},
        {"shared-token", test_shared_acl_creation_token},
        {"token-add-failure", test_creation_token_survives_add_failure},
        {"release-sdk-failure", test_release_failure_retains_ownership},
        {"release-present", test_release_readback_failure_retains_registry},
        {"release-unknown", test_release_unknown_readback_is_not_cleared},
        {"user-counter-batch", test_user_filter_counter_snapshot_single_scan},
        {"ingress-counter-batch", test_ingress_counter_snapshot_single_scan},
    };

    if (argc != 2)
        return 2;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (strcmp(argv[1], tests[i].name) != 0)
            continue;
        tests[i].run();
        printf("%s: PASS\n", tests[i].name);
        return 0;
    }
    return 2;
}
