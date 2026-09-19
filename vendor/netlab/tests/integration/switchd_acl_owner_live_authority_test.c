#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../../sbin/switchd/hal_acl_policer_probe.c"

#define TEST_SW 0
#define TEST_PORT 7
#define TEST_OTHER_PORT 8
#define SIM_MAX_RULES 256
#define SIM_MAX_PORTSETS 128
#define SIM_MAX_POLICERS 400

typedef struct {
    bool present;
    fm_aclEntryState state;
    fm_aclCondition condition;
    fm_aclValue value;
    fm_aclActionExt action;
    fm_aclParamExt param;
    fm_aclCounters counters;
} simulated_rule;

typedef struct {
    bool present;
    fm_uint32 scenarios;
    fm_int precedence;
    fm_int ports[4];
    fm_aclType types[4];
    int n_ports;
} simulated_acl;

typedef struct {
    bool present;
    fm_int members[4];
    int n_members;
} simulated_portset;

typedef struct {
    bool present;
    fm_uint32 attrs[9];
} simulated_policer;

typedef struct {
    simulated_acl shared_acl;
    simulated_acl egress_acls[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];
    simulated_rule shared_rules[SIM_MAX_RULES];
    simulated_rule egress_rules[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];
    simulated_portset portsets[SIM_MAX_PORTSETS];
    simulated_policer policers[SIM_MAX_POLICERS];
    int next_portset;

    int fail_acl;
    int fail_rule_acl;
    int fail_rule;
    int fail_rule_state_acl;
    int fail_rule_state;
    int fail_portset;
    int fail_acl_port;
    int fail_policer;
    int fail_policer_attr;
    int fail_counter_acl;
    int fail_counter_rule;
    fm_status fail_status;

    int create_acl_calls;
    int create_portset_calls;
    int add_portset_port_calls;
    int create_policer_calls;
    int add_acl_port_calls;
    int add_rule_calls;
    int delete_acl_port_calls;
    int delete_rule_calls;
    int delete_policer_calls;
    int delete_portset_calls;
    int delete_acl_calls;
    int compile_calls;
    int apply_calls;
    fm_status compile_status;
    char compile_text[1024];
} acl_owner_simulator;

static acl_owner_simulator g_sim;
static int g_failed;

static simulated_acl *sim_acl(int acl) {
    if (acl == NETLAB_ACL_POLICER_PROBE_ACL_ID)
        return &g_sim.shared_acl;
    if (acl >= NETLAB_ACL_EGRESS_OWNER_ACL_ID &&
        acl < NETLAB_ACL_EGRESS_OWNER_ACL_ID +
              NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS)
        return &g_sim.egress_acls[
            acl - NETLAB_ACL_EGRESS_OWNER_ACL_ID];
    return NULL;
}

static simulated_rule *sim_rule(int acl, int rule) {
    if (acl == NETLAB_ACL_POLICER_PROBE_ACL_ID &&
        rule >= 0 && rule < SIM_MAX_RULES)
        return &g_sim.shared_rules[rule];
    if (acl >= NETLAB_ACL_EGRESS_OWNER_ACL_ID &&
        acl < NETLAB_ACL_EGRESS_OWNER_ACL_ID +
              NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS &&
        rule == NETLAB_ACL_EGRESS_OWNER_RULE)
        return &g_sim.egress_rules[
            acl - NETLAB_ACL_EGRESS_OWNER_ACL_ID];
    return NULL;
}

static int write_count(void) {
    return g_sim.create_acl_calls +
           g_sim.create_portset_calls +
           g_sim.add_portset_port_calls +
           g_sim.create_policer_calls +
           g_sim.add_acl_port_calls +
           g_sim.add_rule_calls +
           g_sim.delete_acl_port_calls +
           g_sim.delete_rule_calls +
           g_sim.delete_policer_calls +
           g_sim.delete_portset_calls +
           g_sim.delete_acl_calls +
           g_sim.compile_calls +
           g_sim.apply_calls;
}

static void expect(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        g_failed++;
}

static void reset_simulator(void) {
    memset(&g_sim, 0, sizeof(g_sim));
    g_sim.shared_acl.present = true;
    g_sim.shared_acl.scenarios =
        FM_ACL_SCENARIO_ANY_FRAME_TYPE |
        FM_ACL_SCENARIO_ANY_ROUTING_TYPE |
        FM_ACL_SCENARIO_ANY_TUNNEL_TYPE;
    g_sim.shared_acl.precedence = FM_ACL_DEFAULT_PRECEDENCE;
    g_sim.next_portset = 50;
    g_sim.fail_acl = -1;
    g_sim.fail_rule_acl = -1;
    g_sim.fail_rule = -1;
    g_sim.fail_rule_state_acl = -1;
    g_sim.fail_rule_state = -1;
    g_sim.fail_portset = -1;
    g_sim.fail_acl_port = -1;
    g_sim.fail_policer = -1;
    g_sim.fail_policer_attr = -1;
    g_sim.fail_counter_acl = -1;
    g_sim.fail_counter_rule = -1;
    g_sim.fail_status = FM_ERR_INVALID_STATE;
    g_sim.compile_status = FM_OK;
    memset(g_acl_policer_owner, 0, sizeof(g_acl_policer_owner));
    memset(g_acl_egress_owner, 0, sizeof(g_acl_egress_owner));
    memset(g_acl_independent_owner, 0, sizeof(g_acl_independent_owner));
    memset(g_acl_shared_creation_registry, 0,
           sizeof(g_acl_shared_creation_registry));
    g_acl_shared_creation_generation = 1;
}

static void seed_portset(int port_set, int port) {
    g_sim.portsets[port_set].present = true;
    g_sim.portsets[port_set].members[0] = (fm_int)port;
    g_sim.portsets[port_set].n_members = 1;
}

static void seed_owner_policer(int policer, int rate_kbps,
                                int burst_bytes) {
    simulated_policer *p = &g_sim.policers[policer];

    memset(p, 0, sizeof(*p));
    p->present = true;
    p->attrs[FM_POLICER_MKDN_DSCP] = FM_DISABLED;
    p->attrs[FM_POLICER_MKDN_SWPRI] = FM_DISABLED;
    p->attrs[FM_POLICER_COLOR_SOURCE] = FM_POLICER_COLOR_SRC_GREEN;
    p->attrs[FM_POLICER_CIR_ACTION] = FM_POLICER_ACTION_DROP;
    p->attrs[FM_POLICER_CIR_CAPACITY] = (fm_uint32)burst_bytes;
    p->attrs[FM_POLICER_CIR_RATE] = (fm_uint32)rate_kbps;
    p->attrs[FM_POLICER_EIR_ACTION] = FM_POLICER_ACTION_DROP;
}

static void seed_policer_owner(int slot, int port, u64 dst_mac,
                                int rate_kbps, int burst_bytes) {
    const int rule_id = owner_rule_for_slot(slot);
    const int policer = owner_policer_for_slot(slot);
    const int port_set = 10 + slot;
    simulated_rule *rule = sim_rule(
        NETLAB_ACL_POLICER_PROBE_ACL_ID, rule_id);

    seed_portset(port_set, port);
    seed_owner_policer(policer, rate_kbps, burst_bytes);
    memset(rule, 0, sizeof(*rule));
    rule->present = true;
    rule->state = FM_ACL_RULE_ENTRY_STATE_VALID;
    rule->condition =
        FM_ACL_MATCH_INGRESS_PORT_SET | FM_ACL_MATCH_DST_MAC;
    rule->value.portSet = (fm_int)port_set;
    rule->value.dst = dst_mac;
    rule->value.dstMask = NETLAB_ACL_INDEPENDENT_MAC_MASK;
    rule->action =
        FM_ACL_ACTIONEXT_POLICE | FM_ACL_ACTIONEXT_COUNT;
    rule->param.policer = (fm_int)policer;
    rule->counters.cntPkts = 11;
    rule->counters.cntOctets = 1100;
}

static void seed_foreign_policer_rule(int slot) {
    simulated_rule *rule = sim_rule(
        NETLAB_ACL_POLICER_PROBE_ACL_ID,
        owner_rule_for_slot(slot));

    memset(rule, 0, sizeof(*rule));
    rule->present = true;
    rule->state = FM_ACL_RULE_ENTRY_STATE_VALID;
    rule->condition = FM_ACL_MATCH_DST_MAC;
    rule->value.dst = 0x02000000f000ULL + (u64)slot;
    rule->value.dstMask = NETLAB_ACL_INDEPENDENT_MAC_MASK;
    rule->action = FM_ACL_ACTIONEXT_PERMIT;
}

static void seed_egress_owner(int slot, int port,
                              u64 src_mac, u64 dst_mac) {
    simulated_acl *acl =
        &g_sim.egress_acls[slot];
    simulated_rule *rule =
        &g_sim.egress_rules[slot];

    memset(acl, 0, sizeof(*acl));
    acl->present = true;
    acl->scenarios =
        FM_ACL_SCENARIO_ANY_FRAME_TYPE |
        FM_ACL_SCENARIO_ANY_ROUTING_TYPE |
        FM_ACL_SCENARIO_ANY_TUNNEL_TYPE;
    acl->precedence = FM_ACL_DEFAULT_PRECEDENCE;
    acl->ports[0] = (fm_int)port;
    acl->types[0] = FM_ACL_TYPE_EGRESS;
    acl->n_ports = 1;
    memset(rule, 0, sizeof(*rule));
    rule->present = true;
    rule->state = FM_ACL_RULE_ENTRY_STATE_VALID;
    rule->condition = fill_egress_mac_value(
        &rule->value, src_mac, dst_mac);
    rule->action = FM_ACL_ACTIONEXT_DENY;
    rule->counters.cntPkts = 7;
    rule->counters.cntOctets = 700;
}

static hal_acl_independent_args independent_args(
    int slot, u64 dst_mac, int rate_kbps, int burst_bytes) {
    hal_acl_independent_args args;

    memset(&args, 0, sizeof(args));
    snprintf(args.group, sizeof(args.group), "g");
    snprintf(args.term, sizeof(args.term), "t-%d", slot);
    snprintf(args.family, sizeof(args.family), "policer");
    snprintf(args.action, sizeof(args.action), "policer");
    args.slot = slot;
    args.vid = 100;
    args.port = TEST_PORT;
    args.has_dst_mac = true;
    args.dst_mac = dst_mac;
    args.rate_kbps = rate_kbps;
    args.burst_bytes = burst_bytes;
    return args;
}

static void seed_independent_owner(
    const hal_acl_independent_args *args) {
    const int port_set = 80 + args->slot;
    const int policer =
        NETLAB_ACL_GENERAL_INGRESS_POLICER_START + args->slot;
    simulated_rule *rule = sim_rule(
        independent_acl_default(),
        independent_rule_for_slot(args->slot));

    seed_portset(port_set, args->port);
    seed_owner_policer(
        policer, args->rate_kbps, args->burst_bytes);
    memset(rule, 0, sizeof(*rule));
    rule->present = true;
    rule->state = FM_ACL_RULE_ENTRY_STATE_VALID;
    rule->condition = fill_independent_acl_term(
        args, (fm_int)port_set, policer, &rule->value,
        &rule->action, &rule->param);
    rule->counters.cntPkts = 5;
    rule->counters.cntOctets = 500;
}

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

const char *fmErrorMsg(fm_int error) {
    (void)error;
    return "simulated SDK failure";
}

bool nl_ifid_is_user_port(int logical_port) {
    return logical_port == TEST_PORT ||
           logical_port == TEST_OTHER_PORT;
}

int hal_acl_resource_reserve(int sw, const hal_acl_resource_spec *spec,
                             hal_acl_resource_reservation *out) {
    (void)sw;
    if (!spec || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->acl = spec->preferred_acl;
    out->acl_count = spec->acl_count > 0 ? spec->acl_count : 1;
    out->rules_per_acl = spec->rules_per_acl;
    out->first_policer = spec->first_policer;
    out->policer_count = spec->policer_count;
    return 0;
}

fm_status fmGetACL(fm_int sw, fm_int acl, fm_aclArguments *args) {
    simulated_acl *simulated = sim_acl((int)acl);

    (void)sw;
    if ((int)acl == g_sim.fail_acl)
        return g_sim.fail_status;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL;
    if (!args)
        return FM_ERR_INVALID_ARGUMENT;
    memset(args, 0, sizeof(*args));
    args->scenarios = simulated->scenarios;
    args->precedence = simulated->precedence;
    return FM_OK;
}

fm_status fmGetACLRule(fm_int sw, fm_int acl, fm_int rule,
                       fm_aclCondition *condition, fm_aclValue *value,
                       fm_aclActionExt *action, fm_aclParamExt *param) {
    simulated_rule *simulated = sim_rule((int)acl, (int)rule);

    (void)sw;
    if ((int)acl == g_sim.fail_rule_acl &&
        (int)rule == g_sim.fail_rule)
        return g_sim.fail_status;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL_RULE;
    *condition = simulated->condition;
    *value = simulated->value;
    *action = simulated->action;
    *param = simulated->param;
    return FM_OK;
}

fm_status fmGetACLRuleFirstExt(
    fm_int sw, fm_int acl, fm_int *first_rule,
    fm_aclCondition *condition, fm_aclValue *value,
    fm_aclActionExt *action, fm_aclParamExt *param) {
    simulated_acl *simulated = sim_acl((int)acl);

    (void)sw;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL;
    if (!first_rule || !condition || !value || !action || !param)
        return FM_ERR_INVALID_ARGUMENT;
    if ((int)acl == NETLAB_ACL_POLICER_PROBE_ACL_ID) {
        for (int rule = 0; rule < SIM_MAX_RULES; rule++) {
            simulated_rule *entry = sim_rule((int)acl, rule);

            if (!entry || !entry->present)
                continue;
            *first_rule = (fm_int)rule;
            *condition = entry->condition;
            *value = entry->value;
            *action = entry->action;
            *param = entry->param;
            return FM_OK;
        }
        return FM_ERR_NO_RULES_IN_ACL;
    }
    simulated_rule *entry = sim_rule(
        (int)acl, NETLAB_ACL_EGRESS_OWNER_RULE);
    if (!entry || !entry->present)
        return FM_ERR_NO_RULES_IN_ACL;
    *first_rule = NETLAB_ACL_EGRESS_OWNER_RULE;
    *condition = entry->condition;
    *value = entry->value;
    *action = entry->action;
    *param = entry->param;
    return FM_OK;
}

fm_status fmGetACLRuleNextExt(
    fm_int sw, fm_int acl, fm_int current_rule, fm_int *next_rule,
    fm_aclCondition *condition, fm_aclValue *value,
    fm_aclActionExt *action, fm_aclParamExt *param) {
    (void)sw;
    (void)acl;
    (void)current_rule;
    (void)next_rule;
    (void)condition;
    (void)value;
    (void)action;
    (void)param;
    return FM_ERR_NO_RULES_IN_ACL;
}

fm_status fmGetACLRuleState(fm_int sw, fm_int acl, fm_int rule,
                            fm_aclEntryState *state) {
    simulated_rule *simulated = sim_rule((int)acl, (int)rule);

    (void)sw;
    if ((int)acl == g_sim.fail_rule_state_acl &&
        (int)rule == g_sim.fail_rule_state)
        return g_sim.fail_status;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL_RULE;
    *state = simulated->state;
    return FM_OK;
}

fm_status fmGetPortSetPortFirst(fm_int sw, fm_int port_set,
                                fm_int *port) {
    simulated_portset *simulated;

    (void)sw;
    if ((int)port_set == g_sim.fail_portset)
        return g_sim.fail_status;
    if (port_set < 0 || port_set >= SIM_MAX_PORTSETS)
        return FM_ERR_INVALID_PORT_SET;
    simulated = &g_sim.portsets[port_set];
    if (!simulated->present)
        return FM_ERR_INVALID_PORT_SET;
    if (simulated->n_members == 0)
        return FM_ERR_NO_PORT_SET_PORT;
    *port = simulated->members[0];
    return FM_OK;
}

fm_status fmGetPortSetPortNext(fm_int sw, fm_int port_set,
                               fm_int current_port, fm_int *next_port) {
    simulated_portset *simulated;

    (void)sw;
    if ((int)port_set == g_sim.fail_portset)
        return g_sim.fail_status;
    if (port_set < 0 || port_set >= SIM_MAX_PORTSETS)
        return FM_ERR_INVALID_PORT_SET;
    simulated = &g_sim.portsets[port_set];
    if (!simulated->present)
        return FM_ERR_INVALID_PORT_SET;
    for (int i = 0; i < simulated->n_members; i++) {
        if (simulated->members[i] != current_port)
            continue;
        if (i + 1 >= simulated->n_members)
            return FM_ERR_NO_PORT_SET_PORT;
        *next_port = simulated->members[i + 1];
        return FM_OK;
    }
    return FM_ERR_NO_PORT_SET_PORT;
}

fm_status fmGetPolicerAttribute(fm_int sw, fm_int policer,
                                fm_int attr, fm_voidptr value) {
    simulated_policer *simulated;

    (void)sw;
    if ((int)policer == g_sim.fail_policer &&
        (g_sim.fail_policer_attr < 0 ||
         (int)attr == g_sim.fail_policer_attr))
        return g_sim.fail_status;
    if (policer < 0 || policer >= SIM_MAX_POLICERS)
        return FM_ERR_INVALID_POLICER;
    simulated = &g_sim.policers[policer];
    if (!simulated->present)
        return FM_ERR_INVALID_POLICER;
    if (attr < FM_POLICER_MKDN_DSCP ||
        attr > FM_POLICER_EIR_RATE)
        return FM_ERR_INVALID_ARGUMENT;
    *(fm_uint32 *)value = simulated->attrs[attr];
    return FM_OK;
}

fm_status fmGetACLPortFirst(fm_int sw, fm_int acl,
                            fm_aclPortAndType *port_and_type) {
    simulated_acl *simulated = sim_acl((int)acl);

    (void)sw;
    if ((int)acl == g_sim.fail_acl_port)
        return g_sim.fail_status;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL;
    if (simulated->n_ports == 0)
        return FM_ERR_NO_MORE;
    port_and_type->port = simulated->ports[0];
    port_and_type->type = simulated->types[0];
    return FM_OK;
}

fm_status fmGetACLPortNext(fm_int sw, fm_int acl,
                           fm_aclPortAndType *port_and_type) {
    simulated_acl *simulated = sim_acl((int)acl);

    (void)sw;
    if ((int)acl == g_sim.fail_acl_port)
        return g_sim.fail_status;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL;
    for (int i = 0; i < simulated->n_ports; i++) {
        if (simulated->ports[i] != port_and_type->port ||
            simulated->types[i] != port_and_type->type)
            continue;
        if (i + 1 >= simulated->n_ports)
            return FM_ERR_NO_MORE;
        port_and_type->port = simulated->ports[i + 1];
        port_and_type->type = simulated->types[i + 1];
        return FM_OK;
    }
    return FM_ERR_NO_MORE;
}

fm_status fmGetACLCountExt(fm_int sw, fm_int acl, fm_int rule,
                           fm_aclCounters *counters) {
    simulated_rule *simulated = sim_rule((int)acl, (int)rule);

    (void)sw;
    if ((int)acl == g_sim.fail_counter_acl &&
        (int)rule == g_sim.fail_counter_rule)
        return g_sim.fail_status;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL_RULE;
    *counters = simulated->counters;
    return FM_OK;
}

fm_status fmGetACLEgressCount(fm_int sw, fm_int port,
                              fm_aclCounters *counters) {
    (void)sw;
    if (g_sim.fail_counter_acl == -2 &&
        (int)port == g_sim.fail_counter_rule)
        return g_sim.fail_status;
    memset(counters, 0, sizeof(*counters));
    counters->cntPkts = 9;
    counters->cntOctets = 900;
    return FM_OK;
}

fm_status fmCreateACL(fm_int sw, fm_int acl) {
    simulated_acl *simulated = sim_acl((int)acl);

    (void)sw;
    g_sim.create_acl_calls++;
    if (!simulated)
        return FM_ERR_INVALID_ACL;
    if (simulated->present)
        return FM_ERR_ALREADY_EXISTS;
    memset(simulated, 0, sizeof(*simulated));
    simulated->present = true;
    simulated->scenarios =
        FM_ACL_SCENARIO_ANY_FRAME_TYPE |
        FM_ACL_SCENARIO_ANY_ROUTING_TYPE |
        FM_ACL_SCENARIO_ANY_TUNNEL_TYPE;
    simulated->precedence = FM_ACL_DEFAULT_PRECEDENCE;
    return FM_OK;
}

fm_status fmCreatePortSet(fm_int sw, fm_int *port_set) {
    (void)sw;
    g_sim.create_portset_calls++;
    while (g_sim.next_portset < SIM_MAX_PORTSETS &&
           g_sim.portsets[g_sim.next_portset].present)
        g_sim.next_portset++;
    if (g_sim.next_portset >= SIM_MAX_PORTSETS)
        return FM_ERR_NO_FREE_PORT_SET;
    *port_set = (fm_int)g_sim.next_portset;
    memset(&g_sim.portsets[g_sim.next_portset], 0,
           sizeof(g_sim.portsets[g_sim.next_portset]));
    g_sim.portsets[g_sim.next_portset].present = true;
    g_sim.next_portset++;
    return FM_OK;
}

fm_status fmAddPortSetPort(fm_int sw, fm_int port_set, fm_int port) {
    simulated_portset *simulated;

    (void)sw;
    g_sim.add_portset_port_calls++;
    if (port_set < 0 || port_set >= SIM_MAX_PORTSETS)
        return FM_ERR_INVALID_PORT_SET;
    simulated = &g_sim.portsets[port_set];
    if (!simulated->present || simulated->n_members >= 4)
        return FM_ERR_INVALID_PORT_SET;
    simulated->members[simulated->n_members++] = port;
    return FM_OK;
}

fm_status fmCreatePolicer(fm_int sw, fm_int bank, fm_int policer,
                          const fm_policerConfig *config) {
    simulated_policer *simulated;

    (void)sw;
    (void)bank;
    g_sim.create_policer_calls++;
    if (policer < 0 || policer >= SIM_MAX_POLICERS || !config)
        return FM_ERR_INVALID_POLICER;
    simulated = &g_sim.policers[policer];
    if (simulated->present)
        return FM_ERR_ALREADY_EXISTS;
    memset(simulated, 0, sizeof(*simulated));
    simulated->present = true;
    simulated->attrs[FM_POLICER_MKDN_DSCP] = config->mkdnDscp;
    simulated->attrs[FM_POLICER_MKDN_SWPRI] = config->mkdnSwPri;
    simulated->attrs[FM_POLICER_COLOR_SOURCE] = config->colorSource;
    simulated->attrs[FM_POLICER_CIR_ACTION] = config->cirAction;
    simulated->attrs[FM_POLICER_CIR_CAPACITY] = config->cirCapacity;
    simulated->attrs[FM_POLICER_CIR_RATE] = config->cirRate;
    simulated->attrs[FM_POLICER_EIR_ACTION] = config->eirAction;
    simulated->attrs[FM_POLICER_EIR_CAPACITY] = config->eirCapacity;
    simulated->attrs[FM_POLICER_EIR_RATE] = config->eirRate;
    return FM_OK;
}

fm_status fmAddACLPortExt(fm_int sw, fm_int acl,
                          const fm_aclPortAndType *port_and_type) {
    simulated_acl *simulated = sim_acl((int)acl);

    (void)sw;
    g_sim.add_acl_port_calls++;
    if (!simulated || !simulated->present || !port_and_type ||
        simulated->n_ports >= 4)
        return FM_ERR_INVALID_ACL;
    simulated->ports[simulated->n_ports] = port_and_type->port;
    simulated->types[simulated->n_ports] = port_and_type->type;
    simulated->n_ports++;
    return FM_OK;
}

fm_status fmAddACLRuleExt(fm_int sw, fm_int acl, fm_int rule,
                          fm_aclCondition condition,
                          const fm_aclValue *value,
                          fm_aclActionExt action,
                          const fm_aclParamExt *param) {
    simulated_rule *simulated = sim_rule((int)acl, (int)rule);

    (void)sw;
    g_sim.add_rule_calls++;
    if (!simulated || simulated->present)
        return FM_ERR_INVALID_ACL_RULE;
    memset(simulated, 0, sizeof(*simulated));
    simulated->present = true;
    simulated->state = FM_ACL_RULE_ENTRY_STATE_VALID;
    simulated->condition = condition;
    simulated->value = *value;
    simulated->action = action;
    simulated->param = *param;
    return FM_OK;
}

fm_status fmCompileACL(fm_int sw, fm_text status_text,
                       fm_int status_text_length, fm_uint32 flags) {
    size_t text_length;

    (void)sw;
    (void)flags;
    g_sim.compile_calls++;
    if (status_text && status_text_length > 0) {
        text_length = strnlen(g_sim.compile_text,
                              sizeof(g_sim.compile_text));
        if (text_length >= (size_t)status_text_length)
            text_length = (size_t)status_text_length - 1U;
        if (text_length > 0)
            memcpy(status_text, g_sim.compile_text, text_length);
        status_text[text_length] = '\0';
    }
    return g_sim.compile_status;
}

fm_status fmApplyACL(fm_int sw, fm_uint32 flags) {
    (void)sw;
    (void)flags;
    g_sim.apply_calls++;
    return FM_OK;
}

fm_status fmDeleteACLPortExt(
    fm_int sw, fm_int acl,
    const fm_aclPortAndType *port_and_type) {
    simulated_acl *simulated = sim_acl((int)acl);

    (void)sw;
    g_sim.delete_acl_port_calls++;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL;
    for (int i = 0; i < simulated->n_ports; i++) {
        if (simulated->ports[i] != port_and_type->port ||
            simulated->types[i] != port_and_type->type)
            continue;
        for (int j = i; j + 1 < simulated->n_ports; j++) {
            simulated->ports[j] = simulated->ports[j + 1];
            simulated->types[j] = simulated->types[j + 1];
        }
        simulated->n_ports--;
        return FM_OK;
    }
    return FM_ERR_INVALID_PORT;
}

fm_status fmDeleteACLRule(fm_int sw, fm_int acl, fm_int rule) {
    simulated_rule *simulated = sim_rule((int)acl, (int)rule);

    (void)sw;
    g_sim.delete_rule_calls++;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL_RULE;
    memset(simulated, 0, sizeof(*simulated));
    return FM_OK;
}

fm_status fmDeletePolicer(fm_int sw, fm_int policer) {
    (void)sw;
    g_sim.delete_policer_calls++;
    if (policer < 0 || policer >= SIM_MAX_POLICERS ||
        !g_sim.policers[policer].present)
        return FM_ERR_INVALID_POLICER;
    memset(&g_sim.policers[policer], 0,
           sizeof(g_sim.policers[policer]));
    return FM_OK;
}

fm_status fmDeletePortSet(fm_int sw, fm_int port_set) {
    (void)sw;
    g_sim.delete_portset_calls++;
    if (port_set < 0 || port_set >= SIM_MAX_PORTSETS ||
        !g_sim.portsets[port_set].present)
        return FM_ERR_INVALID_PORT_SET;
    memset(&g_sim.portsets[port_set], 0,
           sizeof(g_sim.portsets[port_set]));
    return FM_OK;
}

fm_status fmDeleteACL(fm_int sw, fm_int acl) {
    simulated_acl *simulated = sim_acl((int)acl);
    simulated_rule *rule = sim_rule(
        (int)acl, NETLAB_ACL_EGRESS_OWNER_RULE);

    (void)sw;
    g_sim.delete_acl_calls++;
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL;
    memset(simulated, 0, sizeof(*simulated));
    if (rule)
        memset(rule, 0, sizeof(*rule));
    return FM_OK;
}

static void test_restart_cache_empty_live_authority(void) {
    const u64 dst = 0x02000000aa01ULL;
    hal_acl_policer_owner_args policer_args = {
        .port = TEST_PORT,
        .dst_mac = dst,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_egress_owner_args egress_args = {
        .port = TEST_PORT,
        .src_mac = 0x02000000bb01ULL,
        .dst_mac = 0x02000000bb02ULL,
    };
    hal_acl_independent_args independent =
        independent_args(5, 0x02000000cc01ULL, 2000, 8192);
    hal_acl_policer_owner_result policer_result;
    hal_acl_egress_owner_result egress_result;
    hal_acl_independent_result independent_result;

    reset_simulator();
    seed_policer_owner(2, TEST_PORT, dst, 1000, 4096);
    seed_egress_owner(3, TEST_PORT,
                      egress_args.src_mac, egress_args.dst_mac);
    seed_independent_owner(&independent);
    memset(g_acl_policer_owner, 0, sizeof(g_acl_policer_owner));
    memset(g_acl_egress_owner, 0, sizeof(g_acl_egress_owner));
    memset(g_acl_independent_owner, 0, sizeof(g_acl_independent_owner));

    memset(&policer_result, 0, sizeof(policer_result));
    expect("restart cache-empty policer readback discovers live owner",
           hal_acl_policer_owner_readback_match(
               TEST_SW, &policer_args, &policer_result) == 0 &&
           policer_result.active && policer_result.ok &&
           g_acl_policer_owner[2].active);
    memset(&egress_result, 0, sizeof(egress_result));
    expect("restart cache-empty egress readback discovers live owner",
           hal_acl_egress_owner_readback_match(
               TEST_SW, &egress_args, &egress_result) == 0 &&
           egress_result.active && egress_result.ok &&
           g_acl_egress_owner[3].active);
    memset(&independent_result, 0, sizeof(independent_result));
    expect("restart cache-empty independent readback discovers live owner",
           hal_acl_independent_readback_match(
               TEST_SW, &independent, &independent_result) == 0 &&
           independent_result.active && independent_result.ok &&
           g_acl_independent_owner[5].active);
}

static void test_read_error_zero_write(void) {
    hal_acl_policer_owner_args args = {
        .port = TEST_PORT,
        .dst_mac = 0x02000000dd01ULL,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_policer_owner_result result;
    int before;

    reset_simulator();
    g_sim.fail_rule_acl = NETLAB_ACL_POLICER_PROBE_ACL_ID;
    g_sim.fail_rule = owner_rule_for_slot(0);
    before = write_count();
    memset(&result, 0, sizeof(result));
    expect("SDK read error makes policer apply fail closed",
           hal_acl_policer_owner_apply(
               TEST_SW, &args, &result) != 0);
    expect("SDK read error causes zero writes",
           write_count() == before);
}

static void test_foreign_slot_is_not_overwritten(void) {
    hal_acl_policer_owner_args args = {
        .port = TEST_PORT,
        .dst_mac = 0x02000000ee01ULL,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_policer_owner_result result;
    simulated_rule foreign_before;

    reset_simulator();
    seed_foreign_policer_rule(0);
    foreign_before = *sim_rule(
        NETLAB_ACL_POLICER_PROBE_ACL_ID,
        owner_rule_for_slot(0));
    memset(&result, 0, sizeof(result));
    expect("apply skips occupied foreign slot",
           hal_acl_policer_owner_apply(
               TEST_SW, &args, &result) == 0 &&
           result.slot == 1);
    expect("apply never deletes or rewrites foreign slot",
           memcmp(&foreign_before,
                  sim_rule(NETLAB_ACL_POLICER_PROBE_ACL_ID,
                           owner_rule_for_slot(0)),
                  sizeof(foreign_before)) == 0);
}

static void test_changed_rate_snapshot_and_restore(void) {
    const u64 dst = 0x02000000fa01ULL;
    hal_acl_policer_owner_args old_args = {
        .port = TEST_PORT,
        .dst_mac = dst,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_policer_owner_args new_args = old_args;
    hal_acl_policer_owner_transaction_snapshot snapshot;
    hal_acl_policer_owner_transaction_snapshot exact_new;
    hal_acl_policer_owner_result result;

    reset_simulator();
    seed_foreign_policer_rule(0);
    seed_foreign_policer_rule(1);
    seed_policer_owner(2, TEST_PORT, dst, 1000, 4096);
    new_args.rate_kbps = 9000;
    new_args.burst_bytes = 16384;

    snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &new_args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    exact_new = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &new_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    expect("SET semantic snapshot preserves old mutable raw values",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.slot == 2 &&
           snapshot.before.rate_kbps == old_args.rate_kbps &&
           snapshot.before.burst_bytes == old_args.burst_bytes);
    expect("DEL exact rejects changed rate before any write",
           exact_new.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR);

    memset(&result, 0, sizeof(result));
    expect("planner old DEL removes exact old owner",
           hal_acl_policer_owner_rollback_match(
               TEST_SW, &old_args, &result) == 0);
    memset(&result, 0, sizeof(result));
    expect("planner new SET installs new owner",
           hal_acl_policer_owner_apply(
               TEST_SW, &new_args, &result) == 0);
    expect("failed transaction restore replays exact old before-image",
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &new_args, &snapshot) == 0);
    exact_new = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &old_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    expect("existing-object SET rollback proves old rate and slot",
           exact_new.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           exact_new.slot == 2 &&
           exact_new.before.rate_kbps == old_args.rate_kbps &&
           exact_new.before.burst_bytes == old_args.burst_bytes);
}

static void test_external_drift_and_counter_errors(void) {
    const u64 dst = 0x02000000ab01ULL;
    hal_acl_policer_owner_args args = {
        .port = TEST_PORT,
        .dst_mac = dst,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_policer_owner_result result;
    hal_acl_policer_owner_transaction_snapshot snapshot;
    simulated_rule *rule;

    reset_simulator();
    seed_policer_owner(0, TEST_PORT, dst, 1000, 4096);
    rule = sim_rule(
        NETLAB_ACL_POLICER_PROBE_ACL_ID,
        owner_rule_for_slot(0));
    rule->action = FM_ACL_ACTIONEXT_PERMIT;
    memset(&result, 0, sizeof(result));
    expect("external action drift is not reported absent or exact",
           hal_acl_policer_owner_readback_match(
               TEST_SW, &args, &result) != 0);
    snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    expect("external action drift makes transaction capture fail closed",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR);

    reset_simulator();
    seed_policer_owner(0, TEST_PORT, dst, 1000, 4096);
    g_sim.fail_counter_acl = NETLAB_ACL_POLICER_PROBE_ACL_ID;
    g_sim.fail_counter_rule = owner_rule_for_slot(0);
    memset(&result, 0, sizeof(result));
    expect("counter getter failure cannot report verifier success",
           hal_acl_policer_owner_readback_match(
               TEST_SW, &args, &result) != 0 &&
           !result.ok);
}

static void test_egress_live_key_and_exact_port(void) {
    hal_acl_egress_owner_args old_args = {
        .port = TEST_PORT,
        .src_mac = 0x020000001101ULL,
        .dst_mac = 0x020000001102ULL,
    };
    hal_acl_egress_owner_args changed = old_args;
    hal_acl_egress_owner_transaction_snapshot snapshot;
    hal_acl_egress_owner_result result;
    int before;

    reset_simulator();
    seed_egress_owner(
        0, TEST_PORT, old_args.src_mac, old_args.dst_mac);
    changed.dst_mac = 0x020000001103ULL;
    snapshot = hal_acl_egress_owner_transaction_snapshot_get(
        TEST_SW, &changed, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    expect("egress changed match is a different SET semantic key",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT);
    before = write_count();
    memset(&result, 0, sizeof(result));
    expect("direct egress SET refuses an already-owned port",
           hal_acl_egress_owner_apply(
               TEST_SW, &changed, &result) != 0 &&
           write_count() == before);

    g_sim.egress_acls[0].ports[1] = TEST_OTHER_PORT;
    g_sim.egress_acls[0].types[1] = FM_ACL_TYPE_EGRESS;
    g_sim.egress_acls[0].n_ports = 2;
    memset(&result, 0, sizeof(result));
    expect("egress verifier rejects extra ACL port association",
           hal_acl_egress_owner_readback_match(
               TEST_SW, &old_args, &result) != 0);
}

static void test_secondary_port_collision_fails_closed(void) {
    hal_acl_policer_owner_args policer_args = {
        .port = TEST_PORT,
        .dst_mac = 0x020000001801ULL,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_egress_owner_args egress_args = {
        .port = TEST_PORT,
        .src_mac = 0x020000001901ULL,
        .dst_mac = 0x020000001902ULL,
    };
    hal_acl_independent_args independent =
        independent_args(10, 0x020000001a01ULL, 2000, 8192);
    hal_acl_policer_owner_transaction_snapshot policer_snapshot;
    hal_acl_egress_owner_transaction_snapshot egress_snapshot;
    hal_acl_independent_transaction_snapshot independent_snapshot;
    hal_acl_policer_owner_result policer_result;
    hal_acl_egress_owner_result egress_result;
    hal_acl_independent_result independent_result;
    int before;

    reset_simulator();
    seed_policer_owner(
        0, TEST_PORT, policer_args.dst_mac,
        policer_args.rate_kbps, policer_args.burst_bytes);
    g_sim.portsets[10].members[0] = TEST_OTHER_PORT;
    g_sim.portsets[10].members[1] = TEST_PORT;
    g_sim.portsets[10].n_members = 2;
    before = write_count();
    policer_snapshot =
        hal_acl_policer_owner_transaction_snapshot_get(
            TEST_SW, &policer_args,
            HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    memset(&policer_result, 0, sizeof(policer_result));
    expect("policer DEL sees target in secondary malformed member",
           policer_snapshot.state ==
               HAL_TRANSACTION_SNAPSHOT_READ_ERROR);
    expect("policer SET secondary-member collision is zero-write",
           hal_acl_policer_owner_apply(
               TEST_SW, &policer_args, &policer_result) != 0 &&
           write_count() == before);

    reset_simulator();
    seed_egress_owner(
        0, TEST_PORT, egress_args.src_mac, egress_args.dst_mac);
    g_sim.egress_acls[0].ports[0] = TEST_OTHER_PORT;
    g_sim.egress_acls[0].types[0] = FM_ACL_TYPE_EGRESS;
    g_sim.egress_acls[0].ports[1] = TEST_PORT;
    g_sim.egress_acls[0].types[1] = FM_ACL_TYPE_EGRESS;
    g_sim.egress_acls[0].n_ports = 2;
    before = write_count();
    egress_snapshot =
        hal_acl_egress_owner_transaction_snapshot_get(
            TEST_SW, &egress_args,
            HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    memset(&egress_result, 0, sizeof(egress_result));
    expect("egress DEL sees target in secondary malformed association",
           egress_snapshot.state ==
               HAL_TRANSACTION_SNAPSHOT_READ_ERROR);
    expect("egress SET secondary-port collision is zero-write",
           hal_acl_egress_owner_apply(
               TEST_SW, &egress_args, &egress_result) != 0 &&
           write_count() == before);

    reset_simulator();
    seed_independent_owner(&independent);
    g_sim.portsets[80 + independent.slot].members[0] =
        TEST_OTHER_PORT;
    g_sim.portsets[80 + independent.slot].members[1] =
        TEST_PORT;
    g_sim.portsets[80 + independent.slot].n_members = 2;
    before = write_count();
    independent_snapshot =
        hal_acl_independent_transaction_snapshot_get(
            TEST_SW, &independent,
            HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    memset(&independent_result, 0, sizeof(independent_result));
    expect("independent DEL sees target in secondary malformed member",
           independent_snapshot.state ==
               HAL_TRANSACTION_SNAPSHOT_READ_ERROR);
    expect("independent SET secondary-member collision is zero-write",
           hal_acl_independent_apply(
               TEST_SW, &independent, &independent_result) != 0 &&
           write_count() == before);
}

static void test_independent_deterministic_slot_and_restore(void) {
    hal_acl_independent_args old_args =
        independent_args(6, 0x020000002201ULL, 3000, 8192);
    hal_acl_independent_args new_args = old_args;
    hal_acl_independent_args changed_match = old_args;
    hal_acl_independent_transaction_snapshot snapshot;
    hal_acl_independent_transaction_snapshot exact;
    hal_acl_independent_result result;

    reset_simulator();
    seed_independent_owner(&old_args);
    memset(g_acl_independent_owner, 0, sizeof(g_acl_independent_owner));
    new_args.rate_kbps = 7000;
    new_args.burst_bytes = 32768;
    snapshot = hal_acl_independent_transaction_snapshot_get(
        TEST_SW, &new_args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    exact = hal_acl_independent_transaction_snapshot_get(
        TEST_SW, &new_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    expect("independent SET snapshot uses deterministic live slot",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.slot == old_args.slot &&
           snapshot.before.rate_kbps == old_args.rate_kbps);
    expect("independent DEL rejects changed policer values",
           exact.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR);

    memset(&result, 0, sizeof(result));
    expect("independent old DEL succeeds from cache-empty live state",
           hal_acl_independent_rollback_match(
               TEST_SW, &old_args, &result) == 0);
    memset(&result, 0, sizeof(result));
    expect("independent new SET uses the same deterministic slot",
           hal_acl_independent_apply(
               TEST_SW, &new_args, &result) == 0 &&
           result.slot == old_args.slot);
    expect("independent failed SET restores exact old before-image",
           hal_acl_independent_transaction_restore(
               TEST_SW, &new_args, &snapshot) == 0);
    exact = hal_acl_independent_transaction_snapshot_get(
        TEST_SW, &old_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    expect("independent restore proves old raw values",
           exact.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           exact.before.rate_kbps == old_args.rate_kbps &&
           exact.before.burst_bytes == old_args.burst_bytes);

    changed_match.dst_mac = 0x020000002202ULL;
    snapshot = hal_acl_independent_transaction_snapshot_get(
        TEST_SW, &changed_match, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    exact = hal_acl_independent_transaction_snapshot_get(
        TEST_SW, &changed_match, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    expect("independent changed hardware term is SET-absent",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT);
    expect("independent DEL conflicts with occupied different term slot",
           exact.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR);
}

static void test_full_rule_and_acl_contract_exactness(void) {
    hal_acl_policer_owner_args policer_args = {
        .port = TEST_PORT,
        .dst_mac = 0x020000003301ULL,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_egress_owner_args egress_args = {
        .port = TEST_PORT,
        .src_mac = 0x020000003401ULL,
        .dst_mac = 0x020000003402ULL,
    };
    hal_acl_independent_args independent =
        independent_args(7, 0x020000003501ULL, 2000, 8192);
    hal_acl_policer_owner_transaction_snapshot policer_snapshot;
    hal_acl_egress_owner_transaction_snapshot egress_snapshot;
    hal_acl_independent_transaction_snapshot independent_snapshot;
    hal_acl_policer_owner_result result;
    int before;

    reset_simulator();
    seed_policer_owner(
        0, TEST_PORT, policer_args.dst_mac,
        policer_args.rate_kbps, policer_args.burst_bytes);
    sim_rule(NETLAB_ACL_POLICER_PROBE_ACL_ID,
             owner_rule_for_slot(0))->value.protocol = 17;
    policer_snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &policer_args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    expect("policer inactive rule-field drift fails exact capture",
           policer_snapshot.state ==
               HAL_TRANSACTION_SNAPSHOT_READ_ERROR);

    reset_simulator();
    seed_egress_owner(
        0, TEST_PORT, egress_args.src_mac, egress_args.dst_mac);
    g_sim.egress_rules[0].param.policer = 91;
    egress_snapshot = hal_acl_egress_owner_transaction_snapshot_get(
        TEST_SW, &egress_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    expect("egress inactive parameter drift fails exact DEL capture",
           egress_snapshot.state ==
               HAL_TRANSACTION_SNAPSHOT_READ_ERROR);

    reset_simulator();
    seed_independent_owner(&independent);
    sim_rule(independent_acl_default(),
             independent_rule_for_slot(independent.slot))->
        value.protocol = 17;
    independent_snapshot =
        hal_acl_independent_transaction_snapshot_get(
            TEST_SW, &independent,
            HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    expect("independent inactive rule-field drift fails exact capture",
           independent_snapshot.state ==
               HAL_TRANSACTION_SNAPSHOT_READ_ERROR);

    reset_simulator();
    g_sim.shared_acl.scenarios ^= FM_ACL_SCENARIO_ANY_FRAME_TYPE;
    before = write_count();
    memset(&result, 0, sizeof(result));
    expect("shared ACL attribute drift fails before owner writes",
           hal_acl_policer_owner_apply(
               TEST_SW, &policer_args, &result) != 0 &&
           write_count() == before);
}

static void test_fresh_shared_acl_transaction_rollback(void) {
    hal_acl_policer_owner_args policer_args = {
        .port = TEST_PORT,
        .dst_mac = 0x020000004401ULL,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_independent_args independent =
        independent_args(8, 0x020000004501ULL, 3000, 8192);
    hal_acl_policer_owner_transaction_snapshot policer_snapshot;
    hal_acl_independent_transaction_snapshot independent_snapshot;
    hal_acl_policer_owner_result policer_result;
    hal_acl_independent_result independent_result;
    int writes_after_restore;

    reset_simulator();
    memset(&g_sim.shared_acl, 0, sizeof(g_sim.shared_acl));
    policer_snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &policer_args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    expect("fresh policer SET captures shared ACL absence",
           policer_snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT &&
           !policer_snapshot.shared_acl_present &&
           policer_snapshot.slot == 0);
    memset(&policer_result, 0, sizeof(policer_result));
    expect("fresh policer SET safely creates shared ACL",
           hal_acl_policer_owner_transaction_apply(
               TEST_SW, &policer_args, &policer_snapshot,
               &policer_result) == 0 &&
           g_sim.shared_acl.present &&
           g_sim.create_acl_calls == 1 &&
           policer_snapshot.shared_acl_creation.valid &&
           policer_snapshot.shared_acl_creation.creator ==
               HAL_ACL_SHARED_CREATOR_POLICER);
    expect("fresh policer rollback removes owner and created shared ACL",
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &policer_args, &policer_snapshot) == 0 &&
           !g_sim.shared_acl.present);
    writes_after_restore = write_count();
    expect("fresh policer rollback is retry-safe",
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &policer_args, &policer_snapshot) == 0 &&
           write_count() == writes_after_restore);

    reset_simulator();
    memset(&g_sim.shared_acl, 0, sizeof(g_sim.shared_acl));
    independent_snapshot =
        hal_acl_independent_transaction_snapshot_get(
            TEST_SW, &independent,
            HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    expect("fresh independent SET captures shared ACL absence",
           independent_snapshot.state ==
               HAL_TRANSACTION_SNAPSHOT_ABSENT &&
           !independent_snapshot.shared_acl_present);
    memset(&independent_result, 0, sizeof(independent_result));
    expect("fresh independent SET safely creates shared ACL",
           hal_acl_independent_transaction_apply(
               TEST_SW, &independent, &independent_snapshot,
               &independent_result) == 0 &&
           g_sim.shared_acl.present &&
           g_sim.create_acl_calls == 1 &&
           independent_snapshot.shared_acl_creation.valid &&
           independent_snapshot.shared_acl_creation.creator ==
               HAL_ACL_SHARED_CREATOR_INDEPENDENT);
    expect("fresh independent rollback removes created shared ACL",
           hal_acl_independent_transaction_restore(
               TEST_SW, &independent, &independent_snapshot) == 0 &&
           !g_sim.shared_acl.present);
    writes_after_restore = write_count();
    expect("fresh independent rollback is retry-safe",
           hal_acl_independent_transaction_restore(
               TEST_SW, &independent, &independent_snapshot) == 0 &&
           write_count() == writes_after_restore);
}

static void test_shared_acl_creation_token_authority(void) {
    hal_acl_policer_owner_args policer_args = {
        .port = TEST_PORT,
        .dst_mac = 0x020000004601ULL,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_independent_args independent =
        independent_args(9, 0x020000004701ULL, 3000, 8192);
    hal_acl_policer_owner_transaction_snapshot policer_snapshot;
    hal_acl_policer_owner_transaction_snapshot stale_snapshot;
    hal_acl_policer_owner_transaction_snapshot fresh_snapshot;
    hal_acl_independent_transaction_snapshot independent_snapshot;
    hal_acl_policer_owner_result policer_result;
    hal_acl_independent_result independent_result;
    int deletes_before;

    reset_simulator();
    memset(&g_sim.shared_acl, 0, sizeof(g_sim.shared_acl));
    policer_snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &policer_args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    memset(&policer_result, 0, sizeof(policer_result));
    expect("non-transactional fresh SET does not mint rollback authority",
           hal_acl_policer_owner_apply(
               TEST_SW, &policer_args, &policer_result) == 0 &&
           !policer_snapshot.shared_acl_creation.valid &&
           acl_shared_creation_find(
               TEST_SW, NETLAB_ACL_POLICER_PROBE_ACL_ID) == NULL);
    deletes_before = g_sim.delete_acl_calls;
    expect("before-absence alone cannot delete a shared ACL",
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &policer_args, &policer_snapshot) != 0 &&
           g_sim.shared_acl.present &&
           g_sim.delete_acl_calls == deletes_before);

    reset_simulator();
    memset(&g_sim.shared_acl, 0, sizeof(g_sim.shared_acl));
    policer_snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &policer_args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    independent_snapshot =
        hal_acl_independent_transaction_snapshot_get(
            TEST_SW, &independent,
            HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    memset(&policer_result, 0, sizeof(policer_result));
    expect("first shared owner receives the actual ACL creation token",
           hal_acl_policer_owner_transaction_apply(
               TEST_SW, &policer_args, &policer_snapshot,
               &policer_result) == 0 &&
           policer_snapshot.shared_acl_creation.valid);
    memset(&independent_result, 0, sizeof(independent_result));
    expect("later shared owner reuses ACL without receiving a token",
           hal_acl_independent_transaction_apply(
               TEST_SW, &independent, &independent_snapshot,
               &independent_result) == 0 &&
           !independent_snapshot.shared_acl_creation.valid);
    deletes_before = g_sim.delete_acl_calls;
    expect("non-token rollback defers shared ACL deletion",
           hal_acl_independent_transaction_restore(
               TEST_SW, &independent, &independent_snapshot) == 0 &&
           g_sim.shared_acl.present &&
           g_sim.delete_acl_calls == deletes_before);
    expect("token-holder rollback deletes the now-empty shared ACL",
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &policer_args, &policer_snapshot) == 0 &&
           !g_sim.shared_acl.present &&
           g_sim.delete_acl_calls == deletes_before + 1);

    memset(&g_sim.shared_acl, 0, sizeof(g_sim.shared_acl));
    stale_snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &policer_args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    memset(&policer_result, 0, sizeof(policer_result));
    expect("first generation can be created for stale-token test",
           hal_acl_policer_owner_transaction_apply(
               TEST_SW, &policer_args, &stale_snapshot,
               &policer_result) == 0 &&
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &policer_args, &stale_snapshot) == 0);
    fresh_snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &policer_args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    memset(&policer_result, 0, sizeof(policer_result));
    expect("new shared ACL receives a distinct generation token",
           hal_acl_policer_owner_transaction_apply(
               TEST_SW, &policer_args, &fresh_snapshot,
               &policer_result) == 0 &&
           fresh_snapshot.shared_acl_creation.generation !=
               stale_snapshot.shared_acl_creation.generation);
    deletes_before = g_sim.delete_acl_calls;
    expect("stale generation cannot delete a newer shared ACL",
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &policer_args, &stale_snapshot) != 0 &&
           g_sim.shared_acl.present &&
           g_sim.delete_acl_calls == deletes_before);
    expect("current generation can finish cleanup after stale rejection",
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &policer_args, &fresh_snapshot) == 0 &&
           !g_sim.shared_acl.present);
}

static void test_shared_acl_creation_token_retirement(void) {
    hal_acl_policer_owner_args args = {
        .port = TEST_PORT,
        .dst_mac = 0x020000004801ULL,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_policer_owner_transaction_snapshot snapshot;
    hal_acl_policer_owner_result result;
    hal_acl_shared_creation_token duplicated[2];
    acl_shared_creation_registry_entry *entry;

    reset_simulator();
    memset(&g_sim.shared_acl, 0, sizeof(g_sim.shared_acl));
    snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &args, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    memset(&result, 0, sizeof(result));
    expect("retirement fixture creates claimed transaction token",
           hal_acl_policer_owner_transaction_apply(
               TEST_SW, &args, &snapshot, &result) == 0 &&
           snapshot.shared_acl_creation.valid);
    entry = acl_shared_creation_find(
        TEST_SW, NETLAB_ACL_POLICER_PROBE_ACL_ID);
    expect("created token is claimed before commit finalization",
           entry != NULL && entry->claimed);

    duplicated[0] = snapshot.shared_acl_creation;
    duplicated[1] = snapshot.shared_acl_creation;
    expect("copied token batch is rejected atomically",
           hal_acl_shared_creation_tokens_retire(
               duplicated, 2) != 0 &&
           acl_shared_creation_find(
               TEST_SW, NETLAB_ACL_POLICER_PROBE_ACL_ID) == entry);
    expect("single real creator token retires without deleting ACL",
           hal_acl_shared_creation_tokens_retire(
               &snapshot.shared_acl_creation, 1) == 0 &&
           acl_shared_creation_find(
               TEST_SW, NETLAB_ACL_POLICER_PROBE_ACL_ID) == NULL &&
           g_sim.shared_acl.present &&
           sim_rule(NETLAB_ACL_POLICER_PROBE_ACL_ID,
                    owner_rule_for_slot(0))->present);
    expect("retired generation cannot be reused",
           hal_acl_shared_creation_tokens_retire(
               &snapshot.shared_acl_creation, 1) != 0 &&
           g_sim.shared_acl.present);
}

static void test_restore_preserves_allocator_slot(void) {
    hal_acl_policer_owner_args policer_args = {
        .port = TEST_PORT,
        .dst_mac = 0x020000005501ULL,
        .rate_kbps = 1000,
        .burst_bytes = 4096,
    };
    hal_acl_egress_owner_args egress_args = {
        .port = TEST_PORT,
        .src_mac = 0x020000005601ULL,
        .dst_mac = 0x020000005602ULL,
    };
    hal_acl_policer_owner_transaction_snapshot policer_snapshot;
    hal_acl_egress_owner_transaction_snapshot egress_snapshot;
    hal_acl_policer_owner_transaction_snapshot policer_exact;
    hal_acl_egress_owner_transaction_snapshot egress_exact;
    hal_acl_policer_owner_result policer_result;
    hal_acl_egress_owner_result egress_result;

    reset_simulator();
    seed_policer_owner(
        2, TEST_PORT, policer_args.dst_mac,
        policer_args.rate_kbps, policer_args.burst_bytes);
    policer_snapshot = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &policer_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    memset(&policer_result, 0, sizeof(policer_result));
    expect("policer exact DEL removes sparse allocator slot",
           policer_snapshot.slot == 2 &&
           hal_acl_policer_owner_rollback_match(
               TEST_SW, &policer_args, &policer_result) == 0);
    expect("policer restore targets retained sparse slot",
           hal_acl_policer_owner_transaction_restore(
               TEST_SW, &policer_args, &policer_snapshot) == 0);
    policer_exact = hal_acl_policer_owner_transaction_snapshot_get(
        TEST_SW, &policer_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    expect("policer sparse-slot restore is exact",
           policer_exact.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           policer_exact.slot == 2);

    reset_simulator();
    seed_egress_owner(
        3, TEST_PORT, egress_args.src_mac, egress_args.dst_mac);
    egress_snapshot = hal_acl_egress_owner_transaction_snapshot_get(
        TEST_SW, &egress_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    memset(&egress_result, 0, sizeof(egress_result));
    expect("egress exact DEL removes sparse allocator slot",
           egress_snapshot.slot == 3 &&
           hal_acl_egress_owner_rollback_match(
               TEST_SW, &egress_args, &egress_result) == 0);
    expect("egress restore targets retained sparse slot",
           hal_acl_egress_owner_transaction_restore(
               TEST_SW, &egress_args, &egress_snapshot) == 0);
    egress_exact = hal_acl_egress_owner_transaction_snapshot_get(
        TEST_SW, &egress_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    expect("egress sparse-slot restore is exact",
           egress_exact.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           egress_exact.slot == 3);
}

static void test_compile_failure_detail_is_bounded(void) {
    struct {
        char detail[24];
        unsigned char guard[8];
    } tiny;
    char detail[128];
    fm_status status;
    bool guard_ok = true;

    reset_simulator();
    g_sim.compile_status = FM_ERR_INVALID_STATE;
    memset(g_sim.compile_text, 'X', sizeof(g_sim.compile_text) - 1U);
    g_sim.compile_text[sizeof(g_sim.compile_text) - 1U] = '\0';
    memset(detail, 0xa5, sizeof(detail));
    status = compile_and_apply_acl(TEST_SW, detail, sizeof(detail));
    expect("oversized compiler diagnostic preserves SDK failure",
           status == FM_ERR_INVALID_STATE &&
           strstr(detail, "compile failed: simulated SDK failure (") ==
               detail);
    expect("oversized compiler diagnostic is explicitly truncated",
           strstr(detail, NETLAB_ACL_TRUNCATION_MARKER) != NULL &&
           detail[strlen(detail) - 1U] == ')' &&
           detail[sizeof(detail) - 1U] == '\0');
    expect("failed ACL compile is not applied",
           g_sim.compile_calls == 1 && g_sim.apply_calls == 0);

    reset_simulator();
    g_sim.compile_status = FM_ERR_INVALID_STATE;
    memcpy(g_sim.compile_text, "invalid ACL rule",
           sizeof("invalid ACL rule"));
    memset(detail, 0, sizeof(detail));
    status = compile_and_apply_acl(TEST_SW, detail, sizeof(detail));
    expect("short compiler diagnostic remains exact",
           status == FM_ERR_INVALID_STATE &&
           strcmp(detail,
                  "compile failed: simulated SDK failure "
                  "(invalid ACL rule)") == 0);

    memset(&tiny, 0xa5, sizeof(tiny));
    status = compile_and_apply_acl(
        TEST_SW, tiny.detail, sizeof(tiny.detail));
    for (size_t i = 0; i < sizeof(tiny.guard); i++)
        if (tiny.guard[i] != 0xa5)
            guard_ok = false;
    expect("tiny compiler diagnostic buffer remains terminated",
           status == FM_ERR_INVALID_STATE &&
           tiny.detail[sizeof(tiny.detail) - 1U] == '\0');
    expect("tiny compiler diagnostic buffer preserves canary", guard_ok);
}

int main(void) {
    test_restart_cache_empty_live_authority();
    test_read_error_zero_write();
    test_foreign_slot_is_not_overwritten();
    test_changed_rate_snapshot_and_restore();
    test_external_drift_and_counter_errors();
    test_egress_live_key_and_exact_port();
    test_secondary_port_collision_fails_closed();
    test_independent_deterministic_slot_and_restore();
    test_full_rule_and_acl_contract_exactness();
    test_fresh_shared_acl_transaction_rollback();
    test_shared_acl_creation_token_authority();
    test_shared_acl_creation_token_retirement();
    test_restore_preserves_allocator_slot();
    test_compile_failure_detail_is_bounded();

    if (g_failed != 0) {
        printf("FAIL: %d ACL owner live-authority checks failed\n",
               g_failed);
        return 1;
    }
    printf("PASS: ACL owner live-authority transaction checks\n");
    return 0;
}
