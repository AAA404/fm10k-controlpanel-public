/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../../sbin/switchd/hal_control_plane.c"

#define TEST_SW 0
#define LLDP_CLASS_INDEX 1
#define BGP_CLASS_INDEX 7

typedef struct {
    bool present;
    copp_acl_rule_contract contract;
    fm_aclEntryState state;
} simulated_rule;

typedef struct {
    bool acl_present;
    fm_uint32 acl_scenarios;
    fm_int acl_precedence;
    fm_status acl_get_status;
    int acl_get_calls;

    simulated_rule rules[HAL_COPP_TRANSACTION_MAX_RULES];
    int rule_count;
    int rule_get_calls;
    int rule_get_fail_call;
    fm_status rule_get_fail_status;
    int rule_state_get_calls;
    int rule_state_fail_call;
    fm_status rule_state_fail_status;

    bool policer_present;
    fm_int policer;
    fm_int color_source;
    fm_int cir_action;
    fm_uint32 cir_capacity;
    fm_uint32 cir_rate;
    fm_int staged_color_source;
    fm_int staged_cir_action;
    fm_uint32 staged_cir_capacity;
    fm_uint32 staged_cir_rate;
    int policer_get_calls;
    int policer_get_fail_call;
    fm_status policer_get_fail_status;
    int policer_set_calls;
    int policer_set_fail_call;
    fm_status policer_set_fail_status;
    int policer_update_calls;
    fm_status policer_update_status;
    int corrupt_attr_after_update;

    int reserve_calls;
    int create_acl_calls;
    int create_policer_calls;
    int delete_policer_calls;
    int add_rule_calls;
    int delete_rule_calls;
    int compile_calls;
    int apply_calls;
} copp_simulator;

static copp_simulator g_sim;
static int g_failed;

static void expect(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        g_failed++;
}

static int acl_write_count(void) {
    return g_sim.create_acl_calls +
           g_sim.add_rule_calls +
           g_sim.delete_rule_calls +
           g_sim.compile_calls +
           g_sim.apply_calls;
}

static void reset_simulator(int class_index) {
    copp_class_rule *cls = &g_copp_classes[class_index];

    memset(&g_sim, 0, sizeof(g_sim));
    g_sim.acl_present = true;
    g_sim.acl_scenarios = copp_acl_expected_scenarios();
    g_sim.acl_precedence = FM_ACL_DEFAULT_PRECEDENCE;
    g_sim.acl_get_status = FM_OK;
    g_sim.rule_get_fail_call = -1;
    g_sim.rule_get_fail_status = FM_OK;
    g_sim.rule_state_fail_call = -1;
    g_sim.rule_state_fail_status = FM_OK;
    g_sim.rule_count = copp_acl_rule_count(cls);
    for (int i = 0; i < g_sim.rule_count; i++) {
        simulated_rule *rule = &g_sim.rules[i];

        rule->present = true;
        rule->state = FM_ACL_RULE_ENTRY_STATE_VALID;
        (void)copp_acl_rule_contract_build(
            cls, copp_acl_rule_number(cls, i),
            copp_acl_rule_is_bgp_source(cls, i), &rule->contract);
    }

    g_sim.policer_present = true;
    g_sim.policer = cls->policer;
    g_sim.color_source = 17;
    g_sim.cir_action = 23;
    g_sim.cir_capacity = 7777;
    g_sim.cir_rate = 33333;
    g_sim.staged_color_source = g_sim.color_source;
    g_sim.staged_cir_action = g_sim.cir_action;
    g_sim.staged_cir_capacity = g_sim.cir_capacity;
    g_sim.staged_cir_rate = g_sim.cir_rate;
    g_sim.policer_get_fail_call = -1;
    g_sim.policer_get_fail_status = FM_OK;
    g_sim.policer_set_fail_call = -1;
    g_sim.policer_set_fail_status = FM_OK;
    g_sim.policer_update_status = FM_OK;
    g_sim.corrupt_attr_after_update = -1;

    g_copp_acl = -1;
    for (int i = 0; i < NETLAB_COPP_CLASSES; i++)
        g_copp_classes[i].installed = false;
}

static simulated_rule *find_simulated_rule(fm_int rule) {
    for (int i = 0; i < g_sim.rule_count; i++) {
        if (g_sim.rules[i].contract.rule == rule)
            return &g_sim.rules[i];
    }
    return NULL;
}

static hal_copp_policer_transaction_snapshot capture_expected(
    const char *class_name) {
    hal_copp_policer_transaction_snapshot snapshot =
        hal_control_plane_copp_transaction_snapshot(TEST_SW, class_name);

    expect("fixture captures an exact PRESENT baseline",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT);
    return snapshot;
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
    return "injected";
}

int hal_acl_resource_reserve(int sw, const hal_acl_resource_spec *spec,
                             hal_acl_resource_reservation *out) {
    (void)sw;
    (void)spec;
    g_sim.reserve_calls++;
    if (out) {
        memset(out, 0, sizeof(*out));
        out->acl = NETLAB_COPP_ACL_ID;
    }
    return 0;
}

fm_status fmGetACL(fm_int sw, fm_int acl, fm_aclArguments *args) {
    (void)sw;
    g_sim.acl_get_calls++;
    if (acl != NETLAB_COPP_ACL_ID || !args)
        return FM_ERR_INVALID_ARGUMENT;
    if (g_sim.acl_get_status != FM_OK)
        return g_sim.acl_get_status;
    if (!g_sim.acl_present)
        return FM_ERR_INVALID_ACL;
    args->scenarios = g_sim.acl_scenarios;
    args->precedence = g_sim.acl_precedence;
    return FM_OK;
}

fm_status fmGetACLRule(fm_int sw, fm_int acl, fm_int rule,
                       fm_aclCondition *condition, fm_aclValue *value,
                       fm_aclActionExt *action, fm_aclParamExt *param) {
    simulated_rule *simulated;

    (void)sw;
    g_sim.rule_get_calls++;
    if (acl != NETLAB_COPP_ACL_ID || !condition || !value ||
        !action || !param)
        return FM_ERR_INVALID_ARGUMENT;
    if (g_sim.rule_get_calls == g_sim.rule_get_fail_call)
        return g_sim.rule_get_fail_status;
    simulated = find_simulated_rule(rule);
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL_RULE;
    *condition = simulated->contract.condition;
    *value = simulated->contract.value;
    *action = simulated->contract.action;
    *param = simulated->contract.param;
    return FM_OK;
}

fm_status fmGetACLRuleState(fm_int sw, fm_int acl, fm_int rule,
                            fm_aclEntryState *state) {
    simulated_rule *simulated;

    (void)sw;
    g_sim.rule_state_get_calls++;
    if (acl != NETLAB_COPP_ACL_ID || !state)
        return FM_ERR_INVALID_ARGUMENT;
    if (g_sim.rule_state_get_calls == g_sim.rule_state_fail_call)
        return g_sim.rule_state_fail_status;
    simulated = find_simulated_rule(rule);
    if (!simulated || !simulated->present)
        return FM_ERR_INVALID_ACL_RULE;
    *state = simulated->state;
    return FM_OK;
}

fm_status fmGetPolicerAttribute(fm_int sw, fm_int policer,
                                fm_int attr, fm_voidptr value) {
    (void)sw;
    g_sim.policer_get_calls++;
    if (policer != g_sim.policer || !value)
        return FM_ERR_INVALID_ARGUMENT;
    if (g_sim.policer_get_calls == g_sim.policer_get_fail_call)
        return g_sim.policer_get_fail_status;
    if (!g_sim.policer_present)
        return FM_ERR_INVALID_POLICER;

    switch (attr) {
    case FM_POLICER_COLOR_SOURCE:
        *(fm_int *)value = g_sim.color_source;
        return FM_OK;
    case FM_POLICER_CIR_ACTION:
        *(fm_int *)value = g_sim.cir_action;
        return FM_OK;
    case FM_POLICER_CIR_CAPACITY:
        *(fm_uint32 *)value = g_sim.cir_capacity;
        return FM_OK;
    case FM_POLICER_CIR_RATE:
        *(fm_uint32 *)value = g_sim.cir_rate;
        return FM_OK;
    default:
        return FM_ERR_INVALID_ARGUMENT;
    }
}

fm_status fmSetPolicerAttribute(fm_int sw, fm_int policer,
                                fm_int attr, const void *value) {
    (void)sw;
    g_sim.policer_set_calls++;
    if (policer != g_sim.policer || !value || !g_sim.policer_present)
        return FM_ERR_INVALID_POLICER;
    if (g_sim.policer_set_calls == g_sim.policer_set_fail_call)
        return g_sim.policer_set_fail_status;

    switch (attr) {
    case FM_POLICER_COLOR_SOURCE:
        g_sim.staged_color_source = *(const fm_int *)value;
        return FM_OK;
    case FM_POLICER_CIR_ACTION:
        g_sim.staged_cir_action = *(const fm_int *)value;
        return FM_OK;
    case FM_POLICER_CIR_CAPACITY:
        g_sim.staged_cir_capacity = *(const fm_uint32 *)value;
        return FM_OK;
    case FM_POLICER_CIR_RATE:
        g_sim.staged_cir_rate = *(const fm_uint32 *)value;
        return FM_OK;
    default:
        return FM_ERR_INVALID_ARGUMENT;
    }
}

fm_status fmUpdatePolicer(fm_int sw, fm_int policer) {
    (void)sw;
    g_sim.policer_update_calls++;
    if (policer != g_sim.policer || !g_sim.policer_present)
        return FM_ERR_INVALID_POLICER;
    if (g_sim.policer_update_status != FM_OK)
        return g_sim.policer_update_status;

    g_sim.color_source = g_sim.staged_color_source;
    g_sim.cir_action = g_sim.staged_cir_action;
    g_sim.cir_capacity = g_sim.staged_cir_capacity;
    g_sim.cir_rate = g_sim.staged_cir_rate;
    switch (g_sim.corrupt_attr_after_update) {
    case FM_POLICER_COLOR_SOURCE:
        g_sim.color_source++;
        break;
    case FM_POLICER_CIR_ACTION:
        g_sim.cir_action++;
        break;
    case FM_POLICER_CIR_CAPACITY:
        g_sim.cir_capacity++;
        break;
    case FM_POLICER_CIR_RATE:
        g_sim.cir_rate++;
        break;
    default:
        break;
    }
    return FM_OK;
}

fm_status fmCreateACL(fm_int sw, fm_int acl) {
    (void)sw;
    (void)acl;
    g_sim.create_acl_calls++;
    return FM_OK;
}

fm_status fmCreatePolicer(fm_int sw, fm_int bank, fm_int policer,
                          const fm_policerConfig *config) {
    (void)sw;
    (void)bank;
    (void)policer;
    (void)config;
    g_sim.create_policer_calls++;
    return FM_OK;
}

fm_status fmDeletePolicer(fm_int sw, fm_int policer) {
    (void)sw;
    (void)policer;
    g_sim.delete_policer_calls++;
    return FM_OK;
}

fm_status fmAddACLRuleExt(fm_int sw, fm_int acl, fm_int rule,
                          fm_aclCondition condition,
                          const fm_aclValue *value,
                          fm_aclActionExt action,
                          const fm_aclParamExt *param) {
    (void)sw;
    (void)acl;
    (void)rule;
    (void)condition;
    (void)value;
    (void)action;
    (void)param;
    g_sim.add_rule_calls++;
    simulated_rule *simulated = &g_sim.rules[0];
    simulated->present = true;
    simulated->state = FM_ACL_RULE_ENTRY_STATE_VALID;
    simulated->contract = (copp_acl_rule_contract){
        .rule = rule, .condition = condition, .value = *value,
        .action = action, .param = *param,
    };
    return FM_OK;
}

fm_status fmDeleteACLRule(fm_int sw, fm_int acl, fm_int rule) {
    (void)sw;
    (void)acl;
    (void)rule;
    g_sim.delete_rule_calls++;
    return FM_OK;
}

fm_status fmCompileACL(fm_int sw, fm_text status_text,
                       fm_int status_text_length, fm_uint32 flags) {
    (void)sw;
    (void)status_text;
    (void)status_text_length;
    (void)flags;
    g_sim.compile_calls++;
    return FM_OK;
}

fm_status fmApplyACL(fm_int sw, fm_uint32 flags) {
    (void)sw;
    (void)flags;
    g_sim.apply_calls++;
    return FM_OK;
}

static void test_restart_cache_empty_update_is_policer_only(void) {
    copp_class_rule *cls = &g_copp_classes[LLDP_CLASS_INDEX];
    int status;

    reset_simulator(LLDP_CLASS_INDEX);
    expect("restart fixture begins with empty derived CoPP cache",
           g_copp_acl < 0 && !cls->installed);
    status = hal_control_plane_copp_set(TEST_SW, "lldp", 777, 99);
    expect("live ACL/rule/policer state authorizes update after restart",
           status == 0 && cls->installed &&
           g_copp_acl == NETLAB_COPP_ACL_ID);
    expect("method41 changes only four policer fields and commits once",
           g_sim.policer_set_calls == 4 &&
           g_sim.policer_update_calls == 1 &&
           g_sim.cir_rate == (fm_uint32)pps_to_kbps(777) &&
           g_sim.cir_capacity ==
               (fm_uint32)burst_pkts_to_bytes(99));
    expect("exact existing owner rule is never rewritten or re-applied",
           acl_write_count() == 0 &&
           g_sim.reserve_calls == 0 &&
           g_sim.create_policer_calls == 0 &&
           g_sim.delete_policer_calls == 0);
    expect("SET proves the owner and raw policer both before and after",
           g_sim.acl_get_calls == 2 &&
           g_sim.rule_get_calls == 2 &&
           g_sim.rule_state_get_calls == 2 &&
           g_sim.policer_get_calls == 8);
}

static void expect_set_rejected_without_writes(const char *name) {
    int status = hal_control_plane_copp_set(
        TEST_SW, "lldp", 777, 99);

    expect(name, status != 0 &&
           g_sim.policer_set_calls == 0 &&
           g_sim.policer_update_calls == 0 &&
           g_sim.create_policer_calls == 0 &&
           g_sim.delete_policer_calls == 0 &&
           acl_write_count() == 0);
}

static void test_acl_and_rule_fail_closed(void) {
    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.acl_present = false;
    expect_set_rejected_without_writes(
        "absent shared ACL fails closed before policer access");
    expect("absent ACL is classified by the live getter",
           g_sim.acl_get_calls == 1 &&
           g_sim.rule_get_calls == 0 &&
           g_sim.policer_get_calls == 0);

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.acl_get_status = FM_ERR_INVALID_SWITCH;
    expect_set_rejected_without_writes(
        "ACL read error fails closed with zero writes");

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.acl_scenarios ^= 1U;
    expect_set_rejected_without_writes(
        "ACL scenario mismatch fails closed with zero writes");

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.acl_precedence++;
    expect_set_rejected_without_writes(
        "ACL precedence mismatch fails closed with zero writes");

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.rules[0].present = false;
    expect_set_rejected_without_writes(
        "absent deterministic owner rule fails closed");
    expect("absent rule is rejected before policer access",
           g_sim.policer_get_calls == 0);

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.rule_get_fail_call = 1;
    g_sim.rule_get_fail_status = FM_ERR_INVALID_SWITCH;
    expect_set_rejected_without_writes(
        "owner-rule getter error fails closed");

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.rule_state_fail_call = 1;
    g_sim.rule_state_fail_status = FM_ERR_INVALID_SWITCH;
    expect_set_rejected_without_writes(
        "owner-rule state getter error fails closed");

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.rules[0].state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    expect_set_rejected_without_writes(
        "disabled owner rule is an exactness mismatch");

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.rules[0].contract.action ^= FM_ACL_ACTIONEXT_COUNT;
    expect_set_rejected_without_writes(
        "owner-rule action mismatch fails closed");

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.rules[0].contract.value.dstMask ^= 1;
    expect_set_rejected_without_writes(
        "owner-rule match value mismatch fails closed");

    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.rules[0].contract.param.logicalPort = 44;
    expect_set_rejected_without_writes(
        "unexpected inactive owner-rule parameter fails exact comparison");
}

static void test_policer_fail_closed(void) {
    reset_simulator(LLDP_CLASS_INDEX);
    g_sim.policer_present = false;
    expect_set_rejected_without_writes(
        "absent policer is not created by method41");
    expect("policer absence is observed only after exact owner proof",
           g_sim.acl_get_calls == 1 &&
           g_sim.rule_get_calls == 1 &&
           g_sim.rule_state_get_calls == 1 &&
           g_sim.policer_get_calls == 1);

    for (int call = 1; call <= 4; call++) {
        reset_simulator(LLDP_CLASS_INDEX);
        g_sim.policer_get_fail_call = call;
        g_sim.policer_get_fail_status = FM_ERR_INVALID_SWITCH;
        expect_set_rejected_without_writes(
            "partial raw policer read fails closed with zero writes");
        expect("policer snapshot stops at the failing raw getter",
               g_sim.policer_get_calls == call);
    }
}

static void test_transit_classes_cannot_install_ingress_drop(void) {
    for (int i = NETLAB_COPP_IGMP_INDEX; i < NETLAB_COPP_CLASSES; ++i) {
        reset_simulator(i);
        const copp_class_rule *cls = &g_copp_classes[i];
        hal_copp_policer_transaction_snapshot snapshot =
            hal_control_plane_copp_transaction_snapshot(TEST_SW, cls->protocol);
        expect("transit protocols have no ingress-policer transaction",
               snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
               hal_control_plane_copp_set(TEST_SW, cls->protocol, 900, 120) != 0 &&
               hal_control_plane_copp_transaction_restore(TEST_SW, cls->protocol, &snapshot) != 0 &&
               g_sim.acl_get_calls == 0 && g_sim.policer_get_calls == 0 &&
               g_sim.policer_set_calls == 0 && acl_write_count() == 0);
    }

    reset_simulator(NETLAB_COPP_IGMP_INDEX);
    g_copp_acl = NETLAB_COPP_ACL_ID;
    g_sim.rules[0].present = false;
    expect("IGMP provisioning creates only a copy/count rule",
           provision_igmp_copy(TEST_SW) == 0 &&
           g_sim.add_rule_calls == 1 && g_sim.compile_calls == 1 && g_sim.apply_calls == 1 &&
           g_sim.create_policer_calls == 0 && g_sim.policer_set_calls == 0 &&
           g_sim.rules[0].contract.action == (FM_ACL_ACTIONEXT_LOG | FM_ACL_ACTIONEXT_COUNT) &&
           g_sim.rules[0].contract.param.policer == 0 &&
           g_sim.rules[0].contract.value.protocol == 2);
    expect("repeated IGMP provisioning verifies without rewriting",
           provision_igmp_copy(TEST_SW) == 0 && g_sim.add_rule_calls == 1);

    reset_simulator(NETLAB_COPP_IGMP_INDEX);
    g_copp_acl = NETLAB_COPP_ACL_ID;
    g_sim.rules[0].contract.action |= FM_ACL_ACTIONEXT_POLICE;
    expect("old ingress-policed IGMP rule is rejected instead of adopted",
           provision_igmp_copy(TEST_SW) != 0 && acl_write_count() == 0);
    reset_simulator(NETLAB_COPP_IGMP_INDEX);
    g_sim.rule_get_fail_call = 1;
    g_sim.rule_get_fail_status = FM_ERR_INVALID_SWITCH;
    expect("IGMP copy read failure is not absence",
           igmp_copy_read(TEST_SW) != 0 && acl_write_count() == 0);
}

static void test_exact_policer_rollback(void) {
    hal_copp_policer_transaction_snapshot before;
    int status;

    reset_simulator(LLDP_CLASS_INDEX);
    before = capture_expected("lldp");
    g_sim.color_source = 1;
    g_sim.cir_action = 2;
    g_sim.cir_capacity = 4096;
    g_sim.cir_rate = 24000;
    g_sim.staged_color_source = g_sim.color_source;
    g_sim.staged_cir_action = g_sim.cir_action;
    g_sim.staged_cir_capacity = g_sim.cir_capacity;
    g_sim.staged_cir_rate = g_sim.cir_rate;
    g_sim.acl_get_calls = 0;
    g_sim.rule_get_calls = 0;
    g_sim.rule_state_get_calls = 0;
    g_sim.policer_get_calls = 0;
    status = hal_control_plane_copp_transaction_restore(
        TEST_SW, "lldp", &before);
    expect("rollback restores all four raw policer attributes",
           status == 0 &&
           g_sim.color_source == before.color_source &&
           g_sim.cir_action == before.cir_action &&
           g_sim.cir_capacity == before.cir_capacity &&
           g_sim.cir_rate == before.cir_rate &&
           g_sim.policer_set_calls == 4 &&
           g_sim.policer_update_calls == 1);
    expect("rollback proves owner before write and full tuple after write",
           g_sim.acl_get_calls == 2 &&
           g_sim.rule_get_calls == 2 &&
           g_sim.rule_state_get_calls == 2 &&
           g_sim.policer_get_calls == 4);
    expect("rollback never mutates ACL ownership",
           acl_write_count() == 0);

    reset_simulator(LLDP_CLASS_INDEX);
    before = capture_expected("lldp");
    g_sim.rules[0].contract.action ^= FM_ACL_ACTIONEXT_COUNT;
    g_sim.policer_set_calls = 0;
    status = hal_control_plane_copp_transaction_restore(
        TEST_SW, "lldp", &before);
    expect("owner drift blocks rollback before its first policer write",
           status != 0 &&
           g_sim.policer_set_calls == 0 &&
           g_sim.policer_update_calls == 0 &&
           acl_write_count() == 0);

    reset_simulator(LLDP_CLASS_INDEX);
    before = capture_expected("lldp");
    before.rules[0].policer++;
    g_sim.acl_get_calls = 0;
    g_sim.rule_get_calls = 0;
    g_sim.policer_get_calls = 0;
    status = hal_control_plane_copp_transaction_restore(
        TEST_SW, "lldp", &before);
    expect("tampered owner contract is rejected without SDK access",
           status == FM_ERR_INVALID_ARGUMENT &&
           g_sim.acl_get_calls == 0 &&
           g_sim.rule_get_calls == 0 &&
           g_sim.policer_get_calls == 0 &&
           g_sim.policer_set_calls == 0);

    reset_simulator(LLDP_CLASS_INDEX);
    before = capture_expected("lldp");
    g_sim.corrupt_attr_after_update = FM_POLICER_CIR_RATE;
    status = hal_control_plane_copp_transaction_restore(
        TEST_SW, "lldp", &before);
    expect("silently corrupted rollback readback is rejected",
           status == FM_ERR_INVALID_STATE &&
           g_sim.policer_update_calls == 1);

    reset_simulator(LLDP_CLASS_INDEX);
    before = capture_expected("lldp");
    before.state = HAL_TRANSACTION_SNAPSHOT_ABSENT;
    g_sim.policer_set_calls = 0;
    status = hal_control_plane_copp_transaction_restore(
        TEST_SW, "lldp", &before);
    expect("method41 rejects an ABSENT owner snapshot without deletion",
           status == FM_ERR_INVALID_ARGUMENT &&
           g_sim.policer_set_calls == 0 &&
           g_sim.delete_policer_calls == 0 &&
           acl_write_count() == 0);
}

static void test_snapshot_unknown_class_is_zero_io(void) {
    hal_copp_policer_transaction_snapshot snapshot;

    reset_simulator(LLDP_CLASS_INDEX);
    snapshot = hal_control_plane_copp_transaction_snapshot(
        TEST_SW, "not-a-class");
    expect("unknown class is READ_ERROR with no hardware access",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_ERR_INVALID_ARGUMENT &&
           snapshot.policer == -1 &&
           g_sim.acl_get_calls == 0 &&
           g_sim.rule_get_calls == 0 &&
           g_sim.policer_get_calls == 0);
}

int main(void) {
    test_restart_cache_empty_update_is_policer_only();
    test_acl_and_rule_fail_closed();
    test_policer_fail_closed();
    test_transit_classes_cannot_install_ingress_drop();
    test_exact_policer_rollback();
    test_snapshot_unknown_class_is_zero_io();

    if (g_failed != 0) {
        fprintf(stderr, "%d CoPP transaction checks failed\n", g_failed);
        return 1;
    }
    puts("PASS: CoPP transactions prove ACL/rules/policer and write policer only");
    return 0;
}
