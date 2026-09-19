/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "hal_acl_resource.h"
#include "hal_flow_table.h"
#include "hal_cpu_protection.h"

#include "netlab/hal.h"
#include "netlab/hal_transaction_snapshot.h"
#include "netlab/log.h"
#include <arpa/inet.h>
#include <limits.h>
#include <string.h>
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_acl.h>
#include <api/fm_api_flow.h>
#include <api/fm_api_policer.h>
#include <api/fm_api_portset.h>

#define NETLAB_CONTROL_FLOW_MAX_ENTRIES 4
#define NETLAB_CONTROL_FLOW_MAX_ACTIONS 2
#define NETLAB_COPP_ACL_ID 3100
#define NETLAB_COPP_RULE_BASE 100
#define NETLAB_COPP_BGP_SRC_RULE (NETLAB_COPP_RULE_BASE + NETLAB_COPP_CLASSES)
#define NETLAB_COPP_POLICER_BASE 100
#define NETLAB_COPP_PACKET_BYTES 256
#define NETLAB_COPP_MIN_RATE_KBPS 24
#define NETLAB_COPP_CLASSES 8
#define NETLAB_COPP_LINK_LOCAL_CLASSES 3
#define NETLAB_COPP_IGMP_INDEX 3

typedef struct {
    const char *name;
    const char *protocol;
    const char *description;
    fm_macaddr dst;
    fm_int flow_id;
} control_rule;

typedef struct {
    const char *name;
    const char *protocol;
    fm_macaddr dst;
    int reserved_index;
    int default_rate_pps;
    int default_burst_pkts;
    int rate_pps;
    int burst_pkts;
    int policer;
    int rule;
    bool installed;
} copp_class_rule;

static control_rule g_rules[] = {
    { "cisco-pvst",    "vendor-private", "Cisco PVST+/Rapid-PVST",
      0x01000CCCCCCDLL, -1 },
    { "cisco-control", "vendor-private", "Cisco CDP/VTP/control",
      0x01000CCCCCCCLL, -1 },
};

static fm_int g_control_flow_table = -1;
static fm_int g_copp_acl = -1;
static copp_class_rule g_copp_classes[NETLAB_COPP_CLASSES] = {
    { "ieee-rstp", "rstp", 0x0180C2000000LL, 0x00, 256, 512, 256, 512,
      NETLAB_COPP_POLICER_BASE + 0, NETLAB_COPP_RULE_BASE + 0, false },
    { "ieee-lldp", "lldp", 0x0180C200000ELL, 0x0E, 128, 256, 128, 256,
      NETLAB_COPP_POLICER_BASE + 1, NETLAB_COPP_RULE_BASE + 1, false },
    { "ieee-lacp", "lacp", 0x0180C2000002LL, 0x02, 512, 1024, 512, 1024,
      NETLAB_COPP_POLICER_BASE + 2, NETLAB_COPP_RULE_BASE + 2, false },
    { "ipv4-igmp", "igmp", 0, -1, 512, 1024, 512, 1024,
      NETLAB_COPP_POLICER_BASE + 3, NETLAB_COPP_RULE_BASE + 3, false },
    { "ethernet-arp", "arp", 0, -1, 1024, 2048, 1024, 2048,
      NETLAB_COPP_POLICER_BASE + 4, NETLAB_COPP_RULE_BASE + 4, false },
    { "ipv4-icmp", "icmp", 0, -1, 512, 1024, 512, 1024,
      NETLAB_COPP_POLICER_BASE + 5, NETLAB_COPP_RULE_BASE + 5, false },
    { "ipv4-ospf", "ospf", 0, -1, 512, 1024, 512, 1024,
      NETLAB_COPP_POLICER_BASE + 6, NETLAB_COPP_RULE_BASE + 6, false },
    { "ipv4-bgp", "bgp", 0, -1, 512, 1024, 512, 1024,
      NETLAB_COPP_POLICER_BASE + 7, NETLAB_COPP_RULE_BASE + 7, false },
};

static int clamp_u64_to_int(fm_uint64 value) {
    if (value > (fm_uint64)INT_MAX)
        return INT_MAX;
    return (int)value;
}

static int pps_to_kbps(int pps) {
    long long kbps;

    if (pps <= 0)
        return NETLAB_COPP_MIN_RATE_KBPS;
    kbps = ((long long)pps * NETLAB_COPP_PACKET_BYTES * 8 + 999) / 1000;
    if (kbps < NETLAB_COPP_MIN_RATE_KBPS)
        kbps = NETLAB_COPP_MIN_RATE_KBPS;
    if (kbps > INT_MAX)
        kbps = INT_MAX;
    return (int)kbps;
}

static int burst_pkts_to_bytes(int burst_pkts) {
    long long bytes;

    if (burst_pkts <= 0)
        burst_pkts = 1;
    bytes = (long long)burst_pkts * NETLAB_COPP_PACKET_BYTES;
    if (bytes < 1024)
        bytes = 1024;
    if (bytes > INT_MAX)
        bytes = INT_MAX;
    return (int)bytes;
}

static int kbps_to_pps(fm_uint32 kbps) {
    long long pps = ((long long)kbps * 1000) /
                    (NETLAB_COPP_PACKET_BYTES * 8);
    if (pps <= 0 && kbps > 0)
        pps = 1;
    if (pps > INT_MAX)
        pps = INT_MAX;
    return (int)pps;
}

static int bytes_to_burst_pkts(fm_uint32 bytes) {
    int pkts = (int)((bytes + NETLAB_COPP_PACKET_BYTES - 1) /
                     NETLAB_COPP_PACKET_BYTES);
    return pkts > 0 ? pkts : 1;
}

static copp_class_rule *find_copp_class(const char *class_name) {
    if (!class_name)
        return NULL;
    for (int i = 0; i < NETLAB_COPP_CLASSES; i++) {
        if (strcmp(g_copp_classes[i].protocol, class_name) == 0 ||
            strcmp(g_copp_classes[i].name, class_name) == 0)
            return &g_copp_classes[i];
    }
    return NULL;
}

static bool copp_class_is_link_local(const copp_class_rule *cls) {
    return cls && cls->reserved_index >= 0;
}

static bool copp_policer_absent_status(fm_status status) {
    /*
     * fmGetPolicerAttribute() maps an absent tree entry to
     * FM_ERR_INVALID_POLICER.  No other SDK error proves absence.
     */
    return status == FM_ERR_INVALID_POLICER;
}

typedef enum {
    COPP_OWNER_READ_ERROR = -1,
    COPP_OWNER_ABSENT = 0,
    COPP_OWNER_EXACT = 1,
    COPP_OWNER_MISMATCH = 2,
} copp_owner_state;

typedef struct {
    int rule;
    fm_aclCondition condition;
    fm_aclValue value;
    fm_aclActionExt action;
    fm_aclParamExt param;
} copp_acl_rule_contract;

static fm_uint32 copp_acl_expected_scenarios(void) {
    return FM_ACL_SCENARIO_ANY_FRAME_TYPE |
           FM_ACL_SCENARIO_ANY_ROUTING_TYPE |
           FM_ACL_SCENARIO_ANY_TUNNEL_TYPE;
}

static int copp_acl_rule_contract_build(const copp_class_rule *cls,
                                        int rule, bool bgp_source_port,
                                        copp_acl_rule_contract *contract) {
    if (!cls || !contract ||
        (!copp_class_is_link_local(cls) && strcmp(cls->protocol, "igmp") != 0))
        return -1;

    (void)bgp_source_port;

    memset(contract, 0, sizeof(*contract));
    contract->rule = rule;
    contract->value.portSet = FM_PORT_SET_ALL_EXTERNAL;
    contract->condition = FM_ACL_MATCH_INGRESS_PORT_SET;
    contract->action = FM_ACL_ACTIONEXT_COUNT;

    if (strcmp(cls->protocol, "igmp") == 0) {
        /* LOG is orthogonal to forwarding. An ingress policer DROP would
         * discard transit reports/queries and is not a CPU-copy limit.
         * The CPU port shaper and packetd's policy protect the copy. */
        contract->value.ethType = 0x0800;
        contract->value.ethTypeMask = 0xffff;
        contract->value.protocol = 2;
        contract->value.protocolMask = 0xff;
        contract->condition |= FM_ACL_MATCH_ETHERTYPE |
                               FM_ACL_MATCH_PROTOCOL;
        contract->action |= FM_ACL_ACTIONEXT_LOG;
    } else {
        contract->param.policer = cls->policer;
        contract->action |= FM_ACL_ACTIONEXT_POLICE;
        contract->value.dst = cls->dst;
        contract->value.dstMask = 0xFFFFFFFFFFFFULL;
        contract->condition |= FM_ACL_MATCH_DST_MAC;
    }

    return 0;
}

static void copp_acl_rule_contract_export(
    const copp_acl_rule_contract *contract,
    hal_copp_acl_rule_transaction_state *state) {
    if (!contract || !state)
        return;

    memset(state, 0, sizeof(*state));
    state->rule = contract->rule;
    state->condition = (u64)contract->condition;
    state->action = (u64)contract->action;
    state->dst = (u64)contract->value.dst;
    state->dst_mask = (u64)contract->value.dstMask;
    state->eth_type = (u16)contract->value.ethType;
    state->eth_type_mask = (u16)contract->value.ethTypeMask;
    state->protocol = (u8)contract->value.protocol;
    state->protocol_mask = (u8)contract->value.protocolMask;
    state->l4_src_start = (u16)contract->value.L4SrcStart;
    state->l4_src_mask = (u16)contract->value.L4SrcMask;
    state->l4_dst_start = (u16)contract->value.L4DstStart;
    state->l4_dst_mask = (u16)contract->value.L4DstMask;
    state->port_set = (int)contract->value.portSet;
    state->policer = (int)contract->param.policer;
}

static int copp_acl_rule_count(const copp_class_rule *cls) {
    return cls && strcmp(cls->protocol, "bgp") == 0 ? 2 : 1;
}

static int copp_acl_rule_number(const copp_class_rule *cls, int index) {
    if (!cls || index < 0 || index >= copp_acl_rule_count(cls))
        return -1;
    return index == 0 ? cls->rule : NETLAB_COPP_BGP_SRC_RULE;
}

static bool copp_acl_rule_is_bgp_source(const copp_class_rule *cls,
                                        int index) {
    return cls && strcmp(cls->protocol, "bgp") == 0 && index == 1;
}

static copp_owner_state copp_acl_rule_exact_get(
    int sw, const copp_acl_rule_contract *expected, int *sdk_status) {
    fm_aclCondition condition;
    fm_aclValue value;
    fm_aclActionExt action;
    fm_aclParamExt param;
    fm_aclEntryState rule_state;
    fm_status st;

    if (!expected || !sdk_status) {
        if (sdk_status)
            *sdk_status = FM_ERR_INVALID_ARGUMENT;
        return COPP_OWNER_READ_ERROR;
    }

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    condition = 0;
    action = 0;
    st = fmGetACLRule((fm_int)sw, NETLAB_COPP_ACL_ID,
                      (fm_int)expected->rule, &condition, &value,
                      &action, &param);
    *sdk_status = (int)st;
    if (st == FM_ERR_INVALID_ACL_RULE)
        return COPP_OWNER_ABSENT;
    if (st != FM_OK)
        return COPP_OWNER_READ_ERROR;

    rule_state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    st = fmGetACLRuleState((fm_int)sw, NETLAB_COPP_ACL_ID,
                           (fm_int)expected->rule, &rule_state);
    *sdk_status = (int)st;
    if (st != FM_OK)
        return COPP_OWNER_READ_ERROR;
    if (rule_state != FM_ACL_RULE_ENTRY_STATE_VALID ||
        condition != expected->condition ||
        action != expected->action ||
        memcmp(&value, &expected->value, sizeof(value)) != 0 ||
        memcmp(&param, &expected->param, sizeof(param)) != 0) {
        *sdk_status = FM_ERR_INVALID_STATE;
        return COPP_OWNER_MISMATCH;
    }
    *sdk_status = FM_OK;
    return COPP_OWNER_EXACT;
}

static copp_owner_state copp_acl_owner_get(
    int sw, const copp_class_rule *cls,
    hal_copp_policer_transaction_snapshot *snapshot) {
    fm_aclArguments args;
    fm_status st;

    if (!cls || !snapshot) {
        if (snapshot)
            snapshot->sdk_status = FM_ERR_INVALID_ARGUMENT;
        return COPP_OWNER_READ_ERROR;
    }

    memset(&args, 0, sizeof(args));
    st = fmGetACL((fm_int)sw, NETLAB_COPP_ACL_ID, &args);
    snapshot->sdk_status = (int)st;
    if (st == FM_ERR_INVALID_ACL)
        return COPP_OWNER_ABSENT;
    if (st != FM_OK)
        return COPP_OWNER_READ_ERROR;
    if (args.scenarios != copp_acl_expected_scenarios() ||
        args.precedence != FM_ACL_DEFAULT_PRECEDENCE) {
        snapshot->sdk_status = FM_ERR_INVALID_STATE;
        return COPP_OWNER_MISMATCH;
    }

    snapshot->acl = NETLAB_COPP_ACL_ID;
    snapshot->acl_scenarios = (u32)args.scenarios;
    snapshot->acl_precedence = (int)args.precedence;
    snapshot->rule_count = copp_acl_rule_count(cls);
    for (int i = 0; i < snapshot->rule_count; i++) {
        copp_acl_rule_contract expected;
        copp_owner_state rule_result;
        int rule = copp_acl_rule_number(cls, i);

        if (copp_acl_rule_contract_build(
                cls, rule, copp_acl_rule_is_bgp_source(cls, i),
                &expected) != 0) {
            snapshot->sdk_status = FM_ERR_INVALID_ARGUMENT;
            return COPP_OWNER_READ_ERROR;
        }
        rule_result = copp_acl_rule_exact_get(
            sw, &expected, &snapshot->sdk_status);
        if (rule_result != COPP_OWNER_EXACT)
            return rule_result;

        copp_acl_rule_contract_export(&expected, &snapshot->rules[i]);
    }

    snapshot->sdk_status = FM_OK;
    return COPP_OWNER_EXACT;
}

static bool copp_snapshot_owner_contract_valid(
    const copp_class_rule *cls,
    const hal_copp_policer_transaction_snapshot *snapshot) {
    hal_copp_acl_rule_transaction_state expected_state;
    copp_acl_rule_contract expected;

    if (!cls || !snapshot ||
        snapshot->acl != NETLAB_COPP_ACL_ID ||
        snapshot->acl_scenarios != copp_acl_expected_scenarios() ||
        snapshot->acl_precedence != FM_ACL_DEFAULT_PRECEDENCE ||
        snapshot->rule_count != copp_acl_rule_count(cls))
        return false;

    for (int i = 0; i < snapshot->rule_count; i++) {
        int rule = copp_acl_rule_number(cls, i);

        if (copp_acl_rule_contract_build(
                cls, rule, copp_acl_rule_is_bgp_source(cls, i),
                &expected) != 0)
            return false;
        copp_acl_rule_contract_export(&expected, &expected_state);
        if (memcmp(&snapshot->rules[i], &expected_state,
                   sizeof(expected_state)) != 0)
            return false;
    }
    return true;
}

hal_copp_policer_transaction_snapshot
hal_control_plane_copp_transaction_snapshot(int sw, const char *class_name) {
    hal_copp_policer_transaction_snapshot snapshot;
    copp_class_rule *cls = find_copp_class(class_name);
    fm_status st;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    snapshot.policer = cls ? cls->policer : -1;
    if (!copp_class_is_link_local(cls))
        return snapshot;
    if (copp_acl_owner_get(sw, cls, &snapshot) != COPP_OWNER_EXACT)
        return snapshot;

    st = fmGetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                               FM_POLICER_COLOR_SOURCE,
                               &snapshot.color_source);
    snapshot.sdk_status = (int)st;
    if (st != FM_OK)
        return snapshot;

    st = fmGetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                               FM_POLICER_CIR_ACTION,
                               &snapshot.cir_action);
    if (st == FM_OK)
        st = fmGetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                                   FM_POLICER_CIR_CAPACITY,
                                   &snapshot.cir_capacity);
    if (st == FM_OK)
        st = fmGetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                                   FM_POLICER_CIR_RATE,
                                   &snapshot.cir_rate);
    snapshot.sdk_status = (int)st;
    if (st != FM_OK)
        return snapshot;

    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    return snapshot;
}

static bool copp_policer_snapshot_equal(
    const hal_copp_policer_transaction_snapshot *left,
    const hal_copp_policer_transaction_snapshot *right) {
    return left && right &&
           left->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           right->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           left->acl == right->acl &&
           left->acl_scenarios == right->acl_scenarios &&
           left->acl_precedence == right->acl_precedence &&
           left->rule_count == right->rule_count &&
           memcmp(left->rules, right->rules,
                  sizeof(left->rules)) == 0 &&
           left->policer == right->policer &&
           left->color_source == right->color_source &&
           left->cir_action == right->cir_action &&
           left->cir_capacity == right->cir_capacity &&
           left->cir_rate == right->cir_rate;
}

int hal_control_plane_copp_transaction_restore(
    int sw, const char *class_name,
    const hal_copp_policer_transaction_snapshot *snapshot) {
    copp_class_rule *cls = find_copp_class(class_name);
    hal_copp_policer_transaction_snapshot readback;
    fm_status st;

    if (!copp_class_is_link_local(cls) || !snapshot || snapshot->policer != cls->policer ||
        snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        !copp_snapshot_owner_contract_valid(cls, snapshot))
        return FM_ERR_INVALID_ARGUMENT;

    memset(&readback, 0, sizeof(readback));
    if (copp_acl_owner_get(sw, cls, &readback) != COPP_OWNER_EXACT)
        return readback.sdk_status != FM_OK ?
               readback.sdk_status : FM_ERR_INVALID_STATE;

    st = fmSetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                               FM_POLICER_COLOR_SOURCE,
                               &snapshot->color_source);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                                   FM_POLICER_CIR_ACTION,
                                   &snapshot->cir_action);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                                   FM_POLICER_CIR_CAPACITY,
                                   &snapshot->cir_capacity);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                                   FM_POLICER_CIR_RATE,
                                   &snapshot->cir_rate);
    if (st == FM_OK)
        st = fmUpdatePolicer((fm_int)sw, (fm_int)cls->policer);
    if (st != FM_OK)
        return (int)st;

    readback = hal_control_plane_copp_transaction_snapshot(sw, class_name);
    if (readback.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return readback.sdk_status != FM_OK ?
               readback.sdk_status : FM_ERR_INVALID_STATE;
    if (!copp_policer_snapshot_equal(snapshot, &readback))
        return FM_ERR_INVALID_STATE;

    cls->installed = true;
    return 0;
}

static int ensure_copp_acl_resource(int sw) {
    const hal_acl_resource_spec spec = {
        .owner = HAL_ACL_OWNER_COPP,
        .name = "copp-hardware",
        .preferred_acl = NETLAB_COPP_ACL_ID,
        .first_policer = NETLAB_COPP_POLICER_BASE,
        .policer_count = NETLAB_COPP_CLASSES,
    };
    hal_acl_resource_reservation reservation;
    fm_aclArguments args;
    fm_status st;

    memset(&reservation, 0, sizeof(reservation));
    if (hal_acl_resource_reserve(sw, &spec, &reservation) != 0)
        return -1;
    if (reservation.acl != NETLAB_COPP_ACL_ID)
        return -1;

    memset(&args, 0, sizeof(args));
    st = fmGetACL((fm_int)sw, (fm_int)reservation.acl, &args);
    if (st == FM_OK) {
        if (args.scenarios != copp_acl_expected_scenarios() ||
            args.precedence != FM_ACL_DEFAULT_PRECEDENCE)
            return -1;
        g_copp_acl = reservation.acl;
        return 0;
    }
    if (st != FM_ERR_INVALID_ACL) {
        NL_LOG_WARN("CoPP ACL read failed: %s", fmErrorMsg(st));
        return -1;
    }

    st = fmCreateACL((fm_int)sw, (fm_int)reservation.acl);
    if (st != FM_OK) {
        NL_LOG_WARN("CoPP ACL create failed: %s", fmErrorMsg(st));
        return -1;
    }

    memset(&args, 0, sizeof(args));
    st = fmGetACL((fm_int)sw, (fm_int)reservation.acl, &args);
    if (st != FM_OK ||
        args.scenarios != copp_acl_expected_scenarios() ||
        args.precedence != FM_ACL_DEFAULT_PRECEDENCE) {
        NL_LOG_WARN("CoPP ACL create read-back failed: %s",
                    fmErrorMsg(st));
        return -1;
    }
    g_copp_acl = reservation.acl;
    return 0;
}

static int copp_policer_presence_get(int sw, const copp_class_rule *cls,
                                     bool *present) {
    fm_uint32 rate = 0;
    fm_status st;

    if (!cls || !present)
        return FM_ERR_INVALID_ARGUMENT;

    *present = false;
    st = fmGetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                               FM_POLICER_CIR_RATE, &rate);
    if (st == FM_OK) {
        *present = true;
        return 0;
    }
    if (copp_policer_absent_status(st))
        return 0;

    NL_LOG_WARN("CoPP policer presence read failed class=%s policer=%d: %s",
                cls->protocol, cls->policer, fmErrorMsg(st));
    return (int)st;
}

static int create_or_update_copp_policer(int sw, const copp_class_rule *cls,
                                         int rate_pps, int burst_pkts,
                                         bool exists) {
    fm_policerConfig cfg;
    fm_uint32 rate_kbps;
    fm_uint32 burst_bytes;
    fm_status st;

    if (!copp_class_is_link_local(cls))
        return -1;

    memset(&cfg, 0, sizeof(cfg));
    rate_kbps = (fm_uint32)pps_to_kbps(rate_pps);
    burst_bytes = (fm_uint32)burst_pkts_to_bytes(burst_pkts);
    cfg.mkdnDscp = FM_DISABLED;
    cfg.mkdnSwPri = FM_DISABLED;
    cfg.colorSource = FM_POLICER_COLOR_SRC_GREEN;
    cfg.cirAction = FM_POLICER_ACTION_DROP;
    cfg.cirCapacity = burst_bytes;
    cfg.cirRate = rate_kbps;
    cfg.eirAction = FM_POLICER_ACTION_DROP;
    cfg.eirCapacity = 0;
    cfg.eirRate = 0;

    if (!exists) {
        st = fmCreatePolicer((fm_int)sw, FM_POLICER_BANK_AUTOMATIC,
                             (fm_int)cls->policer, &cfg);
        if (st == FM_OK)
            return 0;
        if (st != FM_ERR_ALREADY_EXISTS) {
            NL_LOG_WARN("CoPP policer create failed class=%s policer=%d: %s",
                        cls->protocol, cls->policer, fmErrorMsg(st));
            return (int)st;
        }
    }

    st = fmSetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                               FM_POLICER_COLOR_SOURCE, &cfg.colorSource);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                                   FM_POLICER_CIR_ACTION, &cfg.cirAction);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                                   FM_POLICER_CIR_CAPACITY, &cfg.cirCapacity);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)cls->policer,
                                   FM_POLICER_CIR_RATE, &cfg.cirRate);
    if (st == FM_OK)
        st = fmUpdatePolicer((fm_int)sw, (fm_int)cls->policer);
    if (st != FM_OK) {
        NL_LOG_WARN("CoPP policer update failed class=%s policer=%d: %s",
                    cls->protocol, cls->policer, fmErrorMsg(st));
        return (int)st;
    }
    return 0;
}

static int install_copp_acl_rule_one(int sw, const copp_class_rule *cls,
                                     int rule, bool bgp_source_port) {
    copp_acl_rule_contract contract;
    fm_status st;

    if (!cls || g_copp_acl <= 0)
        return -1;
    if (copp_acl_rule_contract_build(
            cls, rule, bgp_source_port, &contract) != 0)
        return -1;

    st = fmAddACLRuleExt((fm_int)sw, g_copp_acl, (fm_int)rule,
                         contract.condition, &contract.value,
                         contract.action, &contract.param);
    if (st != FM_OK) {
        NL_LOG_WARN("CoPP ACL rule add failed class=%s rule=%d: %s",
                    cls->protocol, rule, fmErrorMsg(st));
        return (int)st;
    }

    return 0;
}

static int install_copp_acl_rule(int sw, const copp_class_rule *cls,
                                 bool add_primary, bool add_bgp_source) {
    fm_status st;
    char compile_text[1024];

    if (!cls || g_copp_acl <= 0)
        return -1;
    if (!add_primary && !add_bgp_source)
        return 0;
    if (add_primary &&
        install_copp_acl_rule_one(sw, cls, cls->rule, false) != 0)
        return -1;
    if (add_bgp_source &&
        install_copp_acl_rule_one(sw, cls, NETLAB_COPP_BGP_SRC_RULE,
                                  true) != 0)
        return -1;

    memset(compile_text, 0, sizeof(compile_text));
    st = fmCompileACL((fm_int)sw, compile_text, sizeof(compile_text),
                      FM_ACL_COMPILE_FLAG_NON_DISRUPTIVE);
    if (st != FM_OK) {
        NL_LOG_WARN("CoPP ACL compile failed class=%s: %s (%s)",
                    cls->protocol, fmErrorMsg(st), compile_text);
        return (int)st;
    }
    st = fmApplyACL((fm_int)sw, FM_ACL_APPLY_FLAG_NON_DISRUPTIVE);
    if (st != FM_OK) {
        NL_LOG_WARN("CoPP ACL apply failed class=%s: %s",
                    cls->protocol, fmErrorMsg(st));
        return (int)st;
    }
    return 0;
}

static bool copp_snapshot_matches_request(
    const hal_copp_policer_transaction_snapshot *snapshot,
    int rate_pps, int burst_pkts) {
    return snapshot &&
           snapshot->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot->color_source == FM_POLICER_COLOR_SRC_GREEN &&
           snapshot->cir_action == FM_POLICER_ACTION_DROP &&
           snapshot->cir_capacity ==
               (u32)burst_pkts_to_bytes(burst_pkts) &&
           snapshot->cir_rate == (u32)pps_to_kbps(rate_pps);
}

static int provision_copp_class(int sw, copp_class_rule *cls,
                                int rate_pps, int burst_pkts) {
    bool add_rule[HAL_COPP_TRANSACTION_MAX_RULES] = { false, false };
    bool policer_present = false;
    int rule_count;
    hal_copp_policer_transaction_snapshot readback;

    if (!copp_class_is_link_local(cls) || rate_pps <= 0 || burst_pkts <= 0)
        return -1;
    if (ensure_copp_acl_resource(sw) != 0)
        return -1;

    rule_count = copp_acl_rule_count(cls);
    for (int i = 0; i < rule_count; i++) {
        copp_acl_rule_contract expected;
        copp_owner_state state;
        int sdk_status = FM_OK;

        if (copp_acl_rule_contract_build(
                cls, copp_acl_rule_number(cls, i),
                copp_acl_rule_is_bgp_source(cls, i), &expected) != 0)
            return -1;
        state = copp_acl_rule_exact_get(sw, &expected, &sdk_status);
        if (state == COPP_OWNER_ABSENT) {
            add_rule[i] = true;
            continue;
        }
        if (state != COPP_OWNER_EXACT) {
            NL_LOG_WARN("CoPP ACL owner rule preflight failed class=%s rule=%d status=%s",
                        cls->protocol, expected.rule,
                        fmErrorMsg(sdk_status));
            return -1;
        }
    }

    if (copp_policer_presence_get(sw, cls, &policer_present) != 0)
        return -1;
    if (create_or_update_copp_policer(sw, cls, rate_pps, burst_pkts,
                                      policer_present) != 0)
        return -1;
    if (install_copp_acl_rule(
            sw, cls, add_rule[0],
            rule_count == 2 && add_rule[1]) != 0)
        return -1;

    readback = hal_control_plane_copp_transaction_snapshot(
        sw, cls->protocol);
    if (!copp_snapshot_matches_request(&readback, rate_pps, burst_pkts))
        return -1;

    cls->rate_pps = rate_pps;
    cls->burst_pkts = burst_pkts;
    cls->installed = true;
    return 0;
}

/* Fresh SDK startup must not inherit the former transit policers or L3 copy
 * rules. An unexpected owner is an error, never permission to overwrite it. */
static int transit_copp_resources_absent(int sw) {
    for (int i = NETLAB_COPP_IGMP_INDEX; i < NETLAB_COPP_CLASSES; ++i) {
        const copp_class_rule *cls = &g_copp_classes[i];
        bool present = false;
        if (copp_policer_presence_get(sw, cls, &present) != 0 || present)
            return -1;
        if (i == NETLAB_COPP_IGMP_INDEX) continue;
        for (int rule = 0; rule < copp_acl_rule_count(cls); ++rule) {
            fm_aclCondition condition = 0;
            fm_aclValue value = {0};
            fm_aclActionExt action = 0;
            fm_aclParamExt param = {0};
            fm_status st = fmGetACLRule(sw, NETLAB_COPP_ACL_ID,
                copp_acl_rule_number(cls, rule), &condition, &value, &action, &param);
            if (st != FM_ERR_INVALID_ACL_RULE) return -1;
        }
    }
    return 0;
}

static int igmp_copy_read(int sw) {
    hal_copp_policer_transaction_snapshot owner = {0};
    return copp_acl_owner_get(sw, &g_copp_classes[NETLAB_COPP_IGMP_INDEX],
                              &owner) == COPP_OWNER_EXACT ? 0 : -1;
}

static int provision_igmp_copy(int sw) {
    copp_class_rule *cls = &g_copp_classes[NETLAB_COPP_IGMP_INDEX];
    copp_acl_rule_contract expected;
    int sdk_status = FM_OK;
    if (copp_acl_rule_contract_build(cls, cls->rule, false, &expected) != 0)
        return -1;
    copp_owner_state state = copp_acl_rule_exact_get(sw, &expected, &sdk_status);
    if (state == COPP_OWNER_ABSENT) {
        if (install_copp_acl_rule(sw, cls, true, false) != 0) return -1;
    } else if (state != COPP_OWNER_EXACT) {
        return -1;
    }
    return igmp_copy_read(sw);
}

static void mac_to_text(fm_macaddr mac, char *buf, size_t len) {
    snprintf(buf, len, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
             (unsigned long long)((mac >> 40) & 0xff),
             (unsigned long long)((mac >> 32) & 0xff),
             (unsigned long long)((mac >> 24) & 0xff),
             (unsigned long long)((mac >> 16) & 0xff),
             (unsigned long long)((mac >> 8) & 0xff),
             (unsigned long long)(mac & 0xff));
}

static const char *reserved_action_name(int action) {
    switch (action) {
    case FM_RES_MAC_ACTION_SWITCH:
        return "switch+external-trap";
    case FM_RES_MAC_ACTION_TRAP:
        return "trap";
    case FM_RES_MAC_ACTION_DROP:
        return "drop";
    case FM_RES_MAC_ACTION_LOG:
        return "log";
    default:
        return "unknown";
    }
}

static const char *reserved_state_name(int action) {
    switch (action) {
    case FM_RES_MAC_ACTION_SWITCH:
    case FM_RES_MAC_ACTION_TRAP:
        return "enabled";
    case FM_RES_MAC_ACTION_DROP:
        return "drop";
    case FM_RES_MAC_ACTION_LOG:
        return "log";
    default:
        return "unknown";
    }
}

static const char *reserved_enforcement_policed(int action) {
    switch (action) {
    case FM_RES_MAC_ACTION_SWITCH:
        return "reserved-mac:switch+external-trap+acl-police";
    case FM_RES_MAC_ACTION_TRAP:
        return "reserved-mac:trap+acl-police";
    case FM_RES_MAC_ACTION_DROP:
        return "reserved-mac:drop+acl-police";
    case FM_RES_MAC_ACTION_LOG:
        return "reserved-mac:log+acl-police";
    default:
        return "reserved-mac:unknown+acl-police";
    }
}

static int reserved_mac_action(int sw, int index, int *action) {
    fm_reservedMacCfg cfg;

    if (!action)
        return -1;
    memset(&cfg, 0, sizeof(cfg));
    cfg.index = index;
    if (fmGetSwitchAttribute((fm_int)sw, FM_SWITCH_RESERVED_MAC_CFG,
                             &cfg) != FM_OK)
        return -1;
    *action = cfg.action;
    return 0;
}

static nl_control_plane_protection_class *next_class(
    struct sdk_result *result) {
    int idx;

    if (!result)
        return NULL;
    idx = result->data.cp_protection.n_classes;
    if (idx < 0 || idx >= NETLAB_CP_PROTECTION_CLASS_MAX)
        return NULL;
    result->data.cp_protection.n_classes++;
    return &result->data.cp_protection.classes[idx];
}

static void set_class_text(nl_control_plane_protection_class *c,
                           const char *name, const char *protocol,
                           const char *match, const char *action,
                           const char *enforcement, const char *state) {
    if (!c)
        return;
    snprintf(c->name, sizeof(c->name), "%s", name ? name : "-");
    snprintf(c->protocol, sizeof(c->protocol), "%s",
             protocol ? protocol : "-");
    snprintf(c->match, sizeof(c->match), "%s", match ? match : "-");
    snprintf(c->action, sizeof(c->action), "%s", action ? action : "-");
    snprintf(c->enforcement, sizeof(c->enforcement), "%s",
             enforcement ? enforcement : "-");
    snprintf(c->state, sizeof(c->state), "%s", state ? state : "unknown");
}

static void add_reserved_class(struct sdk_result *result, int sw,
                               const char *name, const char *protocol,
                               fm_macaddr dst, int index) {
    nl_control_plane_protection_class *c = next_class(result);
    char mac[32];
    char match[64];
    char enforcement[64];
    int action = -1;
    int rate_pps = -1;
    int burst_pkts = -1;
    int policer = -1;
    int acl = -1;
    int rule = -1;
    u64 packets = (u64)-1;
    u64 octets = (u64)-1;

    if (!c)
        return;
    mac_to_text(dst, mac, sizeof(mac));
    snprintf(match, sizeof(match), "dst-mac=%s", mac);
    if (reserved_mac_action(sw, index, &action) == 0)
        snprintf(enforcement, sizeof(enforcement), "reserved-mac:%s",
                 reserved_action_name(action));
    else {
        snprintf(enforcement, sizeof(enforcement), "reserved-mac:unknown");
        action = -1;
    }

    set_class_text(c, name, protocol, match, "trap-to-cpu", enforcement,
                   reserved_state_name(action));
    c->table = -1;
    c->flow = -1;
    c->policer = -1;
    c->rate_kbps = -1;
    c->burst_bytes = -1;
    c->packets = (u64)-1;
    c->octets = (u64)-1;

    if (hal_control_plane_copp_get(sw, protocol, &rate_pps, &burst_pkts,
                                   &policer, &acl, &rule,
                                   &packets, &octets) == 0) {
        snprintf(c->enforcement, sizeof(c->enforcement), "%s",
                 reserved_enforcement_policed(action));
        snprintf(c->action, sizeof(c->action), "trap+police");
        snprintf(c->state, sizeof(c->state), "enabled");
        c->table = acl;
        c->flow = rule;
        c->policer = policer;
        c->rate_kbps = pps_to_kbps(rate_pps);
        c->burst_bytes = burst_pkts_to_bytes(burst_pkts);
        c->packets = packets;
        c->octets = octets;
    }
}

static void add_ip_protocol_class(struct sdk_result *result, int sw,
                                  const char *name, const char *protocol,
                                  const char *match) {
    nl_control_plane_protection_class *c = next_class(result);
    if (!c)
        return;
    bool igmp = strcmp(protocol, "igmp") == 0;
    set_class_text(c, name, protocol, match, igmp ? "copy-to-cpu" : "forward",
                   igmp ? "acl-log+cpu-egress-shaper" : "no-l3-punt-rule",
                   igmp ? "read-error" : "l3-disabled");
    c->table = -1;
    c->flow = -1;
    c->policer = -1;
    c->rate_kbps = -1;
    c->burst_bytes = -1;
    c->packets = (u64)-1;
    c->octets = (u64)-1;
    if (!igmp || igmp_copy_read(sw) != 0) return;
    snprintf(c->state, sizeof(c->state), "enabled");
    c->table = NETLAB_COPP_ACL_ID;
    c->flow = g_copp_classes[NETLAB_COPP_IGMP_INDEX].rule;
    fm_aclCounters counters = {0};
    if (fmGetACLCountExt(sw, c->table, c->flow, &counters) == FM_OK) {
        c->packets = counters.cntPkts;
        c->octets = counters.cntOctets;
    }
}

static int add_cpu_egress_class(struct sdk_result *result, int sw) {
    nl_control_plane_protection_class *c = next_class(result);
    hal_cpu_protection_state state;
    if (!c) return -1;
    set_class_text(c, "cpu-egress", "all-cpu-traffic", "cpu-port/all-tcs",
                   "shape-cpu-egress", "cpu-port:shaping-group-0", "read-error");
    c->table = c->flow = c->policer = -1;
    c->rate_kbps = c->burst_bytes = -1;
    c->packets = c->octets = (u64)-1;
    if (hal_cpu_protection_read(sw, &state) != FM_OK) return -1;
    snprintf(c->match, sizeof(c->match), "cpu-port=%d/all-tcs", state.port);
    c->rate_kbps = clamp_u64_to_int((state.rate_bps + 999ULL) / 1000ULL);
    c->burst_bytes = clamp_u64_to_int((state.burst_bits + 7ULL) / 8ULL);
    bool valid = hal_cpu_protection_matches(&state);
    snprintf(c->state, sizeof(c->state), "%s", valid ? "enabled" : "mismatch");
    return valid ? 0 : -1;
}

static fm_status find_existing_rule(fm_int sw, fm_int table,
                                    control_rule *rule,
                                    fm_int *flow_id) {
    fm_int current;
    fm_status st;

    if (!rule || !flow_id)
        return FM_ERR_INVALID_ARGUMENT;

    st = fmGetFlowRuleFirst(sw, table, &current);
    while (st == FM_OK) {
        fm_flowCondition cond = 0;
        fm_flowValue val;
        fm_flowAction action = 0;
        fm_flowParam param;
        fm_int priority = 0;
        fm_int precedence = 0;

        memset(&val, 0, sizeof(val));
        memset(&param, 0, sizeof(param));
        if (fmGetFlow(sw, table, current, &cond, &val,
                      &action, &param, &priority, &precedence) == FM_OK &&
            (cond & FM_FLOW_MATCH_DST_MAC) != 0 &&
            val.dst == rule->dst &&
            val.dstMask == 0xFFFFFFFFFFFFULL &&
            (action & FM_FLOW_ACTION_DROP) != 0) {
            *flow_id = current;
            return FM_OK;
        }

        {
            fm_int next = 0;
            st = fmGetFlowRuleNext(sw, table, current, &next);
            current = next;
        }
    }

    return FM_ERR_NOT_FOUND;
}

static fm_status install_rule(fm_int sw, fm_int table, control_rule *rule) {
    fm_flowValue cond;
    fm_flowParam param;
    fm_int flow_id = -1;
    fm_status st;

    if (!rule)
        return FM_ERR_INVALID_ARGUMENT;

    st = find_existing_rule(sw, table, rule, &flow_id);
    if (st == FM_OK) {
        rule->flow_id = flow_id;
        NL_LOG_INFO("control-plane protection exists: %s -> DROP+COUNT flow=%d",
                    rule->name, flow_id);
        return FM_OK;
    }

    memset(&cond, 0, sizeof(cond));
    memset(&param, 0, sizeof(param));
    cond.dst = rule->dst;
    cond.dstMask = 0xFFFFFFFFFFFFULL;

    st = fmAddFlow(sw, table, 0, 0,
                   FM_FLOW_MATCH_DST_MAC, &cond,
                   FM_FLOW_ACTION_DROP | FM_FLOW_ACTION_COUNT,
                   &param, FM_FLOW_STATE_ENABLED, &flow_id);
    if (st == FM_OK) {
        rule->flow_id = flow_id;
        NL_LOG_INFO("control-plane protection installed: %s -> DROP+COUNT flow=%d",
                    rule->name, flow_id);
    }
    return st;
}

int hal_control_plane_init(int sw) {
    const hal_flow_table_spec spec = {
        .owner = HAL_FLOW_OWNER_CONTROL_PLANE,
        .name = "control-plane-protection",
        .preferred_table = 31,
        .condition = FM_FLOW_MATCH_DST_MAC,
        .max_entries = NETLAB_CONTROL_FLOW_MAX_ENTRIES,
        .max_actions = NETLAB_CONTROL_FLOW_MAX_ACTIONS,
    };
    hal_flow_table_reservation reservation;
    fm_status st;
    int ok = 0;

    /* The board's initial data-port gate stays closed until this guard and
     * the non-dropping IGMP copy rule have both been read back. */
    if (hal_cpu_protection_init(sw) != FM_OK ||
        ensure_copp_acl_resource(sw) != 0 ||
        transit_copp_resources_absent(sw) != 0 ||
        provision_igmp_copy(sw) != 0)
        return -1;

    memset(&reservation, 0, sizeof(reservation));
    if (hal_flow_table_reserve(sw, &spec, &reservation) != 0) {
        NL_LOG_WARN("control-plane protection table reservation failed");
        return -1;
    }
    g_control_flow_table = reservation.table;

    for (size_t i = 0; i < sizeof(g_rules) / sizeof(g_rules[0]); i++) {
        st = install_rule((fm_int)sw, g_control_flow_table, &g_rules[i]);
        if (st == FM_OK)
            ok++;
        else
            NL_LOG_WARN("control-plane protection %s install failed: %s",
                        g_rules[i].name, fmErrorMsg(st));
    }

    for (int i = 0; i < NETLAB_COPP_LINK_LOCAL_CLASSES; i++) {
        if (provision_copp_class(
                sw, &g_copp_classes[i],
                g_copp_classes[i].default_rate_pps,
                g_copp_classes[i].default_burst_pkts) == 0)
            ok++;
        else
            NL_LOG_WARN("CoPP hardware policer %s initialization failed",
                        g_copp_classes[i].protocol);
    }

    return ok == (int)(sizeof(g_rules) / sizeof(g_rules[0]) +
                       NETLAB_COPP_LINK_LOCAL_CLASSES) ? 0 : -1;
}

int hal_control_plane_copp_set(int sw, const char *class_name,
                               int rate_pps, int burst_pkts) {
    copp_class_rule *cls = find_copp_class(class_name);
    hal_copp_policer_transaction_snapshot before;
    hal_copp_policer_transaction_snapshot readback;

    if (!copp_class_is_link_local(cls) || rate_pps <= 0 || burst_pkts <= 0)
        return -1;
    /*
     * A method-41 update is deliberately update-only.  The complete live ACL,
     * owner-rule, and policer tuple must already be exact before the first
     * write.  Startup provisioning owns creation separately.
     */
    before = hal_control_plane_copp_transaction_snapshot(sw, class_name);
    if (before.state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return -1;
    if (create_or_update_copp_policer(sw, cls, rate_pps, burst_pkts,
                                      true) != 0)
        return -1;
    readback = hal_control_plane_copp_transaction_snapshot(sw, class_name);
    if (!copp_snapshot_matches_request(&readback, rate_pps, burst_pkts))
        return -1;

    g_copp_acl = NETLAB_COPP_ACL_ID;
    cls->rate_pps = rate_pps;
    cls->burst_pkts = burst_pkts;
    cls->installed = true;
    NL_LOG_INFO("CoPP hardware policer set class=%s policer=%d rate=%dpps burst=%dpkts",
                cls->protocol, cls->policer, rate_pps, burst_pkts);
    return 0;
}

int hal_control_plane_copp_get(int sw, const char *class_name,
                               int *rate_pps, int *burst_pkts,
                               int *policer, int *acl, int *rule,
                               u64 *packets, u64 *octets) {
    copp_class_rule *cls = find_copp_class(class_name);
    hal_copp_policer_transaction_snapshot snapshot;
    fm_aclCounters counters;

    if (!cls)
        return -1;
    snapshot = hal_control_plane_copp_transaction_snapshot(
        sw, class_name);
    if (snapshot.state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return -1;

    if (rate_pps)
        *rate_pps = kbps_to_pps(snapshot.cir_rate);
    if (burst_pkts)
        *burst_pkts = bytes_to_burst_pkts(snapshot.cir_capacity);
    if (policer)
        *policer = cls->policer;
    if (acl)
        *acl = snapshot.acl;
    if (rule)
        *rule = cls->rule;
    if (packets)
        *packets = (u64)-1;
    if (octets)
        *octets = (u64)-1;

    memset(&counters, 0, sizeof(counters));
    if (fmGetACLCountExt((fm_int)sw, snapshot.acl, (fm_int)cls->rule,
                         &counters) == FM_OK) {
        if (packets)
            *packets = counters.cntPkts;
        if (octets)
            *octets = counters.cntOctets;
    }
    if (strcmp(cls->protocol, "bgp") == 0) {
        fm_aclCounters reverse;

        memset(&reverse, 0, sizeof(reverse));
        if (fmGetACLCountExt((fm_int)sw, snapshot.acl,
                             NETLAB_COPP_BGP_SRC_RULE, &reverse) == FM_OK) {
            if (packets && *packets != (u64)-1)
                *packets += reverse.cntPkts;
            if (octets && *octets != (u64)-1)
                *octets += reverse.cntOctets;
        }
    }
    g_copp_acl = snapshot.acl;
    cls->rate_pps = kbps_to_pps(snapshot.cir_rate);
    cls->burst_pkts = bytes_to_burst_pkts(snapshot.cir_capacity);
    cls->installed = true;
    return 0;
}

int hal_control_plane_collect_stats(int sw, int *rules, int *pkts, int *octets,
                                    int *table, int *capacity,
                                    int *free_entries) {
    fm_uint64 total_pkts = 0;
    fm_uint64 total_octets = 0;
    int active = 0;

    if (rules)
        *rules = -1;
    if (pkts)
        *pkts = -1;
    if (octets)
        *octets = -1;
    if (table)
        *table = g_control_flow_table >= 0 ? g_control_flow_table : -1;
    if (capacity)
        *capacity = -1;
    if (free_entries)
        *free_entries = -1;

    if (g_control_flow_table >= 0) {
        fm_int value = -1;
        if (capacity &&
            fmGetFlowAttribute((fm_int)sw, g_control_flow_table,
                               FM_FLOW_TABLE_MAX_ENTRIES, &value) == FM_OK)
            *capacity = (int)value;
        value = -1;
        if (free_entries &&
            fmGetFlowAttribute((fm_int)sw, g_control_flow_table,
                               FM_FLOW_TABLE_EMPTY_ENTRIES, &value) == FM_OK)
            *free_entries = (int)value;
    }

    for (size_t i = 0; i < sizeof(g_rules) / sizeof(g_rules[0]); i++) {
        fm_flowCounters counters;

        if (g_control_flow_table < 0)
            break;
        if (g_rules[i].flow_id < 0)
            continue;

        memset(&counters, 0, sizeof(counters));
        if (fmGetFlowCount((fm_int)sw, g_control_flow_table,
                           g_rules[i].flow_id, &counters) != FM_OK)
            continue;

        total_pkts += counters.cntPkts;
        total_octets += counters.cntOctets;
        active++;
    }

    if (rules)
        *rules = active;
    if (pkts)
        *pkts = active > 0 ? clamp_u64_to_int(total_pkts) : -1;
    if (octets)
        *octets = active > 0 ? clamp_u64_to_int(total_octets) : -1;

    return active > 0 ? 0 : -1;
}

int hal_control_plane_collect_protection(int sw, struct sdk_result *result) {
    int rules = -1;
    int packets = -1;
    int octets = -1;
    int table = -1;
    int capacity = -1;
    int free_entries = -1;

    if (!result)
        return -1;

    memset(&result->data.cp_protection, 0,
           sizeof(result->data.cp_protection));
    result->data.cp_protection.table =
        g_control_flow_table >= 0 ? g_control_flow_table : -1;
    result->data.cp_protection.capacity = -1;
    result->data.cp_protection.free = -1;
    result->data.cp_protection.policers = 0;
    for (int i = 0; i < NETLAB_COPP_CLASSES; i++) {
        if (g_copp_classes[i].installed)
            result->data.cp_protection.policers++;
    }

    (void)hal_control_plane_collect_stats(sw, &rules, &packets, &octets,
                                          &table, &capacity, &free_entries);
    result->data.cp_protection.table = table;
    result->data.cp_protection.capacity = capacity;
    result->data.cp_protection.free = free_entries;

    add_reserved_class(result, sw, "ieee-rstp", "rstp",
                       0x0180C2000000LL, 0x00);
    add_reserved_class(result, sw, "ieee-lacp", "lacp",
                       0x0180C2000002LL, 0x02);
    add_reserved_class(result, sw, "ieee-lldp", "lldp",
                       0x0180C200000ELL, 0x0E);
    add_ip_protocol_class(result, sw, "ethernet-arp", "arp",
                          "ethertype=0x0806");
    add_ip_protocol_class(result, sw, "ipv4-icmp", "icmp",
                          "ipv4-proto=1");
    add_ip_protocol_class(result, sw, "ipv4-ospf", "ospf",
                          "ipv4-proto=89");
    add_ip_protocol_class(result, sw, "ipv4-bgp", "bgp",
                          "tcp-src-or-dst-port=179");
    add_ip_protocol_class(result, sw, "ipv4-igmp", "igmp",
                          "ipv4-proto=2");

    int protection_status = add_cpu_egress_class(result, sw);
    if (transit_copp_resources_absent(sw) != 0 || igmp_copy_read(sw) != 0) {
        protection_status = -1;
        for (int i = 0; i < result->data.cp_protection.n_classes; ++i) {
            nl_control_plane_protection_class *c = &result->data.cp_protection.classes[i];
            if (strcmp(c->state, "l3-disabled") == 0 || strcmp(c->protocol, "igmp") == 0)
                snprintf(c->state, sizeof(c->state), "read-error");
        }
    }

    for (size_t i = 0; i < sizeof(g_rules) / sizeof(g_rules[0]); i++) {
        nl_control_plane_protection_class *c = next_class(result);
        char mac[32];
        char match[64];
        fm_flowCounters counters;

        if (!c)
            break;
        mac_to_text(g_rules[i].dst, mac, sizeof(mac));
        snprintf(match, sizeof(match), "dst-mac=%s", mac);
        set_class_text(c, g_rules[i].name, g_rules[i].protocol, match,
                       "drop+count", "flow-tcam", "enabled");
        c->table = g_control_flow_table;
        c->flow = (int)g_rules[i].flow_id;
        c->policer = -1;
        c->rate_kbps = -1;
        c->burst_bytes = -1;
        c->packets = 0;
        c->octets = 0;

        if (g_control_flow_table < 0 || g_rules[i].flow_id < 0) {
            snprintf(c->state, sizeof(c->state), "not-installed");
            continue;
        }

        memset(&counters, 0, sizeof(counters));
        if (fmGetFlowCount((fm_int)sw, g_control_flow_table,
                           g_rules[i].flow_id, &counters) == FM_OK) {
            c->packets = counters.cntPkts;
            c->octets = counters.cntOctets;
        } else {
            c->packets = (u64)-1;
            c->octets = (u64)-1;
        }
    }

    return protection_status;
}
