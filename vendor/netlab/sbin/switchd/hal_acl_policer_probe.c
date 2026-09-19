#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include "hal_acl_owner_transaction_api.h"
#include "hal_acl_resource.h"
#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <fm_sdk.h>
#include <api/fm_api_acl.h>
#include <api/fm_api_policer.h>
#include <api/fm_api_portset.h>

#define NETLAB_ACL_POLICER_PROBE_ACL_ID 3100
#define NETLAB_ACL_POLICER_PROBE_RULE 199
#define NETLAB_ACL_POLICER_PROBE_POLICER 200
#define NETLAB_ACL_POLICER_OWNER_RULE 198
#define NETLAB_ACL_POLICER_OWNER_POLICER 201
#define NETLAB_ACL_POLICER_OWNER_MAX_SLOTS 8
#define NETLAB_ACL_POLICER_PROBE_DST_MAC 0x020000AC1077ULL
#define NETLAB_ACL_POLICER_PROBE_MIN_RATE_KBPS 1
#define NETLAB_ACL_POLICER_PROBE_MAX_RATE_KBPS 100000000
#define NETLAB_ACL_POLICER_PROBE_MIN_BURST_BYTES 1024
#define NETLAB_ACL_POLICER_PROBE_MAX_BURST_BYTES 268435456
#define NETLAB_ACL_EGRESS_PROBE_ACL_ID 3200
#define NETLAB_ACL_EGRESS_PROBE_RULE 1
#define NETLAB_ACL_EGRESS_PROBE_DST_MAC 0x020000ACE901ULL
#define NETLAB_ACL_EGRESS_OWNER_ACL_ID 3201
#define NETLAB_ACL_EGRESS_OWNER_RULE 1
#define NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS 8
#define NETLAB_ACL_GENERAL_INGRESS_ACL_START 3300
#define NETLAB_ACL_GENERAL_INGRESS_ACL_COUNT 16
#define NETLAB_ACL_GENERAL_INGRESS_RULES_PER_ACL 128
#define NETLAB_ACL_GENERAL_INGRESS_POLICER_START 301
#define NETLAB_ACL_GENERAL_INGRESS_POLICER_COUNT 32
#define NETLAB_ACL_INDEPENDENT_SHARED_ACL_ID NETLAB_ACL_POLICER_PROBE_ACL_ID
#define NETLAB_ACL_INDEPENDENT_SHARED_ACL_COUNT 1
#define NETLAB_ACL_GENERAL_EGRESS_ACL_START 3400
#define NETLAB_ACL_GENERAL_EGRESS_ACL_COUNT 16
#define NETLAB_ACL_GENERAL_EGRESS_RULES_PER_ACL 128
#define NETLAB_ACL_GENERAL_COMPILER_RULE 1
#define NETLAB_ACL_GENERAL_COMPILER_DST_MAC 0x020000AC3300ULL
#define NETLAB_ACL_GENERAL_COMPILER_POLICER_RULE 2
#define NETLAB_ACL_GENERAL_COMPILER_POLICER 301
#define NETLAB_ACL_GENERAL_COMPILER_POLICER_DST_MAC 0x020000AC3301ULL
#define NETLAB_ACL_GENERAL_COMPILER_ETH_DST_MAC 0x020000AC3302ULL
#define NETLAB_ACL_GENERAL_COMPILER_INET_SRC_IP 0x0a330001U
#define NETLAB_ACL_GENERAL_COMPILER_INET_DST_IP 0x0a330002U
#define NETLAB_ACL_GENERAL_COMPILER_INET_POLICER_SRC_IP 0x0a330003U
#define NETLAB_ACL_GENERAL_COMPILER_INET_POLICER_DST_IP 0x0a330004U
#define NETLAB_ACL_GENERAL_COMPILER_INET_L4_DST 4789
#define NETLAB_ACL_GENERAL_COMPILER_INET_POLICER_L4_DST 4790
#define NETLAB_ACL_GENERAL_COMPILER_POLICER_RATE_KBPS 1000
#define NETLAB_ACL_GENERAL_COMPILER_POLICER_BURST_BYTES 65536
#define NETLAB_ACL_INDEPENDENT_OWNER_MAX_SLOTS 32
#define NETLAB_ACL_INDEPENDENT_RULE_BASE 16
#define NETLAB_ACL_INDEPENDENT_VLAN_MASK 0x0fff
#define NETLAB_ACL_INDEPENDENT_ETHERTYPE_IPV4 0x0800
#define NETLAB_ACL_INDEPENDENT_ETHERTYPE_MASK 0xffff
#define NETLAB_ACL_INDEPENDENT_MAC_MASK 0xffffffffffffULL
#define NETLAB_ACL_INDEPENDENT_IP_MASK 0xffffffffU
#define NETLAB_ACL_INDEPENDENT_DSCP_MASK 0x3f
#define NETLAB_ACL_INDEPENDENT_PROTOCOL_MASK 0xff
#define NETLAB_ACL_INDEPENDENT_L4_MASK 0xffff
#define NETLAB_ACL_INDEPENDENT_TCP_FLAGS_MASK 0x3f
#define NETLAB_ACL_SHARED_CREATION_REGISTRY_MAX 8
#define NETLAB_ACL_SDK_ERROR_TEXT_MAX 128
#define NETLAB_ACL_TRUNCATION_MARKER " [truncated]"

typedef enum {
    ACL_GENERAL_PROFILE_INGRESS_COUNT_AND_POLICER = 0,
    ACL_GENERAL_PROFILE_ETHERNET_COUNT,
    ACL_GENERAL_PROFILE_INET_COUNT,
    ACL_GENERAL_PROFILE_INET_COUNT_AND_POLICER,
} acl_general_profile;

static bool g_acl_general_allocator_active;
static int g_acl_general_allocator_port;
static int g_acl_general_allocator_port_set = -1;
static acl_general_profile g_acl_general_allocator_profile =
    ACL_GENERAL_PROFILE_INGRESS_COUNT_AND_POLICER;

static const char *general_acl_profile_name(acl_general_profile profile) {
    switch (profile) {
    case ACL_GENERAL_PROFILE_ETHERNET_COUNT:
        return "ethernet-count";
    case ACL_GENERAL_PROFILE_INET_COUNT:
        return "inet-count";
    case ACL_GENERAL_PROFILE_INET_COUNT_AND_POLICER:
        return "inet-count-and-policer";
    case ACL_GENERAL_PROFILE_INGRESS_COUNT_AND_POLICER:
    default:
        return "ingress-count-and-policer";
    }
}

static bool general_acl_profile_uses_policer(acl_general_profile profile) {
    return profile == ACL_GENERAL_PROFILE_INGRESS_COUNT_AND_POLICER ||
           profile == ACL_GENERAL_PROFILE_INET_COUNT_AND_POLICER;
}

static int general_acl_profile_from_args(
    const hal_acl_general_allocator_args *args,
    acl_general_profile *profile) {
    const char *name = args ? args->profile : NULL;

    if (!profile)
        return -1;
    if (!name || name[0] == '\0' ||
        strcmp(name, "ingress-count-and-policer") == 0) {
        *profile = ACL_GENERAL_PROFILE_INGRESS_COUNT_AND_POLICER;
        return 0;
    }
    if (strcmp(name, "ethernet-count") == 0) {
        *profile = ACL_GENERAL_PROFILE_ETHERNET_COUNT;
        return 0;
    }
    if (strcmp(name, "inet-count") == 0) {
        *profile = ACL_GENERAL_PROFILE_INET_COUNT;
        return 0;
    }
    if (strcmp(name, "inet-count-and-policer") == 0) {
        *profile = ACL_GENERAL_PROFILE_INET_COUNT_AND_POLICER;
        return 0;
    }
    return -1;
}

static struct {
    bool active;
    hal_acl_policer_owner_args args;
    int acl;
    int rule;
    int policer;
    int port_set;
} g_acl_policer_owner[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS];

static struct {
    bool active;
    hal_acl_egress_owner_args args;
    int acl;
    int rule;
} g_acl_egress_owner[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];

static struct {
    bool active;
    hal_acl_independent_args args;
    int acl;
    int rule;
    int policer;
    int port_set;
} g_acl_independent_owner[NETLAB_ACL_INDEPENDENT_OWNER_MAX_SLOTS];

typedef struct {
    bool used;
    bool claimed;
    hal_acl_shared_creation_token token;
} acl_shared_creation_registry_entry;

static acl_shared_creation_registry_entry
    g_acl_shared_creation_registry[
        NETLAB_ACL_SHARED_CREATION_REGISTRY_MAX];
static u64 g_acl_shared_creation_generation = 1;

static void clear_acl_shared_creation_token(
    hal_acl_shared_creation_token *token) {
    if (!token)
        return;
    memset(token, 0, sizeof(*token));
    token->sw = -1;
    token->acl = -1;
}

static acl_shared_creation_registry_entry *
acl_shared_creation_find(int sw, int acl) {
    for (int i = 0;
         i < NETLAB_ACL_SHARED_CREATION_REGISTRY_MAX; i++) {
        if (g_acl_shared_creation_registry[i].used &&
            g_acl_shared_creation_registry[i].token.sw == sw &&
            g_acl_shared_creation_registry[i].token.acl == acl)
            return &g_acl_shared_creation_registry[i];
    }
    return NULL;
}

static acl_shared_creation_registry_entry *
acl_shared_creation_slot(int sw, int acl) {
    acl_shared_creation_registry_entry *entry =
        acl_shared_creation_find(sw, acl);

    if (entry)
        return entry;
    for (int i = 0;
         i < NETLAB_ACL_SHARED_CREATION_REGISTRY_MAX; i++) {
        if (!g_acl_shared_creation_registry[i].used)
            return &g_acl_shared_creation_registry[i];
    }
    return NULL;
}

static u64 next_acl_shared_creation_generation(void) {
    u64 generation = g_acl_shared_creation_generation++;

    if (generation == 0) {
        generation = 1;
        g_acl_shared_creation_generation = 2;
    }
    return generation;
}

static bool acl_shared_creation_token_matches(
    const acl_shared_creation_registry_entry *entry,
    const hal_acl_shared_creation_token *token) {
    return entry && token && entry->used && token->valid &&
           entry->token.valid &&
           entry->token.sw == token->sw &&
           entry->token.acl == token->acl &&
           entry->token.creator == token->creator &&
           entry->token.generation == token->generation;
}

static int claim_acl_shared_creation_token(
    const hal_acl_shared_creation_token *token) {
    acl_shared_creation_registry_entry *entry;

    if (!token || !token->valid)
        return -1;
    entry = acl_shared_creation_find(token->sw, token->acl);
    if (!acl_shared_creation_token_matches(entry, token))
        return -1;
    entry->claimed = true;
    return 0;
}

static void abandon_acl_shared_creation_token(
    const hal_acl_shared_creation_token *token) {
    acl_shared_creation_registry_entry *entry;

    if (!token || !token->valid)
        return;
    entry = acl_shared_creation_find(token->sw, token->acl);
    if (acl_shared_creation_token_matches(entry, token))
        memset(entry, 0, sizeof(*entry));
}

int hal_acl_shared_creation_tokens_retire(
    const hal_acl_shared_creation_token *tokens, int count) {
    acl_shared_creation_registry_entry
        *entries[NETLAB_ACL_SHARED_CREATION_REGISTRY_MAX];

    if (count < 0 ||
        count > NETLAB_ACL_SHARED_CREATION_REGISTRY_MAX ||
        (count > 0 && !tokens))
        return -1;
    memset(entries, 0, sizeof(entries));
    for (int i = 0; i < count; i++) {
        acl_shared_creation_registry_entry *entry;

        if (!tokens[i].valid)
            return -1;
        entry = acl_shared_creation_find(
            tokens[i].sw, tokens[i].acl);
        if (!acl_shared_creation_token_matches(
                entry, &tokens[i]) ||
            !entry->claimed)
            return -1;
        for (int j = 0; j < i; j++)
            if (entries[j] == entry)
                return -1;
        entries[i] = entry;
    }
    for (int i = 0; i < count; i++)
        memset(entries[i], 0, sizeof(*entries[i]));
    return 0;
}

static void fill_general_allocator_defaults(
    hal_acl_general_allocator_result *result,
    acl_general_profile profile) {
    if (!result)
        return;
    result->ingress_acl_start = NETLAB_ACL_GENERAL_INGRESS_ACL_START;
    result->ingress_acl_count = NETLAB_ACL_GENERAL_INGRESS_ACL_COUNT;
    result->ingress_rules_per_acl =
        NETLAB_ACL_GENERAL_INGRESS_RULES_PER_ACL;
    result->ingress_policer_start =
        NETLAB_ACL_GENERAL_INGRESS_POLICER_START;
    result->ingress_policer_count =
        NETLAB_ACL_GENERAL_INGRESS_POLICER_COUNT;
    result->egress_acl_start = NETLAB_ACL_GENERAL_EGRESS_ACL_START;
    result->egress_acl_count = NETLAB_ACL_GENERAL_EGRESS_ACL_COUNT;
    result->egress_rules_per_acl = NETLAB_ACL_GENERAL_EGRESS_RULES_PER_ACL;
    result->compiler_acl = NETLAB_ACL_GENERAL_INGRESS_ACL_START;
    result->compiler_rule = NETLAB_ACL_GENERAL_COMPILER_RULE;
    result->compiler_port = g_acl_general_allocator_port;
    result->compiler_port_set = g_acl_general_allocator_port_set;
    result->compiler_profile_id = (int)profile;
    result->compiler_term_count =
        general_acl_profile_uses_policer(profile) ? 2 : 1;
    result->compiler_policer_rule =
        general_acl_profile_uses_policer(profile) ?
        NETLAB_ACL_GENERAL_COMPILER_POLICER_RULE : -1;
    result->compiler_policer =
        general_acl_profile_uses_policer(profile) ?
        NETLAB_ACL_GENERAL_COMPILER_POLICER : 0;
    snprintf(result->compiler_profile, sizeof(result->compiler_profile),
             "%s", general_acl_profile_name(profile));
}

static int general_allocator_owner_count(int sw, int *mismatches) {
    hal_acl_resource_owner_info owners[NETLAB_ACL_RESOURCE_OWNER_MAX];
    int n;
    int found_ingress = 0;
    int found_egress = 0;

    if (mismatches)
        *mismatches = 0;
    n = hal_acl_resource_collect_owners(sw, owners,
                                        NETLAB_ACL_RESOURCE_OWNER_MAX);
    if (n < 0)
        return -1;
    for (int i = 0; i < n; i++) {
        if (owners[i].owner == HAL_ACL_OWNER_GENERAL_INGRESS) {
            found_ingress++;
            if (owners[i].acl != NETLAB_ACL_GENERAL_INGRESS_ACL_START ||
                owners[i].acl_count != NETLAB_ACL_GENERAL_INGRESS_ACL_COUNT ||
                owners[i].rules_per_acl !=
                    NETLAB_ACL_GENERAL_INGRESS_RULES_PER_ACL ||
                owners[i].first_policer !=
                    NETLAB_ACL_GENERAL_INGRESS_POLICER_START ||
                owners[i].policer_count !=
                    NETLAB_ACL_GENERAL_INGRESS_POLICER_COUNT) {
                if (mismatches)
                    (*mismatches)++;
            }
        } else if (owners[i].owner == HAL_ACL_OWNER_GENERAL_EGRESS) {
            found_egress++;
            if (owners[i].acl != NETLAB_ACL_GENERAL_EGRESS_ACL_START ||
                owners[i].acl_count != NETLAB_ACL_GENERAL_EGRESS_ACL_COUNT ||
                owners[i].rules_per_acl !=
                    NETLAB_ACL_GENERAL_EGRESS_RULES_PER_ACL ||
                owners[i].first_policer != 0 ||
                owners[i].policer_count != 0) {
                if (mismatches)
                    (*mismatches)++;
            }
        }
    }
    return found_ingress + found_egress;
}

static bool status_missing_ok(fm_status st) {
    return st == FM_OK ||
        st == FM_ERR_NOT_FOUND ||
        st == FM_ERR_INVALID_ACL ||
        st == FM_ERR_INVALID_ACL_RULE ||
        st == FM_ERR_NO_RULES_IN_ACL;
}

static bool egress_acl_missing_ok(fm_status st) {
    return status_missing_ok(st) || st == FM_ERR_INVALID_PORT;
}

typedef enum {
    ACL_LIVE_READ_ERROR = -1,
    ACL_LIVE_EMPTY = 0,
    ACL_LIVE_OCCUPIED = 1,
    ACL_LIVE_OWNER = 2,
} acl_live_slot_state;

typedef struct {
    hal_transaction_snapshot_state state;
    fm_status sdk_status;
    bool fixed_exact;
    int rate_kbps;
    int burst_bytes;
} acl_live_policer;

typedef struct {
    acl_live_slot_state state;
    fm_status sdk_status;
    int slot;
    int acl;
    int rule;
    int policer;
    int port_set;
    int port;
    u64 dst_mac;
    int rate_kbps;
    int burst_bytes;
    bool dst_key_valid;
    bool semantic_identity_valid;
} acl_policer_live_slot;

typedef struct {
    acl_live_slot_state state;
    fm_status sdk_status;
    int slot;
    int acl;
    int rule;
    int port;
    u64 src_mac;
    u64 dst_mac;
    bool rule_key_valid;
    bool semantic_identity_valid;
} acl_egress_live_slot;

typedef struct {
    acl_live_slot_state state;
    fm_status sdk_status;
    int slot;
    int acl;
    int rule;
    int policer;
    int port_set;
    int port;
    int rate_kbps;
    int burst_bytes;
    bool semantic_match;
    bool exact_match;
} acl_independent_live_slot;

static int acl_presence_get(int sw, int acl, bool *present,
                            fm_status *sdk_status) {
    fm_aclArguments arguments;
    fm_status st;
    const fm_uint32 expected_scenarios =
        FM_ACL_SCENARIO_ANY_FRAME_TYPE |
        FM_ACL_SCENARIO_ANY_ROUTING_TYPE |
        FM_ACL_SCENARIO_ANY_TUNNEL_TYPE;

    if (!present || !sdk_status)
        return -1;
    *present = false;
    *sdk_status = FM_OK;
    memset(&arguments, 0, sizeof(arguments));
    st = fmGetACL((fm_int)sw, (fm_int)acl, &arguments);
    if (st == FM_OK) {
        if (arguments.scenarios != expected_scenarios ||
            arguments.precedence != FM_ACL_DEFAULT_PRECEDENCE) {
            *sdk_status = FM_ERR_INVALID_STATE;
            return -1;
        }
        *present = true;
        return 0;
    }
    if (st == FM_ERR_INVALID_ACL || st == FM_ERR_NO_ACLS)
        return 0;
    *sdk_status = st;
    return -1;
}

static fm_status create_default_acl_exact(int sw, int acl, bool *created) {
    bool present = false;
    fm_status detail_status = FM_OK;
    fm_status st;

    if (!created)
        return FM_ERR_INVALID_ARGUMENT;
    *created = false;
    st = fmCreateACL((fm_int)sw, (fm_int)acl);
    if (st != FM_OK)
        return st;
    *created = true;
    if (acl_presence_get(
            sw, acl, &present, &detail_status) != 0)
        return detail_status;
    return present ? FM_OK : FM_ERR_INVALID_STATE;
}

/*
 * fmDeleteACL() also discards every rule owned by the ACL.  It is therefore
 * safe for a transaction-created shared ACL only after both rule and port
 * iterators prove that the live ACL is empty.
 */
static fm_status delete_empty_default_acl_exact(int sw, int acl) {
    fm_aclCondition condition = 0;
    fm_aclValue value;
    fm_aclActionExt action = 0;
    fm_aclParamExt param;
    fm_aclPortAndType port_and_type;
    fm_int rule = -1;
    bool present = false;
    fm_status detail_status = FM_OK;
    fm_status st;

    if (acl_presence_get(
            sw, acl, &present, &detail_status) != 0)
        return detail_status;
    if (!present)
        return FM_OK;

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    st = fmGetACLRuleFirstExt(
        (fm_int)sw, (fm_int)acl, &rule, &condition, &value,
        &action, &param);
    if (st == FM_OK)
        return FM_ERR_INVALID_STATE;
    if (st != FM_ERR_NO_RULES_IN_ACL)
        return st;

    memset(&port_and_type, 0, sizeof(port_and_type));
    st = fmGetACLPortFirst(
        (fm_int)sw, (fm_int)acl, &port_and_type);
    if (st == FM_OK)
        return FM_ERR_INVALID_STATE;
    if (st != FM_ERR_NO_MORE)
        return st;

    st = fmDeleteACL((fm_int)sw, (fm_int)acl);
    if (st != FM_OK && st != FM_ERR_INVALID_ACL)
        return st;
    if (acl_presence_get(
            sw, acl, &present, &detail_status) != 0)
        return detail_status;
    return present ? FM_ERR_INVALID_STATE : FM_OK;
}

static fm_status create_shared_acl_exact_with_token(
    int sw, int acl, hal_acl_shared_creator creator,
    hal_acl_shared_creation_token *token) {
    acl_shared_creation_registry_entry *entry;
    bool created = false;
    fm_status st;

    clear_acl_shared_creation_token(token);
    if (!token ||
        (creator != HAL_ACL_SHARED_CREATOR_POLICER &&
         creator != HAL_ACL_SHARED_CREATOR_INDEPENDENT))
        return FM_ERR_INVALID_ARGUMENT;
    entry = acl_shared_creation_slot(sw, acl);
    if (!entry)
        return FM_ERR_NO_FREE_RESOURCES;

    st = create_default_acl_exact(sw, acl, &created);
    if (!created)
        return st;

    memset(entry, 0, sizeof(*entry));
    entry->used = true;
    entry->token.valid = true;
    entry->token.sw = sw;
    entry->token.acl = acl;
    entry->token.creator = creator;
    entry->token.generation =
        next_acl_shared_creation_generation();
    *token = entry->token;
    return st;
}

static fm_status release_shared_acl_created_empty(
    int sw, hal_acl_shared_creator creator,
    const hal_acl_shared_creation_token *token) {
    acl_shared_creation_registry_entry *entry;
    fm_status st;

    if (!token || !token->valid ||
        token->sw != sw ||
        token->acl != NETLAB_ACL_POLICER_PROBE_ACL_ID ||
        token->creator != creator)
        return FM_ERR_INVALID_ARGUMENT;
    entry = acl_shared_creation_find(sw, token->acl);
    if (!acl_shared_creation_token_matches(entry, token))
        return FM_ERR_INVALID_STATE;

    st = delete_empty_default_acl_exact(sw, token->acl);
    if (st != FM_OK)
        return st;
    memset(entry, 0, sizeof(*entry));
    return FM_OK;
}

/*
 * Restore ACL absence only with authority from the fmCreateACL() call that
 * produced the live shared object.  A sibling transaction step may have
 * captured the same absent before-image, but it must defer ACL deletion to
 * the step holding the claimed creation token.
 */
static fm_status reconcile_shared_acl_absent_before(
    int sw, int acl, hal_acl_shared_creator creator,
    const hal_acl_shared_creation_token *token) {
    acl_shared_creation_registry_entry *entry;
    bool present = false;
    fm_status detail_status = FM_OK;

    if (acl_presence_get(
            sw, acl, &present, &detail_status) != 0)
        return detail_status;
    if (!present) {
        if (token && token->valid) {
            entry = acl_shared_creation_find(sw, acl);
            if (acl_shared_creation_token_matches(entry, token))
                memset(entry, 0, sizeof(*entry));
        }
        return FM_OK;
    }
    if (token && token->valid)
        return release_shared_acl_created_empty(sw, creator, token);

    entry = acl_shared_creation_find(sw, acl);
    if (entry && entry->claimed)
        return FM_OK;
    return FM_ERR_INVALID_STATE;
}

/*
 * A shared ACL that appeared after an absent before-image can only be used by
 * another step in this in-flight transaction.  Otherwise exact rollback
 * could not prove ownership of the object whose absence it captured.
 */
static int shared_acl_apply_precondition(
    int sw, int acl, bool before_present) {
    acl_shared_creation_registry_entry *entry;
    bool present = false;
    fm_status detail_status = FM_OK;

    if (acl_presence_get(
            sw, acl, &present, &detail_status) != 0)
        return -1;
    if (before_present)
        return present ? 0 : -1;
    if (!present)
        return 0;
    entry = acl_shared_creation_find(sw, acl);
    return entry && entry->claimed ? 0 : -1;
}

static int single_portset_member_get(int sw, int port_set, int *port,
                                     bool *exact,
                                     fm_status *sdk_status) {
    fm_int first = 0;
    fm_int next = 0;
    fm_status st;

    if (!port || !exact || !sdk_status || port_set < 0)
        return -1;
    *port = 0;
    *exact = false;
    *sdk_status = FM_OK;
    st = fmGetPortSetPortFirst((fm_int)sw, (fm_int)port_set, &first);
    if (st == FM_ERR_NO_PORT_SET_PORT ||
        st == FM_ERR_INVALID_PORT_SET)
        return 0;
    if (st != FM_OK) {
        *sdk_status = st;
        return -1;
    }

    st = fmGetPortSetPortNext((fm_int)sw, (fm_int)port_set,
                              first, &next);
    *port = (int)first;
    if (st == FM_ERR_NO_PORT_SET_PORT) {
        *exact = true;
        return 0;
    }
    if (st == FM_OK)
        return 0;
    *sdk_status = st;
    return -1;
}

static int portset_contains_port(int sw, int port_set, int expected_port,
                                 bool *contains,
                                 fm_status *sdk_status) {
    fm_int current = 0;
    fm_int next = 0;
    fm_status st;

    if (!contains || !sdk_status || port_set < 0 ||
        expected_port <= 0)
        return -1;
    *contains = false;
    *sdk_status = FM_OK;
    st = fmGetPortSetPortFirst(
        (fm_int)sw, (fm_int)port_set, &current);
    if (st == FM_ERR_NO_PORT_SET_PORT ||
        st == FM_ERR_INVALID_PORT_SET)
        return 0;
    if (st != FM_OK) {
        *sdk_status = st;
        return -1;
    }
    for (int i = 0; i < NL_MAX_PORTS_PER_PROFILE; i++) {
        if ((int)current == expected_port)
            *contains = true;
        st = fmGetPortSetPortNext(
            (fm_int)sw, (fm_int)port_set, current, &next);
        if (st == FM_ERR_NO_PORT_SET_PORT)
            return 0;
        if (st != FM_OK || next == current) {
            *sdk_status =
                st != FM_OK ? st : FM_ERR_INVALID_STATE;
            return -1;
        }
        current = next;
    }
    *sdk_status = FM_ERR_INVALID_STATE;
    return -1;
}

static int single_acl_port_get(int sw, int acl, int *port,
                               fm_aclType *type, bool *exact,
                               fm_status *sdk_status) {
    fm_aclPortAndType first;
    fm_aclPortAndType next;
    fm_status st;

    if (!port || !type || !exact || !sdk_status)
        return -1;
    *port = 0;
    *type = 0;
    *exact = false;
    *sdk_status = FM_OK;
    memset(&first, 0, sizeof(first));
    st = fmGetACLPortFirst((fm_int)sw, (fm_int)acl, &first);
    if (st == FM_ERR_INVALID_ACL || st == FM_ERR_NO_MORE)
        return 0;
    if (st != FM_OK) {
        *sdk_status = st;
        return -1;
    }

    next = first;
    st = fmGetACLPortNext((fm_int)sw, (fm_int)acl, &next);
    *port = (int)first.port;
    *type = first.type;
    if (st == FM_ERR_NO_MORE) {
        *exact = true;
        return 0;
    }
    if (st == FM_OK)
        return 0;
    *sdk_status = st;
    return -1;
}

static int acl_contains_port(int sw, int acl, int expected_port,
                             fm_aclType expected_type, bool *contains,
                             fm_status *sdk_status) {
    fm_aclPortAndType current;
    fm_aclPortAndType next;
    fm_status st;

    if (!contains || !sdk_status || expected_port <= 0)
        return -1;
    *contains = false;
    *sdk_status = FM_OK;
    memset(&current, 0, sizeof(current));
    st = fmGetACLPortFirst((fm_int)sw, (fm_int)acl, &current);
    if (st == FM_ERR_INVALID_ACL || st == FM_ERR_NO_MORE)
        return 0;
    if (st != FM_OK) {
        *sdk_status = st;
        return -1;
    }
    for (int i = 0;
         i < NL_MAX_PORTS_PER_PROFILE * FM_ACL_TYPE_MAX; i++) {
        if ((int)current.port == expected_port &&
            current.type == expected_type)
            *contains = true;
        next = current;
        st = fmGetACLPortNext(
            (fm_int)sw, (fm_int)acl, &next);
        if (st == FM_ERR_NO_MORE)
            return 0;
        if (st != FM_OK ||
            (next.port == current.port &&
             next.type == current.type)) {
            *sdk_status =
                st != FM_OK ? st : FM_ERR_INVALID_STATE;
            return -1;
        }
        current = next;
    }
    *sdk_status = FM_ERR_INVALID_STATE;
    return -1;
}

static int exact_single_acl_rule_id(
    int sw, int acl, int expected_rule, fm_status *sdk_status) {
    fm_aclCondition condition = 0;
    fm_aclValue value;
    fm_aclActionExt action = 0;
    fm_aclParamExt param;
    fm_int first_rule = -1;
    fm_int next_rule = -1;
    fm_status st;

    if (!sdk_status)
        return -1;
    *sdk_status = FM_OK;
    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    st = fmGetACLRuleFirstExt(
        (fm_int)sw, (fm_int)acl, &first_rule, &condition,
        &value, &action, &param);
    if (st == FM_ERR_NO_RULES_IN_ACL)
        return 0;
    if (st != FM_OK) {
        *sdk_status = st;
        return -1;
    }
    if ((int)first_rule != expected_rule)
        return 0;

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    condition = 0;
    action = 0;
    st = fmGetACLRuleNextExt(
        (fm_int)sw, (fm_int)acl, first_rule, &next_rule,
        &condition, &value, &action, &param);
    if (st == FM_ERR_NO_RULES_IN_ACL)
        return 1;
    if (st == FM_OK)
        return 0;
    *sdk_status = st;
    return -1;
}

static acl_live_policer owner_policer_get(int sw, int policer) {
    static const fm_int attrs[] = {
        FM_POLICER_MKDN_DSCP,
        FM_POLICER_MKDN_SWPRI,
        FM_POLICER_COLOR_SOURCE,
        FM_POLICER_CIR_ACTION,
        FM_POLICER_CIR_CAPACITY,
        FM_POLICER_CIR_RATE,
        FM_POLICER_EIR_ACTION,
        FM_POLICER_EIR_CAPACITY,
        FM_POLICER_EIR_RATE,
    };
    static const fm_uint32 fixed[] = {
        FM_DISABLED,
        FM_DISABLED,
        FM_POLICER_COLOR_SRC_GREEN,
        FM_POLICER_ACTION_DROP,
        0,
        0,
        FM_POLICER_ACTION_DROP,
        0,
        0,
    };
    acl_live_policer live;

    memset(&live, 0, sizeof(live));
    live.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    live.sdk_status = FM_OK;
    live.fixed_exact = true;
    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
        fm_uint32 value = 0;
        fm_status st = fmGetPolicerAttribute(
            (fm_int)sw, (fm_int)policer, attrs[i], &value);

        if (i == 0 && st == FM_ERR_INVALID_POLICER) {
            live.state = HAL_TRANSACTION_SNAPSHOT_ABSENT;
            live.fixed_exact = false;
            return live;
        }
        if (st != FM_OK) {
            live.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
            live.sdk_status = st;
            live.fixed_exact = false;
            return live;
        }
        if (attrs[i] == FM_POLICER_CIR_CAPACITY)
            live.burst_bytes = (int)value;
        else if (attrs[i] == FM_POLICER_CIR_RATE)
            live.rate_kbps = (int)value;
        else if (value != fixed[i])
            live.fixed_exact = false;
    }
    return live;
}

/*
 * These helpers return 1 only when the complete allocator-owned object is
 * proven exact, 0 for a conclusive semantic mismatch, and -1 when an SDK read
 * failed before the state could be classified.
 */
static int exact_single_portset_member(int sw, int port_set,
                                       int expected_port,
                                       fm_status *sdk_status) {
    int port = 0;
    bool exact = false;

    if (!sdk_status)
        return -1;
    if (port_set < 0 || expected_port <= 0) {
        *sdk_status = FM_ERR_INVALID_ARGUMENT;
        return -1;
    }
    if (single_portset_member_get(
            sw, port_set, &port, &exact, sdk_status) != 0)
        return -1;
    return exact && port == expected_port ? 1 : 0;
}

static int exact_single_acl_port(int sw, int acl, int expected_port,
                                 fm_aclType expected_type,
                                 fm_status *sdk_status) {
    fm_aclType type = 0;
    int port = 0;
    bool exact = false;

    if (!sdk_status)
        return -1;
    if (single_acl_port_get(
            sw, acl, &port, &type, &exact, sdk_status) != 0)
        return -1;
    return exact && port == expected_port && type == expected_type ? 1 : 0;
}

static int exact_owner_policer(int sw, int policer, int rate_kbps,
                               int burst_bytes, int *rate_readback,
                               int *burst_readback,
                               fm_status *sdk_status) {
    acl_live_policer live;

    if (!sdk_status)
        return -1;
    live = owner_policer_get(sw, policer);
    *sdk_status = live.sdk_status;
    if (live.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return -1;
    if (live.state == HAL_TRANSACTION_SNAPSHOT_ABSENT)
        return 0;
    if (rate_readback)
        *rate_readback = live.rate_kbps;
    if (burst_readback)
        *burst_readback = live.burst_bytes;
    return live.fixed_exact &&
           live.rate_kbps == rate_kbps &&
           live.burst_bytes == burst_bytes ? 1 : 0;
}

static int first_user_logical_port(void) {
    nl_port_entry entries[NL_MAX_PORTS_PER_PROFILE];
    int n = nl_ifid_get_all(entries, NL_MAX_PORTS_PER_PROFILE);

    for (int i = 0; i < n; i++) {
        if (entries[i].logical_port > 0 &&
            nl_ifid_is_user_port(entries[i].logical_port))
            return entries[i].logical_port;
    }
    return -1;
}

static int owner_rule_for_slot(int slot) {
    return NETLAB_ACL_POLICER_OWNER_RULE - slot;
}

static int owner_policer_for_slot(int slot) {
    return NETLAB_ACL_POLICER_OWNER_POLICER + slot;
}

static int egress_owner_acl_for_slot(int slot) {
    return NETLAB_ACL_EGRESS_OWNER_ACL_ID + slot;
}

static u64 owner_dst_mac(const hal_acl_policer_owner_args *args) {
    if (!args || args->dst_mac == 0)
        return NETLAB_ACL_POLICER_PROBE_DST_MAC;
    return args->dst_mac;
}

static bool acl_policer_owner_args_valid(
    const hal_acl_policer_owner_args *args) {
    return args &&
           args->port > 0 &&
           nl_ifid_is_user_port(args->port) &&
           args->rate_kbps >=
               NETLAB_ACL_POLICER_PROBE_MIN_RATE_KBPS &&
           args->rate_kbps <=
               NETLAB_ACL_POLICER_PROBE_MAX_RATE_KBPS &&
           args->burst_bytes >=
               NETLAB_ACL_POLICER_PROBE_MIN_BURST_BYTES &&
           args->burst_bytes <=
               NETLAB_ACL_POLICER_PROBE_MAX_BURST_BYTES;
}

static bool acl_rule_absent_status(fm_status st) {
    return st == FM_ERR_INVALID_ACL_RULE ||
           st == FM_ERR_NO_RULES_IN_ACL;
}

static int acl_policer_slot_get(int sw, bool acl_present, int slot,
                                acl_policer_live_slot *live) {
    const fm_aclCondition owner_condition =
        FM_ACL_MATCH_INGRESS_PORT_SET | FM_ACL_MATCH_DST_MAC;
    const fm_aclActionExt owner_action =
        FM_ACL_ACTIONEXT_POLICE | FM_ACL_ACTIONEXT_COUNT;
    fm_aclCondition condition = 0;
    fm_aclValue value;
    fm_aclValue expected_value;
    fm_aclActionExt action = 0;
    fm_aclParamExt param;
    fm_aclParamExt expected_param;
    fm_aclEntryState rule_state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    acl_live_policer policer;
    fm_status detail_status = FM_OK;
    fm_status st = FM_ERR_INVALID_ACL_RULE;
    bool port_set_exact = false;
    bool rule_present = false;

    if (!live || slot < 0 ||
        slot >= NETLAB_ACL_POLICER_OWNER_MAX_SLOTS)
        return -1;
    memset(live, 0, sizeof(*live));
    live->state = ACL_LIVE_EMPTY;
    live->sdk_status = FM_OK;
    live->slot = slot;
    live->acl = NETLAB_ACL_POLICER_PROBE_ACL_ID;
    live->rule = owner_rule_for_slot(slot);
    live->policer = owner_policer_for_slot(slot);
    live->port_set = -1;

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    if (acl_present) {
        st = fmGetACLRule((fm_int)sw, (fm_int)live->acl,
                          (fm_int)live->rule, &condition, &value,
                          &action, &param);
        if (st == FM_OK) {
            rule_present = true;
        } else if (!acl_rule_absent_status(st)) {
            live->state = ACL_LIVE_READ_ERROR;
            live->sdk_status = st;
            return -1;
        }
    }

    policer = owner_policer_get(sw, live->policer);
    if (policer.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = policer.sdk_status;
        return -1;
    }
    if (!rule_present) {
        live->state =
            policer.state == HAL_TRANSACTION_SNAPSHOT_ABSENT ?
            ACL_LIVE_EMPTY : ACL_LIVE_OCCUPIED;
        return 0;
    }

    live->port_set = (int)value.portSet;
    live->dst_mac = value.dst;
    if (single_portset_member_get(
            sw, live->port_set, &live->port, &port_set_exact,
            &detail_status) != 0) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = detail_status;
        return -1;
    }
    live->semantic_identity_valid =
        port_set_exact &&
        value.dstMask == NETLAB_ACL_INDEPENDENT_MAC_MASK;
    live->dst_key_valid =
        value.dstMask == NETLAB_ACL_INDEPENDENT_MAC_MASK;

    st = fmGetACLRuleState((fm_int)sw, (fm_int)live->acl,
                           (fm_int)live->rule, &rule_state);
    if (st != FM_OK) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = st;
        return -1;
    }

    live->rate_kbps = policer.rate_kbps;
    live->burst_bytes = policer.burst_bytes;
    memset(&expected_value, 0, sizeof(expected_value));
    memset(&expected_param, 0, sizeof(expected_param));
    expected_value.portSet = (fm_int)live->port_set;
    expected_value.dst = live->dst_mac;
    expected_value.dstMask = NETLAB_ACL_INDEPENDENT_MAC_MASK;
    expected_param.policer = (fm_int)live->policer;
    if (rule_state == FM_ACL_RULE_ENTRY_STATE_VALID &&
        condition == owner_condition &&
        action == owner_action &&
        memcmp(&value, &expected_value, sizeof(value)) == 0 &&
        memcmp(&param, &expected_param, sizeof(param)) == 0 &&
        port_set_exact &&
        policer.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        policer.fixed_exact) {
        live->state = ACL_LIVE_OWNER;
        return 0;
    }
    live->state = ACL_LIVE_OCCUPIED;
    return 0;
}

static int acl_policer_slots_scan(
    int sw,
    acl_policer_live_slot
        slots[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS],
    bool *acl_present, fm_status *sdk_status) {
    bool present = false;
    fm_status detail_status = FM_OK;

    if (!slots || !acl_present || !sdk_status)
        return -1;
    *acl_present = false;
    *sdk_status = FM_OK;
    if (acl_presence_get(
            sw, NETLAB_ACL_POLICER_PROBE_ACL_ID,
            &present, &detail_status) != 0) {
        *sdk_status = detail_status;
        return -1;
    }
    for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
        if (acl_policer_slot_get(sw, present, i, &slots[i]) != 0) {
            *sdk_status = slots[i].sdk_status;
            return -1;
        }
    }

    memset(g_acl_policer_owner, 0, sizeof(g_acl_policer_owner));
    for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
        if (slots[i].state != ACL_LIVE_OWNER)
            continue;
        g_acl_policer_owner[i].active = true;
        g_acl_policer_owner[i].args.port = slots[i].port;
        g_acl_policer_owner[i].args.dst_mac = slots[i].dst_mac;
        g_acl_policer_owner[i].args.rate_kbps = slots[i].rate_kbps;
        g_acl_policer_owner[i].args.burst_bytes = slots[i].burst_bytes;
        g_acl_policer_owner[i].acl = slots[i].acl;
        g_acl_policer_owner[i].rule = slots[i].rule;
        g_acl_policer_owner[i].policer = slots[i].policer;
        g_acl_policer_owner[i].port_set = slots[i].port_set;
    }
    *acl_present = present;
    return 0;
}

static bool acl_policer_semantic_match(
    int sw, const acl_policer_live_slot *live,
    const hal_acl_policer_owner_args *args) {
    bool contains = false;
    fm_status detail_status = FM_OK;

    if (!live || !args || !live->dst_key_valid ||
        live->dst_mac != owner_dst_mac(args))
        return false;
    /*
     * A malformed multi-member port set still collides with every member.
     * Treat an iterator error as a collision so SET/DEL remain zero-write and
     * fail closed instead of allocating a duplicate owner slot.
     */
    if (portset_contains_port(
            sw, live->port_set, args->port,
            &contains, &detail_status) != 0)
        return true;
    return contains;
}

static bool acl_policer_exact_match(
    int sw, const acl_policer_live_slot *live,
    const hal_acl_policer_owner_args *args) {
    return acl_policer_semantic_match(sw, live, args) &&
           live->state == ACL_LIVE_OWNER &&
           live->rate_kbps == args->rate_kbps &&
           live->burst_bytes == args->burst_bytes;
}

static bool egress_owner_mac_valid(u64 mac) {
    return mac != 0 && (mac & 0x010000000000ULL) == 0;
}

static bool acl_egress_owner_args_valid(
    const hal_acl_egress_owner_args *args) {
    return args &&
           args->port > 0 &&
           nl_ifid_is_user_port(args->port) &&
           (args->src_mac != 0 || args->dst_mac != 0) &&
           (args->src_mac == 0 ||
            egress_owner_mac_valid(args->src_mac)) &&
           (args->dst_mac == 0 ||
            egress_owner_mac_valid(args->dst_mac));
}

static fm_aclCondition fill_egress_mac_value(fm_aclValue *value,
                                             u64 src_mac, u64 dst_mac) {
    fm_aclCondition cond = 0;

    if (!value)
        return 0;
    if (src_mac != 0) {
        value->src = src_mac;
        value->srcMask = 0xffffffffffffULL;
        cond |= FM_ACL_MATCH_SRC_MAC;
    }
    if (dst_mac != 0) {
        value->dst = dst_mac;
        value->dstMask = 0xffffffffffffULL;
        cond |= FM_ACL_MATCH_DST_MAC;
    }
    return cond;
}

static int acl_egress_slot_get(int sw, int slot,
                               acl_egress_live_slot *live) {
    fm_aclCondition condition = 0;
    fm_aclCondition expected_condition = 0;
    fm_aclValue value;
    fm_aclValue expected_value;
    fm_aclActionExt action = 0;
    fm_aclParamExt param;
    fm_aclParamExt expected_param;
    fm_aclEntryState rule_state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    fm_aclType acl_type = 0;
    fm_status detail_status = FM_OK;
    fm_status st;
    bool acl_present = false;
    bool acl_port_exact = false;
    int acl_rule_exact = 0;

    if (!live || slot < 0 ||
        slot >= NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS)
        return -1;
    memset(live, 0, sizeof(*live));
    live->state = ACL_LIVE_EMPTY;
    live->sdk_status = FM_OK;
    live->slot = slot;
    live->acl = egress_owner_acl_for_slot(slot);
    live->rule = NETLAB_ACL_EGRESS_OWNER_RULE;

    if (acl_presence_get(
            sw, live->acl, &acl_present, &detail_status) != 0) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = detail_status;
        return -1;
    }
    if (!acl_present)
        return 0;

    live->state = ACL_LIVE_OCCUPIED;
    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    st = fmGetACLRule((fm_int)sw, (fm_int)live->acl,
                      (fm_int)live->rule, &condition, &value,
                      &action, &param);
    if (acl_rule_absent_status(st))
        return 0;
    if (st != FM_OK) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = st;
        return -1;
    }

    st = fmGetACLRuleState((fm_int)sw, (fm_int)live->acl,
                           (fm_int)live->rule, &rule_state);
    if (st != FM_OK) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = st;
        return -1;
    }

    if (single_acl_port_get(
            sw, live->acl, &live->port, &acl_type,
            &acl_port_exact, &detail_status) != 0) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = detail_status;
        return -1;
    }
    acl_rule_exact = exact_single_acl_rule_id(
        sw, live->acl, live->rule, &detail_status);
    if (acl_rule_exact < 0) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = detail_status;
        return -1;
    }
    if (condition & FM_ACL_MATCH_SRC_MAC)
        live->src_mac = value.src;
    if (condition & FM_ACL_MATCH_DST_MAC)
        live->dst_mac = value.dst;
    memset(&expected_value, 0, sizeof(expected_value));
    memset(&expected_param, 0, sizeof(expected_param));
    expected_condition = fill_egress_mac_value(
        &expected_value, live->src_mac, live->dst_mac);
    live->rule_key_valid =
        expected_condition != 0 &&
        condition == expected_condition &&
        (!(condition & FM_ACL_MATCH_SRC_MAC) ||
         value.srcMask == NETLAB_ACL_INDEPENDENT_MAC_MASK) &&
        (!(condition & FM_ACL_MATCH_DST_MAC) ||
         value.dstMask == NETLAB_ACL_INDEPENDENT_MAC_MASK);
    live->semantic_identity_valid =
        live->rule_key_valid &&
        acl_port_exact && acl_type == FM_ACL_TYPE_EGRESS;
    if (rule_state == FM_ACL_RULE_ENTRY_STATE_VALID &&
        live->semantic_identity_valid &&
        acl_rule_exact == 1 &&
        action == FM_ACL_ACTIONEXT_DENY &&
        memcmp(&value, &expected_value, sizeof(value)) == 0 &&
        memcmp(&param, &expected_param, sizeof(param)) == 0) {
        live->state = ACL_LIVE_OWNER;
    }
    return 0;
}

static int acl_egress_slots_scan(
    int sw,
    acl_egress_live_slot
        slots[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS],
    fm_status *sdk_status) {
    if (!slots || !sdk_status)
        return -1;
    *sdk_status = FM_OK;
    for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
        if (acl_egress_slot_get(sw, i, &slots[i]) != 0) {
            *sdk_status = slots[i].sdk_status;
            return -1;
        }
    }

    memset(g_acl_egress_owner, 0, sizeof(g_acl_egress_owner));
    for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
        if (slots[i].state != ACL_LIVE_OWNER)
            continue;
        g_acl_egress_owner[i].active = true;
        g_acl_egress_owner[i].args.port = slots[i].port;
        g_acl_egress_owner[i].args.src_mac = slots[i].src_mac;
        g_acl_egress_owner[i].args.dst_mac = slots[i].dst_mac;
        g_acl_egress_owner[i].acl = slots[i].acl;
        g_acl_egress_owner[i].rule = slots[i].rule;
    }
    return 0;
}

static bool acl_egress_port_collision(
    int sw, const acl_egress_live_slot *live, int port) {
    bool contains = false;
    fm_status detail_status = FM_OK;

    if (!live || live->acl <= 0 || port <= 0)
        return false;
    if (acl_contains_port(
            sw, live->acl, port, FM_ACL_TYPE_EGRESS,
            &contains, &detail_status) != 0)
        return true;
    return contains;
}

static bool acl_egress_semantic_match(
    int sw, const acl_egress_live_slot *live,
    const hal_acl_egress_owner_args *args) {
    return live && args && live->rule_key_valid &&
           acl_egress_port_collision(sw, live, args->port) &&
           live->src_mac == args->src_mac &&
           live->dst_mac == args->dst_mac;
}

static bool acl_egress_exact_match(
    int sw, const acl_egress_live_slot *live,
    const hal_acl_egress_owner_args *args) {
    return acl_egress_semantic_match(sw, live, args) &&
           live->state == ACL_LIVE_OWNER;
}

static void fill_owner_live_identity(
    hal_acl_policer_owner_result *result,
    const acl_policer_live_slot *live) {
    if (!result || !live)
        return;
    result->active = live->state == ACL_LIVE_OWNER;
    result->slot = live->slot;
    result->acl = live->acl;
    result->rule = live->rule;
    result->policer = live->policer;
    result->port_set = live->port_set;
    result->port = live->port;
    result->dst_mac = live->dst_mac;
    result->rate_kbps = live->rate_kbps;
    result->burst_bytes = live->burst_bytes;
}

static void fill_egress_owner_live_identity(
    hal_acl_egress_owner_result *result,
    const acl_egress_live_slot *live) {
    if (!result || !live)
        return;
    result->active = live->state == ACL_LIVE_OWNER;
    result->slot = live->slot;
    result->acl = live->acl;
    result->rule = live->rule;
    result->port = live->port;
    result->src_mac = live->src_mac;
    result->dst_mac = live->dst_mac;
}

static int read_owner_live_state(int sw,
                                 hal_acl_policer_owner_result *result) {
    const fm_aclCondition expected_cond =
        FM_ACL_MATCH_INGRESS_PORT_SET | FM_ACL_MATCH_DST_MAC;
    const fm_aclActionExt expected_action =
        FM_ACL_ACTIONEXT_POLICE | FM_ACL_ACTIONEXT_COUNT;
    fm_aclCondition cond = 0;
    fm_aclValue value;
    fm_aclValue expected_value;
    fm_aclActionExt action = 0;
    fm_aclParamExt param;
    fm_aclParamExt expected_param;
    fm_aclCounters counters;
    fm_aclEntryState rule_state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    fm_status detail_status = FM_OK;
    fm_status st;
    bool acl_present = false;
    int exact;

    if (!result)
        return -1;

    result->compared = 0;
    result->mismatches = 0;

    if (acl_presence_get(
            sw, result->acl, &acl_present, &detail_status) != 0 ||
        !acl_present) {
        result->read_status = detail_status != FM_OK ?
            (int)detail_status : FM_ERR_INVALID_ACL;
        result->mismatches++;
    }
    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    memset(&expected_value, 0, sizeof(expected_value));
    memset(&expected_param, 0, sizeof(expected_param));
    expected_value.portSet = (fm_int)result->port_set;
    expected_value.dst = result->dst_mac;
    expected_value.dstMask = NETLAB_ACL_INDEPENDENT_MAC_MASK;
    expected_param.policer = (fm_int)result->policer;
    st = fmGetACLRule((fm_int)sw, (fm_int)result->acl,
                      (fm_int)result->rule, &cond, &value,
                      &action, &param);
    result->read_status = (int)st;
    result->compared++;
    if (st == FM_OK) {
        if (cond != expected_cond ||
            action != expected_action ||
            memcmp(&value, &expected_value, sizeof(value)) != 0 ||
            memcmp(&param, &expected_param, sizeof(param)) != 0)
            result->mismatches++;
    } else {
        result->mismatches++;
    }
    st = fmGetACLRuleState(
        (fm_int)sw, (fm_int)result->acl, (fm_int)result->rule,
        &rule_state);
    if (result->read_status == FM_OK)
        result->read_status = (int)st;
    result->compared++;
    if (st != FM_OK ||
        rule_state != FM_ACL_RULE_ENTRY_STATE_VALID)
        result->mismatches++;

    exact = exact_single_portset_member(
        sw, result->port_set, result->port, &detail_status);
    result->compared++;
    if (exact != 1) {
        if (exact < 0 && result->read_status == FM_OK)
            result->read_status = (int)detail_status;
        result->mismatches++;
    }

    detail_status = FM_OK;
    exact = exact_owner_policer(
        sw, result->policer, result->rate_kbps,
        result->burst_bytes, &result->rate_readback,
        &result->burst_readback, &detail_status);
    result->policer_read_status = exact < 0 ?
        (int)detail_status : FM_OK;
    result->compared++;
    if (exact != 1)
        result->mismatches++;

    memset(&counters, 0, sizeof(counters));
    st = fmGetACLCountExt((fm_int)sw, (fm_int)result->acl,
                          (fm_int)result->rule, &counters);
    if (result->read_status == FM_OK)
        result->read_status = (int)st;
    if (st == FM_OK) {
        result->packets = counters.cntPkts;
        result->octets = counters.cntOctets;
        result->compared++;
    } else {
        result->mismatches++;
    }

    if (result->mismatches == 0) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "ACL policer owner live read-back verified");
        return 0;
    }

    snprintf(result->detail, sizeof(result->detail),
             "ACL policer owner live read-back mismatch");
    return -1;
}

static int read_egress_owner_live_state(
    int sw, hal_acl_egress_owner_result *result) {
    fm_aclCondition cond = 0;
    fm_aclCondition expected_cond = 0;
    fm_aclValue value;
    fm_aclValue expected_value;
    fm_aclActionExt action = 0;
    fm_aclParamExt param;
    fm_aclParamExt expected_param;
    fm_aclCounters counters;
    fm_aclEntryState rule_state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    fm_status detail_status = FM_OK;
    fm_status st;
    bool acl_present = false;
    int exact;

    if (!result)
        return -1;

    result->compared = 0;
    result->mismatches = 0;

    if (acl_presence_get(
            sw, result->acl, &acl_present, &detail_status) != 0 ||
        !acl_present) {
        result->read_status = detail_status != FM_OK ?
            (int)detail_status : FM_ERR_INVALID_ACL;
        result->mismatches++;
    }
    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    memset(&expected_value, 0, sizeof(expected_value));
    memset(&expected_param, 0, sizeof(expected_param));
    expected_cond = fill_egress_mac_value(
        &expected_value, result->src_mac, result->dst_mac);
    st = fmGetACLRule((fm_int)sw, (fm_int)result->acl,
                      (fm_int)result->rule, &cond, &value,
                      &action, &param);
    result->read_status = (int)st;
    if (st == FM_OK) {
        result->compared++;
        if (expected_cond == 0 || cond != expected_cond ||
            action != FM_ACL_ACTIONEXT_DENY ||
            memcmp(&value, &expected_value, sizeof(value)) != 0 ||
            memcmp(&param, &expected_param, sizeof(param)) != 0)
            result->mismatches++;
    } else {
        result->mismatches++;
    }
    st = fmGetACLRuleState(
        (fm_int)sw, (fm_int)result->acl, (fm_int)result->rule,
        &rule_state);
    if (result->read_status == FM_OK)
        result->read_status = (int)st;
    result->compared++;
    if (st != FM_OK ||
        rule_state != FM_ACL_RULE_ENTRY_STATE_VALID)
        result->mismatches++;

    exact = exact_single_acl_port(
        sw, result->acl, result->port, FM_ACL_TYPE_EGRESS,
        &detail_status);
    result->compared++;
    if (exact != 1) {
        if (exact < 0 && result->read_status == FM_OK)
            result->read_status = (int)detail_status;
        result->mismatches++;
    }

    memset(&counters, 0, sizeof(counters));
    st = fmGetACLEgressCount((fm_int)sw, (fm_int)result->port, &counters);
    if (result->read_status == FM_OK)
        result->read_status = (int)st;
    if (st == FM_OK) {
        result->packets = counters.cntPkts;
        result->octets = counters.cntOctets;
        result->compared++;
    } else {
        result->mismatches++;
    }

    if (result->mismatches == 0) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL owner live read-back verified");
        return 0;
    }

    snprintf(result->detail, sizeof(result->detail),
             "egress ACL owner live read-back mismatch");
    return -1;
}

static void record_cleanup_status(hal_acl_policer_probe_result *result,
                                  fm_status st) {
    if (!result || result->cleanup_status != 0 || status_missing_ok(st))
        return;
    result->cleanup_status = (int)st;
}

static void record_owner_cleanup_status(hal_acl_policer_owner_result *result,
                                        fm_status st) {
    if (!result || result->cleanup_status != 0 || status_missing_ok(st))
        return;
    result->cleanup_status = (int)st;
}

static void record_egress_cleanup_status(hal_acl_egress_probe_result *result,
                                         fm_status st) {
    if (!result || result->cleanup_status != 0 || egress_acl_missing_ok(st))
        return;
    result->cleanup_status = (int)st;
}

static void record_egress_owner_cleanup_status(
    hal_acl_egress_owner_result *result, fm_status st) {
    if (!result || result->cleanup_status != 0 || egress_acl_missing_ok(st))
        return;
    result->cleanup_status = (int)st;
}

static void record_general_cleanup_status(
    hal_acl_general_allocator_result *result, fm_status st) {
    if (!result || result->compiler_cleanup_status != 0 ||
        status_missing_ok(st) || st == FM_ERR_INVALID_PORT_SET)
        return;
    result->compiler_cleanup_status = (int)st;
}

static size_t append_acl_detail(char *detail, size_t detail_size,
                                size_t offset, const char *text,
                                size_t text_length) {
    size_t available;

    if (!detail || detail_size == 0 || offset >= detail_size)
        return offset;
    available = detail_size - offset - 1U;
    if (text_length > available)
        text_length = available;
    if (text_length > 0)
        memcpy(detail + offset, text, text_length);
    offset += text_length;
    detail[offset] = '\0';
    return offset;
}

static void format_acl_compile_failure(char *detail, size_t detail_size,
                                       const char *sdk_error,
                                       const char *compile_text,
                                       size_t compile_text_size) {
    static const char prefix[] = "compile failed: ";
    static const char opening[] = " (";
    static const char closing[] = ")";
    static const char unknown_error[] = "unknown SDK error";
    const size_t marker_length = sizeof(NETLAB_ACL_TRUNCATION_MARKER) - 1U;
    const size_t prefix_length = sizeof(prefix) - 1U;
    const size_t opening_length = sizeof(opening) - 1U;
    const size_t closing_length = sizeof(closing) - 1U;
    size_t sdk_error_length;
    size_t compile_text_length;
    size_t capacity;
    size_t offset = 0;
    size_t remaining;
    bool truncated;

    if (!detail || detail_size == 0)
        return;
    detail[0] = '\0';
    if (!sdk_error)
        sdk_error = unknown_error;
    if (!compile_text) {
        compile_text = "";
        compile_text_size = 0;
    }
    sdk_error_length = strnlen(sdk_error, NETLAB_ACL_SDK_ERROR_TEXT_MAX);
    compile_text_length = strnlen(compile_text, compile_text_size);
    truncated = sdk_error_length == NETLAB_ACL_SDK_ERROR_TEXT_MAX ||
                (compile_text_size > 0 &&
                 compile_text_length == compile_text_size);
    capacity = detail_size - 1U;

    if (!truncated && prefix_length <= capacity &&
        sdk_error_length <= capacity - prefix_length &&
        opening_length <= capacity - prefix_length - sdk_error_length &&
        compile_text_length <= capacity - prefix_length - sdk_error_length -
                               opening_length &&
        closing_length <= capacity - prefix_length - sdk_error_length -
                          opening_length - compile_text_length) {
        offset = append_acl_detail(detail, detail_size, offset,
                                   prefix, prefix_length);
        offset = append_acl_detail(detail, detail_size, offset,
                                   sdk_error, sdk_error_length);
        offset = append_acl_detail(detail, detail_size, offset,
                                   opening, opening_length);
        offset = append_acl_detail(detail, detail_size, offset,
                                   compile_text, compile_text_length);
        (void)append_acl_detail(detail, detail_size, offset,
                                closing, closing_length);
        return;
    }

    offset = append_acl_detail(detail, detail_size, offset,
                               prefix, prefix_length);
    remaining = capacity - offset;
    if (remaining > opening_length + marker_length + closing_length) {
        size_t sdk_error_budget = remaining - opening_length -
                                  marker_length - closing_length;

        if (sdk_error_length > sdk_error_budget)
            sdk_error_length = sdk_error_budget;
    } else {
        sdk_error_length = 0;
    }
    offset = append_acl_detail(detail, detail_size, offset,
                               sdk_error, sdk_error_length);
    offset = append_acl_detail(detail, detail_size, offset,
                               opening, opening_length);
    remaining = capacity - offset;
    if (remaining > marker_length + closing_length) {
        size_t compile_budget = remaining - marker_length - closing_length;

        if (compile_text_length > compile_budget)
            compile_text_length = compile_budget;
        offset = append_acl_detail(detail, detail_size, offset,
                                   compile_text, compile_text_length);
    }
    offset = append_acl_detail(detail, detail_size, offset,
                               NETLAB_ACL_TRUNCATION_MARKER,
                               marker_length);
    (void)append_acl_detail(detail, detail_size, offset,
                            closing, closing_length);
}

static fm_status compile_and_apply_acl(int sw, char *detail,
                                       size_t detail_size) {
    char compile_text[1024];
    fm_status st;

    memset(compile_text, 0, sizeof(compile_text));
    st = fmCompileACL((fm_int)sw, compile_text, sizeof(compile_text),
                      FM_ACL_COMPILE_FLAG_NON_DISRUPTIVE);
    if (st != FM_OK) {
        format_acl_compile_failure(detail, detail_size, fmErrorMsg(st),
                                   compile_text, sizeof(compile_text));
        return st;
    }

    st = fmApplyACL((fm_int)sw, FM_ACL_APPLY_FLAG_NON_DISRUPTIVE);
    if (st != FM_OK && detail && detail_size > 0) {
        snprintf(detail, detail_size, "apply failed: %s",
                 fmErrorMsg(st));
    }
    return st;
}

static fm_status create_or_update_probe_policer(int sw, int policer,
                                                int rate_kbps,
                                                int burst_bytes) {
    fm_policerConfig cfg;
    fm_uint32 value = 0;
    fm_status st;
    bool exists = false;

    memset(&cfg, 0, sizeof(cfg));
    cfg.mkdnDscp = FM_DISABLED;
    cfg.mkdnSwPri = FM_DISABLED;
    cfg.colorSource = FM_POLICER_COLOR_SRC_GREEN;
    cfg.cirAction = FM_POLICER_ACTION_DROP;
    cfg.cirCapacity = (fm_uint32)burst_bytes;
    cfg.cirRate = (fm_uint32)rate_kbps;
    cfg.eirAction = FM_POLICER_ACTION_DROP;
    cfg.eirCapacity = 0;
    cfg.eirRate = 0;

    st = fmGetPolicerAttribute((fm_int)sw, (fm_int)policer,
                               FM_POLICER_CIR_RATE, &value);
    if (st == FM_OK) {
        exists = true;
    } else if (st != FM_ERR_INVALID_POLICER) {
        return st;
    }

    if (!exists) {
        st = fmCreatePolicer((fm_int)sw, FM_POLICER_BANK_AUTOMATIC,
                             (fm_int)policer, &cfg);
        if (st == FM_OK)
            return FM_OK;
        if (st != FM_ERR_ALREADY_EXISTS)
            return st;
    }

    st = fmSetPolicerAttribute((fm_int)sw, (fm_int)policer,
                               FM_POLICER_COLOR_SOURCE, &cfg.colorSource);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)policer,
                                   FM_POLICER_CIR_ACTION, &cfg.cirAction);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)policer,
                                   FM_POLICER_CIR_CAPACITY,
                                   &cfg.cirCapacity);
    if (st == FM_OK)
        st = fmSetPolicerAttribute((fm_int)sw, (fm_int)policer,
                                   FM_POLICER_CIR_RATE, &cfg.cirRate);
    if (st == FM_OK)
        st = fmUpdatePolicer((fm_int)sw, (fm_int)policer);
    return st;
}

static fm_status create_owner_policer(int sw, int policer,
                                      int rate_kbps,
                                      int burst_bytes) {
    fm_policerConfig cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.mkdnDscp = FM_DISABLED;
    cfg.mkdnSwPri = FM_DISABLED;
    cfg.colorSource = FM_POLICER_COLOR_SRC_GREEN;
    cfg.cirAction = FM_POLICER_ACTION_DROP;
    cfg.cirCapacity = (fm_uint32)burst_bytes;
    cfg.cirRate = (fm_uint32)rate_kbps;
    cfg.eirAction = FM_POLICER_ACTION_DROP;
    return fmCreatePolicer((fm_int)sw, FM_POLICER_BANK_AUTOMATIC,
                           (fm_int)policer, &cfg);
}

static void fill_general_ipv4_addr(fm_ipAddr *addr, u32 host_order) {
    if (!addr)
        return;
    memset(addr, 0, sizeof(*addr));
    addr->addr[0] = htonl(host_order);
    addr->isIPv6 = FALSE;
}

static bool same_general_ip_addr(const fm_ipAddr *a, const fm_ipAddr *b) {
    return a && b &&
           a->isIPv6 == b->isIPv6 &&
           a->addr[0] == b->addr[0] &&
           a->addr[1] == b->addr[1] &&
           a->addr[2] == b->addr[2] &&
           a->addr[3] == b->addr[3];
}

static fm_aclCondition fill_general_acl_compiler_term(
    acl_general_profile profile, bool policer_term, fm_int port_set,
    int policer, fm_aclValue *value, fm_aclActionExt *action,
    fm_aclParamExt *param) {
    fm_aclCondition cond;

    if (!value || !action || !param)
        return 0;
    memset(value, 0, sizeof(*value));
    memset(param, 0, sizeof(*param));
    value->portSet = port_set;
    *action = policer_term ?
        (FM_ACL_ACTIONEXT_POLICE | FM_ACL_ACTIONEXT_COUNT) :
        (FM_ACL_ACTIONEXT_PERMIT | FM_ACL_ACTIONEXT_COUNT);
    if (policer_term)
        param->policer = policer;

    cond = FM_ACL_MATCH_INGRESS_PORT_SET;
    switch (profile) {
    case ACL_GENERAL_PROFILE_ETHERNET_COUNT:
        value->dst = NETLAB_ACL_GENERAL_COMPILER_ETH_DST_MAC;
        value->dstMask = 0xffffffffffffULL;
        value->ethType = 0x0800;
        value->ethTypeMask = 0xffff;
        cond |= FM_ACL_MATCH_DST_MAC | FM_ACL_MATCH_ETHERTYPE;
        break;
    case ACL_GENERAL_PROFILE_INET_COUNT:
    case ACL_GENERAL_PROFILE_INET_COUNT_AND_POLICER:
        value->ethType = 0x0800;
        value->ethTypeMask = 0xffff;
        fill_general_ipv4_addr(
            &value->srcIp,
            policer_term ?
            NETLAB_ACL_GENERAL_COMPILER_INET_POLICER_SRC_IP :
            NETLAB_ACL_GENERAL_COMPILER_INET_SRC_IP);
        fill_general_ipv4_addr(&value->srcIpMask, 0xffffffffU);
        fill_general_ipv4_addr(
            &value->dstIp,
            policer_term ?
            NETLAB_ACL_GENERAL_COMPILER_INET_POLICER_DST_IP :
            NETLAB_ACL_GENERAL_COMPILER_INET_DST_IP);
        fill_general_ipv4_addr(&value->dstIpMask, 0xffffffffU);
        value->protocol = 17;
        value->protocolMask = 0xff;
        value->L4DstStart = policer_term ?
            NETLAB_ACL_GENERAL_COMPILER_INET_POLICER_L4_DST :
            NETLAB_ACL_GENERAL_COMPILER_INET_L4_DST;
        value->L4DstMask = 0xffff;
        cond |= FM_ACL_MATCH_ETHERTYPE |
                FM_ACL_MATCH_SRC_IP |
                FM_ACL_MATCH_DST_IP |
                FM_ACL_MATCH_PROTOCOL |
                FM_ACL_MATCH_L4_DST_PORT_WITH_MASK;
        break;
    case ACL_GENERAL_PROFILE_INGRESS_COUNT_AND_POLICER:
    default:
        value->dst = policer_term ?
            NETLAB_ACL_GENERAL_COMPILER_POLICER_DST_MAC :
            NETLAB_ACL_GENERAL_COMPILER_DST_MAC;
        value->dstMask = 0xffffffffffffULL;
        cond |= FM_ACL_MATCH_DST_MAC;
        break;
    }
    return cond;
}

static bool general_acl_term_matches(
    acl_general_profile profile, bool policer_term, int port_set,
    int policer, fm_aclCondition cond, const fm_aclValue *value,
    fm_aclActionExt action, const fm_aclParamExt *param) {
    fm_aclValue expected_value;
    fm_aclParamExt expected_param;
    fm_aclActionExt expected_action = 0;
    fm_aclCondition expected_cond;

    memset(&expected_value, 0, sizeof(expected_value));
    memset(&expected_param, 0, sizeof(expected_param));
    expected_cond = fill_general_acl_compiler_term(
        profile, policer_term, (fm_int)port_set, policer,
        &expected_value, &expected_action, &expected_param);
    if (cond != expected_cond ||
        action != expected_action ||
        !value || !param || value->portSet != expected_value.portSet)
        return false;

    if ((expected_cond & FM_ACL_MATCH_DST_MAC) &&
        (value->dst != expected_value.dst ||
         value->dstMask != expected_value.dstMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_ETHERTYPE) &&
        (value->ethType != expected_value.ethType ||
         value->ethTypeMask != expected_value.ethTypeMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_SRC_IP) &&
        (!same_general_ip_addr(&value->srcIp, &expected_value.srcIp) ||
         !same_general_ip_addr(&value->srcIpMask,
                               &expected_value.srcIpMask)))
        return false;
    if ((expected_cond & FM_ACL_MATCH_DST_IP) &&
        (!same_general_ip_addr(&value->dstIp, &expected_value.dstIp) ||
         !same_general_ip_addr(&value->dstIpMask,
                               &expected_value.dstIpMask)))
        return false;
    if ((expected_cond & FM_ACL_MATCH_PROTOCOL) &&
        (value->protocol != expected_value.protocol ||
         value->protocolMask != expected_value.protocolMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_L4_DST_PORT_WITH_MASK) &&
        (value->L4DstStart != expected_value.L4DstStart ||
         value->L4DstMask != expected_value.L4DstMask))
        return false;
    if (policer_term && param->policer != policer)
        return false;
    return true;
}

static bool independent_is_egress(const hal_acl_independent_args *args) {
    return args && strcmp(args->family, "egress") == 0;
}

static bool independent_wants_policer(
    const hal_acl_independent_args *args) {
    return args &&
           (strcmp(args->family, "policer") == 0 ||
            strcmp(args->action, "policer") == 0);
}

static bool independent_slot_valid(int slot) {
    return slot >= 0 && slot < NETLAB_ACL_INDEPENDENT_OWNER_MAX_SLOTS;
}

static int independent_rule_for_slot(int slot) {
    return NETLAB_ACL_INDEPENDENT_RULE_BASE + slot;
}

static int independent_acl_default(void) {
    return NETLAB_ACL_INDEPENDENT_SHARED_ACL_ID;
}

static bool independent_has_inet_selector(
    const hal_ingress_ipv4_acl_match *m) {
    return m &&
           (m->has_src_ip || m->has_dst_ip || m->has_dscp ||
            m->has_protocol || m->has_src_port || m->has_dst_port ||
            m->has_src_port_range || m->has_dst_port_range ||
            m->has_tcp_flags);
}

static void fill_independent_identity(
    hal_acl_independent_result *result,
    const hal_acl_independent_args *args, int acl, int policer) {
    if (!result || !args)
        return;
    result->slot = args->slot;
    result->port = args->port;
    result->acl = acl;
    result->rule = independent_rule_for_slot(args->slot);
    result->policer = independent_wants_policer(args) ? policer : 0;
    result->port_set = -1;
    result->vid = args->vid;
    result->src_mac = args->src_mac;
    result->dst_mac = args->dst_mac;
    result->rate_kbps = args->rate_kbps;
    result->burst_bytes = args->burst_bytes;
}

static bool independent_args_valid(const hal_acl_independent_args *args) {
    const hal_ingress_ipv4_acl_match *m;
    bool has_mac;
    bool has_inet;

    if (!args || !independent_slot_valid(args->slot) ||
        args->vid < 1 || args->vid > 4094 ||
        args->port <= 0 || !nl_ifid_is_user_port(args->port) ||
        independent_is_egress(args))
        return false;
    m = &args->inet_match;
    has_mac = args->has_src_mac || args->has_dst_mac;
    has_inet = independent_has_inet_selector(m);
    if (strcmp(args->family, "ethernet") == 0) {
        if (!has_mac || has_inet)
            return false;
    } else if (strcmp(args->family, "inet") == 0) {
        if (has_mac || !has_inet)
            return false;
    } else if (strcmp(args->family, "policer") == 0) {
        if (has_mac == has_inet)
            return false;
    } else {
        return false;
    }
    if (strcmp(args->action, "drop") != 0 &&
        strcmp(args->action, "count") != 0 &&
        strcmp(args->action, "policer") != 0)
        return false;
    if (m->has_ecn || m->has_tcp_flags_mask != m->has_tcp_flags)
        return false;
    if (m->has_src_port_range &&
        (m->src_port_start != m->src_port_end ||
         m->src_port_start < 0 || m->src_port_end > 65535))
        return false;
    if (m->has_dst_port_range &&
        (m->dst_port_start != m->dst_port_end ||
         m->dst_port_start < 0 || m->dst_port_end > 65535))
        return false;
    if (independent_wants_policer(args) &&
        (args->rate_kbps < NETLAB_ACL_POLICER_PROBE_MIN_RATE_KBPS ||
         args->rate_kbps > NETLAB_ACL_POLICER_PROBE_MAX_RATE_KBPS ||
         args->burst_bytes < NETLAB_ACL_POLICER_PROBE_MIN_BURST_BYTES ||
         args->burst_bytes > NETLAB_ACL_POLICER_PROBE_MAX_BURST_BYTES))
        return false;
    return true;
}

static fm_aclCondition fill_independent_acl_term(
    const hal_acl_independent_args *args, fm_int port_set, int policer,
    fm_aclValue *value, fm_aclActionExt *action, fm_aclParamExt *param) {
    const hal_ingress_ipv4_acl_match *m;
    fm_aclCondition cond;

    if (!args || !value || !action || !param)
        return 0;
    m = &args->inet_match;
    memset(value, 0, sizeof(*value));
    memset(param, 0, sizeof(*param));
    cond = FM_ACL_MATCH_INGRESS_PORT_SET | FM_ACL_MATCH_VLAN;
    value->portSet = port_set;
    value->vlanId = (fm_uint16)args->vid;
    value->vlanIdMask = NETLAB_ACL_INDEPENDENT_VLAN_MASK;

    if (args->has_src_mac) {
        cond |= FM_ACL_MATCH_SRC_MAC;
        value->src = args->src_mac;
        value->srcMask = NETLAB_ACL_INDEPENDENT_MAC_MASK;
    }
    if (args->has_dst_mac) {
        cond |= FM_ACL_MATCH_DST_MAC;
        value->dst = args->dst_mac;
        value->dstMask = NETLAB_ACL_INDEPENDENT_MAC_MASK;
    }
    if (independent_has_inet_selector(m)) {
        cond |= FM_ACL_MATCH_ETHERTYPE;
        value->ethType = NETLAB_ACL_INDEPENDENT_ETHERTYPE_IPV4;
        value->ethTypeMask = NETLAB_ACL_INDEPENDENT_ETHERTYPE_MASK;
    }
    if (m->has_src_ip) {
        cond |= FM_ACL_MATCH_SRC_IP;
        fill_general_ipv4_addr(&value->srcIp, m->src_ip);
        fill_general_ipv4_addr(
            &value->srcIpMask,
            m->has_src_ip_mask ? m->src_ip_mask :
            NETLAB_ACL_INDEPENDENT_IP_MASK);
    }
    if (m->has_dst_ip) {
        cond |= FM_ACL_MATCH_DST_IP;
        fill_general_ipv4_addr(&value->dstIp, m->dst_ip);
        fill_general_ipv4_addr(
            &value->dstIpMask,
            m->has_dst_ip_mask ? m->dst_ip_mask :
            NETLAB_ACL_INDEPENDENT_IP_MASK);
    }
    if (m->has_dscp) {
        cond |= FM_ACL_MATCH_DSCP;
        value->dscp = (fm_byte)m->dscp;
        value->dscpMask = NETLAB_ACL_INDEPENDENT_DSCP_MASK;
    }
    if (m->has_protocol) {
        cond |= FM_ACL_MATCH_PROTOCOL;
        value->protocol = (fm_byte)m->protocol;
        value->protocolMask = NETLAB_ACL_INDEPENDENT_PROTOCOL_MASK;
    }
    if (m->has_src_port || m->has_src_port_range) {
        cond |= FM_ACL_MATCH_L4_SRC_PORT_WITH_MASK;
        value->L4SrcStart = (fm_uint16)(m->has_src_port ?
                                        m->src_port :
                                        m->src_port_start);
        value->L4SrcMask = NETLAB_ACL_INDEPENDENT_L4_MASK;
    }
    if (m->has_dst_port || m->has_dst_port_range) {
        cond |= FM_ACL_MATCH_L4_DST_PORT_WITH_MASK;
        value->L4DstStart = (fm_uint16)(m->has_dst_port ?
                                        m->dst_port :
                                        m->dst_port_start);
        value->L4DstMask = NETLAB_ACL_INDEPENDENT_L4_MASK;
    }
    if (m->has_tcp_flags) {
        cond |= FM_ACL_MATCH_TCP_FLAGS;
        value->tcpFlags =
            (fm_byte)(m->tcp_flags & NETLAB_ACL_INDEPENDENT_TCP_FLAGS_MASK);
        value->tcpFlagsMask =
            (fm_byte)(m->has_tcp_flags_mask ?
                      m->tcp_flags_mask :
                      NETLAB_ACL_INDEPENDENT_TCP_FLAGS_MASK);
    }

    if (independent_wants_policer(args)) {
        *action = FM_ACL_ACTIONEXT_POLICE | FM_ACL_ACTIONEXT_COUNT;
        param->policer = policer;
    } else if (strcmp(args->action, "count") == 0) {
        *action = FM_ACL_ACTIONEXT_PERMIT | FM_ACL_ACTIONEXT_COUNT;
    } else {
        *action = FM_ACL_ACTIONEXT_DENY | FM_ACL_ACTIONEXT_COUNT;
    }
    return cond;
}

static bool independent_term_matches(
    const hal_acl_independent_args *args, int port_set, int policer,
    fm_aclCondition cond, const fm_aclValue *value,
    fm_aclActionExt action, const fm_aclParamExt *param) {
    fm_aclValue expected_value;
    fm_aclParamExt expected_param;
    fm_aclActionExt expected_action = 0;
    fm_aclCondition expected_cond;

    if (!args || !value || !param)
        return false;
    expected_cond = fill_independent_acl_term(
        args, (fm_int)port_set, policer, &expected_value,
        &expected_action, &expected_param);
    if (cond != expected_cond ||
        action != expected_action ||
        value->portSet != expected_value.portSet ||
        value->vlanId != expected_value.vlanId ||
        value->vlanIdMask != expected_value.vlanIdMask)
        return false;
    if ((expected_cond & FM_ACL_MATCH_SRC_MAC) &&
        (value->src != expected_value.src ||
         value->srcMask != expected_value.srcMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_DST_MAC) &&
        (value->dst != expected_value.dst ||
         value->dstMask != expected_value.dstMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_ETHERTYPE) &&
        (value->ethType != expected_value.ethType ||
         value->ethTypeMask != expected_value.ethTypeMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_SRC_IP) &&
        (!same_general_ip_addr(&value->srcIp, &expected_value.srcIp) ||
         !same_general_ip_addr(&value->srcIpMask,
                               &expected_value.srcIpMask)))
        return false;
    if ((expected_cond & FM_ACL_MATCH_DST_IP) &&
        (!same_general_ip_addr(&value->dstIp, &expected_value.dstIp) ||
         !same_general_ip_addr(&value->dstIpMask,
                               &expected_value.dstIpMask)))
        return false;
    if ((expected_cond & FM_ACL_MATCH_DSCP) &&
        (value->dscp != expected_value.dscp ||
         value->dscpMask != expected_value.dscpMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_PROTOCOL) &&
        (value->protocol != expected_value.protocol ||
         value->protocolMask != expected_value.protocolMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_L4_SRC_PORT_WITH_MASK) &&
        (value->L4SrcStart != expected_value.L4SrcStart ||
         value->L4SrcMask != expected_value.L4SrcMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_L4_DST_PORT_WITH_MASK) &&
        (value->L4DstStart != expected_value.L4DstStart ||
         value->L4DstMask != expected_value.L4DstMask))
        return false;
    if ((expected_cond & FM_ACL_MATCH_TCP_FLAGS) &&
        (value->tcpFlags != expected_value.tcpFlags ||
         value->tcpFlagsMask != expected_value.tcpFlagsMask))
        return false;
    if (independent_wants_policer(args) && param->policer != policer)
        return false;
    return true;
}

static int acl_independent_slot_get(
    int sw, const hal_acl_independent_args *args,
    acl_independent_live_slot *live) {
    fm_aclCondition condition = 0;
    fm_aclCondition expected_condition = 0;
    fm_aclValue value;
    fm_aclValue expected_value;
    fm_aclActionExt action = 0;
    fm_aclActionExt expected_action = 0;
    fm_aclParamExt param;
    fm_aclParamExt expected_param;
    fm_aclEntryState rule_state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    acl_live_policer policer;
    fm_status detail_status = FM_OK;
    fm_status st = FM_ERR_INVALID_ACL_RULE;
    bool acl_present = false;
    bool port_set_contains_target = false;
    bool port_set_exact = false;
    bool rule_present = false;

    if (!args || !live || !independent_slot_valid(args->slot))
        return -1;
    memset(live, 0, sizeof(*live));
    live->state = ACL_LIVE_EMPTY;
    live->sdk_status = FM_OK;
    live->slot = args->slot;
    live->acl = independent_acl_default();
    live->rule = independent_rule_for_slot(args->slot);
    live->policer = independent_wants_policer(args) ?
        NETLAB_ACL_GENERAL_INGRESS_POLICER_START + args->slot : 0;
    live->port_set = -1;

    if (acl_presence_get(
            sw, live->acl, &acl_present, &detail_status) != 0) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = detail_status;
        return -1;
    }
    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    if (acl_present) {
        st = fmGetACLRule((fm_int)sw, (fm_int)live->acl,
                          (fm_int)live->rule, &condition, &value,
                          &action, &param);
        if (st == FM_OK) {
            rule_present = true;
        } else if (!acl_rule_absent_status(st)) {
            live->state = ACL_LIVE_READ_ERROR;
            live->sdk_status = st;
            return -1;
        }
    }

    memset(&policer, 0, sizeof(policer));
    policer.state = HAL_TRANSACTION_SNAPSHOT_ABSENT;
    if (live->policer > 0) {
        policer = owner_policer_get(sw, live->policer);
        if (policer.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR) {
            live->state = ACL_LIVE_READ_ERROR;
            live->sdk_status = policer.sdk_status;
            return -1;
        }
    }
    if (!rule_present) {
        live->state =
            live->policer > 0 &&
            policer.state == HAL_TRANSACTION_SNAPSHOT_PRESENT ?
            ACL_LIVE_OCCUPIED : ACL_LIVE_EMPTY;
        return 0;
    }

    live->state = ACL_LIVE_OCCUPIED;
    live->port_set = (int)value.portSet;
    if (single_portset_member_get(
            sw, live->port_set, &live->port,
            &port_set_exact, &detail_status) != 0) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = detail_status;
        return -1;
    }
    if (portset_contains_port(
            sw, live->port_set, args->port,
            &port_set_contains_target, &detail_status) != 0) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = detail_status;
        return -1;
    }
    st = fmGetACLRuleState((fm_int)sw, (fm_int)live->acl,
                           (fm_int)live->rule, &rule_state);
    if (st != FM_OK) {
        live->state = ACL_LIVE_READ_ERROR;
        live->sdk_status = st;
        return -1;
    }

    live->semantic_match =
        rule_state == FM_ACL_RULE_ENTRY_STATE_VALID &&
        port_set_contains_target &&
        independent_term_matches(
            args, live->port_set, live->policer,
            condition, &value, action, &param);
    if (!live->semantic_match)
        return 0;
    expected_condition = fill_independent_acl_term(
        args, (fm_int)live->port_set, live->policer,
        &expected_value, &expected_action, &expected_param);
    if (condition != expected_condition ||
        action != expected_action ||
        memcmp(&value, &expected_value, sizeof(value)) != 0 ||
        memcmp(&param, &expected_param, sizeof(param)) != 0)
        return 0;
    if (!port_set_exact || live->port != args->port)
        return 0;
    if (live->policer > 0) {
        live->rate_kbps = policer.rate_kbps;
        live->burst_bytes = policer.burst_bytes;
        if (policer.state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
            !policer.fixed_exact)
            return 0;
    }
    live->state = ACL_LIVE_OWNER;
    live->exact_match =
        live->policer == 0 ||
        (live->rate_kbps == args->rate_kbps &&
         live->burst_bytes == args->burst_bytes);

    memset(&g_acl_independent_owner[args->slot], 0,
           sizeof(g_acl_independent_owner[args->slot]));
    g_acl_independent_owner[args->slot].active = true;
    g_acl_independent_owner[args->slot].args = *args;
    if (live->policer > 0) {
        g_acl_independent_owner[args->slot].args.rate_kbps =
            live->rate_kbps;
        g_acl_independent_owner[args->slot].args.burst_bytes =
            live->burst_bytes;
    }
    g_acl_independent_owner[args->slot].acl = live->acl;
    g_acl_independent_owner[args->slot].rule = live->rule;
    g_acl_independent_owner[args->slot].policer = live->policer;
    g_acl_independent_owner[args->slot].port_set = live->port_set;
    return 0;
}

static void cleanup_general_allocator_compiler(
    int sw, hal_acl_general_allocator_result *result, bool delete_acl) {
    fm_status st;
    char detail[128];
    bool need_apply = false;

    if (!result)
        return;

    if (result->compiler_acl > 0 && result->compiler_rule >= 0) {
        st = fmDeleteACLRule((fm_int)sw, (fm_int)result->compiler_acl,
                             (fm_int)result->compiler_rule);
        record_general_cleanup_status(result, st);
        if (status_missing_ok(st))
            need_apply = true;
    }
    if (result->compiler_acl > 0 &&
        result->compiler_policer_rule >= 0) {
        st = fmDeleteACLRule((fm_int)sw, (fm_int)result->compiler_acl,
                             (fm_int)result->compiler_policer_rule);
        record_general_cleanup_status(result, st);
        if (status_missing_ok(st))
            need_apply = true;
    }
    if (need_apply) {
        memset(detail, 0, sizeof(detail));
        st = compile_and_apply_acl(sw, detail, sizeof(detail));
        record_general_cleanup_status(result, st);
        if (st != FM_OK) {
            NL_LOG_WARN("general ACL allocator cleanup compile/apply failed: %s",
                        detail);
        }
    }
    if (result->compiler_policer > 0) {
        st = fmDeletePolicer((fm_int)sw,
                             (fm_int)result->compiler_policer);
        record_general_cleanup_status(result, st);
    }
    if (result->compiler_port_set >= 0) {
        st = fmDeletePortSet((fm_int)sw,
                             (fm_int)result->compiler_port_set);
        record_general_cleanup_status(result, st);
    }
    if (delete_acl && result->compiler_acl > 0) {
        st = fmDeleteACL((fm_int)sw, (fm_int)result->compiler_acl);
        record_general_cleanup_status(result, st);
    }
}

static int read_general_allocator_compiler_state(
    int sw, acl_general_profile profile,
    hal_acl_general_allocator_result *result) {
    fm_aclCondition cond = 0;
    fm_aclValue value;
    fm_aclActionExt action = 0;
    fm_aclParamExt param;
    fm_aclCounters counters;
    fm_status st;

    if (!result)
        return -1;

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    st = fmGetACLRule((fm_int)sw, (fm_int)result->compiler_acl,
                      (fm_int)result->compiler_rule, &cond, &value,
                      &action, &param);
    result->compiler_read_status = (int)st;
    result->compiler_condition = (u64)cond;
    result->compiler_action = (u64)action;
    if (st == FM_OK) {
        result->compared++;
        if (!general_acl_term_matches(
                profile, false, result->compiler_port_set,
                result->compiler_policer, cond, &value, action, &param)) {
            result->mismatches++;
        }
    } else {
        result->mismatches++;
    }

    memset(&counters, 0, sizeof(counters));
    st = fmGetACLCountExt((fm_int)sw, (fm_int)result->compiler_acl,
                          (fm_int)result->compiler_rule, &counters);
    if (result->compiler_read_status == FM_OK)
        result->compiler_read_status = (int)st;
    if (st == FM_OK) {
        result->compiler_packets = counters.cntPkts;
        result->compiler_octets = counters.cntOctets;
        result->compared++;
    } else {
        result->mismatches++;
    }

    if (general_acl_profile_uses_policer(profile)) {
        memset(&value, 0, sizeof(value));
        memset(&param, 0, sizeof(param));
        cond = 0;
        action = 0;
        st = fmGetACLRule((fm_int)sw, (fm_int)result->compiler_acl,
                          (fm_int)result->compiler_policer_rule, &cond,
                          &value, &action, &param);
        result->compiler_policer_read_status = (int)st;
        if (st == FM_OK) {
            result->compared++;
            if (!general_acl_term_matches(
                    profile, true, result->compiler_port_set,
                    result->compiler_policer, cond, &value, action,
                    &param)) {
                result->mismatches++;
            }
        } else {
            result->mismatches++;
        }

        memset(&counters, 0, sizeof(counters));
        st = fmGetACLCountExt((fm_int)sw, (fm_int)result->compiler_acl,
                              (fm_int)result->compiler_policer_rule,
                              &counters);
        if (result->compiler_policer_read_status == FM_OK)
            result->compiler_policer_read_status = (int)st;
        if (st == FM_OK) {
            result->compiler_policer_packets = counters.cntPkts;
            result->compiler_policer_octets = counters.cntOctets;
            result->compared++;
        } else {
            result->mismatches++;
        }
    }

    return result->mismatches == 0 ? 0 : -1;
}

static int apply_general_allocator_compiler_smoke(
    int sw, acl_general_profile profile,
    hal_acl_general_allocator_result *result) {
    fm_aclValue value;
    fm_aclParamExt param;
    fm_aclActionExt action = 0;
    fm_aclCondition cond = 0;
    fm_int port_set = -1;
    fm_status st;
    int port;

    if (!result)
        return -1;

    port = first_user_logical_port();
    if (port <= 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL allocator found no user port for compiler smoke");
        return -1;
    }
    result->compiler_port = port;

    st = fmCreateACL((fm_int)sw, (fm_int)result->compiler_acl);
    result->compiler_create_status = (int)st;
    if (st != FM_OK &&
        st != FM_ERR_ALREADY_EXISTS &&
        st != FM_ERR_INVALID_ACL) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL create failed: %s", fmErrorMsg(st));
        return (int)st;
    }

    st = fmCreatePortSet((fm_int)sw, &port_set);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL port-set create failed: %s", fmErrorMsg(st));
        cleanup_general_allocator_compiler(sw, result, true);
        return (int)st;
    }
    result->compiler_port_set = (int)port_set;

    st = fmAddPortSetPort((fm_int)sw, port_set, (fm_int)port);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL port-set add port failed: %s", fmErrorMsg(st));
        cleanup_general_allocator_compiler(sw, result, true);
        return (int)st;
    }

    st = fmDeleteACLRule((fm_int)sw, (fm_int)result->compiler_acl,
                         (fm_int)result->compiler_rule);
    if (!status_missing_ok(st)) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL stale rule delete failed: %s", fmErrorMsg(st));
        cleanup_general_allocator_compiler(sw, result, true);
        return (int)st;
    }
    st = fmDeleteACLRule((fm_int)sw, (fm_int)result->compiler_acl,
                         (fm_int)NETLAB_ACL_GENERAL_COMPILER_POLICER_RULE);
    if (!status_missing_ok(st)) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL stale policer rule delete failed: %s",
                 fmErrorMsg(st));
        cleanup_general_allocator_compiler(sw, result, true);
        return (int)st;
    }

    cond = fill_general_acl_compiler_term(
        profile, false, port_set, result->compiler_policer,
        &value, &action, &param);
    result->compiler_condition = (u64)cond;
    result->compiler_action = (u64)action;

    st = fmAddACLRuleExt((fm_int)sw, (fm_int)result->compiler_acl,
                         (fm_int)result->compiler_rule,
                         cond, &value, action, &param);
    result->compiler_rule_status = (int)st;
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL rule add failed: %s", fmErrorMsg(st));
        cleanup_general_allocator_compiler(sw, result, true);
        return (int)st;
    }

    if (general_acl_profile_uses_policer(profile)) {
        st = create_or_update_probe_policer(
            sw, result->compiler_policer,
            NETLAB_ACL_GENERAL_COMPILER_POLICER_RATE_KBPS,
            NETLAB_ACL_GENERAL_COMPILER_POLICER_BURST_BYTES);
        result->compiler_policer_status = (int)st;
        if (st != FM_OK) {
            snprintf(result->detail, sizeof(result->detail),
                     "general ACL policer create/update failed: %s",
                     fmErrorMsg(st));
            cleanup_general_allocator_compiler(sw, result, true);
            return (int)st;
        }

        cond = fill_general_acl_compiler_term(
            profile, true, port_set, result->compiler_policer,
            &value, &action, &param);
        st = fmAddACLRuleExt((fm_int)sw, (fm_int)result->compiler_acl,
                             (fm_int)result->compiler_policer_rule,
                             cond, &value, action, &param);
        result->compiler_policer_rule_status = (int)st;
        if (st != FM_OK) {
            snprintf(result->detail, sizeof(result->detail),
                     "general ACL policer rule add failed: %s",
                     fmErrorMsg(st));
            cleanup_general_allocator_compiler(sw, result, true);
            return (int)st;
        }
    }

    st = compile_and_apply_acl(sw, result->detail, sizeof(result->detail));
    result->compiler_compile_status = (int)st;
    result->compiler_apply_status = (int)st;
    if (st != FM_OK) {
        cleanup_general_allocator_compiler(sw, result, true);
        return (int)st;
    }

    return read_general_allocator_compiler_state(sw, profile, result);
}

static void cleanup_probe(int sw, int acl, int rule, int policer,
                          int port_set,
                          hal_acl_policer_probe_result *result) {
    fm_status st;
    char detail[128];

    if (acl > 0 && rule >= 0) {
        st = fmDeleteACLRule((fm_int)sw, (fm_int)acl, (fm_int)rule);
        record_cleanup_status(result, st);
        if (status_missing_ok(st)) {
            memset(detail, 0, sizeof(detail));
            st = compile_and_apply_acl(sw, detail, sizeof(detail));
            record_cleanup_status(result, st);
            if (st != FM_OK) {
                NL_LOG_WARN("ACL policer probe cleanup compile/apply failed: %s",
                            detail);
            }
        }
    }
    if (policer > 0) {
        st = fmDeletePolicer((fm_int)sw, (fm_int)policer);
        record_cleanup_status(result, st);
    }
    if (port_set >= 0) {
        st = fmDeletePortSet((fm_int)sw, (fm_int)port_set);
        record_cleanup_status(result, st);
    }
}

static void cleanup_owner(int sw, int acl, int rule, int policer,
                          int port_set,
                          hal_acl_policer_owner_result *result) {
    fm_status st;
    char detail[128];

    if (acl > 0 && rule >= 0) {
        st = fmDeleteACLRule((fm_int)sw, (fm_int)acl, (fm_int)rule);
        record_owner_cleanup_status(result, st);
        if (status_missing_ok(st)) {
            memset(detail, 0, sizeof(detail));
            st = compile_and_apply_acl(sw, detail, sizeof(detail));
            record_owner_cleanup_status(result, st);
            if (st != FM_OK) {
                NL_LOG_WARN("ACL policer owner cleanup compile/apply failed: %s",
                            detail);
            }
        }
    }
    if (policer > 0) {
        st = fmDeletePolicer((fm_int)sw, (fm_int)policer);
        record_owner_cleanup_status(result, st);
    }
    if (port_set >= 0) {
        st = fmDeletePortSet((fm_int)sw, (fm_int)port_set);
        record_owner_cleanup_status(result, st);
    }
}

static void cleanup_created_shared_acl_for_owner(
    int sw, hal_acl_shared_creation_token *creation_token,
    hal_acl_policer_owner_result *result) {
    fm_status st;

    if (!creation_token || !creation_token->valid)
        return;
    st = release_shared_acl_created_empty(
        sw, HAL_ACL_SHARED_CREATOR_POLICER, creation_token);
    record_owner_cleanup_status(result, st);
    if (st == FM_OK)
        clear_acl_shared_creation_token(creation_token);
}

static void cleanup_egress_probe(int sw, int acl, int rule, int port,
                                 bool delete_acl,
                                 hal_acl_egress_probe_result *result) {
    fm_aclPortAndType port_and_type;
    fm_status st;
    char detail[128];

    memset(&port_and_type, 0, sizeof(port_and_type));
    port_and_type.port = (fm_int)port;
    port_and_type.type = FM_ACL_TYPE_EGRESS;

    if (acl > 0 && port > 0) {
        st = fmDeleteACLPortExt((fm_int)sw, (fm_int)acl, &port_and_type);
        record_egress_cleanup_status(result, st);
    }

    if (acl > 0 && rule >= 0) {
        st = fmDeleteACLRule((fm_int)sw, (fm_int)acl, (fm_int)rule);
        record_egress_cleanup_status(result, st);
    }

    if (acl > 0) {
        memset(detail, 0, sizeof(detail));
        st = compile_and_apply_acl(sw, detail, sizeof(detail));
        record_egress_cleanup_status(result, st);
        if (st != FM_OK) {
            NL_LOG_WARN("ACL egress probe cleanup compile/apply failed: %s",
                        detail);
        }
    }

    if (delete_acl && acl > 0) {
        st = fmDeleteACL((fm_int)sw, (fm_int)acl);
        if (result)
            result->delete_acl_status = (int)st;
        record_egress_cleanup_status(result, st);
    }
}

static void cleanup_egress_owner(int sw, int acl, int rule, int port,
                                 bool delete_acl,
                                 hal_acl_egress_owner_result *result) {
    fm_aclPortAndType port_and_type;
    fm_status st;
    char detail[128];

    memset(&port_and_type, 0, sizeof(port_and_type));
    port_and_type.port = (fm_int)port;
    port_and_type.type = FM_ACL_TYPE_EGRESS;

    if (acl > 0 && port > 0) {
        st = fmDeleteACLPortExt((fm_int)sw, (fm_int)acl, &port_and_type);
        record_egress_owner_cleanup_status(result, st);
    }

    if (acl > 0 && rule >= 0) {
        st = fmDeleteACLRule((fm_int)sw, (fm_int)acl, (fm_int)rule);
        record_egress_owner_cleanup_status(result, st);
    }

    if (acl > 0) {
        memset(detail, 0, sizeof(detail));
        st = compile_and_apply_acl(sw, detail, sizeof(detail));
        record_egress_owner_cleanup_status(result, st);
        if (st != FM_OK) {
            NL_LOG_WARN("egress ACL owner cleanup compile/apply failed: %s",
                        detail);
        }
    }

    if (delete_acl && acl > 0) {
        st = fmDeleteACL((fm_int)sw, (fm_int)acl);
        record_egress_owner_cleanup_status(result, st);
    }
}

int hal_acl_policer_probe(int sw,
                          const hal_acl_policer_probe_args *args,
                          hal_acl_policer_probe_result *result) {
    fm_aclValue value;
    fm_aclParamExt param;
    fm_aclCounters counters;
    fm_int port_set = -1;
    fm_status st;

    if (!args || !result)
        return -1;

    memset(result, 0, sizeof(*result));
    result->port = args->port;
    result->rate_kbps = args->rate_kbps;
    result->burst_bytes = args->burst_bytes;
    result->dst_mac = args->dst_mac ? args->dst_mac :
                      NETLAB_ACL_POLICER_PROBE_DST_MAC;
    result->acl = NETLAB_ACL_POLICER_PROBE_ACL_ID;
    result->rule = NETLAB_ACL_POLICER_PROBE_RULE;
    result->policer = NETLAB_ACL_POLICER_PROBE_POLICER;
    result->port_set = -1;
    snprintf(result->detail, sizeof(result->detail), "not-run");

    if (!acl_policer_owner_args_valid(args)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid probe arguments");
        return -1;
    }

    st = fmCreateACL((fm_int)sw, (fm_int)result->acl);
    result->create_status = (int)st;
    if (st != FM_OK &&
        st != FM_ERR_ALREADY_EXISTS &&
        st != FM_ERR_INVALID_ACL) {
        snprintf(result->detail, sizeof(result->detail),
                 "ACL create failed: %s", fmErrorMsg(st));
        return (int)st;
    }

    st = fmCreatePortSet((fm_int)sw, &port_set);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "port-set create failed: %s", fmErrorMsg(st));
        cleanup_probe(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        return (int)st;
    }
    result->port_set = (int)port_set;

    st = fmAddPortSetPort((fm_int)sw, port_set, (fm_int)args->port);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "port-set add port failed: %s", fmErrorMsg(st));
        cleanup_probe(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        return (int)st;
    }

    st = create_or_update_probe_policer(sw, result->policer,
                                        args->rate_kbps,
                                        args->burst_bytes);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "policer create/update failed: %s", fmErrorMsg(st));
        cleanup_probe(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        return (int)st;
    }

    st = fmDeleteACLRule((fm_int)sw, (fm_int)result->acl,
                         (fm_int)result->rule);
    if (!status_missing_ok(st)) {
        snprintf(result->detail, sizeof(result->detail),
                 "stale rule delete failed: %s", fmErrorMsg(st));
        cleanup_probe(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        return (int)st;
    }

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    value.portSet = port_set;
    value.dst = result->dst_mac;
    value.dstMask = 0xffffffffffffULL;
    param.policer = result->policer;

    st = fmAddACLRuleExt((fm_int)sw, (fm_int)result->acl,
                         (fm_int)result->rule,
                         FM_ACL_MATCH_INGRESS_PORT_SET |
                         FM_ACL_MATCH_DST_MAC,
                         &value,
                         FM_ACL_ACTIONEXT_POLICE |
                         FM_ACL_ACTIONEXT_COUNT,
                         &param);
    result->rule_status = (int)st;
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "ACL rule add failed: %s", fmErrorMsg(st));
        cleanup_probe(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        return (int)st;
    }

    st = compile_and_apply_acl(sw, result->detail, sizeof(result->detail));
    result->compile_status = (int)st;
    result->apply_status = (int)st;
    if (st != FM_OK) {
        cleanup_probe(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        return (int)st;
    }

    memset(&counters, 0, sizeof(counters));
    st = fmGetACLCountExt((fm_int)sw, (fm_int)result->acl,
                          (fm_int)result->rule, &counters);
    result->read_status = (int)st;
    if (st == FM_OK) {
        result->packets = counters.cntPkts;
        result->octets = counters.cntOctets;
    } else {
        snprintf(result->detail, sizeof(result->detail),
                 "ACL counter read failed: %s", fmErrorMsg(st));
        cleanup_probe(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        return (int)st;
    }

    snprintf(result->detail, sizeof(result->detail),
             "ACL compiler policer path verified and cleaned");
    result->ok = true;
    cleanup_probe(sw, result->acl, result->rule, result->policer,
                  port_set, result);
    if (result->cleanup_status != 0) {
        result->ok = false;
        snprintf(result->detail, sizeof(result->detail),
                 "probe passed but cleanup failed: %s",
                 fmErrorMsg(result->cleanup_status));
        return result->cleanup_status;
    }
    return 0;
}

static int acl_policer_owner_apply_internal(
    int sw, const hal_acl_policer_owner_args *args,
    int required_slot, bool allow_shared_acl_create,
    hal_acl_shared_creation_token *creation_token,
    hal_acl_policer_owner_result *result) {
    hal_acl_resource_reservation reservation;
    acl_policer_live_slot
        slots[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS];
    fm_aclValue value;
    fm_aclParamExt param;
    fm_int port_set = -1;
    fm_status scan_status = FM_OK;
    fm_status st;
    bool acl_present = false;
    int slot = -1;

    if (!args || !result)
        return -1;
    clear_acl_shared_creation_token(creation_token);

    memset(result, 0, sizeof(*result));
    result->slot = -1;
    result->acl = NETLAB_ACL_POLICER_PROBE_ACL_ID;
    result->rule = NETLAB_ACL_POLICER_OWNER_RULE;
    result->policer = NETLAB_ACL_POLICER_OWNER_POLICER;
    result->port_set = -1;
    result->port = args->port;
    result->dst_mac = owner_dst_mac(args);
    result->rate_kbps = args->rate_kbps;
    result->burst_bytes = args->burst_bytes;
    snprintf(result->detail, sizeof(result->detail), "not-run");

    if (!acl_policer_owner_args_valid(args)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid owner arguments");
        return -1;
    }
    if (required_slot < -1 ||
        required_slot >= NETLAB_ACL_POLICER_OWNER_MAX_SLOTS) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid required ACL policer owner slot");
        return -1;
    }

    if (acl_policer_slots_scan(
            sw, slots, &acl_present, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        snprintf(result->detail, sizeof(result->detail),
                 "ACL policer owner live scan failed: %s",
                 fmErrorMsg(scan_status));
        return -1;
    }
    for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
        if (acl_policer_semantic_match(sw, &slots[i], args)) {
            fill_owner_live_identity(result, &slots[i]);
            snprintf(result->detail, sizeof(result->detail),
                     slots[i].state == ACL_LIVE_OWNER ?
                     "ACL policer owner semantic key already exists" :
                     "ACL policer owner semantic key is malformed");
            return -1;
        }
        if (required_slot < 0 &&
            slot < 0 && slots[i].state == ACL_LIVE_EMPTY)
            slot = i;
    }
    if (required_slot >= 0) {
        if (slots[required_slot].state != ACL_LIVE_EMPTY) {
            fill_owner_live_identity(result, &slots[required_slot]);
            snprintf(result->detail, sizeof(result->detail),
                     "required ACL policer owner slot is occupied");
            return -1;
        }
        slot = required_slot;
    }
    if (slot < 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "ACL policer owner capacity exhausted");
        return -1;
    }
    result->slot = slot;
    result->rule = owner_rule_for_slot(slot);
    result->policer = owner_policer_for_slot(slot);

    const hal_acl_resource_spec spec = {
        .owner = HAL_ACL_OWNER_ACL_POLICER,
        .name = "acl-policer-owner",
        .preferred_acl = NETLAB_ACL_POLICER_PROBE_ACL_ID,
        .first_policer = NETLAB_ACL_POLICER_OWNER_POLICER,
        .policer_count = NETLAB_ACL_POLICER_OWNER_MAX_SLOTS,
    };
    memset(&reservation, 0, sizeof(reservation));
    if (hal_acl_resource_reserve(sw, &spec, &reservation) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "ACL policer resource reservation failed");
        return -1;
    }
    if (reservation.acl != NETLAB_ACL_POLICER_PROBE_ACL_ID ||
        reservation.first_policer !=
            NETLAB_ACL_POLICER_OWNER_POLICER) {
        snprintf(result->detail, sizeof(result->detail),
                 "ACL policer reservation identity mismatch");
        return -1;
    }
    result->acl = reservation.acl;
    result->policer = reservation.first_policer + slot;

    if (!acl_present && !allow_shared_acl_create) {
        snprintf(result->detail, sizeof(result->detail),
                 "shared ACL disappeared before owner restore");
        return -1;
    }
    if (!acl_present) {
        st = create_shared_acl_exact_with_token(
            sw, result->acl, HAL_ACL_SHARED_CREATOR_POLICER,
            creation_token);
        result->create_status = (int)st;
        if (st != FM_OK) {
            cleanup_created_shared_acl_for_owner(
                sw, creation_token, result);
            snprintf(result->detail, sizeof(result->detail),
                     "shared ACL create/read-back failed: %s",
                     fmErrorMsg(st));
            return (int)st;
        }
    }

    st = fmCreatePortSet((fm_int)sw, &port_set);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "port-set create failed: %s", fmErrorMsg(st));
        cleanup_created_shared_acl_for_owner(
            sw, creation_token, result);
        return (int)st;
    }
    result->port_set = (int)port_set;

    st = fmAddPortSetPort((fm_int)sw, port_set, (fm_int)args->port);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "port-set add port failed: %s", fmErrorMsg(st));
        (void)fmDeletePortSet((fm_int)sw, port_set);
        cleanup_created_shared_acl_for_owner(
            sw, creation_token, result);
        return (int)st;
    }

    st = create_owner_policer(sw, result->policer,
                              args->rate_kbps, args->burst_bytes);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "policer create failed: %s", fmErrorMsg(st));
        (void)fmDeletePortSet((fm_int)sw, port_set);
        cleanup_created_shared_acl_for_owner(
            sw, creation_token, result);
        return (int)st;
    }

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    value.portSet = port_set;
    value.dst = result->dst_mac;
    value.dstMask = 0xffffffffffffULL;
    param.policer = result->policer;

    st = fmAddACLRuleExt((fm_int)sw, (fm_int)result->acl,
                         (fm_int)result->rule,
                         FM_ACL_MATCH_INGRESS_PORT_SET |
                         FM_ACL_MATCH_DST_MAC,
                         &value,
                         FM_ACL_ACTIONEXT_POLICE |
                         FM_ACL_ACTIONEXT_COUNT,
                         &param);
    result->rule_status = (int)st;
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "ACL rule add failed: %s", fmErrorMsg(st));
        (void)fmDeletePolicer((fm_int)sw, (fm_int)result->policer);
        (void)fmDeletePortSet((fm_int)sw, port_set);
        cleanup_created_shared_acl_for_owner(
            sw, creation_token, result);
        return (int)st;
    }

    st = compile_and_apply_acl(sw, result->detail, sizeof(result->detail));
    result->compile_status = (int)st;
    result->apply_status = (int)st;
    if (st != FM_OK) {
        cleanup_owner(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        cleanup_created_shared_acl_for_owner(
            sw, creation_token, result);
        return (int)st;
    }

    g_acl_policer_owner[slot].active = true;
    g_acl_policer_owner[slot].args = *args;
    g_acl_policer_owner[slot].args.dst_mac = result->dst_mac;
    g_acl_policer_owner[slot].acl = result->acl;
    g_acl_policer_owner[slot].rule = result->rule;
    g_acl_policer_owner[slot].policer = result->policer;
    g_acl_policer_owner[slot].port_set = (int)port_set;

    result->active = true;
    if (read_owner_live_state(sw, result) != 0) {
        cleanup_owner(sw, result->acl, result->rule, result->policer,
                      port_set, result);
        cleanup_created_shared_acl_for_owner(
            sw, creation_token, result);
        memset(&g_acl_policer_owner[slot], 0,
               sizeof(g_acl_policer_owner[slot]));
        return -1;
    }
    snprintf(result->detail, sizeof(result->detail),
             "ACL policer owner applied and verified");
    return 0;
}

int hal_acl_policer_owner_apply(int sw,
                                const hal_acl_policer_owner_args *args,
                                hal_acl_policer_owner_result *result) {
    hal_acl_shared_creation_token creation_token;
    int status;

    status = acl_policer_owner_apply_internal(
        sw, args, -1, true, &creation_token, result);
    if (creation_token.valid)
        abandon_acl_shared_creation_token(&creation_token);
    return status;
}

int hal_acl_policer_owner_readback(int sw,
                                   hal_acl_policer_owner_result *result) {
    acl_policer_live_slot
        slots[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;
    bool acl_present = false;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (acl_policer_slots_scan(
            sw, slots, &acl_present, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        snprintf(result->detail, sizeof(result->detail),
                 "ACL policer owner live scan failed: %s",
                 fmErrorMsg(scan_status));
        return -1;
    }
    (void)acl_present;
    for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
        if (slots[i].state != ACL_LIVE_OWNER)
            continue;
        fill_owner_live_identity(result, &slots[i]);
        return read_owner_live_state(sw, result);
    }
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "no active ACL policer owner");
    return 0;
}

int hal_acl_policer_owner_readback_match(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_result *result) {
    acl_policer_live_slot
        slots[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;
    bool acl_present = false;

    if (!args || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (acl_policer_slots_scan(
            sw, slots, &acl_present, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        snprintf(result->detail, sizeof(result->detail),
                 "ACL policer owner live scan failed: %s",
                 fmErrorMsg(scan_status));
        return -1;
    }
    (void)acl_present;
    for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
        if (!acl_policer_semantic_match(sw, &slots[i], args))
            continue;
        fill_owner_live_identity(result, &slots[i]);
        if (slots[i].state != ACL_LIVE_OWNER) {
            result->mismatches = 1;
            snprintf(result->detail, sizeof(result->detail),
                     "matching ACL policer owner is malformed");
            return -1;
        }
        result->rate_kbps = args->rate_kbps;
        result->burst_bytes = args->burst_bytes;
        return read_owner_live_state(sw, result);
    }
    result->port = args->port;
    result->dst_mac = owner_dst_mac(args);
    result->rate_kbps = args->rate_kbps;
    result->burst_bytes = args->burst_bytes;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "no matching ACL policer owner");
    return 0;
}

int hal_acl_policer_counter_snapshot(
    int sw, const nl_acl_counter_query *query,
    nl_acl_counter_snapshot *snapshot) {
    acl_policer_live_slot
        slots[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;
    bool acl_present = false;
    unsigned int policer_count = 0;

    if (!query || !snapshot || snapshot->n_entries != query->n_entries)
        return -1;
    for (u16 i = 0; i < query->n_entries; i++)
        if (query->entries[i].kind == NL_ACL_COUNTER_KIND_POLICER)
            policer_count++;
    if (policer_count == 0)
        return 0;
    if (acl_policer_slots_scan(
            sw, slots, &acl_present, &scan_status) != 0)
        return scan_status != FM_OK ? (int)scan_status : -1;
    (void)acl_present;

    for (u16 i = 0; i < query->n_entries; i++) {
        const nl_acl_counter_query_entry *entry = &query->entries[i];
        nl_acl_counter_snapshot_entry *out = &snapshot->entries[i];
        hal_acl_policer_owner_args args;
        int matching_slot = -1;
        int matching_slots = 0;

        if (entry->kind != NL_ACL_COUNTER_KIND_POLICER)
            continue;
        memset(&args, 0, sizeof(args));
        args.port = entry->match.port;
        args.dst_mac = entry->dst_mac;
        args.rate_kbps = entry->rate_kbps;
        args.burst_bytes = entry->burst_bytes;
        for (int slot = 0; slot < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS;
             slot++) {
            if (!acl_policer_semantic_match(sw, &slots[slot], &args))
                continue;
            matching_slot = slot;
            matching_slots++;
        }
        if (matching_slots > 1) {
            out->state = NL_ACL_COUNTER_STATE_MISMATCH;
            continue;
        }
        if (matching_slot >= 0) {
            hal_acl_policer_owner_result owner;
            int rc;

            memset(&owner, 0, sizeof(owner));
            fill_owner_live_identity(&owner, &slots[matching_slot]);
            if (slots[matching_slot].state != ACL_LIVE_OWNER) {
                out->state = NL_ACL_COUNTER_STATE_MISMATCH;
                continue;
            }
            owner.rate_kbps = args.rate_kbps;
            owner.burst_bytes = args.burst_bytes;
            rc = read_owner_live_state(sw, &owner);
            out->sdk_status = owner.read_status;
            if (rc != 0 &&
                (owner.read_status != FM_OK ||
                 owner.policer_read_status != FM_OK))
                return owner.read_status != FM_OK ? owner.read_status :
                       owner.policer_read_status;
            if (rc != 0 || !owner.ok) {
                out->state = NL_ACL_COUNTER_STATE_MISMATCH;
            } else {
                out->state = NL_ACL_COUNTER_STATE_INSTALLED;
                out->packets = owner.packets;
                out->octets = owner.octets;
            }
        }
    }
    return 0;
}

int hal_acl_policer_owner_rollback(int sw,
                                   hal_acl_policer_owner_result *result) {
    acl_policer_live_slot
        slots[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;
    bool acl_present = false;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (acl_policer_slots_scan(
            sw, slots, &acl_present, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        return -1;
    }
    (void)acl_present;
    for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
        hal_acl_policer_owner_args args;

        if (slots[i].state != ACL_LIVE_OWNER)
            continue;
        memset(&args, 0, sizeof(args));
        args.port = slots[i].port;
        args.dst_mac = slots[i].dst_mac;
        args.rate_kbps = slots[i].rate_kbps;
        args.burst_bytes = slots[i].burst_bytes;
        return hal_acl_policer_owner_rollback_match(
            sw, &args, result);
    }
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "no active ACL policer owner");
    return 0;
}

int hal_acl_policer_owner_rollback_match(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_result *result) {
    acl_policer_live_slot
        slots[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;
    bool acl_present = false;
    int slot = -1;

    if (!args || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (acl_policer_slots_scan(
            sw, slots, &acl_present, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        return -1;
    }
    (void)acl_present;
    for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
        if (!acl_policer_semantic_match(sw, &slots[i], args))
            continue;
        if (!acl_policer_exact_match(sw, &slots[i], args)) {
            fill_owner_live_identity(result, &slots[i]);
            result->mismatches = 1;
            snprintf(result->detail, sizeof(result->detail),
                     "ACL policer owner delete requires exact live match");
            return -1;
        }
        slot = i;
        break;
    }
    if (slot < 0) {
        result->port = args->port;
        result->dst_mac = owner_dst_mac(args);
        result->rate_kbps = args->rate_kbps;
        result->burst_bytes = args->burst_bytes;
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no matching ACL policer owner");
        return 0;
    }

    fill_owner_live_identity(result, &slots[slot]);
    cleanup_owner(sw, result->acl, result->rule, result->policer,
                  result->port_set, result);
    result->rollback_status = result->cleanup_status;
    if (result->cleanup_status == 0) {
        if (acl_policer_slots_scan(
                sw, slots, &acl_present, &scan_status) != 0 ||
            slots[slot].state != ACL_LIVE_EMPTY) {
            result->rollback_status =
                scan_status != FM_OK ? (int)scan_status : -1;
            result->active = true;
            snprintf(result->detail, sizeof(result->detail),
                     "ACL policer owner absence was not proven");
            return -1;
        }
        result->active = false;
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "ACL policer owner match rolled back and cleaned");
        return 0;
    }

    result->active = true;
    snprintf(result->detail, sizeof(result->detail),
             "ACL policer owner match rollback failed: %s",
             fmErrorMsg(result->cleanup_status));
    return result->cleanup_status;
}

static int acl_egress_owner_apply_internal(
    int sw, const hal_acl_egress_owner_args *args,
    int required_slot, hal_acl_egress_owner_result *result) {
    hal_acl_resource_reservation reservation;
    acl_egress_live_slot
        slots[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];
    fm_aclPortAndType port_and_type;
    fm_aclValue value;
    fm_aclParamExt param;
    fm_status scan_status = FM_OK;
    fm_status st;
    bool created_acl = false;
    int slot = -1;

    if (!args || !result)
        return -1;

    memset(result, 0, sizeof(*result));
    result->slot = -1;
    result->acl = NETLAB_ACL_EGRESS_OWNER_ACL_ID;
    result->rule = NETLAB_ACL_EGRESS_OWNER_RULE;
    result->port = args->port;
    result->src_mac = args->src_mac;
    result->dst_mac = args->dst_mac;
    snprintf(result->detail, sizeof(result->detail), "not-run");

    if (!acl_egress_owner_args_valid(args)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid egress ACL owner arguments");
        return -1;
    }
    if (required_slot < -1 ||
        required_slot >= NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid required egress ACL owner slot");
        return -1;
    }

    if (acl_egress_slots_scan(sw, slots, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL owner live scan failed: %s",
                 fmErrorMsg(scan_status));
        return -1;
    }
    for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
        if (acl_egress_semantic_match(sw, &slots[i], args) ||
            acl_egress_port_collision(
                sw, &slots[i], args->port)) {
            fill_egress_owner_live_identity(result, &slots[i]);
            snprintf(result->detail, sizeof(result->detail),
                     "egress ACL owner port is already occupied");
            return -1;
        }
        if (required_slot < 0 &&
            slot < 0 && slots[i].state == ACL_LIVE_EMPTY)
            slot = i;
    }
    if (required_slot >= 0) {
        if (slots[required_slot].state != ACL_LIVE_EMPTY) {
            fill_egress_owner_live_identity(
                result, &slots[required_slot]);
            snprintf(result->detail, sizeof(result->detail),
                     "required egress ACL owner slot is occupied");
            return -1;
        }
        slot = required_slot;
    }
    if (slot < 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL owner capacity exhausted");
        return -1;
    }
    result->slot = slot;
    result->acl = egress_owner_acl_for_slot(slot);

    const hal_acl_resource_spec spec = {
        .owner = HAL_ACL_OWNER_EGRESS_ACL,
        .name = "egress-acl-owner",
        .preferred_acl = NETLAB_ACL_EGRESS_OWNER_ACL_ID,
        .first_policer = 0,
        .policer_count = 0,
    };
    memset(&reservation, 0, sizeof(reservation));
    if (hal_acl_resource_reserve(sw, &spec, &reservation) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL resource reservation failed");
        return -1;
    }
    if (reservation.acl != NETLAB_ACL_EGRESS_OWNER_ACL_ID) {
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL reservation identity mismatch");
        return -1;
    }
    result->acl = reservation.acl + slot;
    result->rule = NETLAB_ACL_EGRESS_OWNER_RULE;

    st = create_default_acl_exact(
        sw, result->acl, &created_acl);
    result->create_status = (int)st;
    if (st != FM_OK) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL owner create failed: %s", fmErrorMsg(st));
        if (created_acl)
            (void)delete_empty_default_acl_exact(sw, result->acl);
        return result->unsupported ? 0 : (int)st;
    }

    memset(&port_and_type, 0, sizeof(port_and_type));
    port_and_type.port = (fm_int)args->port;
    port_and_type.type = FM_ACL_TYPE_EGRESS;
    st = fmAddACLPortExt((fm_int)sw, (fm_int)result->acl, &port_and_type);
    result->port_status = (int)st;
    if (st != FM_OK) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL owner port association failed: %s",
                 fmErrorMsg(st));
        cleanup_egress_owner(sw, result->acl, result->rule, args->port,
                             true, result);
        return result->unsupported && result->cleanup_status == 0 ?
               0 : (result->cleanup_status ? result->cleanup_status : (int)st);
    }

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    fm_aclCondition cond = fill_egress_mac_value(
        &value, args->src_mac, args->dst_mac);
    st = fmAddACLRuleExt((fm_int)sw, (fm_int)result->acl,
                         (fm_int)result->rule,
                         cond,
                         &value, FM_ACL_ACTIONEXT_DENY, &param);
    result->rule_status = (int)st;
    if (st != FM_OK) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL owner rule add failed: %s", fmErrorMsg(st));
        cleanup_egress_owner(sw, result->acl, result->rule, args->port,
                             true, result);
        return result->unsupported && result->cleanup_status == 0 ?
               0 : (result->cleanup_status ? result->cleanup_status : (int)st);
    }

    st = compile_and_apply_acl(sw, result->detail, sizeof(result->detail));
    result->compile_status = (int)st;
    result->apply_status = (int)st;
    if (st != FM_OK) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        cleanup_egress_owner(sw, result->acl, result->rule, args->port,
                             true, result);
        return result->unsupported && result->cleanup_status == 0 ?
               0 : (result->cleanup_status ? result->cleanup_status : (int)st);
    }

    g_acl_egress_owner[slot].active = true;
    g_acl_egress_owner[slot].args = *args;
    g_acl_egress_owner[slot].acl = result->acl;
    g_acl_egress_owner[slot].rule = result->rule;
    result->active = true;
    if (read_egress_owner_live_state(sw, result) != 0) {
        cleanup_egress_owner(sw, result->acl, result->rule, args->port,
                             true, result);
        memset(&g_acl_egress_owner[slot], 0,
               sizeof(g_acl_egress_owner[slot]));
        return -1;
    }
    snprintf(result->detail, sizeof(result->detail),
             "egress ACL owner applied and verified");
    return 0;
}

int hal_acl_egress_owner_apply(int sw,
                               const hal_acl_egress_owner_args *args,
                               hal_acl_egress_owner_result *result) {
    return acl_egress_owner_apply_internal(sw, args, -1, result);
}

int hal_acl_egress_owner_readback(int sw,
                                  hal_acl_egress_owner_result *result) {
    acl_egress_live_slot
        slots[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (acl_egress_slots_scan(sw, slots, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        return -1;
    }
    for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
        if (slots[i].state != ACL_LIVE_OWNER)
            continue;
        fill_egress_owner_live_identity(result, &slots[i]);
        return read_egress_owner_live_state(sw, result);
    }
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "no active egress ACL owner");
    return 0;
}

int hal_acl_egress_owner_readback_match(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_egress_owner_result *result) {
    acl_egress_live_slot
        slots[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;

    if (!args || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (acl_egress_slots_scan(sw, slots, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        return -1;
    }
    for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
        if (!acl_egress_semantic_match(sw, &slots[i], args))
            continue;
        fill_egress_owner_live_identity(result, &slots[i]);
        if (slots[i].state != ACL_LIVE_OWNER) {
            result->mismatches = 1;
            snprintf(result->detail, sizeof(result->detail),
                     "matching egress ACL owner is malformed");
            return -1;
        }
        return read_egress_owner_live_state(sw, result);
    }
    result->port = args->port;
    result->src_mac = args->src_mac;
    result->dst_mac = args->dst_mac;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "no matching egress ACL owner");
    return 0;
}

int hal_acl_egress_owner_rollback(int sw,
                                  hal_acl_egress_owner_result *result) {
    acl_egress_live_slot
        slots[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (acl_egress_slots_scan(sw, slots, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        return -1;
    }
    for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
        hal_acl_egress_owner_args args;

        if (slots[i].state != ACL_LIVE_OWNER)
            continue;
        memset(&args, 0, sizeof(args));
        args.port = slots[i].port;
        args.src_mac = slots[i].src_mac;
        args.dst_mac = slots[i].dst_mac;
        return hal_acl_egress_owner_rollback_match(
            sw, &args, result);
    }
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "no active egress ACL owner");
    return 0;
}

int hal_acl_egress_owner_rollback_match(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_egress_owner_result *result) {
    acl_egress_live_slot
        slots[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;
    int slot = -1;

    if (!args || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (acl_egress_slots_scan(sw, slots, &scan_status) != 0) {
        result->read_status = (int)scan_status;
        return -1;
    }
    for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
        if (!acl_egress_semantic_match(sw, &slots[i], args))
            continue;
        if (!acl_egress_exact_match(sw, &slots[i], args)) {
            fill_egress_owner_live_identity(result, &slots[i]);
            result->mismatches = 1;
            snprintf(result->detail, sizeof(result->detail),
                     "egress ACL delete requires exact live match");
            return -1;
        }
        slot = i;
        break;
    }
    if (slot < 0) {
        result->port = args->port;
        result->src_mac = args->src_mac;
        result->dst_mac = args->dst_mac;
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no matching egress ACL owner");
        return 0;
    }

    fill_egress_owner_live_identity(result, &slots[slot]);
    cleanup_egress_owner(sw, result->acl, result->rule, result->port,
                         true, result);
    result->rollback_status = result->cleanup_status;
    if (result->cleanup_status == 0) {
        if (acl_egress_slots_scan(sw, slots, &scan_status) != 0 ||
            slots[slot].state != ACL_LIVE_EMPTY) {
            result->rollback_status =
                scan_status != FM_OK ? (int)scan_status : -1;
            result->active = true;
            snprintf(result->detail, sizeof(result->detail),
                     "egress ACL owner absence was not proven");
            return -1;
        }
        result->active = false;
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL owner match rolled back and cleaned");
        return 0;
    }

    result->active = true;
    snprintf(result->detail, sizeof(result->detail),
             "egress ACL owner match rollback failed: %s",
             fmErrorMsg(result->cleanup_status));
    return result->cleanup_status;
}

static hal_acl_policer_owner_transaction_before
acl_policer_before_from_args(
    const hal_acl_policer_owner_args *args) {
    hal_acl_policer_owner_transaction_before before;

    memset(&before, 0, sizeof(before));
    if (args) {
        before.port = args->port;
        before.dst_mac = owner_dst_mac(args);
        before.rate_kbps = args->rate_kbps;
        before.burst_bytes = args->burst_bytes;
    }
    return before;
}

static hal_acl_policer_owner_args acl_policer_args_from_before(
    const hal_acl_policer_owner_transaction_before *before) {
    hal_acl_policer_owner_args args;

    memset(&args, 0, sizeof(args));
    if (before) {
        args.port = before->port;
        args.dst_mac = before->dst_mac;
        args.rate_kbps = before->rate_kbps;
        args.burst_bytes = before->burst_bytes;
    }
    return args;
}

static hal_acl_egress_owner_transaction_before
acl_egress_before_from_args(
    const hal_acl_egress_owner_args *args) {
    hal_acl_egress_owner_transaction_before before;

    memset(&before, 0, sizeof(before));
    if (args) {
        before.port = args->port;
        before.src_mac = args->src_mac;
        before.dst_mac = args->dst_mac;
    }
    return before;
}

static hal_acl_egress_owner_args acl_egress_args_from_before(
    const hal_acl_egress_owner_transaction_before *before) {
    hal_acl_egress_owner_args args;

    memset(&args, 0, sizeof(args));
    if (before) {
        args.port = before->port;
        args.src_mac = before->src_mac;
        args.dst_mac = before->dst_mac;
    }
    return args;
}

static bool acl_policer_args_equal(
    const hal_acl_policer_owner_transaction_before *a,
    const hal_acl_policer_owner_transaction_before *b) {
    return a && b &&
           a->port == b->port &&
           a->dst_mac == b->dst_mac &&
           a->rate_kbps == b->rate_kbps &&
           a->burst_bytes == b->burst_bytes;
}

static bool acl_egress_args_equal(
    const hal_acl_egress_owner_transaction_before *a,
    const hal_acl_egress_owner_transaction_before *b) {
    return a && b &&
           a->port == b->port &&
           a->src_mac == b->src_mac &&
           a->dst_mac == b->dst_mac;
}

static bool acl_shared_creation_token_shape_valid(
    const hal_acl_shared_creation_token *token,
    hal_acl_shared_creator creator) {
    return token &&
           (!token->valid ||
            (token->sw >= 0 &&
             token->acl == NETLAB_ACL_POLICER_PROBE_ACL_ID &&
             token->creator == creator &&
             token->generation != 0));
}

static bool acl_policer_snapshot_valid(
    const hal_acl_policer_owner_args *desired,
    const hal_acl_policer_owner_transaction_snapshot *snapshot) {
    hal_acl_policer_owner_transaction_before expected;
    hal_acl_policer_owner_args before_args;

    if (!acl_policer_owner_args_valid(desired) || !snapshot ||
        snapshot->sdk_status != FM_OK ||
        (snapshot->state != HAL_TRANSACTION_SNAPSHOT_ABSENT &&
         snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT) ||
        snapshot->slot < -1 ||
        snapshot->slot >= NETLAB_ACL_POLICER_OWNER_MAX_SLOTS ||
        !acl_shared_creation_token_shape_valid(
            &snapshot->shared_acl_creation,
            HAL_ACL_SHARED_CREATOR_POLICER) ||
        (snapshot->shared_acl_present &&
         snapshot->shared_acl_creation.valid))
        return false;
    expected = acl_policer_before_from_args(desired);
    if (snapshot->state == HAL_TRANSACTION_SNAPSHOT_ABSENT)
        return acl_policer_args_equal(&snapshot->before, &expected);
    before_args = acl_policer_args_from_before(&snapshot->before);
    return snapshot->shared_acl_present &&
           !snapshot->shared_acl_creation.valid &&
           snapshot->slot >= 0 &&
           acl_policer_owner_args_valid(&before_args) &&
           snapshot->before.port == expected.port &&
           snapshot->before.dst_mac == expected.dst_mac;
}

static bool acl_egress_snapshot_valid(
    const hal_acl_egress_owner_args *desired,
    const hal_acl_egress_owner_transaction_snapshot *snapshot) {
    hal_acl_egress_owner_transaction_before expected;
    hal_acl_egress_owner_args before_args;

    if (!acl_egress_owner_args_valid(desired) || !snapshot ||
        snapshot->sdk_status != FM_OK ||
        (snapshot->state != HAL_TRANSACTION_SNAPSHOT_ABSENT &&
         snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT) ||
        snapshot->slot < -1 ||
        snapshot->slot >= NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS)
        return false;
    expected = acl_egress_before_from_args(desired);
    if (!acl_egress_args_equal(&snapshot->before, &expected))
        return false;
    if (snapshot->state == HAL_TRANSACTION_SNAPSHOT_ABSENT)
        return true;
    before_args = acl_egress_args_from_before(&snapshot->before);
    return snapshot->acl_present &&
           snapshot->slot >= 0 &&
           acl_egress_owner_args_valid(&before_args);
}

hal_acl_policer_owner_transaction_snapshot
hal_acl_policer_owner_transaction_snapshot_get(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_owner_transaction_query query) {
    hal_acl_policer_owner_transaction_snapshot snapshot;
    acl_policer_live_slot
        slots[NETLAB_ACL_POLICER_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;
    bool acl_present = false;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    snapshot.slot = -1;
    if (!acl_policer_owner_args_valid(args) ||
        (query != HAL_ACL_OWNER_QUERY_SET_SEMANTIC &&
         query != HAL_ACL_OWNER_QUERY_DELETE_EXACT))
        return snapshot;
    snapshot.before = acl_policer_before_from_args(args);
    if (acl_policer_slots_scan(
            sw, slots, &acl_present, &scan_status) != 0) {
        snapshot.sdk_status = (int)scan_status;
        return snapshot;
    }
    snapshot.shared_acl_present = acl_present;
    for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
        if (!acl_policer_semantic_match(sw, &slots[i], args))
            continue;
        snapshot.slot = i;
        if (slots[i].state != ACL_LIVE_OWNER ||
            (query == HAL_ACL_OWNER_QUERY_DELETE_EXACT &&
             !acl_policer_exact_match(sw, &slots[i], args))) {
            snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
            return snapshot;
        }
        snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
        snapshot.sdk_status = FM_OK;
        snapshot.before.port = slots[i].port;
        snapshot.before.dst_mac = slots[i].dst_mac;
        snapshot.before.rate_kbps = slots[i].rate_kbps;
        snapshot.before.burst_bytes = slots[i].burst_bytes;
        return snapshot;
    }
    if (query == HAL_ACL_OWNER_QUERY_SET_SEMANTIC) {
        for (int i = 0; i < NETLAB_ACL_POLICER_OWNER_MAX_SLOTS; i++) {
            if (slots[i].state == ACL_LIVE_EMPTY) {
                snapshot.slot = i;
                break;
            }
        }
    }
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_ABSENT;
    snapshot.sdk_status = FM_OK;
    return snapshot;
}

int hal_acl_policer_owner_transaction_apply(
    int sw, const hal_acl_policer_owner_args *args,
    hal_acl_policer_owner_transaction_snapshot *snapshot,
    hal_acl_policer_owner_result *result) {
    hal_acl_shared_creation_token creation_token;
    int status;

    if (!result || !acl_policer_snapshot_valid(args, snapshot) ||
        snapshot->shared_acl_creation.valid)
        return -1;
    if (shared_acl_apply_precondition(
            sw, NETLAB_ACL_POLICER_PROBE_ACL_ID,
            snapshot->shared_acl_present) != 0)
        return -1;

    clear_acl_shared_creation_token(
        &snapshot->shared_acl_creation);
    status = acl_policer_owner_apply_internal(
        sw, args, -1, true, &creation_token, result);
    if (creation_token.valid) {
        snapshot->shared_acl_creation = creation_token;
        if (claim_acl_shared_creation_token(
                &creation_token) != 0)
            return -1;
    }
    return status;
}

hal_acl_egress_owner_transaction_snapshot
hal_acl_egress_owner_transaction_snapshot_get(
    int sw, const hal_acl_egress_owner_args *args,
    hal_acl_owner_transaction_query query) {
    hal_acl_egress_owner_transaction_snapshot snapshot;
    acl_egress_live_slot
        slots[NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS];
    fm_status scan_status = FM_OK;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    snapshot.slot = -1;
    if (!acl_egress_owner_args_valid(args) ||
        (query != HAL_ACL_OWNER_QUERY_SET_SEMANTIC &&
         query != HAL_ACL_OWNER_QUERY_DELETE_EXACT))
        return snapshot;
    snapshot.before = acl_egress_before_from_args(args);
    if (acl_egress_slots_scan(sw, slots, &scan_status) != 0) {
        snapshot.sdk_status = (int)scan_status;
        return snapshot;
    }
    for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
        if (!acl_egress_semantic_match(sw, &slots[i], args))
            continue;
        snapshot.slot = i;
        if (slots[i].state != ACL_LIVE_OWNER ||
            (query == HAL_ACL_OWNER_QUERY_DELETE_EXACT &&
             !acl_egress_exact_match(sw, &slots[i], args))) {
            snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
            return snapshot;
        }
        snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
        snapshot.sdk_status = FM_OK;
        snapshot.acl_present = true;
        snapshot.before.port = slots[i].port;
        snapshot.before.src_mac = slots[i].src_mac;
        snapshot.before.dst_mac = slots[i].dst_mac;
        return snapshot;
    }
    if (query == HAL_ACL_OWNER_QUERY_SET_SEMANTIC) {
        for (int i = 0; i < NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS; i++) {
            if (slots[i].state == ACL_LIVE_EMPTY) {
                snapshot.slot = i;
                snapshot.acl_present = false;
                break;
            }
        }
    }
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_ABSENT;
    snapshot.sdk_status = FM_OK;
    return snapshot;
}

int hal_acl_policer_owner_transaction_restore(
    int sw, const hal_acl_policer_owner_args *desired,
    const hal_acl_policer_owner_transaction_snapshot *snapshot) {
    hal_acl_policer_owner_transaction_snapshot current;
    hal_acl_policer_owner_result result;
    hal_acl_policer_owner_args current_args;
    hal_acl_policer_owner_args before_args;

    if (!acl_policer_snapshot_valid(desired, snapshot) ||
        (snapshot->shared_acl_creation.valid &&
         snapshot->shared_acl_creation.sw != sw))
        return -1;
    current = hal_acl_policer_owner_transaction_snapshot_get(
        sw, desired, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    if (current.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return -1;
    if (snapshot->state == HAL_TRANSACTION_SNAPSHOT_ABSENT) {
        if (current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT) {
            current_args = acl_policer_args_from_before(&current.before);
            memset(&result, 0, sizeof(result));
            if (hal_acl_policer_owner_rollback_match(
                    sw, &current_args, &result) != 0)
                return -1;
        }
        current = hal_acl_policer_owner_transaction_snapshot_get(
            sw, desired, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
        if (current.state != HAL_TRANSACTION_SNAPSHOT_ABSENT)
            return -1;
        if (snapshot->shared_acl_present)
            return current.shared_acl_present ? 0 : -1;
        if (reconcile_shared_acl_absent_before(
                sw, NETLAB_ACL_POLICER_PROBE_ACL_ID,
                HAL_ACL_SHARED_CREATOR_POLICER,
                &snapshot->shared_acl_creation) != FM_OK)
            return -1;
        return 0;
    }
    if (snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        !snapshot->shared_acl_present ||
        snapshot->slot < 0 ||
        snapshot->slot >= NETLAB_ACL_POLICER_OWNER_MAX_SLOTS)
        return -1;
    if (current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        acl_policer_args_equal(&current.before, &snapshot->before) &&
        current.slot == snapshot->slot)
        return 0;
    if (current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT) {
        current_args = acl_policer_args_from_before(&current.before);
        memset(&result, 0, sizeof(result));
        if (hal_acl_policer_owner_rollback_match(
                sw, &current_args, &result) != 0)
            return -1;
    }
    before_args = acl_policer_args_from_before(&snapshot->before);
    memset(&result, 0, sizeof(result));
    hal_acl_shared_creation_token creation_token;

    if (acl_policer_owner_apply_internal(
            sw, &before_args, snapshot->slot, false,
            &creation_token, &result) != 0)
        return -1;
    if (creation_token.valid)
        return -1;
    current = hal_acl_policer_owner_transaction_snapshot_get(
        sw, &before_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    return current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           current.slot == snapshot->slot ? 0 : -1;
}

int hal_acl_egress_owner_transaction_restore(
    int sw, const hal_acl_egress_owner_args *desired,
    const hal_acl_egress_owner_transaction_snapshot *snapshot) {
    hal_acl_egress_owner_transaction_snapshot current;
    hal_acl_egress_owner_result result;
    hal_acl_egress_owner_args current_args;
    hal_acl_egress_owner_args before_args;

    if (!acl_egress_snapshot_valid(desired, snapshot))
        return -1;
    current = hal_acl_egress_owner_transaction_snapshot_get(
        sw, desired, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    if (current.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return -1;
    if (snapshot->state == HAL_TRANSACTION_SNAPSHOT_ABSENT) {
        if (current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT) {
            current_args = acl_egress_args_from_before(&current.before);
            memset(&result, 0, sizeof(result));
            if (hal_acl_egress_owner_rollback_match(
                    sw, &current_args, &result) != 0)
                return -1;
        }
        current = hal_acl_egress_owner_transaction_snapshot_get(
            sw, desired, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
        return current.state == HAL_TRANSACTION_SNAPSHOT_ABSENT ? 0 : -1;
    }
    if (snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        !snapshot->acl_present ||
        snapshot->slot < 0 ||
        snapshot->slot >= NETLAB_ACL_EGRESS_OWNER_MAX_SLOTS)
        return -1;
    if (current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        acl_egress_args_equal(&current.before, &snapshot->before) &&
        current.slot == snapshot->slot)
        return 0;
    if (current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT) {
        current_args = acl_egress_args_from_before(&current.before);
        memset(&result, 0, sizeof(result));
        if (hal_acl_egress_owner_rollback_match(
                sw, &current_args, &result) != 0)
            return -1;
    }
    before_args = acl_egress_args_from_before(&snapshot->before);
    memset(&result, 0, sizeof(result));
    if (acl_egress_owner_apply_internal(
            sw, &before_args, snapshot->slot, &result) != 0)
        return -1;
    current = hal_acl_egress_owner_transaction_snapshot_get(
        sw, &before_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    return current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           current.slot == snapshot->slot ? 0 : -1;
}

int hal_acl_general_allocator_apply(
    int sw, const hal_acl_general_allocator_args *args,
    hal_acl_general_allocator_result *result) {
    hal_acl_resource_reservation ingress;
    hal_acl_resource_reservation egress;
    acl_general_profile profile;
    int mismatches = 0;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (general_acl_profile_from_args(args, &profile) != 0) {
        fill_general_allocator_defaults(
            result, ACL_GENERAL_PROFILE_INGRESS_COUNT_AND_POLICER);
        snprintf(result->detail, sizeof(result->detail),
                 "unsupported general ACL compiler profile");
        return -1;
    }
    fill_general_allocator_defaults(result, profile);
    snprintf(result->detail, sizeof(result->detail), "not-run");

    if (g_acl_general_allocator_active) {
        result->active = true;
        result->compared = 1;
        result->owner_count = general_allocator_owner_count(sw, &mismatches);
        result->mismatches = mismatches;
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL allocator already active");
        return -1;
    }

    const hal_acl_resource_spec ingress_spec = {
        .owner = HAL_ACL_OWNER_GENERAL_INGRESS,
        .name = "general-ingress-acl-allocator",
        .preferred_acl = NETLAB_ACL_GENERAL_INGRESS_ACL_START,
        .acl_count = NETLAB_ACL_GENERAL_INGRESS_ACL_COUNT,
        .rules_per_acl = NETLAB_ACL_GENERAL_INGRESS_RULES_PER_ACL,
        .first_policer = NETLAB_ACL_GENERAL_INGRESS_POLICER_START,
        .policer_count = NETLAB_ACL_GENERAL_INGRESS_POLICER_COUNT,
    };
    const hal_acl_resource_spec egress_spec = {
        .owner = HAL_ACL_OWNER_GENERAL_EGRESS,
        .name = "general-egress-acl-allocator",
        .preferred_acl = NETLAB_ACL_GENERAL_EGRESS_ACL_START,
        .acl_count = NETLAB_ACL_GENERAL_EGRESS_ACL_COUNT,
        .rules_per_acl = NETLAB_ACL_GENERAL_EGRESS_RULES_PER_ACL,
        .first_policer = 0,
        .policer_count = 0,
    };

    memset(&ingress, 0, sizeof(ingress));
    memset(&egress, 0, sizeof(egress));
    result->reserve_ingress_status =
        hal_acl_resource_reserve(sw, &ingress_spec, &ingress);
    if (result->reserve_ingress_status != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ingress ACL allocator reservation failed");
        return -1;
    }

    result->reserve_egress_status =
        hal_acl_resource_reserve(sw, &egress_spec, &egress);
    if (result->reserve_egress_status != 0) {
        hal_acl_resource_release_owner(sw, HAL_ACL_OWNER_GENERAL_INGRESS);
        snprintf(result->detail, sizeof(result->detail),
                 "general egress ACL allocator reservation failed");
        return -1;
    }

    result->owner_count = general_allocator_owner_count(sw, &mismatches);
    result->compared = 1;
    result->mismatches = mismatches;
    if (result->owner_count != 2 || mismatches != 0) {
        hal_acl_resource_release_owner(sw, HAL_ACL_OWNER_GENERAL_EGRESS);
        hal_acl_resource_release_owner(sw, HAL_ACL_OWNER_GENERAL_INGRESS);
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL allocator read-back mismatch");
        return -1;
    }

    if (apply_general_allocator_compiler_smoke(sw, profile, result) != 0) {
        cleanup_general_allocator_compiler(sw, result, true);
        hal_acl_resource_release_owner(sw, HAL_ACL_OWNER_GENERAL_EGRESS);
        hal_acl_resource_release_owner(sw, HAL_ACL_OWNER_GENERAL_INGRESS);
        return -1;
    }

    g_acl_general_allocator_active = true;
    g_acl_general_allocator_port = result->compiler_port;
    g_acl_general_allocator_port_set = result->compiler_port_set;
    g_acl_general_allocator_profile = profile;
    result->active = true;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "general ACL allocator reserved and compiler smoke verified");
    return 0;
}

int hal_acl_general_allocator_readback(
    int sw, hal_acl_general_allocator_result *result) {
    int mismatches = 0;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    fill_general_allocator_defaults(result, g_acl_general_allocator_profile);
    result->active = g_acl_general_allocator_active;
    result->compiler_port = g_acl_general_allocator_port;
    result->compiler_port_set = g_acl_general_allocator_port_set;
    result->owner_count = general_allocator_owner_count(sw, &mismatches);
    result->compared = g_acl_general_allocator_active ? 1 : 0;
    result->mismatches = mismatches;

    if (!g_acl_general_allocator_active) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no active general ACL allocator");
        return 0;
    }

    if (read_general_allocator_compiler_state(
            sw, g_acl_general_allocator_profile, result) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL allocator compiler smoke mismatch");
        return -1;
    }

    if (result->owner_count == 2 && mismatches == 0) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL allocator read-back and compiler smoke verified");
        return 0;
    }

    snprintf(result->detail, sizeof(result->detail),
             "general ACL allocator read-back mismatch");
    return -1;
}

int hal_acl_general_allocator_rollback(
    int sw, hal_acl_general_allocator_result *result) {
    int mismatches = 0;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    fill_general_allocator_defaults(result, g_acl_general_allocator_profile);
    if (!g_acl_general_allocator_active) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no active general ACL allocator");
        return 0;
    }

    result->compiler_port = g_acl_general_allocator_port;
    result->compiler_port_set = g_acl_general_allocator_port_set;
    cleanup_general_allocator_compiler(sw, result, true);
    if (result->compiler_cleanup_status != 0) {
        result->active = true;
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL allocator compiler cleanup failed: %s",
                 fmErrorMsg(result->compiler_cleanup_status));
        return result->compiler_cleanup_status;
    }

    result->rollback_egress_status =
        hal_acl_resource_release_owner(sw, HAL_ACL_OWNER_GENERAL_EGRESS);
    result->rollback_ingress_status =
        hal_acl_resource_release_owner(sw, HAL_ACL_OWNER_GENERAL_INGRESS);
    g_acl_general_allocator_active = false;
    g_acl_general_allocator_port = 0;
    g_acl_general_allocator_port_set = -1;
    g_acl_general_allocator_profile =
        ACL_GENERAL_PROFILE_INGRESS_COUNT_AND_POLICER;
    result->owner_count = general_allocator_owner_count(sw, &mismatches);
    result->compared = 1;
    result->mismatches = mismatches;
    if (result->owner_count != 0 || mismatches != 0 ||
        result->rollback_ingress_status < 0 ||
        result->rollback_egress_status < 0) {
        result->active = true;
        snprintf(result->detail, sizeof(result->detail),
                 "general ACL allocator rollback mismatch");
        return -1;
    }

    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "general ACL allocator rolled back and cleaned");
    return 0;
}

static void cleanup_independent_ingress_owner(
    int sw, const acl_independent_live_slot *live,
    hal_acl_independent_result *result) {
    fm_status st;
    char detail[128];
    bool need_apply = false;

    if (!live || !independent_slot_valid(live->slot))
        return;
    if (live->acl > 0 && live->rule >= 0) {
        st = fmDeleteACLRule(
            (fm_int)sw, (fm_int)live->acl, (fm_int)live->rule);
        if (result && result->cleanup_status == 0 && !status_missing_ok(st))
            result->cleanup_status = (int)st;
        if (status_missing_ok(st))
            need_apply = true;
    }
    if (need_apply) {
        memset(detail, 0, sizeof(detail));
        st = compile_and_apply_acl(sw, detail, sizeof(detail));
        if (result && result->cleanup_status == 0 && st != FM_OK)
            result->cleanup_status = (int)st;
        if (st != FM_OK)
            NL_LOG_WARN("independent ACL cleanup compile/apply failed: %s",
                        detail);
    }
    if (live->policer > 0) {
        st = fmDeletePolicer((fm_int)sw, (fm_int)live->policer);
        if (result && result->cleanup_status == 0 && !status_missing_ok(st))
            result->cleanup_status = (int)st;
    }
    if (live->port_set >= 0) {
        st = fmDeletePortSet((fm_int)sw, (fm_int)live->port_set);
        if (result && result->cleanup_status == 0 &&
            st != FM_OK && st != FM_ERR_INVALID_PORT_SET)
            result->cleanup_status = (int)st;
    }
    if (!result || result->cleanup_status == 0)
        memset(&g_acl_independent_owner[live->slot], 0,
               sizeof(g_acl_independent_owner[live->slot]));
}

static void cleanup_created_shared_acl_for_independent(
    int sw, hal_acl_shared_creation_token *creation_token,
    hal_acl_independent_result *result) {
    fm_status st;

    if (!creation_token || !creation_token->valid)
        return;
    st = release_shared_acl_created_empty(
        sw, HAL_ACL_SHARED_CREATOR_INDEPENDENT,
        creation_token);
    if (result && result->cleanup_status == 0 && st != FM_OK)
        result->cleanup_status = (int)st;
    if (st == FM_OK)
        clear_acl_shared_creation_token(creation_token);
}

static int read_independent_ingress_live_state(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_result *result) {
    acl_independent_live_slot live;
    fm_aclCounters counters;
    fm_status st;

    if (!args || !result || !independent_slot_valid(args->slot))
        return -1;
    if (acl_independent_slot_get(sw, args, &live) != 0) {
        result->read_status = (int)live.sdk_status;
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL live scan failed: %s",
                 fmErrorMsg(live.sdk_status));
        return -1;
    }
    fill_independent_identity(result, args, live.acl, live.policer);
    result->port_set = live.port_set;
    result->active = live.semantic_match;
    if (!live.semantic_match) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no matching independent ACL owner");
        return 0;
    }
    result->compared++;
    if (live.state != ACL_LIVE_OWNER || !live.exact_match) {
        result->mismatches++;
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL owner exact read-back mismatch");
        return -1;
    }

    memset(&counters, 0, sizeof(counters));
    st = fmGetACLCountExt((fm_int)sw, (fm_int)result->acl,
                          (fm_int)result->rule, &counters);
    result->read_status = (int)st;
    result->compared++;
    if (st != FM_OK) {
        result->mismatches++;
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL counter read failed: %s", fmErrorMsg(st));
        return (int)st;
    }
    result->packets = counters.cntPkts;
    result->octets = counters.cntOctets;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "independent ACL owner live read-back verified");
    return 0;
}

static int acl_independent_apply_internal(
    int sw, const hal_acl_independent_args *args,
    bool allow_shared_acl_create,
    hal_acl_shared_creation_token *creation_token,
    hal_acl_independent_result *result) {
    hal_acl_resource_reservation reservation;
    acl_independent_live_slot live;
    fm_aclValue value;
    fm_aclParamExt param;
    fm_aclActionExt action = 0;
    fm_aclCondition cond = 0;
    fm_int port_set = -1;
    fm_status detail_status = FM_OK;
    fm_status st;
    bool acl_present = false;
    int slot;
    int policer = 0;

    if (!args || !result)
        return -1;
    clear_acl_shared_creation_token(creation_token);
    memset(result, 0, sizeof(*result));
    snprintf(result->detail, sizeof(result->detail), "not-run");

    if (independent_is_egress(args)) {
        result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "independent egress ACL owner is deferred");
        return -1;
    }
    if (!independent_args_valid(args)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid independent ACL owner arguments");
        return -1;
    }

    slot = args->slot;
    if (acl_independent_slot_get(sw, args, &live) != 0) {
        result->read_status = (int)live.sdk_status;
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL live scan failed: %s",
                 fmErrorMsg(live.sdk_status));
        return -1;
    }
    if (acl_presence_get(
            sw, independent_acl_default(), &acl_present,
            &detail_status) != 0) {
        result->read_status = (int)detail_status;
        snprintf(result->detail, sizeof(result->detail),
                 "shared independent ACL live read failed");
        return -1;
    }
    if (live.state != ACL_LIVE_EMPTY) {
        fill_independent_identity(
            result, args, live.acl, live.policer);
        result->port_set = live.port_set;
        result->active = live.semantic_match;
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL deterministic slot is occupied");
        return -1;
    }

    const hal_acl_resource_spec ingress_spec = {
        .owner = HAL_ACL_OWNER_GENERAL_INGRESS,
        .name = "general-ingress-acl-allocator",
        .preferred_acl = NETLAB_ACL_INDEPENDENT_SHARED_ACL_ID,
        .acl_count = NETLAB_ACL_INDEPENDENT_SHARED_ACL_COUNT,
        .rules_per_acl = NETLAB_ACL_GENERAL_INGRESS_RULES_PER_ACL,
        .first_policer = NETLAB_ACL_GENERAL_INGRESS_POLICER_START,
        .policer_count = NETLAB_ACL_GENERAL_INGRESS_POLICER_COUNT,
    };
    memset(&reservation, 0, sizeof(reservation));
    if (hal_acl_resource_reserve(sw, &ingress_spec, &reservation) != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL resource reservation failed");
        NL_LOG_ERR("independent ACL resource reservation failed group=%s term=%s family=%s",
                   args->group, args->term, args->family);
        return -1;
    }
    if (reservation.acl != independent_acl_default() ||
        reservation.first_policer !=
            NETLAB_ACL_GENERAL_INGRESS_POLICER_START) {
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL reservation identity mismatch");
        return -1;
    }
    policer = independent_wants_policer(args) ?
              reservation.first_policer + slot : 0;
    fill_independent_identity(result, args, reservation.acl, policer);

    if (!acl_present && !allow_shared_acl_create) {
        snprintf(result->detail, sizeof(result->detail),
                 "shared independent ACL disappeared before owner restore");
        return -1;
    }
    if (!acl_present) {
        st = create_shared_acl_exact_with_token(
            sw, result->acl, HAL_ACL_SHARED_CREATOR_INDEPENDENT,
            creation_token);
        if (st != FM_OK) {
            cleanup_created_shared_acl_for_independent(
                sw, creation_token, result);
            snprintf(result->detail, sizeof(result->detail),
                     "shared independent ACL create/read-back failed: %s",
                     fmErrorMsg(st));
            return (int)st;
        }
    }

    st = fmCreatePortSet((fm_int)sw, &port_set);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL port-set create failed: %s",
                 fmErrorMsg(st));
        NL_LOG_ERR("independent ACL port-set create failed group=%s term=%s: %s",
                   args->group, args->term, fmErrorMsg(st));
        cleanup_created_shared_acl_for_independent(
            sw, creation_token, result);
        return (int)st;
    }
    result->port_set = (int)port_set;

    st = fmAddPortSetPort((fm_int)sw, port_set, (fm_int)args->port);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL port-set add failed: %s", fmErrorMsg(st));
        NL_LOG_ERR("independent ACL port-set add failed group=%s term=%s port=%d: %s",
                   args->group, args->term, args->port, fmErrorMsg(st));
        fmDeletePortSet((fm_int)sw, port_set);
        cleanup_created_shared_acl_for_independent(
            sw, creation_token, result);
        return (int)st;
    }

    if (independent_wants_policer(args)) {
        st = create_owner_policer(sw, policer, args->rate_kbps,
                                  args->burst_bytes);
        if (st != FM_OK) {
            snprintf(result->detail, sizeof(result->detail),
                     "independent ACL policer create failed: %s",
                     fmErrorMsg(st));
            NL_LOG_ERR("independent ACL policer create failed group=%s term=%s policer=%d: %s",
                       args->group, args->term, policer, fmErrorMsg(st));
            fmDeletePortSet((fm_int)sw, port_set);
            cleanup_created_shared_acl_for_independent(
                sw, creation_token, result);
            return (int)st;
        }
    }

    cond = fill_independent_acl_term(args, port_set, policer, &value,
                                     &action, &param);
    st = fmAddACLRuleExt((fm_int)sw, (fm_int)result->acl,
                         (fm_int)result->rule, cond, &value, action,
                         &param);
    if (st != FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL rule add failed: %s", fmErrorMsg(st));
        NL_LOG_ERR("independent ACL rule add failed group=%s term=%s acl=%d rule=%d cond=0x%llx action=0x%llx: %s",
                   args->group, args->term, result->acl, result->rule,
                   (unsigned long long)cond, (unsigned long long)action,
                   fmErrorMsg(st));
        if (policer > 0)
            fmDeletePolicer((fm_int)sw, (fm_int)policer);
        fmDeletePortSet((fm_int)sw, port_set);
        cleanup_created_shared_acl_for_independent(
            sw, creation_token, result);
        return (int)st;
    }

    st = compile_and_apply_acl(sw, result->detail, sizeof(result->detail));
    if (st != FM_OK) {
        acl_independent_live_slot created_live;

        NL_LOG_ERR("independent ACL compile/apply failed group=%s term=%s acl=%d rule=%d port=%d vid=%d cond=0x%llx action=0x%llx: %s",
                   args->group, args->term, result->acl, result->rule,
                   args->port, args->vid, (unsigned long long)cond,
                   (unsigned long long)action, result->detail);
        memset(&created_live, 0, sizeof(created_live));
        created_live.slot = slot;
        created_live.acl = result->acl;
        created_live.rule = result->rule;
        created_live.policer = policer;
        created_live.port_set = (int)port_set;
        cleanup_independent_ingress_owner(
            sw, &created_live, result);
        cleanup_created_shared_acl_for_independent(
            sw, creation_token, result);
        return (int)st;
    }

    g_acl_independent_owner[slot].active = true;
    g_acl_independent_owner[slot].args = *args;
    g_acl_independent_owner[slot].acl = result->acl;
    g_acl_independent_owner[slot].rule = result->rule;
    g_acl_independent_owner[slot].policer = policer;
    g_acl_independent_owner[slot].port_set = (int)port_set;
    result->active = true;
    if (read_independent_ingress_live_state(sw, args, result) != 0) {
        acl_independent_live_slot created_live;

        memset(&created_live, 0, sizeof(created_live));
        created_live.slot = slot;
        created_live.acl = result->acl;
        created_live.rule = result->rule;
        created_live.policer = policer;
        created_live.port_set = (int)port_set;
        cleanup_independent_ingress_owner(
            sw, &created_live, result);
        cleanup_created_shared_acl_for_independent(
            sw, creation_token, result);
        return -1;
    }
    return 0;
}

int hal_acl_independent_apply(int sw,
                              const hal_acl_independent_args *args,
                              hal_acl_independent_result *result) {
    hal_acl_shared_creation_token creation_token;
    int status;

    status = acl_independent_apply_internal(
        sw, args, true, &creation_token, result);
    if (creation_token.valid)
        abandon_acl_shared_creation_token(&creation_token);
    return status;
}

int hal_acl_independent_readback_match(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_result *result) {
    if (!args || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (independent_is_egress(args)) {
        result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "independent egress ACL owner is deferred");
        return -1;
    }
    if (!independent_slot_valid(args->slot)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid independent ACL slot");
        return -1;
    }
    return read_independent_ingress_live_state(sw, args, result);
}

int hal_acl_independent_rollback_match(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_result *result) {
    acl_independent_live_slot live;
    acl_independent_live_slot after;

    if (!args || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (independent_is_egress(args)) {
        result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "independent egress ACL owner is deferred");
        return -1;
    }
    if (!independent_slot_valid(args->slot)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid independent ACL slot");
        return -1;
    }
    if (acl_independent_slot_get(sw, args, &live) != 0) {
        result->read_status = (int)live.sdk_status;
        return -1;
    }
    fill_independent_identity(
        result, args, live.acl, live.policer);
    result->port_set = live.port_set;
    if (!live.semantic_match) {
        result->ok = true;
        snprintf(result->detail, sizeof(result->detail),
                 "no matching independent ACL owner");
        return 0;
    }
    if (live.state != ACL_LIVE_OWNER || !live.exact_match) {
        result->active = true;
        result->mismatches = 1;
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL delete requires exact live match");
        return -1;
    }

    cleanup_independent_ingress_owner(sw, &live, result);
    result->rollback_status = result->cleanup_status;
    if (result->cleanup_status != 0) {
        result->active = true;
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL rollback failed: %s",
                 fmErrorMsg(result->cleanup_status));
        return result->cleanup_status;
    }
    if (acl_independent_slot_get(sw, args, &after) != 0 ||
        after.state != ACL_LIVE_EMPTY) {
        result->active = true;
        result->rollback_status =
            after.sdk_status != FM_OK ? (int)after.sdk_status : -1;
        snprintf(result->detail, sizeof(result->detail),
                 "independent ACL owner absence was not proven");
        return -1;
    }
    result->active = false;
    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "independent ACL owner rolled back and cleaned");
    return 0;
}

static hal_acl_independent_transaction_before
acl_independent_before_from_args(
    const hal_acl_independent_args *args) {
    hal_acl_independent_transaction_before before;

    memset(&before, 0, sizeof(before));
    if (!args)
        return before;
    snprintf(before.group, sizeof(before.group), "%s", args->group);
    snprintf(before.term, sizeof(before.term), "%s", args->term);
    snprintf(before.family, sizeof(before.family), "%s", args->family);
    snprintf(before.action, sizeof(before.action), "%s", args->action);
    before.slot = args->slot;
    before.vid = args->vid;
    before.port = args->port;
    before.has_src_mac = args->has_src_mac;
    before.has_dst_mac = args->has_dst_mac;
    before.src_mac = args->src_mac;
    before.dst_mac = args->dst_mac;
#define COPY_INDEPENDENT_MATCH_TO_BEFORE(field) \
    before.inet_match.field = args->inet_match.field
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_src_ip);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_dst_ip);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_src_ip_mask);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_dst_ip_mask);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_dscp);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_ecn);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_protocol);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_src_port);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_dst_port);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_src_port_range);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_dst_port_range);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_tcp_flags);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(has_tcp_flags_mask);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(count_only);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(src_ip);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(dst_ip);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(src_ip_mask);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(dst_ip_mask);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(dscp);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(ecn);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(protocol);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(src_port);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(dst_port);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(src_port_start);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(src_port_end);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(dst_port_start);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(dst_port_end);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(tcp_flags);
    COPY_INDEPENDENT_MATCH_TO_BEFORE(tcp_flags_mask);
#undef COPY_INDEPENDENT_MATCH_TO_BEFORE
    before.rate_kbps = args->rate_kbps;
    before.burst_bytes = args->burst_bytes;
    return before;
}

static hal_acl_independent_args acl_independent_args_from_before(
    const hal_acl_independent_transaction_before *before) {
    hal_acl_independent_args args;

    memset(&args, 0, sizeof(args));
    if (!before)
        return args;
    snprintf(args.group, sizeof(args.group), "%s", before->group);
    snprintf(args.term, sizeof(args.term), "%s", before->term);
    snprintf(args.family, sizeof(args.family), "%s", before->family);
    snprintf(args.action, sizeof(args.action), "%s", before->action);
    args.slot = before->slot;
    args.vid = before->vid;
    args.port = before->port;
    args.has_src_mac = before->has_src_mac;
    args.has_dst_mac = before->has_dst_mac;
    args.src_mac = before->src_mac;
    args.dst_mac = before->dst_mac;
    args.inet_match.vid = before->vid;
    args.inet_match.port = before->port;
#define COPY_INDEPENDENT_MATCH_FROM_BEFORE(field) \
    args.inet_match.field = before->inet_match.field
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_src_ip);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_dst_ip);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_src_ip_mask);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_dst_ip_mask);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_dscp);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_ecn);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_protocol);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_src_port);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_dst_port);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_src_port_range);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_dst_port_range);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_tcp_flags);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(has_tcp_flags_mask);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(count_only);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(src_ip);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(dst_ip);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(src_ip_mask);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(dst_ip_mask);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(dscp);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(ecn);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(protocol);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(src_port);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(dst_port);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(src_port_start);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(src_port_end);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(dst_port_start);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(dst_port_end);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(tcp_flags);
    COPY_INDEPENDENT_MATCH_FROM_BEFORE(tcp_flags_mask);
#undef COPY_INDEPENDENT_MATCH_FROM_BEFORE
    args.rate_kbps = before->rate_kbps;
    args.burst_bytes = before->burst_bytes;
    return args;
}

static bool acl_independent_before_strings_valid(
    const hal_acl_independent_transaction_before *before) {
    return before &&
           memchr(before->group, '\0', sizeof(before->group)) &&
           memchr(before->term, '\0', sizeof(before->term)) &&
           memchr(before->family, '\0', sizeof(before->family)) &&
           memchr(before->action, '\0', sizeof(before->action));
}

static bool acl_independent_snapshot_valid(
    const hal_acl_independent_args *desired,
    const hal_acl_independent_transaction_snapshot *snapshot) {
    hal_acl_independent_transaction_before expected;
    hal_acl_independent_args before_args;

    if (!desired || !snapshot || !independent_args_valid(desired) ||
        snapshot->sdk_status != FM_OK ||
        snapshot->slot != desired->slot ||
        (snapshot->state != HAL_TRANSACTION_SNAPSHOT_ABSENT &&
         snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT) ||
        !acl_shared_creation_token_shape_valid(
            &snapshot->shared_acl_creation,
            HAL_ACL_SHARED_CREATOR_INDEPENDENT) ||
        (snapshot->shared_acl_present &&
         snapshot->shared_acl_creation.valid) ||
        !acl_independent_before_strings_valid(&snapshot->before))
        return false;
    expected = acl_independent_before_from_args(desired);
    if (snapshot->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
        independent_wants_policer(desired)) {
        expected.rate_kbps = snapshot->before.rate_kbps;
        expected.burst_bytes = snapshot->before.burst_bytes;
    }
    if (memcmp(&snapshot->before, &expected, sizeof(expected)) != 0)
        return false;
    if (snapshot->state == HAL_TRANSACTION_SNAPSHOT_ABSENT)
        return true;
    before_args = acl_independent_args_from_before(&snapshot->before);
    return snapshot->shared_acl_present &&
           !snapshot->shared_acl_creation.valid &&
           independent_args_valid(&before_args);
}

hal_acl_independent_transaction_snapshot
hal_acl_independent_transaction_snapshot_get(
    int sw, const hal_acl_independent_args *args,
    hal_acl_owner_transaction_query query) {
    hal_acl_independent_transaction_snapshot snapshot;
    acl_independent_live_slot live;
    fm_status detail_status = FM_OK;
    bool acl_present = false;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_INVALID_ARGUMENT;
    snapshot.slot = -1;
    if (!args ||
        (query != HAL_ACL_OWNER_QUERY_SET_SEMANTIC &&
         query != HAL_ACL_OWNER_QUERY_DELETE_EXACT) ||
        !independent_args_valid(args))
        return snapshot;
    snapshot.before = acl_independent_before_from_args(args);
    snapshot.slot = args->slot;
    if (acl_presence_get(
            sw, independent_acl_default(), &acl_present,
            &detail_status) != 0) {
        snapshot.sdk_status = (int)detail_status;
        return snapshot;
    }
    snapshot.shared_acl_present = acl_present;
    if (acl_independent_slot_get(sw, args, &live) != 0) {
        snapshot.sdk_status = (int)live.sdk_status;
        return snapshot;
    }
    if (!live.semantic_match) {
        if (query == HAL_ACL_OWNER_QUERY_DELETE_EXACT &&
            live.state != ACL_LIVE_EMPTY)
            return snapshot;
        snapshot.state = HAL_TRANSACTION_SNAPSHOT_ABSENT;
        snapshot.sdk_status = FM_OK;
        return snapshot;
    }
    if (live.state != ACL_LIVE_OWNER ||
        (query == HAL_ACL_OWNER_QUERY_DELETE_EXACT &&
         !live.exact_match))
        return snapshot;
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    if (live.policer > 0) {
        snapshot.before.rate_kbps = live.rate_kbps;
        snapshot.before.burst_bytes = live.burst_bytes;
    }
    return snapshot;
}

int hal_acl_independent_transaction_apply(
    int sw, const hal_acl_independent_args *args,
    hal_acl_independent_transaction_snapshot *snapshot,
    hal_acl_independent_result *result) {
    hal_acl_shared_creation_token creation_token;
    int status;

    if (!result || !acl_independent_snapshot_valid(args, snapshot) ||
        snapshot->shared_acl_creation.valid)
        return -1;
    if (shared_acl_apply_precondition(
            sw, independent_acl_default(),
            snapshot->shared_acl_present) != 0)
        return -1;

    clear_acl_shared_creation_token(
        &snapshot->shared_acl_creation);
    status = acl_independent_apply_internal(
        sw, args, true, &creation_token, result);
    if (creation_token.valid) {
        snapshot->shared_acl_creation = creation_token;
        if (claim_acl_shared_creation_token(
                &creation_token) != 0)
            return -1;
    }
    return status;
}

int hal_acl_independent_transaction_restore(
    int sw, const hal_acl_independent_args *desired,
    const hal_acl_independent_transaction_snapshot *snapshot) {
    hal_acl_independent_transaction_snapshot current;
    hal_acl_independent_transaction_snapshot before_live;
    hal_acl_independent_result result;
    hal_acl_independent_args current_args;
    hal_acl_independent_args before_args;

    if (!acl_independent_snapshot_valid(desired, snapshot) ||
        (snapshot->shared_acl_creation.valid &&
         snapshot->shared_acl_creation.sw != sw))
        return -1;
    current = hal_acl_independent_transaction_snapshot_get(
        sw, desired, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
    if (current.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return -1;
    if (snapshot->state == HAL_TRANSACTION_SNAPSHOT_ABSENT) {
        if (current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT) {
            current_args =
                acl_independent_args_from_before(&current.before);
            memset(&result, 0, sizeof(result));
            if (hal_acl_independent_rollback_match(
                    sw, &current_args, &result) != 0)
                return -1;
        }
        current = hal_acl_independent_transaction_snapshot_get(
            sw, desired, HAL_ACL_OWNER_QUERY_SET_SEMANTIC);
        if (current.state != HAL_TRANSACTION_SNAPSHOT_ABSENT)
            return -1;
        if (snapshot->shared_acl_present)
            return current.shared_acl_present ? 0 : -1;
        if (reconcile_shared_acl_absent_before(
                sw, independent_acl_default(),
                HAL_ACL_SHARED_CREATOR_INDEPENDENT,
                &snapshot->shared_acl_creation) != FM_OK)
            return -1;
        return 0;
    }
    if (snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        !snapshot->shared_acl_present)
        return -1;
    before_args =
        acl_independent_args_from_before(&snapshot->before);
    if (current.state == HAL_TRANSACTION_SNAPSHOT_PRESENT) {
        before_live = hal_acl_independent_transaction_snapshot_get(
            sw, &before_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
        if (before_live.state == HAL_TRANSACTION_SNAPSHOT_PRESENT)
            return 0;
        current_args =
            acl_independent_args_from_before(&current.before);
        memset(&result, 0, sizeof(result));
        if (hal_acl_independent_rollback_match(
                sw, &current_args, &result) != 0)
            return -1;
    }
    before_live = hal_acl_independent_transaction_snapshot_get(
        sw, &before_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    if (before_live.state == HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return 0;
    if (before_live.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR)
        return -1;
    if (!before_live.shared_acl_present)
        return -1;
    memset(&result, 0, sizeof(result));
    hal_acl_shared_creation_token creation_token;

    if (acl_independent_apply_internal(
            sw, &before_args, false,
            &creation_token, &result) != 0)
        return -1;
    if (creation_token.valid)
        return -1;
    before_live = hal_acl_independent_transaction_snapshot_get(
        sw, &before_args, HAL_ACL_OWNER_QUERY_DELETE_EXACT);
    return before_live.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           before_live.slot == snapshot->slot ? 0 : -1;
}

int hal_acl_egress_probe(int sw,
                         const hal_acl_egress_probe_args *args,
                         hal_acl_egress_probe_result *result) {
    fm_aclPortAndType port_and_type;
    fm_aclCondition cond = 0;
    fm_aclValue value;
    fm_aclActionExt action = 0;
    fm_aclParamExt param;
    fm_aclCounters counters;
    fm_status st;
    bool delete_acl = false;

    if (!args || !result)
        return -1;

    memset(result, 0, sizeof(*result));
    result->port = args->port;
    result->src_mac = args->src_mac;
    result->dst_mac = (args->src_mac || args->dst_mac) ?
                      args->dst_mac : NETLAB_ACL_EGRESS_PROBE_DST_MAC;
    result->acl = NETLAB_ACL_EGRESS_PROBE_ACL_ID;
    result->rule = NETLAB_ACL_EGRESS_PROBE_RULE;
    snprintf(result->detail, sizeof(result->detail), "not-run");

    if (args->port <= 0 || !nl_ifid_is_user_port(args->port) ||
        (result->src_mac != 0 && !egress_owner_mac_valid(result->src_mac)) ||
        (result->dst_mac != 0 && !egress_owner_mac_valid(result->dst_mac)) ||
        (result->src_mac == 0 && result->dst_mac == 0)) {
        snprintf(result->detail, sizeof(result->detail),
                 "invalid egress probe arguments");
        return -1;
    }

    st = fmCreateACL((fm_int)sw, (fm_int)result->acl);
    result->create_status = (int)st;
    if (st == FM_OK) {
        delete_acl = true;
    } else if (st != FM_ERR_ALREADY_EXISTS) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL create failed: %s", fmErrorMsg(st));
        return result->unsupported ? 0 : (int)st;
    }

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    st = fmGetACLRule((fm_int)sw, (fm_int)result->acl,
                      (fm_int)result->rule, &cond, &value,
                      &action, &param);
    result->pre_rule_status = (int)st;
    if (st == FM_OK) {
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL probe rule already exists; refusing overwrite");
        if (delete_acl)
            cleanup_egress_probe(sw, result->acl, result->rule,
                                 result->port, delete_acl, result);
        return -1;
    }
    if (!status_missing_ok(st)) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL pre-rule read failed: %s", fmErrorMsg(st));
        cleanup_egress_probe(sw, result->acl, result->rule,
                             result->port, delete_acl, result);
        return result->unsupported && result->cleanup_status == 0 ?
               0 : (result->cleanup_status ? result->cleanup_status : (int)st);
    }

    memset(&port_and_type, 0, sizeof(port_and_type));
    port_and_type.port = (fm_int)args->port;
    port_and_type.type = FM_ACL_TYPE_EGRESS;
    st = fmAddACLPortExt((fm_int)sw, (fm_int)result->acl, &port_and_type);
    result->port_status = (int)st;
    if (st != FM_OK) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL port association failed: %s", fmErrorMsg(st));
        cleanup_egress_probe(sw, result->acl, result->rule,
                             result->port, delete_acl, result);
        return result->unsupported && result->cleanup_status == 0 ?
               0 : (result->cleanup_status ? result->cleanup_status : (int)st);
    }

    memset(&value, 0, sizeof(value));
    memset(&param, 0, sizeof(param));
    cond = fill_egress_mac_value(&value, result->src_mac,
                                 result->dst_mac);
    st = fmAddACLRuleExt((fm_int)sw, (fm_int)result->acl,
                         (fm_int)result->rule,
                         cond,
                         &value,
                         FM_ACL_ACTIONEXT_DENY,
                         &param);
    result->rule_status = (int)st;
    if (st != FM_OK) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL rule add failed: %s", fmErrorMsg(st));
        cleanup_egress_probe(sw, result->acl, result->rule,
                             result->port, delete_acl, result);
        return result->unsupported && result->cleanup_status == 0 ?
               0 : (result->cleanup_status ? result->cleanup_status : (int)st);
    }

    st = compile_and_apply_acl(sw, result->detail, sizeof(result->detail));
    result->compile_status = (int)st;
    result->apply_status = (int)st;
    if (st != FM_OK) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        if (strcmp(result->detail, "not-run") == 0) {
            snprintf(result->detail, sizeof(result->detail),
                     "egress ACL compile/apply failed: %s", fmErrorMsg(st));
        }
        cleanup_egress_probe(sw, result->acl, result->rule,
                             result->port, delete_acl, result);
        return result->unsupported && result->cleanup_status == 0 ?
               0 : (result->cleanup_status ? result->cleanup_status : (int)st);
    }

    memset(&counters, 0, sizeof(counters));
    st = fmGetACLEgressCount((fm_int)sw, (fm_int)args->port, &counters);
    result->read_status = (int)st;
    if (st != FM_OK) {
        if (st == FM_ERR_UNSUPPORTED)
            result->unsupported = true;
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL counter read failed: %s", fmErrorMsg(st));
        cleanup_egress_probe(sw, result->acl, result->rule,
                             result->port, delete_acl, result);
        return result->unsupported && result->cleanup_status == 0 ?
               0 : (result->cleanup_status ? result->cleanup_status : (int)st);
    }
    result->packets = counters.cntPkts;
    result->octets = counters.cntOctets;

    cleanup_egress_probe(sw, result->acl, result->rule,
                         result->port, delete_acl, result);
    if (result->cleanup_status != 0) {
        snprintf(result->detail, sizeof(result->detail),
                 "egress ACL probe passed but cleanup failed: %s",
                 fmErrorMsg(result->cleanup_status));
        return result->cleanup_status;
    }

    result->ok = true;
    snprintf(result->detail, sizeof(result->detail),
             "egress ACL drop path and counter read-back verified and cleaned");
    return 0;
}

int hal_acl_egress_counters(int sw, int port, u64 *packets, u64 *octets) {
    fm_aclCounters counters;
    fm_status st;

    if (packets)
        *packets = 0;
    if (octets)
        *octets = 0;
    if (port <= 0 || !nl_ifid_is_user_port(port))
        return -1;

    memset(&counters, 0, sizeof(counters));
    st = fmGetACLEgressCount((fm_int)sw, (fm_int)port, &counters);
    if (st != FM_OK) {
        NL_LOG_WARN("egress ACL counter read port=%d failed: %s",
                    port, fmErrorMsg(st));
        return (int)st;
    }

    if (packets)
        *packets = counters.cntPkts;
    if (octets)
        *octets = counters.cntOctets;
    return 0;
}
