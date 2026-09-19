#include "hal_flow_table.h"

#include "netlab/hal.h"
#include "netlab/hal_l2_flow_snapshot.h"
#include "netlab/log.h"
#include <string.h>
#include <fm_sdk.h>
#include <api/fm_api_flow.h>

#define L2_SECURITY_TABLE 28
#define L2_SECURITY_FLOW_ACL_BASE 21000000
#define L2_SECURITY_MAX_ENTRIES 64
#define L2_SECURITY_MAX_ACTIONS 2
#define L2_SECURITY_DHCP_SRC_PORT 67
#define L2_SECURITY_DHCP_DST_PORT 68
#define L2_SECURITY_ARP_ETHERTYPE 0x0806
#define L2_SECURITY_VLAN_MASK 0x0fff
#define L2_SECURITY_PORT_MASK 0xffff
#define L2_SECURITY_UDP 17
#define L2_SECURITY_PRIORITY_BINDING 100
#define L2_SECURITY_PRIORITY_USER_FILTER 110
#define L2_SECURITY_PRIORITY_DENY 10
#define L2_SECURITY_ARP_SPA_OFFSET 14
#define L2_SECURITY_ARP_SPA_LEN 4

typedef enum {
    L2_SECURITY_RULE_DHCP,
    L2_SECURITY_RULE_ARP,
    L2_SECURITY_RULE_ARP_BINDING,
    L2_SECURITY_RULE_USER_FILTER,
} l2_security_rule_type;

static fm_int g_l2_security_table = -1;
static hal_flow_table_creation_token g_pending_creation_token;

static hal_flow_presence_snapshot flow_snapshot_init(void) {
    hal_flow_presence_snapshot out;

    memset(&out, 0, sizeof(out));
    out.state = HAL_PRESENCE_READ_ERROR;
    out.sdk_status = FM_ERR_INVALID_ARGUMENT;
    out.table = -1;
    out.first_flow = -1;
    return out;
}

static fm_flowCondition l2_security_table_condition(void) {
    return FM_FLOW_MATCH_VLAN |
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
}

static hal_flow_table_spec l2_security_table_spec(void) {
    hal_flow_table_spec spec = {
        .owner = HAL_FLOW_OWNER_L2_SECURITY,
        .name = "l2-security",
        .preferred_table = L2_SECURITY_TABLE,
        .condition = 0,
        .max_entries = L2_SECURITY_MAX_ENTRIES,
        .max_actions = L2_SECURITY_MAX_ACTIONS,
        .with_priority = false,
    };

    spec.condition = l2_security_table_condition();
    return spec;
}

void hal_l2_security_begin_table_operation(void) {
    memset(&g_pending_creation_token, 0, sizeof(g_pending_creation_token));
    g_pending_creation_token.sw = -1;
    g_pending_creation_token.table = -1;
}

int hal_l2_security_take_created_table_token(
    hal_flow_table_creation_token *creation_token) {
    if (!creation_token)
        return -1;
    *creation_token = g_pending_creation_token;
    hal_l2_security_begin_table_operation();
    return creation_token->valid ? 1 : 0;
}

int hal_l2_security_release_created_table_empty(
    const hal_flow_table_creation_token *creation_token) {
    hal_flow_table_spec spec = l2_security_table_spec();

    if (hal_flow_table_release_created_empty(
            creation_token ? creation_token->sw : -1, &spec,
            creation_token) != 0)
        return -1;
    g_l2_security_table = -1;
    if (creation_token &&
        g_pending_creation_token.valid &&
        g_pending_creation_token.generation == creation_token->generation)
        hal_l2_security_begin_table_operation();
    return 0;
}

static int ensure_l2_security_table(int sw) {
    hal_flow_table_spec spec = l2_security_table_spec();
    hal_flow_table_reservation reservation;
    hal_flow_table_creation_token creation_token;

    memset(&reservation, 0, sizeof(reservation));
    memset(&creation_token, 0, sizeof(creation_token));
    if (hal_flow_table_reserve_with_token(
            sw, &spec, &reservation, &creation_token) != 0) {
        NL_LOG_WARN("L2 security flow table reservation failed");
        return -1;
    }
    if (creation_token.valid) {
        if (g_pending_creation_token.valid) {
            NL_LOG_CRIT("multiple unclaimed L2 security table creation tokens");
            return -1;
        }
        g_pending_creation_token = creation_token;
    }
    g_l2_security_table = reservation.table;
    return 0;
}

static fm_int l2_security_table_for_type(int sw, l2_security_rule_type type) {
    (void)type;
    if (ensure_l2_security_table(sw) != 0)
        return -1;
    return g_l2_security_table;
}

int hal_l2_security_flow_table(int sw) {
    return l2_security_table_for_type(sw, L2_SECURITY_RULE_USER_FILTER);
}

hal_flow_presence_snapshot hal_l2_security_table_snapshot(int sw) {
    hal_flow_presence_snapshot out = flow_snapshot_init();
    fm_int current = -1;
    fm_status st;

    out.table = L2_SECURITY_TABLE;
    st = fmGetFlowFirst((fm_int)sw, &current);
    if (st == FM_ERR_NO_MORE) {
        out.state = HAL_PRESENCE_ABSENT;
        out.sdk_status = (int)st;
        return out;
    }
    if (st != FM_OK) {
        out.sdk_status = (int)st;
        return out;
    }

    for (int scanned = 0; scanned < FM_FLOW_MAX_TABLE_TYPE; scanned++) {
        fm_int next = -1;

        if (current == L2_SECURITY_TABLE) {
            fm_flowTableType type = FM_FLOW_TABLE_MAX;
            fm_flowCondition condition = 0;
            fm_bool with_priority = FM_DISABLED;

            st = fmGetFlowTableType((fm_int)sw, current, &type);
            if (st != FM_OK) {
                out.sdk_status = (int)st;
                return out;
            }
            st = fmGetFlowAttribute((fm_int)sw, current,
                                    FM_FLOW_TABLE_CONDITION, &condition);
            if (st != FM_OK) {
                out.sdk_status = (int)st;
                return out;
            }
            st = fmGetFlowAttribute((fm_int)sw, current,
                                    FM_FLOW_TABLE_WITH_PRIORITY,
                                    &with_priority);
            if (st != FM_OK) {
                out.sdk_status = (int)st;
                return out;
            }
            if (type != FM_FLOW_TCAM_TABLE ||
                (condition & l2_security_table_condition()) !=
                    l2_security_table_condition() ||
                with_priority != 0) {
                out.sdk_status = FM_ERR_INVALID_ARGUMENT;
                return out;
            }
            out.state = HAL_PRESENCE_PRESENT;
            out.sdk_status = FM_OK;
            out.exact = true;
            return out;
        }
        st = fmGetFlowNext((fm_int)sw, current, &next);
        if (st == FM_ERR_NO_MORE) {
            out.state = HAL_PRESENCE_ABSENT;
            out.sdk_status = (int)st;
            return out;
        }
        if (st != FM_OK) {
            out.sdk_status = (int)st;
            return out;
        }
        if (next <= current) {
            out.sdk_status = FM_ERR_MODIFIED_WHILE_ITERATING;
            return out;
        }
        current = next;
    }

    out.sdk_status = FM_ERR_MODIFIED_WHILE_ITERATING;
    return out;
}

int hal_l2_security_flow_enabled_read(int sw, int flow_id, bool *enabled,
                                      int *sdk_status) {
    fm_aclEntryState state = FM_ACL_RULE_ENTRY_STATE_INVALID;
    fm_status st;

    if (enabled)
        *enabled = false;
    if (sdk_status)
        *sdk_status = FM_ERR_INVALID_ARGUMENT;
    if (!enabled || flow_id < 0)
        return -1;

    /*
     * The pinned FM10000 flow implementation maps a non-priority TCAM flow
     * ID directly to ACL rule (FLOW_BASE_ACL + table, flow_id).  Flow state
     * has no Flow-API getter, so the public ACL-state getter is the only
     * authoritative enabled/standby read-back.
     */
    st = fmGetACLRuleState((fm_int)sw,
                           L2_SECURITY_FLOW_ACL_BASE + L2_SECURITY_TABLE,
                           (fm_int)flow_id, &state);
    if (sdk_status)
        *sdk_status = (int)st;
    if (st != FM_OK)
        return -1;
    if (state != FM_ACL_RULE_ENTRY_STATE_INVALID &&
        state != FM_ACL_RULE_ENTRY_STATE_VALID) {
        if (sdk_status)
            *sdk_status = FM_ERR_INVALID_ARGUMENT;
        return -1;
    }
    *enabled = state == FM_ACL_RULE_ENTRY_STATE_VALID;
    return 0;
}

static const char *rule_type_name(l2_security_rule_type type) {
    if (type == L2_SECURITY_RULE_DHCP)
        return "dhcp-snooping";
    if (type == L2_SECURITY_RULE_USER_FILTER)
        return "user-filter";
    if (type == L2_SECURITY_RULE_ARP_BINDING)
        return "arp-inspection-binding";
    return "arp-inspection";
}

static void fill_mac_mask(fm_macaddr *mask) {
    if (mask)
        *mask = 0xffffffffffffULL;
}

static fm_macaddr mac_to_u64(const u8 mac[6]) {
    fm_macaddr out = 0;

    if (!mac)
        return 0;
    for (int i = 0; i < 6; i++)
        out = (out << 8) | mac[i];
    return out;
}

static bool fill_rule(l2_security_rule_type type, u16 vid, int port,
                      const u8 mac[6], int mac_kind, u32 ip,
                      fm_flowCondition *condition, fm_flowValue *value,
                      fm_flowAction *action, fm_uint16 *priority) {
    if (!condition || !value || vid < 1 || vid > 4094 || port <= 0)
        return false;

    memset(value, 0, sizeof(*value));
    if (action)
        *action = FM_FLOW_ACTION_DENY | FM_FLOW_ACTION_COUNT;
    if (priority)
        *priority = L2_SECURITY_PRIORITY_DENY;
    value->vlanId = vid;
    value->vlanIdMask = L2_SECURITY_VLAN_MASK;
    value->logicalPort = (fm_int)port;

    if (type == L2_SECURITY_RULE_DHCP) {
        *condition = FM_FLOW_MATCH_VLAN |
                     FM_FLOW_MATCH_LOGICAL_PORT |
                     FM_FLOW_MATCH_PROTOCOL |
                     FM_FLOW_MATCH_L4_SRC_PORT |
                     FM_FLOW_MATCH_L4_DST_PORT;
        value->protocol = L2_SECURITY_UDP;
        value->protocolMask = 0xff;
        value->L4SrcStart = L2_SECURITY_DHCP_SRC_PORT;
        value->L4SrcMask = L2_SECURITY_PORT_MASK;
        value->L4DstStart = L2_SECURITY_DHCP_DST_PORT;
        value->L4DstMask = L2_SECURITY_PORT_MASK;
        return true;
    }

    if (type == L2_SECURITY_RULE_ARP_BINDING) {
        if (!mac)
            return false;
        *condition = FM_FLOW_MATCH_VLAN |
                     FM_FLOW_MATCH_LOGICAL_PORT |
                     FM_FLOW_MATCH_ETHERTYPE |
                     FM_FLOW_MATCH_SRC_MAC |
                     FM_FLOW_MATCH_L2_DEEP_INSPECTION;
        value->ethType = L2_SECURITY_ARP_ETHERTYPE;
        value->ethTypeMask = 0xffff;
        value->src = mac_to_u64(mac);
        fill_mac_mask(&value->srcMask);
        value->L2DeepInspection[L2_SECURITY_ARP_SPA_OFFSET] =
            (fm_byte)((ip >> 24) & 0xff);
        value->L2DeepInspection[L2_SECURITY_ARP_SPA_OFFSET + 1] =
            (fm_byte)((ip >> 16) & 0xff);
        value->L2DeepInspection[L2_SECURITY_ARP_SPA_OFFSET + 2] =
            (fm_byte)((ip >> 8) & 0xff);
        value->L2DeepInspection[L2_SECURITY_ARP_SPA_OFFSET + 3] =
            (fm_byte)(ip & 0xff);
        for (int i = 0; i < L2_SECURITY_ARP_SPA_LEN; i++)
            value->L2DeepInspectionMask[L2_SECURITY_ARP_SPA_OFFSET + i] = 0xff;
        if (action)
            *action = FM_FLOW_ACTION_PERMIT | FM_FLOW_ACTION_COUNT;
        if (priority)
            *priority = L2_SECURITY_PRIORITY_BINDING;
        return true;
    }

    if (type == L2_SECURITY_RULE_USER_FILTER) {
        if (!mac)
            return false;
        *condition = FM_FLOW_MATCH_VLAN |
                     FM_FLOW_MATCH_LOGICAL_PORT;
        if (mac_kind == L2_SECURITY_MAC_DESTINATION) {
            *condition |= FM_FLOW_MATCH_DST_MAC;
            value->dst = mac_to_u64(mac);
            fill_mac_mask(&value->dstMask);
        } else {
            *condition |= FM_FLOW_MATCH_SRC_MAC;
            value->src = mac_to_u64(mac);
            fill_mac_mask(&value->srcMask);
        }
        if (priority)
            *priority = L2_SECURITY_PRIORITY_USER_FILTER;
        return true;
    }

    *condition = FM_FLOW_MATCH_VLAN |
                 FM_FLOW_MATCH_LOGICAL_PORT |
                 FM_FLOW_MATCH_ETHERTYPE;
    value->ethType = L2_SECURITY_ARP_ETHERTYPE;
    value->ethTypeMask = 0xffff;
    return true;
}

static bool flow_identity_matches(l2_security_rule_type type,
                                  fm_flowCondition actual_cond,
                                  const fm_flowValue *actual,
                                  u16 vid, int port, const u8 mac[6],
                                  int mac_kind, u32 ip) {
    fm_flowCondition expected_cond = 0;
    fm_flowValue expected;

    if (!actual || !fill_rule(type, vid, port, mac, mac_kind, ip,
                              &expected_cond, &expected, NULL, NULL))
        return false;
    if ((actual_cond & expected_cond) != expected_cond)
        return false;
    /*
     * A binding permit is a strict condition superset of the per-port ARP
     * deny.  It must not be counted as that deny's identity, otherwise the
     * binding-set reorder cannot prove and restore the deny once the permit
     * exists in the same table.
     */
    if (type == L2_SECURITY_RULE_ARP &&
        actual_cond != expected_cond)
        return false;
    if (actual->vlanId != expected.vlanId ||
        actual->vlanIdMask != expected.vlanIdMask ||
        actual->logicalPort != expected.logicalPort)
        return false;

    if (type == L2_SECURITY_RULE_DHCP) {
        return actual->protocol == expected.protocol &&
               actual->protocolMask == expected.protocolMask &&
               actual->L4SrcStart == expected.L4SrcStart &&
               actual->L4SrcMask == expected.L4SrcMask &&
               actual->L4DstStart == expected.L4DstStart &&
               actual->L4DstMask == expected.L4DstMask;
    }

    if (type == L2_SECURITY_RULE_ARP_BINDING) {
        if (actual->ethType != expected.ethType ||
            actual->ethTypeMask != expected.ethTypeMask ||
            actual->src != expected.src ||
            actual->srcMask != expected.srcMask)
            return false;
        for (int i = 0; i < L2_SECURITY_ARP_SPA_LEN; i++) {
            int idx = L2_SECURITY_ARP_SPA_OFFSET + i;

            if (actual->L2DeepInspection[idx] !=
                    expected.L2DeepInspection[idx] ||
                actual->L2DeepInspectionMask[idx] !=
                    expected.L2DeepInspectionMask[idx])
                return false;
        }
        return true;
    }

    if (type == L2_SECURITY_RULE_USER_FILTER) {
        if (mac_kind == L2_SECURITY_MAC_DESTINATION)
            return actual->dst == expected.dst &&
                   actual->dstMask == expected.dstMask;
        return actual->src == expected.src &&
               actual->srcMask == expected.srcMask;
    }

    return actual->ethType == expected.ethType &&
           actual->ethTypeMask == expected.ethTypeMask;
}

static bool flow_exact_matches(l2_security_rule_type type,
                               fm_flowCondition actual_cond,
                               const fm_flowValue *actual_value,
                               fm_flowAction actual_action,
                               const fm_flowParam *actual_param,
                               fm_int actual_priority,
                               fm_int actual_precedence,
                               bool actual_enabled,
                               u16 vid, int port, const u8 mac[6],
                               int mac_kind, u32 ip) {
    fm_flowCondition expected_cond = 0;
    fm_flowValue expected_value;
    fm_flowAction expected_action = 0;
    fm_flowParam expected_param;

    memset(&expected_param, 0, sizeof(expected_param));
    if (!actual_value || !actual_param ||
        !fill_rule(type, vid, port, mac, mac_kind, ip, &expected_cond,
                   &expected_value, &expected_action, NULL))
        return false;
    /*
     * The shared L2-security table is created with with_priority=false.
     * FM10000 therefore ignores the add-time priority and reads it back as 0.
     */
    return actual_cond == expected_cond &&
           memcmp(actual_value, &expected_value, sizeof(expected_value)) == 0 &&
           actual_action == expected_action &&
           memcmp(actual_param, &expected_param, sizeof(expected_param)) == 0 &&
           actual_priority == 0 &&
           actual_precedence == 0 &&
           actual_enabled;
}

static hal_flow_presence_snapshot security_rule_snapshot(
    int sw, l2_security_rule_type type, u16 vid, int port,
    const u8 mac[6], int mac_kind, u32 ip) {
    hal_flow_presence_snapshot out = flow_snapshot_init();
    hal_flow_presence_snapshot table_snapshot;
    fm_int current = -1;
    fm_status st;
    unsigned int exact_rules = 0;

    out.table = L2_SECURITY_TABLE;
    out.expected_rules = 1;
    if (!fill_rule(type, vid, port, mac, mac_kind, ip,
                   &(fm_flowCondition){0}, &(fm_flowValue){0},
                   NULL, NULL))
        return out;

    table_snapshot = hal_l2_security_table_snapshot(sw);
    if (table_snapshot.state != HAL_PRESENCE_PRESENT) {
        out.state = table_snapshot.state;
        out.sdk_status = table_snapshot.sdk_status;
        return out;
    }

    st = fmGetFlowRuleFirst((fm_int)sw, L2_SECURITY_TABLE, &current);
    if (st == FM_ERR_NO_MORE) {
        out.state = HAL_PRESENCE_ABSENT;
        out.sdk_status = (int)st;
        return out;
    }
    if (st != FM_OK) {
        out.sdk_status = (int)st;
        return out;
    }

    for (unsigned int scanned = 0; ; scanned++) {
        fm_flowCondition condition = 0;
        fm_flowValue value;
        fm_flowAction action = 0;
        fm_flowParam param;
        fm_int priority = 0;
        fm_int precedence = 0;
        fm_int next = -1;
        bool enabled = false;
        int state_status = FM_ERR_INVALID_ARGUMENT;

        if (scanned >= L2_SECURITY_MAX_ENTRIES) {
            out.state = HAL_PRESENCE_READ_ERROR;
            out.sdk_status = FM_ERR_MODIFIED_WHILE_ITERATING;
            out.exact = false;
            return out;
        }

        memset(&value, 0, sizeof(value));
        memset(&param, 0, sizeof(param));
        st = fmGetFlow((fm_int)sw, L2_SECURITY_TABLE, current,
                       &condition, &value, &action, &param, &priority,
                       &precedence);
        if (st != FM_OK) {
            out.state = HAL_PRESENCE_READ_ERROR;
            out.sdk_status = (int)st;
            out.exact = false;
            return out;
        }
        if (hal_l2_security_flow_enabled_read(
                sw, (int)current, &enabled, &state_status) != 0) {
            out.state = HAL_PRESENCE_READ_ERROR;
            out.sdk_status = state_status;
            out.exact = false;
            return out;
        }
        if (flow_identity_matches(type, condition, &value, vid, port, mac,
                                  mac_kind, ip)) {
            if (out.first_flow < 0)
                out.first_flow = (int)current;
            out.observed_rules++;
            if (flow_exact_matches(type, condition, &value, action, &param,
                                   priority, precedence, enabled, vid, port,
                                   mac, mac_kind, ip))
                exact_rules++;
        }

        st = fmGetFlowRuleNext((fm_int)sw, L2_SECURITY_TABLE, current, &next);
        if (st == FM_ERR_NO_MORE)
            break;
        if (st != FM_OK) {
            out.state = HAL_PRESENCE_READ_ERROR;
            out.sdk_status = (int)st;
            out.exact = false;
            return out;
        }
        current = next;
    }

    out.sdk_status = FM_OK;
    if (out.observed_rules == 0) {
        out.state = HAL_PRESENCE_ABSENT;
        return out;
    }
    out.state = HAL_PRESENCE_PRESENT;
    out.exact = out.observed_rules == 1 && exact_rules == 1;
    return out;
}

hal_flow_presence_snapshot hal_l2_security_rule_snapshot(
    int sw, const char *kind, u16 vid, int port) {
    l2_security_rule_type type;

    if (kind && strcmp(kind, "arp-inspection") == 0)
        type = L2_SECURITY_RULE_ARP;
    else if (kind && strcmp(kind, "dhcp-snooping") == 0)
        type = L2_SECURITY_RULE_DHCP;
    else
        return flow_snapshot_init();
    return security_rule_snapshot(sw, type, vid, port, NULL,
                                  L2_SECURITY_MAC_SOURCE, 0);
}

hal_flow_presence_snapshot hal_l2_security_arp_binding_snapshot(
    int sw, u16 vid, int port, const u8 mac[6], u32 ip) {
    return security_rule_snapshot(sw, L2_SECURITY_RULE_ARP_BINDING, vid,
                                  port, mac, L2_SECURITY_MAC_SOURCE, ip);
}

hal_flow_presence_snapshot hal_l2_security_user_filter_snapshot(
    int sw, u16 vid, int port, const u8 mac[6], int mac_kind) {
    return security_rule_snapshot(sw, L2_SECURITY_RULE_USER_FILTER, vid,
                                  port, mac, mac_kind, 0);
}

static int find_rule(int sw, l2_security_rule_type type, u16 vid, int port,
                     const u8 mac[6], int mac_kind, u32 ip,
                     fm_int *flow_id) {
    hal_flow_presence_snapshot snapshot;

    if (flow_id)
        *flow_id = -1;
    snapshot = security_rule_snapshot(sw, type, vid, port, mac, mac_kind, ip);
    if (snapshot.state == HAL_PRESENCE_READ_ERROR)
        return -2;
    if (snapshot.state == HAL_PRESENCE_ABSENT)
        return -1;
    if (!snapshot.exact || snapshot.first_flow < 0)
        return -2;
    if (flow_id)
        *flow_id = (fm_int)snapshot.first_flow;
    return 0;
}

static int install_rule(int sw, l2_security_rule_type type, u16 vid,
                        int port, const u8 mac[6], int mac_kind, u32 ip) {
    fm_flowCondition condition = 0;
    fm_flowValue value;
    fm_flowAction action = 0;
    fm_flowParam param;
    fm_uint16 priority = 0;
    fm_int flow_id = -1;
    fm_int table;
    fm_status st;
    int find_rc;

    find_rc = find_rule(sw, type, vid, port, mac, mac_kind, ip, &flow_id);
    if (find_rc == 0)
        return 0;
    if (find_rc < -1)
        return -1;
    if (!fill_rule(type, vid, port, mac, mac_kind, ip, &condition, &value,
                   &action, &priority))
        return -1;

    /*
     * Only an authoritative target absence may reach the reserve/create
     * boundary.  reserve_with_token distinguishes existing table reuse from
     * this call's actual table creation.
     */
    table = l2_security_table_for_type(sw, type);
    if (table <= 0)
        return -1;

    memset(&param, 0, sizeof(param));
    st = fmAddFlow((fm_int)sw, table, priority, 0,
                   condition, &value, action,
                   &param, FM_FLOW_STATE_ENABLED, &flow_id);
    if (st != FM_OK) {
        NL_LOG_ERR("%s rule install vid=%u port=%d failed: %s",
                   rule_type_name(type), vid, port, fmErrorMsg(st));
        return (int)st;
    }

    NL_LOG_INFO("%s rule installed vid=%u port=%d flow=%d",
                rule_type_name(type), vid, port, (int)flow_id);
    return 0;
}

static int delete_rule(int sw, l2_security_rule_type type, u16 vid, int port,
                       const u8 mac[6], int mac_kind, u32 ip) {
    fm_int flow_id = -1;
    int rc;

    rc = find_rule(sw, type, vid, port, mac, mac_kind, ip, &flow_id);
    if (rc == -1)
        return 0;
    if (rc != 0)
        return -1;
    if (fmDeleteFlow((fm_int)sw, L2_SECURITY_TABLE, flow_id) != FM_OK)
        return -1;
    NL_LOG_INFO("%s rule deleted vid=%u port=%d flow=%d",
                rule_type_name(type), vid, port, (int)flow_id);
    return 0;
}

int hal_l2_security_dhcp_snooping_set(int sw, u16 vid, int port) {
    hal_l2_security_begin_table_operation();
    return install_rule(sw, L2_SECURITY_RULE_DHCP, vid, port, NULL,
                        L2_SECURITY_MAC_SOURCE, 0);
}

int hal_l2_security_dhcp_snooping_delete(int sw, u16 vid, int port) {
    hal_l2_security_begin_table_operation();
    return delete_rule(sw, L2_SECURITY_RULE_DHCP, vid, port, NULL,
                       L2_SECURITY_MAC_SOURCE, 0);
}

int hal_l2_security_arp_inspection_set(int sw, u16 vid, int port) {
    hal_l2_security_begin_table_operation();
    return install_rule(sw, L2_SECURITY_RULE_ARP, vid, port, NULL,
                        L2_SECURITY_MAC_SOURCE, 0);
}

int hal_l2_security_arp_inspection_delete(int sw, u16 vid, int port) {
    hal_l2_security_begin_table_operation();
    return delete_rule(sw, L2_SECURITY_RULE_ARP, vid, port, NULL,
                       L2_SECURITY_MAC_SOURCE, 0);
}

int hal_l2_security_rule_present(int sw, const char *kind, u16 vid, int port) {
    hal_flow_presence_snapshot snapshot =
        hal_l2_security_rule_snapshot(sw, kind, vid, port);

    return snapshot.state == HAL_PRESENCE_PRESENT && snapshot.exact ? 1 : 0;
}

int hal_l2_security_arp_binding_set(int sw, u16 vid, int port,
                                    const u8 mac[6], u32 ip) {
    int deny_find_rc;
    bool reorder_deny;
    int rc;

    hal_l2_security_begin_table_operation();
    deny_find_rc = find_rule(sw, L2_SECURITY_RULE_ARP, vid, port, NULL,
                             L2_SECURITY_MAC_SOURCE, 0, NULL);
    if (deny_find_rc < -1)
        return -1;
    reorder_deny = deny_find_rc == 0;
    if (reorder_deny &&
        delete_rule(sw, L2_SECURITY_RULE_ARP, vid, port, NULL,
                    L2_SECURITY_MAC_SOURCE, 0) != 0)
        return -1;

    rc = install_rule(sw, L2_SECURITY_RULE_ARP_BINDING,
                      vid, port, mac, L2_SECURITY_MAC_SOURCE, ip);

    if (reorder_deny) {
        int deny_rc = install_rule(sw, L2_SECURITY_RULE_ARP,
                                   vid, port, NULL,
                                   L2_SECURITY_MAC_SOURCE, 0);
        if (rc == 0 && deny_rc != 0)
            rc = deny_rc;
    }
    return rc;
}

int hal_l2_security_arp_binding_delete(int sw, u16 vid, int port,
                                       const u8 mac[6], u32 ip) {
    hal_l2_security_begin_table_operation();
    return delete_rule(sw, L2_SECURITY_RULE_ARP_BINDING,
                       vid, port, mac, L2_SECURITY_MAC_SOURCE, ip);
}

int hal_l2_security_arp_binding_present(int sw, u16 vid, int port,
                                        const u8 mac[6], u32 ip) {
    hal_flow_presence_snapshot snapshot =
        hal_l2_security_arp_binding_snapshot(sw, vid, port, mac, ip);

    return snapshot.state == HAL_PRESENCE_PRESENT && snapshot.exact ? 1 : 0;
}

int hal_l2_security_user_filter_set(int sw, u16 vid, int port,
                                    const u8 mac[6], int mac_kind) {
    hal_l2_security_begin_table_operation();
    return install_rule(sw, L2_SECURITY_RULE_USER_FILTER, vid, port, mac,
                        mac_kind, 0);
}

int hal_l2_security_user_filter_delete(int sw, u16 vid, int port,
                                       const u8 mac[6], int mac_kind) {
    hal_l2_security_begin_table_operation();
    return delete_rule(sw, L2_SECURITY_RULE_USER_FILTER, vid, port, mac,
                       mac_kind, 0);
}

int hal_l2_security_user_filter_present(int sw, u16 vid, int port,
                                        const u8 mac[6], int mac_kind) {
    hal_flow_presence_snapshot snapshot =
        hal_l2_security_user_filter_snapshot(sw, vid, port, mac, mac_kind);

    return snapshot.state == HAL_PRESENCE_PRESENT && snapshot.exact ? 1 : 0;
}

int hal_l2_security_user_filter_counters(int sw, u16 vid, int port,
                                         const u8 mac[6], int mac_kind,
                                         bool *found, int *table,
                                         int *flow, u64 *packets,
                                         u64 *octets) {
    fm_int flow_id = -1;
    fm_flowCounters counters;
    fm_status st;
    int rc;

    if (found)
        *found = false;
    if (table)
        *table = -1;
    if (flow)
        *flow = -1;
    if (packets)
        *packets = 0;
    if (octets)
        *octets = 0;
    if (!mac || vid < 1 || vid > 4094 || port <= 0)
        return -1;

    rc = find_rule(sw, L2_SECURITY_RULE_USER_FILTER, vid, port, mac,
                   mac_kind, 0, &flow_id);
    if (rc < -1)
        return -1;
    if (rc != 0)
        return 0;

    if (found)
        *found = true;
    if (table)
        *table = L2_SECURITY_TABLE;
    if (flow)
        *flow = (int)flow_id;

    memset(&counters, 0, sizeof(counters));
    st = fmGetFlowCount((fm_int)sw, L2_SECURITY_TABLE, flow_id,
                        &counters);
    if (st != FM_OK) {
        NL_LOG_WARN("user-filter counter read vid=%u port=%d flow=%d failed: %s",
                    vid, port, (int)flow_id, fmErrorMsg(st));
        return (int)st;
    }
    if (packets)
        *packets = counters.cntPkts;
    if (octets)
        *octets = counters.cntOctets;
    return 0;
}

int hal_l2_security_user_filter_counter_snapshot(
    int sw, const nl_acl_counter_query *query,
    nl_acl_counter_snapshot *snapshot) {
    hal_flow_presence_snapshot table_snapshot;
    fm_int current = -1;
    fm_status st;
    unsigned int user_count = 0;

    if (!query || !snapshot || snapshot->n_entries != query->n_entries)
        return -1;
    for (u16 i = 0; i < query->n_entries; i++) {
        if (query->entries[i].kind != NL_ACL_COUNTER_KIND_USER_FILTER)
            continue;
        user_count++;
        if (query->entries[i].match.vid < 1 ||
            query->entries[i].match.vid > 4094 ||
            query->entries[i].match.port == 0 ||
            (query->entries[i].mac_kind != NL_ACL_COUNTER_MAC_SOURCE &&
             query->entries[i].mac_kind !=
                 NL_ACL_COUNTER_MAC_DESTINATION))
            return -1;
    }
    if (user_count == 0)
        return 0;

    table_snapshot = hal_l2_security_table_snapshot(sw);
    if (table_snapshot.state == HAL_PRESENCE_READ_ERROR)
        return table_snapshot.sdk_status != 0 ? table_snapshot.sdk_status : -1;
    if (table_snapshot.state == HAL_PRESENCE_ABSENT)
        return 0;

    st = fmGetFlowRuleFirst((fm_int)sw, L2_SECURITY_TABLE, &current);
    if (st == FM_ERR_NO_MORE)
        return 0;
    if (st != FM_OK)
        return (int)st;

    for (unsigned int scanned = 0; ; scanned++) {
        fm_flowCondition condition = 0;
        fm_flowValue value;
        fm_flowAction action = 0;
        fm_flowParam param;
        fm_int priority = 0;
        fm_int precedence = 0;
        fm_int next = -1;
        bool enabled = false;
        bool matched[NL_ACL_COUNTER_MAX_ENTRIES] = {0};
        bool read_counter = false;
        int state_status = FM_ERR_INVALID_ARGUMENT;

        if (scanned >= L2_SECURITY_MAX_ENTRIES)
            return FM_ERR_MODIFIED_WHILE_ITERATING;
        memset(&value, 0, sizeof(value));
        memset(&param, 0, sizeof(param));
        st = fmGetFlow((fm_int)sw, L2_SECURITY_TABLE, current,
                       &condition, &value, &action, &param, &priority,
                       &precedence);
        if (st != FM_OK)
            return (int)st;
        if (hal_l2_security_flow_enabled_read(
                sw, (int)current, &enabled, &state_status) != 0)
            return state_status;

        for (u16 i = 0; i < query->n_entries; i++) {
            const nl_acl_counter_query_entry *entry = &query->entries[i];
            nl_acl_counter_snapshot_entry *out = &snapshot->entries[i];

            if (entry->kind != NL_ACL_COUNTER_KIND_USER_FILTER ||
                !flow_identity_matches(
                    L2_SECURITY_RULE_USER_FILTER, condition, &value,
                    entry->match.vid, entry->match.port, entry->mac,
                    entry->mac_kind == NL_ACL_COUNTER_MAC_DESTINATION ?
                        L2_SECURITY_MAC_DESTINATION :
                        L2_SECURITY_MAC_SOURCE,
                    0))
                continue;
            if (out->state == NL_ACL_COUNTER_STATE_INSTALLED ||
                out->state == NL_ACL_COUNTER_STATE_MISMATCH ||
                !flow_exact_matches(
                    L2_SECURITY_RULE_USER_FILTER, condition, &value,
                    action, &param, priority, precedence, enabled,
                    entry->match.vid, entry->match.port, entry->mac,
                    entry->mac_kind == NL_ACL_COUNTER_MAC_DESTINATION ?
                        L2_SECURITY_MAC_DESTINATION :
                        L2_SECURITY_MAC_SOURCE,
                    0)) {
                out->state = NL_ACL_COUNTER_STATE_MISMATCH;
                out->packets = 0;
                out->octets = 0;
                continue;
            }
            matched[i] = true;
            read_counter = true;
        }

        if (read_counter) {
            fm_flowCounters counters;
            memset(&counters, 0, sizeof(counters));
            st = fmGetFlowCount((fm_int)sw, L2_SECURITY_TABLE, current,
                                &counters);
            if (st != FM_OK)
                return (int)st;
            for (u16 i = 0; i < query->n_entries; i++) {
                if (!matched[i])
                    continue;
                snapshot->entries[i].state =
                    NL_ACL_COUNTER_STATE_INSTALLED;
                snapshot->entries[i].packets = counters.cntPkts;
                snapshot->entries[i].octets = counters.cntOctets;
            }
        }

        st = fmGetFlowRuleNext((fm_int)sw, L2_SECURITY_TABLE,
                               current, &next);
        if (st == FM_ERR_NO_MORE)
            break;
        if (st != FM_OK)
            return (int)st;
        current = next;
    }
    return 0;
}
