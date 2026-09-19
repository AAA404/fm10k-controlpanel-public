#ifndef NETLAB_HAL_L2_FLOW_SNAPSHOT_H
#define NETLAB_HAL_L2_FLOW_SNAPSHOT_H

#include "hal.h"
#include "hal_presence.h"

/*
 * A flow rule may be present without being an exact copy of the rule NetLab
 * would program.  This is intentionally separate from the three-state
 * presence result: a rule with the same match identity but drifted writable
 * attributes is PRESENT with exact=false, never ABSENT.
 */
typedef struct {
    hal_presence_state state;
    int sdk_status;
    int table;
    int first_flow;
    unsigned int expected_rules;
    unsigned int observed_rules;
    bool exact;
} hal_flow_presence_snapshot;

/*
 * These snapshots are read-only.  They discover the fixed L2-security flow
 * table through the SDK iterators and never reserve, create, or ensure it.
 */
hal_flow_presence_snapshot hal_l2_security_table_snapshot(int sw);
int hal_l2_security_flow_enabled_read(int sw, int flow_id, bool *enabled,
                                      int *sdk_status);
hal_flow_presence_snapshot hal_l2_security_rule_snapshot(
    int sw, const char *kind, u16 vid, int port);
hal_flow_presence_snapshot hal_l2_security_arp_binding_snapshot(
    int sw, u16 vid, int port, const u8 mac[6], u32 ip);
hal_flow_presence_snapshot hal_l2_security_user_filter_snapshot(
    int sw, u16 vid, int port, const u8 mac[6], int mac_kind);
hal_flow_presence_snapshot hal_ingress_ipv4_acl_snapshot(
    int sw, const hal_ingress_ipv4_acl_match *match);

#endif
