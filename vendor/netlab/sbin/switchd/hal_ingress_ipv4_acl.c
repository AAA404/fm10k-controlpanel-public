#include "hal_flow_table.h"

#include "netlab/hal.h"
#include "netlab/hal_l2_flow_snapshot.h"
#include "netlab/log.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <fm_sdk.h>
#include <api/fm_api_flow.h>

#define INGRESS_IPV4_ACL_ETHERTYPE 0x0800
#define INGRESS_IPV4_ACL_VLAN_MASK 0x0fff
#define INGRESS_IPV4_ACL_DSCP_MASK 0xfc
#define INGRESS_IPV4_ACL_ECN_MASK 0x03
#define INGRESS_IPV4_ACL_PROTOCOL_MASK 0xff
#define INGRESS_IPV4_ACL_PORT_MASK 0xffff
#define INGRESS_IPV4_ACL_TCP_FLAGS_MASK 0x3f
#define INGRESS_IPV4_ACL_PRIORITY 120
#define INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS 32
#define INGRESS_IPV4_ACL_TABLE_MAX_ENTRIES 64
#define INGRESS_IPV4_ACL_MAX_RULES \
    (INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS * \
     INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS)

typedef struct {
    bool enabled;
    fm_uint16 start;
    fm_uint16 mask;
} l4_port_segment;

static void fill_ipv4_addr(fm_ipAddr *addr, u32 host_order) {
    if (!addr)
        return;
    memset(addr, 0, sizeof(*addr));
    addr->addr[0] = htonl(host_order);
    addr->isIPv6 = FALSE;
}

static bool same_ip_addr(const fm_ipAddr *a, const fm_ipAddr *b) {
    return a && b &&
           a->isIPv6 == b->isIPv6 &&
           a->addr[0] == b->addr[0] &&
           a->addr[1] == b->addr[1] &&
           a->addr[2] == b->addr[2] &&
           a->addr[3] == b->addr[3];
}

static fm_int ingress_ipv4_acl_table(int sw) {
    return hal_l2_security_flow_table(sw);
}

static int append_port_range_segments(int start, int end,
                                      l4_port_segment *segments,
                                      int max_segments) {
    unsigned int cur;
    unsigned int last;
    int n = 0;

    if (!segments || max_segments <= 0 || start < 0 || end < 0 ||
        start > end || start > INGRESS_IPV4_ACL_PORT_MASK ||
        end > INGRESS_IPV4_ACL_PORT_MASK)
        return -1;
    cur = (unsigned int)start;
    last = (unsigned int)end;
    while (cur <= last) {
        unsigned int size = cur ? (cur & (~cur + 1U)) : 65536U;
        unsigned int remaining = last - cur + 1U;

        while (size > remaining)
            size >>= 1;
        if (size == 0 || n >= max_segments)
            return -1;
        segments[n].enabled = true;
        segments[n].start = (fm_uint16)cur;
        segments[n].mask = (fm_uint16)(~(size - 1U) &
                                       INGRESS_IPV4_ACL_PORT_MASK);
        n++;
        cur += size;
        if (cur == 0)
            break;
    }
    return n;
}

static int build_port_segments(bool has_exact, int exact,
                               bool has_range, int start, int end,
                               l4_port_segment *segments,
                               int max_segments) {
    if (!segments || max_segments <= 0)
        return -1;
    if (has_exact && has_range)
        return -1;
    if (has_exact) {
        if (exact < 0 || exact > INGRESS_IPV4_ACL_PORT_MASK)
            return -1;
        segments[0].enabled = true;
        segments[0].start = (fm_uint16)exact;
        segments[0].mask = INGRESS_IPV4_ACL_PORT_MASK;
        return 1;
    }
    if (has_range)
        return append_port_range_segments(start, end, segments, max_segments);
    segments[0].enabled = false;
    segments[0].start = 0;
    segments[0].mask = 0;
    return 1;
}

static int build_segment_sets(const hal_ingress_ipv4_acl_match *m,
                              l4_port_segment *src_segments,
                              int *n_src,
                              l4_port_segment *dst_segments,
                              int *n_dst) {
    int src_n;
    int dst_n;

    if (!m || !src_segments || !n_src || !dst_segments || !n_dst)
        return -1;
    src_n = build_port_segments(m->has_src_port, m->src_port,
                                m->has_src_port_range,
                                m->src_port_start, m->src_port_end,
                                src_segments,
                                INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS);
    dst_n = build_port_segments(m->has_dst_port, m->dst_port,
                                m->has_dst_port_range,
                                m->dst_port_start, m->dst_port_end,
                                dst_segments,
                                INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS);
    if (src_n <= 0 || dst_n <= 0)
        return -1;
    *n_src = src_n;
    *n_dst = dst_n;
    return 0;
}

static bool match_valid(const hal_ingress_ipv4_acl_match *m) {
    if (!m || m->vid < 1 || m->vid > 4094 || m->port <= 0)
        return false;
    if (!m->has_src_ip && !m->has_dst_ip && !m->has_protocol &&
        !m->has_dscp && !m->has_ecn &&
        !m->has_src_port && !m->has_dst_port &&
        !m->has_src_port_range && !m->has_dst_port_range &&
        !m->has_tcp_flags)
        return false;
    if (m->has_src_ip &&
        (!m->has_src_ip_mask ||
         (m->src_ip_mask == 0xffffffffU &&
          (m->src_ip == 0 || m->src_ip == 0xffffffffU))))
        return false;
    if (m->has_dst_ip &&
        (!m->has_dst_ip_mask ||
         (m->dst_ip_mask == 0xffffffffU &&
          (m->dst_ip == 0 || m->dst_ip == 0xffffffffU))))
        return false;
    if (m->has_protocol && (m->protocol < 0 || m->protocol > 255))
        return false;
    if (m->has_dscp && (m->dscp < 0 || m->dscp > 63))
        return false;
    if (m->has_ecn && (m->ecn < 0 || m->ecn > 3))
        return false;
    if (m->has_src_port &&
        (m->src_port < 0 || m->src_port > INGRESS_IPV4_ACL_PORT_MASK))
        return false;
    if (m->has_dst_port &&
        (m->dst_port < 0 || m->dst_port > INGRESS_IPV4_ACL_PORT_MASK))
        return false;
    if (m->has_src_port_range &&
        (m->src_port_start < 0 || m->src_port_start > m->src_port_end ||
         m->src_port_end > INGRESS_IPV4_ACL_PORT_MASK))
        return false;
    if (m->has_dst_port_range &&
        (m->dst_port_start < 0 || m->dst_port_start > m->dst_port_end ||
         m->dst_port_end > INGRESS_IPV4_ACL_PORT_MASK))
        return false;
    if (m->has_src_port && m->has_src_port_range)
        return false;
    if (m->has_dst_port && m->has_dst_port_range)
        return false;
    if ((m->has_src_port || m->has_dst_port ||
         m->has_src_port_range || m->has_dst_port_range) &&
        (!m->has_protocol || (m->protocol != 6 && m->protocol != 17)))
        return false;
    if (m->has_tcp_flags &&
        (m->tcp_flags < 0 || m->tcp_flags > INGRESS_IPV4_ACL_TCP_FLAGS_MASK ||
         !m->has_protocol || m->protocol != 6))
        return false;
    if (m->has_tcp_flags_mask &&
        (m->tcp_flags_mask < 1 ||
         m->tcp_flags_mask > INGRESS_IPV4_ACL_TCP_FLAGS_MASK))
        return false;
    if (m->has_tcp_flags_mask && !m->has_tcp_flags)
        return false;
    if (m->has_tcp_flags && m->has_tcp_flags_mask &&
        (m->tcp_flags & ~m->tcp_flags_mask) != 0)
        return false;
    return true;
}

static bool fill_rule_segment(const hal_ingress_ipv4_acl_match *m,
                              const l4_port_segment *src_segment,
                              const l4_port_segment *dst_segment,
                              fm_flowCondition *condition,
                              fm_flowValue *value,
                              fm_flowAction *action,
                              fm_uint16 *priority) {
    if (!match_valid(m) || !condition || !value ||
        !src_segment || !dst_segment)
        return false;

    memset(value, 0, sizeof(*value));
    *condition = FM_FLOW_MATCH_VLAN |
                 FM_FLOW_MATCH_LOGICAL_PORT |
                 FM_FLOW_MATCH_ETHERTYPE;
    value->vlanId = (fm_uint16)m->vid;
    value->vlanIdMask = INGRESS_IPV4_ACL_VLAN_MASK;
    value->logicalPort = (fm_int)m->port;
    value->ethType = INGRESS_IPV4_ACL_ETHERTYPE;
    value->ethTypeMask = 0xffff;

    if (m->has_src_ip) {
        *condition |= FM_FLOW_MATCH_SRC_IP;
        fill_ipv4_addr(&value->srcIp, m->src_ip);
        fill_ipv4_addr(&value->srcIpMask, m->src_ip_mask);
    }
    if (m->has_dst_ip) {
        *condition |= FM_FLOW_MATCH_DST_IP;
        fill_ipv4_addr(&value->dstIp, m->dst_ip);
        fill_ipv4_addr(&value->dstIpMask, m->dst_ip_mask);
    }
    if (m->has_dscp || m->has_ecn) {
        *condition |= FM_FLOW_MATCH_TOS;
        if (m->has_dscp) {
            value->tos |= (fm_byte)((m->dscp & 0x3f) << 2);
            value->tosMask |= INGRESS_IPV4_ACL_DSCP_MASK;
        }
        if (m->has_ecn) {
            value->tos |= (fm_byte)(m->ecn & 0x03);
            value->tosMask |= INGRESS_IPV4_ACL_ECN_MASK;
        }
    }
    if (m->has_protocol) {
        *condition |= FM_FLOW_MATCH_PROTOCOL;
        value->protocol = (fm_byte)m->protocol;
        value->protocolMask = INGRESS_IPV4_ACL_PROTOCOL_MASK;
    }
    if (src_segment->enabled) {
        *condition |= FM_FLOW_MATCH_L4_SRC_PORT;
        value->L4SrcStart = src_segment->start;
        value->L4SrcMask = src_segment->mask;
    }
    if (dst_segment->enabled) {
        *condition |= FM_FLOW_MATCH_L4_DST_PORT;
        value->L4DstStart = dst_segment->start;
        value->L4DstMask = dst_segment->mask;
    }
    if (m->has_tcp_flags) {
        *condition |= FM_FLOW_MATCH_TCP_FLAGS;
        value->tcpFlags = (fm_byte)(m->tcp_flags &
                                    INGRESS_IPV4_ACL_TCP_FLAGS_MASK);
        value->tcpFlagsMask =
            (fm_byte)(m->has_tcp_flags_mask ?
                      m->tcp_flags_mask : INGRESS_IPV4_ACL_TCP_FLAGS_MASK);
    }
    if (action)
        *action = (m->count_only ? FM_FLOW_ACTION_PERMIT :
                   FM_FLOW_ACTION_DENY) | FM_FLOW_ACTION_COUNT;
    if (priority)
        *priority = INGRESS_IPV4_ACL_PRIORITY;
    return true;
}

static bool flow_identity_matches(
    fm_flowCondition actual_cond, const fm_flowValue *actual,
    const hal_ingress_ipv4_acl_match *m,
    const l4_port_segment *src_segment,
    const l4_port_segment *dst_segment) {
    fm_flowCondition expected_cond = 0;
    fm_flowValue expected;

    if (!actual || !fill_rule_segment(m, src_segment, dst_segment,
                                      &expected_cond, &expected, NULL, NULL))
        return false;
    if ((actual_cond & expected_cond) != expected_cond)
        return false;
    if (actual->vlanId != expected.vlanId ||
        actual->vlanIdMask != expected.vlanIdMask ||
        actual->logicalPort != expected.logicalPort ||
        actual->ethType != expected.ethType ||
        actual->ethTypeMask != expected.ethTypeMask)
        return false;
    if (m->has_src_ip &&
        (!same_ip_addr(&actual->srcIp, &expected.srcIp) ||
         !same_ip_addr(&actual->srcIpMask, &expected.srcIpMask)))
        return false;
    if (m->has_dst_ip &&
        (!same_ip_addr(&actual->dstIp, &expected.dstIp) ||
         !same_ip_addr(&actual->dstIpMask, &expected.dstIpMask)))
        return false;
    if ((m->has_dscp || m->has_ecn) &&
        (actual->tos != expected.tos ||
         actual->tosMask != expected.tosMask))
        return false;
    if (m->has_protocol &&
        (actual->protocol != expected.protocol ||
         actual->protocolMask != expected.protocolMask))
        return false;
    if (src_segment->enabled &&
        (actual->L4SrcStart != expected.L4SrcStart ||
         actual->L4SrcMask != expected.L4SrcMask))
        return false;
    if (dst_segment->enabled &&
        (actual->L4DstStart != expected.L4DstStart ||
         actual->L4DstMask != expected.L4DstMask))
        return false;
    if (m->has_tcp_flags &&
        (actual->tcpFlags != expected.tcpFlags ||
         actual->tcpFlagsMask != expected.tcpFlagsMask))
        return false;
    return true;
}

static bool flow_exact_matches(
    fm_flowCondition actual_cond, const fm_flowValue *actual_value,
    fm_flowAction actual_action, const fm_flowParam *actual_param,
    fm_int actual_priority, fm_int actual_precedence,
    bool actual_enabled,
    const hal_ingress_ipv4_acl_match *m,
    const l4_port_segment *src_segment,
    const l4_port_segment *dst_segment) {
    fm_flowCondition expected_cond = 0;
    fm_flowValue expected_value;
    fm_flowAction expected_action = 0;
    fm_flowParam expected_param;

    memset(&expected_param, 0, sizeof(expected_param));
    if (!actual_value || !actual_param ||
        !fill_rule_segment(m, src_segment, dst_segment, &expected_cond,
                           &expected_value, &expected_action, NULL))
        return false;
    return actual_cond == expected_cond &&
           memcmp(actual_value, &expected_value, sizeof(expected_value)) == 0 &&
           actual_action == expected_action &&
           memcmp(actual_param, &expected_param, sizeof(expected_param)) == 0 &&
           actual_priority == 0 &&
           actual_precedence == 0 &&
           actual_enabled;
}

static int find_rule_segment(int sw, const hal_ingress_ipv4_acl_match *m,
                             const l4_port_segment *src_segment,
                             const l4_port_segment *dst_segment,
                             fm_int *flow_id) {
    hal_flow_presence_snapshot table_snapshot;
    fm_int current = -1;
    fm_status st;
    unsigned int identity_rules = 0;
    unsigned int exact_rules = 0;
    fm_int exact_flow = -1;

    if (flow_id)
        *flow_id = -1;
    if (!match_valid(m))
        return -2;
    table_snapshot = hal_l2_security_table_snapshot(sw);
    if (table_snapshot.state == HAL_PRESENCE_READ_ERROR)
        return -2;
    if (table_snapshot.state == HAL_PRESENCE_ABSENT)
        return -1;

    st = fmGetFlowRuleFirst((fm_int)sw, (fm_int)table_snapshot.table,
                            &current);
    if (st == FM_ERR_NO_MORE)
        return -1;
    if (st != FM_OK)
        return -2;
    for (unsigned int scanned = 0;
         st == FM_OK && scanned < INGRESS_IPV4_ACL_TABLE_MAX_ENTRIES;
         scanned++) {
        fm_flowCondition cond = 0;
        fm_flowValue value;
        fm_flowAction action = 0;
        fm_flowParam param;
        fm_int priority = 0;
        fm_int precedence = 0;
        bool enabled = false;
        int state_status = FM_ERR_INVALID_ARGUMENT;

        memset(&value, 0, sizeof(value));
        memset(&param, 0, sizeof(param));
        st = fmGetFlow((fm_int)sw, (fm_int)table_snapshot.table, current,
                       &cond, &value, &action, &param, &priority,
                       &precedence);
        if (st != FM_OK)
            return -2;
        if (hal_l2_security_flow_enabled_read(
                sw, (int)current, &enabled, &state_status) != 0)
            return -2;
        if (flow_identity_matches(cond, &value, m, src_segment,
                                  dst_segment)) {
            identity_rules++;
            if (flow_exact_matches(cond, &value, action, &param, priority,
                                   precedence, enabled, m, src_segment,
                                   dst_segment)) {
                exact_rules++;
                exact_flow = current;
            }
        }
        {
            fm_int next = 0;
            st = fmGetFlowRuleNext((fm_int)sw,
                                   (fm_int)table_snapshot.table,
                                   current, &next);
            current = next;
        }
    }
    if (st != FM_ERR_NO_MORE)
        return -2;
    if (identity_rules == 0)
        return -1;
    if (identity_rules != 1 || exact_rules != 1)
        return -2;
    if (flow_id)
        *flow_id = exact_flow;
    return 0;
}

hal_flow_presence_snapshot hal_ingress_ipv4_acl_snapshot(
    int sw, const hal_ingress_ipv4_acl_match *match) {
    hal_flow_presence_snapshot out;
    hal_flow_presence_snapshot table_snapshot;
    l4_port_segment src_segments[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    l4_port_segment dst_segments[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    unsigned short identity_count[INGRESS_IPV4_ACL_MAX_RULES];
    unsigned short exact_count[INGRESS_IPV4_ACL_MAX_RULES];
    int n_src = 0;
    int n_dst = 0;
    fm_int current = -1;
    fm_status st;

    memset(&out, 0, sizeof(out));
    out.state = HAL_PRESENCE_READ_ERROR;
    out.sdk_status = FM_ERR_INVALID_ARGUMENT;
    out.table = -1;
    out.first_flow = -1;
    memset(identity_count, 0, sizeof(identity_count));
    memset(exact_count, 0, sizeof(exact_count));

    if (!match_valid(match) ||
        build_segment_sets(match, src_segments, &n_src,
                           dst_segments, &n_dst) != 0)
        return out;
    out.expected_rules = (unsigned int)(n_src * n_dst);

    table_snapshot = hal_l2_security_table_snapshot(sw);
    out.table = table_snapshot.table;
    if (table_snapshot.state != HAL_PRESENCE_PRESENT) {
        out.state = table_snapshot.state;
        out.sdk_status = table_snapshot.sdk_status;
        return out;
    }

    st = fmGetFlowRuleFirst((fm_int)sw, (fm_int)out.table, &current);
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

        if (scanned >= INGRESS_IPV4_ACL_TABLE_MAX_ENTRIES) {
            out.state = HAL_PRESENCE_READ_ERROR;
            out.sdk_status = FM_ERR_MODIFIED_WHILE_ITERATING;
            out.exact = false;
            return out;
        }

        memset(&value, 0, sizeof(value));
        memset(&param, 0, sizeof(param));
        st = fmGetFlow((fm_int)sw, (fm_int)out.table, current,
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

        for (int si = 0; si < n_src; si++) {
            for (int di = 0; di < n_dst; di++) {
                int index = si * n_dst + di;

                if (!flow_identity_matches(condition, &value, match,
                                           &src_segments[si],
                                           &dst_segments[di]))
                    continue;
                if (out.first_flow < 0)
                    out.first_flow = (int)current;
                identity_count[index]++;
                out.observed_rules++;
                if (flow_exact_matches(condition, &value, action, &param,
                                       priority, precedence, enabled, match,
                                       &src_segments[si],
                                       &dst_segments[di]))
                    exact_count[index]++;
            }
        }

        st = fmGetFlowRuleNext((fm_int)sw, (fm_int)out.table, current,
                               &next);
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
    out.exact = true;
    for (unsigned int i = 0; i < out.expected_rules; i++) {
        if (identity_count[i] != 1 || exact_count[i] != 1) {
            out.exact = false;
            break;
        }
    }
    return out;
}

static int delete_acl_rules(
    int sw, const hal_ingress_ipv4_acl_match *match);

int hal_ingress_ipv4_acl_set(int sw,
                             const hal_ingress_ipv4_acl_match *match) {
    hal_flow_presence_snapshot snapshot;
    l4_port_segment src_segments[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    l4_port_segment dst_segments[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    int n_src = 0;
    int n_dst = 0;
    fm_int table;

    hal_l2_security_begin_table_operation();
    snapshot = hal_ingress_ipv4_acl_snapshot(sw, match);
    if (snapshot.state == HAL_PRESENCE_READ_ERROR)
        return -1;
    if (snapshot.state == HAL_PRESENCE_PRESENT)
        return snapshot.exact ? 0 : -1;
    if (!match_valid(match) ||
        build_segment_sets(match, src_segments, &n_src,
                           dst_segments, &n_dst) != 0)
        return -1;

    /* The complete target group was authoritatively absent before reserve. */
    table = ingress_ipv4_acl_table(sw);
    if (table <= 0)
        return -1;

    for (int si = 0; si < n_src; si++) {
        for (int di = 0; di < n_dst; di++) {
            fm_flowCondition condition = 0;
            fm_flowValue value;
            fm_flowAction action = 0;
            fm_flowParam param;
            fm_uint16 priority = 0;
            fm_int flow_id = -1;
            fm_status st;

            if (!fill_rule_segment(match, &src_segments[si],
                                   &dst_segments[di], &condition,
                                   &value, &action, &priority)) {
                (void)delete_acl_rules(sw, match);
                return -1;
            }
            memset(&param, 0, sizeof(param));
            st = fmAddFlow((fm_int)sw, table, priority, 0,
                           condition, &value, action, &param,
                           FM_FLOW_STATE_ENABLED, &flow_id);
            if (st != FM_OK) {
                NL_LOG_ERR("ingress-ipv4-acl install vid=%d port=%d failed: %s",
                           match->vid, match->port, fmErrorMsg(st));
                (void)delete_acl_rules(sw, match);
                return (int)st;
            }
            NL_LOG_INFO("ingress-ipv4-acl installed vid=%d port=%d flow=%d",
                        match->vid, match->port, (int)flow_id);
        }
    }

    snapshot = hal_ingress_ipv4_acl_snapshot(sw, match);
    if (snapshot.state != HAL_PRESENCE_PRESENT || !snapshot.exact) {
        (void)delete_acl_rules(sw, match);
        return -1;
    }
    return 0;
}

static int delete_acl_rules(
    int sw, const hal_ingress_ipv4_acl_match *match) {
    hal_flow_presence_snapshot table_snapshot;
    l4_port_segment src_segments[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    l4_port_segment dst_segments[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    int n_src = 0;
    int n_dst = 0;

    if (!match_valid(match) ||
        build_segment_sets(match, src_segments, &n_src,
                           dst_segments, &n_dst) != 0)
        return 0;
    table_snapshot = hal_l2_security_table_snapshot(sw);
    if (table_snapshot.state == HAL_PRESENCE_READ_ERROR)
        return -1;
    if (table_snapshot.state == HAL_PRESENCE_ABSENT)
        return 0;

    for (int si = 0; si < n_src; si++) {
        for (int di = 0; di < n_dst; di++) {
            fm_int flow_id = -1;
            int find_rc;

            find_rc = find_rule_segment(sw, match, &src_segments[si],
                                        &dst_segments[di], &flow_id);
            if (find_rc == -1)
                continue;
            if (find_rc != 0)
                return -1;
            if (fmDeleteFlow((fm_int)sw, (fm_int)table_snapshot.table,
                             flow_id) != FM_OK)
                return -1;
            NL_LOG_INFO("ingress-ipv4-acl deleted vid=%d port=%d flow=%d",
                        match->vid, match->port, (int)flow_id);
        }
    }
    return 0;
}

int hal_ingress_ipv4_acl_delete(int sw,
                                const hal_ingress_ipv4_acl_match *match) {
    hal_l2_security_begin_table_operation();
    return delete_acl_rules(sw, match);
}

int hal_ingress_ipv4_acl_present(int sw,
                                 const hal_ingress_ipv4_acl_match *match) {
    hal_flow_presence_snapshot snapshot =
        hal_ingress_ipv4_acl_snapshot(sw, match);

    return snapshot.state == HAL_PRESENCE_PRESENT && snapshot.exact ? 1 : 0;
}

int hal_ingress_ipv4_acl_counters(int sw,
                                  const hal_ingress_ipv4_acl_match *match,
                                  bool *found, int *table, int *flow,
                                  u64 *packets, u64 *octets) {
    l4_port_segment src_segments[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    l4_port_segment dst_segments[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    int n_src = 0;
    int n_dst = 0;
    int found_count = 0;
    int expected_count = 0;
    hal_flow_presence_snapshot table_snapshot;
    fm_int table_id = -1;

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
    if (!match_valid(match) ||
        build_segment_sets(match, src_segments, &n_src,
                           dst_segments, &n_dst) != 0)
        return -1;
    table_snapshot = hal_l2_security_table_snapshot(sw);
    if (table_snapshot.state == HAL_PRESENCE_READ_ERROR)
        return -1;
    if (table_snapshot.state == HAL_PRESENCE_ABSENT)
        return 0;
    table_id = (fm_int)table_snapshot.table;
    if (table)
        *table = (int)table_id;

    expected_count = n_src * n_dst;
    for (int si = 0; si < n_src; si++) {
        for (int di = 0; di < n_dst; di++) {
            fm_int flow_id = -1;
            fm_flowCounters counters;
            fm_status st;
            int rc = find_rule_segment(sw, match, &src_segments[si],
                                       &dst_segments[di], &flow_id);

            if (rc < -1)
                return -1;
            if (rc != 0)
                continue;
            if (flow && found_count == 0)
                *flow = (expected_count == 1) ? (int)flow_id : -1;
            memset(&counters, 0, sizeof(counters));
            st = fmGetFlowCount((fm_int)sw, table_id, flow_id, &counters);
            if (st != FM_OK) {
                NL_LOG_WARN("ingress-ipv4-acl counter read vid=%d port=%d flow=%d failed: %s",
                            match->vid, match->port, (int)flow_id,
                            fmErrorMsg(st));
                return (int)st;
            }
            if (packets)
                *packets += counters.cntPkts;
            if (octets)
                *octets += counters.cntOctets;
            found_count++;
        }
    }
    if (found)
        *found = found_count == expected_count;
    return 0;
}

typedef struct {
    hal_ingress_ipv4_acl_match match;
    l4_port_segment src[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    l4_port_segment dst[INGRESS_IPV4_ACL_MAX_PORT_SEGMENTS];
    unsigned short identity[INGRESS_IPV4_ACL_MAX_RULES];
    unsigned short exact[INGRESS_IPV4_ACL_MAX_RULES];
    int n_src;
    int n_dst;
    bool used;
} ingress_counter_batch_entry;

static void counter_query_to_match(const nl_acl_counter_query_entry *src,
                                   hal_ingress_ipv4_acl_match *dst) {
    u32 f = src->match.flags;

    memset(dst, 0, sizeof(*dst));
    dst->vid = src->match.vid;
    dst->port = src->match.port;
    dst->has_src_ip = (f & NL_ACL_COUNTER_MATCH_SRC_IP) != 0;
    dst->has_dst_ip = (f & NL_ACL_COUNTER_MATCH_DST_IP) != 0;
    dst->has_src_ip_mask = (f & NL_ACL_COUNTER_MATCH_SRC_IP_MASK) != 0;
    dst->has_dst_ip_mask = (f & NL_ACL_COUNTER_MATCH_DST_IP_MASK) != 0;
    dst->has_dscp = (f & NL_ACL_COUNTER_MATCH_DSCP) != 0;
    dst->has_ecn = (f & NL_ACL_COUNTER_MATCH_ECN) != 0;
    dst->has_protocol = (f & NL_ACL_COUNTER_MATCH_PROTOCOL) != 0;
    dst->has_src_port = (f & NL_ACL_COUNTER_MATCH_SRC_PORT) != 0;
    dst->has_dst_port = (f & NL_ACL_COUNTER_MATCH_DST_PORT) != 0;
    dst->has_src_port_range =
        (f & NL_ACL_COUNTER_MATCH_SRC_PORT_RANGE) != 0;
    dst->has_dst_port_range =
        (f & NL_ACL_COUNTER_MATCH_DST_PORT_RANGE) != 0;
    dst->has_tcp_flags = (f & NL_ACL_COUNTER_MATCH_TCP_FLAGS) != 0;
    dst->has_tcp_flags_mask =
        (f & NL_ACL_COUNTER_MATCH_TCP_FLAGS_MASK) != 0;
    dst->count_only = (f & NL_ACL_COUNTER_MATCH_COUNT_ONLY) != 0;
    dst->src_ip = src->match.src_ip;
    dst->dst_ip = src->match.dst_ip;
    dst->src_ip_mask = src->match.src_ip_mask;
    dst->dst_ip_mask = src->match.dst_ip_mask;
    dst->dscp = src->match.dscp;
    dst->ecn = src->match.ecn;
    dst->protocol = src->match.protocol;
    dst->src_port = src->match.src_port;
    dst->dst_port = src->match.dst_port;
    dst->src_port_start = src->match.src_port_start;
    dst->src_port_end = src->match.src_port_end;
    dst->dst_port_start = src->match.dst_port_start;
    dst->dst_port_end = src->match.dst_port_end;
    dst->tcp_flags = src->match.tcp_flags;
    dst->tcp_flags_mask = src->match.tcp_flags_mask;
}

int hal_ingress_ipv4_acl_counter_snapshot(
    int sw, const nl_acl_counter_query *query,
    nl_acl_counter_snapshot *snapshot) {
    ingress_counter_batch_entry *batch = NULL;
    hal_flow_presence_snapshot table_snapshot;
    fm_int current = -1;
    fm_status st;
    int rc = -1;
    unsigned int ingress_count = 0;

    if (!query || !snapshot || snapshot->n_entries != query->n_entries)
        return -1;
    batch = calloc(query->n_entries ? query->n_entries : 1,
                   sizeof(*batch));
    if (!batch)
        return -1;
    for (u16 i = 0; i < query->n_entries; i++) {
        if (query->entries[i].kind != NL_ACL_COUNTER_KIND_INGRESS_IPV4)
            continue;
        ingress_count++;
        batch[i].used = true;
        counter_query_to_match(&query->entries[i], &batch[i].match);
        if (!match_valid(&batch[i].match) ||
            build_segment_sets(&batch[i].match, batch[i].src,
                               &batch[i].n_src, batch[i].dst,
                               &batch[i].n_dst) != 0)
            goto out;
    }
    if (ingress_count == 0) {
        rc = 0;
        goto out;
    }

    table_snapshot = hal_l2_security_table_snapshot(sw);
    if (table_snapshot.state == HAL_PRESENCE_READ_ERROR)
        goto out;
    if (table_snapshot.state == HAL_PRESENCE_ABSENT) {
        rc = 0;
        goto out;
    }
    st = fmGetFlowRuleFirst((fm_int)sw, (fm_int)table_snapshot.table,
                            &current);
    if (st == FM_ERR_NO_MORE) {
        rc = 0;
        goto out;
    }
    if (st != FM_OK)
        goto out;

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

        if (scanned >= INGRESS_IPV4_ACL_TABLE_MAX_ENTRIES)
            goto out;
        memset(&value, 0, sizeof(value));
        memset(&param, 0, sizeof(param));
        st = fmGetFlow((fm_int)sw, (fm_int)table_snapshot.table, current,
                       &condition, &value, &action, &param, &priority,
                       &precedence);
        if (st != FM_OK)
            goto out;
        if (hal_l2_security_flow_enabled_read(
                sw, (int)current, &enabled, &state_status) != 0)
            goto out;

        for (u16 i = 0; i < query->n_entries; i++) {
            ingress_counter_batch_entry *entry = &batch[i];

            if (!entry->used)
                continue;
            for (int si = 0; si < entry->n_src; si++) {
                for (int di = 0; di < entry->n_dst; di++) {
                    int index = si * entry->n_dst + di;

                    if (!flow_identity_matches(
                            condition, &value, &entry->match,
                            &entry->src[si], &entry->dst[di]))
                        continue;
                    entry->identity[index]++;
                    if (flow_exact_matches(
                            condition, &value, action, &param,
                            priority, precedence, enabled, &entry->match,
                            &entry->src[si], &entry->dst[di])) {
                        entry->exact[index]++;
                        matched[i] = true;
                        read_counter = true;
                    }
                }
            }
        }
        if (read_counter) {
            fm_flowCounters counters;
            memset(&counters, 0, sizeof(counters));
            st = fmGetFlowCount((fm_int)sw, (fm_int)table_snapshot.table,
                                current, &counters);
            if (st != FM_OK)
                goto out;
            for (u16 i = 0; i < query->n_entries; i++) {
                if (!matched[i])
                    continue;
                snapshot->entries[i].packets += counters.cntPkts;
                snapshot->entries[i].octets += counters.cntOctets;
            }
        }
        st = fmGetFlowRuleNext((fm_int)sw, (fm_int)table_snapshot.table,
                               current, &next);
        if (st == FM_ERR_NO_MORE)
            break;
        if (st != FM_OK)
            goto out;
        current = next;
    }

    for (u16 i = 0; i < query->n_entries; i++) {
        ingress_counter_batch_entry *entry = &batch[i];
        bool any = false;
        bool exact = true;

        if (!entry->used)
            continue;
        for (int si = 0; si < entry->n_src; si++) {
            for (int di = 0; di < entry->n_dst; di++) {
                int index = si * entry->n_dst + di;
                if (entry->identity[index] != 0)
                    any = true;
                if (entry->identity[index] != 1 ||
                    entry->exact[index] != 1)
                    exact = false;
            }
        }
        if (exact) {
            snapshot->entries[i].state =
                NL_ACL_COUNTER_STATE_INSTALLED;
        } else if (any) {
            snapshot->entries[i].state =
                NL_ACL_COUNTER_STATE_MISMATCH;
            snapshot->entries[i].packets = 0;
            snapshot->entries[i].octets = 0;
        }
    }
    rc = 0;
out:
    free(batch);
    return rc;
}
