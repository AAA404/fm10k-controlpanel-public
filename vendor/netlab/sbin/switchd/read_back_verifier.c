/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/hal_presence.h"
#include <string.h>
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_lag.h>
#include <api/fm_api_port.h>

static int verify_first_lag(int sw, struct verify_result *result) {
    int lag = -1;
    hal_presence_snapshot snapshot =
        hal_lag_first_snapshot(sw, &lag);
    bool ok = snapshot.state == HAL_PRESENCE_PRESENT;

    if (result) {
        result->sdk_status =
            snapshot.state == HAL_PRESENCE_READ_ERROR ?
            snapshot.sdk_status : 0;
        result->readback_ok = ok;
        if (snapshot.state == HAL_PRESENCE_READ_ERROR)
            snprintf(result->detail, sizeof(result->detail),
                     "LAG read-back failed: %s",
                     fmErrorMsg((fm_status)snapshot.sdk_status));
        else if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "no LAG present in hardware");
    }
    return ok ? lag : -1;
}

static int verify_lag_presence(int sw, int lag_id, bool expect_present,
                               struct verify_result *result) {
    hal_presence_snapshot snapshot = expect_present ?
        hal_lag_presence_snapshot(sw, lag_id) :
        hal_lag_wait_absent(sw, lag_id);
    bool ok = snapshot.state ==
        (expect_present ? HAL_PRESENCE_PRESENT : HAL_PRESENCE_ABSENT);

    if (result) {
        result->sdk_status =
            snapshot.state == HAL_PRESENCE_READ_ERROR ?
            snapshot.sdk_status : 0;
        result->readback_ok = ok;
        if (snapshot.state == HAL_PRESENCE_READ_ERROR)
            snprintf(result->detail, sizeof(result->detail),
                     "LAG %d read-back failed: %s", lag_id,
                     fmErrorMsg((fm_status)snapshot.sdk_status));
        else if (!ok && expect_present)
            snprintf(result->detail, sizeof(result->detail),
                     "LAG %d not found in hardware", lag_id);
        else if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "LAG %d still exists after delete", lag_id);
    }
    return ok ? 0 : -1;
}

static int verify_lag_member_presence(int sw, int lag_id, int port,
                                      bool expect_present,
                                      struct verify_result *result) {
    struct verify_result first_result;

    memset(&first_result, 0, sizeof(first_result));
    if (lag_id <= 0) {
        lag_id = verify_first_lag(sw, &first_result);
        if (lag_id <= 0 && result)
            *result = first_result;
    }
    if (lag_id <= 0) {
        if (result && result->sdk_status == 0)
            snprintf(result->detail, sizeof(result->detail),
                     "no LAG present while checking port %d", port);
        return -1;
    }

    hal_presence_snapshot snapshot =
        hal_lag_member_snapshot(sw, lag_id, port);
    bool ok = snapshot.state ==
        (expect_present ? HAL_PRESENCE_PRESENT : HAL_PRESENCE_ABSENT);

    if (result) {
        result->sdk_status =
            snapshot.state == HAL_PRESENCE_READ_ERROR ?
            snapshot.sdk_status : 0;
        result->readback_ok = ok;
        if (snapshot.state == HAL_PRESENCE_READ_ERROR)
            snprintf(result->detail, sizeof(result->detail),
                     "LAG %d port %d read-back failed: %s",
                     lag_id, port,
                     fmErrorMsg((fm_status)snapshot.sdk_status));
        else if (!ok && expect_present)
            snprintf(result->detail, sizeof(result->detail),
                     "LAG %d: expected port %d not a member", lag_id, port);
        else if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d still in LAG %d after remove", port, lag_id);
    }
    return ok ? 0 : -1;
}

static int verify_lag_id(int sw, int lag_id,
                         struct verify_result *result) {
    return verify_lag_presence(sw, lag_id, true, result);
}

static int verify_lag_member(int sw, int lag_id, int port,
                             struct verify_result *result) {
    return verify_lag_member_presence(
        sw, lag_id, port, true, result);
}

int verify_lag_hash_rotation(int sw, int lag_id, int expected_rotation,
                             struct verify_result *result) {
    int rotation = -1;
    int rc = hal_lag_get_hash_rotation(sw, lag_id, &rotation);
    bool ok = (rc == 0 && rotation == expected_rotation);

    if (result) {
        result->sdk_status = rc;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "LAG %d: expected hash rotation=%d got=%d",
                     lag_id, expected_rotation, rotation);
    }
    return ok ? 0 : -1;
}

int verify_l2_security_rule(int sw, const char *kind, u16 vid, int port,
                            bool expect_present,
                            struct verify_result *result) {
    int present = hal_l2_security_rule_present(sw, kind, vid, port);
    bool ok = expect_present ? present == 1 : present == 0;

    if (result) {
        result->sdk_status = present >= 0 ? 0 : -1;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "%s rule vid=%u port=%d expected %s",
                     kind ? kind : "l2-security", vid, port,
                     expect_present ? "present" : "absent");
    }
    return ok ? 0 : -1;
}

int verify_l2_security_binding(int sw, u16 vid, int port,
                               const u8 mac[6], u32 ip,
                               bool expect_present,
                               struct verify_result *result) {
    int present = hal_l2_security_arp_binding_present(sw, vid, port, mac, ip);
    bool ok = expect_present ? present == 1 : present == 0;

    if (result) {
        result->sdk_status = present >= 0 ? 0 : -1;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "arp-inspection binding vid=%u port=%d expected %s",
                     vid, port, expect_present ? "present" : "absent");
    }
    return ok ? 0 : -1;
}

int verify_l2_security_user_filter(int sw, u16 vid, int port,
                                   const u8 mac[6], int mac_kind,
                                   bool expect_present,
                                   struct verify_result *result) {
    int present = hal_l2_security_user_filter_present(sw, vid, port, mac,
                                                      mac_kind);
    bool ok = expect_present ? present == 1 : present == 0;

    if (result) {
        result->sdk_status = present >= 0 ? 0 : -1;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "user-filter %s-mac vid=%u port=%d expected %s",
                     mac_kind == L2_SECURITY_MAC_DESTINATION ?
                     "destination" : "source",
                     vid, port, expect_present ? "present" : "absent");
    }
    return ok ? 0 : -1;
}

int verify_ingress_ipv4_acl(int sw,
                            const hal_ingress_ipv4_acl_match *match,
                            bool expect_present,
                            struct verify_result *result) {
    int present = hal_ingress_ipv4_acl_present(sw, match);
    bool ok = expect_present ? present == 1 : present == 0;

    if (result) {
        result->sdk_status = present >= 0 ? 0 : -1;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "ingress-ipv4-acl vid=%d port=%d expected %s",
                     match ? match->vid : 0, match ? match->port : 0,
                     expect_present ? "present" : "absent");
    }
    return ok ? 0 : -1;
}

static int verify_acl_policer_owner(
    int sw, const hal_acl_policer_owner_args *args, bool expect_present,
    struct verify_result *result) {
    hal_acl_policer_owner_result owner;
    bool ok;
    int rc;

    memset(&owner, 0, sizeof(owner));
    rc = hal_acl_policer_owner_readback_match(sw, args, &owner);
    ok = rc == 0 && owner.ok &&
         (expect_present ? owner.active : !owner.active);
    if (ok && expect_present && args) {
        ok = owner.port == args->port &&
             owner.dst_mac == args->dst_mac &&
             owner.rate_readback == args->rate_kbps &&
             owner.burst_readback == args->burst_bytes;
    }

    if (result) {
        result->sdk_status = rc;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "acl-policer expected %s active=%s port=%d",
                     expect_present ? "present" : "absent",
                     owner.active ? "true" : "false",
                     owner.port);
    }
    return ok ? 0 : -1;
}

static int verify_egress_acl_owner(
    int sw, const hal_acl_egress_owner_args *args, bool expect_present,
    struct verify_result *result) {
    hal_acl_egress_owner_result owner;
    bool ok;
    int rc;

    memset(&owner, 0, sizeof(owner));
    rc = hal_acl_egress_owner_readback_match(sw, args, &owner);
    ok = rc == 0 && owner.ok &&
         (expect_present ? owner.active : !owner.active);
    if (ok && expect_present && args) {
        ok = owner.port == args->port &&
             owner.src_mac == args->src_mac &&
             owner.dst_mac == args->dst_mac;
    }

    if (result) {
        result->sdk_status = rc;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "egress-acl expected %s active=%s port=%d",
                     expect_present ? "present" : "absent",
                     owner.active ? "true" : "false",
                     owner.port);
    }
    return ok ? 0 : -1;
}

static int verify_acl_independent_owner(
    int sw, const hal_acl_independent_args *args, bool expect_present,
    struct verify_result *result) {
    hal_acl_independent_result owner;
    bool ok;
    int rc;

    memset(&owner, 0, sizeof(owner));
    rc = hal_acl_independent_readback_match(sw, args, &owner);
    ok = rc == 0 && owner.ok &&
         (expect_present ? owner.active : !owner.active);
    if (ok && expect_present && args) {
        ok = owner.slot == args->slot &&
             owner.port == args->port &&
             owner.vid == args->vid;
    }

    if (result) {
        result->sdk_status = rc;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "independent-acl expected %s active=%s slot=%d port=%d",
                     expect_present ? "present" : "absent",
                     owner.active ? "true" : "false",
                     owner.slot, owner.port);
    }
    return ok ? 0 : -1;
}

int verify_copp_class(int sw, const char *class_name, int rate_pps,
                      int burst_pkts, struct verify_result *result) {
    int got_rate = -1;
    int got_burst = -1;
    int policer = -1;
    int acl = -1;
    int rule = -1;
    int rc = hal_control_plane_copp_get(sw, class_name, &got_rate, &got_burst,
                                        &policer, &acl, &rule, NULL, NULL);
    int tolerance = rate_pps / 10;
    bool rate_ok;
    bool burst_ok;
    bool ok;

    if (tolerance < 16)
        tolerance = 16;
    rate_ok = rc == 0 && got_rate >= rate_pps - tolerance &&
              got_rate <= rate_pps + tolerance;
    burst_ok = rc == 0 && got_burst >= burst_pkts;
    ok = rate_ok && burst_ok && policer > 0 && acl > 0 && rule >= 0;

    if (result) {
        result->sdk_status = rc;
        result->readback_ok = ok;
        if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "CoPP %s expected rate=%dpps burst=%dpkts got rate=%dpps burst=%dpkts acl=%d rule=%d policer=%d",
                     class_name ? class_name : "-", rate_pps, burst_pkts,
                     got_rate, got_burst, acl, rule, policer);
    }
    return ok ? 0 : -1;
}

static int verify_vlan_presence(int sw, u16 vlan_id, bool expect_present,
                                struct verify_result *result) {
    hal_presence_snapshot snapshot =
        hal_vlan_presence_snapshot(sw, vlan_id);
    bool ok = snapshot.state ==
        (expect_present ? HAL_PRESENCE_PRESENT : HAL_PRESENCE_ABSENT);

    if (result) {
        result->sdk_status =
            snapshot.state == HAL_PRESENCE_READ_ERROR ?
            snapshot.sdk_status : 0;
        result->readback_ok = ok;
        if (snapshot.state == HAL_PRESENCE_READ_ERROR)
            snprintf(result->detail, sizeof(result->detail),
                     "VLAN %u read-back failed: %s", vlan_id,
                     fmErrorMsg((fm_status)snapshot.sdk_status));
        else if (!ok && expect_present)
            snprintf(result->detail, sizeof(result->detail),
                     "VLAN %u not found in hardware", vlan_id);
        else if (!ok)
            snprintf(result->detail, sizeof(result->detail),
                     "VLAN %u still exists after delete", vlan_id);
    }
    return ok ? 0 : -1;
}

int verify_vlan_exists(int sw, u16 vlanId,
                       struct verify_result *result) {
    return verify_vlan_presence(sw, vlanId, true, result);
}

static int verify_vlan_member_presence(
    int sw, u16 vlan_id, int port, bool expect_present,
    bool check_tag, bool expect_tagged, struct verify_result *result) {
    hal_presence_snapshot snapshot =
        hal_vlan_member_snapshot(sw, vlan_id, port);
    bool presence_ok = snapshot.state ==
        (expect_present ? HAL_PRESENCE_PRESENT : HAL_PRESENCE_ABSENT);
    bool tag_ok = !check_tag ||
        (snapshot.state == HAL_PRESENCE_PRESENT &&
         snapshot.tagged == expect_tagged);
    bool ok = presence_ok && tag_ok;

    if (result) {
        result->sdk_status =
            snapshot.state == HAL_PRESENCE_READ_ERROR ?
            snapshot.sdk_status : 0;
        result->readback_ok = ok;
        if (snapshot.state == HAL_PRESENCE_READ_ERROR)
            snprintf(result->detail, sizeof(result->detail),
                     "VLAN %u port %d read-back failed: %s",
                     vlan_id, port,
                     fmErrorMsg((fm_status)snapshot.sdk_status));
        else if (!presence_ok && expect_present)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d not in VLAN %u", port, vlan_id);
        else if (!presence_ok)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d still in VLAN %u after remove",
                     port, vlan_id);
        else if (!tag_ok)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d in VLAN %u but tag mismatch",
                     port, vlan_id);
    }
    return ok ? 0 : -1;
}

int verify_vlan_exists_with_ports(int sw, u16 vlanId,
                                   const int *expected_ports,
                                   int n_expected_ports,
                                   struct verify_result *result) {
    // First check VLAN exists
    if (verify_vlan_exists(sw, vlanId, result) != 0)
        return -1;

    if (expected_ports && n_expected_ports > 0) {
        for (int i = 0; i < n_expected_ports; i++) {
            if (verify_vlan_member_presence(
                    sw, vlanId, expected_ports[i], true,
                    false, false, result) != 0)
                return -1;
        }
    }
    return 0;
}

int verify_vlan_port_member(int sw, u16 vlanId, int port,
                            bool expect_tagged,
                            struct verify_result *result) {
    return verify_vlan_member_presence(
        sw, vlanId, port, true, true, expect_tagged, result);
}

int verify_pvid(int sw, int port, u16 expected_vid,
                struct verify_result *result) {
    // Read back PVID via fmGetPortAttribute
    fm_uint32 pvid = 0;
    fm_status st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                                       FM_PORT_DEF_VLAN, &pvid);
    if (st != FM_OK) {
        if (result) {
            result->sdk_status = (int)st;
            result->readback_ok = false;
            snprintf(result->detail, sizeof(result->detail),
                     "PVID readback failed: %s", fmErrorMsg(st));
        }
        return -1;
    }

    bool match = ((u16)pvid == expected_vid);
    if (result) {
        result->sdk_status = 0;
        result->readback_ok = match;
        if (!match)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d: expected PVID=%u got=%u", port, expected_vid, (unsigned)pvid);
    }
    return match ? 0 : -1;
}

int verify_stp_state(int sw, u16 vlanId, int port, int expected_state,
                     struct verify_result *result) {
    fm_int stp_state;
    fm_status st = fmGetVlanPortState((fm_int)sw, (fm_int)vlanId,
                                       (fm_int)port, &stp_state);
    if (st != FM_OK) {
        if (result) {
            result->sdk_status = (int)st;
            result->readback_ok = false;
            snprintf(result->detail, sizeof(result->detail),
                     "STP readback failed: %s", fmErrorMsg(st));
        }
        return -1;
    }

    bool match = ((int)stp_state == expected_state);
    if (result) {
        result->sdk_status = 0;
        result->readback_ok = match;
        if (!match)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d VLAN %u: expected STP=%d got=%d",
                     port, vlanId, expected_state, (int)stp_state);
    }
    return match ? 0 : -1;
}

static bool readback_port_target_equal(const l2_apply_step *left,
                                       const l2_apply_step *right) {
    if (!left || !right)
        return false;
    if (left->ae_id >= 0 && right->ae_id >= 0)
        return left->ae_id == right->ae_id;
    return left->port > 0 && left->port == right->port;
}

static bool readback_lag_target_equal(const l2_apply_step *left,
                                      const l2_apply_step *right) {
    if (!left || !right)
        return false;
    if (left->ae_id >= 0 && right->ae_id >= 0)
        return left->ae_id == right->ae_id;
    return left->lag_id > 0 && left->lag_id == right->lag_id;
}

/*
 * Flow identity deliberately excludes count_only.  count_only changes the
 * action on the same live rule identity, so a later SET must supersede an
 * earlier DEL when that is the only changed field.
 */
static bool readback_ingress_acl_identity_equal(
    const hal_ingress_ipv4_acl_match *left,
    const hal_ingress_ipv4_acl_match *right) {
    if (!left || !right ||
        left->vid != right->vid ||
        left->port != right->port ||
        left->has_src_ip != right->has_src_ip ||
        left->has_dst_ip != right->has_dst_ip ||
        left->has_src_ip_mask != right->has_src_ip_mask ||
        left->has_dst_ip_mask != right->has_dst_ip_mask ||
        left->has_dscp != right->has_dscp ||
        left->has_ecn != right->has_ecn ||
        left->has_protocol != right->has_protocol ||
        left->has_src_port != right->has_src_port ||
        left->has_dst_port != right->has_dst_port ||
        left->has_src_port_range != right->has_src_port_range ||
        left->has_dst_port_range != right->has_dst_port_range ||
        left->has_tcp_flags != right->has_tcp_flags ||
        left->has_tcp_flags_mask != right->has_tcp_flags_mask)
        return false;
    return (!left->has_src_ip ||
            left->src_ip == right->src_ip) &&
        (!left->has_dst_ip ||
         left->dst_ip == right->dst_ip) &&
        (!left->has_src_ip_mask ||
         left->src_ip_mask == right->src_ip_mask) &&
        (!left->has_dst_ip_mask ||
         left->dst_ip_mask == right->dst_ip_mask) &&
        (!left->has_dscp ||
         left->dscp == right->dscp) &&
        (!left->has_ecn ||
         left->ecn == right->ecn) &&
        (!left->has_protocol ||
         left->protocol == right->protocol) &&
        (!left->has_src_port ||
         left->src_port == right->src_port) &&
        (!left->has_dst_port ||
         left->dst_port == right->dst_port) &&
        (!left->has_src_port_range ||
         (left->src_port_start == right->src_port_start &&
          left->src_port_end == right->src_port_end)) &&
        (!left->has_dst_port_range ||
         (left->dst_port_start == right->dst_port_start &&
          left->dst_port_end == right->dst_port_end)) &&
        (!left->has_tcp_flags ||
         left->tcp_flags == right->tcp_flags) &&
        (!left->has_tcp_flags_mask ||
         left->tcp_flags_mask == right->tcp_flags_mask);
}

static bool readback_watermark_switch_scoped(int attr) {
    return attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
           attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
           attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
}

/*
 * Return true only when both steps write the same final observable resource.
 * SET/DEL are intentionally paired, while independent attributes on a shared
 * parent (for example scheduler topology versus shaping, or ACL owners sharing
 * an ACL object) remain distinct and are each verified.
 */
static bool readback_resource_equal(const l2_apply_step *left,
                                    const l2_apply_step *right) {
    if (!left || !right)
        return false;

#define TYPE_PAIR(set_type, del_type) \
    (right->type == (set_type) || right->type == (del_type))

    switch (left->type) {
        case L2_STEP_FM10K_GROUP_SET:
            return right->type == L2_STEP_FM10K_GROUP_SET && left->fm10k_group.epl == right->fm10k_group.epl;
        case L2_STEP_FM10K_FAN_SET:
            return right->type == L2_STEP_FM10K_FAN_SET;
        case L2_STEP_NONE:
            return false;
        case L2_STEP_VLAN_CREATE:
        case L2_STEP_VLAN_DELETE:
            return TYPE_PAIR(L2_STEP_VLAN_CREATE, L2_STEP_VLAN_DELETE) &&
                   left->vid == right->vid;
        case L2_STEP_VLAN_ADD_PORT:
        case L2_STEP_VLAN_REM_PORT:
            return TYPE_PAIR(L2_STEP_VLAN_ADD_PORT,
                             L2_STEP_VLAN_REM_PORT) &&
                   left->vid == right->vid &&
                   readback_port_target_equal(left, right);
        case L2_STEP_PVID_SET:
            return right->type == L2_STEP_PVID_SET &&
                   readback_port_target_equal(left, right);
        case L2_STEP_VLAN_STP_SET:
            return right->type == L2_STEP_VLAN_STP_SET &&
                   left->vid == right->vid &&
                   readback_port_target_equal(left, right);
        case L2_STEP_PORT_SET_ADMIN:
            return right->type == L2_STEP_PORT_SET_ADMIN &&
                   readback_port_target_equal(left, right);
        case L2_STEP_PORT_SET_MTU:
            return right->type == L2_STEP_PORT_SET_MTU &&
                   readback_port_target_equal(left, right);
        case L2_STEP_PORT_SET_SPEED:
            return right->type == L2_STEP_PORT_SET_SPEED &&
                   readback_port_target_equal(left, right);
        case L2_STEP_PORT_PARSER_SET:
            return right->type == L2_STEP_PORT_PARSER_SET &&
                   readback_port_target_equal(left, right);
        case L2_STEP_PORT_INGRESS_FILTER_SET:
            return right->type == L2_STEP_PORT_INGRESS_FILTER_SET &&
                   readback_port_target_equal(left, right);
        case L2_STEP_MAC_AGING_SET:
            return right->type == L2_STEP_MAC_AGING_SET;
        case L2_STEP_STATIC_MAC_ADD:
        case L2_STEP_STATIC_MAC_DEL:
            return TYPE_PAIR(L2_STEP_STATIC_MAC_ADD,
                             L2_STEP_STATIC_MAC_DEL) &&
                   left->vid == right->vid &&
                   memcmp(left->mac, right->mac,
                          sizeof(left->mac)) == 0;
        case L2_STEP_LAG_CREATE:
        case L2_STEP_LAG_DELETE:
            return TYPE_PAIR(L2_STEP_LAG_CREATE, L2_STEP_LAG_DELETE) &&
                   readback_lag_target_equal(left, right);
        case L2_STEP_LAG_ADD_PORT:
        case L2_STEP_LAG_DEL_PORT:
            return TYPE_PAIR(L2_STEP_LAG_ADD_PORT,
                             L2_STEP_LAG_DEL_PORT) &&
                   readback_lag_target_equal(left, right) &&
                   left->port == right->port;
        case L2_STEP_LAG_HASH_ROTATION_SET:
            return right->type == L2_STEP_LAG_HASH_ROTATION_SET &&
                   readback_lag_target_equal(left, right);
        case L2_STEP_DHCP_SNOOPING_SET:
        case L2_STEP_DHCP_SNOOPING_DEL:
            return TYPE_PAIR(L2_STEP_DHCP_SNOOPING_SET,
                             L2_STEP_DHCP_SNOOPING_DEL) &&
                   left->security_vid == right->security_vid &&
                   left->security_port == right->security_port;
        case L2_STEP_ARP_INSPECTION_SET:
        case L2_STEP_ARP_INSPECTION_DEL:
            return TYPE_PAIR(L2_STEP_ARP_INSPECTION_SET,
                             L2_STEP_ARP_INSPECTION_DEL) &&
                   left->security_vid == right->security_vid &&
                   left->security_port == right->security_port;
        case L2_STEP_ARP_INSPECTION_BINDING_SET:
        case L2_STEP_ARP_INSPECTION_BINDING_DEL:
            return TYPE_PAIR(L2_STEP_ARP_INSPECTION_BINDING_SET,
                             L2_STEP_ARP_INSPECTION_BINDING_DEL) &&
                   left->security_vid == right->security_vid &&
                   left->security_port == right->security_port &&
                   left->security_ip == right->security_ip &&
                   memcmp(left->security_mac, right->security_mac,
                          sizeof(left->security_mac)) == 0;
        case L2_STEP_USER_FILTER_SET:
        case L2_STEP_USER_FILTER_DEL:
            return TYPE_PAIR(L2_STEP_USER_FILTER_SET,
                             L2_STEP_USER_FILTER_DEL) &&
                   left->security_vid == right->security_vid &&
                   left->security_port == right->security_port &&
                   left->security_mac_kind == right->security_mac_kind &&
                   memcmp(left->security_mac, right->security_mac,
                          sizeof(left->security_mac)) == 0;
        case L2_STEP_INGRESS_IPV4_ACL_SET:
        case L2_STEP_INGRESS_IPV4_ACL_DEL:
            return TYPE_PAIR(L2_STEP_INGRESS_IPV4_ACL_SET,
                             L2_STEP_INGRESS_IPV4_ACL_DEL) &&
                   readback_ingress_acl_identity_equal(
                       &left->ingress_ipv4_acl,
                       &right->ingress_ipv4_acl);
        case L2_STEP_ACL_POLICER_SET:
        case L2_STEP_ACL_POLICER_DEL:
            return TYPE_PAIR(L2_STEP_ACL_POLICER_SET,
                             L2_STEP_ACL_POLICER_DEL) &&
                   left->acl_policer.port == right->acl_policer.port &&
                   left->acl_policer.dst_mac ==
                       right->acl_policer.dst_mac;
        case L2_STEP_EGRESS_ACL_SET:
        case L2_STEP_EGRESS_ACL_DEL:
            return TYPE_PAIR(L2_STEP_EGRESS_ACL_SET,
                             L2_STEP_EGRESS_ACL_DEL) &&
                   left->egress_acl.port == right->egress_acl.port &&
                   left->egress_acl.src_mac ==
                       right->egress_acl.src_mac &&
                   left->egress_acl.dst_mac ==
                       right->egress_acl.dst_mac;
        case L2_STEP_ACL_INDEPENDENT_SET:
        case L2_STEP_ACL_INDEPENDENT_DEL:
            return TYPE_PAIR(L2_STEP_ACL_INDEPENDENT_SET,
                             L2_STEP_ACL_INDEPENDENT_DEL) &&
                   left->acl_independent.slot ==
                       right->acl_independent.slot;
        case L2_STEP_COPP_CLASS_SET:
            return right->type == L2_STEP_COPP_CLASS_SET &&
                   strncmp(left->copp_class, right->copp_class,
                           sizeof(left->copp_class)) == 0;
        case L2_STEP_STORM_CONTROL_SET:
        case L2_STEP_STORM_CONTROL_DEL:
            return TYPE_PAIR(L2_STEP_STORM_CONTROL_SET,
                             L2_STEP_STORM_CONTROL_DEL) &&
                   left->port == right->port && left->storm_kind == right->storm_kind;
        case L2_STEP_INGRESS_RATE_LIMIT_SET:
        case L2_STEP_INGRESS_RATE_LIMIT_DEL:
            return TYPE_PAIR(L2_STEP_INGRESS_RATE_LIMIT_SET,
                             L2_STEP_INGRESS_RATE_LIMIT_DEL) &&
                   left->port == right->port;
        case L2_STEP_EGRESS_RATE_LIMIT_SET:
        case L2_STEP_EGRESS_RATE_LIMIT_DEL:
            return TYPE_PAIR(L2_STEP_EGRESS_RATE_LIMIT_SET,
                             L2_STEP_EGRESS_RATE_LIMIT_DEL) &&
                   left->port == right->port;
        case L2_STEP_QOS_INTERFACE_SET:
        case L2_STEP_QOS_INTERFACE_DEL:
            if (right->type == L2_STEP_LAG_DELETE && left->ae_id >= 0 && left->ae_id == right->ae_id)
                return true; /* Deleting the owner also removes its classifier. */
            return TYPE_PAIR(L2_STEP_QOS_INTERFACE_SET,
                             L2_STEP_QOS_INTERFACE_DEL) &&
                   readback_port_target_equal(left, right);
        case L2_STEP_QOS_PRIORITY_MAP_SET:
        case L2_STEP_QOS_PRIORITY_MAP_DEL:
            return TYPE_PAIR(L2_STEP_QOS_PRIORITY_MAP_SET,
                             L2_STEP_QOS_PRIORITY_MAP_DEL) &&
                   left->qos_switch_priority ==
                       right->qos_switch_priority;
        case L2_STEP_QOS_TC_SMP_SET:
            return right->type == L2_STEP_QOS_TC_SMP_SET &&
                   left->qos_traffic_class == right->qos_traffic_class;
        case L2_STEP_QOS_DSCP_SET:
            return right->type == L2_STEP_QOS_DSCP_SET &&
                   left->qos_dscp == right->qos_dscp;
        case L2_STEP_QOS_PFC_SET:
        case L2_STEP_QOS_PFC_DEL:
            return TYPE_PAIR(L2_STEP_QOS_PFC_SET,
                             L2_STEP_QOS_PFC_DEL) &&
                   left->port == right->port;
        case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
        case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL:
            return TYPE_PAIR(L2_STEP_QOS_SCHEDULER_TC_MAP_SET,
                             L2_STEP_QOS_SCHEDULER_TC_MAP_DEL) &&
                   left->port == right->port &&
                   left->qos_scheduler_traffic_class ==
                       right->qos_scheduler_traffic_class;
        case L2_STEP_QOS_SCHEDULER_GROUP_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
            return TYPE_PAIR(L2_STEP_QOS_SCHEDULER_GROUP_SET,
                             L2_STEP_QOS_SCHEDULER_GROUP_DEL) &&
                   left->port == right->port &&
                   left->qos_scheduler_group ==
                       right->qos_scheduler_group;
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET:
        case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
            return TYPE_PAIR(
                       L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET,
                       L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL) &&
                   left->port == right->port &&
                   left->qos_scheduler_group ==
                       right->qos_scheduler_group;
        case L2_STEP_QOS_SCHEDULER_PORT_SET:
        case L2_STEP_QOS_SCHEDULER_PORT_DEL:
            return TYPE_PAIR(L2_STEP_QOS_SCHEDULER_PORT_SET,
                             L2_STEP_QOS_SCHEDULER_PORT_DEL) &&
                   left->port == right->port;
        case L2_STEP_QOS_WATERMARK_SET:
        case L2_STEP_QOS_WATERMARK_DEL: {
            bool switch_scoped;

            if (!TYPE_PAIR(L2_STEP_QOS_WATERMARK_SET,
                           L2_STEP_QOS_WATERMARK_DEL) ||
                left->qos_watermark_attr !=
                    right->qos_watermark_attr ||
                left->qos_watermark_index !=
                    right->qos_watermark_index)
                return false;
            switch_scoped = readback_watermark_switch_scoped(
                left->qos_watermark_attr);
            return switch_scoped || left->port == right->port;
        }
        case L2_STEP_MIRROR_SESSION_SET:
        case L2_STEP_MIRROR_SESSION_DEL:
            return TYPE_PAIR(L2_STEP_MIRROR_SESSION_SET,
                             L2_STEP_MIRROR_SESSION_DEL) &&
                   left->mirror.group == right->mirror.group;
        case L2_STEP_IGMP_LISTENER_SET:
        case L2_STEP_IGMP_LISTENER_DEL:
            return TYPE_PAIR(L2_STEP_IGMP_LISTENER_SET,
                             L2_STEP_IGMP_LISTENER_DEL) &&
                   left->vid == right->vid &&
                   left->port == right->port &&
                   memcmp(left->mac, right->mac,
                          sizeof(left->mac)) == 0;
    }

#undef TYPE_PAIR
    return false;
}

static int readback_superseding_step_index(const l2_apply_plan *plan,
                                           int index, int n) {
    if (!plan || index < 0 || index >= n)
        return -1;
    for (int i = index + 1; i < n; i++)
        if (readback_resource_equal(&plan->steps[index],
                                    &plan->steps[i]))
            return i;
    return -1;
}

static int verify_mirror_session(int sw, const hal_mirror_state *expected,
                                 bool expect_present,
                                 struct verify_result *result) {
    hal_mirror_state actual;
    int rc = hal_mirror_state_get(sw, NETLAB_MIRROR_V1_GROUP, &actual);
    bool match = rc == 0 &&
        (expect_present ? hal_mirror_state_equal(expected, &actual)
                        : !actual.exists);

    if (result) {
        result->sdk_status = rc;
        result->readback_ok = match;
        if (!match) {
            snprintf(result->detail, sizeof(result->detail),
                     "mirror group %d: expected %s destination=%d sources=%d; got present=%d destination=%d sources=%d",
                     NETLAB_MIRROR_V1_GROUP,
                     expect_present ? "present" : "absent",
                     expected ? expected->destination_port : 0,
                     expected ? expected->n_sources : 0,
                     actual.exists ? 1 : 0,
                     actual.destination_port, actual.n_sources);
        }
    }
    return match ? 0 : -1;
}

int verify_apply_plan(int sw, l2_apply_plan *plan,
                       struct verify_result *results, int max_results) {
    if (!plan || !results || max_results <= 0 ||
        plan->n_steps <= 0 ||
        plan->n_steps > L2_PLAN_MAX_STEPS ||
        plan->n_steps > plan->step_capacity || !plan->steps ||
        plan->n_steps > max_results)
        return -1;
    int n = plan->n_steps;
    int failed = 0;

    for (int i = 0; i < n; i++) {
        l2_apply_plan_checkpoint(plan);
        l2_apply_step *step = &plan->steps[i];
        struct verify_result *vr = &results[i];
        int superseding_index;

        memset(vr, 0, sizeof(*vr));
        vr->op_index = i;

        superseding_index =
            readback_superseding_step_index(plan, i, n);
        if (superseding_index >= 0) {
            vr->sdk_status = 0;
            vr->readback_ok = true;
            snprintf(vr->detail, sizeof(vr->detail),
                     "step superseded by later write at index %d",
                     superseding_index);
            continue;
        }

        switch (step->type) {
            case L2_STEP_VLAN_CREATE:
            case L2_STEP_VLAN_DELETE:  // verify deleted: should NOT exist
                verify_vlan_presence(
                    sw, step->vid,
                    step->type == L2_STEP_VLAN_CREATE, vr);
                break;
            case L2_STEP_VLAN_ADD_PORT:
                verify_vlan_port_member(sw, step->vid, step->port,
                                        step->tagged, vr);
                break;
            case L2_STEP_VLAN_REM_PORT: {
                verify_vlan_member_presence(
                    sw, step->vid, step->port, false,
                    false, false, vr);
                break;
            }
            case L2_STEP_PVID_SET:
                verify_pvid(sw, step->port, step->vid, vr);
                break;
            case L2_STEP_VLAN_STP_SET:
                verify_stp_state(sw, step->vid, step->port,
                                 step->stp_state, vr);
                break;
            case L2_STEP_PORT_SET_ADMIN:
                verify_port_state(sw, step->port, step->admin_mode, vr);
                break;
            case L2_STEP_FM10K_GROUP_SET:
                vr->sdk_status = hal_fm10k_group_verify(sw, &step->fm10k_group);
                vr->readback_ok = vr->sdk_status == 0;
                if (!vr->readback_ok) snprintf(vr->detail, sizeof(vr->detail),
                    "FM10840 EPL%d mode/admin/optical readback mismatch", step->fm10k_group.epl);
                break;
            case L2_STEP_FM10K_FAN_SET:
                vr->sdk_status = hal_fm10k_fan_verify(sw, &step->fm10k_fan);
                vr->readback_ok = vr->sdk_status == 0;
                if (!vr->readback_ok) snprintf(vr->detail, sizeof(vr->detail),
                    "FM10840 fan curve readback mismatch or unavailable");
                break;
            case L2_STEP_PORT_SET_MTU:
                verify_port_mtu(sw, step->port, step->mtu, vr);
                break;
            case L2_STEP_PORT_SET_SPEED:
                verify_port_speed(sw, step->port, step->speed, vr);
                break;
            case L2_STEP_PORT_INGRESS_FILTER_SET: {
                fm_bool enabled = FALSE;
                fm_status st = fmGetPortAttribute(sw, step->port, FM_PORT_DROP_BV, &enabled);
                vr->sdk_status = st == FM_OK ? 0 : (int)st;
                vr->readback_ok = st == FM_OK && enabled == (step->ingress_filtering ? TRUE : FALSE);
                if (!vr->readback_ok)
                    snprintf(vr->detail, sizeof(vr->detail), "port %d: expected ingress-filter=%d got=%d",
                             step->port, step->ingress_filtering, (int)enabled);
                break;
            }
            case L2_STEP_PORT_PARSER_SET: {
                fm_int parser = 0;
                fm_status st = fmGetPortAttribute((fm_int)sw,
                                                  (fm_int)step->port,
                                                  FM_PORT_PARSER, &parser);
                vr->sdk_status = (st == FM_OK) ? 0 : (int)st;
                vr->readback_ok = (st == FM_OK &&
                                   (int)parser == step->parser_mode);
                if (!vr->readback_ok)
                    snprintf(vr->detail, sizeof(vr->detail),
                             "port %d: expected parser=%d got=%d",
                             step->port, step->parser_mode, (int)parser);
                break;
            }
            case L2_STEP_MAC_AGING_SET:
                verify_mac_aging_time(sw, step->aging_time, vr);
                break;
            case L2_STEP_STATIC_MAC_ADD:
                verify_static_mac_entry(sw, step->vid, step->mac,
                                        step->port, true, vr);
                break;
            case L2_STEP_STATIC_MAC_DEL:
                verify_static_mac_entry(sw, step->vid, step->mac,
                                        0, false, vr);
                break;
            case L2_STEP_LAG_CREATE:
                if (step->lag_id > 0)
                    verify_lag_id(sw, step->lag_id, vr);
                else
                    verify_first_lag(sw, vr);
                break;
            case L2_STEP_LAG_DELETE: {
                verify_lag_presence(
                    sw, step->lag_id, false, vr);
                break;
            }
            case L2_STEP_LAG_ADD_PORT:
                verify_lag_member(sw, step->lag_id, step->port, vr);
                break;
            case L2_STEP_LAG_DEL_PORT: {
                verify_lag_member_presence(
                    sw, step->lag_id, step->port, false, vr);
                break;
            }
            case L2_STEP_LAG_HASH_ROTATION_SET:
                verify_lag_hash_rotation(sw, step->lag_id,
                                         step->lag_hash_rotation, vr);
                break;
            case L2_STEP_DHCP_SNOOPING_SET:
                verify_l2_security_rule(sw, "dhcp-snooping",
                                        (u16)step->security_vid,
                                        step->security_port, true, vr);
                break;
            case L2_STEP_DHCP_SNOOPING_DEL:
                verify_l2_security_rule(sw, "dhcp-snooping",
                                        (u16)step->security_vid,
                                        step->security_port, false, vr);
                break;
            case L2_STEP_ARP_INSPECTION_SET:
                verify_l2_security_rule(sw, "arp-inspection",
                                        (u16)step->security_vid,
                                        step->security_port, true, vr);
                break;
            case L2_STEP_ARP_INSPECTION_DEL:
                verify_l2_security_rule(sw, "arp-inspection",
                                        (u16)step->security_vid,
                                        step->security_port, false, vr);
                break;
            case L2_STEP_ARP_INSPECTION_BINDING_SET:
                verify_l2_security_binding(sw, (u16)step->security_vid,
                                           step->security_port,
                                           step->security_mac,
                                           step->security_ip, true, vr);
                break;
            case L2_STEP_ARP_INSPECTION_BINDING_DEL:
                verify_l2_security_binding(sw, (u16)step->security_vid,
                                           step->security_port,
                                           step->security_mac,
                                           step->security_ip, false, vr);
                break;
            case L2_STEP_USER_FILTER_SET:
                verify_l2_security_user_filter(sw, (u16)step->security_vid,
                                               step->security_port,
                                               step->security_mac,
                                               step->security_mac_kind,
                                               true, vr);
                break;
            case L2_STEP_USER_FILTER_DEL:
                verify_l2_security_user_filter(sw, (u16)step->security_vid,
                                               step->security_port,
                                               step->security_mac,
                                               step->security_mac_kind,
                                               false, vr);
                break;
            case L2_STEP_INGRESS_IPV4_ACL_SET:
                verify_ingress_ipv4_acl(sw, &step->ingress_ipv4_acl,
                                        true, vr);
                break;
            case L2_STEP_INGRESS_IPV4_ACL_DEL:
                verify_ingress_ipv4_acl(sw, &step->ingress_ipv4_acl,
                                        false, vr);
                break;
            case L2_STEP_ACL_POLICER_SET:
                verify_acl_policer_owner(sw, &step->acl_policer, true, vr);
                break;
            case L2_STEP_ACL_POLICER_DEL:
                verify_acl_policer_owner(sw, &step->acl_policer, false, vr);
                break;
            case L2_STEP_EGRESS_ACL_SET:
                verify_egress_acl_owner(sw, &step->egress_acl, true, vr);
                break;
            case L2_STEP_EGRESS_ACL_DEL:
                verify_egress_acl_owner(sw, &step->egress_acl, false, vr);
                break;
            case L2_STEP_ACL_INDEPENDENT_SET:
                verify_acl_independent_owner(
                    sw, &step->acl_independent, true, vr);
                break;
            case L2_STEP_ACL_INDEPENDENT_DEL:
                verify_acl_independent_owner(
                    sw, &step->acl_independent, false, vr);
                break;
            case L2_STEP_COPP_CLASS_SET:
                verify_copp_class(sw, step->copp_class,
                                  step->copp_rate_pps,
                                  step->copp_burst_pkts, vr);
                break;
            case L2_STEP_STORM_CONTROL_SET:
                verify_storm_control_kind(sw, step->port, step->storm_kind,
                                     step->storm_rate_kbps,
                                     step->storm_burst_bytes, true, vr);
                break;
            case L2_STEP_STORM_CONTROL_DEL:
                verify_storm_control_kind(sw, step->port, step->storm_kind, 0, 0, false, vr);
                break;
            case L2_STEP_INGRESS_RATE_LIMIT_SET:
                verify_ingress_rate_limit(sw, step->port,
                                          step->ingress_rate_limit_rate_kbps,
                                          step->ingress_rate_limit_burst_bytes,
                                          true, vr);
                break;
            case L2_STEP_INGRESS_RATE_LIMIT_DEL:
                verify_ingress_rate_limit(sw, step->port, 0, 0, false, vr);
                break;
            case L2_STEP_EGRESS_RATE_LIMIT_SET:
                verify_egress_rate_limit(
                    sw, step->port, step->egress_rate_limit_rate_kbps,
                    step->egress_rate_limit_burst_bytes, true, vr);
                break;
            case L2_STEP_EGRESS_RATE_LIMIT_DEL:
                verify_egress_rate_limit(sw, step->port, 0, 0, false, vr);
                break;
            case L2_STEP_QOS_INTERFACE_SET:
            case L2_STEP_QOS_INTERFACE_DEL: {
                int trust = step->type == L2_STEP_QOS_INTERFACE_SET ? step->qos_trust_mode : HAL_QOS_TRUST_IEEE8021P;
                int priority = step->type == L2_STEP_QOS_INTERFACE_SET ? step->qos_default_priority : 0;
                if (step->ae_id >= 0) {
                    hal_qos_interface_entry entry;
                    vr->sdk_status = hal_lag_qos_get(sw, hal_lag_id_for_ae(step->ae_id), &entry);
                    vr->readback_ok = !vr->sdk_status && entry.trust_mode == trust && entry.default_priority == priority;
                    if (!vr->readback_ok) snprintf(vr->detail, sizeof(vr->detail),
                        "ae%d: QoS classifier readback mismatch or unavailable", step->ae_id);
                } else {
                    verify_qos_interface(sw, step->port, trust, priority, vr);
                }
                break;
            }
            case L2_STEP_QOS_TC_SMP_SET: {
                int smp = -1;
                vr->sdk_status = hal_qos_tc_smp_get(sw, step->qos_traffic_class, &smp);
                vr->readback_ok = !vr->sdk_status && smp == step->qos_smp;
                if (!vr->readback_ok) snprintf(vr->detail, sizeof(vr->detail), "TC%d SMP readback mismatch", step->qos_traffic_class);
                break;
            }
            case L2_STEP_QOS_DSCP_SET: {
                int priority = -1;
                vr->sdk_status = hal_qos_dscp_get(sw, step->qos_dscp, &priority);
                vr->readback_ok = !vr->sdk_status && priority == step->qos_dscp_priority;
                if (!vr->readback_ok) snprintf(vr->detail, sizeof(vr->detail),
                                                "DSCP%d priority readback mismatch", step->qos_dscp);
                break;
            }
            case L2_STEP_QOS_PFC_SET:
                verify_qos_pfc(sw, step->port,
                               step->qos_pfc_rx_class_mask,
                               step->qos_pfc_tx_pause_mode,
                               step->qos_pfc_tx_class_mask,
                               step->qos_pfc_lossless_smp_mask,
                               step->qos_pfc_shared_pause_mask, &step->qos_pfc_watchdog, vr);
                break;
            case L2_STEP_QOS_PFC_DEL:
                verify_qos_pfc(sw, step->port, 0,
                               FM_PORT_TX_PAUSE_NORMAL, 0xff, 0, 0, NULL, vr);
                break;
            case L2_STEP_QOS_PRIORITY_MAP_SET:
                verify_qos_priority_map(sw, step->qos_switch_priority,
                                        step->qos_traffic_class, vr);
                break;
            case L2_STEP_QOS_PRIORITY_MAP_DEL:
                verify_qos_priority_map(sw, step->qos_switch_priority,
                                        step->qos_switch_priority & 7, vr);
                break;
            case L2_STEP_QOS_SCHEDULER_TC_MAP_SET:
                verify_qos_scheduler_tc_map(
                    sw, step->port, step->qos_scheduler_traffic_class,
                    step->qos_scheduler_shaping_group, vr);
                break;
            case L2_STEP_QOS_SCHEDULER_TC_MAP_DEL:
                verify_qos_scheduler_tc_map(
                    sw, step->port, step->qos_scheduler_traffic_class,
                    0, vr);
                break;
            case L2_STEP_QOS_SCHEDULER_GROUP_SET:
                verify_qos_scheduler_group(
                    sw, step->port, step->qos_scheduler_group,
                    step->qos_scheduler_strict_priority,
                    step->qos_scheduler_weight, vr);
                break;
            case L2_STEP_QOS_SCHEDULER_GROUP_DEL:
                verify_qos_scheduler_group(
                    sw, step->port, step->qos_scheduler_group,
                    1, 0, vr);
                break;
            case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_SET:
                verify_qos_scheduler_group_shaping(
                    sw, step->port, step->qos_scheduler_group,
                    step->qos_scheduler_group_rate_bps,
                    step->qos_scheduler_group_burst_bits, true, vr);
                break;
            case L2_STEP_QOS_SCHEDULER_GROUP_SHAPING_DEL:
                verify_qos_scheduler_group_shaping(
                    sw, step->port, step->qos_scheduler_group,
                    0, 0, false, vr);
                break;
            case L2_STEP_QOS_SCHEDULER_PORT_SET:
                verify_qos_scheduler_port(
                    sw, step->port,
                    step->qos_scheduler_traffic_class_enable_mask, vr);
                break;
            case L2_STEP_QOS_SCHEDULER_PORT_DEL:
                verify_qos_scheduler_port(sw, step->port, 0xff, vr);
                break;
            case L2_STEP_QOS_WATERMARK_SET:
                verify_qos_watermark(sw, step->port,
                                     step->qos_watermark_attr,
                                     step->qos_watermark_index,
                                     step->qos_watermark_value, vr);
                break;
            case L2_STEP_QOS_WATERMARK_DEL:
                if (step->qos_watermark_delete_target.state !=
                    HAL_TRANSACTION_SNAPSHOT_PRESENT) {
                    vr->sdk_status =
                        step->qos_watermark_delete_target.sdk_status;
                    vr->readback_ok = false;
                    snprintf(vr->detail, sizeof(vr->detail),
                             "qos watermark delete target was not captured");
                } else {
                    verify_qos_watermark(
                        sw, step->port,
                        step->qos_watermark_attr,
                        step->qos_watermark_index,
                        (int)step->qos_watermark_delete_target.value,
                        vr);
                }
                break;
            case L2_STEP_MIRROR_SESSION_SET:
                verify_mirror_session(sw, &step->mirror, true, vr);
                break;
            case L2_STEP_MIRROR_SESSION_DEL:
                verify_mirror_session(sw, &step->mirror, false, vr);
                break;
            case L2_STEP_IGMP_LISTENER_SET:
            case L2_STEP_IGMP_LISTENER_DEL: {
                int present = hal_l2_mcast_listener_present(
                    sw, step->vid, step->mac, step->port);
                bool expected = step->type == L2_STEP_IGMP_LISTENER_SET;
                vr->sdk_status = present < 0 ? present : 0;
                vr->readback_ok = present >= 0 && ((present != 0) == expected);
                if (!vr->readback_ok)
                    snprintf(vr->detail, sizeof(vr->detail),
                             "IGMP listener vid=%u port=%d expected=%d got=%d",
                             step->vid, step->port, expected ? 1 : 0,
                             present);
                break;
            }
            default:
                vr->sdk_status = -1;
                vr->readback_ok = false;
                snprintf(vr->detail, sizeof(vr->detail),
                         "unsupported L2 step type %d", step->type);
                break;
        }

        if (!vr->readback_ok) {
            vr->fatal = true;
            failed++;
            NL_LOG_ERR("verify step %d (%d): %s", i, step->type, vr->detail);
        }
    }

    NL_LOG_INFO("verify_apply_plan: %d/%d steps OK", n - failed, n);
    return (failed == 0) ? 0 : -1;
}

int verify_port_state(int sw, int port, int expected_mode,
                      struct verify_result *result) {
    fm_int mode, state;
    fm_int info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
    int effective_expected = hal_port_effective_admin_mode(expected_mode);
    fm_status st = fmGetPortState((fm_int)sw, (fm_int)port, &mode, &state, info);
    if (st != FM_OK) {
        if (result) {
            result->sdk_status = (int)st;
            result->readback_ok = false;
        }
        return -1;
    }

    if (result) {
        result->sdk_status = 0;
        result->readback_ok =
            ((int)mode == effective_expected ||
             (effective_expected == FM_PORT_MODE_ADMIN_PWRDOWN &&
              (int)mode == FM_PORT_MODE_ADMIN_DOWN));
        if (!result->readback_ok)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d: expected mode=%d got=%d",
                     port, effective_expected, (int)mode);
    }
    return ((int)mode == effective_expected ||
            (effective_expected == FM_PORT_MODE_ADMIN_PWRDOWN &&
             (int)mode == FM_PORT_MODE_ADMIN_DOWN)) ? 0 : -1;
}

int verify_port_mtu(int sw, int port, int expected_mtu,
                    struct verify_result *result) {
    int max_frame = 0;
    int expected_max = hal_port_mtu_to_max_frame(expected_mtu);
    int st = hal_port_get_mtu(sw, port, NULL, &max_frame);
    bool match = st == 0 && max_frame == expected_max;

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d: expected mtu=%d max-frame=%d got max-frame=%d",
                     port, expected_mtu, expected_max, max_frame);
    }

    return match ? 0 : -1;
}

int verify_port_speed(int sw, int port, int expected_speed,
                      struct verify_result *result) {
    int speed = 0;
    int ethernet_mode = 0;
    int expected_mode = expected_speed == 10000 ? FM_ETH_MODE_10GBASE_SR :
                        expected_speed == 25000 ? FM_ETH_MODE_25GBASE_SR : -1;
    int st = expected_mode < 0 ? -1 :
             hal_port_get_speed_mode(sw, port, &speed, &ethernet_mode);
    bool match = st == 0 && speed == expected_speed &&
                 ethernet_mode == expected_mode;

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match)
            snprintf(result->detail, sizeof(result->detail),
                     "port %d: expected speed=%d mode=%s got speed=%d mode=%s",
                     port, expected_speed,
                     hal_port_ethernet_mode_name(expected_mode), speed,
                     hal_port_ethernet_mode_name(ethernet_mode));
    }
    return match ? 0 : -1;
}

int verify_mac_aging_time(int sw, int expected_seconds,
                          struct verify_result *result) {
    int seconds = 0;
    int st = hal_mac_aging_get(sw, &seconds);
    bool match = (st == 0 && seconds == expected_seconds);

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match)
            snprintf(result->detail, sizeof(result->detail),
                     "expected MAC aging-time=%d got=%d",
                     expected_seconds, seconds);
    }

    return match ? 0 : -1;
}

int verify_static_mac_entry(int sw, u16 vlanId, const u8 mac[6],
                            int expected_port, bool expect_present,
                            struct verify_result *result) {
    int port = 0;
    bool is_static = false, present = false;
    int st = hal_mac_entry_snapshot(sw, vlanId, mac, &present, &port, &is_static, NULL);
    if (st != 0) {
        if (result) {
            result->sdk_status = st;
            result->readback_ok = false;
            snprintf(result->detail, sizeof(result->detail),
                     "static MAC VLAN %u read-back failed: %s", vlanId, fmErrorMsg(st));
        }
        return -1;
    }
    bool match = expect_present ?
        (present && is_static && port == expected_port) :
        (!present || !is_static);

    if (result) {
        result->sdk_status = match ? 0 : st;
        result->readback_ok = match;
        if (!match) {
            char expected[64];
            char got[64];

            if (expect_present)
                snprintf(expected, sizeof(expected), "static port=%d",
                         expected_port);
            else
                snprintf(expected, sizeof(expected), "absent");
            if (present)
                snprintf(got, sizeof(got), "%s port=%d",
                         is_static ? "static" : "dynamic", port);
            else
                snprintf(got, sizeof(got), "absent");

            snprintf(result->detail, sizeof(result->detail),
                     "static MAC %02x:%02x:%02x:%02x:%02x:%02x VLAN %u: "
                     "expected %s got %s",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                     vlanId, expected, got);
        }
    }

    return match ? 0 : -1;
}

static int verify_rate_controller(const char *label, nl_storm_kind kind,
                                  int sw, int port, int expected_rate_kbps,
                                  int expected_burst_bytes,
                                  bool expect_present,
                                  struct verify_result *result) {
    hal_storm_rate_transaction_snapshot snapshot = kind == NL_STORM_INGRESS ?
        hal_ingress_rate_limit_transaction_snapshot(sw, port) :
        hal_storm_control_transaction_snapshot_kind(sw, port, kind);
    int st = snapshot.sdk_status;
    if (snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR) {
        if (result) {
            result->sdk_status = st ? st : -1;
            result->readback_ok = false;
            snprintf(result->detail, sizeof(result->detail), "%s port %d: read-back failed", label, port);
        }
        return -1;
    }
    hal_storm_control_entry entry = {.controller = snapshot.controller,
        .rate_kbps = (int)snapshot.rate_kbps, .burst_bytes = (int)snapshot.capacity_bytes};
    bool present = snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT;
    bool match;

    if (!expect_present) {
        match = !present;
    } else {
        int min_rate = expected_rate_kbps - expected_rate_kbps / 10;
        int max_rate = expected_rate_kbps + expected_rate_kbps / 10;
        int min_burst = expected_burst_bytes > 0 ?
                        expected_burst_bytes - expected_burst_bytes / 10 : 0;
        int max_burst = expected_burst_bytes > 0 ?
                        expected_burst_bytes + expected_burst_bytes / 10 : 0;

        if (expected_rate_kbps < 10000) {
            min_rate = expected_rate_kbps - 1000;
            max_rate = expected_rate_kbps + 1000;
        }
        if (expected_burst_bytes > 0 && expected_burst_bytes < 10000) {
            min_burst = expected_burst_bytes - 1024;
            max_burst = expected_burst_bytes + 1024;
        }

        match = present && entry.rate_kbps > 0 &&
                entry.rate_kbps >= min_rate &&
                entry.rate_kbps <= max_rate;
        if (match && expected_burst_bytes > 0) {
            match = entry.burst_bytes >= min_burst &&
                    entry.burst_bytes <= max_burst;
        }
    }

    if (expect_present && kind >= NL_STORM_BROADCAST && kind <= NL_STORM_UNKNOWN_UNICAST)
        match = present && entry.rate_kbps == expected_rate_kbps &&
                (expected_burst_bytes <= 0 || entry.burst_bytes == expected_burst_bytes);
    if (result) {
        result->sdk_status = match ? 0 : st;
        result->readback_ok = match;
        if (!match) {
            if (expect_present && present) {
                snprintf(result->detail, sizeof(result->detail),
                         "%s port %d: expected rate=%d burst=%d "
                         "got controller=%d rate=%d burst=%d",
                         label, port, expected_rate_kbps, expected_burst_bytes,
                         entry.controller, entry.rate_kbps,
                         entry.burst_bytes);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "%s port %d: expected %s got %s",
                         label, port, expect_present ? "present" : "absent",
                         present ? "present" : "absent");
            }
        }
    }

    return match ? 0 : -1;
}

int verify_storm_control(int sw, int port, int expected_rate_kbps,
                         int expected_burst_bytes, bool expect_present,
                         struct verify_result *result) {
    return verify_rate_controller("storm-control", NL_STORM_COMBINED, sw, port,
                                  expected_rate_kbps, expected_burst_bytes,
                                  expect_present, result);
}

int verify_storm_control_kind(int sw, int port, nl_storm_kind kind,
                               int expected_rate_kbps, int expected_burst_bytes,
                               bool expect_present, struct verify_result *result) {
    return verify_rate_controller(nl_storm_kind_name(kind), kind, sw, port,
                                  expected_rate_kbps, expected_burst_bytes, expect_present, result);
}

int verify_ingress_rate_limit(int sw, int port, int expected_rate_kbps,
                              int expected_burst_bytes, bool expect_present,
                              struct verify_result *result) {
    return verify_rate_controller("ingress-rate-limit", NL_STORM_INGRESS, sw, port,
                                  expected_rate_kbps, expected_burst_bytes,
                                  expect_present, result);
}

int verify_egress_rate_limit(int sw, int port, int expected_rate_kbps,
                             int expected_burst_bytes, bool expect_present,
                             struct verify_result *result) {
    hal_egress_rate_limit_entry entry;
    int st = hal_egress_rate_limit_get(sw, port, &entry);
    bool present = st == 0;
    bool match;

    if (!expect_present) {
        match = !present;
    } else {
        int min_rate = expected_rate_kbps - expected_rate_kbps / 10;
        int max_rate = expected_rate_kbps + expected_rate_kbps / 10;
        int min_burst = expected_burst_bytes > 0 ?
                        expected_burst_bytes - expected_burst_bytes / 10 : 0;
        int max_burst = expected_burst_bytes > 0 ?
                        expected_burst_bytes + expected_burst_bytes / 10 : 0;

        if (expected_rate_kbps < 10000) {
            min_rate = expected_rate_kbps - 1000;
            max_rate = expected_rate_kbps + 1000;
        }
        if (expected_burst_bytes > 0 && expected_burst_bytes < 10000) {
            min_burst = expected_burst_bytes - 1024;
            max_burst = expected_burst_bytes + 1024;
        }

        match = present && entry.rate_kbps > 0 &&
                entry.rate_kbps >= min_rate &&
                entry.rate_kbps <= max_rate;
        if (match && expected_burst_bytes > 0) {
            match = entry.burst_bytes >= min_burst &&
                    entry.burst_bytes <= max_burst;
        }
    }

    if (result) {
        result->sdk_status = match ? 0 : st;
        result->readback_ok = match;
        if (!match) {
            if (expect_present && present) {
                snprintf(result->detail, sizeof(result->detail),
                         "egress-rate-limit port %d: expected rate=%d "
                         "burst=%d got sg=%d rate=%d burst=%d",
                         port, expected_rate_kbps, expected_burst_bytes,
                         entry.shaping_group, entry.rate_kbps,
                         entry.burst_bytes);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "egress-rate-limit port %d: expected %s got %s",
                         port, expect_present ? "present" : "absent",
                         present ? "present" : "absent");
            }
        }
    }

    return match ? 0 : -1;
}

int verify_qos_interface(int sw, int port, int expected_trust_mode,
                         int expected_default_priority,
                         struct verify_result *result) {
    hal_qos_interface_entry entry;
    int st = hal_qos_interface_get(sw, port, &entry);
    bool match = st == 0 &&
                 entry.trust_mode == expected_trust_mode &&
                 entry.default_priority == expected_default_priority;

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match) {
            if (st == 0) {
                snprintf(result->detail, sizeof(result->detail),
                         "qos interface port %d: expected trust=%d "
                         "default-priority=%d got trust=%d default-priority=%d",
                         port, expected_trust_mode,
                         expected_default_priority,
                         entry.trust_mode, entry.default_priority);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "qos interface port %d: read-back failed", port);
            }
        }
    }

    return match ? 0 : -1;
}

int verify_qos_priority_map(int sw, int switch_priority,
                            int expected_traffic_class,
                            struct verify_result *result) {
    hal_qos_priority_map_entry entry;
    int st = hal_qos_priority_map_get(sw, switch_priority, &entry);
    bool match = st == 0 && entry.traffic_class == expected_traffic_class;

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match) {
            if (st == 0) {
                snprintf(result->detail, sizeof(result->detail),
                         "qos priority-map %d: expected tc=%d got tc=%d",
                         switch_priority, expected_traffic_class,
                         entry.traffic_class);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "qos priority-map %d: read-back failed",
                         switch_priority);
            }
        }
    }

    return match ? 0 : -1;
}

int verify_qos_pfc(int sw, int port, int expected_rx_class_mask,
                   int expected_tx_pause_mode,
                   int expected_tx_class_mask,
                   int expected_lossless_smp_mask,
                   int expected_shared_pause_mask,
                   const fm10k_pfc_wd_policy *expected_watchdog,
                   struct verify_result *result) {
    hal_qos_flow_control_entry entry;
    int st = hal_qos_flow_control_get(sw, port, &entry);
    fm10k_pfc_wd_policy disabled = fm10k_pfc_wd_default_policy();
    if (!expected_watchdog) expected_watchdog = &disabled;
    bool match = st == 0 &&
                 fm10k_pfc_wd_policy_equal(&entry.watchdog.policy, expected_watchdog) &&
                 (!expected_watchdog->detect_ms || entry.watchdog.supported) &&
                 entry.watchdog.saved_rx_mask < 0 &&
                 entry.rx_class_pause_mask == expected_rx_class_mask &&
                 entry.tx_pause_mode == expected_tx_pause_mode &&
                 entry.tx_class_pause_mask == expected_tx_class_mask &&
                 entry.smp_lossless_pause_mask ==
                    expected_lossless_smp_mask &&
                 entry.pc3_smp == (expected_lossless_smp_mask == 2 ? 1 : 2) &&
                 entry.shared_pause_enable_mask == expected_shared_pause_mask;

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match) {
            if (st == 0) {
                snprintf(result->detail, sizeof(result->detail),
                         "qos pfc port %d: expected rx=0x%02x "
                         "tx-mode=%d tx=0x%02x lossless=0x%02x "
                         "shared=0x%02x got rx=0x%02x tx-mode=%d "
                         "tx=0x%02x lossless=0x%02x shared=0x%02x pc3-smp=%d watchdog=%u/%u/%u",
                         port, expected_rx_class_mask,
                         expected_tx_pause_mode, expected_tx_class_mask,
                         expected_lossless_smp_mask,
                         expected_shared_pause_mask,
                         entry.rx_class_pause_mask,
                         entry.tx_pause_mode,
                         entry.tx_class_pause_mask,
                         entry.smp_lossless_pause_mask,
                         entry.shared_pause_enable_mask, entry.pc3_smp, entry.watchdog.policy.detect_ms,
                         entry.watchdog.policy.recovery_ms, entry.watchdog.policy.cooldown_ms);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "qos pfc port %d: read-back failed", port);
            }
        }
    }

    return match ? 0 : -1;
}

int verify_qos_scheduler_tc_map(int sw, int port, int traffic_class,
                                int expected_shaping_group,
                                struct verify_result *result) {
    int group = -1;
    int st = hal_qos_scheduler_tc_map_get(sw, port, traffic_class, &group);
    bool match = st == 0 && group == expected_shaping_group;

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match) {
            if (st == 0) {
                snprintf(result->detail, sizeof(result->detail),
                         "qos scheduler port %d tc %d: expected group=%d got group=%d",
                         port, traffic_class, expected_shaping_group, group);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "qos scheduler port %d tc %d: read-back failed",
                         port, traffic_class);
            }
        }
    }

    return match ? 0 : -1;
}

int verify_qos_scheduler_group(int sw, int port, int group,
                               int expected_strict_priority,
                               int expected_weight,
                               struct verify_result *result) {
    int strict = -1;
    int weight = -1;
    int st = hal_qos_scheduler_group_get(sw, port, group, &strict, &weight);
    bool match = st == 0 &&
                 strict == expected_strict_priority &&
                 weight == expected_weight;

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match) {
            if (st == 0) {
                snprintf(result->detail, sizeof(result->detail),
                         "qos scheduler port %d group %d: expected strict=%d weight=%d got strict=%d weight=%d",
                         port, group, expected_strict_priority,
                         expected_weight, strict, weight);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "qos scheduler port %d group %d: read-back failed",
                         port, group);
            }
        }
    }

    return match ? 0 : -1;
}

static bool verify_u64_roughly_equal(u64 actual, u64 expected) {
    u64 tolerance = expected / 10ULL;

    if (tolerance < 1000ULL)
        tolerance = 1000ULL;
    return actual + tolerance >= expected && expected + tolerance >= actual;
}

int verify_qos_scheduler_group_shaping(int sw, int port, int group,
                                       u64 expected_rate_bps,
                                       u64 expected_burst_bits,
                                       bool expect_present,
                                       struct verify_result *result) {
    u64 rate = 0;
    u64 burst = 0;
    int st = hal_qos_scheduler_group_shaping_get(sw, port, group,
                                                 &rate, &burst);
    bool present = st == 0;
    bool match;

    if (!expect_present) {
        match = !present;
    } else {
        match = present &&
                verify_u64_roughly_equal(rate, expected_rate_bps) &&
                verify_u64_roughly_equal(burst, expected_burst_bits);
    }

    if (result) {
        result->sdk_status = match ? 0 : st;
        result->readback_ok = match;
        if (!match) {
            if (expect_present && present) {
                snprintf(result->detail, sizeof(result->detail),
                         "qos scheduler port %d group %d shaping: expected rate=%llu burst=%llu got rate=%llu burst=%llu",
                         port, group,
                         (unsigned long long)expected_rate_bps,
                         (unsigned long long)expected_burst_bits,
                         (unsigned long long)rate,
                         (unsigned long long)burst);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "qos scheduler port %d group %d shaping: expected %s got %s",
                         port, group,
                         expect_present ? "present" : "absent",
                         present ? "present" : "absent");
            }
        }
    }

    return match ? 0 : -1;
}

int verify_qos_scheduler_port(int sw, int port,
                              int expected_traffic_class_enable_mask,
                              struct verify_result *result) {
    int mask = -1;
    int st = hal_qos_scheduler_port_get(sw, port, &mask);
    bool match = st == 0 && mask == expected_traffic_class_enable_mask;

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match) {
            if (st == 0) {
                snprintf(result->detail, sizeof(result->detail),
                         "qos scheduler port %d: expected tc-enable-mask=0x%02x got 0x%02x",
                         port, expected_traffic_class_enable_mask, mask);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "qos scheduler port %d: tc-enable-mask read-back failed",
                         port);
            }
        }
    }

    return match ? 0 : -1;
}

static bool verify_qos_watermark_value_equal(int attr,
                                             int expected,
                                             int actual) {
    u64 canonical;

    if (expected < 0 || actual < 0)
        return false;
    if (attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
        attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ||
        attr == HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE)
        return expected == actual;
    canonical = ((u64)(u32)expected + UINT64_C(191)) /
                UINT64_C(192) * UINT64_C(192);
    return canonical == (u64)(u32)actual;
}

int verify_qos_watermark(int sw, int port, int attr, int index,
                         int expected_value,
                         struct verify_result *result) {
    int actual = -1;
    int st = hal_qos_watermark_read(sw, port, attr, index, &actual);
    bool match = st == 0 &&
                 verify_qos_watermark_value_equal(attr,
                                                  expected_value,
                                                  actual);

    if (result) {
        result->sdk_status = st;
        result->readback_ok = match;
        if (!match) {
            if (st == 0) {
                snprintf(result->detail, sizeof(result->detail),
                         "qos watermark port %d attr %d index %d: expected=%d got=%d",
                         port, attr, index, expected_value, actual);
            } else {
                snprintf(result->detail, sizeof(result->detail),
                         "qos watermark port %d attr %d index %d: read-back failed",
                         port, attr, index);
            }
        }
    }

    return match ? 0 : -1;
}
