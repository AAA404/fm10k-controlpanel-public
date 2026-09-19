#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_lag.h>
#include <api/fm_api_qos.h>

static void mac_to_text(fm_macaddr mac, char *buf, size_t len) {
    snprintf(buf, len, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
             (unsigned long long)((mac >> 40) & 0xff),
             (unsigned long long)((mac >> 32) & 0xff),
             (unsigned long long)((mac >> 24) & 0xff),
             (unsigned long long)((mac >> 16) & 0xff),
             (unsigned long long)((mac >> 8) & 0xff),
             (unsigned long long)(mac & 0xff));
}

static void mac_bytes_to_text(const u8 mac[6], char *buf, size_t len) {
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int add_field(struct sdk_result *result, const char *name,
                     const char *status, const char *fmt, ...) {
    int idx;
    va_list ap;

    if (!result)
        return -1;
    idx = result->data.switch_config.n_fields;
    if (idx >= NETLAB_SWITCH_CONFIG_MAX_FIELDS)
        return -1;
    snprintf(result->data.switch_config.field[idx].name,
             sizeof(result->data.switch_config.field[idx].name), "%s", name);
    snprintf(result->data.switch_config.field[idx].status,
             sizeof(result->data.switch_config.field[idx].status), "%s",
             status ? status : "ok");
    va_start(ap, fmt);
    vsnprintf(result->data.switch_config.field[idx].value,
              sizeof(result->data.switch_config.field[idx].value), fmt, ap);
    va_end(ap);
    result->data.switch_config.n_fields++;
    return 0;
}

static int add_na(struct sdk_result *result, const char *name) {
    return add_field(result, name, "na", "NA");
}

static bool append_switch_config_text(char *buf, size_t buf_size, int *off,
                                      const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !off || !fmt || *off < 0 || (size_t)*off >= buf_size)
        return false;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_size - (size_t)*off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - (size_t)*off)
        return false;
    *off += n;
    return true;
}

static int get_int_attr(int sw, fm_int attr, const char *name,
                        struct sdk_result *result) {
    fm_int value = 0;

    if (fmGetSwitchAttribute((fm_int)sw, attr, &value) != FM_OK)
        return add_na(result, name);
    return add_field(result, name, "ok", "%d", (int)value);
}

static int get_bool_attr(int sw, fm_int attr, const char *name,
                         struct sdk_result *result) {
    fm_bool value = FALSE;

    if (fmGetSwitchAttribute((fm_int)sw, attr, &value) != FM_OK)
        return add_na(result, name);
    return add_field(result, name, "ok", "%s", value ? "on" : "off");
}

static int get_mac_attr(int sw, fm_int attr, const char *name,
                        struct sdk_result *result) {
    fm_macaddr mac = 0;
    char text[32];

    if (fmGetSwitchAttribute((fm_int)sw, attr, &mac) != FM_OK)
        return add_na(result, name);
    mac_to_text(mac, text, sizeof(text));
    return add_field(result, name, "ok", "%s", text);
}

static int get_cpu_mac_attr(int sw, struct sdk_result *result) {
    fm_macaddr mac = 0;
    char text[32];

    if (fmGetSwitchAttribute((fm_int)sw, FM_CPU_MAC, &mac) != FM_OK)
        return add_na(result, "cpu_mac");

    mac_to_text(mac, text, sizeof(text));
    if (mac == 0) {
        u8 profile_mac[NL_MAC_ADDR_LEN];
        char profile_text[32];

        memset(profile_mac, 0, sizeof(profile_mac));
        if (nl_platform_system_mac(profile_mac)) {
            mac_bytes_to_text(profile_mac, profile_text,
                              sizeof(profile_text));
            return add_field(result, "cpu_mac", "ok",
                             "%s (default; dmac trap disabled; system-mac=%s)",
                             text, profile_text);
        }
        return add_field(result, "cpu_mac", "ok",
                         "%s (default; dmac trap disabled)", text);
    }
    return add_field(result, "cpu_mac", "ok", "%s (dmac trap)", text);
}

static const char *flood_bcast_name(int value) {
    switch (value) {
    case FM_BCAST_FWD: return "fwd";
    case FM_BCAST_DISCARD: return "discard";
    case FM_BCAST_FWD_EXCPU: return "fwd_exc_cpu";
    case FM_BCAST_FLOODING_PER_PORT: return "per_port";
    default: return "unknown";
    }
}

static const char *flood_mcast_name(int value) {
    switch (value) {
    case FM_MCAST_FWD: return "fwd";
    case FM_MCAST_DISCARD: return "discard";
    case FM_MCAST_FWD_EXCPU: return "fwd_exc_cpu";
    case FM_MCAST_FLOODING_PER_PORT: return "per_port";
    default: return "unknown";
    }
}

static const char *flood_ucast_name(int value) {
    switch (value) {
    case FM_UCAST_FWD: return "fwd";
    case FM_UCAST_DISCARD: return "discard";
    case FM_UCAST_FWD_EXCPU: return "fwd_exc_cpu";
    case FM_UCAST_FLOODING_PER_PORT: return "per_port";
    default: return "unknown";
    }
}

static int get_named_int_attr(int sw, fm_int attr, const char *name,
                              const char *(*namer)(int),
                              struct sdk_result *result) {
    fm_int value = 0;

    if (fmGetSwitchAttribute((fm_int)sw, attr, &value) != FM_OK)
        return add_na(result, name);
    return add_field(result, name, "ok", "%s", namer((int)value));
}

static const char *lag_mode_name(int value) {
    switch (value) {
    case FM_MODE_STATIC: return "static";
    case FM_MODE_DYNAMIC: return "dynamic";
    default: return "unknown";
    }
}

static const char *pdu_name(int value) {
    switch (value) {
    case FM_PDU_DISCARD: return "discard";
    case FM_PDU_TOCPU: return "to_cpu";
    case FM_PDU_FORWARD: return "forward";
    default: return "unknown";
    }
}

static const char *stp_mode_name(int value) {
    switch (value) {
    case FM_SPANNING_TREE_SHARED: return "shared";
    case FM_SPANNING_TREE_PER_VLAN: return "per_vlan";
    case FM_SPANNING_TREE_MULTIPLE: return "multiple";
    default: return "unknown";
    }
}

static const char *vlan_learning_name(int value) {
    switch (value) {
    case FM_VLAN_LEARNING_MODE_INDEPENDENT: return "independent";
    case FM_VLAN_LEARNING_MODE_SHARED: return "shared";
    default: return "unknown";
    }
}

static const char *vlan_mode_name(int value) {
    switch (value) {
    case FM_VLAN_MODE_PORT: return "port";
    case FM_VLAN_MODE_8021Q: return "802.1q";
    default: return "unknown";
    }
}

static const char *lbg_mode_name(int value) {
    switch (value) {
    case FM_LBG_MODE_NPLUS1: return "nplus1";
    case FM_LBG_MODE_REDIRECT: return "redirect";
    case FM_LBG_MODE_MAPPED: return "mapped";
    case FM_LBG_MODE_MAPPED_L234HASH: return "mapped-l234hash";
    default: return "unknown";
    }
}

static const char *ip_options_name(int value) {
    if (value == FM_IP_OPTIONS_FWD)
        return "forward";
    if (value == FM_IP_OPTIONS_TRAP)
        return "trap";
    if (value == FM_IP_OPTIONS_TRAP_UCST)
        return "trap_ucast";
    if (value == FM_IP_OPTIONS_TRAP_MCST)
        return "trap_mcast";
    if (value == FM_IP_OPTIONS_LOG_UCST)
        return "log_ucast";
    return "mixed";
}

static const char *enabled_name(int enabled) {
    return enabled ? "on" : "off";
}

static void add_uint_port_attr(int sw, fm_int attr, const char *name,
                               struct sdk_result *result) {
    fm_uint32 value = 0;

    if (fmGetSwitchAttribute((fm_int)sw, attr, &value) != FM_OK) {
        (void)add_na(result, name);
        return;
    }
    (void)add_field(result, name, "ok", "0x%x (%u)",
                    (unsigned)value, (unsigned)value);
}

static void add_vlan_ethertype_list(int sw, fm_int attr, const char *name,
                                    int max_index,
                                    struct sdk_result *result) {
    char value[128];
    int off = 0;
    bool any = false;
    bool complete;

    complete = append_switch_config_text(value, sizeof(value), &off, "[");
    for (int i = 0; i <= max_index; i++) {
        fm_vlanEtherType et;

        memset(&et, 0, sizeof(et));
        et.index = i;
        if (fmGetSwitchAttribute((fm_int)sw, attr, &et) != FM_OK)
            continue;
        any = true;
        if (!append_switch_config_text(value, sizeof(value), &off,
                                       " %d:0x%04x", i, et.etherType)) {
            complete = false;
            break;
        }
    }
    if (complete)
        complete = append_switch_config_text(value, sizeof(value), &off,
                                             " ]");
    if (!any)
        (void)add_na(result, name);
    else if (!complete)
        (void)add_field(result, name, "error", "response exceeds capacity");
    else
        (void)add_field(result, name, "ok", "%s", value);
}

static void add_l2_hash_key(int sw, struct sdk_result *result) {
    fm_L2HashKey key;

    memset(&key, 0, sizeof(key));
    if (fmGetSwitchAttribute((fm_int)sw, FM_L2_HASH_KEY, &key) != FM_OK) {
        (void)add_na(result, "l2_hash_key");
        return;
    }

    (void)add_field(result, "l2_hash_key", "ok",
                    "profile=%u smac=%s dmac=%s ethertype=%s "
                    "vlan-id=%s vlan-pri=%s l2-if-ip=%s l3=%s "
                    "symmetric-mac=%s",
                    (unsigned)key.profileIndex,
                    enabled_name(key.SMACMask != 0),
                    enabled_name(key.DMACMask != 0),
                    enabled_name(key.etherTypeMask != 0),
                    enabled_name(key.vlanId1Mask != 0),
                    enabled_name(key.vlanPri1Mask != 0),
                    enabled_name(key.useL2ifIP),
                    enabled_name(key.useL3Hash),
                    enabled_name(key.symmetrizeMAC));
}

static void add_l2_hash_rotation(int sw, fm_int attr, const char *name,
                                 struct sdk_result *result) {
    fm_L2HashRot rot;

    memset(&rot, 0, sizeof(rot));
    if (fmGetSwitchAttribute((fm_int)sw, attr, &rot) != FM_OK) {
        (void)add_na(result, name);
        return;
    }

    (void)add_field(result, name, "ok",
                    "profile=%u rotation=%u l3-key=%s l3-rot=%s "
                    "ptable=%s random=%s",
                    (unsigned)rot.profileIndex,
                    (unsigned)rot.hashRotation,
                    enabled_name(rot.useL3HashKey),
                    enabled_name(rot.useL3HashRot),
                    enabled_name(rot.usePTable),
                    enabled_name(rot.randomSelection));
}

static void add_lag_hash_rotations(int sw, struct sdk_result *result) {
    fm_int lags[NETLAB_MAX_AE];
    fm_int n_lags = NETLAB_MAX_AE;
    fm_status st;

    st = fmGetLAGList((fm_int)sw, &n_lags, lags, NETLAB_MAX_AE);
    if (st == FM_ERR_NO_LAGS) {
        (void)add_field(result, "lag_hash_rotation", "ok", "no-lags");
        return;
    }
    if (st != FM_OK) {
        (void)add_na(result, "lag_hash_rotation");
        return;
    }
    if (n_lags <= 0) {
        (void)add_field(result, "lag_hash_rotation", "ok", "no-lags");
        return;
    }

    for (fm_int i = 0; i < n_lags; i++) {
        fm_uint32 rotation = 0;
        char name[48];

        snprintf(name, sizeof(name), "lag_hash_rotation[%d]",
                 (int)lags[i]);
        if (fmGetLAGAttribute((fm_int)sw, FM_LAG_HASH_ROTATION,
                              lags[i], &rotation) != FM_OK) {
            (void)add_na(result, name);
            continue;
        }
        (void)add_field(result, name, "ok", "%s (%u)",
                        rotation == 0 ? "A" :
                        rotation == 1 ? "B" : "unknown",
                        (unsigned)rotation);
    }
}

static void add_mpls_ethertype_list(int sw, struct sdk_result *result) {
    char value[96];
    int off = 0;
    bool any = false;
    bool complete;

    complete = append_switch_config_text(value, sizeof(value), &off, "[");
    for (int i = 0; i < FM_NUM_MPLS_ETHER_TYPES; i++) {
        fm_mplsEtherType et;

        memset(&et, 0, sizeof(et));
        et.index = i;
        if (fmGetSwitchAttribute((fm_int)sw, FM_SWITCH_MPLS_ETHER_TYPES,
                                 &et) != FM_OK)
            continue;
        any = true;
        if (!append_switch_config_text(value, sizeof(value), &off,
                                       " %d:0x%04x", i, et.etherType)) {
            complete = false;
            break;
        }
    }
    if (complete)
        complete = append_switch_config_text(value, sizeof(value), &off,
                                             " ]");
    if (!any)
        (void)add_na(result, "mpls_ether_types");
    else if (!complete)
        (void)add_field(result, "mpls_ether_types", "error",
                        "response exceeds capacity");
    else
        (void)add_field(result, "mpls_ether_types", "ok", "%s", value);
}

static void add_mtu_list(int sw, struct sdk_result *result) {
    char value[160];
    int off = 0;
    bool any = false;
    bool complete;

    complete = append_switch_config_text(value, sizeof(value), &off, "[");
    for (int i = 0; i < 8; i++) {
        fm_mtuEntry mtu;

        memset(&mtu, 0, sizeof(mtu));
        mtu.index = (fm_uint)i;
        if (fmGetSwitchAttribute((fm_int)sw, FM_MTU_LIST, &mtu) != FM_OK)
            continue;
        any = true;
        if (!append_switch_config_text(value, sizeof(value), &off,
                                       " %d:%u", i, (unsigned)mtu.mtu)) {
            complete = false;
            break;
        }
    }
    if (complete)
        complete = append_switch_config_text(value, sizeof(value), &off,
                                             " ]");
    if (!any)
        (void)add_na(result, "mtu_list");
    else if (!complete)
        (void)add_field(result, "mtu_list", "error",
                        "response exceeds capacity");
    else
        (void)add_field(result, "mtu_list", "ok", "%s", value);
}

static void add_qos_wm_list(int sw, fm_int attr, const char *name,
                            struct sdk_result *result) {
    char value[192];
    int off = 0;
    bool any = false;
    bool complete;

    complete = append_switch_config_text(value, sizeof(value), &off, "[");
    for (int i = 0; i < 12; i++) {
        fm_uint32 wm = 0;

        if (fmGetSwitchQOS((fm_int)sw, attr, (fm_int)i, &wm) != FM_OK) {
            complete = append_switch_config_text(value, sizeof(value), &off,
                                                 " %d:NA", i);
        } else {
            any = true;
            complete = append_switch_config_text(
                value, sizeof(value), &off,
                " %d:%uk", i, (unsigned)(wm / 1024));
        }
        if (!complete)
            break;
    }
    if (complete)
        complete = append_switch_config_text(value, sizeof(value), &off,
                                             " ]");
    if (!any)
        (void)add_na(result, name);
    else if (!complete)
        (void)add_field(result, name, "error", "response exceeds capacity");
    else
        (void)add_field(result, name, "ok", "%s", value);
}

static void add_parser_custom_tags(int sw, struct sdk_result *result) {
    for (int i = 0; i <= FM_MAX_CUSTOM_TAG_INDEX; i++) {
        fm_customTag tag;
        char name[32];

        memset(&tag, 0, sizeof(tag));
        tag.index = i;
        snprintf(name, sizeof(name), "parser_custom_tag[%d]", i);
        if (fmGetSwitchAttribute((fm_int)sw, FM_SWITCH_PARSER_CUSTOM_TAG,
                                 &tag) != FM_OK) {
            (void)add_na(result, name);
            continue;
        }
        (void)add_field(result, name, "ok",
                        "EtherType=0x%04x,Capture=0x%x,"
                        "CaptureSelect=%s,Length=%u",
                        tag.customTagConfig.etherType,
                        tag.customTagConfig.capture,
                        tag.customTagConfig.captureSelect ? "L4C/D" : "L4A/B",
                        tag.customTagConfig.length);
    }
}

static void add_parser_di_cfgs(int sw, struct sdk_result *result) {
    for (int i = 0; i <= FM_MAX_PARSER_DI_CFG_INDEX; i++) {
        fm_parserDiCfg cfg;
        fm_parserDiCfgFields *f;
        char name[32];

        memset(&cfg, 0, sizeof(cfg));
        cfg.index = i;
        snprintf(name, sizeof(name), "parser_di_cfg[%d]", i);
        if (fmGetSwitchAttribute((fm_int)sw, FM_SWITCH_PARSER_DI_CFG,
                                 &cfg) != FM_OK) {
            (void)add_na(result, name);
            continue;
        }
        f = &cfg.parserDiCfgFields;
        (void)add_field(result, name, "ok",
                        "Prot=0x%02x,L4 Port=%u,Word Offset=0x%08x,"
                        "Capture TCP Flags=%s,Filter=%s,"
                        "L4 Port Compare=%s",
                        f->protocol, f->l4Port, f->wordOffset,
                        f->captureTcpFlags ? "enabled" : "disabled",
                        f->enable ? "enabled" : "disabled",
                        f->l4Compare ? "enabled" : "disabled");
    }
}

static void add_nvm_macs(int sw, fm_nvmMacType type, const char *prefix,
                         int count, struct sdk_result *result) {
    for (int i = 0; i < count; i++) {
        fm_nvmMac entry;
        char name[32];
        char mac[32];

        memset(&entry, 0, sizeof(entry));
        entry.type = type;
        entry.index = (fm_uint32)i;
        snprintf(name, sizeof(name), "%s[%d]", prefix, i);
        if (fmGetSwitchAttribute((fm_int)sw, FM_SWITCH_NVM_MAC,
                                 &entry) != FM_OK) {
            (void)add_na(result, name);
            continue;
        }
        mac_to_text(entry.mac, mac, sizeof(mac));
        (void)add_field(result, name, "ok", "ctrl=0x%04x mac=%s",
                        entry.ctrlData, mac);
    }
}

int hal_get_switch_config(int sw, struct sdk_result *result) {
    fm_int value = 0;

    if (!result)
        return -1;
    memset(&result->data.switch_config, 0,
           sizeof(result->data.switch_config));

    (void)get_cpu_mac_attr(sw, result);
    (void)get_int_attr(sw, FM_REDIRECT_CPU_TRAFFIC, "cpu_port", result);
    add_nvm_macs(sw, FM_NVM_MAC_TYPE_CUSTOM, "custom_mac", 4, result);
    (void)get_bool_attr(sw, FM_DROP_INVALID_SMAC, "drop_invalid_smac",
                        result);
    (void)get_bool_attr(sw, FM_DROP_PAUSE, "drop_pause", result);
    (void)get_bool_attr(sw, FM_SWITCH_RX_PKT_DROP_UNKNOWN_PORT,
                        "drop_unknown_port", result);
    (void)get_int_attr(sw, FM_SWITCH_ETH_TIMESTAMP_OWNER,
                       "eth_timestamp_owner", result);
    (void)get_named_int_attr(sw, FM_BCAST_FLOODING, "flood_bcast",
                             flood_bcast_name, result);
    (void)get_named_int_attr(sw, FM_MCAST_FLOODING, "flood_mcast",
                             flood_mcast_name, result);
    (void)get_named_int_attr(sw, FM_UCAST_FLOODING, "flood_ucast",
                             flood_ucast_name, result);
    (void)get_int_attr(sw, FM_FRAME_AGING_TIME_MSEC, "frame_age_time",
                       result);
    add_uint_port_attr(sw, FM_SWITCH_GENEVE_TUNNEL_DEST_UDP_PORT,
                       "geneve_udp_port", result);
    add_uint_port_attr(sw, FM_SWITCH_GPE_TUNNEL_DEST_UDP_PORT,
                       "gpe_udp_port", result);
    (void)get_named_int_attr(sw, FM_IP_OPTIONS_DISPOSITION,
                             "ip_options_disp", ip_options_name, result);
    if (fmGetLAGAttribute((fm_int)sw, FM_LAG_LACP_DISPOSITION, 0,
                          &value) == FM_OK)
        (void)add_field(result, "lacp_disp", "ok", "%s",
                        pdu_name((int)value));
    else
        (void)add_na(result, "lacp_disp");
    (void)get_named_int_attr(sw, FM_LAG_MODE, "lag_mode", lag_mode_name,
                             result);
    (void)get_bool_attr(sw, FM_LAG_PRUNING, "lag_pruning", result);
    add_l2_hash_key(sw, result);
    add_l2_hash_rotation(sw, FM_L2_HASH_ROT_A, "l2_hash_rotation_a",
                         result);
    add_l2_hash_rotation(sw, FM_L2_HASH_ROT_B, "l2_hash_rotation_b",
                         result);
    add_lag_hash_rotations(sw, result);
    (void)get_named_int_attr(sw, FM_LBG_MODE, "lbg_mode", lbg_mode_name,
                             result);
    add_vlan_ethertype_list(sw, FM_SWITCH_MODIFY_VLAN_ETYPES,
                            "modify_vlan_ether_types",
                            FM_MAX_MODIFY_VLAN_ETYPE_INDEX, result);
    add_mpls_ethertype_list(sw, result);
    (void)get_bool_attr(sw, FM_MULTIPLE_SPT, "mstp", result);
    add_mtu_list(sw, result);
    add_parser_custom_tags(sw, result);
    add_parser_di_cfgs(sw, result);
    add_vlan_ethertype_list(sw, FM_SWITCH_PARSER_VLAN_ETYPES,
                            "parser_vlan_ether_types",
                            FM_MAX_PARSER_VLAN_ETYPE_INDEX, result);
    (void)get_mac_attr(sw, FM_SWITCH_PAUSE_SMAC, "pause_smac", result);
    add_nvm_macs(sw, FM_NVM_MAC_TYPE_PEP, "pep_mac", 9, result);
    (void)get_int_attr(sw, FM_SWITCH_PEP_TIMESTAMP_TRAP_ID,
                       "pep_timestamp_trap_id", result);
    add_qos_wm_list(sw, FM_QOS_SHARED_PAUSE_OFF_WM,
                    "qos_shared_pause_off_wm", result);
    add_qos_wm_list(sw, FM_QOS_SHARED_PAUSE_ON_WM,
                    "qos_shared_pause_on_wm", result);
    (void)get_int_attr(sw, FM_SWITCH_RESERVED_MAC_TRAP_PRI,
                       "reserved_mac_trap_pri", result);
    (void)get_int_attr(sw, FM_VLAN_LEARNING_SHARED_VLAN, "shared-fid",
                       result);
    (void)get_named_int_attr(sw, FM_SPANNING_TREE_MODE, "spanning-tree",
                             stp_mode_name, result);
    (void)get_bool_attr(sw, FM_SWITCH_TX_TIMESTAMP_MODE,
                        "tx_timestamp_mode", result);
    (void)get_named_int_attr(sw, FM_VLAN_LEARNING_MODE, "vlan-learning",
                             vlan_learning_name, result);
    (void)get_named_int_attr(sw, FM_VLAN_TYPE, "vlan_mode",
                             vlan_mode_name, result);
    add_uint_port_attr(sw, FM_SWITCH_TUNNEL_DEST_UDP_PORT, "vxlan_udp_port",
                       result);

    return result->data.switch_config.n_fields > 0 ? 0 : -1;
}
