/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "l2_plan_internal.h"
#include "netlab/stp_snapshot.h"
#include "netlab/lag_readback.h"
#include "netlab/mcast_readback.h"

#define L2_HW_LAG_XML_BUFFER_SIZE (128 * 1024)
#define L2_HW_QOS_KINDS 6
#define L2_HW_QOS_XML_BYTES 65536
typedef struct {
    bool attempted;
    char *text;
    int length;
    s32 error;
} l2_qos_readback;

typedef struct {
    bool required;
    uint32_t force_ports;
    bool failed;
    bool stp_fetch_attempted;
    nl_stp_snapshot stp_snapshot;
    bool board_fetch_attempted;
    nl_fm10k_config_snapshot board_snapshot;
    l2_qos_readback qos[L2_HW_QOS_KINDS];
    l2_qos_readback multicast;
    char detail[192];
} l2_hw_probe_state;

static _Thread_local l2_hw_probe_state g_probe_state;

static void readbacks_clear(void) {
    for (int i = 0; i < L2_HW_QOS_KINDS; ++i) {
        free(g_probe_state.qos[i].text);
        memset(&g_probe_state.qos[i], 0, sizeof(g_probe_state.qos[i]));
    }
    free(g_probe_state.multicast.text);
    memset(&g_probe_state.multicast, 0, sizeof(g_probe_state.multicast));
}
static int hardware_qos_readback(const char *kind, const char **text, s32 *error) {
    static const char *const kinds[] = {"interfaces", "flow-control", "forwarding", "scheduler", "watermarks", "dscp-map"};
    if (!text || !error) return -1;
    *text = NULL; *error = 0;
    int index = 0;
    while (index < L2_HW_QOS_KINDS && strcmp(kind, kinds[index])) ++index;
    if (index == L2_HW_QOS_KINDS) return -1;
    l2_qos_readback *readback = &g_probe_state.qos[index];
    if (!readback->attempted) {
        readback->attempted = true;
        readback->length = -1;
        readback->text = calloc(1, L2_HW_QOS_XML_BYTES);
        if (readback->text)
            readback->length = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                NL_SWITCHD_COS_GET, 0, (const u8 *)kind, (int)strlen(kind),
                (u8 *)readback->text, L2_HW_QOS_XML_BYTES, 3000, &readback->error);
    }
    *text = readback->text;
    *error = readback->error;
    return readback->length;
}

static void l2_hw_probe_record(const char *operation, const char *reason,
                               int rn, s32 ec) {
    if (!g_probe_state.required || g_probe_state.failed)
        return;
    g_probe_state.failed = true;
    snprintf(g_probe_state.detail, sizeof(g_probe_state.detail),
             "%s: %s (rpc-bytes=%d error-code=%d)",
             operation ? operation : "hardware probe",
             reason ? reason : "failed", rn, ec);
}

void l2_hw_probe_begin(bool require_hw) {
    nl_stp_snapshot_reset(&g_probe_state.stp_snapshot);
    readbacks_clear();
    memset(&g_probe_state, 0, sizeof(g_probe_state));
    g_probe_state.required = require_hw;
}

void l2_hw_force_ports(uint32_t mask) { g_probe_state.force_ports = mask; }
static bool forced_port(int port) {
    return port >= 1 && port <= 24 && (g_probe_state.force_ports & (1U << (port - 1)));
}

bool l2_hw_probe_finish(char *err, size_t err_size) {
    bool failed = g_probe_state.failed;

    if (failed && err && err_size > 0)
        snprintf(err, err_size, "hardware read-back failed: %s",
                 g_probe_state.detail);
    nl_stp_snapshot_reset(&g_probe_state.stp_snapshot);
    readbacks_clear();
    return !failed;
}

#define L2_HW_RPC_OR_RETURN(rn, ec, value) do {                         \
    if ((rn) <= 0 || (ec) != 0) {                                      \
        l2_hw_probe_record(__func__, "RPC failed", (rn), (ec));         \
        return (value);                                                 \
    }                                                                  \
} while (0)

#define L2_HW_PARSE_OR_RETURN(condition, value) do {                    \
    if (!(condition)) {                                                 \
        l2_hw_probe_record(__func__, "malformed read-back", 0, 0);      \
        return (value);                                                 \
    }                                                                  \
} while (0)

int l2_hw_inventory_ports(int *ports, int max_ports) {
    char xml[4096] = {0};
    s32 ec = 0;
    int rn;
    const char *p;
    int n = 0;

    if (!ports || max_ports <= 0)
        return 0;

    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_PORT_GET_INVENTORY, 0,
                        (const u8 *)"", 0, (u8 *)xml, sizeof(xml),
                        2000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, 0);

    p = xml;
    while ((p = strstr(p, "<port ")) && n < max_ports) {
        int id = 0;
        if (sscanf(p, "<port id=\"%d\"", &id) != 1 || id < 0) {
            l2_hw_probe_record(__func__, "malformed port inventory", rn, ec);
            return 0;
        }
        if (id > 0)
            ports[n++] = id;
        p += 6;
    }
    if (n == 0)
        l2_hw_probe_record(__func__, "empty port inventory", rn, ec);
    return n;
}

bool l2_hw_vlan_missing(int vid) {
    char payload[32];
    char resp[64] = {0};
    s32 ec = 0;
    int rn;
    int rvid = 0;
    int exists = 1;

    if (vid < 1 || vid > 4094)
        return false;

    snprintf(payload, sizeof(payload), "vid=%d", vid);
    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_VLAN_GET_STATE, 0,
                        (const u8 *)payload, (int)strlen(payload),
                        (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';
    L2_HW_PARSE_OR_RETURN(
        sscanf(resp, "vlan=%d exists=%d", &rvid, &exists) == 2, false);
    if (rvid != vid) {
        l2_hw_probe_record(__func__, "VLAN response identity mismatch", rn, ec);
        return false;
    }
    return rvid == vid && exists == 0;
}

bool l2_hw_igmp_listener_missing(const cfg_igmp_listener_intent *entry) {
    if (entry && forced_port(entry->port.hw_port)) return true;
    const char *resp;
    char group_needle[128];
    char listener_needle[64];
    const char *group;
    const char *group_end;
    s32 ec = 0;
    int rn;
    bool missing = false;

    if (!entry || entry->vid < 1 || entry->vid > 4094 ||
        entry->port.hw_port <= 0)
        return false;
    l2_qos_readback *readback = &g_probe_state.multicast;
    if (!readback->attempted) {
        readback->attempted = true;
        readback->length = -1;
        readback->text = calloc(1, NETLAB_L2_MCAST_OWNER_MAX);
        if (readback->text) {
            readback->length = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                NL_SWITCHD_L2_MULTICAST_OWNER_GET, 0, (const u8 *)"", 0,
                (u8 *)readback->text, NETLAB_L2_MCAST_OWNER_MAX - 1, 3000, &readback->error);
            if (readback->length > 0 && readback->length < NETLAB_L2_MCAST_OWNER_MAX)
                readback->text[readback->length] = '\0';
            if (readback->length > 0 && (!nl_mcast_readback_valid(readback->text, (size_t)readback->length)))
                readback->error = NL_ERR_INVALID_VALUE;
        }
    }
    resp = readback->text; rn = readback->length; ec = readback->error;
    if (rn <= 0 || ec != 0) {
        l2_hw_probe_record(__func__, "RPC failed", rn, ec);
        goto done;
    }
    snprintf(group_needle, sizeof(group_needle),
             "vlan=\"%d\" mac=\"%02x:%02x:%02x:%02x:%02x:%02x\"",
             entry->vid, entry->mac[0], entry->mac[1], entry->mac[2],
             entry->mac[3], entry->mac[4], entry->mac[5]);
    group = strstr(resp, group_needle);
    if (!group) {
        missing = true;
        goto done;
    }
    group_end = strstr(group, "</group>");
    if (!group_end) {
        l2_hw_probe_record(__func__, "malformed read-back", rn, ec);
        goto done;
    }
    snprintf(listener_needle, sizeof(listener_needle),
             "<listener port=\"%d\" vlan=\"%d\"/>",
             entry->port.hw_port, entry->vid);
    group = strstr(group, listener_needle);
    missing = !group || group >= group_end;

done:
    return missing;
}

int l2_hw_storm_controller_capacity(void) {
    char resp[8192] = {0};
    char value[32] = {0};
    s32 ec = 0;
    int rn;
    const char *p;
    const char *end;

    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_PFE_RESOURCES_GET, 0,
                        (const u8 *)"", 0, (u8 *)resp, sizeof(resp) - 1,
                        3000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, 0);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    p = strstr(resp, "<storm-control ");
    L2_HW_PARSE_OR_RETURN(p != NULL, 0);
    end = strchr(p, '>');
    L2_HW_PARSE_OR_RETURN(end != NULL, 0);
    L2_HW_PARSE_OR_RETURN(
        l2_extract_xml_attr(p, end, "capacity", value, sizeof(value)) == 0,
        0);
    return atoi(value);
}

static int fetch_lag_xml(char *resp, size_t resp_size) {
    s32 ec = 0;
    int rn;

    if (!resp || resp_size == 0)
        return -1;
    resp[0] = '\0';
    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_LAG_GET_ALL, 0,
                        (const u8 *)"", 0, (u8 *)resp, resp_size - 1,
                        2000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, -1);
    resp[rn < (int)resp_size ? rn : (int)resp_size - 1] = '\0';
    char *root = strstr(resp, "<lags"), *end = strstr(resp, "</lags>");
    L2_HW_PARSE_OR_RETURN(root && (root[5] == '>' || root[5] == ' ') &&
        end && end > root && strchr(root, '>') && strchr(root, '>') < end, -1);
    return rn;
}

static char *find_hardware_lag(char *resp, int target_ae_id) {
    char *p = resp;

    if (!resp || target_ae_id < 0)
        return NULL;
    while ((p = strstr(p, "<lag "))) {
        char *end = strstr(p, "</lag>");
        char attr[16] = {0};
        char name[32] = {0};
        if (!end) {
            l2_hw_probe_record(__func__, "malformed LAG read-back", 0, 0);
            return NULL;
        }
        if ((l2_extract_xml_attr(p, end, "ae", attr, sizeof(attr)) == 0 &&
             atoi(attr) == target_ae_id) ||
            (l2_extract_xml_attr(p, end, "name", name, sizeof(name)) == 0 &&
             l2_ae_id(name) == target_ae_id)) {
            if (nl_lag_readback_error(p, end)) {
                l2_hw_probe_record(__func__, "LAG member read-back failed", 0, NL_ERR_PRE_STATE_MISSING);
                return NULL;
            }
            return p;
        }
        p = end + strlen("</lag>");
    }
    return NULL;
}

bool l2_hw_lag_missing(int l2_ae_id) {
    char resp[L2_HW_LAG_XML_BUFFER_SIZE] = {0};

    if (fetch_lag_xml(resp, sizeof(resp)) <= 0)
        return false;
    char *lag = find_hardware_lag(resp, l2_ae_id);
    return !lag && !g_probe_state.failed;
}

int l2_hw_ae_logical_port(int l2_ae_id) {
    char resp[L2_HW_LAG_XML_BUFFER_SIZE] = {0};
    int lag_id = 0;
    int logical_port = 0;
    char *lag;
    char *end;
    char value[32];

    if (fetch_lag_xml(resp, sizeof(resp)) <= 0)
        return 0;

    lag = find_hardware_lag(resp, l2_ae_id);
    if (!lag)
        return 0;
    end = strstr(lag, "</lag>");
    if (!end) {
        l2_hw_probe_record(__func__, "malformed LAG read-back", 0, 0);
        return 0;
    }
    if (l2_extract_xml_attr(lag, end, "logical-port", value, sizeof(value)) == 0) {
        logical_port = atoi(value);
        if (logical_port > 0)
            return logical_port;
    }
    if (sscanf(lag, "<lag id=\"%d\" logical-port=\"%d\"",
               &lag_id, &logical_port) == 2 && logical_port > 0)
        return logical_port;
    return 0;
}

static int hardware_ae_member_ports(int l2_ae_id, int *members,
                                    int max_members) {
    char resp[L2_HW_LAG_XML_BUFFER_SIZE] = {0};
    char *lag;
    char *end;
    char *p;
    int n = 0;

    if (!members || max_members <= 0)
        return 0;

    if (fetch_lag_xml(resp, sizeof(resp)) <= 0)
        return 0;

    lag = find_hardware_lag(resp, l2_ae_id);
    if (!lag)
        return 0;
    end = strstr(lag, "</lag>");
    if (!end)
        return 0;

    p = lag;
    while ((p = strstr(p, "<member ")) && p < end && n < max_members) {
        int port = 0;
        if (sscanf(p, "<member port=\"%d\"", &port) == 1 && port > 0)
            members[n++] = port;
        p += strlen("<member ");
    }
    return n;
}

static const nl_stp_snapshot *hardware_stp_snapshot(void) {
    if (!g_probe_state.stp_fetch_attempted) {
        g_probe_state.stp_fetch_attempted = true;
        if (nl_stp_snapshot_fetch(
                SWITCHD_SOCKET, NL_DAEMON_L2D, 10000,
                &g_probe_state.stp_snapshot) != 0) {
            l2_hw_probe_record(__func__, "complete snapshot unavailable",
                               -1, 0);
            return NULL;
        }
    }
    if (!g_probe_state.stp_snapshot.complete)
        return NULL;
    return &g_probe_state.stp_snapshot;
}

static bool hardware_vlan_member_missing(int vid, int port) {
    const nl_stp_snapshot *snapshot;

    if (vid < 1 || vid > 4094 || port <= 0)
        return false;
    snapshot = hardware_stp_snapshot();
    if (!snapshot)
        return false;
    return !nl_stp_snapshot_has_member(snapshot, vid, port);
}

bool l2_hw_vlan_member_present(int vid, int port) {
    const nl_stp_snapshot *snapshot;

    if (vid < 1 || vid > 4094 || port <= 0)
        return false;
    snapshot = hardware_stp_snapshot();
    if (!snapshot)
        return false;
    return nl_stp_snapshot_has_member(snapshot, vid, port);
}

bool l2_hw_port_member_missing(const cfg_port_ref *port, int vid) {
    if (port && !port->is_aggregate && forced_port(port->hw_port)) return true;
    const nl_stp_snapshot *snapshot;
    int members[NETLAB_MAX_LAG_MEMBERS] = {0};
    int n_members;

    if (!port)
        return false;
    if (!port->is_aggregate)
        return hardware_vlan_member_missing(vid, port->hw_port);
    snapshot = hardware_stp_snapshot();
    if (!snapshot)
        return false;

    n_members = hardware_ae_member_ports(port->ae_id, members,
                                         NETLAB_MAX_LAG_MEMBERS);
    if (n_members <= 0)
        return !nl_stp_snapshot_has_member(snapshot, vid, port->hw_port);
    for (int i = 0; i < n_members; i++) {
        if (!nl_stp_snapshot_has_member(snapshot, vid, members[i]))
            return true;
    }
    return false;
}

bool l2_hw_admin_mismatch(int port, bool want_disabled) {
    nl_platform_identity identity;
    if (port >= 1 && port <= 24 && nl_platform_identity_get(&identity) &&
        nl_fm10k_profile_known(identity.chassis_name)) {
        if (!g_probe_state.board_fetch_attempted) {
            g_probe_state.board_fetch_attempted = true;
            nl_fm10k_config_snapshot *live = &g_probe_state.board_snapshot;
            s32 error = 0;
            int n = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                NL_SWITCHD_FM10K_CONFIG_GET, 0, NULL, 0, (u8 *)live, sizeof(*live), 5000, &error);
            if (n != (int)sizeof(*live) || error || live->schema != NL_FM10K_CONFIG_SCHEMA || live->bytes != sizeof(*live)) {
                memset(live, 0, sizeof(*live));
                l2_hw_probe_record(__func__, "live board admin readback unavailable", n, error);
            }
        }
        int group_index = (port - 1) / 4;
        const nl_fm10k_config_snapshot *live = &g_probe_state.board_snapshot;
        const fm10k_group *group = &live->groups[group_index];
        if (!(live->group_valid_mask & (1U << group_index)) || !nl_fm10k_group_valid(group) ||
            group->epl != (group_index < 3 ? group_index : group_index + 2)) {
            l2_hw_probe_record(__func__, "live board group is incomplete", 0, 0);
            return false;
        }
        bool enabled = (group->enabled & (1U << ((port - 1) % 4))) != 0;
        return enabled == want_disabled;
    }
    char payload[32];
    char resp[128] = {0};
    s32 ec = 0;
    int rn;
    char admin[16] = "?";

    if (port <= 0)
        return false;

    snprintf(payload, sizeof(payload), "port=%d", port);
    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_PORT_GET_STATE, 0,
                        (const u8 *)payload, (int)strlen(payload),
                        (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    L2_HW_PARSE_OR_RETURN(
        sscanf(resp, "port=%*d admin=%15s", admin) == 1, false);
    if (strcmp(admin, "UP") == 0)
        return want_disabled;
    if (strcmp(admin, "DOWN") == 0)
        return !want_disabled;
    l2_hw_probe_record(__func__, "unknown admin state", rn, ec);
    return false;
}

bool l2_hw_mac_aging_mismatch(int want_seconds) {
    char resp[64] = {0};
    s32 ec = 0;
    int rn;
    int got = -1;

    if (want_seconds < 0 || want_seconds > CFG_MAC_AGING_MAX_SECONDS)
        return false;

    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_MAC_AGING_GET, 0,
                        (const u8 *)"", 0, (u8 *)resp, sizeof(resp) - 1,
                        2000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    L2_HW_PARSE_OR_RETURN(
        sscanf(resp, "aging-time=%d", &got) == 1 && got >= 0, false);
    return got != want_seconds;
}

static int mirror_direction_from_readback(const char *text) {
    if (strcmp(text, "ingress") == 0)
        return HAL_MIRROR_DIRECTION_INGRESS;
    if (strcmp(text, "egress") == 0)
        return HAL_MIRROR_DIRECTION_EGRESS;
    if (strcmp(text, "both") == 0)
        return HAL_MIRROR_DIRECTION_BOTH;
    return 0;
}

bool l2_hw_port_mirror_mismatch(const cfg_port_mirror_intent *intent) {
    char resp[4096] = {0};
    char value[32];
    s32 ec = 0;
    int rn;
    const char *root;
    const char *root_end;
    const char *session;
    const char *session_end;
    int group;
    int destination;
    int declared_sources;
    int actual_sources = 0;

    if (!intent)
        return false;
    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_PORT_MIRRORING_GET, 0,
                        (const u8 *)"", 0, (u8 *)resp, sizeof(resp) - 1,
                        3000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';
    root = strstr(resp, "<port-mirroring ");
    root_end = root ? strstr(root, "</port-mirroring>") : NULL;
    L2_HW_PARSE_OR_RETURN(root && root_end, false);
    session = strstr(root, "<session ");
    if (!intent->exists)
        return session && session < root_end;
    if (!session || session >= root_end)
        return true;
    session_end = strstr(session, "</session>");
    L2_HW_PARSE_OR_RETURN(session_end && session_end < root_end, false);
    L2_HW_PARSE_OR_RETURN(
        l2_extract_xml_attr(session, session_end, "group", value,
                            sizeof(value)) == 0,
        false);
    group = atoi(value);
    L2_HW_PARSE_OR_RETURN(
        l2_extract_xml_attr(session, session_end, "destination-port", value,
                            sizeof(value)) == 0,
        false);
    destination = atoi(value);
    L2_HW_PARSE_OR_RETURN(
        l2_extract_xml_attr(session, session_end, "source-count", value,
                            sizeof(value)) == 0,
        false);
    declared_sources = atoi(value);
    if (group != NETLAB_MIRROR_V1_GROUP ||
        destination != intent->destination.hw_port ||
        declared_sources != intent->n_sources)
        return true;

    const char *p = session;
    while ((p = strstr(p, "<source ")) && p < session_end) {
        const char *end = strstr(p, "/>");
        char direction[16];
        int port;
        int sdk_direction;
        bool found = false;

        L2_HW_PARSE_OR_RETURN(end && end < session_end, false);
        L2_HW_PARSE_OR_RETURN(
            l2_extract_xml_attr(p, end, "port", value, sizeof(value)) == 0,
            false);
        port = atoi(value);
        L2_HW_PARSE_OR_RETURN(
            l2_extract_xml_attr(p, end, "direction", direction,
                                sizeof(direction)) == 0,
            false);
        sdk_direction = mirror_direction_from_readback(direction);
        L2_HW_PARSE_OR_RETURN(port > 0 && sdk_direction != 0, false);
        for (int i = 0; i < intent->n_sources; i++) {
            if (intent->sources[i].port.hw_port == port &&
                intent->sources[i].direction == sdk_direction) {
                found = true;
                break;
            }
        }
        if (!found)
            return true;
        actual_sources++;
        p = end + 2;
    }
    if (actual_sources != declared_sources)
        return true;
    if (strstr(session_end + strlen("</session>"), "<session ") &&
        strstr(session_end + strlen("</session>"), "<session ") < root_end) {
        l2_hw_probe_record(__func__, "multiple mirror sessions", rn, ec);
        return false;
    }
    return false;
}

bool l2_hw_static_mac_mismatch(const cfg_static_mac_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    nl_mac_snapshot snapshot = {0};
    u8 expected_mac[NL_MAC_ADDR_LEN];
    u8 *resp;
    s32 ec = 0;
    int rn;
    bool mismatch = true;

    if (!entry || entry->vid < 1 || entry->vid > 4094 ||
        entry->port.hw_port <= 0)
        return false;
    if (!nl_platform_parse_mac(entry->mac, expected_mac))
        return true;
    resp = malloc(NETLAB_MAX_MSG);
    if (!resp) {
        l2_hw_probe_record(__func__, "snapshot allocation failed", 0, 0);
        return false;
    }

    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_MAC_SNAPSHOT_GET, 0,
                        (const u8 *)"", 0, resp, NETLAB_MAX_MSG,
                        3000, &ec);
    if (rn <= 0 || ec != 0) {
        l2_hw_probe_record(__func__, "RPC failed", rn, ec);
        mismatch = false;
        goto done;
    }
    if (nl_mac_snapshot_decode(resp, (size_t)rn, &snapshot) != 0 ||
        !snapshot.complete) {
        l2_hw_probe_record(__func__, "incomplete MAC snapshot", rn, ec);
        mismatch = false;
        goto done;
    }
    for (u32 i = 0; i < snapshot.n_entries; i++) {
        const nl_mac_snapshot_entry *actual = &snapshot.entries[i];

        if (actual->vlan == entry->vid &&
            memcmp(actual->mac, expected_mac, sizeof(expected_mac)) == 0) {
            mismatch = actual->port != entry->port.hw_port ||
                       !actual->is_static;
            break;
        }
    }

done:
    nl_mac_snapshot_reset(&snapshot);
    free(resp);
    return mismatch;
}

static bool storm_effective_rate_matches(int expected, int actual) {
    int lower;
    int upper;

    if (expected <= 0 || actual <= 0)
        return false;

    lower = expected - expected / 3;
    upper = expected + expected / 10;
    if (expected < 10000) {
        lower = expected - 1000;
        upper = expected + 1000;
    }
    return actual >= lower && actual <= upper;
}

static bool storm_effective_burst_matches(int expected, int actual) {
    int lower;
    int upper;

    if (expected <= 0 || actual <= 0)
        return false;

    lower = expected - expected / 10;
    upper = expected + expected / 10;
    if (expected < 10000) {
        lower = expected - 1024;
        upper = expected + 1024;
    }
    return actual >= lower && actual <= upper;
}

static bool l2_hw_rate_controller_mismatch(const cfg_storm_control_intent *entry,
                                           const char *payload) {
    char resp[8192] = {0};
    s32 ec = 0;
    int rn;
    const char *p;
    size_t payload_len = payload ? strlen(payload) : 0;

    if (!entry || entry->port.hw_port <= 0 || entry->rate_kbps <= 0)
        return false;

    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_L2_RATE_LIMIT_GET, 0,
                        (const u8 *)(payload ? payload : ""), payload_len,
                        (u8 *)resp, sizeof(resp) - 1,
                        3000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';

    p = resp;
    while ((p = strstr(p, "<entry "))) {
        const char *end = strchr(p, '>');
        char port_s[32] = {0};
        char rate_s[32] = {0};
        char burst_s[32] = {0};
        char kind_s[32] = "combined";
        int port = 0;
        int rate = 0;
        int burst = 0;

        if (!end)
            break;
        if (l2_extract_xml_attr(p, end, "port", port_s, sizeof(port_s)) == 0 &&
            l2_extract_xml_attr(p, end, "rate", rate_s, sizeof(rate_s)) == 0 &&
            l2_extract_xml_attr(p, end, "burst", burst_s,
                                sizeof(burst_s)) == 0) {
            port = atoi(port_s);
            rate = atoi(rate_s);
            burst = atoi(burst_s);
        }
        if ((!payload || !*payload) &&
            l2_extract_xml_attr(p, end, "kind", kind_s, sizeof(kind_s)) != 0)
            strcpy(kind_s, "combined");
        if (port == entry->port.hw_port &&
            ((payload && *payload) || !strcmp(kind_s, nl_storm_kind_name(entry->kind)))) {
            return !storm_effective_rate_matches(entry->rate_kbps, rate) ||
                   !storm_effective_burst_matches(entry->burst_bytes, burst);
        }
        p += strlen("<entry ");
    }

    return true;
}

bool l2_hw_storm_control_mismatch(const cfg_storm_control_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    return l2_hw_rate_controller_mismatch(entry, "");
}

bool l2_hw_ingress_rate_limit_mismatch(const cfg_ingress_rate_limit_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    return l2_hw_rate_controller_mismatch(entry, "ingress-rate-limit");
}

bool l2_hw_egress_rate_limit_mismatch(
    const cfg_egress_rate_limit_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    return l2_hw_rate_controller_mismatch(entry, "egress-rate-limit");
}

static bool l2_hw_lag_qos_mismatch(const cfg_qos_interface_intent *entry) {
    char resp[L2_HW_LAG_XML_BUFFER_SIZE] = {0};
    if (fetch_lag_xml(resp, sizeof(resp)) <= 0) return false;
    char *lag = find_hardware_lag(resp, entry->port.ae_id);
    if (!lag) return !g_probe_state.failed;
    const char *lag_end = strstr(lag, "</lag>");
    const char *qos = strstr(lag, "<qos-readback ");
    const char *end = qos ? strchr(qos, '>') : NULL;
    L2_HW_PARSE_OR_RETURN(qos && end && lag_end && qos < lag_end && end < lag_end, false);
    char status[16], code[24], trust[16], priority[16];
    L2_HW_PARSE_OR_RETURN(
        !l2_extract_xml_attr(qos, end, "status", status, sizeof(status)) &&
        !l2_extract_xml_attr(qos, end, "code", code, sizeof(code)) &&
        !l2_extract_xml_attr(qos, end, "trust", trust, sizeof(trust)) &&
        !l2_extract_xml_attr(qos, end, "default-priority", priority, sizeof(priority)), false);
    if (strcmp(status, "ok") || strcmp(code, "0")) {
        l2_hw_probe_record(__func__, "LAG QoS read-back failed", 0, NL_ERR_PRE_STATE_MISSING);
        return false;
    }
    char *tail;
    long actual_trust = strtol(trust, &tail, 10);
    L2_HW_PARSE_OR_RETURN(*trust && !*tail && actual_trust >= -1 && actual_trust <= HAL_QOS_TRUST_DSCP, false);
    long actual_priority = strtol(priority, &tail, 10);
    L2_HW_PARSE_OR_RETURN(*priority && !*tail && actual_priority >= -1 && actual_priority <= 7, false);
    return actual_trust != entry->trust_mode || actual_priority != entry->default_priority;
}

bool l2_hw_qos_interface_mismatch(const cfg_qos_interface_intent *entry) {
    if (entry && entry->port.is_aggregate) return l2_hw_lag_qos_mismatch(entry);
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    const char *resp = NULL;
    s32 ec = 0;
    int rn;
    const char *p;

    if (!entry || entry->port.hw_port <= 0)
        return false;

    rn = hardware_qos_readback("interfaces", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);

    p = resp;
    while ((p = strstr(p, "<interface "))) {
        const char *end = strchr(p, '>');
        char port_s[32] = {0};
        char trust_s[32] = {0};
        char priority_s[32] = {0};
        int port = 0;
        int trust = -1;
        int priority = -1;

        if (!end)
            break;
        if (l2_extract_xml_attr(p, end, "port", port_s,
                                sizeof(port_s)) == 0 &&
            l2_extract_xml_attr(p, end, "trust", trust_s,
                                sizeof(trust_s)) == 0 &&
            l2_extract_xml_attr(p, end, "default-priority", priority_s,
                                sizeof(priority_s)) == 0) {
            port = atoi(port_s);
            priority = atoi(priority_s);
            if (strcmp(trust_s, "none") == 0)
                trust = HAL_QOS_TRUST_NONE;
            else if (strcmp(trust_s, "dscp") == 0)
                trust = HAL_QOS_TRUST_DSCP;
            else
                trust = HAL_QOS_TRUST_IEEE8021P;
        }
        if (port == entry->port.hw_port)
            return trust != entry->trust_mode ||
                   priority != entry->default_priority;
        p += strlen("<interface ");
    }

    return true;
}

bool l2_hw_qos_tc_smp_mismatch(int tc, int smp) {
    const char *resp = NULL;
    s32 ec = 0;
    int rn = hardware_qos_readback("flow-control", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    const char *p = resp;
    while ((p = strstr(p, "<traffic-class "))) {
        const char *end = strchr(p, '>');
        char id[16] = {0}, partition[24] = {0}, expected[16];
        if (!end) break;
        snprintf(expected, sizeof(expected), "smp-%d", smp);
        if (!l2_extract_xml_attr(p, end, "id", id, sizeof(id)) &&
            !l2_extract_xml_attr(p, end, "smp", partition, sizeof(partition)) &&
            atoi(id) == tc) return strcmp(partition, expected) != 0;
        p = end + 1;
    }
    return true;
}

bool l2_hw_qos_dscp_mismatch(int dscp, int priority) {
    const char *resp = NULL;
    s32 ec = 0;
    int rn = hardware_qos_readback("dscp-map", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    const char *p = resp;
    while ((p = strstr(p, "<entry "))) {
        const char *end = strchr(p, '>');
        char code[16] = {0}, value[16] = {0};
        if (!end) break;
        if (!l2_extract_xml_attr(p, end, "dscp", code, sizeof(code)) &&
            !l2_extract_xml_attr(p, end, "switch-priority", value, sizeof(value))) {
            char *code_end, *value_end;
            long actual_code = strtol(code, &code_end, 10), actual_priority = strtol(value, &value_end, 10);
            if (*code && !*code_end && *value && !*value_end && actual_code >= 0 && actual_code <= 63 &&
                actual_priority >= 0 && actual_priority <= 15 && actual_code == dscp)
                return actual_priority != priority;
        }
        p = end + 1;
    }
    L2_HW_PARSE_OR_RETURN(false, true);
    return true;
}

bool l2_hw_qos_pfc_mismatch(const cfg_qos_pfc_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    const char *resp = NULL;
    s32 ec = 0;
    int rn;
    const char *p;

    if (!entry || entry->port.hw_port <= 0)
        return false;

    rn = hardware_qos_readback("flow-control", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);

    p = resp;
    while ((p = strstr(p, "<interface "))) {
        const char *end = strchr(p, '>');
        char port_s[32] = {0};
        char rx_s[32] = {0};
        char tx_mode_s[32] = {0};
        char tx_s[32] = {0};
        char lossless_s[32] = {0};
        char shared_s[32] = {0};
        int port = 0;
        int rx = -1;
        int tx_mode = -1;
        int tx = -1;
        int lossless = -1;
        int shared = -1;

        if (!end)
            break;
        if (l2_extract_xml_attr(p, end, "port", port_s,
                                sizeof(port_s)) == 0 &&
            l2_extract_xml_attr(p, end, "rx-class-mask", rx_s,
                                sizeof(rx_s)) == 0 &&
            l2_extract_xml_attr(p, end, "tx-pause-mode", tx_mode_s,
                                sizeof(tx_mode_s)) == 0 &&
            l2_extract_xml_attr(p, end, "tx-class-mask", tx_s,
                                sizeof(tx_s)) == 0 &&
            l2_extract_xml_attr(p, end, "smp-lossless-mask", lossless_s,
                                sizeof(lossless_s)) == 0 &&
            l2_extract_xml_attr(p, end, "shared-pause-mask", shared_s,
                                sizeof(shared_s)) == 0) {
            port = atoi(port_s);
            rx = (int)strtol(rx_s, NULL, 0);
            tx = (int)strtol(tx_s, NULL, 0);
            lossless = (int)strtol(lossless_s, NULL, 0);
            shared = (int)strtol(shared_s, NULL, 0);
            if (strcmp(tx_mode_s, "class-based") == 0)
                tx_mode = 1;
            else if (strcmp(tx_mode_s, "normal") == 0)
                tx_mode = 0;
        }
        if (port == entry->port.hw_port) {
            int expected_tx_mode = entry->tx_class_mask ? 1 : 0;
            fm10k_pfc_wd_policy watchdog = fm10k_pfc_wd_default_policy();
            char wd[32];
            const char *keys[] = {"watchdog-detect-ms", "watchdog-recovery-ms", "watchdog-cooldown-ms"};
            uint32_t *values[] = {&watchdog.detect_ms, &watchdog.recovery_ms, &watchdog.cooldown_ms};
            for (unsigned i = 0; i < 3; ++i) {
                if (l2_extract_xml_attr(p, end, keys[i], wd, sizeof(wd)) != 0) return true;
                char *tail = NULL;
                unsigned long value = strtoul(wd, &tail, 10);
                if (!*wd || *tail || value > UINT32_MAX) return true;
                *values[i] = (uint32_t)value;
            }
            /* Planning may observe a live recovery lease. It must compare
             * the configured policy without mistaking a leased mask for a
             * persistent change; the owner restores it before capture. */
            if (l2_extract_xml_attr(p, end, "watchdog-phase", wd, sizeof(wd)) == 0 &&
                atoi(wd) == HAL_PFC_WD_RECOVERING &&
                l2_extract_xml_attr(p, end, "watchdog-saved-rx-mask", wd, sizeof(wd)) == 0 &&
                atoi(wd) == 8 && rx == 0 && watchdog.detect_ms) rx = 8;
            return rx != entry->rx_class_mask ||
                   tx_mode != expected_tx_mode ||
                   tx != entry->tx_class_mask ||
                   lossless != entry->lossless_smp_mask ||
                   shared != entry->shared_pause_mask ||
                   !fm10k_pfc_wd_policy_equal(&watchdog, &entry->watchdog);
        }
        p += strlen("<interface ");
    }

    return true;
}

bool l2_hw_qos_priority_map_mismatch(
    const cfg_qos_priority_map_intent *entry) {
    const char *resp = NULL;
    s32 ec = 0;
    int rn;
    const char *p;

    if (!entry || entry->switch_priority < 0 ||
        entry->switch_priority > 15)
        return false;

    rn = hardware_qos_readback("forwarding", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);

    p = resp;
    while ((p = strstr(p, "<switch-priority "))) {
        const char *end = strchr(p, '>');
        char pri_s[32] = {0};
        char tc_s[32] = {0};
        int pri = -1;
        int tc = -1;

        if (!end)
            break;
        if (l2_extract_xml_attr(p, end, "priority", pri_s,
                                sizeof(pri_s)) == 0 &&
            l2_extract_xml_attr(p, end, "traffic-class", tc_s,
                                sizeof(tc_s)) == 0) {
            pri = atoi(pri_s);
            tc = atoi(tc_s);
        }
        if (pri == entry->switch_priority)
            return tc != entry->traffic_class;
        p += strlen("<switch-priority ");
    }

    return true;
}

static bool parse_decimal_int(const char *text, int *out) {
    char *end = NULL;
    long value;

    if (!text || !text[0] || !out)
        return false;
    value = strtol(text, &end, 10);
    if (!end || *end != '\0')
        return false;
    *out = (int)value;
    return true;
}

bool l2_hw_qos_scheduler_tc_map_mismatch(
    const cfg_qos_scheduler_tc_map_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    const char *resp = NULL;
    s32 ec = 0;
    int rn;
    const char *p;

    if (!entry || entry->port.hw_port <= 0 ||
        entry->traffic_class < 0 || entry->traffic_class > 7 ||
        entry->shaping_group < 0 || entry->shaping_group > 7)
        return false;

    rn = hardware_qos_readback("scheduler", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);

    p = resp;
    while ((p = strstr(p, "<interface "))) {
        const char *tag_end = strchr(p, '>');
        const char *iface_end = strstr(p, "</interface>");
        char port_s[32] = {0};
        int port = 0;
        const char *tc;

        if (!tag_end || !iface_end)
            break;
        if (l2_extract_xml_attr(p, tag_end, "port", port_s,
                                sizeof(port_s)) != 0 ||
            !parse_decimal_int(port_s, &port)) {
            p = tag_end + 1;
            continue;
        }
        if (port != entry->port.hw_port) {
            p = iface_end + strlen("</interface>");
            continue;
        }

        tc = tag_end;
        while ((tc = strstr(tc, "<traffic-class ")) &&
               tc < iface_end) {
            const char *tc_end = strstr(tc, "/>");
            char id_s[32] = {0};
            char group_s[32] = {0};
            int id = -1;
            int group = -1;

            if (!tc_end || tc_end > iface_end)
                break;
            if (l2_extract_xml_attr(tc, tc_end, "id", id_s,
                                    sizeof(id_s)) == 0 &&
                l2_extract_xml_attr(tc, tc_end, "shaping-group", group_s,
                                    sizeof(group_s)) == 0 &&
                parse_decimal_int(id_s, &id) &&
                parse_decimal_int(group_s, &group) &&
                id == entry->traffic_class)
                return group != entry->shaping_group;
            tc = tc_end + 2;
        }
        return true;
    }

    return true;
}

bool l2_hw_qos_scheduler_group_mismatch(
    const cfg_qos_scheduler_group_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    const char *resp = NULL;
    s32 ec = 0;
    int rn;
    const char *p;

    if (!entry || entry->port.hw_port <= 0 ||
        entry->group < 0 || entry->group > 7 ||
        (entry->strict_priority != 0 && entry->strict_priority != 1) ||
        entry->weight < 0 || entry->weight > CFG_QOS_SCHEDULER_GROUP_MAX_WEIGHT)
        return false;

    rn = hardware_qos_readback("scheduler", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);

    p = resp;
    while ((p = strstr(p, "<interface "))) {
        const char *tag_end = strchr(p, '>');
        const char *iface_end = strstr(p, "</interface>");
        char port_s[32] = {0};
        int port = 0;
        const char *group;

        if (!tag_end || !iface_end)
            break;
        if (l2_extract_xml_attr(p, tag_end, "port", port_s,
                                sizeof(port_s)) != 0 ||
            !parse_decimal_int(port_s, &port)) {
            p = tag_end + 1;
            continue;
        }
        if (port != entry->port.hw_port) {
            p = iface_end + strlen("</interface>");
            continue;
        }

        group = tag_end;
        while ((group = strstr(group, "<group ")) &&
               group < iface_end) {
            const char *group_end = strstr(group, "/>");
            char id_s[32] = {0};
            char strict_s[32] = {0};
            char weight_s[32] = {0};
            int id = -1;
            int weight = -1;
            int strict = -1;

            if (!group_end || group_end > iface_end)
                break;
            if (l2_extract_xml_attr(group, group_end, "id", id_s,
                                    sizeof(id_s)) == 0 &&
                l2_extract_xml_attr(group, group_end, "strict", strict_s,
                                    sizeof(strict_s)) == 0 &&
                l2_extract_xml_attr(group, group_end, "weight", weight_s,
                                    sizeof(weight_s)) == 0 &&
                parse_decimal_int(id_s, &id) &&
                parse_decimal_int(weight_s, &weight)) {
                if (strcmp(strict_s, "on") == 0)
                    strict = 1;
                else if (strcmp(strict_s, "off") == 0)
                    strict = 0;
                if (id == entry->group)
                    return strict != entry->strict_priority ||
                           weight != entry->weight;
            }
            group = group_end + 2;
        }
        return true;
    }

    return true;
}

static bool u64_roughly_equal(u64 actual, u64 expected) {
    u64 tolerance = expected / 10ULL;

    if (tolerance < 1000ULL)
        tolerance = 1000ULL;
    return actual + tolerance >= expected && expected + tolerance >= actual;
}

bool l2_hw_qos_scheduler_group_shaping_mismatch(
    const cfg_qos_scheduler_group_shaping_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    const char *resp = NULL;
    s32 ec = 0;
    int rn;
    const char *p;

    if (!entry || entry->port.hw_port <= 0 ||
        entry->group < 0 || entry->group > 7 ||
        entry->rate_bps < 1 ||
        entry->rate_bps > CFG_QOS_SCHEDULER_GROUP_MAX_RATE_BPS ||
        entry->burst_bits < 1 ||
        entry->burst_bits > CFG_QOS_SCHEDULER_GROUP_MAX_BURST_BITS)
        return false;

    rn = hardware_qos_readback("scheduler", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);

    p = resp;
    while ((p = strstr(p, "<interface "))) {
        const char *tag_end = strchr(p, '>');
        const char *iface_end = strstr(p, "</interface>");
        char port_s[32] = {0};
        int port = 0;
        const char *group;

        if (!tag_end || !iface_end)
            break;
        if (l2_extract_xml_attr(p, tag_end, "port", port_s,
                                sizeof(port_s)) != 0 ||
            !parse_decimal_int(port_s, &port)) {
            p = tag_end + 1;
            continue;
        }
        if (port != entry->port.hw_port) {
            p = iface_end + strlen("</interface>");
            continue;
        }

        group = tag_end;
        while ((group = strstr(group, "<group ")) &&
               group < iface_end) {
            const char *group_end = strstr(group, "/>");
            char id_s[32] = {0};
            char rate_s[32] = {0};
            char burst_s[32] = {0};
            int id = -1;
            u64 rate = 0;
            u64 burst = 0;

            if (!group_end || group_end > iface_end)
                break;
            if (l2_extract_xml_attr(group, group_end, "id", id_s,
                                    sizeof(id_s)) == 0 &&
                l2_extract_xml_attr(group, group_end, "rate-bps", rate_s,
                                    sizeof(rate_s)) == 0 &&
                l2_extract_xml_attr(group, group_end, "burst-bits", burst_s,
                                    sizeof(burst_s)) == 0 &&
                parse_decimal_int(id_s, &id)) {
                if (id == entry->group) {
                    if (strcmp(rate_s, "default") == 0)
                        return true;
                    rate = strtoull(rate_s, NULL, 0);
                    burst = strtoull(burst_s, NULL, 0);
                    return !u64_roughly_equal(rate, entry->rate_bps) ||
                           !u64_roughly_equal(burst, entry->burst_bits);
                }
            }
            group = group_end + 2;
        }
        return true;
    }

    return true;
}

bool l2_hw_qos_scheduler_port_mismatch(
    const cfg_qos_scheduler_port_intent *entry) {
    if (entry && !entry->port.is_aggregate && forced_port(entry->port.hw_port)) return true;
    const char *resp = NULL;
    s32 ec = 0;
    int rn;
    const char *p;

    if (!entry || entry->port.hw_port <= 0 ||
        entry->traffic_class_enable_mask < 1 ||
        entry->traffic_class_enable_mask > 0xff)
        return false;

    rn = hardware_qos_readback("scheduler", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);

    p = resp;
    while ((p = strstr(p, "<interface "))) {
        const char *tag_end = strchr(p, '>');
        char port_s[32] = {0};
        char mask_s[32] = {0};
        int port = 0;
        int mask = 0;

        if (!tag_end)
            break;
        if (l2_extract_xml_attr(p, tag_end, "port", port_s,
                                sizeof(port_s)) == 0 &&
            l2_extract_xml_attr(p, tag_end, "tc-enable-mask", mask_s,
                                sizeof(mask_s)) == 0 &&
            parse_decimal_int(port_s, &port)) {
            mask = (int)strtol(mask_s, NULL, 0);
            if (port == entry->port.hw_port)
                return mask != entry->traffic_class_enable_mask;
        }
        p = tag_end + 1;
    }

    return true;
}

bool l2_hw_qos_watermark_mismatch(const cfg_qos_watermark_intent *entry) {
    const char *resp = NULL;
    s32 ec = 0;
    int rn;
    const char *p;
    const char *attr_name;
    bool switch_attr = false;

    if (!entry ||
        entry->traffic_class < 0 || entry->traffic_class > 7 ||
        entry->value < 0 || entry->value > CFG_QOS_WATERMARK_MAX_VALUE)
        return false;

    if (entry->attr == HAL_QOS_WATERMARK_ATTR_TX_HOG)
        attr_name = "tx-hog-wm";
    else if (entry->attr == HAL_QOS_WATERMARK_ATTR_TX_PRIVATE)
        attr_name = "tx-private-wm";
    else if (entry->attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP) {
        attr_name = "soft-drop-wm";
        switch_attr = true;
    } else if (entry->attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER) {
        attr_name = "soft-drop-jitter";
        switch_attr = true;
    } else if (entry->attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG) {
        attr_name = "soft-drop-hog-wm";
        switch_attr = true;
    } else {
        return false;
    }
    if (!switch_attr && entry->port.hw_port <= 0)
        return false;

    rn = hardware_qos_readback("watermarks", &resp, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);

    if (switch_attr) {
        p = resp;
        while ((p = strstr(p, "<switch-priority "))) {
            const char *tag_end = strstr(p, "/>");
            char id_s[32] = {0};
            char value_s[32] = {0};
            int id = -1;
            int value = -1;
            int diff;

            if (!tag_end)
                break;
            if (l2_extract_xml_attr(p, tag_end, "id", id_s,
                                    sizeof(id_s)) == 0 &&
                l2_extract_xml_attr(p, tag_end, attr_name, value_s,
                                    sizeof(value_s)) == 0 &&
                parse_decimal_int(id_s, &id) &&
                parse_decimal_int(value_s, &value)) {
                if (id == entry->traffic_class) {
                    if (entry->attr ==
                            HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER)
                        return value != entry->value;
                    diff = value > entry->value ?
                           value - entry->value : entry->value - value;
                    return diff > 192;
                }
            }
            p = tag_end + 2;
        }
        return true;
    }

    p = resp;
    while ((p = strstr(p, "<interface "))) {
        const char *tag_end = strchr(p, '>');
        const char *iface_end = strstr(p, "</interface>");
        char port_s[32] = {0};
        int port = 0;
        const char *tc;

        if (!tag_end || !iface_end)
            break;
        if (l2_extract_xml_attr(p, tag_end, "port", port_s,
                                sizeof(port_s)) != 0 ||
            !parse_decimal_int(port_s, &port)) {
            p = tag_end + 1;
            continue;
        }
        if (port != entry->port.hw_port) {
            p = iface_end + strlen("</interface>");
            continue;
        }

        tc = tag_end;
        while ((tc = strstr(tc, "<traffic-class ")) &&
               tc < iface_end) {
            const char *tc_end = strstr(tc, "/>");
            char id_s[32] = {0};
            char value_s[32] = {0};
            int id = -1;
            int value = -1;

            if (!tc_end || tc_end > iface_end)
                break;
            if (l2_extract_xml_attr(tc, tc_end, "id", id_s,
                                    sizeof(id_s)) == 0 &&
                l2_extract_xml_attr(tc, tc_end, attr_name, value_s,
                                    sizeof(value_s)) == 0 &&
                parse_decimal_int(id_s, &id)) {
                value = (int)strtol(value_s, NULL, 0);
                if (id == entry->traffic_class)
                    return value != entry->value;
            }
            tc = tc_end + 2;
        }
        return true;
    }

    return true;
}

static int l2_mtu_to_max_frame(int mtu) {
    int max_frame = mtu + 22;

    if (mtu <= 0)
        return 0;
    return (max_frame + 3) & ~3;
}

bool l2_hw_mtu_mismatch(const cfg_port_ref *port, int mtu) {
    if (port && !port->is_aggregate && forced_port(port->hw_port)) return true;
    char payload[32];
    char resp[128] = {0};
    s32 ec = 0;
    int rn;
    int rport = 0;
    int max_frame = 0;

    if (!port || port->hw_port <= 0 ||
        mtu < CFG_INTERFACE_MIN_MTU ||
        mtu > CFG_INTERFACE_MAX_MTU)
        return false;

    snprintf(payload, sizeof(payload), "port=%d", port->hw_port);
    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_PORT_MTU_GET, 0,
                        (const u8 *)payload, (int)strlen(payload),
                        (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';
    L2_HW_PARSE_OR_RETURN(
        sscanf(resp, "port=%d mtu=%*d max-frame=%d",
               &rport, &max_frame) == 2, false);

    if (rport != port->hw_port) {
        l2_hw_probe_record(__func__, "MTU response identity mismatch", rn, ec);
        return false;
    }

    return max_frame != l2_mtu_to_max_frame(mtu);
}

bool l2_hw_speed_mismatch(const cfg_port_ref *port, int speed_mbps) {
    char payload[32];
    char resp[160] = {0};
    char ethernet_mode[32] = {0};
    const char *wanted_mode;
    s32 ec = 0;
    int rn;
    int rport = 0;
    int actual_mbps = 0;

    if (!port || port->is_aggregate || port->hw_port <= 0 ||
        (speed_mbps != NL_PORT_SPEED_10G_MBPS &&
         speed_mbps != NL_PORT_SPEED_25G_MBPS))
        return false;

    wanted_mode = speed_mbps == NL_PORT_SPEED_10G_MBPS ?
                  "10GBase-SR" : "25GBase-SR";
    snprintf(payload, sizeof(payload), "port=%d", port->hw_port);
    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_PORT_SPEED_GET, 0,
                        (const u8 *)payload, (int)strlen(payload),
                        (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';
    L2_HW_PARSE_OR_RETURN(
        sscanf(resp, "port=%d speed=%d ethernet-mode=%31s",
               &rport, &actual_mbps, ethernet_mode) == 3, false);
    if (rport != port->hw_port) {
        l2_hw_probe_record(__func__, "speed response identity mismatch", rn,
                           ec);
        return false;
    }
    return actual_mbps != speed_mbps ||
           strcmp(ethernet_mode, wanted_mode) != 0;
}

bool l2_hw_pvid_mismatch(const cfg_port_ref *port, int vid) {
    if (port && !port->is_aggregate && forced_port(port->hw_port)) return true;
    char payload[32];
    char resp[128] = {0};
    s32 ec = 0;
    int rn;
    int rport = 0;
    int pvid = 0;

    if (!port || port->hw_port <= 0 ||
        vid < 1 || vid > 4094)
        return false;
    snprintf(payload, sizeof(payload), "port=%d", port->hw_port);
    rn = nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D, NL_DAEMON_SWITCHD,
                        NL_SWITCHD_PORT_MTU_GET, 0,
                        (const u8 *)payload, (int)strlen(payload),
                        (u8 *)resp, sizeof(resp) - 1, 2000, &ec);
    L2_HW_RPC_OR_RETURN(rn, ec, false);
    resp[rn < (int)sizeof(resp) ? rn : (int)sizeof(resp) - 1] = '\0';
    L2_HW_PARSE_OR_RETURN(
        sscanf(resp, "port=%d mtu=%*d max-frame=%*d pvid=%d",
               &rport, &pvid) == 2, false);
    if (rport != port->hw_port) {
        l2_hw_probe_record(__func__, "PVID response identity mismatch", rn,
                           ec);
        return false;
    }
    return pvid != vid;
}
