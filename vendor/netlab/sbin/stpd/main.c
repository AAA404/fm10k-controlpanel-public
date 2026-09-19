/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "stp_config_text.h"
#include "stp_internal.h"
#include "stp_lag.h"
#include "stp_packet_io.h"
#include "stp_show.h"
#include "stp_switchd.h"
#include "stp_wire.h"
#include "netlab/daemon.h"
#include "netlab/error.h"
#include "netlab/ipc.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/port_scope.h"
#include "netlab/packet_event.h"
#include "netlab/journal.h"
#include "netlab/monotonic.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define STPD_SOCKET    "/var/run/netlab/stpd.sock"
#define PACKETD_SOCKET "/var/run/netlab/packetd.sock"
#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
#define PACKETD_SYNTH_BPDU 0x4242
#define PACKETD_RX_IDLE_SEC 5
#define STPD_CONFIG_RELOAD_SEC 2
#define STPD_DEFAULT_HELLO_SEC 2
#define STPD_INITIAL_LISTEN_SEC 10
#define STPD_DEFAULT_BPDU_STALE_SEC 180
#define STPD_TC_FLUSH_MIN_SEC 2
#define STPD_AGREEMENT_REPLY_SEC 6
#define STPD_DEFAULT_BRIDGE_PRIORITY 0x8000
#define STPD_DEFAULT_PORT_COST 1
#define STPD_MAX_MSTI_OPS 512
#define STPD_VLAN_LIST_CAPACITY (STPD_MST_MAX_VLANS - 1)
#define FM_STP_STATE_FORWARDING 3
#define FM_STP_STATE_BLOCKING 4

static volatile sig_atomic_t g_running = 1;
stpd_state g_stp;
static int g_cfg_bridge_priority = -1;
static int g_cfg_hello_sec = 0;
static int g_cfg_max_age_sec = 0;
static int g_cfg_forward_delay_sec = 0;
static int g_cfg_mst_max_hops = 0;
static int g_cfg_port_path_cost[STPD_MAX_PORTS];
static int g_cfg_port_priority[STPD_MAX_PORTS];
static bool g_cfg_port_priority_valid[STPD_MAX_PORTS];
static bool g_cfg_mstp_enabled = false;
static char *g_active_stp_xml;

typedef struct {
    pthread_t rx_thread;
    pthread_t tx_thread;
    bool rx_thread_started;
    bool tx_thread_started;
    bool lock_initialized;
} stpd_runtime;

static stpd_runtime g_runtime;

static int ifname_to_port(const char *ifname);

typedef struct {
    char name[STP_MST_CONFIG_NAME_LEN + 1];
    u16 revision;
    u8 digest[STP_MST_DIGEST_LEN];
    int instance_count;
    stp_mst_instance_state instances[STPD_MAX_MSTI];
    int vlan_to_msti[STPD_MST_MAX_VLANS];
} stp_mst_config_work;

static const char *stpd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_STPD_SOCKET", STPD_SOCKET);
}

static const char *stpd_packetd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_PACKETD_SOCKET",
                                       PACKETD_SOCKET);
}

static const char *stpd_switchd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET",
                                       SWITCHD_SOCKET);
}

static void stpd_wait_seconds(int seconds) {
    while (g_running && seconds-- > 0)
        sleep(1);
}

static int stpd_identity_int(int value, int fallback) {
    return value > 0 ? value : fallback;
}

int stpd_hello_sec(void) {
    nl_platform_identity ident;
    if (g_cfg_hello_sec > 0)
        return g_cfg_hello_sec;
    if (nl_platform_identity_get(&ident))
        return stpd_identity_int(ident.rstp_hello_sec,
                                 STPD_DEFAULT_HELLO_SEC);
    return STPD_DEFAULT_HELLO_SEC;
}

int stpd_max_age_sec(void) {
    if (g_cfg_max_age_sec > 0)
        return g_cfg_max_age_sec;
    return 20;
}

int stpd_forward_delay_sec(void) {
    if (g_cfg_forward_delay_sec > 0)
        return g_cfg_forward_delay_sec;
    return 15;
}

int stpd_mst_max_hops(void) {
    if (g_cfg_mst_max_hops >= 6 && g_cfg_mst_max_hops <= 40)
        return g_cfg_mst_max_hops;
    return STPD_MST_DEFAULT_REMAINING_HOPS;
}

static int stpd_loop_stale_sec(void) {
    return stpd_hello_sec() * 4;
}

static int stpd_bpdu_stale_sec(void) {
    nl_platform_identity ident;
    if (nl_platform_identity_get(&ident))
        return stpd_identity_int(ident.rstp_bpdu_stale_sec,
                                 STPD_DEFAULT_BPDU_STALE_SEC);
    return STPD_DEFAULT_BPDU_STALE_SEC;
}

static int stpd_tc_transmit_sec(void) {
    int sec = (stpd_hello_sec() * 2) + 1;
    return sec < STPD_AGREEMENT_REPLY_SEC ? STPD_AGREEMENT_REPLY_SEC : sec;
}

int stpd_bridge_priority(void) {
    nl_platform_identity ident;
    if (g_cfg_bridge_priority >= 0 && g_cfg_bridge_priority <= 61440)
        return g_cfg_bridge_priority;
    if (nl_platform_identity_get(&ident))
        return stpd_identity_int(ident.rstp_bridge_priority,
                                 STPD_DEFAULT_BRIDGE_PRIORITY);
    return STPD_DEFAULT_BRIDGE_PRIORITY;
}

const char *stpd_protocol_name(void) {
    return g_cfg_mstp_enabled ? "mstp" : "rstp";
}

const char *stpd_mst_config_name(void) {
    return g_stp.mst_config_name;
}

u16 stpd_mst_revision(void) {
    return g_stp.mst_revision;
}

void stpd_mst_digest_hex(char *out, size_t out_size) {
    size_t off = 0;

    if (!out || out_size == 0)
        return;
    out[0] = '\0';
    for (int i = 0; i < STP_MST_DIGEST_LEN && off + 3 <= out_size; i++) {
        int n = snprintf(out + off, out_size - off, "%02x",
                         g_stp.mst_digest[i]);
        if (n <= 0)
            break;
        off += (size_t)n;
    }
}

int stpd_port_path_cost(int port) {
    nl_port_entry entry;
    if (port > 0 && port < STPD_MAX_PORTS &&
        g_cfg_port_path_cost[port] > 0)
        return g_cfg_port_path_cost[port];
    if (nl_ifid_get_by_logical_port(port, &entry) && entry.rstp_cost > 0)
        return entry.rstp_cost;
    return STPD_DEFAULT_PORT_COST;
}

static int stpd_speed_path_cost(const char *speed) {
    if (speed && strcmp(speed, "10g") == 0)
        return 10;
    if (speed && strcmp(speed, "25g") == 0)
        return 4;
    return 0;
}

static void load_interface_speed_path_costs(char *xml, int *costs,
                                            int max_ports) {
    char *interfaces;
    char *interfaces_end;
    char *p;

    if (!xml || !costs || max_ports <= 0)
        return;
    interfaces = strstr(xml, "<interfaces>");
    interfaces_end = interfaces ? strstr(interfaces, "</interfaces>") : NULL;
    if (!interfaces || !interfaces_end)
        return;

    p = interfaces;
    while ((p = strstr(p, "<interface>")) && p < interfaces_end) {
        char *end = strstr(p, "</interface>");
        char ifname[64] = {0};
        char speed[16] = {0};
        int port;
        int cost;

        if (!end || end > interfaces_end)
            break;
        if (stp_config_xml_leaf(p, end, "name", ifname,
                                sizeof(ifname)) != 0 ||
            stp_config_xml_leaf(p, end, "speed", speed,
                                sizeof(speed)) != 0) {
            p = end + strlen("</interface>");
            continue;
        }
        port = ifname_to_port(ifname);
        cost = stpd_speed_path_cost(speed);
        if (port > 0 && port < max_ports && cost > 0)
            costs[port] = cost;
        p = end + strlen("</interface>");
    }
}

int stpd_port_priority(int port) {
    if (port > 0 && port < STPD_MAX_PORTS &&
        g_cfg_port_priority_valid[port])
        return g_cfg_port_priority[port];
    return 0x80;
}

static const stp_mst_instance_state *find_mst_instance_by_id_locked(int mstid) {
    if (mstid <= 0)
        return NULL;
    for (int i = 0; i < STPD_MAX_MSTI; i++) {
        const stp_mst_instance_state *inst = &g_stp.mst_instances[i];

        if (inst->valid && inst->id == mstid)
            return inst;
    }
    return NULL;
}

int stpd_msti_port_path_cost(int mstid, int port) {
    const stp_mst_instance_state *inst =
        find_mst_instance_by_id_locked(mstid);

    if (inst && port > 0 && port < STPD_MAX_PORTS &&
        inst->port_path_cost[port] > 0)
        return inst->port_path_cost[port];
    return stpd_port_path_cost(port);
}

int stpd_msti_port_priority(int mstid, int port) {
    const stp_mst_instance_state *inst =
        find_mst_instance_by_id_locked(mstid);

    if (inst && port > 0 && port < STPD_MAX_PORTS &&
        inst->port_priority_valid[port])
        return inst->port_priority[port];
    return stpd_port_priority(port);
}

static u16 stpd_port_id(int port) {
    return stp_port_id(port, stpd_port_priority(port));
}

const char *block_reason_name(stp_block_reason reason) {
    switch (reason) {
    case STP_BLOCK_LOOP:
        return "loop";
    case STP_BLOCK_ALTERNATE:
        return "alternate";
    case STP_BLOCK_SPLIT_ROOT:
        return "split-root";
    case STP_BLOCK_ROOT_PROTECTION:
        return "root-protection";
    case STP_BLOCK_NONE:
    default:
        return "none";
    }
}

static int ifname_to_port(const char *ifname) {
    return stp_port_from_name(ifname);
}

void ifname_from_port(int port, char *buf, size_t buf_len) {
    stp_port_name(port, buf, buf_len);
}

static void send_text_response(nl_conn *conn, nl_msg_hdr *msg,
                               s32 error_code, const char *text) {
    size_t len = text ? strlen(text) : 0;
    nl_msg_hdr *resp = nl_msg_alloc((u32)len);
    if (!resp)
        return;
    resp->type = NL_MSG_RESPONSE;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)len;
    if (len > 0)
        memcpy(resp->payload, text, len);
    nl_send(conn, resp);
    nl_msg_free(resp);
}

void load_system_mac(u8 mac[6]) {
    memset(mac, 0, 6);
    if (!nl_platform_system_mac(mac))
        NL_LOG_WARN("RSTP bridge MAC is not configured in platform profile");
}

static bool port_link_up(int port) {
    static pthread_mutex_t link_lock = PTHREAD_MUTEX_INITIALIZER;
    static bool last_link[STPD_MAX_PORTS];
    if (port <= 0 || port >= STPD_MAX_PORTS) return false;
    pthread_mutex_lock(&link_lock);
    bool link = last_link[port];
    pthread_mutex_unlock(&link_lock);
    if (stp_port_paused(port)) return link;
    int physical = stp_lag_egress(port);
    link = physical > 0 && stp_switchd_port_link_up(stpd_switchd_socket_path(), physical);
    pthread_mutex_lock(&link_lock); last_link[port] = link; pthread_mutex_unlock(&link_lock);
    return link;
}

static void start_tc_transmit_window_locked(time_t now) {
    time_t until = now + stpd_tc_transmit_sec();
    if (g_stp.tc_tx_until < until)
        g_stp.tc_tx_until = until;
}

static void note_packetd_reconnect(void) {
    pthread_mutex_lock(&g_stp.lock);
    g_stp.packetd_reconnects++;
    pthread_mutex_unlock(&g_stp.lock);
}

static nl_conn g_packetd_subscription = {.fd = -1};

static int packetd_read_event(u8 *frame, int frame_max, int *src_port, int *vlan, u64 *captured_at) {
    u32 net_len;
    u8 event[NETLAB_PACKET_IO_MAX + NL_PACKET_EVENT_HEADER];

    if (g_packetd_subscription.fd < 0) {
        if (!stp_packet_subscribe(
                stpd_packetd_socket_path(), PACKETD_SYNTH_BPDU,
                &g_packetd_subscription)) {
            note_packetd_reconnect();
            stpd_wait_seconds(1);
            return -1;
        }
    }

    int ready = stp_packet_wait_readable(
        g_packetd_subscription.fd, PACKETD_RX_IDLE_SEC,
        &g_running);
    if (ready == 0)
        return 0;
    if (ready < 0) {
        NL_LOG_WARN("STP packetd subscription wait failed; reconnecting");
        nl_client_close(&g_packetd_subscription);
        note_packetd_reconnect();
        return -1;
    }

    if (stp_packet_read_record(
            &g_packetd_subscription, &net_len, sizeof(net_len)) !=
            (int)sizeof(net_len)) {
        NL_LOG_WARN("STP packetd subscription lost; reconnecting");
        nl_client_close(&g_packetd_subscription);
        note_packetd_reconnect();
        return -1;
    }

    int len = (int)ntohl(net_len);
    if (len < 4 || len > (int)sizeof(event)) {
        nl_client_close(&g_packetd_subscription);
        note_packetd_reconnect();
        return -1;
    }
    if (stp_packet_read_record(
            &g_packetd_subscription, event, len) != len) {
        NL_LOG_WARN("STP packetd event read failed; reconnecting");
        nl_client_close(&g_packetd_subscription);
        note_packetd_reconnect();
        return -1;
    }

    int port, vid;
    u64 stamp;
    int header = nl_packet_event_decode(event, len, &port, &vid, &stamp);
    if (header < 0) return -1;
    if (src_port) *src_port = port;
    if (vlan) *vlan = vid;
    if (captured_at) *captured_at = stamp;
    int frame_len = len - header;
    if (frame_len > frame_max) frame_len = frame_max;
    memcpy(frame, event + header, (size_t)frame_len);
    return frame_len;
}

static stp_port_stats *port_stats_locked(int port) {
    stp_port_stats *free_slot = NULL;

    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        if (g_stp.ports[i].valid && g_stp.ports[i].port == port)
            return &g_stp.ports[i];
        if (!g_stp.ports[i].valid && !free_slot)
            free_slot = &g_stp.ports[i];
    }

    if (!free_slot)
        return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->valid = true;
    free_slot->port = port;
    free_slot->role = STP_ROLE_DISABLED;
    snprintf(free_slot->last_root_id, sizeof(free_slot->last_root_id), "-");
    snprintf(free_slot->last_bridge_id, sizeof(free_slot->last_bridge_id), "-");
    snprintf(free_slot->guard_last_error,
             sizeof(free_slot->guard_last_error), "-");
    snprintf(free_slot->protocol_last_error,
             sizeof(free_slot->protocol_last_error), "-");
    return free_slot;
}

static stp_port_stats *find_port_stats_locked(int port) {
    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        if (g_stp.ports[i].valid && g_stp.ports[i].port == port)
            return &g_stp.ports[i];
    }
    return NULL;
}

static void mst_config_work_init(stp_mst_config_work *cfg) {
    if (!cfg)
        return;
    memset(cfg, 0, sizeof(*cfg));
}

static int mst_work_find_instance(stp_mst_config_work *cfg, int id) {
    if (!cfg || id <= 0)
        return -1;
    for (int i = 0; i < cfg->instance_count; i++) {
        if (cfg->instances[i].valid && cfg->instances[i].id == id)
            return i;
    }
    return -1;
}

static int mst_work_ensure_instance(stp_mst_config_work *cfg, int id) {
    int idx;

    if (!cfg || id <= 0 || id > 4094)
        return -1;
    idx = mst_work_find_instance(cfg, id);
    if (idx >= 0)
        return idx;
    if (cfg->instance_count >= STPD_MAX_MSTI)
        return -1;
    idx = cfg->instance_count++;
    memset(&cfg->instances[idx], 0, sizeof(cfg->instances[idx]));
    cfg->instances[idx].valid = true;
    cfg->instances[idx].id = id;
    cfg->instances[idx].bridge_priority = STPD_DEFAULT_BRIDGE_PRIORITY;
    return idx;
}

static void mst_compute_digest(stp_mst_config_work *cfg) {
    static const u8 digest_key[16] = {
        0x13, 0xac, 0x06, 0xa6, 0x2e, 0x47, 0xfd, 0x51,
        0xf9, 0x5d, 0x2b, 0xa2, 0x43, 0xcd, 0x03, 0x46
    };
    u8 table[4096 * 2];
    unsigned int digest_len = 0;
    unsigned char *digest;

    if (!cfg)
        return;
    memset(table, 0, sizeof(table));
    for (int vid = 1; vid <= 4094; vid++) {
        int mstid = cfg->vlan_to_msti[vid];
        if (mstid < 0 || mstid > 4094)
            mstid = 0;
        table[vid * 2] = (u8)((mstid >> 8) & 0xff);
        table[(vid * 2) + 1] = (u8)(mstid & 0xff);
    }

    digest = HMAC(EVP_md5(), digest_key, (int)sizeof(digest_key),
                  table, sizeof(table), cfg->digest, &digest_len);
    if (!digest || digest_len != STP_MST_DIGEST_LEN)
        memset(cfg->digest, 0, sizeof(cfg->digest));
}

static void parse_mstp_config(const char *stp, const char *stp_end,
                              stp_mst_config_work *cfg) {
    const char *p;
    char value[64] = {0};

    mst_config_work_init(cfg);
    if (!stp || !stp_end || !cfg)
        return;

    if (stp_config_xml_leaf(stp, stp_end, "configuration-name",
                            value, sizeof(value)) == 0) {
        size_t len = strlen(value);
        if (len > STP_MST_CONFIG_NAME_LEN)
            len = STP_MST_CONFIG_NAME_LEN;
        memcpy(cfg->name, value, len);
        cfg->name[len] = '\0';
    }
    memset(value, 0, sizeof(value));
    if (stp_config_xml_leaf(stp, stp_end, "revision-level",
                            value, sizeof(value)) == 0)
        cfg->revision = (u16)atoi(value);

    p = stp;
    while ((p = strstr(p, "<instance>")) && p < stp_end) {
        const char *end = strstr(p, "</instance>");
        const char *vlan_p;
        const char *iface_p;
        char id_s[32] = {0};
        char priority_s[32] = {0};
        int id;
        int idx;

        if (!end || end > stp_end)
            break;
        if (stp_config_xml_leaf(p, end, "id", id_s, sizeof(id_s)) != 0) {
            p = end + strlen("</instance>");
            continue;
        }
        id = atoi(id_s);
        idx = mst_work_ensure_instance(cfg, id);
        if (idx < 0) {
            p = end + strlen("</instance>");
            continue;
        }
        if (stp_config_xml_leaf(p, end, "bridge-priority",
                                priority_s, sizeof(priority_s)) == 0)
            cfg->instances[idx].bridge_priority = atoi(priority_s);

        vlan_p = p;
        while ((vlan_p = strstr(vlan_p, "<vlan>")) && vlan_p < end) {
            const char *vlan_end = strstr(vlan_p, "</vlan>");
            char vlan_s[32] = {0};
            int vlan;

            if (!vlan_end || vlan_end > end)
                break;
            if (stp_config_xml_leaf(vlan_p, vlan_end, "vlan-id",
                                    vlan_s, sizeof(vlan_s)) != 0) {
                vlan_p = vlan_end + strlen("</vlan>");
                continue;
            }
            vlan = atoi(vlan_s);
            if (vlan >= 1 && vlan <= 4094) {
                cfg->instances[idx].vlan_map[vlan] = true;
                cfg->instances[idx].vlan_count++;
                cfg->vlan_to_msti[vlan] = id;
            }
            vlan_p = vlan_end + strlen("</vlan>");
        }
        iface_p = p;
        while ((iface_p = strstr(iface_p, "<interface>")) &&
               iface_p < end) {
            const char *iface_end = strstr(iface_p, "</interface>");
            char ifname[64] = {0};
            char path_cost_s[32] = {0};
            char port_priority_s[32] = {0};
            int port;

            if (!iface_end || iface_end > end)
                break;
            if (stp_config_xml_leaf(iface_p, iface_end, "name",
                                    ifname, sizeof(ifname)) != 0) {
                iface_p = iface_end + strlen("</interface>");
                continue;
            }
            port = ifname_to_port(ifname);
            if (port > 0 && port < STPD_MAX_PORTS) {
                int path_cost = 0;
                int port_priority = 0;

                if (stp_config_xml_leaf(iface_p, iface_end, "path-cost",
                                        path_cost_s,
                                        sizeof(path_cost_s)) == 0)
                    path_cost = atoi(path_cost_s);
                if (path_cost > 0)
                    cfg->instances[idx].port_path_cost[port] = path_cost;

                if (stp_config_xml_leaf(iface_p, iface_end, "port-priority",
                                        port_priority_s,
                                        sizeof(port_priority_s)) == 0)
                    port_priority = atoi(port_priority_s);
                if (port_priority_s[0] && port_priority >= 0 &&
                    port_priority <= 240 && (port_priority % 16) == 0) {
                    cfg->instances[idx].port_priority[port] = port_priority;
                    cfg->instances[idx].port_priority_valid[port] = true;
                }
            }
            iface_p = iface_end + strlen("</interface>");
        }
        p = end + strlen("</instance>");
    }
    mst_compute_digest(cfg);
}

static void apply_mst_config_locked(const stp_mst_config_work *cfg,
                                    const u8 local_mac[6]) {
    memset(g_stp.mst_config_name, 0, sizeof(g_stp.mst_config_name));
    g_stp.mst_revision = 0;
    memset(g_stp.mst_digest, 0, sizeof(g_stp.mst_digest));
    g_stp.mst_instance_count = 0;
    memset(g_stp.mst_instances, 0, sizeof(g_stp.mst_instances));

    if (!cfg)
        return;
    snprintf(g_stp.mst_config_name, sizeof(g_stp.mst_config_name),
             "%s", cfg->name);
    g_stp.mst_revision = cfg->revision;
    memcpy(g_stp.mst_digest, cfg->digest, sizeof(g_stp.mst_digest));

    for (int i = 0; i < cfg->instance_count && i < STPD_MAX_MSTI; i++) {
        stp_mst_instance_state *dst = &g_stp.mst_instances[i];

        if (!cfg->instances[i].valid)
            continue;
        *dst = cfg->instances[i];
        if (local_mac)
            stp_build_mst_bridge_id(dst->bridge_id, local_mac,
                                    dst->bridge_priority, dst->id);
        memcpy(dst->selected_root_id, dst->bridge_id,
               sizeof(dst->selected_root_id));
        dst->selected_root_path_cost = 0;
        dst->selected_remaining_hops = stpd_mst_max_hops();
        dst->root_port = 0;
        g_stp.mst_instance_count++;
    }
}

static bool mst_region_matches_locked(const stp_bpdu_info *info) {
    if (!info || !info->has_mstp || !g_cfg_mstp_enabled)
        return false;
    return strcmp(info->mst_config_name, g_stp.mst_config_name) == 0 &&
           info->mst_revision == g_stp.mst_revision &&
           memcmp(info->mst_digest, g_stp.mst_digest,
                  STP_MST_DIGEST_LEN) == 0;
}

static bool stp_config_ptr_inside_tag(const char *container,
                                      const char *container_end,
                                      const char *open_tag,
                                      const char *close_tag,
                                      const char *ptr) {
    const char *p = container;

    if (!container || !container_end || !open_tag || !close_tag || !ptr)
        return false;
    while ((p = strstr(p, open_tag)) && p < container_end && p < ptr) {
        const char *end = strstr(p, close_tag);

        if (!end || end > container_end)
            return false;
        if (ptr > p && ptr < end)
            return true;
        p = end + strlen(close_tag);
    }
    return false;
}

static void reconcile_protocol_blocks(void);
void reconcile_rstp_roles(void);
static int collect_rstp_enabled_ports(int *ports, int max_ports);
static bool shared_rstp_peer_up_locked(int port);
static bool local_root_redundant_port_locked(int port);
static stp_port_msti_stats *port_msti_slot_locked(stp_port_stats *ps,
                                                  int mstid);

static const char *port_config_element(const char *xml, const char *container,
                                       const char *name, size_t *length) {
    *length = 0;
    if (!xml) return NULL;
    char open[32], close[32];
    snprintf(open, sizeof(open), "<%s>", container);
    snprintf(close, sizeof(close), "</%s>", container);
    const char *p = strstr(xml, open), *limit = p ? strstr(p, close) : NULL;
    while (p && limit && (p = strstr(p, "<interface>")) && p < limit) {
        const char *end = strstr(p, "</interface>"); char found[64];
        if (!end || end > limit) break;
        if (!stp_config_xml_leaf(p, end, "name", found, sizeof(found)) && !strcmp(found, name)) {
            *length = (size_t)(end + strlen("</interface>") - p); return p;
        }
        p = end + strlen("</interface>");
    }
    return NULL;
}
static bool same_port_configuration(const char *old, const char *next, const char *name) {
    if (!old || !next) return false;
    const char *containers[] = {"interfaces", "rstp", "mstp"};
    for (unsigned i = 0; i < sizeof(containers) / sizeof(containers[0]); ++i) {
        size_t a, b;
        const char *left = port_config_element(old, containers[i], name, &a);
        const char *right = port_config_element(next, containers[i], name, &b);
        if (a != b || (a && memcmp(left, right, a))) return false;
    }
    return true;
}

static bool reload_stp_config_work(bool force, stp_mst_config_work *mst_cfg) {
    struct stat st;
    char active_path[512];
    time_t now = nl_monotonic_seconds();
    time_t mtime = 0;
    long mtime_nsec = 0;
    char *xml;
    char *rstp;
    char *rstp_end;
    char *mstp;
    char *mstp_end;
    char *stp;
    char *stp_end;
    char *p;
    int cfg_bridge_priority = -1;
    int cfg_hello_sec = 0;
    int cfg_max_age_sec = 0;
    int cfg_forward_delay_sec = 0;
    int cfg_mst_max_hops = 0;
    int cfg_speed_path_cost[STPD_MAX_PORTS] = {0};
    bool cfg_mstp_enabled = false;
    u8 local_mac[6] = {0};

    nl_config_file_path(active_path, sizeof(active_path), "active.conf");
    if (stat(active_path, &st) == 0) {
        mtime = st.st_mtime;
        mtime_nsec = st.st_mtim.tv_nsec;
    }

    pthread_mutex_lock(&g_stp.lock);
    if (!force &&
        now - g_stp.last_config_check < STPD_CONFIG_RELOAD_SEC) {
        pthread_mutex_unlock(&g_stp.lock);
        return true;
    }
    g_stp.last_config_check = now;
    if (!force && mtime == g_stp.config_mtime &&
        mtime_nsec == g_stp.config_mtime_nsec) {
        pthread_mutex_unlock(&g_stp.lock);
        return true;
    }
    pthread_mutex_unlock(&g_stp.lock);
    if (!mtime) return false;
    xml = stp_config_read_active();
    if (!xml) return false;

    rstp = strstr(xml, "<rstp>");
    rstp_end = rstp ? strstr(rstp, "</rstp>") : NULL;
    mstp = strstr(xml, "<mstp>");
    mstp_end = mstp ? strstr(mstp, "</mstp>") : NULL;
    stp = mstp && mstp_end ? mstp : rstp;
    stp_end = mstp && mstp_end ? mstp_end : rstp_end;
    cfg_mstp_enabled = mstp && mstp_end;
    if (!stp || !stp_end) {
        stp = xml + strlen(xml);
        stp_end = stp;
    }
    load_interface_speed_path_costs(xml, cfg_speed_path_cost,
                                    STPD_MAX_PORTS);

    {
        char value[32] = {0};
        if (stp_config_xml_leaf(stp, stp_end, "bridge-priority",
                             value, sizeof(value)) == 0)
            cfg_bridge_priority = atoi(value);
        if (stp_config_xml_leaf(stp, stp_end, "hello-time",
                             value, sizeof(value)) == 0)
            cfg_hello_sec = atoi(value);
        if (stp_config_xml_leaf(stp, stp_end, "max-age",
                             value, sizeof(value)) == 0)
            cfg_max_age_sec = atoi(value);
        if (stp_config_xml_leaf(stp, stp_end, "forward-delay",
                             value, sizeof(value)) == 0)
            cfg_forward_delay_sec = atoi(value);
        if (cfg_mstp_enabled &&
            stp_config_xml_leaf(stp, stp_end, "max-hops",
                             value, sizeof(value)) == 0)
            cfg_mst_max_hops = atoi(value);
    }
    if (cfg_mstp_enabled) {
        parse_mstp_config(stp, stp_end, mst_cfg);
        load_system_mac(local_mac);
    }

    pthread_mutex_lock(&g_stp.lock);
    bool configured[STPD_MAX_PORTS] = {0};
    bool old_mstp = g_cfg_mstp_enabled;
    stp_lag_load_config(xml);
    g_stp.config_mtime = mtime;
    g_stp.config_mtime_nsec = mtime_nsec;
    memset(g_cfg_port_path_cost, 0, sizeof(g_cfg_port_path_cost));
    memset(g_cfg_port_priority, 0, sizeof(g_cfg_port_priority));
    memset(g_cfg_port_priority_valid, 0, sizeof(g_cfg_port_priority_valid));
    g_cfg_bridge_priority = cfg_bridge_priority;
    g_cfg_hello_sec = cfg_hello_sec;
    g_cfg_max_age_sec = cfg_max_age_sec;
    g_cfg_forward_delay_sec = cfg_forward_delay_sec;
    g_cfg_mst_max_hops = cfg_mst_max_hops;
    g_cfg_mstp_enabled = cfg_mstp_enabled;
    for (int i = 1; i < STPD_MAX_PORTS; i++) {
        if (cfg_speed_path_cost[i] > 0)
            g_cfg_port_path_cost[i] = cfg_speed_path_cost[i];
    }
    if (cfg_mstp_enabled)
        apply_mst_config_locked(mst_cfg, local_mac);
    else if (old_mstp)
        apply_mst_config_locked(NULL, NULL);
    p = stp;
    while ((p = strstr(p, "<interface>")) && p < stp_end) {
        char *end = strstr(p, "</interface>");
        char ifname[64] = {0};
        char edge[16] = {0};
        char guard[16] = {0};
        char root_guard[16] = {0};
        char loop_guard[16] = {0};
        char path_cost_s[32] = {0};
        char port_priority_s[32] = {0};
        int port;
        stp_port_stats *ps;

        if (!end || end > stp_end)
            break;
        if (cfg_mstp_enabled &&
            stp_config_ptr_inside_tag(stp, stp_end,
                                      "<instance>", "</instance>", p)) {
            p = end + strlen("</interface>");
            continue;
        }
        if (stp_config_xml_leaf(p, end, "name", ifname, sizeof(ifname)) != 0) {
            p = end + strlen("</interface>");
            continue;
        }
        port = ifname_to_port(ifname);
        if (port <= 0 || port >= STPD_MAX_PORTS) {
            p = end + strlen("</interface>");
            continue;
        }
        stp_config_xml_leaf(p, end, "edge", edge, sizeof(edge));
        stp_config_xml_leaf(p, end, "bpdu-block-on-edge", guard, sizeof(guard));
        stp_config_xml_leaf(p, end, "root-protection", root_guard,
                         sizeof(root_guard));
        stp_config_xml_leaf(p, end, "loop-protection", loop_guard,
                         sizeof(loop_guard));
        stp_config_xml_leaf(p, end, "path-cost", path_cost_s,
                         sizeof(path_cost_s));
        stp_config_xml_leaf(p, end, "port-priority", port_priority_s,
                         sizeof(port_priority_s));

        ps = port_stats_locked(port);
        if (ps) {
            configured[port] = true;
            if (port > 0 && port < STPD_MAX_PORTS) {
                int path_cost = atoi(path_cost_s);
                int port_priority = atoi(port_priority_s);

                if (path_cost > 0)
                    g_cfg_port_path_cost[port] = path_cost;
                if (port_priority_s[0] &&
                    port_priority >= 0 && port_priority <= 240 &&
                    (port_priority % 16) == 0) {
                    g_cfg_port_priority[port] = port_priority;
                    g_cfg_port_priority_valid[port] = true;
                }
            }
            ps->rstp_enabled = true;
            if (ps->role == STP_ROLE_DISABLED)
                ps->role = STP_ROLE_DESIGNATED;
            ps->edge = strcmp(edge, "true") == 0;
            ps->bpdu_guard_enabled = ps->edge &&
                                     strcmp(guard, "true") == 0;
            ps->root_protection = strcmp(root_guard, "true") == 0;
            ps->loop_protection = strcmp(loop_guard, "true") == 0;
            if (!ps->root_protection) {
                ps->root_protection_superior_seen = 0;
                memset(ps->root_protection_root_raw, 0,
                       sizeof(ps->root_protection_root_raw));
                memset(ps->root_protection_bridge_raw, 0,
                       sizeof(ps->root_protection_bridge_raw));
                ps->root_protection_root_path_cost = 0;
                ps->root_protection_port_id = 0;
            }
        }
        p = end + strlen("</interface>");
    }
    for (int i = 0; i < STPD_MAX_PORTS; ++i) {
        stp_port_stats *ps = &g_stp.ports[i];
        if (!ps->valid) continue;
        if (!configured[ps->port]) {
            ps->rstp_enabled = false;
            ps->edge = ps->bpdu_guard_enabled = ps->root_protection = ps->loop_protection = false;
            ps->role = STP_ROLE_DISABLED;
        }
        if (!cfg_mstp_enabled && old_mstp) memset(ps->msti, 0, sizeof(ps->msti));
        char name[32]; stp_port_name(ps->port, name, sizeof(name));
        bool same = same_port_configuration(g_active_stp_xml, xml, name);
        if (ps->rstp_enabled && strstr(xml, "<fm10k-panel>") && (!same || stp_port_paused(ps->port))) {
            ps->configuration_pending = true;
            ps->configuration_since = stp_port_now(ps->port, now);
        }
        if (same) {
            if (ps->protocol_block_config_mtime) ps->protocol_block_config_mtime = mtime;
        }
    }
    free(g_active_stp_xml);
    g_active_stp_xml = xml;
    pthread_mutex_unlock(&g_stp.lock);
    reconcile_protocol_blocks();
    return true;
}

static bool reload_stp_config_if_needed(bool force) {
    stp_mst_config_work *mst_cfg;

    mst_cfg = calloc(1, sizeof(*mst_cfg));
    if (!mst_cfg) {
        NL_LOG_ERR("STP config reload workspace allocation failed");
        return false;
    }
    static pthread_mutex_t reload_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&reload_lock);
    mst_config_work_init(mst_cfg);
    bool ok = reload_stp_config_work(force, mst_cfg);
    pthread_mutex_unlock(&reload_lock);
    free(mst_cfg);
    return ok;
}

static int set_port_stp_state(int port, int vid, int state);

static int collect_hardware_port_vlans(int port, int *vlans, int max_vlans) {
    return stp_switchd_collect_hardware_port_vlans(
        stpd_switchd_socket_path(), stp_lag_hardware_port(port),
                                                   vlans, max_vlans);
}

static void restore_unconfigured_port_vlans(int port, const int *configured,
                                            int n_configured) {
    int hw_vlans[STPD_VLAN_LIST_CAPACITY];
    int n_hw;

    if (port <= 0 || !configured || n_configured <= 0)
        return;

    n_hw = collect_hardware_port_vlans(
        port, hw_vlans, STPD_VLAN_LIST_CAPACITY);
    for (int i = 0; i < n_hw; i++) {
        if (hw_vlans[i] == 1)
            continue;
        if (!stp_config_vlan_seen(configured, n_configured, hw_vlans[i]))
            (void)set_port_stp_state(port, hw_vlans[i],
                                     FM_STP_STATE_FORWARDING);
    }
}

static int collect_port_vlans(int port, int fallback_vlan,
                              int *vlans, int max_vlans) {
    int n;

    if (!vlans || max_vlans <= 0 || port <= 0)
        return 0;

    n = stp_config_collect_port_vlans(port, vlans, max_vlans);
    if (n > 0) {
        restore_unconfigured_port_vlans(port, vlans, n);
        return n;
    }

    n = collect_hardware_port_vlans(port, vlans, max_vlans);
    if (n == 0 && fallback_vlan > 1 && fallback_vlan <= 4094)
        vlans[n++] = fallback_vlan;
    return n;
}

static int collect_decision_port_vlans(int port, int *vlans, int max_vlans) {
    int n;

    if (!vlans || max_vlans <= 0 || port <= 0)
        return 0;

    n = stp_config_collect_port_vlans(port, vlans, max_vlans);
    if (n > 0)
        return n;

    return collect_hardware_port_vlans(port, vlans, max_vlans);
}

static bool ports_share_vlan(int port_a, int port_b) {
    int vlans_a[STPD_VLAN_LIST_CAPACITY];
    int vlans_b[STPD_VLAN_LIST_CAPACITY];
    int n_a;
    int n_b;

    if (port_a <= 0 || port_b <= 0 || port_a == port_b)
        return false;

    n_a = collect_decision_port_vlans(
        port_a, vlans_a, STPD_VLAN_LIST_CAPACITY);
    n_b = collect_decision_port_vlans(
        port_b, vlans_b, STPD_VLAN_LIST_CAPACITY);
    for (int i = 0; i < n_a; i++)
        if (stp_config_vlan_seen(vlans_b, n_b, vlans_a[i]))
            return true;
    return false;
}

static int mst_vlan_to_instance_snapshot(int vlan) {
    int mstid = 0;

    if (vlan < 1 || vlan > 4094 || !g_cfg_mstp_enabled)
        return 0;
    pthread_mutex_lock(&g_stp.lock);
    for (int i = 0; i < STPD_MAX_MSTI; i++) {
        stp_mst_instance_state *inst = &g_stp.mst_instances[i];

        if (!inst->valid)
            continue;
        if (inst->vlan_map[vlan]) {
            mstid = inst->id;
            break;
        }
    }
    pthread_mutex_unlock(&g_stp.lock);
    return mstid;
}

static int collect_msti_port_vlans(int port, int mstid,
                                   int *vlans, int max_vlans) {
    int all_vlans[STPD_VLAN_LIST_CAPACITY];
    int n_all;
    int n = 0;

    if (!vlans || max_vlans <= 0 || port <= 0 || mstid <= 0)
        return 0;

    n_all = collect_port_vlans(
        port, 0, all_vlans, STPD_VLAN_LIST_CAPACITY);
    if (n_all < 0)
        return -1;
    for (int i = 0; i < n_all && n < max_vlans; i++) {
        if (mst_vlan_to_instance_snapshot(all_vlans[i]) == mstid)
            vlans[n++] = all_vlans[i];
    }
    return n;
}

static int set_port_stp_state(int port, int vid, int state) {
    u32 mask = stp_port_scope_mask(port);
    if (!nl_port_scope_enter_mask(mask)) return NL_ERR_RPC_BUSY;
    int rc = stp_switchd_set_port_stp_state(
        stpd_switchd_socket_path(), stp_lag_hardware_port(port), vid, state);
    nl_port_scope_leave_mask(mask);
    return rc;
}

static int set_port_stp_state_all_vlans(int port, int fallback_vlan,
                                        int state, char *err,
                                        size_t err_size) {
    int vlans[STPD_VLAN_LIST_CAPACITY];
    int n_vlans = collect_port_vlans(
        port, fallback_vlan, vlans, STPD_VLAN_LIST_CAPACITY);
    int first_error = 0;

    if (n_vlans < 0) {
        if (err && err_size > 0)
            snprintf(err, err_size, "switchd STP snapshot unavailable");
        return -1;
    }

    for (int i = 0; i < n_vlans; i++) {
        int st = set_port_stp_state(port, vlans[i], state);
        if (st != 0 && first_error == 0)
            first_error = st;
    }
    if (first_error != 0 && err && err_size > 0)
        snprintf(err, err_size, "switchd stp state failed err=%d",
                 first_error);
    return first_error;
}

static int set_port_stp_state_cist_vlans(int port, int fallback_vlan,
                                         int state, char *err,
                                         size_t err_size) {
    int vlans[STPD_VLAN_LIST_CAPACITY];
    int n_vlans = collect_port_vlans(
        port, fallback_vlan, vlans, STPD_VLAN_LIST_CAPACITY);
    int first_error = 0;
    int touched = 0;

    if (n_vlans < 0) {
        if (err && err_size > 0)
            snprintf(err, err_size, "switchd STP snapshot unavailable");
        return -1;
    }

    for (int i = 0; i < n_vlans; i++) {
        int st;

        if (mst_vlan_to_instance_snapshot(vlans[i]) != 0)
            continue;
        st = set_port_stp_state(port, vlans[i], state);
        touched++;
        if (st != 0 && first_error == 0)
            first_error = st;
    }
    if (first_error != 0 && err && err_size > 0)
        snprintf(err, err_size, "switchd CIST stp state failed err=%d",
                 first_error);
    if (touched == 0 && err && err_size > 0)
        snprintf(err, err_size, "-");
    return first_error;
}

static int clear_dynamic_macs_scope(int port, int vid, const char *reason) {
    time_t now;
    char ifname[32];
    char scope[96];
    int rc;

    if (port < 0 || vid < 0 || vid > 4094)
        return -1;

    u32 mask = port ? stp_port_scope_mask(port) : NL_PORT_SCOPE_MASK;
    if (!nl_port_scope_enter_mask(mask)) return NL_ERR_RPC_BUSY;
    rc = stp_switchd_clear_dynamic_macs(
        stpd_switchd_socket_path(), port ? stp_lag_hardware_port(port) : 0, vid);
    nl_port_scope_leave_mask(mask);
    if (rc != 0) {
        NL_LOG_WARN("RSTP MAC flush failed port=%d vid=%d err=%d",
                    port, vid, rc);
        return rc;
    }

    if (port > 0) {
        ifname_from_port(port, ifname, sizeof(ifname));
        if (vid > 0)
            snprintf(scope, sizeof(scope), "%s vlan=%d", ifname, vid);
        else
            snprintf(scope, sizeof(scope), "%s all-vlans", ifname);
    } else if (vid > 0) {
        snprintf(scope, sizeof(scope), "all-ports vlan=%d", vid);
    } else {
        snprintf(scope, sizeof(scope), "all-ports all-vlans");
    }

    now = nl_monotonic_seconds();
    pthread_mutex_lock(&g_stp.lock);
    g_stp.mac_flushes++;
    g_stp.last_mac_flush = now;
    start_tc_transmit_window_locked(now);
    snprintf(g_stp.last_mac_flush_scope,
             sizeof(g_stp.last_mac_flush_scope), "%s", scope);
    snprintf(g_stp.last_mac_flush_reason,
             sizeof(g_stp.last_mac_flush_reason), "%s",
             reason ? reason : "topology change");
    if (port > 0) {
        stp_port_stats *ps = port_stats_locked(port);
        if (ps) {
            ps->mac_flushes++;
            ps->last_mac_flush = now;
            snprintf(ps->last_mac_flush_scope,
                     sizeof(ps->last_mac_flush_scope), "%s", scope);
            snprintf(ps->last_mac_flush_reason,
                     sizeof(ps->last_mac_flush_reason), "%s",
                     reason ? reason : "topology change");
        }
    }
    pthread_mutex_unlock(&g_stp.lock);

    NL_LOG_NOTICE("RSTP dynamic MAC flush scope=%s reason=%s",
                  scope,
                  reason ? reason : "topology change");
    return 0;
}

static void note_mac_flush_source_port(int port, int vid, const char *reason) {
    time_t now;
    char ifname[32];
    char scope[96];

    if (port <= 0)
        return;

    ifname_from_port(port, ifname, sizeof(ifname));
    if (vid > 0)
        snprintf(scope, sizeof(scope), "%s source-vlan=%d", ifname, vid);
    else
        snprintf(scope, sizeof(scope), "%s source-vlan=all", ifname);

    now = nl_monotonic_seconds();
    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = port_stats_locked(port);
    if (ps) {
        ps->mac_flushes++;
        ps->last_mac_flush = now;
        snprintf(ps->last_mac_flush_scope,
                 sizeof(ps->last_mac_flush_scope), "%s", scope);
        snprintf(ps->last_mac_flush_reason,
                 sizeof(ps->last_mac_flush_reason), "%s",
                 reason ? reason : "topology change source");
    }
    pthread_mutex_unlock(&g_stp.lock);
}

static void clear_dynamic_macs_for_port(int port, int fallback_vlan,
                                        const char *reason) {
    int vlans[STPD_VLAN_LIST_CAPACITY];
    int n_vlans;

    if (port <= 0)
        return;

    n_vlans = collect_port_vlans(
        port, fallback_vlan, vlans, STPD_VLAN_LIST_CAPACITY);
    if (n_vlans < 0)
        return;
    if (n_vlans == 0) {
        (void)clear_dynamic_macs_scope(port, 0, reason);
        return;
    }
    for (int i = 0; i < n_vlans; i++)
        (void)clear_dynamic_macs_scope(port, vlans[i], reason);
}

static bool note_topology_change_bpdu(int port) {
    bool do_flush = true;
    time_t now = nl_monotonic_seconds();

    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = port_stats_locked(port);
    g_stp.topology_change_bpdus++;
    if (ps) {
        ps->topology_change_bpdus++;
        if (ps->last_mac_flush > 0 &&
            now - ps->last_mac_flush < STPD_TC_FLUSH_MIN_SEC)
            do_flush = false;
    }
    pthread_mutex_unlock(&g_stp.lock);
    return do_flush;
}

static void handle_topology_change(int src_port, int vlan,
                                   int version, int type, int flags) {
    bool tc = (type == 0x80) ||
              (stp_bpdu_type_is_config(version, type) && (flags & 0x01));
    int vlans[STPD_VLAN_LIST_CAPACITY];
    int n_vlans;

    if (!tc || src_port <= 0)
        return;
    if (!note_topology_change_bpdu(src_port))
        return;

    if (vlan >= 1 && vlan <= 4094) {
        if (clear_dynamic_macs_scope(0, vlan,
                                     "received topology-change BPDU") == 0)
            note_mac_flush_source_port(src_port, vlan,
                                       "received topology-change BPDU");
        return;
    }

    n_vlans = stp_config_collect_port_vlans(
        src_port, vlans, STPD_VLAN_LIST_CAPACITY);
    if (n_vlans <= 0) {
        if (clear_dynamic_macs_scope(0, 0,
                                     "received topology-change BPDU") == 0)
            note_mac_flush_source_port(src_port, 0,
                                       "received topology-change BPDU");
        return;
    }
    for (int i = 0; i < n_vlans; i++)
        if (clear_dynamic_macs_scope(0, vlans[i],
                                     "received topology-change BPDU") == 0)
            note_mac_flush_source_port(src_port, vlans[i],
                                       "received topology-change BPDU");
}

typedef struct {
    u8 root_id[8];
    u32 root_path_cost;
    u8 bridge_id[8];
    u16 port_id;
    u16 receive_port_id;
    int port;
} stp_priority_vector;

typedef struct {
    u8 root_id[8];
    u32 root_path_cost;
    int remaining_hops;
    stp_role_id peer_role;
    int port;
} stp_msti_vector;

typedef struct {
    int port;
    int mstid;
    int state;
    stp_block_reason reason;
} stp_msti_apply_op;

typedef struct {
    int port;
    int fallback_vlan;
    int state;
    stp_block_reason reason;
} stp_apply_op;

static int priority_vector_compare(const stp_priority_vector *a,
                                   const stp_priority_vector *b) {
    int cmp;

    cmp = memcmp(a->root_id, b->root_id, sizeof(a->root_id));
    if (cmp != 0)
        return cmp;
    if (a->root_path_cost != b->root_path_cost)
        return a->root_path_cost < b->root_path_cost ? -1 : 1;
    cmp = memcmp(a->bridge_id, b->bridge_id, sizeof(a->bridge_id));
    if (cmp != 0)
        return cmp;
    if (a->port_id != b->port_id)
        return a->port_id < b->port_id ? -1 : 1;
    if (a->receive_port_id != b->receive_port_id)
        return a->receive_port_id < b->receive_port_id ? -1 : 1;
    return 0;
}

static int msti_vector_compare(const stp_msti_vector *a,
                               const stp_msti_vector *b) {
    int cmp;

    cmp = memcmp(a->root_id, b->root_id, sizeof(a->root_id));
    if (cmp != 0)
        return cmp;
    if (a->root_path_cost != b->root_path_cost)
        return a->root_path_cost < b->root_path_cost ? -1 : 1;
    if (a->port != b->port)
        return a->port < b->port ? -1 : 1;
    return 0;
}

static bool msti_selected_vector_equal(const stp_mst_instance_state *inst,
                                       const stp_msti_vector *vec,
                                       bool external_root) {
    int remaining_hops;

    if (!inst || !vec)
        return false;
    remaining_hops = external_root && vec->remaining_hops > 0 ?
                     vec->remaining_hops - 1 :
                     stpd_mst_max_hops();
    return stp_bridge_id_equal(inst->selected_root_id, vec->root_id) &&
           inst->selected_root_path_cost == vec->root_path_cost &&
           inst->selected_remaining_hops == remaining_hops &&
           inst->root_port == vec->port;
}

static void reset_msti_sync_locked(stp_port_msti_stats *slot,
                                   time_t now,
                                   const char *reason) {
    if (!slot)
        return;
    if (slot->last_agreement_seen != 0) {
        slot->sync_resets++;
        slot->last_sync_reset = now;
        snprintf(slot->last_sync_reset_reason,
                 sizeof(slot->last_sync_reset_reason), "%s",
                 reason && reason[0] ? reason : "unknown");
    }
    slot->last_agreement_seen = 0;
}

static void reset_cist_sync_locked(stp_port_stats *ps,
                                   time_t now,
                                   const char *reason) {
    if (!ps)
        return;
    if (ps->last_agreement_seen != 0) {
        ps->sync_resets++;
        ps->last_sync_reset = now;
        snprintf(ps->last_sync_reset_reason,
                 sizeof(ps->last_sync_reset_reason), "%s",
                 reason && reason[0] ? reason : "unknown");
    }
    ps->last_agreement_seen = 0;
}

static void expire_msti_sync_locked(stp_port_msti_stats *slot, time_t now) {
    if (!slot || slot->last_agreement_seen == 0)
        return;
    if (now - slot->last_agreement_seen <= stpd_bpdu_stale_sec())
        return;
    reset_msti_sync_locked(slot, now, "agreement-timeout");
}

static void expire_cist_sync_locked(stp_port_stats *ps, time_t now) {
    if (!ps || ps->last_agreement_seen == 0)
        return;
    if (now - ps->last_agreement_seen <= stpd_bpdu_stale_sec())
        return;
    reset_cist_sync_locked(ps, now, "agreement-timeout");
}

static void expire_sync_agreements_locked(time_t now) {
    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];

        if (!ps->valid || stp_port_paused(ps->port))
            continue;
        expire_cist_sync_locked(ps, now);
        for (int j = 0; j < STPD_MAX_MSTI; j++)
            if (ps->msti[j].valid)
                expire_msti_sync_locked(&ps->msti[j], now);
    }
}

static void local_priority_vector(stp_priority_vector *vec,
                                  const u8 local_bridge_id[8],
                                  int port) {
    memset(vec, 0, sizeof(*vec));
    memcpy(vec->root_id, local_bridge_id, 8);
    vec->root_path_cost = 0;
    memcpy(vec->bridge_id, local_bridge_id, 8);
    vec->port_id = port > 0 ? stpd_port_id(port) : 0;
    vec->receive_port_id = port > 0 ? stpd_port_id(port) : 0;
    vec->port = port;
}

static stp_port_msti_stats *find_port_msti_locked(stp_port_stats *ps,
                                                  int mstid) {
    if (!ps || mstid <= 0)
        return NULL;
    for (int i = 0; i < STPD_MAX_MSTI; i++) {
        if (ps->msti[i].valid && ps->msti[i].mstid == mstid)
            return &ps->msti[i];
    }
    return NULL;
}

static bool received_msti_vector_locked(stp_port_stats *ps,
                                        int mstid,
                                        time_t now,
                                        stp_msti_vector *vec) {
    stp_port_msti_stats *slot;

    if (!ps || !vec || !ps->rstp_enabled || ps->guard_blocked ||
        mstid <= 0)
        return false;
    slot = find_port_msti_locked(ps, mstid);
    if (!slot || slot->last_seen == 0 ||
        stp_port_now(ps->port, now) - slot->last_seen > stpd_bpdu_stale_sec())
        return false;
    if (slot->remaining_hops <= 0)
        return false;
    if (stp_bridge_id_is_zero(slot->last_root_raw))
        return false;
    memset(vec, 0, sizeof(*vec));
    memcpy(vec->root_id, slot->last_root_raw, sizeof(vec->root_id));
    vec->root_path_cost =
        slot->last_root_path_cost +
        (u32)stpd_msti_port_path_cost(mstid, ps->port);
    vec->remaining_hops = slot->remaining_hops;
    vec->peer_role = slot->last_peer_role;
    vec->port = ps->port;
    return true;
}

static void reconcile_msti_roles_locked(time_t now,
                                        stp_msti_apply_op *ops,
                                        int *n_ops,
                                        int max_ops,
                                        const stp_apply_op *cist_ops,
                                        int n_cist_ops) {
    for (int i = 0; i < STPD_MAX_MSTI; i++) {
        stp_mst_instance_state *inst = &g_stp.mst_instances[i];
        stp_msti_vector best;
        bool external_root = false;
        bool selected_vector_changed;

        if (!inst->valid)
            continue;
        memset(&best, 0, sizeof(best));
        memcpy(best.root_id, inst->bridge_id, sizeof(best.root_id));
        best.root_path_cost = 0;
        best.port = 0;

        for (int j = 0; j < STPD_MAX_PORTS; j++) {
            stp_port_stats *ps = &g_stp.ports[j];
            stp_msti_vector candidate;

            if (!ps->valid)
                continue;
            if (received_msti_vector_locked(ps, inst->id, now,
                                            &candidate) &&
                candidate.peer_role == STP_ROLE_DESIGNATED &&
                msti_vector_compare(&candidate, &best) < 0) {
                best = candidate;
                external_root = true;
            }
        }

        selected_vector_changed =
            !msti_selected_vector_equal(inst, &best, external_root);
        if (external_root) {
            memcpy(inst->selected_root_id, best.root_id,
                   sizeof(inst->selected_root_id));
            inst->selected_root_path_cost = best.root_path_cost;
            inst->selected_remaining_hops =
                best.remaining_hops > 0 ? best.remaining_hops - 1 : 0;
            inst->root_port = best.port;
        } else {
            memcpy(inst->selected_root_id, inst->bridge_id,
                   sizeof(inst->selected_root_id));
            inst->selected_root_path_cost = 0;
            inst->selected_remaining_hops = stpd_mst_max_hops();
            inst->root_port = 0;
        }

        for (int j = 0; j < STPD_MAX_PORTS; j++) {
            stp_port_stats *ps = &g_stp.ports[j];
            stp_port_msti_stats *slot;
            stp_msti_vector candidate;
            bool has_info;
            bool old_blocked;
            bool cist_blocks_mapped = false;
            bool needs_reapply;
            stp_block_reason old_reason;
            stp_role_id old_role;
            bool peer_designated;

            if (!ps->valid)
                continue;
            if (stp_port_paused(ps->port)) continue;
            slot = port_msti_slot_locked(ps, inst->id);
            if (!slot)
                continue;
            old_blocked = slot->protocol_blocked;
            old_reason = slot->block_reason;
            old_role = slot->role;
            needs_reapply =
                slot->protocol_block_config_mtime != g_stp.config_mtime;
            if (ps->protocol_blocked) {
                if (ps->block_reason != STP_BLOCK_ALTERNATE)
                    cist_blocks_mapped = true;
            }
            for (int k = 0; cist_ops && k < n_cist_ops; k++) {
                if (cist_ops[k].port != ps->port ||
                    cist_ops[k].state != FM_STP_STATE_BLOCKING)
                    continue;
                if (cist_ops[k].reason != STP_BLOCK_ALTERNATE)
                    cist_blocks_mapped = true;
            }
            has_info = received_msti_vector_locked(ps, inst->id, now,
                                                   &candidate);
            peer_designated =
                has_info && candidate.peer_role == STP_ROLE_DESIGNATED;
            if (!ps->rstp_enabled || ps->guard_blocked) {
                slot->role = STP_ROLE_DISABLED;
                slot->protocol_blocked = false;
                slot->block_reason = STP_BLOCK_NONE;
            } else if (external_root && ps->port == best.port) {
                slot->role = STP_ROLE_ROOT;
                slot->protocol_blocked = false;
                slot->block_reason = STP_BLOCK_NONE;
            } else if (external_root && peer_designated &&
                       msti_vector_compare(&candidate, &best) <= 0) {
                slot->role = STP_ROLE_ALTERNATE;
                slot->protocol_blocked = true;
                slot->block_reason = STP_BLOCK_ALTERNATE;
            } else {
                slot->role = STP_ROLE_DESIGNATED;
                slot->protocol_blocked = false;
                slot->block_reason = STP_BLOCK_NONE;
            }
            if (selected_vector_changed || old_role != slot->role)
                reset_msti_sync_locked(slot, now, "msti-root-or-role-change");
            if (ops && n_ops && *n_ops < max_ops &&
                !cist_blocks_mapped && !ps->guard_blocked &&
                inst->vlan_count > 0 &&
                (needs_reapply ||
                 old_blocked != slot->protocol_blocked ||
                 old_reason != slot->block_reason)) {
                ops[*n_ops].port = ps->port;
                ops[*n_ops].mstid = inst->id;
                ops[*n_ops].state = slot->protocol_blocked ?
                                    FM_STP_STATE_BLOCKING :
                                    FM_STP_STATE_FORWARDING;
                ops[*n_ops].reason = slot->block_reason;
                (*n_ops)++;
                slot->protocol_block_config_mtime = g_stp.config_mtime;
            }
        }
    }
}

static bool received_priority_vector_locked(const stp_port_stats *ps,
                                            time_t now,
                                            const u8 local_bridge_id[8],
                                            stp_priority_vector *vec) {
    if (!ps || !vec || !ps->rstp_enabled || ps->guard_blocked)
        return false;
    if (!stp_bpdu_type_is_config(ps->last_version, ps->last_type))
        return false;
    if (ps->last_seen == 0 || stp_port_now(ps->port, now) - ps->last_seen > stpd_bpdu_stale_sec())
        return false;
    if (stp_bridge_id_is_zero(ps->last_root_raw) ||
        stp_bridge_id_is_zero(ps->last_bridge_raw))
        return false;
    if (stp_bridge_id_equal(ps->last_root_raw, local_bridge_id) &&
        stp_bridge_id_equal(ps->last_bridge_raw, local_bridge_id))
        return false;

    memset(vec, 0, sizeof(*vec));
    memcpy(vec->root_id, ps->last_root_raw, 8);
    vec->root_path_cost =
        ps->last_root_path_cost + (u32)stpd_port_path_cost(ps->port);
    memcpy(vec->bridge_id, ps->last_bridge_raw, 8);
    vec->port_id = ps->last_port_id > 0 ? (u16)ps->last_port_id : 0;
    vec->receive_port_id = stpd_port_id(ps->port);
    vec->port = ps->port;
    return true;
}

static bool root_protection_superior_locked(const stp_port_stats *ps,
                                            time_t now,
                                            const stp_priority_vector *local_best) {
    stp_priority_vector vec;

    if (!ps || !local_best || !ps->root_protection)
        return false;
    if (ps->root_protection_superior_seen == 0 ||
        stp_port_now(ps->port, now) - ps->root_protection_superior_seen > stpd_bpdu_stale_sec())
        return false;
    if (stp_bridge_id_is_zero(ps->root_protection_root_raw) ||
        stp_bridge_id_is_zero(ps->root_protection_bridge_raw))
        return false;

    memset(&vec, 0, sizeof(vec));
    memcpy(vec.root_id, ps->root_protection_root_raw, sizeof(vec.root_id));
    vec.root_path_cost = ps->root_protection_root_path_cost +
                         (u32)stpd_port_path_cost(ps->port);
    memcpy(vec.bridge_id, ps->root_protection_bridge_raw,
           sizeof(vec.bridge_id));
    vec.port_id = ps->root_protection_port_id > 0 ?
                  (u16)ps->root_protection_port_id : 0;
    vec.receive_port_id = stpd_port_id(ps->port);
    vec.port = ps->port;

    return priority_vector_compare(&vec, local_best) < 0;
}

static void note_root_protection_superior_locked(stp_port_stats *ps,
                                                 const stp_priority_vector *candidate,
                                                 const stp_priority_vector *local_best,
                                                 time_t now) {
    if (!ps || !candidate || !local_best || !ps->root_protection)
        return;
    if (priority_vector_compare(candidate, local_best) >= 0)
        return;

    ps->root_protection_superior_seen = now;
    memcpy(ps->root_protection_root_raw, candidate->root_id,
           sizeof(ps->root_protection_root_raw));
    memcpy(ps->root_protection_bridge_raw, candidate->bridge_id,
           sizeof(ps->root_protection_bridge_raw));
    ps->root_protection_root_path_cost =
        candidate->root_path_cost >= (u32)stpd_port_path_cost(ps->port) ?
        candidate->root_path_cost - (u32)stpd_port_path_cost(ps->port) :
        candidate->root_path_cost;
    ps->root_protection_port_id = candidate->port_id;
}

static void reapply_port_msti_states(int port);

static bool apply_protocol_op(const stp_apply_op *op) {
    if (!op || stp_port_paused(op->port)) return false;
    char ifname[32];
    char err[128] = {0};
    int rc;

    if (!op || op->port <= 0)
        return false;

    ifname_from_port(op->port, ifname, sizeof(ifname));
    if (g_cfg_mstp_enabled && op->reason == STP_BLOCK_ALTERNATE)
        rc = set_port_stp_state_cist_vlans(op->port, op->fallback_vlan,
                                           op->state, err, sizeof(err));
    else
        rc = set_port_stp_state_all_vlans(op->port, op->fallback_vlan,
                                          op->state, err, sizeof(err));
    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = find_port_stats_locked(op->port);
    if (ps) {
        if (rc == 0) {
            ps->configuration_pending = false;
            if (op->state == FM_STP_STATE_BLOCKING) {
                if (!ps->protocol_blocked ||
                    ps->block_reason != op->reason)
                    ps->protocol_blocks++;
                ps->protocol_blocked = true;
                ps->block_reason = op->reason;
                ps->protocol_blocked_at = nl_monotonic_seconds();
                ps->protocol_block_config_mtime = g_stp.config_mtime;
                if (op->reason != STP_BLOCK_LOOP) {
                    ps->loop_last_seen = 0;
                    ps->loop_peer_port = 0;
                }
            } else {
                ps->protocol_blocked = false;
                ps->block_reason = STP_BLOCK_NONE;
                ps->protocol_blocked_at = 0;
                ps->protocol_block_config_mtime = 0;
                ps->root_protection_superior_seen = 0;
                memset(ps->root_protection_root_raw, 0,
                       sizeof(ps->root_protection_root_raw));
                memset(ps->root_protection_bridge_raw, 0,
                       sizeof(ps->root_protection_bridge_raw));
                ps->root_protection_root_path_cost = 0;
                ps->root_protection_port_id = 0;
                ps->loop_last_seen = 0;
                ps->loop_peer_port = 0;
            }
            snprintf(ps->protocol_last_error,
                     sizeof(ps->protocol_last_error), "-");
        } else {
            snprintf(ps->protocol_last_error,
                     sizeof(ps->protocol_last_error), "%s", err);
        }
    }
    pthread_mutex_unlock(&g_stp.lock);

    if (rc == 0)
        clear_dynamic_macs_for_port(op->port, op->fallback_vlan,
                                    op->state == FM_STP_STATE_BLOCKING ?
                                    "port moved to discarding" :
                                    "port moved to forwarding");

    if (rc == 0 && op->state == FM_STP_STATE_BLOCKING)
        NL_LOG_NOTICE("RSTP blocked %s (%s)", ifname,
                      block_reason_name(op->reason));
    else if (rc == 0)
        NL_LOG_NOTICE("RSTP restored %s to forwarding", ifname);
    else
        NL_LOG_WARN("RSTP failed to update %s state: %s", ifname, err);

    if (rc == 0 && g_cfg_mstp_enabled &&
        op->reason == STP_BLOCK_ALTERNATE) {
        /* CIST alternate only owns CIST VLANs; mapped MSTI VLANs may forward. */
        reapply_port_msti_states(op->port);
    }
    return rc == 0;
}

static bool apply_msti_protocol_op(const stp_msti_apply_op *op) {
    if (!op || stp_port_paused(op->port)) return false;
    int vlans[STPD_VLAN_LIST_CAPACITY];
    int n_vlans;
    char ifname[32];
    int first_error = 0;

    if (!op || op->port <= 0 || op->mstid <= 0)
        return false;

    n_vlans = collect_msti_port_vlans(op->port, op->mstid,
                                      vlans, STPD_VLAN_LIST_CAPACITY);
    if (n_vlans <= 0)
        return false;

    for (int i = 0; i < n_vlans; i++) {
        int rc = set_port_stp_state(op->port, vlans[i], op->state);
        if (rc != 0 && first_error == 0)
            first_error = rc;
    }

    ifname_from_port(op->port, ifname, sizeof(ifname));
    if (first_error == 0) {
        for (int i = 0; i < n_vlans; i++)
            (void)clear_dynamic_macs_scope(op->port, vlans[i],
                op->state == FM_STP_STATE_BLOCKING ?
                "MSTI moved VLAN to discarding" :
                "MSTI moved VLAN to forwarding");
        NL_LOG_NOTICE("MSTP MSTI %d %s %s for %d VLAN(s)",
                      op->mstid,
                      op->state == FM_STP_STATE_BLOCKING ?
                      "blocked" : "forwarded",
                      ifname, n_vlans);
    } else {
        NL_LOG_WARN("MSTP MSTI %d failed to update %s err=%d",
                    op->mstid, ifname, first_error);
    }
    return first_error == 0;
}

static int collect_port_msti_reapply_ops(int port,
                                         stp_msti_apply_op *ops,
                                         int max_ops) {
    int n_ops = 0;

    if (port <= 0 || !ops || max_ops <= 0)
        return 0;

    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = find_port_stats_locked(port);
    if (ps && ps->valid && !ps->guard_blocked) {
        for (int i = 0; i < STPD_MAX_MSTI && n_ops < max_ops; i++) {
            stp_mst_instance_state *inst = &g_stp.mst_instances[i];
            stp_port_msti_stats *slot;

            if (!inst->valid || inst->vlan_count <= 0)
                continue;
            slot = find_port_msti_locked(ps, inst->id);
            if (!slot)
                continue;
            ops[n_ops].port = ps->port;
            ops[n_ops].mstid = inst->id;
            ops[n_ops].state = slot->protocol_blocked ?
                               FM_STP_STATE_BLOCKING :
                               FM_STP_STATE_FORWARDING;
            ops[n_ops].reason = slot->block_reason;
            n_ops++;
        }
    }
    pthread_mutex_unlock(&g_stp.lock);
    return n_ops;
}

static void reapply_port_msti_states(int port) {
    stp_msti_apply_op ops[STPD_MAX_MSTI];
    int n_ops = collect_port_msti_reapply_ops(port, ops, STPD_MAX_MSTI);

    for (int i = 0; i < n_ops; i++)
        apply_msti_protocol_op(&ops[i]);
}

static void reconcile_rstp_roles_unscoped(void) {
    stp_apply_op ops[STPD_MAX_PORTS];
    stp_msti_apply_op msti_ops[STPD_MAX_MSTI_OPS];
    int n_ops = 0;
    int n_msti_ops = 0;
    time_t now = nl_monotonic_seconds();
    u8 local_mac[6];
    u8 local_bridge_id[8];
    stp_priority_vector local_best;
    stp_priority_vector best;
    bool external_root = false;
    u8 old_selected_root_id[8];
    u32 old_selected_root_path_cost;
    int old_root_port;
    bool cist_vector_changed;

    load_system_mac(local_mac);
    stp_build_bridge_id(local_bridge_id, local_mac, stpd_bridge_priority());
    local_priority_vector(&local_best, local_bridge_id, 0);
    best = local_best;

    pthread_mutex_lock(&g_stp.lock);
    expire_sync_agreements_locked(now);
    memcpy(old_selected_root_id, g_stp.selected_root_id,
           sizeof(old_selected_root_id));
    old_selected_root_path_cost = g_stp.selected_root_path_cost;
    old_root_port = g_stp.root_port;
    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];
        stp_priority_vector candidate;

        if (!ps->valid)
            continue;
        if (received_priority_vector_locked(ps, now, local_bridge_id,
                                            &candidate) &&
            !ps->root_protection &&
            priority_vector_compare(&candidate, &best) < 0) {
            best = candidate;
            external_root = true;
        }
    }

    if (!external_root) {
        memcpy(g_stp.selected_root_id, local_bridge_id, 8);
        g_stp.selected_root_path_cost = 0;
        g_stp.root_port = 0;
    } else {
        memcpy(g_stp.selected_root_id, best.root_id, 8);
        g_stp.selected_root_path_cost = best.root_path_cost;
        g_stp.root_port = best.port;
    }
    cist_vector_changed =
        !stp_bridge_id_equal(old_selected_root_id, g_stp.selected_root_id) ||
        old_selected_root_path_cost != g_stp.selected_root_path_cost ||
        old_root_port != g_stp.root_port;

    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];
        stp_priority_vector candidate;
        bool has_external_info;
        stp_role_id new_role = STP_ROLE_DISABLED;
        bool wants_alternate = false;
        bool wants_forwarding = false;
        stp_block_reason wants_block_reason = STP_BLOCK_ALTERNATE;
        bool alternate_needs_reapply = false;
        bool keep_stale_alternate = false;
        bool root_guard_superior = false;
        bool current_root_guard_superior = false;
        stp_role_id old_role;

        if (!ps->valid)
            continue;
        if (stp_port_paused(ps->port)) continue;
        old_role = ps->role;
        has_external_info = received_priority_vector_locked(
            ps, now, local_bridge_id, &candidate);
        root_guard_superior =
            root_protection_superior_locked(ps, now, &local_best);
        current_root_guard_superior =
            ps->root_protection && has_external_info &&
            priority_vector_compare(&candidate, &local_best) < 0;
        if (current_root_guard_superior)
            note_root_protection_superior_locked(ps, &candidate,
                                                 &local_best, now);

        if (!ps->rstp_enabled || ps->guard_blocked) {
            new_role = STP_ROLE_DISABLED;
        } else if (root_guard_superior || current_root_guard_superior) {
            new_role = STP_ROLE_ALTERNATE;
            wants_alternate = true;
            wants_block_reason = STP_BLOCK_ROOT_PROTECTION;
        } else if (external_root && ps->port == best.port) {
            new_role = STP_ROLE_ROOT;
            wants_forwarding = true;
        } else if (external_root && has_external_info) {
            stp_priority_vector designated;
            bool shares_root_vlan;

            memset(&designated, 0, sizeof(designated));
            memcpy(designated.root_id, best.root_id, 8);
            designated.root_path_cost = best.root_path_cost;
            memcpy(designated.bridge_id, local_bridge_id, 8);
            designated.port_id = stpd_port_id(ps->port);
            designated.receive_port_id = stpd_port_id(ps->port);
            designated.port = ps->port;
            shares_root_vlan = ports_share_vlan(ps->port, best.port);

            if (priority_vector_compare(&candidate, &designated) < 0) {
                if (shares_root_vlan) {
                    new_role = STP_ROLE_ALTERNATE;
                    wants_alternate = true;
                } else {
                    new_role = STP_ROLE_ROOT;
                    wants_forwarding = true;
                }
            } else {
                new_role = STP_ROLE_DESIGNATED;
                wants_forwarding = true;
            }
        } else if (external_root) {
            if (ports_share_vlan(ps->port, best.port)) {
                new_role = STP_ROLE_ALTERNATE;
                wants_alternate = true;
            } else {
                new_role = STP_ROLE_DESIGNATED;
                wants_forwarding = true;
            }
        } else if (has_external_info) {
            /*
             * Local bridge is still the root, but this segment has a standard
             * peer BPDU. Advertise our superior vector on the port so the peer
             * can make the redundant-port decision. The local fail-closed rule
             * below is only for links with no standard BPDU visibility, such
             * as unsupported PVST+ peers.
             */
            new_role = STP_ROLE_DESIGNATED;
            wants_forwarding = true;
        } else if (local_root_redundant_port_locked(ps->port)) {
            new_role = STP_ROLE_ALTERNATE;
            wants_alternate = true;
        } else {
            new_role = STP_ROLE_DESIGNATED;
            wants_forwarding = true;
        }

        if (ps->protocol_blocked &&
            ps->block_reason == STP_BLOCK_LOOP &&
            !external_root)
            new_role = STP_ROLE_ALTERNATE;
        keep_stale_alternate =
            ps->loop_protection &&
            !external_root &&
            !has_external_info &&
            ps->protocol_blocked &&
            ps->block_reason == STP_BLOCK_ALTERNATE &&
            shared_rstp_peer_up_locked(ps->port);
        if (keep_stale_alternate) {
            new_role = STP_ROLE_ALTERNATE;
            wants_forwarding = false;
        }
        ps->role = new_role;
        if (cist_vector_changed || old_role != new_role)
            reset_cist_sync_locked(ps, now, "cist-root-or-role-change");
        alternate_needs_reapply =
            ps->protocol_blocked &&
            (ps->block_reason == STP_BLOCK_ALTERNATE ||
             ps->block_reason == STP_BLOCK_ROOT_PROTECTION) &&
            ps->protocol_block_config_mtime != g_stp.config_mtime;

        if (wants_alternate &&
            (ps->configuration_pending || alternate_needs_reapply ||
             !ps->protocol_blocked ||
             ps->block_reason != wants_block_reason) &&
            n_ops < STPD_MAX_PORTS) {
            ops[n_ops].port = ps->port;
            ops[n_ops].fallback_vlan = ps->vlan;
            ops[n_ops].state = FM_STP_STATE_BLOCKING;
            ops[n_ops].reason = wants_block_reason;
            n_ops++;
        } else if (wants_forwarding &&
                   (ps->edge || !ps->configuration_pending || now - ps->configuration_since >= STPD_INITIAL_LISTEN_SEC) &&
                   (ps->configuration_pending || (ps->protocol_blocked &&
                   (ps->block_reason == STP_BLOCK_ALTERNATE ||
                    ps->block_reason == STP_BLOCK_ROOT_PROTECTION ||
                    (external_root && ps->block_reason == STP_BLOCK_LOOP)))) &&
                   n_ops < STPD_MAX_PORTS) {
            ops[n_ops].port = ps->port;
            ops[n_ops].fallback_vlan = ps->vlan;
            ops[n_ops].state = FM_STP_STATE_FORWARDING;
            ops[n_ops].reason = ps->block_reason;
            n_ops++;
        }
    }
    if (g_cfg_mstp_enabled)
        reconcile_msti_roles_locked(now, msti_ops, &n_msti_ops,
                                    STPD_MAX_MSTI_OPS, ops, n_ops);
    pthread_mutex_unlock(&g_stp.lock);

    /* Remove the old forwarding path before opening the replacement. */
    bool blocked = true;
    for (int phase = 0; phase < 2 && blocked; ++phase) {
        int state = phase ? FM_STP_STATE_FORWARDING : FM_STP_STATE_BLOCKING;
        for (int i = 0; i < n_ops; i++) if (ops[i].state == state) blocked = apply_protocol_op(&ops[i]) && blocked;
        for (int i = 0; i < n_msti_ops; i++) if (msti_ops[i].state == state) blocked = apply_msti_protocol_op(&msti_ops[i]) && blocked;
    }
}

void reconcile_rstp_roles(void) {
    u32 lease = nl_port_scope_enter_available();
    if (lease) reconcile_rstp_roles_unscoped();
    nl_port_scope_leave_mask(lease);
}

static bool rstp_participating_locked(int port) {
    stp_port_stats *ps = find_port_stats_locked(port);
    return ps && ps->rstp_enabled && !ps->guard_blocked;
}

static bool shared_rstp_peer_up_locked(int port) {
    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];

        if (!ps->valid || ps->port == port)
            continue;
        if (!ps->rstp_enabled || ps->guard_blocked)
            continue;
        if (ports_share_vlan(port, ps->port) && port_link_up(ps->port))
            return true;
    }
    return false;
}

static bool standard_peer_history_locked(const stp_port_stats *ps,
                                         const u8 local_bridge_id[8]) {
    if (!ps || !local_bridge_id)
        return false;
    if (!stp_bpdu_type_is_config(ps->last_version, ps->last_type))
        return false;
    if (stp_bridge_id_is_zero(ps->last_root_raw) ||
        stp_bridge_id_is_zero(ps->last_bridge_raw))
        return false;
    if (stp_bridge_id_equal(ps->last_root_raw, local_bridge_id) &&
        stp_bridge_id_equal(ps->last_bridge_raw, local_bridge_id))
        return false;
    return true;
}

static bool local_root_redundant_port_locked(int port) {
    u8 local_mac[6];
    u8 local_bridge_id[8];
    stp_port_stats *target;

    if (!port_link_up(port))
        return false;

    load_system_mac(local_mac);
    stp_build_bridge_id(local_bridge_id, local_mac, stpd_bridge_priority());
    target = find_port_stats_locked(port);
    if (standard_peer_history_locked(target, local_bridge_id))
        return false;

    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];

        if (!ps->valid || ps->port == port)
            continue;
        if (!ps->rstp_enabled || ps->guard_blocked)
            continue;
        if (!port_link_up(ps->port))
            continue;
        if (ps->port < port && ports_share_vlan(port, ps->port))
            return true;
    }
    return false;
}

static bool protocol_blocked_locked(int port) {
    stp_port_stats *ps = find_port_stats_locked(port);
    return ps && ps->protocol_blocked;
}

static void mark_protocol_forwarding(int port) {
    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = find_port_stats_locked(port);
    if (ps) {
        ps->protocol_blocked = false;
        ps->block_reason = STP_BLOCK_NONE;
        ps->protocol_blocked_at = 0;
        ps->protocol_block_config_mtime = 0;
        ps->root_protection_superior_seen = 0;
        memset(ps->root_protection_root_raw, 0,
               sizeof(ps->root_protection_root_raw));
        memset(ps->root_protection_bridge_raw, 0,
               sizeof(ps->root_protection_bridge_raw));
        ps->root_protection_root_path_cost = 0;
        ps->root_protection_port_id = 0;
        ps->loop_last_seen = 0;
        ps->loop_peer_port = 0;
        snprintf(ps->protocol_last_error,
                 sizeof(ps->protocol_last_error), "-");
    }
    pthread_mutex_unlock(&g_stp.lock);
}

static void clear_protocol_block(int port, int fallback_vlan,
                                 const char *reason) {
    if (stp_port_paused(port)) return;
    char ifname[32];
    char err[128] = {0};

    ifname_from_port(port, ifname, sizeof(ifname));
    if (set_port_stp_state_all_vlans(port, fallback_vlan,
                                     FM_STP_STATE_FORWARDING,
                                     err, sizeof(err)) == 0) {
        mark_protocol_forwarding(port);
        clear_dynamic_macs_for_port(port, fallback_vlan,
                                    "protocol block cleared");
        NL_LOG_NOTICE("RSTP restored %s to forwarding (%s)", ifname, reason);
        return;
    }

    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = find_port_stats_locked(port);
    if (ps)
        snprintf(ps->protocol_last_error,
                 sizeof(ps->protocol_last_error), "%s", err);
    pthread_mutex_unlock(&g_stp.lock);
    NL_LOG_WARN("RSTP failed to restore %s to forwarding: %s", ifname, err);
}

static void block_protocol_port(int block_port, int peer_port, int fallback_vlan,
                                stp_block_reason reason,
                                const char *reason_text) {
    if (stp_port_paused(block_port) || stp_port_paused(peer_port)) return;
    char ifname[32];
    char peer_ifname[32];
    char err[128] = {0};
    bool already_blocked = false;
    bool can_block = false;
    bool peer_can_forward = false;
    bool peer_already_blocked = false;

    pthread_mutex_lock(&g_stp.lock);
    can_block = rstp_participating_locked(block_port);
    already_blocked = protocol_blocked_locked(block_port);
    peer_can_forward = peer_port > 0 && rstp_participating_locked(peer_port);
    peer_already_blocked = peer_port > 0 && protocol_blocked_locked(peer_port);
    if (can_block && already_blocked) {
        stp_port_stats *ps = find_port_stats_locked(block_port);
        if (ps) {
            ps->loop_last_seen = nl_monotonic_seconds();
            ps->loop_peer_port = peer_port;
        }
    }
    pthread_mutex_unlock(&g_stp.lock);

    if (!can_block)
        return;
    if (already_blocked)
        return;

    ifname_from_port(block_port, ifname, sizeof(ifname));
    ifname_from_port(peer_port, peer_ifname, sizeof(peer_ifname));

    if (set_port_stp_state_all_vlans(block_port, fallback_vlan,
                                     FM_STP_STATE_BLOCKING,
                                     err, sizeof(err)) == 0) {
        pthread_mutex_lock(&g_stp.lock);
        stp_port_stats *ps = port_stats_locked(block_port);
        if (ps) {
            ps->protocol_blocked = true;
            ps->block_reason = reason;
            ps->protocol_blocks++;
            ps->protocol_blocked_at = nl_monotonic_seconds();
            ps->protocol_block_config_mtime = g_stp.config_mtime;
            ps->loop_last_seen = ps->protocol_blocked_at;
            ps->loop_peer_port = peer_port;
            snprintf(ps->protocol_last_error,
                     sizeof(ps->protocol_last_error), "-");
        }
        pthread_mutex_unlock(&g_stp.lock);
        clear_dynamic_macs_for_port(block_port, fallback_vlan,
                                    "protocol port blocked");
        NL_LOG_NOTICE("RSTP blocked %s after %s from %s",
                      ifname, reason_text ? reason_text : "protocol guard",
                      peer_ifname);

        if (peer_can_forward && !peer_already_blocked)
            clear_protocol_block(peer_port, fallback_vlan,
                                 "selected designated port");
        return;
    }

    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = port_stats_locked(block_port);
    if (ps)
        snprintf(ps->protocol_last_error,
                 sizeof(ps->protocol_last_error), "%s", err);
    pthread_mutex_unlock(&g_stp.lock);
    NL_LOG_WARN("RSTP failed to block %s: %s", ifname, err);
}

static void block_loop_port(int block_port, int peer_port, int fallback_vlan) {
    block_protocol_port(block_port, peer_port, fallback_vlan, STP_BLOCK_LOOP,
                        "local loop BPDU");
}

static bool port_in_list(int port, const int *ports, int n_ports) {
    for (int i = 0; i < n_ports; i++)
        if (ports[i] == port)
            return true;
    return false;
}

static int detect_local_mac_loop(void) {
    nl_mac_snapshot snapshot = {0};
    u8 local_mac[6];
    int ports[STPD_MAX_PORTS];
    int n_ports;
    int forward_port = 0;
    int block_port = 0;
    int detected = 0;

    load_system_mac(local_mac);

    n_ports = collect_rstp_enabled_ports(ports, STPD_MAX_PORTS);
    if (n_ports < 2)
        return 0;

    for (int i = 0; i < n_ports; i++) {
        if (ports[i] <= 0)
            continue;
        if (forward_port == 0 || ports[i] < forward_port)
            forward_port = ports[i];
        if (ports[i] > block_port)
            block_port = ports[i];
    }
    if (forward_port <= 0 || block_port <= 0 || forward_port == block_port)
        return 0;
    if (!port_link_up(block_port))
        return 0;

    if (stp_switchd_get_mac_snapshot(
            stpd_switchd_socket_path(), &snapshot) != 0)
        return 0;

    for (u32 i = 0; i < snapshot.n_entries; i++) {
        const nl_mac_snapshot_entry *entry = &snapshot.entries[i];

        if (entry->vlan >= 1 && entry->vlan <= 4094 &&
            entry->port > 0 && !entry->is_static &&
            memcmp(entry->mac, local_mac, sizeof(local_mac)) == 0 &&
            port_in_list(entry->port, ports, n_ports) &&
            port_link_up(entry->port)) {
            block_loop_port(block_port, forward_port, entry->vlan);
            detected++;
        }
    }

    nl_mac_snapshot_reset(&snapshot);
    return detected;
}

static int detect_split_root_guard(void) {
    time_t now = nl_monotonic_seconds();
    u8 local_mac[6];
    u8 local_bridge_id[8];
    int forward_port = 0;
    int block_port = 0;
    int fallback_vlan = 1;
    int candidates = 0;

    load_system_mac(local_mac);
    stp_build_bridge_id(local_bridge_id, local_mac, stpd_bridge_priority());

    pthread_mutex_lock(&g_stp.lock);
    if (!stp_bridge_id_is_zero(g_stp.selected_root_id) &&
        !stp_bridge_id_equal(g_stp.selected_root_id, local_bridge_id)) {
        pthread_mutex_unlock(&g_stp.lock);
        return 0;
    }

    for (int i = 0; i < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];

        if (!ps->valid || !ps->rstp_enabled || ps->guard_blocked || stp_port_paused(ps->port))
            continue;
        if (!stp_bpdu_type_is_config(ps->last_version, ps->last_type))
            continue;
        if (ps->last_seen == 0 || now - ps->last_seen > stpd_loop_stale_sec())
            continue;
        if (stp_bridge_id_is_zero(ps->last_root_raw) ||
            stp_bridge_id_equal(ps->last_root_raw, local_bridge_id))
            continue;

        candidates++;
        if (forward_port == 0 || ps->port < forward_port)
            forward_port = ps->port;
        if (ps->port > block_port) {
            block_port = ps->port;
            fallback_vlan = ps->vlan;
        }
    }
    pthread_mutex_unlock(&g_stp.lock);

    if (candidates < 2 || forward_port <= 0 || block_port <= 0 ||
        forward_port == block_port)
        return 0;
    if (!port_link_up(block_port))
        return 0;

    block_protocol_port(block_port, forward_port, fallback_vlan,
                        STP_BLOCK_SPLIT_ROOT, "split-root peer BPDU");
    return 1;
}

static void reconcile_protocol_blocks(void) {
    struct pending_clear {
        int port;
        int vlan;
        char reason[32];
    } clear[STPD_MAX_PORTS];
    int n_clear = 0;
    time_t now = nl_monotonic_seconds();
    u8 local_mac[6];
    u8 local_bridge_id[8];
    stp_priority_vector local_best;

    load_system_mac(local_mac);
    stp_build_bridge_id(local_bridge_id, local_mac, stpd_bridge_priority());
    local_priority_vector(&local_best, local_bridge_id, 0);

    pthread_mutex_lock(&g_stp.lock);
    for (int i = 0; i < STPD_MAX_PORTS && n_clear < STPD_MAX_PORTS; i++) {
        stp_port_stats *ps = &g_stp.ports[i];
        if (!ps->valid || !ps->protocol_blocked || stp_port_paused(ps->port))
            continue;
        if (ps->guard_blocked)
            continue;
        if (!ps->rstp_enabled) {
            clear[n_clear].port = ps->port;
            clear[n_clear].vlan = ps->vlan;
            snprintf(clear[n_clear].reason, sizeof(clear[n_clear].reason),
                     "rstp disabled");
            n_clear++;
            continue;
        }
        if (ps->block_reason == STP_BLOCK_ALTERNATE)
            continue;
        if (ps->block_reason == STP_BLOCK_ROOT_PROTECTION) {
            if (root_protection_superior_locked(ps, now, &local_best)) {
                continue;
            }
            clear[n_clear].port = ps->port;
            clear[n_clear].vlan = ps->vlan;
            snprintf(clear[n_clear].reason, sizeof(clear[n_clear].reason),
                     "root protection cleared");
            n_clear++;
            continue;
        }
        if (ps->loop_last_seen == 0 ||
            now - ps->loop_last_seen > stpd_loop_stale_sec()) {
            clear[n_clear].port = ps->port;
            clear[n_clear].vlan = ps->vlan;
            snprintf(clear[n_clear].reason, sizeof(clear[n_clear].reason),
                     "loop expired");
            n_clear++;
        }
    }
    pthread_mutex_unlock(&g_stp.lock);

    for (int i = 0; i < n_clear; i++)
        clear_protocol_block(clear[i].port, clear[i].vlan, clear[i].reason);
}

static void enforce_bpdu_guard(int port, int vlan) {
    if (stp_port_paused(port)) return;
    bool guard_enabled = false;
    bool already_blocked = false;
    char ifname[32];
    char err[128] = {0};

    reload_stp_config_if_needed(false);

    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = port_stats_locked(port);
    if (ps) {
        guard_enabled = ps->bpdu_guard_enabled;
        already_blocked = ps->guard_blocked;
    }
    pthread_mutex_unlock(&g_stp.lock);

    if (!guard_enabled || already_blocked)
        return;

    ifname_from_port(port, ifname, sizeof(ifname));
    if (set_port_stp_state_all_vlans(port, vlan, FM_STP_STATE_BLOCKING,
                                     err, sizeof(err)) == 0) {
        pthread_mutex_lock(&g_stp.lock);
        ps = port_stats_locked(port);
        if (ps) {
            ps->guard_blocked = true;
            ps->guard_blocks++;
            ps->guard_blocked_at = nl_monotonic_seconds();
            snprintf(ps->guard_last_error, sizeof(ps->guard_last_error), "-");
        }
        pthread_mutex_unlock(&g_stp.lock);
        clear_dynamic_macs_for_port(port, vlan, "BPDU guard blocked port");
        NL_LOG_NOTICE("BPDU guard blocked %s after BPDU rx", ifname);
    } else {
        pthread_mutex_lock(&g_stp.lock);
        ps = port_stats_locked(port);
        if (ps)
            snprintf(ps->guard_last_error,
                     sizeof(ps->guard_last_error), "%s", err);
        pthread_mutex_unlock(&g_stp.lock);
        NL_LOG_WARN("BPDU guard failed to block %s: %s", ifname, err);
    }
}

static void note_rstp_tx(const stp_tx_info *info, bool ok) {
    int port;
    int flags;

    if (!info)
        return;
    port = info->port;
    flags = info->extra_flags;

    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = port_stats_locked(port);
    if (ps) {
        if (ok) {
            ps->tx_bpdus++;
            if (flags & STP_RSTP_FLAG_PROPOSAL)
                ps->tx_proposal_bpdus++;
            if (flags & STP_RSTP_FLAG_AGREEMENT)
                ps->tx_agreement_bpdus++;
            if (flags & STP_RSTP_FLAG_TC)
                ps->tx_tc_bpdus++;
            ps->last_tx = nl_monotonic_seconds();
        } else {
            ps->tx_failures++;
        }
    }
    if (ok && ps) {
        for (int i = 0; i < info->msti_count; i++) {
            const stp_msti_record *rec = &info->msti[i];
            stp_port_msti_stats *slot =
                find_port_msti_locked(ps, rec->mstid);

            if (!slot)
                continue;
            if (rec->flags & STP_RSTP_FLAG_PROPOSAL)
                slot->tx_proposal_bpdus++;
            if (rec->flags & STP_RSTP_FLAG_AGREEMENT)
                slot->tx_agreement_bpdus++;
            slot->last_tx = nl_monotonic_seconds();
        }
    }
    if (ok) {
        g_stp.tx_bpdus++;
        if (flags & STP_RSTP_FLAG_PROPOSAL)
            g_stp.tx_proposal_bpdus++;
        if (flags & STP_RSTP_FLAG_AGREEMENT)
            g_stp.tx_agreement_bpdus++;
        if (flags & STP_RSTP_FLAG_TC)
            g_stp.tx_tc_bpdus++;
    } else {
        g_stp.tx_failures++;
    }
    pthread_mutex_unlock(&g_stp.lock);
}

static int collect_rstp_enabled_ports(int *ports, int max_ports) {
    int n = 0;

    if (!ports || max_ports <= 0)
        return 0;

    reload_stp_config_if_needed(false);
    pthread_mutex_lock(&g_stp.lock);
    for (int i = 0; i < STPD_MAX_PORTS && n < max_ports; i++) {
        if (g_stp.ports[i].valid &&
            g_stp.ports[i].rstp_enabled &&
            !g_stp.ports[i].guard_blocked)
            ports[n++] = g_stp.ports[i].port;
    }
    pthread_mutex_unlock(&g_stp.lock);
    return n;
}

static int mst_flags_for_role(stp_role_id role) {
    switch (role) {
    case STP_ROLE_ROOT:
        return 0x08 | STP_RSTP_FLAG_LEARNING | STP_RSTP_FLAG_FORWARDING;
    case STP_ROLE_DESIGNATED:
        return 0x0c | STP_RSTP_FLAG_LEARNING | STP_RSTP_FLAG_FORWARDING;
    case STP_ROLE_ALTERNATE:
        return 0x04;
    case STP_ROLE_DISABLED:
    default:
        return 0;
    }
}

static void fill_mst_tx_info_locked(stp_tx_info *info, time_t now) {
    stp_port_stats *ps;

    if (!info || !g_cfg_mstp_enabled)
        return;

    ps = find_port_stats_locked(info->port);
    info->mstp = true;
    snprintf(info->mst_config_name, sizeof(info->mst_config_name),
             "%s", g_stp.mst_config_name);
    info->mst_revision = g_stp.mst_revision;
    memcpy(info->mst_digest, g_stp.mst_digest, sizeof(info->mst_digest));
    info->msti_count = 0;

    for (int i = 0; i < STPD_MAX_MSTI && info->msti_count < STPD_MAX_MSTI; i++) {
        const stp_mst_instance_state *inst = &g_stp.mst_instances[i];
        stp_port_msti_stats *slot;
        stp_msti_record *rec;

        if (!inst->valid)
            continue;
        slot = find_port_msti_locked(ps, inst->id);
        rec = &info->msti[info->msti_count++];
        memset(rec, 0, sizeof(*rec));
        rec->mstid = inst->id;
        rec->flags = mst_flags_for_role(slot ? slot->role :
                                        STP_ROLE_DESIGNATED);
        if (slot) {
            bool designated_tx = slot->role == STP_ROLE_DESIGNATED &&
                                 !slot->protocol_blocked;

            if (designated_tx &&
                (slot->last_agreement_seen == 0 ||
                 now - slot->last_agreement_seen > stpd_bpdu_stale_sec()))
                rec->flags |= STP_RSTP_FLAG_PROPOSAL;
            if (slot->agreement_due_until > now) {
                rec->flags |= STP_RSTP_FLAG_AGREEMENT;
                slot->agreement_due_until = 0;
            }
        }
        if (stp_bridge_id_is_zero(inst->selected_root_id))
            memcpy(rec->regional_root_id, inst->bridge_id,
                   sizeof(rec->regional_root_id));
        else
            memcpy(rec->regional_root_id, inst->selected_root_id,
                   sizeof(rec->regional_root_id));
        rec->internal_root_path_cost = inst->selected_root_path_cost;
        rec->bridge_priority = (inst->bridge_priority >> 8) & 0xff;
        rec->port_priority = stpd_msti_port_priority(inst->id, info->port);
        rec->remaining_hops = inst->root_port > 0 ?
                              inst->selected_remaining_hops :
                              stpd_mst_max_hops();
    }
}

static bool mstp_port_tx_needed_locked(stp_port_stats *ps, time_t now) {
    if (!g_cfg_mstp_enabled || !ps || !ps->rstp_enabled ||
        ps->guard_blocked)
        return false;

    for (int i = 0; i < STPD_MAX_MSTI; i++) {
        const stp_mst_instance_state *inst = &g_stp.mst_instances[i];
        stp_port_msti_stats *slot;
        bool designated_tx;

        if (!inst->valid)
            continue;
        slot = find_port_msti_locked(ps, inst->id);
        if (!slot)
            continue;

        if (slot->agreement_due_until > now)
            return true;

        designated_tx = slot->role == STP_ROLE_DESIGNATED &&
                        !slot->protocol_blocked;
        if (designated_tx &&
            (slot->last_agreement_seen == 0 ||
             now - slot->last_agreement_seen > stpd_bpdu_stale_sec()))
            return true;
    }
    return false;
}

static int collect_rstp_tx_ports(stp_tx_info *infos, int max_infos) {
    int n = 0;
    u8 local_mac[6];
    u8 local_bridge_id[8];
    time_t now = nl_monotonic_seconds();

    if (!infos || max_infos <= 0)
        return 0;

    reload_stp_config_if_needed(false);
    load_system_mac(local_mac);
    stp_build_bridge_id(local_bridge_id, local_mac, stpd_bridge_priority());

    pthread_mutex_lock(&g_stp.lock);
    expire_sync_agreements_locked(now);
    if (g_stp.started_at > 0 &&
        now - g_stp.started_at < STPD_INITIAL_LISTEN_SEC) {
        pthread_mutex_unlock(&g_stp.lock);
        return 0;
    }

    if (stp_bridge_id_is_zero(g_stp.selected_root_id)) {
        memcpy(g_stp.selected_root_id, local_bridge_id, 8);
        g_stp.selected_root_path_cost = 0;
    }

    for (int i = 0; i < STPD_MAX_PORTS && n < max_infos; i++) {
        stp_port_stats *ps = &g_stp.ports[i];
        bool agreement_due;
        bool designated_tx;
        bool msti_tx_needed;
        bool tc_active;
        int extra_flags = 0;

        if (!ps->valid || !ps->rstp_enabled || ps->guard_blocked)
            continue;
        if (stp_port_paused(ps->port)) continue;
        agreement_due = ps->agreement_due_until > now;
        designated_tx = ps->role == STP_ROLE_DESIGNATED &&
                        !ps->protocol_blocked;
        msti_tx_needed = mstp_port_tx_needed_locked(ps, now);
        if (!designated_tx && !agreement_due && !msti_tx_needed)
            continue;

        tc_active = g_stp.tc_tx_until > now;
        if (designated_tx) {
            if (tc_active)
                extra_flags |= STP_RSTP_FLAG_TC;
            if (ps->last_agreement_seen == 0 ||
                now - ps->last_agreement_seen > stpd_bpdu_stale_sec())
                extra_flags |= STP_RSTP_FLAG_PROPOSAL;
        }
        if (agreement_due) {
            extra_flags |= STP_RSTP_FLAG_AGREEMENT;
            ps->agreement_due_until = 0;
        }
        infos[n].port = ps->port;
        infos[n].role = ps->role;
        infos[n].extra_flags = extra_flags;
        memcpy(infos[n].root_id, g_stp.selected_root_id, 8);
        infos[n].root_path_cost = g_stp.selected_root_path_cost;
        memcpy(infos[n].bridge_id, local_bridge_id, 8);
        fill_mst_tx_info_locked(&infos[n], now);
        n++;
    }
    pthread_mutex_unlock(&g_stp.lock);
    return n;
}

static int send_rstp_hello(const stp_tx_info *info, const u8 src_mac[6]) {
    u8 frame[1600];
    int frame_len;

    if (!info)
        return -1;

    if (info->mstp) {
        frame_len = stp_build_mstp_frame(
            frame, sizeof(frame), src_mac,
            info->root_id, info->root_path_cost,
            info->bridge_id, info->bridge_id,
            info->port, stpd_port_priority(info->port),
            info->role, info->extra_flags,
            stpd_max_age_sec(), stpd_hello_sec(),
            stpd_forward_delay_sec(),
            info->mst_config_name, info->mst_revision,
            info->mst_digest, 0, stpd_mst_max_hops(),
            info->msti, info->msti_count);
    } else {
        frame_len = stp_build_rstp_frame(frame, sizeof(frame), src_mac,
                                         info->root_id, info->root_path_cost,
                                         info->bridge_id, info->port,
                                         stpd_port_priority(info->port),
                                         info->role, info->extra_flags,
                                         stpd_max_age_sec(),
                                         stpd_hello_sec(),
                                         stpd_forward_delay_sec());
    }
    if (frame_len <= 0)
        return -1;

    return stp_packet_tx(stpd_packetd_socket_path(), stp_lag_egress(info->port),
                         frame, frame_len);
}

static void *tx_thread(void *arg) {
    (void)arg;
    u8 src_mac[6];
    stp_tx_info *tx_infos;

    tx_infos = calloc(STPD_MAX_PORTS, sizeof(*tx_infos));
    if (!tx_infos) {
        NL_LOG_ERR("RSTP transmit workspace allocation failed");
        return NULL;
    }

    while (g_running) {
        int n_ports;

        (void)stp_lag_refresh(stpd_switchd_socket_path());
        u32 lease = nl_port_scope_enter_available();
        load_system_mac(src_mac);
        reconcile_rstp_roles();
        n_ports = collect_rstp_tx_ports(tx_infos, STPD_MAX_PORTS);

        for (int i = 0; i < n_ports; i++) {
            int port = tx_infos[i].port;
            if (stp_port_paused(port)) continue;
            if (!port_link_up(port)) {
                NL_LOG_DBG("RSTP TX port=%d skipped (link not UP)", port);
                continue;
            }
            int st = send_rstp_hello(&tx_infos[i], src_mac);
            note_rstp_tx(&tx_infos[i], st == 0);
            if (st == 0)
                NL_LOG_DBG("RSTP TX port=%d", port);
            else
                NL_LOG_WARN("RSTP TX port=%d failed err=%d", port, st);
        }

        (void)detect_local_mac_loop();
        (void)detect_split_root_guard();
        reconcile_protocol_blocks();
        reconcile_rstp_roles();
        nl_port_scope_leave_mask(lease);
        stpd_wait_seconds(stpd_hello_sec());
    }
    free(tx_infos);
    return NULL;
}

static void handle_local_loop_bpdu(int src_port, int vlan,
                                   const u8 *bpdu, int bpdu_len,
                                   int port_id) {
    u8 local_mac[6];
    u8 local_bridge_id[8];
    int peer_port;
    int block_port;
    int forward_port;
    bool src_ok = false;
    bool peer_ok = false;

    if (!bpdu || bpdu_len < 27 || src_port <= 0)
        return;
    if (port_id <= 0)
        return;

    load_system_mac(local_mac);
    stp_build_bridge_id(local_bridge_id, local_mac, stpd_bridge_priority());
    if (!stp_bridge_id_equal(bpdu + 5, local_bridge_id) ||
        !stp_bridge_id_equal(bpdu + 17, local_bridge_id))
        return;

    peer_port = port_id & 0x0fff;
    if (peer_port <= 0)
        return;

    pthread_mutex_lock(&g_stp.lock);
    src_ok = rstp_participating_locked(src_port);
    peer_ok = rstp_participating_locked(peer_port);
    pthread_mutex_unlock(&g_stp.lock);
    if (!src_ok || !peer_ok)
        return;

    if (peer_port == src_port) {
        block_port = src_port;
        forward_port = 0;
    } else if (src_port > peer_port) {
        block_port = src_port;
        forward_port = peer_port;
    } else {
        block_port = peer_port;
        forward_port = src_port;
    }

    block_loop_port(block_port, forward_port, vlan);
}

static bool bpdu_originates_from_local_bridge(const stp_bpdu_info *info) {
    u8 local_mac[6];
    u8 local_bridge_id[8];
    const u8 *bridge_id;

    if (!info || !info->has_priority_vector)
        return false;

    load_system_mac(local_mac);
    stp_build_bridge_id(local_bridge_id, local_mac, stpd_bridge_priority());
    bridge_id = info->has_mstp ? info->cist_bridge_id : info->bridge_id;
    return stp_bridge_id_equal(info->root_id, local_bridge_id) &&
           stp_bridge_id_equal(bridge_id, local_bridge_id);
}

static stp_port_msti_stats *port_msti_slot_locked(stp_port_stats *ps,
                                                  int mstid) {
    stp_port_msti_stats *free_slot = NULL;

    if (!ps || mstid <= 0)
        return NULL;
    for (int i = 0; i < STPD_MAX_MSTI; i++) {
        if (ps->msti[i].valid && ps->msti[i].mstid == mstid)
            return &ps->msti[i];
        if (!ps->msti[i].valid && !free_slot)
            free_slot = &ps->msti[i];
    }
    if (!free_slot)
        return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->valid = true;
    free_slot->mstid = mstid;
    free_slot->role = STP_ROLE_DISABLED;
    free_slot->block_reason = STP_BLOCK_NONE;
    return free_slot;
}

static bool mst_instance_configured_locked(int mstid) {
    for (int i = 0; i < STPD_MAX_MSTI; i++) {
        if (g_stp.mst_instances[i].valid &&
            g_stp.mst_instances[i].id == mstid)
            return true;
    }
    return false;
}

static void record_mstp_msti_locked(stp_port_stats *ps,
                                    const stp_bpdu_info *info,
                                    time_t now) {
    bool same_region;

    if (!ps || !info || !info->has_mstp)
        return;
    same_region = mst_region_matches_locked(info);
    if (!same_region)
        return;

    for (int i = 0; i < info->msti_count; i++) {
        const stp_msti_record *rec = &info->msti[i];
        stp_port_msti_stats *slot;

        if (!mst_instance_configured_locked(rec->mstid))
            continue;
        slot = port_msti_slot_locked(ps, rec->mstid);
        if (!slot)
            continue;
        slot->rx_bpdus++;
        slot->last_seen = now;
        slot->last_flags = rec->flags;
        slot->last_peer_role = stp_role_from_flags(rec->flags);
        if (rec->flags & STP_RSTP_FLAG_PROPOSAL) {
            slot->proposal_bpdus++;
            slot->last_proposal_seen = now;
            slot->agreement_due_until = now + STPD_AGREEMENT_REPLY_SEC;
        }
        if (rec->flags & STP_RSTP_FLAG_AGREEMENT) {
            slot->agreement_bpdus++;
            slot->last_agreement_seen = now;
        }
        memcpy(slot->last_root_raw, rec->regional_root_id,
               sizeof(slot->last_root_raw));
        slot->last_root_path_cost = rec->internal_root_path_cost;
        slot->remaining_hops = rec->remaining_hops;
    }
}

static void record_malformed(int port, int vlan) {
    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = port_stats_locked(port);
    if (ps) {
        ps->vlan = vlan;
        ps->malformed_bpdus++;
        ps->last_seen = nl_monotonic_seconds();
    }
    g_stp.malformed_bpdus++;
    g_stp.last_rx = nl_monotonic_seconds();
    pthread_mutex_unlock(&g_stp.lock);
    enforce_bpdu_guard(port, vlan);
}

static void record_bpdu(const u8 *frame, int frame_len, int src_port, int vlan) {
    stp_bpdu_info info;
    time_t now;
    stp_priority_vector candidate;
    stp_priority_vector local_best;
    u8 local_mac[6];
    u8 local_bridge_id[8];
    bool local_loop_bpdu;

    if (stp_parse_bpdu_frame(frame, frame_len, &info) != 0) {
        record_malformed(src_port, vlan);
        return;
    }

    now = nl_monotonic_seconds();
    memset(&candidate, 0, sizeof(candidate));
    memset(&local_best, 0, sizeof(local_best));
    memset(local_bridge_id, 0, sizeof(local_bridge_id));
    if (info.has_priority_vector) {
        const u8 *bridge_id = info.has_mstp ?
                              info.cist_bridge_id : info.bridge_id;

        load_system_mac(local_mac);
        stp_build_bridge_id(local_bridge_id, local_mac,
                            stpd_bridge_priority());
        local_priority_vector(&local_best, local_bridge_id, 0);
        memcpy(candidate.root_id, info.root_id, sizeof(candidate.root_id));
        candidate.root_path_cost =
            info.root_path_cost + (u32)stpd_port_path_cost(src_port);
        memcpy(candidate.bridge_id, bridge_id, sizeof(candidate.bridge_id));
        candidate.port_id = info.port_id > 0 ? (u16)info.port_id : 0;
        candidate.receive_port_id = stpd_port_id(src_port);
        candidate.port = src_port;
    }

    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = port_stats_locked(src_port);
    if (ps) {
        ps->vlan = vlan;
        ps->rx_bpdus++;
        ps->last_seen = now;
        ps->last_version = info.version;
        ps->last_type = info.type;
        ps->last_flags = info.flags;
        ps->last_port_id = info.port_id;
        ps->last_peer_timers_valid = info.has_timers;
        if (info.has_timers) {
            ps->last_peer_message_age_ticks = info.message_age_ticks;
            ps->last_peer_max_age_ticks = info.max_age_ticks;
            ps->last_peer_hello_time_ticks = info.hello_time_ticks;
            ps->last_peer_forward_delay_ticks = info.forward_delay_ticks;
        }
        if (info.has_priority_vector) {
            const u8 *bridge_id = info.has_mstp ?
                                  info.cist_bridge_id : info.bridge_id;

            memcpy(ps->last_root_raw, info.root_id, 8);
            ps->last_root_path_cost = info.root_path_cost;
            memcpy(ps->last_bridge_raw, bridge_id, 8);
            stp_format_bridge_id(info.root_id, ps->last_root_id,
                             sizeof(ps->last_root_id));
            stp_format_bridge_id(bridge_id, ps->last_bridge_id,
                             sizeof(ps->last_bridge_id));
        }
        record_mstp_msti_locked(ps, &info, now);
        if (info.has_priority_vector)
            note_root_protection_superior_locked(ps, &candidate,
                                                 &local_best, now);

        if (info.type == 0x80)
            ps->tcn_bpdus++;
        else if (info.version == 0 && info.type == 0x00)
            ps->stp_bpdus++;
        else if (info.version == 2 && info.type == 0x02)
            ps->rstp_bpdus++;
        else if (info.version == 3 && info.type == 0x02)
            ps->mstp_bpdus++;
        else
            ps->unknown_bpdus++;

        if (info.version >= 2 && stp_bpdu_type_is_config(info.version,
                                                         info.type)) {
            if (info.flags & STP_RSTP_FLAG_PROPOSAL) {
                ps->proposal_bpdus++;
                ps->last_proposal_seen = now;
                ps->agreement_due_until = now + STPD_AGREEMENT_REPLY_SEC;
                g_stp.proposal_bpdus++;
            }
            if (info.flags & STP_RSTP_FLAG_AGREEMENT) {
                ps->agreement_bpdus++;
                ps->last_agreement_seen = now;
                g_stp.agreement_bpdus++;
            }
        }
    }
    g_stp.total_bpdus++;
    g_stp.last_rx = nl_monotonic_seconds();
    pthread_mutex_unlock(&g_stp.lock);
    local_loop_bpdu = bpdu_originates_from_local_bridge(&info);
    if (!local_loop_bpdu)
        handle_topology_change(src_port, vlan, info.version, info.type,
                               info.flags);
    enforce_bpdu_guard(src_port, vlan);
    handle_local_loop_bpdu(src_port, vlan, info.payload, info.payload_len,
                           info.port_id);
    reconcile_rstp_roles();

    NL_LOG_DBG("BPDU rx port=%d vlan=%d version=%d type=0x%02x",
               src_port, vlan, info.version, info.type);
}

static void *rx_thread(void *arg) {
    (void)arg;
    u8 frame[NETLAB_PACKET_IO_MAX];

    while (g_running) {
        int src_port = 0;
        int vlan = 0;
        u64 captured_at = 0;
        int n = packetd_read_event(frame, sizeof(frame), &src_port, &vlan, &captured_at);
        if (n > 0 && nl_port_scope_packet_enter(src_port, captured_at)) {
            int bridge_port = stp_lag_ingress(src_port);
            u32 lease = nl_port_scope_enter_available();
            if (bridge_port > 0 && !stp_port_paused(bridge_port)) record_bpdu(frame, n, bridge_port, vlan);
            nl_port_scope_leave_mask(lease);
            nl_port_scope_leave(src_port);
        }
    }
    nl_client_close(&g_packetd_subscription);
    return NULL;
}

static void clear_bpdu_guard(nl_conn *conn, nl_msg_hdr *msg) {
    char payload[128] = {0};
    char ifname[64] = {0};
    char err[128] = {0};
    int port;
    bool was_blocked = false;
    char resp[256];

    if (msg->payload_len > 0) {
        size_t n = msg->payload_len;
        if (n >= sizeof(payload))
            n = sizeof(payload) - 1;
        memcpy(payload, msg->payload, n);
        payload[n] = '\0';
    }

    if (sscanf(payload, "interface=%63s", ifname) != 1 ||
        ifname_to_port(ifname) <= 0) {
        send_text_response(conn, msg, -1,
                           "invalid BPDU guard clear request");
        return;
    }
    port = ifname_to_port(ifname);
    u32 lease = stp_port_scope_mask(port);
    if (!nl_port_scope_enter_mask(lease)) {
        send_text_response(conn, msg, NL_ERR_RPC_BUSY, "port configuration is in progress"); return;
    }

    pthread_mutex_lock(&g_stp.lock);
    stp_port_stats *ps = find_port_stats_locked(port);
    if (ps)
        was_blocked = ps->guard_blocked;
    pthread_mutex_unlock(&g_stp.lock);

    if (was_blocked &&
        set_port_stp_state_all_vlans(port, 0, FM_STP_STATE_FORWARDING,
                                     err, sizeof(err)) != 0) {
        snprintf(resp, sizeof(resp), "failed to clear BPDU guard on %s: %s",
                 ifname, err);
        send_text_response(conn, msg, -1, resp);
        nl_port_scope_leave_mask(lease);
        return;
    }

    pthread_mutex_lock(&g_stp.lock);
    ps = find_port_stats_locked(port);
    if (ps) {
        ps->guard_blocked = false;
        ps->guard_blocked_at = 0;
        snprintf(ps->guard_last_error, sizeof(ps->guard_last_error), "-");
    }
    pthread_mutex_unlock(&g_stp.lock);

    if (was_blocked)
        clear_dynamic_macs_for_port(port, 0, "BPDU guard cleared");

    snprintf(resp, sizeof(resp), "BPDU guard cleared on %s", ifname);
    nl_port_scope_leave_mask(lease);
    send_text_response(conn, msg, 0, resp);
}

static int stpd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    (void)ctx;

    switch (msg->method) {
    case NL_STPD_SHOW_MONITOR:
        stp_show_send_monitor(conn, msg);
        return NL_OK;
    case NL_STPD_CLEAR_BPDU_GUARD:
        clear_bpdu_guard(conn, msg);
        return NL_OK;
    case NL_STPD_SHOW_STATE:
        stp_show_send_state(conn, msg);
        return NL_OK;
    case NL_STPD_RELOAD: {
        bool ok = reload_stp_config_if_needed(true);
        send_text_response(conn, msg, ok ? NL_OK : NL_ERR_HW_STATE_OUT_OF_SYNC, ok ? "stpd reload complete" : "stpd reload failed");
        return NL_OK;
    }
    default:
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        return NL_OK;
    }
}

static void resume_stp_timers(u32 mask, time_t seconds) {
    pthread_mutex_lock(&g_stp.lock);
    for (int i = 0; i < STPD_MAX_PORTS; ++i) {
        stp_port_stats *p = &g_stp.ports[i];
        if (!p->valid || !(stp_port_scope_mask(p->port) & mask)) continue;
        time_t *times[] = {&p->last_seen, &p->last_tx, &p->agreement_due_until,
            &p->last_proposal_seen, &p->last_agreement_seen, &p->loop_last_seen,
            &p->root_protection_superior_seen, &p->configuration_since};
        for (unsigned j = 0; j < sizeof(times) / sizeof(times[0]); ++j) if (*times[j]) *times[j] += seconds;
        for (int j = 0; j < STPD_MAX_MSTI; ++j) {
            stp_port_msti_stats *m = &p->msti[j];
            if (!m->valid) continue;
            time_t *mst_times[] = {&m->last_seen, &m->last_tx, &m->agreement_due_until,
                &m->last_proposal_seen, &m->last_agreement_seen};
            for (unsigned k = 0; k < sizeof(mst_times) / sizeof(mst_times[0]); ++k)
                if (*mst_times[k]) *mst_times[k] += seconds;
        }
    }
    pthread_mutex_unlock(&g_stp.lock);
}

static int stpd_on_init(void *ctx) {
    (void)ctx;

    memset(&g_runtime, 0, sizeof(g_runtime));
    memset(&g_stp, 0, sizeof(g_stp));
    g_running = 1;
    if (pthread_mutex_init(&g_stp.lock, NULL) != 0) {
        NL_LOG_CRIT("failed to initialize STP state lock");
        return -1;
    }
    g_runtime.lock_initialized = true;
    nl_port_scope_on_resume_monotonic(resume_stp_timers);
    g_stp.started_at = nl_monotonic_seconds();
    reload_stp_config_if_needed(true);

    if (pthread_create(&g_runtime.rx_thread, NULL, rx_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create STP receive thread");
        pthread_mutex_destroy(&g_stp.lock);
        g_runtime.lock_initialized = false;
        return -1;
    }
    g_runtime.rx_thread_started = true;
    if (pthread_create(&g_runtime.tx_thread, NULL, tx_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create STP transmit thread");
        g_running = 0;
        pthread_join(g_runtime.rx_thread, NULL);
        g_runtime.rx_thread_started = false;
        pthread_mutex_destroy(&g_stp.lock);
        g_runtime.lock_initialized = false;
        return -1;
    }
    g_runtime.tx_thread_started = true;

    NL_LOG_NOTICE("stpd ready (BPDU monitor)");
    return NL_OK;
}

static void stpd_on_idle(void *ctx, s64 elapsed_ms) {
    (void)ctx;
    (void)elapsed_ms;
    reload_stp_config_if_needed(false);
}

static void stpd_on_shutdown(void *ctx) {
    (void)ctx;

    g_running = 0;
    if (g_runtime.rx_thread_started) {
        pthread_join(g_runtime.rx_thread, NULL);
        g_runtime.rx_thread_started = false;
    }
    if (g_runtime.tx_thread_started) {
        pthread_join(g_runtime.tx_thread, NULL);
        g_runtime.tx_thread_started = false;
    }
    if (g_runtime.lock_initialized) {
        free(g_active_stp_xml); g_active_stp_xml = NULL;
        pthread_mutex_destroy(&g_stp.lock);
        g_runtime.lock_initialized = false;
    }
}

int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name = "stpd",
        .socket_path = stpd_socket_path(),
        .service_id = NL_DAEMON_STPD,
        .auth_mode = NL_DAEMON_AUTH_STANDARD,
        .dispatch = stpd_dispatch,
        .ctx = NULL,
        .on_init = stpd_on_init,
        .on_shutdown = stpd_on_shutdown,
        .poll_interval_ms = 1000,
        .on_idle = stpd_on_idle,
    };

    (void)argc;
    (void)argv;
    return nl_daemon_run(&cfg);
}
