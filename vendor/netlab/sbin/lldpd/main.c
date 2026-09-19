/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/port_scope.h"
#include "netlab/packet_event.h"
#include "lldp_format.h"
#include "lldp_tlv.h"
#include "lldp_xml.h"
#include "netlab/daemon.h"
#include "netlab/error.h"
#include "netlab/ipc.h"
#include "netlab/interface_id.h"
#include "netlab/journal.h"
#include "netlab/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <arpa/inet.h>

#define LLDPD_SOCKET   "/var/run/netlab/lldpd.sock"
#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
#define PACKETD_SOCKET "/var/run/netlab/packetd.sock"
#define LLDP_ETHERTYPE 0x88CC
#define LLDP_DST_MAC   "\x01\x80\xc2\x00\x00\x0e"
#define PACKETD_RX_IDLE_SEC 5
#define LLDP_CONFIG_RELOAD_SEC 2
#define LLDP_PORT_LIMIT NL_MAX_PORTS

static volatile sig_atomic_t g_running = 1;

static lldp_neighbor g_neighbors[64];
static int g_n_neighbors = 0;
static pthread_mutex_t g_nb_lock;

typedef struct {
    u64 rx_frames;
    u64 rx_valid;
    u64 rx_dropped;
    u64 tx_frames;
    u64 tx_failures;
    u64 aged_out;
    u64 packetd_reconnects;
    time_t last_rx;
    time_t last_tx;
} lldp_stats;

static lldp_stats g_stats;
static pthread_mutex_t g_stats_lock;

typedef struct {
    bool configured;
    bool disabled;
    dcbx_state dcbx;
    u64 dcbx_tx_frames;
    u64 rx_frames;
    u64 tx_frames;
    u64 tx_failures;
    time_t last_rx;
    time_t last_tx;
} lldp_port_state;

static lldp_port_state g_ports[LLDP_PORT_LIMIT + 1];
static lldp_config g_config;
static pthread_mutex_t g_port_lock;
static time_t g_last_config_check;
static time_t g_config_mtime;
static long g_config_mtime_nsec;

typedef struct {
    pthread_t rx_thread;
    pthread_t tx_thread;
    pthread_t aging_thread;
    bool rx_thread_started;
    bool tx_thread_started;
    bool aging_thread_started;
    bool nb_lock_initialized;
    bool stats_lock_initialized;
    bool port_lock_initialized;
} lldpd_runtime;

static lldpd_runtime g_runtime;

static time_t monotonic_seconds(void) {
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 ? now.tv_sec : 0;
}

static const char *lldpd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_LLDPD_SOCKET", LLDPD_SOCKET);
}

static const char *lldpd_switchd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET",
                                       SWITCHD_SOCKET);
}

static const char *lldpd_packetd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_PACKETD_SOCKET",
                                       PACKETD_SOCKET);
}

static void lldpd_wait_seconds(int seconds) {
    while (g_running && seconds-- > 0)
        sleep(1);
}

static bool default_port_enabled(int port) {
    return nl_ifid_lldp_default_enabled(port);
}

static void config_defaults(lldp_config *cfg) {
    nl_platform_identity ident;

    if (!cfg)
        return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->tx_interval = LLDP_DEFAULT_TX_INTERVAL;
    cfg->hold_multiplier = LLDP_DEFAULT_HOLD_MULTIPLIER;
    if (nl_platform_identity_get(&ident)) {
        snprintf(cfg->system_name, sizeof(cfg->system_name), "%s",
                 ident.system_name);
        snprintf(cfg->system_description, sizeof(cfg->system_description),
                 "%s", ident.system_description);
    }
}

static bool port_enabled_locked(int port) {
    if (port <= 0 || port > LLDP_PORT_LIMIT)
        return false;
    if (g_config.disabled)
        return false;
    if (g_ports[port].configured)
        return !g_ports[port].disabled;
    return default_port_enabled(port);
}

static bool lldp_port_enabled(int port) {
    bool enabled;

    pthread_mutex_lock(&g_port_lock);
    enabled = port_enabled_locked(port);
    pthread_mutex_unlock(&g_port_lock);
    return enabled;
}

static void lldp_config_snapshot(lldp_config *cfg) {
    if (!cfg)
        return;
    pthread_mutex_lock(&g_port_lock);
    *cfg = g_config;
    pthread_mutex_unlock(&g_port_lock);
}

static void stats_note_rx(int port, bool valid) {
    pthread_mutex_lock(&g_stats_lock);
    g_stats.rx_frames++;
    if (valid)
        g_stats.rx_valid++;
    else
        g_stats.rx_dropped++;
    g_stats.last_rx = monotonic_seconds();
    pthread_mutex_unlock(&g_stats_lock);

    if (valid && port > 0 && port <= LLDP_PORT_LIMIT) {
        pthread_mutex_lock(&g_port_lock);
        g_ports[port].rx_frames++;
        g_ports[port].last_rx = monotonic_seconds();
        pthread_mutex_unlock(&g_port_lock);
    }
}

static void stats_note_tx(int port, bool ok) {
    pthread_mutex_lock(&g_stats_lock);
    if (ok) {
        g_stats.tx_frames++;
        g_stats.last_tx = monotonic_seconds();
    } else {
        g_stats.tx_failures++;
    }
    pthread_mutex_unlock(&g_stats_lock);

    if (port > 0 && port <= LLDP_PORT_LIMIT) {
        pthread_mutex_lock(&g_port_lock);
        if (ok) {
            g_ports[port].tx_frames++;
            g_ports[port].last_tx = monotonic_seconds();
        } else {
            g_ports[port].tx_failures++;
        }
        pthread_mutex_unlock(&g_port_lock);
    }
}

static void stats_note_aged_out(void) {
    pthread_mutex_lock(&g_stats_lock);
    g_stats.aged_out++;
    pthread_mutex_unlock(&g_stats_lock);
}

static void stats_note_packetd_reconnect(void) {
    pthread_mutex_lock(&g_stats_lock);
    g_stats.packetd_reconnects++;
    pthread_mutex_unlock(&g_stats_lock);
}

static void load_system_mac(u8 mac[6]) {
    memset(mac, 0, 6);
    if (!nl_platform_system_mac(mac))
        NL_LOG_WARN("LLDP system MAC is not configured in platform profile");
}

static void load_system_name(char *buf, size_t buf_size) {
    nl_platform_identity ident;

    if (!buf || buf_size == 0)
        return;
    if (nl_platform_identity_get(&ident) && ident.system_name[0]) {
        snprintf(buf, buf_size, "%s", ident.system_name);
        return;
    }
    if (gethostname(buf, buf_size) != 0 || !buf[0])
        snprintf(buf, buf_size, "netlab");
    buf[buf_size - 1] = '\0';
}

static int ifname_to_port(const char *ifname) {
    return nl_ifid_name_to_logical_port(ifname);
}

static void ifname_from_port(int port, char *buf, size_t buf_size) {
    if (!buf || buf_size == 0)
        return;
    if (!nl_ifid_logical_port_to_name(port, buf, buf_size))
        snprintf(buf, buf_size, "-");
}

static int lldp_profile_ports(int *ports, int max_ports) {
    nl_port_entry entries[NL_MAX_PORTS_PER_PROFILE];
    int n_entries = nl_ifid_get_all(entries, NL_MAX_PORTS_PER_PROFILE);
    int n = 0;

    if (!ports || max_ports <= 0)
        return 0;
    for (int i = 0; i < n_entries && n < max_ports; i++) {
        if (entries[i].logical_port > 0 &&
            nl_ifid_is_user_port(entries[i].logical_port) &&
            (entries[i].flags & NL_PORT_FLAG_LLDP_CAPABLE) &&
            entries[i].logical_port <= LLDP_PORT_LIMIT)
            ports[n++] = entries[i].logical_port;
    }
    return n;
}

static char *read_active_config(void) {
    char path[512];
    FILE *f;
    long n;
    char *buf;

    nl_config_file_path(path, sizeof(path), "active.conf");
    f = fopen(path, "r");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    n = ftell(f);
    if (n < 0 || n > 1024 * 1024) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = calloc(1, (size_t)n + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    return buf;
}

static void remove_neighbors_on_disabled_ports(bool enabled[LLDP_PORT_LIMIT + 1]) {
    pthread_mutex_lock(&g_nb_lock);
    for (int i = 0; i < 64; i++) {
        int port = g_neighbors[i].rx_port;
        if (g_neighbors[i].valid && port > 0 && port <= LLDP_PORT_LIMIT &&
            !enabled[port]) {
            g_neighbors[i].valid = false;
            stats_note_aged_out();
        }
    }
    pthread_mutex_unlock(&g_nb_lock);
}

static bool reload_lldp_config_work(bool force) {
    struct stat st;
    char active_path[512];
    time_t now = monotonic_seconds();
    time_t mtime = 0;
    long mtime_nsec = 0;
    char *xml;
    char *lldp;
    char *lldp_end;
    char *global_end;
    char *p;
    lldp_config cfg;
    bool enabled[LLDP_PORT_LIMIT + 1] = {false};
    int profile_ports[NL_MAX_PORTS_PER_PROFILE];
    int n_profile_ports = lldp_profile_ports(profile_ports,
                                             NL_MAX_PORTS_PER_PROFILE);

    config_defaults(&cfg);
    nl_config_file_path(active_path, sizeof(active_path), "active.conf");
    if (stat(active_path, &st) == 0) {
        mtime = st.st_mtime;
        mtime_nsec = st.st_mtim.tv_nsec;
    }

    pthread_mutex_lock(&g_port_lock);
    if (!force && now - g_last_config_check < LLDP_CONFIG_RELOAD_SEC) {
        pthread_mutex_unlock(&g_port_lock);
        return true;
    }
    g_last_config_check = now;
    if (!force && mtime == g_config_mtime &&
        mtime_nsec == g_config_mtime_nsec) {
        pthread_mutex_unlock(&g_port_lock);
        return true;
    }
    pthread_mutex_unlock(&g_port_lock);
    xml = read_active_config();
    if (!xml) return false;
    pthread_mutex_lock(&g_port_lock);
    g_config_mtime = mtime;
    g_config_mtime_nsec = mtime_nsec;
    g_config = cfg;
    for (int i = 0; i < n_profile_ports; ++i) {
        int port = profile_ports[i];
        g_ports[port].configured = false;
        g_ports[port].disabled = false;
        memset(&g_ports[port].dcbx, 0, sizeof(g_ports[port].dcbx));
        g_ports[port].dcbx_tx_frames = 0;
    }
    lldp = strstr(xml, "<lldp>");
    lldp_end = lldp ? strstr(lldp, "</lldp>") : NULL;
    if (lldp && lldp_end) {
        char value[256];
        global_end = strstr(lldp, "<interface>");
        if (!global_end || global_end > lldp_end)
            global_end = lldp_end;

        if (lldp_xml_leaf(lldp, global_end, "disable", value,
                          sizeof(value)) == 0)
            cfg.disabled = strcmp(value, "true") == 0;
        if (lldp_xml_leaf(lldp, global_end, "transmit-interval", value,
                          sizeof(value)) == 0)
            lldp_parse_int_text(value, 5, 3600, &cfg.tx_interval);
        if (lldp_xml_leaf(lldp, global_end, "hold-multiplier", value,
                          sizeof(value)) == 0)
            lldp_parse_int_text(value, 2, 10, &cfg.hold_multiplier);
        if (lldp_xml_leaf(lldp, global_end, "system-name", value,
                          sizeof(value)) == 0)
            lldp_xml_unescape(value, cfg.system_name,
                              sizeof(cfg.system_name));
        if (lldp_xml_leaf(lldp, global_end, "system-description", value,
                          sizeof(value)) == 0)
            lldp_xml_unescape(value, cfg.system_description,
                              sizeof(cfg.system_description));
        if (lldp_xml_leaf(lldp, global_end, "management-address", value,
                          sizeof(value)) == 0)
            lldp_parse_management_address_text(value, &cfg);

        p = lldp;
        g_config = cfg;
        while ((p = strstr(p, "<interface>")) && p < lldp_end) {
            char *end = strstr(p, "</interface>");
            char ifname[64] = {0};
            char disable[16] = {0};
            int port;

            if (!end || end > lldp_end)
                break;
            if (lldp_xml_leaf(p, end, "name", ifname,
                              sizeof(ifname)) != 0) {
                p = end + strlen("</interface>");
                continue;
            }
            port = ifname_to_port(ifname);
            if (port > 0) {
                lldp_xml_leaf(p, end, "disable", disable,
                              sizeof(disable));
                g_ports[port].configured = true;
                g_ports[port].disabled = strcmp(disable, "true") == 0;
                if (!dcbx_load_xml(p, end, &g_ports[port].dcbx))
                    g_ports[port].dcbx.malformed = true;
            }
            p = end + strlen("</interface>");
        }
    }
    for (int i = 0; i < n_profile_ports; i++) {
        int port = profile_ports[i];
        enabled[port] = port_enabled_locked(port);
    }
    pthread_mutex_unlock(&g_port_lock);
    remove_neighbors_on_disabled_ports(enabled);
    free(xml);
    bool valid = true;
    pthread_mutex_lock(&g_port_lock);
    for (int i = 0; i < n_profile_ports; i++)
        if (g_ports[profile_ports[i]].dcbx.malformed) valid = false;
    pthread_mutex_unlock(&g_port_lock);
    return valid;
}

static bool reload_lldp_config_if_needed(bool force) {
    static pthread_mutex_t reload_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&reload_lock);
    bool ok = reload_lldp_config_work(force);
    pthread_mutex_unlock(&reload_lock);
    return ok;
}

// ===== NEIGHBOR TABLE =====

// ===== SWITCHD IPC =====

static int switchd_call(nl_rpc_method method, u8 *payload, int plen,
                         u8 *resp, int resp_max) {
    s32 ec = 0;
    int n;

    if (!resp || resp_max <= 0)
        return -1;
    n = nl_rpc_call_ex(lldpd_switchd_socket_path(), NL_DAEMON_LLDPD,
                       NL_DAEMON_SWITCHD, method, 0,
                       payload, plen, resp, resp_max, 3000, &ec);
    if (n < 0 || ec != 0) {
        NL_LOG_ERR("switchd method %u returned error %d",
                   (unsigned)method, (int)ec);
        return -1;
    }
    return n;
}

static bool port_link_up(int port) {
    char buf[16];
    int n = snprintf(buf, sizeof(buf), "port=%d", port);
    u8 resp[128];
    int rn = switchd_call(NL_SWITCHD_PORT_GET_STATE,
                          (u8 *)buf, n, resp, sizeof(resp));
    if (rn <= 0) return false;
    resp[rn] = 0;
    return strstr((char *)resp, "link=UP") != NULL;
}

static nl_conn g_packetd_subscription = {.fd = -1};

static int read_packetd_record(
    nl_conn *conn, void *buffer, int expected) {
    if (expected <= 0)
        return -1;
    return nl_recv_peer_record(
               conn, buffer, (size_t)expected, MSG_TRUNC) == expected ?
        expected : -1;
}

static int packetd_tx(int port, const u8 *frame, int frame_len) {
    nl_conn conn;
    char header[32];
    u8 msg[2048];
    u8 resp[64];
    u32 net_len;
    int header_len;
    int msg_len;
    int resp_len;

    if (port <= 0 || !frame || frame_len <= 0)
        return -1;
    u64 issued_at = nl_port_scope_clock();
    if (nl_client_connect(lldpd_packetd_socket_path(), &conn) != NL_OK)
        return -1;

    header_len = snprintf(header, sizeof(header), "tx %d %016llx\n", port, (unsigned long long)issued_at);
    if (header_len <= 0 || header_len >= (int)sizeof(header) ||
        header_len + frame_len > (int)sizeof(msg)) {
        nl_client_close(&conn);
        return -1;
    }
    memcpy(msg, header, (size_t)header_len);
    memcpy(msg + header_len, frame, (size_t)frame_len);
    msg_len = header_len + frame_len;

    net_len = htonl((u32)msg_len);
    if (nl_send_record(&conn, &net_len, sizeof(net_len)) != NL_OK ||
        nl_send_record(&conn, msg, (size_t)msg_len) != NL_OK) {
        nl_client_close(&conn);
        return -1;
    }

    if (read_packetd_record(
            &conn, &net_len, sizeof(net_len)) !=
            (int)sizeof(net_len)) {
        nl_client_close(&conn);
        return -1;
    }
    resp_len = (int)ntohl(net_len);
    if (resp_len <= 0 || resp_len >= (int)sizeof(resp) ||
        read_packetd_record(&conn, resp, resp_len) != resp_len) {
        nl_client_close(&conn);
        return -1;
    }
    nl_client_close(&conn);
    return resp_len >= 3 && memcmp(resp, "ok\n", 3) == 0 ? 0 : -1;
}

static bool packetd_subscribe(u16 ethertype, nl_conn *conn) {
    if (!conn ||
        nl_client_connect(
            lldpd_packetd_socket_path(), conn) != NL_OK)
        return false;

    char sub[32];
    int len = snprintf(sub, sizeof(sub), "subscribe %04x", ethertype);
    u32 net_len = htonl((u32)len);
    if (nl_send_record(conn, &net_len, sizeof(net_len)) != NL_OK ||
        nl_send_record(conn, sub, (size_t)len) != NL_OK) {
        nl_client_close(conn);
        return false;
    }
    return true;
}

static int wait_readable(int fd, int timeout_sec) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    struct timeval tv = {timeout_sec, 0};
    int r;
    do {
        r = select(fd + 1, &rfds, NULL, NULL, &tv);
    } while (r < 0 && errno == EINTR && g_running);

    if (r < 0)
        return -1;
    return r > 0 ? 1 : 0;
}

static int lldp_rx_poll(u8 *buf, int max, int *rx_port, int *rx_vlan, u64 *captured_at) {
    u32 net_len;
    u8 event[2048 + NL_PACKET_EVENT_HEADER];

    if (g_packetd_subscription.fd < 0) {
        if (!packetd_subscribe(
                LLDP_ETHERTYPE, &g_packetd_subscription)) {
            stats_note_packetd_reconnect();
            lldpd_wait_seconds(1);
            return -1;
        }
    }

    int ready = wait_readable(
        g_packetd_subscription.fd, PACKETD_RX_IDLE_SEC);
    if (ready == 0)
        return 0;
    if (ready < 0) {
        NL_LOG_WARN("LLDP packetd subscription wait failed; reconnecting");
        nl_client_close(&g_packetd_subscription);
        stats_note_packetd_reconnect();
        return -1;
    }

    if (read_packetd_record(
            &g_packetd_subscription, &net_len, sizeof(net_len)) !=
            (int)sizeof(net_len)) {
        NL_LOG_WARN("LLDP packetd subscription lost; reconnecting");
        nl_client_close(&g_packetd_subscription);
        stats_note_packetd_reconnect();
        return -1;
    }
    u32 len = ntohl(net_len);
    if (len < 4U || len > sizeof(event)) {
        nl_client_close(&g_packetd_subscription);
        stats_note_packetd_reconnect();
        return -1;
    }
    if (read_packetd_record(
            &g_packetd_subscription, event, (size_t)len) != (int)len) {
        NL_LOG_WARN("LLDP packetd event read failed; reconnecting");
        nl_client_close(&g_packetd_subscription);
        stats_note_packetd_reconnect();
        return -1;
    }

    int port, vlan;
    u64 stamp;
    int header = nl_packet_event_decode(event, (int)len, &port, &vlan, &stamp);
    if (header < 0) return -1;
    if (rx_port) *rx_port = port;
    if (rx_vlan) *rx_vlan = vlan;
    if (captured_at) *captured_at = stamp;
    size_t frame_len = (size_t)len - (size_t)header;
    size_t max_len = max > 0 ? (size_t)max : 0U;
    if (frame_len > max_len) frame_len = max_len;
    memcpy(buf, event + header, frame_len);
    return (int)frame_len;
}

// ===== RX THREAD =====

static void *rx_thread(void *arg) {
    (void)arg;
    u8 buf[2048];
    while (g_running) {
        int drained = 0;
        reload_lldp_config_if_needed(false);
        while (drained < 32) {
            int rx_port = 0;
            u64 captured_at = 0;
            bool valid = false;
            int n = lldp_rx_poll(buf, sizeof(buf), &rx_port, NULL, &captured_at);
            if (n <= 0) break;
            drained++;
            if (!lldp_port_enabled(rx_port)) {
                stats_note_rx(rx_port, false);
                continue;
            }
            if (!nl_port_scope_packet_enter(rx_port, captured_at)) continue;
            if (n > 14) {
                u16 etype = (u16)((buf[12] << 8) | buf[13]);
                if (etype == LLDP_ETHERTYPE) {
                    lldp_neighbor nb;
                    lldp_parse_lldpdu(buf + 14, n - 14, &nb, rx_port);

                    if (nb.valid) {
                        pthread_mutex_lock(&g_nb_lock);
                        lldp_neighbor_store(g_neighbors, &g_n_neighbors, &nb, monotonic_seconds(), time(NULL));
                        pthread_mutex_unlock(&g_nb_lock);
                        NL_LOG_DBG("LLDP rx: port=%.*s from %.*s",
                                    nb.port_id_len > 0 ? nb.port_id_len : 1,
                                    nb.port_id_len > 0 ? (char*)nb.port_id : "?",
                                    nb.sys_name_len > 0 ? nb.sys_name_len : 1,
                                    nb.sys_name_len > 0 ? (char*)nb.sys_name : "?");
                        valid = true;
                    }
                }
            }
            stats_note_rx(rx_port, valid);
            nl_port_scope_leave(rx_port);
        }
        lldpd_wait_seconds(2);
    }
    nl_client_close(&g_packetd_subscription);
    return NULL;
}

// ===== TX THREAD =====

static void *tx_thread(void *arg) {
    (void)arg;
    int retry = 5;
    while (g_running) {
        u8 lldpdu[1500];
        u8 frame[1536];
        u8 chassis_mac[6];
        char sys_name[64];
        int total_ok = 0;
        lldp_config cfg;
        int profile_ports[NL_MAX_PORTS_PER_PROFILE];
        int n_profile_ports;

        load_system_mac(chassis_mac);
        load_system_name(sys_name, sizeof(sys_name));

        reload_lldp_config_if_needed(false);
        lldp_config_snapshot(&cfg);
        if (!cfg.system_name[0])
            snprintf(cfg.system_name, sizeof(cfg.system_name), "%s", sys_name);
        if (cfg.disabled) {
            lldpd_wait_seconds(LLDP_CONFIG_RELOAD_SEC);
            retry = 5;
            continue;
        }

        n_profile_ports = lldp_profile_ports(profile_ports,
                                             NL_MAX_PORTS_PER_PROFILE);
        for (int i = 0; i < n_profile_ports; i++) {
            int p = profile_ports[i];
            if (!lldp_port_enabled(p))
                continue;
            if (!nl_port_scope_enter(p)) continue;
            if (!port_link_up(p)) {
                NL_LOG_DBG("LLDP TX port=%d skipped (link not UP)", p);
                nl_port_scope_leave(p);
                continue;
            }
            char port_id_str[32];
            ifname_from_port(p, port_id_str, sizeof(port_id_str));
            pthread_mutex_lock(&g_port_lock);
            cfg.dcbx = g_ports[p].dcbx;
            pthread_mutex_unlock(&g_port_lock);

            int len = lldp_build_lldpdu(lldpdu, sizeof(lldpdu),
                                        chassis_mac,
                                        port_id_str,
                                        &cfg,
                                        p);
            if (len <= 0 || len + 14 > (int)sizeof(frame)) {
                NL_LOG_WARN("LLDP build failed port=%d", p);
                stats_note_tx(p, false);
                nl_port_scope_leave(p);
                continue;
            }
            memset(frame, 0, 14);
            memcpy(frame, LLDP_DST_MAC, 6);
            memcpy(frame + 6, chassis_mac, 6);
            frame[12] = 0x88; frame[13] = 0xCC;
            memcpy(frame + 14, lldpdu, len);

            int st = packetd_tx(p, frame, len + 14);
            if (st == 0) {
                total_ok++;
                stats_note_tx(p, true);
                pthread_mutex_lock(&g_port_lock);
                if (cfg.dcbx.enabled && !memcmp(&cfg.dcbx, &g_ports[p].dcbx, sizeof(cfg.dcbx)))
                    g_ports[p].dcbx_tx_frames++;
                pthread_mutex_unlock(&g_port_lock);
                NL_LOG_DBG("LLDP TX port=%d (%s)", p, port_id_str);
            } else {
                NL_LOG_WARN("LLDP TX port=%d FAIL", p);
                stats_note_tx(p, false);
            }
            nl_port_scope_leave(p);
        }

        if (total_ok == 0) {
            NL_LOG_DBG("LLDP TX no ports ready, retry in %ds", retry);
            lldpd_wait_seconds(retry);
            retry = (retry < 30) ? retry + 5 : 30;
        } else {
            NL_LOG_DBG("LLDP TX OK (%d ports)", total_ok);
            lldpd_wait_seconds(cfg.tx_interval);
            retry = 5;
        }
    }
    return NULL;
}

// ===== AGING THREAD =====

static void *aging_thread(void *arg) {
    (void)arg;
    while (g_running) {
        time_t now = monotonic_seconds();
        pthread_mutex_lock(&g_nb_lock);
        for (int i = 0; i < 64; i++) {
            int port = g_neighbors[i].rx_port;
            if (!nl_port_scope_enter(port)) continue;
            if (g_neighbors[i].valid && !lldp_neighbor_current(&g_neighbors[i], now)) {
                NL_LOG_INFO("LLDP neighbor aged out (chassis_id_len=%d)",
                            g_neighbors[i].chassis_id_len);
                g_neighbors[i].valid = false;
                stats_note_aged_out();
            }
            nl_port_scope_leave(port);
        }
        pthread_mutex_unlock(&g_nb_lock);
        lldpd_wait_seconds(10);
    }
    return NULL;
}

// ===== IPC FOR CLI =====

static bool append_cli_text(char *buf, size_t size, size_t *off,
                            const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !off || !fmt || *off >= size)
        return false;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, size - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= size - *off) {
        buf[*off] = '\0';
        return false;
    }
    *off += (size_t)n;
    return true;
}

static void handle_cli_get_neighbors_common(nl_conn *conn, nl_msg_hdr *msg,
                                            bool detail) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    size_t off = 0;
    bool ok;
    time_t now = monotonic_seconds();

    if (!buf) {
        nl_send_response(conn, msg->request_id, NL_ERR);
        return;
    }
    ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                         "<lldp-neighbors detail=\"%s\">\n",
                         detail ? "true" : "false");
    pthread_mutex_lock(&g_nb_lock);
    for (int i = 0; ok && i < 64; i++) {
        if (!lldp_neighbor_current(&g_neighbors[i], now)) continue;
        char cid[128];
        char port_id[128];
        char port_desc[192];
        char sys_name[128];
        char sys_desc[256];
        char caps_supported[128];
        char caps_enabled[128];
        char esc_cid[256];
        char esc_port[256];
        char esc_port_desc[384];
        char esc_sys_name[256];
        char esc_sys_desc[512];
        char esc_mgmt[128];
        char local_if[32] = "-";
        int age = (int)(now - g_neighbors[i].monotonic_seen);
        int ttl = g_neighbors[i].ttl ? g_neighbors[i].ttl : 120;
        int remaining = age >= 0 && ttl > age ? ttl - age : 0;
        if (g_neighbors[i].rx_port > 0)
            ifname_from_port(g_neighbors[i].rx_port, local_if,
                             sizeof(local_if));
        lldp_fmt_chassis_id(cid, sizeof(cid),
                            g_neighbors[i].chassis_id,
                            g_neighbors[i].chassis_id_len,
                            g_neighbors[i].chassis_subtype);
        lldp_fmt_bytes(port_id, sizeof(port_id),
                       g_neighbors[i].port_id,
                       g_neighbors[i].port_id_len);
        lldp_fmt_string(port_desc, sizeof(port_desc),
                        g_neighbors[i].port_desc,
                        g_neighbors[i].port_desc_len);
        lldp_fmt_string(sys_name, sizeof(sys_name),
                        g_neighbors[i].sys_name,
                        g_neighbors[i].sys_name_len);
        lldp_fmt_string(sys_desc, sizeof(sys_desc),
                        g_neighbors[i].sys_desc,
                        g_neighbors[i].sys_desc_len);
        lldp_fmt_caps(caps_supported, sizeof(caps_supported),
                      g_neighbors[i].caps_supported);
        lldp_fmt_caps(caps_enabled, sizeof(caps_enabled),
                      g_neighbors[i].caps_enabled);
        lldp_xml_escape(cid, esc_cid, sizeof(esc_cid));
        lldp_xml_escape(port_id, esc_port, sizeof(esc_port));
        lldp_xml_escape(port_desc, esc_port_desc, sizeof(esc_port_desc));
        lldp_xml_escape(sys_name, esc_sys_name, sizeof(esc_sys_name));
        lldp_xml_escape(sys_desc, esc_sys_desc, sizeof(esc_sys_desc));
        lldp_xml_escape(g_neighbors[i].mgmt_addr, esc_mgmt,
                        sizeof(esc_mgmt));
        ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
            "  <neighbor>\n"
            "    <local-interface>%s</local-interface>\n"
            "    <chassis-id>%s</chassis-id>\n"
            "    <chassis-id-subtype>%s</chassis-id-subtype>\n"
            "    <port-id>%s</port-id>\n"
            "    <port-id-subtype>%s</port-id-subtype>\n"
            "    <sys-name>%s</sys-name>\n"
            "    <age>%d</age>\n"
            "    <ttl>%d</ttl>\n"
            "    <time-remaining>%d</time-remaining>\n",
            local_if, esc_cid,
            lldp_chassis_subtype_name(g_neighbors[i].chassis_subtype),
            esc_port,
            lldp_port_subtype_name(g_neighbors[i].port_subtype),
            esc_sys_name,
            age, ttl, remaining);
        if (detail) {
            ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                "    <port-description>%s</port-description>\n"
                "    <sys-description>%s</sys-description>\n"
                "    <system-capabilities>%s</system-capabilities>\n"
                "    <enabled-capabilities>%s</enabled-capabilities>\n"
                "    <management-address>%s</management-address>\n",
                esc_port_desc, esc_sys_desc,
                caps_supported, caps_enabled, esc_mgmt);
        }
        if (ok)
            ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                                 "  </neighbor>\n");
    }
    pthread_mutex_unlock(&g_nb_lock);
    if (ok)
        ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                             "</lldp-neighbors>\n");

    if (!ok) {
        free(buf);
        nl_send_response(conn, msg->request_id,
                         NL_ERR_CAPABILITY_INSUFFICIENT);
        return;
    }

    nl_msg_hdr *resp = nl_msg_alloc((u32)off);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)off;
        memcpy(resp->payload, buf, (size_t)off);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    free(buf);
}

static void handle_cli_get_neighbors(nl_conn *conn, nl_msg_hdr *msg) {
    handle_cli_get_neighbors_common(conn, msg, false);
}

static void handle_cli_get_neighbors_detail(nl_conn *conn, nl_msg_hdr *msg) {
    handle_cli_get_neighbors_common(conn, msg, true);
}

static void handle_cli_get_statistics(nl_conn *conn, nl_msg_hdr *msg) {
    char buf[1024];
    int neighbors = 0;
    int off;
    time_t now = monotonic_seconds();
    lldp_stats stats;
    lldp_config cfg;

    pthread_mutex_lock(&g_nb_lock);
    for (int i = 0; i < 64; i++)
        if (lldp_neighbor_current(&g_neighbors[i], now))
            neighbors++;
    pthread_mutex_unlock(&g_nb_lock);

    pthread_mutex_lock(&g_stats_lock);
    stats = g_stats;
    pthread_mutex_unlock(&g_stats_lock);
    lldp_config_snapshot(&cfg);

    off = snprintf(buf, sizeof(buf),
        "<lldp-statistics neighbors=\"%d\" tx-frames=\"%llu\" "
        "tx-failures=\"%llu\" rx-frames=\"%llu\" rx-valid=\"%llu\" "
        "rx-dropped=\"%llu\" aged-out=\"%llu\" "
        "packetd-reconnects=\"%llu\" last-rx-age=\"%d\" "
        "last-tx-age=\"%d\" tx-interval=\"%d\" "
        "hold-multiplier=\"%d\" ttl=\"%d\" disabled=\"%s\"/>\n",
        neighbors,
        (unsigned long long)stats.tx_frames,
        (unsigned long long)stats.tx_failures,
        (unsigned long long)stats.rx_frames,
        (unsigned long long)stats.rx_valid,
        (unsigned long long)stats.rx_dropped,
        (unsigned long long)stats.aged_out,
        (unsigned long long)stats.packetd_reconnects,
        stats.last_rx ? (int)(now - stats.last_rx) : -1,
        stats.last_tx ? (int)(now - stats.last_tx) : -1,
        cfg.tx_interval,
        cfg.hold_multiplier,
        lldp_config_ttl(&cfg),
        cfg.disabled ? "true" : "false");
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(buf)) {
        nl_send_response(conn, msg->request_id,
                         NL_ERR_CAPABILITY_INSUFFICIENT);
        return;
    }

    nl_msg_hdr *resp = nl_msg_alloc((u32)off);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)off;
        memcpy(resp->payload, buf, (size_t)off);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
}

static int count_neighbors_on_port(int port) {
    int count = 0;
    time_t now = monotonic_seconds();

    pthread_mutex_lock(&g_nb_lock);
    for (int i = 0; i < 64; i++) {
        if (lldp_neighbor_current(&g_neighbors[i], now) && g_neighbors[i].rx_port == port)
            count++;
    }
    pthread_mutex_unlock(&g_nb_lock);
    return count;
}

static void handle_cli_get_interfaces(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    size_t off = 0;
    bool ok;
    time_t now = monotonic_seconds();
    lldp_port_state ports[LLDP_PORT_LIMIT + 1];
    bool enabled[LLDP_PORT_LIMIT + 1] = {false};
    int profile_ports[NL_MAX_PORTS_PER_PROFILE];
    int n_profile_ports = lldp_profile_ports(profile_ports,
                                             NL_MAX_PORTS_PER_PROFILE);

    if (!buf) {
        nl_send_response(conn, msg->request_id, NL_ERR);
        return;
    }

    reload_lldp_config_if_needed(false);

    pthread_mutex_lock(&g_port_lock);
    memcpy(ports, g_ports, sizeof(ports));
    for (int i = 0; i < n_profile_ports; i++) {
        int port = profile_ports[i];
        enabled[port] = port_enabled_locked(port);
    }
    pthread_mutex_unlock(&g_port_lock);

    ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                         "<lldp-interfaces>\n");
    for (int i = 0; ok && i < n_profile_ports; i++) {
        int port = profile_ports[i];
        char ifname[32];
        bool link_up = port_link_up(port);
        int neighbors = count_neighbors_on_port(port);
        ifname_from_port(port, ifname, sizeof(ifname));
        ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
            "  <interface name=\"%s\" admin=\"%s\" configured=\"%s\" "
            "link=\"%s\" neighbors=\"%d\" rx-frames=\"%llu\" "
            "tx-frames=\"%llu\" tx-failures=\"%llu\" "
            "last-rx-age=\"%d\" last-tx-age=\"%d\"/>\n",
            ifname,
            enabled[port] ? "enabled" : "disabled",
            ports[port].configured ? "true" : "false",
            link_up ? "up" : "down",
            neighbors,
            (unsigned long long)ports[port].rx_frames,
            (unsigned long long)ports[port].tx_frames,
            (unsigned long long)ports[port].tx_failures,
            ports[port].last_rx ? (int)(now - ports[port].last_rx) : -1,
            ports[port].last_tx ? (int)(now - ports[port].last_tx) : -1);
    }
    if (ok)
        ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                             "</lldp-interfaces>\n");

    if (!ok) {
        free(buf);
        nl_send_response(conn, msg->request_id,
                         NL_ERR_CAPABILITY_INSUFFICIENT);
        return;
    }

    nl_msg_hdr *resp = nl_msg_alloc((u32)off);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)off;
        memcpy(resp->payload, buf, (size_t)off);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    free(buf);
}

static void handle_cli_get_local(nl_conn *conn, nl_msg_hdr *msg) {
    char buf[2048];
    char sys_name[128];
    char sys_desc[384];
    char mgmt[128];
    int off;
    lldp_config cfg;

    reload_lldp_config_if_needed(false);
    lldp_config_snapshot(&cfg);
    lldp_xml_escape(cfg.system_name, sys_name, sizeof(sys_name));
    lldp_xml_escape(cfg.system_description, sys_desc, sizeof(sys_desc));
    lldp_xml_escape(cfg.mgmt_addr_text, mgmt, sizeof(mgmt));

    off = snprintf(buf, sizeof(buf),
        "<lldp-local disabled=\"%s\" tx-interval=\"%d\" "
        "hold-multiplier=\"%d\" ttl=\"%d\" system-name=\"%s\" "
        "system-description=\"%s\" management-address=\"%s\"/>\n",
        cfg.disabled ? "true" : "false",
        cfg.tx_interval,
        cfg.hold_multiplier,
        lldp_config_ttl(&cfg),
        sys_name,
        sys_desc,
        mgmt);
    if (off < 0)
        off = 0;
    if (off >= (int)sizeof(buf)) {
        nl_send_response(conn, msg->request_id,
                         NL_ERR_CAPABILITY_INSUFFICIENT);
        return;
    }

    nl_msg_hdr *resp = nl_msg_alloc((u32)off);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)off;
        memcpy(resp->payload, buf, (size_t)off);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
}

static void send_text_response(nl_conn *conn, nl_msg_hdr *msg,
                               s32 error_code, const char *text) {
    size_t len = text ? strlen(text) : 0;
    nl_msg_hdr *resp = nl_msg_alloc((u32)len);

    if (!resp)
        return;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)len;
    if (len > 0)
        memcpy(resp->payload, text, len);
    nl_send(conn, resp);
    nl_msg_free(resp);
}

static void handle_dcbx(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    size_t off = 0;
    if (!buf) { nl_send_response(conn, msg->request_id, NL_ERR_CAPABILITY_INSUFFICIENT); return; }
    bool ok = append_cli_text(buf, NETLAB_MAX_MSG, &off, "<dcbx mode=\"ieee-local\" peer-policy-applied=\"false\">");
    int ports[NL_MAX_PORTS_PER_PROFILE];
    int count = lldp_profile_ports(ports, NL_MAX_PORTS_PER_PROFILE);
    time_t now = monotonic_seconds();
    for (int i = 0; ok && i < count; i++) {
        int port = ports[i];
        pthread_mutex_lock(&g_port_lock);
        dcbx_state local = g_ports[port].dcbx;
        bool lldp_enabled = port_enabled_locked(port);
        u64 frames = g_ports[port].dcbx_tx_frames;
        pthread_mutex_unlock(&g_port_lock);
        if (!local.enabled && !local.malformed) continue;
        char text[4096];
        if (dcbx_format_xml(text, sizeof(text), "local", &local) < 0) { ok = false; break; }
        ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
            "<interface port=\"%d\" lldp-enabled=\"%s\" tx-frames=\"%llu\">%s", port,
            lldp_enabled?"true":"false", (unsigned long long)frames, text);
        pthread_mutex_lock(&g_nb_lock);
        for (int n = 0; ok && n < g_n_neighbors; n++) {
            const lldp_neighbor *peer = &g_neighbors[n];
            time_t age = now - peer->monotonic_seen;
            if (peer->rx_port != port || !lldp_neighbor_current(peer, now)) continue;
            if (dcbx_format_xml(text, sizeof(text), "remote", &peer->dcbx) < 0) { ok = false; break; }
            char name[65] = {0}, escaped[400];
            lldp_fmt_string(name, sizeof(name), peer->sys_name, peer->sys_name_len);
            lldp_xml_escape(name, escaped, sizeof(escaped));
            ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                "<peer state=\"%s\" age-seconds=\"%ld\" ttl=\"%u\" system-name=\"%s\">%s</peer>",
                dcbx_compare(&local, &peer->dcbx), (long)age, peer->ttl, escaped, text);
        }
        pthread_mutex_unlock(&g_nb_lock);
        if (ok) ok = append_cli_text(buf, NETLAB_MAX_MSG, &off, "</interface>");
    }
    if (ok) ok = append_cli_text(buf, NETLAB_MAX_MSG, &off, "</dcbx>");
    send_text_response(conn, msg, ok ? NL_OK : NL_ERR_CAPABILITY_INSUFFICIENT, ok ? buf : "DCBX snapshot exceeds response capacity");
    free(buf);
}

static int lldpd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    (void)ctx;

    switch (msg->method) {
    case NL_LLDPD_SHOW_NEIGHBORS:
        handle_cli_get_neighbors(conn, msg);
        return NL_OK;
    case NL_LLDPD_SHOW_STATISTICS:
        handle_cli_get_statistics(conn, msg);
        return NL_OK;
    case NL_LLDPD_SHOW_INTERFACES:
        handle_cli_get_interfaces(conn, msg);
        return NL_OK;
    case NL_LLDPD_SHOW_NEIGHBOR_DETAIL:
        handle_cli_get_neighbors_detail(conn, msg);
        return NL_OK;
    case NL_LLDPD_SHOW_LOCAL:
        handle_cli_get_local(conn, msg);
        return NL_OK;
    case NL_LLDPD_SHOW_DCBX:
        handle_dcbx(conn, msg);
        return NL_OK;
    case NL_LLDPD_RELOAD: {
        bool ok = reload_lldp_config_if_needed(true);
        send_text_response(conn, msg, ok ? NL_OK : NL_ERR_HW_STATE_OUT_OF_SYNC,
                            ok ? "lldpd reload complete" : "lldpd reload failed");
        return NL_OK;
    }
    default:
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        return NL_OK;
    }
}

static void lldpd_join_threads(void) {
    if (g_runtime.rx_thread_started) {
        pthread_join(g_runtime.rx_thread, NULL);
        g_runtime.rx_thread_started = false;
    }
    if (g_runtime.tx_thread_started) {
        pthread_join(g_runtime.tx_thread, NULL);
        g_runtime.tx_thread_started = false;
    }
    if (g_runtime.aging_thread_started) {
        pthread_join(g_runtime.aging_thread, NULL);
        g_runtime.aging_thread_started = false;
    }
}

static void lldpd_destroy_locks(void) {
    if (g_runtime.port_lock_initialized) {
        pthread_mutex_destroy(&g_port_lock);
        g_runtime.port_lock_initialized = false;
    }
    if (g_runtime.stats_lock_initialized) {
        pthread_mutex_destroy(&g_stats_lock);
        g_runtime.stats_lock_initialized = false;
    }
    if (g_runtime.nb_lock_initialized) {
        pthread_mutex_destroy(&g_nb_lock);
        g_runtime.nb_lock_initialized = false;
    }
}

static int lldpd_on_init(void *ctx) {
    (void)ctx;

    memset(&g_runtime, 0, sizeof(g_runtime));
    memset(g_neighbors, 0, sizeof(g_neighbors));
    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_ports, 0, sizeof(g_ports));
    memset(&g_config, 0, sizeof(g_config));
    g_n_neighbors = 0;
    g_last_config_check = 0;
    g_config_mtime = 0;
    g_config_mtime_nsec = 0;
    g_running = 1;
    /* LLDP/DCBX TTL is elapsed time since reception, including a maintenance
     * pause. Never extend a peer's lease using a wall-clock correction. */
    nl_port_scope_on_resume(NULL);

    if (pthread_mutex_init(&g_nb_lock, NULL) != 0) {
        NL_LOG_CRIT("failed to initialize LLDP neighbor lock");
        return -1;
    }
    g_runtime.nb_lock_initialized = true;
    if (pthread_mutex_init(&g_stats_lock, NULL) != 0) {
        NL_LOG_CRIT("failed to initialize LLDP statistics lock");
        lldpd_destroy_locks();
        return -1;
    }
    g_runtime.stats_lock_initialized = true;
    if (pthread_mutex_init(&g_port_lock, NULL) != 0) {
        NL_LOG_CRIT("failed to initialize LLDP port lock");
        lldpd_destroy_locks();
        return -1;
    }
    g_runtime.port_lock_initialized = true;

    reload_lldp_config_if_needed(true);
    if (pthread_create(&g_runtime.rx_thread, NULL, rx_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create LLDP receive thread");
        lldpd_destroy_locks();
        return -1;
    }
    g_runtime.rx_thread_started = true;
    if (pthread_create(&g_runtime.tx_thread, NULL, tx_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create LLDP transmit thread");
        g_running = 0;
        lldpd_join_threads();
        lldpd_destroy_locks();
        return -1;
    }
    g_runtime.tx_thread_started = true;
    if (pthread_create(&g_runtime.aging_thread, NULL,
                       aging_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create LLDP aging thread");
        g_running = 0;
        lldpd_join_threads();
        lldpd_destroy_locks();
        return -1;
    }
    g_runtime.aging_thread_started = true;

    NL_LOG_NOTICE("lldpd ready");
    return NL_OK;
}

static void lldpd_on_shutdown(void *ctx) {
    (void)ctx;

    g_running = 0;
    lldpd_join_threads();
    lldpd_destroy_locks();
}

// ===== MAIN =====

int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name = "lldpd",
        .socket_path = lldpd_socket_path(),
        .service_id = NL_DAEMON_LLDPD,
        .auth_mode = NL_DAEMON_AUTH_STANDARD,
        .dispatch = lldpd_dispatch,
        .ctx = NULL,
        .on_init = lldpd_on_init,
        .on_shutdown = lldpd_on_shutdown,
    };

    (void)argc;
    (void)argv;
    return nl_daemon_run(&cfg);
}
