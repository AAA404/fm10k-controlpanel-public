/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "lacp_config.h"
#include "lacp_packet_io.h"
#include "lacp_wire.h"
#include "netlab/daemon.h"
#include "netlab/error.h"
#include "netlab/ipc.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include "netlab/journal.h"
#include "netlab/hal.h"
#include "netlab/port_scope.h"
#include "netlab/lag_readback.h"
#include "netlab/l2_plan_build.h"
#include "netlab/monotonic.h"
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define LACPD_SOCKET   "/var/run/netlab/lacpd.sock"
#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
#define PACKETD_SOCKET "/var/run/netlab/packetd.sock"

#define LACP_DEFAULT_TTL_SEC 90
#define LACP_FAST_TTL_SEC 3
#define LACP_FAST_TX_SEC 1
#define LACP_SLOW_TX_SEC 30
#define PACKETD_RX_IDLE_SEC 5

typedef struct {
    bool configured;
    char ifname[32];
    int  port;
    char mode[16];
    u16  port_priority;

    bool partner_valid;
    lacp_info partner;
    lacp_info partner_view_of_us;
    time_t last_rx;
    time_t last_tx;
    bool link_up;
    bool hw_attached;
    u64 rx_pdus;
    u64 tx_pdus;
} lacp_member;

typedef struct {
    bool configured;
    char ifname[16];
    char mode[16];
    char periodic[8];
    int ae_id;
    lacp_member members[NETLAB_MAX_LAG_MEMBERS];
    int n_members;
    int min_links;
    u16 actor_key;
    int tx_interval_sec;
    int ttl_sec;
    int lag_id;
    int logical_port;
    time_t last_config_load;
    time_t last_hw_poll;
} lacp_lag;

typedef struct {
    lacp_lag lags[NETLAB_MAX_AE];
    u8  actor_mac[6];
    u16 system_priority;
    u16 port_priority;
    time_t config_mtime;
    long config_mtime_nsec;
    bool native_required;
    bool native_hw_valid;
    u64 native_generation;
    u64 native_epoch_started;
    pthread_mutex_t lock;
} lacpd_state;

typedef struct {
    int ae_id;
    int port;
} lacp_member_ref;

typedef struct {
    bool send_pdu;
    u8 frame[128];
    int frame_len;
    bool change_hw;
    bool desired_hw;
    int lag_id;
    u64 native_generation;
    char lag_ifname[16];
    char member_ifname[32];
} lacp_member_action;

static lacpd_state g_lacp;
static volatile sig_atomic_t g_running = 1;

static u8 g_actor_mac[6] = {0};

typedef struct {
    pthread_t rx_thread;
    pthread_t tx_thread;
    bool rx_thread_started;
    bool tx_thread_started;
    bool lock_initialized;
} lacpd_runtime;

static lacpd_runtime g_runtime;

static const char *lacpd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_LACPD_SOCKET", LACPD_SOCKET);
}

static const char *lacpd_switchd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET",
                                       SWITCHD_SOCKET);
}

static const char *lacpd_packetd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_PACKETD_SOCKET",
                                       PACKETD_SOCKET);
}

static int lacp_profile_int(int value, int fallback) {
    return value > 0 ? value : fallback;
}

static int lacp_max_ae(void) {
    int n = nl_platform_max_ae();
    if (n <= 0)
        return 0;
    if (n > NETLAB_MAX_AE)
        return NETLAB_MAX_AE;
    return n;
}

static int lacp_ttl_sec(void) {
    nl_platform_identity ident;
    if (nl_platform_identity_get(&ident))
        return lacp_profile_int(ident.lacp_ttl_sec,
                                LACP_DEFAULT_TTL_SEC);
    return LACP_DEFAULT_TTL_SEC;
}

static u16 lacp_default_system_priority(void) {
    nl_platform_identity ident;
    if (nl_platform_identity_get(&ident))
        return (u16)lacp_profile_int(ident.lacp_system_priority, 0x8000);
    return 0x8000;
}

static u16 lacp_default_port_priority(void) {
    nl_platform_identity ident;
    if (nl_platform_identity_get(&ident))
        return (u16)lacp_profile_int(ident.lacp_port_priority, 0x8000);
    return 0x8000;
}

static void load_system_mac(u8 mac[6]) {
    if (!nl_platform_system_mac(mac))
        NL_LOG_WARN("LACP actor MAC is not configured in platform profile");
}

static bool switchd_method_needs_tx(nl_rpc_method method) {
    return method == NL_SWITCHD_LAG_ADD_PORT ||
           method == NL_SWITCHD_LAG_DEL_PORT;
}

static u64 lacp_runtime_tx_id(nl_rpc_method method) {
    static u64 seq;

    seq++;
    return 0x4c41435000000000ULL |
           (((u64)time(NULL) & 0x00ffffffULL) << 16) |
           ((u64)(method & 0xff) << 8) |
           (seq & 0xff);
}

static int sw_call(nl_rpc_method method, const u8 *payload, int plen,
                   u8 *resp, int resp_max) {
    s32 error_code = 0;
    u64 tx_id = switchd_method_needs_tx(method) ?
        lacp_runtime_tx_id(method) : 0;
    int rn;

    if (!resp || resp_max <= 0)
        return -1;
    rn = nl_rpc_call_ex(lacpd_switchd_socket_path(), NL_DAEMON_LACPD,
                        NL_DAEMON_SWITCHD, method, tx_id,
                        payload, plen, resp, resp_max, 3000, &error_code);
    if (rn < 0 || error_code != 0)
        return -1;
    if (rn >= resp_max)
        rn = resp_max - 1;
    return rn;
}

static int ifname_to_port(const char *ifname) {
    return nl_ifid_name_to_logical_port(ifname);
}

static int ae_id_from_name(const char *name) {
    char *end = NULL;
    long id;

    if (!name || name[0] != 'a' || name[1] != 'e' || name[2] == '\0')
        return -1;
    id = strtol(name + 2, &end, 10);
    if (!end || *end || id < 0 || id >= lacp_max_ae())
        return -1;
    return (int)id;
}

static void init_lag_defaults(lacp_lag *lag, int ae_id) {
    memset(lag, 0, sizeof(*lag));
    lag->ae_id = ae_id;
    lag->min_links = 1;
    lag->tx_interval_sec = LACP_SLOW_TX_SEC;
    lag->ttl_sec = lacp_ttl_sec();
    snprintf(lag->ifname, sizeof(lag->ifname), "ae%d", ae_id);
    snprintf(lag->mode, sizeof(lag->mode), "active");
    snprintf(lag->periodic, sizeof(lag->periodic), "slow");
}

static bool port_link_up(int port) {
    char payload[32];
    u8 resp[128];
    int len = snprintf(payload, sizeof(payload), "port=%d", port);
    int rn = sw_call(NL_SWITCHD_PORT_GET_STATE,
                     (const u8 *)payload, len, resp, sizeof(resp) - 1);
    if (rn <= 0)
        return false;
    if (rn >= (int)sizeof(resp))
        rn = (int)sizeof(resp) - 1;
    resp[rn] = 0;
    return strstr((char *)resp, "link=UP") != NULL;
}

static bool same_member_settings(const lacp_lag *before, const lacp_lag *after, bool dynamic) {
    if (before->n_members != after->n_members) return false;
    for (int i = 0; i < before->n_members; ++i) {
        bool found = false;
        for (int j = 0; j < after->n_members; ++j)
            if (before->members[i].port == after->members[j].port &&
                (!dynamic || before->members[i].port_priority == after->members[j].port_priority)) {
                found = true;
                break;
            }
        if (!found) return false;
    }
    return true;
}

static bool load_config_locked(bool force) {
    nl_platform_identity identity;
    nl_board_profile board;
    g_lacp.native_required = g_lacp.native_required ||
        (nl_platform_identity_get(&identity) && nl_fm10k_profile_known(identity.chassis_name)) ||
        (nl_platform_board_get(&board) && !strcmp(board.asic, "FM10840"));
    struct stat st;
    time_t mtime = 0;
    long mtime_nsec = 0;
    char config_path[512];

    nl_config_file_path(config_path, sizeof(config_path), "active.conf");
    if (stat(config_path, &st) == 0) {
        mtime = st.st_mtime;
        mtime_nsec = st.st_mtim.tv_nsec;
    }
    if (!force && mtime == g_lacp.config_mtime &&
        mtime_nsec == g_lacp.config_mtime_nsec)
        return true;

    FILE *f = fopen(config_path, "r");
    if (!f) return false;

    /* The panel's fixed port/VLAN configuration already exceeds 64 KiB
     * after a breakout. Read the opened inode at the configd size limit;
     * never publish a truncated or concurrently modified configuration. */
    struct stat opened;
    if (fstat(fileno(f), &opened) || opened.st_size <= 0 ||
        (uintmax_t)opened.st_size > NL_L2_PLAN_CONFIG_MAX_BYTES) {
        fclose(f);
        NL_LOG_ERR("LACP active configuration size is invalid");
        return false;
    }
    size_t size = (size_t)opened.st_size;
    char *xml = malloc(size + 1);
    if (!xml) { fclose(f); return false; }
    size_t n = fread(xml, 1, size, f);
    bool complete = n == size && fgetc(f) == EOF && !ferror(f);
    fclose(f);
    if (!complete || memchr(xml, '\0', n)) { free(xml); return false; }
    xml[n] = '\0';
    mtime = opened.st_mtime;
    mtime_nsec = opened.st_mtim.tv_nsec;

    lacp_lag *next;
    char *interfaces = NULL;
    char *interfaces_end = NULL;

    next = calloc(NETLAB_MAX_AE, sizeof(*next));
    if (!next) {
        NL_LOG_ERR("LACP config reload workspace allocation failed");
        free(xml);
        return false;
    }
    for (int i = 0; i < lacp_max_ae(); i++)
        init_lag_defaults(&next[i], i);
    u16 system_priority = lacp_default_system_priority();
    u16 port_priority = lacp_default_port_priority();
    u8 actor_mac[6];
    memcpy(actor_mac, g_actor_mac, sizeof(actor_mac));
    lacp_config_extract_global(xml, &system_priority, &port_priority,
                               actor_mac);
    if (!lacp_xml_find_container(xml, "interfaces", &interfaces, &interfaces_end))
        interfaces = interfaces_end = NULL;

    char *p = interfaces;
    while (p && p < interfaces_end && (p = strstr(p, "<interface>"))) {
        char *end = strstr(p, "</interface>");
        char name[32] = {0};
        char mode[16] = {0};
        char min_links[16] = {0};
        char periodic[8] = {0};
        u16 actor_key = 0;
        int ae_id;
        if (!end || end > interfaces_end) break;
        if (lacp_xml_leaf(p, end, "name", name, sizeof(name)) &&
            (ae_id = ae_id_from_name(name)) >= 0 &&
            lacp_config_extract_aggregator(p, end, mode, sizeof(mode),
                                           min_links, sizeof(min_links),
                                           periodic, sizeof(periodic),
                                           &actor_key)) {
            next[ae_id].configured = true;
            snprintf(next[ae_id].mode, sizeof(next[ae_id].mode),
                     "%s", mode);
            next[ae_id].min_links = lacp_config_parse_min_links(min_links);
            next[ae_id].actor_key = actor_key;
            if (periodic[0])
                snprintf(next[ae_id].periodic, sizeof(next[ae_id].periodic),
                         "%s", periodic);
            if (strcmp(next[ae_id].periodic, "fast") == 0) {
                next[ae_id].tx_interval_sec = LACP_FAST_TX_SEC;
                next[ae_id].ttl_sec = LACP_FAST_TTL_SEC;
            } else {
                snprintf(next[ae_id].periodic, sizeof(next[ae_id].periodic),
                         "slow");
                next[ae_id].tx_interval_sec = LACP_SLOW_TX_SEC;
                next[ae_id].ttl_sec = lacp_ttl_sec();
            }
        }
        p = end + strlen("</interface>");
    }

    p = interfaces;
    while (p && p < interfaces_end && (p = strstr(p, "<interface>"))) {
        char *end = strstr(p, "</interface>");
        char name[32] = {0};
        char member[32] = {0};
        int ae_id;
        if (!end || end > interfaces_end) break;
        if (lacp_xml_leaf(p, end, "name", name, sizeof(name)) &&
            lacp_xml_leaf(p, end, "ieee8023ad", member, sizeof(member)) &&
            (ae_id = ae_id_from_name(member)) >= 0 &&
            next[ae_id].configured &&
            next[ae_id].n_members < (int)(sizeof(next[ae_id].members) /
                                          sizeof(next[ae_id].members[0]))) {
            int port = ifname_to_port(name);
            if (port > 0) {
                lacp_member *m = &next[ae_id].members[next[ae_id].n_members++];
                memset(m, 0, sizeof(*m));
                m->configured = true;
                snprintf(m->ifname, sizeof(m->ifname), "%s", name);
                snprintf(m->mode, sizeof(m->mode), "%s", next[ae_id].mode);
                m->port = port;
                m->port_priority =
                    lacp_config_extract_member_port_priority(p, end);
            }
        }
        p = end + strlen("</interface>");
    }

    for (int ae = 0; ae < lacp_max_ae(); ae++) {
        const lacp_lag *previous = &g_lacp.lags[ae];
        bool dynamic = strcmp(next[ae].mode, "static") != 0;
        bool unchanged = previous->configured && next[ae].configured &&
            !strcmp(previous->mode, next[ae].mode) && previous->min_links == next[ae].min_links &&
            same_member_settings(previous, &next[ae], dynamic) &&
            (!dynamic || (previous->actor_key == next[ae].actor_key &&
             !strcmp(previous->periodic, next[ae].periodic) && g_lacp.system_priority == system_priority &&
             g_lacp.port_priority == port_priority && !memcmp(g_lacp.actor_mac, actor_mac, sizeof(actor_mac))));
        next[ae].lag_id = g_lacp.lags[ae].lag_id;
        next[ae].logical_port = g_lacp.lags[ae].logical_port;
        next[ae].last_hw_poll = unchanged ? previous->last_hw_poll : 0;
        for (int i = 0; i < next[ae].n_members; i++) {
            for (int j = 0; j < g_lacp.lags[ae].n_members; j++) {
                if (unchanged && g_lacp.lags[ae].members[j].port == next[ae].members[i].port) {
                    next[ae].members[i].partner_valid =
                        g_lacp.lags[ae].members[j].partner_valid;
                    next[ae].members[i].partner =
                        g_lacp.lags[ae].members[j].partner;
                    next[ae].members[i].partner_view_of_us =
                        g_lacp.lags[ae].members[j].partner_view_of_us;
                    next[ae].members[i].last_rx =
                        g_lacp.lags[ae].members[j].last_rx;
                    next[ae].members[i].last_tx =
                        g_lacp.lags[ae].members[j].last_tx;
                    next[ae].members[i].link_up =
                        g_lacp.lags[ae].members[j].link_up;
                    next[ae].members[i].hw_attached =
                        g_lacp.lags[ae].members[j].hw_attached;
                    next[ae].members[i].rx_pdus =
                        g_lacp.lags[ae].members[j].rx_pdus;
                    next[ae].members[i].tx_pdus =
                        g_lacp.lags[ae].members[j].tx_pdus;
                    break;
                }
            }
        }
        next[ae].last_config_load = nl_monotonic_seconds();
    }

    memcpy(g_lacp.lags, next, sizeof(g_lacp.lags));
    memcpy(g_lacp.actor_mac, actor_mac, sizeof(g_lacp.actor_mac));
    g_lacp.system_priority = system_priority;
    g_lacp.port_priority = port_priority;
    g_lacp.config_mtime = mtime;
    g_lacp.config_mtime_nsec = mtime_nsec;
    free(next);
    free(xml);
    return true;
}

static void apply_lag_hw_locked(const char *response) {
    for (int ae = 0; ae < lacp_max_ae(); ae++) {
        g_lacp.lags[ae].lag_id = 0;
        g_lacp.lags[ae].logical_port = 0;
        for (int i = 0; i < g_lacp.lags[ae].n_members; i++)
            g_lacp.lags[ae].members[i].hw_attached = false;
    }
    if (g_lacp.native_required) {
        char value[32];
        uint64_t generation = 0;
        const char *root_end = response ? strchr(response, '>') : NULL;
        g_lacp.native_hw_valid = false;
        if (!response || strncmp(response, "<lags ", 6) || !root_end ||
            !strstr(root_end, "</lags>") ||
            !lacp_xml_attr(response, root_end, "native-generation", value, sizeof(value)) ||
            !nl_lag_generation_parse(value, &generation)) return;
        if (generation != g_lacp.native_generation) {
            u64 started = nl_port_scope_clock();
            if (!started) return;
            /* An unchanged configuration does not make the old peer's
             * synchronization valid for a newly initialized SDK. Keep
             * counters, but require fresh PDUs and fresh link observations. */
            for (int ae = 0; ae < lacp_max_ae(); ++ae) {
                lacp_lag *lag = &g_lacp.lags[ae];
                for (int i = 0; i < lag->n_members; ++i) {
                    lacp_member *m = &lag->members[i];
                    m->partner_valid = false;
                    memset(&m->partner, 0, sizeof(m->partner));
                    memset(&m->partner_view_of_us, 0, sizeof(m->partner_view_of_us));
                    m->last_rx = m->last_tx = 0;
                    m->link_up = false;
                }
            }
            NL_LOG_NOTICE("LACP SDK generation %016llx -> %016llx; fresh negotiation required",
                (unsigned long long)g_lacp.native_generation, (unsigned long long)generation);
            g_lacp.native_generation = generation;
            g_lacp.native_epoch_started = started;
        }
        g_lacp.native_hw_valid = true;
    }
    char *lag = (char *)response;
    while ((lag = strstr(lag, "<lag "))) {
        char *end = strstr(lag, "</lag>");
        char value[32] = {0};
        int ae_id = -1;
        if (!end) break;
        if (nl_lag_readback_error(lag, end)) {
            lag = end + strlen("</lag>");
            continue;
        }
        if (lacp_xml_attr(lag, end, "ae", value, sizeof(value)))
            ae_id = atoi(value);
        if (ae_id < 0 || ae_id >= lacp_max_ae()) {
            char ifname[16] = {0};
            if (lacp_xml_attr(lag, end, "name", ifname, sizeof(ifname)))
                ae_id = ae_id_from_name(ifname);
        }
        if (ae_id >= 0 && ae_id < lacp_max_ae()) {
            if (lacp_xml_attr(lag, end, "id", value, sizeof(value)))
                g_lacp.lags[ae_id].lag_id = atoi(value);
            if (lacp_xml_attr(lag, end, "logical-port", value, sizeof(value)))
                g_lacp.lags[ae_id].logical_port = atoi(value);
            g_lacp.lags[ae_id].last_hw_poll = nl_monotonic_seconds();
            char *member = lag;
            while ((member = strstr(member, "<member "))) {
                char *member_end = strstr(member, "/>");
                int port = 0;
                if (!member_end || member_end > end)
                    break;
                if (lacp_xml_attr(member, member_end, "port",
                                  value, sizeof(value)))
                    port = atoi(value);
                if (port > 0) {
                    for (int i = 0; i < g_lacp.lags[ae_id].n_members; i++) {
                        if (g_lacp.lags[ae_id].members[i].port == port) {
                            g_lacp.lags[ae_id].members[i].hw_attached = true;
                            break;
                        }
                    }
                }
                member = member_end + 2;
            }
        }
        lag = end + strlen("</lag>");
    }
}

static bool has_configured_lag_locked(void) {
    for (int ae = 0; ae < lacp_max_ae(); ae++) {
        if (g_lacp.lags[ae].configured)
            return true;
    }
    return false;
}

static void poll_lag_hw(void) {
    u8 resp[4096];
    bool configured;
    int n;

    pthread_mutex_lock(&g_lacp.lock);
    configured = has_configured_lag_locked();
    pthread_mutex_unlock(&g_lacp.lock);
    if (!configured)
        return;

    n = sw_call(NL_SWITCHD_LAG_GET_ALL, NULL, 0,
                resp, sizeof(resp) - 1);
    if (n <= 0) {
        pthread_mutex_lock(&g_lacp.lock);
        apply_lag_hw_locked("");
        pthread_mutex_unlock(&g_lacp.lock);
        return;
    }
    resp[n] = '\0';

    pthread_mutex_lock(&g_lacp.lock);
    if (has_configured_lag_locked())
        apply_lag_hw_locked((char *)resp);
    pthread_mutex_unlock(&g_lacp.lock);
}

static bool find_member_locked(int port, lacp_lag **lag_out,
                               lacp_member **member_out) {
    for (int ae = 0; ae < lacp_max_ae(); ae++) {
        lacp_lag *lag = &g_lacp.lags[ae];
        if (!lag->configured)
            continue;
        for (int i = 0; i < lag->n_members; i++) {
            if (lag->members[i].port == port) {
                if (lag_out)
                    *lag_out = lag;
                if (member_out)
                    *member_out = &lag->members[i];
                return true;
            }
        }
    }
    return false;
}

static bool find_member_ref_locked(const lacp_member_ref *ref,
                                   lacp_lag **lag_out,
                                   lacp_member **member_out) {
    lacp_lag *lag;

    if (!ref || ref->ae_id < 0 || ref->ae_id >= lacp_max_ae())
        return false;
    lag = &g_lacp.lags[ref->ae_id];
    if (!lag->configured)
        return false;
    for (int i = 0; i < lag->n_members; i++) {
        if (lag->members[i].port == ref->port) {
            if (lag_out)
                *lag_out = lag;
            if (member_out)
                *member_out = &lag->members[i];
            return true;
        }
    }
    return false;
}

static int collect_member_refs_locked(lacp_member_ref *refs, int max_refs) {
    int count = 0;

    if (!refs || max_refs <= 0)
        return 0;
    for (int ae = 0; ae < lacp_max_ae() && count < max_refs; ae++) {
        lacp_lag *lag = &g_lacp.lags[ae];

        if (!lag->configured)
            continue;
        for (int i = 0; i < lag->n_members && count < max_refs; i++) {
            refs[count].ae_id = ae;
            refs[count].port = lag->members[i].port;
            count++;
        }
    }
    return count;
}

static int partner_timeout_sec(const lacp_member *m) {
    if (m && (m->partner.state & LACP_STATE_TIMEOUT))
        return LACP_FAST_TTL_SEC;
    return lacp_ttl_sec();
}

static bool member_recent(const lacp_member *m, time_t now) {
    if ((g_lacp.native_required && !g_lacp.native_hw_valid) || !m ||
        !m->partner_valid || m->last_rx <= 0) return false;
    time_t scoped_now = nl_port_scope_now_monotonic(m->port, now);
    return scoped_now >= m->last_rx && scoped_now - m->last_rx <= partner_timeout_sec(m);
}

static bool partner_protocol_up(const lacp_member *m, time_t now) {
    if (!member_recent(m, now))
        return false;
    return (m->partner.state & LACP_STATE_SYNC) != 0;
}

static bool partner_allows_aggregation(const lacp_member *m, time_t now) {
    if (!member_recent(m, now))
        return false;
    return (m->partner.state & LACP_STATE_AGGREGATION) != 0;
}

static u16 lag_actor_key(const lacp_lag *lag) {
    if (!lag)
        return 0;
    if (lag->actor_key)
        return lag->actor_key;
    return (u16)(lag->ae_id + 1);
}

static u16 member_actor_port_priority(const lacp_member *m) {
    if (m && m->port_priority)
        return m->port_priority;
    if (g_lacp.port_priority)
        return g_lacp.port_priority;
    return lacp_default_port_priority();
}

static bool partner_view_matches_actor(const lacp_lag *lag,
                                       const lacp_member *m,
                                       time_t now) {
    const lacp_info *view;

    if (!lag || !m || !member_recent(m, now))
        return false;
    view = &m->partner_view_of_us;
    return view->system_priority == g_lacp.system_priority &&
           memcmp(view->system_mac, g_lacp.actor_mac, 6) == 0 &&
           view->key == lag_actor_key(lag) &&
           view->port_priority == member_actor_port_priority(m) &&
           view->port == (u16)m->port;
}

static bool same_partner_aggregator(const lacp_member *a,
                                    const lacp_member *b) {
    return a->partner.system_priority == b->partner.system_priority &&
           memcmp(a->partner.system_mac, b->partner.system_mac, 6) == 0 &&
           a->partner.key == b->partner.key;
}

static bool member_partner_candidate(const lacp_member *m, time_t now) {
    return m && m->link_up && member_recent(m, now) &&
           partner_allows_aggregation(m, now);
}

static int partner_group_size(const lacp_lag *lag, const lacp_member *anchor,
                              time_t now) {
    int count = 0;

    if (!lag || !member_partner_candidate(anchor, now))
        return 0;
    for (int i = 0; i < lag->n_members; i++) {
        const lacp_member *m = &lag->members[i];
        if (member_partner_candidate(m, now) &&
            same_partner_aggregator(anchor, m))
            count++;
    }
    return count;
}

static bool partner_group_preferred(const lacp_member *candidate,
                                    const lacp_member *current) {
    int cmp;

    if (!current)
        return true;
    if (candidate->partner.system_priority !=
        current->partner.system_priority)
        return candidate->partner.system_priority <
               current->partner.system_priority;
    cmp = memcmp(candidate->partner.system_mac,
                 current->partner.system_mac, 6);
    if (cmp != 0)
        return cmp < 0;
    if (candidate->partner.key != current->partner.key)
        return candidate->partner.key < current->partner.key;
    return candidate->port < current->port;
}

static const lacp_member *selected_partner_anchor(const lacp_lag *lag,
                                                  time_t now,
                                                  int *group_count) {
    const lacp_member *best = NULL;
    int best_count = 0;

    if (group_count)
        *group_count = 0;
    if (!lag)
        return NULL;

    for (int i = 0; i < lag->n_members; i++) {
        const lacp_member *m = &lag->members[i];
        int count;

        if (!member_partner_candidate(m, now))
            continue;
        count = partner_group_size(lag, m, now);
        if (count > best_count ||
            (count == best_count && partner_group_preferred(m, best))) {
            best = m;
            best_count = count;
        }
    }
    if (group_count)
        *group_count = best_count;
    return best;
}

static bool partner_aggregator_consistent(const lacp_lag *lag,
                                          const lacp_member *m,
                                          time_t now) {
    const lacp_member *anchor =
        selected_partner_anchor(lag, now, NULL);

    if (!anchor || !member_partner_candidate(m, now))
        return false;
    return same_partner_aggregator(anchor, m);
}

static bool member_selected(const lacp_lag *lag, const lacp_member *m,
                            time_t now) {
    int group_count = 0;
    const lacp_member *anchor;
    int min_links;

    if (!lag || !member_partner_candidate(m, now))
        return false;
    anchor = selected_partner_anchor(lag, now, &group_count);
    min_links = lag->min_links > 0 ? lag->min_links : 1;
    if (!anchor || group_count < min_links)
        return false;
    return same_partner_aggregator(anchor, m);
}

static bool member_oper_up(const lacp_lag *lag, const lacp_member *m,
                           time_t now) {
    if (lag && m && !strcmp(lag->mode, "static")) {
        int up = 0;
        for (int i = 0; i < lag->n_members; ++i) if (lag->members[i].link_up) ++up;
        return m->link_up && up >= lag->min_links;
    }
    if (!member_selected(lag, m, now) ||
        !partner_protocol_up(m, now) ||
        !partner_view_matches_actor(lag, m, now))
        return false;
    int ready = 0;
    for (int i = 0; i < lag->n_members; ++i) {
        const lacp_member *peer = &lag->members[i];
        if (member_partner_candidate(peer, now) && same_partner_aggregator(m, peer) &&
            partner_protocol_up(peer, now) && partner_view_matches_actor(lag, peer, now)) ++ready;
    }
    return ready >= (lag->min_links > 0 ? lag->min_links : 1);
}

static u8 actor_state(const lacp_lag *lag, const lacp_member *m, time_t now) {
    u8 st = LACP_STATE_AGGREGATION;
    if (strcmp(m->mode, "active") == 0)
        st |= LACP_STATE_ACTIVITY;
    if (lag && strcmp(lag->periodic, "fast") == 0)
        st |= LACP_STATE_TIMEOUT;
    if (member_selected(lag, m, now))
        st |= LACP_STATE_SYNC;
    if (member_oper_up(lag, m, now) && m->hw_attached)
        st |= LACP_STATE_COLLECTING | LACP_STATE_DISTRIBUTING;
    else if (!member_recent(m, now))
        st |= LACP_STATE_DEFAULTED;
    return st;
}

static int build_lacpdu(const lacp_lag *lag, const lacp_member *m,
                        u8 *frame, int max) {
    if (!lag || !m || !frame || max < 128) return -1;
    memset(frame, 0, 128);

    const u8 dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x02};
    memcpy(frame, dst, 6);
    u8 src[6];
    memcpy(src, g_actor_mac, 6);
    src[5] = (u8)m->port;
    memcpy(frame + 6, src, 6);
    frame[12] = 0x88; frame[13] = 0x09;
    frame[14] = LACP_SUBTYPE;
    frame[15] = LACP_VERSION;

    lacp_info actor;
    memset(&actor, 0, sizeof(actor));
    actor.system_priority = g_lacp.system_priority ?
        g_lacp.system_priority : lacp_default_system_priority();
    memcpy(actor.system_mac, g_lacp.actor_mac, 6);
    actor.key = lag_actor_key(lag);
    actor.port_priority = member_actor_port_priority(m);
    actor.port = (u16)m->port;
    actor.state = actor_state(lag, m, nl_monotonic_seconds());

    lacp_info partner;
    memset(&partner, 0, sizeof(partner));
    if (m->partner_valid)
        partner = m->partner;

    frame[16] = 1; frame[17] = 20;
    lacp_write_info(frame + 18, &actor);
    frame[36] = 2; frame[37] = 20;
    lacp_write_info(frame + 38, &partner);
    frame[56] = 3; frame[57] = 16;
    lacp_put16(frame + 58, 0);
    frame[74] = 0; frame[75] = 0;
    return 128;
}

static void receive_lacpdu(const u8 *frame, int n, int src_port, u64 captured_at) {
    lacp_info actor, partner;
    memset(&actor, 0, sizeof(actor));
    memset(&partner, 0, sizeof(partner));
    if (!lacp_parse_pdu(frame, n, &actor, &partner)) return;
    if (!nl_port_scope_packet_enter(src_port, captured_at)) return;

    pthread_mutex_lock(&g_lacp.lock);
    lacp_lag *lag = NULL;
    lacp_member *m = NULL;
    if ((!g_lacp.native_required || (g_lacp.native_hw_valid &&
         captured_at > g_lacp.native_epoch_started)) &&
        find_member_locked(src_port, &lag, &m) && strcmp(lag->mode, "static")) {
        m->partner = actor;
        m->partner_view_of_us = partner;
        m->partner_valid = true;
        m->last_rx = nl_monotonic_seconds();
        m->rx_pdus++;
        NL_LOG_DBG("LACP rx %s port=%d partner=%02x:%02x:%02x:%02x:%02x:%02x state=0x%02x",
                   lag ? lag->ifname : "ae?", src_port,
                   actor.system_mac[0], actor.system_mac[1],
                   actor.system_mac[2], actor.system_mac[3],
                   actor.system_mac[4], actor.system_mac[5], actor.state);
    }
    pthread_mutex_unlock(&g_lacp.lock);
    nl_port_scope_leave(src_port);
}

static void *rx_thread(void *arg) {
    (void)arg;
    u8 frame[NETLAB_PACKET_IO_MAX];
    while (g_running) {
        int src_port = 0;
        u64 captured_at = 0;
        int n = lacp_packet_read_event(lacpd_packetd_socket_path(),
                                       LACP_ETHERTYPE,
                                       PACKETD_RX_IDLE_SEC, &g_running,
                                       frame, sizeof(frame), &src_port, &captured_at);
        if (n > 0) receive_lacpdu(frame, n, src_port, captured_at);
    }
    lacp_packet_close_subscription();
    return NULL;
}

static void prepare_member_action_locked(const lacp_member_ref *ref,
                                         bool link_up,
                                         lacp_member_action *action) {
    lacp_lag *lag = NULL;
    lacp_member *m = NULL;
    time_t now = nl_monotonic_seconds();
    bool desired;

    memset(action, 0, sizeof(*action));
    if (g_lacp.native_required && !g_lacp.native_hw_valid) return;
    if (!find_member_ref_locked(ref, &lag, &m))
        return;
    action->native_generation = g_lacp.native_required ? g_lacp.native_generation : 0;

    m->link_up = link_up;
    if (m->partner_valid && !member_recent(m, now)) {
        m->partner_valid = false;
        memset(&m->partner, 0, sizeof(m->partner));
        memset(&m->partner_view_of_us, 0, sizeof(m->partner_view_of_us));
    }
    if (m->link_up && strcmp(m->mode, "static") &&
        (strcmp(m->mode, "active") == 0 || m->partner_valid) &&
        (!m->last_tx || now - m->last_tx >= lag->tx_interval_sec)) {
        action->frame_len = build_lacpdu(lag, m, action->frame,
                                         sizeof(action->frame));
        action->send_pdu = action->frame_len > 0;
    }

    desired = member_oper_up(lag, m, now);
    if (lag->lag_id > 0 && desired != m->hw_attached) {
        action->change_hw = true;
        action->desired_hw = desired;
        action->lag_id = lag->lag_id;
        snprintf(action->lag_ifname, sizeof(action->lag_ifname), "%s",
                 lag->ifname);
        snprintf(action->member_ifname, sizeof(action->member_ifname), "%s",
                 m->ifname);
    }
}

static void record_lacpdu_sent(const lacp_member_ref *ref) {
    lacp_member *m = NULL;

    pthread_mutex_lock(&g_lacp.lock);
    if (find_member_ref_locked(ref, NULL, &m)) {
        m->tx_pdus++;
        m->last_tx = nl_monotonic_seconds();
    }
    pthread_mutex_unlock(&g_lacp.lock);
}

static void record_hw_change(const lacp_member_ref *ref,
                             const lacp_member_action *action) {
    lacp_lag *lag = NULL;
    lacp_member *m = NULL;

    pthread_mutex_lock(&g_lacp.lock);
    if (find_member_ref_locked(ref, &lag, &m) &&
        lag->lag_id == action->lag_id &&
        (!g_lacp.native_required || (g_lacp.native_hw_valid &&
         action->native_generation == g_lacp.native_generation)))
        m->hw_attached = action->desired_hw;
    pthread_mutex_unlock(&g_lacp.lock);
}

static void run_member_cycle(const lacp_member_ref *ref) {
    if (!nl_port_scope_enter(ref->port)) return;
    lacp_member_action action;
    bool link_up = port_link_up(ref->port);

    pthread_mutex_lock(&g_lacp.lock);
    prepare_member_action_locked(ref, link_up, &action);
    pthread_mutex_unlock(&g_lacp.lock);

    if (action.send_pdu &&
        lacp_packet_tx(lacpd_packetd_socket_path(), ref->port,
                       action.frame, action.frame_len) == 0)
        record_lacpdu_sent(ref);

    if (action.change_hw) {
        char payload[64];
        u8 resp[64];
        int len = action.native_generation ?
            snprintf(payload, sizeof(payload), "%d %d generation=%016llx",
                action.lag_id, ref->port, (unsigned long long)action.native_generation) :
            snprintf(payload, sizeof(payload), "%d %d", action.lag_id, ref->port);
        int method = action.desired_hw ? 71 : 72;

        if (sw_call(method, (const u8 *)payload, len,
                    resp, sizeof(resp)) >= 0) {
            record_hw_change(ref, &action);
            NL_LOG_INFO("LACP %s %s port=%d hw-lag=%d %s",
                        action.lag_ifname, action.member_ifname, ref->port,
                        action.lag_id,
                        action.desired_hw ? "attached" : "detached");
        } else {
            NL_LOG_WARN("LACP %s %s port=%d hw-lag=%d %s failed",
                        action.lag_ifname, action.member_ifname, ref->port,
                        action.lag_id,
                        action.desired_hw ? "attach" : "detach");
        }
    }
    nl_port_scope_leave(ref->port);
}

static void resume_member_timers(u32 mask, time_t seconds) {
    pthread_mutex_lock(&g_lacp.lock);
    for (int ae = 0; ae < lacp_max_ae(); ++ae) {
        lacp_lag *lag = &g_lacp.lags[ae];
        for (int i = 0; i < lag->n_members; ++i) {
            lacp_member *m = &lag->members[i];
            if (m->port < 1 || m->port > 24 || !(mask & (1U << (m->port - 1)))) continue;
            if (m->last_rx) m->last_rx += seconds;
            if (m->last_tx) m->last_tx += seconds;
        }
    }
    pthread_mutex_unlock(&g_lacp.lock);
}

static void *tx_thread(void *arg) {
    (void)arg;
    while (g_running) {
        lacp_member_ref refs[NETLAB_MAX_AE * NETLAB_MAX_LAG_MEMBERS];
        int n_refs;

        pthread_mutex_lock(&g_lacp.lock);
        load_config_locked(false);
        pthread_mutex_unlock(&g_lacp.lock);

        poll_lag_hw();

        pthread_mutex_lock(&g_lacp.lock);
        n_refs = collect_member_refs_locked(
            refs, (int)(sizeof(refs) / sizeof(refs[0])));
        pthread_mutex_unlock(&g_lacp.lock);

        for (int i = 0; i < n_refs; i++)
            run_member_cycle(&refs[i]);
        sleep(1);
    }
    return NULL;
}

static void mac_str(const u8 mac[6], char *out, size_t out_size) {
    snprintf(out, out_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

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

static void handle_get_lacp(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    size_t off = 0;
    bool ok;
    time_t now = nl_monotonic_seconds();

    if (!buf) {
        nl_send_response(conn, msg->request_id, NL_ERR);
        return;
    }

    pthread_mutex_lock(&g_lacp.lock);
    char actor_mac[32];
    mac_str(g_lacp.actor_mac, actor_mac, sizeof(actor_mac));
    ok = append_cli_text(buf, NETLAB_MAX_MSG, &off, "<lags>\n");
    for (int ae = 0; ok && ae < lacp_max_ae(); ae++) {
        lacp_lag *lag = &g_lacp.lags[ae];
        int up_members = 0;
        int min_links;
        const char *status;
        const char *health;
        u16 actor_key;

        if (!lag->configured)
            continue;
        min_links = lag->min_links > 0 ? lag->min_links : 1;
        actor_key = lag_actor_key(lag);
        for (int i = 0; i < lag->n_members; i++)
            if (member_oper_up(lag, &lag->members[i], now) && lag->members[i].hw_attached)
                up_members++;
        if (lag->lag_id <= 0 || lag->logical_port <= 0) {
            status = "unknown";
            health = "hardware-readback";
        } else if (lag->n_members == 0) {
            status = "down";
            health = "no-members";
        } else if (up_members >= min_links) {
            status = "up";
            health = up_members == lag->n_members ? "full" : "degraded";
        } else {
            status = "down";
            health = "minimum-links";
        }
        ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                        "  <lag name=\"%s\" id=\"%d\" logical-port=\"%d\" "
                        "status=\"%s\" actor-system=\"%s\" actor-key=\"%u\" "
                        "mode=\"%s\" periodic=\"%s\" "
                        "actor-system-priority=\"%u\" actor-port-priority=\"%u\" "
                        "tx-interval=\"%d\" timeout=\"%d\" "
                        "minimum-links=\"%d\" health=\"%s\" "
                        "configured-members=\"%d\" up-members=\"%d\" "
                        "last-config-age=\"%d\" last-hw-poll-age=\"%d\">\n",
                        lag->ifname, lag->lag_id, lag->logical_port,
                        status, actor_mac, actor_key,
                        lag->mode, lag->periodic,
                        g_lacp.system_priority, g_lacp.port_priority,
                        lag->tx_interval_sec, lag->ttl_sec,
                        min_links, health,
                        lag->n_members, up_members,
                        lag->last_config_load ?
                            (int)(now - lag->last_config_load) : -1,
                        lag->last_hw_poll ?
                            (int)(now - lag->last_hw_poll) : -1);
        for (int i = 0; ok && i < lag->n_members; i++) {
            lacp_member *m = &lag->members[i];
            char pmac[32] = "00:00:00:00:00:00";
            char vmac[32] = "00:00:00:00:00:00";
            if (m->partner_valid)
                mac_str(m->partner.system_mac, pmac, sizeof(pmac));
            if (m->partner_valid)
                mac_str(m->partner_view_of_us.system_mac, vmac, sizeof(vmac));
            bool selected = member_selected(lag, m, now);
            bool up = member_oper_up(lag, m, now) && m->hw_attached;
            int age = m->last_rx ? (int)(now - m->last_rx) : -1;
            bool sync = up && (m->partner.state & LACP_STATE_SYNC);
            bool collecting = up && (m->partner.state & LACP_STATE_COLLECTING);
            bool distributing = up && (m->partner.state & LACP_STATE_DISTRIBUTING);
            bool partner_aggregation = partner_allows_aggregation(m, now);
            int partner_group_members = partner_group_size(lag, m, now);
            bool actor_consistent = partner_view_matches_actor(lag, m, now);
            ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                "    <member interface=\"%s\" port=\"%d\" status=\"%s\" "
                "link=\"%s\" hw-attached=\"%s\" partner-consistent=\"%s\" "
                "partner-aggregation=\"%s\" selected=\"%s\" "
                "partner-group-members=\"%d\" "
                "actor-state=\"0x%02x\" partner-system=\"%s\" "
                "partner-system-priority=\"%u\" "
                "partner-key=\"%u\" partner-port-priority=\"%u\" "
                "partner-port=\"%u\" partner-state=\"0x%02x\" "
                "partner-view-system=\"%s\" partner-view-key=\"%u\" "
                "partner-view-port-priority=\"%u\" partner-view-port=\"%u\" "
                "actor-consistent=\"%s\" "
                "actor-port-priority=\"%u\" "
                "sync=\"%s\" collecting=\"%s\" distributing=\"%s\" "
                "rx-pdus=\"%llu\" tx-pdus=\"%llu\" last-rx-age=\"%d\"/>\n",
                m->ifname, m->port, up ? "up" : "down",
                m->link_up ? "up" : "down",
                m->hw_attached ? "true" : "false",
                partner_aggregator_consistent(lag, m, now) ? "true" : "false",
                partner_aggregation ? "true" : "false",
                selected ? "true" : "false",
                partner_group_members,
                actor_state(lag, m, now), pmac,
                m->partner.system_priority,
                m->partner.key, m->partner.port_priority,
                m->partner.port, m->partner.state,
                vmac, m->partner_view_of_us.key,
                m->partner_view_of_us.port_priority,
                m->partner_view_of_us.port,
                actor_consistent ? "true" : "false",
                member_actor_port_priority(m),
                sync ? "true" : "false",
                collecting ? "true" : "false",
                distributing ? "true" : "false",
                (unsigned long long)m->rx_pdus,
                (unsigned long long)m->tx_pdus, age);
        }
        if (ok)
            ok = append_cli_text(buf, NETLAB_MAX_MSG, &off,
                                 "  </lag>\n");
    }
    if (ok)
        ok = append_cli_text(buf, NETLAB_MAX_MSG, &off, "</lags>\n");
    pthread_mutex_unlock(&g_lacp.lock);

    if (!ok) {
        free(buf);
        nl_send_response(conn, msg->request_id,
                         NL_ERR_CAPABILITY_INSUFFICIENT);
        return;
    }

    nl_msg_hdr *r = nl_msg_alloc((u32)off);
    if (r) {
        r->type = NL_MSG_RESPONSE;
        r->request_id = msg->request_id;
        r->payload_len = (u32)off;
        memcpy(r->payload, buf, (size_t)off);
        nl_send(conn, r);
        nl_msg_free(r);
    }
    free(buf);
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

static int lacpd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    (void)ctx;

    switch (msg->method) {
    case NL_LACPD_SHOW:
        handle_get_lacp(conn, msg);
        return NL_OK;
    case NL_LACPD_RELOAD: {
        pthread_mutex_lock(&g_lacp.lock);
        bool ok = load_config_locked(true);
        pthread_mutex_unlock(&g_lacp.lock);
        send_text_response(conn, msg, ok ? NL_OK : NL_ERR_HW_STATE_OUT_OF_SYNC,
                            ok ? "lacpd reload complete" : "lacpd reload failed");
        return NL_OK;
    }
    default:
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        return NL_OK;
    }
}

static int lacpd_on_init(void *ctx) {
    (void)ctx;

    memset(&g_runtime, 0, sizeof(g_runtime));
    memset(&g_lacp, 0, sizeof(g_lacp));
    memset(g_actor_mac, 0, sizeof(g_actor_mac));
    nl_port_scope_on_resume_monotonic(resume_member_timers);
    g_running = 1;

    load_system_mac(g_actor_mac);
    NL_LOG_INFO("lacpd actor system=%02x:%02x:%02x:%02x:%02x:%02x",
                g_actor_mac[0], g_actor_mac[1], g_actor_mac[2],
                g_actor_mac[3], g_actor_mac[4], g_actor_mac[5]);

    memcpy(g_lacp.actor_mac, g_actor_mac, sizeof(g_lacp.actor_mac));
    g_lacp.system_priority = lacp_default_system_priority();
    g_lacp.port_priority = lacp_default_port_priority();
    if (pthread_mutex_init(&g_lacp.lock, NULL) != 0) {
        NL_LOG_CRIT("failed to initialize lacpd state lock");
        return -1;
    }
    g_runtime.lock_initialized = true;
    pthread_mutex_lock(&g_lacp.lock);
    load_config_locked(true);
    pthread_mutex_unlock(&g_lacp.lock);
    poll_lag_hw();

    if (pthread_create(&g_runtime.rx_thread, NULL, rx_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create LACP receive thread");
        pthread_mutex_destroy(&g_lacp.lock);
        g_runtime.lock_initialized = false;
        return -1;
    }
    g_runtime.rx_thread_started = true;

    if (pthread_create(&g_runtime.tx_thread, NULL, tx_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create LACP transmit thread");
        g_running = 0;
        pthread_join(g_runtime.rx_thread, NULL);
        g_runtime.rx_thread_started = false;
        pthread_mutex_destroy(&g_lacp.lock);
        g_runtime.lock_initialized = false;
        return -1;
    }
    g_runtime.tx_thread_started = true;

    NL_LOG_NOTICE("lacpd ready (stateful LACP)");
    return NL_OK;
}

static void lacpd_on_shutdown(void *ctx) {
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
        pthread_mutex_destroy(&g_lacp.lock);
        g_runtime.lock_initialized = false;
    }
}

int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name = "lacpd",
        .socket_path = lacpd_socket_path(),
        .service_id = NL_DAEMON_LACPD,
        .auth_mode = NL_DAEMON_AUTH_STANDARD,
        .dispatch = lacpd_dispatch,
        .ctx = NULL,
        .on_init = lacpd_on_init,
        .on_shutdown = lacpd_on_shutdown,
    };

    (void)argc;
    (void)argv;
    return nl_daemon_run(&cfg);
}
