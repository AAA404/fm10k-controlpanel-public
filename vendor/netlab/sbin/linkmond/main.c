#include "netlab/interface_id.h"
#include "netlab/daemon.h"
#include "netlab/error.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>

#define LINKMOND_SOCKET  "/var/run/netlab/linkmond.sock"
#define SWITCHD_SOCKET   "/var/run/netlab/switchd.sock"
#define STATSD_SOCKET    "/var/run/netlab/statsd.sock"
#define MAX_PORTS        NL_MAX_PORTS_PER_PROFILE
#define POLL_INTERVAL_S  5

typedef enum { LINK_UNKNOWN = -1, LINK_DOWN = 0, LINK_UP = 1 } link_state_t;

typedef struct {
    int    port_id;
    char   name[64];
    int    admin_state;
    link_state_t link_state;
    int    speed;
    u64    rx_pkts;
    u64    tx_pkts;
    u64    rx_bytes;
    u64    tx_bytes;
    u64    rx_errs;
    time_t last_link_change;
    time_t last_poll;
    bool   alive;
} port_entry_t;

static port_entry_t   g_ports[MAX_PORTS];
static int            g_num_ports = 0;
static volatile sig_atomic_t g_running = 1;
static pthread_mutex_t g_lock;

typedef struct {
    pthread_t poll_thread;
    bool poll_thread_started;
    bool lock_initialized;
} linkmond_runtime;

static linkmond_runtime g_runtime;

static const char *linkmond_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_LINKMOND_SOCKET",
                                       LINKMOND_SOCKET);
}

static const char *switchd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET",
                                       SWITCHD_SOCKET);
}

static const char *statsd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_STATSD_SOCKET",
                                       STATSD_SOCKET);
}

static void ifname_from_port(int port_id, char *buf, size_t buflen) {
    if (!nl_ifid_logical_port_to_name(port_id, buf, buflen))
        snprintf(buf, buflen, "logical-port-%d", port_id);
}

static port_entry_t *find_port(port_entry_t *ports, int count, int port_id) {
    for (int i = 0; i < count; i++) {
        if (ports[i].port_id == port_id)
            return &ports[i];
    }
    return NULL;
}

// ===== SWITCHD IPC =====

static int get_port_state(int port, link_state_t *link, int *admin,
                           int *speed, link_state_t prev_link) {
    char buf[16];
    int n = snprintf(buf, sizeof(buf), "port=%d", port);
    u8 resp[256] = {0};
    s32 ec = 0;
    link_state_t next_link;
    int rn = nl_rpc_call_ex(switchd_socket_path(), NL_DAEMON_LINKMOND,
                            NL_DAEMON_SWITCHD, NL_SWITCHD_PORT_GET_STATE,
                            0, (u8 *)buf, n, resp, sizeof(resp),
                            2000, &ec);
    if (rn <= 0 || ec != 0) return -1;

    char admin_str[16] = "?", link_str[16] = "?";
    int s = 0;
    if (sscanf((char *)resp, "port=%*d admin=%15s link=%15s speed=%d",
               admin_str, link_str, &s) != 3)
        return -1;

    if (strcmp(link_str, "UP") == 0)          next_link = LINK_UP;
    else if (strcmp(link_str, "DOWN") == 0)   next_link = LINK_DOWN;
    else                                        next_link = LINK_UNKNOWN;
    if (link)
        *link = next_link;
    if (admin) {
        if (strcmp(admin_str, "UP") == 0) *admin = 1;
        else                              *admin = 0;
    }
    if (speed) *speed = s;

    if (next_link != prev_link) {
        NL_LOG_INFO("port %d link %s->%s", port,
                    prev_link == LINK_UP ? "UP" : prev_link == LINK_DOWN ? "DOWN" : "?",
                    next_link == LINK_UP ? "UP" : next_link == LINK_DOWN ? "DOWN" : "?");
    }
    return 0;
}

static bool extract_counter_tag(const char *xml, const char *tag, u64 *value) {
    char open[64];
    char close[64];
    const char *start;
    char *end = NULL;
    unsigned long long parsed;

    if (!xml || !tag || !value)
        return false;
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    start = strstr(xml, open);
    if (!start)
        return false;
    start += strlen(open);
    errno = 0;
    parsed = strtoull(start, &end, 10);
    if (errno != 0 || end == start || strncmp(end, close, strlen(close)) != 0)
        return false;
    *value = (u64)parsed;
    return true;
}

static int get_port_counters(int port, u64 *rxb, u64 *txb,
                              u64 *rxp, u64 *txp, u64 *rxe) {
    char ifname[32];
    u8 resp[4096] = {0};
    s32 ec = 0;
    u64 next_rxb, next_txb, next_rxp, next_txp, next_rxe;
    int rn;

    ifname_from_port(port, ifname, sizeof(ifname));
    rn = nl_rpc_call_ex(statsd_socket_path(), NL_DAEMON_LINKMOND,
                        NL_DAEMON_STATSD, NL_STATSD_GET_COUNTERS, 0,
                        (u8 *)ifname, (int)strlen(ifname), resp,
                        sizeof(resp), 2000, &ec);
    if (rn <= 0 || ec != 0 ||
        !extract_counter_tag((char *)resp, "rx-bytes", &next_rxb) ||
        !extract_counter_tag((char *)resp, "tx-bytes", &next_txb) ||
        !extract_counter_tag((char *)resp, "rx-packets", &next_rxp) ||
        !extract_counter_tag((char *)resp, "tx-packets", &next_txp) ||
        !extract_counter_tag((char *)resp, "rx-errors", &next_rxe))
        return -1;
    if (rxb) *rxb = next_rxb;
    if (txb) *txb = next_txb;
    if (rxp) *rxp = next_rxp;
    if (txp) *txp = next_txp;
    if (rxe) *rxe = next_rxe;
    return 0;
}

// ===== PORT INVENTORY POLL =====

static void refresh_inventory(void) {
    u8 resp[16384] = {0};
    s32 ec = 0;
    int rn = nl_rpc_call_ex(switchd_socket_path(), NL_DAEMON_LINKMOND,
                            NL_DAEMON_SWITCHD,
                            NL_SWITCHD_PORT_GET_INVENTORY, 0,
                            NULL, 0, resp, sizeof(resp), 3000, &ec);
    port_entry_t next[MAX_PORTS];
    port_entry_t old[MAX_PORTS];
    int old_count;
    int next_count = 0;

    if (rn <= 0 || ec != 0 || !strstr((char *)resp, "</ports>")) return;
    memset(next, 0, sizeof(next));

    pthread_mutex_lock(&g_lock);
    memcpy(old, g_ports, sizeof(old));
    old_count = g_num_ports;
    pthread_mutex_unlock(&g_lock);
    char *p = (char *)resp;
    while (next_count < MAX_PORTS) {
        char *tag = strstr(p, "<port ");
        if (!tag) break;
        int port_id = 0;
        if (sscanf(tag, "<port id=\"%d\"", &port_id) == 1) {
            port_entry_t *previous = find_port(old, old_count, port_id);
            port_entry_t *e = &next[next_count];
            if (previous)
                *e = *previous;
            else
                memset(e, 0, sizeof(*e));
            e->port_id = port_id;
            ifname_from_port(port_id, e->name, sizeof(e->name));
            if (!previous)
                e->link_state = LINK_UNKNOWN;
            e->alive = true;
            next_count++;
        }
        p = strchr(tag + 1, '<');
        if (!p) break;
    }
    memcpy(g_ports, next, sizeof(g_ports));
    g_num_ports = next_count;
    pthread_mutex_unlock(&g_lock);
    if (next_count != old_count)
        NL_LOG_INFO("inventory: %d ports", next_count);
}

// ===== POLLING THREAD =====

static void *poll_thread(void *arg) {
    (void)arg;
    bool first_pass = true;

    while (g_running) {
        if (!first_pass) {
            sleep(POLL_INTERVAL_S);
            if (!g_running) break;
        }
        first_pass = false;

        refresh_inventory();

        pthread_mutex_lock(&g_lock);
        port_entry_t next[MAX_PORTS];
        int next_count = g_num_ports;
        memcpy(next, g_ports, sizeof(next));
        pthread_mutex_unlock(&g_lock);
        for (int i = 0; g_running && i < next_count; i++) {
            if (!next[i].alive) continue;
            port_entry_t *e = &next[i];
            link_state_t prev = e->link_state;

            get_port_state(e->port_id, &e->link_state, &e->admin_state,
                           &e->speed, prev);
            get_port_counters(e->port_id, &e->rx_bytes, &e->tx_bytes,
                              &e->rx_pkts, &e->tx_pkts, &e->rx_errs);

            if (e->link_state != prev) {
                e->last_link_change = time(NULL);
            }
            e->last_poll = time(NULL);
        }
        pthread_mutex_lock(&g_lock);
        memcpy(g_ports, next, sizeof(g_ports));
        g_num_ports = next_count;
        pthread_mutex_unlock(&g_lock);
    }
    return NULL;
}

// ===== IPC FOR CLI =====

static const char *link_str(link_state_t s) {
    if (s == LINK_UP)   return "up";
    if (s == LINK_DOWN) return "down";
    return "unknown";
}

static bool append_text(char *buf, size_t size, size_t *off,
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

static void handle_get_interfaces(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    port_entry_t *snapshot = calloc(MAX_PORTS, sizeof(*snapshot));
    size_t off = 0;
    int count;
    bool ok;

    if (!buf || !snapshot) {
        free(buf);
        free(snapshot);
        nl_send_response(conn, msg->request_id, NL_ERR);
        return;
    }

    pthread_mutex_lock(&g_lock);
    memcpy(snapshot, g_ports, sizeof(g_ports));
    count = g_num_ports;
    pthread_mutex_unlock(&g_lock);

    ok = append_text(buf, NETLAB_MAX_MSG, &off, "<interfaces>\n");
    for (int i = 0; ok && i < count; i++) {
        port_entry_t *e = &snapshot[i];
        if (!e->alive) continue;
        ok = append_text(buf, NETLAB_MAX_MSG, &off,
            "  <interface>\n"
            "    <name>%s</name>\n"
            "    <ifid>%d</ifid>\n"
            "    <admin-state>%s</admin-state>\n"
            "    <link-state>%s</link-state>\n"
            "    <speed>%d</speed>\n"
            "    <rx-packets>%llu</rx-packets>\n"
            "    <tx-packets>%llu</tx-packets>\n"
            "    <rx-bytes>%llu</rx-bytes>\n"
            "    <tx-bytes>%llu</tx-bytes>\n"
            "    <rx-errors>%llu</rx-errors>\n"
            "    <last-link-change>%ld</last-link-change>\n"
            "  </interface>\n",
            e->name, e->port_id,
            e->admin_state ? "up" : "down",
            link_str(e->link_state),
            e->speed,
            (unsigned long long)e->rx_pkts,
            (unsigned long long)e->tx_pkts,
            (unsigned long long)e->rx_bytes,
            (unsigned long long)e->tx_bytes,
            (unsigned long long)e->rx_errs,
            (long)e->last_link_change);
    }
    if (ok)
        ok = append_text(buf, NETLAB_MAX_MSG, &off, "</interfaces>\n");

    free(snapshot);
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

static int linkmond_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    (void)ctx;

    switch (msg->method) {
    case NL_LINKMOND_SHOW_INTERFACES:
        handle_get_interfaces(conn, msg);
        return NL_OK;
    default:
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        return NL_OK;
    }
}

static int linkmond_on_init(void *ctx) {
    (void)ctx;

    memset(&g_runtime, 0, sizeof(g_runtime));
    memset(g_ports, 0, sizeof(g_ports));
    g_num_ports = 0;
    g_running = 1;
    if (pthread_mutex_init(&g_lock, NULL) != 0) {
        NL_LOG_CRIT("failed to initialize linkmond state lock");
        return -1;
    }
    g_runtime.lock_initialized = true;

    // Wait for switchd to be ready
    nl_conn test_conn;
    for (int retry = 0; retry < 30; retry++) {
        if (nl_client_connect(switchd_socket_path(), &test_conn) == NL_OK) {
            nl_client_close(&test_conn);
            break;
        }
        sleep(1);
    }

    // Start poller thread
    if (pthread_create(&g_runtime.poll_thread, NULL,
                       poll_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create poll thread");
        pthread_mutex_destroy(&g_lock);
        g_runtime.lock_initialized = false;
        return -1;
    }
    g_runtime.poll_thread_started = true;
    NL_LOG_NOTICE("linkmond ready (poll interval=%ds)", POLL_INTERVAL_S);
    return NL_OK;
}

static void linkmond_on_shutdown(void *ctx) {
    (void)ctx;

    g_running = 0;
    if (g_runtime.poll_thread_started) {
        pthread_join(g_runtime.poll_thread, NULL);
        g_runtime.poll_thread_started = false;
    }
    if (g_runtime.lock_initialized) {
        pthread_mutex_destroy(&g_lock);
        g_runtime.lock_initialized = false;
    }
}

// ===== MAIN =====

int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name = "linkmond",
        .socket_path = linkmond_socket_path(),
        .service_id = NL_DAEMON_LINKMOND,
        .auth_mode = NL_DAEMON_AUTH_STANDARD,
        .dispatch = linkmond_dispatch,
        .ctx = NULL,
        .on_init = linkmond_on_init,
        .on_shutdown = linkmond_on_shutdown,
    };

    (void)argc;
    (void)argv;
    return nl_daemon_run(&cfg);
}
