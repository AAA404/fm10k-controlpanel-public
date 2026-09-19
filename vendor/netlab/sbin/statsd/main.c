#include "netlab/daemon.h"
#include "netlab/error.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include "netlab/types.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define STATSD_SOCKET "/var/run/netlab/statsd.sock"
#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
#define STATSD_COUNTERS_XML_MAX NETLAB_MAX_MSG
#define STATSD_POLL_INTERVAL_MS 5000
#define STATSD_MIN_POLL_INTERVAL_MS 1000
#define STATSD_MAX_POLL_INTERVAL_MS 60000

typedef struct {
    u64 rx_packets, tx_packets;
    u64 rx_bytes, tx_bytes;
    u64 rx_ucast_packets, rx_mcast_packets, rx_bcast_packets;
    u64 tx_ucast_packets, tx_mcast_packets, tx_bcast_packets;
    u64 rx_errors, tx_errors;
    u64 rx_drops, tx_drops;
    u64 rx_fcs_errors, rx_symbol_errors, rx_frame_size_errors;
    u64 rx_pause_packets, tx_pause_packets;
    u64 stp_drops, vlan_tag_drops, security_violations;
    u64 flood_control_drops, policer_drops, ttl_drops;
} if_counter;

typedef struct {
    int port_id;
    char ifname[64];
    if_counter counters;
    if_counter prev_counters;
    bool have_prev;
    s64 last_sample_ms;
    double rx_bps, tx_bps;
    double rx_pps, tx_pps;
    bool hw_synced;
} port_counter;

typedef struct {
    port_counter ports[256];
    int   num_ports;
    bool  switchd_up;
    time_t last_poll;
    pthread_mutex_t lock;
    pthread_mutex_t poll_lock;
    pthread_t poll_thread;
    bool poll_thread_started;
    atomic_bool poll_running;
    int poll_interval_ms;
} statsd_ctx;

static statsd_ctx g_stats;

static const char *statsd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_STATSD_SOCKET",
                                       STATSD_SOCKET);
}

static const char *switchd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET",
                                       SWITCHD_SOCKET);
}

static s64 monotonic_ms(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (s64)now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
}

static u64 counter_delta(u64 current, u64 previous) {
    return current >= previous ? current - previous : current;
}

static int poll_interval_from_env(void) {
    const char *text = getenv("NETLAB_STATSD_POLL_INTERVAL_MS");
    char *end = NULL;
    long value;

    if (!text || !text[0])
        return STATSD_POLL_INTERVAL_MS;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        value < STATSD_MIN_POLL_INTERVAL_MS ||
        value > STATSD_MAX_POLL_INTERVAL_MS)
        return STATSD_POLL_INTERVAL_MS;
    return (int)value;
}

static bool extract_u64_attr(const char *begin, const char *end,
                             const char *attr, u64 *value) {
    char needle[64];
    const char *p;
    char *parse_end = NULL;
    unsigned long long parsed;

    if (!begin || !end || !attr || !value)
        return false;
    snprintf(needle, sizeof(needle), "%s=\"", attr);
    p = strstr(begin, needle);
    if (!p || p >= end)
        return false;
    p += strlen(needle);
    errno = 0;
    parsed = strtoull(p, &parse_end, 10);
    if (errno != 0 || parse_end == p || parse_end >= end ||
        *parse_end != '"')
        return false;
    *value = (u64)parsed;
    return true;
}

static bool extract_int_attr(const char *begin, const char *end,
                             const char *attr, int *value) {
    u64 parsed = 0;

    if (!value || !extract_u64_attr(begin, end, attr, &parsed) ||
        parsed > INT_MAX)
        return false;
    *value = (int)parsed;
    return true;
}

static void port_name_from_id(int port_id, char *buf, size_t buflen) {
    if (!nl_ifid_logical_port_to_name(port_id, buf, buflen))
        snprintf(buf, buflen, "logical-port-%d", port_id);
}

static bool ifname_to_hw_port(const char *ifname, int *port_out) {
    char *end = NULL;
    long value;
    int port;

    if (!ifname || !ifname[0] || !port_out)
        return false;
    port = nl_ifid_name_to_logical_port(ifname);
    if (port > 0) {
        *port_out = port;
        return true;
    }
    errno = 0;
    value = strtol(ifname, &end, 10);
    if (errno != 0 || end == ifname || *end != '\0' ||
        value <= 0 || value > INT_MAX)
        return false;
    *port_out = (int)value;
    return true;
}

static port_counter *find_port_locked(int port_id) {
    for (int i = 0; i < g_stats.num_ports; i++) {
        if (g_stats.ports[i].port_id == port_id)
            return &g_stats.ports[i];
    }
    return NULL;
}

static void replace_inventory_locked(const int *ports, int n_ports) {
    port_counter next[256];
    int next_count = 0;

    memset(next, 0, sizeof(next));
    for (int i = 0; i < n_ports && next_count < 256; i++) {
        int port_id = ports[i];
        port_counter *old = find_port_locked(port_id);

        if (nl_ifid_get_by_logical_port(port_id, NULL) &&
            !nl_ifid_is_user_port(port_id))
            continue;
        if (nl_ifid_is_cpu_port(port_id))
            continue;
        next[next_count].port_id = port_id;
        port_name_from_id(port_id, next[next_count].ifname,
                          sizeof(next[next_count].ifname));
        if (old)
            next[next_count] = *old;
        next[next_count].port_id = port_id;
        port_name_from_id(port_id, next[next_count].ifname,
                          sizeof(next[next_count].ifname));
        next_count++;
    }

    memcpy(g_stats.ports, next, sizeof(g_stats.ports));
    g_stats.num_ports = next_count;
}

// Poll counters from switchd. This is the single hardware reader for statsd;
// show requests only read this cache.
static void poll_counters(void) {
    char *xml = calloc(1, STATSD_COUNTERS_XML_MAX + 1);
    int ports[256] = {0};
    if_counter samples[256];
    bool valid[256] = {0};
    int n_ports = 0;
    time_t poll_time = time(NULL);
    s64 sample_ms = 0;
    s32 ec = 0;
    int rn = -1;

    memset(samples, 0, sizeof(samples));
    if (xml) {
        rn = nl_rpc_call_ex(
            switchd_socket_path(), NL_DAEMON_STATSD, NL_DAEMON_SWITCHD,
            NL_SWITCHD_PORT_SNAPSHOT_GET, 0,
            (const u8 *)"counters=1", 10,
            (u8 *)xml, STATSD_COUNTERS_XML_MAX + 1, 5000, &ec);
    }
    if (rn > 0 && ec == 0 && strstr(xml, "</port-snapshot>")) {
        const char *port = xml;

        xml[rn] = '\0';
        while (n_ports < 256 &&
               (port = strstr(port, "<port ")) != NULL) {
            const char *end = strstr(port, "/>");
            int port_id = 0;
            int counter_status = -1;
            if_counter *counters = &samples[n_ports];

            if (!end)
                break;
            if (extract_int_attr(port, end, "id", &port_id) && port_id > 0) {
                ports[n_ports] = port_id;
                valid[n_ports] =
                    extract_int_attr(port, end, "counter-status",
                                     &counter_status) &&
                    counter_status == 0 &&
                    extract_u64_attr(port, end, "rx-packets",
                                     &counters->rx_packets) &&
                    extract_u64_attr(port, end, "tx-packets",
                                     &counters->tx_packets) &&
                    extract_u64_attr(port, end, "rx-bytes",
                                     &counters->rx_bytes) &&
                    extract_u64_attr(port, end, "tx-bytes",
                                     &counters->tx_bytes) &&
                    extract_u64_attr(port, end, "rx-ucast-packets",
                                     &counters->rx_ucast_packets) &&
                    extract_u64_attr(port, end, "rx-mcast-packets",
                                     &counters->rx_mcast_packets) &&
                    extract_u64_attr(port, end, "rx-bcast-packets",
                                     &counters->rx_bcast_packets) &&
                    extract_u64_attr(port, end, "tx-ucast-packets",
                                     &counters->tx_ucast_packets) &&
                    extract_u64_attr(port, end, "tx-mcast-packets",
                                     &counters->tx_mcast_packets) &&
                    extract_u64_attr(port, end, "tx-bcast-packets",
                                     &counters->tx_bcast_packets) &&
                    extract_u64_attr(port, end, "rx-errors",
                                     &counters->rx_errors) &&
                    extract_u64_attr(port, end, "tx-errors",
                                     &counters->tx_errors) &&
                    extract_u64_attr(port, end, "rx-drops",
                                     &counters->rx_drops) &&
                    extract_u64_attr(port, end, "tx-drops",
                                     &counters->tx_drops) &&
                    extract_u64_attr(port, end, "rx-fcs-errors",
                                     &counters->rx_fcs_errors) &&
                    extract_u64_attr(port, end, "rx-symbol-errors",
                                     &counters->rx_symbol_errors) &&
                    extract_u64_attr(port, end, "rx-frame-size-errors",
                                     &counters->rx_frame_size_errors) &&
                    extract_u64_attr(port, end, "rx-pause-packets",
                                     &counters->rx_pause_packets) &&
                    extract_u64_attr(port, end, "tx-pause-packets",
                                     &counters->tx_pause_packets) &&
                    extract_u64_attr(port, end, "stp-drops",
                                     &counters->stp_drops) &&
                    extract_u64_attr(port, end, "vlan-tag-drops",
                                     &counters->vlan_tag_drops) &&
                    extract_u64_attr(port, end, "security-violations",
                                     &counters->security_violations) &&
                    extract_u64_attr(port, end, "flood-control-drops",
                                     &counters->flood_control_drops) &&
                    extract_u64_attr(port, end, "policer-drops",
                                     &counters->policer_drops) &&
                    extract_u64_attr(port, end, "ttl-drops",
                                     &counters->ttl_drops);
                n_ports++;
            }
            port = end + 2;
        }
        sample_ms = monotonic_ms();
    }

    pthread_mutex_lock(&g_stats.lock);
    g_stats.last_poll = poll_time;
    if (rn <= 0 || ec != 0 || n_ports == 0) {
        g_stats.switchd_up = false;
        for (int i = 0; i < g_stats.num_ports; i++)
            g_stats.ports[i].hw_synced = false;
        pthread_mutex_unlock(&g_stats.lock);
        free(xml);
        return;
    }

    g_stats.switchd_up = true;
    replace_inventory_locked(ports, n_ports);
    for (int i = 0; i < n_ports; i++) {
        int hw_port = ports[i];
        port_counter *pc = find_port_locked(hw_port);
        if (pc) {
            if (valid[i]) {
                double dt = pc->last_sample_ms > 0 && sample_ms > 0 ?
                    (double)(sample_ms - pc->last_sample_ms) / 1000.0 : 0.0;
                if (pc->have_prev && dt > 0.0) {
                    pc->rx_bps = (double)counter_delta(
                        samples[i].rx_bytes, pc->prev_counters.rx_bytes) *
                        8.0 / dt;
                    pc->tx_bps = (double)counter_delta(
                        samples[i].tx_bytes, pc->prev_counters.tx_bytes) *
                        8.0 / dt;
                    pc->rx_pps = (double)counter_delta(
                        samples[i].rx_packets,
                        pc->prev_counters.rx_packets) /
                        dt;
                    pc->tx_pps = (double)counter_delta(
                        samples[i].tx_packets,
                        pc->prev_counters.tx_packets) /
                        dt;
                } else {
                    pc->rx_bps = 0.0;
                    pc->tx_bps = 0.0;
                    pc->rx_pps = 0.0;
                    pc->tx_pps = 0.0;
                }
                pc->counters = samples[i];
                pc->prev_counters = samples[i];
                pc->have_prev = true;
                pc->last_sample_ms = sample_ms;
                pc->hw_synced = true;
            } else {
                pc->hw_synced = false;
            }
        }
    }
    pthread_mutex_unlock(&g_stats.lock);
    free(xml);
}

static bool wait_for_next_poll(int interval_ms) {
    int waited_ms = 0;

    while (atomic_load_explicit(&g_stats.poll_running,
                                memory_order_relaxed) &&
           waited_ms < interval_ms) {
        int step_ms = interval_ms - waited_ms;
        struct timespec delay;

        if (step_ms > 100)
            step_ms = 100;
        delay.tv_sec = step_ms / 1000;
        delay.tv_nsec = (long)(step_ms % 1000) * 1000000L;
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
            if (!atomic_load_explicit(&g_stats.poll_running,
                                      memory_order_relaxed))
                return false;
        }
        waited_ms += step_ms;
    }
    return atomic_load_explicit(&g_stats.poll_running,
                                memory_order_relaxed);
}

static void *statsd_poll_main(void *arg) {
    (void)arg;

    while (atomic_load_explicit(&g_stats.poll_running,
                                memory_order_relaxed)) {
        pthread_mutex_lock(&g_stats.poll_lock);
        if (atomic_load_explicit(&g_stats.poll_running,
                                 memory_order_relaxed))
            poll_counters();
        pthread_mutex_unlock(&g_stats.poll_lock);
        if (!wait_for_next_poll(g_stats.poll_interval_ms))
            break;
    }
    return NULL;
}

static int xml_appendf(char *buf, size_t buf_sz, size_t *off,
                       const char *fmt, ...) {
    size_t start;
    size_t avail;
    va_list ap;
    int n;

    if (!buf || !off || !fmt || buf_sz == 0 || *off >= buf_sz)
        return -1;

    start = *off;
    avail = buf_sz - start;
    va_start(ap, fmt);
    n = vsnprintf(buf + start, avail, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= avail) {
        buf[start] = '\0';
        return -1;
    }

    *off = start + (size_t)n;
    return 0;
}

// Build counters XML for all interfaces
static size_t build_counters_xml(char *buf, size_t buf_sz, const char *ifname) {
    size_t off = 0;
    bool truncated = false;

    pthread_mutex_lock(&g_stats.lock);
    if (xml_appendf(buf, buf_sz, &off,
                    "<counters switchd=\"%s\" last-poll=\"%ld\">\n",
                    g_stats.switchd_up ? "up" : "down",
                    (long)g_stats.last_poll) < 0) {
        truncated = true;
    }

    for (int i = 0; !truncated && i < g_stats.num_ports; i++) {
        port_counter *p = &g_stats.ports[i];
        if_counter *c = &p->counters;

        if (ifname && strcmp(p->ifname, ifname) != 0)
            continue;
        if (xml_appendf(buf, buf_sz, &off,
            "  <interface name=\"%s\" port=\"%d\" hw-sync=\"%s\">\n"
            "    <rx-packets>%llu</rx-packets>\n"
            "    <tx-packets>%llu</tx-packets>\n"
            "    <rx-bytes>%llu</rx-bytes>\n"
            "    <tx-bytes>%llu</tx-bytes>\n"
            "    <rx-errors>%llu</rx-errors>\n"
            "    <tx-errors>%llu</tx-errors>\n"
            "    <rx-drops>%llu</rx-drops>\n"
            "    <tx-drops>%llu</tx-drops>\n"
            "    <rx-bps>%.2f</rx-bps>\n"
            "    <tx-bps>%.2f</tx-bps>\n"
            "    <rx-pps>%.2f</rx-pps>\n"
            "    <tx-pps>%.2f</tx-pps>\n"
            "    <rx-ucast-packets>%llu</rx-ucast-packets>\n"
            "    <rx-mcast-packets>%llu</rx-mcast-packets>\n"
            "    <rx-bcast-packets>%llu</rx-bcast-packets>\n"
            "    <tx-ucast-packets>%llu</tx-ucast-packets>\n"
            "    <tx-mcast-packets>%llu</tx-mcast-packets>\n"
            "    <tx-bcast-packets>%llu</tx-bcast-packets>\n"
            "    <rx-fcs-errors>%llu</rx-fcs-errors>\n"
            "    <rx-symbol-errors>%llu</rx-symbol-errors>\n"
            "    <rx-frame-size-errors>%llu</rx-frame-size-errors>\n"
            "    <rx-pause-packets>%llu</rx-pause-packets>\n"
            "    <tx-pause-packets>%llu</tx-pause-packets>\n"
            "    <stp-drops>%llu</stp-drops>\n"
            "    <vlan-tag-drops>%llu</vlan-tag-drops>\n"
            "    <security-violations>%llu</security-violations>\n"
            "    <flood-control-drops>%llu</flood-control-drops>\n"
            "    <policer-drops>%llu</policer-drops>\n"
            "    <ttl-drops>%llu</ttl-drops>\n"
            "  </interface>\n",
            p->ifname, p->port_id, p->hw_synced ? "in-sync" : "out-of-sync",
            (unsigned long long)c->rx_packets,
            (unsigned long long)c->tx_packets,
            (unsigned long long)c->rx_bytes,
            (unsigned long long)c->tx_bytes,
            (unsigned long long)c->rx_errors,
            (unsigned long long)c->tx_errors,
            (unsigned long long)c->rx_drops,
            (unsigned long long)c->tx_drops,
            p->rx_bps, p->tx_bps, p->rx_pps, p->tx_pps,
            (unsigned long long)c->rx_ucast_packets,
            (unsigned long long)c->rx_mcast_packets,
            (unsigned long long)c->rx_bcast_packets,
            (unsigned long long)c->tx_ucast_packets,
            (unsigned long long)c->tx_mcast_packets,
            (unsigned long long)c->tx_bcast_packets,
            (unsigned long long)c->rx_fcs_errors,
            (unsigned long long)c->rx_symbol_errors,
            (unsigned long long)c->rx_frame_size_errors,
            (unsigned long long)c->rx_pause_packets,
            (unsigned long long)c->tx_pause_packets,
            (unsigned long long)c->stp_drops,
            (unsigned long long)c->vlan_tag_drops,
            (unsigned long long)c->security_violations,
            (unsigned long long)c->flood_control_drops,
            (unsigned long long)c->policer_drops,
            (unsigned long long)c->ttl_drops) < 0) {
            truncated = true;
            break;
        }
    }

    if (truncated &&
        xml_appendf(buf, buf_sz, &off,
                    "  <truncated>true</truncated>\n") < 0) {
        off = 0;
        (void)xml_appendf(buf, buf_sz, &off,
                          "<counters error=\"truncated\"/>\n");
        pthread_mutex_unlock(&g_stats.lock);
        return off;
    }

    if (xml_appendf(buf, buf_sz, &off, "</counters>\n") < 0) {
        off = 0;
        (void)xml_appendf(buf, buf_sz, &off,
                          "<counters error=\"truncated\"/>\n");
    }

    pthread_mutex_unlock(&g_stats.lock);
    return off;
}

// ===== Handlers =====
static int handle_get_counters(nl_conn *conn, nl_msg_hdr *msg) {
    char ifname[64] = {0};
    if (msg->payload_len >= sizeof(ifname) ||
        (msg->payload_len > 0 &&
         memchr(msg->payload, '\0', msg->payload_len) != NULL)) {
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        return 0;
    }
    if (msg->payload_len > 0)
        memcpy(ifname, msg->payload, msg->payload_len);

    char *buf = calloc(1, STATSD_COUNTERS_XML_MAX);
    if (!buf) {
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }

    size_t off = build_counters_xml(buf, STATSD_COUNTERS_XML_MAX,
                                    ifname[0] ? ifname : NULL);

    nl_msg_hdr *resp = nl_msg_alloc((u32)off);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)off;
        memcpy(resp->payload, buf, off);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    free(buf);
    return 0;
}

static int handle_clear_counters(nl_conn *conn, nl_msg_hdr *msg) {
    int ports[256];
    int n_ports = 0;
    int requested_port = 0;
    int failures = 0;
    bool cleared[256] = {0};

    if (msg->payload_len > 0) {
        char ifname[64] = {0};
        bool known = false;

        if (msg->payload_len >= sizeof(ifname) ||
            memchr(msg->payload, '\0', msg->payload_len) != NULL) {
            nl_send_response(conn, msg->request_id,
                             NL_ERR_MALFORMED_REQUEST);
            return 0;
        }
        memcpy(ifname, msg->payload, msg->payload_len);
        if (!ifname_to_hw_port(ifname, &requested_port)) {
            nl_send_response(conn, msg->request_id,
                             NL_ERR_INTERFACE_NOT_FOUND);
            return 0;
        }
        pthread_mutex_lock(&g_stats.lock);
        known = find_port_locked(requested_port) != NULL;
        pthread_mutex_unlock(&g_stats.lock);
        if (!known) {
            nl_send_response(conn, msg->request_id,
                             NL_ERR_INTERFACE_NOT_FOUND);
            return 0;
        }
    }

    pthread_mutex_lock(&g_stats.poll_lock);
    if (requested_port > 0) {
        ports[0] = requested_port;
        n_ports = 1;
    } else {
        pthread_mutex_lock(&g_stats.lock);
        for (int i = 0; i < g_stats.num_ports && n_ports < 256; i++)
            ports[n_ports++] = g_stats.ports[i].port_id;
        pthread_mutex_unlock(&g_stats.lock);
    }

    for (int i = 0; i < n_ports; i++) {
        char payload[32];
        char resp[64] = {0};
        s32 ec = 0;
        int rn;

        snprintf(payload, sizeof(payload), "%d", ports[i]);
        rn = nl_rpc_call_ex(
            switchd_socket_path(), NL_DAEMON_STATSD, NL_DAEMON_SWITCHD,
            NL_SWITCHD_PORT_COUNTERS_RESET, 0,
                            (const u8 *)payload, (int)strlen(payload),
                            (u8 *)resp, sizeof(resp), 5000, &ec);
        if (rn < 0 || ec != 0) {
            failures++;
        } else {
            cleared[i] = true;
        }
    }

    pthread_mutex_lock(&g_stats.lock);
    for (int i = 0; i < n_ports; i++) {
        port_counter *pc;

        if (!cleared[i])
            continue;
        pc = find_port_locked(ports[i]);
        if (pc) {
            memset(&pc->counters, 0, sizeof(if_counter));
            memset(&pc->prev_counters, 0, sizeof(if_counter));
            pc->have_prev = false;
            pc->last_sample_ms = 0;
            pc->rx_bps = 0.0;
            pc->tx_bps = 0.0;
            pc->rx_pps = 0.0;
            pc->tx_pps = 0.0;
        }
    }
    pthread_mutex_unlock(&g_stats.lock);
    pthread_mutex_unlock(&g_stats.poll_lock);
    nl_send_response(conn, msg->request_id,
                     failures == 0 ? NL_OK : NL_ERR_SDK_CALL_FAILED);
    return 0;
}

static int statsd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    (void)ctx;
    switch (msg->method) {
    case NL_STATSD_GET_COUNTERS: return handle_get_counters(conn, msg);
    case NL_STATSD_CLEAR_COUNTERS: return handle_clear_counters(conn, msg);
    default: nl_send_response(conn, msg->request_id, -1); return 0;
    }
}

static int statsd_on_init(void *ctx) {
    (void)ctx;
    memset(&g_stats, 0, sizeof(g_stats));
    pthread_mutex_init(&g_stats.lock, NULL);
    pthread_mutex_init(&g_stats.poll_lock, NULL);
    atomic_init(&g_stats.poll_running, true);
    g_stats.poll_interval_ms = poll_interval_from_env();
    if (pthread_create(&g_stats.poll_thread, NULL, statsd_poll_main, NULL) != 0) {
        atomic_store_explicit(&g_stats.poll_running, false,
                              memory_order_relaxed);
        pthread_mutex_destroy(&g_stats.poll_lock);
        pthread_mutex_destroy(&g_stats.lock);
        return -1;
    }
    g_stats.poll_thread_started = true;
    return 0;
}

static void statsd_on_shutdown(void *ctx) {
    (void)ctx;
    atomic_store_explicit(&g_stats.poll_running, false, memory_order_relaxed);
    if (g_stats.poll_thread_started)
        pthread_join(g_stats.poll_thread, NULL);
    pthread_mutex_destroy(&g_stats.poll_lock);
    pthread_mutex_destroy(&g_stats.lock);
}

int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name        = "statsd",
        .socket_path = statsd_socket_path(),
        .service_id  = NL_DAEMON_STATSD,
        .auth_mode   = NL_DAEMON_AUTH_STANDARD,
        .dispatch    = statsd_dispatch,
        .ctx         = NULL,
        .on_init     = statsd_on_init,
        .on_shutdown = statsd_on_shutdown,
        .max_concurrent_handlers = 8,
        .poll_interval_ms = 1000,
    };
    (void)argc; (void)argv;
    return nl_daemon_run(&cfg);
}
