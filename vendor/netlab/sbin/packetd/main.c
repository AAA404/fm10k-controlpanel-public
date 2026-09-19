/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/port_scope.h"
#include "netlab/packet_event.h"
#include "authority.h"
#include "netlab/ipc.h"
#include "netlab/interface_id.h"
#include "netlab/journal.h"
#include "netlab/log.h"
#include "netlab/hal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>

#define PACKETD_DEFAULT_SOCKET "/var/run/netlab/packetd.sock"
#define SWITCHD_SOCKET "/var/run/netlab/switchd.sock"
#define PACKETD_SYNTH_BPDU 0x4242
#define PACKETD_L3_TAP_DEFAULT_IFNAME "netlab-l3"
#define PACKETD_L3_TAP_MAX_EGRESS_PORTS 16
#define PACKETD_AUTH_TIMEOUT_MS 2000U
#define PACKETD_MAX_CONNECTION_WORKERS 32
#define PACKETD_SWITCHD_RPC_TIMEOUT_MS 3000U

static volatile sig_atomic_t g_running = 1;

static bool append_packetd_text(char *buf, size_t buf_size, int *off,
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

// Subscriber entry
typedef struct {
    int      fd;
    u16      ethertype;   // subscribed Ethertype in host byte order
    time_t   last_active;
    packetd_peer_authority authority;
} subscriber_t;

typedef struct {
    u64 rx_packets;
    u64 rx_delivered;
    u64 rx_internal_self_drops;
    u64 rx_policy_drops;
    u64 tx_requests;
    u64 tx_ok;
    u64 tx_fail;
} packetd_stats;

typedef struct {
    const char *name;
    u16 ethertype;
    int default_rate_pps;
    int default_burst_pkts;
    int rate_pps;
    int burst_pkts;
    bool configured;
    double tokens;
    struct timespec last_refill;
    u64 rx_packets;
    u64 delivered;
    u64 drops;
} punt_policy_class;

typedef struct {
    bool enabled;
    bool opened;
    int fd;
    char ifname[IFNAMSIZ];
    char status[32];
    char last_error[160];
    int egress_ports[PACKETD_L3_TAP_MAX_EGRESS_PORTS];
    int n_egress_ports;
    char egress_ports_text[128];
    u64 rx_to_tap;
    u64 rx_tap_write_fail;
    u64 tx_from_tap;
    u64 tx_to_asic;
    u64 tx_no_egress_drop;
    u64 tx_policy_drops;
    u64 tx_fail;
} l3_tap_state;

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int active;
    bool stopping;
} packetd_worker_state;

typedef struct {
    nl_conn conn;
    packetd_peer_authority peer;
    packetd_worker_state *state;
    const char *socket_path;
} packetd_worker_job;

static subscriber_t g_subscribers[16];
static int g_num_subs = 0;
static pthread_mutex_t g_sub_lock = PTHREAD_MUTEX_INITIALIZER;
static packetd_stats g_stats;
static pthread_mutex_t g_stats_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_policy_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_l3_tap_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_command_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_l3_tap_thread;
static bool g_l3_tap_thread_started = false;

static const char *packetd_socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_PACKETD_SOCKET",
                                       PACKETD_DEFAULT_SOCKET);
}
static l3_tap_state g_l3_tap = {
    false, false, -1, PACKETD_L3_TAP_DEFAULT_IFNAME,
    "disabled", "", {0}, 0, "-", 0, 0, 0, 0, 0, 0, 0
};
static punt_policy_class g_punt_policy[] = {
    { "rstp", PACKETD_SYNTH_BPDU, 256, 512, 256, 512, false, 512.0, {0, 0}, 0, 0, 0 },
    { "lldp", 0x88cc, 128, 256, 128, 256, false, 256.0, {0, 0}, 0, 0, 0 },
    { "lacp", 0x8809, 512, 1024, 512, 1024, false, 1024.0, {0, 0}, 0, 0, 0 },
    { "arp", 0x0806, 1024, 2048, 1024, 2048, false, 2048.0, {0, 0}, 0, 0, 0 },
    { "icmp", 0x0800, 512, 1024, 512, 1024, false, 1024.0, {0, 0}, 0, 0, 0 },
    { "ospf", 0x0800, 512, 1024, 512, 1024, false, 1024.0, {0, 0}, 0, 0, 0 },
    { "bgp", 0x0800, 512, 1024, 512, 1024, false, 1024.0, {0, 0}, 0, 0, 0 },
    { "igmp", 0x0800, 512, 1024, 512, 1024, false, 1024.0, {0, 0}, 0, 0, 0 },
};
static time_t g_policy_config_mtime = 0;
static long g_policy_config_mtime_nsec = 0;

static bool is_bpdu_frame(const u8 *frame, int frame_len);

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void close_subscriber(int idx) {
    if (idx < 0 || idx >= 16) return;
    if (g_subscribers[idx].fd >= 0)
        close(g_subscribers[idx].fd);
    g_subscribers[idx].fd = -1;
    g_subscribers[idx].ethertype = 0;
    g_subscribers[idx].last_active = 0;
    packetd_peer_authority_close(&g_subscribers[idx].authority);
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void stats_inc(u64 *field) {
    pthread_mutex_lock(&g_stats_lock);
    (*field)++;
    pthread_mutex_unlock(&g_stats_lock);
}

static punt_policy_class *punt_class_by_name_locked(const char *name) {
    if (!name)
        return NULL;
    for (size_t i = 0; i < sizeof(g_punt_policy) / sizeof(g_punt_policy[0]); i++) {
        if (strcmp(g_punt_policy[i].name, name) == 0)
            return &g_punt_policy[i];
    }
    return NULL;
}

static bool env_truthy(const char *name) {
    const char *v = getenv(name);

    return v && (strcmp(v, "1") == 0 ||
                 strcmp(v, "true") == 0 ||
                 strcmp(v, "TRUE") == 0 ||
                 strcmp(v, "yes") == 0 ||
                 strcmp(v, "YES") == 0);
}

static bool packetd_test_control_enabled(void) {
    return env_truthy("NETLAB_PACKETD_TEST_CONTROL");
}

static bool ffu_slice_enabled(int first, int last) {
    return first >= 0 && last >= first;
}

static bool port_capability_contains(const nl_port_entry *port,
                                     const char *wanted) {
    char tmp[128];
    char *save = NULL;
    char *tok;

    if (!port || !wanted || !port->capabilities[0])
        return false;
    snprintf(tmp, sizeof(tmp), "%s", port->capabilities);
    tok = strtok_r(tmp, ",", &save);
    while (tok) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (strcmp(tok, wanted) == 0)
            return true;
        tok = strtok_r(NULL, ",", &save);
    }
    return false;
}

static bool platform_l3_profile_ready(void) {
    nl_ffu_slice_allocation ffu;
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n;
    bool route_slices;

    if (!nl_platform_ffu_slices(&ffu))
        return false;
    route_slices = ffu_slice_enabled(ffu.ipv4_uc_first, ffu.ipv4_uc_last) ||
                   ffu_slice_enabled(ffu.ipv4_mc_first, ffu.ipv4_mc_last) ||
                   ffu_slice_enabled(ffu.ipv6_uc_first, ffu.ipv6_uc_last) ||
                   ffu_slice_enabled(ffu.ipv6_mc_first, ffu.ipv6_mc_last);
    if (!route_slices)
        return false;
    n = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n; i++) {
        if (!(ports[i].flags & NL_PORT_FLAG_EXTERNAL) &&
            strcmp(ports[i].role, "external") != 0)
            continue;
        if (port_capability_contains(&ports[i], "ROUTE"))
            return true;
    }
    return false;
}

static bool l3_tap_auto_enabled(char *reason, size_t reason_size) {
    if (env_truthy("NETLAB_DISABLE_PACKETD_L3_TAP")) {
        snprintf(reason, reason_size,
                 "NETLAB_DISABLE_PACKETD_L3_TAP is set");
        return false;
    }
    if (env_truthy("NETLAB_ENABLE_PACKETD_L3_TAP")) {
        snprintf(reason, reason_size,
                 "NETLAB_ENABLE_PACKETD_L3_TAP is set");
        return true;
    }
    if (platform_l3_profile_ready()) {
        snprintf(reason, reason_size,
                 "enabled by active L3 chassis mode");
        return true;
    }
    snprintf(reason, reason_size,
             "active chassis mode is not L3 and "
             "NETLAB_ENABLE_PACKETD_L3_TAP is not set");
    return false;
}

static u16 frame_ethertype(const u8 *frame, int frame_len, int *l3_offset) {
    u16 etype;

    if (l3_offset)
        *l3_offset = 14;
    if (!frame || frame_len < 14)
        return 0;
    etype = (u16)(((u16)frame[12] << 8) | frame[13]);
    if ((etype == 0x8100 || etype == 0x88a8) && frame_len >= 18) {
        if (l3_offset)
            *l3_offset = 18;
        etype = (u16)(((u16)frame[16] << 8) | frame[17]);
    }
    return etype;
}

static bool ipv4_l4_ports(const u8 *frame, int frame_len, int l3_offset,
                          u8 *proto, u16 *src_port, u16 *dst_port,
                          u32 *dst_ip) {
    const u8 *ip;
    int ihl;
    int l4;

    if (proto)
        *proto = 0;
    if (src_port)
        *src_port = 0;
    if (dst_port)
        *dst_port = 0;
    if (dst_ip)
        *dst_ip = 0;
    if (!frame || frame_len < l3_offset + 20)
        return false;
    ip = frame + l3_offset;
    if ((ip[0] >> 4) != 4)
        return false;
    ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || frame_len < l3_offset + ihl)
        return false;
    if (proto)
        *proto = ip[9];
    if (dst_ip)
        *dst_ip = ((u32)ip[16] << 24) |
                  ((u32)ip[17] << 16) |
                  ((u32)ip[18] << 8) |
                  (u32)ip[19];
    l4 = l3_offset + ihl;
    if (ip[9] == 6 || ip[9] == 17) {
        if (frame_len < l4 + 4)
            return true;
        if (src_port)
            *src_port = (u16)(((u16)frame[l4] << 8) | frame[l4 + 1]);
        if (dst_port)
            *dst_port = (u16)(((u16)frame[l4 + 2] << 8) |
                              frame[l4 + 3]);
    }
    return true;
}

static const char *punt_class_name_for_frame(const u8 *frame, int frame_len,
                                             u16 *dispatch_ethertype) {
    int l3_offset = 14;
    u16 etype;
    u8 proto = 0;
    u16 sport = 0;
    u16 dport = 0;
    u32 dst_ip = 0;

    if (is_bpdu_frame(frame, frame_len)) {
        if (dispatch_ethertype)
            *dispatch_ethertype = PACKETD_SYNTH_BPDU;
        return "rstp";
    }

    etype = frame_ethertype(frame, frame_len, &l3_offset);
    if (dispatch_ethertype)
        *dispatch_ethertype = etype;
    switch (etype) {
    case 0x88cc:
        return "lldp";
    case 0x8809:
        return "lacp";
    case 0x0806:
        return "arp";
    case 0x0800:
        if (!ipv4_l4_ports(frame, frame_len, l3_offset,
                           &proto, &sport, &dport, &dst_ip))
            return NULL;
        if (proto == 1)
            return "icmp";
        if (proto == 2)
            return "igmp";
        if (proto == 89)
            return "ospf";
        if (proto == 6 && (sport == 179 || dport == 179))
            return "bgp";
        return NULL;
    default:
        return NULL;
    }
}

static bool punt_class_is_l3(const char *name) {
    return name &&
           (strcmp(name, "arp") == 0 ||
            strcmp(name, "icmp") == 0 ||
            strcmp(name, "ospf") == 0 ||
            strcmp(name, "bgp") == 0);
}

static const char *punt_class_protocol(const char *name) {
    if (!name)
        return "-";
    if (strcmp(name, "rstp") == 0)
        return "bpdu";
    if (strcmp(name, "lldp") == 0)
        return "lldp";
    if (strcmp(name, "lacp") == 0)
        return "lacp";
    if (strcmp(name, "arp") == 0)
        return "arp";
    if (strcmp(name, "icmp") == 0)
        return "icmp";
    if (strcmp(name, "ospf") == 0)
        return "ospf";
    if (strcmp(name, "bgp") == 0)
        return "bgp";
    if (strcmp(name, "igmp") == 0)
        return "igmp";
    return "-";
}

static const char *punt_class_match(const char *name) {
    if (!name)
        return "-";
    if (strcmp(name, "rstp") == 0)
        return "802.3-llc-bpdu";
    if (strcmp(name, "lldp") == 0)
        return "ethertype=0x88cc";
    if (strcmp(name, "lacp") == 0)
        return "ethertype=0x8809";
    if (strcmp(name, "arp") == 0)
        return "ethertype=0x0806";
    if (strcmp(name, "icmp") == 0)
        return "ipv4-proto=1";
    if (strcmp(name, "ospf") == 0)
        return "ipv4-proto=89";
    if (strcmp(name, "bgp") == 0)
        return "tcp-port=179";
    if (strcmp(name, "igmp") == 0)
        return "ipv4-proto=2";
    return "-";
}

static void punt_policy_reset_locked(void) {
    for (size_t i = 0; i < sizeof(g_punt_policy) / sizeof(g_punt_policy[0]); i++) {
        punt_policy_class *cls = &g_punt_policy[i];
        cls->rate_pps = cls->default_rate_pps;
        cls->burst_pkts = cls->default_burst_pkts;
        cls->configured = false;
        if (cls->tokens > (double)cls->burst_pkts)
            cls->tokens = (double)cls->burst_pkts;
    }
}

static bool xml_leaf_in_range(const char *start, const char *end,
                              const char *leaf, char *out, size_t out_size) {
    char open[64];
    char close[64];
    const char *p;
    const char *q;
    size_t len;

    if (!start || !end || !leaf || !out || out_size == 0 || start >= end)
        return false;
    snprintf(open, sizeof(open), "<%s>", leaf);
    snprintf(close, sizeof(close), "</%s>", leaf);
    p = strstr(start, open);
    if (!p || p >= end)
        return false;
    p += strlen(open);
    q = strstr(p, close);
    if (!q || q > end || q < p)
        return false;
    len = (size_t)(q - p);
    if (len >= out_size)
        len = out_size - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

static bool parse_positive_int(const char *text, int min_value,
                               int max_value, int *out) {
    char *end = NULL;
    long value;

    if (!text || !text[0] || !out)
        return false;
    value = strtol(text, &end, 10);
    if (!end || *end != '\0' || value < min_value || value > max_value)
        return false;
    *out = (int)value;
    return true;
}

static char *read_active_config_file(void) {
    char path[512];
    FILE *f;
    long size;
    char *buf;

    nl_config_file_path(path, sizeof(path), "active.conf");
    f = fopen(path, "r");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    size = ftell(f);
    if (size <= 0 || size > 1024 * 1024) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = calloc(1, (size_t)size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    return buf;
}

static void apply_policy_class_locked(const char *class_block,
                                      const char *class_end) {
    char name[32] = {0};
    char value[32] = {0};
    int rate = 0;
    int burst = 0;
    bool has_rate = false;
    bool has_burst = false;
    punt_policy_class *cls;

    if (!xml_leaf_in_range(class_block, class_end, "name",
                           name, sizeof(name)))
        return;
    cls = punt_class_by_name_locked(name);
    if (!cls) {
        NL_LOG_WARN("packetd ignoring unknown CoPP class '%s'", name);
        return;
    }
    if (xml_leaf_in_range(class_block, class_end, "rate-pps",
                          value, sizeof(value))) {
        has_rate = parse_positive_int(value, 1, 1000000, &rate);
        if (!has_rate)
            NL_LOG_WARN("packetd ignoring invalid CoPP rate-pps=%s for %s",
                        value, name);
    }
    if (xml_leaf_in_range(class_block, class_end, "burst-pkts",
                          value, sizeof(value))) {
        has_burst = parse_positive_int(value, 1, 1000000, &burst);
        if (!has_burst)
            NL_LOG_WARN("packetd ignoring invalid CoPP burst-pkts=%s for %s",
                        value, name);
    }
    if (!has_rate && !has_burst)
        return;
    if (has_rate)
        cls->rate_pps = rate;
    if (has_burst)
        cls->burst_pkts = burst;
    cls->configured = true;
    if (cls->tokens > (double)cls->burst_pkts)
        cls->tokens = (double)cls->burst_pkts;
}

static void parse_policy_config_locked(const char *xml) {
    const char *cp;
    const char *cp_end;
    const char *prot;
    const char *prot_end;
    const char *p;

    punt_policy_reset_locked();
    if (!xml)
        return;
    cp = strstr(xml, "<control-plane>");
    if (!cp)
        return;
    cp_end = strstr(cp, "</control-plane>");
    if (!cp_end)
        return;
    prot = strstr(cp, "<protection>");
    if (!prot || prot > cp_end)
        return;
    prot_end = strstr(prot, "</protection>");
    if (!prot_end || prot_end > cp_end)
        return;

    p = prot;
    while ((p = strstr(p, "<class>")) && p < prot_end) {
        const char *class_end = strstr(p, "</class>");
        if (!class_end || class_end > prot_end)
            break;
        apply_policy_class_locked(p, class_end);
        p = class_end + strlen("</class>");
    }
}

static void punt_policy_reload_config(bool force) {
    struct stat st;
    char active_path[512];
    time_t mtime;
    long mtime_nsec;
    char *xml = NULL;

    nl_config_file_path(active_path, sizeof(active_path), "active.conf");
    if (stat(active_path, &st) != 0) {
        if (!force && g_policy_config_mtime == 0)
            return;
        pthread_mutex_lock(&g_policy_lock);
        punt_policy_reset_locked();
        g_policy_config_mtime = 0;
        g_policy_config_mtime_nsec = 0;
        pthread_mutex_unlock(&g_policy_lock);
        return;
    }
    mtime = st.st_mtime;
    mtime_nsec = st.st_mtim.tv_nsec;
    if (!force && mtime == g_policy_config_mtime &&
        mtime_nsec == g_policy_config_mtime_nsec)
        return;

    xml = read_active_config_file();
    pthread_mutex_lock(&g_policy_lock);
    parse_policy_config_locked(xml);
    g_policy_config_mtime = mtime;
    g_policy_config_mtime_nsec = mtime_nsec;
    pthread_mutex_unlock(&g_policy_lock);
    free(xml);
}

static void punt_policy_refill_locked(punt_policy_class *cls,
                                      const struct timespec *now) {
    double elapsed;
    double refill;

    if (!cls || !now)
        return;
    if (cls->last_refill.tv_sec == 0 && cls->last_refill.tv_nsec == 0) {
        cls->last_refill = *now;
        cls->tokens = (double)cls->burst_pkts;
        return;
    }

    elapsed = (double)(now->tv_sec - cls->last_refill.tv_sec) +
              (double)(now->tv_nsec - cls->last_refill.tv_nsec) / 1000000000.0;
    if (elapsed <= 0.0)
        return;

    refill = elapsed * (double)cls->rate_pps;
    cls->tokens += refill;
    if (cls->tokens > (double)cls->burst_pkts)
        cls->tokens = (double)cls->burst_pkts;
    cls->last_refill = *now;
}

static bool punt_policy_allow_class(const char *class_name) {
    struct timespec now;
    bool allow = true;

    if (!class_name)
        return true;
    clock_gettime(CLOCK_MONOTONIC, &now);
    pthread_mutex_lock(&g_policy_lock);
    punt_policy_class *cls = punt_class_by_name_locked(class_name);
    if (cls) {
        cls->rx_packets++;
        punt_policy_refill_locked(cls, &now);
        if (cls->tokens >= 1.0) {
            cls->tokens -= 1.0;
        } else {
            cls->drops++;
            allow = false;
        }
    }
    pthread_mutex_unlock(&g_policy_lock);

    if (!allow)
        stats_inc(&g_stats.rx_policy_drops);
    return allow;
}

static void punt_policy_note_delivered_class(const char *class_name) {
    if (!class_name)
        return;
    pthread_mutex_lock(&g_policy_lock);
    punt_policy_class *cls = punt_class_by_name_locked(class_name);
    if (cls)
        cls->delivered++;
    pthread_mutex_unlock(&g_policy_lock);
}

static void load_system_mac(u8 mac[6]) {
    memset(mac, 0, 6);
    (void)nl_platform_system_mac(mac);
}

static bool is_control_frame(const u8 *frame, int frame_len) {
    static const u8 prefix[5] = {0x01, 0x80, 0xc2, 0x00, 0x00};
    if (!frame || frame_len < 14)
        return false;
    return memcmp(frame, prefix, sizeof(prefix)) == 0;
}

static bool is_internal_self_control_frame(int src_port,
                                           const u8 *frame,
                                           int frame_len) {
    u8 local_mac[6];

    if (!is_control_frame(frame, frame_len) || nl_ifid_is_external(src_port))
        return false;
    load_system_mac(local_mac);
    if (local_mac[0] == 0 && local_mac[1] == 0 && local_mac[2] == 0 &&
        local_mac[3] == 0 && local_mac[4] == 0 && local_mac[5] == 0)
        return false;
    return memcmp(frame + 6, local_mac, 6) == 0;
}

static bool send_record_nonblock(int fd, const void *buf, size_t len) {
    ssize_t wr = send(fd, buf, len, MSG_NOSIGNAL | MSG_DONTWAIT);
    if (wr == (ssize_t)len)
        return true;
    if (wr < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        NL_LOG_WARN("packetd subscriber backpressure; dropping subscriber");
    return false;
}

static void send_record_blocking(int fd, const void *buf, size_t len) {
    const u8 *p = buf;
    size_t off = 0;
    u32 net_len = htonl((u32)len);

    (void)send(fd, &net_len, 4, MSG_NOSIGNAL);
    while (off < len) {
        ssize_t wr = send(fd, p + off, len - off, MSG_NOSIGNAL);
        if (wr <= 0)
            return;
        off += (size_t)wr;
    }
}

static int read_command_message(nl_conn *conn, u8 *msg, int msg_cap) {
    u8 first[NETLAB_PACKET_IO_MAX + 69];
    struct timeval timeout = {1, 0};
    u32 net_len;
    int msg_len;
    ssize_t n;

    if (!conn || conn->fd < 0 || !msg || msg_cap <= 1)
        return -1;

    (void)setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO,
                     &timeout, sizeof(timeout));

    n = nl_recv_peer_record(
        conn, first, sizeof(first), MSG_TRUNC);
    if (n < 4)
        return -1;

    memcpy(&net_len, first, 4);
    msg_len = (int)ntohl(net_len);
    if (msg_len <= 0 || msg_len >= msg_cap)
        return -1;

    if (n == 4) {
        n = nl_recv_peer_record(
            conn, msg, (size_t)msg_len, MSG_TRUNC);
        if (n != msg_len)
            return -1;
    } else {
        if (n - 4 != msg_len)
            return -1;
        memcpy(msg, first + 4, (size_t)msg_len);
    }

    msg[msg_len] = '\0';
    return msg_len;
}

static packetd_command packetd_command_from_message(
    const u8 *msg, int msg_len) {
    if (!msg || msg_len <= 0)
        return PACKETD_COMMAND_INVALID;
    if (msg_len >= 11 && memcmp(msg, "subscribe ", 10) == 0)
        return PACKETD_COMMAND_SUBSCRIBE;
    if (msg_len >= 4 && memcmp(msg, "tx ", 3) == 0)
        return PACKETD_COMMAND_TX;
    if (msg_len >= 10 && memcmp(msg, "classify ", 9) == 0)
        return PACKETD_COMMAND_CLASSIFY;
    if (msg_len >= 11 && memcmp(msg, "inject-rx ", 10) == 0)
        return PACKETD_COMMAND_INJECT_RX;
    if (msg_len == 5 && memcmp(msg, "stats", 5) == 0)
        return PACKETD_COMMAND_STATS;
    if (msg_len == 6 && memcmp(msg, "reload", 6) == 0)
        return PACKETD_COMMAND_RELOAD;
    if (msg_len > 6 && msg_len < 100 && !memcmp(msg, "scope ", 6)) return PACKETD_COMMAND_SCOPE;
    return PACKETD_COMMAND_INVALID;
}

static bool parse_subscribe_ethertype(
    const u8 *msg, int msg_len, u16 *ethertype) {
    unsigned int parsed;
    char trailing;

    if (!msg || msg_len < 11 || !ethertype ||
        sscanf((const char *)msg + 10, "%x%c", &parsed, &trailing) != 1 ||
        parsed > UINT16_MAX)
        return false;
    *ethertype = (u16)parsed;
    return true;
}

static bool parse_tx_message(
    u8 *msg, int msg_len, int *port, u8 **frame, int *frame_len, u64 *issued_at) {
    int parsed_port = 0;
    int consumed = 0;
    unsigned long long stamp = 0;
    if (!msg || msg_len <= 0 || !port || !frame || !frame_len) return false;
    const u8 *newline = memchr(msg, '\n', (size_t)msg_len);
    char header[48];
    size_t length = newline ? (size_t)(newline - msg) : sizeof(header);
    if (length >= sizeof(header)) return false;
    memcpy(header, msg, length); header[length] = 0;
    if (sscanf(header, "tx %d %16llx%n", &parsed_port, &stamp, &consumed) != 2) {
        stamp = 0;
        if (sscanf(header, "tx %d%n", &parsed_port, &consumed) != 1) return false;
    }
    if (
        parsed_port <= 0 || parsed_port > (int)UINT16_MAX ||
        consumed <= 0 || (size_t)consumed != length || consumed >= msg_len ||
        msg[consumed] != '\n' || msg_len - consumed - 1 < 14)
        return false;
    *port = parsed_port;
    *frame = msg + consumed + 1;
    *frame_len = msg_len - consumed - 1;
    if (issued_at) *issued_at = (u64)stamp;
    return true;
}

static bool packetd_command_payload_authorized(
    const packetd_peer_authority *peer, packetd_command command,
    u8 *msg, int msg_len) {
    static const u8 lldp_destination[6] =
        {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
    static const u8 lacp_destination[6] =
        {0x01, 0x80, 0xc2, 0x00, 0x00, 0x02};
    u16 ethertype;
    int port;
    int frame_len;
    u8 *frame;

    if (!peer)
        return false;
    if (peer->test_peer)
        return command == PACKETD_COMMAND_CLASSIFY ||
            command == PACKETD_COMMAND_INJECT_RX ||
            command == PACKETD_COMMAND_STATS;
    if (command == PACKETD_COMMAND_SUBSCRIBE) {
        if (!parse_subscribe_ethertype(msg, msg_len, &ethertype))
            return false;
        switch (peer->daemon_id) {
        case NL_DAEMON_L2D:
            return ethertype == 0x0800;
        case NL_DAEMON_LLDPD:
            return ethertype == 0x88cc;
        case NL_DAEMON_LACPD:
            return ethertype == 0x8809;
        case NL_DAEMON_STPD:
            return ethertype == PACKETD_SYNTH_BPDU;
        default:
            return false;
        }
    }
    if (command != PACKETD_COMMAND_TX)
        return true;
    if (!parse_tx_message(msg, msg_len, &port, &frame, &frame_len, NULL))
        return false;
    (void)port;
    if (peer->daemon_id == NL_DAEMON_LLDPD)
        return frame_len >= 14 &&
            memcmp(frame, lldp_destination, sizeof(lldp_destination)) == 0 &&
            frame[12] == 0x88 && frame[13] == 0xcc;
    if (peer->daemon_id == NL_DAEMON_LACPD)
        return frame_len >= 15 &&
            memcmp(frame, lacp_destination, sizeof(lacp_destination)) == 0 &&
            frame[12] == 0x88 && frame[13] == 0x09 &&
            frame[14] == 0x01;
    if (peer->daemon_id == NL_DAEMON_STPD)
        return is_bpdu_frame(frame, frame_len);
    return false;
}

static bool is_bpdu_frame(const u8 *frame, int frame_len) {
    static const u8 bpdu_dst[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
    u16 len_type;
    u8 version;
    u8 type;

    if (!frame || frame_len < 21)
        return false;
    if (memcmp(frame, bpdu_dst, sizeof(bpdu_dst)) != 0)
        return false;

    len_type = (u16)(((u16)frame[12] << 8) | frame[13]);
    if (len_type < 7 || len_type > 1500 ||
        (int)len_type > frame_len - 14)
        return false;
    if (frame[14] != 0x42 || frame[15] != 0x42 || frame[16] != 0x03 ||
        frame[17] != 0 || frame[18] != 0)
        return false;
    version = frame[19];
    type = frame[20];
    if (version == 0 && type == 0x80)
        return true;
    if (version == 0 && type == 0x00)
        return len_type >= 38;
    if (version == 2 && type == 0x02)
        return len_type >= 39;
    if (version == 3 && type == 0x02)
        return len_type >= 105;
    return false;
}

// ===== SWITCHD IPC HELPERS =====

static int switchd_call(nl_rpc_method method, u8 *payload, int plen,
                         u8 *resp_buf, int resp_max) {
    s32 ec = 0;
    u8 scratch[1];

    if (!resp_buf || resp_max <= 0) {
        resp_buf = scratch;
        resp_max = (int)sizeof(scratch);
    }

    int n = nl_rpc_call_ex(
        nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET", SWITCHD_SOCKET),
        NL_DAEMON_PACKETD, NL_DAEMON_SWITCHD, method, 0, payload, plen,
        resp_buf, resp_max, PACKETD_SWITCHD_RPC_TIMEOUT_MS, &ec);
    if (n < 0 || ec != 0)
        return -1;
    return n;
}

static int packet_tx_stamped(int port, const u8 *frame, int frame_len, u64 issued_at) {
    u8 payload[NETLAB_PACKET_IO_MAX + NL_PACKET_EVENT_HEADER];

    if (port <= 0 || !frame || frame_len <= 0 ||
        frame_len > NETLAB_PACKET_IO_MAX)
        return -1;

    if (!nl_port_scope_packet_enter(port, issued_at)) return -1;
    int length = nl_packet_event_encode(payload, sizeof(payload), port, 0,
        issued_at ? issued_at : nl_port_scope_clock(), frame, frame_len);
    int rc = length > 0 && switchd_call(NL_SWITCHD_PACKET_TX, payload, length, NULL, 0) >= 0 ? 0 : -1;
    nl_port_scope_leave(port);
    return rc;
}
static int packet_tx(int port, const u8 *frame, int frame_len) {
    return packet_tx_stamped(port, frame, frame_len, nl_port_scope_clock());
}

static void l3_tap_set_status_locked(const char *status,
                                     const char *error) {
    snprintf(g_l3_tap.status, sizeof(g_l3_tap.status), "%s",
             status ? status : "unknown");
    if (error)
        snprintf(g_l3_tap.last_error, sizeof(g_l3_tap.last_error), "%s",
                 error);
}

static bool l3_tap_ifname_valid(const char *ifname) {
    size_t len;

    if (!ifname || !ifname[0])
        return false;
    len = strlen(ifname);
    if (len >= IFNAMSIZ)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)ifname[i];

        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return false;
    }
    return true;
}

static bool l3_tap_parse_egress_ports_locked(void) {
    const char *csv = getenv("NETLAB_PACKETD_L3_TAP_EGRESS_PORTS");
    const char *single = getenv("NETLAB_PACKETD_L3_TAP_EGRESS_PORT");
    char buf[128];
    char *save = NULL;
    char *tok;
    size_t off = 0;

    g_l3_tap.n_egress_ports = 0;
    snprintf(g_l3_tap.egress_ports_text,
             sizeof(g_l3_tap.egress_ports_text), "-");
    if (!csv || !csv[0])
        csv = single;
    if (!csv || !csv[0])
        return true;
    if (strlen(csv) >= sizeof(buf)) {
        l3_tap_set_status_locked("error",
                                 "NETLAB_PACKETD_L3_TAP_EGRESS_PORTS is too long");
        return false;
    }
    snprintf(buf, sizeof(buf), "%s", csv);
    tok = strtok_r(buf, ",", &save);
    while (tok && g_l3_tap.n_egress_ports < PACKETD_L3_TAP_MAX_EGRESS_PORTS) {
        char *end = NULL;
        long port;

        while (*tok == ' ' || *tok == '\t')
            tok++;
        port = strtol(tok, &end, 10);
        while (end && (*end == ' ' || *end == '\t'))
            end++;
        if (!end || *end != '\0' || port <= 0 || port > 65535) {
            l3_tap_set_status_locked("error",
                                     "invalid NETLAB_PACKETD_L3_TAP_EGRESS_PORTS");
            return false;
        }
        g_l3_tap.egress_ports[g_l3_tap.n_egress_ports++] = (int)port;
        tok = strtok_r(NULL, ",", &save);
    }
    if (tok) {
        l3_tap_set_status_locked("error",
                                 "too many NETLAB_PACKETD_L3_TAP_EGRESS_PORTS");
        return false;
    }
    g_l3_tap.egress_ports_text[0] = '\0';
    for (int i = 0; i < g_l3_tap.n_egress_ports; i++) {
        int n = snprintf(g_l3_tap.egress_ports_text + off,
                         sizeof(g_l3_tap.egress_ports_text) - off,
                         "%s%d", i == 0 ? "" : ",",
                         g_l3_tap.egress_ports[i]);
        if (n < 0 || (size_t)n >= sizeof(g_l3_tap.egress_ports_text) - off) {
            snprintf(g_l3_tap.egress_ports_text,
                     sizeof(g_l3_tap.egress_ports_text), "truncated");
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

static int l3_tap_open_device(char *ifname, size_t ifname_size,
                              char *err, size_t err_size) {
    struct ifreq ifr;
    const char *requested = getenv("NETLAB_PACKETD_L3_TAP_IFNAME");
    const char *test_fd_env = getenv("NETLAB_PACKETD_L3_TAP_TEST_FD");
    int fd;

    if (!requested || !requested[0])
        requested = PACKETD_L3_TAP_DEFAULT_IFNAME;
    if (!l3_tap_ifname_valid(requested)) {
        snprintf(err, err_size, "invalid NETLAB_PACKETD_L3_TAP_IFNAME");
        return -1;
    }
    if (packetd_test_control_enabled() && test_fd_env && test_fd_env[0]) {
        char *end = NULL;
        long inherited_fd = strtol(test_fd_env, &end, 10);

        if (!end || *end != '\0' || inherited_fd < 0 ||
            inherited_fd > 1048576) {
            snprintf(err, err_size,
                     "invalid NETLAB_PACKETD_L3_TAP_TEST_FD");
            return -1;
        }
        if (fcntl((int)inherited_fd, F_GETFL, 0) < 0) {
            snprintf(err, err_size,
                     "NETLAB_PACKETD_L3_TAP_TEST_FD is not open: %s",
                     strerror(errno));
            return -1;
        }
        fd = dup((int)inherited_fd);
        if (fd < 0) {
            snprintf(err, err_size,
                     "dup NETLAB_PACKETD_L3_TAP_TEST_FD failed: %s",
                     strerror(errno));
            return -1;
        }
        set_nonblocking(fd);
        snprintf(ifname, ifname_size, "%s", requested);
        return fd;
    }
    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        snprintf(err, err_size, "open /dev/net/tun failed: %s",
                 strerror(errno));
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", requested);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        snprintf(err, err_size, "TUNSETIFF %s failed: %s",
                 requested, strerror(errno));
        close(fd);
        return -1;
    }
    snprintf(ifname, ifname_size, "%s", ifr.ifr_name);
    return fd;
}

static bool l3_tap_snapshot_ports(int *ports, int *n_ports) {
    if (!ports || !n_ports)
        return false;
    pthread_mutex_lock(&g_l3_tap_lock);
    *n_ports = g_l3_tap.n_egress_ports;
    for (int i = 0; i < *n_ports; i++)
        ports[i] = g_l3_tap.egress_ports[i];
    pthread_mutex_unlock(&g_l3_tap_lock);
    return *n_ports > 0;
}

static void *l3_tap_tx_thread(void *arg) {
    (void)arg;
    u8 frame[NETLAB_PACKET_IO_MAX];

    while (g_running) {
        int fd;
        ssize_t n;
        int ports[PACKETD_L3_TAP_MAX_EGRESS_PORTS];
        int n_ports = 0;
        bool sent = false;

        pthread_mutex_lock(&g_l3_tap_lock);
        fd = g_l3_tap.fd;
        pthread_mutex_unlock(&g_l3_tap_lock);
        if (fd < 0) {
            usleep(100000);
            continue;
        }
        n = read(fd, frame, sizeof(frame));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(20000);
                continue;
            }
            pthread_mutex_lock(&g_l3_tap_lock);
            g_l3_tap.tx_fail++;
            l3_tap_set_status_locked("error", strerror(errno));
            pthread_mutex_unlock(&g_l3_tap_lock);
            usleep(100000);
            continue;
        }
        if (n < 14)
            continue;
        pthread_mutex_lock(&g_l3_tap_lock);
        g_l3_tap.tx_from_tap++;
        pthread_mutex_unlock(&g_l3_tap_lock);
        if (!punt_class_is_l3(punt_class_name_for_frame(frame, (int)n,
                                                        NULL))) {
            pthread_mutex_lock(&g_l3_tap_lock);
            g_l3_tap.tx_policy_drops++;
            pthread_mutex_unlock(&g_l3_tap_lock);
            continue;
        }
        if (!l3_tap_snapshot_ports(ports, &n_ports)) {
            pthread_mutex_lock(&g_l3_tap_lock);
            g_l3_tap.tx_no_egress_drop++;
            pthread_mutex_unlock(&g_l3_tap_lock);
            continue;
        }
        /*
         * One frame owns one bounded switchd deadline.  A stalled backend
         * must not multiply shutdown latency by the configured fanout.
         */
        nl_rpc_deadline_scope_enter(PACKETD_SWITCHD_RPC_TIMEOUT_MS);
        for (int i = 0; i < n_ports && g_running; i++) {
            if (nl_rpc_effective_timeout_ms(
                    PACKETD_SWITCHD_RPC_TIMEOUT_MS) == 0)
                break;
            stats_inc(&g_stats.tx_requests);
            if (packet_tx(ports[i], frame, (int)n) == 0) {
                stats_inc(&g_stats.tx_ok);
                pthread_mutex_lock(&g_l3_tap_lock);
                g_l3_tap.tx_to_asic++;
                pthread_mutex_unlock(&g_l3_tap_lock);
                sent = true;
            } else {
                stats_inc(&g_stats.tx_fail);
                pthread_mutex_lock(&g_l3_tap_lock);
                g_l3_tap.tx_fail++;
                pthread_mutex_unlock(&g_l3_tap_lock);
            }
        }
        nl_rpc_deadline_scope_leave();
        if (!sent) {
            pthread_mutex_lock(&g_l3_tap_lock);
            if (strcmp(g_l3_tap.status, "open") == 0)
                l3_tap_set_status_locked("tx-degraded",
                                         "tap-to-asic packet_tx failed");
            pthread_mutex_unlock(&g_l3_tap_lock);
        } else {
            pthread_mutex_lock(&g_l3_tap_lock);
            if (strcmp(g_l3_tap.status, "tx-degraded") == 0)
                l3_tap_set_status_locked("open", "");
            pthread_mutex_unlock(&g_l3_tap_lock);
        }
    }
    return NULL;
}

static void l3_tap_init(void) {
    char err[160] = {0};
    char enable_reason[160] = {0};
    const char *requested_ifname;
    bool ifname_ok;
    bool ports_ok;
    bool enabled = l3_tap_auto_enabled(enable_reason,
                                       sizeof(enable_reason));
    int fd;

    pthread_mutex_lock(&g_l3_tap_lock);
    g_l3_tap.enabled = enabled;
    requested_ifname = getenv("NETLAB_PACKETD_L3_TAP_IFNAME");
    if (!requested_ifname || !requested_ifname[0])
        requested_ifname = PACKETD_L3_TAP_DEFAULT_IFNAME;
    ifname_ok = l3_tap_ifname_valid(requested_ifname);
    snprintf(g_l3_tap.ifname, sizeof(g_l3_tap.ifname), "%s",
             ifname_ok ? requested_ifname : PACKETD_L3_TAP_DEFAULT_IFNAME);
    ports_ok = l3_tap_parse_egress_ports_locked();
    if (!g_l3_tap.enabled) {
        l3_tap_set_status_locked("disabled", enable_reason);
        pthread_mutex_unlock(&g_l3_tap_lock);
        return;
    }
    if (!ifname_ok) {
        g_l3_tap.fd = -1;
        g_l3_tap.opened = false;
        l3_tap_set_status_locked("error",
                                 "invalid NETLAB_PACKETD_L3_TAP_IFNAME");
        pthread_mutex_unlock(&g_l3_tap_lock);
        return;
    }
    if (!ports_ok) {
        g_l3_tap.fd = -1;
        g_l3_tap.opened = false;
        pthread_mutex_unlock(&g_l3_tap_lock);
        return;
    }
    pthread_mutex_unlock(&g_l3_tap_lock);

    fd = l3_tap_open_device(g_l3_tap.ifname, sizeof(g_l3_tap.ifname),
                            err, sizeof(err));

    pthread_mutex_lock(&g_l3_tap_lock);
    if (fd < 0) {
        g_l3_tap.fd = -1;
        g_l3_tap.opened = false;
        l3_tap_set_status_locked("error", err);
        pthread_mutex_unlock(&g_l3_tap_lock);
        NL_LOG_WARN("packetd L3 TAP disabled: %s", err);
        return;
    }
    g_l3_tap.fd = fd;
    g_l3_tap.opened = true;
    l3_tap_set_status_locked("open", "");
    pthread_mutex_unlock(&g_l3_tap_lock);
    if (pthread_create(&g_l3_tap_thread, NULL,
                       l3_tap_tx_thread, NULL) == 0) {
        g_l3_tap_thread_started = true;
        NL_LOG_INFO("packetd L3 TAP open ifname=%s egress-ports=%s",
                    g_l3_tap.ifname, g_l3_tap.egress_ports_text);
    } else {
        pthread_mutex_lock(&g_l3_tap_lock);
        close(g_l3_tap.fd);
        g_l3_tap.fd = -1;
        g_l3_tap.opened = false;
        l3_tap_set_status_locked("error", "failed to start TAP TX thread");
        pthread_mutex_unlock(&g_l3_tap_lock);
    }
}

static bool l3_tap_deliver_from_asic(const char *class_name,
                                     const u8 *frame, int frame_len) {
    int fd;
    ssize_t n;

    if (!punt_class_is_l3(class_name) || !frame || frame_len <= 0)
        return false;
    pthread_mutex_lock(&g_l3_tap_lock);
    fd = g_l3_tap.fd;
    if (!g_l3_tap.enabled || !g_l3_tap.opened || fd < 0) {
        pthread_mutex_unlock(&g_l3_tap_lock);
        return false;
    }
    pthread_mutex_unlock(&g_l3_tap_lock);

    n = write(fd, frame, (size_t)frame_len);
    pthread_mutex_lock(&g_l3_tap_lock);
    if (n == frame_len) {
        g_l3_tap.rx_to_tap++;
        if (strcmp(g_l3_tap.status, "rx-degraded") == 0)
            l3_tap_set_status_locked("open", "");
        pthread_mutex_unlock(&g_l3_tap_lock);
        punt_policy_note_delivered_class(class_name);
        return true;
    }
    g_l3_tap.rx_tap_write_fail++;
    if (n < 0)
        l3_tap_set_status_locked("rx-degraded", strerror(errno));
    pthread_mutex_unlock(&g_l3_tap_lock);
    return false;
}

static bool l3_tap_append_xml(char *buf, size_t buf_size, int *off) {
    l3_tap_state snapshot;

    if (!buf || !off || *off < 0 || (size_t)*off >= buf_size)
        return false;
    pthread_mutex_lock(&g_l3_tap_lock);
    snapshot = g_l3_tap;
    pthread_mutex_unlock(&g_l3_tap_lock);
    return append_packetd_text(buf, buf_size, off,
                     "  <l3-tap enabled=\"%s\" status=\"%s\" "
                     "ifname=\"%s\" opened=\"%s\" "
                     "egress-ports=\"%s\" rx-to-tap=\"%llu\" "
                     "rx-tap-write-fail=\"%llu\" tx-from-tap=\"%llu\" "
                     "tx-to-asic=\"%llu\" tx-no-egress-drop=\"%llu\" "
                     "tx-policy-drops=\"%llu\" tx-fail=\"%llu\" "
                     "last-error=\"%s\"/>\n",
                     snapshot.enabled ? "true" : "false",
                     snapshot.status,
                     snapshot.ifname,
                     snapshot.opened ? "true" : "false",
                     snapshot.egress_ports_text,
                     (unsigned long long)snapshot.rx_to_tap,
                     (unsigned long long)snapshot.rx_tap_write_fail,
                     (unsigned long long)snapshot.tx_from_tap,
                     (unsigned long long)snapshot.tx_to_asic,
                     (unsigned long long)snapshot.tx_no_egress_drop,
                     (unsigned long long)snapshot.tx_policy_drops,
                     (unsigned long long)snapshot.tx_fail,
                     snapshot.last_error);
}

static void send_stats(int fd) {
    char buf[4096];
    int n;
    int off = 0;
    bool complete;
    packetd_stats stats;

    punt_policy_reload_config(true);

    pthread_mutex_lock(&g_stats_lock);
    stats = g_stats;
    pthread_mutex_unlock(&g_stats_lock);
    complete = append_packetd_text(
        buf, sizeof(buf), &off,
        "<packetd-stats rx-packets=\"%llu\" "
        "rx-delivered=\"%llu\" "
        "rx-internal-self-drops=\"%llu\" "
        "rx-policy-drops=\"%llu\" "
        "tx-requests=\"%llu\" tx-ok=\"%llu\" "
        "tx-fail=\"%llu\">\n",
        (unsigned long long)stats.rx_packets,
        (unsigned long long)stats.rx_delivered,
        (unsigned long long)stats.rx_internal_self_drops,
        (unsigned long long)stats.rx_policy_drops,
        (unsigned long long)stats.tx_requests,
        (unsigned long long)stats.tx_ok,
        (unsigned long long)stats.tx_fail);
    if (complete)
        complete = append_packetd_text(buf, sizeof(buf), &off,
                                       "  <punt-policy>\n");
    pthread_mutex_lock(&g_policy_lock);
    for (size_t i = 0;
         complete && i < sizeof(g_punt_policy) / sizeof(g_punt_policy[0]);
         i++) {
        punt_policy_class *cls = &g_punt_policy[i];
        complete = append_packetd_text(
            buf, sizeof(buf), &off,
            "    <class name=\"%s\" ethertype=\"0x%04x\" "
            "protocol=\"%s\" match=\"%s\" "
            "rate-pps=\"%d\" burst-pkts=\"%d\" configured=\"%s\" "
            "rx-packets=\"%llu\" delivered=\"%llu\" "
            "drops=\"%llu\"/>\n",
            cls->name, cls->ethertype, punt_class_protocol(cls->name),
            punt_class_match(cls->name), cls->rate_pps, cls->burst_pkts,
            cls->configured ? "true" : "false",
            (unsigned long long)cls->rx_packets,
            (unsigned long long)cls->delivered,
            (unsigned long long)cls->drops);
    }
    pthread_mutex_unlock(&g_policy_lock);
    if (complete)
        complete = append_packetd_text(buf, sizeof(buf), &off,
                                       "  </punt-policy>\n");
    if (complete)
        complete = l3_tap_append_xml(buf, sizeof(buf), &off);
    if (complete)
        complete = append_packetd_text(buf, sizeof(buf), &off,
                                       "</packetd-stats>\n");
    if (!complete) {
        static const char error[] =
            "err packetd-stats response exceeds capacity\n";

        send_record_blocking(fd, error, sizeof(error) - 1);
        return;
    }
    n = off;
    send_record_blocking(fd, buf, (size_t)n);
}

static void handle_packet_tx_command(int fd, u8 *msg, int msg_len) {
    int port = 0;
    int frame_len;
    u8 *frame;
    int rc;
    char resp[64];
    u64 issued_at = 0;

    if (!parse_tx_message(msg, msg_len, &port, &frame, &frame_len, &issued_at)) {
        send_record_blocking(fd, "err invalid-tx-command\n", 23);
        return;
    }

    stats_inc(&g_stats.tx_requests);
    rc = packet_tx_stamped(port, frame, frame_len, issued_at);
    if (rc == 0) {
        stats_inc(&g_stats.tx_ok);
        send_record_blocking(fd, "ok\n", 3);
    } else {
        stats_inc(&g_stats.tx_fail);
        snprintf(resp, sizeof(resp), "err tx-failed\n");
        send_record_blocking(fd, resp, strlen(resp));
    }
}

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int parse_hex_frame(const char *text, u8 *frame, int frame_cap) {
    int n = 0;
    int hi = -1;

    if (!text || !frame || frame_cap <= 0)
        return -1;
    for (const char *p = text; *p; p++) {
        int v;

        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == ':' ||
            *p == '-')
            continue;
        v = hex_nibble((unsigned char)*p);
        if (v < 0)
            return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= frame_cap)
                return -1;
            frame[n++] = (u8)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0)
        return -1;
    return n;
}

static void handle_classify_command(int fd, u8 *msg, int msg_len) {
    u8 frame[NETLAB_PACKET_IO_MAX];
    char payload[NETLAB_PACKET_IO_MAX + 65];
    char resp[256];
    int payload_len;
    int frame_len;
    u16 ethertype = 0;
    const char *class_name;
    int n;

    if (msg_len <= 9) {
        send_record_blocking(fd, "err invalid-classify-command\n", 29);
        return;
    }
    payload_len = msg_len - 9;
    if (payload_len < 0 || payload_len >= (int)sizeof(payload)) {
        send_record_blocking(fd, "err invalid-frame\n", 18);
        return;
    }
    memcpy(payload, msg + 9, (size_t)payload_len);
    payload[payload_len] = '\0';
    frame_len = parse_hex_frame(payload, frame, sizeof(frame));
    if (frame_len < 14) {
        send_record_blocking(fd, "err invalid-frame\n", 18);
        return;
    }
    class_name = punt_class_name_for_frame(frame, frame_len, &ethertype);
    n = snprintf(resp, sizeof(resp),
                 "<packetd-classify ethertype=\"0x%04x\" class=\"%s\" "
                 "protocol=\"%s\" match=\"%s\" l3-tap-eligible=\"%s\"/>\n",
                 ethertype,
                 class_name ? class_name : "-",
                 punt_class_protocol(class_name),
                 punt_class_match(class_name),
                 punt_class_is_l3(class_name) ? "true" : "false");
    if (n < 0)
        return;
    if (n >= (int)sizeof(resp))
        n = (int)sizeof(resp) - 1;
    send_record_blocking(fd, resp, (size_t)n);
}

static void packetd_process_rx_frame_unscoped(int src_port, int vlan,
                                     const u8 *frame, int frame_len, u64 captured_at) {
    u16 ethertype = 0;
    const char *class_name =
        punt_class_name_for_frame(frame, frame_len, &ethertype);

    stats_inc(&g_stats.rx_packets);
    if (is_internal_self_control_frame(src_port, frame, frame_len)) {
        stats_inc(&g_stats.rx_internal_self_drops);
        NL_LOG_WARN("packetd dropped self control frame on non-external port=%d ethertype=0x%04x",
                    src_port, ethertype);
        return;
    }
    if (!punt_policy_allow_class(class_name))
        return;

    (void)l3_tap_deliver_from_asic(class_name, frame, frame_len);

    pthread_mutex_lock(&g_sub_lock);
    for (int i = 0; i < g_num_subs; i++) {
        u8 event[NETLAB_PACKET_IO_MAX + NL_PACKET_EVENT_HEADER];
        u32 len32;

        if (g_subscribers[i].fd < 0)
            continue;
        if (!packetd_peer_authority_revalidate(
                &g_subscribers[i].authority)) {
            NL_LOG_WARN("packetd subscriber identity expired slot=%d "
                        "daemon=%u", i,
                        (unsigned)g_subscribers[i].authority.daemon_id);
            close_subscriber(i);
            continue;
        }
        if (g_subscribers[i].ethertype != ethertype &&
            g_subscribers[i].ethertype != 0xFFFF)
            continue;

        int length = nl_packet_event_encode(event, sizeof(event), src_port, vlan,
                                            captured_at, frame, frame_len);
        if (length < 0) continue;
        len32 = htonl((u32)length);
        if (!send_record_nonblock(g_subscribers[i].fd, &len32, 4) ||
            !send_record_nonblock(g_subscribers[i].fd, event,
                                  (size_t)length)) {
            close_subscriber(i);
            continue;
        }
        stats_inc(&g_stats.rx_delivered);
        punt_policy_note_delivered_class(class_name);
        g_subscribers[i].last_active = time(NULL);
    }
    pthread_mutex_unlock(&g_sub_lock);
}

static void packetd_process_rx_frame(int src_port, int vlan, const u8 *frame, int frame_len) {
    if (!nl_port_scope_enter(src_port)) return;
    packetd_process_rx_frame_unscoped(src_port, vlan, frame, frame_len, nl_port_scope_clock());
    nl_port_scope_leave(src_port);
}

static void handle_inject_rx_command(int fd, u8 *msg, int msg_len) {
    u8 frame[NETLAB_PACKET_IO_MAX];
    char payload[NETLAB_PACKET_IO_MAX + 65];
    char resp[256];
    int port = 0;
    int vlan = 0;
    int hex_off = 0;
    int payload_len;
    int frame_len;
    int matched;
    int n;

    if (!packetd_test_control_enabled()) {
        send_record_blocking(fd, "err test-control-disabled\n", 26);
        return;
    }
    payload_len = msg_len;
    if (payload_len <= 0 || payload_len >= (int)sizeof(payload)) {
        send_record_blocking(fd, "err invalid-inject-command\n", 27);
        return;
    }
    memcpy(payload, msg, (size_t)payload_len);
    payload[payload_len] = '\0';

    matched = sscanf(payload, "inject-rx %d %d %n", &port, &vlan, &hex_off);
    if (matched != 2 || hex_off <= 0 || port <= 0 ||
        vlan < 0 || vlan > 4095) {
        send_record_blocking(fd, "err invalid-inject-command\n", 27);
        return;
    }
    frame_len = parse_hex_frame(payload + hex_off, frame, sizeof(frame));
    if (frame_len < 14) {
        send_record_blocking(fd, "err invalid-frame\n", 18);
        return;
    }
    packetd_process_rx_frame(port, vlan, frame, frame_len);
    n = snprintf(resp, sizeof(resp),
                 "<packetd-inject-rx status=\"ok\" port=\"%d\" "
                 "vlan=\"%d\" length=\"%d\"/>\n",
                 port, vlan, frame_len);
    if (n < 0)
        return;
    if (n >= (int)sizeof(resp))
        n = (int)sizeof(resp) - 1;
    send_record_blocking(fd, resp, (size_t)n);
}

// ===== RX POLL THREAD =====

static void *rx_poll_thread(void *arg) {
    (void)arg;
    u8 buf[NETLAB_PACKET_IO_MAX + NL_PACKET_EVENT_HEADER];

    while (g_running) {
        int n = switchd_call(NL_SWITCHD_PACKET_RX_POLL_META,
                             NULL, 0, buf, sizeof(buf));
        if (n > 18) {
            int src_port, vlan;
            u64 captured_at;
            int header = nl_packet_event_decode(buf, n, &src_port, &vlan, &captured_at);
            if (header > 0 && n - header >= 14 &&
                nl_port_scope_packet_enter(src_port, captured_at)) {
                packetd_process_rx_frame_unscoped(src_port, vlan, buf + header, n - header,
                                                 captured_at ? captured_at : nl_port_scope_clock());
                nl_port_scope_leave(src_port);
            }
        }
        usleep(50000);  // 50ms poll interval
    }
    return NULL;
}

static bool add_subscriber(
    nl_conn *conn, packetd_peer_authority *peer,
    const u8 *msg, int msg_len) {
    unsigned int ethertype;
    char trailing;
    int subscriber_fd;
    int slot = -1;
    nl_daemon_id subscriber_daemon;

    if (!conn || !peer || !msg || msg_len < 11 ||
        sscanf((const char *)msg + 10, "%x%c",
               &ethertype, &trailing) != 1 ||
        ethertype > UINT16_MAX) {
        if (conn)
            send_record_blocking(
                conn->fd, "err invalid-subscribe-command\n",
                sizeof("err invalid-subscribe-command\n") - 1U);
        return false;
    }
    subscriber_daemon = peer->daemon_id;

    subscriber_fd = fcntl(conn->fd, F_DUPFD_CLOEXEC, 3);
    if (subscriber_fd < 0) {
        send_record_blocking(
            conn->fd, "err subscriber-fd\n",
            sizeof("err subscriber-fd\n") - 1U);
        return false;
    }
    set_nonblocking(subscriber_fd);

    pthread_mutex_lock(&g_sub_lock);
    for (int i = 0; i < 16; i++) {
        if (g_subscribers[i].fd < 0) {
            slot = i;
            break;
        }
    }
    if (slot >= 0) {
        g_subscribers[slot].fd = subscriber_fd;
        g_subscribers[slot].ethertype = (u16)ethertype;
        g_subscribers[slot].last_active = time(NULL);
        if (!packetd_peer_authority_move(
                &g_subscribers[slot].authority, peer)) {
            close_subscriber(slot);
            subscriber_fd = -1;
            slot = -1;
        } else if (slot >= g_num_subs) {
            g_num_subs = slot + 1;
        }
    }
    pthread_mutex_unlock(&g_sub_lock);

    if (slot < 0) {
        if (subscriber_fd >= 0)
            close(subscriber_fd);
        send_record_blocking(
            conn->fd, "err subscriber-limit\n",
            sizeof("err subscriber-limit\n") - 1U);
        return false;
    }
    NL_LOG_INFO("subscriber %d: daemon=%u ethertype=0x%04x",
                slot, (unsigned)subscriber_daemon,
                ethertype);
    return true;
}

static bool write_all_fd(int fd, const void *data, size_t data_len) {
    const u8 *bytes = data;
    size_t written = 0;

    while (written < data_len) {
        ssize_t rc = write(fd, bytes + written, data_len - written);

        if (rc < 0 && errno == EINTR)
            continue;
        if (rc <= 0)
            return false;
        written += (size_t)rc;
    }
    return true;
}

static int packetd_test_client_main(const char *command) {
    const char *socket_path = packetd_socket_path();
    nl_conn conn;
    size_t command_len;
    u32 net_len;
    u32 response_len;
    u8 *response = NULL;
    size_t received = 0;
    int result = 1;

    if (!packetd_test_control_enabled() ||
        !packetd_test_socket_allowed(socket_path) ||
        !command || (command_len = strlen(command)) == 0 ||
        command_len > NETLAB_PACKET_IO_MAX + 64U) {
        fprintf(stderr,
                "error: packetd test command requires explicit test control "
                "and an isolated temporary socket\n");
        return 2;
    }
    if (nl_client_connect(socket_path, &conn) != NL_OK)
        return 3;
    net_len = htonl((u32)command_len);
    if (nl_send_record(
            &conn, &net_len, sizeof(net_len)) != NL_OK ||
        nl_send_record(&conn, command, command_len) != NL_OK)
        goto out;
    if (nl_recv_peer_record(
            &conn, &net_len, sizeof(net_len), MSG_TRUNC) !=
        (ssize_t)sizeof(net_len))
        goto out;
    response_len = ntohl(net_len);
    if (response_len == 0 || response_len > NETLAB_MAX_MSG)
        goto out;
    response = malloc(response_len);
    if (!response)
        goto out;
    while (received < response_len) {
        ssize_t count = nl_recv_peer_record(
            &conn, response + received,
            response_len - received, MSG_TRUNC);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto out;
        received += (size_t)count;
    }
    if (!write_all_fd(STDOUT_FILENO, response, response_len))
        goto out;
    result = 0;

out:
    free(response);
    nl_client_close(&conn);
    return result;
}

static void packetd_worker_complete(packetd_worker_state *state) {
    if (!state)
        return;
    pthread_mutex_lock(&state->lock);
    if (state->active > 0)
        state->active--;
    pthread_cond_broadcast(&state->cond);
    pthread_mutex_unlock(&state->lock);
}

static void packetd_process_connection(packetd_worker_job *job) {
    packetd_command command;
    u8 msg[NETLAB_PACKET_IO_MAX + 65];
    int msg_len;

    if (!job)
        return;
    if (nl_server_authenticate_timeout(
            &job->conn, PACKETD_AUTH_TIMEOUT_MS) != NL_OK) {
        NL_LOG_DBG("packetd peer authentication failed "
                   "uid=%d gid=%d pid=%d",
                   (int)job->conn.peer_uid, (int)job->conn.peer_gid,
                   (int)job->conn.peer_pid);
        return;
    }
    msg_len = read_command_message(
        &job->conn, msg, sizeof(msg));
    command = packetd_command_from_message(msg, msg_len);
    if (msg_len <= 0 || command == PACKETD_COMMAND_INVALID) {
        send_record_blocking(
            job->conn.fd, "err unknown-command\n",
            sizeof("err unknown-command\n") - 1U);
        return;
    }
    if (!packetd_peer_authority_authorize(
            &job->conn, &job->peer, command, job->socket_path,
            packetd_test_control_enabled())) {
        NL_LOG_WARN("packetd denied command=%s "
                    "uid=%d gid=%d pid=%d",
                    packetd_command_name(command),
                    (int)job->conn.peer_uid, (int)job->conn.peer_gid,
                    (int)job->conn.peer_pid);
        send_record_blocking(
            job->conn.fd, "err permission-denied\n",
            sizeof("err permission-denied\n") - 1U);
        return;
    }

    /*
     * Preserve packetd's original serial command semantics while allowing
     * authentication and record receipt to proceed in bounded parallel.
     */
    pthread_mutex_lock(&g_command_lock);
    if (!packetd_peer_authority_authorize(
            &job->conn, &job->peer, command, job->socket_path,
            packetd_test_control_enabled())) {
        NL_LOG_WARN("packetd peer identity expired while queued "
                    "command=%s pid=%d",
                    packetd_command_name(command),
                    (int)job->conn.peer_pid);
        send_record_blocking(
            job->conn.fd, "err permission-denied\n",
            sizeof("err permission-denied\n") - 1U);
        pthread_mutex_unlock(&g_command_lock);
        return;
    }
    if (!packetd_command_payload_authorized(
            &job->peer, command, msg, msg_len)) {
        NL_LOG_WARN("packetd denied command payload command=%s "
                    "daemon=%u pid=%d",
                    packetd_command_name(command),
                    (unsigned)job->peer.daemon_id,
                    (int)job->conn.peer_pid);
        send_record_blocking(
            job->conn.fd, "err permission-denied\n",
            sizeof("err permission-denied\n") - 1U);
        pthread_mutex_unlock(&g_command_lock);
        return;
    }

    switch (command) {
    case PACKETD_COMMAND_SUBSCRIBE:
        (void)add_subscriber(
            &job->conn, &job->peer, msg, msg_len);
        break;
    case PACKETD_COMMAND_TX:
        handle_packet_tx_command(job->conn.fd, msg, msg_len);
        break;
    case PACKETD_COMMAND_CLASSIFY:
        handle_classify_command(job->conn.fd, msg, msg_len);
        break;
    case PACKETD_COMMAND_INJECT_RX:
        handle_inject_rx_command(job->conn.fd, msg, msg_len);
        break;
    case PACKETD_COMMAND_STATS:
        send_stats(job->conn.fd);
        break;
    case PACKETD_COMMAND_SCOPE: {
        char operation[12] = {0}, reply[128];
        unsigned long long tx = 0;
        unsigned mask = 0;
        int used = -1, rc = NL_ERR_MALFORMED_REQUEST;
        if (sscanf((const char *)msg, "scope %11s %llx %x %n", operation, &tx, &mask, &used) == 3 && used == msg_len) {
            if (!strcmp(operation, "begin")) rc = nl_port_scope_begin(tx, mask, 5000);
            else if (!strcmp(operation, "end") && mask == 0) rc = nl_port_scope_end(tx);
            else if (!strcmp(operation, "status") && !tx && !mask) rc = 0;
        }
        nl_port_scope_status status = nl_port_scope_get();
        int n = snprintf(reply, sizeof(reply), "scope %u %016llx %06x %u %d", status.schema,
            (unsigned long long)status.tx_id, status.mask, status.degraded, rc);
        send_record_blocking(job->conn.fd, reply, (size_t)n);
        break;
    }
    case PACKETD_COMMAND_RELOAD:
        punt_policy_reload_config(true);
        send_record_blocking(
            job->conn.fd, "packetd reload complete",
            sizeof("packetd reload complete") - 1U);
        break;
    case PACKETD_COMMAND_INVALID:
        break;
    }
    pthread_mutex_unlock(&g_command_lock);
}

static void *packetd_worker_main(void *arg) {
    packetd_worker_job *job = arg;
    packetd_worker_state *state;

    if (!job)
        return NULL;
    state = job->state;
    packetd_process_connection(job);
    packetd_peer_authority_close(&job->peer);
    nl_client_close(&job->conn);
    packetd_worker_complete(state);
    free(job);
    return NULL;
}

static bool packetd_start_worker(
    packetd_worker_state *state, const char *socket_path,
    const nl_conn *conn, packetd_peer_authority *peer) {
    packetd_worker_job *job;
    pthread_t thread;

    if (!state || !socket_path || !conn || !peer)
        return false;
    pthread_mutex_lock(&state->lock);
    if (state->stopping ||
        state->active >= PACKETD_MAX_CONNECTION_WORKERS) {
        pthread_mutex_unlock(&state->lock);
        return false;
    }
    state->active++;
    pthread_mutex_unlock(&state->lock);

    job = calloc(1, sizeof(*job));
    if (!job) {
        packetd_worker_complete(state);
        return false;
    }
    job->conn = *conn;
    job->state = state;
    job->socket_path = socket_path;
    packetd_peer_authority_init(&job->peer);
    if (!packetd_peer_authority_move(&job->peer, peer)) {
        packetd_worker_complete(state);
        free(job);
        return false;
    }
    if (pthread_create(
            &thread, NULL, packetd_worker_main, job) != 0) {
        packetd_peer_authority_close(&job->peer);
        packetd_worker_complete(state);
        free(job);
        return false;
    }
    pthread_detach(thread);
    return true;
}

static void packetd_wait_for_workers(packetd_worker_state *state) {
    if (!state)
        return;
    pthread_mutex_lock(&state->lock);
    state->stopping = true;
    while (state->active > 0)
        pthread_cond_wait(&state->cond, &state->lock);
    pthread_mutex_unlock(&state->lock);
}

// ===== IPC SERVER =====

int main(int argc, char *argv[]) {
    if (argc == 3 && strcmp(argv[1], "--test-command") == 0)
        return packetd_test_client_main(argv[2]);
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--test-command COMMAND]\n", argv[0]);
        return 2;
    }
    nl_log_init("packetd", LOG_DAEMON, NL_LOG_INFO);
    NL_LOG_INFO("packetd starting...");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    mkdir("/var/run/netlab", 0755);

    // Init subscriber slots
    for (int i = 0; i < 16; i++) {
        g_subscribers[i].fd = -1;
        packetd_peer_authority_init(&g_subscribers[i].authority);
    }

    const char *socket_path = packetd_socket_path();
    int listen_fd;
    pthread_t rx_thread;
    bool rx_thread_started = false;
    packetd_worker_state worker_state = {
        .lock = PTHREAD_MUTEX_INITIALIZER,
        .cond = PTHREAD_COND_INITIALIZER,
    };

    punt_policy_reload_config(true);
    if (nl_server_listen(socket_path, &listen_fd) != NL_OK) {
        NL_LOG_CRIT("failed to create socket");
        pthread_cond_destroy(&worker_state.cond);
        pthread_mutex_destroy(&worker_state.lock);
        return 1;
    }
    if (nl_port_scope_init("packetd")) { close(listen_fd); return 1; }
    l3_tap_init();
    if (pthread_create(
            &rx_thread, NULL, rx_poll_thread, NULL) != 0) {
        NL_LOG_CRIT("failed to create packet RX poll thread");
        g_running = 0;
        if (g_l3_tap_thread_started)
            pthread_join(g_l3_tap_thread, NULL);
        pthread_mutex_lock(&g_l3_tap_lock);
        if (g_l3_tap.fd >= 0) {
            close(g_l3_tap.fd);
            g_l3_tap.fd = -1;
        }
        pthread_mutex_unlock(&g_l3_tap_lock);
        close(listen_fd);
        (void)nl_ipc_unlink_socket(socket_path);
        pthread_cond_destroy(&worker_state.cond);
        pthread_mutex_destroy(&worker_state.lock);
        return 1;
    }
    rx_thread_started = true;

    NL_LOG_NOTICE("packetd ready");

    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);

        // Also add subscriber fds
        pthread_mutex_lock(&g_sub_lock);
        int max_fd = listen_fd;
        for (int i = 0; i < 16; i++) {
            if (g_subscribers[i].fd >= 0) {
                FD_SET(g_subscribers[i].fd, &rfds);
                if (g_subscribers[i].fd > max_fd)
                    max_fd = g_subscribers[i].fd;
            }
        }
        pthread_mutex_unlock(&g_sub_lock);

        struct timeval tv = {1, 0};
        if (select(max_fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
            punt_policy_reload_config(false);
            continue;
        }

        if (FD_ISSET(listen_fd, &rfds)) {
            nl_conn conn;
            if (nl_server_accept(listen_fd, &conn) == NL_OK) {
                packetd_peer_authority peer =
                    PACKETD_PEER_AUTHORITY_INITIALIZER;

                if (!packetd_peer_authority_capture(&conn, &peer)) {
                    NL_LOG_WARN("packetd rejected unstable peer "
                                "uid=%d gid=%d pid=%d",
                                (int)conn.peer_uid, (int)conn.peer_gid,
                                (int)conn.peer_pid);
                    close(conn.fd);
                    continue;
                }
                if (!packetd_start_worker(
                        &worker_state, socket_path, &conn, &peer)) {
                    NL_LOG_DBG("packetd connection worker limit reached; "
                               "closing uid=%d gid=%d pid=%d",
                               (int)conn.peer_uid, (int)conn.peer_gid,
                               (int)conn.peer_pid);
                    packetd_peer_authority_close(&peer);
                    close(conn.fd);
                    continue;
                }
            }
        }

        pthread_mutex_lock(&g_sub_lock);
        for (int i = 0; i < 16; i++) {
            if (g_subscribers[i].fd < 0)
                continue;
            if (!packetd_peer_authority_revalidate(
                    &g_subscribers[i].authority)) {
                close_subscriber(i);
                continue;
            }
            if (!FD_ISSET(g_subscribers[i].fd, &rfds))
                continue;
            char tmp;
            ssize_t r = recv(g_subscribers[i].fd, &tmp, 1,
                             MSG_PEEK | MSG_DONTWAIT);
            if (r > 0 || r == 0 ||
                (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
                close_subscriber(i);
        }
        pthread_mutex_unlock(&g_sub_lock);
    }

    // Cleanup
    close(listen_fd);
    (void)nl_ipc_unlink_socket(socket_path);
    packetd_wait_for_workers(&worker_state);
    if (g_l3_tap_thread_started)
        pthread_join(g_l3_tap_thread, NULL);
    if (rx_thread_started)
        pthread_join(rx_thread, NULL);
    pthread_mutex_lock(&g_l3_tap_lock);
    if (g_l3_tap.fd >= 0) {
        close(g_l3_tap.fd);
        g_l3_tap.fd = -1;
    }
    pthread_mutex_unlock(&g_l3_tap_lock);
    pthread_mutex_lock(&g_sub_lock);
    for (int i = 0; i < 16; i++)
        close_subscriber(i);
    pthread_mutex_unlock(&g_sub_lock);
    pthread_cond_destroy(&worker_state.cond);
    pthread_mutex_destroy(&worker_state.lock);
    NL_LOG_NOTICE("packetd stopped");
    return 0;
}
