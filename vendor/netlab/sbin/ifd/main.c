#include "netlab/daemon.h"
#include "netlab/error.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include "netlab/journal.h"
#include "netlab/log.h"
#include "netlab/yang_config.h"
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define IFD_SOCKET "/var/run/netlab/ifd.sock"
#define SW_SOCKET  "/var/run/netlab/switchd.sock"
#define LACP_SOCKET "/var/run/netlab/lacpd.sock"
#define MAX_IFS    128
#define DEFAULT_INTERFACE_MTU 1514
#define IFD_REFRESH_INTERVAL_SEC 2
#define IFD_SNAPSHOT_XML_MAX (64 * 1024)

typedef struct {
    char name[64];
    int port_id;
    int link_state;      // -1 unknown, 0 down, 1 up
    int hw_admin;        // -1 unknown, 0 down, 1 up
    int speed;
    int mtu;
    bool hw_present;
    bool config_present;
    bool config_disabled;
    char proto[32];
    char l2_mode[32];
    char ae_parent[64];
    char media_type[8];
    char role[16];
    char interface_type[32];
    char ethernet_mode[32];
    char capabilities[128];
    u32 flags;
    int fpc;
    int pic;
    int port_num;
    int switch_id;
    int port_index;
    int pcie_port;
    int epl_port;
    int hw_resource_id;
    int front_panel_port;
    u64 default_speed;
    u64 line_rate;
    u64 scheduler_speed;
    u64 supported_speeds[8];
    int num_speeds;
} if_state;

typedef struct {
    if_state ifs[MAX_IFS];
    int num_ifs;
    bool switchd_up;
    bool config_loaded;
    time_t last_refresh;
    pthread_mutex_t lock;
    pthread_mutex_t refresh_lock;
    pthread_cond_t refresh_cond;
    pthread_t refresh_thread;
    bool refresh_thread_started;
    bool refresh_running;
    bool refresh_requested;
    bool force_config_reload;
    u64 refresh_requested_generation;
    u64 refresh_completed_generation;
} ifd_ctx;

static ifd_ctx g_ifd;

typedef struct {
    if_state ifs[MAX_IFS];
    int num_ifs;
    bool loaded;
    time_t mtime;
    long mtime_nsec;
} ifd_config_cache;

static ifd_config_cache g_cfg_cache;

static bool ifd_request_refresh(bool force_reload, bool wait);

static void strset(char *dst, size_t dst_len, const char *src) {
    size_t copy_len;

    if (dst_len == 0)
        return;
    if (!src)
        src = "";
    copy_len = strnlen(src, dst_len - 1);
    memmove(dst, src, copy_len);
    dst[copy_len] = '\0';
}

static if_state *find_if(if_state *ifs, int count, const char *name) {
    for (int i = 0; i < count; i++) {
        if (strcmp(ifs[i].name, name) == 0)
            return &ifs[i];
    }
    return NULL;
}

static if_state *find_or_add_if(if_state *ifs, int *count, const char *name) {
    if_state *st = find_if(ifs, *count, name);

    if (st)
        return st;
    if (*count >= MAX_IFS)
        return NULL;
    st = &ifs[*count];
    memset(st, 0, sizeof(*st));
    snprintf(st->name, sizeof(st->name), "%s", name);
    st->link_state = -1;
    st->hw_admin = -1;
    st->mtu = DEFAULT_INTERFACE_MTU;
    (*count)++;
    return st;
}

static void clear_config_overlay(if_state *st) {
    if (!st)
        return;
    st->config_present = false;
    st->config_disabled = false;
    st->proto[0] = '\0';
    st->l2_mode[0] = '\0';
    st->ae_parent[0] = '\0';
    st->mtu = DEFAULT_INTERFACE_MTU;
}

static void copy_config_overlay(if_state *dst, const if_state *src) {
    if (!dst || !src)
        return;
    dst->config_present = src->config_present;
    dst->config_disabled = src->config_disabled;
    dst->mtu = src->mtu;
    strset(dst->proto, sizeof(dst->proto), src->proto);
    strset(dst->l2_mode, sizeof(dst->l2_mode), src->l2_mode);
    strset(dst->ae_parent, sizeof(dst->ae_parent), src->ae_parent);
}

static void ifname_from_port(int port_id, char *buf, size_t buflen) {
    if (!nl_ifid_logical_port_to_name(port_id, buf, buflen))
        snprintf(buf, buflen, "logical-port-%d", port_id);
}

static void apply_profile_port(if_state *st, int port_id) {
    nl_port_entry entry;

    if (!st || !nl_ifid_get_by_logical_port(port_id, &entry))
        return;
    strset(st->media_type, sizeof(st->media_type), entry.media_type);
    strset(st->role, sizeof(st->role), entry.role);
    strset(st->interface_type, sizeof(st->interface_type),
           entry.interface_type);
    strset(st->ethernet_mode, sizeof(st->ethernet_mode),
           entry.ethernet_mode);
    strset(st->capabilities, sizeof(st->capabilities), entry.capabilities);
    st->flags = entry.flags;
    st->fpc = entry.fpc;
    st->pic = entry.pic;
    st->port_num = entry.port;
    st->switch_id = entry.switch_id;
    st->port_index = entry.port_index;
    st->pcie_port = entry.pcie_port;
    st->epl_port = entry.epl_port;
    st->hw_resource_id = entry.hw_resource_id;
    st->front_panel_port = entry.front_panel_port;
    st->default_speed = entry.default_speed;
    st->line_rate = entry.line_rate;
    st->scheduler_speed = entry.scheduler_speed;
    st->num_speeds = entry.num_speeds;
    for (int i = 0; i < entry.num_speeds && i < 8; i++)
        st->supported_speeds[i] = entry.supported_speeds[i];
}

static char *read_active_config(void) {
    char path[512];
    FILE *f;
    long sz;
    char *buf;
    size_t n;

    nl_config_file_path(path, sizeof(path), "active.conf");
    f = fopen(path, "r");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 0 || sz > NETLAB_MAX_MSG) {
        fclose(f);
        return NULL;
    }
    rewind(f);

    buf = calloc(1, (size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static bool xml_tag_value(const char *begin, const char *end, const char *tag,
                          char *out, size_t out_len) {
    char open[64];
    char close[64];
    const char *p;
    const char *q;
    size_t n;

    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    p = strstr(begin, open);
    if (!p || (end && p >= end))
        return false;
    p += strlen(open);
    q = strstr(p, close);
    if (!q || (end && q > end))
        return false;
    n = (size_t)(q - p);
    if (n >= out_len)
        n = out_len - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static bool xml_attr_value(const char *begin, const char *end, const char *attr,
                           char *out, size_t out_len) {
    char needle[64];
    const char *p;
    const char *q;
    size_t n;

    if (!begin || !attr || !out || out_len == 0)
        return false;
    snprintf(needle, sizeof(needle), "%s=\"", attr);
    p = strstr(begin, needle);
    if (!p || (end && p >= end))
        return false;
    p += strlen(needle);
    q = strchr(p, '"');
    if (!q || (end && q > end))
        return false;
    n = (size_t)(q - p);
    if (n >= out_len)
        n = out_len - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static int snapshot_attr_int(const char *begin, const char *end,
                             const char *name, int default_value) {
    char value[32];

    if (!xml_attr_value(begin, end, name, value, sizeof(value)))
        return default_value;
    return atoi(value);
}

static int collect_port_snapshot(if_state *ifs, int *count) {
    char *xml;
    const char *port;
    s32 ec = 0;
    int rn;
    int observed = 0;

    if (!ifs || !count)
        return -1;
    xml = calloc(1, IFD_SNAPSHOT_XML_MAX + 1);
    if (!xml)
        return -1;
    rn = nl_rpc_call_ex(
        SW_SOCKET, NL_DAEMON_IFD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_PORT_SNAPSHOT_GET, 0,
                        (const u8 *)"counters=0", 10,
                        (u8 *)xml, IFD_SNAPSHOT_XML_MAX + 1, 5000, &ec);
    if (rn <= 0 || ec != 0 || !strstr(xml, "</port-snapshot>")) {
        free(xml);
        return -1;
    }
    xml[rn] = '\0';

    port = xml;
    while ((port = strstr(port, "<port ")) != NULL) {
        const char *tag = port;
        const char *end = strstr(port, "/>");
        char admin[16] = "unknown";
        char link[16] = "unknown";
        char name[64];
        int port_id;
        if_state *state;

        if (!end)
            break;
        port_id = snapshot_attr_int(tag, end, "id", 0);
        port = end + 2;
        if (port_id <= 0)
            continue;
        if (nl_ifid_get_by_logical_port(port_id, NULL) &&
            !nl_ifid_is_user_port(port_id))
            continue;
        if (nl_ifid_is_cpu_port(port_id))
            continue;
        ifname_from_port(port_id, name, sizeof(name));
        state = find_or_add_if(ifs, count, name);
        if (!state)
            continue;

        state->port_id = port_id;
        state->hw_present = true;
        state->speed = snapshot_attr_int(tag, end, "speed", 0);
        (void)xml_attr_value(tag, end, "admin", admin, sizeof(admin));
        (void)xml_attr_value(tag, end, "link", link, sizeof(link));
        state->hw_admin = strcmp(admin, "up") == 0 ? 1 :
            strcmp(admin, "down") == 0 ? 0 : -1;
        state->link_state = strcmp(link, "up") == 0 ? 1 :
            strcmp(link, "down") == 0 ? 0 : -1;
        apply_profile_port(state, port_id);
        (void)xml_attr_value(tag, end, "ethernet-mode",
                             state->ethernet_mode,
                             sizeof(state->ethernet_mode));
        observed++;
    }
    free(xml);
    return observed;
}

static void apply_config_block(if_state *st, const char *begin, const char *end) {
    char value[64];

    st->config_present = true;
    st->config_disabled = strstr(begin, "<disable>true</disable>") &&
                          (!end || strstr(begin, "<disable>true</disable>") < end);
    st->proto[0] = '\0';
    st->l2_mode[0] = '\0';
    st->ae_parent[0] = '\0';
    st->mtu = DEFAULT_INTERFACE_MTU;

    if (xml_tag_value(begin, end, "mtu", value, sizeof(value)))
        st->mtu = atoi(value);

    if (xml_tag_value(begin, end, "interface-mode", value, sizeof(value))) {
        strset(st->l2_mode, sizeof(st->l2_mode), value);
        strset(st->proto, sizeof(st->proto), "eth-switch");
    }
    if (xml_tag_value(begin, end, "vlan-members", value, sizeof(value)) && !st->proto[0])
        strset(st->proto, sizeof(st->proto), "eth-switch");
    if (xml_tag_value(begin, end, "ieee8023ad", value, sizeof(value))) {
        strset(st->ae_parent, sizeof(st->ae_parent), value);
        strset(st->proto, sizeof(st->proto), "aenet-member");
    }
    if (xml_tag_value(begin, end, "mode", value, sizeof(value)) &&
        strstr(begin, "<aggregated-ether-options>") &&
        (!end || strstr(begin, "<aggregated-ether-options>") < end)) {
        if (strcmp(value, "active") == 0)
            strset(st->l2_mode, sizeof(st->l2_mode), "lacp-active");
        else if (strcmp(value, "passive") == 0)
            strset(st->l2_mode, sizeof(st->l2_mode), "lacp-passive");
        else
            strset(st->l2_mode, sizeof(st->l2_mode), "lacp-unknown");
        strset(st->proto, sizeof(st->proto), "aenet");
    }
}

static bool config_validates(const char *xml) {
    bool ok = false;
    nl_yang_session *s = nl_yang_session_create(NULL);
    struct lyd_node *tree;

    if (!s)
        return false;
    tree = nl_yang_from_xml(s, xml);
    if (tree) {
        ok = true;
        lyd_free_all(tree);
    }
    nl_yang_session_destroy(s);
    return ok;
}

static bool reload_active_config_cache(bool force) {
    struct stat st;
    char active_path[512];
    time_t mtime = 0;
    long mtime_nsec = 0;
    char *xml = NULL;
    const char *section;
    const char *section_end;
    const char *p;

    nl_config_file_path(active_path, sizeof(active_path), "active.conf");
    if (stat(active_path, &st) == 0) {
        mtime = st.st_mtime;
        mtime_nsec = st.st_mtim.tv_nsec;
    }
    if (!force && mtime == g_cfg_cache.mtime &&
        mtime_nsec == g_cfg_cache.mtime_nsec)
        return g_cfg_cache.loaded;

    memset(g_cfg_cache.ifs, 0, sizeof(g_cfg_cache.ifs));
    g_cfg_cache.num_ifs = 0;
    g_cfg_cache.loaded = false;
    g_cfg_cache.mtime = mtime;
    g_cfg_cache.mtime_nsec = mtime_nsec;

    xml = read_active_config();
    if (!xml)
        return false;
    if (!config_validates(xml)) {
        free(xml);
        return false;
    }

    section = strstr(xml, "<interfaces>");
    section_end = section ? strstr(section, "</interfaces>") : NULL;
    g_cfg_cache.loaded = true;
    if (!section || !section_end) {
        free(xml);
        return true;
    }

    p = section;
    while ((p = strstr(p, "<interface>")) && p < section_end) {
        const char *end = strstr(p, "</interface>");
        char name[64];
        if (!end || end > section_end)
            break;
        if (xml_tag_value(p, end, "name", name, sizeof(name))) {
            nl_port_entry entry;
            if_state *st;
            if (nl_ifid_get_by_name(name, &entry) &&
                !nl_ifid_is_user_port(entry.logical_port)) {
                p = end + strlen("</interface>");
                continue;
            }
            st = find_or_add_if(g_cfg_cache.ifs, &g_cfg_cache.num_ifs, name);
            if (st)
                apply_config_block(st, p, end);
        }
        p = end + strlen("</interface>");
    }
    free(xml);
    return true;
}

static bool apply_active_config(if_state *ifs, int *count, bool force) {
    bool loaded = reload_active_config_cache(force);

    for (int i = 0; i < *count; i++)
        clear_config_overlay(&ifs[i]);
    if (loaded) {
        for (int i = 0; i < g_cfg_cache.num_ifs; i++) {
            if_state *dst = find_or_add_if(ifs, count, g_cfg_cache.ifs[i].name);
            if (dst)
                copy_config_overlay(dst, &g_cfg_cache.ifs[i]);
        }
    }
    return loaded;
}

static void apply_lacp_state(if_state *ifs, int *count) {
    char xml[8192] = {0};
    s32 ec = 0;
    int rn;
    char *lag;
    char value[32];

    rn = nl_rpc_call_ex(LACP_SOCKET, NL_DAEMON_IFD, NL_DAEMON_LACPD,
                        NL_LACPD_SHOW, 0, (const u8 *)"", 0, (u8 *)xml,
                        sizeof(xml) - 1, 1000, &ec);
    if (rn <= 0 || ec != 0)
        return;
    xml[rn] = '\0';

    lag = xml;
    while ((lag = strstr(lag, "<lag "))) {
        char *lag_end = strstr(lag, "</lag>");
        char name[32] = {0};
        char status[16] = {0};
        if (!lag_end)
            break;
        if (!xml_attr_value(lag, lag_end, "name", name, sizeof(name))) {
            lag = lag_end + strlen("</lag>");
            continue;
        }
        if_state *ae = find_or_add_if(ifs, count, name);
        if (ae) {
            if (xml_attr_value(lag, lag_end, "logical-port",
                               value, sizeof(value)))
                ae->port_id = atoi(value);
            (void)xml_attr_value(lag, lag_end, "status",
                                 status, sizeof(status));
            ae->hw_present = true;
            ae->link_state = strcmp(status, "up") == 0 ? 1 : 0;
            ae->hw_admin = ae->config_disabled ? 0 : 1;
        }
        lag = lag_end + strlen("</lag>");
    }
}

static void refresh_state(bool force_config_reload) {
    if_state next[MAX_IFS];
    int next_count = 0;
    int n_ports;
    bool switchd_up = false;
    bool config_loaded;

    memset(next, 0, sizeof(next));
    n_ports = collect_port_snapshot(next, &next_count);
    if (n_ports >= 0) {
        switchd_up = true;
    } else {
        pthread_mutex_lock(&g_ifd.lock);
        memcpy(next, g_ifd.ifs, sizeof(next));
        next_count = g_ifd.num_ifs;
        pthread_mutex_unlock(&g_ifd.lock);

        for (int i = 0; i < next_count; i++) {
            next[i].link_state = -1;
            next[i].hw_admin = -1;
        }
    }

    config_loaded = apply_active_config(next, &next_count, force_config_reload);
    apply_lacp_state(next, &next_count);

    pthread_mutex_lock(&g_ifd.lock);
    memcpy(g_ifd.ifs, next, sizeof(g_ifd.ifs));
    g_ifd.num_ifs = next_count;
    g_ifd.switchd_up = switchd_up;
    g_ifd.config_loaded = config_loaded;
    g_ifd.last_refresh = time(NULL);
    pthread_mutex_unlock(&g_ifd.lock);
}

static const char *link_text(int link_state) {
    if (link_state == 1)
        return "up";
    if (link_state == 0)
        return "down";
    return "unknown";
}

static const char *admin_text(const if_state *st) {
    if (st->config_present)
        return st->config_disabled ? "down" : "up";
    if (st->hw_admin == 1)
        return "up";
    if (st->hw_admin == 0)
        return "down";
    return "unknown";
}

static const char *hw_sync_text(const if_state *st) {
    if (!st->hw_present)
        return "not-applicable";
    return g_ifd.switchd_up ? "in-sync" : "out-of-sync";
}

static bool append_ifd_text(char *buf, size_t size, size_t *off,
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

static int build_interfaces_terse(char *buf, size_t buf_sz) {
    size_t off = 0;
    bool ok;

    pthread_mutex_lock(&g_ifd.lock);
    ok = append_ifd_text(
        buf, buf_sz, &off,
        "<interfaces switchd=\"%s\" config=\"%s\" last-refresh=\"%ld\">\n",
        g_ifd.switchd_up ? "up" : "down",
        g_ifd.config_loaded ? "loaded" : "missing",
        (long)g_ifd.last_refresh);

    for (int i = 0; ok && i < g_ifd.num_ifs; i++) {
        if_state *st = &g_ifd.ifs[i];
        ok = append_ifd_text(buf, buf_sz, &off,
            "  <interface>\n"
            "    <name>%s</name>\n"
            "    <admin>%s</admin>\n"
            "    <link>%s</link>\n"
            "    <proto>%s</proto>\n"
            "  </interface>\n",
            st->name, admin_text(st), link_text(st->link_state), st->proto);
    }
    if (ok)
        ok = append_ifd_text(buf, buf_sz, &off, "</interfaces>\n");
    pthread_mutex_unlock(&g_ifd.lock);
    return ok ? (int)off : -1;
}

static int build_interface_detail(const char *name, char *buf, size_t buf_sz) {
    size_t off = 0;
    bool ok = true;
    bool all = !name || !name[0];

    pthread_mutex_lock(&g_ifd.lock);
    if (all)
        ok = append_ifd_text(buf, buf_sz, &off, "<interfaces>\n");
    for (int i = 0; ok && i < g_ifd.num_ifs; i++) {
        if_state *st = &g_ifd.ifs[i];
        if (!all && strcmp(st->name, name) != 0)
            continue;

        ok = append_ifd_text(buf, buf_sz, &off,
            "<interface>\n"
            "  <name>%s</name>\n"
            "  <port-id>%d</port-id>\n"
            "  <admin-state>%s</admin-state>\n"
            "  <link-state>%s</link-state>\n"
            "  <speed>%d</speed>\n"
            "  <mtu>%d</mtu>\n"
            "  <default-speed>%llu</default-speed>\n"
            "  <media-type>%s</media-type>\n"
            "  <role>%s</role>\n"
            "  <interface-type>%s</interface-type>\n"
            "  <ethernet-mode>%s</ethernet-mode>\n"
            "  <capabilities>%s</capabilities>\n"
            "  <fpc>%d</fpc>\n"
            "  <pic>%d</pic>\n"
            "  <port>%d</port>\n"
            "  <switch-index>%d</switch-index>\n"
            "  <port-index>%d</port-index>\n"
            "  <pcie-port>%d</pcie-port>\n"
            "  <epl-port>%d</epl-port>\n"
            "  <hw-resource-id>%d</hw-resource-id>\n"
            "  <front-panel-port>%d</front-panel-port>\n"
            "  <flags>%u</flags>\n"
            "  <line-rate>%llu</line-rate>\n"
            "  <scheduler-speed>%llu</scheduler-speed>\n"
            "  <l2-mode>%s</l2-mode>\n"
            "  <proto>%s</proto>\n"
            "  <hw-sync>%s</hw-sync>\n",
            st->name, st->port_id, admin_text(st),
            link_text(st->link_state), st->speed, st->mtu,
            (unsigned long long)st->default_speed,
            st->media_type, st->role, st->interface_type,
            st->ethernet_mode, st->capabilities,
            st->fpc, st->pic, st->port_num, st->switch_id,
            st->port_index, st->pcie_port, st->epl_port,
            st->hw_resource_id, st->front_panel_port, st->flags,
            (unsigned long long)st->line_rate,
            (unsigned long long)st->scheduler_speed,
            st->l2_mode[0] ? st->l2_mode : "none",
            st->proto, hw_sync_text(st));
        if (st->num_speeds > 0) {
            ok = append_ifd_text(buf, buf_sz, &off,
                                 "  <supported-speeds>");
            for (int j = 0; ok && j < st->num_speeds && j < 8; j++) {
                ok = append_ifd_text(
                    buf, buf_sz, &off, "%s%llu", j ? "," : "",
                    (unsigned long long)st->supported_speeds[j]);
            }
            if (ok)
                ok = append_ifd_text(buf, buf_sz, &off,
                                     "</supported-speeds>\n");
        }
        if (ok && st->ae_parent[0])
            ok = append_ifd_text(buf, buf_sz, &off,
                                 "  <aggregate>%s</aggregate>\n",
                                 st->ae_parent);
        if (ok)
            ok = append_ifd_text(buf, buf_sz, &off, "</interface>\n");
        if (!all)
            break;
    }
    if (ok && all)
        ok = append_ifd_text(buf, buf_sz, &off, "</interfaces>\n");
    pthread_mutex_unlock(&g_ifd.lock);
    if (!ok)
        return -1;
    if (off == 0) {
        int n = snprintf(buf, buf_sz,
            "<interface>\n"
            "  <name>%s</name>\n"
            "  <admin-state>unknown</admin-state>\n"
            "  <link-state>unknown</link-state>\n"
            "  <l2-mode>none</l2-mode>\n"
            "  <hw-sync>not-found</hw-sync>\n"
            "</interface>\n", name ? name : "");
        if (n < 0 || (size_t)n >= buf_sz)
            return -1;
        off = (size_t)n;
    }
    return (int)off;
}

static int handle_get_interfaces(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, NETLAB_MAX_MSG);
    int off;
    char req[256] = {0};

    if (!buf) {
        nl_send_response(conn, msg->request_id, NL_ERR);
        return 0;
    }
    if (msg->payload_len >= sizeof(req) ||
        (msg->payload_len > 0 &&
         memchr(msg->payload, '\0', msg->payload_len) != NULL)) {
        free(buf);
        nl_send_response(conn, msg->request_id, NL_ERR_MALFORMED_REQUEST);
        return 0;
    }
    if (msg->payload_len > 0)
        memcpy(req, msg->payload, msg->payload_len);

    if (strstr(req, "detail name=")) {
        char *np = strstr(req, "name=");
        off = build_interface_detail(np ? np + 5 : "", buf,
                                     NETLAB_MAX_MSG);
    } else if (strcmp(req, "detail") == 0) {
        off = build_interface_detail("", buf, NETLAB_MAX_MSG);
    } else {
        off = build_interfaces_terse(buf, NETLAB_MAX_MSG);
    }
    if (off < 0) {
        free(buf);
        nl_send_response(conn, msg->request_id,
                         NL_ERR_CAPABILITY_INSUFFICIENT);
        return 0;
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
    return 0;
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

static int ifd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    (void)ctx;
    switch (msg->method) {
    case NL_IFD_SHOW_INTERFACES:
        return handle_get_interfaces(conn, msg);
    case NL_IFD_RELOAD:
        if (ifd_request_refresh(true, true))
            send_text_response(conn, msg, 0, "ifd reload complete");
        else
            send_text_response(conn, msg, NL_ERR_DAEMON_UNREACHABLE,
                               "ifd refresh worker is unavailable");
        return 0;
    case NL_IFD_COMPAT_METHOD_3:
    case NL_IFD_COMPAT_METHOD_4:
        nl_send_response(conn, msg->request_id, NL_OK);
        return 0;
    default:
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }
}

static void *ifd_refresh_main(void *arg) {
    ifd_ctx *state = arg;

    for (;;) {
        struct timespec deadline;
        bool force_reload;
        u64 target_generation;

        pthread_mutex_lock(&state->refresh_lock);
        if (state->refresh_running && !state->refresh_requested) {
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += IFD_REFRESH_INTERVAL_SEC;
            (void)pthread_cond_timedwait(&state->refresh_cond,
                                         &state->refresh_lock, &deadline);
        }
        if (!state->refresh_running) {
            pthread_mutex_unlock(&state->refresh_lock);
            break;
        }
        force_reload = state->force_config_reload;
        target_generation = state->refresh_requested_generation;
        state->refresh_requested = false;
        state->force_config_reload = false;
        pthread_mutex_unlock(&state->refresh_lock);

        refresh_state(force_reload);

        pthread_mutex_lock(&state->refresh_lock);
        if (target_generation > state->refresh_completed_generation)
            state->refresh_completed_generation = target_generation;
        pthread_cond_broadcast(&state->refresh_cond);
        pthread_mutex_unlock(&state->refresh_lock);
    }
    return NULL;
}

static bool ifd_request_refresh(bool force_reload, bool wait) {
    u64 generation;

    pthread_mutex_lock(&g_ifd.refresh_lock);
    if (!g_ifd.refresh_running) {
        pthread_mutex_unlock(&g_ifd.refresh_lock);
        return false;
    }
    generation = ++g_ifd.refresh_requested_generation;
    g_ifd.refresh_requested = true;
    if (force_reload)
        g_ifd.force_config_reload = true;
    pthread_cond_signal(&g_ifd.refresh_cond);
    while (wait && g_ifd.refresh_running &&
           g_ifd.refresh_completed_generation < generation)
        pthread_cond_wait(&g_ifd.refresh_cond, &g_ifd.refresh_lock);
    bool completed = !wait ||
        g_ifd.refresh_completed_generation >= generation;
    pthread_mutex_unlock(&g_ifd.refresh_lock);
    return completed;
}

static int ifd_on_init(void *ctx) {
    (void)ctx;
    memset(&g_ifd, 0, sizeof(g_ifd));
    memset(&g_cfg_cache, 0, sizeof(g_cfg_cache));
    pthread_mutex_init(&g_ifd.lock, NULL);
    pthread_mutex_init(&g_ifd.refresh_lock, NULL);
    pthread_cond_init(&g_ifd.refresh_cond, NULL);
    refresh_state(true);
    g_ifd.refresh_running = true;
    if (pthread_create(&g_ifd.refresh_thread, NULL,
                       ifd_refresh_main, &g_ifd) != 0) {
        g_ifd.refresh_running = false;
        pthread_cond_destroy(&g_ifd.refresh_cond);
        pthread_mutex_destroy(&g_ifd.refresh_lock);
        pthread_mutex_destroy(&g_ifd.lock);
        return -1;
    }
    g_ifd.refresh_thread_started = true;
    NL_LOG_NOTICE("ifd ready (%d interfaces, switchd=%s)",
                  g_ifd.num_ifs, g_ifd.switchd_up ? "up" : "down");
    return 0;
}

static void ifd_on_stopping(void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&g_ifd.refresh_lock);
    g_ifd.refresh_running = false;
    pthread_cond_broadcast(&g_ifd.refresh_cond);
    pthread_mutex_unlock(&g_ifd.refresh_lock);
}

static void ifd_on_shutdown(void *ctx) {
    (void)ctx;
    if (g_ifd.refresh_thread_started)
        pthread_join(g_ifd.refresh_thread, NULL);
    pthread_cond_destroy(&g_ifd.refresh_cond);
    pthread_mutex_destroy(&g_ifd.refresh_lock);
    pthread_mutex_destroy(&g_ifd.lock);
}

int main(int argc, char *argv[]) {
    nl_daemon_config cfg = {
        .name        = "ifd",
        .socket_path = IFD_SOCKET,
        .service_id  = NL_DAEMON_IFD,
        .auth_mode   = NL_DAEMON_AUTH_STANDARD,
        .dispatch    = ifd_dispatch,
        .ctx         = NULL,
        .on_init     = ifd_on_init,
        .on_stopping = ifd_on_stopping,
        .on_shutdown = ifd_on_shutdown,
        .max_concurrent_handlers = 4,
    };

    (void)argc;
    (void)argv;
    return nl_daemon_run(&cfg);
}
