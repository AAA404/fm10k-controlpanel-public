/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "igmp_snooping.h"
#include "igmp_state.h"

#include "l2_plan_internal.h"
#include "l2d_paths.h"
#include "l2d_switchd.h"
#include "netlab/interface_id.h"
#include "netlab/journal.h"
#include "netlab/log.h"
#include "netlab/yang_config.h"
#include "netlab/port_scope.h"
#include "netlab/packet_event.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define IGMP_ETHERTYPE 0x0800
#define IGMP_DEFAULT_MEMBERSHIP_TIMEOUT 260
#define IGMP_ROUTER_WRITE_BUDGET 16
#define IGMP_MEMBER_WRITE_BUDGET 16
#define IGMP_MAX_VLANS 256
#define IGMP_MAX_SCOPES 1024
#define IGMP_CONFIG_BYTES 262144
#define IGMP_SHOW_BYTES (240 * 1024)
#define IGMP_PACKETD_IO_TIMEOUT_MS 2000U

typedef struct {
    int vid;
    int port;
    bool fast_leave;
    bool mrouter;
} igmp_vlan_port_scope;

typedef struct {
    pthread_mutex_t lock;
    pthread_t thread;
    bool thread_started;
    atomic_bool thread_running;
    int stop_fd;
    bool enabled;
    int membership_timeout;
    int vlans[IGMP_MAX_VLANS];
    int n_vlans;
    igmp_vlan_port_scope scopes[IGMP_MAX_SCOPES];
    int n_scopes;
    cfg_igmp_listener_intent static_members[CFG_IGMP_STATIC_MAX_MEMBERS];
    int n_static_members;
    igmp_runtime_image runtime;
    bool checkpoint_error;
    unsigned recovered_members;
    unsigned router_cursor;
    unsigned dynamic_cursor;
    u64 reports;
    u64 leaves;
    u64 aged;
    u64 invalid;
    u64 rx_events;
    u64 ignored_scope;
    u64 apply_failures;
    int last_port;
    int last_vid;
    int last_resolved_vid;
    u8 last_type;
    char last_group[16];
} igmp_owner_state;

static igmp_owner_state g_igmp;
static igmp_state_store g_igmp_store = {.directory = -1, .lock = -1};
static bool owner_has_listener(const char *owner, int vid, int port, const u8 mac[6]);

static bool checkpoint_locked(void) {
    bool ok = igmp_state_save(&g_igmp_store, &g_igmp.runtime) == 0;
    if (!ok && !g_igmp.checkpoint_error)
        NL_LOG_ERR("IGMP runtime checkpoint failed; hardware updates require a saved ownership record");
    g_igmp.checkpoint_error = !ok;
    return ok;
}

static bool append_output(char *buf, size_t size, int *off,
                          const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !off || *off < 0 || (size_t)*off >= size)
        return false;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, size - (size_t)*off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= size - (size_t)*off) {
        buf[size - 1] = '\0';
        return false;
    }
    *off += n;
    return true;
}

static const char *config_dir(void) {
    const char *dir = getenv("NETLAB_CONFIG_DIR");

    return dir && dir[0] ? dir : NL_CONFIG_DIR;
}

static u16 checksum16(const u8 *data, int len) {
    u32 sum = 0;

    while (len > 1) {
        sum += ((u32)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }
    if (len == 1)
        sum += (u32)data[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return (u16)~sum;
}

static bool vlan_enabled_locked(int vid) {
    if (!g_igmp.enabled)
        return false;
    for (int i = 0; i < g_igmp.n_vlans; i++)
        if (g_igmp.vlans[i] == vid)
            return true;
    return false;
}

static bool scope_enabled_locked(int vid, int port) {
    if (!vlan_enabled_locked(vid))
        return false;
    for (int i = 0; i < g_igmp.n_scopes; i++)
        if (g_igmp.scopes[i].vid == vid && g_igmp.scopes[i].port == port)
            return true;
    return false;
}

static int resolve_scope_vid_locked(int reported_vid, int port) {
    int resolved = -1;

    if (reported_vid != 0)
        return scope_enabled_locked(reported_vid, port) ? reported_vid : -1;
    for (int i = 0; i < g_igmp.n_scopes; i++) {
        if (g_igmp.scopes[i].port != port)
            continue;
        if (resolved >= 0 && resolved != g_igmp.scopes[i].vid)
            return -1;
        resolved = g_igmp.scopes[i].vid;
    }
    return resolved;
}

static bool same_hardware_key(int vid, int port, const u8 mac[6],
                              const igmp_dynamic_member *member) {
    return member->used && member->vid == vid && member->port == port &&
           memcmp(member->mac, mac, 6) == 0;
}

static bool hardware_referenced_locked(int vid, int port, const u8 mac[6]) {
    for (int i = 0; i < g_igmp.n_static_members; i++) {
        if (g_igmp.static_members[i].vid == vid &&
            g_igmp.static_members[i].port.hw_port == port &&
            memcmp(g_igmp.static_members[i].mac, mac, 6) == 0)
            return true;
    }
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; i++)
        if (same_hardware_key(vid, port, mac, &g_igmp.runtime.dynamic[i]))
            return true;
    return false;
}

static bool hardware_key_pending_locked(int vid, int port, const u8 mac[6]) {
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; ++i) {
        const igmp_dynamic_member *m = &g_igmp.runtime.dynamic[i];
        if (same_hardware_key(vid, port, mac, m) && (m->pending || m->retiring)) return true;
    }
    return false;
}

static void mark_dynamic_key_locked(int vid, int port, const u8 mac[6], bool pending) {
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; ++i) {
        igmp_dynamic_member *m = &g_igmp.runtime.dynamic[i];
        if (same_hardware_key(vid, port, mac, m) && !m->retiring) m->pending = pending;
    }
}

static bool dynamic_group_present_locked(int vid, const u8 mac[6]) {
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; ++i) {
        const igmp_dynamic_member *m = &g_igmp.runtime.dynamic[i];
        if (m->used && !m->retiring && m->vid == vid && !memcmp(m->mac, mac, 6) &&
            scope_enabled_locked(vid, m->port)) return true;
    }
    return false;
}

static u32 router_ports_locked(int vid) {
    u32 mask = 0;
    if (!vlan_enabled_locked(vid)) return 0;
    for (int i = 0; i < g_igmp.n_scopes; ++i) {
        const igmp_vlan_port_scope *s = &g_igmp.scopes[i];
        if (s->vid == vid && s->mrouter && s->port >= 1 && s->port <= 24)
            mask |= 1U << (s->port - 1);
    }
    return mask;
}

static bool router_needed_locked(int vid, int port, const u8 mac[6]) {
    return port >= 1 && port <= 24 && (router_ports_locked(vid) & (1U << (port - 1))) &&
        dynamic_group_present_locked(vid, mac);
}

static u64 next_txid_locked(void) {
    g_igmp.runtime.tx_sequence++;
    if (g_igmp.runtime.tx_sequence == 0)
        g_igmp.runtime.tx_sequence++;
    return ((u64)time(NULL) << 32) | (g_igmp.runtime.tx_sequence & 0xffffffffULL);
}

static int apply_listener_locked(bool add, int vid, int port,
                                 const char *group) {
    if (!nl_port_scope_enter(port)) return NL_ERR_RPC_BUSY;
    u64 txid = next_txid_locked();
    int rc = !checkpoint_locked() ? NL_ERR_HW_STATE_OUT_OF_SYNC : l2d_switchd_apply_igmp_listener(
        l2d_switchd_socket_path(), add, vid, port, group,
        txid);

    if (rc != 0)
        g_igmp.apply_failures++;
    nl_port_scope_leave(port);
    return rc;
}

static void sync_router_groups_locked(const char *owner, unsigned budget) {
    /* Track a hardware MAC/VLAN key, not one record per IP alias or router.
     * Removed memberships survive failed deletes and are retried on a later
     * tick. Each pass has a fixed SDK-write budget. */
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; ++i) {
        const igmp_dynamic_member *m = &g_igmp.runtime.dynamic[i];
        if (!m->used || m->retiring || !scope_enabled_locked(m->vid, m->port) || !router_ports_locked(m->vid)) continue;
        int free_slot = -1;
        bool found = false;
        for (int j = 0; j < IGMP_MAX_ROUTER_GROUPS; ++j) {
            igmp_router_group *r = &g_igmp.runtime.router_groups[j];
            if (!r->used && free_slot < 0) free_slot = j;
            if (r->used && r->vid == m->vid && !memcmp(r->mac, m->mac, 6)) { found = true; break; }
        }
        if (found) continue;
        if (free_slot < 0) { ++g_igmp.apply_failures; continue; }
        igmp_router_group *r = &g_igmp.runtime.router_groups[free_slot];
        *r = (igmp_router_group){.used = true, .vid = m->vid};
        memcpy(r->mac, m->mac, 6);
        snprintf(r->group, sizeof(r->group), "%s", m->group);
    }
    unsigned start = g_igmp.router_cursor;
    for (unsigned step = 0; step < IGMP_MAX_ROUTER_GROUPS; ++step) {
        unsigned i = (start + step) % IGMP_MAX_ROUTER_GROUPS;
        igmp_router_group *r = &g_igmp.runtime.router_groups[i];
        if (!r->used) continue;
        u32 wanted = dynamic_group_present_locked(r->vid, r->mac) ? router_ports_locked(r->vid) : 0;
        for (int port = 1; port <= 24; ++port) {
            u32 bit = 1U << (port - 1);
            if (owner && (wanted & bit) && owner_has_listener(owner, r->vid, port, r->mac)) {
                r->applied_ports |= bit;
                r->uncertain_ports &= ~bit;
            }
            if (owner && (wanted & r->applied_ports & bit) &&
                !owner_has_listener(owner, r->vid, port, r->mac)) r->applied_ports &= ~bit;
            bool add = (wanted & bit) != 0;
            if (add == ((r->applied_ports & bit) != 0) && !(r->uncertain_ports & bit)) continue;
            if (!add && hardware_referenced_locked(r->vid, port, r->mac)) {
                r->applied_ports &= ~bit;
                r->uncertain_ports &= ~bit;
                continue;
            }
            if (!budget || nl_port_scope_paused(port)) continue;
            --budget;
            r->uncertain_ports |= bit;
            if (apply_listener_locked(add, r->vid, port, r->group) == 0) {
                if (add) r->applied_ports |= bit;
                else r->applied_ports &= ~bit;
                r->uncertain_ports &= ~bit;
            }
            if (!budget) g_igmp.router_cursor = (i + 1) % IGMP_MAX_ROUTER_GROUPS;
        }
        if (!wanted && !r->applied_ports && !r->uncertain_ports) memset(r, 0, sizeof(*r));
    }
    (void)checkpoint_locked();
}

static bool remove_dynamic_locked(int index) {
    igmp_dynamic_member removed = g_igmp.runtime.dynamic[index];
    if (!nl_port_scope_enter(removed.port)) return false;
    removed.retiring = removed.pending = true;
    g_igmp.runtime.dynamic[index] = removed;
    if (!checkpoint_locked()) { nl_port_scope_leave(removed.port); return false; }
    /* Calculate other ownership without dropping the durable tombstone from
     * the image that the delete RPC checkpoints. */
    memset(&g_igmp.runtime.dynamic[index], 0, sizeof(g_igmp.runtime.dynamic[index]));
    bool shared = hardware_referenced_locked(removed.vid, removed.port, removed.mac) ||
                  router_needed_locked(removed.vid, removed.port, removed.mac);
    g_igmp.runtime.dynamic[index] = removed;
    if (!shared &&
        apply_listener_locked(false, removed.vid, removed.port, removed.group) != 0) {
        nl_port_scope_leave(removed.port);
        return false;
    }
    memset(&g_igmp.runtime.dynamic[index], 0, sizeof(g_igmp.runtime.dynamic[index]));
    (void)checkpoint_locked();
    nl_port_scope_leave(removed.port);
    return true;
}

static int collect_port_refs(cfg_port_ref *ports, int max_ports) {
    nl_port_entry inventory[NL_MAX_PORTS_PER_PROFILE];
    int count = nl_ifid_get_all(inventory, NL_MAX_PORTS_PER_PROFILE);
    int n = 0;

    for (int i = 0; i < count && n < max_ports; i++) {
        if (!nl_ifid_is_user_port(inventory[i].logical_port))
            continue;
        snprintf(ports[n].name, sizeof(ports[n].name), "%s",
                 inventory[i].canonical_name);
        ports[n].hw_port = inventory[i].logical_port;
        ports[n].is_aggregate = false;
        ports[n].ae_id = -1;
        ports[n].flags = inventory[i].flags;
        n++;
    }
    return n;
}

static int port_ref_by_name(const cfg_port_ref *ports, int n_ports,
                            const char *name) {
    for (int i = 0; i < n_ports; i++)
        if (strcmp(ports[i].name, name) == 0)
            return ports[i].hw_port;
    return -1;
}

static int collect_enabled_vlans(nl_yang_session *ys, const char *xml,
                                 int *vlans, int max_vlans,
                                 const cfg_port_ref *ports, int n_ports,
                                 igmp_vlan_port_scope *scopes,
                                 int max_scopes, int *n_scopes) {
    const char *igmp = strstr(xml, "<igmp-snooping>");
    const char *igmp_end = igmp ? strstr(igmp, "</igmp-snooping>") : NULL;
    const char *p = igmp;
    int n = 0;

    *n_scopes = 0;

    while (igmp && igmp_end && (p = strstr(p, "<vlan>")) && p < igmp_end &&
           n < max_vlans) {
        const char *end = strstr(p, "</vlan>");
        char name[64] = {0};
        int vid;

        if (!end || end > igmp_end)
            break;
        if (l2_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0) {
            vid = l2_get_vlan_id(ys, name);
            if (vid >= 1 && vid <= 4094) {
                const char *iface = p;

                vlans[n++] = vid;
                while ((iface = strstr(iface, "<interface>")) && iface < end &&
                       *n_scopes < max_scopes) {
                    const char *iface_end = strstr(iface, "</interface>");
                    char ifname[64] = {0};
                    int port;

                    if (!iface_end || iface_end > end)
                        break;
                    if (l2_extract_xml_leaf(iface, iface_end, "name", ifname,
                                            sizeof(ifname)) == 0 &&
                        (port = port_ref_by_name(ports, n_ports, ifname)) > 0) {
                        scopes[*n_scopes].vid = vid;
                        scopes[*n_scopes].port = port;
                        char fast[16] = {0};
                        char router[16] = {0};
                        char direct_path[256];
                        snprintf(direct_path, sizeof(direct_path),
                            "/netlab:netlab-config/interfaces/interface[name='%s']/fm10k-port/direct-receiver", ifname);
                        const char *direct = nl_yang_get(ys, direct_path);
                        scopes[*n_scopes].fast_leave = direct && strcmp(direct, "true") == 0 &&
                            l2_extract_xml_leaf(iface, iface_end, "fast-leave", fast, sizeof(fast)) == 0 &&
                            strcmp(fast, "true") == 0;
                        scopes[*n_scopes].mrouter =
                            l2_extract_xml_leaf(iface, iface_end, "mrouter", router, sizeof(router)) == 0 &&
                            strcmp(router, "true") == 0;
                        (*n_scopes)++;
                    }
                    iface = iface_end + strlen("</interface>");
                }
            }
        }
        p = end + strlen("</vlan>");
    }
    return n;
}

static bool load_config(bool *enabled, int *timeout, int *vlans,
                        int *n_vlans, igmp_vlan_port_scope *scopes,
                        int *n_scopes,
                        cfg_igmp_listener_intent *static_members,
                        int *n_static_members) {
    char path[512];
    char *xml = NULL;
    FILE *file = NULL;
    nl_yang_session *ys = NULL;
    struct lyd_node *tree;
    cfg_port_ref ports[NL_MAX_PORTS_PER_PROFILE];
    char timeout_text[32] = {0};
    const char *igmp;
    const char *igmp_end;
    size_t n;
    int n_ports;
    bool ok = false;

    snprintf(path, sizeof(path), "%s/active.conf", config_dir());
    file = fopen(path, "r");
    if (!file)
        goto done;
    xml = calloc(1, IGMP_CONFIG_BYTES);
    if (!xml)
        goto done;
    n = fread(xml, 1, IGMP_CONFIG_BYTES - 1, file);
    if (n == 0 || n >= IGMP_CONFIG_BYTES - 1)
        goto done;
    xml[n] = '\0';
    ys = nl_yang_session_create(NULL);
    if (!ys)
        goto done;
    tree = nl_yang_from_xml(ys, xml);
    if (!tree)
        goto done;
    nl_yang_data_set(ys, tree);

    igmp = strstr(xml, "<igmp-snooping>");
    igmp_end = igmp ? strstr(igmp, "</igmp-snooping>") : NULL;
    *enabled = igmp != NULL && igmp_end != NULL;
    *timeout = IGMP_DEFAULT_MEMBERSHIP_TIMEOUT;
    if (*enabled && l2_extract_xml_leaf(igmp, igmp_end,
                                        "membership-timeout", timeout_text,
                                        sizeof(timeout_text)) == 0) {
        int value = atoi(timeout_text);
        if (value >= 10 && value <= 3600)
            *timeout = value;
    }
    n_ports = collect_port_refs(ports, NL_MAX_PORTS_PER_PROFILE);
    *n_vlans = *enabled ? collect_enabled_vlans(
        ys, xml, vlans, IGMP_MAX_VLANS, ports, n_ports, scopes,
        IGMP_MAX_SCOPES, n_scopes) : 0;
    if (!*enabled)
        *n_scopes = 0;
    *n_static_members = *enabled ? l2_collect_igmp_listener_intents(
        ys, static_members, CFG_IGMP_STATIC_MAX_MEMBERS,
        ports, n_ports) : 0;
    ok = *n_static_members >= 0 && *n_static_members <= CFG_IGMP_STATIC_MAX_MEMBERS;

done:
    if (file)
        fclose(file);
    nl_yang_session_destroy(ys);
    free(xml);
    return ok;
}

static bool reload_config_work(void) {
    bool enabled = false;
    int timeout = IGMP_DEFAULT_MEMBERSHIP_TIMEOUT;
    int vlans[IGMP_MAX_VLANS] = {0};
    int n_vlans = 0;
    igmp_vlan_port_scope scopes[IGMP_MAX_SCOPES] = {{0}};
    int n_scopes = 0;
    cfg_igmp_listener_intent
        static_members[CFG_IGMP_STATIC_MAX_MEMBERS];
    cfg_igmp_listener_intent
        old_static_members[CFG_IGMP_STATIC_MAX_MEMBERS];
    int n_static_members = 0;
    int n_old_static_members;

    memset(static_members, 0, sizeof(static_members));
    if (!load_config(&enabled, &timeout, vlans, &n_vlans, scopes, &n_scopes,
                     static_members, &n_static_members))
        return false;

    pthread_mutex_lock(&g_igmp.lock);
    n_old_static_members = g_igmp.n_static_members;
    memcpy(old_static_members, g_igmp.static_members,
           sizeof(old_static_members));
    g_igmp.enabled = enabled;
    g_igmp.membership_timeout = timeout;
    memcpy(g_igmp.vlans, vlans, sizeof(vlans));
    g_igmp.n_vlans = n_vlans;
    memcpy(g_igmp.scopes, scopes, sizeof(scopes));
    g_igmp.n_scopes = n_scopes;
    memcpy(g_igmp.static_members, static_members, sizeof(static_members));
    g_igmp.n_static_members = n_static_members;

    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; i++) {
        if (!g_igmp.runtime.dynamic[i].used ||
            scope_enabled_locked(g_igmp.runtime.dynamic[i].vid,
                                 g_igmp.runtime.dynamic[i].port))
            continue;
        (void)remove_dynamic_locked(i);
    }
    for (int i = 0; i < n_old_static_members; i++) {
        const cfg_igmp_listener_intent *removed = &old_static_members[i];

        if (!hardware_referenced_locked(removed->vid,
                                        removed->port.hw_port,
                                        removed->mac) &&
            !router_needed_locked(removed->vid, removed->port.hw_port, removed->mac))
            (void)apply_listener_locked(false, removed->vid,
                                        removed->port.hw_port,
                                        removed->group);
    }
    pthread_mutex_unlock(&g_igmp.lock);
    return true;
}

static bool reload_config(void) {
    static pthread_mutex_t reload_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&reload_lock);
    bool ok = reload_config_work();
    pthread_mutex_unlock(&reload_lock);
    return ok;
}
bool igmp_snooping_reload(void) { return reload_config(); }

bool igmp_snooping_dynamic_hardware_key_present(int vid, int port,
                                                 const u8 mac[6]) {
    bool present = false;

    if (vid < 1 || vid > 4094 || port <= 0 || !mac)
        return false;
    pthread_mutex_lock(&g_igmp.lock);
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; i++) {
        if (same_hardware_key(vid, port, mac, &g_igmp.runtime.dynamic[i])) {
            present = true;
            break;
        }
    }
    if (!present && port <= 24) {
        for (int i = 0; i < IGMP_MAX_ROUTER_GROUPS; ++i) {
            const igmp_router_group *r = &g_igmp.runtime.router_groups[i];
            if (r->used && r->vid == vid && !memcmp(r->mac, mac, 6) &&
                ((r->applied_ports | r->uncertain_ports) & (1U << (port - 1)))) { present = true; break; }
        }
    }
    pthread_mutex_unlock(&g_igmp.lock);
    return present;
}

static int frame_igmp_group(const u8 *frame, int frame_len, u8 *type,
                            char group[16], u32 *group_ip, u8 mac[6]) {
    int ip_offset = 14;
    const u8 *ip;
    const u8 *igmp;
    int ihl;
    int total;
    int igmp_len;
    u32 value;
    u32 destination;
    u8 expected_mac[6];
    struct in_addr addr;

    if (!frame || frame_len < 14 || !type || !group || !group_ip || !mac)
        return -1;
    if (frame[12] == 0x81 && frame[13] == 0x00) {
        if (frame_len < 18 || frame[16] != 0x08 || frame[17] != 0x00)
            return -1;
        ip_offset = 18;
    } else if (frame[12] != 0x08 || frame[13] != 0x00) {
        return -1;
    }
    if (frame_len < ip_offset + 28)
        return -1;
    ip = frame + ip_offset;
    ihl = (ip[0] & 0x0f) * 4;
    total = ((int)ip[2] << 8) | ip[3];
    if ((ip[0] >> 4) != 4 || ihl < 20 || total < ihl + 8 ||
        frame_len < ip_offset + total ||
        (ip[6] & 0x3f) != 0 || ip[7] != 0 || ip[8] != 1 ||
        checksum16(ip, ihl) != 0)
        return -1;
    if (ip[9] != 2)
        return 1;
    igmp = ip + ihl;
    igmp_len = total - ihl;
    if (checksum16(igmp, igmp_len) != 0)
        return -1;
    *type = igmp[0];
    if (*type != 0x12 && *type != 0x16 && *type != 0x17)
        return 1;
    value = ((u32)igmp[4] << 24) | ((u32)igmp[5] << 16) |
            ((u32)igmp[6] << 8) | igmp[7];
    addr.s_addr = htonl(value);
    if (!inet_ntop(AF_INET, &addr, group, 16) ||
        !l2_parse_igmp_group(group, group_ip, mac))
        return -1;
    destination = ((u32)ip[16] << 24) | ((u32)ip[17] << 16) |
                  ((u32)ip[18] << 8) | ip[19];
    if ((*type == 0x12 || *type == 0x16) && destination != value)
        return -1;
    if (*type == 0x17 && destination != 0xe0000002U)
        return -1;
    if (*type == 0x17) {
        const u8 all_routers_mac[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x02};

        memcpy(expected_mac, all_routers_mac, sizeof(expected_mac));
    } else {
        memcpy(expected_mac, mac, sizeof(expected_mac));
    }
    if (memcmp(frame, expected_mac, sizeof(expected_mac)) != 0)
        return -1;
    return 0;
}

static void process_report(int vid, int port, const char *group,
                           u32 group_ip, const u8 mac[6]) {
    int free_slot = -1;
    time_t now = igmp_clock_seconds();

    pthread_mutex_lock(&g_igmp.lock);
    if (now < 0) { ++g_igmp.apply_failures; pthread_mutex_unlock(&g_igmp.lock); return; }
    if (!scope_enabled_locked(vid, port) || !nl_ifid_is_user_port(port)) {
        g_igmp.ignored_scope++;
        pthread_mutex_unlock(&g_igmp.lock);
        return;
    }
    g_igmp.reports++;
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; i++) {
        if (!g_igmp.runtime.dynamic[i].used) {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }
        if (g_igmp.runtime.dynamic[i].vid == vid &&
            g_igmp.runtime.dynamic[i].port == port &&
            g_igmp.runtime.dynamic[i].group_ip == group_ip) {
            g_igmp.runtime.dynamic[i].expires_at =
                now + g_igmp.membership_timeout;
            g_igmp.runtime.dynamic[i].retiring = false;
            (void)checkpoint_locked();
            pthread_mutex_unlock(&g_igmp.lock);
            return;
        }
    }
    if (free_slot < 0) {
        g_igmp.apply_failures++;
        pthread_mutex_unlock(&g_igmp.lock);
        return;
    }
    bool referenced = hardware_referenced_locked(vid, port, mac);
    bool pending = !referenced || hardware_key_pending_locked(vid, port, mac);
    /* Reserve ownership before the RPC: an error or lost reply does not
     * prove the SDK left the listener absent. Retain the report until it
     * is confirmed, expires, or is explicitly removed. */
    g_igmp.runtime.dynamic[free_slot].used = true;
    g_igmp.runtime.dynamic[free_slot].pending = pending;
    g_igmp.runtime.dynamic[free_slot].retiring = false;
    g_igmp.runtime.dynamic[free_slot].vid = vid;
    g_igmp.runtime.dynamic[free_slot].port = port;
    snprintf(g_igmp.runtime.dynamic[free_slot].group,
             sizeof(g_igmp.runtime.dynamic[free_slot].group), "%s", group);
    g_igmp.runtime.dynamic[free_slot].group_ip = group_ip;
    memcpy(g_igmp.runtime.dynamic[free_slot].mac, mac, 6);
    g_igmp.runtime.dynamic[free_slot].expires_at =
        now + g_igmp.membership_timeout;
    if (!referenced && apply_listener_locked(true, vid, port, group) == 0)
        mark_dynamic_key_locked(vid, port, mac, false);
    sync_router_groups_locked(NULL, IGMP_ROUTER_WRITE_BUDGET);
    (void)checkpoint_locked();
    pthread_mutex_unlock(&g_igmp.lock);
}

static void process_leave(int vid, int port, u32 group_ip) {
    pthread_mutex_lock(&g_igmp.lock);
    if (!scope_enabled_locked(vid, port) || !nl_ifid_is_user_port(port)) {
        g_igmp.ignored_scope++;
        pthread_mutex_unlock(&g_igmp.lock);
        return;
    }
    g_igmp.leaves++;
    bool fast = false;
    for (int i = 0; i < g_igmp.n_scopes; ++i)
        if (g_igmp.scopes[i].vid == vid && g_igmp.scopes[i].port == port)
            fast = g_igmp.scopes[i].fast_leave;
    if (!fast) {
        /* An external querier solicits reports from remaining receivers.
         * A shared segment's Leave must not remove every listener on it. */
        pthread_mutex_unlock(&g_igmp.lock);
        return;
    }
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; i++) {
        if (!g_igmp.runtime.dynamic[i].used || g_igmp.runtime.dynamic[i].vid != vid ||
            g_igmp.runtime.dynamic[i].port != port ||
            g_igmp.runtime.dynamic[i].group_ip != group_ip)
            continue;
        (void)remove_dynamic_locked(i);
        sync_router_groups_locked(NULL, IGMP_ROUTER_WRITE_BUDGET);
        break;
    }
    pthread_mutex_unlock(&g_igmp.lock);
}

static int read_packetd_record(
    nl_conn *conn, void *buffer, int expected) {
    if (expected <= 0)
        return -1;
    return nl_recv_peer_record(
               conn, buffer, (size_t)expected, MSG_TRUNC) == expected ?
        expected : -1;
}

static bool packetd_subscribe(nl_conn *conn) {
    const char command[] = "subscribe 0800";
    struct timeval timeout = {
        .tv_sec = IGMP_PACKETD_IO_TIMEOUT_MS / 1000U,
        .tv_usec =
            (IGMP_PACKETD_IO_TIMEOUT_MS % 1000U) * 1000U,
    };
    u32 net_len = htonl((u32)(sizeof(command) - 1));

    if (!conn ||
        nl_client_connect_timeout(
            l2d_packetd_socket_path(), conn,
            IGMP_PACKETD_IO_TIMEOUT_MS) != NL_OK)
        return false;
    if (setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) != 0 ||
        setsockopt(conn->fd, SOL_SOCKET, SO_SNDTIMEO,
                   &timeout, sizeof(timeout)) != 0) {
        nl_client_close(conn);
        return false;
    }
    if (nl_send_record(conn, &net_len, sizeof(net_len)) != NL_OK ||
        nl_send_record(
            conn, command, sizeof(command) - 1U) != NL_OK) {
        nl_client_close(conn);
        return false;
    }
    return true;
}

static void *packet_thread(void *arg) {
    nl_conn packetd = {.fd = -1};

    (void)arg;
    while (atomic_load_explicit(
               &g_igmp.thread_running, memory_order_acquire)) {
        struct pollfd fds[2];
        u32 net_len;
        u8 event[NETLAB_PACKET_IO_MAX + NL_PACKET_EVENT_HEADER];
        int ready;
        int len;
        int vid;
        int port;
        int resolved_vid;
        u8 type;
        char group[16];
        u32 group_ip;
        u8 mac[6];

        if (packetd.fd < 0) {
            if (!packetd_subscribe(&packetd)) {
                fds[0].fd = g_igmp.stop_fd;
                fds[0].events = POLLIN;
                fds[0].revents = 0;
                do {
                    ready = poll(fds, 1, 1000);
                } while (ready < 0 && errno == EINTR &&
                         atomic_load_explicit(
                             &g_igmp.thread_running,
                             memory_order_acquire));
                continue;
            }
        }
        fds[0].fd = g_igmp.stop_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = packetd.fd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;
        do {
            ready = poll(fds, 2, 1000);
        } while (ready < 0 && errno == EINTR &&
                 atomic_load_explicit(
                     &g_igmp.thread_running, memory_order_acquire));
        if (!atomic_load_explicit(
                &g_igmp.thread_running, memory_order_acquire))
            break;
        if (ready == 0)
            continue;
        if (ready < 0)
            continue;
        if ((fds[0].revents &
             (POLLIN | POLLERR | POLLHUP | POLLNVAL)) != 0)
            break;
        if ((fds[1].revents &
             (POLLIN | POLLERR | POLLHUP | POLLNVAL)) == 0)
            continue;
        if (read_packetd_record(
                &packetd, &net_len, sizeof(net_len)) !=
                (int)sizeof(net_len)) {
            nl_client_close(&packetd);
            continue;
        }
        len = (int)ntohl(net_len);
        if (len < 4 || len > (int)sizeof(event) ||
            read_packetd_record(&packetd, event, len) != len) {
            nl_client_close(&packetd);
            continue;
        }
        u64 captured_at;
        int header = nl_packet_event_decode(event, len, &port, &vid, &captured_at);
        if (header < 0) continue;
        int parse_status = frame_igmp_group(
            event + header, len - header, &type, group, &group_ip, mac);
        if (parse_status > 0)
            continue;
        if (parse_status < 0) {
            pthread_mutex_lock(&g_igmp.lock);
            g_igmp.invalid++;
            pthread_mutex_unlock(&g_igmp.lock);
            continue;
        }
        if (!nl_port_scope_packet_enter(port, captured_at)) continue;
        pthread_mutex_lock(&g_igmp.lock);
        resolved_vid = resolve_scope_vid_locked(vid, port);
        g_igmp.rx_events++;
        g_igmp.last_port = port;
        g_igmp.last_vid = vid;
        g_igmp.last_resolved_vid = resolved_vid;
        g_igmp.last_type = type;
        snprintf(g_igmp.last_group, sizeof(g_igmp.last_group), "%s", group);
        pthread_mutex_unlock(&g_igmp.lock);
        if (type == 0x12 || type == 0x16)
            process_report(resolved_vid, port, group, group_ip, mac);
        else if (type == 0x17)
            process_leave(resolved_vid, port, group_ip);
        nl_port_scope_leave(port);
    }
    nl_client_close(&packetd);
    return NULL;
}

static bool owner_has_listener(const char *owner, int vid, int port,
                               const u8 mac[6]) {
    char group_needle[96];
    char listener_needle[64];
    const char *group;
    const char *group_end;

    if (!owner)
        return false;
    snprintf(group_needle, sizeof(group_needle),
             "vlan=\"%d\" mac=\"%02x:%02x:%02x:%02x:%02x:%02x\"",
             vid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    group = strstr(owner, group_needle);
    group_end = group ? strstr(group, "</group>") : NULL;
    snprintf(listener_needle, sizeof(listener_needle),
             "<listener port=\"%d\" vlan=\"%d\"/>", port, vid);
    return group && group_end && strstr(group, listener_needle) &&
           strstr(group, listener_needle) < group_end;
}

static void expire_dynamic_members_locked(time_t now) {
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; ++i) {
        if (!g_igmp.runtime.dynamic[i].used ||
            (!g_igmp.runtime.dynamic[i].retiring && g_igmp.runtime.dynamic[i].expires_at > now)) continue;
        if (remove_dynamic_locked(i)) ++g_igmp.aged;
    }
}

static void sync_dynamic_members_locked(const char *owner, unsigned budget) {
    unsigned start = g_igmp.dynamic_cursor;
    for (unsigned step = 0; step < IGMP_MAX_DYNAMIC_MEMBERS; ++step) {
        unsigned index = (start + step) % IGMP_MAX_DYNAMIC_MEMBERS;
        igmp_dynamic_member *m = &g_igmp.runtime.dynamic[index];
        if (!m->used || m->retiring || !scope_enabled_locked(m->vid, m->port)) continue;
        /* Multiple IPv4 aliases share one hardware MAC/VLAN/port key. */
        bool first = true;
        for (unsigned earlier = 0; earlier < index; ++earlier) {
            const igmp_dynamic_member *other = &g_igmp.runtime.dynamic[earlier];
            if (!other->retiring && same_hardware_key(m->vid, m->port, m->mac, other)) { first = false; break; }
        }
        if (!first) continue;
        bool present = owner_has_listener(owner, m->vid, m->port, m->mac);
        mark_dynamic_key_locked(m->vid, m->port, m->mac, !present);
        if (present || !budget || nl_port_scope_paused(m->port)) continue;
        --budget;
        g_igmp.dynamic_cursor = (index + 1) % IGMP_MAX_DYNAMIC_MEMBERS;
        if (apply_listener_locked(true, m->vid, m->port, m->group) == 0)
            mark_dynamic_key_locked(m->vid, m->port, m->mac, false);
    }
}

void igmp_snooping_tick(void) {
    char *owner = NULL;
    time_t now = igmp_clock_seconds();

    if (now < 0 || !reload_config()) return;
    pthread_mutex_lock(&g_igmp.lock);
    expire_dynamic_members_locked(now);
    pthread_mutex_unlock(&g_igmp.lock);

    owner = calloc(1, NETLAB_L2_MCAST_OWNER_MAX);
    if (!owner || l2d_switchd_get_multicast_owner(
            l2d_switchd_socket_path(), owner,
            NETLAB_L2_MCAST_OWNER_MAX) < 0) {
        free(owner);
        return;
    }
    pthread_mutex_lock(&g_igmp.lock);
    sync_dynamic_members_locked(owner, IGMP_MEMBER_WRITE_BUDGET);
    sync_router_groups_locked(owner, IGMP_ROUTER_WRITE_BUDGET);
    pthread_mutex_unlock(&g_igmp.lock);
    free(owner);
}

static void resume_listener_timers(u32 mask, time_t seconds) {
    pthread_mutex_lock(&g_igmp.lock);
    nl_port_scope_status scope = nl_port_scope_get();
    time_t added[24] = {0};
    for (int port = 0; port < 24; ++port) if (mask & (1U << port)) {
        time_t previous = scope.tx_id && g_igmp.runtime.resumed_tx[port] == scope.tx_id ?
                          g_igmp.runtime.resumed_seconds[port] : 0;
        added[port] = seconds > previous ? seconds - previous : 0;
        g_igmp.runtime.resumed_tx[port] = scope.tx_id;
        g_igmp.runtime.resumed_seconds[port] = seconds > previous ? seconds : previous;
    }
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; ++i) {
        igmp_dynamic_member *m = &g_igmp.runtime.dynamic[i];
        if (m->used && !m->retiring && m->port >= 1 && m->port <= 24 && (mask & (1U << (m->port - 1))))
            m->expires_at += added[m->port - 1];
    }
    if (!checkpoint_locked() && scope.tx_id) nl_port_scope_degrade(scope.tx_id);
    pthread_mutex_unlock(&g_igmp.lock);
}

int igmp_snooping_init(void) {
    memset(&g_igmp, 0, sizeof(g_igmp));
    g_igmp.stop_fd = -1;
    atomic_init(&g_igmp.thread_running, false);
    if (pthread_mutex_init(&g_igmp.lock, NULL) != 0)
        return -1;
    nl_port_scope_on_resume(resume_listener_timers);
    g_igmp.stop_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (g_igmp.stop_fd < 0) {
        pthread_mutex_destroy(&g_igmp.lock);
        return -1;
    }
    g_igmp.membership_timeout = IGMP_DEFAULT_MEMBERSHIP_TIMEOUT;
    reload_config();
    if (igmp_state_open(&g_igmp_store, &g_igmp.runtime) != 0 || !checkpoint_locked()) {
        NL_LOG_ERR("IGMP runtime ownership cannot be recovered; refusing to start");
        igmp_state_close(&g_igmp_store);
        close(g_igmp.stop_fd); g_igmp.stop_fd = -1;
        pthread_mutex_destroy(&g_igmp.lock);
        return -1;
    }
    for (int i = 0; i < IGMP_MAX_DYNAMIC_MEMBERS; ++i)
        if (g_igmp.runtime.dynamic[i].used) ++g_igmp.recovered_members;
    atomic_store_explicit(
        &g_igmp.thread_running, true, memory_order_release);
    if (pthread_create(&g_igmp.thread, NULL, packet_thread, NULL) != 0) {
        atomic_store_explicit(
            &g_igmp.thread_running, false, memory_order_release);
        close(g_igmp.stop_fd);
        g_igmp.stop_fd = -1;
        igmp_state_close(&g_igmp_store);
        pthread_mutex_destroy(&g_igmp.lock);
        return -1;
    }
    g_igmp.thread_started = true;
    return 0;
}

void igmp_snooping_stop(void) {
    u64 wake = 1;
    ssize_t written;

    if (!atomic_exchange_explicit(
            &g_igmp.thread_running, false, memory_order_acq_rel))
        return;
    if (g_igmp.stop_fd < 0)
        return;
    do {
        written = write(g_igmp.stop_fd, &wake, sizeof(wake));
    } while (written < 0 && errno == EINTR);
}

void igmp_snooping_shutdown(void) {
    igmp_snooping_stop();
    if (g_igmp.thread_started) {
        pthread_join(g_igmp.thread, NULL);
        g_igmp.thread_started = false;
    }
    if (g_igmp.stop_fd >= 0) {
        close(g_igmp.stop_fd);
        g_igmp.stop_fd = -1;
    }
    pthread_mutex_lock(&g_igmp.lock);
    (void)checkpoint_locked();
    igmp_state_close(&g_igmp_store);
    pthread_mutex_unlock(&g_igmp.lock);
    pthread_mutex_destroy(&g_igmp.lock);
}

int igmp_snooping_show(nl_conn *conn, nl_msg_hdr *msg) {
    char *buf = calloc(1, IGMP_SHOW_BYTES);
    char *hardware = calloc(1, NETLAB_L2_MCAST_OWNER_MAX);
    int off = 0;
    int dynamic_count = 0;
    time_t now = igmp_clock_seconds();
    nl_msg_hdr *resp;
    bool output_ok;

    if (!buf || !hardware) {
        free(buf);
        free(hardware);
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }
    pthread_mutex_lock(&g_igmp.lock);
    output_ok = append_output(
        buf, IGMP_SHOW_BYTES, &off,
        "<igmp-snooping enabled=\"%s\" timeout=\"%d\" "
        "reports=\"%llu\" leaves=\"%llu\" aged=\"%llu\" "
        "invalid=\"%llu\" rx-events=\"%llu\" "
        "ignored-scope=\"%llu\" last-port=\"%d\" "
        "last-vlan=\"%d\" last-resolved-vlan=\"%d\" "
        "last-type=\"0x%02x\" "
        "last-group=\"%s\" apply-failures=\"%llu\" "
        "recovery-state=\"%s\" recovered-members=\"%u\" checkpoint-failures=\"%llu\">",
        g_igmp.enabled ? "true" : "false",
        g_igmp.membership_timeout,
        (unsigned long long)g_igmp.reports,
        (unsigned long long)g_igmp.leaves,
        (unsigned long long)g_igmp.aged,
        (unsigned long long)g_igmp.invalid,
        (unsigned long long)g_igmp.rx_events,
        (unsigned long long)g_igmp.ignored_scope,
        g_igmp.last_port, g_igmp.last_vid,
        g_igmp.last_resolved_vid, g_igmp.last_type,
        g_igmp.last_group,
        (unsigned long long)g_igmp.apply_failures,
        g_igmp.checkpoint_error ? "retrying" : g_igmp_store.enabled ? "durable" : "memory-only",
        g_igmp.recovered_members, (unsigned long long)g_igmp_store.failures);
    for (int i = 0; output_ok && i < g_igmp.n_static_members; i++) {
        output_ok = append_output(
            buf, IGMP_SHOW_BYTES, &off,
            "<member source=\"%s\" vlan=\"%d\" port=\"%d\" "
            "interface=\"%s\" group=\"%s\"/>",
            g_igmp.static_members[i].router ? "static-router" : "static",
            g_igmp.static_members[i].vid,
            g_igmp.static_members[i].port.hw_port,
            g_igmp.static_members[i].ifname,
            g_igmp.static_members[i].group);
    }
    for (int i = 0; output_ok && i < g_igmp.n_scopes; ++i) {
        const igmp_vlan_port_scope *s = &g_igmp.scopes[i];
        if (s->mrouter) output_ok = append_output(buf, IGMP_SHOW_BYTES, &off,
            "<router-port source=\"static\" vlan=\"%d\" port=\"%d\"/>", s->vid, s->port);
    }
    for (int i = 0; output_ok && i < IGMP_MAX_ROUTER_GROUPS; ++i) {
        const igmp_router_group *r = &g_igmp.runtime.router_groups[i];
        if (!r->used) continue;
        u32 wanted = dynamic_group_present_locked(r->vid, r->mac) ? router_ports_locked(r->vid) : 0;
        output_ok = append_output(buf, IGMP_SHOW_BYTES, &off,
            "<router-group vlan=\"%d\" group=\"%s\" applied-mask=\"%06x\" desired-mask=\"%06x\" uncertain-mask=\"%06x\"/>",
            r->vid, r->group, r->applied_ports, wanted, r->uncertain_ports);
    }
    for (int i = 0; output_ok && i < IGMP_MAX_DYNAMIC_MEMBERS; i++) {
        if (!g_igmp.runtime.dynamic[i].used)
            continue;
        dynamic_count++;
        output_ok = append_output(
            buf, IGMP_SHOW_BYTES, &off,
            "<member source=\"dynamic\" vlan=\"%d\" port=\"%d\" "
            "group=\"%s\" expires-in=\"%lld\" hardware-state=\"%s\"/>",
            g_igmp.runtime.dynamic[i].vid, g_igmp.runtime.dynamic[i].port,
            g_igmp.runtime.dynamic[i].group,
            (long long)(g_igmp.runtime.dynamic[i].expires_at > now ?
                        g_igmp.runtime.dynamic[i].expires_at - now : 0),
            g_igmp.runtime.dynamic[i].retiring ? "retiring" : g_igmp.runtime.dynamic[i].pending ? "pending" : "installed");
    }
    if (output_ok)
        output_ok = append_output(
            buf, IGMP_SHOW_BYTES, &off,
            "<summary static=\"%d\" dynamic=\"%d\"/>",
            g_igmp.n_static_members, dynamic_count);
    pthread_mutex_unlock(&g_igmp.lock);

    if (output_ok && l2d_switchd_get_multicast_owner(
            l2d_switchd_socket_path(), hardware,
            NETLAB_L2_MCAST_OWNER_MAX) > 0)
        output_ok = append_output(buf, IGMP_SHOW_BYTES, &off,
                                  "%s", hardware);
    else if (output_ok)
        output_ok = append_output(
            buf, IGMP_SHOW_BYTES, &off,
            "<multicast-owner status=\"unavailable\"/>");
    if (output_ok)
        output_ok = append_output(buf, IGMP_SHOW_BYTES, &off,
                                  "</igmp-snooping>");
    if (!output_ok) {
        nl_send_response(conn, msg->request_id, -1);
        free(hardware);
        free(buf);
        return 0;
    }
    resp = nl_msg_alloc((u32)off);
    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->error_code = 0;
        resp->payload_len = (u32)off;
        memcpy(resp->payload, buf, (size_t)off);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    free(hardware);
    free(buf);
    return 0;
}
