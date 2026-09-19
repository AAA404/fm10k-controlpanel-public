#include "l2d_cache.h"

#include "netlab/error.h"
#include "netlab/interface_id.h"
#include "netlab/journal.h"
#include "netlab/log.h"
#include "netlab/yang_config.h"
#include "l2_plan_internal.h"
#include "l2_plan_text.h"
#include "l2d_state.h"
#include "l2d_switchd.h"
#include "l2d_util.h"

#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define L2D_LAG_XML_BUFFER_SIZE (128 * 1024)
#define L2D_MAC_UPDATE_XML_BUFFER_SIZE (512 * 1024)
#define L2D_CONFIG_MAX_BYTES (8 * 1024 * 1024)

typedef struct {
    l2_vlan_state vlans[L2D_MAX_VLANS];
    l2_if_state ifs[L2D_MAX_IFS];
    l2_lag_info lags[L2D_AE_LIMIT];
    l2_mac_entry mac_entries[L2D_MAX_MAC_ENTRIES];
    char dhcp_snooping_vlans[L2D_MAX_SECURITY_VLANS][64];
    char arp_inspection_vlans[L2D_MAX_SECURITY_VLANS][64];
    l2_dhcp_binding dhcp_bindings[L2D_MAX_DHCP_BINDINGS];
    l2_user_filter user_filters[L2D_MAX_USER_FILTERS];
    l2_ingress_ipv4_acl ingress_ipv4_acl[L2D_MAX_INGRESS_IPV4_ACL];
    l2_acl_policer acl_policer[L2D_MAX_ACL_POLICER];
    l2_egress_acl egress_acl[L2D_MAX_EGRESS_ACL];
    l2_acl_independent acl_independent[L2D_MAX_ACL_INDEPENDENT];
    char known_ifs[L2D_MAX_IFS][64];
    nl_port_entry port_entries[NL_MAX_PORTS_PER_PROFILE];
} l2d_refresh_work;

static char *read_config_text_exact(const char *path) {
    struct stat metadata;
    char *text = NULL;
    size_t offset = 0;
    char extra;
    int fd;

    if (!path)
        return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NULL;
    if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size <= 0 ||
        metadata.st_size > (off_t)L2D_CONFIG_MAX_BYTES)
        goto done;
    text = calloc(1, (size_t)metadata.st_size + 1U);
    if (!text)
        goto done;
    while (offset < (size_t)metadata.st_size) {
        ssize_t received = read(fd, text + offset,
                                (size_t)metadata.st_size - offset);

        if (received <= 0) {
            free(text);
            text = NULL;
            goto done;
        }
        offset += (size_t)received;
    }
    if (read(fd, &extra, 1) != 0) {
        free(text);
        text = NULL;
        goto done;
    }
    text[offset] = '\0';

done:
    close(fd);
    return text;
}

static int find_if_state(l2_if_state *ifs, int n_ifs, const char *ifname) {
    if (!ifname)
        return -1;
    for (int i = 0; i < n_ifs; i++)
        if (strcmp(ifs[i].name, ifname) == 0)
            return i;
    return -1;
}

static int find_vlan_vid(const l2_vlan_state *vlans, int n_vlans,
                         const char *name) {
    if (!name)
        return 0;
    for (int i = 0; i < n_vlans; i++)
        if (strcmp(vlans[i].name, name) == 0)
            return vlans[i].vid;
    return 0;
}

static bool security_vlan_list_has(char names[][64], int n_names,
                                   const char *name) {
    if (!name)
        return false;
    for (int i = 0; i < n_names; i++)
        if (strcmp(names[i], name) == 0)
            return true;
    return false;
}

static int find_seen_entry(const l2d_ctx *ctx, int vlan, const char *mac) {
    for (int i = 0; i < ctx->n_seen; i++) {
        if (ctx->seen[i].vlan == vlan &&
            strcmp(ctx->seen[i].mac, mac) == 0)
            return i;
    }
    return -1;
}

static bool current_has_entry(const l2_mac_entry *entries, int n_entries,
                              int vlan, const char *mac) {
    for (int i = 0; i < n_entries; i++) {
        if (entries[i].vlan == vlan && strcmp(entries[i].mac, mac) == 0)
            return true;
    }
    return false;
}

static int find_move_event(const l2d_ctx *ctx, int vlan, const char *mac) {
    for (int i = 0; i < ctx->n_moves; i++) {
        if (ctx->moves[i].vlan == vlan &&
            strcmp(ctx->moves[i].mac, mac) == 0)
            return i;
    }
    return -1;
}

static void reset_move_window(l2_mac_move *move, time_t now) {
    if (!move)
        return;
    move->window_start = now;
    move->window_count = 0;
    move->dampened = false;
    move->dampened_time = 0;
    move->dampened_if[0] = '\0';
}

static void record_mac_move(l2d_ctx *ctx, const l2_mac_seen *old_seen,
                            const l2_mac_entry *new_entry, time_t now,
                            l2_if_state *ifs, int n_ifs,
                            bool dampening_configured, int threshold,
                            int window, const char *action) {
    int idx;
    l2_mac_move *move;
    int ifidx;

    if (!ctx || !old_seen || !new_entry)
        return;
    idx = find_move_event(ctx, new_entry->vlan, new_entry->mac);
    if (idx < 0) {
        if (ctx->n_moves < L2D_MAX_MAC_MOVES) {
            idx = ctx->n_moves++;
        } else {
            idx = L2D_MAX_MAC_MOVES - 1;
            memmove(&ctx->moves[0], &ctx->moves[1],
                    sizeof(ctx->moves[0]) * (L2D_MAX_MAC_MOVES - 1));
        }
        memset(&ctx->moves[idx], 0, sizeof(ctx->moves[idx]));
        ctx->moves[idx].vlan = new_entry->vlan;
        snprintf(ctx->moves[idx].mac, sizeof(ctx->moves[idx].mac), "%s",
                 new_entry->mac);
        reset_move_window(&ctx->moves[idx], now);
    }
    move = &ctx->moves[idx];
    if (move->window_start <= 0 ||
        (window > 0 && now - move->window_start > window))
        reset_move_window(move, now);
    snprintf(move->from_if, sizeof(move->from_if), "%s", old_seen->ifname);
    snprintf(move->to_if, sizeof(move->to_if), "%s", new_entry->ifname);
    move->count++;
    move->window_count++;
    move->last_seen = now;
    ctx->total_moves++;

    if (!dampening_configured || threshold <= 0 || window <= 0 ||
        move->window_count < (unsigned long)threshold || move->dampened)
        return;

    move->dampened = true;
    move->dampened_time = now;
    snprintf(move->dampened_if, sizeof(move->dampened_if), "%s",
             new_entry->ifname);
    ctx->total_move_dampens++;

    if (!action || strcmp(action, "shutdown") != 0)
        return;

    ifidx = find_if_state(ifs, n_ifs, new_entry->ifname);
    if (ifidx < 0 || ifs[ifidx].disabled || ifs[ifidx].mac_move_shutdown)
        return;
    if (nl_ifid_name_to_logical_port(new_entry->ifname) <= 0)
        return;

    if (l2d_switchd_set_runtime_admin(SW_SOCKET,
                                      nl_ifid_name_to_logical_port(new_entry->ifname),
                                      1) == 0) {
        ifs[ifidx].mac_move_shutdown = true;
        ifs[ifidx].mac_move_shutdown_time = now;
        snprintf(ifs[ifidx].mac_move_shutdown_reason,
                 sizeof(ifs[ifidx].mac_move_shutdown_reason),
                 "MAC %s moved %lu times in %ds window (vlan %d)",
                 new_entry->mac, move->window_count, window, new_entry->vlan);
        NL_LOG_WARN("mac-move dampening shutdown %s: %s",
                    ifs[ifidx].name, ifs[ifidx].mac_move_shutdown_reason);
    }
}

static bool collect_mac_entries(l2_mac_entry *entries, int max_entries,
                                int *n_entries) {
    nl_mac_snapshot snapshot = {0};
    u8 *resp;
    int rn;
    int n = 0;

    if (n_entries)
        *n_entries = 0;
    if (!entries || max_entries <= 0 || !n_entries)
        return false;
    resp = malloc(NETLAB_MAX_MSG);
    if (!resp)
        return false;
    rn = l2d_switchd_get_mac_snapshot(SW_SOCKET, resp, NETLAB_MAX_MSG);
    if (rn <= 0 ||
        nl_mac_snapshot_decode(resp, (size_t)rn, &snapshot) != 0 ||
        !snapshot.complete || snapshot.n_entries > (u32)max_entries) {
        free(resp);
        nl_mac_snapshot_reset(&snapshot);
        return false;
    }
    free(resp);

    for (u32 i = 0; i < snapshot.n_entries; i++) {
        const nl_mac_snapshot_entry *source = &snapshot.entries[i];
        char mac[18];
        char type[16];
        char ifname[64] = {0};

        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 source->mac[0], source->mac[1], source->mac[2],
                 source->mac[3], source->mac[4], source->mac[5]);
        snprintf(type, sizeof(type), "%s",
                 source->is_static ? "static" : "dynamic");
        if (source->ae_id >= 0)
            snprintf(ifname, sizeof(ifname), "ae%d", source->ae_id);
        else
            (void)nl_ifid_logical_port_to_name(source->port, ifname,
                                               sizeof(ifname));
        if (l2d_mac_entry_visible(mac, type, ifname) &&
            source->vlan >= 1 && source->vlan <= 4094) {
            entries[n].vlan = source->vlan;
            snprintf(entries[n].mac, sizeof(entries[n].mac), "%s", mac);
            snprintf(entries[n].ifname, sizeof(entries[n].ifname), "%s",
                     ifname);
            n++;
        }
    }
    nl_mac_snapshot_reset(&snapshot);
    *n_entries = n;
    return true;
}

static void seed_seen_entry_locked(l2d_ctx *ctx, const l2_mac_entry *entry,
                                   time_t now) {
    int idx;

    if (!ctx || !entry)
        return;
    idx = find_seen_entry(ctx, entry->vlan, entry->mac);
    if (idx < 0) {
        if (ctx->n_seen >= (int)L2D_MAX_MAC_SEEN)
            return;
        idx = ctx->n_seen++;
        ctx->seen[idx].vlan = entry->vlan;
        snprintf(ctx->seen[idx].mac, sizeof(ctx->seen[idx].mac), "%s",
                 entry->mac);
    }
    snprintf(ctx->seen[idx].ifname, sizeof(ctx->seen[idx].ifname), "%s",
             entry->ifname);
    ctx->seen[idx].last_seen = now;
}

static void process_mac_update_events_locked(
        l2d_ctx *ctx, const char *xml, l2_if_state *ifs, int n_ifs,
        time_t now, bool dampening_configured, int threshold, int window,
        const char *action) {
    const char *p;
    unsigned long max_seq = ctx ? ctx->mac_update_last_seq : 0;
    bool baseline_ready = ctx ? ctx->mac_update_baseline_ready : false;

    if (!ctx || !xml || !xml[0])
        return;

    p = xml;
    while ((p = strstr(p, "<event "))) {
        const char *end = strstr(p, "/>");
        char seq_s[32] = {0};
        char vlan_s[16] = {0};
        char port_s[16] = {0};
        char valid_s[8] = {0};
        char type[24] = {0};
        char mac[18] = {0};
        char ifname[64] = {0};
        unsigned long seq;
        int vlan;
        int port;
        int valid;
        l2_mac_entry entry;

        if (!end)
            break;
        (void)l2d_xml_attr_value(p, end, "seq", seq_s, sizeof(seq_s));
        seq = strtoul(seq_s, NULL, 10);
        if (seq > max_seq)
            max_seq = seq;
        if (seq == 0 || seq <= ctx->mac_update_last_seq) {
            p = end + 2;
            continue;
        }
        if (!baseline_ready) {
            p = end + 2;
            continue;
        }

        (void)l2d_xml_attr_value(p, end, "type", type, sizeof(type));
        if (strcmp(type, "learned") != 0) {
            p = end + 2;
            continue;
        }

        (void)l2d_xml_attr_value(p, end, "vlan", vlan_s, sizeof(vlan_s));
        (void)l2d_xml_attr_value(p, end, "port", port_s, sizeof(port_s));
        (void)l2d_xml_attr_value(p, end, "valid", valid_s,
                                 sizeof(valid_s));
        (void)l2d_xml_attr_value(p, end, "mac", mac, sizeof(mac));
        vlan = atoi(vlan_s);
        port = atoi(port_s);
        valid = atoi(valid_s);

        if (valid && vlan >= 1 && vlan <= 4094 && port > 0 &&
            nl_ifid_logical_port_to_name(port, ifname, sizeof(ifname)) == 0 &&
            l2d_mac_entry_visible(mac, "dynamic", ifname)) {
            memset(&entry, 0, sizeof(entry));
            entry.vlan = vlan;
            snprintf(entry.mac, sizeof(entry.mac), "%s", mac);
            snprintf(entry.ifname, sizeof(entry.ifname), "%s", ifname);

            int idx = find_seen_entry(ctx, entry.vlan, entry.mac);
            if (idx < 0) {
                seed_seen_entry_locked(ctx, &entry, now);
            } else if (strcmp(ctx->seen[idx].ifname, entry.ifname) != 0) {
                l2_mac_seen old_seen = ctx->seen[idx];
                record_mac_move(ctx, &old_seen, &entry, now,
                                ifs, n_ifs, dampening_configured,
                                threshold, window, action);
                snprintf(ctx->seen[idx].ifname,
                         sizeof(ctx->seen[idx].ifname), "%s", entry.ifname);
                ctx->seen[idx].last_seen = now;
            } else {
                ctx->seen[idx].last_seen = now;
            }
        }

        p = end + 2;
    }

    ctx->mac_update_last_seq = max_seq;
    ctx->mac_update_baseline_ready = true;
}

static int collect_lag_info(l2_lag_info *infos, int max_infos) {
    char resp[L2D_LAG_XML_BUFFER_SIZE] = {0};
    int rn;
    char *lag;
    int n_lags = 0;

    if (!infos || max_infos <= 0)
        return 0;
    for (int i = 0; i < max_infos; i++) {
        memset(&infos[i], 0, sizeof(infos[i]));
        infos[i].ae_id = i;
        snprintf(infos[i].name, sizeof(infos[i].name), "ae%d", i);
    }

    rn = l2d_switchd_get_lag_table(SW_SOCKET, resp, sizeof(resp));
    if (rn <= 0)
        return 0;

    lag = resp;
    while ((lag = strstr(lag, "<lag "))) {
        char *end = strstr(lag, "</lag>");
        char value[32] = {0};
        int ae_id = -1;
        l2_lag_info *info;
        char *p;
        if (!end)
            break;
        if (l2d_xml_attr_value(lag, end, "ae", value, sizeof(value)))
            ae_id = atoi(value);
        if (ae_id < 0 || ae_id >= max_infos) {
            char ifname[16] = {0};
            if (l2d_xml_attr_value(lag, end, "name", ifname,
                                   sizeof(ifname)))
                ae_id = l2d_ae_id_from_name(ifname);
        }
        if (ae_id < 0 || ae_id >= max_infos) {
            lag = end + strlen("</lag>");
            continue;
        }
        info = &infos[ae_id];
        info->present = true;
        n_lags++;
        if (l2d_xml_attr_value(lag, end, "logical-port", value,
                               sizeof(value)))
            info->logical_port = atoi(value);
        p = lag;
        while ((p = strstr(p, "<member ")) && p < end &&
               info->n_members < (int)(sizeof(info->members) /
                                       sizeof(info->members[0]))) {
            if (l2d_xml_attr_value(p, end, "port", value, sizeof(value))) {
                int port = atoi(value);
                if (port > 0)
                    info->members[info->n_members++] = port;
            }
            p += strlen("<member ");
        }
        lag = end + strlen("</lag>");
    }
    return n_lags;
}

static int ifname_to_port(const char *ifname,
                          const l2_lag_info *lags, int n_lags) {
    int port = nl_ifid_name_to_logical_port(ifname);
    if (port > 0)
        return port;
    int ae_id = l2d_ae_id_from_name(ifname);
    if (ae_id >= 0 && ae_id < n_lags)
        return lags[ae_id].logical_port;
    return 0;
}

static int vlan_name_to_id(nl_yang_session *ys, const char *name) {
    char path[256];
    snprintf(path, sizeof(path),
             "/netlab:netlab-config/vlans/vlan[name='%s']/vlan-id", name);
    const char *v = nl_yang_get(ys, path);
    return v ? atoi(v) : 0;
}

static int collect_vlan_state_from_xml(const char *xml,
                                       l2_vlan_state *vlans,
                                       int max_vlans, bool sw_up) {
    const char *vlans_node;
    const char *vlans_end;
    const char *p;
    int n = 0;

    if (!xml || !vlans || max_vlans <= 0)
        return 0;

    vlans_node = strstr(xml, "<vlans>");
    vlans_end = vlans_node ? strstr(vlans_node, "</vlans>") : NULL;
    if (!vlans_node || !vlans_end)
        return 0;

    p = vlans_node;
    while ((p = strstr(p, "<vlan>")) && p < vlans_end && n < max_vlans) {
        const char *end = strstr(p, "</vlan>");
        char name[64] = {0};
        char vid_buf[32] = {0};
        int vid;

        if (!end || end > vlans_end)
            break;
        if (l2d_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0 &&
            l2d_extract_xml_leaf(p, end, "vlan-id", vid_buf,
                                 sizeof(vid_buf)) == 0) {
            vid = atoi(vid_buf);
            if (vid >= 1 && vid <= 4094) {
                snprintf(vlans[n].name, sizeof(vlans[n].name), "%s",
                         name);
                vlans[n].vid = vid;
                vlans[n].hw_exists =
                    sw_up && l2d_switchd_vlan_exists(SW_SOCKET, vid);
                n++;
            }
        }
        p = end + strlen("</vlan>");
    }
    return n;
}

static void l2_if_add_member(nl_yang_session *ys, l2_if_state *st,
                             const char *member) {
    size_t off;
    int n;
    int vid;

    if (!ys || !st || !member || !member[0])
        return;
    vid = vlan_name_to_id(ys, member);
    for (int i = 0; i < st->n_members; i++) {
        if (st->member_vids[i] == vid)
            return;
    }
    if (st->n_members >= L2_IF_MAX_MEMBERS)
        return;
    if (st->n_members == 0) {
        snprintf(st->member, sizeof(st->member), "%s", member);
        st->member_vid = vid;
        snprintf(st->members, sizeof(st->members), "%s", member);
    } else {
        off = strlen(st->members);
        if (off >= sizeof(st->members))
            return;
        n = snprintf(st->members + off, sizeof(st->members) - off,
                     ",%s", member);
        if (n < 0 || (size_t)n >= sizeof(st->members) - off)
            return;
    }
    st->member_vids[st->n_members++] = vid;
}

static void collect_interface_members(nl_yang_session *ys, const char *xml,
                                      const char *ifname, l2_if_state *st) {
    const char *p;

    if (!ys || !xml || !ifname || !st)
        return;
    p = xml;
    while ((p = strstr(p, "<interface>"))) {
        const char *end = strstr(p, "</interface>");
        char name[64];
        if (!end)
            break;
        if (l2d_extract_xml_leaf(p, end, "name", name, sizeof(name)) == 0 &&
            strcmp(name, ifname) == 0) {
            const char *m = p;
            while ((m = strstr(m, "<vlan-members>")) && m < end) {
                const char *vstart = m + strlen("<vlan-members>");
                const char *vend = strstr(vstart, "</vlan-members>");
                char member[64];
                size_t len;

                if (!vend || vend > end)
                    break;
                len = (size_t)(vend - vstart);
                if (len >= sizeof(member))
                    len = sizeof(member) - 1;
                memcpy(member, vstart, len);
                member[len] = '\0';
                l2_if_add_member(ys, st, member);
                m = vend + strlen("</vlan-members>");
            }
            return;
        }
        p = end + strlen("</interface>");
    }
}

static void restore_secure_state(l2_if_state *ifs, int n_ifs,
                                 bool preserve_dynamic_count) {
    l2_if_state *prev;
    int n_prev;

    prev = calloc(L2D_MAX_IFS, sizeof(*prev));
    if (!prev)
        return;
    pthread_mutex_lock(&g_l2d.lock);
    n_prev = g_l2d.n_ifs;
    if (n_prev > L2D_MAX_IFS)
        n_prev = L2D_MAX_IFS;
    memcpy(prev, g_l2d.ifs,
           sizeof(*prev) * (size_t)L2D_MAX_IFS);
    pthread_mutex_unlock(&g_l2d.lock);

    for (int i = 0; i < n_ifs; i++) {
        int idx = find_if_state(prev, n_prev, ifs[i].name);
        if (idx < 0)
            continue;
        if (preserve_dynamic_count)
            ifs[i].dynamic_macs = prev[idx].dynamic_macs;
        if (prev[idx].mac_shutdown) {
            ifs[i].mac_shutdown = true;
            ifs[i].mac_shutdown_time = prev[idx].mac_shutdown_time;
            snprintf(ifs[i].mac_shutdown_reason,
                     sizeof(ifs[i].mac_shutdown_reason), "%s",
                     prev[idx].mac_shutdown_reason);
        }
        ifs[i].mac_drop_active = prev[idx].mac_drop_active;
        ifs[i].mac_drop_time = prev[idx].mac_drop_time;
        ifs[i].n_mac_enforced_ports = prev[idx].n_mac_enforced_ports;
        if (ifs[i].n_mac_enforced_ports < 0 ||
            ifs[i].n_mac_enforced_ports > NL_MAX_PORTS)
            ifs[i].n_mac_enforced_ports = 0;
        memcpy(ifs[i].mac_enforced_ports, prev[idx].mac_enforced_ports,
               sizeof(ifs[i].mac_enforced_ports));
        snprintf(ifs[i].mac_enforced_action,
                 sizeof(ifs[i].mac_enforced_action), "%s",
                 prev[idx].mac_enforced_action);
        if (prev[idx].mac_move_shutdown) {
            ifs[i].mac_move_shutdown = true;
            ifs[i].mac_move_shutdown_time = prev[idx].mac_move_shutdown_time;
            snprintf(ifs[i].mac_move_shutdown_reason,
                     sizeof(ifs[i].mac_move_shutdown_reason), "%s",
                     prev[idx].mac_move_shutdown_reason);
        }
    }
    free(prev);
}

static bool int_list_has(const int *ports, int n_ports, int port) {
    if (!ports || port <= 0)
        return false;
    for (int i = 0; i < n_ports; i++)
        if (ports[i] == port)
            return true;
    return false;
}

static void int_list_add_unique(int *ports, int *n_ports, int max_ports,
                                int port) {
    if (!ports || !n_ports || *n_ports >= max_ports || port <= 0)
        return;
    if (int_list_has(ports, *n_ports, port))
        return;
    ports[(*n_ports)++] = port;
}

static int secure_access_target_ports(const l2_if_state *st,
                                      const l2_lag_info *lags,
                                      int max_lags,
                                      int *ports, int max_ports) {
    int port;
    int ae_id;
    int n_ports = 0;

    if (!st || !ports || max_ports <= 0)
        return 0;

    port = nl_ifid_name_to_logical_port(st->name);
    if (port > 0 && nl_ifid_is_user_port(port)) {
        ports[n_ports++] = port;
        return n_ports;
    }

    ae_id = l2d_ae_id_from_name(st->name);
    if (ae_id < 0 || !lags || ae_id >= max_lags || !lags[ae_id].present)
        return 0;

    for (int i = 0; i < lags[ae_id].n_members && n_ports < max_ports; i++) {
        port = lags[ae_id].members[i];
        if (port > 0 && nl_ifid_is_user_port(port) &&
            !int_list_has(ports, n_ports, port))
            ports[n_ports++] = port;
    }
    return n_ports;
}

static int secure_access_shutdown_ports(const l2_if_state *st,
                                        const int *current_ports,
                                        int n_current_ports,
                                        int *ports, int max_ports) {
    int n_ports = 0;
    int port;

    if (!st || !ports || max_ports <= 0)
        return 0;
    for (int i = 0; i < st->n_mac_enforced_ports; i++)
        int_list_add_unique(ports, &n_ports, max_ports,
                            st->mac_enforced_ports[i]);
    for (int i = 0; i < n_current_ports; i++)
        int_list_add_unique(ports, &n_ports, max_ports, current_ports[i]);
    if (n_ports == 0) {
        port = nl_ifid_name_to_logical_port(st->name);
        if (port > 0 && nl_ifid_is_user_port(port))
            int_list_add_unique(ports, &n_ports, max_ports, port);
    }
    return n_ports;
}

static bool secure_access_disable_tracked(l2_if_state *st,
                                          const int *keep_ports,
                                          int n_keep_ports) {
    bool ok = true;

    if (!st)
        return true;
    for (int i = 0; i < st->n_mac_enforced_ports; i++) {
        int port = st->mac_enforced_ports[i];
        if (port <= 0 || int_list_has(keep_ports, n_keep_ports, port))
            continue;
        if (l2d_switchd_set_port_security(SW_SOCKET, port,
                                          false, "drop") != 0) {
            ok = false;
            NL_LOG_WARN("secure-access-port %s: failed to disable stale port-security on port %d",
                        st->name, port);
        }
    }
    return ok;
}

static void secure_access_clear_drop_state(l2_if_state *st) {
    if (!st)
        return;
    st->mac_drop_active = false;
    st->mac_drop_time = 0;
    st->n_mac_enforced_ports = 0;
    st->mac_enforced_action[0] = '\0';
    st->mac_shutdown_reason[0] = '\0';
}

static void secure_access_store_drop_state(l2_if_state *st,
                                           const int *ports, int n_ports,
                                           const char *action) {
    if (!st)
        return;
    if (n_ports < 0)
        n_ports = 0;
    if (n_ports > NL_MAX_PORTS)
        n_ports = NL_MAX_PORTS;
    st->n_mac_enforced_ports = n_ports;
    for (int i = 0; i < n_ports; i++)
        st->mac_enforced_ports[i] = ports[i];
    snprintf(st->mac_enforced_action, sizeof(st->mac_enforced_action),
             "%s", action ? action : "");
}

static bool secure_access_restore_shutdown(l2_if_state *st,
                                           const int *current_ports,
                                           int n_current_ports) {
    int ports[NL_MAX_PORTS];
    int n_ports;
    bool ok = true;

    if (!st)
        return true;
    n_ports = secure_access_shutdown_ports(st, current_ports, n_current_ports,
                                           ports, NL_MAX_PORTS);
    for (int i = 0; i < n_ports; i++) {
        if (l2d_switchd_set_runtime_admin(SW_SOCKET, ports[i], 0) != 0) {
            ok = false;
            NL_LOG_WARN("secure-access-port %s: failed to re-enable shutdown port %d",
                        st->name, ports[i]);
        }
    }
    if (!ok)
        return false;
    st->mac_shutdown = false;
    st->mac_shutdown_time = 0;
    st->mac_shutdown_reason[0] = '\0';
    if (strcmp(st->mac_enforced_action, "shutdown") == 0) {
        st->n_mac_enforced_ports = 0;
        st->mac_enforced_action[0] = '\0';
    }
    return true;
}

static bool secure_access_apply_shutdown(l2_if_state *st,
                                         const int *target_ports,
                                         int n_target_ports,
                                         time_t now) {
    int tracked[NL_MAX_PORTS];
    int n_tracked = 0;
    bool ok = true;
    bool was_shutdown;

    if (!st || !target_ports || n_target_ports <= 0)
        return false;

    for (int i = 0; i < st->n_mac_enforced_ports; i++)
        int_list_add_unique(tracked, &n_tracked, NL_MAX_PORTS,
                            st->mac_enforced_ports[i]);

    for (int i = 0; i < n_target_ports; i++) {
        int port = target_ports[i];
        if (int_list_has(tracked, n_tracked, port))
            continue;
        if (l2d_switchd_set_runtime_admin(SW_SOCKET, port, 1) != 0) {
            ok = false;
            NL_LOG_WARN("secure-access-port shutdown %s: failed to disable member port %d",
                        st->name, port);
            continue;
        }
        int_list_add_unique(tracked, &n_tracked, NL_MAX_PORTS, port);
    }
    if (!ok)
        return false;

    was_shutdown = st->mac_shutdown;
    st->mac_shutdown = true;
    if (!was_shutdown || st->mac_shutdown_time <= 0)
        st->mac_shutdown_time = now;
    secure_access_store_drop_state(st, tracked, n_tracked, "shutdown");
    snprintf(st->mac_shutdown_reason, sizeof(st->mac_shutdown_reason),
             "dynamic MAC limit exceeded (%d/%d), shutdown active",
             st->dynamic_macs, st->mac_limit);
    if (!was_shutdown)
        NL_LOG_WARN("secure-access-port shutdown %s: %s",
                    st->name, st->mac_shutdown_reason);
    return true;
}

static void enforce_secure_access(l2_if_state *ifs, int n_ifs,
                                  const l2_lag_info *lags, int max_lags,
                                  time_t now) {
    for (int i = 0; i < n_ifs; i++) {
        l2_if_state *st = &ifs[i];
        bool shutdown_action = strcmp(st->mac_action, "shutdown") == 0;
        bool drop_action = strcmp(st->mac_action, "drop") == 0 ||
                           strcmp(st->mac_action, "restrict") == 0;
        bool over_limit = st->mac_limit_configured &&
                          st->mac_limit > 0 &&
                          st->dynamic_macs > st->mac_limit;
        int target_ports[NL_MAX_PORTS];
        int n_target_ports = 0;

        if (drop_action || shutdown_action)
            n_target_ports = secure_access_target_ports(st, lags, max_lags,
                                                        target_ports,
                                                        NL_MAX_PORTS);

        if (!st->mac_limit_configured || !drop_action ||
            st->disabled || n_target_ports <= 0) {
            if (st->mac_drop_active &&
                secure_access_disable_tracked(st, NULL, 0))
                secure_access_clear_drop_state(st);
        }

        if (!st->mac_limit_configured || (!shutdown_action && !drop_action)) {
            if (st->mac_shutdown && !st->disabled)
                (void)secure_access_restore_shutdown(st, NULL, 0);
            continue;
        }

        if (!shutdown_action && st->mac_shutdown && !st->disabled)
            (void)secure_access_restore_shutdown(st, NULL, 0);

        if (drop_action) {
            if ((over_limit || st->mac_drop_active) &&
                !st->disabled && n_target_ports > 0) {
                bool stale_ok;
                bool enable_ok = true;
                bool action_changed =
                    strcmp(st->mac_enforced_action, st->mac_action) != 0;

                stale_ok = secure_access_disable_tracked(st, target_ports,
                                                         n_target_ports);
                for (int j = 0; j < n_target_ports; j++) {
                    int port = target_ports[j];
                    if (st->mac_drop_active && !action_changed &&
                        int_list_has(st->mac_enforced_ports,
                                     st->n_mac_enforced_ports, port))
                        continue;
                    if (l2d_switchd_set_port_security(SW_SOCKET, port,
                                                      true,
                                                      st->mac_action) != 0) {
                        enable_ok = false;
                        NL_LOG_WARN("secure-access-port %s %s: failed to enable port-security on port %d",
                                    st->mac_action, st->name, port);
                    }
                }
                if (stale_ok && enable_ok) {
                    bool was_active = st->mac_drop_active;
                    st->mac_drop_active = true;
                    if (!was_active || st->mac_drop_time <= 0)
                        st->mac_drop_time = now;
                    secure_access_store_drop_state(st, target_ports,
                                                   n_target_ports,
                                                   st->mac_action);
                    snprintf(st->mac_shutdown_reason,
                             sizeof(st->mac_shutdown_reason),
                             "dynamic MAC limit exceeded (%d/%d), port-security %s active",
                             st->dynamic_macs, st->mac_limit,
                             st->mac_action);
                    if (!was_active || action_changed)
                        NL_LOG_WARN("secure-access-port %s %s: %s",
                                    st->mac_action, st->name,
                                    st->mac_shutdown_reason);
                }
            }
            continue;
        }

        if (st->mac_shutdown) {
            if (!st->disabled && n_target_ports > 0)
                (void)secure_access_apply_shutdown(st, target_ports,
                                                   n_target_ports, now);
            continue;
        }

        if (!over_limit || st->disabled || n_target_ports <= 0)
            continue;

        (void)secure_access_apply_shutdown(st, target_ports,
                                           n_target_ports, now);
    }
}

static void mark_config_snapshot_incomplete(void) {
    pthread_mutex_lock(&g_l2d.lock);
    g_l2d.config_complete = false;
    pthread_mutex_unlock(&g_l2d.lock);
}

void l2d_refresh_cache(void) {
    nl_yang_session *ys = nl_yang_session_create(NULL);
    l2d_refresh_work *work = NULL;
    char active_path[512];
    char *xml;
    struct lyd_node *tree;

    if (!ys) {
        mark_config_snapshot_incomplete();
        return;
    }

    nl_config_file_path(active_path, sizeof(active_path), "active.conf");
    xml = read_config_text_exact(active_path);
    if (!xml) {
        NL_LOG_WARN("l2d cache kept previous generation: cannot read complete active config");
        mark_config_snapshot_incomplete();
        nl_yang_session_destroy(ys);
        return;
    }
    tree = nl_yang_from_xml(ys, xml);
    if (!tree) {
        NL_LOG_WARN("l2d cache kept previous generation: active config is invalid");
        mark_config_snapshot_incomplete();
        free(xml);
        nl_yang_session_destroy(ys);
        return;
    }
    nl_yang_data_set(ys, tree);

    work = calloc(1, sizeof(*work));
    if (!work) {
        mark_config_snapshot_incomplete();
        free(xml);
        nl_yang_session_destroy(ys);
        return;
    }
    l2_vlan_state *vlans = work->vlans;
    l2_if_state *ifs = work->ifs;
    int n_vlans = 0;
    int n_ifs = 0;
    bool sw_up = l2d_switchd_reachable(SW_SOCKET);
    int max_ae = l2d_max_ae();
    l2_lag_info *lags = work->lags;
    int n_lags = 0;
    nl_stp_snapshot stp_snapshot = {0};
    l2_mac_entry *mac_entries = work->mac_entries;
    int n_mac_entries = 0;
    bool mac_snapshot_complete = false;
    bool stp_snapshot_complete = false;
    char *mac_update_xml = NULL;
    bool move_dampening_configured = false;
    int move_dampening_threshold = 0;
    int move_dampening_window = 0;
    char move_dampening_action[16] = "alarm";
    char (*dhcp_snooping_vlans)[64] = work->dhcp_snooping_vlans;
    int n_dhcp_snooping_vlans = 0;
    char (*arp_inspection_vlans)[64] = work->arp_inspection_vlans;
    int n_arp_inspection_vlans = 0;
    l2_dhcp_binding *dhcp_bindings = work->dhcp_bindings;
    int n_dhcp_bindings = 0;
    l2_user_filter *user_filters = work->user_filters;
    int n_user_filters = 0;
    l2_ingress_ipv4_acl *ingress_ipv4_acl = work->ingress_ipv4_acl;
    int n_ingress_ipv4_acl = 0;
    l2_acl_policer *acl_policer = work->acl_policer;
    int n_acl_policer = 0;
    l2_egress_acl *egress_acl = work->egress_acl;
    int n_egress_acl = 0;
    l2_acl_independent *acl_independent = work->acl_independent;
    int n_acl_independent = 0;
    for (int i = 0; i < max_ae; i++) {
        memset(&lags[i], 0, sizeof(lags[i]));
        lags[i].ae_id = i;
        snprintf(lags[i].name, sizeof(lags[i].name), "ae%d", i);
    }
    if (sw_up)
        n_lags = collect_lag_info(lags, max_ae);
    if (sw_up) {
        stp_snapshot_complete = l2d_switchd_get_stp_snapshot(
            SW_SOCKET, &stp_snapshot) == 0 && stp_snapshot.complete;
        mac_snapshot_complete = collect_mac_entries(
            mac_entries, L2D_MAX_MAC_ENTRIES, &n_mac_entries);
        mac_update_xml = calloc(1, L2D_MAC_UPDATE_XML_BUFFER_SIZE);
        if (mac_update_xml) {
            if (l2d_switchd_get_mac_update_events(
                    SW_SOCKET, mac_update_xml,
                    L2D_MAC_UPDATE_XML_BUFFER_SIZE) <= 0)
                mac_update_xml[0] = '\0';
        }
    }

    {
        const char *threshold;
        const char *window;
        const char *action;
        threshold = nl_yang_get(ys,
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/mac-move/dampening/threshold");
        window = nl_yang_get(ys,
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/mac-move/dampening/window");
        action = nl_yang_get(ys,
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/mac-move/dampening/action");
        if (threshold && threshold[0] && window && window[0]) {
            move_dampening_configured = true;
            move_dampening_threshold = atoi(threshold);
            move_dampening_window = atoi(window);
            snprintf(move_dampening_action, sizeof(move_dampening_action),
                     "%s", action && action[0] ? action : "alarm");
        }
    }

    n_vlans = collect_vlan_state_from_xml(xml, vlans,
                                          L2D_MAX_VLANS,
                                          sw_up);

    for (int i = 0; i < n_vlans; i++) {
        char path[256];
        const char *present;
        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/dhcp-snooping/vlan[name='%s']/name",
                 vlans[i].name);
        present = nl_yang_get(ys, path);
        if (present && n_dhcp_snooping_vlans < L2D_MAX_SECURITY_VLANS)
            snprintf(dhcp_snooping_vlans[n_dhcp_snooping_vlans++],
                     sizeof(dhcp_snooping_vlans[0]), "%s", present);
        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/arp-inspection/vlan[name='%s']/name",
                 vlans[i].name);
        present = nl_yang_get(ys, path);
        if (present && n_arp_inspection_vlans < L2D_MAX_SECURITY_VLANS)
            snprintf(arp_inspection_vlans[n_arp_inspection_vlans++],
                     sizeof(arp_inspection_vlans[0]), "%s", present);
    }

    char (*known_ifs)[64] = work->known_ifs;
    int n_known_ifs = 0;
    nl_port_entry *entries = work->port_entries;
    int n_entries = nl_ifid_get_all(entries, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_entries &&
         n_known_ifs < L2D_MAX_IFS; i++) {
        if (!nl_ifid_is_user_port(entries[i].logical_port))
            continue;
        snprintf(known_ifs[n_known_ifs++], sizeof(known_ifs[0]), "%s",
                 entries[i].canonical_name);
    }
    for (int ae = 0; ae < max_ae &&
         n_known_ifs < L2D_MAX_IFS; ae++)
        snprintf(known_ifs[n_known_ifs++], sizeof(known_ifs[0]), "ae%d", ae);
    (void)n_lags;
    for (int i = 0; i < n_known_ifs && n_ifs < L2D_MAX_IFS; i++) {
        char path[256];
        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/interfaces/interface[name='%s']/name",
                 known_ifs[i]);
        const char *ifname = nl_yang_get(ys, path);
        if (!ifname)
            continue;

        l2_if_state *st = &ifs[n_ifs];
        memset(st, 0, sizeof(*st));
        snprintf(st->name, sizeof(st->name), "%s", ifname);

        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/interfaces/interface[name='%s']"
                 "/disable", ifname);
        const char *disable = nl_yang_get(ys, path);
        st->disabled = disable && strcmp(disable, "true") == 0;

        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/interfaces/interface[name='%s']"
                 "/unit/logical-unit[unit-id='0']"
                 "/family/ethernet-switching/interface-mode", ifname);
        const char *mode = nl_yang_get(ys, path);
        if (mode)
            snprintf(st->mode, sizeof(st->mode), "%s", mode);
        else
            snprintf(st->mode, sizeof(st->mode), "none");

        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/secure-access-port/interface[name='%s']/mac-limit",
                 ifname);
        const char *limit = nl_yang_get(ys, path);
        if (limit && limit[0]) {
            st->mac_limit_configured = true;
            st->mac_limit = atoi(limit);
        }
        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/secure-access-port/interface[name='%s']/violation-action",
                 ifname);
        const char *action = nl_yang_get(ys, path);
        snprintf(st->mac_action, sizeof(st->mac_action), "%s",
                 action && action[0] ? action : "alarm");

        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/dhcp-snooping/interface[name='%s']/trusted",
                 ifname);
        action = nl_yang_get(ys, path);
        st->dhcp_snooping_trusted = action && strcmp(action, "true") == 0;

        snprintf(path, sizeof(path),
                 "/netlab:netlab-config/ethernet-switching-options"
                 "/arp-inspection/interface[name='%s']/trusted",
                 ifname);
        action = nl_yang_get(ys, path);
        st->arp_inspection_trusted = action && strcmp(action, "true") == 0;

        collect_interface_members(ys, xml, ifname, st);
        int port = ifname_to_port(ifname, lags, max_ae);
        st->hw_member = sw_up && port > 0 && st->n_members > 0;
        for (int j = 0; st->hw_member && j < st->n_members; j++) {
            int ae_id = l2d_ae_id_from_name(ifname);
            if (st->member_vids[j] <= 0) {
                st->hw_member = false;
            } else if (ae_id >= 0 && ae_id < max_ae &&
                       lags[ae_id].n_members > 0) {
                for (int k = 0; k < lags[ae_id].n_members; k++) {
                    if (!l2d_stp_has_member(&stp_snapshot,
                                            st->member_vids[j],
                                            lags[ae_id].members[k])) {
                        st->hw_member = false;
                        break;
                    }
                }
            } else if (!l2d_stp_has_member(&stp_snapshot,
                                           st->member_vids[j],
                                           port)) {
                st->hw_member = false;
            }
        }
        n_ifs++;
    }

    {
        char *dhcp = strstr(xml, "<dhcp-snooping>");
        char *dhcp_end = dhcp ? strstr(dhcp, "</dhcp-snooping>") : NULL;
        char *p = dhcp;

        while (dhcp && dhcp_end &&
               (p = strstr(p, "<binding>")) && p < dhcp_end &&
               n_dhcp_bindings < L2D_MAX_DHCP_BINDINGS) {
            char *end = strstr(p, "</binding>");
            char mac[18];
            char vlan[64];
            char ifname[64];
            char ip[16];

            if (!end || end > dhcp_end)
                break;
            if (l2d_extract_xml_leaf(p, end, "mac-address", mac,
                                     sizeof(mac)) == 0 &&
                l2d_extract_xml_leaf(p, end, "vlan", vlan,
                                     sizeof(vlan)) == 0 &&
                l2d_extract_xml_leaf(p, end, "interface", ifname,
                                     sizeof(ifname)) == 0 &&
                l2d_extract_xml_leaf(p, end, "ip-address", ip,
                                     sizeof(ip)) == 0) {
                l2_dhcp_binding *b = &dhcp_bindings[n_dhcp_bindings++];
                snprintf(b->mac, sizeof(b->mac), "%s", mac);
                snprintf(b->vlan, sizeof(b->vlan), "%s", vlan);
                snprintf(b->ifname, sizeof(b->ifname), "%s", ifname);
                snprintf(b->ip, sizeof(b->ip), "%s", ip);
                b->vid = find_vlan_vid(vlans, n_vlans, vlan);
                b->active_dai =
                    b->vid > 0 &&
                    security_vlan_list_has(arp_inspection_vlans,
                                           n_arp_inspection_vlans, vlan);
            }
            p = end + strlen("</binding>");
        }
    }

    {
        const char *feature_names[] = { "user-filter", "ingress-acl" };

        for (size_t i = 0;
             i < sizeof(feature_names) / sizeof(feature_names[0]);
             i++) {
            char open_tag[64];
            char close_tag[64];
            char *feature;
            char *feature_end;
            char *p;

            snprintf(open_tag, sizeof(open_tag), "<%s>", feature_names[i]);
            snprintf(close_tag, sizeof(close_tag), "</%s>",
                     feature_names[i]);
            feature = strstr(xml, open_tag);
            feature_end = feature ? strstr(feature, close_tag) : NULL;
            p = feature;

            while (feature && feature_end &&
                   (p = strstr(p, "<term>")) && p < feature_end &&
                   n_user_filters < L2D_MAX_USER_FILTERS) {
                char *end = strstr(p, "</term>");
                char name[64];
                char vlan[64];
                char ifname[64];
                char src_mac[18];
                char dst_mac[18];
                char action[16] = "drop";
                bool has_src;
                bool has_dst;

                if (!end || end > feature_end)
                    break;
                has_src = l2d_extract_xml_leaf(p, end, "source-mac",
                                               src_mac,
                                               sizeof(src_mac)) == 0;
                has_dst = l2d_extract_xml_leaf(p, end, "destination-mac",
                                               dst_mac,
                                               sizeof(dst_mac)) == 0;
                if (l2d_extract_xml_leaf(p, end, "name", name,
                                         sizeof(name)) == 0 &&
                    l2d_extract_xml_leaf(p, end, "vlan", vlan,
                                         sizeof(vlan)) == 0 &&
                    l2d_extract_xml_leaf(p, end, "interface", ifname,
                                         sizeof(ifname)) == 0 &&
                    has_src != has_dst) {
                    l2_user_filter *f = &user_filters[n_user_filters++];
                    snprintf(f->feature, sizeof(f->feature), "%s",
                             feature_names[i]);
                    snprintf(f->name, sizeof(f->name), "%s", name);
                    snprintf(f->vlan, sizeof(f->vlan), "%s", vlan);
                    f->vid = find_vlan_vid(vlans, n_vlans, vlan);
                    snprintf(f->ifname, sizeof(f->ifname), "%s", ifname);
                    snprintf(f->mac, sizeof(f->mac), "%s",
                             has_src ? src_mac : dst_mac);
                    snprintf(f->mac_kind, sizeof(f->mac_kind), "%s",
                             has_dst ? "destination" : "source");
                    if (l2d_extract_xml_leaf(p, end, "action", action,
                                             sizeof(action)) == 0 &&
                        action[0])
                        snprintf(f->action, sizeof(f->action), "%s",
                                 action);
                    else
                        snprintf(f->action, sizeof(f->action), "drop");
                }
                p = end + strlen("</term>");
            }
        }
    }

    {
        char *feature = strstr(xml, "<ingress-ipv4-acl>");
        char *feature_end = feature ? strstr(feature,
                                             "</ingress-ipv4-acl>") : NULL;
        char *p = feature;

        while (feature && feature_end &&
               (p = strstr(p, "<term>")) && p < feature_end &&
               n_ingress_ipv4_acl < L2D_MAX_INGRESS_IPV4_ACL) {
            char *end = strstr(p, "</term>");
            char name[64];
            char vlan[64];
            char ifname[64];
            char src_ip[16];
            char dst_ip[16];
            char src_prefix[32];
            char dst_prefix[32];
            char dscp[16];
            char ecn[16];
            char proto[16];
            char src_port[16];
            char dst_port[16];
            char src_port_range[16];
            char dst_port_range[16];
            char tcp_flags[16];
            char tcp_flags_mask[16];
            char action[16] = "drop";
            u32 prefix_ip;
            u32 prefix_mask;
            int prefix_len;
            l2_ingress_ipv4_acl *acl;

            if (!end || end > feature_end)
                break;
            if (l2d_extract_xml_leaf(p, end, "name", name,
                                     sizeof(name)) != 0 ||
                l2d_extract_xml_leaf(p, end, "vlan", vlan,
                                     sizeof(vlan)) != 0 ||
                l2d_extract_xml_leaf(p, end, "interface", ifname,
                                     sizeof(ifname)) != 0) {
                p = end + strlen("</term>");
                continue;
            }
            acl = &ingress_ipv4_acl[n_ingress_ipv4_acl++];
            snprintf(acl->name, sizeof(acl->name), "%s", name);
            snprintf(acl->vlan, sizeof(acl->vlan), "%s", vlan);
            acl->vid = find_vlan_vid(vlans, n_vlans, vlan);
            snprintf(acl->ifname, sizeof(acl->ifname), "%s", ifname);
            if (l2d_extract_xml_leaf(p, end, "source-ip", src_ip,
                                     sizeof(src_ip)) == 0) {
                acl->has_src_ip = true;
                acl->has_src_ip_mask = true;
                snprintf(acl->src_ip, sizeof(acl->src_ip), "%s", src_ip);
                snprintf(acl->src_mask, sizeof(acl->src_mask),
                         "255.255.255.255");
            } else if (l2d_extract_xml_leaf(p, end, "source-prefix",
                                            src_prefix,
                                            sizeof(src_prefix)) == 0 &&
                       l2_parse_ipv4_prefix_text(src_prefix, &prefix_ip,
                                                 &prefix_mask,
                                                 &prefix_len)) {
                acl->has_src_ip = true;
                acl->has_src_ip_mask = true;
                acl->has_src_prefix = true;
                l2_format_ipv4_text(prefix_ip, acl->src_ip,
                                    sizeof(acl->src_ip));
                l2_format_ipv4_text(prefix_mask, acl->src_mask,
                                    sizeof(acl->src_mask));
                l2_format_ipv4_prefix_text(prefix_ip, prefix_len,
                                           acl->src_prefix,
                                           sizeof(acl->src_prefix));
            }
            if (l2d_extract_xml_leaf(p, end, "destination-ip", dst_ip,
                                     sizeof(dst_ip)) == 0) {
                acl->has_dst_ip = true;
                acl->has_dst_ip_mask = true;
                snprintf(acl->dst_ip, sizeof(acl->dst_ip), "%s", dst_ip);
                snprintf(acl->dst_mask, sizeof(acl->dst_mask),
                         "255.255.255.255");
            } else if (l2d_extract_xml_leaf(p, end, "destination-prefix",
                                            dst_prefix,
                                            sizeof(dst_prefix)) == 0 &&
                       l2_parse_ipv4_prefix_text(dst_prefix, &prefix_ip,
                                                 &prefix_mask,
                                                 &prefix_len)) {
                acl->has_dst_ip = true;
                acl->has_dst_ip_mask = true;
                acl->has_dst_prefix = true;
                l2_format_ipv4_text(prefix_ip, acl->dst_ip,
                                    sizeof(acl->dst_ip));
                l2_format_ipv4_text(prefix_mask, acl->dst_mask,
                                    sizeof(acl->dst_mask));
                l2_format_ipv4_prefix_text(prefix_ip, prefix_len,
                                           acl->dst_prefix,
                                           sizeof(acl->dst_prefix));
            }
            if (l2d_extract_xml_leaf(p, end, "protocol", proto,
                                     sizeof(proto)) == 0) {
                acl->has_protocol = true;
                acl->protocol = atoi(proto);
            }
            if (l2d_extract_xml_leaf(p, end, "dscp", dscp,
                                     sizeof(dscp)) == 0) {
                acl->has_dscp = true;
                acl->dscp = atoi(dscp);
            }
            if (l2d_extract_xml_leaf(p, end, "ecn", ecn,
                                     sizeof(ecn)) == 0) {
                acl->has_ecn = true;
                acl->ecn = atoi(ecn);
            }
            if (l2d_extract_xml_leaf(p, end, "source-port", src_port,
                                     sizeof(src_port)) == 0) {
                acl->has_src_port = true;
                acl->src_port = atoi(src_port);
            }
            if (l2d_extract_xml_leaf(p, end, "destination-port", dst_port,
                                     sizeof(dst_port)) == 0) {
                acl->has_dst_port = true;
                acl->dst_port = atoi(dst_port);
            }
            if (l2d_extract_xml_leaf(p, end, "source-port-range",
                                     src_port_range,
                                     sizeof(src_port_range)) == 0 &&
                l2_parse_port_range_text(src_port_range,
                                         &acl->src_port_start,
                                         &acl->src_port_end)) {
                acl->has_src_port_range = true;
                snprintf(acl->src_port_range,
                         sizeof(acl->src_port_range), "%d-%d",
                         acl->src_port_start, acl->src_port_end);
            }
            if (l2d_extract_xml_leaf(p, end, "destination-port-range",
                                     dst_port_range,
                                     sizeof(dst_port_range)) == 0 &&
                l2_parse_port_range_text(dst_port_range,
                                         &acl->dst_port_start,
                                         &acl->dst_port_end)) {
                acl->has_dst_port_range = true;
                snprintf(acl->dst_port_range,
                         sizeof(acl->dst_port_range), "%d-%d",
                         acl->dst_port_start, acl->dst_port_end);
            }
            if (l2d_extract_xml_leaf(p, end, "tcp-flags", tcp_flags,
                                     sizeof(tcp_flags)) == 0) {
                acl->has_tcp_flags = true;
                acl->tcp_flags = atoi(tcp_flags);
                acl->tcp_flags_mask = 63;
            }
            if (l2d_extract_xml_leaf(p, end, "tcp-flags-mask",
                                     tcp_flags_mask,
                                     sizeof(tcp_flags_mask)) == 0) {
                acl->has_tcp_flags_mask = true;
                acl->tcp_flags_mask = atoi(tcp_flags_mask);
            }
            if (l2d_extract_xml_leaf(p, end, "action", action,
                                     sizeof(action)) == 0 && action[0])
                snprintf(acl->action, sizeof(acl->action), "%s", action);
            else
                snprintf(acl->action, sizeof(acl->action), "drop");
            p = end + strlen("</term>");
        }
    }

    {
        char *feature = strstr(xml, "<acl-policer>");
        char *feature_end = feature ? strstr(feature,
                                             "</acl-policer>") : NULL;
        char *p = feature;

        while (feature && feature_end &&
               (p = strstr(p, "<term>")) && p < feature_end &&
               n_acl_policer < L2D_MAX_ACL_POLICER) {
            char *end = strstr(p, "</term>");
            char name[64];
            char ifname[64];
            char dst_mac[18];
            char rate_text[32];
            char burst_text[32] = "65536";
            l2_acl_policer *policer;

            if (!end || end > feature_end)
                break;
            if (l2d_extract_xml_leaf(p, end, "name", name,
                                     sizeof(name)) != 0 ||
                l2d_extract_xml_leaf(p, end, "interface", ifname,
                                     sizeof(ifname)) != 0 ||
                l2d_extract_xml_leaf(p, end, "destination-mac", dst_mac,
                                     sizeof(dst_mac)) != 0 ||
                l2d_extract_xml_leaf(p, end, "bandwidth", rate_text,
                                     sizeof(rate_text)) != 0) {
                p = end + strlen("</term>");
                continue;
            }
            (void)l2d_extract_xml_leaf(p, end, "burst-size", burst_text,
                                       sizeof(burst_text));
            policer = &acl_policer[n_acl_policer++];
            snprintf(policer->name, sizeof(policer->name), "%s", name);
            snprintf(policer->ifname, sizeof(policer->ifname), "%s",
                     ifname);
            snprintf(policer->dst_mac, sizeof(policer->dst_mac), "%s",
                     dst_mac);
            policer->rate_kbps = atoi(rate_text);
            policer->burst_bytes = atoi(burst_text);
            p = end + strlen("</term>");
        }
    }

    {
        char *feature = strstr(xml, "<egress-acl>");
        char *feature_end = feature ? strstr(feature,
                                             "</egress-acl>") : NULL;
        char *p = feature;

        while (feature && feature_end &&
               (p = strstr(p, "<term>")) && p < feature_end &&
               n_egress_acl < L2D_MAX_EGRESS_ACL) {
            char *end = strstr(p, "</term>");
            char name[64];
            char ifname[64];
            char src_mac[18] = {0};
            char dst_mac[18];
            char action[16] = "drop";
            bool has_src;
            bool has_dst;
            l2_egress_acl *acl;

            if (!end || end > feature_end)
                break;
            if (l2d_extract_xml_leaf(p, end, "name", name,
                                     sizeof(name)) != 0 ||
                l2d_extract_xml_leaf(p, end, "interface", ifname,
                                     sizeof(ifname)) != 0) {
                p = end + strlen("</term>");
                continue;
            }
            has_src = l2d_extract_xml_leaf(p, end, "source-mac", src_mac,
                                           sizeof(src_mac)) == 0 &&
                      src_mac[0] != '\0';
            has_dst = l2d_extract_xml_leaf(p, end, "destination-mac", dst_mac,
                                           sizeof(dst_mac)) == 0 &&
                      dst_mac[0] != '\0';
            if (!has_src && !has_dst) {
                p = end + strlen("</term>");
                continue;
            }
            acl = &egress_acl[n_egress_acl++];
            snprintf(acl->name, sizeof(acl->name), "%s", name);
            snprintf(acl->ifname, sizeof(acl->ifname), "%s", ifname);
            if (has_src)
                snprintf(acl->src_mac, sizeof(acl->src_mac), "%s", src_mac);
            if (has_dst)
                snprintf(acl->dst_mac, sizeof(acl->dst_mac), "%s", dst_mac);
            if (l2d_extract_xml_leaf(p, end, "action", action,
                                     sizeof(action)) == 0 && action[0])
                snprintf(acl->action, sizeof(acl->action), "%s", action);
            else
                snprintf(acl->action, sizeof(acl->action), "drop");
            p = end + strlen("</term>");
        }
    }

    {
        char *feature = strstr(xml, "<acl-independent>");
        char *feature_end = feature ? strstr(feature,
                                             "</acl-independent>") : NULL;
        char *g = feature;

        while (feature && feature_end &&
               (g = strstr(g, "<group>")) && g < feature_end &&
               n_acl_independent < L2D_MAX_ACL_INDEPENDENT) {
            char *g_end = strstr(g, "</group>");
            char *first_term;
            char *group_leaf_end;
            char group_name[64];
            char *p;

            if (!g_end || g_end > feature_end)
                break;
            first_term = strstr(g, "<term>");
            group_leaf_end = (first_term && first_term < g_end) ?
                             first_term : g_end;
            if (l2d_extract_xml_leaf(g, group_leaf_end, "name", group_name,
                                     sizeof(group_name)) != 0 ||
                !group_name[0]) {
                g = g_end + strlen("</group>");
                continue;
            }

            p = g;
            while ((p = strstr(p, "<term>")) && p < g_end &&
                   n_acl_independent < L2D_MAX_ACL_INDEPENDENT) {
                char *end = strstr(p, "</term>");
                char term_name[64];
                char family[16];
                char vlan[64] = {0};
                char ifname[64] = {0};
                char action[16] = {0};
                char src_mac_text[32] = {0};
                char dst_mac_text[32] = {0};
                char src_ip[16] = {0};
                char dst_ip[16] = {0};
                char src_prefix[32] = {0};
                char dst_prefix[32] = {0};
                char dscp_text[16] = {0};
                char proto_text[16] = {0};
                char src_port_text[16] = {0};
                char dst_port_text[16] = {0};
                char src_port_range_text[16] = {0};
                char dst_port_range_text[16] = {0};
                char tcp_flags_text[16] = {0};
                char tcp_flags_mask_text[16] = {0};
                char rate_text[32] = {0};
                char burst_text[32] = {0};
                struct in_addr addr;
                u32 prefix_ip;
                u32 prefix_mask;
                int prefix_len;
                int range_start;
                int range_end;
                l2_acl_independent *acl;

                if (!end || end > g_end)
                    break;
                if (l2d_extract_xml_leaf(p, end, "name", term_name,
                                         sizeof(term_name)) != 0 ||
                    l2d_extract_xml_leaf(p, end, "family", family,
                                         sizeof(family)) != 0) {
                    p = end + strlen("</term>");
                    continue;
                }

                acl = &acl_independent[n_acl_independent];
                memset(acl, 0, sizeof(*acl));
                acl->slot = n_acl_independent;
                snprintf(acl->group, sizeof(acl->group), "%s", group_name);
                snprintf(acl->term, sizeof(acl->term), "%s", term_name);
                snprintf(acl->family, sizeof(acl->family), "%s", family);
                if (l2d_extract_xml_leaf(p, end, "vlan", vlan,
                                         sizeof(vlan)) == 0 && vlan[0]) {
                    snprintf(acl->vlan, sizeof(acl->vlan), "%s", vlan);
                    acl->vid = find_vlan_vid(vlans, n_vlans, vlan);
                }
                if (l2d_extract_xml_leaf(p, end, "interface", ifname,
                                         sizeof(ifname)) == 0 && ifname[0])
                    snprintf(acl->ifname, sizeof(acl->ifname), "%s", ifname);
                if (l2d_extract_xml_leaf(p, end, "source-mac", src_mac_text,
                                         sizeof(src_mac_text)) == 0 &&
                    src_mac_text[0] &&
                    l2_normalize_mac_text(src_mac_text, acl->src_mac,
                                          sizeof(acl->src_mac)))
                    acl->has_src_mac = true;
                if (l2d_extract_xml_leaf(p, end, "destination-mac",
                                         dst_mac_text,
                                         sizeof(dst_mac_text)) == 0 &&
                    dst_mac_text[0] &&
                    l2_normalize_mac_text(dst_mac_text, acl->dst_mac,
                                          sizeof(acl->dst_mac)))
                    acl->has_dst_mac = true;
                if (l2d_extract_xml_leaf(p, end, "source-ip", src_ip,
                                         sizeof(src_ip)) == 0 &&
                    inet_pton(AF_INET, src_ip, &addr) == 1) {
                    acl->has_src_ip = true;
                    acl->has_src_ip_mask = true;
                    snprintf(acl->src_ip, sizeof(acl->src_ip), "%s", src_ip);
                    snprintf(acl->src_mask, sizeof(acl->src_mask),
                             "255.255.255.255");
                } else if (l2d_extract_xml_leaf(p, end, "source-prefix",
                                                src_prefix,
                                                sizeof(src_prefix)) == 0 &&
                           l2_parse_ipv4_prefix_text(src_prefix, &prefix_ip,
                                                     &prefix_mask,
                                                     &prefix_len)) {
                    acl->has_src_ip = true;
                    acl->has_src_ip_mask = true;
                    acl->has_src_prefix = true;
                    l2_format_ipv4_text(prefix_ip, acl->src_ip,
                                        sizeof(acl->src_ip));
                    l2_format_ipv4_text(prefix_mask, acl->src_mask,
                                        sizeof(acl->src_mask));
                    l2_format_ipv4_prefix_text(prefix_ip, prefix_len,
                                               acl->src_prefix,
                                               sizeof(acl->src_prefix));
                }
                if (l2d_extract_xml_leaf(p, end, "destination-ip", dst_ip,
                                         sizeof(dst_ip)) == 0 &&
                    inet_pton(AF_INET, dst_ip, &addr) == 1) {
                    acl->has_dst_ip = true;
                    acl->has_dst_ip_mask = true;
                    snprintf(acl->dst_ip, sizeof(acl->dst_ip), "%s", dst_ip);
                    snprintf(acl->dst_mask, sizeof(acl->dst_mask),
                             "255.255.255.255");
                } else if (l2d_extract_xml_leaf(p, end, "destination-prefix",
                                                dst_prefix,
                                                sizeof(dst_prefix)) == 0 &&
                           l2_parse_ipv4_prefix_text(dst_prefix, &prefix_ip,
                                                     &prefix_mask,
                                                     &prefix_len)) {
                    acl->has_dst_ip = true;
                    acl->has_dst_ip_mask = true;
                    acl->has_dst_prefix = true;
                    l2_format_ipv4_text(prefix_ip, acl->dst_ip,
                                        sizeof(acl->dst_ip));
                    l2_format_ipv4_text(prefix_mask, acl->dst_mask,
                                        sizeof(acl->dst_mask));
                    l2_format_ipv4_prefix_text(prefix_ip, prefix_len,
                                               acl->dst_prefix,
                                               sizeof(acl->dst_prefix));
                }
                if (l2d_extract_xml_leaf(p, end, "dscp", dscp_text,
                                         sizeof(dscp_text)) == 0) {
                    acl->has_dscp = true;
                    acl->dscp = atoi(dscp_text);
                }
                if (l2d_extract_xml_leaf(p, end, "protocol", proto_text,
                                         sizeof(proto_text)) == 0) {
                    acl->has_protocol = true;
                    acl->protocol = atoi(proto_text);
                }
                if (l2d_extract_xml_leaf(p, end, "source-port", src_port_text,
                                         sizeof(src_port_text)) == 0) {
                    acl->has_src_port = true;
                    acl->src_port = atoi(src_port_text);
                }
                if (l2d_extract_xml_leaf(p, end, "destination-port",
                                         dst_port_text,
                                         sizeof(dst_port_text)) == 0) {
                    acl->has_dst_port = true;
                    acl->dst_port = atoi(dst_port_text);
                }
                if (l2d_extract_xml_leaf(p, end, "source-port-range",
                                         src_port_range_text,
                                         sizeof(src_port_range_text)) == 0 &&
                    l2_parse_port_range_text(src_port_range_text,
                                             &range_start, &range_end)) {
                    acl->has_src_port_range = true;
                    acl->src_port_start = range_start;
                    acl->src_port_end = range_end;
                    snprintf(acl->src_port_range,
                             sizeof(acl->src_port_range), "%d-%d",
                             range_start, range_end);
                }
                if (l2d_extract_xml_leaf(p, end, "destination-port-range",
                                         dst_port_range_text,
                                         sizeof(dst_port_range_text)) == 0 &&
                    l2_parse_port_range_text(dst_port_range_text,
                                             &range_start, &range_end)) {
                    acl->has_dst_port_range = true;
                    acl->dst_port_start = range_start;
                    acl->dst_port_end = range_end;
                    snprintf(acl->dst_port_range,
                             sizeof(acl->dst_port_range), "%d-%d",
                             range_start, range_end);
                }
                if (l2d_extract_xml_leaf(p, end, "tcp-flags", tcp_flags_text,
                                         sizeof(tcp_flags_text)) == 0) {
                    acl->has_tcp_flags = true;
                    acl->tcp_flags = atoi(tcp_flags_text);
                    acl->tcp_flags_mask = 63;
                }
                if (l2d_extract_xml_leaf(p, end, "tcp-flags-mask",
                                         tcp_flags_mask_text,
                                         sizeof(tcp_flags_mask_text)) == 0) {
                    acl->has_tcp_flags_mask = true;
                    acl->tcp_flags_mask = atoi(tcp_flags_mask_text);
                }
                if (l2d_extract_xml_leaf(p, end, "action", action,
                                         sizeof(action)) == 0 && action[0])
                    snprintf(acl->action, sizeof(acl->action), "%s", action);
                else
                    snprintf(acl->action, sizeof(acl->action), "drop");
                if (l2d_extract_xml_leaf(p, end, "bandwidth", rate_text,
                                         sizeof(rate_text)) == 0)
                    acl->rate_kbps = atoi(rate_text);
                if (l2d_extract_xml_leaf(p, end, "burst-size", burst_text,
                                         sizeof(burst_text)) == 0)
                    acl->burst_bytes = atoi(burst_text);
                n_acl_independent++;
                p = end + strlen("</term>");
            }
            g = g_end + strlen("</group>");
        }
    }

    if (mac_snapshot_complete)
        for (int i = 0; i < n_mac_entries; i++) {
            int idx = find_if_state(ifs, n_ifs, mac_entries[i].ifname);
            if (idx >= 0)
                ifs[idx].dynamic_macs++;
        }

    time_t now = time(NULL);
    restore_secure_state(ifs, n_ifs, !mac_snapshot_complete);
    if (mac_snapshot_complete)
        enforce_secure_access(ifs, n_ifs, lags, max_ae, now);

    pthread_mutex_lock(&g_l2d.lock);
    for (int i = 0; mac_snapshot_complete && i < n_mac_entries; i++) {
        int idx = find_seen_entry(&g_l2d, mac_entries[i].vlan,
                                  mac_entries[i].mac);
        if (idx < 0) {
            if (g_l2d.n_seen < (int)L2D_MAX_MAC_SEEN) {
                idx = g_l2d.n_seen++;
                g_l2d.seen[idx].vlan = mac_entries[i].vlan;
                snprintf(g_l2d.seen[idx].mac,
                         sizeof(g_l2d.seen[idx].mac), "%s",
                         mac_entries[i].mac);
                snprintf(g_l2d.seen[idx].ifname,
                         sizeof(g_l2d.seen[idx].ifname), "%s",
                         mac_entries[i].ifname);
                g_l2d.seen[idx].last_seen = now;
            }
            continue;
        }
        if (strcmp(g_l2d.seen[idx].ifname, mac_entries[i].ifname) != 0) {
            l2_mac_seen old_seen = g_l2d.seen[idx];
            record_mac_move(&g_l2d, &old_seen, &mac_entries[i], now,
                            ifs, n_ifs, move_dampening_configured,
                            move_dampening_threshold,
                            move_dampening_window,
                            move_dampening_action);
            snprintf(g_l2d.seen[idx].ifname,
                     sizeof(g_l2d.seen[idx].ifname), "%s",
                     mac_entries[i].ifname);
            g_l2d.seen[idx].last_seen = now;
        } else {
            g_l2d.seen[idx].last_seen = now;
        }
    }
    if (mac_snapshot_complete)
        process_mac_update_events_locked(
            &g_l2d, mac_update_xml, ifs, n_ifs, now,
            move_dampening_configured, move_dampening_threshold,
            move_dampening_window, move_dampening_action);
    for (int i = 0; mac_snapshot_complete && i < g_l2d.n_seen; ) {
        int retain_window = move_dampening_configured ?
            move_dampening_window : 0;
        if (current_has_entry(mac_entries, n_mac_entries,
                              g_l2d.seen[i].vlan, g_l2d.seen[i].mac) ||
            (retain_window > 0 && g_l2d.seen[i].last_seen > 0 &&
             now - g_l2d.seen[i].last_seen <= retain_window)) {
            i++;
            continue;
        }
        memmove(&g_l2d.seen[i], &g_l2d.seen[i + 1],
                sizeof(g_l2d.seen[0]) * (size_t)(g_l2d.n_seen - i - 1));
        g_l2d.n_seen--;
    }
    memcpy(g_l2d.vlans, vlans, sizeof(work->vlans));
    memcpy(g_l2d.ifs, ifs, sizeof(work->ifs));
    g_l2d.n_vlans = n_vlans;
    g_l2d.n_ifs = n_ifs;
    g_l2d.move_dampening_configured = move_dampening_configured;
    g_l2d.move_dampening_threshold = move_dampening_threshold;
    g_l2d.move_dampening_window = move_dampening_window;
    snprintf(g_l2d.move_dampening_action,
             sizeof(g_l2d.move_dampening_action), "%s",
             move_dampening_configured ? move_dampening_action : "alarm");
    memcpy(g_l2d.dhcp_snooping_vlans, dhcp_snooping_vlans,
           sizeof(work->dhcp_snooping_vlans));
    g_l2d.n_dhcp_snooping_vlans = n_dhcp_snooping_vlans;
    memcpy(g_l2d.arp_inspection_vlans, arp_inspection_vlans,
           sizeof(work->arp_inspection_vlans));
    g_l2d.n_arp_inspection_vlans = n_arp_inspection_vlans;
    memcpy(g_l2d.dhcp_bindings, dhcp_bindings,
           sizeof(work->dhcp_bindings));
    g_l2d.n_dhcp_bindings = n_dhcp_bindings;
    memcpy(g_l2d.user_filters, user_filters,
           sizeof(work->user_filters));
    g_l2d.n_user_filters = n_user_filters;
    memcpy(g_l2d.ingress_ipv4_acl, ingress_ipv4_acl,
           sizeof(work->ingress_ipv4_acl));
    g_l2d.n_ingress_ipv4_acl = n_ingress_ipv4_acl;
    memcpy(g_l2d.acl_policer, acl_policer,
           sizeof(work->acl_policer));
    g_l2d.n_acl_policer = n_acl_policer;
    memcpy(g_l2d.egress_acl, egress_acl,
           sizeof(work->egress_acl));
    g_l2d.n_egress_acl = n_egress_acl;
    memcpy(g_l2d.acl_independent, acl_independent,
           sizeof(work->acl_independent));
    g_l2d.n_acl_independent = n_acl_independent;
    g_l2d.switchd_up = sw_up;
    g_l2d.config_complete = true;
    g_l2d.mac_snapshot_complete = mac_snapshot_complete;
    g_l2d.stp_snapshot_complete = stp_snapshot_complete;
    g_l2d.cache_generation++;
    g_l2d.last_update = now;
    if (mac_snapshot_complete)
        g_l2d.mac_snapshot_last_update = now;
    if (stp_snapshot_complete)
        g_l2d.stp_snapshot_last_update = now;
    pthread_mutex_unlock(&g_l2d.lock);

    nl_stp_snapshot_reset(&stp_snapshot);
    free(mac_update_xml);
    free(work);
    free(xml);
    nl_yang_session_destroy(ys);
}

static int send_l2d_text(nl_conn *conn, nl_msg_hdr *msg, s32 error_code,
                         const char *text) {
    size_t len = text ? strlen(text) : 0;
    nl_msg_hdr *resp = nl_msg_alloc((u32)len);

    if (!resp)
        return -1;
    resp->type = error_code == 0 ? NL_MSG_RESPONSE : NL_MSG_ERROR;
    resp->request_id = msg->request_id;
    resp->error_code = error_code;
    resp->payload_len = (u32)len;
    if (len > 0)
        memcpy(resp->payload, text, len);
    nl_send(conn, resp);
    nl_msg_free(resp);
    return 0;
}

int l2d_clear_secure_access(nl_conn *conn, nl_msg_hdr *msg) {
    char payload[128] = {0};
    char ifname[64] = {0};
    int port;
    int ae_id;
    int clear_ports[NL_MAX_PORTS];
    int n_clear_ports = 0;
    int mac_clear_ports[NL_MAX_PORTS];
    int n_mac_clear_ports = 0;
    bool configured_disabled = false;
    bool was_shutdown = false;
    bool is_aggregate = false;

    if (msg->payload_len > 0) {
        size_t n = msg->payload_len;
        if (n >= sizeof(payload))
            n = sizeof(payload) - 1;
        memcpy(payload, msg->payload, n);
        payload[n] = '\0';
    }
    if (!l2_plan_text_get_str(payload, "interface", ifname, sizeof(ifname)) ||
        !ifname[0])
        return send_l2d_text(conn, msg, NL_ERR_INVALID_VALUE,
                             "error: missing interface");

    port = nl_ifid_name_to_logical_port(ifname);
    ae_id = l2d_ae_id_from_name(ifname);
    is_aggregate = port <= 0 && ae_id >= 0;
    if ((port <= 0 || !nl_ifid_is_user_port(port)) && !is_aggregate)
        return send_l2d_text(conn, msg, NL_ERR_INVALID_VALUE,
                             "error: secure-access-port clear requires a physical user or aggregate interface");

    pthread_mutex_lock(&g_l2d.lock);
    int idx = find_if_state(g_l2d.ifs, g_l2d.n_ifs, ifname);
    if (idx >= 0) {
        configured_disabled = g_l2d.ifs[idx].disabled;
        was_shutdown = g_l2d.ifs[idx].mac_shutdown;
        for (int i = 0; i < g_l2d.ifs[idx].n_mac_enforced_ports &&
                        n_clear_ports < NL_MAX_PORTS; i++) {
            int tracked = g_l2d.ifs[idx].mac_enforced_ports[i];
            if (tracked > 0 && !int_list_has(clear_ports, n_clear_ports,
                                             tracked))
                clear_ports[n_clear_ports++] = tracked;
        }
    }
    pthread_mutex_unlock(&g_l2d.lock);
    if (idx < 0)
        return send_l2d_text(conn, msg, NL_ERR_INVALID_VALUE,
                             "error: secure-access-port interface is not configured");

    if (is_aggregate) {
        l2_lag_info lags[L2D_AE_LIMIT];
        int max_ae = l2d_max_ae();

        if (max_ae > L2D_AE_LIMIT)
            max_ae = L2D_AE_LIMIT;
        (void)collect_lag_info(lags, max_ae);
        if (ae_id >= 0 && ae_id < max_ae) {
            if (lags[ae_id].logical_port > 0)
                mac_clear_ports[n_mac_clear_ports++] =
                    lags[ae_id].logical_port;
            for (int i = 0; i < lags[ae_id].n_members; i++) {
                int member = lags[ae_id].members[i];
                if (member > 0 &&
                    !int_list_has(mac_clear_ports, n_mac_clear_ports, member) &&
                    n_mac_clear_ports < NL_MAX_PORTS)
                    mac_clear_ports[n_mac_clear_ports++] = member;
                if (member > 0 && nl_ifid_is_user_port(member) &&
                    !int_list_has(clear_ports, n_clear_ports, member) &&
                    n_clear_ports < NL_MAX_PORTS)
                    clear_ports[n_clear_ports++] = member;
            }
        }
    } else {
        if (!int_list_has(mac_clear_ports, n_mac_clear_ports, port))
            mac_clear_ports[n_mac_clear_ports++] = port;
        if (!int_list_has(clear_ports, n_clear_ports, port))
            clear_ports[n_clear_ports++] = port;
    }
    for (int i = 0; i < n_clear_ports; i++) {
        int tracked = clear_ports[i];

        if (tracked > 0 && !int_list_has(mac_clear_ports, n_mac_clear_ports,
                                         tracked) &&
            n_mac_clear_ports < NL_MAX_PORTS)
            mac_clear_ports[n_mac_clear_ports++] = tracked;
    }

    for (int i = 0; i < n_mac_clear_ports; i++)
        (void)l2d_switchd_clear_dynamic_macs(SW_SOCKET, mac_clear_ports[i]);
    for (int i = 0; i < n_clear_ports; i++)
        (void)l2d_switchd_set_port_security(SW_SOCKET, clear_ports[i],
                                            false, "drop");
    if (was_shutdown && !configured_disabled) {
        bool admin_ok = true;

        if (is_aggregate) {
            for (int i = 0; i < n_clear_ports; i++) {
                if (l2d_switchd_set_runtime_admin(SW_SOCKET,
                                                  clear_ports[i], 0) != 0)
                    admin_ok = false;
            }
        } else {
            admin_ok = l2d_switchd_set_runtime_admin(SW_SOCKET,
                                                     port, 0) == 0;
        }
        if (!admin_ok)
            return send_l2d_text(conn, msg, NL_ERR_PFE_DOWN,
                                 "error: failed to re-enable interface");
    }

    pthread_mutex_lock(&g_l2d.lock);
    idx = find_if_state(g_l2d.ifs, g_l2d.n_ifs, ifname);
    if (idx >= 0) {
        g_l2d.ifs[idx].mac_shutdown = false;
        g_l2d.ifs[idx].mac_shutdown_time = 0;
        g_l2d.ifs[idx].mac_drop_active = false;
        g_l2d.ifs[idx].mac_drop_time = 0;
        g_l2d.ifs[idx].n_mac_enforced_ports = 0;
        g_l2d.ifs[idx].mac_enforced_action[0] = '\0';
        g_l2d.ifs[idx].mac_shutdown_reason[0] = '\0';
    }
    pthread_mutex_unlock(&g_l2d.lock);

    char resp[128];
    snprintf(resp, sizeof(resp), "secure-access-port cleared on %s%s",
             ifname, configured_disabled ? " (interface remains disabled)" : "");
    return send_l2d_text(conn, msg, 0, resp);
}

int l2d_clear_mac_move(nl_conn *conn, nl_msg_hdr *msg) {
    char payload[128] = {0};
    char ifname[64] = {0};
    bool have_ifname = false;
    bool configured_disabled[L2D_MAX_IFS];
    char reenable[L2D_MAX_IFS][64];
    int n_reenable = 0;

    memset(configured_disabled, 0, sizeof(configured_disabled));
    if (msg->payload_len > 0) {
        size_t n = msg->payload_len;
        if (n >= sizeof(payload))
            n = sizeof(payload) - 1;
        memcpy(payload, msg->payload, n);
        payload[n] = '\0';
        have_ifname = l2_plan_text_get_str(payload, "interface", ifname,
                                           sizeof(ifname)) && ifname[0];
    }

    if (have_ifname) {
        int port = nl_ifid_name_to_logical_port(ifname);
        if (port <= 0 || !nl_ifid_is_user_port(port))
            return send_l2d_text(conn, msg, NL_ERR_INVALID_VALUE,
                         "error: mac-move clear requires a physical user interface");
    }

    pthread_mutex_lock(&g_l2d.lock);
    for (int i = 0; i < g_l2d.n_ifs && i < L2D_MAX_IFS; i++) {
        l2_if_state *st = &g_l2d.ifs[i];
        if (have_ifname && strcmp(st->name, ifname) != 0)
            continue;
        configured_disabled[i] = st->disabled;
        if (st->mac_move_shutdown && !st->disabled &&
            n_reenable < L2D_MAX_IFS) {
            snprintf(reenable[n_reenable++], sizeof(reenable[0]), "%s",
                     st->name);
        }
        st->mac_move_shutdown = false;
        st->mac_move_shutdown_time = 0;
        st->mac_move_shutdown_reason[0] = '\0';
    }

    for (int i = 0; i < g_l2d.n_moves; ) {
        bool remove = !have_ifname ||
            strcmp(g_l2d.moves[i].from_if, ifname) == 0 ||
            strcmp(g_l2d.moves[i].to_if, ifname) == 0 ||
            strcmp(g_l2d.moves[i].dampened_if, ifname) == 0;
        if (!remove) {
            i++;
            continue;
        }
        memmove(&g_l2d.moves[i], &g_l2d.moves[i + 1],
                sizeof(g_l2d.moves[0]) * (size_t)(g_l2d.n_moves - i - 1));
        g_l2d.n_moves--;
    }
    pthread_mutex_unlock(&g_l2d.lock);

    (void)configured_disabled;
    for (int i = 0; i < n_reenable; i++) {
        int port = nl_ifid_name_to_logical_port(reenable[i]);
        if (port > 0)
            (void)l2d_switchd_set_runtime_admin(SW_SOCKET, port, 0);
    }

    {
        char resp[128];
        if (have_ifname)
            snprintf(resp, sizeof(resp), "MAC move state cleared on %s",
                     ifname);
        else
            snprintf(resp, sizeof(resp), "MAC move state cleared");
        return send_l2d_text(conn, msg, 0, resp);
    }
}
