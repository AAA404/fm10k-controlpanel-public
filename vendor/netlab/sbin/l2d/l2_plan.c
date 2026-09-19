/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "l2_plan_internal.h"
#include "igmp_snooping.h"
#include "l2_fm10k.h"

static int collect_known_ports(nl_yang_session *ys, cfg_port_ref *ports,
                               int max_ports) {
    nl_port_entry entries[NL_MAX_PORTS_PER_PROFILE];
    int n_entries;
    int n = 0;
    int inv[64];
    int n_inv;
    int max_ae = l2_cfg_max_ae();

    (void)ys;

    n_inv = l2_hw_inventory_ports(inv, 64);
    n_entries = nl_ifid_get_all(entries, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; i < n_entries && n < max_ports; i++) {
        bool present = n_inv <= 0;
        if (!nl_ifid_is_user_port(entries[i].logical_port))
            continue;
        for (int j = 0; j < n_inv; j++) {
            if (entries[i].logical_port == inv[j]) {
                present = true;
                break;
            }
        }
        if (!present)
            continue;
        memset(&ports[n], 0, sizeof(ports[n]));
        snprintf(ports[n].name, sizeof(ports[n].name), "%s",
                 entries[i].canonical_name);
        ports[n].hw_port = entries[i].logical_port > 0 ?
                           entries[i].logical_port : entries[i].port + 1;
        ports[n].is_aggregate = false;
        ports[n].ae_id = -1;
        ports[n].flags = entries[i].flags;
        ports[n].default_speed_bps = entries[i].default_speed;
        ports[n].scheduler_speed_bps = entries[i].scheduler_speed;
        ports[n].num_speeds = entries[i].num_speeds;
        for (int j = 0; j < entries[i].num_speeds && j < 8; j++)
            ports[n].supported_speeds_bps[j] = entries[i].supported_speeds[j];
        n++;
    }
    for (int ae = 0; ae < max_ae && n < max_ports; ae++) {
        int lport = l2_hw_ae_logical_port(ae);
        memset(&ports[n], 0, sizeof(ports[n]));
        snprintf(ports[n].name, sizeof(ports[n].name), "ae%d", ae);
        ports[n].hw_port = lport > 0 ? lport : 0;
        ports[n].is_aggregate = true;
        ports[n].ae_id = ae;
        ports[n].flags = NL_PORT_FLAG_TAGGED_TRUNK |
                          NL_PORT_FLAG_RSTP_CAPABLE |
                          NL_PORT_FLAG_LACP_CAPABLE;
        n++;
    }
    return n;
}

static int emit_interface_removal(const cfg_port_ref *port,
                                  const cfg_if_intent *old_i,
                                  const cfg_if_intent *new_i,
                                  bool becomes_lag_member,
                                  char *plan, size_t plan_size, int *off,
                                  bool *l2);

static void lag_reselection_scope(const cfg_port_ref *ports, int n_ports,
                                  nl_yang_session *active,
                                  nl_yang_session *candidate,
                                  bool reselect[CFG_AE_LIMIT]) {
    static const char *global_leaves[] = {
        "/netlab:netlab-config/protocols/lacp/system-id",
        "/netlab:netlab-config/protocols/lacp/system-priority",
        "/netlab:netlab-config/protocols/lacp/port-priority",
    };
    bool global_changed = false;
    memset(reselect, 0, sizeof(bool) * CFG_AE_LIMIT);
    for (size_t i = 0; i < sizeof(global_leaves) / sizeof(global_leaves[0]); ++i)
        if (!l2_text_eq(nl_yang_get(active, global_leaves[i]), nl_yang_get(candidate, global_leaves[i])))
            global_changed = true;
    for (int ae = 0; ae < l2_cfg_max_ae(); ++ae) {
        char name[16];
        snprintf(name, sizeof(name), "ae%d", ae);
        const char *old_mode = l2_get_lacp_mode(active, name);
        const char *new_mode = l2_get_lacp_mode(candidate, name);
        bool dynamic = !l2_text_eq(old_mode, "static") || !l2_text_eq(new_mode, "static");
        reselect[ae] = !l2_text_eq(old_mode, new_mode) ||
            l2_get_lacp_min_links(active, name, NULL, NULL) != l2_get_lacp_min_links(candidate, name, NULL, NULL) ||
            (dynamic && (global_changed ||
             !l2_text_eq(l2_get_lacp_periodic(active, name), l2_get_lacp_periodic(candidate, name)) ||
             !l2_text_eq(l2_get_lacp_actor_key(active, name), l2_get_lacp_actor_key(candidate, name))));
    }
    for (int i = 0; i < n_ports; ++i) {
        const char *old_member = l2_get_lag_member(active, ports[i].name);
        const char *new_member = l2_get_lag_member(candidate, ports[i].name);
        int old_ae = l2_ae_id(old_member), new_ae = l2_ae_id(new_member);
        if (!l2_text_eq(old_member, new_member)) {
            /* Member selection and minimum-links apply to the aggregate,
             * including the members that remain in it after this edit. */
            if (old_ae >= 0 && old_ae < CFG_AE_LIMIT) reselect[old_ae] = true;
            if (new_ae >= 0 && new_ae < CFG_AE_LIMIT) reselect[new_ae] = true;
        } else if (old_ae >= 0 && old_ae < CFG_AE_LIMIT &&
                   !l2_text_eq(l2_get_lacp_mode(active, old_member), "static") &&
                   !l2_text_eq(l2_get_lacp_member_port_priority(active, ports[i].name),
                               l2_get_lacp_member_port_priority(candidate, ports[i].name))) {
            reselect[old_ae] = true;
        }
    }
}

static int emit_lag_member_removals(const cfg_port_ref *ports, int n_ports,
                                    nl_yang_session *active,
                                    nl_yang_session *candidate,
                                    char *plan, size_t plan_size, int *off,
                                    bool *l2) {
    bool reselect[CFG_AE_LIMIT];
    lag_reselection_scope(ports, n_ports, active, candidate, reselect);
    for (int i = 0; i < n_ports; i++) {
        const char *old_member = l2_get_lag_member(active, ports[i].name);
        const char *new_member = l2_get_lag_member(candidate, ports[i].name);

        int old_ae = l2_ae_id(old_member);
        bool renegotiate = old_ae >= 0 && old_ae < CFG_AE_LIMIT && reselect[old_ae];
        if (!old_member || !old_member[0] || (l2_text_eq(old_member, new_member) && !renegotiate))
            continue;
        if (old_ae >= 0 && l2_hw_lag_missing(old_ae))
            continue; /* No member ownership survives a verified absent LAG. */
        *l2 = true;
        if (l2_plan_append(plan, plan_size, off,
                        "lag-del-port ae=%d port=%d\n",
                        l2_ae_id(old_member), ports[i].hw_port, 0) != 0)
            return -1;
    }
    return 0;
}

static int emit_lag_member_l2_cleanup(const cfg_port_ref *ports, int n_ports,
                                      nl_yang_session *active,
                                      nl_yang_session *candidate,
                                      char *plan, size_t plan_size, int *off,
                                      bool *l2) {
    for (int i = 0; i < n_ports; i++) {
        cfg_if_intent old_agg;
        cfg_if_intent new_i;
        const char *old_member;
        const char *new_member;

        if (ports[i].is_aggregate || ports[i].hw_port <= 0)
            continue;

        old_member = l2_get_lag_member(active, ports[i].name);
        new_member = l2_get_lag_member(candidate, ports[i].name);
        if (!old_member || !old_member[0] || l2_text_eq(old_member, new_member))
            continue;

        l2_read_interface_intent(active, old_member, &old_agg);
        if (!old_agg.has_l2)
            continue;

        l2_read_interface_intent(candidate, ports[i].name, &new_i);
        if (emit_interface_removal(&ports[i], &old_agg, &new_i, false,
                                   plan, plan_size, off, l2) != 0)
            return -1;
    }
    return 0;
}

static int emit_ingress_filter_updates(const cfg_port_ref *ports, int n_ports,
                                       nl_yang_session *active, nl_yang_session *candidate,
                                       const l2_fm10k_groups *groups, const bool *lag_missing,
                                       char *plan, size_t size, int *off, bool *has_l2) {
    if (!groups->managed) return 0;
    bool reselect[CFG_AE_LIMIT];
    lag_reselection_scope(ports, n_ports, active, candidate, reselect);
    for (int i = 0; i < n_ports; ++i) {
        const cfg_port_ref *port = &ports[i];
        if (!port->is_aggregate && (!l2_fm10k_port_active(groups, port->hw_port) ||
            port->hw_port < 1 || port->hw_port > 24)) continue;
        if (port->is_aggregate && !l2_aggregate_configured(candidate, port->name)) continue;
        cfg_if_intent before, after;
        l2_read_interface_intent(active, port->name, &before);
        l2_read_interface_intent(candidate, port->name, &after);
        const char *old_lag = l2_get_lag_member(active, port->name);
        const char *new_lag = l2_get_lag_member(candidate, port->name);
        bool enabled = l2_get_ingress_filtering(candidate, port->name);
        bool force = !l2_text_eq(old_lag, new_lag) || (!before.has_l2 && after.has_l2) ||
            (after.has_l2 && l2_fm10k_port_changed(groups, port->hw_port));
        if (port->is_aggregate) {
            force = force || !l2_aggregate_configured(active, port->name) || lag_missing[port->ae_id];
        } else if (new_lag && *new_lag) {
            int ae = l2_ae_id(new_lag);
            if (ae < 0 || ae >= CFG_AE_LIMIT) return -1;
            /* Keep the isolated physical baseline filtered while waiting for
             * LACP. Attach projects the aggregate policy onto this member. */
            if (!force && !reselect[ae] && !lag_missing[ae]) continue;
            enabled = true;
            force = true;
        }
        if (!force && enabled == l2_get_ingress_filtering(active, port->name)) continue;
        char target[32];
        l2_port_target_arg(port, target, sizeof(target));
        if (l2_plan_appendf(plan, size, off, "port-ingress-filter-set %s enabled=%d\n", target, enabled ? 1 : 0))
            return -1;
        *has_l2 = true;
    }
    return 0;
}

static int emit_lag_create_update(nl_yang_session *active,
                                  nl_yang_session *candidate,
                                  const bool *lag_missing,
                                  char *plan, size_t plan_size, int *off,
                                  bool *l2) {
    for (int ae = 0; ae < l2_cfg_max_ae(); ae++) {
        char ifname[16];
        bool old_ae;
        bool new_ae;

        snprintf(ifname, sizeof(ifname), "ae%d", ae);
        old_ae = l2_aggregate_configured(active, ifname);
        new_ae = l2_aggregate_configured(candidate, ifname);
        if (new_ae && (!old_ae || (lag_missing && lag_missing[ae]))) {
            *l2 = true;
            if (l2_plan_append(plan, plan_size, off,
                            "lag-create ae=%d\n", ae, 0, 0) != 0)
                return -1;
        }
    }
    return 0;
}

static int hash_rotation_value(nl_yang_session *ys, const char *ifname) {
    const char *value = l2_get_lag_hash_rotation(ys, ifname);

    if (!value || !value[0] || strcmp(value, "a") == 0)
        return 0;
    if (strcmp(value, "b") == 0)
        return 1;
    return -1;
}

static int emit_lag_hash_rotation_updates(nl_yang_session *active,
                                          nl_yang_session *candidate,
                                          const bool *lag_missing,
                                          char *plan, size_t plan_size,
                                          int *off, bool *l2) {
    for (int ae = 0; ae < l2_cfg_max_ae(); ae++) {
        char ifname[16];
        int old_rotation;
        int new_rotation;
        bool missing = lag_missing && lag_missing[ae];

        snprintf(ifname, sizeof(ifname), "ae%d", ae);
        if (!l2_aggregate_configured(candidate, ifname))
            continue;
        old_rotation = hash_rotation_value(active, ifname);
        new_rotation = hash_rotation_value(candidate, ifname);
        if (new_rotation < 0)
            return -1;
        if (!missing && old_rotation == new_rotation)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "lag-hash-rotation-set ae=%d rotation=%d\n",
                         ae, new_rotation) != 0)
            return -1;
    }
    return 0;
}

static int emit_lag_delete_after_cleanup(nl_yang_session *active,
                                         nl_yang_session *candidate,
                                         char *plan, size_t plan_size,
                                         int *off, bool *l2) {
    for (int ae = 0; ae < l2_cfg_max_ae(); ae++) {
        char ifname[16];
        bool old_ae;
        bool new_ae;

        snprintf(ifname, sizeof(ifname), "ae%d", ae);
        old_ae = l2_aggregate_configured(active, ifname);
        new_ae = l2_aggregate_configured(candidate, ifname);
        if (old_ae && !new_ae) {
            if (l2_hw_lag_missing(ae)) continue;
            *l2 = true;
            if (l2_plan_append(plan, plan_size, off,
                            "lag-delete ae=%d\n", ae, 0, 0) != 0)
                return -1;
        }
    }
    return 0;
}

static int emit_default_vlan_cleanup(const cfg_port_ref *ports, int n_ports,
                                     nl_yang_session *active,
                                     nl_yang_session *candidate,
                                     char *plan, size_t plan_size, int *off,
                                     bool *l2) {
    for (int i = 0; i < n_ports; i++) {
        cfg_if_intent old_i;
        cfg_if_intent new_i;
        const char *new_lag_member;
        char target[32];

        if (ports[i].is_aggregate || ports[i].hw_port <= 0)
            continue;
        new_lag_member = l2_get_lag_member(candidate, ports[i].name);
        bool lag_member = new_lag_member && new_lag_member[0];
        l2_read_interface_intent(active, ports[i].name, &old_i);
        l2_read_interface_intent(candidate, ports[i].name, &new_i);
        if (!lag_member && l2_intent_has_vid(&new_i, 1))
            continue;
        if (l2_intent_has_vid(&old_i, 1))
            continue;
        if (!l2_hw_vlan_member_present(1, ports[i].hw_port))
            continue;

        l2_port_target_arg(&ports[i], target, sizeof(target));
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "vlan-rem-port vid=1 %s tagged=0\n",
                         target) != 0)
            return -1;
    }
    return 0;
}

static int emit_interface_removal(const cfg_port_ref *port,
                                  const cfg_if_intent *old_i,
                                  const cfg_if_intent *new_i,
                                  bool becomes_lag_member,
                                  char *plan, size_t plan_size, int *off,
                                  bool *l2) {
    bool member_changed = l2_membership_changed(old_i, new_i);

    /* Detached members must have an isolated physical baseline. lacpd
     * attaches them only after negotiation (or static minimum-links), and
     * the SDK projects the aggregate's attributes at that point. */
    (void)becomes_lag_member;

    if (old_i->has_l2 && member_changed) {
        for (int i = 0; i < old_i->n_members; i++) {
            int old_vid = old_i->member_vids[i];
            bool old_tagged = l2_intent_vid_tagged(old_i, old_vid);
            char target[32];

            if (old_vid <= 0 ||
                l2_intent_has_member_tagged(new_i, old_vid, old_tagged))
                continue;
            l2_port_target_arg(port, target, sizeof(target));
            *l2 = true;
            if (l2_plan_appendf(plan, plan_size, off,
                             "vlan-rem-port vid=%d %s tagged=%d\n",
                             old_vid, target, old_tagged ? 1 : 0) != 0)
                return -1;
        }
    }

    if (old_i->has_l2 && !new_i->has_l2 && !port->is_aggregate) {
        char target[32];
        l2_port_target_arg(port, target, sizeof(target));
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "pvid-set %s vid=%d\n", target, 1) != 0 ||
            l2_plan_appendf(plan, plan_size, off,
                         "port-parser-set %s mode=%d\n", target, 0) != 0)
            return -1;
    } else if (old_i->has_l2 && new_i->has_l2 &&
               l2_intent_is_trunk(new_i) && !new_i->has_native &&
               (strcmp(old_i->mode, "access") == 0 || old_i->has_native)) {
        char target[32];
        l2_port_target_arg(port, target, sizeof(target));
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "pvid-set %s vid=%d\n", target, 1) != 0)
            return -1;
    }

    return 0;
}

static int emit_vlan_deletes(const cfg_vlan_ref *old_vlans, int n_old,
                             const cfg_vlan_ref *new_vlans, int n_new,
                             char *plan, size_t plan_size, int *off,
                             bool *l2, char *err, size_t err_size) {
    for (int i = 0; i < n_old; i++) {
        if (l2_vlan_vid_present(new_vlans, n_new, old_vlans[i].vid))
            continue;
        if (old_vlans[i].vid == 1)
            return l2_plan_set_error(err, err_size, "cannot delete default VLAN %s",
                             old_vlans[i].name, NULL);
        *l2 = true;
        if (l2_plan_append(plan, plan_size, off,
                        "vlan-delete vid=%d\n", old_vlans[i].vid, 0, 0) != 0)
            return -1;
    }
    return 0;
}

static int emit_vlan_creates_diff(const cfg_vlan_ref *old_vlans, int n_old,
                                  const cfg_vlan_ref *new_vlans, int n_new,
                                  const bool *missing_by_vid,
                                  char *plan, size_t plan_size, int *off,
                                  bool *l2) {
    for (int i = 0; i < n_new; i++) {
        if (l2_vlan_vid_present(old_vlans, n_old, new_vlans[i].vid) &&
            !l2_vlan_marked_missing(missing_by_vid, new_vlans[i].vid))
            continue;
        *l2 = true;
        if (l2_plan_append(plan, plan_size, off,
                        "vlan-create vid=%d\n", new_vlans[i].vid, 0, 0) != 0)
            return -1;
    }
    return 0;
}

static int emit_interface_add_update(const cfg_port_ref *port,
                                     const cfg_if_intent *old_i,
                                     const cfg_if_intent *new_i,
                                     const bool *missing_by_vid,
                                     char *plan, size_t plan_size, int *off,
                                     bool *l2) {
    bool any_member_changed = false;
    bool mode_changed;
    bool parser_prepared = false;
    char target[32];

    if (!new_i->has_l2)
        return 0;

    l2_port_target_arg(port, target, sizeof(target));
    mode_changed = !l2_text_eq(old_i->mode, new_i->mode);

    for (int i = 0; i < new_i->n_members; i++) {
        int vid = new_i->member_vids[i];
        bool tagged = l2_intent_vid_tagged(new_i, vid);

        if (vid <= 0)
            continue;
        if (!l2_intent_has_member_tagged(old_i, vid, tagged) ||
            l2_vlan_marked_missing(missing_by_vid, vid) ||
            l2_hw_port_member_missing(port, vid)) {
            any_member_changed = true;
            break;
        }
    }

    if (strcmp(new_i->mode, "trunk") == 0 &&
        (any_member_changed || mode_changed)) {
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "port-parser-set %s mode=%d\n", target, 2) != 0)
            return -1;
        parser_prepared = true;
    }

    for (int i = 0; i < new_i->n_members; i++) {
        int vid = new_i->member_vids[i];
        bool tagged = l2_intent_vid_tagged(new_i, vid);
        bool member_changed;

        if (vid <= 0)
            continue;
        member_changed = !l2_intent_has_member_tagged(old_i, vid, tagged) ||
                         l2_vlan_marked_missing(missing_by_vid, vid) ||
                         l2_hw_port_member_missing(port, vid);
        if (!member_changed)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "vlan-add-port vid=%d %s tagged=%d\n",
                         vid, target, tagged ? 1 : 0) != 0)
            return -1;
    }

    if (strcmp(new_i->mode, "access") == 0) {
        if (any_member_changed || !old_i->has_l2 ||
            old_i->member_vid != new_i->member_vid ||
            mode_changed || old_i->has_native ||
            l2_hw_pvid_mismatch(port, new_i->member_vid)) {
            *l2 = true;
            if (l2_plan_appendf(plan, plan_size, off,
                             "pvid-set %s vid=%d\n",
                             target, new_i->member_vid) != 0)
                return -1;
        }
    } else if (strcmp(new_i->mode, "trunk") == 0 && new_i->has_native) {
        if (any_member_changed || !old_i->has_l2 || !old_i->has_native ||
            old_i->native_vid != new_i->native_vid || mode_changed ||
            l2_hw_pvid_mismatch(port, new_i->native_vid)) {
            *l2 = true;
            if (l2_plan_appendf(plan, plan_size, off,
                             "pvid-set %s vid=%d\n",
                             target, new_i->native_vid) != 0)
                return -1;
        }
    } else if (strcmp(new_i->mode, "trunk") == 0 &&
               l2_hw_pvid_mismatch(port, 1)) {
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "pvid-set %s vid=1\n", target) != 0)
            return -1;
    }

    if (any_member_changed || mode_changed || old_i->rstp_managed != new_i->rstp_managed) {
        *l2 = true;
        for (int i = 0; i < new_i->n_members; i++) {
            if (new_i->member_vids[i] <= 0)
                continue;
            if (l2_plan_appendf(plan, plan_size, off,
                             "stp-set vid=%d %s state=%d\n",
                             new_i->member_vids[i], target, new_i->rstp_managed ? 4 : 3) != 0)
                return -1;
        }
        if (!parser_prepared &&
            l2_plan_appendf(plan, plan_size, off,
                         "port-parser-set %s mode=%d\n", target, 2) != 0)
            return -1;
    }

    return 0;
}

static int emit_admin_delta(const cfg_port_ref *port,
                            const cfg_if_intent *old_i,
                            const cfg_if_intent *new_i,
                            char *plan, size_t plan_size, int *off,
                            bool *l2) {
    bool configured = new_i->exists || new_i->has_l2 || old_i->exists;
    bool hw_mismatch = configured &&
                       !port->is_aggregate &&
                       l2_hw_admin_mismatch(port->hw_port,
                                               new_i->disabled);

    if (port->is_aggregate)
        return 0;
    if (old_i->disabled == new_i->disabled && !hw_mismatch)
        return 0;
    *l2 = true;
    return l2_plan_append(plan, plan_size, off,
                       "port-set-admin port=%d mode=%d\n",
                       port->hw_port,
                       new_i->disabled ? CFG_PORT_MODE_ADMIN_PWRDOWN
                                       : CFG_PORT_MODE_UP,
                       0);
}

static int emit_mtu_delta(const cfg_port_ref *port,
                          const cfg_if_intent *old_i,
                          const cfg_if_intent *new_i,
                          bool force,
                          char *plan, size_t plan_size, int *off,
                          bool *l2) {
    char target[32];
    int new_mtu;
    bool changed;

    if (!old_i->has_mtu && !new_i->has_mtu && !force)
        return 0;

    new_mtu = new_i->has_mtu ? new_i->mtu : CFG_INTERFACE_DEFAULT_MTU;
    changed = force || old_i->has_mtu != new_i->has_mtu ||
              (old_i->has_mtu && new_i->has_mtu &&
               old_i->mtu != new_i->mtu) ||
              l2_hw_mtu_mismatch(port, new_mtu);
    if (!changed)
        return 0;

    l2_port_target_arg(port, target, sizeof(target));
    *l2 = true;
    return l2_plan_appendf(plan, plan_size, off,
                        "port-set-mtu %s mtu=%d\n", target, new_mtu);
}

static int emit_speed_delta(const cfg_port_ref *port,
                            const cfg_if_intent *old_i,
                            const cfg_if_intent *new_i,
                            nl_yang_session *active,
                            char *plan, size_t plan_size, int *off,
                            bool *l2, char *err, size_t err_size) {
    const char *active_lag;
    int default_mbps;
    int wanted_mbps;
    bool changed;

    if (!port || port->is_aggregate || port->hw_port <= 0)
        return 0;
    if (!old_i->has_speed && !new_i->has_speed)
        return 0;

    default_mbps = (int)(port->default_speed_bps / 1000000ULL);
    wanted_mbps = new_i->has_speed ? new_i->speed_mbps : default_mbps;
    if (wanted_mbps != NL_PORT_SPEED_10G_MBPS &&
        wanted_mbps != NL_PORT_SPEED_25G_MBPS) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "interface %s has no valid platform default speed",
                     port->name);
        return -1;
    }

    changed = old_i->has_speed != new_i->has_speed ||
              (old_i->has_speed && new_i->has_speed &&
               old_i->speed_mbps != new_i->speed_mbps) ||
              l2_hw_speed_mismatch(port, wanted_mbps);
    if (!changed)
        return 0;

    active_lag = l2_get_lag_member(active, port->name);
    if (active_lag && active_lag[0]) {
        if (err && err_size > 0)
            snprintf(err, err_size,
                     "interface %s must be removed from %s and committed before changing speed",
                     port->name, active_lag);
        return -1;
    }

    *l2 = true;
    return l2_plan_appendf(plan, plan_size, off,
                           "port-set-speed port=%d speed=%d\n",
                           port->hw_port, wanted_mbps);
}

static int emit_mac_aging_delta(nl_yang_session *active,
                                nl_yang_session *candidate,
                                char *plan, size_t plan_size, int *off,
                                bool *l2) {
    int old_seconds = l2_get_mac_aging_time(active, NULL);
    int new_seconds = l2_get_mac_aging_time(candidate, NULL);

    if (new_seconds < 0 || new_seconds > CFG_MAC_AGING_MAX_SECONDS)
        return -1;
    if (old_seconds == new_seconds &&
        !l2_hw_mac_aging_mismatch(new_seconds))
        return 0;

    *l2 = true;
    return l2_plan_append(plan, plan_size, off,
                       "mac-aging-set seconds=%d\n",
                       new_seconds, 0, 0);
}

static int emit_static_mac_deletes(const cfg_static_mac_intent *old_entries,
                                   int n_old,
                                   const cfg_static_mac_intent *new_entries,
                                   int n_new,
                                   char *plan, size_t plan_size, int *off,
                                   bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_static_mac_by_key(new_entries, n_new,
                                       old_entries[i].mac,
                                       old_entries[i].vid);
        if (j >= 0 && l2_static_mac_same_target(&old_entries[i], &new_entries[j]))
            continue;
        if (old_entries[i].vid <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "static-mac-del vid=%d mac=%s\n",
                         old_entries[i].vid, old_entries[i].mac) != 0)
            return -1;
    }
    return 0;
}

static int emit_static_mac_adds(const cfg_static_mac_intent *old_entries,
                                int n_old,
                                const cfg_static_mac_intent *new_entries,
                                int n_new,
                                const bool *lag_missing,
                                char *plan, size_t plan_size, int *off,
                                bool *l2) {
    for (int i = 0; i < n_new; i++) {
        char target[32];
        int j = l2_find_static_mac_by_key(old_entries, n_old,
                                       new_entries[i].mac,
                                       new_entries[i].vid);
        bool changed = (new_entries[i].port.is_aggregate &&
                        lag_missing[new_entries[i].port.ae_id]) || j < 0 ||
                       !l2_static_mac_same_target(&old_entries[j],
                                               &new_entries[i]) ||
                       l2_hw_static_mac_mismatch(&new_entries[i]);

        if (!changed ||
            (!new_entries[i].port.is_aggregate &&
             new_entries[i].port.hw_port <= 0))
            continue;

        l2_port_target_arg(&new_entries[i].port, target, sizeof(target));
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "static-mac-add vid=%d mac=%s %s\n",
                         new_entries[i].vid, new_entries[i].mac, target) != 0)
            return -1;
    }
    return 0;
}

static int emit_igmp_listener_deletes(
    const cfg_igmp_listener_intent *old_entries, int n_old,
    const cfg_igmp_listener_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        bool configured = false;

        for (int j = 0; j < n_new; j++) {
            if (old_entries[i].vid == new_entries[j].vid &&
                old_entries[i].port.hw_port ==
                    new_entries[j].port.hw_port &&
                memcmp(old_entries[i].mac, new_entries[j].mac, 6) == 0) {
                configured = true;
                break;
            }
        }
        if (configured || igmp_snooping_dynamic_hardware_key_present(
                old_entries[i].vid, old_entries[i].port.hw_port,
                old_entries[i].mac))
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "igmp-listener-del vid=%d port=%d group=%s\n",
                old_entries[i].vid, old_entries[i].port.hw_port,
                old_entries[i].group) != 0)
            return -1;
    }
    return 0;
}

static int emit_igmp_listener_sets(
    const cfg_igmp_listener_intent *old_entries, int n_old,
    const cfg_igmp_listener_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        bool configured = false;

        for (int j = 0; j < n_old; j++) {
            if (new_entries[i].vid == old_entries[j].vid &&
                new_entries[i].port.hw_port ==
                    old_entries[j].port.hw_port &&
                memcmp(new_entries[i].mac, old_entries[j].mac, 6) == 0) {
                configured = true;
                break;
            }
        }

        if (configured && !l2_hw_igmp_listener_missing(&new_entries[i]))
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "igmp-listener-set vid=%d port=%d group=%s\n",
                new_entries[i].vid, new_entries[i].port.hw_port,
                new_entries[i].group) != 0)
            return -1;
    }
    return 0;
}

static int emit_storm_control_deletes(
    const cfg_storm_control_intent *old_entries, int n_old,
    const cfg_storm_control_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_storm_control_by_ifname(new_entries, n_new,
                                                old_entries[i].ifname, old_entries[i].kind);
        if (j >= 0 && l2_storm_control_same(&old_entries[i], &new_entries[j]))
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            old_entries[i].kind == NL_STORM_COMBINED ?
                            "storm-control-del port=%d\n" : "storm-control-del port=%d kind=%s\n",
                            old_entries[i].port.hw_port,
                            nl_storm_kind_name(old_entries[i].kind)) != 0)
            return -1;
    }
    return 0;
}

static int emit_storm_control_sets(
    const cfg_storm_control_intent *old_entries, int n_old,
    const cfg_storm_control_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_storm_control_by_ifname(old_entries, n_old,
                                                new_entries[i].ifname, new_entries[i].kind);
        bool changed = j < 0 ||
                       !l2_storm_control_same(&old_entries[j],
                                              &new_entries[i]) ||
                       l2_hw_storm_control_mismatch(&new_entries[i]);

        if (!changed || new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            new_entries[i].kind == NL_STORM_COMBINED ?
                            "storm-control-set port=%d rate=%d burst=%d\n" :
                            "storm-control-set port=%d rate=%d burst=%d kind=%s\n",
                            new_entries[i].port.hw_port,
                            new_entries[i].rate_kbps,
                            new_entries[i].burst_bytes,
                            nl_storm_kind_name(new_entries[i].kind)) != 0)
            return -1;
    }
    return 0;
}

static int emit_ingress_rate_limit_deletes(
    const cfg_ingress_rate_limit_intent *old_entries, int n_old,
    const cfg_ingress_rate_limit_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_ingress_rate_limit_by_ifname(new_entries, n_new,
                                             old_entries[i].ifname);
        if (j >= 0 && l2_ingress_rate_limit_same(&old_entries[i], &new_entries[j]))
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "ingress-rate-limit-del port=%d\n",
                            old_entries[i].port.hw_port) != 0)
            return -1;
    }
    return 0;
}

static int emit_ingress_rate_limit_sets(
    const cfg_ingress_rate_limit_intent *old_entries, int n_old,
    const cfg_ingress_rate_limit_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_ingress_rate_limit_by_ifname(old_entries, n_old,
                                             new_entries[i].ifname);
        bool changed = j < 0 ||
                       !l2_ingress_rate_limit_same(&old_entries[j],
                                           &new_entries[i]) ||
                       l2_hw_ingress_rate_limit_mismatch(&new_entries[i]);

        if (!changed || new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "ingress-rate-limit-set port=%d rate=%d burst=%d\n",
                            new_entries[i].port.hw_port,
                            new_entries[i].rate_kbps,
                            new_entries[i].burst_bytes) != 0)
            return -1;
    }
    return 0;
}

static int emit_egress_rate_limit_deletes(
    const cfg_egress_rate_limit_intent *old_entries, int n_old,
    const cfg_egress_rate_limit_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_egress_rate_limit_by_ifname(new_entries, n_new,
                                                    old_entries[i].ifname);
        if (j >= 0 &&
            l2_egress_rate_limit_same(&old_entries[i], &new_entries[j]))
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "egress-rate-limit-del port=%d\n",
                            old_entries[i].port.hw_port) != 0)
            return -1;
    }
    return 0;
}

static int emit_egress_rate_limit_sets(
    const cfg_egress_rate_limit_intent *old_entries, int n_old,
    const cfg_egress_rate_limit_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_egress_rate_limit_by_ifname(old_entries, n_old,
                                                    new_entries[i].ifname);
        bool changed = j < 0 ||
                       !l2_egress_rate_limit_same(&old_entries[j],
                                                  &new_entries[i]) ||
                       l2_hw_egress_rate_limit_mismatch(&new_entries[i]);

        if (!changed || new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "egress-rate-limit-set port=%d rate=%d burst=%d\n",
                            new_entries[i].port.hw_port,
                            new_entries[i].rate_kbps,
                            new_entries[i].burst_bytes) != 0)
            return -1;
    }
    return 0;
}

/* IES per-LAG management projects classifier attributes from the aggregate.
 * Keep the user-facing per-member intent, but program its single owner. */
static int fold_lag_qos(nl_yang_session *ys, cfg_qos_interface_intent *entries,
                        int count, const cfg_port_ref *ports, int n_ports,
                        bool strict, char *err, size_t err_size) {
    if (count <= 0) return count;
    cfg_qos_interface_intent *folded = calloc((size_t)count, sizeof(*folded));
    if (!folded) return -1;
    int n = 0, result = -1;
    for (int i = 0; i < count; ++i) {
        cfg_qos_interface_intent item = entries[i];
        const char *lag = l2_get_lag_member(ys, item.ifname);
        if (lag && *lag) {
            const cfg_port_ref *aggregate = l2_find_port_ref(ports, n_ports, lag);
            if (!aggregate || !aggregate->is_aggregate) goto done;
            item.port = *aggregate;
            snprintf(item.ifname, sizeof(item.ifname), "%s", lag);
            if (strict) {
                for (int p = 0; p < n_ports; ++p) {
                    const char *peer_lag = l2_get_lag_member(ys, ports[p].name);
                    if (ports[p].is_aggregate || !l2_text_eq(lag, peer_lag)) continue;
                    int peer = l2_find_qos_interface_by_ifname(entries, count, ports[p].name);
                    int trust = peer >= 0 ? entries[peer].trust_mode : HAL_QOS_TRUST_IEEE8021P;
                    int priority = peer >= 0 ? entries[peer].default_priority : 0;
                    if (trust != item.trust_mode || priority != item.default_priority) {
                        l2_plan_set_error(err, err_size,
                            "LAG %s requires identical QoS classifier settings on all members", lag, NULL);
                        goto done;
                    }
                }
            }
        }
        if (l2_find_qos_interface_by_ifname(folded, n, item.ifname) < 0)
            folded[n++] = item;
    }
    memcpy(entries, folded, (size_t)n * sizeof(*entries));
    result = n;
done:
    free(folded);
    return result;
}

static int emit_qos_interface_deletes(
    const cfg_qos_interface_intent *old_entries, int n_old,
    const cfg_qos_interface_intent *new_entries, int n_new,
    nl_yang_session *candidate, bool per_lag,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_qos_interface_by_ifname(new_entries, n_new,
                                                old_entries[i].ifname);
        if (j >= 0)
            continue;
        if (old_entries[i].port.is_aggregate) {
            if (!l2_aggregate_configured(candidate, old_entries[i].ifname) ||
                l2_hw_lag_missing(old_entries[i].port.ae_id)) continue;
        } else {
            const char *lag = per_lag ? l2_get_lag_member(candidate, old_entries[i].ifname) : NULL;
            /* The new aggregate owns this classifier. Do not reset an
             * attached physical member through a per-LAG-only attribute. */
            if ((lag && *lag) || old_entries[i].port.hw_port <= 0) continue;
        }
        char target[32];
        l2_port_target_arg(&old_entries[i].port, target, sizeof(target));
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "qos-interface-del %s\n", target) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_interface_sets(
    const cfg_qos_interface_intent *old_entries, int n_old,
    const cfg_qos_interface_intent *new_entries, int n_new,
    const bool *lag_missing,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_qos_interface_by_ifname(old_entries, n_old,
                                                new_entries[i].ifname);
        bool changed = (new_entries[i].port.is_aggregate &&
                        lag_missing[new_entries[i].port.ae_id]) || j < 0 ||
                       !l2_qos_interface_same(&old_entries[j],
                                              &new_entries[i]) ||
                       l2_hw_qos_interface_mismatch(&new_entries[i]);

        if (!changed || (!new_entries[i].port.is_aggregate && new_entries[i].port.hw_port <= 0))
            continue;
        char target[32];
        l2_port_target_arg(&new_entries[i].port, target, sizeof(target));
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "qos-interface-set %s trust=%d default-priority=%d\n", target,
                         new_entries[i].trust_mode,
                         new_entries[i].default_priority) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_dscp(nl_yang_session *old, nl_yang_session *next,
                         char *plan, size_t size, int *off, bool *changed) {
    for (int dscp = 0; dscp < 64; dscp++) {
        char path[192];
        snprintf(path, sizeof(path), "/netlab:netlab-config/class-of-service/dscp-map/entry[dscp='%d']/switch-priority", dscp);
        const char *before = old ? nl_yang_get(old, path) : NULL;
        const char *after = nl_yang_get(next, path);
        int a = before ? atoi(before) : 0, b = after ? atoi(after) : 0;
        if (a != b || l2_hw_qos_dscp_mismatch(dscp, b)) {
            if (l2_plan_appendf(plan, size, off, "qos-dscp-set dscp=%d priority=%d\n", dscp, b)) return -1;
            *changed = true;
        }
    }
    return 0;
}

static int emit_qos_tc_smp(nl_yang_session *old, nl_yang_session *next,
                            char *plan, size_t size, int *off, bool *changed) {
    for (int tc = 0; tc < 8; tc++) {
        char path[192];
        snprintf(path, sizeof(path), "/netlab:netlab-config/class-of-service/shared-memory/traffic-class[class='%d']/partition", tc);
        const char *before = old ? nl_yang_get(old, path) : NULL;
        const char *after = nl_yang_get(next, path);
        int a = before ? atoi(before) : 0, b = after ? atoi(after) : 0;
        if (a != b || l2_hw_qos_tc_smp_mismatch(tc, b)) {
            if (l2_plan_appendf(plan, size, off, "qos-tc-smp-set traffic-class=%d smp=%d\n", tc, b)) return -1;
            *changed = true;
        }
    }
    return 0;
}

static int emit_qos_pfc_deletes(
    const cfg_qos_pfc_intent *old_entries, int n_old,
    const cfg_qos_pfc_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_qos_pfc_by_ifname(new_entries, n_new,
                                          old_entries[i].ifname);
        if (j >= 0)
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "qos-pfc-del port=%d\n",
                            old_entries[i].port.hw_port) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_pfc_sets(
    const cfg_qos_pfc_intent *old_entries, int n_old,
    const cfg_qos_pfc_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_qos_pfc_by_ifname(old_entries, n_old,
                                          new_entries[i].ifname);
        bool changed = j < 0 ||
                       !l2_qos_pfc_same(&old_entries[j], &new_entries[i]) ||
                       l2_hw_qos_pfc_mismatch(&new_entries[i]);

        if (!changed || new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-pfc-set port=%d rx-class-mask=%d tx-class-mask=%d "
                "lossless-smp-mask=%d shared-pause-mask=%d "
                "watchdog-detect-ms=%u watchdog-recovery-ms=%u watchdog-cooldown-ms=%u\n",
                new_entries[i].port.hw_port,
                new_entries[i].rx_class_mask,
                new_entries[i].tx_class_mask,
                new_entries[i].lossless_smp_mask,
                new_entries[i].shared_pause_mask, new_entries[i].watchdog.detect_ms,
                new_entries[i].watchdog.recovery_ms, new_entries[i].watchdog.cooldown_ms) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_priority_map_deletes(
    const cfg_qos_priority_map_intent *old_entries, int n_old,
    const cfg_qos_priority_map_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_qos_priority_map(new_entries, n_new,
                                         old_entries[i].switch_priority);
        if (j >= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "qos-priority-map-del priority=%d\n",
                            old_entries[i].switch_priority) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_priority_map_sets(
    const cfg_qos_priority_map_intent *old_entries, int n_old,
    const cfg_qos_priority_map_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_qos_priority_map(old_entries, n_old,
                                         new_entries[i].switch_priority);
        bool changed = j < 0 ||
                       !l2_qos_priority_map_same(&old_entries[j],
                                                 &new_entries[i]) ||
                       l2_hw_qos_priority_map_mismatch(&new_entries[i]);

        if (!changed)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "qos-priority-map-set priority=%d traffic-class=%d\n",
                         new_entries[i].switch_priority,
                         new_entries[i].traffic_class) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_priority_map_candidate_reconcile(
    const cfg_qos_priority_map_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int priority = 0;
         priority < CFG_QOS_PRIORITY_MAP_MAX_ENTRIES; priority++) {
        int j = l2_find_qos_priority_map(
            new_entries, n_new, priority);
        int traffic_class = j >= 0 ?
            new_entries[j].traffic_class : (priority & 7);

        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-priority-map-set priority=%d traffic-class=%d\n",
                priority, traffic_class) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_pfc_candidate_reconcile(
    const cfg_qos_pfc_intent *new_entries, int n_new,
    const cfg_port_ref *ports, int n_ports,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_ports; i++) {
        int j;

        if (ports[i].is_aggregate || ports[i].hw_port <= 0)
            continue;
        j = l2_find_qos_pfc_by_ifname(
            new_entries, n_new, ports[i].name);
        *l2 = true;
        if (j < 0) {
            if (l2_plan_appendf(
                    plan, plan_size, off,
                    "qos-pfc-del port=%d\n",
                    ports[i].hw_port) != 0)
                return -1;
            continue;
        }
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-pfc-set port=%d rx-class-mask=%d "
                "tx-class-mask=%d lossless-smp-mask=%d "
                "shared-pause-mask=%d watchdog-detect-ms=%u "
                "watchdog-recovery-ms=%u watchdog-cooldown-ms=%u\n",
                ports[i].hw_port,
                new_entries[j].rx_class_mask,
                new_entries[j].tx_class_mask,
                new_entries[j].lossless_smp_mask,
                new_entries[j].shared_pause_mask, new_entries[j].watchdog.detect_ms,
                new_entries[j].watchdog.recovery_ms, new_entries[j].watchdog.cooldown_ms) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_scheduler_tc_map_deletes(
    const cfg_qos_scheduler_tc_map_intent *old_entries, int n_old,
    const cfg_qos_scheduler_tc_map_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_qos_scheduler_tc_map(
            new_entries, n_new, old_entries[i].ifname,
            old_entries[i].traffic_class);
        if (j >= 0)
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-scheduler-tc-map-del port=%d traffic-class=%d\n",
                old_entries[i].port.hw_port,
                old_entries[i].traffic_class) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_scheduler_tc_map_sets(
    const cfg_qos_scheduler_tc_map_intent *old_entries, int n_old,
    const cfg_qos_scheduler_tc_map_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_qos_scheduler_tc_map(
            old_entries, n_old, new_entries[i].ifname,
            new_entries[i].traffic_class);
        bool changed = j < 0 ||
                       !l2_qos_scheduler_tc_map_same(&old_entries[j],
                                                     &new_entries[i]) ||
                       l2_hw_qos_scheduler_tc_map_mismatch(&new_entries[i]);

        if (!changed || new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-scheduler-tc-map-set port=%d traffic-class=%d shaping-group=%d\n",
                new_entries[i].port.hw_port,
                new_entries[i].traffic_class,
                new_entries[i].shaping_group) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_scheduler_group_deletes(
    const cfg_qos_scheduler_group_intent *old_entries, int n_old,
    const cfg_qos_scheduler_group_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_qos_scheduler_group(
            new_entries, n_new, old_entries[i].ifname,
            old_entries[i].group);
        if (j >= 0)
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-scheduler-group-del port=%d group=%d\n",
                old_entries[i].port.hw_port,
                old_entries[i].group) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_scheduler_group_sets(
    const cfg_qos_scheduler_group_intent *old_entries, int n_old,
    const cfg_qos_scheduler_group_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_qos_scheduler_group(
            old_entries, n_old, new_entries[i].ifname,
            new_entries[i].group);
        bool changed = j < 0 ||
                       !l2_qos_scheduler_group_same(&old_entries[j],
                                                    &new_entries[i]) ||
                       l2_hw_qos_scheduler_group_mismatch(&new_entries[i]);

        if (!changed || new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-scheduler-group-set port=%d group=%d strict=%d weight=%d\n",
                new_entries[i].port.hw_port,
                new_entries[i].group,
                new_entries[i].strict_priority,
                new_entries[i].weight) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_scheduler_group_shaping_deletes(
    const cfg_qos_scheduler_group_shaping_intent *old_entries, int n_old,
    const cfg_qos_scheduler_group_shaping_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_qos_scheduler_group_shaping(
            new_entries, n_new, old_entries[i].ifname,
            old_entries[i].group);
        if (j >= 0)
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-scheduler-group-shaping-del port=%d group=%d\n",
                old_entries[i].port.hw_port,
                old_entries[i].group) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_scheduler_group_shaping_sets(
    const cfg_qos_scheduler_group_shaping_intent *old_entries, int n_old,
    const cfg_qos_scheduler_group_shaping_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_qos_scheduler_group_shaping(
            old_entries, n_old, new_entries[i].ifname,
            new_entries[i].group);
        bool changed = j < 0 ||
                       !l2_qos_scheduler_group_shaping_same(&old_entries[j],
                                                            &new_entries[i]) ||
                       l2_hw_qos_scheduler_group_shaping_mismatch(
                           &new_entries[i]);

        if (!changed || new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-scheduler-group-shaping-set port=%d group=%d rate-bps=%llu burst-bits=%llu\n",
                new_entries[i].port.hw_port,
                new_entries[i].group,
                (unsigned long long)new_entries[i].rate_bps,
                (unsigned long long)new_entries[i].burst_bits) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_scheduler_port_deletes(
    const cfg_qos_scheduler_port_intent *old_entries, int n_old,
    const cfg_qos_scheduler_port_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_qos_scheduler_port_by_ifname(
            new_entries, n_new, old_entries[i].ifname);
        if (j >= 0)
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-scheduler-port-del port=%d\n",
                old_entries[i].port.hw_port) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_scheduler_port_sets(
    const cfg_qos_scheduler_port_intent *old_entries, int n_old,
    const cfg_qos_scheduler_port_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_qos_scheduler_port_by_ifname(
            old_entries, n_old, new_entries[i].ifname);
        bool changed = j < 0 ||
                       !l2_qos_scheduler_port_same(&old_entries[j],
                                                   &new_entries[i]) ||
                       l2_hw_qos_scheduler_port_mismatch(&new_entries[i]);

        if (!changed || new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-scheduler-port-set port=%d traffic-class-enable-mask=%d\n",
                new_entries[i].port.hw_port,
                new_entries[i].traffic_class_enable_mask) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_watermark_deletes(
    const cfg_qos_watermark_intent *old_entries, int n_old,
    const cfg_qos_watermark_intent *new_entries, int n_new,
    bool calculator_reconciled,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int port = old_entries[i].port.hw_port;
        bool switch_attr =
            old_entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
            old_entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
            old_entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
        int j = l2_find_qos_watermark(
            new_entries, n_new, old_entries[i].ifname,
            old_entries[i].traffic_class, old_entries[i].attr);
        if (j >= 0)
            continue;
        if (!switch_attr && port <= 0)
            continue;
        if (switch_attr)
            port = 0;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-watermark-del port=%d attr=%d index=%d reconcile=%d\n",
                port,
                old_entries[i].attr,
                old_entries[i].traffic_class,
                calculator_reconciled ? 1 : 0) != 0)
            return -1;
    }
    return 0;
}

static int emit_qos_watermark_sets(
    const cfg_qos_watermark_intent *old_entries, int n_old,
    const cfg_qos_watermark_intent *new_entries, int n_new,
    bool replay_all, bool calculator_reconciled,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int port = new_entries[i].port.hw_port;
        bool switch_attr =
            new_entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP ||
            new_entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER ||
            new_entries[i].attr == HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_HOG;
        int j = l2_find_qos_watermark(
            old_entries, n_old, new_entries[i].ifname,
            new_entries[i].traffic_class, new_entries[i].attr);
        bool changed = replay_all || j < 0 ||
                       !l2_qos_watermark_same(&old_entries[j],
                                              &new_entries[i]) ||
                       l2_hw_qos_watermark_mismatch(&new_entries[i]);

        if (!changed || (!switch_attr && port <= 0))
            continue;
        if (switch_attr)
            port = 0;
        *l2 = true;
        if (l2_plan_appendf(
                plan, plan_size, off,
                "qos-watermark-set port=%d attr=%d index=%d value=%d "
                "owner-create=%d reconcile=%d\n",
                port,
                new_entries[i].attr,
                new_entries[i].traffic_class,
                new_entries[i].value,
                j < 0 ? 1 : 0,
                calculator_reconciled ? 1 : 0) != 0)
            return -1;
    }
    return 0;
}

static bool qos_watermark_has_deletes(
    const cfg_qos_watermark_intent *old_entries, int n_old,
    const cfg_qos_watermark_intent *new_entries, int n_new) {
    for (int i = 0; i < n_old; i++)
        if (l2_find_qos_watermark(
                new_entries, n_new, old_entries[i].ifname,
                old_entries[i].traffic_class,
                old_entries[i].attr) < 0)
            return true;
    return false;
}

static const char *l2_security_op_prefix(cfg_l2_security_kind kind) {
    return kind == CFG_L2_SECURITY_ARP_INSPECTION ? "arp-inspection" :
                                                    "dhcp-snooping";
}

static int emit_l2_security_deletes(
    const cfg_l2_security_rule_intent *old_entries, int n_old,
    const cfg_l2_security_rule_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_l2_security_rule(new_entries, n_new,
                                         old_entries[i].kind,
                                         old_entries[i].vid,
                                         old_entries[i].port.hw_port);
        if (j >= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "%s-del vid=%d port=%d\n",
                         l2_security_op_prefix(old_entries[i].kind),
                         old_entries[i].vid,
                         old_entries[i].port.hw_port) != 0)
            return -1;
    }
    return 0;
}

static int emit_l2_security_sets(
    const cfg_l2_security_rule_intent *old_entries, int n_old,
    const cfg_l2_security_rule_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_l2_security_rule(old_entries, n_old,
                                         new_entries[i].kind,
                                         new_entries[i].vid,
                                         new_entries[i].port.hw_port);
        if (j >= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "%s-set vid=%d port=%d\n",
                         l2_security_op_prefix(new_entries[i].kind),
                         new_entries[i].vid,
                         new_entries[i].port.hw_port) != 0)
            return -1;
    }
    return 0;
}

static bool l2_security_vlan_configured(nl_yang_session *ys,
                                        const char *feature,
                                        const char *vlan) {
    char path[256];

    if (!ys || !feature || !vlan || !vlan[0])
        return false;
    snprintf(path, sizeof(path),
             "/netlab:netlab-config/ethernet-switching-options"
             "/%s/vlan[name='%s']/name", feature, vlan);
    return nl_yang_get(ys, path) != NULL;
}

static int emit_dai_binding_deletes(
    nl_yang_session *active, nl_yang_session *candidate,
    const cfg_dhcp_binding_intent *old_entries, int n_old,
    const cfg_dhcp_binding_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        bool old_dai = l2_security_vlan_configured(active, "arp-inspection",
                                                   old_entries[i].vlan);
        bool keep = false;
        int j;

        if (!old_dai || old_entries[i].port.hw_port <= 0)
            continue;
        j = l2_find_dhcp_binding(new_entries, n_new,
                                 old_entries[i].mac, old_entries[i].vid);
        if (j >= 0 &&
            l2_security_vlan_configured(candidate, "arp-inspection",
                                        new_entries[j].vlan) &&
            l2_dhcp_binding_same_target(&old_entries[i], &new_entries[j]))
            keep = true;
        if (keep)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "arp-inspection-binding-del vid=%d port=%d mac=%s ip=%s\n",
                         old_entries[i].vid, old_entries[i].port.hw_port,
                         old_entries[i].mac, old_entries[i].ip) != 0)
            return -1;
    }
    return 0;
}

static int emit_dai_binding_sets(
    nl_yang_session *active, nl_yang_session *candidate,
    const cfg_dhcp_binding_intent *old_entries, int n_old,
    const cfg_dhcp_binding_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        bool new_dai = l2_security_vlan_configured(candidate, "arp-inspection",
                                                   new_entries[i].vlan);
        bool unchanged = false;
        int j;

        if (!new_dai || new_entries[i].port.hw_port <= 0)
            continue;
        j = l2_find_dhcp_binding(old_entries, n_old,
                                 new_entries[i].mac, new_entries[i].vid);
        if (j >= 0 &&
            l2_security_vlan_configured(active, "arp-inspection",
                                        old_entries[j].vlan) &&
            l2_dhcp_binding_same_target(&old_entries[j], &new_entries[i]))
            unchanged = true;
        if (unchanged)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "arp-inspection-binding-set vid=%d port=%d mac=%s ip=%s\n",
                         new_entries[i].vid, new_entries[i].port.hw_port,
                         new_entries[i].mac, new_entries[i].ip) != 0)
            return -1;
    }
    return 0;
}

static int emit_user_filter_deletes(
    const cfg_user_filter_intent *old_entries, int n_old,
    const cfg_user_filter_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        int j = l2_find_user_filter_by_name(new_entries, n_new,
                                            old_entries[i].name);
        if (j >= 0 && l2_user_filter_same(&old_entries[i], &new_entries[j]))
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "user-filter-del name=%s vid=%d port=%d field=%s mac=%s\n",
                            old_entries[i].name, old_entries[i].vid,
                            old_entries[i].port.hw_port,
                            old_entries[i].mac_kind[0] ?
                            old_entries[i].mac_kind : "source",
                            old_entries[i].mac) != 0)
            return -1;
    }
    return 0;
}

static int emit_user_filter_sets(
    const cfg_user_filter_intent *old_entries, int n_old,
    const cfg_user_filter_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_user_filter_by_name(old_entries, n_old,
                                            new_entries[i].name);
        if (j >= 0 && l2_user_filter_same(&old_entries[j], &new_entries[i]))
            continue;
        if (new_entries[i].port.hw_port <= 0)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "user-filter-set name=%s vid=%d port=%d field=%s mac=%s\n",
                            new_entries[i].name, new_entries[i].vid,
                            new_entries[i].port.hw_port,
                            new_entries[i].mac_kind[0] ?
                            new_entries[i].mac_kind : "source",
                            new_entries[i].mac) != 0)
            return -1;
    }
    return 0;
}

static int format_ingress_ipv4_acl_match(
    const cfg_ingress_ipv4_acl_intent *entry, char *buf, size_t buf_size) {
    int off = 0;
    const hal_ingress_ipv4_acl_match *m;

    if (!entry || !buf || buf_size == 0)
        return -1;
    m = &entry->match;
    off += snprintf(buf + off, buf_size - (size_t)off,
                    "name=%s vid=%d port=%d",
                    entry->name, entry->vid, entry->port.hw_port);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_src_ip) {
        char ip_text[16];
        const char *text = entry->src_ip_text;
        if (!text[0]) {
            if (!l2_format_ipv4_text(m->src_ip, ip_text, sizeof(ip_text)))
                return -1;
            text = ip_text;
        }
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " src-ip=%s", text);
    }
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_src_ip && m->has_src_ip_mask &&
        m->src_ip_mask != 0xffffffffU) {
        char mask[16];
        if (!l2_format_ipv4_text(m->src_ip_mask, mask, sizeof(mask)))
            return -1;
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " src-mask=%s", mask);
    }
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_dst_ip) {
        char ip_text[16];
        const char *text = entry->dst_ip_text;
        if (!text[0]) {
            if (!l2_format_ipv4_text(m->dst_ip, ip_text, sizeof(ip_text)))
                return -1;
            text = ip_text;
        }
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " dst-ip=%s", text);
    }
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_dst_ip && m->has_dst_ip_mask &&
        m->dst_ip_mask != 0xffffffffU) {
        char mask[16];
        if (!l2_format_ipv4_text(m->dst_ip_mask, mask, sizeof(mask)))
            return -1;
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " dst-mask=%s", mask);
    }
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_dscp)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " dscp=%d", m->dscp);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_ecn)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " ecn=%d", m->ecn);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_protocol)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " proto=%d", m->protocol);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_src_port)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " src-port=%d", m->src_port);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_src_port_range) {
        char range_text[16];
        const char *text = entry->src_port_range_text;
        if (!text[0]) {
            snprintf(range_text, sizeof(range_text), "%d-%d",
                     m->src_port_start, m->src_port_end);
            text = range_text;
        }
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " src-port-range=%s", text);
    }
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_dst_port)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " dst-port=%d", m->dst_port);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_dst_port_range) {
        char range_text[16];
        const char *text = entry->dst_port_range_text;
        if (!text[0]) {
            snprintf(range_text, sizeof(range_text), "%d-%d",
                     m->dst_port_start, m->dst_port_end);
            text = range_text;
        }
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " dst-port-range=%s", text);
    }
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_tcp_flags)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " tcp-flags=%d", m->tcp_flags);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (m->has_tcp_flags_mask)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " tcp-flags-mask=%d", m->tcp_flags_mask);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    if (entry->action[0] && strcmp(entry->action, "drop") != 0)
        off += snprintf(buf + off, buf_size - (size_t)off,
                        " action=%s", entry->action);
    if (off < 0 || (size_t)off >= buf_size)
        return -1;
    return 0;
}

static int emit_ingress_ipv4_acl_deletes(
    const cfg_ingress_ipv4_acl_intent *old_entries, int n_old,
    const cfg_ingress_ipv4_acl_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        char args[384];
        int j = l2_find_ingress_ipv4_acl_by_name(
            new_entries, n_new, old_entries[i].name);
        if (j >= 0 &&
            l2_ingress_ipv4_acl_same(&old_entries[i], &new_entries[j]))
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        if (format_ingress_ipv4_acl_match(&old_entries[i], args,
                                          sizeof(args)) != 0)
            return -1;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "ingress-ipv4-acl-del %s\n", args) != 0)
            return -1;
    }
    return 0;
}

static int emit_ingress_ipv4_acl_sets(
    const cfg_ingress_ipv4_acl_intent *old_entries, int n_old,
    const cfg_ingress_ipv4_acl_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        char args[384];
        int j = l2_find_ingress_ipv4_acl_by_name(
            old_entries, n_old, new_entries[i].name);
        if (j >= 0 &&
            l2_ingress_ipv4_acl_same(&old_entries[j], &new_entries[i]))
            continue;
        if (new_entries[i].port.hw_port <= 0)
            continue;
        if (format_ingress_ipv4_acl_match(&new_entries[i], args,
                                          sizeof(args)) != 0)
            return -1;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "ingress-ipv4-acl-set %s\n", args) != 0)
            return -1;
    }
    return 0;
}

static int format_acl_policer_args(const cfg_acl_policer_intent *entry,
                                   char *buf, size_t buf_size) {
    int n;

    if (!entry || !buf || buf_size == 0)
        return -1;
    n = snprintf(buf, buf_size,
                 "name=%s port=%d dst-mac=%s rate=%d burst=%d",
                 entry->name, entry->port.hw_port, entry->dst_mac_text,
                 entry->rate_kbps, entry->burst_bytes);
    if (n < 0 || (size_t)n >= buf_size)
        return -1;
    return 0;
}

static int emit_acl_policer_deletes(
    const cfg_acl_policer_intent *old_entries, int n_old,
    const cfg_acl_policer_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        char args[192];
        int j = l2_find_acl_policer_by_name(new_entries, n_new,
                                            old_entries[i].name);
        if (j >= 0 && l2_acl_policer_same(&old_entries[i],
                                          &new_entries[j]))
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        if (format_acl_policer_args(&old_entries[i], args,
                                    sizeof(args)) != 0)
            return -1;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "acl-policer-del %s\n", args) != 0)
            return -1;
    }
    return 0;
}

static int emit_acl_policer_sets(
    const cfg_acl_policer_intent *old_entries, int n_old,
    const cfg_acl_policer_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        char args[192];
        int j = l2_find_acl_policer_by_name(old_entries, n_old,
                                            new_entries[i].name);
        if (j >= 0 && l2_acl_policer_same(&old_entries[j],
                                          &new_entries[i]))
            continue;
        if (new_entries[i].port.hw_port <= 0)
            continue;
        if (format_acl_policer_args(&new_entries[i], args,
                                    sizeof(args)) != 0)
            return -1;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "acl-policer-set %s\n", args) != 0)
            return -1;
    }
    return 0;
}

static int format_egress_acl_args(const cfg_egress_acl_intent *entry,
                                  char *buf, size_t buf_size) {
    int n;
    int off = 0;

    if (!entry || !buf || buf_size == 0)
        return -1;
    n = snprintf(buf + off, buf_size - (size_t)off,
                 "name=%s port=%d", entry->name, entry->port.hw_port);
    if (n < 0 || (size_t)n >= buf_size - (size_t)off)
        return -1;
    off += n;
    if (entry->has_src_mac) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " src-mac=%s", entry->src_mac_text);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (entry->has_dst_mac) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " dst-mac=%s", entry->dst_mac_text);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    n = snprintf(buf + off, buf_size - (size_t)off, " action=drop");
    if (n < 0 || (size_t)n >= buf_size - (size_t)off)
        return -1;
    return 0;
}

static int emit_egress_acl_deletes(
    const cfg_egress_acl_intent *old_entries, int n_old,
    const cfg_egress_acl_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        char args[192];
        int j = l2_find_egress_acl_by_name(new_entries, n_new,
                                           old_entries[i].name);
        if (j >= 0 && l2_egress_acl_same(&old_entries[i],
                                         &new_entries[j]))
            continue;
        if (old_entries[i].port.hw_port <= 0)
            continue;
        if (format_egress_acl_args(&old_entries[i], args,
                                   sizeof(args)) != 0)
            return -1;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "egress-acl-del %s\n", args) != 0)
            return -1;
    }
    return 0;
}

static int emit_egress_acl_sets(
    const cfg_egress_acl_intent *old_entries, int n_old,
    const cfg_egress_acl_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        char args[192];
        int j = l2_find_egress_acl_by_name(old_entries, n_old,
                                           new_entries[i].name);
        if (j >= 0 && l2_egress_acl_same(&old_entries[j],
                                         &new_entries[i]))
            continue;
        if (new_entries[i].port.hw_port <= 0)
            continue;
        if (format_egress_acl_args(&new_entries[i], args,
                                   sizeof(args)) != 0)
            return -1;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "egress-acl-set %s\n", args) != 0)
            return -1;
    }
    return 0;
}

static int format_acl_independent_args(
    const cfg_acl_independent_intent *entry, char *buf, size_t buf_size) {
    int n;
    int off = 0;
    const hal_ingress_ipv4_acl_match *m;

    if (!entry || !buf || buf_size == 0)
        return -1;
    m = &entry->inet_match;
    n = snprintf(buf + off, buf_size - (size_t)off,
                 "group=%s term=%s family=%s slot=%d",
                 entry->group, entry->term, entry->family, entry->slot);
    if (n < 0 || (size_t)n >= buf_size - (size_t)off)
        return -1;
    off += n;
    if (entry->vid > 0) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " vid=%d", entry->vid);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (entry->port.hw_port > 0) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " port=%d", entry->port.hw_port);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (entry->has_src_mac) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " src-mac=%s", entry->src_mac_text);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (entry->has_dst_mac) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " dst-mac=%s", entry->dst_mac_text);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_src_ip) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " src-ip=%s", entry->src_ip_text);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
        if (m->has_src_ip_mask && m->src_ip_mask != 0xffffffffU) {
            char mask[16];
            if (!l2_format_ipv4_text(m->src_ip_mask, mask, sizeof(mask)))
                return -1;
            n = snprintf(buf + off, buf_size - (size_t)off,
                         " src-mask=%s", mask);
            if (n < 0 || (size_t)n >= buf_size - (size_t)off)
                return -1;
            off += n;
        }
    }
    if (m->has_dst_ip) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " dst-ip=%s", entry->dst_ip_text);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
        if (m->has_dst_ip_mask && m->dst_ip_mask != 0xffffffffU) {
            char mask[16];
            if (!l2_format_ipv4_text(m->dst_ip_mask, mask, sizeof(mask)))
                return -1;
            n = snprintf(buf + off, buf_size - (size_t)off,
                         " dst-mask=%s", mask);
            if (n < 0 || (size_t)n >= buf_size - (size_t)off)
                return -1;
            off += n;
        }
    }
    if (m->has_dscp) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " dscp=%d", m->dscp);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_ecn) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " ecn=%d", m->ecn);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_protocol) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " proto=%d", m->protocol);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_src_port) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " src-port=%d", m->src_port);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_src_port_range) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " src-port-range=%s", entry->src_port_range_text);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_dst_port) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " dst-port=%d", m->dst_port);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_dst_port_range) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " dst-port-range=%s", entry->dst_port_range_text);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_tcp_flags) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " tcp-flags=%d", m->tcp_flags);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    if (m->has_tcp_flags_mask) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " tcp-flags-mask=%d", m->tcp_flags_mask);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
        off += n;
    }
    n = snprintf(buf + off, buf_size - (size_t)off,
                 " action=%s", entry->action[0] ? entry->action : "drop");
    if (n < 0 || (size_t)n >= buf_size - (size_t)off)
        return -1;
    off += n;
    if (entry->rate_kbps > 0) {
        n = snprintf(buf + off, buf_size - (size_t)off,
                     " rate=%d burst=%d",
                     entry->rate_kbps, entry->burst_bytes);
        if (n < 0 || (size_t)n >= buf_size - (size_t)off)
            return -1;
    }
    return 0;
}

static int emit_acl_independent_deletes(
    const cfg_acl_independent_intent *old_entries, int n_old,
    const cfg_acl_independent_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_old; i++) {
        char args[768];
        int j = l2_find_acl_independent_by_key(
            new_entries, n_new, old_entries[i].group,
            old_entries[i].term, old_entries[i].family);

        if (j >= 0 &&
            l2_acl_independent_same(&old_entries[i], &new_entries[j]))
            continue;
        if (format_acl_independent_args(&old_entries[i], args,
                                        sizeof(args)) != 0)
            return -1;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "acl-independent-del %s\n", args) != 0)
            return -1;
    }
    return 0;
}

static int emit_acl_independent_sets(
    const cfg_acl_independent_intent *old_entries, int n_old,
    const cfg_acl_independent_intent *new_entries, int n_new,
    char *plan, size_t plan_size, int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        char args[768];
        int j = l2_find_acl_independent_by_key(
            old_entries, n_old, new_entries[i].group,
            new_entries[i].term, new_entries[i].family);

        if (j >= 0 &&
            l2_acl_independent_same(&old_entries[j], &new_entries[i]))
            continue;
        if (format_acl_independent_args(&new_entries[i], args,
                                        sizeof(args)) != 0)
            return -1;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                            "acl-independent-set %s\n", args) != 0)
            return -1;
    }
    return 0;
}

static int emit_copp_updates(const cfg_copp_class_intent *old_entries,
                             int n_old,
                             const cfg_copp_class_intent *new_entries,
                             int n_new,
                             char *plan, size_t plan_size,
                             int *off, bool *l2) {
    for (int i = 0; i < n_new; i++) {
        int j = l2_find_copp_class(old_entries, n_old,
                                   new_entries[i].class_name);
        if (j >= 0 &&
            old_entries[j].rate_pps == new_entries[i].rate_pps &&
            old_entries[j].burst_pkts == new_entries[i].burst_pkts)
            continue;
        *l2 = true;
        if (l2_plan_appendf(plan, plan_size, off,
                         "copp-class-set class=%s rate-pps=%d burst-pkts=%d\n",
                         new_entries[i].class_name,
                         new_entries[i].rate_pps,
                         new_entries[i].burst_pkts) != 0)
            return -1;
    }
    return 0;
}

static int emit_port_mirror_delta(const cfg_port_mirror_intent *old_intent,
                                  const cfg_port_mirror_intent *new_intent,
                                  char *plan, size_t plan_size, int *off,
                                  bool *l2) {
    bool mismatch = l2_hw_port_mirror_mismatch(new_intent);

    if (l2_port_mirror_same(old_intent, new_intent) && !mismatch)
        return 0;
    *l2 = true;
    if (!new_intent->exists)
        return l2_plan_appendf(
            plan, plan_size, off, "mirror-session-del group=%d\n",
            NETLAB_MIRROR_V1_GROUP);
    if (l2_plan_appendf(
            plan, plan_size, off,
            "mirror-session-set group=%d destination=%d sources=",
            NETLAB_MIRROR_V1_GROUP,
            new_intent->destination.hw_port) != 0)
        return -1;
    for (int i = 0; i < new_intent->n_sources; i++) {
        if (l2_plan_appendf(
                plan, plan_size, off, "%s%d:%d", i ? "," : "",
                new_intent->sources[i].port.hw_port,
                new_intent->sources[i].direction) != 0)
            return -1;
    }
    return l2_plan_appendf(plan, plan_size, off, "\n");
}

typedef struct {
    cfg_port_ref ports[NL_MAX_PORTS_PER_PROFILE];
    cfg_vlan_ref old_vlans[4096];
    cfg_vlan_ref new_vlans[4096];
    cfg_static_mac_intent old_static[CFG_STATIC_MAC_MAX_ENTRIES];
    cfg_static_mac_intent new_static[CFG_STATIC_MAC_MAX_ENTRIES];
    cfg_storm_control_intent old_storm[CFG_STORM_CONTROL_MAX_ENTRIES];
    cfg_storm_control_intent new_storm[CFG_STORM_CONTROL_MAX_ENTRIES];
    cfg_ingress_rate_limit_intent
        old_ingress_rate_limit[CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES];
    cfg_ingress_rate_limit_intent
        new_ingress_rate_limit[CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES];
    cfg_egress_rate_limit_intent
        old_egress_rate_limit[CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES];
    cfg_egress_rate_limit_intent
        new_egress_rate_limit[CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES];
    cfg_l2_security_rule_intent old_security[CFG_L2_SECURITY_MAX_RULES];
    cfg_l2_security_rule_intent new_security[CFG_L2_SECURITY_MAX_RULES];
    cfg_dhcp_binding_intent old_bindings[CFG_DHCP_BINDING_MAX_ENTRIES];
    cfg_dhcp_binding_intent new_bindings[CFG_DHCP_BINDING_MAX_ENTRIES];
    cfg_user_filter_intent old_user_filters[CFG_USER_FILTER_MAX_ENTRIES];
    cfg_user_filter_intent new_user_filters[CFG_USER_FILTER_MAX_ENTRIES];
    cfg_ingress_ipv4_acl_intent
        old_ingress_ipv4_acl[CFG_INGRESS_IPV4_ACL_MAX_ENTRIES];
    cfg_ingress_ipv4_acl_intent
        new_ingress_ipv4_acl[CFG_INGRESS_IPV4_ACL_MAX_ENTRIES];
    cfg_acl_policer_intent old_acl_policer[CFG_ACL_POLICER_MAX_ENTRIES];
    cfg_acl_policer_intent new_acl_policer[CFG_ACL_POLICER_MAX_ENTRIES];
    cfg_egress_acl_intent old_egress_acl[CFG_EGRESS_ACL_MAX_ENTRIES];
    cfg_egress_acl_intent new_egress_acl[CFG_EGRESS_ACL_MAX_ENTRIES];
    cfg_acl_independent_intent
        old_acl_independent[CFG_ACL_INDEPENDENT_MAX_TERMS];
    cfg_acl_independent_intent
        new_acl_independent[CFG_ACL_INDEPENDENT_MAX_TERMS];
    cfg_copp_class_intent old_copp[CFG_COPP_CLASS_MAX];
    cfg_copp_class_intent new_copp[CFG_COPP_CLASS_MAX];
    cfg_qos_interface_intent old_qos_ifaces[CFG_QOS_INTERFACE_MAX_ENTRIES];
    cfg_qos_interface_intent new_qos_ifaces[CFG_QOS_INTERFACE_MAX_ENTRIES];
    cfg_qos_pfc_intent old_qos_pfc[CFG_QOS_PFC_MAX_ENTRIES];
    cfg_qos_pfc_intent new_qos_pfc[CFG_QOS_PFC_MAX_ENTRIES];
    cfg_qos_priority_map_intent old_qos_maps[CFG_QOS_PRIORITY_MAP_MAX_ENTRIES];
    cfg_qos_priority_map_intent new_qos_maps[CFG_QOS_PRIORITY_MAP_MAX_ENTRIES];
    cfg_qos_scheduler_tc_map_intent
        old_qos_scheduler[CFG_QOS_SCHEDULER_TC_MAP_MAX_ENTRIES];
    cfg_qos_scheduler_tc_map_intent
        new_qos_scheduler[CFG_QOS_SCHEDULER_TC_MAP_MAX_ENTRIES];
    cfg_qos_scheduler_group_intent
        old_qos_scheduler_groups[CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES];
    cfg_qos_scheduler_group_intent
        new_qos_scheduler_groups[CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES];
    cfg_qos_scheduler_group_shaping_intent
        old_qos_scheduler_group_shaping[CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES];
    cfg_qos_scheduler_group_shaping_intent
        new_qos_scheduler_group_shaping[CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES];
    cfg_qos_scheduler_port_intent
        old_qos_scheduler_ports[CFG_QOS_SCHEDULER_PORT_MAX_ENTRIES];
    cfg_qos_scheduler_port_intent
        new_qos_scheduler_ports[CFG_QOS_SCHEDULER_PORT_MAX_ENTRIES];
    cfg_qos_watermark_intent
        old_qos_watermarks[CFG_QOS_WATERMARK_MAX_ENTRIES];
    cfg_qos_watermark_intent
        new_qos_watermarks[CFG_QOS_WATERMARK_MAX_ENTRIES];
    cfg_port_mirror_intent old_mirror;
    cfg_port_mirror_intent new_mirror;
    cfg_igmp_listener_intent old_igmp[CFG_IGMP_STATIC_MAX_MEMBERS];
    cfg_igmp_listener_intent new_igmp[CFG_IGMP_STATIC_MAX_MEMBERS];
    bool missing_by_vid[4095];
    bool lag_missing[CFG_AE_LIMIT];
} l2_plan_work;

#define ports (work->ports)
#define old_vlans (work->old_vlans)
#define new_vlans (work->new_vlans)
#define old_static (work->old_static)
#define new_static (work->new_static)
#define old_storm (work->old_storm)
#define new_storm (work->new_storm)
#define old_ingress_rate_limit (work->old_ingress_rate_limit)
#define new_ingress_rate_limit (work->new_ingress_rate_limit)
#define old_egress_rate_limit (work->old_egress_rate_limit)
#define new_egress_rate_limit (work->new_egress_rate_limit)
#define old_security (work->old_security)
#define new_security (work->new_security)
#define old_bindings (work->old_bindings)
#define new_bindings (work->new_bindings)
#define old_user_filters (work->old_user_filters)
#define new_user_filters (work->new_user_filters)
#define old_ingress_ipv4_acl (work->old_ingress_ipv4_acl)
#define new_ingress_ipv4_acl (work->new_ingress_ipv4_acl)
#define old_acl_policer (work->old_acl_policer)
#define new_acl_policer (work->new_acl_policer)
#define old_egress_acl (work->old_egress_acl)
#define new_egress_acl (work->new_egress_acl)
#define old_acl_independent (work->old_acl_independent)
#define new_acl_independent (work->new_acl_independent)
#define old_copp (work->old_copp)
#define new_copp (work->new_copp)
#define old_qos_ifaces (work->old_qos_ifaces)
#define new_qos_ifaces (work->new_qos_ifaces)
#define old_qos_pfc (work->old_qos_pfc)
#define new_qos_pfc (work->new_qos_pfc)
#define old_qos_maps (work->old_qos_maps)
#define new_qos_maps (work->new_qos_maps)
#define old_qos_scheduler (work->old_qos_scheduler)
#define new_qos_scheduler (work->new_qos_scheduler)
#define old_qos_scheduler_groups (work->old_qos_scheduler_groups)
#define new_qos_scheduler_groups (work->new_qos_scheduler_groups)
#define old_qos_scheduler_group_shaping \
    (work->old_qos_scheduler_group_shaping)
#define new_qos_scheduler_group_shaping \
    (work->new_qos_scheduler_group_shaping)
#define old_qos_scheduler_ports (work->old_qos_scheduler_ports)
#define new_qos_scheduler_ports (work->new_qos_scheduler_ports)
#define old_qos_watermarks (work->old_qos_watermarks)
#define new_qos_watermarks (work->new_qos_watermarks)
#define old_mirror (work->old_mirror)
#define new_mirror (work->new_mirror)
#define old_igmp (work->old_igmp)
#define new_igmp (work->new_igmp)
#define missing_by_vid (work->missing_by_vid)
#define lag_missing (work->lag_missing)

static int l2_build_plan_with_work(nl_yang_session *active,
                                   nl_yang_session *candidate,
                                   bool require_hw,
                                   char *plan, size_t plan_size,
                                   int *plan_len, bool *has_l2,
                                   char *err, size_t err_size,
                                   l2_plan_work *work) {
    int n_ports;
    int n_old_vlans;
    int n_new_vlans;
    int n_old_static;
    int n_new_static;
    int n_old_storm;
    int n_new_storm;
    int n_old_ingress_rate_limit;
    int n_new_ingress_rate_limit;
    int n_old_egress_rate_limit;
    int n_new_egress_rate_limit;
    int n_old_security = 0;
    int n_new_security = 0;
    int n_old_bindings;
    int n_new_bindings;
    int n_old_user_filters;
    int n_new_user_filters;
    int n_old_ingress_ipv4_acl;
    int n_new_ingress_ipv4_acl;
    int n_old_acl_policer;
    int n_new_acl_policer;
    int n_old_egress_acl;
    int n_new_egress_acl;
    int n_old_acl_independent;
    int n_new_acl_independent;
    int n_old_copp;
    int n_new_copp;
    int n_old_qos_ifaces;
    int n_new_qos_ifaces;
    int n_old_qos_pfc;
    int n_new_qos_pfc;
    int n_old_qos_maps;
    int n_new_qos_maps;
    int n_old_qos_scheduler;
    int n_new_qos_scheduler;
    int n_old_qos_scheduler_groups;
    int n_new_qos_scheduler_groups;
    int n_old_qos_scheduler_group_shaping;
    int n_new_qos_scheduler_group_shaping;
    int n_old_qos_scheduler_ports;
    int n_new_qos_scheduler_ports;
    int n_old_qos_watermarks;
    int n_new_qos_watermarks;
    int n_old_igmp;
    int n_new_igmp;
    int off = 0;
    bool l2 = false;
    l2_fm10k_groups board_groups;
    bool qos_auto_pause_triggered = false;
    bool qos_watermark_delete_needed = false;

    if (!active || !candidate || !plan || plan_size == 0 ||
        !plan_len || !has_l2)
        return -1;

    l2_hw_probe_begin(require_hw);
    plan[0] = '\0';
    *plan_len = 0;
    *has_l2 = false;
    if (err && err_size > 0)
        err[0] = '\0';

    if (l2_validate_duplicate_vlan_ids(candidate, err, err_size) != 0)
        return -1;
    if (l2_validate_mac_aging_time(candidate, err, err_size) != 0)
        return -1;

    if (l2_fm10k_groups_prepare(active, candidate, require_hw, &board_groups, err, err_size))
        return -1;
    uint32_t replay_ports = 0;
    for (int i = 0; i < FM10K_GROUP_COUNT; ++i)
        if (board_groups.changed_mask & (1U << i)) replay_ports |= 15U << (4 * i);
    l2_hw_force_ports(replay_ports);
    n_ports = collect_known_ports(candidate, ports, NL_MAX_PORTS_PER_PROFILE);
    for (int i = 0; board_groups.managed && i < n_ports; ++i) {
        cfg_port_ref *p = &ports[i];
        if (p->is_aggregate || p->hw_port < 1 || p->hw_port > 24) continue;
        const fm10k_group *g = &board_groups.target[(p->hw_port - 1) / 4];
        int lane = (p->hw_port - 1) % 4;
        int speed = g->mode ? (lane ? 0 : g->mode) : g->lane_gbps[lane];
        /* Fixed inventory survives an online switch. Runtime mode, not the
         * boot profile's preferred speed, supplies LAG validation. */
        p->default_speed_bps = (u64)speed * 1000000000ULL;
        p->scheduler_speed_bps = (u64)(lane ? 25 : 100) * 1000000000ULL;
    }
    if (l2_validate_configured_interfaces(candidate, ports, n_ports,
                                       err, err_size) != 0)
        return -1;
    if (l2_validate_lldp_intents(candidate, ports, n_ports,
                              err, err_size) != 0)
        return -1;
    if (l2_validate_rstp_intents(candidate, ports, n_ports,
                              err, err_size) != 0)
        return -1;
    if (l2_validate_lag_intents(candidate, ports, n_ports,
                             err, err_size) != 0)
        return -1;
    if (l2_validate_static_mac_intents(candidate, ports, n_ports,
                                    err, err_size) != 0)
        return -1;
    if (l2_validate_igmp_snooping_intents(candidate, ports, n_ports,
                                          err, err_size) != 0)
        return -1;
    if (l2_validate_secure_access_intents(candidate, ports, n_ports,
                                       err, err_size) != 0)
        return -1;
    if (l2_validate_mac_move_intents(candidate, err, err_size) != 0)
        return -1;
    if (l2_validate_l2_security_intents(candidate, ports, n_ports,
                                        err, err_size) != 0)
        return -1;
    if (l2_validate_dhcp_binding_intents(candidate, ports, n_ports,
                                         err, err_size) != 0)
        return -1;
    if (l2_validate_user_filter_intents(candidate, ports, n_ports,
                                        err, err_size) != 0)
        return -1;
    if (l2_validate_ingress_ipv4_acl_intents(candidate, ports, n_ports,
                                            err, err_size) != 0)
        return -1;
    if (l2_validate_acl_policer_intents(candidate, ports, n_ports,
                                        err, err_size) != 0)
        return -1;
    if (l2_validate_egress_acl_intents(candidate, ports, n_ports,
                                       err, err_size) != 0)
        return -1;
    if (l2_validate_acl_independent_intents(candidate, ports, n_ports,
                                           err, err_size) != 0)
        return -1;
    if (l2_validate_l2_security_capacity(candidate, ports, n_ports,
                                         err, err_size) != 0)
        return -1;
    if (l2_validate_storm_control_intents(candidate, ports, n_ports,
                                       err, err_size) != 0)
        return -1;
    if (l2_validate_ingress_rate_limit_intents(candidate, ports, n_ports,
                                       err, err_size) != 0)
        return -1;
    if (l2_validate_rate_controller_capacity(candidate, err, err_size) != 0)
        return -1;
    if (l2_validate_egress_rate_limit_intents(candidate, ports, n_ports,
                                             err, err_size) != 0)
        return -1;
    if (l2_validate_qos_intents(candidate, ports, n_ports,
                                err, err_size) != 0)
        return -1;
    if (l2_validate_port_mirror_intent(candidate, ports, n_ports,
                                       err, err_size) != 0)
        return -1;

    for (int i = 0; i < n_ports; i++) {
        cfg_if_intent new_i;
        if (!ports[i].is_aggregate && ports[i].hw_port <= 0)
            continue;
        l2_read_interface_intent(candidate, ports[i].name, &new_i);
        if (l2_validate_interface_intent(&ports[i], &new_i, err, err_size) != 0)
            return -1;
    }

    n_old_vlans = l2_collect_vlans(active, old_vlans, 4096);
    n_new_vlans = l2_collect_vlans(candidate, new_vlans, 4096);
    n_old_static = l2_collect_static_mac_intents(active, old_static,
                                              CFG_STATIC_MAC_MAX_ENTRIES);
    n_new_static = l2_collect_static_mac_intents(candidate, new_static,
                                              CFG_STATIC_MAC_MAX_ENTRIES);
    n_old_storm = l2_collect_storm_control_intents(active, old_storm,
                                                CFG_STORM_CONTROL_MAX_ENTRIES);
    n_new_storm = l2_collect_storm_control_intents(candidate, new_storm,
                                                CFG_STORM_CONTROL_MAX_ENTRIES);
    if (n_old_storm < 0 || n_new_storm < 0)
        return l2_plan_set_error(err, err_size, "cannot read all storm-control policies", NULL, NULL);
    n_old_ingress_rate_limit = l2_collect_ingress_rate_limit_intents(
        active, old_ingress_rate_limit, CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES);
    n_new_ingress_rate_limit = l2_collect_ingress_rate_limit_intents(
        candidate, new_ingress_rate_limit, CFG_INGRESS_RATE_LIMIT_MAX_ENTRIES);
    n_old_egress_rate_limit = l2_collect_egress_rate_limit_intents(
        active, old_egress_rate_limit, CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES);
    n_new_egress_rate_limit = l2_collect_egress_rate_limit_intents(
        candidate, new_egress_rate_limit, CFG_EGRESS_RATE_LIMIT_MAX_ENTRIES);
    n_old_bindings = l2_collect_dhcp_binding_intents(
        active, old_bindings, CFG_DHCP_BINDING_MAX_ENTRIES, ports, n_ports);
    n_new_bindings = l2_collect_dhcp_binding_intents(
        candidate, new_bindings, CFG_DHCP_BINDING_MAX_ENTRIES, ports, n_ports);
    n_old_user_filters = l2_collect_user_filter_intents(
        active, old_user_filters, CFG_USER_FILTER_MAX_ENTRIES, ports, n_ports);
    n_new_user_filters = l2_collect_user_filter_intents(
        candidate, new_user_filters, CFG_USER_FILTER_MAX_ENTRIES, ports,
        n_ports);
    n_old_ingress_ipv4_acl = l2_collect_ingress_ipv4_acl_intents(
        active, old_ingress_ipv4_acl, CFG_INGRESS_IPV4_ACL_MAX_ENTRIES,
        ports, n_ports);
    n_new_ingress_ipv4_acl = l2_collect_ingress_ipv4_acl_intents(
        candidate, new_ingress_ipv4_acl, CFG_INGRESS_IPV4_ACL_MAX_ENTRIES,
        ports, n_ports);
    n_old_acl_policer = l2_collect_acl_policer_intents(
        active, old_acl_policer, CFG_ACL_POLICER_MAX_ENTRIES, ports,
        n_ports);
    n_new_acl_policer = l2_collect_acl_policer_intents(
        candidate, new_acl_policer, CFG_ACL_POLICER_MAX_ENTRIES, ports,
        n_ports);
    n_old_egress_acl = l2_collect_egress_acl_intents(
        active, old_egress_acl, CFG_EGRESS_ACL_MAX_ENTRIES, ports, n_ports);
    n_new_egress_acl = l2_collect_egress_acl_intents(
        candidate, new_egress_acl, CFG_EGRESS_ACL_MAX_ENTRIES, ports,
        n_ports);
    n_old_acl_independent = l2_collect_acl_independent_intents(
        active, old_acl_independent, CFG_ACL_INDEPENDENT_MAX_TERMS,
        ports, n_ports);
    n_new_acl_independent = l2_collect_acl_independent_intents(
        candidate, new_acl_independent, CFG_ACL_INDEPENDENT_MAX_TERMS,
        ports, n_ports);
    n_old_copp = l2_collect_copp_class_intents(active, old_copp,
                                               CFG_COPP_CLASS_MAX);
    n_new_copp = l2_collect_copp_class_intents(candidate, new_copp,
                                               CFG_COPP_CLASS_MAX);
    n_old_qos_ifaces = l2_collect_qos_interface_intents(
        active, old_qos_ifaces, CFG_QOS_INTERFACE_MAX_ENTRIES);
    n_new_qos_ifaces = l2_collect_qos_interface_intents(
        candidate, new_qos_ifaces, CFG_QOS_INTERFACE_MAX_ENTRIES);
    n_old_qos_pfc = l2_collect_qos_pfc_intents(
        active, old_qos_pfc, CFG_QOS_PFC_MAX_ENTRIES);
    n_new_qos_pfc = l2_collect_qos_pfc_intents(
        candidate, new_qos_pfc, CFG_QOS_PFC_MAX_ENTRIES);
    n_old_qos_maps = l2_collect_qos_priority_map_intents(
        active, old_qos_maps, CFG_QOS_PRIORITY_MAP_MAX_ENTRIES);
    n_new_qos_maps = l2_collect_qos_priority_map_intents(
        candidate, new_qos_maps, CFG_QOS_PRIORITY_MAP_MAX_ENTRIES);
    n_old_qos_scheduler = l2_collect_qos_scheduler_tc_map_intents(
        active, old_qos_scheduler, CFG_QOS_SCHEDULER_TC_MAP_MAX_ENTRIES);
    n_new_qos_scheduler = l2_collect_qos_scheduler_tc_map_intents(
        candidate, new_qos_scheduler, CFG_QOS_SCHEDULER_TC_MAP_MAX_ENTRIES);
    n_old_qos_scheduler_groups = l2_collect_qos_scheduler_group_intents(
        active, old_qos_scheduler_groups,
        CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES);
    n_new_qos_scheduler_groups = l2_collect_qos_scheduler_group_intents(
        candidate, new_qos_scheduler_groups,
        CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES);
    n_old_qos_scheduler_group_shaping =
        l2_collect_qos_scheduler_group_shaping_intents(
            active, old_qos_scheduler_group_shaping,
            CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES);
    n_new_qos_scheduler_group_shaping =
        l2_collect_qos_scheduler_group_shaping_intents(
            candidate, new_qos_scheduler_group_shaping,
            CFG_QOS_SCHEDULER_GROUP_MAX_ENTRIES);
    n_old_qos_scheduler_ports = l2_collect_qos_scheduler_port_intents(
        active, old_qos_scheduler_ports,
        CFG_QOS_SCHEDULER_PORT_MAX_ENTRIES);
    n_new_qos_scheduler_ports = l2_collect_qos_scheduler_port_intents(
        candidate, new_qos_scheduler_ports,
        CFG_QOS_SCHEDULER_PORT_MAX_ENTRIES);
    n_old_qos_watermarks = l2_collect_qos_watermark_intents(
        active, old_qos_watermarks, CFG_QOS_WATERMARK_MAX_ENTRIES);
    n_new_qos_watermarks = l2_collect_qos_watermark_intents(
        candidate, new_qos_watermarks, CFG_QOS_WATERMARK_MAX_ENTRIES);
    qos_watermark_delete_needed = qos_watermark_has_deletes(
        old_qos_watermarks, n_old_qos_watermarks,
        new_qos_watermarks, n_new_qos_watermarks);
    (void)l2_collect_port_mirror_intent(active, &old_mirror,
                                        ports, n_ports);
    (void)l2_collect_port_mirror_intent(candidate, &new_mirror,
                                        ports, n_ports);
    n_old_igmp = l2_collect_igmp_listener_intents(
        active, old_igmp, CFG_IGMP_STATIC_MAX_MEMBERS, ports, n_ports);
    n_new_igmp = l2_collect_igmp_listener_intents(
        candidate, new_igmp, CFG_IGMP_STATIC_MAX_MEMBERS, ports, n_ports);
    if (n_old_igmp < 0 || n_new_igmp < 0)
        return l2_plan_set_error(err, err_size, "cannot collect IGMP transaction ownership", NULL, NULL);
    n_old_security += l2_collect_l2_security_rule_intents(
        active, "dhcp-snooping", old_security + n_old_security,
        CFG_L2_SECURITY_MAX_RULES - n_old_security, ports, n_ports);
    n_old_security += l2_collect_l2_security_rule_intents(
        active, "arp-inspection", old_security + n_old_security,
        CFG_L2_SECURITY_MAX_RULES - n_old_security, ports, n_ports);
    n_new_security += l2_collect_l2_security_rule_intents(
        candidate, "dhcp-snooping", new_security + n_new_security,
        CFG_L2_SECURITY_MAX_RULES - n_new_security, ports, n_ports);
    n_new_security += l2_collect_l2_security_rule_intents(
        candidate, "arp-inspection", new_security + n_new_security,
        CFG_L2_SECURITY_MAX_RULES - n_new_security, ports, n_ports);
    l2_resolve_static_mac_ports(old_static, n_old_static, ports, n_ports);
    l2_resolve_static_mac_ports(new_static, n_new_static, ports, n_ports);
    l2_resolve_storm_control_ports(old_storm, n_old_storm, ports, n_ports);
    l2_resolve_storm_control_ports(new_storm, n_new_storm, ports, n_ports);
    l2_resolve_ingress_rate_limit_ports(old_ingress_rate_limit,
                                        n_old_ingress_rate_limit,
                                        ports, n_ports);
    l2_resolve_ingress_rate_limit_ports(new_ingress_rate_limit,
                                        n_new_ingress_rate_limit,
                                        ports, n_ports);
    l2_resolve_egress_rate_limit_ports(old_egress_rate_limit,
                                       n_old_egress_rate_limit,
                                       ports, n_ports);
    l2_resolve_egress_rate_limit_ports(new_egress_rate_limit,
                                       n_new_egress_rate_limit,
                                       ports, n_ports);
    l2_resolve_qos_interface_ports(old_qos_ifaces, n_old_qos_ifaces,
                                   ports, n_ports);
    l2_resolve_qos_interface_ports(new_qos_ifaces, n_new_qos_ifaces,
                                   ports, n_ports);
    if (board_groups.managed) {
        n_old_qos_ifaces = fold_lag_qos(active, old_qos_ifaces, n_old_qos_ifaces,
                                       ports, n_ports, false, err, err_size);
        n_new_qos_ifaces = fold_lag_qos(candidate, new_qos_ifaces, n_new_qos_ifaces,
                                       ports, n_ports, true, err, err_size);
        if (n_old_qos_ifaces < 0 || n_new_qos_ifaces < 0) return -1;
    }
    l2_resolve_qos_pfc_ports(old_qos_pfc, n_old_qos_pfc, ports, n_ports);
    l2_resolve_qos_pfc_ports(new_qos_pfc, n_new_qos_pfc, ports, n_ports);
    l2_resolve_qos_scheduler_tc_map_ports(old_qos_scheduler,
                                          n_old_qos_scheduler,
                                          ports, n_ports);
    l2_resolve_qos_scheduler_tc_map_ports(new_qos_scheduler,
                                          n_new_qos_scheduler,
                                          ports, n_ports);
    l2_resolve_qos_scheduler_group_ports(old_qos_scheduler_groups,
                                         n_old_qos_scheduler_groups,
                                         ports, n_ports);
    l2_resolve_qos_scheduler_group_ports(new_qos_scheduler_groups,
                                         n_new_qos_scheduler_groups,
                                         ports, n_ports);
    l2_resolve_qos_scheduler_group_shaping_ports(
        old_qos_scheduler_group_shaping,
        n_old_qos_scheduler_group_shaping,
        ports, n_ports);
    l2_resolve_qos_scheduler_group_shaping_ports(
        new_qos_scheduler_group_shaping,
        n_new_qos_scheduler_group_shaping,
        ports, n_ports);
    l2_resolve_qos_scheduler_port_ports(old_qos_scheduler_ports,
                                        n_old_qos_scheduler_ports,
                                        ports, n_ports);
    l2_resolve_qos_scheduler_port_ports(new_qos_scheduler_ports,
                                        n_new_qos_scheduler_ports,
                                        ports, n_ports);
    l2_resolve_qos_watermark_ports(old_qos_watermarks,
                                   n_old_qos_watermarks,
                                   ports, n_ports);
    l2_resolve_qos_watermark_ports(new_qos_watermarks,
                                   n_new_qos_watermarks,
                                   ports, n_ports);
    for (int i = 0; i < n_new_vlans; i++)
        missing_by_vid[new_vlans[i].vid] =
            l2_hw_vlan_missing(new_vlans[i].vid);
    for (int ae = 0; ae < l2_cfg_max_ae(); ae++) {
        char ifname[16];
        snprintf(ifname, sizeof(ifname), "ae%d", ae);
        if (l2_aggregate_configured(candidate, ifname))
            lag_missing[ae] = l2_hw_lag_missing(ae);
    }

    if (l2_fm10k_groups_emit(&board_groups, 0, plan, plan_size, &off, &l2))
        return -1;

    if (emit_lag_member_removals(ports, n_ports, active, candidate,
                                 plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_lag_member_l2_cleanup(ports, n_ports, active, candidate,
                                   plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_lag_create_update(active, candidate, lag_missing,
                               plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_lag_hash_rotation_updates(active, candidate, lag_missing,
                                       plan, plan_size, &off, &l2) != 0)
        return -1;

    for (int i = 0; i < n_ports; i++) {
        cfg_if_intent old_i;
        cfg_if_intent new_i;
        if (!ports[i].is_aggregate && ports[i].hw_port <= 0)
            continue;
        l2_read_interface_intent(active, ports[i].name, &old_i);
        l2_read_interface_intent(candidate, ports[i].name, &new_i);
        if (!board_groups.managed && emit_speed_delta(&ports[i], &old_i, &new_i, active,
                             plan, plan_size, &off, &l2,
                             err, err_size) != 0)
            return -1;
    }

    if (emit_static_mac_deletes(old_static, n_old_static,
                                new_static, n_new_static,
                                plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_igmp_listener_deletes(old_igmp, n_old_igmp,
                                   new_igmp, n_new_igmp,
                                   plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_storm_control_deletes(old_storm, n_old_storm,
                                   new_storm, n_new_storm,
                                   plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_ingress_rate_limit_deletes(old_ingress_rate_limit,
                                        n_old_ingress_rate_limit,
                                        new_ingress_rate_limit,
                                        n_new_ingress_rate_limit,
                                        plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_egress_rate_limit_deletes(old_egress_rate_limit,
                                       n_old_egress_rate_limit,
                                       new_egress_rate_limit,
                                       n_new_egress_rate_limit,
                                       plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_interface_deletes(old_qos_ifaces, n_old_qos_ifaces,
                                   new_qos_ifaces, n_new_qos_ifaces,
                                   candidate, board_groups.managed,
                                   plan, plan_size, &off, &l2) != 0)
        return -1;

    {
        int before = off;
        if (emit_qos_pfc_deletes(old_qos_pfc, n_old_qos_pfc,
                                 new_qos_pfc, n_new_qos_pfc,
                                 plan, plan_size, &off, &l2) != 0)
            return -1;
        qos_auto_pause_triggered =
            qos_auto_pause_triggered || off != before;
    }

    {
        int before = off;
        if (emit_qos_priority_map_deletes(old_qos_maps, n_old_qos_maps,
                                          new_qos_maps, n_new_qos_maps,
                                          plan, plan_size, &off, &l2) != 0)
            return -1;
        qos_auto_pause_triggered =
            qos_auto_pause_triggered || off != before;
    }

    if (emit_qos_scheduler_tc_map_deletes(old_qos_scheduler,
                                          n_old_qos_scheduler,
                                          new_qos_scheduler,
                                          n_new_qos_scheduler,
                                          plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_scheduler_group_deletes(old_qos_scheduler_groups,
                                         n_old_qos_scheduler_groups,
                                         new_qos_scheduler_groups,
                                         n_new_qos_scheduler_groups,
                                         plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_scheduler_group_shaping_deletes(
            old_qos_scheduler_group_shaping,
            n_old_qos_scheduler_group_shaping,
            new_qos_scheduler_group_shaping,
            n_new_qos_scheduler_group_shaping,
            plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_scheduler_port_deletes(old_qos_scheduler_ports,
                                        n_old_qos_scheduler_ports,
                                        new_qos_scheduler_ports,
                                        n_new_qos_scheduler_ports,
                                        plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_port_mirror_delta(&old_mirror, &new_mirror,
                               plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_dai_binding_deletes(active, candidate,
                                 old_bindings, n_old_bindings,
                                 new_bindings, n_new_bindings,
                                 plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_user_filter_deletes(old_user_filters, n_old_user_filters,
                                 new_user_filters, n_new_user_filters,
                                 plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_ingress_ipv4_acl_deletes(old_ingress_ipv4_acl,
                                      n_old_ingress_ipv4_acl,
                                      new_ingress_ipv4_acl,
                                      n_new_ingress_ipv4_acl,
                                      plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_acl_policer_deletes(old_acl_policer, n_old_acl_policer,
                                 new_acl_policer, n_new_acl_policer,
                                 plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_egress_acl_deletes(old_egress_acl, n_old_egress_acl,
                                new_egress_acl, n_new_egress_acl,
                                plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_acl_independent_deletes(old_acl_independent,
                                     n_old_acl_independent,
                                     new_acl_independent,
                                     n_new_acl_independent,
                                     plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_l2_security_deletes(old_security, n_old_security,
                                 new_security, n_new_security,
                                 plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_copp_updates(old_copp, n_old_copp, new_copp, n_new_copp,
                          plan, plan_size, &off, &l2) != 0)
        return -1;

    // Remove old memberships and reset per-port state before deleting VLANs.
    for (int i = 0; i < n_ports; i++) {
        cfg_if_intent old_i;
        cfg_if_intent new_i;
        if (!ports[i].is_aggregate && ports[i].hw_port <= 0)
            continue;
        /* On recovery after a new SDK lifetime, the removed aggregate may
         * already be absent. A complete hardware read proves that no VLAN
         * membership exists to remove; an RPC error never takes this path. */
        if (ports[i].is_aggregate && !l2_aggregate_configured(candidate, ports[i].name) &&
            l2_hw_lag_missing(l2_ae_id(ports[i].name))) continue;
        l2_read_interface_intent(active, ports[i].name, &old_i);
        l2_read_interface_intent(candidate, ports[i].name, &new_i);
        const char *new_lag_member =
            l2_get_lag_member(candidate, ports[i].name);
        bool becomes_lag_member = !ports[i].is_aggregate &&
                                  new_lag_member && new_lag_member[0];
        if (emit_interface_removal(&ports[i], &old_i, &new_i,
                                   becomes_lag_member,
                                   plan, plan_size, &off, &l2) != 0)
            return -1;
    }

    if (l2_fm10k_groups_emit(&board_groups, 1, plan, plan_size, &off, &l2))
        return -1;
    bool mtu_reselect[CFG_AE_LIMIT];
    lag_reselection_scope(ports, n_ports, active, candidate, mtu_reselect);
    for (int i = 0; i < n_ports; ++i) {
        cfg_if_intent old_i, new_i;
        if (!ports[i].is_aggregate && ports[i].hw_port <= 0) continue;
        /* Removed aggregates have no target MTU. Resetting the old object
         * before deletion also fails when recovery has already removed it. */
        if (ports[i].is_aggregate && !l2_aggregate_configured(candidate, ports[i].name)) continue;
        if (!l2_fm10k_port_active(&board_groups, ports[i].hw_port)) continue;
        bool force = ports[i].is_aggregate && lag_missing[ports[i].ae_id];
        if (board_groups.managed && !ports[i].is_aggregate) {
            const char *old_lag = l2_get_lag_member(active, ports[i].name);
            const char *new_lag = l2_get_lag_member(candidate, ports[i].name);
            int ae = l2_ae_id(new_lag);
            if (ae >= 0 && ae < CFG_AE_LIMIT) {
                /* Attached members inherit MTU from the aggregate. Only
                 * detached/new members can receive an independent value. */
                if (l2_text_eq(old_lag, new_lag) && !mtu_reselect[ae] && !lag_missing[ae]) continue;
                force = true;
            } else if (old_lag && *old_lag) {
                /* Detach restores the saved independent image, which can
                 * differ from the projected value read before this plan. */
                force = true;
            }
        }
        l2_read_interface_intent(active, ports[i].name, &old_i);
        l2_read_interface_intent(candidate, ports[i].name, &new_i);
        if (emit_mtu_delta(&ports[i], &old_i, &new_i, force,
                plan, plan_size, &off, &l2)) return -1;
    }

    if (emit_lag_delete_after_cleanup(active, candidate,
                                      plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_default_vlan_cleanup(ports, n_ports, active, candidate,
                                  plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_vlan_deletes(old_vlans, n_old_vlans, new_vlans, n_new_vlans,
                          plan, plan_size, &off, &l2, err, err_size) != 0)
        return -1;

    if (emit_vlan_creates_diff(old_vlans, n_old_vlans, new_vlans, n_new_vlans,
                               missing_by_vid,
                               plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_ingress_filter_updates(ports, n_ports, active, candidate, &board_groups,
                                    lag_missing, plan, plan_size, &off, &l2) != 0)
        return -1;

    // Add or update new memberships only after required VLANs exist.
    for (int i = 0; i < n_ports; i++) {
        cfg_if_intent old_i;
        cfg_if_intent new_i;
        if (!ports[i].is_aggregate && ports[i].hw_port <= 0)
            continue;
        l2_read_interface_intent(active, ports[i].name, &old_i);
        l2_read_interface_intent(candidate, ports[i].name, &new_i);
        if (emit_interface_add_update(&ports[i], &old_i, &new_i,
                                      missing_by_vid,
                                      plan, plan_size, &off, &l2) != 0)
            return -1;
    }

    if (emit_static_mac_adds(old_static, n_old_static,
                             new_static, n_new_static,
                             lag_missing,
                             plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_igmp_listener_sets(old_igmp, n_old_igmp,
                                new_igmp, n_new_igmp,
                                plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_storm_control_sets(old_storm, n_old_storm,
                                new_storm, n_new_storm,
                                plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_ingress_rate_limit_sets(old_ingress_rate_limit,
                                     n_old_ingress_rate_limit,
                                     new_ingress_rate_limit,
                                     n_new_ingress_rate_limit,
                                     plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_egress_rate_limit_sets(old_egress_rate_limit,
                                    n_old_egress_rate_limit,
                                    new_egress_rate_limit,
                                    n_new_egress_rate_limit,
                                    plan, plan_size, &off, &l2) != 0)
        return -1;

    {
        int before = off;
        if (emit_qos_priority_map_sets(old_qos_maps, n_old_qos_maps,
                                       new_qos_maps, n_new_qos_maps,
                                       plan, plan_size, &off, &l2) != 0)
            return -1;
        qos_auto_pause_triggered =
            qos_auto_pause_triggered || off != before;
    }

    /*
     * A watermark deletion must not depend on process-local history.  Replay
     * the complete candidate SWPRI->TC map to invoke the SDK auto-pause
     * calculator, then retain its value as the explicit delete target.
     */
    if (qos_watermark_delete_needed) {
        if (emit_qos_priority_map_candidate_reconcile(
                new_qos_maps, n_new_qos_maps,
                plan, plan_size, &off, &l2) != 0)
            return -1;
        qos_auto_pause_triggered = true;
    }

    {
        int before = off;
        if (emit_qos_tc_smp(active, candidate, plan, plan_size, &off, &l2)) return -1;
        qos_auto_pause_triggered = qos_auto_pause_triggered || off != before;
    }
    if (emit_qos_dscp(active, candidate, plan, plan_size, &off, &l2)) return -1;

    if (emit_qos_scheduler_tc_map_sets(old_qos_scheduler,
                                       n_old_qos_scheduler,
                                       new_qos_scheduler,
                                       n_new_qos_scheduler,
                                       plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_scheduler_group_sets(old_qos_scheduler_groups,
                                      n_old_qos_scheduler_groups,
                                      new_qos_scheduler_groups,
                                      n_new_qos_scheduler_groups,
                                      plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_scheduler_group_shaping_sets(
            old_qos_scheduler_group_shaping,
            n_old_qos_scheduler_group_shaping,
            new_qos_scheduler_group_shaping,
            n_new_qos_scheduler_group_shaping,
            plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_scheduler_port_sets(old_qos_scheduler_ports,
                                     n_old_qos_scheduler_ports,
                                     new_qos_scheduler_ports,
                                     n_new_qos_scheduler_ports,
                                     plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_interface_sets(old_qos_ifaces, n_old_qos_ifaces,
                                new_qos_ifaces, n_new_qos_ifaces,
                                lag_missing,
                                plan, plan_size, &off, &l2) != 0)
        return -1;

    {
        int before = off;
        if (emit_qos_pfc_sets(old_qos_pfc, n_old_qos_pfc,
                              new_qos_pfc, n_new_qos_pfc,
                              plan, plan_size, &off, &l2) != 0)
            return -1;
        qos_auto_pause_triggered =
            qos_auto_pause_triggered || off != before;
    }

    /*
     * SWPRI maps alone are not the complete calculator authority: every
     * physical port's candidate lossless/PFC tuple also contributes.  A
     * restart-safe watermark DEL therefore rematerializes configured tuples
     * and explicit product defaults for all other present user ports.
     */
    if (qos_watermark_delete_needed) {
        if (emit_qos_pfc_candidate_reconcile(
                new_qos_pfc, n_new_qos_pfc, ports, n_ports,
                plan, plan_size, &off, &l2) != 0)
            return -1;
        qos_auto_pause_triggered = true;
    }

    if (emit_qos_watermark_deletes(
            old_qos_watermarks, n_old_qos_watermarks,
            new_qos_watermarks, n_new_qos_watermarks,
            qos_auto_pause_triggered,
            plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_qos_watermark_sets(old_qos_watermarks,
                                n_old_qos_watermarks,
                                new_qos_watermarks,
                                n_new_qos_watermarks,
                                qos_auto_pause_triggered,
                                qos_auto_pause_triggered,
                                plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_l2_security_sets(old_security, n_old_security,
                              new_security, n_new_security,
                              plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_dai_binding_sets(active, candidate,
                              old_bindings, n_old_bindings,
                              new_bindings, n_new_bindings,
                              plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_user_filter_sets(old_user_filters, n_old_user_filters,
                              new_user_filters, n_new_user_filters,
                              plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_ingress_ipv4_acl_sets(old_ingress_ipv4_acl,
                                   n_old_ingress_ipv4_acl,
                                   new_ingress_ipv4_acl,
                                   n_new_ingress_ipv4_acl,
                                   plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_acl_policer_sets(old_acl_policer, n_old_acl_policer,
                              new_acl_policer, n_new_acl_policer,
                              plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_egress_acl_sets(old_egress_acl, n_old_egress_acl,
                             new_egress_acl, n_new_egress_acl,
                             plan, plan_size, &off, &l2) != 0)
        return -1;

    if (emit_acl_independent_sets(old_acl_independent,
                                  n_old_acl_independent,
                                  new_acl_independent,
                                  n_new_acl_independent,
                                  plan, plan_size, &off, &l2) != 0)
        return -1;

    for (int i = 0; i < n_ports; i++) {
        cfg_if_intent old_i;
        cfg_if_intent new_i;
        if (!ports[i].is_aggregate && ports[i].hw_port <= 0)
            continue;
        l2_read_interface_intent(active, ports[i].name, &old_i);
        l2_read_interface_intent(candidate, ports[i].name, &new_i);
        if (!l2_fm10k_port_active(&board_groups, ports[i].hw_port) ||
            l2_fm10k_port_changed(&board_groups, ports[i].hw_port)) continue;
        if (emit_admin_delta(&ports[i], &old_i, &new_i,
                             plan, plan_size, &off, &l2) != 0)
            return -1;
    }

    if (emit_mac_aging_delta(active, candidate,
                             plan, plan_size, &off, &l2) != 0)
        return -1;

    if (l2_fm10k_fan_plan(active, candidate, require_hw, plan, plan_size, &off,
                          &l2, err, err_size) != 0)
        return -1;

    if (l2_fm10k_groups_emit(&board_groups, 2, plan, plan_size, &off, &l2))
        return -1;

    if (!l2_hw_probe_finish(err, err_size))
        return -1;
    if (l2_fm10k_scope_plan(active, candidate, plan, plan_size, &off, err, err_size))
        return -1;

    *plan_len = off;
    *has_l2 = l2;
    NL_LOG_INFO("l2d L2 plan: has_l2=%d len=%d", l2, off);
    return 0;
}

#undef ports
#undef old_vlans
#undef new_vlans
#undef old_static
#undef new_static
#undef old_storm
#undef new_storm
#undef old_ingress_rate_limit
#undef new_ingress_rate_limit
#undef old_egress_rate_limit
#undef new_egress_rate_limit
#undef old_security
#undef new_security
#undef old_bindings
#undef new_bindings
#undef old_user_filters
#undef new_user_filters
#undef old_ingress_ipv4_acl
#undef new_ingress_ipv4_acl
#undef old_acl_policer
#undef new_acl_policer
#undef old_egress_acl
#undef new_egress_acl
#undef old_acl_independent
#undef new_acl_independent
#undef old_copp
#undef new_copp
#undef old_qos_ifaces
#undef new_qos_ifaces
#undef old_qos_pfc
#undef new_qos_pfc
#undef old_qos_maps
#undef new_qos_maps
#undef old_qos_scheduler
#undef new_qos_scheduler
#undef old_qos_scheduler_groups
#undef new_qos_scheduler_groups
#undef old_qos_scheduler_group_shaping
#undef new_qos_scheduler_group_shaping
#undef old_qos_scheduler_ports
#undef new_qos_scheduler_ports
#undef old_qos_watermarks
#undef new_qos_watermarks
#undef old_mirror
#undef new_mirror
#undef old_igmp
#undef new_igmp
#undef missing_by_vid
#undef lag_missing

int nl_l2_build_plan(nl_yang_session *active,
                     nl_yang_session *candidate,
                     bool require_hw,
                     char *plan, size_t plan_size, int *plan_len,
                     bool *has_l2,
                     char *err, size_t err_size) {
    l2_plan_work *work;
    int status;

    work = calloc(1, sizeof(*work));
    if (!work) {
        if (err && err_size > 0)
            snprintf(err, err_size, "L2 plan workspace allocation failed");
        return -1;
    }
    status = l2_build_plan_with_work(
        active, candidate, require_hw, plan, plan_size, plan_len,
        has_l2, err, err_size, work);
    free(work);
    return status;
}
