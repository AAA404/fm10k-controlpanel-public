#include "l2_fm10k.h"
#include "l2_plan_internal.h"
#include "netlab/ipc.h"
#include "netlab/fm10k_plan_scope.h"
#include "netlab/fm10k_plan_codec.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int invalid(char *err, size_t size, const char *message) {
    if (err && size) snprintf(err, size, "%s", message);
    return -1;
}
static int read_number(nl_yang_session *ys, const char *leaf, int *out) {
    char path[256];
    snprintf(path, sizeof(path), L2_FM10K_ROOT "/fan/%s", leaf);
    const char *text = nl_yang_get(ys, path);
    if (!text || !*text) return -1;
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || *end || value < 0 || value > INT_MAX) return -1;
    *out = (int)value;
    return 0;
}
int l2_fm10k_read_fan(nl_yang_session *ys, fm10k_fan_curve *out) {
    if (!ys || !out) return -1;
    memset(out, 0, sizeof(*out));
    const char *sensor = nl_yang_get(ys, L2_FM10K_ROOT "/fan/sensor");
    const char *response = nl_yang_get(ys, L2_FM10K_ROOT "/fan/response-time-s");
    if (!sensor || strcmp(sensor, "fm10840_core") || !response) return -1;
    if (!strcmp(response, "5.45")) out->response_milliseconds = 5450;
    else if (!strcmp(response, "10.9") || !strcmp(response, "10.90")) out->response_milliseconds = 10900;
    else if (!strcmp(response, "21.6") || !strcmp(response, "21.60")) out->response_milliseconds = 21600;
    else if (!strcmp(response, "43.7") || !strcmp(response, "43.70")) out->response_milliseconds = 43700;
    else return -1;
    if (read_number(ys, "idle-temperature-c", &out->idle_c) ||
        read_number(ys, "load-temperature-c", &out->load_c) ||
        read_number(ys, "critical-temperature-c", &out->critical_c) ||
        read_number(ys, "idle-speed-percent", &out->idle_pwm) ||
        read_number(ys, "load-speed-percent", &out->load_pwm) ||
        read_number(ys, "hysteresis-c", &out->hysteresis_c)) return -1;
    return nl_fm10k_fan_valid(out) ? 0 : -1;
}
int l2_fm10k_read_hardware(nl_fm10k_config_snapshot *out, char *err, size_t err_size) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    s32 error = 0;
    int n = nl_rpc_call_ex(nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET", "/var/run/netlab/switchd.sock"),
        NL_DAEMON_L2D, NL_DAEMON_SWITCHD, NL_SWITCHD_FM10K_CONFIG_GET, 0,
        NULL, 0, (u8 *)out, sizeof(*out), 5000, &error);
    if (n != (int)sizeof(*out) || error || out->schema != NL_FM10K_CONFIG_SCHEMA || out->bytes != sizeof(*out))
        return invalid(err, err_size, "FM10840 configuration readback is unavailable or incompatible");
    return 0;
}
int l2_fm10k_fan_plan(nl_yang_session *active, nl_yang_session *candidate,
                       bool require_hw, char *plan, size_t size, int *offset,
                       bool *has_l2, char *err, size_t err_size) {
    bool old = nl_yang_exists(active, L2_FM10K_ROOT);
    if (!nl_yang_exists(candidate, L2_FM10K_ROOT))
        return old ? invalid(err, err_size, "FM10840 board configuration cannot be removed") : 0;
    const char *profile = nl_yang_get(candidate, L2_FM10K_ROOT "/profile");
    fm10k_fan_curve before = {0}, target;
    if (!nl_fm10k_profile_known(profile) || l2_fm10k_read_fan(candidate, &target) ||
        (old && l2_fm10k_read_fan(active, &before)))
        return invalid(err, err_size, "invalid FM10840 fan configuration");
    bool changed = !old || !nl_fm10k_fan_equal(&before, &target);
    if (require_hw) {
        nl_fm10k_config_snapshot live;
        if (l2_fm10k_read_hardware(&live, err, err_size)) return -1;
        if (!live.fan.valid)
            return invalid(err, err_size, "FM10840 fan state is unreadable, inconsistent, or in a manual test");
        /* An equal configd tree still needs replay when the SDK owner has
         * restarted into its verified full-speed startup baseline. */
        changed = changed || !live.fan.curve_valid || !nl_fm10k_fan_equal(&live.fan.curve, &target);
    }
    if (!changed) return 0;
    if (l2_plan_appendf(plan, size, offset,
        "fm10k-fan-set idle=%d load=%d critical=%d idle-pwm=%d load-pwm=%d hysteresis=%d response-ms=%d\n",
        target.idle_c, target.load_c, target.critical_c, target.idle_pwm, target.load_pwm,
        target.hysteresis_c, target.response_milliseconds)) return -1;
    *has_l2 = true;
    return 0;
}

static bool foreign_reference(const struct lyd_node *nodes, const char *ifname) {
    const struct lyd_node *node;
    LY_LIST_FOR(nodes, node) {
        if ((node->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) &&
            (!strcmp(LYD_NAME(node), "name") || !strcmp(LYD_NAME(node), "interface")) &&
            !strcmp(lyd_get_value(node), ifname)) {
            const struct lyd_node *parent = lyd_parent(node);
            const struct lyd_node *grandparent = parent ? lyd_parent(parent) : NULL;
            if (!parent || !grandparent || strcmp(LYD_NAME(node), "name") ||
                strcmp(LYD_NAME(parent), "interface") || strcmp(LYD_NAME(grandparent), "interfaces"))
                return true;
            /* QoS also uses interfaces/interface/name. Only the root-level
             * physical interface declaration is an allowed inactive-slot name. */
            const struct lyd_node *root = lyd_parent(grandparent);
            if (!root || strcmp(LYD_NAME(root), "netlab-config")) return true;
        }
        if (foreign_reference(lyd_child(node), ifname)) return true;
    }
    return false;
}
int l2_fm10k_read_groups(nl_yang_session *ys, fm10k_group out[FM10K_GROUP_COUNT],
                          char *err, size_t err_size) {
    const char *profile = nl_yang_get(ys, L2_FM10K_ROOT "/profile");
    if (!nl_fm10k_profile_known(profile) ||
        nl_yang_count(ys, L2_FM10K_ROOT "/port-group") != FM10K_GROUP_COUNT)
        return invalid(err, err_size, "FM10840 requires its complete fixed six-EPL configuration");
    struct lyd_node *tree = nl_yang_data_clone(ys);
    if (!tree) return invalid(err, err_size, "cannot inspect FM10840 port references");
    int rc = -1;
    for (int index = 0; index < FM10K_GROUP_COUNT; ++index) {
        fm10k_group *group = &out[index];
        char path[256];
        memset(group, 0, sizeof(*group));
        group->epl = index < 3 ? index : index + 2;
        snprintf(path, sizeof(path), L2_FM10K_ROOT "/port-group[epl='%d']/mode", group->epl);
        const char *mode = nl_yang_get(ys, path);
        if (!mode) goto done;
        group->mode = !strcmp(mode, "split") ? 0 : !strcmp(mode, "40g") ? 40 : !strcmp(mode, "100g") ? 100 : -1;
        for (int lane = 0; lane < 4; ++lane) {
            snprintf(path, sizeof(path), L2_FM10K_ROOT "/port-group[epl='%d']/lane[index='%d']/speed", group->epl, lane);
            const char *speed = nl_yang_get(ys, path);
            if (!speed || (strcmp(speed, "10") && strcmp(speed, "25"))) goto done;
            group->lane_gbps[lane] = atoi(speed);
            char name[32];
            snprintf(name, sizeof(name), "et-0/0/%d", index * 4 + lane);
            const char *disabled = l2_get_interface_leaf(ys, name, "disable");
            if (!disabled || (strcmp(disabled, "true") && strcmp(disabled, "false"))) goto done;
            if (!strcmp(disabled, "false")) group->enabled |= (uint8_t)(1U << lane);
            bool inactive = group->mode && lane;
            cfg_if_intent intent;
            l2_read_interface_intent(ys, name, &intent);
            const char *lag = l2_get_lag_member(ys, name);
            if (inactive && (!intent.disabled || intent.has_l2 || intent.has_speed ||
                (lag && *lag) || foreign_reference(tree, name))) {
                snprintf(err, err_size, "inactive slot %s still has configuration references", name);
                goto cleanup;
            }
            if (!inactive && !intent.disabled && !intent.has_l2 && !(lag && *lag)) {
                snprintf(err, err_size, "enabled slot %s requires a VLAN or LAG", name);
                goto cleanup;
            }
            if (!group->mode && (!intent.has_speed || intent.speed_mbps != group->lane_gbps[lane] * 1000)) {
                snprintf(err, err_size, "slot %s speed disagrees with its EPL lane", name);
                goto cleanup;
            }
            if (group->mode && intent.has_speed) goto done;
            static const char *const rates[] = {"broadcast-kbps", "multicast-kbps", "unknown-unicast-kbps"};
            for (int r = 0; inactive && r < 3; ++r) {
                char leaf[80];
                snprintf(leaf, sizeof(leaf), "fm10k-port/%s", rates[r]);
                const char *value = l2_get_interface_leaf(ys, name, leaf);
                if (value && strcmp(value, "0")) goto done;
            }
        }
        if (!nl_fm10k_group_valid(group)) goto done;
    }
    rc = 0;
    goto cleanup;
done:
    invalid(err, err_size, "invalid or incomplete FM10840 group/slot configuration");
cleanup:
    lyd_free_all(tree);
    return rc;
}
bool l2_fm10k_port_active(const l2_fm10k_groups *groups, int port) {
    if (!groups->managed || port < 1 || port > 24) return true;
    return !groups->target[(port - 1) / 4].mode || (port - 1) % 4 == 0;
}
bool l2_fm10k_port_changed(const l2_fm10k_groups *groups, int port) {
    return groups->managed && port >= 1 && port <= 24 &&
        (groups->changed_mask & (1U << ((port - 1) / 4)));
}
int l2_fm10k_groups_prepare(nl_yang_session *active, nl_yang_session *candidate,
                             bool require_hw, l2_fm10k_groups *out, char *err, size_t err_size) {
    memset(out, 0, sizeof(*out));
    bool old = nl_yang_exists(active, L2_FM10K_ROOT);
    if (!nl_yang_exists(candidate, L2_FM10K_ROOT))
        return old ? invalid(err, err_size, "FM10840 board configuration cannot be removed") : 0;
    out->managed = true;
    const char *old_profile = nl_yang_get(active, L2_FM10K_ROOT "/profile");
    const char *new_profile = nl_yang_get(candidate, L2_FM10K_ROOT "/profile");
    if (old && (!old_profile || !new_profile || strcmp(old_profile, new_profile)))
        return invalid(err, err_size, "FM10840 board profile cannot change in an online transaction");
    if (l2_fm10k_read_groups(candidate, out->target, err, err_size)) return -1;
    if (old) {
        if (l2_fm10k_read_groups(active, out->before, err, err_size)) return -1;
    } else {
        memcpy(out->before, out->target, sizeof(out->before));
        for (int i = 0; i < FM10K_GROUP_COUNT; ++i) out->before[i].enabled = 0;
    }
    fm10k_group configured[FM10K_GROUP_COUNT];
    memcpy(configured, out->before, sizeof(configured));
    if (require_hw) {
        nl_fm10k_config_snapshot live;
        if (l2_fm10k_read_hardware(&live, err, err_size)) return -1;
        if (live.group_valid_mask != (1U << FM10K_GROUP_COUNT) - 1)
            return invalid(err, err_size, "FM10840 group readback is incomplete or inconsistent");
        for (int i = 0; i < FM10K_GROUP_COUNT; ++i)
            if (!nl_fm10k_group_valid(&live.groups[i]) || live.groups[i].epl != out->target[i].epl)
                return invalid(err, err_size, "FM10840 readback has an invalid group identity");
        memcpy(out->before, live.groups, sizeof(out->before));
    }
    for (int i = 0; i < FM10K_GROUP_COUNT; ++i) {
        if (nl_fm10k_group_modes_equal(&out->before[i], &out->target[i]) &&
            nl_fm10k_group_modes_equal(&configured[i], &out->target[i])) continue;
        out->changed_mask |= 1U << i;
        for (int lane = 0; lane < 4; ++lane) {
            char name[32];
            snprintf(name, sizeof(name), "et-0/0/%d", i * 4 + lane);
            const char *previous = l2_get_lag_member(active, name);
            const char *next = l2_get_lag_member(candidate, name);
            if (previous && *previous && next && *next)
                return invalid(err, err_size, "remove affected EPL members from LAG before changing its mode/speeds");
        }
    }
    return 0;
}
int l2_fm10k_groups_emit(const l2_fm10k_groups *groups, int phase,
                           char *plan, size_t size, int *offset, bool *has_l2) {
    if (phase < 0 || phase > 2) return -1;
    for (int i = 0; i < FM10K_GROUP_COUNT; ++i) {
        if (!(groups->changed_mask & (1U << i))) continue;
        fm10k_group g = phase == 0 ? groups->before[i] : groups->target[i];
        if (phase < 2) g.enabled = 0;
        if (l2_plan_appendf(plan, size, offset,
            "fm10k-group-set epl=%d mode=%d lane0=%d lane1=%d lane2=%d lane3=%d enabled=%u\n",
            g.epl, g.mode, g.lane_gbps[0], g.lane_gbps[1], g.lane_gbps[2], g.lane_gbps[3], g.enabled)) return -1;
        *has_l2 = true;
    }
    return 0;
}

typedef struct { nl_yang_session *active, *candidate; } scope_config;
static int resolve_config_scope(void *context, nl_fm10k_scope_target kind, int id, u32 *mask) {
    const scope_config *config = context;
    nl_yang_session *trees[] = {config->active, config->candidate};
    *mask = 0;
    if ((kind == NL_FM10K_SCOPE_AE && (id < 0 || id >= 64)) ||
        (kind == NL_FM10K_SCOPE_VLAN && (id < 1 || id > 4094))) return NL_ERR_INVALID_VALUE;
    for (unsigned t = 0; t < 2; ++t) for (int port = 1; port <= 24; ++port) {
        char name[32], effective[32];
        snprintf(name, sizeof(name), "et-0/0/%d", port - 1);
        const char *lag = l2_get_lag_member(trees[t], name);
        if (kind == NL_FM10K_SCOPE_AE) {
            if (lag && l2_ae_id(lag) == id) *mask |= 1U << (port - 1);
        } else {
            snprintf(effective, sizeof(effective), "%s", lag && *lag ? lag : name);
            cfg_if_intent intent;
            l2_read_interface_intent(trees[t], effective, &intent);
            for (int v = 0; v < intent.n_members; ++v)
                if (intent.member_vids[v] == id) *mask |= 1U << (port - 1);
        }
    }
    return 0;
}
int l2_fm10k_scope_plan(nl_yang_session *active, nl_yang_session *candidate,
                         char *text, size_t size, int *length, char *err, size_t err_size) {
    if (!length || !text || *length < 0 || (size_t)*length >= size) return -1;
    if (!*length || !nl_yang_exists(candidate, L2_FM10K_ROOT)) return 0;
    l2_apply_plan plan;
    l2_apply_plan_init(&plan);
    u32 mask = 0;
    scope_config config = {active, candidate};
    int rc = l2_plan_parse(text, &plan) > 0 ?
        nl_fm10k_plan_port_mask(&plan, resolve_config_scope, &config, &mask) : -1;
    l2_apply_plan_reset(&plan);
    if (rc) return invalid(err, err_size, "cannot derive complete FM10840 protocol scope");
    char header[64];
    int n = snprintf(header, sizeof(header), NL_FM10K_SCOPE_HEADER "%06x\n", mask);
    if (n < 0 || n >= (int)sizeof(header) || (size_t)*length + (size_t)n + 1 > size)
        return invalid(err, err_size, "FM10840 plan scope exceeds plan capacity");
    memmove(text + n, text, (size_t)*length + 1);
    memcpy(text, header, (size_t)n);
    *length += n;
    return 0;
}
