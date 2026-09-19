/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/hal.h"
#include "netlab/hal_transaction_snapshot.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include <fm_sdk.h>
#include <api/fm_api_init.h>
#include <api/fm_api_portset.h>
#include <api/fm_api_storm.h>
#include <limits.h>
#include <math.h>
#include <string.h>

#define NETLAB_STORM_DEFAULT_BURST_BYTES 65536
#define NETLAB_STORM_MAX_CONDITIONS 16
#define NETLAB_STORM_MAX_ACTIONS 8

/* SDK-owner-only records. Failed allocation/deletion retains its handles
 * until cleanup is proven. Rollback retries the same resources; the records
 * belong to the current SDK lifecycle. */
typedef struct {
    bool used;
    int sw, port;
    nl_storm_kind kind;
    int controller;
    int portsets[NETLAB_STORM_MAX_CONDITIONS + NETLAB_STORM_MAX_ACTIONS];
    int n_portsets;
} storm_cleanup;
static storm_cleanup pending[FM_MAX_NUM_STORM_CTRL];

static hal_storm_rate_transaction_snapshot read_error(fm_status status) {
    hal_storm_rate_transaction_snapshot out = {0};
    out.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    out.sdk_status = status == FM_OK ? FM_FAIL : (int)status;
    return out;
}

static fm_status controllers_read(int sw, fm_int *ids, fm_int *count) {
    *count = FM_MAX_NUM_STORM_CTRL;
    fm_status st = fmGetStormCtrlList(sw, count, ids, FM_MAX_NUM_STORM_CTRL);
    if (st != FM_OK) return st;
    if (*count < 0 || *count > FM_MAX_NUM_STORM_CTRL) return FM_ERR_BAD_BUFFER;
    for (int i = 0; i < *count; ++i) {
        if (ids[i] < 0) return FM_ERR_INVALID_STORM_CTRL;
        for (int j = 0; j < i; ++j)
            if (ids[i] == ids[j]) return FM_ERR_MODIFIED_WHILE_ITERATING;
    }
    return FM_OK;
}

static fm_status portset_read(int sw, int set, int *ports, int *count) {
    fm_int current = -1;
    *count = 0;
    if (set <= 0) return FM_ERR_INVALID_PORT_SET;
    fm_status st = fmGetPortSetPortFirst(sw, set, &current);
    while (st == FM_OK) {
        if (current <= 0 || *count >= NL_MAX_PORTS_PER_PROFILE)
            return FM_ERR_MODIFIED_WHILE_ITERATING;
        for (int i = 0; i < *count; ++i)
            if (ports[i] == current) return FM_ERR_MODIFIED_WHILE_ITERATING;
        ports[(*count)++] = current;
        fm_int next = -1;
        st = fmGetPortSetPortNext(sw, set, current, &next);
        current = next;
    }
    return st == FM_ERR_NO_PORT_SET_PORT ? FM_OK : st;
}

static fm_status conditions_read(int sw, int id, fm_stormCondition *conditions,
                                  fm_int *count) {
    *count = NETLAB_STORM_MAX_CONDITIONS;
    fm_status st = fmGetStormCtrlConditionList(sw, id, count, conditions,
                                               NETLAB_STORM_MAX_CONDITIONS);
    if (st != FM_OK) return st;
    if (*count < 0 || *count > NETLAB_STORM_MAX_CONDITIONS) return FM_ERR_BAD_BUFFER;
    return FM_OK;
}

/* FM10000 matches frame class AND handler action. FLOOD_UCAST is an older
 * chip condition: unknown unicast here uses UNICAST + FLOOD, without
 * FIDFORWARD. The whole signature separates it from ingress rate. */
static nl_storm_kind classify(const fm_stormCondition *conditions, int count) {
    unsigned classes = 0, handlers = 0;
    int ingress = 0;
    for (int i = 0; i < count; ++i) {
        unsigned bit = 0;
        switch (conditions[i].type) {
        case FM_STORM_COND_BROADCAST: bit = 1; break;
        case FM_STORM_COND_MULTICAST: bit = 2; break;
        case FM_STORM_COND_UNICAST: bit = 4; break;
        case FM_STORM_COND_FLOOD: handlers |= 1; break;
        case FM_STORM_COND_FIDFORWARD: handlers |= 2; break;
        case FM_STORM_COND_INGRESS_PORTSET: ++ingress; break;
        default: return NL_STORM_INVALID;
        }
        if (bit && (classes & bit)) return NL_STORM_INVALID;
        classes |= bit;
    }
    if (ingress != 1) return NL_STORM_INVALID;
    if (classes == 4 && handlers == 1) return NL_STORM_UNKNOWN_UNICAST;
    if (classes == 1 && handlers == 3) return NL_STORM_BROADCAST;
    if (classes == 2 && handlers == 3) return NL_STORM_MULTICAST;
    /* Preserve the reference combined-policy snapshot format. */
    if (classes == 3 && (handlers & 1)) return NL_STORM_COMBINED;
    if (classes == 7 && (handlers & 1)) return NL_STORM_INGRESS;
    return NL_STORM_INVALID;
}

static bool is_typed(nl_storm_kind kind) {
    return kind >= NL_STORM_BROADCAST && kind <= NL_STORM_UNKNOWN_UNICAST;
}

static fm_status typed_action_check(int sw, int controller) {
    fm_stormAction actions[NETLAB_STORM_MAX_ACTIONS];
    fm_int count = NETLAB_STORM_MAX_ACTIONS;
    fm_status st = fmGetStormCtrlActionList(sw, controller, &count, actions,
                                            NETLAB_STORM_MAX_ACTIONS);
    if (st != FM_OK) return st;
    if (count != 1 || actions[0].type != FM_STORM_ACTION_FILTER_PORTSET)
        return FM_ERR_INVALID_ARGUMENT;
    int ports[NL_MAX_PORTS_PER_PROFILE], n_ports;
    st = portset_read(sw, (int)actions[0].param, ports, &n_ports);
    if (st != FM_OK) return st;
    nl_port_entry all[NL_MAX_PORTS_PER_PROFILE];
    int n_all = nl_ifid_get_all(all, NL_MAX_PORTS_PER_PROFILE), wanted = 0;
    if (n_all <= 0 || n_all > NL_MAX_PORTS_PER_PROFILE) return FM_FAIL;
    for (int i = 0; i < n_all; ++i) {
        if (!nl_ifid_is_user_port(all[i].logical_port)) continue;
        ++wanted;
        bool found = false;
        for (int j = 0; j < n_ports; ++j) found |= ports[j] == all[i].logical_port;
        if (!found) return FM_FAIL;
    }
    return wanted && n_ports == wanted ? FM_OK : FM_FAIL;
}

static hal_storm_rate_transaction_snapshot controller_snapshot(int sw, int port,
                                                                nl_storm_kind kind) {
    if (!nl_ifid_is_user_port(port) || kind < NL_STORM_COMBINED || kind > NL_STORM_INGRESS)
        return read_error(FM_ERR_INVALID_ARGUMENT);
    for (int i = 0; i < FM_MAX_NUM_STORM_CTRL; ++i)
        if (pending[i].used && pending[i].sw == sw && pending[i].port == port && pending[i].kind == kind)
            return read_error(FM_FAIL);
    fm_int ids[FM_MAX_NUM_STORM_CTRL], count;
    fm_status st = controllers_read(sw, ids, &count);
    if (st != FM_OK) return read_error(st);
    hal_storm_rate_transaction_snapshot out = {.state = HAL_TRANSACTION_SNAPSHOT_ABSENT};
    for (int i = 0; i < count; ++i) {
        fm_stormCondition conditions[NETLAB_STORM_MAX_CONDITIONS];
        fm_int n;
        st = conditions_read(sw, ids[i], conditions, &n);
        if (st != FM_OK) return read_error(st);
        nl_storm_kind observed = classify(conditions, n);
        if (observed != kind) {
            /* A malformed traffic policy on this port is unknown, not absent.
             * Do not create a second policy or delete an unidentified one. */
            if (observed == NL_STORM_INVALID) {
                bool traffic = false;
                for (int j = 0; j < n; ++j)
                    traffic |= conditions[j].type == FM_STORM_COND_BROADCAST ||
                               conditions[j].type == FM_STORM_COND_MULTICAST ||
                               conditions[j].type == FM_STORM_COND_UNICAST;
                for (int j = 0; traffic && j < n; ++j) {
                    if (conditions[j].type != FM_STORM_COND_INGRESS_PORTSET) continue;
                    int ports[NL_MAX_PORTS_PER_PROFILE], n_ports;
                    st = portset_read(sw, (int)conditions[j].param, ports, &n_ports);
                    if (st != FM_OK) return read_error(st);
                    for (int p = 0; p < n_ports; ++p)
                        if (ports[p] == port) return read_error(FM_ERR_INVALID_STORM_COND);
                }
            }
            continue;
        }
        bool found = false;
        for (int j = 0; j < n; ++j) {
            if (conditions[j].type != FM_STORM_COND_INGRESS_PORTSET) continue;
            int ports[NL_MAX_PORTS_PER_PROFILE], n_ports;
            st = portset_read(sw, (int)conditions[j].param, ports, &n_ports);
            if (st != FM_OK) return read_error(st);
            for (int p = 0; p < n_ports; ++p) found |= ports[p] == port;
            /* Updating a per-port policy must never change a shared bucket. */
            if (found && n_ports != 1) return read_error(FM_ERR_INVALID_ARGUMENT);
        }
        if (!found) continue;
        if (out.state == HAL_TRANSACTION_SNAPSHOT_PRESENT) return read_error(FM_ERR_ALREADY_EXISTS);
        if (is_typed(kind) && (st = typed_action_check(sw, ids[i])) != FM_OK) return read_error(st);
        out.controller = ids[i];
        st = fmGetStormCtrlAttribute(sw, ids[i], FM_STORM_RATE, &out.rate_kbps);
        if (st != FM_OK) return read_error(st);
        st = fmGetStormCtrlAttribute(sw, ids[i], FM_STORM_CAPACITY, &out.capacity_bytes);
        if (st != FM_OK) return read_error(st);
        if (out.rate_kbps > INT_MAX || out.capacity_bytes > INT_MAX) return read_error(FM_ERR_INVALID_VALUE);
        out.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    }
    return out;
}

hal_storm_rate_transaction_snapshot
hal_storm_control_transaction_snapshot_kind(int sw, int port, nl_storm_kind kind) {
    if (kind < NL_STORM_COMBINED || kind > NL_STORM_UNKNOWN_UNICAST)
        return read_error(FM_ERR_INVALID_ARGUMENT);
    return controller_snapshot(sw, port, kind);
}
hal_storm_rate_transaction_snapshot hal_storm_control_transaction_snapshot(int sw, int port) {
    return controller_snapshot(sw, port, NL_STORM_COMBINED);
}
hal_storm_rate_transaction_snapshot hal_ingress_rate_limit_transaction_snapshot(int sw, int port) {
    return controller_snapshot(sw, port, NL_STORM_INGRESS);
}

static storm_cleanup *cleanup_reserve(int sw, int port, nl_storm_kind kind) {
    for (int i = 0; i < FM_MAX_NUM_STORM_CTRL; ++i) {
        if (pending[i].used) continue;
        pending[i] = (storm_cleanup){.used = true, .sw = sw, .port = port,
                                     .kind = kind, .controller = -1};
        return &pending[i];
    }
    return NULL;
}

static int cleanup_run(storm_cleanup *record) {
    if (record->controller >= 0) {
        (void)fmDeleteStormCtrl(record->sw, record->controller);
        fm_int ids[FM_MAX_NUM_STORM_CTRL], count;
        if (controllers_read(record->sw, ids, &count) != FM_OK) return -1;
        for (int i = 0; i < count; ++i)
            if (ids[i] == record->controller) return -1;
        record->controller = -1;
    }
    for (int i = 0; i < record->n_portsets; ++i) {
        int set = record->portsets[i];
        if (set <= 0) continue;
        (void)fmDeletePortSet(record->sw, set);
        fm_int first = -1;
        if (fmGetPortSetPortFirst(record->sw, set, &first) != FM_ERR_INVALID_PORT_SET) return -1;
        record->portsets[i] = 0;
    }
    memset(record, 0, sizeof(*record));
    return 0;
}

static int cleanup_retry(int sw, int port, nl_storm_kind kind) {
    for (int i = 0; i < FM_MAX_NUM_STORM_CTRL; ++i)
        if (pending[i].used && pending[i].sw == sw && pending[i].port == port && pending[i].kind == kind &&
            cleanup_run(&pending[i])) return -1;
    return 0;
}

static int delete_controller(int sw, int port, nl_storm_kind kind) {
    if (cleanup_retry(sw, port, kind)) return -1;
    hal_storm_rate_transaction_snapshot before = controller_snapshot(sw, port, kind);
    if (before.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR) return -1;
    if (before.state == HAL_TRANSACTION_SNAPSHOT_ABSENT) return 0;
    fm_stormCondition conditions[NETLAB_STORM_MAX_CONDITIONS];
    fm_stormAction actions[NETLAB_STORM_MAX_ACTIONS];
    fm_int n, a = NETLAB_STORM_MAX_ACTIONS;
    if (conditions_read(sw, before.controller, conditions, &n) != FM_OK ||
        fmGetStormCtrlActionList(sw, before.controller, &a, actions, NETLAB_STORM_MAX_ACTIONS) != FM_OK ||
        a < 0 || a > NETLAB_STORM_MAX_ACTIONS) return -1;
    storm_cleanup *record = cleanup_reserve(sw, port, kind);
    if (!record) return -1;
    record->controller = before.controller;
    for (int i = 0; i < n; ++i)
        if (conditions[i].type == FM_STORM_COND_INGRESS_PORTSET)
            record->portsets[record->n_portsets++] = (int)conditions[i].param;
    for (int i = 0; i < a; ++i)
        if (actions[i].type == FM_STORM_ACTION_FILTER_PORTSET)
            record->portsets[record->n_portsets++] = (int)actions[i].param;
    if (cleanup_run(record)) return -1;
    return controller_snapshot(sw, port, kind).state == HAL_TRANSACTION_SNAPSHOT_ABSENT ? 0 : -1;
}

int hal_storm_control_delete_kind(int sw, int port, nl_storm_kind kind) {
    if (kind < NL_STORM_COMBINED || kind > NL_STORM_UNKNOWN_UNICAST) return -1;
    return delete_controller(sw, port, kind);
}
int hal_storm_control_delete(int sw, int port) { return delete_controller(sw, port, NL_STORM_COMBINED); }
int hal_ingress_rate_limit_delete(int sw, int port) { return delete_controller(sw, port, NL_STORM_INGRESS); }

/* Match the pinned SDK's 12-bit mantissa and handler-clock quantization.
 * Compute before writing: adopting an arbitrary readback would hide a write
 * that did not latch. Capacity uses the SDK's whole-KiB representation. */
static int effective_values(int sw, int rate, int burst, u32 *actual_rate, u32 *actual_burst) {
    fm_float mhz = 0;
    if (fmComputeFHClockFreq(sw, &mhz) != FM_OK || !isfinite(mhz) || mhz <= 0 || mhz > 2000)
        return -1;
    uint64_t quantum = (8ULL * (uint64_t)(mhz * 1e6)) / 256000ULL;
    if (!quantum) return -1;
    unsigned exponent = 3;
    uint64_t mantissa = (uint64_t)rate / quantum;
    while (mantissa >= 4096 && exponent) {
        --exponent;
        mantissa = (((uint64_t)rate / quantum) << (exponent + 2)) / 32;
    }
    if (mantissa >= 4096) mantissa = 4095;
    *actual_rate = (u32)(((mantissa * 32) >> (exponent + 2)) * quantum);
    *actual_burst = (u32)(burst / 1024) * 1024;
    return *actual_rate && *actual_burst && *actual_burst < 4194304 ? 0 : -1;
}

static int set_attributes(int sw, int controller, int rate, int burst, u32 expected_rate, u32 expected_burst) {
    fm_uint32 value = (fm_uint32)burst, read_rate = 0, read_burst = 0;
    fm_status st = fmSetStormCtrlAttribute(sw, controller, FM_STORM_CAPACITY, &value);
    if (st != FM_OK) return (int)st;
    value = (fm_uint32)rate;
    st = fmSetStormCtrlAttribute(sw, controller, FM_STORM_RATE, &value);
    if (st != FM_OK) return (int)st;
    if (fmGetStormCtrlAttribute(sw, controller, FM_STORM_RATE, &read_rate) != FM_OK ||
        fmGetStormCtrlAttribute(sw, controller, FM_STORM_CAPACITY, &read_burst) != FM_OK)
        return -1;
    return read_rate == expected_rate && read_burst == expected_burst ? 0 : -1;
}

static int set_controller(int sw, int port, nl_storm_kind kind, int rate, int burst) {
    /* Transaction restoration may pass a quantized rate just below 22000.
     * Public configuration enforces the advertised request minimum. */
    if (!nl_ifid_is_user_port(port) || kind < NL_STORM_COMBINED || kind > NL_STORM_INGRESS ||
        rate <= 0 || rate > 100000000) return -1;
    if (burst <= 0) burst = NETLAB_STORM_DEFAULT_BURST_BYTES;
    u32 expected_rate, expected_burst;
    if (effective_values(sw, rate, burst, &expected_rate, &expected_burst) || cleanup_retry(sw, port, kind))
        return -1;
    hal_storm_rate_transaction_snapshot before = controller_snapshot(sw, port, kind);
    if (before.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR) return -1;
    if (before.state == HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return set_attributes(sw, before.controller, rate, burst, expected_rate, expected_burst);

    storm_cleanup *record = cleanup_reserve(sw, port, kind);
    if (!record) return -1;
    fm_int controller = -1, ingress = -1, action_set = -1;
    fm_status st = fmCreateStormCtrl(sw, &controller);
    record->controller = controller;
    if (st != FM_OK || controller < 0) goto fail;
    st = fmCreatePortSet(sw, &ingress);
    if (ingress > 0) record->portsets[record->n_portsets++] = ingress;
    if (st != FM_OK || ingress <= 0) goto fail;
    st = fmAddPortSetPort(sw, ingress, port);
    if (st != FM_OK) goto fail;
    st = fmCreatePortSet(sw, &action_set);
    if (action_set > 0) record->portsets[record->n_portsets++] = action_set;
    if (st != FM_OK || action_set <= 0) goto fail;
    nl_port_entry ports[NL_MAX_PORTS_PER_PROFILE];
    int n = nl_ifid_get_all(ports, NL_MAX_PORTS_PER_PROFILE), added = 0;
    if (n <= 0 || n > NL_MAX_PORTS_PER_PROFILE) { st = FM_FAIL; goto fail; }
    for (int i = 0; i < n; ++i) {
        if (!nl_ifid_is_user_port(ports[i].logical_port)) continue;
        st = fmAddPortSetPort(sw, action_set, ports[i].logical_port);
        if (st != FM_OK) goto fail;
        ++added;
    }
    if (!added) { st = FM_FAIL; goto fail; }
    if (set_attributes(sw, controller, rate, burst, expected_rate, expected_burst)) { st = FM_FAIL; goto fail; }
    fm_stormCondition condition = {.type = FM_STORM_COND_INGRESS_PORTSET, .param = ingress};
    st = fmAddStormCtrlCondition(sw, controller, &condition);
    if (st != FM_OK) goto fail;
    const fm_stormCondType types[] = {FM_STORM_COND_BROADCAST, FM_STORM_COND_MULTICAST,
        FM_STORM_COND_UNICAST, FM_STORM_COND_FLOOD, FM_STORM_COND_FIDFORWARD};
    unsigned mask = kind == NL_STORM_BROADCAST ? 0x19 : kind == NL_STORM_MULTICAST ? 0x1a :
        kind == NL_STORM_UNKNOWN_UNICAST ? 0x0c : kind == NL_STORM_INGRESS ? 0x1f : 0x1b;
    condition.param = 0;
    for (int i = 0; i < 5; ++i) {
        if (!(mask & (1U << i))) continue;
        condition.type = types[i];
        st = fmAddStormCtrlCondition(sw, controller, &condition);
        if (st != FM_OK) goto fail;
    }
    fm_stormAction action = {.type = FM_STORM_ACTION_FILTER_PORTSET, .param = action_set};
    st = fmAddStormCtrlAction(sw, controller, &action);
    if (st != FM_OK) goto fail;
    /* Clear the pending marker only while checking the completed object. */
    record->used = false;
    hal_storm_rate_transaction_snapshot after = controller_snapshot(sw, port, kind);
    if (after.state != HAL_TRANSACTION_SNAPSHOT_PRESENT || after.rate_kbps != expected_rate ||
        after.capacity_bytes != expected_burst) { record->used = true; st = FM_FAIL; goto fail; }
    memset(record, 0, sizeof(*record));
    NL_LOG_INFO("storm %s port=%d controller=%d effective-rate=%uKbps", nl_storm_kind_name(kind), port, controller, expected_rate);
    return 0;
fail:
    if (cleanup_run(record)) NL_LOG_ERR("storm %s port=%d retains incomplete resource cleanup", nl_storm_kind_name(kind), port);
    return st == FM_OK ? -1 : (int)st;
}

int hal_storm_control_set_kind(int sw, int port, nl_storm_kind kind, int rate, int burst) {
    if (kind < NL_STORM_COMBINED || kind > NL_STORM_UNKNOWN_UNICAST) return -1;
    return set_controller(sw, port, kind, rate, burst);
}
int hal_storm_control_set(int sw, int port, int rate, int burst) {
    return set_controller(sw, port, NL_STORM_COMBINED, rate, burst);
}
int hal_ingress_rate_limit_set(int sw, int port, int rate, int burst) {
    return set_controller(sw, port, NL_STORM_INGRESS, rate, burst);
}

static int get_controller(int sw, int port, nl_storm_kind kind, hal_storm_control_entry *entry) {
    if (!entry) return -1;
    hal_storm_rate_transaction_snapshot snapshot = controller_snapshot(sw, port, kind);
    if (snapshot.state != HAL_TRANSACTION_SNAPSHOT_PRESENT) return -1;
    *entry = (hal_storm_control_entry){.port = port, .kind = kind, .controller = snapshot.controller,
        .rate_kbps = (int)snapshot.rate_kbps, .burst_bytes = (int)snapshot.capacity_bytes};
    return 0;
}
int hal_storm_control_get_kind(int sw, int port, nl_storm_kind kind, hal_storm_control_entry *entry) {
    if (kind < NL_STORM_COMBINED || kind > NL_STORM_UNKNOWN_UNICAST) return -1;
    return get_controller(sw, port, kind, entry);
}
int hal_storm_control_get(int sw, int port, hal_storm_control_entry *entry) {
    return get_controller(sw, port, NL_STORM_COMBINED, entry);
}
int hal_ingress_rate_limit_get(int sw, int port, hal_storm_control_entry *entry) {
    return get_controller(sw, port, NL_STORM_INGRESS, entry);
}

static int list_controllers(int sw, hal_storm_control_entry *entries, int max, bool ingress) {
    if (!entries || max <= 0) return -1;
    for (int i = 0; i < FM_MAX_NUM_STORM_CTRL; ++i)
        if (pending[i].used && pending[i].sw == sw) return -1;
    fm_int ids[FM_MAX_NUM_STORM_CTRL], count;
    if (controllers_read(sw, ids, &count) != FM_OK) return -1;
    int result = 0;
    for (int i = 0; i < count; ++i) {
        fm_stormCondition conditions[NETLAB_STORM_MAX_CONDITIONS];
        fm_int n;
        if (conditions_read(sw, ids[i], conditions, &n) != FM_OK) return -1;
        nl_storm_kind kind = classify(conditions, n);
        if (kind == NL_STORM_INVALID || ((kind == NL_STORM_INGRESS) != ingress)) continue;
        for (int j = 0; j < n; ++j) {
            if (conditions[j].type != FM_STORM_COND_INGRESS_PORTSET) continue;
            int ports[NL_MAX_PORTS_PER_PROFILE], n_ports;
            if (portset_read(sw, (int)conditions[j].param, ports, &n_ports) != FM_OK || n_ports != 1 || result >= max)
                return -1;
            for (int k = 0; k < result; ++k)
                if (entries[k].port == ports[0] && entries[k].kind == kind) return -1;
            hal_storm_control_entry *entry = &entries[result];
            if (get_controller(sw, ports[0], kind, entry)) return -1;
            fm_uint64 packets = 0;
            if (fmGetStormCtrlAttribute(sw, ids[i], FM_STORM_COUNT, &packets) != FM_OK) return -1;
            entry->packets = packets;
            ++result;
        }
    }
    return result;
}
int hal_storm_control_list(int sw, hal_storm_control_entry *entries, int max) {
    return list_controllers(sw, entries, max, false);
}
int hal_ingress_rate_limit_list(int sw, hal_storm_control_entry *entries, int max) {
    return list_controllers(sw, entries, max, true);
}
