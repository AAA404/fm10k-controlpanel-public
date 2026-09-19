#include "fm10k_board_runtime.h"
#include "fm10k_board_sdk.h"
#include "fm10k_startup.h"
#include "fm10k_basic100g.h"
#include "fm10k_monitor.h"
#include "netlab/interface_id.h"
#include "netlab/hal_fm10k.h"
#include "netlab/error.h"
#include "netlab/port_scope.h"
#include "netlab/log.h"
#include "hal_port_xcvr_sdk_adapter.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fm_sdk_int.h>

static fm10k_sdk_bus g_bus;
static fm10k_monitor g_monitor, g_snapshot;
static pthread_mutex_t g_snapshot_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint_fast64_t g_native_generation;
static atomic_uint_fast64_t g_native_commit;
static atomic_bool g_native_bound;

bool fm10k_native_profile(void) {
    nl_platform_identity identity;
    nl_board_profile board;
    return (nl_platform_identity_get(&identity) &&
            nl_fm10k_profile_known(identity.chassis_name)) ||
           (nl_platform_board_get(&board) && strcmp(board.asic, "FM10840") == 0);
}
bool fm10k_native_bound(void) {
    return atomic_load(&g_native_bound) && atomic_load(&g_native_generation) != 0;
}
bool fm10k_native_ready(void) { return atomic_load(&g_native_generation) != 0; }
uint64_t fm10k_native_generation(void) { return atomic_load(&g_native_generation); }
bool fm10k_native_aux_port(int sw, int port) {
    if (sw != 0 || (port != 28 && port != 29) || !fm10k_native_profile() ||
        !fmRootPlatform || fmRootPlatform->cfg.numSwitches != 1 || !fmRootPlatform->cfg.switches ||
        fmRootPlatform->cfg.switches[sw].numPorts <= port || !fmRootPlatform->cfg.switches[sw].ports) return false;
    const fm_platformCfgPort *p = &fmRootPlatform->cfg.switches[sw].ports[port];
    return p->port == port && p->portIdx == port &&
        p->portType == FM_PLAT_PORT_TYPE_TUNNEL && p->tunnel == port - 28;
}
int fm10k_native_mark_ready(void) {
    struct timespec clock;
    if (!fm10k_startup_control() || !g_bus.attached ||
        !pthread_equal(g_bus.owner, pthread_self()) || !g_monitor.fan.curve_valid ||
        clock_gettime(CLOCK_MONOTONIC, &clock) || fm10k_native_ready()) return FM10K_INVALID;
    uint64_t generation = ((uint64_t)clock.tv_sec * 1000000000ULL + (uint64_t)clock.tv_nsec) ^
                          ((uint64_t)(unsigned)getpid() << 32);
    if (!generation) return FM10K_IO;
    atomic_store(&g_native_bound, false);
    atomic_store(&g_native_commit, 0);
    atomic_store(&g_native_generation, generation);
    return FM10K_OK;
}
int fm10k_native_bind(uint64_t generation, uint64_t tx) {
    nl_port_scope_status scope = nl_port_scope_get();
    if (!fm10k_startup_control() || !generation || !tx ||
        generation != atomic_load(&g_native_generation) || !nl_port_scope_ready() ||
        scope.tx_id || scope.mask || scope.degraded) return NL_ERR_HW_STATE_OUT_OF_SYNC;
    atomic_store(&g_native_commit, tx);
    atomic_store(&g_native_bound, true);
    return 0;
}
int fm10k_native_bootstrap_closed(int sw) {
    static bool attempted;
    if (attempted || !fm10k_startup_validated() || !fm10k_native_profile()) return FM10K_INVALID;
    attempted = true;
    /* First sampling attaches to the SDK owner and establishes full PWM. */
    int sample = fm10k_native_poll(sw);
    int closed = netlab_fm10k_bootstrap_closed(sw);
    if (sample || closed) return FM10K_IO;
    for (int mpo = 1; mpo <= 2; ++mpo) {
        fm10k_obt_setup_report setup;
        int rc = fm10k_obt_setup(&g_bus.bus, mpo, &setup);
        if (rc) {
            NL_LOG_ERR("OBT%d setup failed: status=%d address=0x%x register=%d restored=%d; ports remain closed",
                       mpo, rc, setup.failed_address, setup.failed_register, setup.restored);
            return rc;
        }
        NL_LOG_NOTICE("OBT%d mux=0x%02x setup verified: changed=%u TX-CDR=%u->%u RX-CDR=%u->%u RX-enable=0x%03x->0x%03x TX=0x000",
            mpo, mpo, setup.changed, setup.before[6], setup.after[6],
            setup.before[19], setup.after[19],
            ((setup.before[20] & 15) << 8) | setup.before[21],
            ((setup.after[20] & 15) << 8) | setup.after[21]);
    }
    const fm10k_fan_curve initial = {35, 70, 80, 50, 80, 4, 10900};
    int curve = fm10k_native_curve(&initial);
    return curve || !fm10k_startup_basic100g() ? curve : fm10k_basic100g_start(sw);
}
static int clocks(uint64_t *mono, double *wall) {
    struct timespec m, w;
    if (clock_gettime(CLOCK_MONOTONIC, &m) || clock_gettime(CLOCK_REALTIME, &w))
        return FM10K_IO;
    *mono = (uint64_t)m.tv_sec * 1000 + (uint64_t)m.tv_nsec / 1000000;
    *wall = (double)w.tv_sec + w.tv_nsec / 1000000000.0;
    return FM10K_OK;
}
static bool on_owner(void) {
    return g_bus.attached && pthread_equal(g_bus.owner, pthread_self());
}
static void publish(void) {
    pthread_mutex_lock(&g_snapshot_lock);
    g_snapshot = g_monitor;
    g_snapshot.bus = NULL;
    pthread_mutex_unlock(&g_snapshot_lock);
}
int fm10k_native_poll(int sw) {
    if (!fm10k_native_profile()) return FM10K_INVALID;
    if (!g_bus.attached) {
        nl_platform_identity identity;
        if (!nl_platform_identity_get(&identity) || !nl_fm10k_profile_known(identity.chassis_name))
            return FM10K_INVALID;
        int rc = fm10k_sdk_bus_attach(&g_bus, sw);
        if (rc) return rc;
        fm10k_monitor_init(&g_monitor, &g_bus.bus);
        snprintf(g_monitor.profile, sizeof(g_monitor.profile), "%.*s",
                 (int)sizeof(g_monitor.profile) - 1, identity.chassis_name);
        rc = fm10k_fan_bootstrap(&g_bus.bus);
        if (rc) {
            g_monitor.fan.failsafe = true;
            ++g_monitor.io_errors;
            publish();
            return rc;
        }
    }
    if (!on_owner() || g_bus.sw != sw) return FM10K_INVALID;
    uint64_t now;
    double wall;
    if (clocks(&now, &wall)) return FM10K_IO;
    int rc = fm10k_monitor_step(&g_monitor, now, wall);
    publish();
    return rc;
}
int fm10k_native_curve(const fm10k_fan_curve *curve) {
    if (!on_owner()) return FM10K_INVALID;
    fm10k_fan_snapshot before;
    if (hal_fm10k_fan_capture(g_bus.sw, &before)) return FM10K_IO;
    return hal_fm10k_fan_apply(g_bus.sw, curve, &before);
}
static int config_result(int rc) {
    return rc == FM10K_OK ? 0 : rc == FM10K_ROLLBACK_FAILED ? NL_ERR_ROLLBACK_FAILED :
        rc == FM10K_INVALID ? NL_ERR_INVALID_VALUE : NL_ERR_SDK_CALL_FAILED;
}
int hal_fm10k_fan_capture(int sw, fm10k_fan_snapshot *out) {
    if (!on_owner() || sw != g_bus.sw || !fm10k_native_profile()) return NL_ERR_PFE_DOWN;
    return config_result(fm10k_monitor_fan_capture(&g_monitor, out));
}
int hal_fm10k_fan_apply(int sw, const fm10k_fan_curve *curve, const fm10k_fan_snapshot *before) {
    uint64_t now;
    double wall;
    if (!on_owner() || sw != g_bus.sw || !fm10k_native_profile()) return NL_ERR_PFE_DOWN;
    if (clocks(&now, &wall)) return NL_ERR_SDK_CALL_FAILED;
    int rc = fm10k_monitor_fan_apply(&g_monitor, curve, before, now);
    publish();
    return config_result(rc);
}
int hal_fm10k_fan_restore(int sw, const fm10k_fan_snapshot *before) {
    uint64_t now;
    double wall;
    if (!on_owner() || sw != g_bus.sw || !fm10k_native_profile()) return NL_ERR_PFE_DOWN;
    if (clocks(&now, &wall)) return NL_ERR_SDK_CALL_FAILED;
    int rc = fm10k_monitor_fan_restore(&g_monitor, before, now);
    publish();
    return config_result(rc);
}
int hal_fm10k_fan_verify(int sw, const fm10k_fan_curve *curve) {
    fm10k_fan_snapshot actual;
    int rc = hal_fm10k_fan_capture(sw, &actual);
    return rc ? rc : actual.curve_valid && fm10k_fan_curve_equal(&actual.curve, curve) ? 0 :
        NL_ERR_READBACK_MISMATCH;
}
int fm10k_native_config_snapshot(int sw, nl_fm10k_config_snapshot *out) {
    if (!out || !on_owner() || sw != g_bus.sw || !fm10k_native_profile()) return FM10K_INVALID;
    memset(out, 0, sizeof(*out));
    out->schema = NL_FM10K_CONFIG_SCHEMA;
    out->bytes = sizeof(*out);
    for (int i = 0; i < FM10K_GROUP_COUNT; ++i) {
        int epl = i < 3 ? i : i + 2;
        if (!netlab_fm10k_group_sdk_get(sw, epl, &out->groups[i]))
            out->group_valid_mask |= 1U << i;
    }
    (void)hal_fm10k_fan_capture(sw, &out->fan);
    return FM10K_OK;
}
int fm10k_native_manual(int pwm, int seconds, double *expires_at) {
    uint64_t now;
    double wall;
    if (!fm10k_native_bound() || !on_owner() || !expires_at) return FM10K_INVALID;
    if (clocks(&now, &wall)) return FM10K_IO;
    int rc = fm10k_monitor_manual(&g_monitor, pwm, seconds, now);
    if (!rc) *expires_at = wall + seconds;
    publish();
    return rc;
}
int fm10k_native_shutdown(void) {
    atomic_store(&g_native_bound, false);
    atomic_store(&g_native_generation, 0);
    atomic_store(&g_native_commit, 0);
    if (!g_bus.attached) return FM10K_OK;
    if (!on_owner()) return FM10K_INVALID;
    int rc = fm10k_monitor_shutdown(&g_monitor);
    publish();
    int detach = fm10k_sdk_bus_detach(&g_bus);
    return rc ? rc : detach;
}
int fm10k_native_cache(char *out, size_t size) {
    fm10k_monitor copy;
    uint64_t now;
    double wall;
    if (clocks(&now, &wall)) return FM10K_IO;
    pthread_mutex_lock(&g_snapshot_lock);
    copy = g_snapshot;
    pthread_mutex_unlock(&g_snapshot_lock);
    copy.native_generation = atomic_load(&g_native_generation);
    copy.native_commit = atomic_load(&g_native_commit);
    copy.native_ready = copy.native_generation != 0;
    copy.native_bound = copy.native_ready && fm10k_native_bound();
    /* A pending snapshot must report its configured profile without touching
     * the SDK. This is inventory, not an independent identity/write binding. */
    if (!copy.profile[0]) {
        nl_platform_identity identity;
        if (nl_platform_identity_get(&identity) && nl_fm10k_profile_known(identity.chassis_name))
            snprintf(copy.profile, sizeof(copy.profile), "%.*s",
                     (int)sizeof(copy.profile) - 1, identity.chassis_name);
    }
    return fm10k_monitor_format(&copy, now, wall, out, size);
}

/* The RPC/configd coordinator holds the protocol lease across all L2 steps.
 * SDK callbacks inspect local state only; no daemon RPC runs on the owner. */
static int group_lease(void *context, int epl, bool paused) {
    (void)paused;
    uint64_t tx = *(const uint64_t *)context;
    int index = nl_fm10k_group_index(epl);
    nl_port_scope_status scope = nl_port_scope_get();
    uint32_t mask = index < 0 ? 0 : 15U << (4 * index);
    return tx && tx == scope.tx_id && mask && (scope.mask & mask) == mask && nl_port_scope_ready() ?
        FM10K_OK : FM10K_INVALID;
}
static void group_degraded(void *context, int epl) {
    (void)epl;
    nl_port_scope_degrade(*(const uint64_t *)context);
}
int hal_fm10k_group_capture(int sw, int epl, fm10k_group *out) {
    if (!on_owner() || sw != g_bus.sw || !fm10k_native_profile()) return NL_ERR_PFE_DOWN;
    return config_result(netlab_fm10k_group_sdk_get(sw, epl, out));
}
int hal_fm10k_group_apply(int sw, const fm10k_group *target, const fm10k_group *before, uint64_t tx) {
    if (!on_owner() || sw != g_bus.sw || !fm10k_native_profile()) return NL_ERR_PFE_DOWN;
    if (!target || group_lease(&tx, target->epl, true)) return NL_ERR_COMMIT_LOCKED;
    netlab_fm10k_group_control control = {&tx, group_lease, group_degraded};
    return config_result(netlab_fm10k_group_sdk_apply(sw, target, before, &control));
}
int hal_fm10k_group_restore(int sw, const fm10k_group *before, uint64_t tx) {
    fm10k_group actual;
    if (!before || hal_fm10k_group_capture(sw, before->epl, &actual)) return NL_ERR_PRE_STATE_MISSING;
    if (nl_fm10k_group_equal(before, &actual)) return 0;
    return hal_fm10k_group_apply(sw, before, &actual, tx);
}
int hal_fm10k_group_verify(int sw, const fm10k_group *target) {
    fm10k_group actual;
    int rc = target ? hal_fm10k_group_capture(sw, target->epl, &actual) : NL_ERR_INVALID_VALUE;
    return rc ? rc : nl_fm10k_group_equal(target, &actual) ? 0 : NL_ERR_READBACK_MISMATCH;
}
