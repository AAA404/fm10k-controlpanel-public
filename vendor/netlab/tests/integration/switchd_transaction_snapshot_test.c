/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef NETLAB_QOS_WATERMARK_PROVENANCE_PATH
#define NETLAB_QOS_WATERMARK_PROVENANCE_PATH \
    "/opt/netlab/build/qos-watermark-provenance-test.v1"
#endif

#include "../../sbin/switchd/hal_storm_control.c"
#include "../../sbin/switchd/hal_qos.c"
#include "../../sbin/switchd/hal_egress_rate_limit.c"
#include "watchdog_disabled_fixture.h"

#define TEST_PORT 7
#define TEST_STORM_CONTROLLER 3
#define TEST_INGRESS_CONTROLLER 4
#define TEST_PORTSET 11
#define TEST_SHAPING_GROUP 4
#define TEST_CARDINAL_PORT_2 8
#define TEST_CARDINAL_PORT_COUNT 2

typedef struct {
    fm_uint32 num_groups;
    fm_uint32 strict[HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS];
    fm_uint32 weight[HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS];
    fm_uint32 boundary_a[HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS];
    fm_uint32 boundary_b[HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS];
} scheduler_topology_simulator;

typedef struct {
    fm_int port;
    fm_uint32 rx_private_wm[HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    fm_uint32 rx_hog_wm[HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    fm_uint32 private_pause_on_wm[
        HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    fm_uint32 private_pause_off_wm[
        HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    fm_uint32 tx_private_wm[HAL_TRANSACTION_QOS_TRAFFIC_CLASSES];
    fm_uint32 tx_hog_wm[HAL_TRANSACTION_QOS_TRAFFIC_CLASSES];
    fm_uint32 tx_soft_drop_on_private[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    fm_uint32 tx_soft_drop_on_rxmp_free[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
} watermark_port_simulator;

typedef struct {
    fm_uint32 global_private_wm;
    fm_uint32 shared_pause_on_wm[
        HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    fm_uint32 shared_pause_off_wm[
        HAL_TRANSACTION_QOS_MEMORY_PARTITIONS];
    fm_uint32 shared_priority_wm[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    fm_uint32 shared_soft_drop_wm[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    fm_uint32 shared_soft_drop_hog_wm[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    fm_uint32 shared_soft_drop_jitter[
        HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    watermark_port_simulator ports[TEST_CARDINAL_PORT_COUNT];
} watermark_image_simulator;

typedef struct {
    fm_status controller_list_status;
    fm_int controllers[FM_MAX_NUM_STORM_CTRL];
    fm_int n_controllers;
    fm_status condition_status[FM_MAX_NUM_STORM_CTRL];
    fm_stormCondition
        conditions[FM_MAX_NUM_STORM_CTRL][NETLAB_STORM_MAX_CONDITIONS];
    fm_int n_conditions[FM_MAX_NUM_STORM_CTRL];
    fm_status portset_first_status;
    fm_status portset_next_status;
    fm_int portset_member;
    fm_status rate_status[FM_MAX_NUM_STORM_CTRL];
    fm_status capacity_status[FM_MAX_NUM_STORM_CTRL];
    fm_uint32 rates[FM_MAX_NUM_STORM_CTRL];
    fm_uint32 capacities[FM_MAX_NUM_STORM_CTRL];

    fm_status qos_get_status[4];
    fm_status qos_set_status[4];
    fm_uint32 qos_source;
    fm_bool qos_dscp_preference;
    fm_uint32 qos_default_priority;
    fm_uint32 qos_default_switch_priority;
    bool ignore_default_switch_priority_write;
    int qos_set_calls[4];

    scheduler_topology_simulator scheduler_active;
    scheduler_topology_simulator scheduler_staging;
    fm_int port_qos_get_fail_attr;
    fm_int port_qos_get_fail_index;
    fm_status port_qos_get_fail_status;
    fm_int port_qos_set_fail_attr;
    fm_int port_qos_set_fail_index;
    fm_status port_qos_set_fail_status;
    bool ignore_scheduler_apply;
    bool ignore_shaping_rate_write;
    bool ignore_shaping_burst_write;
    fm_uint64
        shaping_rate[HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS];
    fm_uint64
        shaping_burst[HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS];
    fm_uint32
        egress_tc_map[HAL_TRANSACTION_EGRESS_RATE_TC_COUNT];
    fm_uint32 scheduler_tc_enable;
    bool ignore_scheduler_tc_enable_write;
    int scheduler_tc_enable_set_calls;

    fm_bool auto_pause_mode;
    fm_int cardinal_ports[TEST_CARDINAL_PORT_COUNT];
    fm_int cardinal_port_count;
    fm_status cardinal_port_status;
    fm_uint32 priority_map[HAL_TRANSACTION_QOS_SWITCH_PRIORITIES];
    fm_uint32 pfc_rx_class_mask;
    fm_uint32 pfc_tx_class_mask;
    fm_uint32 pfc_tx_pause_mode;
    fm_uint32 pfc_lossless_smp_mask;
    fm_uint32 pfc_shared_pause_mask;
    fm_uint32 pfc_pc3_smp;
    watermark_image_simulator watermark;
    watermark_image_simulator calculated_watermark;
    fm_int watermark_port_get_fail_port;
    fm_int watermark_port_get_fail_attr;
    fm_int watermark_port_get_fail_index;
    fm_status watermark_port_get_fail_status;
    fm_int watermark_port_set_fail_port;
    fm_int watermark_port_set_fail_attr;
    fm_int watermark_port_set_fail_index;
    fm_status watermark_port_set_fail_status;
    fm_int watermark_switch_get_fail_attr;
    fm_int watermark_switch_get_fail_index;
    fm_status watermark_switch_get_fail_status;
    fm_int watermark_switch_set_fail_attr;
    fm_int watermark_switch_set_fail_index;
    fm_status watermark_switch_set_fail_status;
    fm_int watermark_ignore_port;
    fm_int watermark_ignore_port_attr;
    fm_int watermark_ignore_port_index;
    fm_int watermark_ignore_switch_attr;
    fm_int watermark_ignore_switch_index;
    int watermark_write_calls;
    int auto_pause_recalculate_calls;
} transaction_simulator;

static transaction_simulator g_sim;
static int g_failed;

enum {
    QOS_SOURCE = 0,
    QOS_DSCP_PREFERENCE,
    QOS_DEFAULT_PRIORITY,
    QOS_DEFAULT_SWITCH_PRIORITY,
};

static int controller_slot(fm_int controller) {
    for (int i = 0; i < g_sim.n_controllers; i++)
        if (g_sim.controllers[i] == controller)
            return i;
    return -1;
}

static int qos_attr_slot(fm_int attr) {
    switch (attr) {
    case FM_PORT_SWPRI_SOURCE:
        return QOS_SOURCE;
    case FM_PORT_SWPRI_DSCP_PREF:
        return QOS_DSCP_PREFERENCE;
    case FM_PORT_DEF_PRI:
        return QOS_DEFAULT_PRIORITY;
    case FM_PORT_DEF_SWPRI:
        return QOS_DEFAULT_SWITCH_PRIORITY;
    default:
        return -1;
    }
}

static watermark_port_simulator *watermark_port_find(
    watermark_image_simulator *image, fm_int port) {
    if (!image)
        return NULL;
    for (int i = 0; i < TEST_CARDINAL_PORT_COUNT; i++)
        if (image->ports[i].port == port)
            return &image->ports[i];
    return NULL;
}

static void seed_calculated_watermark(
    watermark_image_simulator *image) {
    memset(image, 0, sizeof(*image));
    image->global_private_wm = 192U * 100U;
    for (int smp = 0;
         smp < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS; smp++) {
        image->shared_pause_on_wm[smp] =
            192U * (fm_uint32)(110 + smp);
        image->shared_pause_off_wm[smp] =
            192U * (fm_uint32)(120 + smp);
    }
    for (int priority = 0;
         priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
        image->shared_priority_wm[priority] =
            192U * (fm_uint32)(200 + priority);
        image->shared_soft_drop_wm[priority] =
            192U * (fm_uint32)(300 + priority);
        image->shared_soft_drop_hog_wm[priority] =
            192U * (fm_uint32)(400 + priority);
        image->shared_soft_drop_jitter[priority] =
            (fm_uint32)(priority % 8);
    }
    for (int i = 0; i < TEST_CARDINAL_PORT_COUNT; i++) {
        watermark_port_simulator *port = &image->ports[i];
        int base = 500 + i * 200;

        port->port = i == 0 ? TEST_PORT : TEST_CARDINAL_PORT_2;
        for (int smp = 0;
             smp < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS; smp++) {
            port->rx_private_wm[smp] =
                192U * (fm_uint32)(base + smp);
            port->rx_hog_wm[smp] =
                192U * (fm_uint32)(base + 10 + smp);
            port->private_pause_on_wm[smp] =
                192U * (fm_uint32)(base + 20 + smp);
            port->private_pause_off_wm[smp] =
                192U * (fm_uint32)(base + 30 + smp);
        }
        for (int tc = 0;
             tc < HAL_TRANSACTION_QOS_TRAFFIC_CLASSES; tc++) {
            port->tx_private_wm[tc] =
                192U * (fm_uint32)(base + 40 + tc);
            port->tx_hog_wm[tc] =
                192U * (fm_uint32)(base + 60 + tc);
        }
        for (int priority = 0;
             priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
            port->tx_soft_drop_on_private[priority] =
                (fm_uint32)((priority + i) & 1);
            port->tx_soft_drop_on_rxmp_free[priority] =
                (fm_uint32)((priority + i + 1) & 1);
        }
    }
}

static void seed_application_watermark_overrides(
    watermark_image_simulator *image) {
    for (int priority = 0;
         priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
        image->shared_soft_drop_wm[priority] += 192U * 5U;
        image->shared_soft_drop_hog_wm[priority] += 192U * 7U;
        image->shared_soft_drop_jitter[priority] =
            (image->shared_soft_drop_jitter[priority] + 1U) % 8U;
    }
    for (int i = 0; i < TEST_CARDINAL_PORT_COUNT; i++) {
        watermark_port_simulator *port = &image->ports[i];

        for (int tc = 0;
             tc < HAL_TRANSACTION_QOS_TRAFFIC_CLASSES; tc++) {
            port->tx_private_wm[tc] += 192U * 11U;
            port->tx_hog_wm[tc] += 192U * 13U;
        }
        for (int priority = 0;
             priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++) {
            port->tx_soft_drop_on_private[priority] ^= 1U;
            port->tx_soft_drop_on_rxmp_free[priority] ^= 1U;
        }
    }
}

static void simulate_auto_pause_recalculation(void) {
    g_sim.watermark = g_sim.calculated_watermark;
    g_sim.auto_pause_recalculate_calls++;
}

static void add_condition(int slot, fm_stormCondType type, int param) {
    fm_int index = g_sim.n_conditions[slot]++;

    g_sim.conditions[slot][index].type = type;
    g_sim.conditions[slot][index].param = (fm_int)param;
}

static void reset_simulator(void) {
    memset(&g_sim, 0, sizeof(g_sim));
    memset(g_qos_watermark_config, 0, sizeof(g_qos_watermark_config));
    memset(&g_qos_watermark_owner, 0, sizeof(g_qos_watermark_owner));
    g_qos_watermark_provenance_loaded = false;
    g_qos_watermark_provenance_load_status = 0;
    (void)unlink(NETLAB_QOS_WATERMARK_PROVENANCE_PATH);
    g_sim.controller_list_status = FM_OK;
    g_sim.portset_first_status = FM_OK;
    g_sim.portset_next_status = FM_ERR_NO_PORT_SET_PORT;
    g_sim.portset_member = TEST_PORT;
    for (int i = 0; i < FM_MAX_NUM_STORM_CTRL; i++) {
        g_sim.condition_status[i] = FM_OK;
        g_sim.rate_status[i] = FM_OK;
        g_sim.capacity_status[i] = FM_OK;
    }
    for (int i = 0; i < 4; i++) {
        g_sim.qos_get_status[i] = FM_OK;
        g_sim.qos_set_status[i] = FM_OK;
    }
    g_sim.qos_source = FM_PORT_SWPRI_DSCP | FM_PORT_SWPRI_VPRI1 |
                       FM_PORT_SWPRI_ISL_TAG;
    g_sim.qos_dscp_preference = TRUE;
    g_sim.qos_default_priority = 3;
    g_sim.qos_default_switch_priority = 11;
    g_sim.port_qos_get_fail_attr = -1;
    g_sim.port_qos_get_fail_index = -1;
    g_sim.port_qos_get_fail_status = FM_OK;
    g_sim.port_qos_set_fail_attr = -1;
    g_sim.port_qos_set_fail_index = -1;
    g_sim.port_qos_set_fail_status = FM_OK;
    g_sim.scheduler_active.num_groups = 3;
    for (int group = 0;
         group < HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS;
         group++) {
        g_sim.scheduler_active.strict[group] =
            (fm_uint32)(group & 1);
        g_sim.scheduler_active.weight[group] =
            (fm_uint32)(1000 + group * 37);
        g_sim.scheduler_active.boundary_a[group] =
            (fm_uint32)group;
        g_sim.scheduler_active.boundary_b[group] =
            (fm_uint32)(group + 1);
        g_sim.shaping_rate[group] =
            FM_QOS_SHAPING_GROUP_RATE_DEFAULT;
        g_sim.shaping_burst[group] =
            NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS;
    }
    g_sim.scheduler_staging = g_sim.scheduler_active;
    g_sim.shaping_rate[NETLAB_EGRESS_RATE_LIMIT_SG] = 123456789ULL;
    g_sim.shaping_burst[NETLAB_EGRESS_RATE_LIMIT_SG] = 987654321ULL;
    for (int tc = 0; tc < HAL_TRANSACTION_EGRESS_RATE_TC_COUNT; tc++)
        g_sim.egress_tc_map[tc] = (fm_uint32)(tc % 3);
    g_sim.scheduler_tc_enable = 0x5aU;

    g_sim.auto_pause_mode = TRUE;
    g_sim.cardinal_ports[0] = TEST_CARDINAL_PORT_2;
    g_sim.cardinal_ports[1] = TEST_PORT;
    g_sim.cardinal_port_count = TEST_CARDINAL_PORT_COUNT;
    g_sim.cardinal_port_status = FM_OK;
    for (int priority = 0;
         priority < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES; priority++)
        g_sim.priority_map[priority] =
            (fm_uint32)(priority %
                        HAL_TRANSACTION_QOS_TRAFFIC_CLASSES);
    g_sim.pfc_tx_class_mask = 0xffU;
    g_sim.pfc_tx_pause_mode = FM_PORT_TX_PAUSE_NORMAL;
    seed_calculated_watermark(&g_sim.calculated_watermark);
    g_sim.watermark = g_sim.calculated_watermark;
    seed_application_watermark_overrides(&g_sim.watermark);
    g_sim.watermark_port_get_fail_port = -1;
    g_sim.watermark_port_get_fail_attr = -1;
    g_sim.watermark_port_get_fail_index = -1;
    g_sim.watermark_port_get_fail_status = FM_OK;
    g_sim.watermark_port_set_fail_port = -1;
    g_sim.watermark_port_set_fail_attr = -1;
    g_sim.watermark_port_set_fail_index = -1;
    g_sim.watermark_port_set_fail_status = FM_OK;
    g_sim.watermark_switch_get_fail_attr = -1;
    g_sim.watermark_switch_get_fail_index = -1;
    g_sim.watermark_switch_get_fail_status = FM_OK;
    g_sim.watermark_switch_set_fail_attr = -1;
    g_sim.watermark_switch_set_fail_index = -1;
    g_sim.watermark_switch_set_fail_status = FM_OK;
    g_sim.watermark_ignore_port = -1;
    g_sim.watermark_ignore_port_attr = -1;
    g_sim.watermark_ignore_port_index = -1;
    g_sim.watermark_ignore_switch_attr = -1;
    g_sim.watermark_ignore_switch_index = -1;
}

static void configure_storm_controller(int slot, int controller,
                                       bool ingress_rate_limit) {
    g_sim.controllers[slot] = controller;
    if (g_sim.n_controllers <= slot)
        g_sim.n_controllers = slot + 1;
    add_condition(slot, FM_STORM_COND_INGRESS_PORTSET, TEST_PORTSET);
    add_condition(slot, FM_STORM_COND_BROADCAST, 0);
    add_condition(slot, FM_STORM_COND_MULTICAST, 0);
    add_condition(slot, FM_STORM_COND_FLOOD, 0);
    if (ingress_rate_limit)
        add_condition(slot, FM_STORM_COND_UNICAST, 0);
    g_sim.rates[slot] = ingress_rate_limit ? 222000 : 111000;
    g_sim.capacities[slot] = ingress_rate_limit ? 8192 : 4096;
}

static void expect(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        g_failed++;
}

static fm_uint32 *watermark_port_value(
    watermark_image_simulator *image, fm_int port,
    fm_int attr, fm_int index) {
    watermark_port_simulator *port_state =
        watermark_port_find(image, port);

    if (!port_state)
        return NULL;
    switch (attr) {
    case FM_QOS_RX_PRIVATE_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS ?
               &port_state->rx_private_wm[index] : NULL;
    case FM_QOS_RX_HOG_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS ?
               &port_state->rx_hog_wm[index] : NULL;
    case FM_QOS_PRIVATE_PAUSE_ON_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS ?
               &port_state->private_pause_on_wm[index] : NULL;
    case FM_QOS_PRIVATE_PAUSE_OFF_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS ?
               &port_state->private_pause_off_wm[index] : NULL;
    case FM_QOS_TX_TC_PRIVATE_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_TRAFFIC_CLASSES ?
               &port_state->tx_private_wm[index] : NULL;
    case FM_QOS_TX_HOG_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_TRAFFIC_CLASSES ?
               &port_state->tx_hog_wm[index] : NULL;
    case FM_QOS_TX_SOFT_DROP_ON_PRIVATE:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES ?
               &port_state->tx_soft_drop_on_private[index] : NULL;
    case FM_QOS_TX_SOFT_DROP_ON_RXMP_FREE:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES ?
               &port_state->tx_soft_drop_on_rxmp_free[index] : NULL;
    default:
        return NULL;
    }
}

static fm_uint32 *watermark_switch_value(
    watermark_image_simulator *image, fm_int attr, fm_int index) {
    if (!image)
        return NULL;
    switch (attr) {
    case FM_QOS_PRIV_WM:
        return index == 0 ? &image->global_private_wm : NULL;
    case FM_QOS_SHARED_PAUSE_ON_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS ?
               &image->shared_pause_on_wm[index] : NULL;
    case FM_QOS_SHARED_PAUSE_OFF_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_MEMORY_PARTITIONS ?
               &image->shared_pause_off_wm[index] : NULL;
    case FM_QOS_SHARED_PRI_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES ?
               &image->shared_priority_wm[index] : NULL;
    case FM_QOS_SHARED_SOFT_DROP_WM:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES ?
               &image->shared_soft_drop_wm[index] : NULL;
    case FM_QOS_SHARED_SOFT_DROP_WM_HOG:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES ?
               &image->shared_soft_drop_hog_wm[index] : NULL;
    case FM_QOS_SHARED_SOFT_DROP_WM_JITTER:
        return index >= 0 &&
               index < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES ?
               &image->shared_soft_drop_jitter[index] : NULL;
    default:
        return NULL;
    }
}

static fm_uint32 *pfc_port_attribute_value(fm_int attr) {
    switch (attr) {
    case FM_PORT_RX_CLASS_PAUSE:
        return &g_sim.pfc_rx_class_mask;
    case FM_PORT_TX_CLASS_PAUSE:
        return &g_sim.pfc_tx_class_mask;
    case FM_PORT_TX_PAUSE_MODE:
        return &g_sim.pfc_tx_pause_mode;
    case FM_PORT_SMP_LOSSLESS_PAUSE:
        return &g_sim.pfc_lossless_smp_mask;
    default:
        return NULL;
    }
}

bool nl_ifid_is_user_port(int logical_port) {
    return logical_port == TEST_PORT;
}

/* Typed action readback is exercised by native_storm_transaction_test.c. */
int nl_ifid_get_all(nl_port_entry *entries, int max) {
    (void)entries; (void)max; return -1;
}
fm_status fmGetStormCtrlActionList(fm_int sw, fm_int id, fm_int *count,
                                  fm_stormAction *actions, fm_int max) {
    (void)sw; (void)id; (void)count; (void)actions; (void)max; return FM_FAIL;
}

fm_status fmGetCardinalPortList(fm_int sw, fm_int *count,
                                fm_int *ports, fm_int max_ports) {
    (void)sw;
    if (g_sim.cardinal_port_status != FM_OK)
        return g_sim.cardinal_port_status;
    if (!count || !ports || max_ports < g_sim.cardinal_port_count)
        return FM_ERR_BUFFER_FULL;
    *count = g_sim.cardinal_port_count;
    memcpy(ports, g_sim.cardinal_ports,
           (size_t)*count * sizeof(ports[0]));
    return FM_OK;
}

fm_status fmGetStormCtrlList(fm_int sw, fm_int *count,
                             fm_int *controllers, fm_int max) {
    (void)sw;
    if (g_sim.controller_list_status != FM_OK)
        return g_sim.controller_list_status;
    if (!count || !controllers || max < g_sim.n_controllers)
        return FM_ERR_BUFFER_FULL;
    *count = g_sim.n_controllers;
    memcpy(controllers, g_sim.controllers,
           (size_t)g_sim.n_controllers * sizeof(controllers[0]));
    return FM_OK;
}

fm_status fmGetStormCtrlConditionList(
    fm_int sw, fm_int controller, fm_int *count,
    fm_stormCondition *conditions, fm_int max) {
    int slot = controller_slot(controller);

    (void)sw;
    if (slot < 0)
        return FM_ERR_INVALID_STORM_CTRL;
    if (g_sim.condition_status[slot] != FM_OK)
        return g_sim.condition_status[slot];
    if (!count || !conditions || max < g_sim.n_conditions[slot])
        return FM_ERR_BUFFER_FULL;
    *count = g_sim.n_conditions[slot];
    memcpy(conditions, g_sim.conditions[slot],
           (size_t)*count * sizeof(conditions[0]));
    return FM_OK;
}

fm_status fmGetPortSetPortFirst(fm_int sw, fm_int portset, fm_int *port) {
    (void)sw;
    if (portset != TEST_PORTSET)
        return FM_ERR_INVALID_PORT_SET;
    if (g_sim.portset_first_status != FM_OK)
        return g_sim.portset_first_status;
    *port = g_sim.portset_member;
    return FM_OK;
}

fm_status fmGetPortSetPortNext(fm_int sw, fm_int portset,
                               fm_int current, fm_int *next) {
    (void)sw;
    (void)current;
    (void)next;
    if (portset != TEST_PORTSET)
        return FM_ERR_INVALID_PORT_SET;
    return g_sim.portset_next_status;
}

fm_status fmGetStormCtrlAttribute(fm_int sw, fm_int controller,
                                  fm_int attr, void *value) {
    int slot = controller_slot(controller);

    (void)sw;
    if (slot < 0 || !value)
        return FM_ERR_INVALID_ARGUMENT;
    if (attr == FM_STORM_RATE) {
        if (g_sim.rate_status[slot] != FM_OK)
            return g_sim.rate_status[slot];
        *(fm_uint32 *)value = g_sim.rates[slot];
        return FM_OK;
    }
    if (attr == FM_STORM_CAPACITY) {
        if (g_sim.capacity_status[slot] != FM_OK)
            return g_sim.capacity_status[slot];
        *(fm_uint32 *)value = g_sim.capacities[slot];
        return FM_OK;
    }
    return FM_ERR_INVALID_ATTRIB;
}

fm_status fmGetPortAttribute(fm_int sw, fm_int port,
                             fm_int attr, void *value) {
    int slot = qos_attr_slot(attr);
    fm_uint32 *pfc_value = pfc_port_attribute_value(attr);

    (void)sw;
    if (port != TEST_PORT || !value)
        return FM_ERR_INVALID_ARGUMENT;
    if (pfc_value) {
        *(fm_uint32 *)value = *pfc_value;
        return FM_OK;
    }
    if (slot < 0)
        return FM_ERR_INVALID_ARGUMENT;
    if (g_sim.qos_get_status[slot] != FM_OK)
        return g_sim.qos_get_status[slot];
    switch (slot) {
    case QOS_SOURCE:
        *(fm_uint32 *)value = g_sim.qos_source;
        break;
    case QOS_DSCP_PREFERENCE:
        *(fm_bool *)value = g_sim.qos_dscp_preference;
        break;
    case QOS_DEFAULT_PRIORITY:
        *(fm_uint32 *)value = g_sim.qos_default_priority;
        break;
    case QOS_DEFAULT_SWITCH_PRIORITY:
        *(fm_uint32 *)value = g_sim.qos_default_switch_priority;
        break;
    default:
        return FM_ERR_INVALID_ATTRIB;
    }
    return FM_OK;
}

fm_status fmSetPortAttribute(fm_int sw, fm_int port,
                             fm_int attr, void *value) {
    int slot = qos_attr_slot(attr);
    fm_uint32 *pfc_value = pfc_port_attribute_value(attr);

    (void)sw;
    if (port != TEST_PORT || !value)
        return FM_ERR_INVALID_ARGUMENT;
    if (pfc_value) {
        fm_uint32 prior = *pfc_value;

        *pfc_value = *(fm_uint32 *)value;
        if (attr == FM_PORT_SMP_LOSSLESS_PAUSE &&
            prior != *pfc_value && g_sim.auto_pause_mode == TRUE)
            simulate_auto_pause_recalculation();
        return FM_OK;
    }
    if (slot < 0)
        return FM_ERR_INVALID_ARGUMENT;
    g_sim.qos_set_calls[slot]++;
    if (g_sim.qos_set_status[slot] != FM_OK)
        return g_sim.qos_set_status[slot];
    switch (slot) {
    case QOS_SOURCE:
        g_sim.qos_source = *(fm_uint32 *)value;
        break;
    case QOS_DSCP_PREFERENCE:
        g_sim.qos_dscp_preference = *(fm_bool *)value;
        break;
    case QOS_DEFAULT_PRIORITY:
        g_sim.qos_default_priority = *(fm_uint32 *)value;
        break;
    case QOS_DEFAULT_SWITCH_PRIORITY:
        if (!g_sim.ignore_default_switch_priority_write)
            g_sim.qos_default_switch_priority = *(fm_uint32 *)value;
        break;
    default:
        return FM_ERR_INVALID_ATTRIB;
    }
    return FM_OK;
}

fm_status fmGetPortQOS(fm_int sw, fm_int port, fm_int attr,
                       fm_int index, void *value) {
    scheduler_topology_simulator *topology = &g_sim.scheduler_staging;
    fm_uint32 *watermark_value =
        watermark_port_value(&g_sim.watermark, port, attr, index);

    (void)sw;
    if (!value)
        return FM_ERR_INVALID_ARGUMENT;
    if (watermark_value) {
        if (port == g_sim.watermark_port_get_fail_port &&
            attr == g_sim.watermark_port_get_fail_attr &&
            index == g_sim.watermark_port_get_fail_index)
            return g_sim.watermark_port_get_fail_status;
        *(fm_uint32 *)value = *watermark_value;
        return FM_OK;
    }
    if (port != TEST_PORT)
        return FM_ERR_INVALID_ARGUMENT;
    if (attr == FM_QOS_SHARED_PAUSE_ENABLE && index == 0) {
        *(fm_uint32 *)value = g_sim.pfc_shared_pause_mask;
        return FM_OK;
    }
    if (attr == FM_QOS_PC_RXMP_MAP && index == 3) {
        *(fm_uint32 *)value = g_sim.pfc_pc3_smp;
        return FM_OK;
    }
    if (attr == g_sim.port_qos_get_fail_attr &&
        index == g_sim.port_qos_get_fail_index)
        return g_sim.port_qos_get_fail_status;

    switch (attr) {
    case FM_QOS_RETRIEVE_ACTIVE_SCHED:
        g_sim.scheduler_staging = g_sim.scheduler_active;
        *(fm_uint32 *)value = 0;
        return FM_OK;
    case FM_QOS_NUM_SCHED_GROUPS:
        *(fm_uint32 *)value = topology->num_groups;
        return FM_OK;
    case FM_QOS_SCHED_GROUP_STRICT:
        if (index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_INDEX;
        *(fm_uint32 *)value = topology->strict[index];
        return FM_OK;
    case FM_QOS_SCHED_GROUP_WEIGHT:
        if (index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_INDEX;
        *(fm_uint32 *)value = topology->weight[index];
        return FM_OK;
    case FM_QOS_SCHED_GROUP_TCBOUNDARY_A:
        if (index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_INDEX;
        *(fm_uint32 *)value = topology->boundary_a[index];
        return FM_OK;
    case FM_QOS_SCHED_GROUP_TCBOUNDARY_B:
        if (index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_INDEX;
        *(fm_uint32 *)value = topology->boundary_b[index];
        return FM_OK;
    case FM_QOS_SHAPING_GROUP_RATE:
        if (index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_INDEX;
        *(fm_uint64 *)value = g_sim.shaping_rate[index];
        return FM_OK;
    case FM_QOS_SHAPING_GROUP_MAX_BURST:
        if (index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_INDEX;
        *(fm_uint64 *)value = g_sim.shaping_burst[index];
        return FM_OK;
    case FM_QOS_TC_SHAPING_GROUP_MAP:
        if (index < 0 ||
            index >= HAL_TRANSACTION_EGRESS_RATE_TC_COUNT)
            return FM_ERR_INVALID_INDEX;
        *(fm_uint32 *)value = g_sim.egress_tc_map[index];
        return FM_OK;
    case FM_QOS_TC_ENABLE:
        if (index != 0)
            return FM_ERR_INVALID_INDEX;
        *(fm_uint32 *)value = g_sim.scheduler_tc_enable;
        return FM_OK;
    default:
        return FM_ERR_INVALID_ATTRIB;
    }
}

fm_status fmSetPortQOS(fm_int sw, fm_int port, fm_int attr,
                       fm_int index, void *value) {
    scheduler_topology_simulator *topology = &g_sim.scheduler_staging;
    fm_uint32 *watermark_value =
        watermark_port_value(&g_sim.watermark, port, attr, index);

    (void)sw;
    if (watermark_value) {
        if (!value)
            return FM_ERR_INVALID_ARGUMENT;
        g_sim.watermark_write_calls++;
        if (port == g_sim.watermark_port_set_fail_port &&
            attr == g_sim.watermark_port_set_fail_attr &&
            index == g_sim.watermark_port_set_fail_index)
            return g_sim.watermark_port_set_fail_status;
        if (!(port == g_sim.watermark_ignore_port &&
              attr == g_sim.watermark_ignore_port_attr &&
              index == g_sim.watermark_ignore_port_index))
            *watermark_value = *(fm_uint32 *)value;
        return FM_OK;
    }
    if (port != TEST_PORT)
        return FM_ERR_INVALID_ARGUMENT;
    if (attr == FM_QOS_SHARED_PAUSE_ENABLE && index == 0) {
        if (!value)
            return FM_ERR_INVALID_ARGUMENT;
        g_sim.pfc_shared_pause_mask = *(fm_uint32 *)value;
        return FM_OK;
    }
    if (attr == FM_QOS_PC_RXMP_MAP && index == 3 && value) {
        g_sim.pfc_pc3_smp = *(fm_uint32 *)value;
        return FM_OK;
    }
    if (attr == g_sim.port_qos_set_fail_attr &&
        index == g_sim.port_qos_set_fail_index)
        return g_sim.port_qos_set_fail_status;

    switch (attr) {
    case FM_QOS_NUM_SCHED_GROUPS:
        if (!value)
            return FM_ERR_INVALID_ARGUMENT;
        topology->num_groups = *(fm_uint32 *)value;
        return FM_OK;
    case FM_QOS_SCHED_GROUP_STRICT:
        if (!value || index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_ARGUMENT;
        topology->strict[index] = *(fm_uint32 *)value;
        return FM_OK;
    case FM_QOS_SCHED_GROUP_WEIGHT:
        if (!value || index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_ARGUMENT;
        topology->weight[index] = *(fm_uint32 *)value;
        return FM_OK;
    case FM_QOS_SCHED_GROUP_TCBOUNDARY_A:
        if (!value || index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_ARGUMENT;
        topology->boundary_a[index] = *(fm_uint32 *)value;
        return FM_OK;
    case FM_QOS_SCHED_GROUP_TCBOUNDARY_B:
        if (!value || index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_ARGUMENT;
        topology->boundary_b[index] = *(fm_uint32 *)value;
        return FM_OK;
    case FM_QOS_APPLY_NEW_SCHED:
        if (!g_sim.ignore_scheduler_apply)
            g_sim.scheduler_active = g_sim.scheduler_staging;
        return FM_OK;
    case FM_QOS_SHAPING_GROUP_RATE:
        if (!value || index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_ARGUMENT;
        if (!g_sim.ignore_shaping_rate_write)
            g_sim.shaping_rate[index] = *(fm_uint64 *)value;
        return FM_OK;
    case FM_QOS_SHAPING_GROUP_MAX_BURST:
        if (!value || index < 0 ||
            index >= HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS)
            return FM_ERR_INVALID_ARGUMENT;
        if (!g_sim.ignore_shaping_burst_write)
            g_sim.shaping_burst[index] = *(fm_uint64 *)value;
        return FM_OK;
    case FM_QOS_TC_SHAPING_GROUP_MAP:
        if (!value || index < 0 ||
            index >= HAL_TRANSACTION_EGRESS_RATE_TC_COUNT)
            return FM_ERR_INVALID_ARGUMENT;
        g_sim.egress_tc_map[index] = *(fm_uint32 *)value;
        return FM_OK;
    case FM_QOS_TC_ENABLE:
        if (!value || index != 0)
            return FM_ERR_INVALID_ARGUMENT;
        g_sim.scheduler_tc_enable_set_calls++;
        if (!g_sim.ignore_scheduler_tc_enable_write)
            g_sim.scheduler_tc_enable = *(fm_uint32 *)value;
        return FM_OK;
    default:
        return FM_ERR_INVALID_ATTRIB;
    }
}

fm_status fmGetSwitchQOS(fm_int sw, fm_int attr,
                         fm_int index, void *value) {
    fm_uint32 *watermark_value =
        watermark_switch_value(&g_sim.watermark, attr, index);

    (void)sw;
    if (!value)
        return FM_ERR_INVALID_ARGUMENT;
    if (attr == g_sim.watermark_switch_get_fail_attr &&
        index == g_sim.watermark_switch_get_fail_index)
        return g_sim.watermark_switch_get_fail_status;
    if (attr == FM_AUTO_PAUSE_MODE && index == 0) {
        *(fm_bool *)value = g_sim.auto_pause_mode;
        return FM_OK;
    }
    if (attr == FM_QOS_SWPRI_TC_MAP &&
        index >= 0 &&
        index < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES) {
        *(fm_uint32 *)value = g_sim.priority_map[index];
        return FM_OK;
    }
    if (watermark_value) {
        *(fm_uint32 *)value = *watermark_value;
        return FM_OK;
    }
    return FM_ERR_INVALID_ATTRIB;
}

fm_status fmSetSwitchQOS(fm_int sw, fm_int attr,
                         fm_int index, void *value) {
    fm_uint32 *watermark_value =
        watermark_switch_value(&g_sim.watermark, attr, index);

    (void)sw;
    if (!value)
        return FM_ERR_INVALID_ARGUMENT;
    if (attr == FM_AUTO_PAUSE_MODE || watermark_value)
        g_sim.watermark_write_calls++;
    if (attr == g_sim.watermark_switch_set_fail_attr &&
        index == g_sim.watermark_switch_set_fail_index)
        return g_sim.watermark_switch_set_fail_status;
    if (attr == FM_AUTO_PAUSE_MODE && index == 0) {
        g_sim.auto_pause_mode = *(fm_bool *)value;
        if (g_sim.auto_pause_mode == TRUE)
            simulate_auto_pause_recalculation();
        return FM_OK;
    }
    if (attr == FM_QOS_SWPRI_TC_MAP &&
        index >= 0 &&
        index < HAL_TRANSACTION_QOS_SWITCH_PRIORITIES) {
        g_sim.priority_map[index] = *(fm_uint32 *)value;
        if (g_sim.auto_pause_mode == TRUE)
            simulate_auto_pause_recalculation();
        return FM_OK;
    }
    if (watermark_value) {
        if (!(attr == g_sim.watermark_ignore_switch_attr &&
              index == g_sim.watermark_ignore_switch_index))
            *watermark_value = *(fm_uint32 *)value;
        return FM_OK;
    }
    return FM_ERR_INVALID_ATTRIB;
}

const char *fmErrorMsg(fm_int status) {
    (void)status;
    return "injected SDK status";
}

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

static void test_storm_snapshot_success_and_absence(void) {
    hal_storm_rate_transaction_snapshot snapshot;

    reset_simulator();
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("empty controller enumeration proves storm ABSENT",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT &&
           snapshot.sdk_status == FM_OK);

    reset_simulator();
    configure_storm_controller(0, TEST_STORM_CONTROLLER, false);
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("storm exact snapshot includes controller/rate/capacity",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.controller == TEST_STORM_CONTROLLER &&
           snapshot.rate_kbps == 111000 &&
           snapshot.capacity_bytes == 4096);
    snapshot = hal_ingress_rate_limit_transaction_snapshot(0, TEST_PORT);
    expect("storm controller is not misclassified as ingress rate",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT);

    reset_simulator();
    configure_storm_controller(0, TEST_INGRESS_CONTROLLER, true);
    snapshot = hal_ingress_rate_limit_transaction_snapshot(0, TEST_PORT);
    expect("ingress-rate exact snapshot includes raw rate/capacity",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.controller == TEST_INGRESS_CONTROLLER &&
           snapshot.rate_kbps == 222000 &&
           snapshot.capacity_bytes == 8192);
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("ingress-rate controller is excluded from storm snapshot",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT);

    reset_simulator();
    configure_storm_controller(0, TEST_STORM_CONTROLLER, false);
    g_sim.portset_member = TEST_PORT + 1;
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("successful complete portset walk proves per-port ABSENT",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT &&
           snapshot.sdk_status == FM_OK);
}

static void test_storm_snapshot_fails_closed(void) {
    hal_storm_rate_transaction_snapshot snapshot;

    reset_simulator();
    g_sim.controller_list_status = FM_FAIL;
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("controller enumeration error remains READ_ERROR",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    configure_storm_controller(0, TEST_STORM_CONTROLLER, false);
    g_sim.condition_status[0] = FM_FAIL;
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("condition-list error remains READ_ERROR",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    configure_storm_controller(0, TEST_STORM_CONTROLLER, false);
    g_sim.portset_first_status = FM_FAIL;
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("portset-first error remains READ_ERROR",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    configure_storm_controller(0, TEST_STORM_CONTROLLER, false);
    g_sim.portset_next_status = FM_FAIL;
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("portset-next error after target match remains READ_ERROR",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    configure_storm_controller(0, TEST_STORM_CONTROLLER, false);
    g_sim.rate_status[0] = FM_FAIL;
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("rate attribute error remains READ_ERROR",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    configure_storm_controller(0, TEST_STORM_CONTROLLER, false);
    g_sim.capacity_status[0] = FM_FAIL;
    snapshot = hal_storm_control_transaction_snapshot(0, TEST_PORT);
    expect("capacity attribute error remains READ_ERROR",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);
}

static void test_qos_exact_snapshot(void) {
    hal_qos_interface_transaction_snapshot snapshot;

    reset_simulator();
    snapshot = hal_qos_interface_transaction_snapshot_get(0, TEST_PORT);
    expect("QoS snapshot preserves the raw four-attribute tuple",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.source == g_sim.qos_source &&
           snapshot.dscp_preference == TRUE &&
           snapshot.default_priority == 3 &&
           snapshot.default_switch_priority == 11);

    for (int slot = 0; slot < 4; slot++) {
        reset_simulator();
        g_sim.qos_get_status[slot] = FM_FAIL;
        snapshot = hal_qos_interface_transaction_snapshot_get(
            0, TEST_PORT);
        expect("each QoS tuple read error remains READ_ERROR",
               snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
               snapshot.sdk_status == FM_FAIL);
    }

    reset_simulator();
    g_sim.qos_get_status[QOS_DEFAULT_SWITCH_PRIORITY] = FM_FAIL;
    snapshot = hal_qos_interface_transaction_snapshot_get(0, TEST_PORT);
    expect("DEF_SWPRI failure never falls back to DEF_PRI",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.default_switch_priority == 0);
}

static void test_qos_exact_restore(void) {
    hal_qos_interface_transaction_snapshot wanted;

    reset_simulator();
    wanted = hal_qos_interface_transaction_snapshot_get(0, TEST_PORT);
    g_sim.qos_source = FM_PORT_SWPRI_VPRI1;
    g_sim.qos_dscp_preference = FALSE;
    g_sim.qos_default_priority = 0;
    g_sim.qos_default_switch_priority = 0;
    expect("QoS restore writes and proves all four raw attributes",
           hal_qos_interface_transaction_restore(
               0, TEST_PORT, &wanted) == 0 &&
           g_sim.qos_source == wanted.source &&
           g_sim.qos_dscp_preference == wanted.dscp_preference &&
           g_sim.qos_default_priority == wanted.default_priority &&
           g_sim.qos_default_switch_priority ==
               wanted.default_switch_priority &&
           g_sim.qos_set_calls[QOS_SOURCE] == 1 &&
           g_sim.qos_set_calls[QOS_DSCP_PREFERENCE] == 1 &&
           g_sim.qos_set_calls[QOS_DEFAULT_PRIORITY] == 1 &&
           g_sim.qos_set_calls[QOS_DEFAULT_SWITCH_PRIORITY] == 1);

    reset_simulator();
    wanted = hal_qos_interface_transaction_snapshot_get(0, TEST_PORT);
    g_sim.qos_set_status[QOS_DSCP_PREFERENCE] = FM_FAIL;
    expect("QoS restore reports an SDK write error",
           hal_qos_interface_transaction_restore(
               0, TEST_PORT, &wanted) == FM_FAIL);

    reset_simulator();
    wanted = hal_qos_interface_transaction_snapshot_get(0, TEST_PORT);
    wanted.default_switch_priority = 12;
    g_sim.ignore_default_switch_priority_write = true;
    expect("QoS restore rejects a successful write with mismatched readback",
           hal_qos_interface_transaction_restore(
               0, TEST_PORT, &wanted) == FM_ERR_INVALID_STATE);

    reset_simulator();
    wanted = hal_qos_interface_transaction_snapshot_get(0, TEST_PORT);
    g_sim.qos_get_status[QOS_SOURCE] = FM_FAIL;
    expect("QoS restore propagates post-write READ_ERROR",
           hal_qos_interface_transaction_restore(
               0, TEST_PORT, &wanted) == FM_FAIL);
}

static void test_scheduler_topology_exact_snapshot(void) {
    hal_qos_scheduler_topology_transaction_snapshot snapshot;
    const fm_int attrs[] = {
        FM_QOS_RETRIEVE_ACTIVE_SCHED,
        FM_QOS_NUM_SCHED_GROUPS,
        FM_QOS_SCHED_GROUP_STRICT,
        FM_QOS_SCHED_GROUP_WEIGHT,
        FM_QOS_SCHED_GROUP_TCBOUNDARY_A,
        FM_QOS_SCHED_GROUP_TCBOUNDARY_B,
    };

    reset_simulator();
    snapshot = hal_qos_scheduler_topology_transaction_snapshot_get(
        0, TEST_PORT);
    expect("scheduler snapshot preserves the complete active topology",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.num_groups == 3 &&
           snapshot.groups[0].strict_priority == 0 &&
           snapshot.groups[1].weight == 1037 &&
           snapshot.groups[1].traffic_class_boundary_a == 1 &&
           snapshot.groups[2].traffic_class_boundary_b == 3);

    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
        reset_simulator();
        g_sim.port_qos_get_fail_attr = attrs[i];
        g_sim.port_qos_get_fail_index =
            attrs[i] == FM_QOS_RETRIEVE_ACTIVE_SCHED ||
            attrs[i] == FM_QOS_NUM_SCHED_GROUPS ? 0 : 1;
        g_sim.port_qos_get_fail_status = FM_FAIL;
        snapshot = hal_qos_scheduler_topology_transaction_snapshot_get(
            0, TEST_PORT);
        expect("every scheduler topology read error remains READ_ERROR",
               snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
               snapshot.sdk_status == FM_FAIL);
    }

    reset_simulator();
    g_sim.scheduler_active.num_groups =
        HAL_TRANSACTION_QOS_SCHEDULER_MAX_GROUPS + 1;
    snapshot = hal_qos_scheduler_topology_transaction_snapshot_get(
        0, TEST_PORT);
    expect("invalid active scheduler group count fails closed",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status ==
               FM_ERR_INVALID_ACTIVE_ESCHED_CONFIG);
}

static void test_scheduler_topology_exact_restore(void) {
    hal_qos_scheduler_topology_transaction_snapshot wanted;

    reset_simulator();
    wanted = hal_qos_scheduler_topology_transaction_snapshot_get(
        0, TEST_PORT);
    g_sim.scheduler_active.num_groups = 2;
    g_sim.scheduler_active.strict[0] = 1;
    g_sim.scheduler_active.weight[0] = 7;
    g_sim.scheduler_active.boundary_a[0] = 6;
    g_sim.scheduler_active.boundary_b[0] = 7;
    expect("scheduler restore replaces and proves the whole topology",
           hal_qos_scheduler_topology_transaction_restore(
               0, TEST_PORT, &wanted) == 0 &&
           g_sim.scheduler_active.num_groups == wanted.num_groups &&
           g_sim.scheduler_active.strict[0] ==
               wanted.groups[0].strict_priority &&
           g_sim.scheduler_active.weight[1] ==
               wanted.groups[1].weight &&
           g_sim.scheduler_active.boundary_a[2] ==
               wanted.groups[2].traffic_class_boundary_a &&
           g_sim.scheduler_active.boundary_b[2] ==
               wanted.groups[2].traffic_class_boundary_b);

    reset_simulator();
    wanted = hal_qos_scheduler_topology_transaction_snapshot_get(
        0, TEST_PORT);
    g_sim.port_qos_set_fail_attr = FM_QOS_SCHED_GROUP_WEIGHT;
    g_sim.port_qos_set_fail_index = 1;
    g_sim.port_qos_set_fail_status = FM_FAIL;
    expect("scheduler restore reports a topology write error",
           hal_qos_scheduler_topology_transaction_restore(
               0, TEST_PORT, &wanted) == FM_FAIL);

    reset_simulator();
    wanted = hal_qos_scheduler_topology_transaction_snapshot_get(
        0, TEST_PORT);
    g_sim.scheduler_active.weight[1]++;
    g_sim.ignore_scheduler_apply = true;
    expect("scheduler restore rejects mismatched active readback",
           hal_qos_scheduler_topology_transaction_restore(
               0, TEST_PORT, &wanted) == FM_ERR_INVALID_STATE);
}

static void test_scheduler_group_shaping_exact_snapshot(void) {
    hal_qos_scheduler_group_shaping_transaction_snapshot snapshot;
    bool present = true;
    u64 rate = 0;
    u64 burst = 0;

    reset_simulator();
    snapshot = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    expect("complete SDK shaping defaults are exactly ABSENT",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT &&
           snapshot.sdk_status == FM_OK &&
           snapshot.raw_rate_bps ==
               (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT &&
           snapshot.raw_burst_bits ==
               NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS);

    reset_simulator();
    g_sim.shaping_burst[TEST_SHAPING_GROUP] = 1234567ULL;
    snapshot = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    expect("default rate with custom burst remains exact PRESENT state",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.raw_rate_bps ==
               (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT &&
           snapshot.raw_burst_bits == 1234567ULL);
    expect("legacy shaping snapshot carries the same raw tuple",
           hal_qos_scheduler_group_shaping_snapshot(
               0, TEST_PORT, TEST_SHAPING_GROUP,
               &present, &rate, &burst) == 0 &&
           present &&
           rate == (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT &&
           burst == 1234567ULL);

    reset_simulator();
    g_sim.shaping_rate[TEST_SHAPING_GROUP] = 7654321ULL;
    snapshot = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    expect("custom rate with default burst remains exact PRESENT state",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.raw_rate_bps == 7654321ULL &&
           snapshot.raw_burst_bits ==
               NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS);

    reset_simulator();
    g_sim.port_qos_get_fail_attr = FM_QOS_SHAPING_GROUP_RATE;
    g_sim.port_qos_get_fail_index = TEST_SHAPING_GROUP;
    g_sim.port_qos_get_fail_status = FM_FAIL;
    snapshot = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    expect("shaping rate read error remains READ_ERROR",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);

    reset_simulator();
    g_sim.port_qos_get_fail_attr =
        FM_QOS_SHAPING_GROUP_MAX_BURST;
    g_sim.port_qos_get_fail_index = TEST_SHAPING_GROUP;
    g_sim.port_qos_get_fail_status = FM_FAIL;
    snapshot = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    expect("default rate never suppresses a shaping burst read error",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL);
}

static void test_scheduler_group_shaping_exact_restore(void) {
    hal_qos_scheduler_group_shaping_transaction_snapshot wanted;
    const fm_int attrs[] = {
        FM_QOS_SHAPING_GROUP_MAX_BURST,
        FM_QOS_SHAPING_GROUP_RATE,
    };

    reset_simulator();
    g_sim.shaping_burst[TEST_SHAPING_GROUP] = 1234567ULL;
    wanted = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    g_sim.shaping_rate[TEST_SHAPING_GROUP] = 99887766ULL;
    g_sim.shaping_burst[TEST_SHAPING_GROUP] =
        NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS;
    expect("shaping restore accepts default rate with custom burst",
           hal_qos_scheduler_group_shaping_transaction_restore(
               0, TEST_PORT, TEST_SHAPING_GROUP, &wanted) == 0 &&
           g_sim.shaping_rate[TEST_SHAPING_GROUP] ==
               wanted.raw_rate_bps &&
           g_sim.shaping_burst[TEST_SHAPING_GROUP] ==
               wanted.raw_burst_bits);

    reset_simulator();
    wanted = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    g_sim.shaping_rate[TEST_SHAPING_GROUP] = 99887766ULL;
    g_sim.shaping_burst[TEST_SHAPING_GROUP] = 1234567ULL;
    expect("shaping restore exactly recreates complete SDK defaults",
           hal_qos_scheduler_group_shaping_transaction_restore(
               0, TEST_PORT, TEST_SHAPING_GROUP, &wanted) == 0 &&
           g_sim.shaping_rate[TEST_SHAPING_GROUP] ==
               (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT &&
           g_sim.shaping_burst[TEST_SHAPING_GROUP] ==
               NETLAB_QOS_SHAPING_GROUP_DEFAULT_BURST_BITS);

    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
        reset_simulator();
        g_sim.shaping_rate[TEST_SHAPING_GROUP] = 7654321ULL;
        wanted =
            hal_qos_scheduler_group_shaping_transaction_snapshot_get(
                0, TEST_PORT, TEST_SHAPING_GROUP);
        g_sim.port_qos_set_fail_attr = attrs[i];
        g_sim.port_qos_set_fail_index = TEST_SHAPING_GROUP;
        g_sim.port_qos_set_fail_status = FM_FAIL;
        expect("each shaping raw write error is propagated",
               hal_qos_scheduler_group_shaping_transaction_restore(
                   0, TEST_PORT, TEST_SHAPING_GROUP,
                   &wanted) == FM_FAIL);
    }

    reset_simulator();
    g_sim.shaping_rate[TEST_SHAPING_GROUP] = 7654321ULL;
    wanted = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    g_sim.shaping_rate[TEST_SHAPING_GROUP]++;
    g_sim.ignore_shaping_rate_write = true;
    expect("shaping restore rejects mismatched raw rate readback",
           hal_qos_scheduler_group_shaping_transaction_restore(
               0, TEST_PORT, TEST_SHAPING_GROUP,
               &wanted) == FM_ERR_INVALID_STATE);

    reset_simulator();
    g_sim.shaping_burst[TEST_SHAPING_GROUP] = 1234567ULL;
    wanted = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    g_sim.shaping_burst[TEST_SHAPING_GROUP]++;
    g_sim.ignore_shaping_burst_write = true;
    expect("shaping restore rejects mismatched raw burst readback",
           hal_qos_scheduler_group_shaping_transaction_restore(
               0, TEST_PORT, TEST_SHAPING_GROUP,
               &wanted) == FM_ERR_INVALID_STATE);

    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
        reset_simulator();
        wanted =
            hal_qos_scheduler_group_shaping_transaction_snapshot_get(
                0, TEST_PORT, TEST_SHAPING_GROUP);
        g_sim.port_qos_get_fail_attr = attrs[i];
        g_sim.port_qos_get_fail_index = TEST_SHAPING_GROUP;
        g_sim.port_qos_get_fail_status = FM_FAIL;
        expect("each shaping post-write read error is propagated",
               hal_qos_scheduler_group_shaping_transaction_restore(
                   0, TEST_PORT, TEST_SHAPING_GROUP,
                   &wanted) == FM_FAIL);
    }

    reset_simulator();
    wanted = hal_qos_scheduler_group_shaping_transaction_snapshot_get(
        0, TEST_PORT, TEST_SHAPING_GROUP);
    wanted.raw_burst_bits--;
    expect("inconsistent ABSENT shaping snapshot is rejected",
           hal_qos_scheduler_group_shaping_transaction_restore(
               0, TEST_PORT, TEST_SHAPING_GROUP,
               &wanted) == FM_ERR_INVALID_ARGUMENT);
}

static void test_scheduler_port_raw_restore_boundaries(void) {
    bool every_sdk_mask_restored = true;
    int mask = -1;

    reset_simulator();
    g_sim.scheduler_tc_enable = 0;
    expect("scheduler port getter preserves SDK mask zero",
           hal_qos_scheduler_port_get(0, TEST_PORT, &mask) == 0 &&
           mask == 0);

    reset_simulator();
    expect("ordinary scheduler setter keeps user mask semantics",
           hal_qos_scheduler_port_set(0, TEST_PORT, 0) == -1 &&
           hal_qos_scheduler_port_set(0, TEST_PORT, -1) == -1 &&
           hal_qos_scheduler_port_set(0, TEST_PORT, 0x100) == -1 &&
           g_sim.scheduler_tc_enable_set_calls == 0 &&
           hal_qos_scheduler_port_set(0, TEST_PORT, 1) == 0 &&
           hal_qos_scheduler_port_set(0, TEST_PORT, 0xff) == 0 &&
           g_sim.scheduler_tc_enable == 0xffU);

    reset_simulator();
    for (u32 raw_mask = 0; raw_mask <= 0xffU; raw_mask++) {
        if (hal_qos_scheduler_port_transaction_restore(
                0, TEST_PORT, raw_mask) != 0 ||
            g_sim.scheduler_tc_enable != raw_mask) {
            every_sdk_mask_restored = false;
            break;
        }
    }
    expect("transaction restore accepts and proves every SDK mask 0..0xff",
           every_sdk_mask_restored);

    reset_simulator();
    expect("transaction restore rejects a mask above the SDK boundary",
           hal_qos_scheduler_port_transaction_restore(
               0, TEST_PORT, 0x100U) == FM_ERR_INVALID_ARGUMENT &&
           g_sim.scheduler_tc_enable_set_calls == 0);

    reset_simulator();
    g_sim.port_qos_set_fail_attr = FM_QOS_TC_ENABLE;
    g_sim.port_qos_set_fail_index = 0;
    g_sim.port_qos_set_fail_status = FM_FAIL;
    expect("scheduler-port raw restore propagates write failure",
           hal_qos_scheduler_port_transaction_restore(
               0, TEST_PORT, 0) == FM_FAIL);

    reset_simulator();
    g_sim.scheduler_tc_enable = 0x5aU;
    g_sim.ignore_scheduler_tc_enable_write = true;
    expect("scheduler-port raw restore rejects mismatched readback",
           hal_qos_scheduler_port_transaction_restore(
               0, TEST_PORT, 0) == FM_ERR_INVALID_STATE);

    reset_simulator();
    g_sim.port_qos_get_fail_attr = FM_QOS_TC_ENABLE;
    g_sim.port_qos_get_fail_index = 0;
    g_sim.port_qos_get_fail_status = FM_FAIL;
    expect("scheduler-port raw restore propagates readback failure",
           hal_qos_scheduler_port_transaction_restore(
               0, TEST_PORT, 0) == FM_FAIL);
}

static void test_egress_rate_exact_snapshot(void) {
    hal_egress_rate_transaction_snapshot snapshot;
    const fm_int attrs[] = {
        FM_QOS_SHAPING_GROUP_RATE,
        FM_QOS_SHAPING_GROUP_MAX_BURST,
        FM_QOS_TC_SHAPING_GROUP_MAP,
    };
    const fm_int indices[] = {
        NETLAB_EGRESS_RATE_LIMIT_SG,
        NETLAB_EGRESS_RATE_LIMIT_SG,
        4,
    };

    reset_simulator();
    snapshot = hal_egress_rate_limit_transaction_snapshot(0, TEST_PORT);
    expect("egress-rate snapshot preserves raw bps/bits and all TC maps",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.raw_rate_bps == 123456789ULL &&
           snapshot.raw_burst_bits == 987654321ULL &&
           snapshot.tc_shaping_group_map[4] == 1 &&
           snapshot.tc_shaping_group_map[7] == 1);

    reset_simulator();
    g_sim.shaping_rate[NETLAB_EGRESS_RATE_LIMIT_SG] =
        FM_QOS_SHAPING_GROUP_RATE_DEFAULT;
    snapshot = hal_egress_rate_limit_transaction_snapshot(0, TEST_PORT);
    expect("absent egress limiter still carries exact burst and TC maps",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_ABSENT &&
           snapshot.raw_rate_bps ==
               (u64)FM_QOS_SHAPING_GROUP_RATE_DEFAULT &&
           snapshot.raw_burst_bits == 987654321ULL &&
           snapshot.tc_shaping_group_map[5] == 2);

    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
        reset_simulator();
        g_sim.port_qos_get_fail_attr = attrs[i];
        g_sim.port_qos_get_fail_index = indices[i];
        g_sim.port_qos_get_fail_status = FM_FAIL;
        snapshot = hal_egress_rate_limit_transaction_snapshot(
            0, TEST_PORT);
        expect("every egress-rate raw read error remains READ_ERROR",
               snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
               snapshot.sdk_status == FM_FAIL);
    }
}

static void test_egress_rate_exact_restore(void) {
    hal_egress_rate_transaction_snapshot wanted;

    reset_simulator();
    wanted = hal_egress_rate_limit_transaction_snapshot(0, TEST_PORT);
    g_sim.shaping_rate[NETLAB_EGRESS_RATE_LIMIT_SG] = 64000000ULL;
    g_sim.shaping_burst[NETLAB_EGRESS_RATE_LIMIT_SG] = 65536ULL;
    memset(g_sim.egress_tc_map, 0, sizeof(g_sim.egress_tc_map));
    expect("egress-rate restore writes and proves the raw before-image",
           hal_egress_rate_limit_transaction_restore(
               0, TEST_PORT, &wanted) == 0 &&
           g_sim.shaping_rate[NETLAB_EGRESS_RATE_LIMIT_SG] ==
               wanted.raw_rate_bps &&
           g_sim.shaping_burst[NETLAB_EGRESS_RATE_LIMIT_SG] ==
               wanted.raw_burst_bits &&
           memcmp(g_sim.egress_tc_map, wanted.tc_shaping_group_map,
                  sizeof(g_sim.egress_tc_map)) == 0);

    reset_simulator();
    wanted = hal_egress_rate_limit_transaction_snapshot(0, TEST_PORT);
    g_sim.port_qos_set_fail_attr = FM_QOS_TC_SHAPING_GROUP_MAP;
    g_sim.port_qos_set_fail_index = 3;
    g_sim.port_qos_set_fail_status = FM_FAIL;
    expect("egress-rate restore reports a TC-map write error",
           hal_egress_rate_limit_transaction_restore(
               0, TEST_PORT, &wanted) == FM_FAIL);

    reset_simulator();
    wanted = hal_egress_rate_limit_transaction_snapshot(0, TEST_PORT);
    g_sim.shaping_burst[NETLAB_EGRESS_RATE_LIMIT_SG]++;
    g_sim.ignore_shaping_burst_write = true;
    expect("egress-rate restore rejects mismatched raw readback",
           hal_egress_rate_limit_transaction_restore(
               0, TEST_PORT, &wanted) == FM_ERR_INVALID_STATE);
}

static void test_auto_pause_watermark_exact_snapshot(void) {
    hal_qos_auto_pause_watermark_transaction_snapshot snapshot;
    hal_qos_auto_pause_watermark_transaction_snapshot invalid;
    const struct {
        fm_int attr;
        fm_int index;
    } switch_reads[] = {
        { FM_AUTO_PAUSE_MODE, 0 },
        { FM_QOS_PRIV_WM, 0 },
        { FM_QOS_SHARED_PAUSE_ON_WM, 1 },
        { FM_QOS_SHARED_PAUSE_OFF_WM, 1 },
        { FM_QOS_SHARED_PRI_WM, 9 },
        { FM_QOS_SHARED_SOFT_DROP_WM, 9 },
        { FM_QOS_SHARED_SOFT_DROP_WM_HOG, 9 },
        { FM_QOS_SHARED_SOFT_DROP_WM_JITTER, 9 },
    };
    const struct {
        fm_int attr;
        fm_int index;
    } port_reads[] = {
        { FM_QOS_RX_PRIVATE_WM, 1 },
        { FM_QOS_RX_HOG_WM, 1 },
        { FM_QOS_PRIVATE_PAUSE_ON_WM, 1 },
        { FM_QOS_PRIVATE_PAUSE_OFF_WM, 1 },
        { FM_QOS_TX_TC_PRIVATE_WM, 5 },
        { FM_QOS_TX_HOG_WM, 5 },
        { FM_QOS_TX_SOFT_DROP_ON_PRIVATE, 11 },
        { FM_QOS_TX_SOFT_DROP_ON_RXMP_FREE, 11 },
    };

    reset_simulator();
    snapshot =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    expect("auto-pause snapshot preserves the complete sorted cardinal image",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           snapshot.sdk_status == FM_OK &&
           snapshot.auto_pause_mode == 1 &&
           snapshot.num_ports == TEST_CARDINAL_PORT_COUNT &&
           snapshot.ports[0].port == TEST_PORT &&
           snapshot.ports[1].port == TEST_CARDINAL_PORT_2 &&
           snapshot.global_private_wm ==
               g_sim.watermark.global_private_wm &&
           snapshot.ports[1].rx_hog_wm[1] ==
               g_sim.watermark.ports[1].rx_hog_wm[1] &&
           snapshot.ports[0].tx_private_wm[5] ==
               g_sim.watermark.ports[0].tx_private_wm[5] &&
           snapshot.shared_soft_drop_jitter[9] ==
               g_sim.watermark.shared_soft_drop_jitter[9]);
    invalid = snapshot;
    invalid.sdk_status = FM_FAIL;
    expect("auto-pause PRESENT snapshots require successful SDK status",
           !hal_qos_auto_pause_watermark_transaction_snapshot_equal(
               &snapshot, &invalid) &&
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &invalid) == FM_ERR_INVALID_ARGUMENT &&
           g_sim.watermark_write_calls == 0);

    reset_simulator();
    g_sim.cardinal_port_status = FM_FAIL;
    snapshot =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    expect("cardinal enumeration failure aborts before mutation",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           snapshot.sdk_status == FM_FAIL &&
           g_sim.watermark_write_calls == 0);

    for (size_t i = 0;
         i < sizeof(switch_reads) / sizeof(switch_reads[0]); i++) {
        reset_simulator();
        g_sim.watermark_switch_get_fail_attr = switch_reads[i].attr;
        g_sim.watermark_switch_get_fail_index = switch_reads[i].index;
        g_sim.watermark_switch_get_fail_status = FM_FAIL;
        snapshot =
            hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
        expect("every switch watermark read failure remains READ_ERROR",
               snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
               snapshot.sdk_status == FM_FAIL &&
               g_sim.watermark_write_calls == 0);
    }

    for (size_t i = 0;
         i < sizeof(port_reads) / sizeof(port_reads[0]); i++) {
        reset_simulator();
        g_sim.watermark_port_get_fail_port = TEST_CARDINAL_PORT_2;
        g_sim.watermark_port_get_fail_attr = port_reads[i].attr;
        g_sim.watermark_port_get_fail_index = port_reads[i].index;
        g_sim.watermark_port_get_fail_status = FM_FAIL;
        snapshot =
            hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
        expect("every cardinal-port watermark read failure is fatal",
               snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
               snapshot.sdk_status == FM_FAIL &&
               g_sim.watermark_write_calls == 0);
    }
}

static void test_auto_pause_trigger_paths_restore_exactly(void) {
    hal_qos_auto_pause_watermark_transaction_snapshot wanted;
    hal_qos_auto_pause_watermark_transaction_snapshot readback;
    fm_uint32 original_map;
    fm_uint32 original_rx;
    fm_uint32 original_tx;
    fm_uint32 original_mode;
    fm_uint32 original_lossless;
    fm_uint32 original_shared;
    fm_uint32 original_pc3;

    reset_simulator();
    wanted =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    original_map = g_sim.priority_map[3];
    expect("priority-map apply runs the simulated auto-pause calculator",
           hal_qos_priority_map_set(
               0, 3, (int)((original_map + 1U) %
                            HAL_TRANSACTION_QOS_TRAFFIC_CLASSES)) == 0 &&
           g_sim.auto_pause_recalculate_calls == 1);
    readback =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    expect("priority-map trigger rewrites application watermark overrides",
           !hal_qos_auto_pause_watermark_transaction_snapshot_equal(
               &wanted, &readback));
    expect("priority-map input then shared watermark image restore exactly",
           hal_qos_priority_map_set(0, 3, (int)original_map) == 0 &&
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &wanted) == 0 &&
           (readback =
                hal_qos_auto_pause_watermark_transaction_snapshot_get(0),
            hal_qos_auto_pause_watermark_transaction_snapshot_equal(
                &wanted, &readback)) &&
           g_sim.auto_pause_recalculate_calls >= 3);

    reset_simulator();
    wanted =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    original_rx = g_sim.pfc_rx_class_mask;
    original_tx = g_sim.pfc_tx_class_mask;
    original_mode = g_sim.pfc_tx_pause_mode;
    original_lossless = g_sim.pfc_lossless_smp_mask;
    original_shared = g_sim.pfc_shared_pause_mask;
    original_pc3 = g_sim.pfc_pc3_smp;
    expect("PFC lossless-SMP apply runs the simulated auto-pause calculator",
           hal_qos_pfc_apply(
               0, TEST_PORT, 0x3,
               FM_PORT_TX_PAUSE_CLASS_BASED, 0x7,
               1, 1) == 0 &&
           g_sim.auto_pause_recalculate_calls == 1);
    expect("PFC inputs then shared watermark image restore exactly",
           hal_qos_pfc_apply(
               0, TEST_PORT, (int)original_rx, (int)original_mode,
               (int)original_tx, (int)original_lossless,
               (int)original_shared) == 0 &&
           hal_qos_pfc_pc3_smp_set(0, TEST_PORT, (int)original_pc3) == 0 &&
           g_sim.pfc_pc3_smp == original_pc3 &&
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &wanted) == 0 &&
           (readback =
                hal_qos_auto_pause_watermark_transaction_snapshot_get(0),
            hal_qos_auto_pause_watermark_transaction_snapshot_equal(
                &wanted, &readback)) &&
           g_sim.auto_pause_recalculate_calls >= 3);
}

static void test_auto_pause_watermark_restore_faults_and_retry(void) {
    hal_qos_auto_pause_watermark_transaction_snapshot wanted;
    hal_qos_auto_pause_watermark_transaction_snapshot readback;

    reset_simulator();
    wanted =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    simulate_auto_pause_recalculation();
    g_sim.watermark_port_set_fail_port = TEST_CARDINAL_PORT_2;
    g_sim.watermark_port_set_fail_attr = FM_QOS_TX_HOG_WM;
    g_sim.watermark_port_set_fail_index = 3;
    g_sim.watermark_port_set_fail_status = FM_FAIL;
    expect("auto-pause restore propagates an exact port write failure",
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &wanted) == FM_FAIL);
    g_sim.watermark_port_set_fail_port = -1;
    g_sim.watermark_port_set_fail_attr = -1;
    g_sim.watermark_port_set_fail_index = -1;
    g_sim.watermark_port_set_fail_status = FM_OK;
    expect("auto-pause restore retry converges from partial writes",
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &wanted) == 0 &&
           (readback =
                hal_qos_auto_pause_watermark_transaction_snapshot_get(0),
            hal_qos_auto_pause_watermark_transaction_snapshot_equal(
                &wanted, &readback)));

    reset_simulator();
    wanted =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    simulate_auto_pause_recalculation();
    g_sim.watermark_ignore_switch_attr =
        FM_QOS_SHARED_SOFT_DROP_WM_HOG;
    g_sim.watermark_ignore_switch_index = 6;
    expect("auto-pause restore rejects a successful mismatched write",
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &wanted) == FM_ERR_INVALID_STATE);
    g_sim.watermark_ignore_switch_attr = -1;
    g_sim.watermark_ignore_switch_index = -1;
    expect("auto-pause restore retries after readback mismatch",
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &wanted) == 0);

    reset_simulator();
    wanted =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    g_sim.cardinal_ports[0] = TEST_PORT + 99;
    expect("cardinal topology drift is rejected before restore mutation",
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &wanted) == FM_ERR_INVALID_STATE &&
           g_sim.watermark_write_calls == 0);

    reset_simulator();
    g_sim.auto_pause_mode = FALSE;
    wanted =
        hal_qos_auto_pause_watermark_transaction_snapshot_get(0);
    memset(&g_sim.watermark, 0, sizeof(g_sim.watermark));
    g_sim.watermark.ports[0].port = TEST_PORT;
    g_sim.watermark.ports[1].port = TEST_CARDINAL_PORT_2;
    expect("disabled auto-pause replays and proves every raw field",
           hal_qos_auto_pause_watermark_transaction_restore(
               0, &wanted) == 0 &&
           (readback =
                hal_qos_auto_pause_watermark_transaction_snapshot_get(0),
            hal_qos_auto_pause_watermark_transaction_snapshot_equal(
                &wanted, &readback)));
}

static void test_direct_watermark_snapshot_restore(void) {
    hal_qos_watermark_transaction_snapshot wanted;
    hal_qos_watermark_transaction_snapshot invalid;
    fm_uint32 *live_value;

    reset_simulator();
    live_value = watermark_port_value(
        &g_sim.watermark, TEST_PORT, FM_QOS_TX_HOG_WM, 2);
    wanted = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 2);
    expect("direct watermark snapshot is the exact hardware before-image",
           live_value &&
           wanted.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           wanted.sdk_status == FM_OK &&
           wanted.value == *live_value);
    invalid = wanted;
    invalid.sdk_status = FM_FAIL;
    expect("direct PRESENT snapshots require successful SDK status",
           !hal_qos_watermark_transaction_snapshot_equal(
               &wanted, &invalid) &&
           hal_qos_watermark_transaction_restore(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               2, &invalid) == FM_ERR_INVALID_ARGUMENT &&
           g_sim.watermark_write_calls == 0);
    *live_value += 192U;
    expect("direct watermark restore writes and proves the exact getter value",
           hal_qos_watermark_transaction_restore(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               2, &wanted) == 0 &&
           *live_value == wanted.value);

    reset_simulator();
    g_sim.watermark_port_get_fail_port = TEST_PORT;
    g_sim.watermark_port_get_fail_attr = FM_QOS_TX_HOG_WM;
    g_sim.watermark_port_get_fail_index = 2;
    g_sim.watermark_port_get_fail_status = FM_FAIL;
    wanted = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 2);
    expect("direct watermark pre-read failure never mutates hardware",
           wanted.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           wanted.sdk_status == FM_FAIL &&
           g_sim.watermark_write_calls == 0);

    reset_simulator();
    wanted = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 2);
    live_value = watermark_port_value(
        &g_sim.watermark, TEST_PORT, FM_QOS_TX_HOG_WM, 2);
    *live_value += 192U;
    g_sim.watermark_port_set_fail_port = TEST_PORT;
    g_sim.watermark_port_set_fail_attr = FM_QOS_TX_HOG_WM;
    g_sim.watermark_port_set_fail_index = 2;
    g_sim.watermark_port_set_fail_status = FM_FAIL;
    expect("direct watermark restore propagates the SDK write failure",
           hal_qos_watermark_transaction_restore(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               2, &wanted) == FM_FAIL);
    g_sim.watermark_port_set_fail_port = -1;
    g_sim.watermark_port_set_fail_attr = -1;
    g_sim.watermark_port_set_fail_index = -1;
    g_sim.watermark_port_set_fail_status = FM_OK;
    expect("direct watermark restore is retry-safe",
           hal_qos_watermark_transaction_restore(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               2, &wanted) == 0);

    reset_simulator();
    wanted = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 2);
    live_value = watermark_port_value(
        &g_sim.watermark, TEST_PORT, FM_QOS_TX_HOG_WM, 2);
    *live_value += 192U;
    g_sim.watermark_ignore_port = TEST_PORT;
    g_sim.watermark_ignore_port_attr = FM_QOS_TX_HOG_WM;
    g_sim.watermark_ignore_port_index = 2;
    expect("direct watermark restore rejects mismatched readback",
           hal_qos_watermark_transaction_restore(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               2, &wanted) == FM_ERR_INVALID_STATE);
}

static void test_watermark_restart_baseline_provenance(void) {
    hal_qos_watermark_transaction_snapshot before;
    hal_qos_watermark_transaction_snapshot delete_target;
    qos_watermark_config_state *slot;
    fm_uint32 *live_value;
    int requested;
    int baseline;

    reset_simulator();
    live_value = watermark_port_value(
        &g_sim.watermark, TEST_PORT, FM_QOS_TX_HOG_WM, 0);
    baseline = (int)*live_value;
    before = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0);
    expect("candidate create authority captures baseline even when live equals requested",
           hal_qos_watermark_transaction_apply(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               0, baseline, true, false, &before) == 0 &&
           g_sim.watermark_write_calls == 1);
    slot = qos_watermark_config_find(
        TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0);
    expect("candidate create authority persists an exact known baseline",
           slot && slot->active && slot->baseline_known &&
           slot->baseline == baseline && slot->value == baseline);

    before = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0);
    requested = baseline + 192;
    expect("later candidate SET preserves the proven baseline",
           hal_qos_watermark_transaction_apply(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               0, requested, false, false, &before) == 0 &&
           *live_value == (fm_uint32)requested);

    /*
     * Drop every process-local copy without deleting the durable file.  The
     * first accessor after this point must reconstruct DEL authority from
     * disk, exactly as a new switchd process would.
     */
    memset(g_qos_watermark_config, 0, sizeof(g_qos_watermark_config));
    memset(&g_qos_watermark_owner, 0, sizeof(g_qos_watermark_owner));
    g_qos_watermark_provenance_loaded = false;
    g_qos_watermark_provenance_load_status = 0;
    delete_target = hal_qos_watermark_delete_target_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0);
    expect("restart reloads the durable exact DEL target",
           delete_target.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           delete_target.sdk_status == FM_OK &&
           delete_target.value == (u32)baseline);
    before = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0);
    expect("restart-safe DEL restores and proves the durable baseline",
           hal_qos_watermark_transaction_delete(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               0, false, &before, &delete_target) == 0 &&
           *live_value == (fm_uint32)baseline);
    memset(g_qos_watermark_config, 0, sizeof(g_qos_watermark_config));
    g_qos_watermark_provenance_loaded = false;
    g_qos_watermark_provenance_load_status = 0;
    delete_target = hal_qos_watermark_delete_target_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0);
    expect("successful DEL durably removes owner provenance",
           delete_target.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           delete_target.sdk_status == FM_ERR_INVALID_STATE);

    reset_simulator();
    live_value = watermark_port_value(
        &g_sim.watermark, TEST_PORT, FM_QOS_TX_HOG_WM, 0);
    baseline = (int)*live_value;
    requested = baseline + 192;
    expect("generic SET writes requested state without inventing authority",
           hal_qos_watermark_set(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               0, requested) == 0 &&
           (slot = qos_watermark_config_find(
                TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0),
            slot && slot->active && !slot->baseline_known &&
            slot->baseline == NETLAB_QOS_UNSUPPORTED) &&
           g_sim.watermark_write_calls == 1);
    expect("a second generic SET cannot manufacture a baseline",
           hal_qos_watermark_set(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               0, requested + 192) == 0 &&
           (slot = qos_watermark_config_find(
                TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0),
            slot && !slot->baseline_known) &&
           g_sim.watermark_write_calls == 2);
    delete_target = hal_qos_watermark_delete_target_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0);
    expect("unknown generic provenance exposes no DEL target",
           delete_target.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           delete_target.sdk_status == FM_ERR_INVALID_STATE);
    expect("DEL with unknown provenance fails closed without another write",
           hal_qos_watermark_delete(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               0) == FM_ERR_INVALID_STATE &&
           g_sim.watermark_write_calls == 2);

    reset_simulator();
    live_value = watermark_port_value(
        &g_sim.watermark, TEST_PORT, FM_QOS_TX_HOG_WM, 0);
    requested = (int)*live_value + 192;
    g_sim.watermark_ignore_port = TEST_PORT;
    g_sim.watermark_ignore_port_attr = FM_QOS_TX_HOG_WM;
    g_sim.watermark_ignore_port_index = 0;
    expect("ordinary SET rejects an ignored write one segment away",
           hal_qos_watermark_set(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               0, requested) != 0 &&
           qos_watermark_config_find(
               TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 0) == NULL);

    reset_simulator();
    expect("DEL with no durable or process-local provenance fails closed",
           hal_qos_watermark_delete(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               0) == FM_ERR_INVALID_STATE &&
           g_sim.watermark_write_calls == 0);
}

static void test_watermark_calculator_reconciliation(void) {
    hal_qos_watermark_transaction_snapshot before;
    hal_qos_watermark_transaction_snapshot target;
    qos_watermark_config_state *slot;
    fm_uint32 *live_value;
    int calculator_value;

    reset_simulator();
    live_value = watermark_port_value(
        &g_sim.watermark, TEST_PORT, FM_QOS_TX_HOG_WM, 1);
    expect("legacy SET creates only unknown provenance",
           hal_qos_watermark_set(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               1, (int)*live_value + 192) == 0);
    memset(g_qos_watermark_config, 0, sizeof(g_qos_watermark_config));
    g_qos_watermark_provenance_loaded = false;
    g_qos_watermark_provenance_load_status = 0;
    simulate_auto_pause_recalculation();
    calculator_value = (int)*live_value;
    before = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 1);
    memset(&target, 0, sizeof(target));
    target.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    target.sdk_status = FM_OK;
    target.value = before.value;
    target.owner_baseline = NETLAB_QOS_UNSUPPORTED;
    target.owner_value = NETLAB_QOS_UNSUPPORTED;
    expect("calculator-reconciled DEL accepts the captured candidate target",
           before.owner_present && !before.owner_baseline_known &&
           hal_qos_watermark_transaction_delete(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               1, true, &before, &target) == 0 &&
           *live_value == (fm_uint32)calculator_value);
    expect("calculator-reconciled DEL clears unknown durable provenance",
           qos_watermark_config_find(
               TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 1) == NULL);

    reset_simulator();
    simulate_auto_pause_recalculation();
    live_value = watermark_port_value(
        &g_sim.watermark, TEST_PORT, FM_QOS_TX_HOG_WM, 1);
    calculator_value = (int)*live_value;
    before = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 1);
    expect("candidate replay reconstructs missing baseline only after calculator reconciliation",
           !before.owner_present &&
           hal_qos_watermark_transaction_apply(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               1, calculator_value + 192,
               false, true, &before) == 0 &&
           (slot = qos_watermark_config_find(
                TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 1),
            slot && slot->baseline_known &&
            slot->baseline == calculator_value));
    target = hal_qos_watermark_delete_target_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 1);
    expect("reconstructed calculator baseline becomes an exact DEL target",
           target.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           target.value == (u32)calculator_value);

    reset_simulator();
    g_sim.auto_pause_mode = FALSE;
    before = hal_qos_watermark_transaction_snapshot_get(
        0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG, 1);
    expect("reconcile metadata fails closed when auto-pause is disabled",
           hal_qos_watermark_transaction_apply(
               0, TEST_PORT, HAL_QOS_WATERMARK_ATTR_TX_HOG,
               1, (int)before.value, false, true, &before) ==
               FM_ERR_INVALID_STATE &&
           g_sim.watermark_write_calls == 0);
}

static void test_watermark_scope_and_canonical_values(void) {
    hal_qos_watermark_owner_args switch_args = {
        .scope = HAL_QOS_WATERMARK_SCOPE_SWITCH,
        .port = TEST_PORT,
        .attr = HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP,
        .index = 0,
        .value = 0,
    };
    const int attrs[] = {
        HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE,
        HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_RXMP_FREE,
    };

    expect("byte watermarks canonicalize by mathematical ceiling",
           qos_watermark_canonical_value(
               HAL_QOS_WATERMARK_ATTR_TX_HOG, 0) == 0 &&
           qos_watermark_canonical_value(
               HAL_QOS_WATERMARK_ATTR_TX_HOG, 1) == 192 &&
           qos_watermark_canonical_value(
               HAL_QOS_WATERMARK_ATTR_TX_HOG, 192) == 192 &&
           qos_watermark_canonical_value(
               HAL_QOS_WATERMARK_ATTR_TX_HOG, 193) == 384);
    expect("byte verifier requires the one exact canonical value",
           qos_watermark_value_matches(
               HAL_QOS_WATERMARK_ATTR_TX_HOG, 193, 384) &&
           !qos_watermark_value_matches(
               HAL_QOS_WATERMARK_ATTR_TX_HOG, 193, 192) &&
           !qos_watermark_value_matches(
               HAL_QOS_WATERMARK_ATTR_TX_HOG, 193, 576));
    expect("jitter and bit attributes remain bit-exact",
           qos_watermark_canonical_value(
               HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER, 7) == 7 &&
           qos_watermark_canonical_value(
               HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE, 1) == 1 &&
           !qos_watermark_value_matches(
               HAL_QOS_WATERMARK_ATTR_SHARED_SOFT_DROP_JITTER, 7, 6) &&
           !qos_watermark_value_matches(
               HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE, 1, 0));
    expect("switch-scoped direct arguments require port zero",
           !qos_watermark_args_valid(&switch_args));

    for (size_t i = 0; i < sizeof(attrs) / sizeof(attrs[0]); i++) {
        hal_qos_watermark_entry entry;
        hal_qos_watermark_transaction_snapshot before;
        hal_qos_watermark_transaction_snapshot invalid;
        fm_uint32 *port_value;
        int requested;

        reset_simulator();
        port_value = watermark_port_value(
            &g_sim.watermark, TEST_PORT,
            qos_watermark_sdk_attr(attrs[i]), 15);
        before = hal_qos_watermark_transaction_snapshot_get(
            0, TEST_PORT, attrs[i], 15);
        requested = *port_value ? 0 : 1;
        expect("attributes 11/12 use a per-port priority-15 SDK slot",
               port_value != NULL &&
               before.state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
               hal_qos_watermark_transaction_apply(
                   0, TEST_PORT, attrs[i], 15, requested,
                   true, false, &before) == 0 &&
               *port_value == (fm_uint32)requested);
        expect("watermark inventory reports attributes 11/12 under their interface",
               hal_qos_watermark_get(0, TEST_PORT, &entry) == 0 &&
               (attrs[i] ==
                    HAL_QOS_WATERMARK_ATTR_TX_SOFT_DROP_ON_PRIVATE ?
                entry.tx_soft_drop_on_private[15] == requested :
                entry.tx_soft_drop_on_rxmp_free[15] == requested));
        invalid = hal_qos_watermark_transaction_snapshot_get(
            0, 0, attrs[i], 15);
        expect("attributes 11/12 reject a switch-scoped port zero",
               invalid.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
               invalid.sdk_status == FM_ERR_INVALID_ARGUMENT);
        invalid = hal_qos_watermark_transaction_snapshot_get(
            0, TEST_PORT, attrs[i], 16);
        expect("attributes 11/12 reject index 16",
               invalid.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
               invalid.sdk_status == FM_ERR_INVALID_ARGUMENT);
    }
}

int main(void) {
    test_storm_snapshot_success_and_absence();
    test_storm_snapshot_fails_closed();
    test_qos_exact_snapshot();
    test_qos_exact_restore();
    test_scheduler_topology_exact_snapshot();
    test_scheduler_topology_exact_restore();
    test_scheduler_group_shaping_exact_snapshot();
    test_scheduler_group_shaping_exact_restore();
    test_scheduler_port_raw_restore_boundaries();
    test_egress_rate_exact_snapshot();
    test_egress_rate_exact_restore();
    test_auto_pause_watermark_exact_snapshot();
    test_auto_pause_trigger_paths_restore_exactly();
    test_auto_pause_watermark_restore_faults_and_retry();
    test_direct_watermark_snapshot_restore();
    test_watermark_restart_baseline_provenance();
    test_watermark_calculator_reconciliation();
    test_watermark_scope_and_canonical_values();
    (void)unlink(NETLAB_QOS_WATERMARK_PROVENANCE_PATH);
    if (g_failed != 0) {
        fprintf(stderr, "%d transaction snapshot checks failed\n", g_failed);
        return 1;
    }
    puts("PASS: transaction snapshots are exact and fail closed");
    return 0;
}
