/* Exercise the production SDK adapter without initializing any device. */
#include "../vendor/netlab/sbin/switchd/hal_qos.c"
#include <assert.h>

static fm_uint32 actual_map[8];
static fm_uint32 actual_dscp[64];
static int cardinal_count = 30, writes, fail_read, fail_after_write, drop_write;
static fm_bool automatic = TRUE;
static fm_uint32 pause_on = 512000, pause_off = 256000;
static int multiple_destinations;
static fm_uint32 pc3_smp = 2;

bool nl_ifid_is_user_port(int port) { return port >= 1 && port <= 24; }
fm_status fmGetLogicalPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(!sw && port == 13 && attr == FM_LPORT_DEST_MASK);
    fm_portmask *mask = out;
    mask->maskWord[0] = (1U << 20) | (multiple_destinations ? 1U << 21 : 0);
    return FM_OK;
}
fm_status fmReadUncachedUINT64Mult(fm_int sw, fm_uint reg, fm_int n, fm_uint64 *out) {
    assert(!sw && reg == 0xE61400U + 4U * 20 && n == 2);
    if (fail_read) return FM_FAIL;
    out[0] = (fm_uint64)0x1234 << 48; out[1] = (fm_uint64)10 << 32;
    return FM_OK;
}
fm_status fmReadUncachedUINT32(fm_int sw, fm_uint reg, fm_uint32 *out) {
    assert(!sw && (reg == 0xE612C0U + 20 || reg == 0xE60800U + 20));
    *out = reg == 0xE60800U + 20 ? 8 : 2;
    return FM_OK;
}
fm_status fmGetPortQOS(fm_int sw, fm_int port, fm_int attr, fm_int index, void *out) {
    if (attr == FM_QOS_PC_RXMP_MAP) {
        assert(!sw && port == 13 && index == 3);
        if (fail_read) return FM_FAIL;
        *(fm_uint32 *)out = pc3_smp; return FM_OK;
    }
    assert(!sw && port == 13 && attr == FM_QOS_TX_TC_USAGE && index == 7);
    *(fm_uint32 *)out = 192; return FM_OK;
}

fm_status fmSetPortQOS(fm_int sw, fm_int port, fm_int attr, fm_int index, void *value) {
    assert(!sw && port == 13 && attr == FM_QOS_PC_RXMP_MAP && index == 3);
    writes++;
    if (!drop_write) pc3_smp = *(fm_uint32 *)value;
    return fail_after_write ? FM_FAIL : FM_OK;
}

fm_status fmGetCardinalPortList(fm_int sw, fm_int *count, fm_int *ports, fm_int capacity) {
    assert(sw == 0 && capacity >= cardinal_count);
    *count = cardinal_count;
    for (int i = 0; i < *count; i++) ports[i] = i;
    return FM_OK;
}
fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(sw == 0 && port >= 0 && attr == FM_PORT_MAX_FRAME_SIZE);
    *(fm_int *)out = 1540;
    return FM_OK;
}
fm_status fmGetSwitchAttribute(fm_int sw, fm_int attr, void *out) {
    assert(sw == 0 && attr == FM_MTU_LIST);
    fm_mtuEntry *entry = out;
    assert(entry->index < 8);
    entry->mtu = 1540;
    return FM_OK;
}
fm_status fmGetSwitchQOS(fm_int sw, fm_int attr, fm_int index, void *out) {
    assert(sw == 0);
    if (fail_read) return FM_FAIL;
    switch (attr) {
    case FM_AUTO_PAUSE_MODE: *(fm_bool *)out = automatic; break;
    case FM_QOS_PRIV_WM: *(fm_uint32 *)out = 4669440; break;
    case FM_QOS_SHARED_PAUSE_ON_WM: *(fm_uint32 *)out = pause_on; break;
    case FM_QOS_SHARED_PAUSE_OFF_WM: *(fm_uint32 *)out = pause_off; break;
    case FM_QOS_TC_SMP_MAP: *(fm_uint32 *)out = actual_map[index]; break;
    case FM_QOS_DSCP_SWPRI_MAP: assert(index >= 0 && index < 64); *(fm_uint32 *)out = actual_dscp[index]; break;
    default: assert(false);
    }
    return FM_OK;
}
fm_status fmSetSwitchQOS(fm_int sw, fm_int attr, fm_int index, void *value) {
    assert(sw == 0);
    if (attr == FM_QOS_DSCP_SWPRI_MAP) {
        assert(index >= 0 && index < 64);
        writes++;
        if (!drop_write) actual_dscp[index] = *(fm_uint32 *)value;
        return fail_after_write ? FM_FAIL : FM_OK;
    }
    assert(attr == FM_QOS_TC_SMP_MAP && index >= 0 && index < 8);
    writes++;
    if (!drop_write) actual_map[index] = *(fm_uint32 *)value;
    return fail_after_write ? FM_FAIL : FM_OK;
}

int main(void) {
    for (int i = 0; i < 8; i++) actual_map[i] = FM_QOS_TC_SMP_0;
    assert(!hal_qos_roce_buffer_ready(0));
    assert(!hal_qos_tc_smp_set(0, 3, 1));
    int value = -1;
    assert(!hal_qos_tc_smp_get(0, 3, &value) && value == 1);
    assert(!hal_qos_tc_smp_set(0, 3, 0));
    fail_after_write = 1;
    assert(hal_qos_tc_smp_set(0, 3, 1) == FM_FAIL);
    assert(actual_map[3] == FM_QOS_TC_SMP_1); /* engine must compensate */
    fail_after_write = 0;
    assert(!hal_qos_tc_smp_set(0, 3, 0));
    drop_write = 1;
    assert(hal_qos_tc_smp_set(0, 3, 1) != FM_OK);
    drop_write = 0;
    int before = writes;
    automatic = FALSE;
    assert(hal_qos_tc_smp_set(0, 3, 1) != FM_OK && writes == before);
    automatic = TRUE;
    pause_on = 6291264; /* lossy defaults are not valid PFC thresholds */
    assert(hal_qos_tc_smp_set(0, 3, 1) != FM_OK && writes == before);
    pause_on = pause_off;
    assert(hal_qos_roce_buffer_ready(0) != FM_OK);
    pause_on = 512000;
    cardinal_count = 31;
    assert(hal_qos_roce_buffer_ready(0) != FM_OK);
    cardinal_count = 30;
    fail_read = 1;
    assert(hal_qos_tc_smp_get(0, 3, &value) == FM_FAIL);
    assert(hal_qos_tc_smp_set(0, 3, 1) == FM_FAIL && writes == before);
    fail_read = 0;
    assert(!hal_qos_dscp_set(0, 26, 3) && !hal_qos_dscp_set(0, 48, 6));
    int dscp[64];
    assert(hal_qos_dscp_list(0, dscp) == 64 && dscp[26] == 3 && dscp[48] == 6 && dscp[0] == 0);
    before = writes;
    assert(hal_qos_dscp_set(0, 64, 3) != FM_OK && hal_qos_dscp_set(0, 26, 16) != FM_OK && writes == before);
    drop_write = 1;
    assert(hal_qos_dscp_set(0, 26, 5) != FM_OK && actual_dscp[26] == 3);
    drop_write = 0; fail_after_write = 1;
    assert(hal_qos_dscp_set(0, 26, 5) != FM_OK && actual_dscp[26] == 5);
    fail_after_write = 0; fail_read = 1;
    assert(hal_qos_dscp_list(0, dscp) < 0);
    fail_read = 0;
    hal_qos_flow_control_entry flow = {.port=13};
    assert(!hal_qos_pause_state_get(0,&flow) && flow.pause_state_status == 0);
    assert(flow.rx_pause_quanta[3] == 0x1234 && flow.rx_pause_quanta[6] == 10);
    assert(flow.paused_class_mask == 0x48 && flow.generated_smp_pause_mask == 2 && flow.cnp_tc_usage == 192);
    assert(flow.rx_class_mask_hardware == 8);
    fail_read = 1;
    assert(hal_qos_pause_state_get(0,&flow) != 0 && flow.paused_class_mask == -1 && flow.rx_pause_quanta[3] == -1);
    fail_read = 0; multiple_destinations = 1;
    assert(hal_qos_pause_state_get(0,&flow) != 0);
    assert(!hal_qos_pfc_pc3_smp_set(0,13,1) && pc3_smp == 1);
    drop_write = 1;
    assert(hal_qos_pfc_pc3_smp_set(0,13,2) != FM_OK && pc3_smp == 1);
    drop_write = 0; fail_after_write = 1;
    assert(hal_qos_pfc_pc3_smp_set(0,13,2) == FM_FAIL && pc3_smp == 2);
    fail_after_write = 0;
    assert(!hal_qos_pfc_pc3_smp_set(0,13,0) && pc3_smp == 0); /* exact compensation */
    before = writes;
    assert(hal_qos_pfc_pc3_smp_set(0,13,3) != FM_OK && before == writes);
    puts("RoCE SDK budget, DSCP and PFC generation maps, partial write and failure gating passed");
    return 0;
}
