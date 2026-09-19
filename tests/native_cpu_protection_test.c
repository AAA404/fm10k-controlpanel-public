#include <assert.h>
#include <stdio.h>
#include "../vendor/netlab/sbin/switchd/hal_cpu_protection.c"

static hal_cpu_protection_state hardware;
static int cpu_port, reads, writes, fail_read, fail_write, wrong_port_writes;
static bool corrupt_rate;

void nl_log_write(nl_log_level level, const char *file, int line, const char *fmt, ...) {
    (void)level; (void)file; (void)line; (void)fmt;
}
bool nl_ifid_is_cpu_port(int port) { return port == 27; }
bool nl_ifid_is_user_port(int port) { return port >= 1 && port <= 24; }
fm_status fmGetCpuPort(fm_int sw, fm_int *port) {
    assert(sw == 0);
    *port = cpu_port;
    return FM_OK;
}
fm_status fmGetPortQOS(fm_int sw, fm_int port, fm_int attr, fm_int index, void *out) {
    assert(sw == 0 && port == 27);
    if (++reads == fail_read) return FM_FAIL;
    switch (attr) {
    case FM_QOS_SHAPING_GROUP_RATE:
        assert(index == 0); *(fm_uint64 *)out = hardware.rate_bps; break;
    case FM_QOS_SHAPING_GROUP_MAX_BURST:
        assert(index == 0); *(fm_uint64 *)out = hardware.burst_bits; break;
    case FM_QOS_TC_SHAPING_GROUP_MAP:
        assert(index >= 0 && index < 8); *(fm_uint32 *)out = hardware.tc_group[index]; break;
    default: assert(0);
    }
    return FM_OK;
}
fm_status fmSetPortQOS(fm_int sw, fm_int port, fm_int attr, fm_int index, void *value) {
    assert(sw == 0);
    ++writes;
    if (port != 27) ++wrong_port_writes;
    assert(port == 27);
    /* A failed SDK response may follow a latched write. */
    switch (attr) {
    case FM_QOS_SHAPING_GROUP_RATE:
        assert(index == 0);
        hardware.rate_bps = *(fm_uint64 *)value;
        if (hardware.rate_bps == HAL_CPU_PROTECTION_RATE_BPS && corrupt_rate)
            hardware.rate_bps = 0;
        break;
    case FM_QOS_SHAPING_GROUP_MAX_BURST:
        assert(index == 0); hardware.burst_bits = *(fm_uint64 *)value; break;
    case FM_QOS_TC_SHAPING_GROUP_MAP:
        assert(index >= 0 && index < 8); hardware.tc_group[index] = *(fm_uint32 *)value; break;
    default: assert(0);
    }
    return writes == fail_write ? FM_FAIL : FM_OK;
}

static void reset(void) {
    memset(&hardware, 0, sizeof(hardware));
    hardware.port = cpu_port = 27;
    hardware.rate_bps = FM_QOS_SHAPING_GROUP_RATE_DEFAULT;
    hardware.burst_bits = 67100672;
    for (int i = 0; i < 8; ++i) hardware.tc_group[i] = (u32)(1 + i % 7);
    reads = writes = wrong_port_writes = fail_read = fail_write = 0;
    corrupt_rate = false;
}

int main(void) {
    reset();
    assert(hal_cpu_protection_init(0) == FM_OK && writes == 10);
    assert(hal_cpu_protection_matches(&hardware) && !wrong_port_writes);
    int first = writes;
    assert(hal_cpu_protection_init(0) == FM_OK && writes == first);
    puts("PASS: all CPU traffic classes share a verified aggregate bound; replay is read-only");

    for (int i = 1; i <= 10; ++i) {
        reset();
        fail_read = i;
        assert(hal_cpu_protection_init(0) != FM_OK && writes == 0);
    }
    for (int i = 1; i <= 10; ++i) {
        reset();
        hal_cpu_protection_state before = hardware;
        fail_write = i;
        assert(hal_cpu_protection_init(0) != FM_OK);
        assert(memcmp(&before, &hardware, sizeof(before)) == 0 && !wrong_port_writes);
    }
    for (int i = 11; i <= 20; ++i) {
        reset();
        hal_cpu_protection_state before = hardware;
        fail_read = i;
        assert(hal_cpu_protection_init(0) != FM_OK);
        assert(memcmp(&before, &hardware, sizeof(before)) == 0);
    }
    puts("PASS: every partial snapshot, latched write failure and readback failure rejects startup and restores CPU state");

    reset();
    hal_cpu_protection_state before = hardware;
    corrupt_rate = true;
    assert(hal_cpu_protection_init(0) != FM_OK);
    assert(memcmp(&before, &hardware, sizeof(before)) == 0);
    reset(); cpu_port = 1;
    assert(hal_cpu_protection_init(0) != FM_OK && writes == 0);
    reset(); cpu_port = 28;
    assert(hal_cpu_protection_init(0) != FM_OK && writes == 0);
    reset(); hardware.tc_group[7] = 8;
    assert(hal_cpu_protection_init(0) != FM_OK && writes == 0);
    puts("PASS: zero rate, external/unknown CPU ownership and invalid TC maps cannot pass verification");
    return 0;
}
