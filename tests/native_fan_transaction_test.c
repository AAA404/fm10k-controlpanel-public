#define FM10K_SAMPLING_FIXTURE_ONLY
#include "native_sampling_test.c"
#include "fm10k_monitor.h"

static fm10k_bus bus;
static fm10k_monitor monitor;
static const fm10k_fan_curve curve = {35, 70, 80, 50, 80, 4, 10900};
static void initialize(bool configured) {
    reset();
    bus = (fm10k_bus){.context = &f, .read = read_bytes, .write = write_bytes,
        .enter = enter, .leave = leave, .delay_ms = delay};
    fm10k_monitor_init(&monitor, &bus);
    assert(!fm10k_fan_full(&bus));
    if (configured) {
        fm10k_fan_snapshot before;
        assert(!fm10k_monitor_fan_capture(&monitor, &before));
        assert(!fm10k_monitor_fan_apply(&monitor, &curve, &before, 1000));
        assert(monitor.fan.failsafe && f.registers[8][0x4c][0x4a] == 0x30);
        assert(!fm10k_monitor_step(&monitor, 1000, 100));
        assert(!monitor.fan.failsafe && f.registers[8][0x4c][0x4a] == 0x10);
    }
}
static void isolated(void) {
    assert(!f.locked && f.enters == f.leaves);
    for (int mpo = 1; mpo <= 2; ++mpo) {
        assert(f.registers[mpo][0x50][56] == (0xa0 | mpo));
        assert(f.registers[mpo][0x50][57] == 0x12 && f.registers[mpo][0x50][0x7f] == 3);
    }
}
int main(void) {
    fm10k_fan_snapshot before, after;
    initialize(false);
    assert(!fm10k_monitor_fan_capture(&monitor, &before) && !before.curve_valid);
    assert(!fm10k_monitor_fan_apply(&monitor, &curve, &before, 1000));
    assert(!fm10k_monitor_fan_restore(&monitor, &before, 1000));
    assert(!fm10k_monitor_fan_capture(&monitor, &after) && fm10k_fan_snapshot_equal(&before, &after));
    assert(f.registers[8][0x4c][0x4a] == 0x30 && f.registers[8][0x4c][0x4c] == 255);
    isolated();
    fm10k_fan_curve target = curve; target.idle_pwm = 60; target.response_milliseconds = 21600;
    for (int fail = 1; fail <= 160; ++fail) {
        initialize(true);
        assert(!fm10k_monitor_fan_capture(&monitor, &before));
        f.fail_at = f.transfers + fail;
        int rc = fm10k_monitor_fan_apply(&monitor, &target, &before, 1100);
        f.fail_at = 0;
        assert(!fm10k_monitor_fan_capture(&monitor, &after));
        if (rc) assert(rc == FM10K_IO && fm10k_fan_snapshot_equal(&before, &after));
        else assert(fm10k_fan_curve_equal(&after.curve, &target));
        isolated();
    }
    initialize(true);
    assert(!fm10k_monitor_fan_capture(&monitor, &before));
    assert(!fm10k_monitor_manual(&monitor, 30, 1, 1100));
    int transfers = f.transfers;
    assert(fm10k_monitor_fan_capture(&monitor, &after) == FM10K_INVALID && f.transfers == transfers);
    assert(fm10k_monitor_fan_apply(&monitor, &target, &before, 1200) == FM10K_IO && f.transfers == transfers);
    assert(!fm10k_monitor_step(&monitor, 2100, 101.1));
    assert(!fm10k_monitor_fan_apply(&monitor, &target, &before, 2200));
    assert(fm10k_monitor_fan_apply(&monitor, &curve, &before, 2300) == FM10K_IO); /* stale CAS */
    /* Safety override remains active while an older LUT is restored. */
    monitor.temperatures[0].value = 90;
    assert(!fm10k_monitor_fan_restore(&monitor, &before, 2400));
    assert(monitor.fan.failsafe && f.registers[8][0x4c][0x4c] == 255);
    assert(!fm10k_monitor_fan_capture(&monitor, &after) && fm10k_fan_snapshot_equal(&before, &after));
    isolated();
    initialize(true);
    assert(!fm10k_monitor_fan_capture(&monitor, &before));
    f.fail_from = f.transfers + 50;
    assert(fm10k_monitor_fan_apply(&monitor, &target, &before, 1100) == FM10K_ROLLBACK_FAILED);
    assert(monitor.fan.failsafe && !monitor.fan.manual);
    assert(f.registers[8][0x4c][0x4a] == 0x30 && f.registers[8][0x4c][0x4c] == 255);
    isolated();
    puts("fan transactions: startup replay, 160 transfer faults, raw LUT restore, CAS and thermal protection passed");
    return 0;
}
