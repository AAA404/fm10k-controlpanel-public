#define FM10K_SAMPLING_FIXTURE_ONLY
#include "native_sampling_test.c"
#include "fm10k_monitor.h"

int main(void) {
    fm10k_bus b = {.context = &f, .read = read_bytes, .write = write_bytes,
        .enter = enter, .leave = leave, .delay_ms = delay};
    fm10k_monitor monitor;
    const fm10k_fan_curve curve = {35, 70, 80, 50, 80, 4, 10900};
    char output[4096];
    reset();
    fm10k_monitor_init(&monitor, &b);
    assert(!f.transfers);
    assert(fm10k_monitor_format(&monitor, 1000, 100, output, sizeof(output)) > 0);
    assert(strstr(output, "\"celsius\":null") && strstr(output, "\"profile\":\"unknown\"") && !f.transfers);
    strcpy(monitor.profile, "sil001-hw5-a11");
    assert(fm10k_monitor_format(&monitor, 1000, 100, output, sizeof(output)) > 0);
    assert(strstr(output, "\"profile\":\"sil001-hw5-a11\"") && !f.transfers);
    strcpy(monitor.profile, "sil001-hw4-b0");
    assert(!fm10k_monitor_curve(&monitor, &curve));
    assert(!fm10k_monitor_step(&monitor, 1000, 100));
    assert(monitor.temperatures[0].valid && monitor.temperatures[0].value == 45.125);
    assert(!fm10k_monitor_step(&monitor, 1001, 100.001));
    assert(!fm10k_monitor_step(&monitor, 1002, 100.002));
    const char identity_text[] = "FCI MergeOptics  10124588-211";
    for (int mpo = 1; mpo <= 2; ++mpo)
        memcpy(f.registers[mpo][0x50] + 128, identity_text, sizeof(identity_text) - 1);
    for (unsigned i = 0; i < 22; ++i) {
        int before = f.transfers;
        assert(!fm10k_monitor_step(&monitor, 1100 + i, 100.1 + i / 1000.0));
        assert(f.transfers - before < 16); /* exactly one bounded identity chunk */
        assert(!f.locked && f.mux == 4);
    }
    assert(monitor.identity_valid[0] && monitor.identity_valid[1]);
    int before = f.transfers;
    for (int i = 0; i < 100; ++i)
        assert(fm10k_monitor_format(&monitor, 1500, 100.5, output, sizeof(output)) > 0);
    assert(f.transfers == before);
    assert(strstr(output, "10124588-211") && strstr(output, "\"board_hal\":\"unbound\""));
    assert(strstr(output, "\"rpm\":1512") && strstr(output, "\"tach_source\":\"cpld\""));
    assert(fm10k_monitor_format(&monitor, 20000, 119, output, sizeof(output)) > 0);
    assert(strstr(output, "\"rpm\":null")); /* An old count is not a current speed. */
    assert(fm10k_monitor_format(&monitor, 1500, 100.5, output, sizeof(output)) > 0);
    puts(output);
    assert(!fm10k_monitor_manual(&monitor, 25, 1, 1500));
    assert(f.registers[8][0x4c][0x4a] == 0x30 && monitor.fan.manual);
    assert(!fm10k_monitor_step(&monitor, 2500, 101.5));
    assert(!monitor.fan.manual && f.registers[8][0x4c][0x4a] == 0x10);
    f.registers[8][0x4c][0x01] = 90;
    assert(!fm10k_monitor_step(&monitor, 6000, 105));
    assert(monitor.fan.failsafe && f.registers[8][0x4c][0x4c] == 255);
    assert(fm10k_monitor_manual(&monitor, 25, 60, 6001) == FM10K_INVALID);
    f.registers[8][0x4c][0x01] = 79;
    assert(!fm10k_monitor_step(&monitor, 12000, 111) && monitor.fan.failsafe);
    f.registers[8][0x4c][0x01] = 75;
    assert(!fm10k_monitor_step(&monitor, 18000, 117) && !monitor.fan.failsafe);
    assert(fm10k_monitor_manual(&monitor, 25, 60, 40000) == FM10K_INVALID);
    /* A failed sample keeps the original sample time, never a fresh stamp
     * on an old reading. A failed manual restore enters full-speed recovery. */
    f.drop_mux = 1;
    assert(fm10k_monitor_step(&monitor, 40000, 139) == FM10K_IO);
    assert(fm10k_monitor_format(&monitor, 40000, 139, output, sizeof(output)) > 0);
    assert(strstr(output, "\"quality\":\"stale\"") && monitor.temperatures[0].sampled_at == 117);
    f.drop_mux = 0;
    assert(!fm10k_monitor_step(&monitor, 46000, 145));
    assert(!fm10k_monitor_manual(&monitor, 30, 10, 46000));
    assert(!fm10k_monitor_shutdown(&monitor) && !monitor.fan.manual);
    assert(f.registers[8][0x4c][0x4a] == 0x10);
    fm10k_fan_curve target = curve; target.idle_pwm = 60;
    f.fail_at = f.transfers + 20;
    assert(fm10k_monitor_curve(&monitor, &target) == FM10K_IO);
    assert(monitor.fan.curve.idle_pwm == 50 && !monitor.fan.manual);
    assert(fm10k_monitor_format(&monitor, 46000, 145, output, 2) == FM10K_INVALID);
    return 0;
}
