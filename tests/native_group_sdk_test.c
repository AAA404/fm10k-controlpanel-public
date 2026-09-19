#define FM10K_FCI_FIXTURE_ONLY
#include "native_fci_test.c"

static int target_epl, degraded_groups;
static bool paused, fail_pause, fail_resume;
static int group_pause(void *unused, int epl, bool value) {
    (void)unused;
    assert(epl == target_epl && !lock_stage);
    if (value) paused = true;
    if ((value && fail_pause) || (!value && fail_resume)) return FM10K_IO;
    paused = value;
    return FM10K_OK;
}
static void group_degraded(void *unused, int epl) {
    (void)unused;
    assert(epl == target_epl);
    ++degraded_groups;
}
static const netlab_fm10k_group_control control = {NULL, group_pause, group_degraded};
static void begin(int index) {
    configure();
    group_write_base = index * 4 + 1;
    target_epl = inventory[group_write_base - 1].epl_port;
    paused = fail_pause = fail_resume = false;
    degraded_groups = 0;
}
static void unchanged_others(int index, const fm_ethMode modes[30], const fm_int admins[30],
                              const uint16_t tx[2]) {
    for (int p = 1; p <= 24; ++p) {
        if ((p - 1) / 4 == index) continue;
        assert(runtime_modes[p] == modes[p] && admin_modes[p] == admins[p]);
    }
    int mpo = index / 3 + 1;
    uint16_t mask = (uint16_t)(15U << (index % 3 * 4));
    assert(!((enabled(mpo) ^ tx[mpo - 1]) & ~mask));
    assert(enabled(3 - mpo) == tx[2 - mpo]);
    assert(!unexpected_xcvr_writer && fake_mux == 4 && !lock_stage);
    for (int module = 1; module <= 2; ++module)
        assert((registers[module][0x50][56] & 0xf0) == 0xa0 && registers[module][0x50][86] == 0x69);
}
int main(void) {
    for (int index = 0; index < 6; ++index) {
        begin(index);
        for (int cycle = 0; cycle < 100; ++cycle) {
            fm10k_group before, after;
            assert(!netlab_fm10k_group_sdk_get(0, target_epl, &before));
            fm10k_group desired = before;
            desired.mode = cycle % 3 == 0 ? 100 : cycle % 3 == 1 ? 40 : 0;
            desired.lane_gbps[0] = desired.lane_gbps[2] = 10;
            desired.lane_gbps[1] = desired.lane_gbps[3] = 25;
            desired.enabled = desired.mode ? 1 : 5;
            fm_ethMode modes[30]; fm_int admins[30];
            memcpy(modes, runtime_modes, sizeof(modes)); memcpy(admins, admin_modes, sizeof(admins));
            const uint16_t tx[] = {enabled(1), enabled(2)};
            assert(!netlab_fm10k_group_sdk_apply(0, &desired, &before, &control));
            assert(!netlab_fm10k_group_sdk_get(0, target_epl, &after));
            assert(fm10k_group_equal(&after, &desired) && !paused && !degraded_groups);
            unchanged_others(index, modes, admins, tx);
        }
        /* Fail each mode call before and after mutation. Restore the exact
         * runtime group even though its boot preferences never changed. */
        for (int after_write = 0; after_write < 2; ++after_write) {
            for (int fail = 1; fail <= 5; ++fail) {
                begin(index);
                fm10k_group before, after;
                assert(!netlab_fm10k_group_sdk_get(0, target_epl, &before));
                fm10k_group desired = before; desired.mode = 100; desired.enabled = 1;
                fail_mode_call = fail; mode_fail_after = after_write != 0;
                assert(netlab_fm10k_group_sdk_apply(0, &desired, &before, &control) == FM10K_IO);
                assert(!netlab_fm10k_group_sdk_get(0, target_epl, &after));
                assert(fm10k_group_equal(&before, &after) && !paused && !degraded_groups);
                assert(enabled(1) == 0xfff && enabled(2) == 0xfff && !unexpected_xcvr_writer);
            }
        }
        begin(index);
        fm10k_group before, after;
        assert(!netlab_fm10k_group_sdk_get(0, target_epl, &before));
        fm10k_group desired = before; desired.mode = 40; desired.enabled = 1;
        drop_mode_call = 3;
        assert(netlab_fm10k_group_sdk_apply(0, &desired, &before, &control) == FM10K_IO);
        assert(!netlab_fm10k_group_sdk_get(0, target_epl, &after) && fm10k_group_equal(&before, &after));
        begin(index);
        fail_mode_from = 2;
        assert(netlab_fm10k_group_sdk_apply(0, &desired, &before, &control) == FM10K_ROLLBACK_FAILED);
        assert(paused && degraded_groups == 1);
        assert(!(enabled(index / 3 + 1) & (15U << (index % 3 * 4))));
        for (int lane = 0; lane < 4; ++lane)
            assert(admin_modes[group_write_base + lane] == FM_PORT_MODE_ADMIN_PWRDOWN);
    }
    begin(0);
    fm10k_group before, after;
    assert(!netlab_fm10k_group_sdk_get(0, 0, &before));
    fm10k_group desired = before; desired.mode = 100; desired.enabled = 1;
    fail_pause = true;
    assert(netlab_fm10k_group_sdk_apply(0, &desired, &before, &control) == FM10K_IO);
    assert(!paused && !sdk_admin_calls && !mode_calls);
    fail_resume = true;
    assert(netlab_fm10k_group_sdk_apply(0, &desired, &before, &control) == FM10K_ROLLBACK_FAILED);
    assert(paused && degraded_groups == 1 && (enabled(1) & 15) == 0 && enabled(2) == 0xfff);
    begin(0);
    before.enabled = 0; /* A stale expected before-image cannot authorize writes. */
    int n = sdk_admin_calls;
    assert(netlab_fm10k_group_sdk_apply(0, &desired, &before, &control) == FM10K_IO && sdk_admin_calls == n);
    assert(!netlab_fm10k_group_sdk_get(0, 0, &after) && after.enabled == 15);
    puts("SDK EPL modes: 600 isolated transitions, partial writes, stale images and local compensation passed");
    return 0;
}
