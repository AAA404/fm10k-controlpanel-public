#include "fm10k_board.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

typedef struct {
    uint8_t mux, reg[9][128][256];
    int drop_reg, drop_count, calls, fail_call, fail_from_call, persistent_fail, target, degraded;
    fm10k_group group[6];
    bool paused[6];
} fixture;
static fixture f;
static int rd(void *ctx, uint8_t addr, int reg, uint8_t *out, size_t n) {
    fixture *s = ctx;
    if (addr == 0x58) { *out = s->mux; return 0; }
    assert(reg >= 0 && n == 1);
    *out = s->reg[s->mux][addr][reg]; return 0;
}
static int wr(void *ctx, uint8_t addr, int reg, const uint8_t *in, size_t n) {
    fixture *s = ctx;
    if (addr == 0x58) { s->mux = *in; return 0; }
    assert(reg >= 0 && n == 1);
    if (reg == s->drop_reg && s->drop_count) {
        --s->drop_count; return 0;
    }
    s->reg[s->mux][addr][reg] = *in; return 0;
}
static void init(void) {
    memset(&f, 0, sizeof(f)); f.mux = 4; f.drop_reg = -1; f.target = -1;
    const int epls[6] = {0,1,2,5,6,7};
    for (int i = 0; i < 6; ++i)
        f.group[i] = (fm10k_group){epls[i], 100, {25,25,25,25}, 1};
    for (int i = 1; i <= 2; ++i) {
        f.reg[i][0x50][56] = 0xaf;
        f.reg[i][0x50][57] = 0xff;
    }
}
static int maybe_fail(fixture *s, int epl) {
    assert(epl == s->target);
    s->calls++;
    if (s->persistent_fail || (s->fail_call && s->calls == s->fail_call) ||
        (s->fail_from_call && s->calls >= s->fail_from_call))
        return -1;
    return 0;
}
static int capture(void *ctx, int epl, fm10k_group *out) {
    fixture *s = ctx; *out = s->group[fm10k_group_index(epl)];
    return maybe_fail(s, epl);
}
static int pause_group(void *ctx, int epl, bool paused) {
    fixture *s = ctx;
    if (maybe_fail(s, epl)) return -1;
    s->paused[fm10k_group_index(epl)] = paused; return 0;
}
static int disable_group(void *ctx, int epl) {
    fixture *s = ctx;
    if (maybe_fail(s, epl)) return -1;
    s->group[fm10k_group_index(epl)].enabled = 0; return 0;
}
static int modes(void *ctx, const fm10k_group *g) {
    fixture *s = ctx;
    if (maybe_fail(s, g->epl)) return -1;
    s->group[fm10k_group_index(g->epl)] = *g; return 0;
}
static int restore(void *ctx, const fm10k_group *g) {
    fixture *s = ctx;
    if (maybe_fail(s, g->epl)) return -1;
    s->group[fm10k_group_index(g->epl)] = *g; return 0;
}
static int verify(void *ctx, const fm10k_group *g) {
    fixture *s = ctx;
    if (maybe_fail(s, g->epl)) return -1;
    return memcmp(g, &s->group[fm10k_group_index(g->epl)], sizeof(*g));
}
static void degraded(void *ctx, int epl) {
    fixture *s = ctx; assert(epl == s->target); s->degraded++;
}
int main(void) {
    fm10k_bus bus = {.context = &f, .read = rd, .write = wr};
    fm10k_group_ops ops = {&f, capture, pause_group, disable_group, modes, restore, verify, degraded};
    fm10k_fan_curve curve = {35,70,80,50,80,4,10900};
    fm10k_lut_point lut[12];
    init();
    assert(fm10k_fan_lut(&curve, lut) == 0);
    assert(lut[0].pwm == 128 && lut[1].celsius == 35);
    assert(lut[5].celsius == 52 && lut[5].pwm == 166);
    assert(lut[10].celsius == 80 && lut[11].pwm == 255);
    assert(fm10k_fan_apply(&bus, &curve) == 0 && f.mux == 4);
    assert(f.reg[8][0x4c][0x4a] == 0x10 && f.reg[8][0x4c][0x45] == 0x13);
    const int responses[] = {5450, 10900, 21600, 43700};
    const int response_registers[] = {0x11, 0x13, 0x15, 0x17};
    for (int i = 0; i < 4; ++i) {
        fm10k_fan_curve changed = curve;
        changed.response_milliseconds = responses[i];
        assert(fm10k_fan_apply(&bus, &changed) == 0);
        assert(f.reg[8][0x4c][0x45] == response_registers[i]);
    }
    init(); f.drop_reg = 0x51; f.drop_count = 1;
    assert(fm10k_fan_apply(&bus, &curve) == FM10K_IO);
    assert(f.reg[8][0x4c][0x4a] == 0x30 && f.reg[8][0x4c][0x4c] == 255 && f.mux == 4);
    init();
    assert(fm10k_tx_update(&bus, 1, 0xf0, 0x50) == 0 && f.mux == 4);
    assert(f.reg[1][0x50][56] == 0xaf && f.reg[1][0x50][57] == 0x5f);
    assert(f.reg[2][0x50][57] == 0xff);
    f.drop_reg = 57; f.drop_count = 2;
    assert(fm10k_tx_update(&bus, 1, 0xf, 0) == 0 && f.drop_count == 0);
    f.drop_count = 50;
    assert(fm10k_tx_update(&bus, 1, 0xf, 0xf) == FM10K_IO && f.mux == 4);
    assert(fm10k_tach_rpm(0, 5400000) == -1);
    assert(fm10k_tach_rpm(65535, 5400000) == -1);
    assert(fm10k_tach_rpm(3600, 5400000) == 1500);
    for (int group = 0; group < 6; ++group) {
        for (int failure = 0; failure <= 7; ++failure) {
            init();
            fm10k_group before[6]; memcpy(before, f.group, sizeof(before));
            fm10k_group target = f.group[group]; target.mode = 0;
            target.enabled = 5; target.lane_gbps[1] = 10;
            f.target = target.epl; f.fail_call = failure;
            int rc = fm10k_group_apply(&bus, &ops, &target);
            assert(rc == (failure ? FM10K_IO : FM10K_OK));
            assert(f.mux == 4);
            for (int i = 0; i < 6; ++i)
                if (i != group || failure)
                    assert(memcmp(&before[i], &f.group[i], sizeof(before[i])) == 0);
            assert(!f.paused[group]);
            assert(f.reg[1 + (group < 3)][0x50][57] == 0xff);
        }
        init();
        f.target = f.group[group].epl;
        for (int iteration = 0; iteration < 100; ++iteration) {
            fm10k_group before[6]; memcpy(before, f.group, sizeof(before));
            fm10k_group target = f.group[group];
            target.mode = iteration % 3 == 0 ? 40 : iteration % 3 == 1 ? 100 : 0;
            target.enabled = target.mode ? 1 : 5;
            target.lane_gbps[0] = 10;
            target.lane_gbps[1] = 25;
            assert(fm10k_group_apply(&bus, &ops, &target) == FM10K_OK);
            for (int i = 0; i < 6; ++i)
                if (i != group)
                    assert(memcmp(&before[i], &f.group[i], sizeof(before[i])) == 0);
            assert(!f.paused[group] && f.mux == 4);
        }
        init();
        fm10k_group before[6]; memcpy(before, f.group, sizeof(before));
        fm10k_group target = f.group[group]; target.mode = 0;
        f.target = target.epl;
        f.fail_from_call = 4;
        assert(fm10k_group_apply(&bus, &ops, &target) == FM10K_ROLLBACK_FAILED);
        assert(f.group[group].enabled == 0 && f.degraded == 1);
        uint16_t tx = 0xffff;
        assert(fm10k_tx_read(&bus, group / 3 + 1, &tx) == 0);
        assert((tx & (15 << ((group % 3) * 4))) == 0);
        for (int i = 0; i < 6; ++i)
            if (i != group)
                assert(memcmp(&before[i], &f.group[i], sizeof(before[i])) == 0);
    }
    init();
    fm10k_fan_state state = {.curve=curve, .curve_valid=true};
    assert(fm10k_fan_manual(&bus, &state, 40, 60, 1000, true, 40) == 0);
    assert(state.manual && state.manual_deadline_ms == 61000);
    assert(fm10k_fan_tick(&bus, &state, 61000, true, 40) == 0);
    assert(!state.manual && f.reg[8][0x4c][0x4a] == 0x10);
    assert(fm10k_fan_tick(&bus, &state, 62000, false, 0) == 0);
    assert(state.failsafe && f.reg[8][0x4c][0x4c] == 255);
    assert(fm10k_fan_tick(&bus, &state, 66000, true, 40) == 0);
    f.drop_reg = 0x4c; f.drop_count = 1;
    assert(fm10k_fan_manual(&bus, &state, 40, 60, 67000, true, 40) == FM10K_IO);
    assert(state.failsafe && !state.manual && state.manual_deadline_ms == 0);
    assert(fm10k_fan_tick(&bus, &state, 68000, true, 40) == 0);
    assert(!state.failsafe && f.reg[8][0x4c][0x4a] == 0x10);
    assert(fm10k_fan_manual(&bus, &state, 40, 60, 69000, true, NAN) == FM10K_INVALID);
    assert(fm10k_fan_tick(&bus, &state, 69000, true, NAN) == 0);
    assert(state.failsafe && f.reg[8][0x4c][0x4c] == 255);
    puts("native board HAL: masks, LUT, failures, six-EPL isolation and timers passed");
    return 0;
}
