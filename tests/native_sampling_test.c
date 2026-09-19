#include "fm10k_board.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t mux, registers[9][128][256];
    int enters, leaves, transfers, fail_at, fail_from, fail_enter, fail_leave;
    int drop_mux, drop_page, locked, delays;
} fixture;
static fixture f;
static int enter(void *ctx) {
    fixture *s = ctx;
    assert(!s->locked);
    ++s->enters;
    if (s->fail_enter) return FM10K_IO;
    s->locked = 1;
    return 0;
}
static int leave(void *ctx) {
    fixture *s = ctx;
    assert(s->locked);
    ++s->leaves; s->locked = 0;
    return s->fail_leave ? FM10K_IO : 0;
}
static int transfer(fixture *s) {
    assert(s->locked);
    ++s->transfers;
    return s->transfers == s->fail_at || (s->fail_from && s->transfers >= s->fail_from) ? FM10K_IO : 0;
}
static int read_bytes(void *ctx, uint8_t addr, int reg, uint8_t *out, size_t n) {
    fixture *s = ctx;
    if (transfer(s)) return FM10K_IO;
    if (addr == 0x58) { assert(n == 1 && reg == -1); *out = s->mux; return 0; }
    assert(reg >= 0 && n <= 12);
    memcpy(out, s->registers[s->mux][addr] + reg, n);
    return 0;
}
static int write_bytes(void *ctx, uint8_t addr, int reg, const uint8_t *in, size_t n) {
    fixture *s = ctx;
    if (transfer(s)) return FM10K_IO;
    if (addr == 0x58) { if (!s->drop_mux) s->mux = *in; return 0; }
    assert(n == 1 && reg >= 0);
    if (!s->drop_page || reg != 0x7f) s->registers[s->mux][addr][reg] = *in;
    return 0;
}
static void delay(void *ctx, unsigned ms) {
    fixture *s = ctx; assert(s->locked && ms == 30); ++s->delays;
}
static void reset(void) {
    memset(&f, 0, sizeof(f)); f.mux = 4;
    f.registers[8][0x4c][0x01] = 45;
    f.registers[8][0x4c][0x10] = 0x20;
    f.registers[8][0x4c][0x4a] = 0x10;
    f.registers[8][0x4c][0x4c] = 128;
    f.registers[8][0x4c][0x03] = 0x06;
    f.registers[8][0x4c][0x46] = 0xf3;
    f.registers[8][0x4c][0x47] = 0x0d;
    f.registers[8][0x59][0xa3] = 0xf3;
    f.registers[8][0x59][0xa4] = 0x0d;
    for (int mpo = 1; mpo <= 2; ++mpo) {
        f.registers[mpo][0x50][0x16] = 30 + mpo;
        f.registers[mpo][0x50][0x17] = 0x80;
        f.registers[mpo][0x50][56] = 0xa0 | mpo;
        f.registers[mpo][0x50][57] = 0x12;
        f.registers[mpo][0x50][0x7f] = 3;
        memcpy(f.registers[mpo][0x50] + 0x80, "FCI MergeOpt", 12);
    }
}
#ifndef FM10K_SAMPLING_FIXTURE_ONLY
int main(void) {
    fm10k_bus b = {.context = &f, .read = read_bytes, .write = write_bytes,
        .enter = enter, .leave = leave, .delay_ms = delay};
    fm10k_fan_sample fan;
    fm10k_obt_sample obt;
    uint8_t identity[12];
    reset();
    assert(!fm10k_fan_read(&b, &fan));
    assert(fan.core_valid && fan.core_c == 45.125 && fan.pwm_valid && fan.pwm == 128);
    assert(fan.tach_valid && fan.tach_count == 0x0df3 && fm10k_tach_rpm(fan.tach_count, 5400000) == 1512);
    assert(fan.tach_source == FM10K_TACH_CPLD && fan.tach_shadow_matches);
    assert(f.mux == 4 && f.enters == f.leaves && !f.locked);
    f.registers[8][0x59][0xa3] = f.registers[8][0x59][0xa4] = 0xff;
    assert(!fm10k_fan_read(&b, &fan) && fan.tach_valid && fan.tach_source == FM10K_TACH_LM96163);
    f.registers[8][0x59][0xa3] = 0xa3; f.registers[8][0x59][0xa4] = 0xa4;
    assert(!fm10k_fan_read(&b, &fan) && fan.tach_count == 0x0df3 && !fan.tach_shadow_matches);
    f.registers[8][0x4c][0x46] = f.registers[8][0x4c][0x47] = 0xff;
    assert(!fm10k_fan_read(&b, &fan) && !fan.tach_valid && fan.tach_count == 0xffff);
    assert(fan.cpld_tach_count == 0xa4a3); /* A stable shadow cannot invent an RPM. */
    f.registers[8][0x4c][0x46] = 0xf3; f.registers[8][0x4c][0x47] = 0x0d;
    f.registers[8][0x4c][0x03] = 0x02;
    assert(!fm10k_fan_read(&b, &fan) && !fan.tach_valid);
    f.registers[8][0x4c][0x03] = 0x46;
    assert(!fm10k_fan_read(&b, &fan) && !fan.tach_valid);
    f.registers[8][0x4c][0x03] = 0x06;
    f.registers[8][0x4c][0x01] = 0x80;
    assert(fm10k_fan_read(&b, &fan) == FM10K_IO && !fan.core_valid);
    for (int mpo = 1; mpo <= 2; ++mpo) {
        assert(!fm10k_obt_read(&b, mpo, &obt));
        assert(obt.temperature_valid && obt.temperature_c == 30.5 + mpo);
        assert(obt.tx_valid && obt.tx_enabled == ((mpo << 8) | 0x12));
        assert(f.mux == 4);
        assert(!fm10k_obt_identity_read(&b, mpo, 128, identity, 12));
        assert(!memcmp(identity, "FCI MergeOpt", 12));
        assert(f.registers[mpo][0x50][0x7f] == 3 && f.mux == 4);
    }
    reset(); f.drop_mux = 1;
    assert(fm10k_obt_read(&b, 1, &obt) == FM10K_IO && !obt.tx_valid);
    assert(f.enters == f.leaves && !f.locked && f.mux == 4);
    reset(); f.drop_page = 1;
    memset(identity, 0xee, sizeof(identity));
    assert(fm10k_obt_identity_read(&b, 1, 128, identity, 12) == FM10K_IO);
    assert(identity[0] == 0xee && f.mux == 4 && !f.locked);
    /* Every failing transfer must leave the bus lease balanced; failed
     * restore does not publish data from an uncertain selection. */
    for (int fail = 1; fail <= 12; ++fail) {
        reset(); f.fail_at = fail;
        (void)fm10k_obt_identity_read(&b, 2, 128, identity, 12);
        assert(!f.locked && f.enters == f.leaves);
    }
    reset(); f.fail_enter = 1;
    assert(fm10k_fan_read(&b, &fan) == FM10K_IO && !f.transfers && !f.leaves);
    reset(); f.fail_leave = 1;
    assert(fm10k_fan_read(&b, &fan) == FM10K_IO && !fan.core_valid && !fan.tach_valid);
    puts("board sampling, mux/page restoration and fault ownership passed");
    return 0;
}
#endif
