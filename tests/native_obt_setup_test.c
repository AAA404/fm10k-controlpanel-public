#define FM10K_SAMPLING_FIXTURE_ONLY
#include "native_sampling_test.c"

static int setup_writes, fail_write, drop_attempts, bad_restore, failed_reg;
static int setup_write(void *ctx, uint8_t address, int reg, const uint8_t *in, size_t n) {
    if (address == 0x58) return write_bytes(ctx, address, reg, in, n);
    assert((address == 0x50 || address == 0x40) && n == 1);
    assert(reg != 0x7f && !(address == 0x50 && (reg == 56 || reg == 57)));
    ++setup_writes;
    if (drop_attempts && reg == 43 && address == 0x40) { --drop_attempts; return 0; }
    if (bad_restore && reg == failed_reg && in[0] == 0x33) return FM10K_IO;
    int rc = write_bytes(ctx, address, reg, in, n);
    if (setup_writes == fail_write) {
        failed_reg = reg;
        return FM10K_IO; /* Write latched before the transport reported failure. */
    }
    return rc;
}
static void setup_reset(void) {
    reset();
    setup_writes = fail_write = drop_attempts = bad_restore = 0;
    failed_reg = -1;
    for (int mpo = 1; mpo <= 2; ++mpo) {
        memset(f.registers[mpo][0x50], 0x33, 128);
        memset(f.registers[mpo][0x40], 0x33, 128);
        f.registers[mpo][0x50][56] = 0xa0;
        f.registers[mpo][0x50][57] = 0;
        f.registers[mpo][0x50][127] = 5;
        f.registers[mpo][0x40][127] = 2;
    }
}
static void check_lease(void) {
    assert(f.mux == 4 && !f.locked && f.enters == f.leaves);
    for (int mpo = 1; mpo <= 2; ++mpo) {
        assert(f.registers[mpo][0x50][127] == 5 && f.registers[mpo][0x40][127] == 2);
        assert(f.registers[mpo][0x50][56] == 0xa0 && f.registers[mpo][0x50][57] == 0);
    }
}
int main(void) {
    fm10k_bus bus = {.context = &f, .read = read_bytes, .write = setup_write,
                    .enter = enter, .leave = leave, .delay_ms = delay};
    fm10k_obt_setup_report report;
    uint8_t sibling[128][256], before[128][256];
    for (int mpo = 1; mpo <= 2; ++mpo) {
        setup_reset();
        memcpy(sibling, f.registers[3 - mpo], sizeof(sibling));
        drop_attempts = 2;
        assert(fm10k_obt_setup(&bus, mpo, &report) == FM10K_OK);
        assert(report.captured && report.verified && report.changed == 22 && !drop_attempts);
        assert(f.registers[mpo][0x50][43] == 1 && f.registers[mpo][0x40][43] == 0);
        assert(f.registers[mpo][0x40][56] == 0x3f && f.registers[mpo][0x40][57] == 255);
        assert(!memcmp(sibling, f.registers[3 - mpo], sizeof(sibling)));
        int writes = setup_writes;
        assert(!fm10k_obt_setup(&bus, mpo, &report) && !report.changed && setup_writes == writes);
        check_lease();
    }
    for (int fail = 1; fail <= 22; ++fail) {
        setup_reset();
        memcpy(before, f.registers[2], sizeof(before));
        memcpy(sibling, f.registers[1], sizeof(sibling));
        fail_write = fail;
        assert(fm10k_obt_setup(&bus, 2, &report) == FM10K_IO);
        assert(report.captured && report.restored && !report.verified);
        assert(!memcmp(before, f.registers[2], sizeof(before)));
        assert(!memcmp(sibling, f.registers[1], sizeof(sibling)));
        check_lease();
    }
    setup_reset(); fail_write = 2; bad_restore = 1;
    assert(fm10k_obt_setup(&bus, 2, &report) == FM10K_ROLLBACK_FAILED && !report.restored);
    check_lease();
    setup_reset(); f.registers[2][0x50][57] = 1;
    assert(fm10k_obt_setup(&bus, 2, &report) == FM10K_INVALID && !setup_writes);
    setup_reset(); f.fail_at = 8;
    assert(fm10k_obt_setup(&bus, 2, &report) == FM10K_IO && !setup_writes && !report.captured);
    check_lease();
    assert(fm10k_obt_setup(&bus, 3, &report) == FM10K_INVALID);
    puts("OBT bootstrap: two independent muxes, closed TX, bounded retries, exact rollback and page preservation passed");
}
