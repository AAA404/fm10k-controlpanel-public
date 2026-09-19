#include "fm10k_board.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct {
    uint8_t registers[256], mux;
    int locked, not_ready, delayed_ms, fan_writes, low_resolution_writes, fail_reg;
    int spin_on_write, spin_reads, pwm_writes;
} device;

static int enter(void *context) {
    (void)context;
    assert(!device.locked);
    device.locked = 1;
    return 0;
}
static int leave(void *context) {
    (void)context;
    assert(device.locked);
    device.locked = 0;
    return 0;
}
static int read_register(void *context, uint8_t address, int reg, uint8_t *out, size_t n) {
    (void)context;
    assert(device.locked && n == 1);
    if (address == 0x58) { assert(reg == -1); *out = device.mux; return 0; }
    assert(address == 0x4c && device.mux == 8 && reg >= 0 && reg <= 255);
    *out = reg == 0x33 && device.not_ready-- > 0 ? 0x80 :
        reg == 0x4c && device.spin_reads-- > 0 ? 0 : device.registers[reg];
    return 0;
}
static int write_register(void *context, uint8_t address, int reg, const uint8_t *in, size_t n) {
    (void)context;
    assert(device.locked && n == 1);
    if (address == 0x58) { assert(reg == -1); device.mux = *in; return 0; }
    assert(address == 0x4c && device.mux == 8 && reg >= 0 && reg <= 255);
    ++device.fan_writes;
    if (device.fail_reg == reg) return FM10K_IO;
    device.registers[reg] = *in;
    if (reg == 0x4c) { ++device.pwm_writes; device.spin_reads = device.spin_on_write; }
    if (reg == 0x4c && (!(device.registers[0x45] & 0x10) ||
                       (device.registers[0x4a] & 8) || device.registers[0x4d] != 8)) {
        device.registers[reg] &= 0x3f;
        ++device.low_resolution_writes;
    }
    return 0;
}
static void delay(void *context, unsigned ms) {
    (void)context;
    assert(ms == 30 && device.locked);
    device.delayed_ms += (int)ms;
}
static void reset(void) {
    memset(&device, 0, sizeof(device));
    device.mux = 4; device.fail_reg = -1;
    device.registers[0x4a] = 0x20;
    device.registers[0x4b] = 0x3f;
    device.registers[0x4d] = 0x17;
}

int main(void) {
    fm10k_bus bus = {.read=read_register, .write=write_register, .enter=enter, .leave=leave, .delay_ms=delay};
    reset();
    assert(fm10k_fan_full(&bus) == FM10K_IO);
    assert(device.registers[0x4c] == 0x3f && device.low_resolution_writes == 1);
    reset(); device.not_ready = 2;
    assert(fm10k_fan_bootstrap(&bus) == FM10K_OK);
    assert(device.delayed_ms == 60 && device.low_resolution_writes == 0);
    assert(device.registers[0x4a] == 0x30 && device.registers[0x4d] == 8);
    assert(device.registers[0x45] == 0x10 && device.registers[0x4c] == 0xff);
    assert(device.mux == 4 && !device.locked);
    const fm10k_fan_curve curve = {35,70,80,50,80,4,10900};
    assert(fm10k_fan_apply(&bus, &curve) == FM10K_OK);
    assert(device.registers[0x4a] == 0x10 && device.registers[0x45] == 0x13);
    assert(fm10k_fan_bootstrap(&bus) == FM10K_OK);
    assert(device.registers[0x4c] == 0xff && !device.low_resolution_writes);
    reset(); device.spin_on_write = 4;
    assert(fm10k_fan_bootstrap(&bus) == FM10K_OK);
    assert(device.delayed_ms == 120 && device.pwm_writes == 1);
    reset(); device.spin_on_write = 1000;
    assert(fm10k_fan_bootstrap(&bus) == FM10K_IO);
    assert(device.delayed_ms == 4500 && device.mux == 4 && !device.locked);
    reset(); device.not_ready = 100;
    assert(fm10k_fan_bootstrap(&bus) == FM10K_IO);
    assert(!device.fan_writes && device.delayed_ms == 360 && device.mux == 4 && !device.locked);
    reset(); device.fail_reg = 0x45;
    assert(fm10k_fan_bootstrap(&bus) == FM10K_IO && device.mux == 4 && !device.locked);
    puts("fan cold boot: POR, resolution, full-speed verification and failed writes passed");
    return 0;
}
