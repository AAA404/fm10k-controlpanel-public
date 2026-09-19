#include <fm_sdk_int.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static int lock_stage, fail_capture, fail_release, transfers;
static int drop_register = -1, drop_writes, fail_after_write;
static fm_lock fake_lock;
static fm_byte fake_mux = 4;
static fm_byte registers[9][128][256];
static fm_status take_switch(fm_int sw) {
    assert(sw == 0 && lock_stage == 0); lock_stage = 1; return FM_OK;
}
static fm_status drop_switch(fm_int sw) {
    assert(sw == 0 && lock_stage == 1); lock_stage = 0; return FM_OK;
}
static fm_status capture_bus(fm_lock *lock) {
    assert(lock == &fake_lock && lock_stage == 1);
    if (fail_capture) return FM_ERR_INVALID_ARGUMENT;
    lock_stage = 2; return FM_OK;
}
static fm_status release_bus(fm_lock *lock) {
    assert(lock == &fake_lock && lock_stage == 2); lock_stage = 1;
    return fail_release ? FM_ERR_INVALID_ARGUMENT : FM_OK;
}
static void delay(fm_int seconds, fm_int nanoseconds) {
    assert(lock_stage == 2 && seconds == 0 && nanoseconds == 30000000);
}
static fm_status raw_transfer(fm_int sw, fm_int address, fm_byte *data,
                               fm_int nwrite, fm_int nread) {
    assert(sw == 0 && lock_stage == 2 && data); ++transfers;
    if (address == 0x58) {
        if (nread) { assert(nwrite == 0 && nread == 1); data[0] = fake_mux; }
        else { assert(nwrite == 1); fake_mux = data[0]; }
        return FM_OK;
    }
    fm_byte reg = data[0];
    if (nread) {
        assert(nwrite == 1 && nread <= 12);
        memcpy(data, registers[fake_mux][address] + reg, (size_t)nread);
    } else {
        assert(nwrite >= 2 && nwrite <= 13);
        if (drop_writes && reg == drop_register) { --drop_writes; return FM_OK; }
        memcpy(registers[fake_mux][address] + reg, data + 1, (size_t)nwrite - 1);
        if (fail_after_write && reg == drop_register) {
            --fail_after_write;
            return FM_ERR_INVALID_ARGUMENT;
        }
    }
    return FM_OK;
}
static fm_platformLib fake_lib;

#define FM10K_SDK_ROOT_READY(sw) ((sw) == 0)
#define FM10K_SDK_LIB(sw) ((void)(sw), &fake_lib)
#define FM10K_SDK_I2C_LOCK(sw) ((void)(sw), &fake_lock)
#define FM10K_SDK_SWITCH_TAKE take_switch
#define FM10K_SDK_SWITCH_DROP drop_switch
#define FM10K_SDK_CAPTURE capture_bus
#define FM10K_SDK_RELEASE release_bus
#define FM10K_SDK_DELAY delay
#include "../vendor/netlab/sbin/switchd/fm10k_board_sdk.c"

#ifndef FM10K_BUS_FIXTURE_ONLY
static void *other_thread(void *context) {
    fm10k_sdk_bus *s = context;
    uint16_t mask;
    int before = transfers;
    assert(fm10k_tx_read(&s->bus, 1, &mask) == FM10K_IO);
    assert(transfers == before);
    return NULL;
}
int main(void) {
    fm10k_sdk_bus s = {0};
    fake_lib.I2cWriteRead = raw_transfer;
    assert(fm10k_sdk_bus_attach(&s, 1) == FM10K_INVALID);
    assert(!fm10k_sdk_bus_attach(&s, 0) && !transfers);
    assert(fm10k_sdk_bus_attach(&s, 0) == FM10K_INVALID);
    registers[1][0x50][56] = 0xa3;
    registers[1][0x50][57] = 0xff;
    uint16_t mask = 0;
    assert(!fm10k_tx_read(&s.bus, 1, &mask) && mask == 0x3ff);
    assert(!lock_stage && fake_mux == 4);
    assert(!fm10k_tx_update(&s.bus, 1, 0xf, 0x5));
    assert(registers[1][0x50][56] == 0xa3 && registers[1][0x50][57] == 0xf5);
    assert(!lock_stage && fake_mux == 4);
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, other_thread, &s));
    assert(!pthread_join(thread, NULL));
    fail_capture = 1;
    assert(fm10k_tx_read(&s.bus, 1, &mask) == FM10K_IO && !lock_stage);
    fail_capture = 0;
    assert(!s.bus.enter(s.bus.context));
    const uint8_t value = 1;
    assert(s.bus.write(s.bus.context, 0x59, 0xa0, &value, 1) == FM10K_INVALID);
    assert(s.bus.read(s.bus.context, 0x40, 0, (uint8_t *)&mask, 1) == FM10K_INVALID);
    assert(!s.bus.write(s.bus.context, 0x40, 127, &value, 1));
    assert(s.bus.write(s.bus.context, 0x40, 206, &value, 1) == FM10K_INVALID);
    uint8_t power[12];
    assert(!s.bus.read(s.bus.context, 0x40, 206, power, 12));
    assert(s.bus.read(s.bus.context, 0x40, 229, power, 2) == FM10K_INVALID);
    assert(s.bus.read(s.bus.context, 0x40, 205, power, 1) == FM10K_INVALID);
    assert(s.bus.write(s.bus.context, 0x40, 8, &value, 1) == FM10K_INVALID);
    assert(!s.bus.read(s.bus.context, 0x40, 8, (uint8_t *)&mask, 1));
    assert(!s.bus.write(s.bus.context, 0x40, 43, &value, 1));
    assert(s.bus.enter(s.bus.context) == FM10K_IO && lock_stage == 2);
    assert(!s.bus.leave(s.bus.context));
    fail_release = 1;
    assert(fm10k_tx_read(&s.bus, 1, &mask) == FM10K_IO && !lock_stage && s.faulted);
    fail_release = 0;
    int before = transfers;
    assert(fm10k_tx_read(&s.bus, 1, &mask) == FM10K_IO && transfers == before);
    assert(fm10k_sdk_bus_detach(&s) == FM10K_IO);
    puts("pinned SDK bus lock ordering, owner thread, restricted transfers and fault gate passed");
    return 0;
}
#endif
