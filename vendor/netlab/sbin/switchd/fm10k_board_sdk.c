#include "fm10k_board_sdk.h"

#include <fm_sdk_int.h>
#include <stddef.h>
#include <string.h>

/* Checked against the same locked IES 4.3.2 headers as the port adapter. */
_Static_assert(sizeof(void *) == 8 && sizeof(fm_bool) == 1,
               "board adapter requires the pinned amd64 SDK ABI");
_Static_assert(offsetof(fm_platformLib, I2cWriteRead) == 24 &&
               sizeof(fm_platformLib) == 104,
               "board adapter platform function table ABI changed");

#ifndef FM10K_SDK_ROOT_READY
#define FM10K_SDK_ROOT_READY(sw) \
    ((sw) == 0 && fmRootPlatform && fmRootPlatform->cfg.numSwitches == 1 && \
     fmRootPlatform->platformState && fmPlatformProcessState)
#endif
#ifndef FM10K_SDK_LIB
#define FM10K_SDK_LIB(sw) FM_PLAT_GET_LIB_FUNCS_PTR(sw)
#endif
#ifndef FM10K_SDK_I2C_LOCK
#define FM10K_SDK_I2C_LOCK(sw) \
    (&fmRootPlatform->platformState[(sw)].accessLocks[FM_PLAT_I2C_BUS])
#endif
#ifndef FM10K_SDK_SWITCH_TAKE
#define FM10K_SDK_SWITCH_TAKE fmPlatformMgmtTakeSwitchLock
#endif
#ifndef FM10K_SDK_SWITCH_DROP
#define FM10K_SDK_SWITCH_DROP fmPlatformMgmtDropSwitchLock
#endif
#ifndef FM10K_SDK_CAPTURE
#define FM10K_SDK_CAPTURE(lock) fmCaptureLock((lock), FM_WAIT_FOREVER)
#endif
#ifndef FM10K_SDK_RELEASE
#define FM10K_SDK_RELEASE fmReleaseLock
#endif
#ifndef FM10K_SDK_DELAY
#define FM10K_SDK_DELAY fmDelay
#endif

/* Every board-bus instance shares the SDK's one physical lock. An ambiguous
 * release failure must stop new instances too, not just the failing caller. */
static bool board_bus_faulted;

static bool owner(const fm10k_sdk_bus *s) {
    return s && s->attached && pthread_equal(pthread_self(), s->owner);
}

static int bus_leave(void *context) {
    fm10k_sdk_bus *s = context;
    int rc = FM10K_OK;
    if (!owner(s)) return FM10K_IO;
    if (s->bus_locked) {
        if (FM10K_SDK_RELEASE(FM10K_SDK_I2C_LOCK(s->sw)) != FM_OK)
            rc = FM10K_IO;
        s->bus_locked = false;
    }
    if (s->switch_locked) {
        if (FM10K_SDK_SWITCH_DROP(s->sw) != FM_OK) rc = FM10K_IO;
        s->switch_locked = false;
    }
    if (rc) { s->faulted = true; board_bus_faulted = true; }
    return rc;
}

static int bus_enter(void *context) {
    fm10k_sdk_bus *s = context;
    if (!owner(s) || board_bus_faulted || s->faulted || s->switch_locked || s->bus_locked ||
        !FM10K_SDK_ROOT_READY(s->sw)) return FM10K_IO;
    if (FM10K_SDK_SWITCH_TAKE(s->sw) != FM_OK) return FM10K_IO;
    s->switch_locked = true;
    if (FM10K_SDK_CAPTURE(FM10K_SDK_I2C_LOCK(s->sw)) != FM_OK) {
        (void)bus_leave(s);
        return FM10K_IO;
    }
    s->bus_locked = true;
    return FM10K_OK;
}

static bool transfer_allowed(fm10k_sdk_bus *s, uint8_t address, int reg,
                              size_t n, bool writing) {
    if (!owner(s) || !s->switch_locked || !s->bus_locked ||
        !FM10K_SDK_ROOT_READY(s->sw) || n == 0 || n > 12)
        return false;
    if (address == 0x58) return reg == -1 && n == 1;
    if (address == 0x40) {
        /* CXP RX monitors are fixed reads; the only added write is the
         * volatile page selector, restored by the board transaction. */
        if (!writing && reg >= 206 && reg <= 229 && n <= (size_t)(230 - reg)) return true;
        if (n == 1 && (reg == 127 || (!writing && reg == 2))) return true;
        if (n != 1) return false;
        return (!writing && (reg == 7 || reg == 8)) || reg == 43 ||
               reg == 56 || reg == 57 || (reg >= 62 && reg <= 73);
    }
    if (address != 0x50 && address != 0x4c && address != 0x59) return false;
    if (address == 0x59 && writing) return false;
    return reg >= 0 && reg <= 255 && n <= (size_t)(256 - reg);
}

static int bus_read(void *context, uint8_t address, int reg,
                     uint8_t *out, size_t n) {
    fm10k_sdk_bus *s = context;
    fm_byte data[13] = {0};
    if (!out || !transfer_allowed(s, address, reg, n, false))
        return FM10K_INVALID;
    fm_platformLib *lib = FM10K_SDK_LIB(s->sw);
    if (!lib || !lib->I2cWriteRead) return FM10K_IO;
    if (reg >= 0) data[0] = (fm_byte)reg;
    /* The convenience fmPlatformI2cWriteRead() acquires this same bus lock.
     * Invoke the loaded function directly to avoid recursive locking. */
    if (lib->I2cWriteRead(s->sw, address, data, reg < 0 ? 0 : 1,
                         (fm_int)n) != FM_OK) return FM10K_IO;
    memcpy(out, data, n);
    return FM10K_OK;
}

static int bus_write(void *context, uint8_t address, int reg,
                      const uint8_t *in, size_t n) {
    fm10k_sdk_bus *s = context;
    fm_byte data[13] = {0};
    if (!in || !transfer_allowed(s, address, reg, n, true))
        return FM10K_INVALID;
    fm_platformLib *lib = FM10K_SDK_LIB(s->sw);
    if (!lib || !lib->I2cWriteRead) return FM10K_IO;
    size_t prefix = reg < 0 ? 0 : 1;
    if (prefix) data[0] = (fm_byte)reg;
    memcpy(data + prefix, in, n);
    return lib->I2cWriteRead(s->sw, address, data, (fm_int)(n + prefix), 0)
        == FM_OK ? FM10K_OK : FM10K_IO;
}

static void bus_delay(void *context, unsigned ms) {
    if (owner(context) && ms <= 30)
        FM10K_SDK_DELAY(0, ms * 1000000U);
}

int fm10k_sdk_bus_attach(fm10k_sdk_bus *s, int sw) {
    if (!s || s->attached || board_bus_faulted || !FM10K_SDK_ROOT_READY(sw)) return FM10K_INVALID;
    fm_platformLib *lib = FM10K_SDK_LIB(sw);
    if (!lib || !lib->I2cWriteRead) return FM10K_IO;
    memset(s, 0, sizeof(*s));
    s->sw = sw;
    s->owner = pthread_self();
    s->attached = true;
    s->bus = (fm10k_bus){.context = s, .read = bus_read, .write = bus_write,
        .enter = bus_enter, .leave = bus_leave, .delay_ms = bus_delay};
    return FM10K_OK;
}

int fm10k_sdk_bus_detach(fm10k_sdk_bus *s) {
    if (!owner(s)) return FM10K_INVALID;
    int rc = bus_leave(s);
    if (!rc && !s->faulted) memset(s, 0, sizeof(*s));
    else rc = FM10K_IO;
    return rc;
}
