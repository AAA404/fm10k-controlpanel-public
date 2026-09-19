#ifndef NETLAB_FM10K_BOARD_SDK_H
#define NETLAB_FM10K_BOARD_SDK_H

#include "fm10k_board.h"
#include <pthread.h>

typedef struct {
    fm10k_bus bus;
    int sw;
    pthread_t owner;
    bool attached, switch_locked, bus_locked, faulted;
} fm10k_sdk_bus;

/* Requires a zero-initialized instance. Called by the SDK executor after
 * hardware identity and startup checks.
 * This only binds callbacks: it does not initialize the ASIC, write the bus,
 * or certify that the complete board HAL is ready for configd writes. */
int fm10k_sdk_bus_attach(fm10k_sdk_bus *, int sw);
int fm10k_sdk_bus_detach(fm10k_sdk_bus *);

#endif
