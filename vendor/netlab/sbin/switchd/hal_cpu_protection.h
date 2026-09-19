#ifndef NETLAB_HAL_CPU_PROTECTION_H
#define NETLAB_HAL_CPU_PROTECTION_H

#include "netlab/types.h"

/* One aggregate hardware bound for copies/traps leaving the ASIC for the
 * management CPU. packetd retains the per-protocol packet-rate policies. */
#define HAL_CPU_PROTECTION_RATE_BPS 8000000ULL
#define HAL_CPU_PROTECTION_BURST_BITS (65536ULL * 8)
#define HAL_CPU_PROTECTION_TC_COUNT 8

typedef struct {
    int port;
    u64 rate_bps;
    u64 burst_bits;
    u32 tc_group[HAL_CPU_PROTECTION_TC_COUNT];
} hal_cpu_protection_state;

int hal_cpu_protection_read(int sw, hal_cpu_protection_state *out);
bool hal_cpu_protection_matches(const hal_cpu_protection_state *state);
int hal_cpu_protection_init(int sw);

#endif
