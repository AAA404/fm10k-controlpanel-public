#ifndef NETLAB_PORT_SCOPE_H
#define NETLAB_PORT_SCOPE_H
#include "types.h"
#include "ipc_contract.h"
#include <time.h>

/* A scoped protocol barrier, never an ASIC lock. Configuration RPCs drain
 * in-flight port activity before returning; timeout leaves the barrier held. */
#define NL_PORT_SCOPE_MASK 0x00ffffffU
#define NL_PORT_SCOPE_SCHEMA 1U
typedef struct {
    u32 schema, mask;
    u64 tx_id;
    u32 degraded, reserved;
} nl_port_scope_status;
typedef void (*nl_port_scope_resume_fn)(u32 mask, time_t paused_seconds);
int nl_port_scope_init(const char *service);
void nl_port_scope_on_resume(nl_port_scope_resume_fn);
/* Monotonic protocol timers are process-local: after a daemon restart, only
 * time spent paused in the new process may be added to its fresh timers. */
void nl_port_scope_on_resume_monotonic(nl_port_scope_resume_fn);
int nl_port_scope_begin(u64 tx_id, u32 mask, unsigned timeout_ms);
int nl_port_scope_end(u64 tx_id);
void nl_port_scope_degrade(u64 tx_id);
nl_port_scope_status nl_port_scope_get(void);
bool nl_port_scope_enter_mask(u32 mask);
bool nl_port_scope_enter_epoch_mask(u32 mask, u64 issued_at);
u32 nl_port_scope_enter_available(void);
void nl_port_scope_leave_mask(u32 mask);
bool nl_port_scope_enter(int port);
/* Packet timestamps use CLOCK_MONOTONIC across all local services. A packet
 * queued before the last resume must never enter the new Ethernet mode. */
u64 nl_port_scope_clock(void);
bool nl_port_scope_packet_enter(int port, u64 received_at);
void nl_port_scope_leave(int port);
bool nl_port_scope_paused(int port);
time_t nl_port_scope_now(int port, time_t wall_now);
time_t nl_port_scope_now_monotonic(int port, time_t monotonic_now);
bool nl_port_scope_ready(void);
#endif
