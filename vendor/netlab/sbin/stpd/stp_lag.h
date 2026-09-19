#ifndef NETLAB_STP_LAG_H
#define NETLAB_STP_LAG_H
#include "netlab/types.h"
#include <stddef.h>
#include <time.h>

/* Stable protocol IDs are separate from SDK-allocated LAG logical ports. */
#define STP_AGGREGATE_BASE 64
#define STP_AGGREGATE_COUNT 64
int stp_port_from_name(const char *name);
void stp_port_name(int port, char *name, size_t size);
void stp_lag_load_config(const char *xml);
bool stp_lag_refresh(const char *switchd_socket);
int stp_lag_ingress(int physical_port);
int stp_lag_egress(int bridge_port);
int stp_lag_hardware_port(int bridge_port);
u32 stp_port_scope_mask(int bridge_port);
bool stp_port_paused(int bridge_port);
time_t stp_port_now(int bridge_port, time_t wall_time);
#endif
