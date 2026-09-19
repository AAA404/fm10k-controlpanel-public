/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef SWITCHD_RPC_FORMAT_H
#define SWITCHD_RPC_FORMAT_H

#include "netlab/hal.h"
#include <stddef.h>

int hal_rpc_format_pfe_resources(const struct sdk_result *result,
                                 char *resp, size_t resp_size);
int hal_rpc_format_switch_config(const struct sdk_result *result,
                                 char *resp, size_t resp_size);
int hal_rpc_format_switch_sensors(const struct sdk_result *result,
                                  char *resp, size_t resp_size);
int hal_rpc_format_board_env(const struct sdk_result *result,
                             char *resp, size_t resp_size);
int hal_rpc_format_control_plane_protection(const struct sdk_result *result,
                                            char *resp, size_t resp_size);
int hal_rpc_format_storm_control(const hal_storm_control_entry *entries,
                                 int n_entries, char *resp,
                                 size_t resp_size);
int hal_rpc_format_ingress_rate_limit(const hal_storm_control_entry *entries,
                              int n_entries, char *resp,
                              size_t resp_size);
int hal_rpc_format_egress_rate_limit(
    const hal_egress_rate_limit_entry *entries,
    int n_entries, char *resp, size_t resp_size);
int hal_rpc_format_qos_interfaces(const hal_qos_interface_entry *entries,
                                  int n_entries, char *resp,
                                  size_t resp_size);
int hal_rpc_format_qos_priority_map(
    const hal_qos_priority_map_entry *entries,
    int n_entries, char *resp, size_t resp_size);
int hal_rpc_format_qos_dscp_map(const int *priorities, int n_entries,
                                char *resp, size_t resp_size);
int hal_rpc_format_qos_flow_control(
    const hal_qos_flow_control_global *global,
    const hal_qos_flow_control_entry *entries,
    int n_entries, char *resp, size_t resp_size);
int hal_rpc_format_qos_scheduler(
    const hal_qos_scheduler_entry *entries,
    int n_entries, char *resp, size_t resp_size);
int hal_rpc_format_qos_queues(
    const hal_qos_queue_entry *entries,
    int n_entries, char *resp, size_t resp_size);
int hal_rpc_format_qos_watermarks(
    const hal_qos_watermark_global *global,
    const hal_qos_watermark_entry *entries,
    int n_entries, char *resp, size_t resp_size);

#endif
