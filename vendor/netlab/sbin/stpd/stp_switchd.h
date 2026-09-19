#ifndef STPD_STP_SWITCHD_H
#define STPD_STP_SWITCHD_H

#include "netlab/mac_snapshot.h"
#include "netlab/stp_snapshot.h"

#include <stdbool.h>

bool stp_switchd_port_link_up(const char *socket_path, int port);
int stp_switchd_collect_hardware_port_vlans(const char *socket_path,
                                            int port, int *vlans,
                                            int max_vlans);
int stp_switchd_get_stp_snapshot(const char *socket_path,
                                 nl_stp_snapshot *snapshot);
int stp_switchd_set_port_stp_state(const char *socket_path, int port,
                                   int vid, int state);
int stp_switchd_clear_dynamic_macs(const char *socket_path, int port,
                                   int vid);
int stp_switchd_get_mac_snapshot(const char *socket_path,
                                 nl_mac_snapshot *snapshot);

#endif
