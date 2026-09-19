#ifndef STPD_STP_CONFIG_TEXT_H
#define STPD_STP_CONFIG_TEXT_H

#include <stdbool.h>
#include <stddef.h>

int stp_config_xml_leaf(const char *start, const char *end,
                        const char *leaf, char *out, size_t out_size);
char *stp_config_read_active(void);
bool stp_config_vlan_seen(const int *vlans, int n_vlans, int vid);
int stp_config_collect_port_vlans(int port, int *vlans, int max_vlans);

#endif
