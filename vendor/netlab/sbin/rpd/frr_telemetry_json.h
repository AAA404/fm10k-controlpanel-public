#ifndef RPD_FRR_TELEMETRY_JSON_H
#define RPD_FRR_TELEMETRY_JSON_H

#include "frr_runtime.h"

int rpd_frr_parse_ospf_neighbors_json(const char *json,
                                      rpd_frr_runtime *rt,
                                      int *neighbors, int *full,
                                      char *err, size_t err_size);
int rpd_frr_parse_bgp_summary_json(const char *json,
                                   rpd_frr_runtime *rt,
                                   int *peers, int *established,
                                   char *err, size_t err_size);

#endif
