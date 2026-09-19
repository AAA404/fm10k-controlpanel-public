#ifndef LLDPPD_LLDP_FORMAT_H
#define LLDPPD_LLDP_FORMAT_H

#include "netlab/types.h"

void lldp_fmt_chassis_id(char *out, int out_max,
                         const u8 *data, int len, u8 subtype);
const char *lldp_chassis_subtype_name(u8 subtype);
const char *lldp_port_subtype_name(u8 subtype);
void lldp_fmt_bytes(char *out, int out_max, const u8 *data, int len);
void lldp_fmt_string(char *out, int out_max, const u8 *data, int len);
void lldp_fmt_caps(char *out, int out_max, u16 caps);

#endif
