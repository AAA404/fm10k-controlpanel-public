#ifndef LLDPPD_LLDP_XML_H
#define LLDPPD_LLDP_XML_H

#include "lldp_tlv.h"
#include <stdbool.h>
#include <stddef.h>

int lldp_xml_leaf(const char *start, const char *end,
                  const char *leaf, char *out, size_t out_size);
void lldp_xml_unescape(const char *src, char *dst, size_t dst_len);
void lldp_xml_escape(const char *src, char *dst, size_t dst_len);
bool lldp_parse_int_text(const char *text, int min, int max, int *value);
bool lldp_parse_management_address_text(const char *text,
                                        lldp_config *cfg);

#endif
