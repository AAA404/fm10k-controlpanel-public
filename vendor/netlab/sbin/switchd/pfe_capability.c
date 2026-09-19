#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/pfe_capability.h"
#include <string.h>
#include <stdio.h>
#include <fm_sdk.h>

nl_pfe_capability g_pfe_cap;

void sdk_pfe_capability_register(nl_pfe_capability *cap) {
    g_pfe_cap = *cap;
}

void nl_pfe_cap_init(nl_pfe_capability *cap) {
    memset(cap, 0, sizeof(*cap));
}

void nl_pfe_cap_set_field(nl_pfe_capability *cap, const char *field, bool val) {
    if (!cap || !field) return;
    if (strcmp(field, "sdk_initialized") == 0) cap->sdk_initialized = val;
    else if (strcmp(field, "switch_enabled") == 0) cap->switch_enabled = val;
    else if (strcmp(field, "port_inventory_ok") == 0) cap->port_inventory_ok = val;
    else if (strcmp(field, "port_programming_ok") == 0) cap->port_programming_ok = val;
    else if (strcmp(field, "vlan_programming_ok") == 0) cap->vlan_programming_ok = val;
    else if (strcmp(field, "pvid_programming_ok") == 0) cap->pvid_programming_ok = val;
    else if (strcmp(field, "vlan_mode_programming_ok") == 0) cap->vlan_mode_programming_ok = val;
    else if (strcmp(field, "readback_verify_ok") == 0) cap->readback_verify_ok = val;
    else if (strcmp(field, "counters_ok") == 0) cap->counters_ok = val;
    else if (strcmp(field, "transceiver_i2c_ok") == 0) cap->transceiver_i2c_ok = val;
    else if (strcmp(field, "packet_io_ok") == 0) cap->packet_io_ok = val;
    else if (strcmp(field, "hw_out_of_sync") == 0) cap->hw_out_of_sync = val;
    else NL_LOG_WARN("pfe_cap: unknown field %s", field);
}

bool nl_pfe_can_l2_commit(nl_pfe_capability *cap) {
    return cap->port_programming_ok &&
           cap->vlan_programming_ok &&
           cap->pvid_programming_ok &&
           cap->vlan_mode_programming_ok &&
           cap->readback_verify_ok &&
           !cap->hw_out_of_sync;
}

bool nl_pfe_can_l3_commit(nl_pfe_capability *cap) {
    return nl_pfe_can_l2_commit(cap) &&
           cap->l3_interface_programming_ok &&
           cap->route_programming_ok &&
           cap->arp_programming_ok;
}

const char *nl_pfe_status_str(nl_pfe_capability *cap) {
    if (cap->hw_out_of_sync) return "HW_OUT_OF_SYNC";
    if (!cap->sdk_initialized) return "SDK_DOWN";
    if (!cap->switch_enabled) return "SWITCH_DOWN";
    if (!nl_pfe_can_l2_commit(cap)) return "PFE_DOWN";
    return "UP";
}

int nl_pfe_cap_to_json(nl_pfe_capability *cap, char *buf, int buf_sz) {
    return snprintf(buf, buf_sz,
        "{\n"
        "  \"sdk_initialized\": %s,\n"
        "  \"switch_enabled\": %s,\n"
        "  \"port_inventory_ok\": %s,\n"
        "  \"port_programming_ok\": %s,\n"
        "  \"vlan_programming_ok\": %s,\n"
        "  \"pvid_programming_ok\": %s,\n"
        "  \"vlan_mode_programming_ok\": %s,\n"
        "  \"readback_verify_ok\": %s,\n"
        "  \"counters_ok\": %s,\n"
        "  \"transceiver_i2c_ok\": %s,\n"
        "  \"packet_io_ok\": %s,\n"
        "  \"hw_out_of_sync\": %s,\n"
        "  \"status\": \"%s\"\n"
        "}\n",
        cap->sdk_initialized ? "true" : "false",
        cap->switch_enabled ? "true" : "false",
        cap->port_inventory_ok ? "true" : "false",
        cap->port_programming_ok ? "true" : "false",
        cap->vlan_programming_ok ? "true" : "false",
        cap->pvid_programming_ok ? "true" : "false",
        cap->vlan_mode_programming_ok ? "true" : "false",
        cap->readback_verify_ok ? "true" : "false",
        cap->counters_ok ? "true" : "false",
        cap->transceiver_i2c_ok ? "true" : "false",
        cap->packet_io_ok ? "true" : "false",
        cap->hw_out_of_sync ? "true" : "false",
        nl_pfe_status_str(cap));
}
