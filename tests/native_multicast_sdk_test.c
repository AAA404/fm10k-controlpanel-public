#include <stdlib.h>
#include <stdbool.h>
static bool allocation_failure;
static void *test_calloc(size_t count, size_t size) { return allocation_failure ? NULL : calloc(count, size); }
#define calloc test_calloc
#include "../vendor/netlab/sbin/switchd/hal_multicast.c"
#undef calloc
#include <assert.h>

static fm_multicastListener rows[160];
static int n_rows, listener_calls, writes;
static fm_status group_first_error, group_next_error, address_error, lookup_error, listener_error;
static int first_handle = 7, next_handle = -1, lookup_handle = 7, listener_cycle;
static int address_kind = FM_MCAST_ADDR_TYPE_L2MAC_VLAN;
static u16 address_vlan = 100;
static fm_macaddr address_mac = UINT64_C(0x01005e010101);
static bool extra_internal;

bool nl_ifid_is_user_port(int port) { return port > 0 && port <= 24; }
const char *fmErrorMsg(fm_int error) { (void)error; return "fixture"; }
void nl_log_write(nl_log_level level, const char *file, int line, const char *fmt, ...) {
    (void)level; (void)file; (void)line; (void)fmt;
}
fm_status fmFindMcastGroupByAddress(fm_int sw, fm_multicastAddress *address, fm_int *group) {
    assert(sw == 0 && address->addressType == FM_MCAST_ADDR_TYPE_L2MAC_VLAN);
    *group = lookup_handle; return lookup_error;
}
fm_status fmGetMcastGroupAddress(fm_int sw, fm_int group, fm_multicastAddress *address) {
    assert(sw == 0);
    if (group == 9 && extra_internal) return FM_ERR_MCAST_ADDR_NOT_ASSIGNED;
    address->addressType = address_kind; address->info.mac.vlan = address_vlan;
    address->info.mac.destMacAddress = address_mac; address->mcastGroup = group;
    return address_error;
}
fm_status fmGetMcastGroupFirst(fm_int sw, fm_int *group) {
    assert(sw == 0); *group = first_handle; return group_first_error;
}
fm_status fmGetMcastGroupNext(fm_int sw, fm_int current, fm_int *group) {
    assert(sw == 0);
    if (group_next_error) return group_next_error;
    if (next_handle >= 0) { *group = next_handle; return FM_OK; }
    if (extra_internal && current == 7) { *group = 9; return FM_OK; }
    return FM_ERR_NO_MORE;
}
fm_status fmGetMcastGroupListenerFirst(fm_int sw, fm_int group, fm_multicastListener *out) {
    assert(sw == 0 && group == 7); listener_calls = 0;
    if (!n_rows) return FM_ERR_NO_MORE;
    *out = rows[0]; return FM_OK;
}
fm_status fmGetMcastGroupListenerNext(fm_int sw, fm_int group, fm_multicastListener *current, fm_multicastListener *out) {
    (void)current; assert(sw == 0 && group == 7);
    ++listener_calls;
    if (listener_error) return listener_error;
    if (listener_cycle) { *out = rows[listener_calls % listener_cycle]; return FM_OK; }
    if (listener_calls >= n_rows) return FM_ERR_NO_MORE;
    *out = rows[listener_calls]; return FM_OK;
}
fm_status fmCreateMcastGroup(fm_int sw, fm_int *group) { (void)sw; (void)group; ++writes; return FM_FAIL; }
fm_status fmSetMcastGroupAddress(fm_int sw, fm_int group, fm_multicastAddress *address) {
    (void)sw; (void)group; (void)address; ++writes; return FM_FAIL;
}
fm_status fmActivateMcastGroup(fm_int sw, fm_int group) { (void)sw; (void)group; ++writes; return FM_FAIL; }
fm_status fmDeactivateMcastGroup(fm_int sw, fm_int group) { (void)sw; (void)group; ++writes; return FM_FAIL; }
fm_status fmDeleteMcastGroup(fm_int sw, fm_int group) { (void)sw; (void)group; ++writes; return FM_FAIL; }
fm_status fmAddMcastGroupListener(fm_int sw, fm_int group, fm_multicastListener *listener) {
    (void)sw; (void)group; (void)listener; ++writes; return FM_FAIL;
}
fm_status fmDeleteMcastGroupListener(fm_int sw, fm_int group, fm_multicastListener *listener) {
    (void)sw; (void)group; (void)listener; ++writes; return FM_FAIL;
}
static void bad_snapshot(void) {
    char text[4096] = "old";
    assert(hal_l2_mcast_owner_format(0, text, sizeof(text)) < 0 && !text[0]);
}
int main(void) {
    const u8 mac[6] = {1, 0, 0x5e, 1, 1, 1};
    rows[0] = (fm_multicastListener){.port = 5, .vlan = 100};
    rows[1] = (fm_multicastListener){.port = 1, .vlan = 100};
    rows[2] = (fm_multicastListener){.port = 0, .vlan = 100};
    rows[3] = (fm_multicastListener){.port = 26, .vlan = 100};
    rows[4] = (fm_multicastListener){.port = 2, .vlan = 200};
    n_rows = 5; extra_internal = true;
    char text[4096];
    int length = hal_l2_mcast_owner_format(0, text, sizeof(text));
    assert(length > 0 && nl_mcast_readback_valid(text, (size_t)length));
    assert(strstr(text, "groups=\"1\" listeners=\"2\""));
    assert(hal_l2_mcast_listener_present(0, 100, mac, 1) == 1);
    assert(hal_l2_mcast_listener_present(0, 100, mac, 9) == 0);
    listener_error = FM_FAIL;
    assert(hal_l2_mcast_listener_present(0, 100, mac, 5) == -1); bad_snapshot();
    listener_error = 0; listener_cycle = 2; bad_snapshot(); assert(listener_calls == 2);
    listener_cycle = 0; next_handle = 7; bad_snapshot(); next_handle = 6; bad_snapshot(); next_handle = -1;
    first_handle = 0; bad_snapshot(); first_handle = FM_MAX_LOGICAL_PORT; bad_snapshot(); first_handle = 7;
    group_first_error = FM_FAIL; bad_snapshot(); group_first_error = 0;
    group_next_error = FM_FAIL; bad_snapshot(); group_next_error = 0;
    address_error = FM_FAIL; bad_snapshot();
    assert(hal_l2_mcast_listener_set(0, 100, mac, 1) == -1 && !writes);
    assert(hal_l2_mcast_listener_delete(0, 100, mac, 1) == -1 && !writes);
    address_error = 0; address_vlan = 200;
    assert(hal_l2_mcast_listener_present(0, 100, mac, 1) == -1);
    assert(hal_l2_mcast_listener_delete(0, 100, mac, 1) == -1 && !writes);
    address_vlan = 100; address_mac = UINT64_C(0x00005e010101); bad_snapshot();
    address_mac = UINT64_C(0x01005e010101); address_kind = 99; bad_snapshot();
    address_kind = FM_MCAST_ADDR_TYPE_L2MAC_VLAN;
    lookup_error = FM_FAIL; bad_snapshot(); lookup_error = FM_ERR_NOT_FOUND;
    assert(hal_l2_mcast_listener_set(0, 100, mac, 1) == -1 && !writes);
    lookup_error = FM_ERR_MCAST_ADDR_NOT_ASSIGNED;
    assert(hal_l2_mcast_listener_present(0, 100, mac, 1) == 0);
    lookup_error = 0; lookup_handle = 8; bad_snapshot(); lookup_handle = 0;
    assert(hal_l2_mcast_listener_present(0, 100, mac, 1) == -1); lookup_handle = 7;
    rows[1].port = -1; bad_snapshot(); rows[1].port = 1;
    rows[1].remoteFlag = TRUE; bad_snapshot(); rows[1].remoteFlag = FALSE;
    allocation_failure = true; bad_snapshot(); allocation_failure = false;
    assert(hal_l2_mcast_owner_format(0, text, 10) < 0 && !text[0]);
    for (int i = 0; i < 130; ++i) rows[i] = (fm_multicastListener){.port = i, .vlan = 100};
    n_rows = 130; length = hal_l2_mcast_owner_format(0, text, sizeof(text));
    assert(length > 0 && nl_mcast_readback_valid(text, (size_t)length));
    n_rows = 0; length = hal_l2_mcast_owner_format(0, text, sizeof(text));
    assert(length > 0 && nl_mcast_readback_valid(text, (size_t)length) && strstr(text, "groups=\"0\""));
    group_first_error = FM_ERR_NO_MORE;
    length = hal_l2_mcast_owner_format(0, text, sizeof(text));
    assert(length > 0 && nl_mcast_readback_valid(text, (size_t)length));
    assert(!writes);
    puts("Multicast SDK errors, binding checks, complete enumeration and no writes passed");
    return 0;
}
