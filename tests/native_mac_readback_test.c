#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "netlab/hal.h"
#include "netlab/hal_presence.h"
#include "netlab/log.h"
#include <fm_sdk.h>
#include <api/fm_api_addr.h>

static const u8 mac[6] = {2, 0, 0, 0, 0, 1};
static fm_macAddressEntry live;
static bool present, apply_delete, relearn;
static int gets, deletes, fail_get;
static fm_status get_error, delete_status;
static hal_presence_state vlan_presence;

hal_presence_snapshot hal_vlan_presence_snapshot(int sw, u16 vid) {
    assert(sw == 0 && vid == 10);
    return (hal_presence_snapshot){.state = vlan_presence, .sdk_status = FM_OK};
}

void nl_log_write(nl_log_level level, const char *file, int line, const char *fmt, ...) {
    (void)level; (void)file; (void)line; (void)fmt;
}
const char *fmErrorMsg(fm_int error) { (void)error; return "injected read error"; }

fm_status fmGetAddress(fm_int sw, fm_macaddr address, fm_int vlan, fm_macAddressEntry *entry) {
    assert(sw == 0 && address == 0x020000000001ULL && vlan == 10);
    if (++gets == fail_get) return get_error;
    if (!present) return FM_ERR_ADDR_NOT_FOUND;
    *entry = live;
    return FM_OK;
}
fm_status fmDeleteAddress(fm_int sw, fm_macAddressEntry *entry) {
    assert(sw == 0 && entry->macAddress == 0x020000000001ULL && entry->vlanID == 10);
    assert(entry->type == live.type);
    ++deletes;
    if (apply_delete) present = false;
    if (relearn) { present = true; live.type = FM_ADDRESS_DYNAMIC; }
    return delete_status;
}

static void reset(void) {
    memset(&live, 0, sizeof(live));
    live.macAddress = 0x020000000001ULL;
    live.vlanID = 10;
    live.port = 5;
    live.type = FM_ADDRESS_STATIC;
    present = apply_delete = true;
    relearn = false;
    gets = deletes = fail_get = 0;
    get_error = FM_FAIL;
    delete_status = FM_OK;
    vlan_presence = HAL_PRESENCE_PRESENT;
}

int main(void) {
    struct verify_result result;
    bool found = true, fixed = true;
    int port = 999, type = 999;

    reset(); present = false;
    assert(hal_mac_entry_snapshot(0, 10, mac, &found, &port, &fixed, &type) == 0);
    assert(!found && !fixed && port == 0 && type == -1);
    assert(hal_static_mac_delete(0, 10, mac) == 0 && deletes == 0);
    for (int secure = 0; secure < 2; ++secure) {
        reset(); live.type = secure ? FM_ADDRESS_SECURE_DYNAMIC : FM_ADDRESS_DYNAMIC;
        assert(hal_static_mac_delete(0, 10, mac) == 0 && deletes == 0 && present);
        assert(verify_static_mac_entry(0, 10, mac, 5, false, &result) == 0);
        reset(); live.type = secure ? FM_ADDRESS_SECURE_STATIC : FM_ADDRESS_STATIC;
        assert(hal_static_mac_delete(0, 10, mac) == 0 && deletes == 1 && !present);
    }
    puts("PASS: true absence is idempotent; static delete preserves dynamic replacements and handles secure-static entries");

    fm_status errors[] = {FM_FAIL, FM_ERR_INVALID_SWITCH, FM_ERR_NOT_FOUND};
    for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        reset(); fail_get = 1; get_error = errors[i];
        assert(hal_static_mac_delete(0, 10, mac) == errors[i] && deletes == 0);
        reset(); fail_get = 2; get_error = errors[i];
        assert(hal_static_mac_delete(0, 10, mac) == errors[i] && deletes == 1);
        reset(); fail_get = 2; get_error = errors[i]; delete_status = FM_FAIL;
        assert(hal_static_mac_delete(0, 10, mac) == errors[i] && deletes == 1);
        for (int expect_present = 0; expect_present < 2; ++expect_present) {
            reset(); fail_get = 1; get_error = errors[i];
            memset(&result, 0, sizeof(result));
            assert(verify_static_mac_entry(0, 10, mac, 5, expect_present, &result) != 0);
            assert(!result.readback_ok && result.sdk_status == errors[i]);
            assert(strstr(result.detail, "read-back failed"));
        }
    }
    puts("PASS: pre-delete, post-delete and final verification errors never become successful absence");

    reset(); fail_get = 1; get_error = FM_ERR_INVALID_VLAN; vlan_presence = HAL_PRESENCE_ABSENT;
    assert(hal_static_mac_delete(0, 10, mac) == 0 && deletes == 0);
    for (int state = 0; state < 2; ++state) {
        reset(); fail_get = 1; get_error = FM_ERR_INVALID_VLAN;
        vlan_presence = state ? HAL_PRESENCE_READ_ERROR : HAL_PRESENCE_PRESENT;
        assert(hal_static_mac_delete(0, 10, mac) != 0 && deletes == 0);
    }
    puts("PASS: an already absent parent VLAN requires its own authoritative absence proof");

    reset(); apply_delete = false;
    assert(hal_static_mac_delete(0, 10, mac) != 0 && deletes == 1 && present);
    reset(); delete_status = FM_FAIL;
    assert(hal_static_mac_delete(0, 10, mac) == 0 && deletes == 1 && !present);
    reset(); relearn = true;
    assert(hal_static_mac_delete(0, 10, mac) == 0 && deletes == 1 && present);
    assert(verify_static_mac_entry(0, 10, mac, 5, false, &result) == 0);
    reset();
    assert(verify_static_mac_entry(0, 10, mac, 5, true, &result) == 0);
    assert(verify_static_mac_entry(0, 10, mac, 1, true, &result) != 0);
    assert(verify_static_mac_entry(0, 10, mac, 5, false, &result) != 0);
    puts("PASS: successful SDK replies must satisfy readback; a lost delete reply requires proven absence or relearning");

    for (int fault = 0; fault < 4; ++fault) {
        reset();
        if (fault == 0) ++live.macAddress;
        if (fault == 1) live.type = 65535;
        if (fault == 2) live.port = -1;
        if (fault == 3) live.isTunnelEntry = true;
        assert(hal_static_mac_delete(0, 10, mac) != 0 && deletes == 0);
        assert(verify_static_mac_entry(0, 10, mac, 5, false, &result) != 0);
    }
    puts("PASS: wrong address, unsupported type, invalid destination and tunnel objects cannot authorize static deletion");
    return 0;
}
