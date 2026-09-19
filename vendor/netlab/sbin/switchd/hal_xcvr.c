#include "netlab/log.h"
#include "netlab/hal.h"
#include <fm_sdk.h>
#include <platforms/libertyTrail/platform_app_api.h>
#include <platforms/common/phy/fm_platform_xcvr.h>
#include <platforms/libertyTrail/platform_lib_api.h>

int hal_get_xcvr_info(int sw, int port,
                      int *present, int *type,
                      float *temp, float *voltage,
                      float *tx_bias, float *tx_power,
                      float *rx_power) {
    fm_bool is_present = FALSE;
    fm_status st = fmPlatformXcvrIsPresent((fm_int)sw, (fm_int)port, &is_present);
    if (st != FM_OK) {
        *present = 0; *type = 0;
        *temp = *voltage = *tx_bias = *tx_power = *rx_power = 0;
        return -1;
    }
    *present = is_present ? 1 : 0;

    if (!is_present) {
        *type = 0;
        *temp = *voltage = *tx_bias = *tx_power = *rx_power = 0;
        return 0;
    }

    // Read EEPROM to determine type
    fm_byte eeprom[256];
    st = fmPlatformXcvrEepromRead((fm_int)sw, (fm_int)port, 0, 0, eeprom, 256);
    if (st == FM_OK) {
        *type = (int)fmPlatformXcvrEepromGetType(eeprom);
    } else {
        *type = 0;
    }

    // Read DOM data
    fm_byte dom[16];
    // SFP DOM at A2h offset 96, QSFP at page 0 offset 22
    st = fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 96, dom, 2);
    if (st == FM_OK) {
        *temp = (float)((int)(s16)((dom[0] << 8) | dom[1])) / 256.0f;
    } else {
        *temp = 0;
    }

    st = fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 98, dom, 2);
    *voltage = (st == FM_OK) ? (float)((dom[0] << 8) | dom[1]) / 10000.0f : 0;

    st = fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 100, dom, 2);
    *tx_bias = (st == FM_OK) ? (float)((dom[0] << 8) | dom[1]) / 500.0f : 0;

    st = fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 102, dom, 2);
    *tx_power = (st == FM_OK) ? (float)((dom[0] << 8) | dom[1]) / 10000.0f : 0;

    st = fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 104, dom, 2);
    *rx_power = (st == FM_OK) ? (float)((dom[0] << 8) | dom[1]) / 10000.0f : 0;

    return 0;
}
