#include "fm10k_phy.h"
#include "fm10k_board_runtime.h"
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_port.h>
#include <api/fm_api_regs.h>
#include <api/internal/fm10000/fm10000_api_regs_int.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define PHY_RESPONSE_SIZE 8192
#define PHY_CACHE_MS 5000

typedef struct {
    char text[PHY_RESPONSE_SIZE];
    size_t length;
    uint64_t at_ms;
} phy_cache;
static phy_cache cache[6]; /* Sole SDK owner, like the board cache. */

static uint64_t phy_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

typedef struct { char text[PHY_RESPONSE_SIZE]; size_t used; int failed; } writer;
static void emit(writer *w, const char *format, ...) {
    if (w->failed) return;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(w->text + w->used, sizeof(w->text) - w->used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= sizeof(w->text) - w->used) w->failed = 1;
    else w->used += (size_t)n;
}

static void field(writer *w, const char *name, int status, fm_uint32 value) {
    if (status != FM_OK) emit(w, "<field name=\"%s\" status=\"%d\"/>", name, status);
    else emit(w, "<field name=\"%s\" status=\"0\" value=\"%d\" raw=\"0x%08x\"/>",
              name, (int32_t)value, (unsigned)value);
}
static void reg_field(writer *w, int sw, const char *name, fm_uint address) {
    fm_uint32 value = 0;
    fm_status status = fmReadUncachedUINT32(sw, address, &value);
    field(w, name, status, value);
}

int fm10k_phy_snapshot(int sw, int port, char *out, size_t capacity) {
    static const int epls[] = {0, 1, 2, 5, 6, 7};
    static const struct { const char *name; fm_int attribute; } attributes[] = {
        {"tx_pre", FM_PORT_TX_LANE_PRECURSOR},
        {"tx_cursor", FM_PORT_TX_LANE_CURSOR},
        {"tx_post", FM_PORT_TX_LANE_POSTCURSOR},
        {"rx_polarity", FM_PORT_RX_LANE_POLARITY},
        {"tx_polarity", FM_PORT_TX_LANE_POLARITY},
        {"rx_termination", FM_PORT_RX_TERMINATION},
        {"dfe_mode", FM_PORT_DFE_MODE},
        {"coarse_dfe", FM_PORT_COARSE_DFE_STATE},
        {"fine_dfe", FM_PORT_FINE_DFE_STATE},
        {"signal_transition_threshold", FM_PORT_SERDES_SIGNAL_TRANSITION_THRESHOLD},
    };
    if (!out || !capacity || !fm10k_native_profile() || sw != 0 ||
        port < 1 || port > 21 || (port - 1) % 4) return -1;
    out[0] = '\0';
    int index = (port - 1) / 4, epl = epls[index];
    uint64_t now = phy_now();
    if (!now) return -1;
    phy_cache *saved = &cache[index];
    if (saved->length && now >= saved->at_ms && now - saved->at_ms < PHY_CACHE_MS) {
        if (capacity <= saved->length) return -1;
        memcpy(out, saved->text, saved->length + 1);
        return 0;
    }

    /* Limit this view to an actual four-lane port. In split mode its
     * individual lanes are independent ports and need a different view. */
    fm_ethMode eth = FM_ETH_MODE_DISABLED;
    fm_int lanes = 0, mode = 0, state = 0, info[8] = {0};
    if (fmGetPortAttribute(sw, port, FM_PORT_ETHERNET_INTERFACE_MODE, &eth) != FM_OK ||
        (eth != FM_ETH_MODE_100GBASE_SR4 && eth != FM_ETH_MODE_40GBASE_SR4) ||
        fmGetNumPortLanes(sw, port, 0, &lanes) != FM_OK || lanes != 4 ||
        fmGetPortState(sw, port, &mode, &state, info) != FM_OK) return -1;

    writer w = {0};
    emit(&w, "<fm10k-phy port=\"%d\" epl=\"%d\" sampled-monotonic-ms=\"%llu\" "
             "cache-ms=\"%d\" ethernet-mode-raw=\"%d\" sdk-mode-raw=\"%d\" sdk-state-raw=\"%d\">",
         port, epl, (unsigned long long)now, PHY_CACHE_MS, eth, mode, state);
    fm_int speed = 0;
    fm_status status = fmGetPortAttribute(sw, port, FM_PORT_SPEED, &speed);
    field(&w, "speed_mbps", status, (fm_uint32)speed);
    /* Fixed status/configuration registers only: no interrupt, clear-on-write,
     * BIP counter, EEPROM, test-mode, or caller-selected register access. */
    reg_field(&w, sw, "pcs_ml_baser_cfg", FM10000_PCS_ML_BASER_CFG(epl));
    reg_field(&w, sw, "pcs_ml_baser_rx_status", FM10000_PCS_ML_BASER_RX_STATUS(epl));
    for (int lane = 0; lane < 4; ++lane) {
        emit(&w, "<lane id=\"%d\" sdk-info-raw=\"%d\">", lane, info[lane]);
        reg_field(&w, sw, "lane_cfg", FM10000_LANE_CFG(epl, lane));
        reg_field(&w, sw, "lane_serdes_status", FM10000_LANE_SERDES_STATUS(epl, lane));
        for (size_t a = 0; a < sizeof(attributes) / sizeof(*attributes); ++a) {
            fm_uint32 value = 0;
            status = fmGetPortAttributeV2(sw, port, 0, lane, attributes[a].attribute, &value);
            field(&w, attributes[a].name, status, value);
        }
        emit(&w, "</lane>");
    }
    emit(&w, "</fm10k-phy>");
    if (w.failed || capacity <= w.used) return -1;
    memcpy(out, w.text, w.used + 1);
    memcpy(saved->text, w.text, w.used + 1);
    saved->length = w.used;
    saved->at_ms = now;
    return 0;
}
