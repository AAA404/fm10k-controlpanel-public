/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "hal_sflow.h"
#include "fm10k_board_runtime.h"
#include "fm10k_phy.h"
#include "fm10k_eye.h"
#include "hal_pfc_watchdog.h"
#include "fm10k_congestion_counters.h"
#include "netlab/port_scope.h"
#include "sdk_runtime_scope.h"
#include "netlab/fm10k_plan_scope.h"
#include "netlab/interface_id.h"
#include "netlab/hal_presence.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_regs.h>
#include <api/fm_api_stats.h>
#include <platforms/platform_app.h>
#include <platforms/libertyTrail/platform_app_api.h>
#include <platforms/common/phy/fm_platform_xcvr.h>
#include <platforms/libertyTrail/platform_lib_api.h>

#define MAX_QUEUE 1024
#define SDK_EXEC_AGING_NS (250ULL * 1000ULL * 1000ULL)
#define SDK_EXEC_MAINTENANCE_NS (1000ULL * 1000ULL * 1000ULL)
#define SDK_EXEC_HIST_BUCKETS 10
#define SDK_EXEC_SLICE_DONE 0
#define SDK_EXEC_SLICE_YIELD INT_MIN
#define OPTICS_MUX_READ_CHUNK 12

static u64 monotonic_ns(void);
static int sdk_scope_resolve_lag(int sw, int id, bool lag_handle, u32 *mask);
static int sdk_plan_scope_resolve(void *context, nl_fm10k_scope_target kind, int id, u32 *mask);
static int sdk_plan_scope_check(int sw, const struct sdk_op *op);
static int sdk_exec_op_dispatch_inner(int sw, struct sdk_op *op, struct sdk_result *result);

#ifndef NETLAB_SDK_EXECUTOR_DISPATCH
#define NETLAB_SDK_EXECUTOR_DISPATCH sdk_exec_op_dispatch_inner
#endif

static const u64 sdk_exec_hist_us[SDK_EXEC_HIST_BUCKETS] = {
    100, 500, 1000, 5000, 10000,
    50000, 100000, 500000, 1000000, 10000000,
};

typedef struct {
    u64 enqueued;
    u64 completed;
    u64 failed;
    u64 cancelled;
    u64 queue_full;
    u64 timed_out;
    u64 wait_total_ns;
    u64 wait_max_ns;
    u64 exec_total_ns;
    u64 exec_max_ns;
    u64 wait_hist[SDK_EXEC_HIST_BUCKETS];
    u64 exec_hist[SDK_EXEC_HIST_BUCKETS];
    u32 high_watermark;
} sdk_exec_priority_metrics;

typedef enum {
    OPTICS_MUX_PHASE_INIT = 0,
    OPTICS_MUX_PHASE_BRANCH_BEGIN,
    OPTICS_MUX_PHASE_SCAN,
    OPTICS_MUX_PHASE_DUMP,
    OPTICS_MUX_PHASE_DONE,
} optics_mux_phase;

typedef struct {
    optics_mux_phase phase;
    int branch_values[NETLAB_OPTICS_MUX_MAX_BRANCHES];
    int branch;
    int scan_index;
    int dump_index;
    int dump_done;
} optics_mux_progress;

typedef struct sdk_exec_op {
    struct sdk_op op;
    struct sdk_result result;
    l2_apply_plan *apply_plan_copy;
    nl_acl_counter_query *acl_counter_query_copy;
    l2_apply_plan *apply_plan_output;
    bool completed;
    bool cancelled;
    bool running;
    int priority;
    u64 submitted_ns;
    u64 enqueued_ns;
    u64 started_ns;
    u64 deadline_ns;
    u64 exec_total_ns;
    optics_mux_progress optics_mux;
    pthread_cond_t cond;
    pthread_mutex_t lock;
} sdk_exec_op_t;

struct sdk_executor {
    int sw;
    /* One extra slot lets a sliced operation requeue after submissions fill. */
    sdk_exec_op_t *queues[SDK_PRIO_COUNT][MAX_QUEUE + 1];
    int queue_count[SDK_PRIO_COUNT];
    sdk_exec_priority_metrics metrics[SDK_PRIO_COUNT];
    u64 snapshot_generation;
    pthread_mutex_t lock;
    pthread_cond_t work_avail;
    bool running;
    pthread_t thread;
};

static float xcvr_s16_to_celsius(fm_byte msb, fm_byte lsb) {
    return (float)(int)(s16)(((u16)msb << 8) | lsb) / 256.0f;
}

static float xcvr_u16_to_voltage(fm_byte msb, fm_byte lsb) {
    return (float)(((u16)msb << 8) | lsb) / 10000.0f;
}

static float xcvr_u16_to_bias_ma(fm_byte msb, fm_byte lsb) {
    return (float)(((u16)msb << 8) | lsb) / 500.0f;
}

static float xcvr_u16_to_mw(fm_byte msb, fm_byte lsb) {
    return (float)(((u16)msb << 8) | lsb) / 10000.0f;
}

static bool xcvr_dom_plausible(float temp, float voltage) {
    return temp > -50.0f && temp < 130.0f &&
           voltage > 0.1f && voltage < 5.0f;
}

static bool xcvr_read_qsfp_dom(int sw, int port, struct sdk_result *result) {
    fm_byte dom[64] = {0};
    fm_status st = fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0, 0,
                                         dom, sizeof(dom));
    if (st != FM_OK)
        return false;

    float temp = xcvr_s16_to_celsius(dom[22], dom[23]);
    float voltage = xcvr_u16_to_voltage(dom[26], dom[27]);
    if (!xcvr_dom_plausible(temp, voltage))
        return false;

    float rx_power = 0.0f;
    float tx_bias = 0.0f;
    float tx_power = 0.0f;
    for (int i = 0; i < NETLAB_XCVR_MAX_LANES; i++) {
        int rx_off = 34 + (i * 2);
        int bias_off = 42 + (i * 2);
        int tx_off = 50 + (i * 2);
        result->data.xcvr.lane[i].rx_power =
            xcvr_u16_to_mw(dom[rx_off], dom[rx_off + 1]);
        result->data.xcvr.lane[i].tx_bias =
            xcvr_u16_to_bias_ma(dom[bias_off], dom[bias_off + 1]);
        result->data.xcvr.lane[i].tx_power =
            xcvr_u16_to_mw(dom[tx_off], dom[tx_off + 1]);
        rx_power += result->data.xcvr.lane[i].rx_power;
        tx_bias += result->data.xcvr.lane[i].tx_bias;
        tx_power += result->data.xcvr.lane[i].tx_power;
    }
    rx_power /= (float)NETLAB_XCVR_MAX_LANES;
    tx_bias /= (float)NETLAB_XCVR_MAX_LANES;
    tx_power /= (float)NETLAB_XCVR_MAX_LANES;

    result->data.xcvr.temp = temp;
    result->data.xcvr.voltage = voltage;
    result->data.xcvr.rx_power = rx_power;
    result->data.xcvr.tx_bias = tx_bias;
    result->data.xcvr.tx_power = tx_power;
    result->data.xcvr.dom_valid = 1;
    result->data.xcvr.lane_count = NETLAB_XCVR_MAX_LANES;

    if (result->data.xcvr.type == FM_PLATFORM_XCVR_TYPE_UNKNOWN) {
        if (dom[0] == 0x11)
            result->data.xcvr.type = (u8)FM_PLATFORM_XCVR_TYPE_QSFP28_OPT;
        else if (dom[0] == 0x0d || dom[0] == 0x0c)
            result->data.xcvr.type = (u8)FM_PLATFORM_XCVR_TYPE_QSFP_OPT;
    }
    return true;
}

static bool xcvr_read_sfp_dom(int sw, int port, struct sdk_result *result) {
    fm_byte dom[2] = {0};
    float temp = 0.0f;
    float voltage = 0.0f;
    bool got_temp = false;
    bool got_voltage = false;

    if (fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 96,
                              dom, sizeof(dom)) == FM_OK) {
        temp = xcvr_s16_to_celsius(dom[0], dom[1]);
        got_temp = true;
    }
    if (fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 98,
                              dom, sizeof(dom)) == FM_OK) {
        voltage = xcvr_u16_to_voltage(dom[0], dom[1]);
        got_voltage = true;
    }
    if (!got_temp || !got_voltage || !xcvr_dom_plausible(temp, voltage))
        return false;

    result->data.xcvr.temp = temp;
    result->data.xcvr.voltage = voltage;
    if (fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 100,
                              dom, sizeof(dom)) == FM_OK)
        result->data.xcvr.tx_bias = xcvr_u16_to_bias_ma(dom[0], dom[1]);
    if (fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 102,
                              dom, sizeof(dom)) == FM_OK)
        result->data.xcvr.tx_power = xcvr_u16_to_mw(dom[0], dom[1]);
    if (fmPlatformXcvrMemRead((fm_int)sw, (fm_int)port, 0xA2, 104,
                              dom, sizeof(dom)) == FM_OK)
        result->data.xcvr.rx_power = xcvr_u16_to_mw(dom[0], dom[1]);
    result->data.xcvr.lane[0].tx_bias = result->data.xcvr.tx_bias;
    result->data.xcvr.lane[0].tx_power = result->data.xcvr.tx_power;
    result->data.xcvr.lane[0].rx_power = result->data.xcvr.rx_power;
    result->data.xcvr.lane_count = 1;
    result->data.xcvr.dom_valid = 1;
    return true;
}

static bool xcvr_type_is_qsfp(fm_platformXcvrType type) {
    return type == FM_PLATFORM_XCVR_TYPE_QSFP_DAC ||
        type == FM_PLATFORM_XCVR_TYPE_QSFP_AOC ||
        type == FM_PLATFORM_XCVR_TYPE_QSFP_OPT ||
        type == FM_PLATFORM_XCVR_TYPE_QSFP28_DAC ||
        type == FM_PLATFORM_XCVR_TYPE_QSFP28_AOC ||
        type == FM_PLATFORM_XCVR_TYPE_QSFP28_OPT ||
        type == FM_PLATFORM_XCVR_TYPE_FCI_OPT ||
        type == FM_PLATFORM_XCVR_TYPE_FCI;
}

static int optics_mux_read_bytes(int sw, int addr, int offset,
                                 u8 *out, int len) {
    int done = 0;

    if (!out || offset < 0 || len < 0 ||
        offset + len > NETLAB_OPTICS_MUX_DUMP_LEN)
        return FM_ERR_INVALID_ARGUMENT;

    while (done < len) {
        fm_byte tmp[12];
        int chunk = len - done;
        fm_status st;

        if (chunk > (int)sizeof(tmp))
            chunk = (int)sizeof(tmp);
        memset(tmp, 0, sizeof(tmp));
        tmp[0] = (fm_byte)(offset + done);
        st = fmI2cWriteRead((fm_int)sw, (fm_uint)addr, tmp, 1,
                            (fm_uint)chunk);
        if (st != FM_OK)
            return (int)st;
        memcpy(out + done, tmp, (size_t)chunk);
        done += chunk;
    }

    return 0;
}

static int optics_mux_write_byte(int sw, int addr, int offset, int value) {
    fm_byte tmp[2];
    fm_status st;

    if (offset < 0 || offset > 255 || value < 0 || value > 255)
        return FM_ERR_INVALID_ARGUMENT;
    tmp[0] = (fm_byte)offset;
    tmp[1] = (fm_byte)value;
    st = fmI2cWriteRead((fm_int)sw, (fm_uint)addr, tmp, 2, 0);
    return (int)st;
}

static int optics_mux_probe_address(int sw, int addr) {
    fm_byte tmp[1] = {0};
    fm_status st;

    st = fmI2cWriteRead((fm_int)sw, (fm_uint)addr, tmp, 0, 1);
    return (int)st;
}

static void optics_mux_dump_descriptor(int index, int *addr, int *page,
                                       int *offset, int *length) {
    if (index == 0 || index == 1 || index == 2) {
        *addr = index == 0 ? 0x50 : (index == 1 ? 0x51 : 0x40);
        *page = -1;
        *offset = 0;
        *length = NETLAB_OPTICS_MUX_DUMP_LEN;
    } else if (index >= 3 && index < 19) {
        *addr = 0x40;
        *page = index - 3;
        *offset = 128;
        *length = 128;
    } else if (index >= 19 && index < 35) {
        *addr = 0x50;
        *page = index - 19;
        *offset = 128;
        *length = 128;
    } else if (index >= 35 && index < 39) {
        *addr = 0x64;
        *page = -1;
        *offset = index - 35;
        *length = 1;
    } else {
        *addr = index == 39 ? 0x59 : 0x49;
        *page = -1;
        *offset = 0;
        *length = NETLAB_OPTICS_MUX_DUMP_LEN;
    }
}

static int optics_mux_restore(int sw, hal_optics_mux_probe_result *probe) {
    fm_uint32 word;

    if (!probe || probe->control_before < 0)
        return -1;
    word = (fm_uint32)(probe->control_before & 0xff);
    probe->restore_status = (int)fmPlatformI2cWriteRead(
        (fm_int)sw, (fm_int)probe->bus, (fm_int)probe->mux_addr,
        &word, 1, 0);
    return probe->restore_status;
}

static int optics_mux_select(int sw, hal_optics_mux_probe_result *probe,
                             int branch) {
    fm_uint32 word;

    word = (fm_uint32)(probe->branch[branch].mux_value & 0xff);
    return (int)fmPlatformI2cWriteRead(
        (fm_int)sw, (fm_int)probe->bus, (fm_int)probe->mux_addr,
        &word, 1, 0);
}

static void optics_mux_advance_branch(optics_mux_progress *progress) {
    if (++progress->branch >= NETLAB_OPTICS_MUX_MAX_BRANCHES) {
        progress->phase = OPTICS_MUX_PHASE_DONE;
        return;
    }
    progress->scan_index = 0;
    progress->dump_index = 0;
    progress->dump_done = 0;
    progress->phase = OPTICS_MUX_PHASE_BRANCH_BEGIN;
}

static int optics_mux_yield_or_complete(
    optics_mux_progress *progress, hal_optics_mux_probe_result *probe) {
    u64 sampled_ns;

    if (progress->phase != OPTICS_MUX_PHASE_DONE)
        return SDK_EXEC_SLICE_YIELD;
    sampled_ns = monotonic_ns();
    if (sampled_ns == 0)
        return -EIO;
    probe->complete = true;
    probe->sampled_monotonic_ms = sampled_ns / 1000000ULL;
    return SDK_EXEC_SLICE_DONE;
}

/*
 * Run one bounded optics-I2C slice.  Every yielded slice restores both the
 * selected device page and the board mux before returning.  The executor can
 * therefore schedule control/readback work between slices without allowing a
 * second thread into the vendor SDK or leaking transient mux state.
 */
static int optics_mux_probe_slice(int sw, const struct sdk_op *op,
                                  struct sdk_result *result,
                                  optics_mux_progress *progress) {
    hal_optics_mux_probe_result *probe;
    hal_optics_mux_branch_dump *branch;
    hal_optics_mux_addr_dump *dump;
    fm_uint32 word = 0;
    fm_byte raw[OPTICS_MUX_READ_CHUNK];
    int address;
    int page;
    int offset;
    int length;
    int chunk;
    int status;
    int page_restore_status = 0;
    bool page_selected = false;

    if (!op || !result || !progress)
        return -1;
    probe = &result->data.optics_mux_probe;

    if (progress->phase == OPTICS_MUX_PHASE_INIT) {
        memset(probe, 0, sizeof(*probe));
        probe->bus = op->args.optics_mux_probe.bus >= 0 ?
            op->args.optics_mux_probe.bus : 0;
        probe->mux_addr = op->args.optics_mux_probe.mux_addr > 0 ?
            op->args.optics_mux_probe.mux_addr : 0x58;
        probe->control_before = -1;
        probe->restore_status = -1;
        probe->branch_count = NETLAB_OPTICS_MUX_MAX_BRANCHES;
        for (int b = 0; b < NETLAB_OPTICS_MUX_MAX_BRANCHES; b++) {
            progress->branch_values[b] =
                op->args.optics_mux_probe.branch[b] > 0 ?
                op->args.optics_mux_probe.branch[b] : b + 1;
            branch = &probe->branch[b];
            branch->mux_value = progress->branch_values[b];
            branch->select_status = -1;
            branch->control_after = -1;
            branch->addr_count = NETLAB_OPTICS_MUX_MAX_ADDRS;
            branch->scan_start = NETLAB_OPTICS_MUX_SCAN_MIN;
            branch->scan_count = NETLAB_OPTICS_MUX_SCAN_COUNT;
            for (int i = 0; i < NETLAB_OPTICS_MUX_SCAN_COUNT; i++)
                branch->scan_status[i] = -1;
            for (int i = 0; i < NETLAB_OPTICS_MUX_MAX_ADDRS; i++) {
                optics_mux_dump_descriptor(i, &address, &page, &offset,
                                           &length);
                branch->addr[i].addr = address;
                branch->addr[i].page = page;
                branch->addr[i].offset = offset;
                branch->addr[i].status = -1;
                branch->addr[i].length = 0;
            }
        }
        status = (int)fmPlatformI2cWriteRead(
            (fm_int)sw, (fm_int)probe->bus, (fm_int)probe->mux_addr,
            &word, 0, 1);
        if (status != FM_OK)
            return status;
        probe->control_before = (int)(word & 0xff);
        progress->phase = OPTICS_MUX_PHASE_BRANCH_BEGIN;
        return SDK_EXEC_SLICE_YIELD;
    }

    if (progress->phase == OPTICS_MUX_PHASE_DONE) {
        u64 sampled_ns = monotonic_ns();

        if (sampled_ns == 0)
            return -EIO;
        probe->complete = true;
        probe->sampled_monotonic_ms = sampled_ns / 1000000ULL;
        return SDK_EXEC_SLICE_DONE;
    }

    branch = &probe->branch[progress->branch];
    status = optics_mux_select(sw, probe, progress->branch);
    if (progress->phase == OPTICS_MUX_PHASE_BRANCH_BEGIN)
        branch->select_status = status;
    if (status != FM_OK) {
        if (optics_mux_restore(sw, probe) != FM_OK)
            return probe->restore_status;
        if (progress->phase == OPTICS_MUX_PHASE_BRANCH_BEGIN) {
            for (int i = 0; i < NETLAB_OPTICS_MUX_SCAN_COUNT; i++)
                branch->scan_status[i] = status;
            for (int i = 0; i < NETLAB_OPTICS_MUX_MAX_ADDRS; i++)
                branch->addr[i].status = status;
            optics_mux_advance_branch(progress);
            return optics_mux_yield_or_complete(progress, probe);
        } else if (progress->phase == OPTICS_MUX_PHASE_SCAN) {
            branch->scan_status[progress->scan_index++] = status;
            if (progress->scan_index >= NETLAB_OPTICS_MUX_SCAN_COUNT) {
                progress->dump_index = 0;
                progress->dump_done = 0;
                progress->phase = OPTICS_MUX_PHASE_DUMP;
            }
        } else if (progress->phase == OPTICS_MUX_PHASE_DUMP) {
            branch->addr[progress->dump_index].status = status;
            progress->dump_index++;
            progress->dump_done = 0;
            if (progress->dump_index >= NETLAB_OPTICS_MUX_MAX_ADDRS) {
                optics_mux_advance_branch(progress);
                return optics_mux_yield_or_complete(progress, probe);
            }
        } else {
            return status;
        }
        return SDK_EXEC_SLICE_YIELD;
    }

    if (progress->phase == OPTICS_MUX_PHASE_BRANCH_BEGIN) {
        word = 0;
        status = (int)fmPlatformI2cWriteRead(
            (fm_int)sw, (fm_int)probe->bus, (fm_int)probe->mux_addr,
            &word, 0, 1);
        if (optics_mux_restore(sw, probe) != FM_OK)
            return probe->restore_status;
        if (status != FM_OK)
            return status;
        branch->control_after = (int)(word & 0xff);
        progress->scan_index = 0;
        progress->phase = OPTICS_MUX_PHASE_SCAN;
        return SDK_EXEC_SLICE_YIELD;
    }

    if (progress->phase == OPTICS_MUX_PHASE_SCAN) {
        address = NETLAB_OPTICS_MUX_SCAN_MIN + progress->scan_index;
        branch->scan_status[progress->scan_index++] =
            optics_mux_probe_address(sw, address);
        if (optics_mux_restore(sw, probe) != FM_OK)
            return probe->restore_status;
        if (progress->scan_index >= NETLAB_OPTICS_MUX_SCAN_COUNT) {
            progress->dump_index = 0;
            progress->dump_done = 0;
            progress->phase = OPTICS_MUX_PHASE_DUMP;
        }
        return SDK_EXEC_SLICE_YIELD;
    }

    if (progress->phase == OPTICS_MUX_PHASE_DUMP) {
        dump = &branch->addr[progress->dump_index];
        optics_mux_dump_descriptor(progress->dump_index, &address, &page,
                                   &offset, &length);
        if (page >= 0) {
            status = optics_mux_write_byte(sw, address, 0x7f, page);
            if (status != FM_OK) {
                dump->status = status;
            } else {
                page_selected = true;
            }
        }
        if (dump->status == -1 || dump->status == 0) {
            chunk = length - progress->dump_done;
            if (chunk > OPTICS_MUX_READ_CHUNK)
                chunk = OPTICS_MUX_READ_CHUNK;
            memset(raw, 0, sizeof(raw));
            raw[0] = (fm_byte)(offset + progress->dump_done);
            status = (int)fmI2cWriteRead(
                (fm_int)sw, (fm_uint)address, raw, 1, (fm_uint)chunk);
            if (status == FM_OK) {
                memcpy(dump->bytes + progress->dump_done, raw,
                       (size_t)chunk);
                progress->dump_done += chunk;
                dump->status = 0;
            } else {
                dump->status = status;
            }
        }
        if (page_selected)
            page_restore_status = optics_mux_write_byte(
                sw, address, 0x7f, 0);
        if (optics_mux_restore(sw, probe) != FM_OK)
            return probe->restore_status;
        if (page_restore_status != FM_OK)
            return page_restore_status;
        if (dump->status != 0 || progress->dump_done >= length) {
            if (dump->status == 0)
                dump->length = length;
            progress->dump_index++;
            progress->dump_done = 0;
            if (progress->dump_index >= NETLAB_OPTICS_MUX_MAX_ADDRS) {
                optics_mux_advance_branch(progress);
                return optics_mux_yield_or_complete(progress, probe);
            }
        }
        return SDK_EXEC_SLICE_YIELD;
    }

    return -EINVAL;
}

static bool board_env_all_ff(const u8 *raw, int len) {
    if (!raw || len <= 0)
        return true;
    for (int i = 0; i < len; i++)
        if (raw[i] != 0xff)
            return false;
    return true;
}

static hal_board_env_sensor *board_env_add_sensor(
    hal_board_env_result *env, const char *name, const char *sensor_class,
    const char *unit, const char *chip, int branch, int addr, int reg,
    const u8 *raw, int raw_len) {
    hal_board_env_sensor *sensor;

    if (!env || env->sensor_count >= NETLAB_BOARD_ENV_MAX_SENSORS)
        return NULL;
    sensor = &env->sensor[env->sensor_count++];
    memset(sensor, 0, sizeof(*sensor));
    snprintf(sensor->name, sizeof(sensor->name), "%s", name);
    snprintf(sensor->sensor_class, sizeof(sensor->sensor_class), "%s",
             sensor_class);
    snprintf(sensor->unit, sizeof(sensor->unit), "%s", unit);
    snprintf(sensor->chip, sizeof(sensor->chip), "%s", chip);
    snprintf(sensor->status, sizeof(sensor->status), "unavailable");
    sensor->branch = branch;
    sensor->addr = addr;
    sensor->reg = reg;
    if (raw && raw_len > 0) {
        if (raw_len > NETLAB_BOARD_ENV_RAW_MAX)
            raw_len = NETLAB_BOARD_ENV_RAW_MAX;
        memcpy(sensor->raw, raw, (size_t)raw_len);
        sensor->raw_len = raw_len;
    }
    return sensor;
}

static void board_env_set_value(hal_board_env_sensor *sensor, float value,
                                float minimum, float maximum) {
    if (!sensor || board_env_all_ff(sensor->raw, sensor->raw_len) ||
        value < minimum || value > maximum)
        return;
    sensor->value = value;
    sensor->valid = true;
    snprintf(sensor->status, sizeof(sensor->status), "available");
}

static void board_env_add_responder(hal_board_env_result *env,
                                    const char *role, int branch,
                                    int addr, int status) {
    hal_board_env_responder *responder;

    if (!env || env->responder_count >= NETLAB_BOARD_ENV_MAX_RESPONDERS)
        return;
    responder = &env->responder[env->responder_count++];
    memset(responder, 0, sizeof(*responder));
    snprintf(responder->role, sizeof(responder->role), "%s", role);
    responder->branch = branch;
    responder->addr = addr;
    responder->status = status;
    if (status != 0)
        env->sample_failures = 1;
}

static int board_env_read_registers(int sw, int addr, int reg,
                                    u8 *raw, int len) {
    int status = optics_mux_read_bytes(sw, addr, reg, raw, len);

    if (status == 0 && board_env_all_ff(raw, len))
        return -ENODEV;
    return status;
}

static float board_env_signed_temperature(u8 msb, u8 lsb) {
    return (float)(int)(s16)(((u16)msb << 8) | lsb) / 256.0f;
}

static void board_env_parse_cpld_snapshot(hal_board_env_result *env,
                                          int branch, int cpld_addr,
                                          const u8 *raw, int len) {
    static const int rail_offsets[8] = {
        0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
    };
    hal_board_env_sensor *sensor;
    char name[48];

    if (!env || !raw || len <= 0xa4)
        return;
    sensor = board_env_add_sensor(env, "cpld-fci-1-temperature",
                                  "temperature", "celsius", "FCI",
                                  branch, cpld_addr, 0x00, raw + 0x00, 2);
    (void)sensor;
    sensor = board_env_add_sensor(env, "cpld-fci-2-temperature",
                                  "temperature", "celsius", "FCI",
                                  branch, cpld_addr, 0x20, raw + 0x20, 2);
    (void)sensor;

    sensor = board_env_add_sensor(env, "ir3584-temperature-1", "temperature",
                                  "celsius", "IR3584", branch, cpld_addr,
                                  0x60, raw + 0x60, 1);
    sensor = board_env_add_sensor(env, "ir3584-temperature-2", "temperature",
                                  "celsius", "IR3584", branch, cpld_addr,
                                  0x61, raw + 0x61, 1);
    sensor = board_env_add_sensor(env, "ir3584-vout", "voltage", "volts",
                                  "IR3584", branch, cpld_addr, 0x62,
                                  raw + 0x62, 1);
    sensor = board_env_add_sensor(env, "ir3584-status", "status", "boolean",
                                  "IR3584", branch, cpld_addr, 0x63,
                                  raw + 0x63, 1);

    for (int i = 0; i < 8; i++) {
        snprintf(name, sizeof(name), "ucd9081-rail-%d", i + 1);
        sensor = board_env_add_sensor(env, name, "voltage", "volts",
                                      "UCD9081", branch, cpld_addr,
                                      rail_offsets[i], raw + rail_offsets[i],
                                      2);
        (void)sensor;
    }
    sensor = board_env_add_sensor(env, "lm96163-fan", "fan", "rpm",
                                  "LM96163", branch, cpld_addr, 0xa3,
                                  raw + 0xa3, 2);
    (void)sensor;
}

static void board_env_collect_fci(int sw, const struct sdk_op *op,
                                  hal_board_env_result *env) {
    u8 snapshot[0xb2] = {0};
    u8 one[1] = {0};
    u8 module[32] = {0};
    int branch = op->args.board_env.branch;
    int status;

    status = board_env_read_registers(sw, 0x40, 0x00, one, 1);
    board_env_add_responder(env, "fci-memory-0x40", branch, 0x40, status);
    status = board_env_read_registers(sw, 0x50, 0x00, module,
                                      sizeof(module));
    board_env_add_responder(env, "fci-memory-0x50", branch, 0x50, status);
    {
        char name[48];
        hal_board_env_sensor *sensor;
        const u8 *temperature_raw =
            (status == 0 || status == -ENODEV) ? module + 22 : NULL;

        snprintf(name, sizeof(name), "fci-%d-temperature",
                 op->args.board_env.sample + 1);
        sensor = board_env_add_sensor(env, name, "temperature", "celsius",
                                      "FCI", branch, 0x50, 22,
                                      temperature_raw,
                                      temperature_raw ? 2 : 0);
        if (status == 0)
            board_env_set_value(
                sensor, board_env_signed_temperature(module[22], module[23]),
                -40.0f, 125.0f);
    }
    status = board_env_read_registers(sw, op->args.board_env.cpld_ram_addr,
                                      0x00, snapshot, sizeof(snapshot));
    board_env_add_responder(env, "cpld-dual-port-ram", branch,
                            op->args.board_env.cpld_ram_addr, status);
    if ((status == 0 || status == -ENODEV) &&
        op->args.board_env.sample == 0)
        board_env_parse_cpld_snapshot(
            env, branch, op->args.board_env.cpld_ram_addr,
            snapshot, sizeof(snapshot));

    status = board_env_read_registers(sw, op->args.board_env.reset_gpio_addr,
                                      0x00, one, 1);
    board_env_add_responder(env, "fci-reset-gpio", branch,
                            op->args.board_env.reset_gpio_addr, status);
    {
        int bit = op->args.board_env.sample;
        char name[48];
        hal_board_env_sensor *sensor;
        const u8 *reset_raw =
            (status == 0 || status == -ENODEV) ? one : NULL;

        snprintf(name, sizeof(name), "fci-%d-reset-deasserted", bit + 1);
        sensor = board_env_add_sensor(env, name, "status", "boolean",
                                      "PCA9538", branch,
                                      op->args.board_env.reset_gpio_addr,
                                      0x00, reset_raw, reset_raw ? 1 : 0);
        if (sensor && status == 0) {
            sensor->value = (one[0] & (1U << bit)) ? 1.0f : 0.0f;
            sensor->valid = true;
            snprintf(sensor->status, sizeof(sensor->status), "available");
        }
    }
}

static void board_env_collect_adt7461(int sw, const struct sdk_op *op,
                                      hal_board_env_result *env) {
    u8 local[1] = {0};
    u8 remote_msb[1] = {0};
    u8 remote_lsb[1] = {0};
    int branch = op->args.board_env.branch;
    int st_local = board_env_read_registers(sw, 0x4c, 0x00, local, 1);
    int st_msb = board_env_read_registers(sw, 0x4c, 0x01, remote_msb, 1);
    int st_lsb = board_env_read_registers(sw, 0x4c, 0x10, remote_lsb, 1);
    hal_board_env_sensor *sensor;
    u8 remote[2] = {remote_msb[0], remote_lsb[0]};
    const u8 *local_raw =
        (st_local == 0 || st_local == -ENODEV) ? local : NULL;
    const u8 *remote_raw =
        ((st_msb == 0 || st_msb == -ENODEV) &&
         (st_lsb == 0 || st_lsb == -ENODEV)) ? remote : NULL;

    board_env_add_responder(env, "adt7461", branch, 0x4c,
                            st_local != 0 ? st_local :
                            (st_msb != 0 ? st_msb : st_lsb));
    sensor = board_env_add_sensor(env, "adt7461-local-temperature",
                                  "temperature", "celsius", "ADT7461",
                                  branch, 0x4c, 0x00, local_raw,
                                  local_raw ? 1 : 0);
    (void)sensor;
    sensor = board_env_add_sensor(env, "adt7461-remote-temperature",
                                  "temperature", "celsius", "ADT7461",
                                  branch, 0x4c, 0x01, remote_raw,
                                  remote_raw ? 2 : 0);
    (void)sensor;
    (void)st_msb;
    (void)st_lsb;
}

static void board_env_collect_power(int sw, const struct sdk_op *op,
                                    hal_board_env_result *env) {
    u8 ir[1] = {0};
    u8 ucd[2] = {0};
    u8 local[1] = {0};
    u8 remote[2] = {0};
    int branch = op->args.board_env.branch;
    int st_ir = board_env_read_registers(sw, 0x08, 0x8d, ir, 1);
    int st_ucd = board_env_read_registers(sw, 0x60, 0x00, ucd, 2);
    int st_local = board_env_read_registers(sw, 0x4c, 0x00, local, 1);
    int st_msb = -ENODATA;
    int st_lsb = -ENODATA;
    int st_lm;
    hal_board_env_sensor *sensor;
    const u8 *local_raw;
    const u8 *remote_raw;

    board_env_add_responder(env, "ir3584", branch, 0x08, st_ir);
    board_env_add_responder(env, "ucd9081", branch, 0x60, st_ucd);
    if (st_local == 0) {
        st_msb = board_env_read_registers(sw, 0x4c, 0x01, remote, 1);
        if (st_msb == 0)
            st_lsb = board_env_read_registers(sw, 0x4c, 0x10,
                                              remote + 1, 1);
    }
    st_lm = st_local != 0 ? st_local : (st_msb != 0 ? st_msb : st_lsb);
    board_env_add_responder(env, "lm96163", branch, 0x4c, st_lm);
    local_raw = (st_local == 0 || st_local == -ENODEV) ? local : NULL;
    remote_raw =
        ((st_msb == 0 || st_msb == -ENODEV) &&
         (st_lsb == 0 || st_lsb == -ENODEV)) ? remote : NULL;
    sensor = board_env_add_sensor(env, "lm96163-local-temperature",
                                  "temperature", "celsius", "LM96163",
                                  branch, 0x4c, 0x00, local_raw,
                                  local_raw ? 1 : 0);
    (void)sensor;
    sensor = board_env_add_sensor(env, "lm96163-remote-temperature",
                                  "temperature", "celsius", "LM96163",
                                  branch, 0x4c, 0x01, remote_raw,
                                  remote_raw ? 2 : 0);
    (void)sensor;
}

static int board_env_get(int sw, const struct sdk_op *op,
                         struct sdk_result *result) {
    hal_board_env_result *env;
    fm_uint32 word = 0;
    fm_status status;

    if (!op || !result)
        return -1;
    env = &result->data.board_env;
    memset(env, 0, sizeof(*env));
    env->bus = op->args.board_env.bus;
    env->mux_addr = op->args.board_env.mux_addr;
    env->mux_before = -1;
    env->restore_status = -1;
    env->sample_count = 1;

    status = fmPlatformI2cWriteRead((fm_int)sw, (fm_int)env->bus,
                                    (fm_int)env->mux_addr, &word, 0, 1);
    if (status != FM_OK) {
        env->sample_failures = 1;
        return 0;
    }
    env->mux_before = (int)(word & 0xff);
    word = (fm_uint32)(op->args.board_env.branch & 0xff);
    status = fmPlatformI2cWriteRead((fm_int)sw, (fm_int)env->bus,
                                    (fm_int)env->mux_addr, &word, 1, 0);
    if (status != FM_OK) {
        env->sample_failures = 1;
        goto restore;
    }

    switch (op->args.board_env.sample) {
    case 0:
    case 1:
        board_env_collect_fci(sw, op, env);
        break;
    case 2:
        board_env_collect_adt7461(sw, op, env);
        break;
    case 3:
        board_env_collect_power(sw, op, env);
        break;
    default:
        env->sample_failures = 1;
        break;
    }

restore:
    word = (fm_uint32)(env->mux_before & 0xff);
    env->restore_status = (int)fmPlatformI2cWriteRead(
        (fm_int)sw, (fm_int)env->bus, (fm_int)env->mux_addr,
        &word, 1, 0);
    if (env->restore_status != FM_OK)
        env->sample_failures = 1;
    return 0;
}

static u64 monotonic_ns(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (u64)now.tv_sec * 1000000000ULL + (u64)now.tv_nsec;
}

static int monotonic_cond_init(pthread_cond_t *cond) {
    pthread_condattr_t attr;
    int rc;

    if (!cond)
        return EINVAL;
    rc = pthread_condattr_init(&attr);
    if (rc != 0)
        return rc;
    rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (rc == 0)
        rc = pthread_cond_init(cond, &attr);
    pthread_condattr_destroy(&attr);
    return rc;
}

static struct timespec monotonic_deadline(u64 now_ns, u64 delay_ns) {
    struct timespec deadline;
    u64 value = UINT64_MAX - now_ns < delay_ns ?
        UINT64_MAX : now_ns + delay_ns;

    deadline.tv_sec = (time_t)(value / 1000000000ULL);
    deadline.tv_nsec = (long)(value % 1000000000ULL);
    return deadline;
}

static void metric_hist_record(u64 *hist, u64 duration_ns) {
    u64 duration_us = duration_ns / 1000ULL;

    for (int i = 0; i < SDK_EXEC_HIST_BUCKETS; i++) {
        if (duration_us <= sdk_exec_hist_us[i]) {
            hist[i]++;
            return;
        }
    }
    hist[SDK_EXEC_HIST_BUCKETS - 1]++;
}

static u64 metric_hist_quantile(const u64 *hist, u64 count,
                                unsigned percentile) {
    u64 target;
    u64 seen = 0;

    if (!hist || count == 0)
        return 0;
    target = (count * percentile + 99ULL) / 100ULL;
    if (target == 0)
        target = 1;
    for (int i = 0; i < SDK_EXEC_HIST_BUCKETS; i++) {
        seen += hist[i];
        if (seen >= target)
            return sdk_exec_hist_us[i];
    }
    return sdk_exec_hist_us[SDK_EXEC_HIST_BUCKETS - 1];
}

static bool executor_has_work(const struct sdk_executor *exec) {
    if (!exec)
        return false;
    for (int priority = 0; priority < SDK_PRIO_COUNT; priority++) {
        if (exec->queue_count[priority] > 0)
            return true;
    }
    return false;
}

static int executor_select_priority(const struct sdk_executor *exec,
                                    u64 now_ns) {
    int selected = -1;
    u64 oldest_ns = UINT64_MAX;

    if (!exec)
        return -1;
    for (int priority = SDK_PRIO_CONTROL_PACKET;
         priority < SDK_PRIO_COUNT; priority++) {
        sdk_exec_op_t *head;
        u64 age_ns;

        if (exec->queue_count[priority] <= 0)
            continue;
        head = exec->queues[priority][0];
        age_ns = now_ns >= head->enqueued_ns ?
            now_ns - head->enqueued_ns : 0;
        if (age_ns >= SDK_EXEC_AGING_NS && head->enqueued_ns < oldest_ns) {
            selected = priority;
            oldest_ns = head->enqueued_ns;
        }
    }
    if (selected >= 0)
        return selected;
    for (int priority = SDK_PRIO_CONTROL_PACKET;
         priority < SDK_PRIO_COUNT; priority++) {
        if (exec->queue_count[priority] > 0)
            return priority;
    }
    return -1;
}

static bool sdk_op_can_detach_on_timeout(sdk_op_type type) {
    switch (type) {
        case SDK_OP_GET_PORT_STATE:
        case SDK_OP_GET_COUNTERS:
        case SDK_OP_GET_XCVR:
        case SDK_OP_GET_TEMPERATURE:
        case SDK_OP_GET_MAC_TABLE:
        case SDK_OP_GET_MAC_AGING_TIME:
        case SDK_OP_GET_STP_TABLE:
        case SDK_OP_GET_VLAN_STATE:
        case SDK_OP_PACKET_RX_POLL:
        case SDK_OP_LAG_GET_ALL:
        case SDK_OP_GET_PFE_RESOURCES:
        case SDK_OP_GET_SWITCH_SENSORS:
        case SDK_OP_GET_SWITCH_CONFIG:
        case SDK_OP_GET_CONTROL_PLANE_PROTECTION:
        case SDK_OP_GET_L2_SECURITY_USER_FILTER_COUNTERS:
        case SDK_OP_GET_INGRESS_IPV4_ACL_COUNTERS:
        case SDK_OP_GET_EGRESS_ACL_COUNTERS:
        case SDK_OP_GET_ACL_POLICER_COUNTERS:
        case SDK_OP_GET_ACL_COUNTER_SNAPSHOT:
        case SDK_OP_OPTICS_MUX_PROBE:
        case SDK_OP_GET_PORT_SNAPSHOT:
        case SDK_OP_GET_QOS_READBACK:
        case SDK_OP_L3_SDK_READBACK_PROBE:
        case SDK_OP_GET_SFLOW_STATE:
        case SDK_OP_NOP:
            return true;
        default:
            return false;
    }
}

static void sdk_exec_op_destroy(sdk_exec_op_t *op) {
    if (!op)
        return;
    if (op->op.type == SDK_OP_GET_MAC_TABLE)
        nl_mac_snapshot_reset(&op->result.data.mac_table);
    if (op->op.type == SDK_OP_GET_STP_TABLE)
        nl_stp_snapshot_reset(&op->result.data.stp_table);
    if (op->apply_plan_copy) {
        l2_apply_plan_reset(op->apply_plan_copy);
        free(op->apply_plan_copy);
    }
    free(op->acl_counter_query_copy);
    pthread_mutex_destroy(&op->lock);
    pthread_cond_destroy(&op->cond);
    free(op);
}

static int sdk_exec_op_prepare(sdk_exec_op_t *eop,
                               const struct sdk_op *op) {
    eop->op = *op;
    if ((op->type == SDK_OP_APPLY_L2_PLAN ||
         op->type == SDK_OP_ROLLBACK_L2_PLAN) &&
        op->args.apply_plan) {
        eop->apply_plan_copy = calloc(1, sizeof(*eop->apply_plan_copy));
        if (!eop->apply_plan_copy)
            return -1;
        l2_apply_plan_init(eop->apply_plan_copy);
        if (l2_apply_plan_clone(eop->apply_plan_copy,
                                op->args.apply_plan) != 0) {
            l2_apply_plan_reset(eop->apply_plan_copy);
            free(eop->apply_plan_copy);
            eop->apply_plan_copy = NULL;
            return -1;
        }
        eop->apply_plan_output = op->args.apply_plan;
        eop->op.args.apply_plan = eop->apply_plan_copy;
    }
    if (op->type == SDK_OP_GET_ACL_COUNTER_SNAPSHOT &&
        op->args.acl_counter_query) {
        eop->acl_counter_query_copy =
            malloc(sizeof(*eop->acl_counter_query_copy));
        if (!eop->acl_counter_query_copy)
            return -1;
        *eop->acl_counter_query_copy = *op->args.acl_counter_query;
        eop->op.args.acl_counter_query = eop->acl_counter_query_copy;
    }
    return 0;
}

static bool sdk_exec_remove_queued(struct sdk_executor *exec,
                                   sdk_exec_op_t *target,
                                   int priority) {
    if (!exec || !target || priority < 0 || priority >= SDK_PRIO_COUNT)
        return false;
    for (int i = 0; i < exec->queue_count[priority]; i++) {
        if (exec->queues[priority][i] != target)
            continue;
        for (int j = i + 1; j < exec->queue_count[priority]; j++)
            exec->queues[priority][j - 1] = exec->queues[priority][j];
        exec->queue_count[priority]--;
        exec->queues[priority][exec->queue_count[priority]] = NULL;
        exec->metrics[priority].cancelled++;
        return true;
    }
    return false;
}

/* A configuration keeps its stack, snapshots and pause ownership while the
 * sole SDK thread handles a bounded amount of unrelated runtime work. */
typedef struct {
    struct sdk_executor *exec;
    bool allow_fan_poll, entered;
    u64 nested_ns;
} sdk_plan_checkpoint;

#define SDK_PLAN_CHECKPOINT_MAX_OPS 4
#define SDK_PLAN_CHECKPOINT_NS (5ULL * 1000ULL * 1000ULL)

static void executor_run_op(struct sdk_executor *, sdk_exec_op_t *, int, u64);

static bool checkpoint_eligible(const sdk_exec_op_t *request, bool fan_poll) {
    const struct sdk_op *op = &request->op;
    if (!op->runtime)
        return fan_poll && op->type == SDK_OP_FM10K_BOARD_POLL;
    switch (op->type) {
    case SDK_OP_PACKET_TX:
    case SDK_OP_PACKET_RX_POLL:
    case SDK_OP_RUNTIME_STP_SET:
    case SDK_OP_LAG_ADD_PORT:
    case SDK_OP_LAG_DEL_PORT:
    case SDK_OP_PORT_SET_ADMIN:
    case SDK_OP_CLEAR_DYNAMIC_MAC_TABLE:
    case SDK_OP_APPLY_L2_PLAN: /* Runtime scope validation admits only IGMP steps. */
    case SDK_OP_GET_PORT_STATE:
    case SDK_OP_GET_PORT_SNAPSHOT:
    case SDK_OP_LAG_GET_ALL:
        return true;
    default:
        return false;
    }
}

static void executor_plan_checkpoint(void *context) {
    sdk_plan_checkpoint *checkpoint = context;
    struct sdk_executor *exec = checkpoint ? checkpoint->exec : NULL;
    if (!exec || checkpoint->entered || !pthread_equal(pthread_self(), exec->thread))
        return;
    checkpoint->entered = true;
    u64 begin = monotonic_ns();
    for (int dispatched = 0; dispatched < SDK_PLAN_CHECKPOINT_MAX_OPS; ++dispatched) {
        u64 now = monotonic_ns();
        if (now - begin >= SDK_PLAN_CHECKPOINT_NS) break;
        int chosen_priority = -1, chosen_index = -1;
        int fallback_priority = -1, fallback_index = -1;
        u64 oldest = UINT64_MAX;
        pthread_mutex_lock(&exec->lock);
        /* Skip another configuration at the head of a queue. It cannot block
         * eligible protocol work behind it, nor run inside the current plan. */
        for (int priority = 0; priority < SDK_PRIO_COUNT; ++priority) {
            for (int index = 0; index < exec->queue_count[priority]; ++index) {
                sdk_exec_op_t *candidate = exec->queues[priority][index];
                if (!checkpoint_eligible(candidate, checkpoint->allow_fan_poll)) continue;
                if (fallback_priority < 0) { fallback_priority = priority; fallback_index = index; }
                if (now >= candidate->enqueued_ns && now - candidate->enqueued_ns >= SDK_EXEC_AGING_NS &&
                    candidate->enqueued_ns < oldest) {
                    chosen_priority = priority; chosen_index = index; oldest = candidate->enqueued_ns;
                }
            }
        }
        if (chosen_priority < 0) { chosen_priority = fallback_priority; chosen_index = fallback_index; }
        if (chosen_priority < 0) { pthread_mutex_unlock(&exec->lock); break; }
        sdk_exec_op_t *request = exec->queues[chosen_priority][chosen_index];
        for (int index = chosen_index + 1; index < exec->queue_count[chosen_priority]; ++index)
            exec->queues[chosen_priority][index - 1] = exec->queues[chosen_priority][index];
        exec->queues[chosen_priority][--exec->queue_count[chosen_priority]] = NULL;
        pthread_mutex_unlock(&exec->lock);
        executor_run_op(exec, request, chosen_priority, monotonic_ns());
    }
    checkpoint->nested_ns += monotonic_ns() - begin;
    checkpoint->entered = false;
}

static void executor_run_op(struct sdk_executor *exec, sdk_exec_op_t *op,
                             int priority, u64 started_ns) {
    u64 completed_ns;
    int dispatch_status;
    bool yielded = false;
    pthread_mutex_lock(&op->lock);
    if (op->cancelled) {
        pthread_mutex_unlock(&op->lock);
        sdk_exec_op_destroy(op);
        return;
    }
    op->running = true;
    if (op->started_ns == 0)
        op->started_ns = started_ns;
    pthread_mutex_unlock(&op->lock);

    bool native = fm10k_native_profile();
    sdk_plan_checkpoint checkpoint = {.exec = exec, .allow_fan_poll = true};
    l2_apply_plan *cooperative_plan = native && !op->op.runtime &&
        (op->op.type == SDK_OP_APPLY_L2_PLAN || op->op.type == SDK_OP_ROLLBACK_L2_PLAN) ?
        op->op.args.apply_plan : NULL;
    if (cooperative_plan) {
        for (int i = 0; i < cooperative_plan->n_steps; ++i)
            if (cooperative_plan->steps[i].type == L2_STEP_FM10K_FAN_SET)
                checkpoint.allow_fan_poll = false;
        cooperative_plan->checkpoint = executor_plan_checkpoint;
        cooperative_plan->checkpoint_context = &checkpoint;
    }
    int scope_status = native ? sdk_plan_scope_check(exec->sw, &op->op) : 0;
    if (fm10k_native_profile() && !sdk_native_op_supported(&op->op)) {
        dispatch_status = NL_ERR_CAPABILITY_INSUFFICIENT;
    } else if (scope_status) {
        dispatch_status = scope_status;
    } else if (op->op.type == SDK_OP_OPTICS_MUX_PROBE &&
        op->deadline_ns != 0 && started_ns >= op->deadline_ns) {
        dispatch_status = -ETIMEDOUT;
        op->result.error_msg = "executor request deadline exceeded";
    } else if (op->op.type == SDK_OP_OPTICS_MUX_PROBE) {
        dispatch_status = optics_mux_probe_slice(
            exec->sw, &op->op, &op->result, &op->optics_mux);
        yielded = dispatch_status == SDK_EXEC_SLICE_YIELD;
        if (!yielded && dispatch_status != 0)
            op->result.error_msg = "optics mux probe incomplete";
    } else {
        dispatch_status = sdk_runtime_dispatch(exec->sw, &op->op, &op->result,
            NETLAB_SDK_EXECUTOR_DISPATCH, sdk_scope_resolve_lag, fm10k_native_profile());
    }
    if (cooperative_plan) {
        cooperative_plan->checkpoint = NULL;
        cooperative_plan->checkpoint_context = NULL;
    }
    completed_ns = monotonic_ns();
    u64 elapsed = completed_ns >= started_ns ? completed_ns - started_ns : 0;
    /* Protocol work has its own priority metrics; avoid counting it again as
     * configuration execution time. Caller latency still includes the yield. */
    op->exec_total_ns += elapsed >= checkpoint.nested_ns ? elapsed - checkpoint.nested_ns : 0;

    if (yielded) {
        pthread_mutex_lock(&op->lock);
        op->running = false;
        if (op->cancelled) {
            pthread_mutex_unlock(&op->lock);
            sdk_exec_op_destroy(op);
            return;
        }
        pthread_mutex_lock(&exec->lock);
        op->enqueued_ns = completed_ns;
        exec->queues[priority][exec->queue_count[priority]++] = op;
        pthread_cond_signal(&exec->work_avail);
        pthread_mutex_unlock(&exec->lock);
        pthread_mutex_unlock(&op->lock);
        return;
    }

    op->result.status = dispatch_status;
    op->result.sdk_status = dispatch_status;

    pthread_mutex_lock(&exec->lock);
    sdk_exec_priority_metrics *metrics = &exec->metrics[priority];
    u64 wait_ns = op->started_ns >= op->submitted_ns ?
        op->started_ns - op->submitted_ns : 0;
    u64 exec_ns = op->exec_total_ns;
    metrics->completed++;
    if (op->result.status != 0)
        metrics->failed++;
    metrics->wait_total_ns += wait_ns;
    if (wait_ns > metrics->wait_max_ns)
        metrics->wait_max_ns = wait_ns;
    metrics->exec_total_ns += exec_ns;
    if (exec_ns > metrics->exec_max_ns)
        metrics->exec_max_ns = exec_ns;
    metric_hist_record(metrics->wait_hist, wait_ns);
    metric_hist_record(metrics->exec_hist, exec_ns);
    if (op->op.type == SDK_OP_GET_PORT_SNAPSHOT) {
        exec->snapshot_generation++;
        op->result.data.port_snapshot.generation =
            exec->snapshot_generation;
    }
    if (op->op.type == SDK_OP_GET_MAC_TABLE &&
        op->result.status == 0 &&
        op->result.data.mac_table.complete) {
        exec->snapshot_generation++;
        op->result.data.mac_table.generation =
            exec->snapshot_generation;
    }
    if (op->op.type == SDK_OP_OPTICS_MUX_PROBE &&
        op->result.status == 0 &&
        op->result.data.optics_mux_probe.complete) {
        exec->snapshot_generation++;
        op->result.data.optics_mux_probe.generation =
            exec->snapshot_generation;
    }
    pthread_mutex_unlock(&exec->lock);

    pthread_mutex_lock(&op->lock);
    op->running = false;
    op->completed = true;
    if (op->cancelled) {
        pthread_mutex_unlock(&op->lock);
        sdk_exec_op_destroy(op);
        return;
    }
    pthread_cond_signal(&op->cond);
    pthread_mutex_unlock(&op->lock);
}

static void *executor_thread(void *arg) {
    struct sdk_executor *exec = (struct sdk_executor *)arg;
    for (;;) {
        int priority;
        u64 started_ns;

        /*
         * This maintenance hook runs while the executor is busy and while it
         * is otherwise idle.  Snapshot reclamation therefore does not depend
         * on a later request from the same protocol or client.
         */
        (void)l3_fib_snapshot_sweep(monotonic_ns());
        if (fm10k_native_profile()) hal_pfc_watchdog_poll(exec->sw, monotonic_ns() / 1000000ULL);
        pthread_mutex_lock(&exec->lock);
        while (exec->running && !executor_has_work(exec)) {
            struct timespec deadline = monotonic_deadline(
                monotonic_ns(), hal_pfc_watchdog_enabled() ? 100000000ULL : SDK_EXEC_MAINTENANCE_NS);
            int wait_rc = pthread_cond_timedwait(
                &exec->work_avail, &exec->lock, &deadline);

            if (wait_rc == ETIMEDOUT)
                break;
        }
        if (exec->running && !executor_has_work(exec)) {
            pthread_mutex_unlock(&exec->lock);
            continue;
        }
        if (!exec->running && !executor_has_work(exec)) {
            pthread_mutex_unlock(&exec->lock);
            break;
        }
        started_ns = monotonic_ns();
        priority = executor_select_priority(exec, started_ns);
        sdk_exec_op_t *op = priority >= 0 ? exec->queues[priority][0] : NULL;
        if (!op) {
            pthread_mutex_unlock(&exec->lock);
            continue;
        }
        for (int i = 1; i < exec->queue_count[priority]; i++)
            exec->queues[priority][i - 1] = exec->queues[priority][i];
        exec->queue_count[priority]--;
        exec->queues[priority][exec->queue_count[priority]] = NULL;
        pthread_mutex_unlock(&exec->lock);

        executor_run_op(exec, op, priority, started_ns);
    }
    if (hal_pfc_watchdog_quiesce(exec->sw))
        NL_LOG_CRIT("SDK owner exit with an unrestored PFC watchdog mask");
    return NULL;
}

int sdk_executor_init(struct sdk_executor **exec, int sw) {
    struct sdk_executor *e;
    int rc;

    if (!exec)
        return -1;
    *exec = NULL;
    e = calloc(1, sizeof(*e));
    if (!e)
        return -1;
    e->sw = sw;
    e->running = true;
    if (pthread_mutex_init(&e->lock, NULL) != 0) {
        free(e);
        return -1;
    }
    rc = monotonic_cond_init(&e->work_avail);
    if (rc != 0) {
        pthread_mutex_destroy(&e->lock);
        free(e);
        return -1;
    }
    rc = pthread_create(&e->thread, NULL, executor_thread, e);
    if (rc != 0) {
        pthread_cond_destroy(&e->work_avail);
        pthread_mutex_destroy(&e->lock);
        free(e);
        return -1;
    }
    *exec = e;
    return 0;
}

void sdk_executor_shutdown(struct sdk_executor **exec) {
    struct sdk_executor *e;

    if (!exec || !*exec)
        return;
    e = *exec;
    pthread_mutex_lock(&e->lock);
    e->running = false;
    pthread_cond_broadcast(&e->work_avail);
    pthread_mutex_unlock(&e->lock);
    pthread_join(e->thread, NULL);
    pthread_cond_destroy(&e->work_avail);
    pthread_mutex_destroy(&e->lock);
    free(e);
    *exec = NULL;
}

void sdk_executor_stats_snapshot(struct sdk_executor *exec,
                                 sdk_executor_stats *stats) {
    if (!stats)
        return;
    memset(stats, 0, sizeof(*stats));
    if (!exec)
        return;

    pthread_mutex_lock(&exec->lock);
    stats->running = exec->running;
    stats->snapshot_generation = exec->snapshot_generation;
    for (int priority = 0; priority < SDK_PRIO_COUNT; priority++) {
        const sdk_exec_priority_metrics *src = &exec->metrics[priority];
        sdk_executor_priority_stats *dst = &stats->priority[priority];

        dst->queue_depth = (u32)exec->queue_count[priority];
        dst->queue_high_watermark = src->high_watermark;
        dst->enqueued = src->enqueued;
        dst->completed = src->completed;
        dst->failed = src->failed;
        dst->cancelled = src->cancelled;
        dst->queue_full = src->queue_full;
        dst->timed_out = src->timed_out;
        if (src->completed > 0) {
            dst->wait_avg_us = src->wait_total_ns /
                src->completed / 1000ULL;
            dst->exec_avg_us = src->exec_total_ns /
                src->completed / 1000ULL;
        }
        dst->wait_p50_us = metric_hist_quantile(
            src->wait_hist, src->completed, 50);
        dst->wait_p95_us = metric_hist_quantile(
            src->wait_hist, src->completed, 95);
        dst->wait_max_us = src->wait_max_ns / 1000ULL;
        dst->exec_p50_us = metric_hist_quantile(
            src->exec_hist, src->completed, 50);
        dst->exec_p95_us = metric_hist_quantile(
            src->exec_hist, src->completed, 95);
        dst->exec_max_us = src->exec_max_ns / 1000ULL;
    }
    pthread_mutex_unlock(&exec->lock);
}

int sdk_exec(struct sdk_executor *exec, struct sdk_op *op,
             struct sdk_result *result) {
    return sdk_exec_with_prio(exec, op, result, SDK_PRIO_CONFIG_CHANGE, 30000);
}

int sdk_exec_with_prio(struct sdk_executor *exec, struct sdk_op *op,
                       struct sdk_result *result,
                       int priority, u32 timeout_ms) {
    bool detachable;
    bool timeout_recorded = false;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    /*
     * Keep every setup failure fail-closed, including allocation and
     * pthread-initialization failures below.  Many RPC callers consume the
     * structured result after this function returns, so a zero-initialized
     * status must never escape an operation that was not enqueued.
     */
    result->status = -1;
    result->sdk_status = -1;
    result->error_msg = "executor request setup failed";
    if (!exec || !op || priority < 0 || priority >= SDK_PRIO_COUNT) {
        result->error_msg = "invalid executor request";
        return -1;
    }

    sdk_exec_op_t *eop = calloc(1, sizeof(*eop));
    if (!eop) return -1;
    if (sdk_exec_op_prepare(eop, op) != 0) {
        free(eop);
        result->error_msg = "executor plan snapshot allocation failed";
        return -1;
    }
    detachable = sdk_op_can_detach_on_timeout(eop->op.type);
    eop->priority = priority;
    eop->submitted_ns = monotonic_ns();
    eop->enqueued_ns = eop->submitted_ns;
    if (timeout_ms > 0 &&
        UINT64_MAX - eop->submitted_ns >=
            (u64)timeout_ms * 1000000ULL)
        eop->deadline_ns = eop->submitted_ns +
            (u64)timeout_ms * 1000000ULL;
    if (pthread_mutex_init(&eop->lock, NULL) != 0) {
        l2_apply_plan_reset(eop->apply_plan_copy);
        free(eop->apply_plan_copy);
        free(eop->acl_counter_query_copy);
        free(eop);
        return -1;
    }
    if (monotonic_cond_init(&eop->cond) != 0) {
        pthread_mutex_destroy(&eop->lock);
        l2_apply_plan_reset(eop->apply_plan_copy);
        free(eop->apply_plan_copy);
        free(eop->acl_counter_query_copy);
        free(eop);
        return -1;
    }

    pthread_mutex_lock(&exec->lock);
    if (!exec->running) {
        pthread_mutex_unlock(&exec->lock);
        sdk_exec_op_destroy(eop);
        result->status = -1;
        result->error_msg = "executor shutting down";
        return -1;
    }
    if (exec->queue_count[priority] >= MAX_QUEUE) {
        exec->metrics[priority].queue_full++;
        pthread_mutex_unlock(&exec->lock);
        sdk_exec_op_destroy(eop);
        result->status = -1;
        result->error_msg = "executor queue full";
        return -1;
    }
    exec->queues[priority][exec->queue_count[priority]++] = eop;
    exec->metrics[priority].enqueued++;
    if ((u32)exec->queue_count[priority] >
        exec->metrics[priority].high_watermark)
        exec->metrics[priority].high_watermark =
            (u32)exec->queue_count[priority];
    pthread_cond_signal(&exec->work_avail);
    pthread_mutex_unlock(&exec->lock);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec += ts.tv_nsec / 1000000000L;
        ts.tv_nsec %= 1000000000L;
    }

    pthread_mutex_lock(&eop->lock);
    while (!eop->completed) {
        int wait_st = pthread_cond_timedwait(&eop->cond, &eop->lock, &ts);
        if (wait_st == 0)
            continue;
        if (wait_st == ETIMEDOUT && !timeout_recorded) {
            pthread_mutex_lock(&exec->lock);
            exec->metrics[priority].timed_out++;
            pthread_mutex_unlock(&exec->lock);
            timeout_recorded = true;
        }
        if (wait_st != 0 && eop->running && !detachable) {
            while (!eop->completed)
                pthread_cond_wait(&eop->cond, &eop->lock);
            break;
        }
        if (!eop->running) {
            bool removed;

            pthread_mutex_lock(&exec->lock);
            removed = sdk_exec_remove_queued(exec, eop, priority);
            pthread_mutex_unlock(&exec->lock);
            if (removed) {
                pthread_mutex_unlock(&eop->lock);
                memset(result, 0, sizeof(*result));
                result->status = -1;
                result->error_msg = wait_st == ETIMEDOUT ?
                    "timeout" : "wait error";
                sdk_exec_op_destroy(eop);
                return -1;
            }
        }
        eop->cancelled = true;
        pthread_mutex_lock(&exec->lock);
        exec->metrics[priority].cancelled++;
        pthread_mutex_unlock(&exec->lock);
        pthread_mutex_unlock(&eop->lock);
        memset(result, 0, sizeof(*result));
        result->status = -1;
        result->error_msg = wait_st == ETIMEDOUT ? "timeout" : "wait error";
        return -1;
    }
    if (eop->apply_plan_output)
        l2_apply_plan_move(eop->apply_plan_output,
                           eop->apply_plan_copy);
    *result = eop->result;
    if (eop->op.type == SDK_OP_GET_MAC_TABLE)
        eop->result.data.mac_table.entries = NULL;
    if (eop->op.type == SDK_OP_GET_STP_TABLE)
        eop->result.data.stp_table.entries = NULL;
    pthread_mutex_unlock(&eop->lock);
    sdk_exec_op_destroy(eop);
    return result->status;
}

int sdk_exec_staged(struct sdk_executor *exec,
                    struct sdk_op *ops, int n_ops,
                    struct sdk_result *results) {
    if (!exec || !ops || n_ops <= 0) return -1;
    for (int i = 0; i < n_ops; i++) {
        hw_state_tracker_record_pre(&ops[i]);
        int st = sdk_exec(exec, &ops[i], &results[i]);
        results[i].status = st;
        if (st != 0) {
            for (int j = i - 1; j >= 0; j--)
                sdk_exec_undo(&ops[j]);
            return st;
        }
    }
    return 0;
}

static int sdk_read_port_state(int sw, int port, hal_port_state *state_out, bool configuration_only) {
    fm_int mode = 0;
    fm_int state = 0;
    fm_int info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
    fm_status st;

    if (!state_out)
        return -1;
    memset(state_out, 0, sizeof(*state_out));
    /* IES fmGetPortStateV3 excludes ALLOW_LAG. MTU/PVID belong to
     * aggregate ports too and must not depend on a physical MAC query. */
    if (!configuration_only) {
        st = fmGetPortState((fm_int)sw, (fm_int)port, &mode, &state, info);
        if (st != FM_OK) return -1;
        state_out->mode = (int)mode;
        state_out->state = (int)state;
        for (int i = 0; i < NETLAB_PORT_STATE_INFO_SLOTS; i++)
            state_out->info[i] = (int)info[i];
        fm_uint32 speed = 0;
        if (fmGetPortAttribute((fm_int)sw, (fm_int)port, FM_PORT_SPEED, &speed) == FM_OK)
            state_out->speed = (int)speed;
        fm_ethMode ethernet_mode = FM_ETH_MODE_DISABLED;
        if (fmGetPortAttribute((fm_int)sw, (fm_int)port, FM_PORT_ETHERNET_INTERFACE_MODE, &ethernet_mode) == FM_OK)
            state_out->ethernet_mode = (int)ethernet_mode;
    }
    if (hal_port_get_mtu(sw, port, &state_out->mtu,
                         &state_out->max_frame) != 0) {
        state_out->mtu = 0;
        state_out->max_frame = 0;
        if (configuration_only) return -1;
    }
    fm_uint32 pvid = 0;
    if (fmGetPortAttribute((fm_int)sw, (fm_int)port,
                           FM_PORT_DEF_VLAN, &pvid) == FM_OK)
        state_out->pvid = (int)pvid;
    else if (configuration_only) return -1;
    return 0;
}

static int sdk_read_port_counters(int sw, int port,
                                  hal_port_counters *counters) {
    fm_portCounters cnt;
    fm_status st;

    if (!counters)
        return -1;
    memset(counters, 0, sizeof(*counters));
    st = fmGetPortCounters((fm_int)sw, (fm_int)port, &cnt);
    if (st != FM_OK)
        return -1;

    counters->rx_bytes = cnt.cntRxGoodOctets;
    counters->tx_bytes = cnt.cntTxOctets;
    counters->rx_ucast_pkts = cnt.cntRxUcstPkts;
    counters->rx_mcast_pkts = cnt.cntRxMcstPkts;
    counters->rx_bcast_pkts = cnt.cntRxBcstPkts;
    counters->tx_ucast_pkts = cnt.cntTxUcstPkts;
    counters->tx_mcast_pkts = cnt.cntTxMcstPkts;
    counters->tx_bcast_pkts = cnt.cntTxBcstPkts;
    counters->rx_pkts = cnt.cntRxUcstPkts + cnt.cntRxBcstPkts +
        cnt.cntRxMcstPkts;
    counters->tx_pkts = cnt.cntTxUcstPkts + cnt.cntTxBcstPkts +
        cnt.cntTxMcstPkts;
    counters->rx_fcs_errors = cnt.cntRxFCSErrors;
    counters->rx_symbol_errors = cnt.cntRxSymbolErrors;
    counters->rx_frame_size_errors = cnt.cntRxFrameSizeErrors +
        cnt.cntRxFramingErrorPkts;
    counters->rx_errors = cnt.cntRxFCSErrors + cnt.cntRxSymbolErrors +
        cnt.cntRxFrameSizeErrors + cnt.cntRxFramingErrorPkts;
    counters->tx_errors = cnt.cntTxErrorDropPkts + cnt.cntTxErrorSentPkts +
        cnt.cntTxTimeOutPkts + cnt.cntTxOutOfMemErrPkts +
        cnt.cntTxUnrepairEccPkts;
    fm10k_congestion_counts congestion = fm10k_decode_congestion(&cnt);
    counters->rx_drops = cnt.cntParseErrDropPkts + cnt.cntPauseDropPkts +
        cnt.cntSTPDropPkts + cnt.cntSTPIngressDropsPkts +
        cnt.cntVLANTagDropPkts + cnt.cntLoopbackDropsPkts +
        cnt.cntGlortMissDropPkts + cnt.cntFFUDropPkts +
        cnt.cntInvalidDropPkts + cnt.cntPolicerDropPkts +
        cnt.cntTTLDropPkts + congestion.rx +
        cnt.cntFloodControlDropPkts + cnt.cntSecurityViolationPkts;
    counters->tx_drops = cnt.cntTxErrorDropPkts + cnt.cntTxTTLDropPkts + congestion.tx;
    counters->rx_pfc_pkts = cnt.cntRxCBPausePkts;
    counters->tx_pfc_pkts = cnt.cntTxCBPausePkts;
    counters->rx_congestion_drops = congestion.rx;
    counters->tx_congestion_drops = congestion.tx;
    counters->rx_pause_pkts = cnt.cntRxPausePkts;
    counters->tx_pause_pkts = cnt.cntTxPausePkts;
    counters->stp_drops = cnt.cntSTPDropPkts + cnt.cntSTPIngressDropsPkts +
        cnt.cntSTPEgressDropsPkts;
    counters->vlan_tag_drops = cnt.cntVLANTagDropPkts;
    counters->security_violations = cnt.cntSecurityViolationPkts;
    counters->flood_control_drops = cnt.cntFloodControlDropPkts;
    counters->policer_drops = cnt.cntPolicerDropPkts;
    counters->ttl_drops = cnt.cntTTLDropPkts;
    return 0;
}

static int sdk_read_port_snapshot(int sw, const struct sdk_op *op,
                                  struct sdk_result *result) {
    hal_port_snapshot *snapshot;
    int n_ports;

    if (!op || !result)
        return -1;
    snapshot = &result->data.port_snapshot;
    memset(snapshot, 0, sizeof(*snapshot));
    n_ports = op->args.port_snapshot.n_ports;
    if (n_ports < 0)
        n_ports = 0;
    if (n_ports > NETLAB_PORT_SNAPSHOT_MAX)
        n_ports = NETLAB_PORT_SNAPSHOT_MAX;
    snapshot->n_ports = n_ports;
    snapshot->counters_included = op->args.port_snapshot.include_counters;
    snapshot->sampled_monotonic_ms = monotonic_ns() / 1000000ULL;

    for (int i = 0; i < n_ports; i++) {
        hal_port_snapshot_entry *entry = &snapshot->ports[i];

        entry->port = op->args.port_snapshot.ports[i];
        entry->state_status = sdk_read_port_state(
            sw, entry->port, &entry->state, false);
        if (entry->state_status != 0)
            snapshot->state_failures++;
        entry->counters_status = 0;
        if (snapshot->counters_included) {
            entry->counters_status = sdk_read_port_counters(
                sw, entry->port, &entry->counters);
            if (entry->counters_status != 0)
                snapshot->counter_failures++;
        }
    }
    return n_ports > 0 ? 0 : -1;
}

static int sdk_read_qos_snapshot(int sw, const struct sdk_op *op,
                                 struct sdk_result *result) {
    hal_qos_readback *snapshot;
    int n_entries = -1;

    if (!op || !result)
        return -1;
    snapshot = &result->data.qos_readback;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->kind = op->args.qos_readback.kind;

    switch (snapshot->kind) {
        case HAL_QOS_READBACK_DSCP_MAP:
            n_entries = hal_qos_dscp_list(sw, snapshot->entries.dscp_map);
            break;
        case HAL_QOS_READBACK_STORM_CONTROL:
            n_entries = hal_storm_control_list(
                sw, snapshot->entries.storm_control,
                NETLAB_QOS_READBACK_MAX_PORTS);
            break;
        case HAL_QOS_READBACK_INGRESS_RATE_LIMIT:
            n_entries = hal_ingress_rate_limit_list(
                sw, snapshot->entries.storm_control,
                NETLAB_QOS_READBACK_MAX_PORTS);
            break;
        case HAL_QOS_READBACK_EGRESS_RATE_LIMIT:
            n_entries = hal_egress_rate_limit_list(
                sw, snapshot->entries.egress_rate_limit,
                NETLAB_QOS_READBACK_MAX_PORTS);
            break;
        case HAL_QOS_READBACK_INTERFACES:
            n_entries = hal_qos_interface_list(
                sw, snapshot->entries.interfaces,
                NETLAB_QOS_READBACK_MAX_PORTS);
            break;
        case HAL_QOS_READBACK_PRIORITY_MAP:
            n_entries = hal_qos_priority_map_list(
                sw, snapshot->entries.priority_map,
                HAL_QOS_MAX_SWITCH_PRIORITIES);
            break;
        case HAL_QOS_READBACK_FLOW_CONTROL:
            snapshot->global_status = hal_qos_flow_control_global_get(
                sw, &snapshot->flow_control_global);
            if (snapshot->global_status != 0)
                return snapshot->global_status;
            n_entries = hal_qos_flow_control_list(
                sw, snapshot->entries.flow_control,
                NETLAB_QOS_READBACK_MAX_PORTS);
            for (int i = 0; i < n_entries; i++)
                (void)hal_qos_pause_state_get(sw, &snapshot->entries.flow_control[i]);
            break;
        case HAL_QOS_READBACK_SCHEDULERS:
            n_entries = hal_qos_scheduler_list(
                sw, snapshot->entries.schedulers,
                NETLAB_QOS_READBACK_MAX_PORTS);
            break;
        case HAL_QOS_READBACK_QUEUES:
            n_entries = hal_qos_queue_list(
                sw, snapshot->entries.queues,
                NETLAB_QOS_READBACK_MAX_QUEUES);
            break;
        case HAL_QOS_READBACK_WATERMARKS:
            snapshot->global_status = hal_qos_watermark_global_get(
                sw, &snapshot->watermark_global);
            if (snapshot->global_status != 0)
                return snapshot->global_status;
            n_entries = hal_qos_watermark_list(
                sw, snapshot->entries.watermarks,
                NETLAB_QOS_READBACK_MAX_PORTS);
            break;
        default:
            return -1;
    }
    if (n_entries < 0)
        return -1;
    snapshot->n_entries = n_entries;
    return 0;
}

static int sdk_l3_runtime_dispatch(int sw, const struct sdk_op *op,
                                   struct sdk_result *result) {
    const char *text;
    const char *router_mac;
    char *resp;
    size_t resp_size;

    if (!op || !result)
        return -1;
    text = op->args.l3_runtime.text ? op->args.l3_runtime.text : "";
    router_mac = op->args.l3_runtime.router_mac[0] ?
        op->args.l3_runtime.router_mac : NULL;
    resp = result->data.l3_runtime.response;
    resp_size = sizeof(result->data.l3_runtime.response);

    switch (op->args.l3_runtime.kind) {
        case HAL_L3_RUNTIME_HIDDEN_READBACK:
            return l3_transaction_hidden_readback(
                sw, op->args.l3_runtime.live_readback, resp, resp_size);
        case HAL_L3_RUNTIME_RIF_LIVE_PROBE:
            return l3_transaction_hidden_rif_live_probe(
                sw, text, op->args.l3_runtime.acknowledged,
                op->args.l3_runtime.tx_id, resp, resp_size);
        case HAL_L3_RUNTIME_ARP_LIVE_PROBE:
            return l3_transaction_hidden_arp_live_probe(
                sw, text, op->args.l3_runtime.acknowledged,
                op->args.l3_runtime.tx_id, resp, resp_size);
        case HAL_L3_RUNTIME_ECMP_LIVE_PROBE:
            return l3_transaction_hidden_ecmp_live_probe(
                sw, text, op->args.l3_runtime.acknowledged,
                op->args.l3_runtime.tx_id, resp, resp_size);
        case HAL_L3_RUNTIME_ROUTE_LIVE_PROBE:
            return l3_transaction_hidden_route_live_probe(
                sw, text, op->args.l3_runtime.acknowledged,
                op->args.l3_runtime.tx_id, op->args.l3_runtime.hold_sec,
                router_mac, resp, resp_size);
        case HAL_L3_RUNTIME_PERSISTENT_APPLY:
            return l3_transaction_hidden_persistent_apply(
                sw, text, op->args.l3_runtime.acknowledged,
                op->args.l3_runtime.tx_id, resp, resp_size);
        case HAL_L3_RUNTIME_PERSISTENT_READBACK:
            return l3_transaction_hidden_persistent_readback(
                sw, resp, resp_size);
        case HAL_L3_RUNTIME_PERSISTENT_ROLLBACK:
            return l3_transaction_hidden_persistent_rollback(
                sw, op->args.l3_runtime.acknowledged,
                op->args.l3_runtime.tx_id, resp, resp_size);
        case HAL_L3_RUNTIME_FIB_READBACK:
            return l3_fib_batch_readback(sw, resp, resp_size);
        case HAL_L3_RUNTIME_FIB_RECONCILE:
            return l3_fib_batch_reconcile(sw, resp, resp_size);
        case HAL_L3_RUNTIME_FIB_ROLLBACK:
            return l3_fib_batch_rollback(
                sw, op->args.l3_runtime.tx_id, resp, resp_size);
        default:
            return -1;
    }
}

static int sdk_exec_op_dispatch_inner(int sw, struct sdk_op *op,
                          struct sdk_result *result) {
    switch (op->type) {
        case SDK_OP_PORT_SET_ADMIN:
        case SDK_OP_PORT_SET_SPEED:
        case SDK_OP_PORT_SET_MTU:
        case SDK_OP_PORT_RECOVERY_POLL:
        case SDK_OP_RESET_COUNTERS:
        case SDK_OP_FM10K_BOOTSTRAP_CLOSED:
        case SDK_OP_FM10K_CONTROL_INIT:
        case SDK_OP_FM10K_BOARD_SHUTDOWN:
        case SDK_OP_FM10K_EYE_CONTROL:
        case SDK_OP_APPLY_L2_PLAN:
        case SDK_OP_ROLLBACK_L2_PLAN:
            if (hal_pfc_watchdog_quiesce(sw)) return NL_ERR_HW_STATE_OUT_OF_SYNC;
            break;
        default: break;
    }
    switch (op->type) {
        case SDK_OP_PORT_SET_ADMIN:
        case SDK_OP_PORT_SET_SPEED:
        case SDK_OP_PORT_RECOVERY_POLL:
        case SDK_OP_FM10K_BOOTSTRAP_CLOSED:
        case SDK_OP_FM10K_CONTROL_INIT:
        case SDK_OP_ROLLBACK_L2_PLAN:
            if (fm10k_eye_preempt(sw)) return NL_ERR_SDK_CALL_FAILED;
            break;
        case SDK_OP_FM10K_BOARD_SHUTDOWN:
            if (fm10k_eye_shutdown(sw)) return NL_ERR_SDK_CALL_FAILED;
            break;
        case SDK_OP_APPLY_L2_PLAN:
            if (!op->runtime && fm10k_eye_preempt(sw)) return NL_ERR_SDK_CALL_FAILED;
            break;
        default: break;
    }
    switch (op->type) {
        case SDK_OP_PORT_SET_ADMIN:
            return hal_port_set_admin_state(sw, op->args.port.port,
                                            op->args.port.mode);
        case SDK_OP_PORT_SET_SPEED:
            return hal_port_set_speed(sw, op->args.port.port,
                                      op->args.port.speed);
        case SDK_OP_PORT_SET_MTU:
            return hal_port_set_mtu(sw, op->args.port.port,
                                    op->args.port.mtu);
        case SDK_OP_VLAN_CREATE:
            return (int)fmCreateVlan((fm_int)sw, (fm_uint16)op->args.vlan.vid);
        case SDK_OP_VLAN_DELETE:
            return (int)fmDeleteVlan((fm_int)sw, (fm_uint16)op->args.vlan.vid);
        case SDK_OP_VLAN_ADD_PORT:
            return (int)fmAddVlanPort((fm_int)sw, (fm_uint16)op->args.vlan.vid,
                                      (fm_int)op->args.vlan.port,
                                      op->args.vlan.tagged ? TRUE : FALSE);
        case SDK_OP_VLAN_REM_PORT:
            return (int)fmDeleteVlanPort((fm_int)sw, (fm_uint16)op->args.vlan.vid,
                                         (fm_int)op->args.vlan.port);
        case SDK_OP_PVID_SET: {
            fm_uint32 pv = (fm_uint32)op->args.vlan.vid;
            return (int)fmSetPortAttribute((fm_int)sw, (fm_int)op->args.vlan.port,
                                            FM_PORT_DEF_VLAN, &pv);
        }
        case SDK_OP_ROUTE_ADD:
        case SDK_OP_ROUTE_DELETE:
            return -1;
        case SDK_OP_VLAN_STP_SET:
            return (int)fmSetVlanPortState((fm_int)sw, (fm_uint16)op->args.vlan.vid,
                                           (fm_int)op->args.vlan.port,
                                           (fm_int)op->args.vlan.stp_state);
        case SDK_OP_RUNTIME_STP_SET: {
            int port = op->args.vlan.port;
            int rc = (int)fmSetVlanPortState(sw, op->args.vlan.vid, port, op->args.vlan.stp_state);
            fm_int actual = -1;
            if (!rc && (fmGetVlanPortState(sw, op->args.vlan.vid, port, &actual) != FM_OK ||
                        actual != op->args.vlan.stp_state)) rc = NL_ERR_READBACK_MISMATCH;
            return rc;
        }
        case SDK_OP_PORT_PARSER_SET:
            return (int)fmSetPortAttribute((fm_int)sw, (fm_int)op->args.port.port,
                                            FM_PORT_PARSER, &op->args.port.speed);
        case SDK_OP_NOP:
            return 0;
        case SDK_OP_FM10K_BOARD_POLL: {
            int rc = fm10k_native_poll(sw);
            fm10k_eye_poll(sw);
            return rc;
        }
        case SDK_OP_FM10K_BOOTSTRAP_CLOSED:
            return fm10k_native_bootstrap_closed(sw);
        case SDK_OP_FM10K_CONTROL_INIT:
            return sdk_fm10k_control_initialize(op->args.fm10k_control.ctx, op->args.fm10k_control.netdev);
        case SDK_OP_FM10K_FAN_MANUAL:
            return result ? fm10k_native_manual(op->args.fm10k_fan.pwm,
                op->args.fm10k_fan.seconds, &result->data.fm10k_fan.expires_at) : -1;
        case SDK_OP_FM10K_BOARD_SHUTDOWN:
            return fm10k_native_shutdown();
        case SDK_OP_FM10K_CONFIG_GET:
            return result ? fm10k_native_config_snapshot(sw, &result->data.fm10k_config) : -1;
        case SDK_OP_FM10K_EYE_GET:
        case SDK_OP_FM10K_EYE_CONTROL:
            return result ? fm10k_eye_command(sw, op->args.fm10k_eye.command,
                op->type == SDK_OP_FM10K_EYE_CONTROL, result->data.fm10k_phy.response,
                sizeof(result->data.fm10k_phy.response)) : -1;
        case SDK_OP_FM10K_PHY_GET:
            return result ? fm10k_phy_snapshot(sw, op->args.port.port,
                result->data.fm10k_phy.response, sizeof(result->data.fm10k_phy.response)) : -1;

        // === Query operations: fill result->data ===
        case SDK_OP_GET_PORT_STATE:
            return result ? sdk_read_port_state(
                sw, op->args.port.port, &result->data.port_state, op->args.port.configuration_only) : -1;
        case SDK_OP_GET_COUNTERS:
            return result ? sdk_read_port_counters(
                sw, op->args.port.port, &result->data.counters) : -1;
        case SDK_OP_GET_PORT_SNAPSHOT:
            return sdk_read_port_snapshot(sw, op, result);
        case SDK_OP_GET_QOS_READBACK:
            return sdk_read_qos_snapshot(sw, op, result);
        case SDK_OP_L3_SDK_READBACK_PROBE:
            if (!result)
                return -1;
            return hal_l3_sdk_readback_probe(
                sw, result->data.l3_sdk_readback.response,
                sizeof(result->data.l3_sdk_readback.response));
        case SDK_OP_L3_SDK_WRITE_CANARY:
            if (!result)
                return -1;
            return hal_l3_sdk_write_canary(
                sw, op->args.l3_sdk_canary.acknowledged,
                result->data.l3_sdk_canary.response,
                sizeof(result->data.l3_sdk_canary.response));
        case SDK_OP_L3_RUNTIME:
            return sdk_l3_runtime_dispatch(sw, op, result);
        case SDK_OP_GET_SFLOW_STATE:
            return result ?
                hal_sflow_state_get(sw, &result->data.sflow_state) : -1;
        case SDK_OP_SFLOW_LIVE_PROBE:
            if (!result)
                return -1;
            return hal_sflow_live_probe(
                sw, op->args.sflow_probe.port,
                op->args.sflow_probe.acknowledged,
                op->args.sflow_probe.tx_id,
                result->data.sflow_probe.response,
                sizeof(result->data.sflow_probe.response));
        case SDK_OP_RESET_COUNTERS: {
            fm_status st = fmResetPortCounters((fm_int)sw, (fm_int)op->args.port.port);
            return (st == FM_OK) ? 0 : -1;
        }
        case SDK_OP_GET_XCVR: {
            /* FCI has a private layout. Its qualified readings come only
             * from the board cache; never fall back to standard QSFP DOM. */
            if (fm10k_native_profile()) return -EOPNOTSUPP;
            int port = op->args.port.port;
            fm_bool present = FALSE;
            fm_status st = fmPlatformXcvrIsPresent((fm_int)sw, (fm_int)port, &present);
            if (result) {
                fm_platformXcvrType type = FM_PLATFORM_XCVR_TYPE_UNKNOWN;
                result->data.xcvr.present = present ? 1 : 0;
                result->data.xcvr.type = present ? (u8)FM_PLATFORM_XCVR_TYPE_UNKNOWN :
                                         (u8)FM_PLATFORM_XCVR_TYPE_NOT_PRESENT;
                result->data.xcvr.dom_valid = 0;
                result->data.xcvr.lane_count = 0;
                result->data.xcvr.temp = 0;
                result->data.xcvr.voltage = 0;
                result->data.xcvr.tx_bias = 0;
                result->data.xcvr.tx_power = 0;
                result->data.xcvr.rx_power = 0;
                if (present) {
                    fm_byte eeprom[256];
                    if (fmPlatformXcvrEepromRead((fm_int)sw, (fm_int)port, 0, 0,
                                                 eeprom, sizeof(eeprom)) == FM_OK) {
                        type = fmPlatformXcvrEepromGetType(eeprom);
                        result->data.xcvr.type = (u8)type;
                    }

                    if (xcvr_type_is_qsfp(type)) {
                        if (!xcvr_read_qsfp_dom(sw, port, result))
                            xcvr_read_sfp_dom(sw, port, result);
                    } else {
                        if (!xcvr_read_sfp_dom(sw, port, result))
                            xcvr_read_qsfp_dom(sw, port, result);
                    }
                }
            }
            return (st == FM_OK) ? 0 : -1;
        }
        case SDK_OP_OPTICS_MUX_PROBE:
            /* This operation must be sliced by sdk_executor_thread(). */
            return -EOPNOTSUPP;
        case SDK_OP_BOARD_ENV_GET:
            return board_env_get(sw, op, result);
        case SDK_OP_GET_MIRROR_STATE:
            if (!result)
                return -1;
            return hal_mirror_state_get(
                sw, NETLAB_MIRROR_V1_GROUP,
                &result->data.mirror_state);
        case SDK_OP_GET_L2_MCAST_OWNER:
            return hal_l2_mcast_owner_format(
                sw, op->args.l2_mcast_owner.buf,
                op->args.l2_mcast_owner.buf_size) < 0 ? -1 : 0;
        case SDK_OP_APPLY_L2_PLAN:
            if (!op->args.apply_plan)
                return -1;
            /*
             * Apply currently consumes only the aggregate status.  Do not
             * reserve one 64 KiB sdk_result union per plan step on the
             * executor thread stack merely to discard it.
             */
            return hal_apply_l2_plan(
                (fm_int)sw, op->args.apply_plan, NULL,
                L2_PLAN_MAX_STEPS);
        case SDK_OP_ROLLBACK_L2_PLAN:
            if (!op->args.apply_plan)
                return -1;
            return hal_rollback_l2_plan((fm_int)sw,
                                        op->args.apply_plan);
        case SDK_OP_COMMIT_MARK_SUCCESS:
            return hal_commit_mark_success(op->args.commit.tracker, op->args.commit.tx_id, "applied");
        case SDK_OP_COMMIT_MARK_FAILED:
            return hal_commit_mark_failed(op->args.commit.tracker, op->args.commit.tx_id);
        case SDK_OP_GET_MAC_TABLE:
            return hal_get_mac_table((fm_int)sw, result);
        case SDK_OP_CLEAR_DYNAMIC_MAC_TABLE:
            return hal_clear_dynamic_mac_table((fm_int)sw,
                                               op->args.vlan.port,
                                               op->args.vlan.vid);
        case SDK_OP_PORT_SECURITY_SET:
            return hal_port_security_set((fm_int)sw,
                                         op->args.port_security.port,
                                         op->args.port_security.enable != 0,
                                         op->args.port_security.action,
                                         op->args.port_security.strict != 0);
        case SDK_OP_GET_MAC_AGING_TIME: {
            int seconds = 0;
            int st = hal_mac_aging_get((fm_int)sw, &seconds);
            if (st == 0 && result)
                result->data.mac_aging.seconds = seconds;
            return st;
        }
        case SDK_OP_GET_STP_TABLE:
            return hal_get_stp_table((fm_int)sw, result);
        case SDK_OP_GET_VLAN_STATE: {
            hal_presence_snapshot state = hal_vlan_presence_snapshot(sw, op->args.vlan.vid);
            if (result) result->data.vlan_state.exists = state.state == HAL_PRESENCE_PRESENT;
            return state.state == HAL_PRESENCE_READ_ERROR ? NL_ERR_PRE_STATE_MISSING : 0;
        }
        case SDK_OP_PACKET_TX:
            return hal_packet_tx((fm_int)sw, op->args.pkt_tx.port,
                                 op->args.pkt_tx.data, op->args.pkt_tx.len);
        case SDK_OP_LAG_DELETE:
            return hal_lag_delete((fm_int)sw, op->args.lag.lag_id);
        case SDK_OP_LAG_ADD_PORT:
            return hal_lag_add_port((fm_int)sw, op->args.lag.lag_id,
                                     op->args.lag.port);
        case SDK_OP_LAG_DEL_PORT:
            return hal_lag_del_port((fm_int)sw, op->args.lag.lag_id,
                                     op->args.lag.port);
        case SDK_OP_LAG_GET_ALL:
            return hal_lag_get_all((fm_int)sw, result);
        case SDK_OP_GET_PFE_RESOURCES:
            return hal_get_pfe_resources((fm_int)sw, result);
        case SDK_OP_GET_SWITCH_SENSORS:
            if (op->args.switch_sensors.count > 0)
                return hal_get_switch_digital_sensors_range(
                    (fm_int)sw, op->args.switch_sensors.first,
                    op->args.switch_sensors.count, result);
            return hal_get_switch_digital_sensors((fm_int)sw, result);
        case SDK_OP_GET_SWITCH_CONFIG:
            return hal_get_switch_config((fm_int)sw, result);
        case SDK_OP_GET_CONTROL_PLANE_PROTECTION:
            return hal_control_plane_collect_protection((fm_int)sw, result);
        case SDK_OP_GET_L2_SECURITY_USER_FILTER_COUNTERS: {
            bool found = false;
            int table = -1;
            int flow = -1;
            u64 packets = 0;
            u64 octets = 0;
            int st = hal_l2_security_user_filter_counters(
                (fm_int)sw, op->args.l2_security_counter.vid,
                op->args.l2_security_counter.port,
                op->args.l2_security_counter.mac,
                op->args.l2_security_counter.mac_kind,
                &found, &table, &flow, &packets, &octets);
            if (result) {
                result->data.l2_security_counter.found = found;
                result->data.l2_security_counter.table = table;
                result->data.l2_security_counter.flow = flow;
                result->data.l2_security_counter.packets = packets;
                result->data.l2_security_counter.octets = octets;
            }
            return st;
        }
        case SDK_OP_GET_INGRESS_IPV4_ACL_COUNTERS: {
            bool found = false;
            int table = -1;
            int flow = -1;
            u64 packets = 0;
            u64 octets = 0;
            int st = hal_ingress_ipv4_acl_counters(
                (fm_int)sw, &op->args.ingress_ipv4_acl, &found, &table,
                &flow, &packets, &octets);
            if (result) {
                result->data.ingress_ipv4_acl_counter.found = found;
                result->data.ingress_ipv4_acl_counter.table = table;
                result->data.ingress_ipv4_acl_counter.flow = flow;
                result->data.ingress_ipv4_acl_counter.packets = packets;
                result->data.ingress_ipv4_acl_counter.octets = octets;
            }
            return st;
        }
        case SDK_OP_GET_EGRESS_ACL_COUNTERS: {
            u64 packets = 0;
            u64 octets = 0;
            int port = op->args.egress_acl_counter.port;
            int st = hal_acl_egress_counters((fm_int)sw, port,
                                             &packets, &octets);
            if (result) {
                result->data.egress_acl_counter.found = st == 0;
                result->data.egress_acl_counter.port = port;
                result->data.egress_acl_counter.packets = packets;
                result->data.egress_acl_counter.octets = octets;
            }
            return st;
        }
        case SDK_OP_GET_ACL_POLICER_COUNTERS:
            return hal_acl_policer_owner_readback_match(
                (fm_int)sw, &op->args.acl_policer_owner,
                result ? &result->data.acl_policer_owner : NULL);
        case SDK_OP_GET_ACL_INDEPENDENT_COUNTERS:
            return hal_acl_independent_readback_match(
                (fm_int)sw, &op->args.acl_independent,
                result ? &result->data.acl_independent : NULL);
        case SDK_OP_GET_ACL_COUNTER_SNAPSHOT:
            return hal_acl_counter_snapshot_get(
                (fm_int)sw, op->args.acl_counter_query,
                result ? &result->data.acl_counter_snapshot : NULL);
        case SDK_OP_ACL_POLICER_PROBE:
            return hal_acl_policer_probe(
                (fm_int)sw, &op->args.acl_policer_probe,
                result ? &result->data.acl_policer_probe : NULL);
        case SDK_OP_ACL_POLICER_OWNER_APPLY:
            return hal_acl_policer_owner_apply(
                (fm_int)sw, &op->args.acl_policer_owner,
                result ? &result->data.acl_policer_owner : NULL);
        case SDK_OP_ACL_POLICER_OWNER_READBACK:
            return hal_acl_policer_owner_readback(
                (fm_int)sw,
                result ? &result->data.acl_policer_owner : NULL);
        case SDK_OP_ACL_POLICER_OWNER_ROLLBACK:
            return hal_acl_policer_owner_rollback(
                (fm_int)sw,
                result ? &result->data.acl_policer_owner : NULL);
        case SDK_OP_ACL_EGRESS_PROBE:
            return hal_acl_egress_probe(
                (fm_int)sw, &op->args.acl_egress_probe,
                result ? &result->data.acl_egress_probe : NULL);
        case SDK_OP_ACL_GENERAL_ALLOCATOR_APPLY:
            return hal_acl_general_allocator_apply(
                (fm_int)sw, &op->args.acl_general_allocator,
                result ? &result->data.acl_general_allocator : NULL);
        case SDK_OP_ACL_GENERAL_ALLOCATOR_READBACK:
            return hal_acl_general_allocator_readback(
                (fm_int)sw,
                result ? &result->data.acl_general_allocator : NULL);
        case SDK_OP_ACL_GENERAL_ALLOCATOR_ROLLBACK:
            return hal_acl_general_allocator_rollback(
                (fm_int)sw,
                result ? &result->data.acl_general_allocator : NULL);
        case SDK_OP_QOS_QUEUE_PROBE:
            return hal_qos_queue_probe(
                (fm_int)sw, &op->args.qos_queue_probe,
                result ? &result->data.qos_queue_probe : NULL);
        case SDK_OP_QOS_QUEUE_OWNER_APPLY:
            return hal_qos_queue_owner_apply(
                (fm_int)sw, &op->args.qos_queue_owner,
                result ? &result->data.qos_queue_owner : NULL);
        case SDK_OP_QOS_QUEUE_OWNER_READBACK:
            return hal_qos_queue_owner_readback(
                (fm_int)sw,
                result ? &result->data.qos_queue_owner : NULL);
        case SDK_OP_QOS_QUEUE_OWNER_ROLLBACK:
            return hal_qos_queue_owner_rollback(
                (fm_int)sw,
                result ? &result->data.qos_queue_owner : NULL);
        case SDK_OP_QOS_QUEUE_PROFILE_OWNER_APPLY:
            return hal_qos_queue_profile_owner_apply(
                (fm_int)sw, &op->args.qos_queue_profile_owner,
                result ? &result->data.qos_queue_profile_owner : NULL);
        case SDK_OP_QOS_QUEUE_PROFILE_OWNER_READBACK:
            return hal_qos_queue_profile_owner_readback(
                (fm_int)sw,
                result ? &result->data.qos_queue_profile_owner : NULL);
        case SDK_OP_QOS_QUEUE_PROFILE_OWNER_ROLLBACK:
            return hal_qos_queue_profile_owner_rollback(
                (fm_int)sw,
                result ? &result->data.qos_queue_profile_owner : NULL);
        case SDK_OP_QOS_WATERMARK_OWNER_APPLY:
            return hal_qos_watermark_owner_apply(
                (fm_int)sw, &op->args.qos_watermark_owner,
                result ? &result->data.qos_watermark_owner : NULL);
        case SDK_OP_QOS_WATERMARK_OWNER_READBACK:
            return hal_qos_watermark_owner_readback(
                (fm_int)sw,
                result ? &result->data.qos_watermark_owner : NULL);
        case SDK_OP_QOS_WATERMARK_OWNER_ROLLBACK:
            return hal_qos_watermark_owner_rollback(
                (fm_int)sw,
                result ? &result->data.qos_watermark_owner : NULL);
        case SDK_OP_L3_FIB_BATCH_APPLY:
            return l3_fib_batch_apply(
                sw, op->args.l3_fib_batch.text,
                op->args.l3_fib_batch.tx_id,
                op->args.l3_fib_batch.resp,
                op->args.l3_fib_batch.resp_size);
        case SDK_OP_L3_FIB_SNAPSHOT_BEGIN:
            return l3_fib_snapshot_begin(
                op->args.l3_fib_batch.text,
                op->args.l3_fib_batch.tx_id,
                op->args.l3_fib_batch.resp,
                op->args.l3_fib_batch.resp_size);
        case SDK_OP_L3_FIB_SNAPSHOT_PART:
            return l3_fib_snapshot_part(
                op->args.l3_fib_batch.text,
                op->args.l3_fib_batch.tx_id,
                op->args.l3_fib_batch.resp,
                op->args.l3_fib_batch.resp_size);
        case SDK_OP_L3_FIB_SNAPSHOT_COMMIT:
            return l3_fib_snapshot_commit(
                sw, op->args.l3_fib_batch.text,
                op->args.l3_fib_batch.tx_id,
                op->args.l3_fib_batch.resp,
                op->args.l3_fib_batch.resp_size);
        case SDK_OP_L3_FIB_SNAPSHOT_ABORT:
            return l3_fib_snapshot_abort(
                op->args.l3_fib_batch.text,
                op->args.l3_fib_batch.tx_id,
                op->args.l3_fib_batch.resp,
                op->args.l3_fib_batch.resp_size);
        case SDK_OP_PORT_RECOVERY_POLL:
            sdk_port_recovery_poll(op->args.port_recovery.ctx);
            return 0;
        default:
            return -1;
    }
}

static int sdk_scope_resolve_lag(int sw, int id, bool lag_handle, u32 *mask) {
    fm_int lag = lag_handle ? id : -1, members[NETLAB_MAX_LAG_MEMBERS], count = 0;
    if ((!lag_handle && fmLogicalPortToLAGNumber(sw, id, &lag) != FM_OK) || lag <= 0 ||
        hal_lag_ae_for_id(lag) < 0 ||
        fmGetLAGPortList(sw, lag, &count, members, NETLAB_MAX_LAG_MEMBERS) != FM_OK ||
        count < 0 || count > NETLAB_MAX_LAG_MEMBERS) return NL_ERR_INTERFACE_NOT_FOUND;
    for (int i = 0; i < count; ++i) {
        if (members[i] < 1 || members[i] > 24) return NL_ERR_INVALID_VALUE;
        *mask |= 1U << (members[i] - 1);
    }
    return 0;
}
static int sdk_plan_scope_resolve(void *context, nl_fm10k_scope_target kind, int id, u32 *mask) {
    int sw = *(const int *)context;
    fm_int members[NL_MAX_PORTS_PER_PROFILE], count = 0;
    fm_status status;
    *mask = 0;
    if (kind == NL_FM10K_SCOPE_AE) {
        int lag = hal_lag_id_for_ae(id);
        if (lag <= 0) return 0;
        status = fmGetLAGPortList(sw, lag, &count, members, NL_MAX_PORTS_PER_PROFILE);
    } else {
        status = fmGetVlanPortList(sw, (fm_uint16)id, &count, members, NL_MAX_PORTS_PER_PROFILE);
        if (status == FM_ERR_INVALID_VLAN) return 0;
    }
    if (status != FM_OK || count < 0 || count > NL_MAX_PORTS_PER_PROFILE) {
        NL_LOG_ERR("plan scope readback failed kind=%d id=%d sdk=%d count=%d", kind, id, status, count);
        return NL_ERR_PRE_STATE_MISSING;
    }
    for (int i = 0; i < count; ++i) {
        /* IES includes CPU logical port 0 in VLAN membership. It is outside
         * the 24 data slots and must not be resolved as a LAG. */
        if (kind == NL_FM10K_SCOPE_VLAN &&
            (members[i] == 0 || fm10k_native_aux_port(sw, members[i]))) continue;
        if (members[i] >= 1 && members[i] <= 24) *mask |= 1U << (members[i] - 1);
        else {
            nl_port_entry entry;
            if (nl_ifid_get_by_logical_port(members[i], &entry) &&
                !(entry.flags & NL_PORT_FLAG_EXTERNAL)) continue;
            u32 lag_mask = 0;
            if (kind == NL_FM10K_SCOPE_AE || sdk_scope_resolve_lag(sw, members[i], false, &lag_mask)) {
                NL_LOG_ERR("plan scope has unmapped member kind=%d id=%d port=%d", kind, id, members[i]);
                return NL_ERR_PRE_STATE_MISSING;
            }
            *mask |= lag_mask;
        }
    }
    return 0;
}
static int sdk_plan_scope_check(int sw, const struct sdk_op *op) {
    if (!op) return NL_ERR_INVALID_VALUE;
    if (op->type == SDK_OP_LAG_ADD_PORT || op->type == SDK_OP_LAG_DEL_PORT) {
        if (!op->args.lag.native_generation ||
            op->args.lag.native_generation != fm10k_native_generation())
            return NL_ERR_HW_STATE_OUT_OF_SYNC;
    }
    if (op->runtime || (op->type != SDK_OP_APPLY_L2_PLAN && op->type != SDK_OP_ROLLBACK_L2_PLAN)) return 0;
    const l2_apply_plan *plan = op->args.apply_plan;
    if (!plan || !plan->fm10k_scope_present || !plan->tx_id) return NL_ERR_INVALID_VALUE;
    nl_port_scope_status scope = nl_port_scope_get();
    if (plan->fm10k_scope_mask && (!nl_port_scope_ready() ||
        scope.tx_id != plan->tx_id || (plan->fm10k_scope_mask & ~scope.mask))) return NL_ERR_COMMIT_LOCKED;
    u32 affected = 0;
    int rc = nl_fm10k_plan_port_mask(plan, sdk_plan_scope_resolve, &sw, &affected);
    if (rc) return rc;
    return affected & ~plan->fm10k_scope_mask ? NL_ERR_COMMIT_LOCKED : 0;
}
int sdk_exec_op_dispatch(int sw, struct sdk_op *op, struct sdk_result *result) {
    /* A lease starts on the SDK owner thread, immediately before mutation.
     * A timed-out RPC queued before cutover cannot run in the new epoch. */
    if (fm10k_native_profile()) {
        int rc = sdk_plan_scope_check(sw, op);
        if (rc) return rc;
    }
    return sdk_runtime_dispatch(sw, op, result, sdk_exec_op_dispatch_inner,
        sdk_scope_resolve_lag, fm10k_native_profile());
}

int sdk_exec_undo(struct sdk_op *op) {
    struct sdk_op undo;
    memset(&undo, 0, sizeof(undo));
    switch (op->type) {
        case SDK_OP_VLAN_CREATE:
            undo.type = SDK_OP_VLAN_DELETE;
            undo.args.vlan.vid = op->args.vlan.vid;
            break;
        case SDK_OP_VLAN_ADD_PORT:
            undo.type = SDK_OP_VLAN_REM_PORT;
            undo.args.vlan.vid = op->args.vlan.vid;
            undo.args.vlan.port = op->args.vlan.port;
            break;
        case SDK_OP_PORT_SET_ADMIN:
            undo.type = SDK_OP_PORT_SET_ADMIN;
            undo.args.port.port = op->pre_state.port.port;
            undo.args.port.mode = op->pre_state.port.mode;
            break;
        default:
            return -1;
    }
    return sdk_exec_op_dispatch(0, &undo, NULL);
}
