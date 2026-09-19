#include "netlab/log.h"
#include "netlab/hal.h"
#include <stdio.h>
#include <string.h>
#include <fm_sdk.h>
#include <debug/fm_debug.h>

typedef struct {
    int index;
    const char *label;
    const char *sensor_class;
    const char *unit;
} switch_sensor_def;

static const switch_sensor_def switch_sensor_defs[] = {
    {0, "MAIN TEMP SENSOR", "temperature", "celsius"},
    {1, "REMOTE TEMP SENSOR 0", "temperature", "celsius"},
    {2, "REMOTE TEMP SENSOR 1", "temperature", "celsius"},
    {3, "REMOTE TEMP SENSOR 2", "temperature", "celsius"},
    {4, "REMOTE TEMP SENSOR 3", "temperature", "celsius"},
    {5, "REMOTE TEMP SENSOR 4", "temperature", "celsius"},
    {6, "REMOTE TEMP SENSOR 5", "temperature", "celsius"},
    {7, "REMOTE TEMP SENSOR 6", "temperature", "celsius"},
    {8, "REMOTE TEMP SENSOR 7", "temperature", "celsius"},
    {9, "VOLTAGE SENSOR VDD", "voltage", "volts"},
    {10, "VOLTAGE SENSOR CORE_VDD_VIN", "voltage", "volts"},
    {11, "VOLTAGE SENSOR A2D_VIN[0]", "voltage", "volts"},
    {12, "VOLTAGE SENSOR A2D_VIN[1]", "voltage", "volts"},
    {13, "VOLTAGE SENSOR A2D_VIN[2]", "voltage", "volts"},
    {14, "VOLTAGE SENSOR A2D_VIN[3]", "voltage", "volts"},
    {15, "VOLTAGE SENSOR A2D_VIN[4]", "voltage", "volts"},
    {16, "VOLTAGE SENSOR A2D_VIN[5]", "voltage", "volts"},
};

static float sbus_sensor_value(const switch_sensor_def *def,
                               fm_uint32 raw) {
    if (strcmp(def->sensor_class, "voltage") == 0)
        return (float)(raw & 0x0fff) / 2000.0f;
    return (float)(raw & 0x7fff) / 8.0f;
}

int hal_get_switch_info(int sw, int *num_ports) {
    fm_switchInfo info;
    fm_status st = fmGetSwitchInfo((fm_int)sw, &info);
    if (st != FM_OK) return -1;
    *num_ports = info.numPorts;
    return 0;
}

int hal_get_switch_digital_sensors_range(int sw, int first, int count,
                                         struct sdk_result *result) {
    fm_status st;
    fm_uint32 raw = 0;
    const fm_int sbus_addr = 0x145;
    const fm_int reset_start_reg = 0;
    const fm_int sensor_div_reg = 1;
    const fm_int sensor_mode_reg = 3;
    const fm_int sensor_result_base = 65;
    int n_sensors = 0;

    int sensor_count = (int)(sizeof(switch_sensor_defs) /
                             sizeof(switch_sensor_defs[0]));

    if (!result || first < 0 || count <= 0 || first >= sensor_count)
        return -1;
    if (count > sensor_count - first)
        count = sensor_count - first;
    memset(&result->data.switch_sensors, 0,
           sizeof(result->data.switch_sensors));

    st = fmDbgWriteSBusRegister((fm_int)sw, sbus_addr, reset_start_reg, 3);
    if (st != FM_OK)
        return -1;
    st = fmDbgReadSBusRegister((fm_int)sw, sbus_addr, reset_start_reg,
                               FALSE, &raw);
    if (st != FM_OK)
        return -1;
    st = fmDbgWriteSBusRegister((fm_int)sw, sbus_addr, sensor_div_reg, 25);
    if (st != FM_OK)
        return -1;

    for (int i = first; i < first + count; i++) {
        const switch_sensor_def *def = &switch_sensor_defs[i];
        fm_uint32 mode = (fm_uint32)1U << def->index;
        bool valid = false;
        float value = 0.0f;

        st = fmDbgWriteSBusRegister((fm_int)sw, sbus_addr,
                                    sensor_mode_reg, mode);
        if (st != FM_OK)
            return -1;
        st = fmDbgWriteSBusRegister((fm_int)sw, sbus_addr,
                                    reset_start_reg, 2);
        if (st != FM_OK)
            return -1;

        for (int retry = 0; retry < 5; retry++) {
            raw = 0;
            st = fmDbgReadSBusRegister((fm_int)sw, sbus_addr,
                                       sensor_result_base + def->index,
                                       FALSE, &raw);
            if (st != FM_OK)
                return -1;
            if (raw & 0x8000) {
                value = sbus_sensor_value(def, raw);
                valid = true;
                break;
            }
            fmDelay(0, 100 * 1000 * 1000);
        }

        (void)fmDbgWriteSBusRegister((fm_int)sw, sbus_addr,
                                     reset_start_reg, 2);
        if (n_sensors < NETLAB_SWITCH_SENSOR_MAX) {
            result->data.switch_sensors.sensor[n_sensors].index = def->index;
            snprintf(result->data.switch_sensors.sensor[n_sensors].label,
                     sizeof(result->data.switch_sensors.sensor[n_sensors].label),
                     "%s", def->label);
            snprintf(result->data.switch_sensors.sensor[n_sensors].sensor_class,
                     sizeof(result->data.switch_sensors.sensor[n_sensors].sensor_class),
                     "%s", def->sensor_class);
            snprintf(result->data.switch_sensors.sensor[n_sensors].unit,
                     sizeof(result->data.switch_sensors.sensor[n_sensors].unit),
                     "%s", def->unit);
            result->data.switch_sensors.sensor[n_sensors].value = value;
            result->data.switch_sensors.sensor[n_sensors].valid = valid;
            n_sensors++;
        }
    }

    result->data.switch_sensors.n_sensors = n_sensors;
    return n_sensors > 0 ? 0 : -1;
}

int hal_get_switch_digital_sensors(int sw, struct sdk_result *result) {
    return hal_get_switch_digital_sensors_range(
        sw, 0, NETLAB_SWITCH_SENSOR_MAX, result);
}

int hal_get_temperature(int sw, float *temp_c) {
    struct sdk_result result;

    if (!temp_c)
        return -1;
    memset(&result, 0, sizeof(result));
    if (hal_get_switch_digital_sensors_range(sw, 0, 1, &result) != 0)
        return -1;
    for (int i = 0; i < result.data.switch_sensors.n_sensors; i++) {
        if (result.data.switch_sensors.sensor[i].index == 0 &&
            result.data.switch_sensors.sensor[i].valid) {
            *temp_c = result.data.switch_sensors.sensor[i].value;
            return 0;
        }
    }
    return -1;
}
