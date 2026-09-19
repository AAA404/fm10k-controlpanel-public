#include "netlab/daemon.h"
#include "netlab/interface_id.h"
#include "netlab/ipc.h"
#include "netlab/log.h"
#include <dirent.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHASSISD_SOCKET "/var/run/netlab/chassisd.sock"
#define IDENTITYD_SOCKET "/var/run/netlab/identityd.sock"
#define SWITCHD_SOCKET  "/var/run/netlab/switchd.sock"
#define HWMON_BASE      "/sys/class/hwmon"
#define MAX_SENSORS     96
#define CHASSISD_POLL_INTERVAL_SEC 5
#define CHASSISD_STALE_AFTER_SEC 15
#define CHASSISD_BOARD_POLL_INTERVAL_SEC 30
#define CHASSISD_BOARD_MAX_SENSORS 24

typedef struct {
    int id;
    char label[96];
    char source[32];
    char sensor_class[32];
    char status[24];
    bool has_temp;
    bool has_voltage;
    bool has_current;
    bool has_power;
    bool has_fan;
    bool has_state;
    bool has_temp_high;
    bool has_temp_crit;
    bool has_temp_low;
    bool has_voltage_high;
    bool has_voltage_low;
    bool has_current_high;
    bool has_power_cap;
    bool has_power_high;
    float temp_c;
    float voltage_v;
    float current_a;
    float power_w;
    float fan_rpm;
    bool state;
    char raw[40];
    float temp_high_c;
    float temp_crit_c;
    float temp_low_c;
    float voltage_high_v;
    float voltage_low_v;
    float current_high_a;
    float power_cap_w;
    float power_high_w;
} sensor_state;

typedef struct {
    bool present;
    bool reachable;
    bool failed;
    int sensor_count;
    int available_count;
} sensor_source_state;

typedef struct {
    sensor_state sensors[MAX_SENSORS];
    int sensor_count;
    sensor_source_state switchd;
    sensor_source_state sysfs;
    sensor_source_state board_i2c;
    sensor_state board_sensors[CHASSISD_BOARD_MAX_SENSORS];
    int board_sensor_count;
    time_t board_last_poll;
    time_t last_poll;
    u64 poll_generation;
    u64 last_poll_duration_ms;
    pthread_mutex_t lock;
    pthread_mutex_t poll_lock;
    pthread_cond_t poll_cond;
    pthread_t poll_thread;
    bool poll_thread_started;
    bool poll_running;
} chassisd_ctx;

static chassisd_ctx g_chassis;

static u64 monotonic_ms(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (u64)now.tv_sec * 1000ULL + (u64)now.tv_nsec / 1000000ULL;
}

static bool sysfs_try_read_int(const char *path, int *out) {
    FILE *f = fopen(path, "r");
    int val;

    if (!f)
        return false;
    if (fscanf(f, "%d", &val) != 1) {
        fclose(f);
        return false;
    }
    fclose(f);
    if (out)
        *out = val;
    return true;
}

static void mark_alarm(sensor_state *sensor, const char *status) {
    if (strcmp(status, "critical") == 0 ||
        strcmp(sensor->status, "ok") == 0)
        snprintf(sensor->status, sizeof(sensor->status), "%s", status);
}

static void appendf(char *buf, int buf_sz, int *off, const char *fmt, ...) {
    va_list ap;
    int n;

    if (*off >= buf_sz)
        return;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, (size_t)(buf_sz - *off), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (n >= buf_sz - *off) {
        *off = buf_sz - 1;
        return;
    }
    *off += n;
}

static void xml_escape_attr(const char *src, char *dst, size_t dst_len) {
    size_t off = 0;

    if (!dst_len)
        return;
    if (!src)
        src = "";
    for (const char *p = src; *p && off + 1 < dst_len; p++) {
        const char *rep = NULL;

        switch (*p) {
        case '&': rep = "&amp;"; break;
        case '<': rep = "&lt;"; break;
        case '>': rep = "&gt;"; break;
        case '"': rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default:
            dst[off++] = *p;
            continue;
        }
        size_t len = strlen(rep);
        if (off + len >= dst_len)
            break;
        memcpy(dst + off, rep, len);
        off += len;
    }
    dst[off] = '\0';
}

static void sysfs_read_label(const char *path, char *label, size_t label_len,
                             const char *fallback) {
    FILE *f = fopen(path, "r");

    snprintf(label, label_len, "%s", fallback);
    if (!f)
        return;
    if (fgets(label, (int)label_len, f)) {
        char *nl = strchr(label, '\n');
        if (nl)
            *nl = '\0';
    }
    fclose(f);
}

static bool extract_tag(const char *xml, const char *tag,
                        char *out, size_t out_len) {
    char open[64];
    char close[64];
    const char *start;
    const char *end;
    size_t len;

    snprintf(open, sizeof(open), "<%s", tag);
    start = strstr(xml, open);
    if (!start)
        return false;
    start = strchr(start, '>');
    if (!start)
        return false;
    start++;
    snprintf(close, sizeof(close), "</%s>", tag);
    end = strstr(start, close);
    if (!end)
        return false;
    len = (size_t)(end - start);
    if (len >= out_len)
        len = out_len - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static bool extract_tag_float(const char *xml, const char *tag, float *value) {
    char buf[64];
    char *end = NULL;
    float parsed;

    if (!extract_tag(xml, tag, buf, sizeof(buf)))
        return false;
    parsed = strtof(buf, &end);
    if (end == buf)
        return false;
    *value = parsed;
    return true;
}

static bool extract_attr(const char *tag, const char *attr,
                         char *out, size_t out_len) {
    char needle[64];
    const char *start;
    const char *end;
    size_t len;

    if (!tag || !attr || !out || out_len == 0)
        return false;
    snprintf(needle, sizeof(needle), "%s=\"", attr);
    start = strstr(tag, needle);
    if (!start)
        return false;
    start += strlen(needle);
    end = strchr(start, '"');
    if (!end)
        return false;
    len = (size_t)(end - start);
    if (len >= out_len)
        len = out_len - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static void get_chassis_identity(char *name, size_t name_size,
                                 char *serial, size_t serial_size) {
    nl_platform_identity ident;
    nl_board_profile board;
    char dmi_serial[128];

    if (name && name_size > 0)
        name[0] = '\0';
    if (serial && serial_size > 0)
        serial[0] = '\0';

    memset(&ident, 0, sizeof(ident));
    memset(&board, 0, sizeof(board));
    if (nl_platform_identity_get(&ident)) {
        if (name && name_size > 0)
            snprintf(name, name_size, "%s", ident.chassis_name);
    }
    if (nl_platform_board_get(&board) && name && name_size > 0)
        snprintf(name, name_size, "%s", board.model);
    sysfs_read_label("/sys/class/dmi/id/product_serial", dmi_serial,
                     sizeof(dmi_serial), "");
    if (serial && serial_size > 0 && dmi_serial[0]) {
        size_t copy_len = strnlen(dmi_serial, serial_size - 1);

        memcpy(serial, dmi_serial, copy_len);
        serial[copy_len] = '\0';
    }
    if (name && name_size > 0 && !name[0])
        snprintf(name, name_size, "unknown");
    if (serial && serial_size > 0 && !serial[0])
        snprintf(serial, serial_size, "unknown");
}

static void init_sensor(sensor_state *sensor, const char *source,
                        const char *sensor_class, const char *label) {
    memset(sensor, 0, sizeof(*sensor));
    snprintf(sensor->source, sizeof(sensor->source), "%s", source);
    snprintf(sensor->sensor_class, sizeof(sensor->sensor_class), "%s",
             sensor_class);
    snprintf(sensor->label, sizeof(sensor->label), "%s", label);
    snprintf(sensor->status, sizeof(sensor->status), "ok");
}

static bool add_sensor(sensor_state *sensors, int *sensor_count,
                       const sensor_state *sensor) {
    if (*sensor_count >= MAX_SENSORS)
        return false;
    sensors[*sensor_count] = *sensor;
    sensors[*sensor_count].id = *sensor_count;
    (*sensor_count)++;
    return true;
}

static void poll_switchd_sensors(sensor_state *sensors, int *sensor_count,
                                 sensor_source_state *source) {
    char xml[8192] = {0};
    s32 ec = 0;
    int rn;
    int before = *sensor_count;
    float temp_c = 0.0f;
    sensor_state sensor;

    memset(source, 0, sizeof(*source));
    source->present = access(SWITCHD_SOCKET, F_OK) == 0;
    if (!source->present)
        return;

    rn = nl_rpc_call_ex(
        SWITCHD_SOCKET, NL_DAEMON_CHASSISD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_SWITCH_SENSORS_GET, 0,
                        (const u8 *)"", 0, (u8 *)xml, sizeof(xml),
                        12000, &ec);
    if (rn > 0) {
        source->reachable = true;
        xml[sizeof(xml) - 1] = '\0';
    }
    if (rn > 0 && ec == 0) {
        const char *p = xml;

        while ((p = strstr(p, "<sensor ")) != NULL) {
            const char *end = strchr(p, '>');
            char tag[512];
            char label[96];
            char sensor_class[32];
            char valid[8];
            char value[64];
            char *parse_end = NULL;
            float parsed = 0.0f;
            size_t len;

            if (!end)
                break;
            len = (size_t)(end - p + 1);
            if (len >= sizeof(tag))
                len = sizeof(tag) - 1;
            memcpy(tag, p, len);
            tag[len] = '\0';
            p = end + 1;

            if (!extract_attr(tag, "label", label, sizeof(label)) ||
                !extract_attr(tag, "class", sensor_class,
                              sizeof(sensor_class)) ||
                !extract_attr(tag, "valid", valid, sizeof(valid)) ||
                !extract_attr(tag, "value", value, sizeof(value)))
                continue;
            if (strcmp(valid, "1") != 0)
                continue;
            parsed = strtof(value, &parse_end);
            if (parse_end == value)
                continue;

            init_sensor(&sensor, "switchd-sbus", sensor_class, label);
            if (strcmp(sensor_class, "temperature") == 0) {
                if (parsed < -50.0f || parsed > 130.0f)
                    continue;
                sensor.has_temp = true;
                sensor.temp_c = parsed;
            } else if (strcmp(sensor_class, "voltage") == 0) {
                if (parsed < 0.0f || parsed > 20.0f)
                    continue;
                sensor.has_voltage = true;
                sensor.voltage_v = parsed;
            } else {
                continue;
            }
            add_sensor(sensors, sensor_count, &sensor);
        }
        source->sensor_count = *sensor_count - before;
        source->available_count = source->sensor_count;
        if (source->sensor_count > 0)
            return;
    }

    memset(xml, 0, sizeof(xml));
    ec = 0;
    rn = nl_rpc_call_ex(
        SWITCHD_SOCKET, NL_DAEMON_CHASSISD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_TEMPERATURE_GET, 0,
                        (const u8 *)"", 0, (u8 *)xml, sizeof(xml),
                        3000, &ec);
    if (rn <= 0 || ec != 0)
        return;
    source->reachable = true;
    xml[sizeof(xml) - 1] = '\0';
    if (!extract_tag_float(xml, "temperature", &temp_c))
        return;
    if (temp_c < -50.0f || temp_c > 130.0f)
        return;

    init_sensor(&sensor, "switchd-sbus", "temperature", "MAIN TEMP SENSOR");
    sensor.has_temp = true;
    sensor.temp_c = temp_c;
    add_sensor(sensors, sensor_count, &sensor);
    source->sensor_count = *sensor_count - before;
    source->available_count = source->sensor_count;
}

static void poll_board_i2c_sensors(sensor_state *sensors, int *sensor_count,
                                   sensor_source_state *source) {
    char xml[32768] = {0};
    s32 ec = 0;
    int rn;
    int before = *sensor_count;
    nl_board_profile board;

    memset(source, 0, sizeof(*source));
    memset(&board, 0, sizeof(board));
    source->present = nl_platform_board_get(&board) &&
                      access(SWITCHD_SOCKET, F_OK) == 0;
    if (!source->present)
        return;
    rn = nl_rpc_call_ex(
        SWITCHD_SOCKET, NL_DAEMON_CHASSISD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_BOARD_ENV_GET, 0, NULL, 0, (u8 *)xml, sizeof(xml),
        15000, &ec);
    if (rn <= 0)
        return;
    source->reachable = true;
    xml[sizeof(xml) - 1] = '\0';
    if (ec != 0) {
        source->failed = true;
        return;
    }

    {
        const char *root_end = strchr(xml, '>');
        char root_tag[512];
        char failures[32] = {0};
        char restore[32] = {0};
        char topology[32] = {0};
        size_t root_len = root_end ? (size_t)(root_end - xml + 1) : 0;

        if (root_len == 0 || root_len >= sizeof(root_tag)) {
            source->failed = true;
        } else {
            memcpy(root_tag, xml, root_len);
            root_tag[root_len] = '\0';
            if (!extract_attr(root_tag, "sample-failures", failures,
                              sizeof(failures)) ||
                !extract_attr(root_tag, "restore-status", restore,
                              sizeof(restore)) ||
                !extract_attr(root_tag, "topology-status", topology,
                              sizeof(topology)) ||
                atoi(failures) != 0 || atoi(restore) != 0)
                source->failed = true;
            if (strcmp(topology, "consistent") != 0)
                source->failed = true;
        }
    }

    const char *p = xml;
    while ((p = strstr(p, "<sensor ")) != NULL) {
        const char *end = strchr(p, '>');
        char tag[768];
        char name[96];
        char sensor_class[32];
        char valid[8];
        char value[64];
        char raw[40] = {0};
        char *parse_end = NULL;
        float parsed = 0.0f;
        bool is_valid;
        sensor_state sensor;
        size_t len;

        if (!end)
            break;
        len = (size_t)(end - p + 1);
        if (len >= sizeof(tag))
            len = sizeof(tag) - 1;
        memcpy(tag, p, len);
        tag[len] = '\0';
        p = end + 1;
        if (!extract_attr(tag, "name", name, sizeof(name)) ||
            !extract_attr(tag, "class", sensor_class,
                          sizeof(sensor_class)) ||
            !extract_attr(tag, "valid", valid, sizeof(valid)) ||
            !extract_attr(tag, "value", value, sizeof(value)))
            continue;
        (void)extract_attr(tag, "raw", raw, sizeof(raw));
        parsed = strtof(value, &parse_end);
        is_valid = strcmp(valid, "1") == 0 && parse_end != value;
        init_sensor(&sensor, "board-i2c", sensor_class, name);
        snprintf(sensor.raw, sizeof(sensor.raw), "%s", raw);
        if (!is_valid) {
            snprintf(sensor.status, sizeof(sensor.status), "unavailable");
        } else if (strcmp(sensor_class, "temperature") == 0 &&
                   parsed >= -55.0f && parsed <= 150.0f) {
            sensor.has_temp = true;
            sensor.temp_c = parsed;
        } else if (strcmp(sensor_class, "voltage") == 0 &&
                   parsed >= 0.0f && parsed <= 20.0f) {
            sensor.has_voltage = true;
            sensor.voltage_v = parsed;
        } else if (strcmp(sensor_class, "fan") == 0 && parsed >= 0.0f) {
            sensor.has_fan = true;
            sensor.fan_rpm = parsed;
        } else if (strcmp(sensor_class, "status") == 0) {
            sensor.has_state = true;
            sensor.state = parsed != 0.0f;
            if (!sensor.state)
                snprintf(sensor.status, sizeof(sensor.status), "critical");
        } else {
            snprintf(sensor.status, sizeof(sensor.status), "unavailable");
        }
        if (strcmp(sensor.status, "unavailable") != 0)
            source->available_count++;
        add_sensor(sensors, sensor_count, &sensor);
    }
    source->sensor_count = *sensor_count - before;
}

static void poll_hwmon_sensors(sensor_state *sensors, int *sensor_count,
                               sensor_source_state *source) {
    DIR *d;
    struct dirent *entry;
    int before = *sensor_count;

    memset(source, 0, sizeof(*source));

    d = opendir(HWMON_BASE);
    if (!d)
        return;

    source->reachable = true;
    while ((entry = readdir(d))) {
        char path[512];
        char chip[64];
        char name_path[640];

        if (entry->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "%s/%s", HWMON_BASE, entry->d_name);
        source->present = true;
        snprintf(name_path, sizeof(name_path), "%s/name", path);
        sysfs_read_label(name_path, chip, sizeof(chip), entry->d_name);

        for (int ti = 1; ti <= 32; ti++) {
            char input_path[640];
            char label_path[640];
            char fallback[128];
            int temp_mc;
            int threshold;
            sensor_state sensor;
            char label[96];

            snprintf(input_path, sizeof(input_path), "%s/temp%d_input",
                     path, ti);
            if (!sysfs_try_read_int(input_path, &temp_mc))
                continue;

            snprintf(label_path, sizeof(label_path), "%s/temp%d_label",
                     path, ti);
            snprintf(fallback, sizeof(fallback), "%s temp%d", chip, ti);
            sysfs_read_label(label_path, label, sizeof(label), fallback);

            init_sensor(&sensor, "sysfs-hwmon", "temperature", label);
            sensor.has_temp = true;
            sensor.temp_c = (float)temp_mc / 1000.0f;
            snprintf(input_path, sizeof(input_path), "%s/temp%d_max",
                     path, ti);
            if (sysfs_try_read_int(input_path, &threshold)) {
                sensor.has_temp_high = true;
                sensor.temp_high_c = (float)threshold / 1000.0f;
                if (sensor.temp_c >= sensor.temp_high_c)
                    mark_alarm(&sensor, "high");
            }
            snprintf(input_path, sizeof(input_path), "%s/temp%d_crit",
                     path, ti);
            if (sysfs_try_read_int(input_path, &threshold)) {
                sensor.has_temp_crit = true;
                sensor.temp_crit_c = (float)threshold / 1000.0f;
                if (sensor.temp_c >= sensor.temp_crit_c)
                    mark_alarm(&sensor, "critical");
            }
            snprintf(input_path, sizeof(input_path), "%s/temp%d_min",
                     path, ti);
            if (sysfs_try_read_int(input_path, &threshold)) {
                sensor.has_temp_low = true;
                sensor.temp_low_c = (float)threshold / 1000.0f;
                if (sensor.temp_c <= sensor.temp_low_c)
                    mark_alarm(&sensor, "low");
            }
            add_sensor(sensors, sensor_count, &sensor);
        }

        for (int vi = 1; vi <= 32; vi++) {
            char input_path[640];
            char label_path[640];
            char fallback[128];
            int mv;
            int threshold;
            sensor_state sensor;
            char label[96];

            snprintf(input_path, sizeof(input_path), "%s/in%d_input",
                     path, vi);
            if (!sysfs_try_read_int(input_path, &mv))
                continue;

            snprintf(label_path, sizeof(label_path), "%s/in%d_label",
                     path, vi);
            snprintf(fallback, sizeof(fallback), "%s in%d", chip, vi);
            sysfs_read_label(label_path, label, sizeof(label), fallback);

            init_sensor(&sensor, "sysfs-hwmon", "voltage", label);
            sensor.has_voltage = true;
            sensor.voltage_v = (float)mv / 1000.0f;
            snprintf(input_path, sizeof(input_path), "%s/in%d_max",
                     path, vi);
            if (sysfs_try_read_int(input_path, &threshold)) {
                sensor.has_voltage_high = true;
                sensor.voltage_high_v = (float)threshold / 1000.0f;
                if (sensor.voltage_v >= sensor.voltage_high_v)
                    mark_alarm(&sensor, "high");
            }
            snprintf(input_path, sizeof(input_path), "%s/in%d_min",
                     path, vi);
            if (sysfs_try_read_int(input_path, &threshold)) {
                sensor.has_voltage_low = true;
                sensor.voltage_low_v = (float)threshold / 1000.0f;
                if (sensor.voltage_v <= sensor.voltage_low_v)
                    mark_alarm(&sensor, "low");
            }
            add_sensor(sensors, sensor_count, &sensor);
        }

        for (int ci = 1; ci <= 32; ci++) {
            char input_path[640];
            char label_path[640];
            char fallback[128];
            int ma;
            int threshold;
            sensor_state sensor;
            char label[96];

            snprintf(input_path, sizeof(input_path), "%s/curr%d_input",
                     path, ci);
            if (!sysfs_try_read_int(input_path, &ma))
                continue;

            snprintf(label_path, sizeof(label_path), "%s/curr%d_label",
                     path, ci);
            snprintf(fallback, sizeof(fallback), "%s current%d", chip, ci);
            sysfs_read_label(label_path, label, sizeof(label), fallback);

            init_sensor(&sensor, "sysfs-hwmon", "current", label);
            sensor.has_current = true;
            sensor.current_a = (float)ma / 1000.0f;
            snprintf(input_path, sizeof(input_path), "%s/curr%d_max",
                     path, ci);
            if (sysfs_try_read_int(input_path, &threshold)) {
                sensor.has_current_high = true;
                sensor.current_high_a = (float)threshold / 1000.0f;
                if (sensor.current_a >= sensor.current_high_a)
                    mark_alarm(&sensor, "high");
            }
            add_sensor(sensors, sensor_count, &sensor);
        }

        for (int pi = 1; pi <= 32; pi++) {
            char input_path[640];
            char label_path[640];
            char fallback[128];
            int microwatts;
            int threshold;
            sensor_state sensor;
            char label[96];

            snprintf(input_path, sizeof(input_path), "%s/power%d_input",
                     path, pi);
            if (!sysfs_try_read_int(input_path, &microwatts))
                continue;

            snprintf(label_path, sizeof(label_path), "%s/power%d_label",
                     path, pi);
            snprintf(fallback, sizeof(fallback), "%s power%d", chip, pi);
            sysfs_read_label(label_path, label, sizeof(label), fallback);

            init_sensor(&sensor, "sysfs-hwmon", "power", label);
            sensor.has_power = true;
            sensor.power_w = (float)microwatts / 1000000.0f;
            snprintf(input_path, sizeof(input_path), "%s/power%d_cap",
                     path, pi);
            if (sysfs_try_read_int(input_path, &threshold)) {
                sensor.has_power_cap = true;
                sensor.power_cap_w = (float)threshold / 1000000.0f;
                if (sensor.power_w >= sensor.power_cap_w)
                    mark_alarm(&sensor, "high");
            }
            snprintf(input_path, sizeof(input_path), "%s/power%d_max",
                     path, pi);
            if (sysfs_try_read_int(input_path, &threshold)) {
                sensor.has_power_high = true;
                sensor.power_high_w = (float)threshold / 1000000.0f;
                if (sensor.power_w >= sensor.power_high_w)
                    mark_alarm(&sensor, "high");
            }
            add_sensor(sensors, sensor_count, &sensor);
        }
    }
    closedir(d);
    source->sensor_count = *sensor_count - before;
    source->available_count = source->sensor_count;
}

static void poll_sensors(void) {
    sensor_state sensors[MAX_SENSORS];
    int sensor_count = 0;
    sensor_source_state switchd;
    sensor_source_state sysfs;
    sensor_source_state board_i2c;
    sensor_state board_sensors[CHASSISD_BOARD_MAX_SENSORS];
    int board_sensor_count = 0;
    bool board_due;
    time_t now = time(NULL);
    u64 started_ms = monotonic_ms();
    u64 finished_ms;

    memset(sensors, 0, sizeof(sensors));
    poll_switchd_sensors(sensors, &sensor_count, &switchd);
    poll_hwmon_sensors(sensors, &sensor_count, &sysfs);
    pthread_mutex_lock(&g_chassis.lock);
    board_due = !g_chassis.board_last_poll ||
        now - g_chassis.board_last_poll >= CHASSISD_BOARD_POLL_INTERVAL_SEC;
    board_i2c = g_chassis.board_i2c;
    board_sensor_count = g_chassis.board_sensor_count;
    memcpy(board_sensors, g_chassis.board_sensors, sizeof(board_sensors));
    pthread_mutex_unlock(&g_chassis.lock);
    if (board_due) {
        memset(board_sensors, 0, sizeof(board_sensors));
        board_sensor_count = 0;
        poll_board_i2c_sensors(board_sensors, &board_sensor_count,
                               &board_i2c);
    }
    for (int i = 0; i < board_sensor_count; i++)
        add_sensor(sensors, &sensor_count, &board_sensors[i]);
    finished_ms = monotonic_ms();

    pthread_mutex_lock(&g_chassis.lock);
    memcpy(g_chassis.sensors, sensors, sizeof(g_chassis.sensors));
    g_chassis.sensor_count = sensor_count;
    g_chassis.switchd = switchd;
    g_chassis.sysfs = sysfs;
    g_chassis.board_i2c = board_i2c;
    if (board_due) {
        memcpy(g_chassis.board_sensors, board_sensors,
               sizeof(g_chassis.board_sensors));
        g_chassis.board_sensor_count = board_sensor_count;
        g_chassis.board_last_poll = now;
    }
    g_chassis.last_poll = time(NULL);
    g_chassis.poll_generation++;
    g_chassis.last_poll_duration_ms =
        finished_ms >= started_ms ? finished_ms - started_ms : 0;
    pthread_mutex_unlock(&g_chassis.lock);
}

static void *chassisd_poll_main(void *arg) {
    chassisd_ctx *state = arg;

    for (;;) {
        struct timespec deadline;

        pthread_mutex_lock(&state->poll_lock);
        if (!state->poll_running) {
            pthread_mutex_unlock(&state->poll_lock);
            break;
        }
        pthread_mutex_unlock(&state->poll_lock);

        poll_sensors();

        pthread_mutex_lock(&state->poll_lock);
        if (state->poll_running) {
            clock_gettime(CLOCK_REALTIME, &deadline);
            deadline.tv_sec += CHASSISD_POLL_INTERVAL_SEC;
            (void)pthread_cond_timedwait(&state->poll_cond,
                                         &state->poll_lock, &deadline);
        }
        bool running = state->poll_running;
        pthread_mutex_unlock(&state->poll_lock);
        if (!running)
            break;
    }
    return NULL;
}

static const char *source_status(const sensor_source_state *source) {
    if (!source->present)
        return "unavailable";
    if (!source->reachable)
        return "down";
    if (source->failed)
        return source->available_count > 0 ? "degraded" : "unavailable";
    if (source->sensor_count == 0)
        return "empty";
    if (source->available_count == 0)
        return "unavailable";
    if (source->available_count < source->sensor_count)
        return "degraded";
    return "ok";
}

static void append_sensor_xml(char *buf, int buf_sz, int *off,
                              const sensor_state *sensor) {
    char label[160];
    char source[64];
    char sensor_class[64];

    xml_escape_attr(sensor->label, label, sizeof(label));
    xml_escape_attr(sensor->source, source, sizeof(source));
    xml_escape_attr(sensor->sensor_class, sensor_class, sizeof(sensor_class));
    appendf(buf, buf_sz, off,
            "    <sensor id=\"%d\" label=\"%s\" source=\"%s\" "
            "class=\"%s\" status=\"%s\"",
            sensor->id, label, source, sensor_class, sensor->status);
    if (sensor->has_temp)
        appendf(buf, buf_sz, off, " temp=\"%.1f\"", sensor->temp_c);
    if (sensor->has_temp_high)
        appendf(buf, buf_sz, off, " temp-high=\"%.1f\"",
                sensor->temp_high_c);
    if (sensor->has_temp_crit)
        appendf(buf, buf_sz, off, " temp-crit=\"%.1f\"",
                sensor->temp_crit_c);
    if (sensor->has_temp_low)
        appendf(buf, buf_sz, off, " temp-low=\"%.1f\"",
                sensor->temp_low_c);
    if (sensor->has_voltage)
        appendf(buf, buf_sz, off, " voltage=\"%.4f\"", sensor->voltage_v);
    if (sensor->has_voltage_high)
        appendf(buf, buf_sz, off, " voltage-high=\"%.4f\"",
                sensor->voltage_high_v);
    if (sensor->has_voltage_low)
        appendf(buf, buf_sz, off, " voltage-low=\"%.4f\"",
                sensor->voltage_low_v);
    if (sensor->has_current)
        appendf(buf, buf_sz, off, " current=\"%.3f\"", sensor->current_a);
    if (sensor->has_current_high)
        appendf(buf, buf_sz, off, " current-high=\"%.3f\"",
                sensor->current_high_a);
    if (sensor->has_power)
        appendf(buf, buf_sz, off, " power=\"%.3f\"", sensor->power_w);
    if (sensor->has_power_cap)
        appendf(buf, buf_sz, off, " power-cap=\"%.3f\"",
                sensor->power_cap_w);
    if (sensor->has_power_high)
        appendf(buf, buf_sz, off, " power-high=\"%.3f\"",
                sensor->power_high_w);
    if (sensor->has_fan)
        appendf(buf, buf_sz, off, " fan-rpm=\"%.0f\"", sensor->fan_rpm);
    if (sensor->has_state)
        appendf(buf, buf_sz, off, " state=\"%s\"",
                sensor->state ? "true" : "false");
    if (sensor->raw[0]) {
        char raw[80];
        xml_escape_attr(sensor->raw, raw, sizeof(raw));
        appendf(buf, buf_sz, off, " raw=\"%s\"", raw);
    }
    appendf(buf, buf_sz, off, "/>\n");
}

static int build_chassis_xml(char *buf, int buf_sz) {
    int off = 0;
    char chassis_name[64];
    char serial[64];
    time_t now = time(NULL);
    long age;
    bool stale;

    pthread_mutex_lock(&g_chassis.lock);
    age = g_chassis.last_poll ? (long)(now - g_chassis.last_poll) : -1L;
    stale = age < 0 || age > CHASSISD_STALE_AFTER_SEC;
    get_chassis_identity(chassis_name, sizeof(chassis_name),
                         serial, sizeof(serial));
    appendf(buf, buf_sz, &off,
        "<chassis last-poll=\"%ld\" generation=\"%llu\" "
        "age-seconds=\"%ld\" stale=\"%s\" duration-ms=\"%llu\">\n"
        "  <name>%s</name>\n"
        "  <serial>%s</serial>\n"
        "  <sources>\n"
        "    <source name=\"switchd-sbus\" status=\"%s\" sensors=\"%d\"/>\n"
        "    <source name=\"sysfs-hwmon\" status=\"%s\" sensors=\"%d\"/>\n"
        "    <source name=\"board-i2c\" status=\"%s\" sensors=\"%d\"/>\n"
        "  </sources>\n"
        "  <sensors>\n",
        (long)g_chassis.last_poll,
        (unsigned long long)g_chassis.poll_generation,
        age, stale ? "true" : "false",
        (unsigned long long)g_chassis.last_poll_duration_ms,
        chassis_name, serial,
        source_status(&g_chassis.switchd), g_chassis.switchd.sensor_count,
        source_status(&g_chassis.sysfs), g_chassis.sysfs.sensor_count,
        source_status(&g_chassis.board_i2c),
        g_chassis.board_i2c.sensor_count);

    if (g_chassis.sensor_count == 0) {
        appendf(buf, buf_sz, &off,
                "    <sensor id=\"0\" label=\"no switch sensors available\" "
                "source=\"none\" class=\"none\" status=\"unavailable\"/>\n");
    } else {
        for (int i = 0; i < g_chassis.sensor_count; i++)
            append_sensor_xml(buf, buf_sz, &off, &g_chassis.sensors[i]);
    }

    appendf(buf, buf_sz, &off,
        "  </sensors>\n"
        "</chassis>\n");
    pthread_mutex_unlock(&g_chassis.lock);
    return off;
}

static int handle_get_chassis(nl_conn *conn, nl_msg_hdr *msg) {
    char buf[16384];
    int off = build_chassis_xml(buf, sizeof(buf));
    nl_msg_hdr *resp = nl_msg_alloc((u32)off);

    if (resp) {
        resp->type = NL_MSG_RESPONSE;
        resp->request_id = msg->request_id;
        resp->payload_len = (u32)off;
        memcpy(resp->payload, buf, (size_t)off);
        nl_send(conn, resp);
        nl_msg_free(resp);
    }
    return 0;
}

static int chassisd_dispatch(nl_conn *conn, nl_msg_hdr *msg, void *ctx) {
    (void)ctx;
    switch (msg->method) {
    case NL_CHASSISD_SHOW:
        return handle_get_chassis(conn, msg);
    default:
        nl_send_response(conn, msg->request_id, -1);
        return 0;
    }
}

static int chassisd_on_init(void *ctx) {
    (void)ctx;
    memset(&g_chassis, 0, sizeof(g_chassis));
    pthread_mutex_init(&g_chassis.lock, NULL);
    pthread_mutex_init(&g_chassis.poll_lock, NULL);
    pthread_cond_init(&g_chassis.poll_cond, NULL);
    g_chassis.poll_running = true;
    if (pthread_create(&g_chassis.poll_thread, NULL,
                       chassisd_poll_main, &g_chassis) != 0) {
        g_chassis.poll_running = false;
        pthread_cond_destroy(&g_chassis.poll_cond);
        pthread_mutex_destroy(&g_chassis.poll_lock);
        pthread_mutex_destroy(&g_chassis.lock);
        return -1;
    }
    g_chassis.poll_thread_started = true;
    return 0;
}

static void chassisd_on_shutdown(void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&g_chassis.poll_lock);
    g_chassis.poll_running = false;
    pthread_cond_broadcast(&g_chassis.poll_cond);
    pthread_mutex_unlock(&g_chassis.poll_lock);
    if (g_chassis.poll_thread_started)
        pthread_join(g_chassis.poll_thread, NULL);
    pthread_cond_destroy(&g_chassis.poll_cond);
    pthread_mutex_destroy(&g_chassis.poll_lock);
    pthread_mutex_destroy(&g_chassis.lock);
}

int main(int argc, char *argv[]) {
    if (argc != 3 ||
        strcmp(argv[1], "--inherited-listener-fd=3") != 0 ||
        strcmp(argv[2], "--ready-fd=4") != 0)
        return 1;

    nl_daemon_config cfg = {
        .name        = "chassisd",
        .socket_path = CHASSISD_SOCKET,
        .service_id  = NL_DAEMON_CHASSISD,
        .auth_mode   = NL_DAEMON_AUTH_STANDARD,
        .dispatch    = chassisd_dispatch,
        .ctx         = NULL,
        .on_init     = chassisd_on_init,
        .on_shutdown = chassisd_on_shutdown,
        .inherited_listen_fd = 3,
        .ready_fd = 4,
        .identity_broker_socket_path = IDENTITYD_SOCKET,
        .brokered_peer_id = NL_DAEMON_MGMTD,
    };

    return nl_daemon_run(&cfg);
}
