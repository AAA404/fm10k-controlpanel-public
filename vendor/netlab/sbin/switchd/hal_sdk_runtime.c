#include "hal_sdk_runtime.h"
#include "netlab/interface_id.h"
#include <stdarg.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SDK_RUNTIME_MAX_PATH 512
#define SDK_RUNTIME_MAX_VALUE 160
#define SDK_RUNTIME_RDI_PATH "/etc/rdi/fm_platform_attributes.cfg"

typedef struct {
    const char *name;
    bool loaded;
    bool stat_ok;
    char path[SDK_RUNTIME_MAX_PATH];
    struct stat st;
} sdk_runtime_library;

typedef struct {
    bool present;
    char platform_name[SDK_RUNTIME_MAX_VALUE];
    char uio_dev_name[SDK_RUNTIME_MAX_VALUE];
    char shared_library[SDK_RUNTIME_MAX_VALUE];
    char shared_library_disable[SDK_RUNTIME_MAX_VALUE];
    char msi_enabled[SDK_RUNTIME_MAX_VALUE];
    char port_intr_gpio[SDK_RUNTIME_MAX_VALUE];
    char num_ports[SDK_RUNTIME_MAX_VALUE];
    char cpu_port[SDK_RUNTIME_MAX_VALUE];
    char mgmt_pep[SDK_RUNTIME_MAX_VALUE];
} sdk_runtime_rdi;

static int appendf(char *dst, size_t dst_size, int off,
                   const char *fmt, ...) {
    va_list ap;
    int n;

    if (!dst || dst_size == 0 || off < 0 || (size_t)off >= dst_size)
        return off;

    va_start(ap, fmt);
    n = vsnprintf(dst + off, dst_size - (size_t)off, fmt, ap);
    va_end(ap);
    if (n < 0)
        return off;
    if ((size_t)n >= dst_size - (size_t)off)
        return (int)dst_size - 1;
    return off + n;
}

static void xml_escape_attr(const char *src, char *dst, size_t dst_len) {
    size_t off = 0;

    if (!dst_len)
        return;
    if (!src)
        src = "";
    for (const char *p = src; *p && off + 1 < dst_len; p++) {
        const char *rep = NULL;
        size_t len;

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
        len = strlen(rep);
        if (off + len >= dst_len)
            break;
        memcpy(dst + off, rep, len);
        off += len;
    }
    dst[off] = '\0';
}

static char *trim(char *s) {
    char *end;

    if (!s)
        return s;
    while (*s && isspace((unsigned char)*s))
        s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

static void unquote(char *s) {
    size_t len;

    if (!s)
        return;
    len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static void copy_value(char *dst, size_t dst_size, const char *value) {
    if (!dst || dst_size == 0)
        return;
    snprintf(dst, dst_size, "%s", value ? value : "");
}

static bool line_value_after_type(const char *line, char *out,
                                  size_t out_size) {
    char buf[512];
    char *p;
    char *type;
    char *value;

    if (!line || !out || out_size == 0)
        return false;

    snprintf(buf, sizeof(buf), "%s", line);
    p = trim(buf);
    if (*p == '#' || *p == '\0')
        return false;

    type = p;
    while (*type && !isspace((unsigned char)*type))
        type++;
    if (!*type)
        return false;
    type = trim(type);
    while (*type && !isspace((unsigned char)*type))
        type++;
    if (!*type)
        return false;
    value = trim(type);
    unquote(value);
    copy_value(out, out_size, value);
    return true;
}

static void set_rdi_field(sdk_runtime_rdi *rdi, const char *key,
                          const char *line) {
    char value[SDK_RUNTIME_MAX_VALUE];

    if (!rdi || !key || !line || !strstr(line, key))
        return;
    if (!line_value_after_type(line, value, sizeof(value)))
        return;

    if (strcmp(key, "api.platform.config.platformName") == 0)
        copy_value(rdi->platform_name, sizeof(rdi->platform_name), value);
    else if (strcmp(key, "api.platform.config.switch.0.uioDevName") == 0)
        copy_value(rdi->uio_dev_name, sizeof(rdi->uio_dev_name), value);
    else if (strcmp(key, "api.platform.config.switch.0.sharedLibraryName") == 0)
        copy_value(rdi->shared_library, sizeof(rdi->shared_library), value);
    else if (strcmp(key, "api.platform.config.switch.0.sharedLibrary.disable") == 0)
        copy_value(rdi->shared_library_disable, sizeof(rdi->shared_library_disable), value);
    else if (strcmp(key, "api.platform.config.switch.0.msiEnabled") == 0)
        copy_value(rdi->msi_enabled, sizeof(rdi->msi_enabled), value);
    else if (strcmp(key, "api.platform.config.switch.0.portIntrGpio") == 0)
        copy_value(rdi->port_intr_gpio, sizeof(rdi->port_intr_gpio), value);
    else if (strcmp(key, "api.platform.config.switch.0.numPorts") == 0)
        copy_value(rdi->num_ports, sizeof(rdi->num_ports), value);
    else if (strcmp(key, "api.platform.config.switch.0.cpuPort") == 0)
        copy_value(rdi->cpu_port, sizeof(rdi->cpu_port), value);
    else if (strcmp(key, "api.platform.config.switch.0.bootCfg.mgmtPep") == 0)
        copy_value(rdi->mgmt_pep, sizeof(rdi->mgmt_pep), value);
}

static void collect_rdi(sdk_runtime_rdi *rdi) {
    FILE *fp;
    char line[512];

    memset(rdi, 0, sizeof(*rdi));
    fp = fopen(SDK_RUNTIME_RDI_PATH, "r");
    if (!fp)
        return;
    rdi->present = true;
    while (fgets(line, sizeof(line), fp)) {
        set_rdi_field(rdi, "api.platform.config.platformName", line);
        set_rdi_field(rdi, "api.platform.config.switch.0.uioDevName", line);
        set_rdi_field(rdi, "api.platform.config.switch.0.sharedLibraryName", line);
        set_rdi_field(rdi, "api.platform.config.switch.0.sharedLibrary.disable", line);
        set_rdi_field(rdi, "api.platform.config.switch.0.msiEnabled", line);
        set_rdi_field(rdi, "api.platform.config.switch.0.portIntrGpio", line);
        set_rdi_field(rdi, "api.platform.config.switch.0.numPorts", line);
        set_rdi_field(rdi, "api.platform.config.switch.0.cpuPort", line);
        set_rdi_field(rdi, "api.platform.config.switch.0.bootCfg.mgmtPep", line);
    }
    fclose(fp);
}

static void remember_library_path(sdk_runtime_library *lib,
                                  const char *line) {
    const char *path;
    char tmp[SDK_RUNTIME_MAX_PATH];

    if (!lib || lib->loaded || !line || !strstr(line, lib->name))
        return;
    path = strchr(line, '/');
    if (!path)
        return;
    snprintf(tmp, sizeof(tmp), "%s", path);
    copy_value(lib->path, sizeof(lib->path), trim(tmp));
    lib->loaded = true;
    lib->stat_ok = stat(lib->path, &lib->st) == 0;
}

static void collect_libraries(sdk_runtime_library *libs, size_t n_libs) {
    FILE *fp;
    char line[1024];

    fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        for (size_t i = 0; i < n_libs; i++)
            remember_library_path(&libs[i], line);
    }
    fclose(fp);
}

static void format_library(char *resp, size_t resp_size, int *off,
                           const sdk_runtime_library *lib) {
    char name[96];
    char path[SDK_RUNTIME_MAX_PATH * 2];

    xml_escape_attr(lib->name, name, sizeof(name));
    xml_escape_attr(lib->path, path, sizeof(path));
    *off = appendf(resp, resp_size, *off,
                   "  <library name=\"%s\" loaded=\"%s\" path=\"%s\"",
                   name, lib->loaded ? "true" : "false", path);
    if (lib->stat_ok) {
        *off = appendf(resp, resp_size, *off,
                       " size=\"%llu\" mtime=\"%lld\" dev=\"%llu\" ino=\"%llu\"",
                       (unsigned long long)lib->st.st_size,
                       (long long)lib->st.st_mtime,
                       (unsigned long long)lib->st.st_dev,
                       (unsigned long long)lib->st.st_ino);
    }
    *off = appendf(resp, resp_size, *off, "/>\n");
}

static void format_rdi_field(char *resp, size_t resp_size, int *off,
                             const char *name, const char *value) {
    char name_attr[96];
    char value_attr[SDK_RUNTIME_MAX_VALUE * 2];

    xml_escape_attr(name, name_attr, sizeof(name_attr));
    xml_escape_attr(value, value_attr, sizeof(value_attr));
    *off = appendf(resp, resp_size, *off,
                   "    <field name=\"%s\" value=\"%s\"/>\n",
                   name_attr, value_attr);
}

int hal_sdk_runtime_format(struct sdk_context *ctx,
                           char *resp, size_t resp_size) {
    sdk_runtime_library libs[] = {
        {.name = "libFocalpointSDK.so"},
        {.name = "libLTStdPlatform.so"},
    };
    sdk_runtime_rdi rdi;
    sdk_executor_stats executor_stats;
    sdk_port_recovery_stats recovery_stats;
    nl_platform_identity ident;
    char exe[SDK_RUNTIME_MAX_PATH];
    char exe_attr[SDK_RUNTIME_MAX_PATH * 2];
    char profile_attr[SDK_RUNTIME_MAX_PATH * 2];
    char model_attr[96];
    int off = 0;
    ssize_t exe_len;

    if (!resp || resp_size == 0)
        return 0;
    resp[0] = '\0';
    memset(&ident, 0, sizeof(ident));
    memset(exe, 0, sizeof(exe));

    exe_len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (exe_len >= 0)
        exe[exe_len] = '\0';
    else
        snprintf(exe, sizeof(exe), "unknown");

    collect_libraries(libs, sizeof(libs) / sizeof(libs[0]));
    collect_rdi(&rdi);
    sdk_executor_stats_snapshot(ctx ? ctx->exec : NULL, &executor_stats);
    sdk_port_recovery_stats_snapshot(ctx, &recovery_stats);
    (void)nl_platform_identity_get(&ident);

    xml_escape_attr(exe, exe_attr, sizeof(exe_attr));
    xml_escape_attr(nl_platform_loaded_profile(), profile_attr,
                    sizeof(profile_attr));
    xml_escape_attr(ident.model, model_attr, sizeof(model_attr));

    off = appendf(resp, resp_size, off,
                  "<sdk-runtime source=\"switchd\" status=\"0\">\n");
    off = appendf(resp, resp_size, off,
                  "  <process pid=\"%ld\" executable=\"%s\"/>\n",
                  (long)getpid(), exe_attr);
    off = appendf(resp, resp_size, off,
                  "  <profile path=\"%s\" model=\"%s\"/>\n",
                  profile_attr, model_attr);
    for (size_t i = 0; i < sizeof(libs) / sizeof(libs[0]); i++)
        format_library(resp, resp_size, &off, &libs[i]);

    off = appendf(resp, resp_size, off,
                  "  <rdi path=\"%s\" present=\"%s\">\n",
                  SDK_RUNTIME_RDI_PATH, rdi.present ? "true" : "false");
    format_rdi_field(resp, resp_size, &off, "platformName",
                     rdi.platform_name);
    format_rdi_field(resp, resp_size, &off, "uioDevName",
                     rdi.uio_dev_name);
    format_rdi_field(resp, resp_size, &off, "sharedLibraryName",
                     rdi.shared_library);
    format_rdi_field(resp, resp_size, &off, "sharedLibrary.disable",
                     rdi.shared_library_disable[0] ?
                     rdi.shared_library_disable : "NONE");
    format_rdi_field(resp, resp_size, &off, "msiEnabled",
                     rdi.msi_enabled);
    format_rdi_field(resp, resp_size, &off, "portIntrGpio",
                     rdi.port_intr_gpio);
    format_rdi_field(resp, resp_size, &off, "numPorts",
                     rdi.num_ports);
    format_rdi_field(resp, resp_size, &off, "cpuPort",
                     rdi.cpu_port);
    format_rdi_field(resp, resp_size, &off, "mgmtPep",
                     rdi.mgmt_pep);
    off = appendf(resp, resp_size, off, "  </rdi>\n");
    off = appendf(resp, resp_size, off,
                  "  <executor running=\"%s\" priorities=\"%d\" "
                  "snapshot-generation=\"%llu\">\n",
                  executor_stats.running ? "true" : "false",
                  SDK_PRIO_COUNT,
                  (unsigned long long)executor_stats.snapshot_generation);
    for (int priority = 0; priority < SDK_PRIO_COUNT; priority++) {
        const sdk_executor_priority_stats *stats =
            &executor_stats.priority[priority];

        off = appendf(
            resp, resp_size, off,
            "    <queue priority=\"%d\" depth=\"%u\" high-watermark=\"%u\" "
            "enqueued=\"%llu\" completed=\"%llu\" failed=\"%llu\" "
            "cancelled=\"%llu\" queue-full=\"%llu\" timed-out=\"%llu\" "
            "wait-avg-us=\"%llu\" wait-p50-us=\"%llu\" "
            "wait-p95-us=\"%llu\" wait-max-us=\"%llu\" "
            "exec-avg-us=\"%llu\" exec-p50-us=\"%llu\" "
            "exec-p95-us=\"%llu\" exec-max-us=\"%llu\"/>\n",
            priority, stats->queue_depth, stats->queue_high_watermark,
            (unsigned long long)stats->enqueued,
            (unsigned long long)stats->completed,
            (unsigned long long)stats->failed,
            (unsigned long long)stats->cancelled,
            (unsigned long long)stats->queue_full,
            (unsigned long long)stats->timed_out,
            (unsigned long long)stats->wait_avg_us,
            (unsigned long long)stats->wait_p50_us,
            (unsigned long long)stats->wait_p95_us,
            (unsigned long long)stats->wait_max_us,
            (unsigned long long)stats->exec_avg_us,
            (unsigned long long)stats->exec_p50_us,
            (unsigned long long)stats->exec_p95_us,
            (unsigned long long)stats->exec_max_us);
    }
    off = appendf(resp, resp_size, off, "  </executor>\n");
    off = appendf(
        resp, resp_size, off,
        "  <port-recovery enabled=\"%s\" window-seconds=\"%d\" "
        "last-poll-age=\"%ld\" max-attempts=\"%d\" "
        "full-pfe-escalation=\"operator-required\">\n",
        recovery_stats.enabled ? "true" : "false",
        recovery_stats.window_seconds,
        recovery_stats.last_poll_age,
        recovery_stats.max_attempts);
    for (int i = 0; i < recovery_stats.n_ports; i++) {
        const sdk_port_recovery_entry *entry = &recovery_stats.ports[i];
        const char *state = entry->exhausted ? "exhausted" :
            entry->attempts > 0 ? "recovering" : "monitoring";

        off = appendf(
            resp, resp_size, off,
            "    <port id=\"%d\" state=\"%s\" attempts=\"%d\" "
            "unknown-polls=\"%d\" last-attempt-age=\"%ld\" "
            "episode-elapsed-seconds=\"%ld\" window-expired=\"%s\"/>\n",
            entry->port, state, entry->attempts,
            entry->unknown_polls, entry->last_attempt_age,
            entry->episode_elapsed_seconds,
            entry->window_expired ? "true" : "false");
    }
    off = appendf(resp, resp_size, off, "  </port-recovery>\n");
    off = appendf(resp, resp_size, off, "</sdk-runtime>\n");
    return off;
}
