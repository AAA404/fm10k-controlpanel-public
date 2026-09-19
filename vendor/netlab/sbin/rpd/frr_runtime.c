#include "frr_runtime.h"
#include "frr_telemetry_json.h"
#include "netlab/log.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RPD_FRR_VTYSH_OUTPUT_MAX 16384
#define RPD_FRR_VTYSH_STDERR_MAX 512
#define RPD_FRR_VTYSH_TIMEOUT_MS 1000
#define RPD_FRR_EXEC_TIMEOUT_MS 1000
#define RPD_FRR_PROCESS_STABILITY_MS 250
#define RPD_FRR_WAIT_SLICE_MS 50

static int64_t monotonic_ms(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void str_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0)
        return;
    snprintf(dst, dst_size, "%s", src ? src : "");
}

static bool proc_pid_starttime(pid_t pid, u64 *starttime) {
    char path[128];
    char line[4096];
    char *fields;
    char *save = NULL;
    char *token;
    FILE *fp;
    int field = 3;

    if (pid <= 0 || !starttime)
        return false;
    if (snprintf(path, sizeof(path), "/proc/%ld/stat",
                 (long)pid) >= (int)sizeof(path))
        return false;
    fp = fopen(path, "r");
    if (!fp)
        return false;
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    fields = strrchr(line, ')');
    if (!fields || fields[1] != ' ')
        return false;
    fields += 2;
    token = strtok_r(fields, " \n", &save);
    while (token) {
        if (field == 22) {
            char *end = NULL;
            unsigned long long value;

            errno = 0;
            value = strtoull(token, &end, 10);
            if (errno != 0 || !end || *end != '\0' || value == 0)
                return false;
            *starttime = (u64)value;
            return true;
        }
        field++;
        token = strtok_r(NULL, " \n", &save);
    }
    return false;
}

static bool proc_pid_effective_uid(pid_t pid, uid_t *uid) {
    char path[128];
    char line[256];
    FILE *fp;

    if (pid <= 0 || !uid)
        return false;
    if (snprintf(path, sizeof(path), "/proc/%ld/status",
                 (long)pid) >= (int)sizeof(path))
        return false;
    fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long real_uid;
        unsigned long effective_uid;

        if (sscanf(line, "Uid:%lu%lu", &real_uid, &effective_uid) == 2) {
            (void)real_uid;
            fclose(fp);
            if ((unsigned long)(uid_t)effective_uid != effective_uid)
                return false;
            *uid = (uid_t)effective_uid;
            return true;
        }
    }
    fclose(fp);
    return false;
}

static bool proc_pid_executable(pid_t pid, char *out, size_t out_size) {
    char path[128];
    ssize_t len;

    if (pid <= 0 || !out || out_size < 2)
        return false;
    out[0] = '\0';
    if (snprintf(path, sizeof(path), "/proc/%ld/exe",
                 (long)pid) >= (int)sizeof(path))
        return false;
    len = readlink(path, out, out_size - 1);
    if (len <= 0 || (size_t)len >= out_size - 1)
        return false;
    out[len] = '\0';
    return out[0] == '/';
}

static void invalidate_zebra_authority(rpd_frr_runtime *rt) {
    if (!rt)
        return;
    if (rt->zebra_authority_ready)
        rt->zebra_authority_generation++;
    rt->zebra_authority_ready = false;
    rt->zebra_starttime = 0;
    rt->zebra_executable[0] = '\0';
}

static int capture_zebra_authority(rpd_frr_runtime *rt, uid_t run_uid,
                                   char *err, size_t err_size) {
    u64 starttime_before = 0;
    u64 starttime_after = 0;
    uid_t effective_uid = (uid_t)-1;
    char executable[RPD_FRR_RUNTIME_PATH_MAX];
    char *expected = NULL;
    int rc = -1;

    if (!rt || rt->zebra_pid <= 0 || !rt->zebra_path[0] ||
        !(expected = realpath(rt->zebra_path, NULL)) ||
        !proc_pid_starttime(rt->zebra_pid, &starttime_before) ||
        !proc_pid_effective_uid(rt->zebra_pid, &effective_uid) ||
        !proc_pid_executable(rt->zebra_pid, executable,
                             sizeof(executable)) ||
        !proc_pid_starttime(rt->zebra_pid, &starttime_after)) {
        snprintf(err, err_size,
                 "failed to capture stable managed zebra identity");
        invalidate_zebra_authority(rt);
        goto out;
    }
    if (starttime_before != starttime_after ||
        effective_uid != run_uid ||
        strcmp(executable, expected) != 0) {
        snprintf(err, err_size,
                 "managed zebra identity does not match rpd launch authority");
        invalidate_zebra_authority(rt);
        goto out;
    }
    invalidate_zebra_authority(rt);
    rt->run_uid = run_uid;
    rt->runtime_identity_ready = true;
    rt->zebra_starttime = starttime_after;
    str_copy(rt->zebra_executable, sizeof(rt->zebra_executable),
             executable);
    rt->zebra_authority_generation++;
    rt->zebra_authority_ready = true;
    rc = 0;
out:
    free(expected);
    return rc;
}

static bool env_truthy(const char *name) {
    const char *v = getenv(name);

    return v && (strcmp(v, "1") == 0 ||
                 strcmp(v, "true") == 0 ||
                 strcmp(v, "TRUE") == 0 ||
                 strcmp(v, "yes") == 0 ||
                 strcmp(v, "YES") == 0);
}

static bool config_gate_from_env(bool current) {
    if (env_truthy("NETLAB_DISABLE_RPD_FRR_CONFIG"))
        return false;
    if (env_truthy("NETLAB_ENABLE_RPD_FRR_CONFIG"))
        return true;
    return current;
}

static bool start_gate_from_env(bool current) {
    if (env_truthy("NETLAB_DISABLE_RPD_FRR_RUNTIME"))
        return false;
    if (env_truthy("NETLAB_ENABLE_RPD_FRR_RUNTIME"))
        return true;
    return current;
}

static bool path_exists(const char *path) {
    return path && access(path, X_OK) == 0;
}

static bool dir_exists(const char *path) {
    struct stat st;

    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool path_token_safe(const char *path) {
    size_t len;

    if (!path || !path[0])
        return false;
    len = strlen(path);
    if (len >= RPD_FRR_RUNTIME_PATH_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];

        if (!(isalnum(c) || c == '/' || c == '.' || c == '_' ||
              c == '-' || c == ':'))
            return false;
    }
    return true;
}

static bool module_token_safe(const char *module) {
    size_t len;

    if (!module)
        return false;
    len = strlen(module);
    if (len >= RPD_FRR_RUNTIME_PATH_MAX)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)module[i];

        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return false;
    }
    return true;
}

static bool env_list_token_safe(const char *value) {
    size_t len;

    if (!value || !value[0])
        return true;
    len = strlen(value);
    if (len >= 1024)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!(isalnum(c) || c == '/' || c == '.' || c == '_' ||
              c == '-' || c == ':'))
            return false;
    }
    return true;
}

static void stop_pid(pid_t *pid);
static bool runtime_refresh_paths(rpd_frr_runtime *rt);

static void set_status(rpd_frr_runtime *rt, const char *status,
                       const char *reason) {
    if (!rt)
        return;
    str_copy(rt->status, sizeof(rt->status), status ? status : "unknown");
    if (reason)
        str_copy(rt->reason, sizeof(rt->reason), reason);
}

static void default_run_dir(char *out, size_t out_size) {
    const char *env = getenv("NETLAB_RPD_FRR_DIR");

    if (env && env[0] && path_token_safe(env)) {
        str_copy(out, out_size, env);
        return;
    }
    str_copy(out, out_size, "/var/run/netlab-frr");
}

static bool default_config_path(const char *run_dir, char *out,
                                size_t out_size) {
    const char *env = getenv("NETLAB_RPD_FRR_CONFIG_PATH");
    int n;

    if (env && env[0] && path_token_safe(env)) {
        str_copy(out, out_size, env);
        return true;
    }
    n = snprintf(out, out_size, "%s/frr.conf", run_dir);
    return n > 0 && (size_t)n < out_size && path_token_safe(out);
}

static bool join_root_path(const char *root, const char *suffix,
                           char *out, size_t out_size) {
    int n;

    if (!path_token_safe(root) || !suffix || !suffix[0] ||
        suffix[0] == '/')
        return false;
    n = snprintf(out, out_size, "%s/%s", root, suffix);
    return n > 0 && (size_t)n < out_size && path_token_safe(out);
}

static bool join_dir_path(const char *dir, const char *name,
                          char *out, size_t out_size) {
    int n;

    if (!path_token_safe(dir) || !name || !name[0] || strchr(name, '/'))
        return false;
    n = snprintf(out, out_size, "%s/%s", dir, name);
    return n > 0 && (size_t)n < out_size && path_token_safe(out);
}

static void set_env_if_dir(const char *name, const char *path) {
    if (!getenv(name) && path_token_safe(path) && dir_exists(path))
        setenv(name, path, 1);
}

static void set_env_if_exec(const char *name, const char *path) {
    if (!getenv(name) && path_token_safe(path) && path_exists(path))
        setenv(name, path, 1);
}

static void prepend_env_paths(const char *name, const char **paths,
                              int n_paths) {
    const char *existing = getenv(name);
    char buf[1024] = {0};
    size_t off = 0;

    for (int i = 0; i < n_paths; i++) {
        const char *path = paths[i];
        int n;

        if (!path_token_safe(path) || !dir_exists(path))
            continue;
        n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
                     off ? ":" : "", path);
        if (n < 0 || (size_t)n >= sizeof(buf) - off)
            return;
        off += (size_t)n;
    }
    if (existing && existing[0] && env_list_token_safe(existing)) {
        int n = snprintf(buf + off, sizeof(buf) - off, "%s%s",
                         off ? ":" : "", existing);
        if (n < 0 || (size_t)n >= sizeof(buf) - off)
            return;
        off += (size_t)n;
    }
    if (off > 0)
        setenv(name, buf, 1);
}

static const char *default_frr_root(char *out, size_t out_size) {
    const char *netlab_root = getenv("NETLAB_ROOT");
    int n;

    if (netlab_root && netlab_root[0] && path_token_safe(netlab_root)) {
        n = snprintf(out, out_size, "%s/third_party/frr-root",
                     netlab_root);
        if (n > 0 && (size_t)n < out_size && path_token_safe(out) &&
            dir_exists(out))
            return out;
    }
    str_copy(out, out_size, "/tmp/netlab-frr-root");
    if (dir_exists(out))
        return out;
    return NULL;
}

static void bootstrap_frr_root_env(void) {
    const char *root = getenv("NETLAB_RPD_FRR_ROOT");
    char default_root[RPD_FRR_RUNTIME_PATH_MAX];
    char path[RPD_FRR_RUNTIME_PATH_MAX];
    char lib64[RPD_FRR_RUNTIME_PATH_MAX];
    char frr_lib64[RPD_FRR_RUNTIME_PATH_MAX];
    char lib[RPD_FRR_RUNTIME_PATH_MAX];
    char frr_lib[RPD_FRR_RUNTIME_PATH_MAX];
    const char *ld_paths[4];

    if (!root || !root[0])
        root = default_frr_root(default_root, sizeof(default_root));
    if (!root || !root[0] || !path_token_safe(root) || !dir_exists(root))
        return;
    setenv("NETLAB_RPD_FRR_ROOT", root, 1);

    if (!getenv("NETLAB_RPD_FRR_BIN_DIR")) {
        const char *bins[] = {
            "usr/libexec/frr",
            "usr/lib/frr",
            "usr/sbin",
            "usr/bin",
        };

        for (size_t i = 0; i < sizeof(bins) / sizeof(bins[0]); i++) {
            char zebra[RPD_FRR_RUNTIME_PATH_MAX];
            char ospfd[RPD_FRR_RUNTIME_PATH_MAX];
            char bgpd[RPD_FRR_RUNTIME_PATH_MAX];

            if (!join_root_path(root, bins[i], path, sizeof(path)))
                continue;
            if (!join_dir_path(path, "zebra", zebra, sizeof(zebra)) ||
                !join_dir_path(path, "ospfd", ospfd, sizeof(ospfd)) ||
                !join_dir_path(path, "bgpd", bgpd, sizeof(bgpd)))
                continue;
            if (path_exists(zebra) && path_exists(ospfd) &&
                path_exists(bgpd)) {
                setenv("NETLAB_RPD_FRR_BIN_DIR", path, 1);
                break;
            }
        }
    }

    if (join_root_path(root, "usr/bin/vtysh", path, sizeof(path)))
        set_env_if_exec("NETLAB_RPD_FRR_VTYSH", path);
    if (join_root_path(root, "usr/sbin/vtysh", path, sizeof(path)))
        set_env_if_exec("NETLAB_RPD_FRR_VTYSH", path);
    if (join_root_path(root, "usr/lib64/frr/modules", path, sizeof(path)))
        set_env_if_dir("NETLAB_RPD_FRR_MODULE_DIR", path);
    if (join_root_path(root, "usr/lib/frr/modules", path, sizeof(path)))
        set_env_if_dir("NETLAB_RPD_FRR_MODULE_DIR", path);
    if (join_root_path(root, "usr/lib64/libyang1/extensions",
                       path, sizeof(path)))
        set_env_if_dir("LIBYANG_EXTENSIONS_PLUGINS_DIR", path);
    if (join_root_path(root, "usr/lib/libyang1/extensions",
                       path, sizeof(path)))
        set_env_if_dir("LIBYANG_EXTENSIONS_PLUGINS_DIR", path);
    if (join_root_path(root, "usr/lib64/libyang1/user_types",
                       path, sizeof(path)))
        set_env_if_dir("LIBYANG_USER_TYPES_PLUGINS_DIR", path);
    if (join_root_path(root, "usr/lib/libyang1/user_types",
                       path, sizeof(path)))
        set_env_if_dir("LIBYANG_USER_TYPES_PLUGINS_DIR", path);
    if (!getenv("NETLAB_RPD_FRR_USER"))
        setenv("NETLAB_RPD_FRR_USER", "netlab-frr", 1);
    if (!getenv("NETLAB_RPD_FRR_GROUP"))
        setenv("NETLAB_RPD_FRR_GROUP", "netlab-frr", 1);
    if (!getenv("NETLAB_RPD_FRR_VTY_GROUP"))
        setenv("NETLAB_RPD_FRR_VTY_GROUP", "frrvty", 1);

    lib64[0] = frr_lib64[0] = lib[0] = frr_lib[0] = '\0';
    (void)join_root_path(root, "usr/lib64", lib64, sizeof(lib64));
    (void)join_root_path(root, "usr/lib64/frr", frr_lib64,
                         sizeof(frr_lib64));
    (void)join_root_path(root, "usr/lib", lib, sizeof(lib));
    (void)join_root_path(root, "usr/lib/frr", frr_lib, sizeof(frr_lib));
    ld_paths[0] = lib64;
    ld_paths[1] = frr_lib64;
    ld_paths[2] = lib;
    ld_paths[3] = frr_lib;
    prepend_env_paths("LD_LIBRARY_PATH", ld_paths, 4);
}

static bool default_zebra_module(char *out, size_t out_size) {
    const char *env = getenv("NETLAB_RPD_FRR_ZEBRA_MODULE");

    if (!env || !env[0])
        env = "dplane_fpm_nl";
    if (strcmp(env, "none") == 0 || strcmp(env, "disabled") == 0) {
        str_copy(out, out_size, "");
        return true;
    }
    if (!module_token_safe(env))
        return false;
    str_copy(out, out_size, env);
    return true;
}

static bool find_program(const char *name, const char *env_name,
                         char *out, size_t out_size) {
    const char *env;
    const char *bin_dir;
    const char *dirs[] = {
        NULL,
        "/usr/lib/frr",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
        NULL,
    };
    char path[RPD_FRR_RUNTIME_PATH_MAX];

    bootstrap_frr_root_env();
    env = getenv(env_name);
    bin_dir = getenv("NETLAB_RPD_FRR_BIN_DIR");
    if (env && env[0] && path_token_safe(env) && path_exists(env)) {
        str_copy(out, out_size, env);
        return true;
    }
    dirs[0] = bin_dir && bin_dir[0] && path_token_safe(bin_dir) ?
        bin_dir : NULL;
    for (int i = 0; dirs[i] || i == 0; i++) {
        if (!dirs[i])
            continue;
        snprintf(path, sizeof(path), "%s/%s", dirs[i], name);
        if (path_exists(path)) {
            str_copy(out, out_size, path);
            return true;
        }
    }
    if (out && out_size)
        out[0] = '\0';
    return false;
}

bool rpd_frr_runtime_program_present(const char *name) {
    char out[RPD_FRR_RUNTIME_PATH_MAX];
    char env_name[64];

    if (!name || !name[0])
        return false;
    snprintf(env_name, sizeof(env_name), "NETLAB_RPD_FRR_%s",
             strcmp(name, "zebra") == 0 ? "ZEBRA" :
             strcmp(name, "ospfd") == 0 ? "OSPFD" :
             strcmp(name, "bgpd") == 0 ? "BGPD" :
             strcmp(name, "vtysh") == 0 ? "VTYSH" : "PROGRAM");
    return find_program(name, env_name, out, sizeof(out));
}

bool rpd_frr_runtime_present(void) {
    return rpd_frr_runtime_program_present("zebra") &&
           rpd_frr_runtime_program_present("ospfd") &&
           rpd_frr_runtime_program_present("bgpd");
}

static bool user_in_group(const struct passwd *pw, const struct group *gr) {
    char **member;

    if (!pw || !gr)
        return false;
    if (pw->pw_gid == gr->gr_gid)
        return true;
    for (member = gr->gr_mem; member && *member; member++)
        if (strcmp(*member, pw->pw_name) == 0)
            return true;
    return false;
}

static int runtime_identity(uid_t *uid, gid_t *gid,
                            char *err, size_t err_size) {
    const char *run_user = getenv("NETLAB_RPD_FRR_USER");
    const char *run_group = getenv("NETLAB_RPD_FRR_GROUP");
    const char *vty_group = getenv("NETLAB_RPD_FRR_VTY_GROUP");
    struct passwd *pw;
    struct group *gr;
    struct group *vty_gr;
    gid_t run_gid;

    bootstrap_frr_root_env();
    run_user = getenv("NETLAB_RPD_FRR_USER");
    run_group = getenv("NETLAB_RPD_FRR_GROUP");
    vty_group = getenv("NETLAB_RPD_FRR_VTY_GROUP");
    if (!module_token_safe(run_user) || !module_token_safe(run_group) ||
        !module_token_safe(vty_group)) {
        snprintf(err, err_size, "invalid FRR runtime identity environment");
        return -1;
    }
    pw = getpwnam(run_user);
    if (!pw) {
        snprintf(err, err_size, "FRR runtime user %s does not exist", run_user);
        return -1;
    }
    gr = getgrnam(run_group);
    if (!gr) {
        snprintf(err, err_size, "FRR runtime group %s does not exist", run_group);
        return -1;
    }
    run_gid = gr->gr_gid;
    vty_gr = getgrnam(vty_group);
    if (!vty_gr) {
        snprintf(err, err_size, "FRR VTY group %s does not exist", vty_group);
        return -1;
    }
    if (!user_in_group(pw, vty_gr)) {
        snprintf(err, err_size,
                 "FRR runtime user %s is not a member of VTY group %s",
                 run_user, vty_group);
        return -1;
    }
    if (uid)
        *uid = pw->pw_uid;
    if (gid)
        *gid = run_gid;
    return 0;
}

static bool group_list_contains(const gid_t *groups, int count, gid_t gid) {
    for (int i = 0; groups && i < count; i++)
        if (groups[i] == gid)
            return true;
    return false;
}

static bool mode_allows(const struct stat *st, uid_t uid,
                        const gid_t *groups, int group_count, int mask) {
    mode_t bits;

    if (!st)
        return false;
    if (uid == 0)
        return true;
    if (st->st_uid == uid)
        bits = (st->st_mode >> 6) & 07;
    else if (group_list_contains(groups, group_count, st->st_gid))
        bits = (st->st_mode >> 3) & 07;
    else
        bits = st->st_mode & 07;
    return (bits & (mode_t)mask) == (mode_t)mask;
}

static bool identity_can_access_path(const char *user, uid_t uid, gid_t gid,
                                     const char *path, int final_mask) {
    gid_t *groups = NULL;
    int group_count = 0;
    char probe[RPD_FRR_RUNTIME_PATH_MAX];
    bool ok = false;

    if (!user || !path_token_safe(path) || path[0] != '/')
        return false;
    (void)getgrouplist(user, gid, NULL, &group_count);
    if (group_count <= 0)
        group_count = 1;
    groups = calloc((size_t)group_count, sizeof(*groups));
    if (!groups)
        return false;
    if (getgrouplist(user, gid, groups, &group_count) < 0)
        goto out;
    str_copy(probe, sizeof(probe), path);
    for (char *p = probe + 1;; p++) {
        struct stat st;
        char saved;
        int mask;

        if (*p != '/' && *p != '\0')
            continue;
        saved = *p;
        *p = '\0';
        if (stat(probe, &st) != 0) {
            *p = saved;
            goto out;
        }
        mask = saved == '\0' ? final_mask : X_OK;
        if (!mode_allows(&st, uid, groups, group_count, mask)) {
            *p = saved;
            goto out;
        }
        *p = saved;
        if (saved == '\0')
            break;
    }
    ok = true;
out:
    free(groups);
    return ok;
}

static int runtime_paths_accessible(const rpd_frr_runtime *rt,
                                    char *err, size_t err_size) {
    const char *run_user = getenv("NETLAB_RPD_FRR_USER");
    const char *module_dir = getenv("NETLAB_RPD_FRR_MODULE_DIR");
    const char *yang_ext = getenv("LIBYANG_EXTENSIONS_PLUGINS_DIR");
    const char *yang_types = getenv("LIBYANG_USER_TYPES_PLUGINS_DIR");
    uid_t uid;
    gid_t gid;
    const char *programs[4];
    const char *data_dirs[3];

    if (!rt || runtime_identity(&uid, &gid, err, err_size) != 0)
        return -1;
    programs[0] = rt->zebra_path;
    programs[1] = rt->ospfd_path;
    programs[2] = rt->bgpd_path;
    programs[3] = rt->vtysh_path;
    for (size_t i = 0; i < sizeof(programs) / sizeof(programs[0]); i++) {
        if (programs[i][0] &&
            !identity_can_access_path(run_user, uid, gid,
                                      programs[i], X_OK)) {
            snprintf(err, err_size,
                     "FRR runtime user %s cannot execute %s",
                     run_user, programs[i]);
            return -1;
        }
    }
    data_dirs[0] = module_dir;
    data_dirs[1] = yang_ext;
    data_dirs[2] = yang_types;
    for (size_t i = 0; i < sizeof(data_dirs) / sizeof(data_dirs[0]); i++) {
        if (data_dirs[i] && data_dirs[i][0] &&
            !identity_can_access_path(run_user, uid, gid,
                                      data_dirs[i], R_OK | X_OK)) {
            snprintf(err, err_size,
                     "FRR runtime user %s cannot read %s",
                     run_user, data_dirs[i]);
            return -1;
        }
    }
    return 0;
}

int rpd_frr_runtime_preflight(rpd_frr_runtime *rt,
                              char *err, size_t err_size) {
    char local_err[192] = {0};
    uid_t run_uid;
    gid_t run_gid;
    int rc = -1;

    if (!err || err_size == 0) {
        err = local_err;
        err_size = sizeof(local_err);
    }
    if (!rt) {
        snprintf(err, err_size, "invalid FRR runtime preflight request");
        return -1;
    }
    err[0] = '\0';
    rt->preflight_ready = false;
    rt->runtime_identity_ready = false;
    rt->last_preflight = time(NULL);
    rt->config_gate_enabled = config_gate_from_env(rt->config_gate_enabled);
    rt->start_gate_enabled = start_gate_from_env(rt->start_gate_enabled);
    if (!runtime_refresh_paths(rt)) {
        snprintf(err, err_size, "%s", rt->reason);
        goto out;
    }
    if (!rt->config_gate_enabled || !rt->start_gate_enabled) {
        snprintf(err, err_size, "FRR config or runtime start gate is closed");
        goto out;
    }
    if (!rt->runtime_present) {
        snprintf(err, err_size, "FRR runtime binaries are incomplete");
        goto out;
    }
    if (runtime_identity(&run_uid, &run_gid, err, err_size) != 0)
        goto out;
    rt->run_uid = run_uid;
    rt->run_gid = run_gid;
    rt->runtime_identity_ready = true;
    if (runtime_paths_accessible(rt, err, err_size) != 0)
        goto out;
    rt->preflight_ready = true;
    rc = 0;
out:
    str_copy(rt->preflight_reason, sizeof(rt->preflight_reason),
             rc == 0 ? "FRR runtime preflight passed" :
             (err[0] ? err : "FRR runtime preflight failed"));
    return rc;
}

static bool runtime_refresh_paths(rpd_frr_runtime *rt) {
    bool zebra;
    bool ospfd;
    bool bgpd;
    bool vtysh;

    if (!rt)
        return false;
    default_run_dir(rt->run_dir, sizeof(rt->run_dir));
    if (!default_config_path(rt->run_dir, rt->config_path,
                             sizeof(rt->config_path))) {
        rt->config_path[0] = '\0';
        set_status(rt, "error", "FRR runtime config path exceeds limit");
        return false;
    }
    if (!path_token_safe(rt->run_dir) ||
        !path_token_safe(rt->config_path)) {
        set_status(rt, "error", "invalid FRR runtime path environment");
        return false;
    }
    if (!default_zebra_module(rt->zebra_module,
                              sizeof(rt->zebra_module))) {
        set_status(rt, "error", "invalid FRR zebra module environment");
        return false;
    }
    zebra = find_program("zebra", "NETLAB_RPD_FRR_ZEBRA",
                         rt->zebra_path, sizeof(rt->zebra_path));
    ospfd = find_program("ospfd", "NETLAB_RPD_FRR_OSPFD",
                         rt->ospfd_path, sizeof(rt->ospfd_path));
    bgpd = find_program("bgpd", "NETLAB_RPD_FRR_BGPD",
                        rt->bgpd_path, sizeof(rt->bgpd_path));
    vtysh = find_program("vtysh", "NETLAB_RPD_FRR_VTYSH",
                         rt->vtysh_path, sizeof(rt->vtysh_path));
    rt->runtime_present = zebra && ospfd && bgpd;
    rt->vtysh_present = vtysh;
    return true;
}

void rpd_frr_runtime_init(rpd_frr_runtime *rt, bool config_gate_enabled,
                          bool start_gate_enabled) {
    char preflight_err[192] = {0};

    if (!rt)
        return;
    memset(rt, 0, sizeof(*rt));
    rt->config_gate_enabled = config_gate_enabled;
    rt->start_gate_enabled = start_gate_enabled;
    rt->zebra_pid = -1;
    rt->ospfd_pid = -1;
    rt->bgpd_pid = -1;
    str_copy(rt->vtysh_status, sizeof(rt->vtysh_status), "unavailable");
    str_copy(rt->vtysh_reason, sizeof(rt->vtysh_reason),
             "vtysh has not been queried");
    set_status(rt, "idle", "no dynamic protocol intent");
    (void)rpd_frr_runtime_preflight(rt, preflight_err,
                                    sizeof(preflight_err));
    if (!config_gate_enabled)
        set_status(rt, "gated", "FRR config writer gate is closed");
}

static int mkdir_p(const char *path) {
    char tmp[RPD_FRR_RUNTIME_PATH_MAX];
    size_t len;

    if (!path_token_safe(path))
        return -1;
    str_copy(tmp, sizeof(tmp), path);
    len = strlen(tmp);
    if (len == 0)
        return -1;
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int prepare_runtime_dir(rpd_frr_runtime *rt,
                               uid_t *uid, gid_t *gid,
                               char *err, size_t err_size) {
    struct stat st;

    if (runtime_identity(uid, gid, err, err_size) != 0)
        return -1;
    rt->run_uid = *uid;
    rt->run_gid = *gid;
    rt->runtime_identity_ready = true;
    if (mkdir_p(rt->run_dir) != 0) {
        snprintf(err, err_size, "failed to create FRR runtime directory");
        return -1;
    }
    if (geteuid() == 0) {
        if (chown(rt->run_dir, *uid, *gid) != 0 ||
            chmod(rt->run_dir, 0750) != 0) {
            snprintf(err, err_size,
                     "failed to assign FRR runtime directory ownership");
            return -1;
        }
    } else if (stat(rt->run_dir, &st) != 0 ||
               st.st_uid != geteuid() || access(rt->run_dir, W_OK | X_OK) != 0) {
        snprintf(err, err_size,
                 "FRR runtime directory is not writable by the current user");
        return -1;
    }
    return 0;
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int write_config_atomic(rpd_frr_runtime *rt,
                               const rpd_frr_config *cfg,
                               char *err, size_t err_size) {
    char tmp_path[RPD_FRR_RUNTIME_PATH_MAX + 8];
    int fd;
    size_t len;
    uid_t run_uid;
    gid_t run_gid;

    if (!rt || !cfg) {
        snprintf(err, err_size, "invalid FRR runtime config write");
        return -1;
    }
    if (prepare_runtime_dir(rt, &run_uid, &run_gid, err, err_size) != 0)
        return -1;
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", rt->config_path);
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) {
        snprintf(err, err_size, "failed to open FRR config temp file");
        return -1;
    }
    if (fchmod(fd, 0640) != 0 ||
        (geteuid() == 0 && fchown(fd, run_uid, run_gid) != 0)) {
        snprintf(err, err_size, "failed to secure FRR config temp file");
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    len = strlen(cfg->config);
    if (write_all(fd, cfg->config, len) != 0 ||
        fsync(fd) != 0) {
        snprintf(err, err_size, "failed to write FRR config file");
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    if (close(fd) != 0) {
        snprintf(err, err_size, "failed to close FRR config file");
        unlink(tmp_path);
        return -1;
    }
    if (rename(tmp_path, rt->config_path) != 0) {
        snprintf(err, err_size, "failed to install FRR config file");
        unlink(tmp_path);
        return -1;
    }
    rt->config_written = true;
    rt->last_write = time(NULL);
    return 0;
}

static void reap_pid(pid_t *pid) {
    int status;

    if (!pid || *pid <= 0)
        return;
    if (waitpid(*pid, &status, WNOHANG) == *pid)
        *pid = -1;
}

static void refresh_process_state(rpd_frr_runtime *rt) {
    pid_t zebra_pid;

    if (!rt)
        return;
    zebra_pid = rt->zebra_pid;
    reap_pid(&rt->zebra_pid);
    if (zebra_pid > 0 && rt->zebra_pid <= 0)
        invalidate_zebra_authority(rt);
    reap_pid(&rt->ospfd_pid);
    reap_pid(&rt->bgpd_pid);
    rt->running_processes = 0;
    if (rt->zebra_pid > 0)
        rt->running_processes++;
    if (rt->ospfd_pid > 0)
        rt->running_processes++;
    if (rt->bgpd_pid > 0)
        rt->running_processes++;
    rt->processes_started = rt->running_processes > 0;
}

static bool wait_for_process_set_stable(rpd_frr_runtime *rt) {
    int64_t started = monotonic_ms();
    int64_t deadline = started >= 0 ?
                       started + RPD_FRR_PROCESS_STABILITY_MS : -1;

    for (;;) {
        int delay_ms = RPD_FRR_WAIT_SLICE_MS;
        int64_t now;

        refresh_process_state(rt);
        if (rt->running_processes != 3)
            return false;
        now = monotonic_ms();
        if (deadline < 0) {
            usleep(RPD_FRR_PROCESS_STABILITY_MS * 1000);
            refresh_process_state(rt);
            return rt->running_processes == 3;
        }
        if (now >= deadline) {
            refresh_process_state(rt);
            return rt->running_processes == 3;
        }
        if (deadline - now < delay_ms)
            delay_ms = (int)(deadline - now);
        (void)poll(NULL, 0, delay_ms);
    }
}

static int wait_for_process_exec(int fd) {
    int64_t started = monotonic_ms();
    int64_t deadline = started >= 0 ? started + RPD_FRR_EXEC_TIMEOUT_MS : -1;
    int fallback_polls = 0;

    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
        int timeout_ms = RPD_FRR_WAIT_SLICE_MS;
        int child_errno = 0;
        int64_t now = monotonic_ms();
        ssize_t n;
        int rc;

        if (deadline >= 0) {
            if (now < 0 || now >= deadline)
                break;
            if (deadline - now < timeout_ms)
                timeout_ms = (int)(deadline - now);
        } else if (fallback_polls++ >=
                   RPD_FRR_EXEC_TIMEOUT_MS / RPD_FRR_WAIT_SLICE_MS) {
            break;
        }
        rc = poll(&pfd, 1, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (rc == 0)
            continue;
        n = read(fd, &child_errno, sizeof(child_errno));
        if (n == 0)
            return 0;
        if (n == (ssize_t)sizeof(child_errno)) {
            errno = child_errno;
            return -1;
        }
        if (n < 0 && errno == EINTR)
            continue;
        errno = EIO;
        return -1;
    }
    errno = ETIMEDOUT;
    return -1;
}

static pid_t start_frr_process(const char *path, const char *name,
                               const char *run_dir,
                               const char *config_path,
                               const char *module) {
    char pid_path[RPD_FRR_RUNTIME_PATH_MAX];
    char zserv_path[RPD_FRR_RUNTIME_PATH_MAX];
    const char *module_dir = getenv("NETLAB_RPD_FRR_MODULE_DIR");
    const char *run_user = getenv("NETLAB_RPD_FRR_USER");
    const char *run_group = getenv("NETLAB_RPD_FRR_GROUP");
    char *argv[32];
    int exec_pipe[2];
    int argc = 0;
    pid_t pid;

    snprintf(pid_path, sizeof(pid_path), "%s/%s.pid", run_dir, name);
    snprintf(zserv_path, sizeof(zserv_path), "%s/zserv.api", run_dir);
    if (pipe2(exec_pipe, O_CLOEXEC) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(exec_pipe[0]);
        close(exec_pipe[1]);
        return -1;
    }
    if (pid != 0) {
        int saved_errno;

        close(exec_pipe[1]);
        if (wait_for_process_exec(exec_pipe[0]) == 0) {
            close(exec_pipe[0]);
            return pid;
        }
        saved_errno = errno;
        close(exec_pipe[0]);
        kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        errno = saved_errno;
        return -1;
    }
    close(exec_pipe[0]);
    argv[argc++] = (char *)path;
    if (module && module[0] && module_dir && path_token_safe(module_dir) &&
        dir_exists(module_dir)) {
        argv[argc++] = "--moduledir";
        argv[argc++] = (char *)module_dir;
    }
    if (module && module[0]) {
        argv[argc++] = "-M";
        argv[argc++] = (char *)module;
    }
    if (run_user && module_token_safe(run_user)) {
        argv[argc++] = "-u";
        argv[argc++] = (char *)run_user;
    }
    if (run_group && module_token_safe(run_group)) {
        argv[argc++] = "-g";
        argv[argc++] = (char *)run_group;
    }
    argv[argc++] = "--vty_socket";
    argv[argc++] = (char *)run_dir;
    argv[argc++] = "-f";
    argv[argc++] = (char *)config_path;
    argv[argc++] = "-i";
    argv[argc++] = pid_path;
    argv[argc++] = "-z";
    argv[argc++] = zserv_path;
    argv[argc++] = "-A";
    argv[argc++] = "127.0.0.1";
    argv[argc] = NULL;
    execv(path, argv);
    {
        int child_errno = errno;
        ssize_t unused;

        do {
            unused = write(exec_pipe[1], &child_errno,
                           sizeof(child_errno));
        } while (unused < 0 && errno == EINTR);
    }
    _exit(127);
}

static int connect_runtime_socket(const char *path) {
    struct sockaddr_un addr;
    int fd;

    if (!path || strlen(path) >= sizeof(addr.sun_path))
        return -1;
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int wait_for_protocol_sockets(rpd_frr_runtime *rt,
                                     char *err, size_t err_size) {
    char ospfd_path[RPD_FRR_RUNTIME_PATH_MAX];
    char bgpd_path[RPD_FRR_RUNTIME_PATH_MAX];
    bool ospfd_ready = false;
    bool bgpd_ready = false;

    if (!rt ||
        snprintf(ospfd_path, sizeof(ospfd_path), "%s/ospfd.vty",
                 rt->run_dir) >= (int)sizeof(ospfd_path) ||
        snprintf(bgpd_path, sizeof(bgpd_path), "%s/bgpd.vty",
                 rt->run_dir) >= (int)sizeof(bgpd_path)) {
        snprintf(err, err_size, "invalid FRR protocol socket path");
        return -1;
    }
    for (int i = 0; i < 100; i++) {
        refresh_process_state(rt);
        if (rt->zebra_pid <= 0 || rt->ospfd_pid <= 0 || rt->bgpd_pid <= 0) {
            snprintf(err, err_size,
                     "FRR process exited before protocol sockets became ready");
            return -1;
        }
        if (!ospfd_ready)
            ospfd_ready = connect_runtime_socket(ospfd_path) == 0;
        if (!bgpd_ready)
            bgpd_ready = connect_runtime_socket(bgpd_path) == 0;
        if (ospfd_ready && bgpd_ready)
            return 0;
        (void)poll(NULL, 0, RPD_FRR_WAIT_SLICE_MS);
    }
    snprintf(err, err_size, "FRR protocol sockets did not become ready");
    return -1;
}

static int clean_stale_runtime_endpoints(rpd_frr_runtime *rt,
                                         char *err, size_t err_size) {
    static const char *const names[] = {
        "zserv.api", "zebra.vty", "ospfd.vty", "bgpd.vty",
    };
    char path[RPD_FRR_RUNTIME_PATH_MAX];

    if (!rt)
        return -1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (snprintf(path, sizeof(path), "%s/%s", rt->run_dir,
                     names[i]) >= (int)sizeof(path)) {
            snprintf(err, err_size, "FRR runtime endpoint path is too long");
            return -1;
        }
        if (access(path, F_OK) != 0)
            continue;
        if (connect_runtime_socket(path) == 0) {
            snprintf(err, err_size,
                     "FRR runtime endpoint is still active: %s", names[i]);
            return -1;
        }
        if (unlink(path) != 0 && errno != ENOENT) {
            snprintf(err, err_size,
                     "failed to remove stale FRR endpoint: %s", names[i]);
            return -1;
        }
    }
    return 0;
}

static int wait_for_zebra_socket(rpd_frr_runtime *rt,
                                 char *err, size_t err_size) {
    char path[RPD_FRR_RUNTIME_PATH_MAX];

    if (!rt || snprintf(path, sizeof(path), "%s/zserv.api", rt->run_dir) >=
                   (int)sizeof(path)) {
        snprintf(err, err_size, "invalid zebra socket path");
        return -1;
    }
    for (int i = 0; i < 100; i++) {
        int status;

        if (rt->zebra_pid <= 0 ||
            waitpid(rt->zebra_pid, &status, WNOHANG) == rt->zebra_pid) {
            invalidate_zebra_authority(rt);
            rt->zebra_pid = -1;
            snprintf(err, err_size,
                     "zebra exited before its runtime socket became ready");
            return -1;
        }
        if (connect_runtime_socket(path) == 0)
            return 0;
        usleep(50000);
    }
    snprintf(err, err_size, "zebra runtime socket did not become ready");
    return -1;
}

static int start_processes(rpd_frr_runtime *rt, char *err,
                           size_t err_size) {
    uid_t run_uid;
    gid_t run_gid;

    if (!rt || !rt->runtime_present) {
        snprintf(err, err_size, "FRR runtime binaries are incomplete");
        return -1;
    }
    if (runtime_paths_accessible(rt, err, err_size) != 0) {
        set_status(rt, "failed", err);
        rt->retry_after = time(NULL) + 30;
        return -1;
    }
    if (prepare_runtime_dir(rt, &run_uid, &run_gid, err, err_size) != 0) {
        set_status(rt, "failed", err);
        rt->retry_after = time(NULL) + 30;
        return -1;
    }
    refresh_process_state(rt);
    if (rt->running_processes == 3) {
        set_status(rt, "running", "FRR processes already started by rpd");
        return 0;
    }
    if (rt->running_processes > 0) {
        set_status(rt, "degraded",
                   "one or more FRR processes exited before restart");
        return -1;
    }
    if (clean_stale_runtime_endpoints(rt, err, err_size) != 0) {
        set_status(rt, "degraded", err);
        rt->retry_after = time(NULL) + 30;
        return -1;
    }
    rt->start_attempts++;
    invalidate_zebra_authority(rt);
    rt->zebra_pid = start_frr_process(rt->zebra_path, "zebra",
                                      rt->run_dir, rt->config_path,
                                      rt->zebra_module);
    if (rt->zebra_pid < 0 ||
        wait_for_zebra_socket(rt, err, err_size) != 0) {
        int saved_errno = errno;

        invalidate_zebra_authority(rt);
        stop_pid(&rt->zebra_pid);
        refresh_process_state(rt);
        rt->last_errno = saved_errno;
        set_status(rt, "degraded", err[0] ? err :
                   "zebra runtime socket failed during start");
        rt->retry_after = time(NULL) + 30;
        return -1;
    }
    if (capture_zebra_authority(rt, run_uid, err, err_size) != 0) {
        invalidate_zebra_authority(rt);
        stop_pid(&rt->zebra_pid);
        refresh_process_state(rt);
        set_status(rt, "degraded", err);
        rt->retry_after = time(NULL) + 30;
        return -1;
    }
    rt->ospfd_pid = start_frr_process(rt->ospfd_path, "ospfd",
                                      rt->run_dir, rt->config_path, NULL);
    rt->bgpd_pid = start_frr_process(rt->bgpd_path, "bgpd",
                                     rt->run_dir, rt->config_path, NULL);
    if (rt->zebra_pid < 0 || rt->ospfd_pid < 0 || rt->bgpd_pid < 0) {
        int saved_errno = errno;

        invalidate_zebra_authority(rt);
        stop_pid(&rt->bgpd_pid);
        stop_pid(&rt->ospfd_pid);
        stop_pid(&rt->zebra_pid);
        refresh_process_state(rt);
        rt->last_errno = saved_errno;
        snprintf(err, err_size, "failed to start one or more FRR processes");
        set_status(rt, "failed", "failed to start FRR process set");
        rt->retry_after = time(NULL) + 30;
        return -1;
    }
    if (wait_for_protocol_sockets(rt, err, err_size) != 0) {
        invalidate_zebra_authority(rt);
        stop_pid(&rt->bgpd_pid);
        stop_pid(&rt->ospfd_pid);
        stop_pid(&rt->zebra_pid);
        refresh_process_state(rt);
        set_status(rt, "degraded", err);
        rt->retry_after = time(NULL) + 30;
        return -1;
    }
    rt->last_start = time(NULL);
    if (!wait_for_process_set_stable(rt)) {
        invalidate_zebra_authority(rt);
        stop_pid(&rt->bgpd_pid);
        stop_pid(&rt->ospfd_pid);
        stop_pid(&rt->zebra_pid);
        refresh_process_state(rt);
        snprintf(err, err_size, "one or more FRR processes exited during start");
        set_status(rt, "degraded", "FRR process set failed during start");
        rt->retry_after = time(NULL) + 30;
        return -1;
    }
    rt->retry_after = 0;
    set_status(rt, "running", "FRR processes started by rpd");
    NL_LOG_NOTICE("rpd started FRR runtime zebra=%d ospfd=%d bgpd=%d",
                  (int)rt->zebra_pid, (int)rt->ospfd_pid,
                  (int)rt->bgpd_pid);
    return 0;
}

int rpd_frr_runtime_configure(rpd_frr_runtime *rt,
                              const rpd_frr_config *cfg,
                              char *err, size_t err_size) {
    bool config_changed;
    bool had_running_processes;
    bool has_dynamic;
    char local_err[192] = {0};

    if (!err || err_size == 0) {
        err = local_err;
        err_size = sizeof(local_err);
    }

    if (!rt || !cfg) {
        snprintf(err, err_size, "invalid FRR runtime configure request");
        return -1;
    }
    err[0] = '\0';
    config_changed = rt->config_written &&
                     rt->config_hash != cfg->config_hash;
    refresh_process_state(rt);
    had_running_processes = rt->running_processes > 0;
    rt->last_update = time(NULL);
    rt->retry_after = 0;
    rt->generation = cfg->generation;
    rt->config_hash = cfg->config_hash;
    rt->config_gate_enabled = config_gate_from_env(rt->config_gate_enabled);
    rt->start_gate_enabled = start_gate_from_env(rt->start_gate_enabled);
    if (!runtime_refresh_paths(rt)) {
        snprintf(err, err_size, "%s", rt->reason);
        return -1;
    }
    has_dynamic = cfg->ospf_enabled || cfg->bgp_enabled || cfg->policies;
    if (!has_dynamic) {
        rpd_frr_runtime_stop(rt);
        rt->config_written = false;
        set_status(rt, "idle", "no dynamic protocol intent");
        return 0;
    }
    if (!rt->config_gate_enabled) {
        set_status(rt, "gated",
                   env_truthy("NETLAB_DISABLE_RPD_FRR_CONFIG") ?
                   "NETLAB_DISABLE_RPD_FRR_CONFIG is set" :
                   "FRR config writer gate is closed");
        snprintf(err, err_size, "%s", rt->reason);
        return -1;
    }
    if (write_config_atomic(rt, cfg, err, err_size) != 0) {
        rt->last_errno = errno;
        set_status(rt, "error", err[0] ? err : "FRR config write failed");
        return -1;
    }
    if (!rt->runtime_present) {
        set_status(rt, "config-ready",
                   "FRR config written; runtime binaries are incomplete");
        return 0;
    }
    if (!rt->start_gate_enabled) {
        set_status(rt, "config-ready",
                   env_truthy("NETLAB_DISABLE_RPD_FRR_RUNTIME") ?
                   "FRR config written; NETLAB_DISABLE_RPD_FRR_RUNTIME is set" :
                   "FRR config written; FRR runtime start gate is closed");
        return 0;
    }
    if (config_changed && had_running_processes) {
        rt->restart_events++;
        rpd_frr_runtime_stop(rt);
        rt->config_written = true;
        set_status(rt, "restarting",
                   "FRR configuration changed; restarting process set");
    }
    if (start_processes(rt, err, err_size) != 0)
        return -1;
    if (config_changed && had_running_processes)
        set_status(rt, "running",
                   "FRR processes restarted for configuration change");
    return 0;
}

int rpd_frr_runtime_maintain(rpd_frr_runtime *rt,
                             char *err, size_t err_size) {
    char local_err[192] = {0};

    if (!err || err_size == 0) {
        err = local_err;
        err_size = sizeof(local_err);
    }
    if (!rt) {
        snprintf(err, err_size, "invalid FRR runtime maintain request");
        return -1;
    }
    err[0] = '\0';
    if (!rt->config_written || !rt->start_gate_enabled)
        return 0;
    if (rt->retry_after > time(NULL))
        return 0;
    if (!runtime_refresh_paths(rt)) {
        snprintf(err, err_size, "%s", rt->reason);
        return -1;
    }
    if (!rt->runtime_present) {
        set_status(rt, "config-ready",
                   "FRR config written; runtime binaries are incomplete");
        return 0;
    }
    refresh_process_state(rt);
    if (rt->running_processes == 3) {
        set_status(rt, "running", "FRR processes are running");
        return 0;
    }
    if (rt->running_processes > 0) {
        rt->restart_events++;
        set_status(rt, "restarting",
                   "FRR process set degraded; restarting all FRR processes");
        rpd_frr_runtime_stop(rt);
        rt->config_written = true;
    }
    if (start_processes(rt, err, err_size) != 0) {
        if (!err[0])
            snprintf(err, err_size, "%s", rt->reason);
        return -1;
    }
    if (rt->restart_events > 0)
        set_status(rt, "running", "FRR processes restarted by rpd");
    return 0;
}

bool rpd_frr_runtime_zebra_authority(
    const rpd_frr_runtime *rt, rpd_frr_zebra_authority *authority,
    char *err, size_t err_size) {
    if (!rt || !authority) {
        if (err && err_size)
            snprintf(err, err_size,
                     "invalid managed zebra authority request");
        return false;
    }
    memset(authority, 0, sizeof(*authority));
    if (!rt->runtime_identity_ready || !rt->zebra_authority_ready ||
        rt->zebra_pid <= 0 || rt->zebra_starttime == 0 ||
        !rt->zebra_executable[0]) {
        if (err && err_size)
            snprintf(err, err_size,
                     "rpd has no active managed zebra authority");
        return false;
    }
    authority->pid = rt->zebra_pid;
    authority->uid = rt->run_uid;
    authority->starttime = rt->zebra_starttime;
    authority->generation = rt->zebra_authority_generation;
    str_copy(authority->executable, sizeof(authority->executable),
             rt->zebra_executable);
    return true;
}

static void stop_pid(pid_t *pid) {
    if (!pid || *pid <= 0)
        return;
    kill(*pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        if (waitpid(*pid, NULL, WNOHANG) == *pid) {
            *pid = -1;
            return;
        }
        usleep(50000);
    }
    kill(*pid, SIGKILL);
    (void)waitpid(*pid, NULL, 0);
    *pid = -1;
}

void rpd_frr_runtime_stop(rpd_frr_runtime *rt) {
    if (!rt)
        return;
    invalidate_zebra_authority(rt);
    stop_pid(&rt->bgpd_pid);
    stop_pid(&rt->ospfd_pid);
    stop_pid(&rt->zebra_pid);
    refresh_process_state(rt);
    if (rt->status[0] && strcmp(rt->status, "gated") != 0)
        set_status(rt, "stopped", "rpd shutdown stopped FRR runtime");
}

static int capture_fd(int fd, char *out, size_t out_size, size_t *off,
                      bool *eof, bool *truncated) {
    char chunk[512];

    for (;;) {
        ssize_t n = read(fd, chunk, sizeof(chunk));

        if (n > 0) {
            size_t available = *off < out_size ? out_size - *off - 1 : 0;
            size_t copy = (size_t)n < available ? (size_t)n : available;

            if (copy > 0) {
                memcpy(out + *off, chunk, copy);
                *off += copy;
                out[*off] = '\0';
            }
            if (copy != (size_t)n)
                *truncated = true;
            continue;
        }
        if (n == 0) {
            *eof = true;
            return 0;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }
}

static void sanitize_vtysh_stderr(const char *input, char *out,
                                  size_t out_size) {
    size_t off = 0;
    bool spacing = false;

    if (!out || out_size == 0)
        return;
    for (const unsigned char *p = (const unsigned char *)input;
         p && *p && off + 1 < out_size; p++) {
        unsigned char c = *p;

        if (isspace(c)) {
            spacing = off > 0;
            continue;
        }
        if (c < 0x20 || c > 0x7e || c == '&' || c == '<' ||
            c == '>' || c == '\'' || c == '"')
            continue;
        if (spacing && off + 1 < out_size)
            out[off++] = ' ';
        spacing = false;
        if (off + 1 < out_size)
            out[off++] = (char)c;
    }
    out[off] = '\0';
}

static int run_vtysh_capture(const rpd_frr_runtime *rt, const char *cmd,
                             char *out, size_t out_size,
                             char *err, size_t err_size) {
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    char stderr_output[RPD_FRR_VTYSH_STDERR_MAX] = {0};
    char safe_stderr[160] = {0};
    size_t stdout_off = 0;
    size_t stderr_off = 0;
    bool stdout_eof = false;
    bool stderr_eof = false;
    bool stdout_truncated = false;
    bool stderr_truncated = false;
    bool child_done = false;
    int fallback_polls = 0;
    int status = 0;
    int64_t started;
    int64_t deadline;
    pid_t pid;

    if (!rt || !cmd || !out || out_size == 0 || !err || err_size == 0) {
        if (err && err_size > 0)
            snprintf(err, err_size, "invalid vtysh capture request");
        return -1;
    }
    out[0] = '\0';
    err[0] = '\0';
    if (!rt->vtysh_present || !path_token_safe(rt->vtysh_path)) {
        snprintf(err, err_size, "vtysh binary is unavailable");
        return -1;
    }
    if (pipe(stdout_pipe) != 0 || pipe(stderr_pipe) != 0) {
        if (stdout_pipe[0] >= 0) {
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);
        }
        if (stderr_pipe[0] >= 0) {
            close(stderr_pipe[0]);
            close(stderr_pipe[1]);
        }
        snprintf(err, err_size, "failed to create vtysh capture pipes");
        return -1;
    }
    pid = fork();
    if (pid == 0) {
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0 ||
            dup2(stderr_pipe[1], STDERR_FILENO) < 0)
            _exit(127);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
        execl(rt->vtysh_path, rt->vtysh_path, "--vty_socket",
              rt->run_dir, "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);
    if (pid < 0) {
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        snprintf(err, err_size, "failed to fork vtysh");
        return -1;
    }
    (void)fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK);
    (void)fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK);
    started = monotonic_ms();
    deadline = started >= 0 ? started + RPD_FRR_VTYSH_TIMEOUT_MS : -1;
    while (!(child_done && stdout_eof && stderr_eof)) {
        struct pollfd pfds[2] = {
            {.fd = stdout_eof ? -1 : stdout_pipe[0],
             .events = POLLIN | POLLHUP},
            {.fd = stderr_eof ? -1 : stderr_pipe[0],
             .events = POLLIN | POLLHUP},
        };
        int poll_timeout = RPD_FRR_WAIT_SLICE_MS;
        int64_t now = monotonic_ms();
        pid_t waited;

        if (deadline >= 0) {
            if (now < 0 || now >= deadline)
                break;
            if (deadline - now < poll_timeout)
                poll_timeout = (int)(deadline - now);
        } else if (fallback_polls++ >=
                   RPD_FRR_VTYSH_TIMEOUT_MS / RPD_FRR_WAIT_SLICE_MS) {
            break;
        }
        (void)poll(pfds, 2, poll_timeout);
        if ((!stdout_eof &&
             capture_fd(stdout_pipe[0], out, out_size, &stdout_off,
                        &stdout_eof, &stdout_truncated) != 0) ||
            (!stderr_eof &&
             capture_fd(stderr_pipe[0], stderr_output,
                        sizeof(stderr_output), &stderr_off,
                        &stderr_eof, &stderr_truncated) != 0)) {
            kill(pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
            close(stdout_pipe[0]);
            close(stderr_pipe[0]);
            snprintf(err, err_size, "failed to read vtysh output");
            return -1;
        }
        if (!child_done) {
            waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid)
                child_done = true;
            else if (waited < 0 && errno != EINTR) {
                close(stdout_pipe[0]);
                close(stderr_pipe[0]);
                snprintf(err, err_size, "failed to wait for vtysh");
                return -1;
            }
        }
    }
    if (!child_done || !stdout_eof || !stderr_eof) {
        if (!child_done) {
            kill(pid, SIGKILL);
            (void)waitpid(pid, &status, 0);
        }
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        snprintf(err, err_size, "vtysh query timed out");
        return -1;
    }
    close(stdout_pipe[0]);
    close(stderr_pipe[0]);
    if (stdout_truncated) {
        snprintf(err, err_size, "vtysh JSON output exceeds capture limit");
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        sanitize_vtysh_stderr(stderr_output, safe_stderr,
                              sizeof(safe_stderr));
        if (safe_stderr[0] && !stderr_truncated)
            snprintf(err, err_size, "vtysh query failed: %s", safe_stderr);
        else
            snprintf(err, err_size, "vtysh query failed");
        return -1;
    }
    return 0;
}

static void refresh_vtysh_state(rpd_frr_runtime *rt) {
    char out[RPD_FRR_VTYSH_OUTPUT_MAX];
    char ospf_err[192] = {0};
    char bgp_err[192] = {0};
    int ospf_neighbors = 0;
    int ospf_full = 0;
    int bgp_peers = 0;
    int bgp_established = 0;
    bool ospf_ok = false;
    bool bgp_ok = false;

    if (!rt)
        return;
    rt->ospf_neighbors = 0;
    rt->ospf_full = 0;
    rt->ospf_neighbor_entries = 0;
    rt->ospf_neighbor_complete = false;
    rt->ospf_neighbor_truncated = false;
    rt->bgp_peers = 0;
    rt->bgp_established = 0;
    rt->bgp_peer_entries = 0;
    rt->bgp_peer_complete = false;
    rt->bgp_peer_truncated = false;
    if (!rt->vtysh_present) {
        str_copy(rt->vtysh_status, sizeof(rt->vtysh_status), "unavailable");
        str_copy(rt->vtysh_reason, sizeof(rt->vtysh_reason),
                 "vtysh binary is unavailable");
        return;
    }
    refresh_process_state(rt);
    if (rt->running_processes <= 0) {
        str_copy(rt->vtysh_status, sizeof(rt->vtysh_status), "idle");
        str_copy(rt->vtysh_reason, sizeof(rt->vtysh_reason),
                 "FRR processes are not running under rpd");
        return;
    }
    if (run_vtysh_capture(rt, "show ip ospf neighbor json",
                          out, sizeof(out), ospf_err,
                          sizeof(ospf_err)) != 0) {
        rt->vtysh_errors++;
    } else {
        rt->vtysh_queries++;
        if (rpd_frr_parse_ospf_neighbors_json(
                out, rt, &ospf_neighbors, &ospf_full,
                ospf_err, sizeof(ospf_err)) != 0) {
            char parse_err[sizeof(ospf_err)];

            str_copy(parse_err, sizeof(parse_err), ospf_err);
            snprintf(ospf_err, sizeof(ospf_err),
                     "OSPF JSON parse failed: %.150s", parse_err);
            rt->vtysh_errors++;
            rt->vtysh_parse_errors++;
        } else {
            rt->ospf_neighbors = ospf_neighbors;
            rt->ospf_full = ospf_full;
            ospf_ok = true;
        }
    }

    if (run_vtysh_capture(rt, "show bgp summary json",
                          out, sizeof(out), bgp_err,
                          sizeof(bgp_err)) != 0) {
        rt->vtysh_errors++;
    } else {
        rt->vtysh_queries++;
        if (rpd_frr_parse_bgp_summary_json(
                out, rt, &bgp_peers, &bgp_established,
                bgp_err, sizeof(bgp_err)) != 0) {
            char parse_err[sizeof(bgp_err)];

            str_copy(parse_err, sizeof(parse_err), bgp_err);
            snprintf(bgp_err, sizeof(bgp_err),
                     "BGP JSON parse failed: %.151s", parse_err);
            rt->vtysh_errors++;
            rt->vtysh_parse_errors++;
        } else {
            rt->bgp_peers = bgp_peers;
            rt->bgp_established = bgp_established;
            bgp_ok = true;
        }
    }
    if (ospf_ok || bgp_ok)
        rt->last_vtysh = time(NULL);
    if (ospf_ok && bgp_ok) {
        str_copy(rt->vtysh_status, sizeof(rt->vtysh_status), "ok");
        str_copy(rt->vtysh_reason, sizeof(rt->vtysh_reason),
                 "FRR vtysh JSON read-back succeeded");
    } else {
        str_copy(rt->vtysh_status, sizeof(rt->vtysh_status), "error");
        if (!ospf_ok)
            str_copy(rt->vtysh_reason, sizeof(rt->vtysh_reason),
                     ospf_err[0] ? ospf_err : "OSPF vtysh query failed");
        else
            str_copy(rt->vtysh_reason, sizeof(rt->vtysh_reason),
                     bgp_err[0] ? bgp_err : "BGP vtysh query failed");
    }
}

int rpd_frr_runtime_collect_observation(const rpd_frr_runtime *source,
                                        rpd_frr_runtime *observation) {
    char preflight_err[192] = {0};

    if (!source || !observation)
        return -1;
    *observation = *source;
    (void)rpd_frr_runtime_preflight(observation, preflight_err,
                                    sizeof(preflight_err));
    refresh_vtysh_state(observation);
    return 0;
}

bool rpd_frr_runtime_merge_observation(rpd_frr_runtime *rt,
                                       const rpd_frr_runtime *observation) {
    if (!rt || !observation || rt->generation != observation->generation ||
        rt->config_hash != observation->config_hash ||
        rt->zebra_authority_generation !=
            observation->zebra_authority_generation)
        return false;

    rt->runtime_present = observation->runtime_present;
    rt->preflight_ready = observation->preflight_ready;
    rt->run_uid = observation->run_uid;
    rt->run_gid = observation->run_gid;
    rt->runtime_identity_ready = observation->runtime_identity_ready;
    rt->last_preflight = observation->last_preflight;
    snprintf(rt->preflight_reason, sizeof(rt->preflight_reason), "%s",
             observation->preflight_reason);
    rt->vtysh_present = observation->vtysh_present;
    snprintf(rt->zebra_path, sizeof(rt->zebra_path), "%s",
             observation->zebra_path);
    snprintf(rt->ospfd_path, sizeof(rt->ospfd_path), "%s",
             observation->ospfd_path);
    snprintf(rt->bgpd_path, sizeof(rt->bgpd_path), "%s",
             observation->bgpd_path);
    snprintf(rt->vtysh_path, sizeof(rt->vtysh_path), "%s",
             observation->vtysh_path);
    rt->zebra_pid = observation->zebra_pid;
    rt->zebra_starttime = observation->zebra_starttime;
    snprintf(rt->zebra_executable, sizeof(rt->zebra_executable), "%s",
             observation->zebra_executable);
    rt->zebra_authority_ready = observation->zebra_authority_ready;
    rt->ospfd_pid = observation->ospfd_pid;
    rt->bgpd_pid = observation->bgpd_pid;
    rt->running_processes = observation->running_processes;
    snprintf(rt->vtysh_status, sizeof(rt->vtysh_status), "%s",
             observation->vtysh_status);
    snprintf(rt->vtysh_reason, sizeof(rt->vtysh_reason), "%s",
             observation->vtysh_reason);
    rt->last_vtysh = observation->last_vtysh;
    rt->vtysh_queries = observation->vtysh_queries;
    rt->vtysh_errors = observation->vtysh_errors;
    rt->vtysh_parse_errors = observation->vtysh_parse_errors;
    rt->ospf_neighbors = observation->ospf_neighbors;
    rt->ospf_full = observation->ospf_full;
    rt->ospf_neighbor_entries = observation->ospf_neighbor_entries;
    rt->ospf_neighbor_complete = observation->ospf_neighbor_complete;
    rt->ospf_neighbor_truncated = observation->ospf_neighbor_truncated;
    memcpy(rt->ospf_neighbor, observation->ospf_neighbor,
           sizeof(rt->ospf_neighbor));
    rt->bgp_peers = observation->bgp_peers;
    rt->bgp_established = observation->bgp_established;
    rt->bgp_peer_entries = observation->bgp_peer_entries;
    rt->bgp_peer_complete = observation->bgp_peer_complete;
    rt->bgp_peer_truncated = observation->bgp_peer_truncated;
    memcpy(rt->bgp_peer, observation->bgp_peer, sizeof(rt->bgp_peer));
    return true;
}

int rpd_frr_runtime_append_xml(rpd_frr_runtime *rt, char *buf,
                               size_t buf_size, size_t *off) {
    int n;
    time_t now = time(NULL);

    if (!rt || !buf || !off || *off >= buf_size)
        return -1;
    n = snprintf(buf + *off, buf_size - *off,
                 "  <frr-runtime status=\"%s\" reason=\"%s\" "
                 "config-gate=\"%s\" start-gate=\"%s\" "
                 "runtime-present=\"%s\" preflight-ready=\"%s\" "
                 "preflight-reason=\"%s\" config-written=\"%s\" "
                 "run-dir=\"%s\" config-path=\"%s\" "
                 "zebra-module=\"%s\" "
                 "generation=\"%llu\" config-hash=\"%08x\" "
                 "last-update-age=\"%ld\" last-write-age=\"%ld\" "
                 "last-preflight-age=\"%ld\" "
                 "last-start-age=\"%ld\" start-attempts=\"%d\" "
                 "restart-events=\"%d\" "
                 "running-processes=\"%d\" zebra-pid=\"%d\" "
                 "ospfd-pid=\"%d\" bgpd-pid=\"%d\" last-errno=\"%d\"/>\n",
                 rt->status, rt->reason,
                 rt->config_gate_enabled ? "true" : "false",
                 rt->start_gate_enabled ? "true" : "false",
                 rt->runtime_present ? "true" : "false",
                 rt->preflight_ready ? "true" : "false",
                 rt->preflight_reason,
                 rt->config_written ? "true" : "false",
                 rt->run_dir, rt->config_path, rt->zebra_module,
                 (unsigned long long)rt->generation,
                 rt->config_hash,
                 rt->last_update ? (long)(now - rt->last_update) : -1L,
                 rt->last_write ? (long)(now - rt->last_write) : -1L,
                 rt->last_preflight ?
                     (long)(now - rt->last_preflight) : -1L,
                 rt->last_start ? (long)(now - rt->last_start) : -1L,
                 rt->start_attempts, rt->restart_events,
                 rt->running_processes,
                 (int)rt->zebra_pid, (int)rt->ospfd_pid,
                 (int)rt->bgpd_pid, rt->last_errno);
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    n = snprintf(buf + *off, buf_size - *off,
                 "  <frr-vtysh present=\"%s\" status=\"%s\" "
                 "format=\"json\" reason=\"%s\" queries=\"%d\" "
                 "errors=\"%d\" parse-errors=\"%d\" "
                 "last-age=\"%ld\" ospf-neighbors=\"%d\" "
                 "ospf-full=\"%d\" ospf-neighbor-entries=\"%d\" "
                 "ospf-neighbor-total=\"%d\" "
                 "ospf-neighbor-complete=\"%s\" "
                 "ospf-neighbor-truncated=\"%s\" "
                 "bgp-peers=\"%d\" bgp-established=\"%d\" "
                 "bgp-peer-entries=\"%d\" bgp-peer-total=\"%d\" "
                 "bgp-peer-complete=\"%s\" "
                 "bgp-peer-truncated=\"%s\">\n",
                 rt->vtysh_present ? "true" : "false",
                 rt->vtysh_status, rt->vtysh_reason,
                 rt->vtysh_queries, rt->vtysh_errors,
                 rt->vtysh_parse_errors,
                 rt->last_vtysh ? (long)(now - rt->last_vtysh) : -1L,
                 rt->ospf_neighbors, rt->ospf_full,
                 rt->ospf_neighbor_entries, rt->ospf_neighbors,
                 rt->ospf_neighbor_complete ? "true" : "false",
                 rt->ospf_neighbor_truncated ? "true" : "false",
                 rt->bgp_peers, rt->bgp_established,
                 rt->bgp_peer_entries, rt->bgp_peers,
                 rt->bgp_peer_complete ? "true" : "false",
                 rt->bgp_peer_truncated ? "true" : "false");
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    for (int i = 0; i < rt->ospf_neighbor_entries; i++) {
        const rpd_frr_ospf_neighbor *entry = &rt->ospf_neighbor[i];

        n = snprintf(buf + *off, buf_size - *off,
                     "    <ospf-neighbor id=\"%s\" state=\"%s\" "
                     "full=\"%s\" dead-time=\"%s\" address=\"%s\" "
                     "interface=\"%s\" priority=\"%d\"/>\n",
                     entry->neighbor_id, entry->state,
                     entry->full ? "true" : "false",
                     entry->dead_time, entry->address,
                     entry->interface, entry->priority);
        if (n < 0 || (size_t)n >= buf_size - *off)
            return -1;
        *off += (size_t)n;
    }
    for (int i = 0; i < rt->bgp_peer_entries; i++) {
        const rpd_frr_bgp_peer *entry = &rt->bgp_peer[i];

        n = snprintf(buf + *off, buf_size - *off,
                     "    <bgp-peer neighbor=\"%s\" remote-as=\"%s\" "
                     "uptime=\"%s\" state=\"%s\" established=\"%s\" "
                     "prefixes=\"%s\"/>\n",
                     entry->neighbor, entry->remote_as, entry->uptime,
                     entry->state, entry->established ? "true" : "false",
                     entry->prefixes);
        if (n < 0 || (size_t)n >= buf_size - *off)
            return -1;
        *off += (size_t)n;
    }
    n = snprintf(buf + *off, buf_size - *off, "  </frr-vtysh>\n");
    if (n < 0 || (size_t)n >= buf_size - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}
