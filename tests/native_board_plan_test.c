#include "netlab/hal.h"
#include "netlab/yang_config.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include "l2_fm10k.h"
#include "l2_plan_text.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static nl_fm10k_config_snapshot hardware;
static int rpc_error, rpc_calls, short_reply;
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) {
    assert(!strcmp(name, "NETLAB_SWITCHD_SOCKET")); return fallback;
}
int nl_rpc_call_ex(const char *socket_path, nl_daemon_id caller, nl_daemon_id service,
                    nl_rpc_method method, u64 tx, const u8 *payload, int payload_len,
                    u8 *out, int capacity, int timeout, s32 *error) {
    (void)socket_path;
    assert(caller == NL_DAEMON_L2D && service == NL_DAEMON_SWITCHD && method == NL_SWITCHD_FM10K_CONFIG_GET);
    assert(!tx && !payload && !payload_len && capacity == (int)sizeof(hardware) && timeout == 5000);
    ++rpc_calls; *error = rpc_error;
    memcpy(out, &hardware, sizeof(hardware));
    return short_reply ? (int)sizeof(hardware) - 1 : (int)sizeof(hardware);
}
bool nl_ifid_get_by_logical_port(int port, nl_port_entry *out) {
    if (port < 1 || port > 24) return false;
    memset(out, 0, sizeof(*out)); out->logical_port = port; return true;
}
bool nl_ifid_is_user_port(int port) { return port >= 1 && port <= 24; }
int nl_platform_max_ae(void) { return 64; }

static void check_plan(const char *text, const fm10k_fan_curve *expected) {
    l2_apply_plan plan;
    l2_apply_plan_init(&plan);
    int count = 0;
    char error[512];
    assert(!l2_plan_text_validate(text, &count, error, sizeof(error)) && count == 1);
    assert(l2_plan_parse(text, &plan) == 1 && plan.steps[0].type == L2_STEP_FM10K_FAN_SET);
    assert(nl_fm10k_fan_equal(&plan.steps[0].fm10k_fan, expected));
    l2_apply_plan_reset(&plan);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *file = fopen(argv[1], "r"); assert(file);
    char xml[250001] = {0};
    size_t length = fread(xml, 1, sizeof(xml) - 1, file); assert(length && !ferror(file));
    fclose(file);
    nl_yang_session *active = nl_yang_session_create(NULL), *candidate = nl_yang_session_create(NULL);
    assert(active && candidate);
    struct lyd_node *data = nl_yang_from_xml(candidate, xml); assert(data);
    nl_yang_data_set(candidate, data);
    fm10k_fan_curve target;
    assert(!l2_fm10k_read_fan(candidate, &target) && target.idle_pwm == 50 && target.response_milliseconds == 10900);
    char text[2048] = {0}, error[512];
    int offset = 0;
    bool has = false;
    assert(!l2_fm10k_fan_plan(active, candidate, false, text, sizeof(text), &offset, &has, error, sizeof(error)));
    assert(has && !rpc_calls); check_plan(text, &target);
    offset = 0; has = false; text[0] = 0;
    assert(!l2_fm10k_fan_plan(candidate, candidate, false, text, sizeof(text), &offset, &has, error, sizeof(error)));
    assert(!has && !offset && !rpc_calls);
    hardware.schema = NL_FM10K_CONFIG_SCHEMA; hardware.bytes = sizeof(hardware);
    hardware.fan.valid = true; /* Full-speed startup with no applied curve. */
    assert(!l2_fm10k_fan_plan(candidate, candidate, true, text, sizeof(text), &offset, &has, error, sizeof(error)));
    assert(has && rpc_calls == 1); check_plan(text, &target);
    offset = 0; has = false; text[0] = 0;
    hardware.fan.curve_valid = true; hardware.fan.curve = target;
    assert(!l2_fm10k_fan_plan(candidate, candidate, true, text, sizeof(text), &offset, &has, error, sizeof(error)));
    assert(!has && !offset);
    for (int failure = 0; failure < 4; ++failure) {
        rpc_error = failure == 0 ? -1 : 0;
        short_reply = failure == 1;
        hardware.schema = failure == 2 ? 99 : NL_FM10K_CONFIG_SCHEMA;
        hardware.fan.valid = failure != 3;
        assert(l2_fm10k_fan_plan(candidate, candidate, true, text, sizeof(text), &offset, &has, error, sizeof(error)) != 0);
        assert(!offset);
    }
    assert(l2_fm10k_fan_plan(candidate, active, false, text, sizeof(text), &offset, &has, error, sizeof(error)) != 0);
    assert(nl_yang_set(candidate, L2_FM10K_ROOT "/fan/load-temperature-c", "40") == NL_ERR_OK);
    assert(l2_fm10k_read_fan(candidate, &target) != 0); /* Cross-leaf check also enforced by consumer. */
    static const char *invalid[] = {
        "fm10k-fan-set idle=35 load=70 critical=80 idle-pwm=20 load-pwm=80 hysteresis=4 response-ms=10900",
        "fm10k-fan-set idle=35 load=70 critical=80 idle-pwm=50 load-pwm=80 hysteresis=4 response-ms=11000",
        "fm10k-fan-set idle=35 load=70 critical=80 idle-pwm=50 load-pwm=80 hysteresis=4",
        "fm10k-fan-set idle=35 load=70 critical=80 idle-pwm=50 load-pwm=80 hysteresis=4 response-ms=10900 idle=35",
        "fm10k-fan-set idle=35 load=70 critical=80 idle-pwm=50 load-pwm=80 hysteresis=4 response-ms=10900 epl=0",
        "fm10k-fan-set idle=35 load=70 critical=80 idle-pwm=50 load-pwm=80 hysteresis=-1 response-ms=10900",
        "fm10k-fan-set idle=999999999999999999999 load=70 critical=80 idle-pwm=50 load-pwm=80 hysteresis=4 response-ms=10900",
        "fm10k-fan-set idle=35x load=70 critical=80 idle-pwm=50 load-pwm=80 hysteresis=4 response-ms=10900"
    };
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        l2_apply_plan plan; l2_apply_plan_init(&plan);
        int count;
        assert(l2_plan_text_validate(invalid[i], &count, error, sizeof(error)) != 0);
        assert(l2_plan_parse(invalid[i], &plan) < 0);
        l2_apply_plan_reset(&plan);
    }
    nl_yang_session_destroy(active); nl_yang_session_destroy(candidate);
    puts("real libyang fan intent, typed plan, replay, strict parsing and readback failure gates passed");
    return 0;
}
