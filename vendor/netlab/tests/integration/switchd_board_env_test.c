/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "../../sbin/switchd/sdk_executor.c"
#include "watchdog_disabled_fixture.h"

typedef struct {
    int mux;
    int select_fail;
    int restore_fail;
    int all_ff;
    int mux_writes;
} board_env_simulator;

static board_env_simulator sim;
static int failed;

fm_status fmPlatformI2cWriteRead(fm_int sw, fm_int bus, fm_int address,
                                 fm_uint32 *data, fm_int write_length,
                                 fm_int read_length) {
    (void)sw;
    (void)bus;
    (void)address;
    if (write_length == 0 && read_length == 1) {
        *data = (fm_uint32)sim.mux;
        return FM_OK;
    }
    if (write_length == 1 && read_length == 0) {
        int target = (int)(*data & 0xff);
        sim.mux_writes++;
        if (sim.select_fail && target == 0x04)
            return (fm_status)-101;
        if (sim.restore_fail && target == 0x0a)
            return (fm_status)-102;
        sim.mux = target;
        return FM_OK;
    }
    return (fm_status)-103;
}

fm_status fmI2cWriteRead(fm_int sw, fm_uint device, fm_byte *data,
                         fm_uint wl, fm_uint rl) {
    int reg;

    (void)sw;
    if (wl != 1 || rl == 0)
        return (fm_status)-201;
    reg = data[0];
    memset(data, sim.all_ff ? 0xff : 0, rl);
    if (sim.all_ff)
        return FM_OK;
    if (device == 0x40 || device == 0x50)
        data[0] = 0x11;
    if (device == 0x50 && reg <= 22 && reg + (int)rl > 23) {
        data[22 - reg] = 0x28;
        data[23 - reg] = 0x00;
    }
    if (device == 0x64 && reg == 0)
        data[0] = 0x03;
    if (device == 0x59) {
        for (fm_uint i = 0; i < rl; i++) {
            int offset = reg + (int)i;
            if (offset == 0x00)
                data[i] = 0x28;
            else if (offset == 0x20)
                data[i] = 0x29;
        }
    }
    if (device == 0x4c) {
        if (reg == 0x00)
            data[0] = 35;
        else if (reg == 0x01)
            data[0] = 42;
        else if (reg == 0x10)
            data[0] = 0x80;
    }
    return FM_OK;
}

static void expect(const char *name, int condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        failed++;
}

static struct sdk_op operation(int sample, int branch) {
    struct sdk_op op;

    memset(&op, 0, sizeof(op));
    op.type = SDK_OP_BOARD_ENV_GET;
    op.args.board_env.sample = sample;
    op.args.board_env.bus = 0;
    op.args.board_env.mux_addr = 0x58;
    op.args.board_env.branch = branch;
    op.args.board_env.cpld_ram_addr = 0x59;
    op.args.board_env.reset_gpio_addr = 0x64;
    return op;
}

static hal_board_env_sensor *find_sensor(hal_board_env_result *env,
                                         const char *name) {
    for (int i = 0; i < env->sensor_count; i++)
        if (strcmp(env->sensor[i].name, name) == 0)
            return &env->sensor[i];
    return NULL;
}

int main(void) {
    struct sdk_result result;
    struct sdk_op op;
    hal_board_env_sensor *sensor;

    memset(&sim, 0, sizeof(sim));
    sim.mux = 0x0a;
    memset(&result, 0, sizeof(result));
    op = operation(0, 0x01);
    expect("board environment sample completes",
           board_env_get(0, &op, &result) == 0);
    expect("mux state is restored after successful sample",
           sim.mux == 0x0a && result.data.board_env.restore_status == 0 &&
           sim.mux_writes == 2);
    sensor = find_sensor(&result.data.board_env, "fci-1-temperature");
    expect("verified FCI temperature conversion is exposed",
           sensor && sensor->valid && fabsf(sensor->value - 40.0f) < 0.01f);
    sensor = find_sensor(&result.data.board_env,
                         "cpld-fci-1-temperature");
    expect("unverified CPLD temperature format remains unavailable",
           sensor && !sensor->valid &&
           strcmp(sensor->status, "unavailable") == 0);
    sensor = find_sensor(&result.data.board_env, "ucd9081-rail-1");
    expect("rail without board divider calibration remains unavailable",
           sensor && !sensor->valid &&
           strcmp(sensor->status, "unavailable") == 0);
    expect("board operation stays attached to enforce one outstanding poll",
           !sdk_op_can_detach_on_timeout(SDK_OP_BOARD_ENV_GET));

    memset(&sim, 0, sizeof(sim));
    sim.mux = 0x0a;
    sim.all_ff = 1;
    memset(&result, 0, sizeof(result));
    op = operation(2, 0x04);
    board_env_get(0, &op, &result);
    sensor = find_sensor(&result.data.board_env,
                         "adt7461-local-temperature");
    expect("all-ff temperature is unavailable rather than healthy",
           sensor && !sensor->valid && sim.mux == 0x0a);

    memset(&sim, 0, sizeof(sim));
    sim.mux = 0x0a;
    sim.select_fail = 1;
    memset(&result, 0, sizeof(result));
    op = operation(2, 0x04);
    board_env_get(0, &op, &result);
    expect("mux state is restored after branch selection failure",
           sim.mux == 0x0a && result.data.board_env.sample_failures == 1 &&
           result.data.board_env.restore_status == 0);

    memset(&sim, 0, sizeof(sim));
    sim.mux = 0x0a;
    sim.restore_fail = 1;
    memset(&result, 0, sizeof(result));
    op = operation(2, 0x04);
    board_env_get(0, &op, &result);
    expect("mux restore failure is never reported healthy",
           result.data.board_env.restore_status == -102 &&
           result.data.board_env.sample_failures == 1);
    return failed ? 1 : 0;
}
