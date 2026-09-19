#!/usr/bin/env python3.11
"""Verify l2d handles the full structured switchd PFE response."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

C_SOURCE = r'''
#include "l2d_switchd.h"
#include "netlab/ipc.h"
#include <stdio.h>
#include <string.h>

static int response_mode;

int nl_rpc_call_ex(const char *socket_path, nl_daemon_id caller,
                   nl_daemon_id service, nl_rpc_method method, u64 tx_id,
                   const u8 *payload, int payload_len,
                   u8 *resp_buf, int max_resp, int timeout_ms,
                   s32 *error_code) {
    const char *status = response_mode == 1 ? "DOWN" : "UP";
    char response[NETLAB_PFE_STATUS_JSON_BYTES];
    int length = NETLAB_PFE_STATUS_JSON_BYTES - 1;

    (void)socket_path;
    (void)tx_id;
    (void)payload;
    (void)payload_len;
    (void)timeout_ms;
    if (response_mode == 2 || caller != NL_DAEMON_L2D ||
        service != NL_DAEMON_SWITCHD ||
        method != NL_SWITCHD_PFE_STATUS_GET)
        return -1;
    if (max_resp <= length)
        return -1;
    memset(response, ' ', (size_t)length);
    snprintf(response, sizeof(response), "{\"status\": \"%s\"}", status);
    memset(response + strlen(response), ' ',
           (size_t)length - strlen(response));
    memcpy(resp_buf, response, (size_t)length);
    resp_buf[length] = '\0';
    if (error_code)
        *error_code = 0;
    return length;
}

static int check(const char *name, int condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    return condition ? 0 : 1;
}

int main(void) {
    int failed = 0;

    response_mode = 0;
    failed += check("full PFE response with UP state is reachable",
                    l2d_switchd_reachable("/fake/switchd.sock"));
    response_mode = 1;
    failed += check("structured DOWN state is not reachable",
                    !l2d_switchd_reachable("/fake/switchd.sock"));
    response_mode = 2;
    failed += check("transport failure is not reachable",
                    !l2d_switchd_reachable("/fake/switchd.sock"));
    return failed ? 1 : 0;
}
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="netlab-l2d-pfe-") as raw:
        temporary = Path(raw)
        source = temporary / "l2d_switchd_reachability.c"
        binary = temporary / "l2d_switchd_reachability"
        source.write_text(C_SOURCE, encoding="ascii")
        build = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-D_GNU_SOURCE", "-ffunction-sections",
                "-I", str(ROOT / "include"),
                "-I", str(ROOT / "sbin" / "l2d"),
                str(source), str(ROOT / "sbin" / "l2d" / "l2d_switchd.c"),
                "-Wl,--gc-sections", "-o", str(binary),
            ],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        if build.returncode != 0:
            print("FAIL: l2d switchd reachability contract builds")
            print(build.stdout)
            return 1
        run = subprocess.run(
            [str(binary)], cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        print(run.stdout, end="")
        return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
