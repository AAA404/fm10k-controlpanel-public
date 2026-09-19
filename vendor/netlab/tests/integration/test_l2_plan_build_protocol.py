#!/usr/bin/env python3.11
"""Validate the bounded, tokenized configd-to-l2d plan-build protocol."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

C_SOURCE = r'''
#include "netlab/l2_plan_build.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int check(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    return condition ? 0 : 1;
}

int main(void) {
    nl_l2_plan_build_begin begin = {0};
    nl_l2_plan_build_begin decoded_begin = {0};
    nl_l2_plan_build_part part = {0};
    nl_l2_plan_build_part decoded_part = {0};
    u8 decoded_token[NL_L2_PLAN_BUILD_TOKEN_BYTES] = {0};
    const u8 payload[] = {'<', 'x', '/', '>'};
    const u8 *decoded_data = NULL;
    size_t decoded_length = 0;
    u8 wire[256] = {0};
    int length;
    int failed = 0;

    for (size_t i = 0; i < sizeof(begin.token); i++)
        begin.token[i] = (u8)(i + 1U);
    begin.active_length = NL_L2_PLAN_CONFIG_MAX_BYTES;
    begin.candidate_length = 1;
    begin.require_hardware = true;
    length = nl_l2_plan_build_begin_encode(&begin, wire, sizeof(wire));
    failed += check("maximum bounded begin round-trips exactly",
                    length == 40 &&
                    nl_l2_plan_build_begin_decode(
                        wire, (size_t)length, &decoded_begin) == 0 &&
                    decoded_begin.active_length == begin.active_length &&
                    decoded_begin.candidate_length == 1 &&
                    decoded_begin.require_hardware &&
                    memcmp(decoded_begin.token, begin.token,
                           sizeof(begin.token)) == 0);
    failed += check("oversized configuration is rejected",
                    (begin.active_length =
                         NL_L2_PLAN_CONFIG_MAX_BYTES + 1U,
                     nl_l2_plan_build_begin_encode(
                         &begin, wire, sizeof(wire)) < 0));
    begin.active_length = 1;

    memcpy(part.token, begin.token, sizeof(part.token));
    part.stream = NL_L2_PLAN_BUILD_CANDIDATE;
    part.offset = 4;
    part.total_length = 8;
    length = nl_l2_plan_build_part_encode(
        &part, payload, sizeof(payload), wire, sizeof(wire));
    failed += check("binary part preserves token, offset, total, and bytes",
                    length == 44 &&
                    nl_l2_plan_build_part_decode(
                        wire, (size_t)length, &decoded_part,
                        &decoded_data, &decoded_length) == 0 &&
                    decoded_part.stream == NL_L2_PLAN_BUILD_CANDIDATE &&
                    decoded_part.offset == 4 &&
                    decoded_part.total_length == 8 &&
                    decoded_length == sizeof(payload) &&
                    memcmp(decoded_data, payload, sizeof(payload)) == 0);
    failed += check("truncated and extended part frames fail closed",
                    nl_l2_plan_build_part_decode(
                        wire, (size_t)length - 1U, &decoded_part,
                        &decoded_data, &decoded_length) < 0 &&
                    nl_l2_plan_build_part_decode(
                        wire, (size_t)length + 1U, &decoded_part,
                        &decoded_data, &decoded_length) < 0);
    wire[25] = 1;
    failed += check("nonzero reserved wire bytes are rejected",
                    nl_l2_plan_build_part_decode(
                        wire, (size_t)length, &decoded_part,
                        &decoded_data, &decoded_length) < 0);
    wire[25] = 0;

    length = nl_l2_plan_build_token_encode(
        begin.token, wire, sizeof(wire));
    failed += check("commit/abort token round-trips exactly",
                    length == 24 &&
                    nl_l2_plan_build_token_decode(
                        wire, (size_t)length, decoded_token) == 0 &&
                    memcmp(decoded_token, begin.token,
                           sizeof(begin.token)) == 0);
    memset(begin.token, 0, sizeof(begin.token));
    failed += check("all-zero session token is never accepted",
                    nl_l2_plan_build_token_encode(
                        begin.token, wire, sizeof(wire)) < 0);
    return failed ? 1 : 0;
}
'''


def main() -> int:
    client = (ROOT / "sbin/configd/l2_client.c").read_text(encoding="utf-8")
    server = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in ("sbin/l2d/main.c", "sbin/l2d/l2_plan_stage.c")
    )
    checks = {
        "client uses staged methods, not combined XML payload": all(
            token in client for token in (
                "NL_L2D_BUILD_PLAN_BEGIN", "NL_L2D_BUILD_PLAN_PART",
                "NL_L2D_BUILD_PLAN_COMMIT", "NL_L2D_BUILD_PLAN_ABORT",
            )
        ) and "header_len + active_len + candidate_len" not in client,
        "server enforces exact stream offsets":
            "part->offset != *received" in server,
        "malformed matching stream resets staged authority":
            "reset_locked(stage);" in server,
        "stale sessions have a bounded lifetime":
            "L2_PLAN_BUILD_STAGE_TTL_SECONDS" in server and
            "expire_locked(stage, now_seconds)" in server,
    }
    failed = 0
    for name, condition in checks.items():
        print(("PASS" if condition else "FAIL") + f": {name}")
        failed += not condition

    with tempfile.TemporaryDirectory(prefix="netlab-l2-plan-build-wire-") as td:
        source = Path(td) / "l2_plan_build_wire_test.c"
        binary = Path(td) / "l2_plan_build_wire_test"
        source.write_text(C_SOURCE, encoding="utf-8")
        built = subprocess.run(
            [
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-I", str(ROOT / "include"), str(source),
                str(ROOT / "lib/libipc/l2_plan_build.c"),
                "-o", str(binary),
            ],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        if built.returncode != 0:
            print("FAIL: L2 plan build wire fixture builds")
            print(built.stdout, end="")
            return 1
        print("PASS: L2 plan build wire fixture builds")
        run = subprocess.run(
            [str(binary)], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=10, check=False,
        )
        print(run.stdout, end="")
        return 1 if failed or run.returncode else 0


if __name__ == "__main__":
    raise SystemExit(main())
