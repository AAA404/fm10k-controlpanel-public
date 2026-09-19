#!/usr/bin/env python3.11
"""Exercise l2d's token authority, ordering, expiry, and ownership transfer."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

C_SOURCE = r'''
#include "l2_plan_stage.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    return condition ? 0 : 1;
}

static void fill_token(u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES], u8 seed) {
    for (size_t i = 0; i < NL_L2_PLAN_BUILD_TOKEN_BYTES; i++)
        token[i] = (u8)(seed + i);
}

static nl_l2_plan_build_part part_for(
    const nl_l2_plan_build_begin *begin, nl_l2_plan_build_stream stream,
    u32 offset, u32 total) {
    nl_l2_plan_build_part part = {0};
    memcpy(part.token, begin->token, sizeof(part.token));
    part.stream = stream;
    part.offset = offset;
    part.total_length = total;
    return part;
}

int main(void) {
    l2_plan_stage stage;
    nl_l2_plan_build_begin first = {0};
    nl_l2_plan_build_begin other = {0};
    nl_l2_plan_build_begin zero = {0};
    nl_l2_plan_build_part part;
    char *active = NULL;
    char *candidate = NULL;
    bool require_hardware = false;
    int failed = 0;

    fill_token(first.token, 1);
    fill_token(other.token, 33);
    first.active_length = 4;
    first.candidate_length = 4;
    first.require_hardware = true;
    other = first;
    fill_token(other.token, 33);
    zero.active_length = 1;
    zero.candidate_length = 1;

    failed += check("stage initializes", l2_plan_stage_init(&stage) == 0);
    failed += check("zero token is rejected",
                    l2_plan_stage_begin(&stage, &zero, 1) != 0);
    failed += check("first token owns the session",
                    l2_plan_stage_begin(&stage, &first, 100) == 0);
    failed += check("concurrent token is busy",
                    l2_plan_stage_begin(&stage, &other, 100) != 0);

    part = part_for(&other, NL_L2_PLAN_BUILD_ACTIVE, 0, 4);
    failed += check("wrong token cannot append",
                    l2_plan_stage_append(
                        &stage, &part, (const u8 *)"nope", 4, 101) != 0);
    part = part_for(&first, NL_L2_PLAN_BUILD_ACTIVE, 0, 4);
    failed += check("wrong token did not destroy owner",
                    l2_plan_stage_append(
                        &stage, &part, (const u8 *)"<a/>", 4, 101) == 0);
    part = part_for(&first, NL_L2_PLAN_BUILD_CANDIDATE, 1, 4);
    failed += check("out-of-order owner part fails closed",
                    l2_plan_stage_append(
                        &stage, &part, (const u8 *)"bad", 3, 101) != 0);
    failed += check("malformed owner stream resets the session",
                    l2_plan_stage_take(
                        &stage, first.token, 101, &active, &candidate,
                        &require_hardware) != 0);

    failed += check("session can restart after reset",
                    l2_plan_stage_begin(&stage, &first, 200) == 0);
    part = part_for(&first, NL_L2_PLAN_BUILD_ACTIVE, 0, 4);
    failed += check("partial active stream accepted",
                    l2_plan_stage_append(
                        &stage, &part, (const u8 *)"<a", 2, 201) == 0);
    failed += check("incomplete commit fails closed",
                    l2_plan_stage_take(
                        &stage, first.token, 201, &active, &candidate,
                        &require_hardware) != 0);

    failed += check("complete session begins",
                    l2_plan_stage_begin(&stage, &first, 300) == 0);
    part = part_for(&first, NL_L2_PLAN_BUILD_ACTIVE, 0, 4);
    failed += check("active chunk one accepted",
                    l2_plan_stage_append(
                        &stage, &part, (const u8 *)"<a", 2, 301) == 0);
    part.offset = 2;
    failed += check("active chunk two accepted",
                    l2_plan_stage_append(
                        &stage, &part, (const u8 *)"/>", 2, 301) == 0);
    part = part_for(&first, NL_L2_PLAN_BUILD_CANDIDATE, 0, 4);
    failed += check("candidate stream accepted",
                    l2_plan_stage_append(
                        &stage, &part, (const u8 *)"<b/>", 4, 301) == 0);
    failed += check("complete commit transfers exact ownership",
                    l2_plan_stage_take(
                        &stage, first.token, 302, &active, &candidate,
                        &require_hardware) == 0 && active && candidate &&
                    strcmp(active, "<a/>") == 0 &&
                    strcmp(candidate, "<b/>") == 0 && require_hardware);
    free(active);
    free(candidate);
    active = NULL;
    candidate = NULL;
    failed += check("committed session is consumed once",
                    l2_plan_stage_take(
                        &stage, first.token, 302, &active, &candidate,
                        &require_hardware) != 0);

    failed += check("expiring session begins",
                    l2_plan_stage_begin(&stage, &first, 400) == 0);
    part = part_for(&first, NL_L2_PLAN_BUILD_ACTIVE, 0, 4);
    failed += check("expired token cannot append",
                    l2_plan_stage_append(
                        &stage, &part, (const u8 *)"<a/>", 4,
                        400 + L2_PLAN_BUILD_STAGE_TTL_SECONDS) != 0);
    failed += check("new owner starts after expiry",
                    l2_plan_stage_begin(&stage, &other, 431) == 0);
    failed += check("wrong token cannot abort owner",
                    l2_plan_stage_abort(&stage, first.token, 431) != 0);
    failed += check("right token aborts owner",
                    l2_plan_stage_abort(&stage, other.token, 431) == 0);

    failed += check("abandoned session begins",
                    l2_plan_stage_begin(&stage, &first, 500) == 0);
    failed += check("daemon idle sweep actively expires abandoned heap",
                    l2_plan_stage_expire(
                        &stage, 500 + L2_PLAN_BUILD_STAGE_TTL_SECONDS));
    failed += check("expired heap is gone before any client returns",
                    l2_plan_stage_take(
                        &stage, first.token, 531, &active, &candidate,
                        &require_hardware) != 0);

    l2_plan_stage_destroy(&stage);
    return failed ? 1 : 0;
}
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="netlab-l2-plan-stage-") as td:
        source = Path(td) / "l2_plan_stage_test.c"
        binary = Path(td) / "l2_plan_stage_test"
        source.write_text(C_SOURCE, encoding="utf-8")
        built = subprocess.run(
            [
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-pedantic", "-I", str(ROOT / "include"),
                "-I", str(ROOT / "sbin/l2d"), str(source),
                str(ROOT / "sbin/l2d/l2_plan_stage.c"), "-pthread",
                "-o", str(binary),
            ],
            cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
        if built.returncode != 0:
            print("FAIL: L2 plan stage fixture builds")
            print(built.stdout, end="")
            return 1
        print("PASS: L2 plan stage fixture builds")
        run = subprocess.run(
            [str(binary)], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=10, check=False,
        )
        print(run.stdout, end="")
        return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
