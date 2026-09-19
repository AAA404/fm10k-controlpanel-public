#!/usr/bin/env python3.11
# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
"""Exercise heap-backed L2 plan ownership and the 4094-VLAN boundary."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

C_SOURCE = r'''
#include "netlab/hal.h"
#include "netlab/l2_plan.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    return condition ? 0 : 1;
}

static void checkpoint(void *context) {
    (*(unsigned *)context)++;
}

static char *make_plan(int count) {
    size_t capacity = (size_t)count * 24U + 1U;
    char *text = calloc(capacity, 1);
    size_t offset = 0;

    if (!text)
        return NULL;
    for (int i = 0; i < count; i++) {
        int written = snprintf(text + offset, capacity - offset,
                               "vlan-create vid=%d\n", i % 4094 + 1);
        if (written <= 0 || (size_t)written >= capacity - offset) {
            free(text);
            return NULL;
        }
        offset += (size_t)written;
    }
    return text;
}

int main(void) {
    l2_apply_plan source;
    l2_apply_plan clone;
    l2_apply_plan moved;
    char *text = make_plan(4094);
    char *oversized = make_plan(NL_L2_PLAN_MAX_STEPS + 1);
    int failed = 0;
    unsigned checkpoints = 0;

    l2_apply_plan_init(&source);
    l2_apply_plan_init(&clone);
    l2_apply_plan_init(&moved);
    failed += check("plan descriptor does not embed multi-MiB step arrays",
                    sizeof(l2_apply_plan) < 64U * 1024U);
    failed += check("rare VLAN rollback images are not embedded per step",
                    sizeof(l2_apply_step) < 4096U);
    failed += check("4094-VLAN plan fixture allocated", text != NULL);
    if (text) {
        failed += check("4094 VLAN operations parse without truncation",
                        l2_plan_parse(text, &source) == 4094 &&
                        source.n_steps == 4094 &&
                        source.step_capacity == 4094 && source.steps &&
                        source.steps[4093].vid == 4094);
        source.tx_id = 0x1234U;
        source.checkpoint = checkpoint;
        source.checkpoint_context = &checkpoints;
        failed += check("plan clone owns an independent exact-sized image",
                        l2_apply_plan_clone(&clone, &source) == 0 &&
                        clone.steps != source.steps &&
                        clone.step_capacity == 4094 &&
                        clone.n_steps == 4094 && clone.tx_id == 0x1234U);
        l2_apply_plan_checkpoint(&source);
        l2_apply_plan_checkpoint(&clone);
        failed += check("clone never retains an executor stack callback",
                        checkpoints == 1 && !clone.checkpoint &&
                        !clone.checkpoint_context);
        clone.checkpoint = checkpoint;
        clone.checkpoint_context = &checkpoints;
        l2_apply_plan_move(&moved, &clone);
        failed += check("plan move transfers ownership and clears source",
                        moved.n_steps == 4094 && moved.steps &&
                        clone.n_steps == 0 && clone.steps == NULL);
        l2_apply_plan_checkpoint(&moved);
        l2_apply_plan_checkpoint(&clone);
        failed += check("move clears callbacks from both descriptors",
                        checkpoints == 1 && !moved.checkpoint &&
                        !moved.checkpoint_context && !clone.checkpoint &&
                        !clone.checkpoint_context);
    }
    failed += check("oversized operation set is rejected before allocation",
                    oversized && l2_plan_parse(oversized, &clone) < 0 &&
                    clone.n_steps == 0 && clone.steps == NULL);

    l2_apply_plan_reset(&source);
    l2_apply_plan_reset(&moved);
    if (l2_apply_plan_allocate_steps(&source, 1) == 0 &&
        l2_apply_plan_allocate_original(&source, 1) == 0) {
        source.n_steps = 1;
        source.original_n_steps = 1;
        source.steps[0].pre_static_mac_count = 1;
        source.steps[0].pre_static_macs =
            calloc(1, sizeof(*source.steps[0].pre_static_macs));
        source.original_steps[0].pre_vlan_member_count = 1;
        source.original_steps[0].pre_vlan_members =
            calloc(1, sizeof(*source.original_steps[0].pre_vlan_members));
        if (source.steps[0].pre_static_macs)
            source.steps[0].pre_static_macs[0].port = 17;
        if (source.original_steps[0].pre_vlan_members)
            source.original_steps[0].pre_vlan_members[0].port = 19;
        failed += check("sparse before-images are deep-cloned",
                        source.steps[0].pre_static_macs &&
                        source.original_steps[0].pre_vlan_members &&
                        l2_apply_plan_clone(&clone, &source) == 0 &&
                        clone.steps[0].pre_static_macs !=
                            source.steps[0].pre_static_macs &&
                        clone.original_steps[0].pre_vlan_members !=
                            source.original_steps[0].pre_vlan_members &&
                        clone.steps[0].pre_static_macs[0].port == 17 &&
                        clone.original_steps[0].pre_vlan_members[0].port == 19);
    } else {
        failed += check("sparse before-image fixture allocates", false);
    }

    l2_apply_plan_reset(&source);
    l2_apply_plan_reset(&clone);
    l2_apply_plan_reset(&moved);
    free(text);
    free(oversized);
    return failed ? 1 : 0;
}
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="netlab-l2-plan-storage-") as td:
        source = Path(td) / "l2_plan_storage_test.c"
        binary = Path(td) / "l2_plan_storage_test"
        source.write_text(C_SOURCE, encoding="utf-8")
        built = subprocess.run(
            [
                "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                "-Werror", "-pedantic", "-I", str(ROOT / "include"),
                str(source),
                str(ROOT / "sbin/switchd/l2_plan_storage.c"),
                str(ROOT / "sbin/switchd/l2_plan_parser.c"),
                "-L", str(ROOT / "build"), "-llog", "-lpthread",
                "-o", str(binary),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if built.returncode != 0:
            print("FAIL: L2 plan storage fixture builds")
            print(built.stdout, end="")
            return 1
        print("PASS: L2 plan storage fixture builds")
        run = subprocess.run(
            [str(binary)], cwd=ROOT, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=30, check=False,
        )
        print(run.stdout, end="")
        return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
