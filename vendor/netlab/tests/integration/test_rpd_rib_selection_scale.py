#!/usr/bin/env python3.11
"""Prove full and delta RIB selection stay bounded through 4096 routes."""

import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tests" / "integration" / "rpd_rib_selection_scale_test.c"


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def main():
    failed = 0
    env = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="rpd-rib-selection-scale-") as td:
        temp = Path(td)
        rib_object = temp / "rib.o"
        binary = temp / "rpd_rib_selection_scale_test"
        compile_rib = subprocess.run(
            [
                "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                "-Dstrcmp=rpd_test_strcmp", "-Iinclude", "-Isbin/rpd",
                "-c", "sbin/rpd/rib.c", "-o", str(rib_object),
            ],
            cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, check=False,
        )
        failed += check("instrumented RIB selection builds",
                        compile_rib.returncode == 0, compile_rib.stdout)
        if compile_rib.returncode == 0:
            link = subprocess.run(
                [
                    "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                    "-Iinclude", "-Isbin/rpd", str(SRC), str(rib_object),
                    "-o", str(binary),
                ],
                cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, check=False,
            )
            failed += check("RIB selection scale fixture links",
                            link.returncode == 0, link.stdout)
            if link.returncode == 0:
                run = subprocess.run(
                    [str(binary)], cwd=str(ROOT), env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, check=False,
                )
                failed += check(
                    "1/128/512/4096 selection and oversized full compile stay bounded",
                                run.returncode == 0, run.stdout)
                print(run.stdout, end="")
    if failed:
        print(f"FAILED: {failed} RIB selection scale checks failed")
    else:
        print("OK: RIB selection scale checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
