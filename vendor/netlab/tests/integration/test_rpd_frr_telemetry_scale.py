#!/usr/bin/env python3.11
"""Check FRR telemetry completeness at the old and product boundaries."""

import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tests" / "integration" / "rpd_frr_telemetry_scale_test.c"


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def main():
    failed = 0
    env = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="rpd-frr-telemetry-scale-") as td:
        binary = Path(td) / "rpd_frr_telemetry_scale_test"
        build = subprocess.run(
            [
                "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                "-Iinclude", "-Isbin/rpd", str(SRC),
                "sbin/rpd/frr_telemetry_json.c", "-o", str(binary),
            ],
            cwd=str(ROOT), env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, check=False,
        )
        failed += check("FRR telemetry scale fixture builds",
                        build.returncode == 0, build.stdout)
        if build.returncode == 0:
            run = subprocess.run(
                [str(binary)], cwd=str(ROOT), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, check=False,
            )
            failed += check("8/9/64/65 telemetry boundaries pass",
                            run.returncode == 0, run.stdout)
            print(run.stdout, end="")
    if failed:
        print(f"FAILED: {failed} FRR telemetry scale checks failed")
    else:
        print("OK: FRR telemetry scale checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
