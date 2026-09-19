#!/usr/bin/env python3.11
"""Exercise the offline typed/chunked rpd FIB snapshot transaction."""
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "tests" / "integration" /
          "switchd_rpd_fib_batch_offline_test.c")
BINARY = ROOT / "build" / "switchd_rpd_fib_snapshot_offline_test"


def check(name: str, condition: bool, detail: str = "") -> int:
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def main() -> int:
    failed = 0
    env = os.environ.copy()
    env["NETLAB_ROOT"] = str(ROOT)
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    build = subprocess.run(
        [
            "cc", "-std=c99", "-D_GNU_SOURCE", "-Wall", "-Wextra",
            "-Iinclude", "-pthread", "-o", str(BINARY), str(SOURCE),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    failed += check("typed FIB snapshot fixture builds",
                    build.returncode == 0, build.stdout)
    if build.returncode != 0:
        return 1
    run = subprocess.run(
        [str(BINARY), "--snapshot"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    failed += check(
        "typed FIB snapshot covers scale, ordering, integrity, and rollback",
        run.returncode == 0,
        run.stdout,
    )
    if run.returncode == 0:
        print(run.stdout, end="")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
