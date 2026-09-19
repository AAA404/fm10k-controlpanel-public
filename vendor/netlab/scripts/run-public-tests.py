#!/usr/bin/env python3
"""Run the isolated tests that form the public contributor contract."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PUBLIC_TESTS = (
    "tests/integration/test_acl_counter_snapshot.py",
    "tests/integration/test_cli_public_namespace_cleanup.py",
    "tests/integration/test_configd_l2_staged_build.py",
    "tests/integration/test_configd_l2_test_boundary.py",
    "tests/integration/test_configd_l3_build_plan.py",
    "tests/integration/test_configd_public_capabilities.py",
    "tests/integration/test_control_plane_responsiveness_contract.py",
    "tests/integration/test_ipc_contract_registry.py",
    "tests/integration/test_ipc_policy_persistence.py",
    "tests/integration/test_ipc_v2.py",
    "tests/integration/test_l2_plan_build_protocol.py",
    "tests/integration/test_l2_plan_stage.py",
    "tests/integration/test_l2d_switchd_reachability.py",
    "tests/integration/test_l3_capacity_contract.py",
    "tests/integration/test_mac_snapshot.py",
    "tests/integration/test_rpd_frr_telemetry_scale.py",
    "tests/integration/test_rpd_rib_selection_scale.py",
    "tests/integration/test_switchd_l2_plan_storage.py",
    "tests/integration/test_switchd_l3_owner_storage.py",
    "tests/integration/test_switchd_rpd_fib_snapshot.py",
    "tests/integration/test_yang_xml_cache.py",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--timeout", type=int, default=180)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    missing = [path for path in PUBLIC_TESTS if not (ROOT / path).is_file()]
    if missing:
        print("ERROR: public test manifest references missing files:", file=sys.stderr)
        print("\n".join(missing), file=sys.stderr)
        return 2
    if args.list:
        print("\n".join(PUBLIC_TESTS))
        return 0

    failures: list[str] = []
    started = time.monotonic()
    environment = {
        **os.environ,
        "NETLAB_ROOT": str(ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    libyang_prefix = environment.get("NETLAB_LIBYANG_PREFIX")
    if libyang_prefix:
        prefix = Path(libyang_prefix)
        library_dir = prefix / "lib64"
        if not library_dir.is_dir():
            library_dir = prefix / "lib"
        previous = environment.get("LD_LIBRARY_PATH")
        environment["LD_LIBRARY_PATH"] = (
            str(library_dir) + (":" + previous if previous else "")
        )
    print(f"NetLab OS public tests: selected={len(PUBLIC_TESTS)}", flush=True)
    for relative in PUBLIC_TESTS:
        test_started = time.monotonic()
        try:
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / relative)],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=args.timeout,
                check=False,
            )
            passed = result.returncode == 0
            output = result.stdout
        except subprocess.TimeoutExpired as error:
            passed = False
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            output += f"\nTIMEOUT after {args.timeout}s\n"
        duration = time.monotonic() - test_started
        print(f"{'PASS' if passed else 'FAIL'}: {relative} ({duration:.1f}s)",
              flush=True)
        if not passed:
            failures.append(relative)
            print(output.rstrip())

    duration = time.monotonic() - started
    print(
        f"Results: passed={len(PUBLIC_TESTS) - len(failures)} "
        f"failed={len(failures)} duration={duration:.1f}s"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
