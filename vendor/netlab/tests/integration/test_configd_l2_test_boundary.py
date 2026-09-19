#!/usr/bin/env python3.11
"""Keep configd's staged-plan fixture outside production socket authority."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path


sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

ROOT = Path(__file__).resolve().parents[2]
CONFIGD = ROOT / "build" / "configd"
CLIENT_PATH = ROOT / "tests" / "integration" / "l2_plan_staged_client.py"
EMPTY_CONFIG = b'<netlab-config xmlns="urn:netlab:config"/>\n'


def _load_client():
    spec = importlib.util.spec_from_file_location("l2_plan_staged_client", CLIENT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load staged L2 client")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_configd(socket_path: Path, active: Path, candidate: Path):
    environment = os.environ.copy()
    environment.update({
        "NETLAB_CONFIGD_TEST_CONTROL": "1",
        "NETLAB_L2D_SOCKET": str(socket_path),
    })
    return subprocess.run(
        [str(CONFIGD), "--test-build-l2-plan", str(active), str(candidate), "0"],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )


def check(name: str, condition: bool, detail: str = "") -> int:
    print(("PASS" if condition else "FAIL") + ": " + name)
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def main() -> int:
    built = subprocess.run(
        ["make", "configd"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    failed = check(
        "configd fixture boundary builds", built.returncode == 0, built.stdout
    )
    if built.returncode != 0:
        return failed

    client = _load_client()
    with tempfile.TemporaryDirectory(prefix="netlab-configd-boundary-") as raw:
        temporary = Path(raw)
        active = temporary / "active.xml"
        candidate = temporary / "candidate.xml"
        active.write_bytes(EMPTY_CONFIG)
        candidate.write_bytes(EMPTY_CONFIG)

        dot_alias = Path(
            f"/tmp/../run/netlab-configd-test-{os.getpid()}-missing.sock"
        )
        dot_result = _run_configd(dot_alias, active, candidate)
        failed += check(
            "dot-segment alias cannot escape the temporary socket roots",
            dot_result.returncode == 2 and "isolated temporary socket" in dot_result.stdout,
            dot_result.stdout,
        )

        symlink_alias = temporary / "alias.sock"
        symlink_alias.symlink_to(
            f"/run/netlab-configd-test-{os.getpid()}-missing.sock"
        )
        symlink_result = _run_configd(symlink_alias, active, candidate)
        failed += check(
            "symlink alias cannot escape the private temporary directory",
            symlink_result.returncode == 2 and
            "isolated temporary socket" in symlink_result.stdout,
            symlink_result.stdout,
        )

        client_status, client_detail = client.build_staged_l2_plan(
            dot_alias, EMPTY_CONFIG, EMPTY_CONFIG, False
        )
        failed += check(
            "Python fixture rejects the same canonical-path escape",
            client_status == -1 and "invalid staged L2 test input" in client_detail,
            client_detail,
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
