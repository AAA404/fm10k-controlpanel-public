#!/usr/bin/env python3.11
"""Verify production L2 plan builds fail when required read-back is absent."""
from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
L2D = ROOT / "build" / "l2d"
from l2_plan_staged_client import build_staged_l2_plan


def check(name: str, condition: bool, detail: str = "") -> int:
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def wait_socket(path: Path, proc: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"l2d exited early with {proc.returncode}")
        if path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                probe.connect(str(path))
                return
            except OSError:
                pass
            finally:
                probe.close()
        time.sleep(0.05)
    raise RuntimeError("l2d socket did not become connectable")


def build_plan(socket_path: Path, xml: bytes,
               require_hw: bool) -> tuple[int, str]:
    return build_staged_l2_plan(socket_path, xml, xml, require_hw)


def main() -> int:
    failed = 0
    subprocess.run(["make", "l2d", "configd"], cwd=ROOT, check=True)
    xml = b'<netlab-config xmlns="urn:netlab:config"/>'

    with tempfile.TemporaryDirectory(prefix="netlab-l2d-probe-") as td:
        temp = Path(td)
        config_dir = temp / "config"
        config_dir.mkdir(mode=0o700)
        (config_dir / "active.conf").write_bytes(xml)
        socket_path = temp / "l2d.sock"
        env = os.environ.copy()
        env.update({
            "NETLAB_ROOT": str(ROOT),
            "NETLAB_CONFIG_DIR": str(config_dir),
            "NETLAB_L2D_SOCKET": str(socket_path),
            "NETLAB_SWITCHD_SOCKET": str(temp / "missing-switchd.sock"),
            "NETLAB_LOG_LEVEL": "error",
        })
        proc = subprocess.Popen(
            [str(L2D)], cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_socket(socket_path, proc)
            offline_ec, offline_body = build_plan(socket_path, xml, False)
            strict_ec, strict_body = build_plan(socket_path, xml, True)
            failed += check(
                "offline L2 plan build remains available",
                offline_ec == 0,
                offline_body,
            )
            failed += check(
                "required L2 hardware read-back fails closed",
                strict_ec != 0 and
                "hardware read-back failed" in strict_body and
                "RPC failed" in strict_body,
                strict_body,
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    print(f"Results: {failed == 0 and 'all passed' or str(failed) + ' failed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
