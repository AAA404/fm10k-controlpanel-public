#!/usr/bin/env python3.11
"""Sealed configd fixture for the internal staged L2-plan protocol."""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONFIGD = ROOT / "build" / "configd"
_MAX_CONFIG_BYTES = 8 * 1024 * 1024


def build_staged_l2_plan(socket_path: Path, active: bytes,
                         candidate: bytes,
                         require_hardware: bool) -> tuple[int, str]:
    """Build through configd methods 10-13; retired method 5 stays closed."""
    try:
        canonical_socket = socket_path.resolve(strict=True)
        socket_metadata = socket_path.lstat()
        parent_metadata = canonical_socket.parent.lstat()
        socket_allowed = (
            socket_path == canonical_socket and
            str(canonical_socket).startswith(("/tmp/", "/var/tmp/")) and
            stat.S_ISSOCK(socket_metadata.st_mode) and
            socket_metadata.st_nlink == 1 and
            socket_metadata.st_uid == os.geteuid() and
            stat.S_ISDIR(parent_metadata.st_mode) and
            parent_metadata.st_uid == os.geteuid() and
            stat.S_IMODE(parent_metadata.st_mode) == 0o700
        )
    except (FileNotFoundError, OSError, RuntimeError):
        socket_allowed = False
    if (not active or not candidate or
            len(active) > _MAX_CONFIG_BYTES or
            len(candidate) > _MAX_CONFIG_BYTES or not socket_allowed):
        return -1, "invalid staged L2 test input"

    with tempfile.TemporaryDirectory(
            prefix="netlab-configd-l2-input-") as raw:
        temporary = Path(raw)
        active_path = temporary / "active.xml"
        candidate_path = temporary / "candidate.xml"
        active_path.write_bytes(active)
        candidate_path.write_bytes(candidate)
        environment = {
            **os.environ,
            "NETLAB_CONFIGD_TEST_CONTROL": "1",
            "NETLAB_L2D_SOCKET": str(socket_path),
        }
        completed = subprocess.run(
            [
                str(CONFIGD), "--test-build-l2-plan",
                str(active_path), str(candidate_path),
                "1" if require_hardware else "0",
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=40,
            check=False,
        )
    if completed.returncode == 0:
        return 0, completed.stdout.decode(errors="replace")
    detail = completed.stderr or completed.stdout
    return completed.returncode, detail.decode(errors="replace")
