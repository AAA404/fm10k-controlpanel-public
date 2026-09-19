"""Pinned-SDK control-plane fixtures; no device or network is opened."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires Debian and pinned SDK headers; no ASIC access")
@pytest.mark.parametrize("source", [
    "tests/native_cpu_protection_test.c",
    "vendor/netlab/tests/integration/switchd_copp_transaction_snapshot_test.c",
])
def test_cpu_protection_preserves_transit_and_restores_failures(tmp_path, source):
    root = Path(__file__).resolve().parents[1]
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / p for p in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                  "platforms", "platforms/libertyTrail", "platforms/common",
                                  "platforms/util/boardManager")]
    binary = tmp_path / "fixture"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-pedantic",
                    *[v for p in includes for v in ("-I", str(p))],
                    "-I", str(root / "vendor/netlab/include"), "-I", str(root / "hardware/native"),
                    str(root / source), "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
