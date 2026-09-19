from pathlib import Path
import os
import subprocess
import sys

import pytest


def test_native_watchdog_state_machine(tmp_path):
    root = Path(__file__).resolve().parents[1]
    binary = tmp_path / "pfc-watchdog"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(root / "hardware/native"),
                    "-I", str(root / "vendor/netlab/include"),
                    str(root / "hardware/native/fm10k_pfc_watchdog.c"),
                    str(root / "tests/native_pfc_watchdog_test.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=5)


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires Debian/pinned SDK; no hardware access")
def test_native_watchdog_sdk_recovery_and_quiesce(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / p for p in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                 "platforms", "platforms/libertyTrail", "platforms/common", "platforms/util/boardManager")]
    binary = tmp_path / "pfc-watchdog-sdk"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    *[a for p in includes for a in ("-I", str(p))],
                    "-I", str(root / "vendor/netlab/include"), "-I", str(root / "hardware/native"),
                    str(root / "tests/native_pfc_watchdog_sdk_test.c"),
                    str(root / "hardware/native/fm10k_pfc_watchdog.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=5)
