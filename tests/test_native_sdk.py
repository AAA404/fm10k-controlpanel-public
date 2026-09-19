import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires the explicitly requested Debian/pinned-SDK validation")
@pytest.mark.parametrize("fixture", ["native_sdk_bus_test.c", "native_fci_test.c", "native_group_sdk_test.c",
                                   "native_board_runtime_test.c", "native_lag_sdk_test.c", "native_phy_test.c", "native_eye_sdk_test.c", "native_stp_inventory_test.c"])
def test_sdk_bus_callback_binding(tmp_path, fixture):
    root = Path(__file__).resolve().parents[1]
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / path for path in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                        "platforms", "platforms/libertyTrail", "platforms/common",
                                        "platforms/util/boardManager")]
    flags = [flag for path in includes for flag in ("-I", str(path))]
    binary = tmp_path / "sdk-bus-test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-pedantic",
                    *flags, "-I", str(root / "hardware/native"),
                    "-I", str(root / "vendor/netlab/include"),
                    str(root / "hardware/native/fm10k_board.c"),
                    str(root / "tests" / fixture), "-Wl,--gc-sections", "-pthread", "-lm", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires the explicitly requested Debian/pinned-SDK validation")
def test_sdk_queue_scope_admission(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / path for path in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                        "platforms", "platforms/libertyTrail", "platforms/common",
                                        "platforms/util/boardManager")]
    flags = [flag for path in includes for flag in ("-I", str(path))]
    binary = tmp_path / "sdk-queue-test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-pedantic", *flags,
                    "-I", str(root / "hardware/native"), "-I", str(root / "vendor/netlab/include"),
                    str(root / "tests/native_executor_test.c"),
                    str(root / "vendor/netlab/sbin/switchd/l2_plan_storage.c"),
                    str(root / "vendor/netlab/lib/libipc/port_scope.c"),
                    "-Wl,--gc-sections", "-pthread", "-lm", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=25,
                   env={**os.environ, "NETLAB_FM10K_NATIVE": "0"})
