import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires the explicitly requested Debian/pinned-SDK validation")
@pytest.mark.parametrize("fixture", ["native_hal_plan_test.c", "native_lag_transaction_test.c", "native_storm_transaction_test.c"])
def test_native_production_hal_multistep_rollback(tmp_path, fixture):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / path for path in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                        "platforms", "platforms/libertyTrail", "platforms/common",
                                        "platforms/util/boardManager")]
    flags = [flag for path in includes for flag in ("-I", str(path))]
    binary = tmp_path / "hal-plan-test"
    sources = [root / "tests" / fixture, root / "hardware/native/fm10k_board.c",
               root / "hardware/native/fm10k_monitor.c"]
    sources += [netlab / "sbin/switchd" / name for name in (
        "hal_config.c", "read_back_verifier.c", "hal_vlan.c", "hal_lag.c", "l2_plan_storage.c",
        "hw_state_tracker.c", "commit_finalizer.c")]
    sources += [netlab / "lib/libipc/port_scope.c"]
    if fixture == "native_storm_transaction_test.c":
        sources += [netlab / "sbin/switchd/hal_storm_control.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic", *flags,
                    "-I", str(root / "hardware/native"), "-I", str(netlab / "include"),
                    *map(str, sources), "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    cases = ("rollback", "retry", "retry-second", "readback", "commit", "delete", "delete-partial", "added",
             "apply-failure", "apply-negative") if fixture == "native_lag_transaction_test.c" else (None,)
    if fixture == "native_lag_transaction_test.c":
        cases += ("qos-update", "qos-default", "qos-create", "qos-delete", "qos-drop", "qos-restore-retry")
        cases += tuple(f"qos-fail-{position}" for position in range(1, 9))
    for case in cases:
        subprocess.run([str(binary), *([case] if case else [])], check=True, timeout=30,
                       env={**os.environ, "NETLAB_FM10K_NATIVE": "0"})
