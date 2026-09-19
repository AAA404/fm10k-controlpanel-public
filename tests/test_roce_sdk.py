import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires Debian/pinned SDK; no hardware access")
@pytest.mark.parametrize("source", ["native_roce_sdk_test.c", "native_congestion_counters_test.c",
                                    "native_qos_transaction_snapshot_test.c"])
def test_roce_sdk_budget_and_write_failure(tmp_path, source):
    root = Path(__file__).resolve().parents[1]
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / p for p in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                 "platforms", "platforms/libertyTrail", "platforms/common", "platforms/util/boardManager")]
    binary = tmp_path / "roce-sdk-test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    *[a for p in includes for a in ("-I", str(p))],
                    "-I", str(root / "vendor/netlab/include"), "-I", str(root / "hardware/native"),
                    str(root / "tests" / source), "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15, cwd=tmp_path)
