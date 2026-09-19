import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="native l2d fixture requires Linux")
def test_multicast_preflight_and_runtime_require_complete_snapshot(tmp_path):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libyang"], text=True))
    binary = tmp_path / "multicast-probe"
    sources = [root / "tests/native_multicast_probe_test.c", netlab / "sbin/l2d/l2d_switchd.c",
               netlab / "lib/libipc/stp_snapshot.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), "-I", str(netlab / "sbin/l2d"),
                    *map(str, sources), *flags, "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires explicitly requested pinned-SDK validation")
def test_multicast_sdk_readback_is_complete_and_bounded(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / path for path in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                        "platforms", "platforms/libertyTrail", "platforms/common",
                                        "platforms/util/boardManager")]
    flags = [flag for path in includes for flag in ("-I", str(path))]
    binary = tmp_path / "multicast-sdk"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-pedantic", *flags,
                    "-I", str(root / "vendor/netlab/include"), "-I", str(root / "hardware/native"),
                    str(root / "tests/native_multicast_sdk_test.c"), "-Wl,--gc-sections", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
