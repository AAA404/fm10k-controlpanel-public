from pathlib import Path
import shlex
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the Debian libyang 2.x build environment")
def test_complete_qos_snapshot_is_reused_only_within_one_plan(tmp_path):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    binary = tmp_path / "qos-probe"
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libyang"], text=True))
    sources = [root / "tests/native_qos_probe_test.c", netlab / "sbin/l2d/l2_intent.c", netlab / "lib/libipc/stp_snapshot.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), "-I", str(netlab / "sbin/l2d"),
                    *map(str, sources), *flags, "-Wl,--gc-sections", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
