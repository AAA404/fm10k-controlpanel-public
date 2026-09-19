from pathlib import Path
import shlex
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="native l2d requires Linux eventfd; checked in Debian container")
def test_native_igmp_leave_ownership(tmp_path):
    root = Path(__file__).resolve().parents[1]
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "libyang"], text=True))
    executable = tmp_path / "igmp-runtime"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-I", str(root / "vendor/netlab/include"), *flags, str(root / "tests/igmp_runtime_test.c"),
                    str(root / "vendor/netlab/sbin/l2d/igmp_state.c"),
                    str(root / "vendor/netlab/lib/liblog/log.c"),
                    str(root / "vendor/netlab/lib/libipc/port_scope.c"),
                    "-Wl,--gc-sections", "-pthread", "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=15)


@pytest.mark.skipif(sys.platform != "linux", reason="native IGMP restart fixture requires Linux")
def test_native_igmp_process_restart_ownership(tmp_path):
    root = Path(__file__).resolve().parents[1]
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "libyang"], text=True))
    executable = tmp_path / "igmp-restart"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation",
                    "-I", str(root / "vendor/netlab/include"), *flags,
                    str(root / "tests/igmp_restart_test.c"),
                    str(root / "vendor/netlab/sbin/l2d/igmp_state.c"),
                    str(root / "vendor/netlab/lib/libipc/port_scope.c"),
                    str(root / "vendor/netlab/lib/liblog/log.c"),
                    "-Wl,--gc-sections", "-pthread", "-o", str(executable)], check=True)
    scenarios = [
        [("crash-add", 42), ("recover-add-crash-delete", 43), ("recover-delete", 0)],
        [("router-crash-add", 42), ("router-recover", 0)],
        [("aliases-prepare", 0), ("aliases-recover", 0)],
        [("expire-prepare", 0), ("expire-recover", 0)],
        [("failed-checkpoint", 0), ("recover-empty", 0)],
        [("pause-prepare", 0), ("pause-recover", 0)],
        [("new-boot-prepare", 0), ("new-boot-recover", 0)],
        [("crash-add", 42), ("corrupt", 0)],
        [("lock", 0)],
    ]
    for number, phases in enumerate(scenarios):
        state = tmp_path / str(number)
        state.mkdir()
        for phase, code in phases:
            result = subprocess.run([str(executable), str(state), phase], capture_output=True, text=True, timeout=15)
            assert result.returncode == code, f"{phase}: {result.stdout}\n{result.stderr}"
