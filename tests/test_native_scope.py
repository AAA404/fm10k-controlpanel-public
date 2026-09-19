import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_scope_coordinator_faults_and_restart(tmp_path):
    binary = tmp_path / "scope-coordinator-test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "vendor/netlab/include"),
                    str(ROOT / "tests/native_scope_coordinator_test.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=20)


@pytest.fixture
def scope_binary(tmp_path):
    binary = tmp_path / "scope-test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "vendor/netlab/include"),
                    str(ROOT / "tests/native_scope_test.c"),
                    str(ROOT / "vendor/netlab/lib/libipc/port_scope.c"), "-pthread", "-o", str(binary)], check=True)
    return binary


def test_scope_concurrent_target_drain_and_packet_epoch(scope_binary):
    subprocess.run([str(scope_binary)], check=True, timeout=20,
                   env={**os.environ, "NETLAB_FM10K_NATIVE": "0"})


def test_scope_restart_persistence_and_degraded_hold(scope_binary, tmp_path):
    state = tmp_path / "scopes"
    env = {**os.environ, "NETLAB_FM10K_NATIVE": "1", "NETLAB_PORT_SCOPE_DIR": str(state)}
    for mode in ("persist", "restore", "persist", "expand", "expanded", "degrade", "degraded"):
        subprocess.run([str(scope_binary), mode], env=env, check=True, timeout=10)
    text = (state / "testd.state").read_text()
    assert text.startswith("FM10K_SCOPE_V3 ") and text.split()[3] == "1"
    # Old records remain readable and are upgraded without releasing their ports.
    (state / "testd.state").write_text("FM10K_SCOPE_V2 000000000000007b 0000000f 1 0\n")
    subprocess.run([str(scope_binary), "expand"], env=env, check=True, timeout=10)
    subprocess.run([str(scope_binary), "expanded"], env=env, check=True, timeout=10)


@pytest.mark.parametrize("invalid", ["truncated", "symlink", "permissions"])
def test_scope_rejects_untrusted_persistent_state(scope_binary, tmp_path, invalid):
    state = tmp_path / "scopes"
    state.mkdir(mode=0o700)
    path = state / "testd.state"
    if invalid == "symlink":
        external = tmp_path / "untouched"
        external.write_text("original")
        path.symlink_to(external)
    else:
        path.write_text("invalid" if invalid == "truncated" else "FM10K_SCOPE_V2 000000000000007b 0000000f 1 0\n")
        path.chmod(0o600 if invalid == "truncated" else 0o666)
    subprocess.run([str(scope_binary), "invalid"], check=True, timeout=10,
                   env={**os.environ, "NETLAB_FM10K_NATIVE": "1", "NETLAB_PORT_SCOPE_DIR": str(state)})
    if invalid == "symlink":
        assert external.read_text() == "original"
def test_scope_clock_boundary(tmp_path):
    root = Path(__file__).resolve().parents[1]
    binary = tmp_path / "scope-clock-test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root / "vendor/netlab/include"), str(root / "tests/native_scope_clock_test.c"),
                    "-pthread", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10, env={**os.environ, "NETLAB_FM10K_NATIVE": "0"})
