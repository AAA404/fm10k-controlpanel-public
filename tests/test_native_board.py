import shutil
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_fan_cold_boot_prepares_resolution_before_full_speed(tmp_path):
    binary = tmp_path / "native-fan-boot-test"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "hardware/native"),
                    str(ROOT / "hardware/native/fm10k_board.c"),
                    str(ROOT / "tests/native_fan_boot_test.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)


def test_obt_setup_preserves_other_engine_and_rolls_back_ambiguous_writes(tmp_path):
    binary = tmp_path / "native-obt-setup-test"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "hardware/native"),
                    str(ROOT / "hardware/native/fm10k_board.c"),
                    str(ROOT / "tests/native_obt_setup_test.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


def test_native_board_faults_and_isolation(tmp_path):
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("C compiler not installed")
    binary = tmp_path / "native-board-test"
    subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "hardware/native"),
                    str(ROOT / "hardware/native/fm10k_board.c"),
                    str(ROOT / "tests/native_board_test.c"), "-o", str(binary)], check=True)
    result = subprocess.run([str(binary)], text=True, capture_output=True, check=True)
    assert "six-EPL isolation and timers passed" in result.stdout


def test_native_sampling_and_bus_restoration(tmp_path):
    binary = tmp_path / "native-sampling-test"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "hardware/native"),
                    str(ROOT / "hardware/native/fm10k_board.c"),
                    str(ROOT / "tests/native_sampling_test.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


def test_native_monitor_deadlines_and_cache(tmp_path):
    binary = tmp_path / "native-monitor-test"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "hardware/native"),
                    str(ROOT / "hardware/native/fm10k_board.c"),
                    str(ROOT / "hardware/native/fm10k_monitor.c"),
                    str(ROOT / "tests/native_monitor_test.c"), "-lm", "-o", str(binary)], check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    snapshot = json.loads(result.stdout)
    assert snapshot["board_hal"] == "unbound"
    assert snapshot["profile"] == "sil001-hw4-b0"
    assert snapshot["sensors"]["temperatures"][0]["celsius"] == 45.125
    assert snapshot["sensors"]["fan"]["rpm"] == 1512
    assert snapshot["optics"][0]["tx_enable_mask"] == 0x112
    assert snapshot["optics"][0]["rx_power"] is None


def test_native_fan_transaction_images(tmp_path):
    binary = tmp_path / "native-fan-transaction-test"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "hardware/native"),
                    str(ROOT / "hardware/native/fm10k_board.c"),
                    str(ROOT / "hardware/native/fm10k_monitor.c"),
                    str(ROOT / "tests/native_fan_transaction_test.c"), "-lm", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
