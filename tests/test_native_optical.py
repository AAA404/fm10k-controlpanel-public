from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("fixture,sources", [
    ("native_eye_scan_test.c", ["fm10k_eye_scan.c"]),
    ("native_optical_power_test.c", ["fm10k_board.c", "fm10k_monitor.c"]),
])
def test_native_optical_faults(tmp_path, fixture, sources):
    binary = tmp_path / "test-optical"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "hardware/native"),
                    *[str(ROOT / "hardware/native" / source) for source in sources],
                    str(ROOT / "tests" / fixture), "-lm", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
