"""Read CPU DTS through Linux sysfs; never touch the switch SDK or I2C mux."""
from __future__ import annotations

import copy
import math
import time
from pathlib import Path


class AtomTemperature:
    THERMAL_TYPES = {"x86_pkg_temp", "coretemp", "soc_dts0", "soc_dts1", "intel_soc_dts_thermal"}

    def __init__(self, sysfs: Path = Path("/sys"), clock=time.time):
        self.sysfs, self.clock = sysfs, clock
        self.last = None

    @staticmethod
    def _value(path):
        value = int(path.read_text().strip()) / 1000
        if not math.isfinite(value) or not -20 <= value <= 125:
            raise ValueError("CPU temperature outside supported DTS range")
        return value

    def sample(self):
        candidates = []
        for directory in sorted((self.sysfs / "class/hwmon").glob("hwmon*")):
            try:
                name = (directory / "name").read_text().strip()
            except OSError:
                continue
            if name != "coretemp":
                continue
            for path in sorted(directory.glob("temp*_input")):
                try:
                    label_path = path.with_name(path.name.replace("_input", "_label"))
                    label = label_path.read_text().strip() if label_path.exists() else ""
                    # Do not assign an unrelated board/ACPI temperature to CPU.
                    if not (label.lower().startswith("package id") or label.lower().startswith("core ")):
                        continue
                    rank = 0 if label.lower().startswith("package id") else 1
                    candidates.append((rank, self._value(path), f"Linux coretemp · {label}", str(path)))
                except (OSError, ValueError, OverflowError):
                    continue
        if not candidates:
            for directory in sorted((self.sysfs / "class/thermal").glob("thermal_zone*")):
                try:
                    kind = (directory / "type").read_text().strip()
                    if kind in self.THERMAL_TYPES:
                        path = directory / "temp"
                        candidates.append((2, self._value(path), f"Linux thermal · {kind}", str(path)))
                except (OSError, ValueError, OverflowError):
                    continue
        if candidates:
            rank = min(item[0] for item in candidates)
            _, value, source, path = max((item for item in candidates if item[0] == rank), key=lambda item: item[1])
            self.last = {"id": "atom_cpu", "label": "Intel Atom CPU", "celsius": value, "source": source,
                         "sampled_at": self.clock(), "quality": "valid", "sensor_path": path}
            return copy.deepcopy(self.last)
        if self.last:
            return {**copy.deepcopy(self.last), "quality": "stale", "error": "CPU DTS 读取失败，保留最后成功采样"}
        return {"id": "atom_cpu", "label": "Intel Atom CPU", "celsius": None, "source": "Linux CPU DTS",
                "sampled_at": None, "quality": "unavailable",
                "error": "未找到可读的 CPU DTS；请核对 coretemp / Intel SoC DTS 驱动"}
