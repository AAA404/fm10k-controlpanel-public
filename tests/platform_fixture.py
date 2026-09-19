"""Artificial platform inputs for software tests, never for hardware use.

The CLI harness substitutes the input registry only in its own test process.
Production entry points have no test flag or digest override.
"""
from dataclasses import replace
import hashlib
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.profiles import PROFILES


def reference_text(profile: str) -> str:
    lines = [
        "# ARTIFICIAL TEST INPUT: not a manufacturer configuration.",
        "api.platform.config.platformName text sil001",
        "api.platform.config.switch.0.numPorts int 12",
        "api.platform.config.switch.0.cpuPort int 9",
        "api.platform.config.switch.0.fci text on",
        "api.platform.config.sharedLibraryName text libLTStdPlatform.so",
        "api.perLagManagement bool false",
        "api.mailbox.ignoreMbxMacUpdates bool true",
        "api.event.countLogicalPortEvents bool true",
    ]
    if profile == "sil001-hw5-a11":
        lines.append("api.platform.config.switch.0.port.default.lanePolarity text INVERT_NONE")
    for port in range(1, 7):
        prefix = f"api.platform.config.switch.0.portIndex.{port}."
        lines.append(prefix + "linkOptimMode text QUALITY")
        for lane in range(4):
            if profile == "sil001-hw4-b0":
                polarity = "INVERT_RX" if lane % 2 else "INVERT_NONE"
                lines.append(prefix + f"lane.{lane}.lanePolarity text {polarity}")
            # Deliberately distinct invented values detect incorrect Lane copies.
            for name, value in (("rxTermination", port * 10 + lane),
                                ("preCursor25GOptical", -port - lane),
                                ("cursor25GOptical", lane),
                                ("postCursor25GOptical", port + lane)):
                lines.append(prefix + f"lane.{lane}.{name} int {value}")
    return "\n".join(lines) + "\n"


def install_test_profiles(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    for name, spec in tuple(PROFILES.items()):
        data = reference_text(name).encode()
        path = directory / (name + ".cfg")
        path.write_bytes(data)
        PROFILES[name] = replace(spec, reference=str(path), sha256=hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    install_test_profiles(Path(sys.argv[1]))
    entry = ROOT / "scripts/generate_boot.py"
    sys.argv = [str(entry), *sys.argv[2:]]
    runpy.run_path(str(entry), run_name="__main__")
