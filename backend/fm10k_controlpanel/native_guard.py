"""Fresh, privileged startup checks for the native observation deployment.

switchd holds the ASIC lock while invoking this helper before fmOSInitialize.
No saved preflight report can authorize startup. Configuration writes remain
closed until native replay and recovery have been integrated separately.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess

from .models import PHYSICAL, SwitchConfiguration
from .netlab_codec import decode_configuration, parse_xml
from .preflight import inventory

ROOT = Path("/opt/fm10k-controlpanel/native")
BOOT = Path("/etc/fm10k-controlpanel/native")
STATE = Path("/var/lib/fm10k-controlpanel-native")
CPU_DEVICE = Path("/sys/bus/pci/devices/0000:01:00.0")


def trusted_file(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid or metadata.st_mode & 0o022:
        raise ValueError(f"untrusted startup file: {path}")
    for parent in path.parents:
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid or metadata.st_mode & 0o022:
            raise ValueError(f"untrusted startup directory: {parent}")
    return path.read_bytes()


def initial_configuration(profile: str, mode: str = "observe") -> SwitchConfiguration:
    expected = SwitchConfiguration(profile=profile)
    if mode == "observe":
        return expected
    if mode != "basic100g":
        raise ValueError("unknown native startup mode")
    data = expected.model_dump()
    data["vlans"] = [{"id": 1, "name": "100G connectivity test"}]
    data["rstp"]["enabled"] = data["lldp"]["enabled"] = False
    for physical in PHYSICAL.values():
        port = data["ports"][physical["base"]]
        port.update(enabled=True, pvid=1, lldp=False,
                    name=f"MPO{physical['mpo']}-EPL{physical['epl']}-100G")
    return SwitchConfiguration.model_validate(data)


def validate_initial_configuration(raw: bytes, profile: str, mode: str = "observe") -> SwitchConfiguration:
    config = decode_configuration(raw)
    expected = initial_configuration(profile, mode)
    if config != expected:
        raise ValueError(f"native startup requires the exact installed {mode} configuration")
    return config


def validate_replay_authority(profile: str, seed: int) -> int:
    """Check configd's current immutable snapshot without replacing it.

    Historical seed snapshots may have been compacted. The pinned boot seed
    describes a closed hardware baseline, while tx_counter selects the only
    configuration that the control service may replay after initialization.
    """
    pointer_path = STATE / "config/journal/tx_counter"
    pointer = trusted_file(pointer_path)
    if not re.fullmatch(rb"[1-9][0-9]{0,15}\n", pointer):
        raise ValueError("invalid active configuration pointer")
    commit = int(pointer)
    if commit < seed:
        raise ValueError("active configuration predates the installed seed")
    raw = trusted_file(STATE / f"config/rollback/{commit:016x}.conf")
    config = decode_configuration(raw)
    tree = parse_xml(raw)
    if config.profile != profile or tree.findtext("./chassis/fm10k-panel/profile") != profile:
        raise ValueError("active configuration targets a different board profile")
    if any(tree.find(path) is not None for path in (
        "./routing-options", "./routing-instances", "./interfaces-routing",
        "./protocols/ospf", "./protocols/bgp")):
        raise ValueError("L3 intent cannot be replayed by this L2-only release")
    if trusted_file(pointer_path) != pointer:
        raise ValueError("configuration authority changed during startup validation")
    return commit


def validate_identity(report: dict, profile: str) -> dict:
    if not report.get("preflight_passed") or report.get("profile") != profile:
        raise ValueError("fresh PCI/VPD/driver/UIO identity does not match the selected profile")
    devices = report.get("devices", [])
    if len(devices) != 1 or devices[0].get("bdf") != "0000:01:00.0":
        raise ValueError("native observation deployment requires the verified PCI function 0000:01:00.0")
    return devices[0]


def check_other_owners(parent: int) -> None:
    device = Path("/sys/bus/pci/devices/0000:01:00.0").resolve()
    targets = ("/dev/uio0", str(device / "resource0"), str(device / "resource2"))
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal() or int(process.name) in (parent, os.getpid()):
            continue
        try:
            maps = (process / "maps").read_text()
            descriptors = [os.readlink(item) for item in (process / "fd").iterdir()]
        except (FileNotFoundError, ProcessLookupError):
            continue
        if any(target in maps or target in descriptors for target in targets):
            raise ValueError(f"another process owns the ASIC mapping: pid={process.name}")


def prepare_power() -> None:
    adapters = [item.parent for item in Path("/sys/class/i2c-dev").glob("i2c-*/name")
                if item.read_text().startswith("SMBus I801 adapter")]
    if len(adapters) != 1 or not re.fullmatch(r"i2c-\d+", adapters[0].name):
        raise ValueError("the board power I801 adapter is ambiguous or missing")
    bus = adapters[0].name[4:]
    def read():
        return int(subprocess.check_output(["/usr/sbin/i2cget", "-y", bus, "0x36", "0x00"],
                                          text=True, timeout=5).strip(), 16)
    if read() != 0x3c:
        subprocess.run(["/usr/sbin/i2cset", "-y", bus, "0x36", "0x00", "0x3c"],
                       check=True, timeout=5)
        if read() != 0x3c:
            raise ValueError("board power write did not latch")


def prepare_cpu_network() -> dict:
    """Enable host DMA on the already verified ASIC function before SDK init."""
    interfaces = list((CPU_DEVICE / "net").iterdir())
    if len(interfaces) != 1 or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interfaces[0].name):
        raise ValueError("the verified ASIC CPU network interface is ambiguous or missing")
    interface = interfaces[0]
    mtu = int((interface / "mtu").read_text())
    flags = int((interface / "flags").read_text(), 16)
    if mtu < 1518 or not flags & 1:
        subprocess.run(["/usr/sbin/ip", "link", "set", "dev", interface.name,
                        "mtu", str(max(mtu, 1518)), "up"], check=True, timeout=10)
    mtu = int((interface / "mtu").read_text())
    if mtu < 1518 or not int((interface / "flags").read_text(), 16) & 1:
        raise ValueError("the ASIC CPU network interface did not become administratively ready")
    # Carrier can remain down until fmSetSwitchState; only IFF_UP is required.
    return {"interface": interface.name, "mtu": mtu, "admin_up": True}


def verify_startup(profile: str) -> dict:
    if os.geteuid() != 0:
        raise ValueError("native startup checks require root")
    from .update_gate import verify_update_gate
    verify_update_gate()
    # Vendor shared memory retains process pointers and non-robust locks.
    # A fresh systemd IPC namespace makes every SDK lifetime independent.
    if os.readlink("/proc/self/ns/ipc") == os.readlink("/proc/1/ns/ipc"):
        raise ValueError("switchd requires systemd PrivateIPC=yes before SDK startup")
    manifest = json.loads(trusted_file(BOOT / "startup.json"))
    mode = manifest.get("mode")
    if manifest.get("schema") != 1 or mode not in ("observe", "basic100g", "control") or manifest.get("profile") != profile:
        raise ValueError("the native installation is not explicitly configured")
    if os.environ.get("NETLAB_FM10K_STARTUP_MODE", "observe") != mode:
        raise ValueError("startup mode differs from the installed manifest")
    expected_environment = {
        "NETLAB_ROOT": str(ROOT / "vendor/netlab"),
        "NETLAB_PLATFORM_PROFILE": str(BOOT / "platform.profile"),
        "FM_LIBERTY_TRAIL_CONFIG_FILE": str(BOOT / "fm_platform_attributes.cfg"),
        "NETLAB_CONFIG_DIR": str(STATE / "config"),
        "NETLAB_FM10K_OBSERVE_ONLY": "0" if mode == "control" else "1",
        "FM_API_SHM_KEY": "51701",
        "LD_LIBRARY_PATH": str(ROOT / "hardware/sdk/ies/build") + ":/opt/netlab-deps/libyang2/lib",
    }
    if any(os.environ.get(key) != value for key, value in expected_environment.items()):
        raise ValueError("native startup environment does not match the installed release")
    expected_files = {str(BOOT / name) for name in ("platform.profile", "fm_platform_attributes.cfg", "active.conf")}
    if set(manifest.get("sha256", {})) != expected_files:
        raise ValueError("incomplete boot artifact manifest")
    for path, digest in manifest["sha256"].items():
        if hashlib.sha256(trusted_file(Path(path))).hexdigest() != digest:
            raise ValueError(f"startup artifact changed: {path}")
    raw = trusted_file(BOOT / "active.conf")
    bootstrap_mode = manifest.get("bootstrap_mode") if mode == "control" else mode
    if bootstrap_mode not in ("observe", "basic100g"):
        raise ValueError("control startup requires an explicit fixed bootstrap baseline")
    validate_initial_configuration(raw, profile, bootstrap_mode)
    seed = manifest.get("seed_commit_id", 1)
    if type(seed) is not int or seed < 1 or seed > 9999999999999999:
        raise ValueError("invalid installed configuration revision")
    if mode == "control":
        active_commit = validate_replay_authority(profile, seed)
    else:
        if trusted_file(STATE / "config/journal/tx_counter") != f"{seed}\n".encode() or \
           trusted_file(STATE / f"config/rollback/{seed:016x}.conf") != raw:
            raise ValueError("native startup cannot replace an existing configuration or pending transaction")
        active_commit = seed
    report = inventory(bdf="0000:01:00.0")
    validate_identity(report, profile)
    uio = Path("/sys/class/uio/uio0/device").resolve()
    if uio != Path("/sys/bus/pci/devices/0000:01:00.0").resolve() or not stat.S_ISCHR(Path("/dev/uio0").stat().st_mode):
        raise ValueError("/dev/uio0 does not map to the independently identified board")
    parent = os.getppid()
    if Path(f"/proc/{parent}/exe").resolve() != ROOT / "vendor/netlab/build/switchd":
        raise ValueError("startup helper was not invoked by the installed switchd")
    sdk_manifest = json.loads(trusted_file(ROOT / "hardware/sdk-inputs.json"))
    for entry in sdk_manifest["libraries"]:
        library = ROOT / "hardware/sdk/ies/build" / Path(entry["suffix"]).name
        if hashlib.sha256(trusted_file(library)).hexdigest() != entry["sha256"]:
            raise ValueError("SDK library no longer matches the locked build input")
    maps = Path(f"/proc/{parent}/maps").read_text()
    sdk_path = str(ROOT / "hardware/sdk/ies/build/libFocalpointSDK.so")
    sdk_mappings = {line.split()[-1] for line in maps.splitlines() if "libFocalpointSDK.so" in line}
    if sdk_mappings != {sdk_path}:
        raise ValueError("switchd loaded a different SDK library")
    check_other_owners(parent)
    prepare_power()
    cpu_network = prepare_cpu_network()
    (STATE / "preflight-latest.json").write_text(json.dumps(report, indent=2) + "\n")
    (STATE / "preflight-latest.json").chmod(0o600)
    return {"profile": profile, "startup": mode, "identity": "verified", "configuration_writes": False,
            "active_commit_id": active_commit, "replay_required": mode == "control", "cpu_network": cpu_network}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=("sil001-hw4-b0", "sil001-hw5-a11"))
    args = parser.parse_args()
    signal.alarm(45)
    try:
        result = verify_startup(args.profile)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Native startup refused: {error}\n")
    print(json.dumps(result))
    return 0
