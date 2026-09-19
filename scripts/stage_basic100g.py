#!/usr/bin/env python3
"""Stage the fixed six-port 100G test baseline on the dedicated Debian board.

Stop fm10k-switch.target first. This migration accepts only the untouched
observation seed and preserves its immutable snapshot as revision 1. It does
not enable the incomplete generic configuration transaction contract.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.native_guard import (
    BOOT, STATE, ROOT as INSTALLED, initial_configuration, trusted_file,
    validate_identity, validate_initial_configuration,
)
from fm10k_controlpanel.netlab_codec import compile_configuration
from fm10k_controlpanel.platform_config import render_sdk_platform, render_netlab_profile
from fm10k_controlpanel.preflight import inventory
from fm10k_controlpanel.profiles import PROFILES


def atomic(path, data, mode=0o600):
    temporary = path.with_name(path.name + ".new")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(mode)
    temporary.replace(path)


def main():
    if os.geteuid() or ROOT != INSTALLED:
        raise ValueError("run the installed source as root on the dedicated Debian board")
    target = subprocess.check_output(["systemctl", "show", "fm10k-switch.target",
                                      "-p", "ActiveState", "--value"], text=True).strip()
    if target not in ("inactive", "deactivating", "failed"):
        raise ValueError("stop fm10k-switch.target before changing the installation baseline")
    # The target's stop job may complete before all PartOf services exit.
    # Wait for their existing stop jobs; do not terminate or restart services.
    deadline = time.monotonic() + 35
    while True:
        pids = {unit: subprocess.check_output(["systemctl", "show", unit,
                    "-p", "MainPID", "--value"], text=True).strip()
                for unit in ("fm10k-switchd.service", "fm10k-configd.service")}
        if all(pid == "0" for pid in pids.values()):
            break
        if time.monotonic() >= deadline:
            raise ValueError(f"native services have not finished stopping: {pids}")
        time.sleep(0.25)
    manifest = json.loads(trusted_file(BOOT / "startup.json"))
    if manifest.get("schema") != 1 or manifest.get("mode") != "observe" or manifest.get("seed_commit_id", 1) != 1:
        raise ValueError("only the initial observation installation can become the fixed 100G test baseline")
    expected = {str(BOOT / n) for n in ("active.conf", "platform.profile", "fm_platform_attributes.cfg")}
    if set(manifest.get("sha256", {})) != expected:
        raise ValueError("incomplete startup manifest")
    for path, digest in manifest["sha256"].items():
        if hashlib.sha256(trusted_file(Path(path))).hexdigest() != digest:
            raise ValueError(f"existing startup artifact changed: {path}")
    profile = manifest["profile"]
    raw = trusted_file(BOOT / "active.conf")
    validate_initial_configuration(raw, profile)
    if trusted_file(STATE / "config/journal/tx_counter") != b"1\n" or \
            trusted_file(STATE / "config/rollback/0000000000000001.conf") != raw:
        raise ValueError("configuration authority changed; fixed-baseline migration refused")
    board = validate_identity(inventory(bdf="0000:01:00.0"), profile)
    netdevs = sorted(Path("/sys/bus/pci/devices/0000:01:00.0/net").iterdir())
    if len(netdevs) != 1:
        raise ValueError("ASIC CPU network device is ambiguous")
    config = initial_configuration(profile, "basic100g")
    files = {
        "active.conf": compile_configuration(config),
        "platform.profile": render_netlab_profile(config,
            system_mac=(netdevs[0] / "address").read_text().strip(),
            serial=board["identity"]["serial"]).encode(),
        "fm_platform_attributes.cfg": render_sdk_platform(
            (ROOT / PROFILES[profile].reference).read_text(), config).encode(),
    }
    seed = STATE / "config/rollback/0000000000000002.conf"
    if seed.exists():
        raise ValueError("revision 2 already exists; refusing to replace an immutable snapshot")
    env_path = Path("/etc/fm10k-controlpanel/native.env")
    environment = trusted_file(env_path).decode()
    if "NETLAB_FM10K_STARTUP_MODE=" in environment:
        raise ValueError("startup mode was already customized")
    environment += "NETLAB_FM10K_STARTUP_MODE=basic100g\n"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path("/var/backups/fm10k-controlpanel") / ("before-basic100g-" + stamp)
    backup.mkdir(mode=0o700, parents=True)
    for name in (*files, "startup.json"):
        shutil.copy2(BOOT / name, backup / name)
    shutil.copy2(env_path, backup / "native.env")
    shutil.copy2(STATE / "config/journal/tx_counter", backup / "tx_counter")
    manifest.update(mode="basic100g", seed_commit_id=2,
                    sha256={str(BOOT / name): hashlib.sha256(data).hexdigest() for name, data in files.items()})
    atomic(seed, files["active.conf"])
    for name, data in files.items():
        atomic(BOOT / name, data, 0o644)
    atomic(env_path, environment.encode(), 0o644)
    atomic(STATE / "config/journal/tx_counter", b"2\n")
    atomic(BOOT / "startup.json", (json.dumps(manifest, indent=2) + "\n").encode())
    print(json.dumps({"staged": "basic100g", "profile": profile, "vlan": 1,
                      "ports": [1, 5, 9, 13, 17, 21], "backup": str(backup),
                      "full_configuration_writes": False}))


if __name__ == "__main__":
    main()
