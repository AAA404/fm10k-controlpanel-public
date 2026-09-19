#!/usr/bin/env python3
"""Move an existing verified native installation to configd-owned L2 replay.

Install the matching native binaries and Web package first, then stop the
switch target. This operation changes startup policy, never the active
configuration, port mapping, management network, SDK or driver.
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
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.native_guard import BOOT, STATE, trusted_file, validate_initial_configuration, validate_replay_authority

DAEMONS = ("identityd", "switchd", "configd", "ifd", "packetd", "l2d", "stpd",
           "lacpd", "lldpd", "statsd", "chassisd", "linkmond", "mgmtd")


def replace(path: Path, content: bytes):
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600 if path.name.endswith(".json") else 0o644)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def stage():
    if os.geteuid() != 0 or ROOT != Path("/opt/fm10k-controlpanel/native"):
        raise ValueError("run the installed script as root on the Debian board")
    for daemon in DAEMONS:
        pid = subprocess.check_output(["systemctl", "show", "fm10k-" + daemon + ".service",
                                       "--property=MainPID", "--value"], text=True).strip()
        if pid != "0": raise ValueError("stop the switch target before staging: " + daemon)
    manifest_path = BOOT / "startup.json"
    env_path = Path("/etc/fm10k-controlpanel/native.env")
    original_manifest, original_env = trusted_file(manifest_path), trusted_file(env_path)
    manifest = json.loads(original_manifest)
    mode, profile = manifest.get("mode"), manifest.get("profile")
    if manifest.get("schema") != 1 or mode not in ("observe", "basic100g"):
        raise ValueError("expected an existing observation or basic100g installation")
    expected = {str(BOOT / name) for name in ("platform.profile", "fm_platform_attributes.cfg", "active.conf")}
    if set(manifest.get("sha256", {})) != expected:
        raise ValueError("incomplete startup manifest")
    for name, digest in manifest["sha256"].items():
        if hashlib.sha256(trusted_file(Path(name))).hexdigest() != digest:
            raise ValueError("startup artifact changed: " + name)
    validate_initial_configuration(trusted_file(BOOT / "active.conf"), profile, mode)
    seed = manifest.get("seed_commit_id", 1)
    if type(seed) is not int or not 1 <= seed <= 9999999999999999:
        raise ValueError("invalid seed revision")
    commit = validate_replay_authority(profile, seed)
    environment = dict(line.split("=", 1) for line in original_env.decode().splitlines() if line and not line.startswith("#"))
    if environment.get("NETLAB_FM10K_NATIVE") != "1" or environment.get("NETLAB_FM10K_OBSERVE_ONLY") != "1":
        raise ValueError("the prior native startup environment is not recognized")
    if environment.get("NETLAB_FM10K_STARTUP_MODE", "observe") != mode:
        raise ValueError("the prior environment and manifest disagree")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path("/var/backups/fm10k-controlpanel") / ("before-native-control-" + stamp)
    backup.mkdir(mode=0o700)
    shutil.copy2(manifest_path, backup / "startup.json")
    shutil.copy2(env_path, backup / "native.env")
    manifest.update(mode="control", bootstrap_mode=mode)
    environment.update(NETLAB_FM10K_OBSERVE_ONLY="0", NETLAB_FM10K_STARTUP_MODE="control")
    try:
        replace(manifest_path, (json.dumps(manifest, indent=2) + "\n").encode())
        replace(env_path, "".join(f"{key}={value}\n" for key, value in environment.items()).encode())
    except BaseException:
        replace(manifest_path, original_manifest)
        replace(env_path, original_env)
        raise
    print(json.dumps({"staged": "control", "profile": profile, "active_commit": commit,
                      "backup": str(backup), "replay_required": True}))


if __name__ == "__main__":
    stage()
