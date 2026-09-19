#!/usr/bin/env python3
"""Prepare the native observation release, then retire the legacy services.

Run on the Debian board, after building this exact source with the pinned SDK.
The two explicit phases keep the old owner running until the new artifacts,
identity, runtime libraries and service definitions have been checked.
"""
from __future__ import annotations

import argparse
import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.auth import Auth
from fm10k_controlpanel.https_setup import prepare as prepare_https
from fm10k_controlpanel.models import Credentials, SwitchConfiguration
from fm10k_controlpanel.native_guard import BOOT, STATE, trusted_file, validate_identity, validate_initial_configuration
from fm10k_controlpanel.netlab_codec import compile_configuration
from fm10k_controlpanel.platform_config import render_netlab_profile, render_sdk_platform
from fm10k_controlpanel.preflight import inventory
from fm10k_controlpanel.profiles import PROFILES
from build_deb import build as build_web

NATIVE = Path("/opt/fm10k-controlpanel/native")
DAEMONS = ("identityd", "switchd", "configd", "ifd", "packetd", "l2d", "stpd",
           "lacpd", "lldpd", "statsd", "chassisd", "linkmond", "mgmtd")
LEGACY = ("pe31625g24dira-switch-manager.service", "pe31625g24dira-fan-init.service",
          "pe31625g24dira-switch.service", "pe31625g24dira-board-init.service")


def run(*arguments, **options):
    return subprocess.run(list(arguments), check=True, text=True, **options)


def put(path: Path, text: str, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() != text:
        raise ValueError(f"refusing to overwrite different installation data: {path}")
    path.write_text(text)
    path.chmod(mode)


def save_json(path: Path, value):
    put(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n", 0o600)


def credentials():
    for group in ("netlab-ipc", "netlab-identityd", "netlab-chassisd", "fm10k-web"):
        try:
            grp.getgrnam(group)
        except KeyError:
            run("addgroup", "--system", group)
    for user in ("netlab-identityd", "netlab-chassisd", "fm10k-web"):
        try:
            pwd.getpwnam(user)
        except KeyError:
            run("adduser", "--system", "--ingroup", user, "--no-create-home", user)
    run("adduser", "fm10k-web", "netlab-ipc")


def service(name):
    dedicated = name in ("identityd", "chassisd")
    executable = f"{NATIVE}/vendor/netlab/build/"
    executable += f"netlab-daemon-launch {name}" if dedicated else name
    dependencies = "local-fs.target systemd-modules-load.service"
    if name != "identityd":
        dependencies += " fm10k-identityd.service"
    if name not in ("identityd", "switchd"):
        dependencies += " fm10k-switchd.service"
    if name not in ("identityd", "switchd", "configd"):
        dependencies += " fm10k-configd.service"
    return f"""[Unit]
Description=FM10840 native {name}
After={dependencies}
PartOf=fm10k-switch.target
Conflicts=fm10k-testpoint.service {' '.join(LEGACY)}

[Service]
Type=simple
User=root
Group=root
WorkingDirectory={NATIVE}/vendor/netlab
EnvironmentFile=/etc/fm10k-controlpanel/native.env
ExecStart={executable}
Restart=no
TimeoutStartSec=150
TimeoutStopSec=30
KillMode=control-group
{"PrivateIPC=yes" if name == "switchd" else ""}
UMask=0077

[Install]
WantedBy=fm10k-switch.target
"""


def prepare(management_ip):
    if ROOT != NATIVE:
        raise ValueError(f"install source must reside at {NATIVE}")
    report = inventory(bdf="0000:01:00.0")
    profile = report.get("profile")
    board = validate_identity(report, profile)
    addresses = json.loads(subprocess.check_output(["ip", "-j", "address", "show", "dev", "enp2s0"]))
    if management_ip not in {address["local"] for item in addresses for address in item["addr_info"]}:
        raise ValueError("HTTPS must use the existing enp2s0 management address")
    for name in (*DAEMONS, "netlab-daemon-launch", "netlab-internal-rpc"):
        binary = ROOT / "vendor/netlab/build" / name
        if binary.read_bytes()[:4] != b"\x7fELF":
            raise ValueError(f"missing native ELF binary: {name}")
    environment = dict(os.environ, LD_LIBRARY_PATH=str(ROOT / "hardware/sdk/ies/build") + ":/opt/netlab-deps/libyang2/lib")
    for name in ("switchd", "configd", "l2d"):
        result = run("ldd", "-r", str(ROOT / "vendor/netlab/build" / name),
                     env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if "not found" in result.stdout or "undefined symbol:" in result.stdout:
            raise ValueError(f"unresolved native dependency: {name}")
    credentials()
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.chmod(0o700)
    BOOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    for path in (STATE / "config/journal", STATE / "config/rollback", STATE / "scopes"):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
    config = SwitchConfiguration(profile=profile)
    netdevs = sorted(Path("/sys/bus/pci/devices/0000:01:00.0/net").iterdir())
    if len(netdevs) != 1:
        raise ValueError("ASIC CPU network device is ambiguous")
    mac = (netdevs[0] / "address").read_text().strip()
    serial = board["identity"]["serial"]
    sdk = render_sdk_platform((ROOT / PROFILES[profile].reference).read_text(), config)
    # IES stores the library name in a short fixed-size field. Keep the
    # basename; native_guard verifies the exact LD_LIBRARY_PATH and SDK hashes.
    files = {"fm_platform_attributes.cfg": sdk,
             "platform.profile": render_netlab_profile(config, system_mac=mac, serial=serial),
             "active.conf": compile_configuration(config).decode()}
    for name, text in files.items():
        put(BOOT / name, text)
    put(STATE / "config/rollback/0000000000000001.conf", files["active.conf"], 0o600)
    put(STATE / "config/journal/tx_counter", "1\n", 0o600)
    save_json(BOOT / "startup.json", {"schema": 1, "mode": "observe", "profile": profile,
        "sha256": {str(BOOT / name): hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()}})
    native_env = {
        "NETLAB_ROOT": str(ROOT / "vendor/netlab"), "NETLAB_CONFIG_DIR": str(STATE / "config"),
        "NETLAB_PLATFORM_PROFILE": str(BOOT / "platform.profile"),
        "NETLAB_PORT_SCOPE_DIR": str(STATE / "scopes"), "NETLAB_FM10K_NATIVE": "1",
        "NETLAB_FM10K_OBSERVE_ONLY": "1", "NETLAB_SWITCHD_DISABLE_PORT_RECOVERY": "1",
        "FM_API_SHM_KEY": "51701", "FM_LIBERTY_TRAIL_CONFIG_FILE": str(BOOT / "fm_platform_attributes.cfg"),
        "LD_LIBRARY_PATH": environment["LD_LIBRARY_PATH"],
    }
    put(Path("/etc/fm10k-controlpanel/native.env"), "".join(f"{key}={value}\n" for key, value in native_env.items()))
    runtime = Path("/run/netlab")
    runtime.mkdir(mode=0o711, exist_ok=True)
    runtime.chmod(0o711)
    put(Path("/etc/tmpfiles.d/fm10k-controlpanel.conf"), "d /run/netlab 0711 root root -\n")
    put(Path("/etc/modules-load.d/fm10k-controlpanel.conf"), "i2c_i801\ni2c-dev\nfm10k\n")
    for name in DAEMONS:
        put(Path(f"/etc/systemd/system/fm10k-{name}.service"), service(name))
    put(Path("/etc/systemd/system/fm10k-switch.target"),
        "[Unit]\nDescription=FM10840 native hardware observation\nWants=" +
        " ".join(f"fm10k-{name}.service" for name in DAEMONS) +
        "\nConflicts=fm10k-testpoint.service " + " ".join(LEGACY) +
        "\nAfter=local-fs.target\n\n[Install]\nWantedBy=multi-user.target\n")
    panel_env = ("PANEL_BACKEND=netlab\nPANEL_STATE_DIR=/var/lib/fm10k-controlpanel\n"
                 "PANEL_STATIC_DIR=/usr/share/fm10k-controlpanel/web\n"
                 "PANEL_NETLAB_ROOT=/usr/lib/fm10k-controlpanel/netlab\nPANEL_SECURE_COOKIE=1\n")
    put(Path("/etc/fm10k-controlpanel/panel.env"), panel_env)
    package = ROOT / "artifacts/fm10k-controlpanel_0.1.0~hwobs1_all.deb"
    build_web(ROOT, package, "0.1.0~hwobs1", 0)
    run("dpkg", "--force-confold", "-i", str(package))
    auth_dir = Path("/var/lib/fm10k-controlpanel")
    auth = Auth(auth_dir)
    if not auth.initialized:
        password = secrets.token_urlsafe(24)
        auth.setup(Credentials(username="admin", password=password))
        user = pwd.getpwnam("fm10k-web")
        os.chown(auth.path, user.pw_uid, user.pw_gid)
        save_json(STATE / "initial-admin.json", {"username": "admin", "password": password,
                                               "url": f"https://{management_ip}"})
    https = STATE / "https-files"
    if not https.exists():
        prepare_https(https, ROOT / "deploy/nginx/fm10k-controlpanel.conf.in", management_ip, management_ip, days=365)
    tls = Path("/etc/fm10k-controlpanel/tls")
    tls.mkdir(mode=0o700, exist_ok=True)
    for name, mode in (("server.crt", 0o644), ("server.key", 0o600)):
        put(tls / name, (https / name).read_text(), mode)
    site = Path("/etc/nginx/sites-available/fm10k-controlpanel")
    text = (https / "fm10k-controlpanel.conf").read_text()
    text += f"\nserver {{ listen {management_ip}:80; server_name {management_ip}; return 308 https://{management_ip}$request_uri; }}\n"
    put(site, text)
    enabled = Path("/etc/nginx/sites-enabled/fm10k-controlpanel")
    if not enabled.exists(): enabled.symlink_to(site)
    default = Path("/etc/nginx/sites-enabled/default")
    if default.is_symlink() and default.resolve() == Path("/etc/nginx/sites-available/default"):
        default.unlink()
    put(Path("/etc/systemd/system/nginx.service.d/fm10k-startup.conf"),
        (ROOT / "deploy/systemd/nginx.service.d/fm10k-startup.conf").read_text())
    run("nginx", "-t")
    run("systemd-analyze", "verify", *[f"/etc/systemd/system/fm10k-{name}.service" for name in DAEMONS])
    run("systemctl", "daemon-reload")
    save_json(STATE / "prepared.json", {"profile": profile, "management_ip": management_ip,
        "mode": "observe", "configuration_writes": False, "legacy_retired": False})
    print("Native artifacts prepared; legacy owner has not been stopped.")


def refresh_boot():
    """Regenerate SDK startup input without replacing configd's installation."""
    if ROOT != NATIVE:
        raise ValueError(f"install source must reside at {NATIVE}")
    state = subprocess.check_output([
        "systemctl", "show", "fm10k-switchd.service", "--property=MainPID", "--value",
    ], text=True).strip()
    if state != "0":
        raise ValueError("stop fm10k-switchd before refreshing its startup artifact")
    manifest = json.loads(trusted_file(BOOT / "startup.json"))
    profile = manifest["profile"]
    mode = manifest.get("mode")
    if manifest.get("schema") != 1 or mode not in ("observe", "basic100g"):
        raise ValueError("only an existing fixed native installation can be refreshed")
    expected = {str(BOOT / name) for name in ("platform.profile", "fm_platform_attributes.cfg", "active.conf")}
    if set(manifest.get("sha256", {})) != expected:
        raise ValueError("incomplete startup manifest")
    for path, digest in manifest["sha256"].items():
        if hashlib.sha256(trusted_file(Path(path))).hexdigest() != digest:
            raise ValueError(f"existing startup artifact changed: {path}")
    raw = trusted_file(BOOT / "active.conf")
    config = validate_initial_configuration(raw, profile, mode)
    seed = manifest.get("seed_commit_id", 1)
    if type(seed) is not int or not 1 <= seed <= 9999999999999999:
        raise ValueError("invalid installed seed revision")
    if trusted_file(STATE / "config/journal/tx_counter") != f"{seed}\n".encode() or \
            trusted_file(STATE / f"config/rollback/{seed:016x}.conf") != raw:
        raise ValueError("configuration authority has changed; native refresh refused")
    validate_identity(inventory(bdf="0000:01:00.0"), profile)
    sdk = render_sdk_platform((ROOT / PROFILES[profile].reference).read_text(), config).encode()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path("/var/backups/fm10k-controlpanel") / ("boot-" + stamp)
    backup.mkdir(mode=0o700, parents=True)
    for name in ("startup.json", "fm_platform_attributes.cfg"):
        shutil.copy2(BOOT / name, backup / name)
    manifest["sha256"][str(BOOT / "fm_platform_attributes.cfg")] = hashlib.sha256(sdk).hexdigest()
    for name, data, mode in (
        ("fm_platform_attributes.cfg", sdk, 0o644),
        ("startup.json", (json.dumps(manifest, indent=2) + "\n").encode(), 0o600),
    ):
        temporary = BOOT / (name + ".new")
        with temporary.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        temporary.replace(BOOT / name)
    print(json.dumps({"boot_refreshed": True, "profile": profile, "backup": str(backup),
                      "configuration_unchanged": True}))


def cutover():
    json.loads((STATE / "prepared.json").read_text())
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = Path("/var/backups/fm10k-controlpanel") / ("legacy-" + stamp)
    backup.mkdir(mode=0o700, parents=True)
    paths = [Path(name) for name in ("/etc/pe31625g24dira", "/opt/pe31625g24dira-switch-manager",
             "/opt/silicom-legacy", "/usr/local/rrc", "/usr/share/netfab/fm_platform_attributes.cfg")]
    paths.extend(Path("/usr/local/sbin").glob("pe31625g24dira-*"))
    for root in (Path("/etc/systemd/system"), Path("/usr/lib/systemd/system")):
        for unit in LEGACY:
            paths.extend(path for path in (root / unit, root / (unit + ".d")) if path.exists())
    paths = sorted({path for path in paths if path.exists()})
    evidence = {}
    for unit in LEGACY:
        evidence[unit] = subprocess.run(["systemctl", "show", unit, "-p", "ActiveState", "-p", "MainPID",
                                        "-p", "FragmentPath", "-p", "ExecStart"], text=True, capture_output=True).stdout
    save_json(backup / "services-before.json", evidence)
    run("tar", "--acls", "--xattrs", "-czf", str(backup / "legacy.tar.gz"), "-C", "/",
        *[str(path).lstrip("/") for path in paths])
    archive = backup / "legacy.tar.gz"
    save_json(backup / "archive.json", {"sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                                        "paths": [str(path) for path in paths]})
    run("tar", "-tzf", str(archive), stdout=subprocess.DEVNULL)
    run("systemctl", "disable", "--now", *LEGACY)
    for unit in LEGACY:
        if subprocess.run(["systemctl", "is-active", "--quiet", unit]).returncode == 0:
            raise ValueError(f"legacy unit did not stop: {unit}")
    for path in paths:
        destination = backup / "removed" / str(path).lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(destination))
    run("systemctl", "daemon-reload")
    run("systemctl", "mask", *LEGACY, "rrcd.service", "netfabagent.service", "hmonagent.service")
    run("systemctl", "enable", "fm10k-switch.target", "fm10k-panel.service", "nginx.service")
    run("systemctl", "start", "fm10k-switch.target")
    run("systemctl", "restart", "fm10k-panel.service")
    run("systemctl", "start", "nginx.service")
    save_json(STATE / "cutover.json", {"legacy_backup": str(backup), "legacy_units": LEGACY,
                                       "new_target": "fm10k-switch.target", "mode": "observe"})
    print(json.dumps({"legacy_backup": str(backup), "native_target_started": True, "configuration_writes": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "cutover", "refresh-boot"))
    parser.add_argument("--management-ip", help="required for prepare: this board's management IP")
    args = parser.parse_args()
    if args.phase == "prepare" and not args.management_ip:
        parser.error("prepare requires --management-ip")
    if os.geteuid() != 0: parser.error("run as root on the Debian board")
    if args.phase == "prepare":
        prepare(args.management_ip)
    elif args.phase == "refresh-boot":
        refresh_boot()
    else:
        cutover()


if __name__ == "__main__":
    main()
