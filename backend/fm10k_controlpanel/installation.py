"""Explicit native installation and checkpointed, paired native/Web upgrades.

Importing this module performs no host operations. Hardware services are only
started by install/upgrade after fresh admission and complete artifact checks.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import ssl
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request

from .install_checks import BDF, LEGACY_UNITS, preflight
from .preflight import inventory, inspect_sdk
from .profiles import PROFILES
from .release import ReleaseError, json_bytes, safe_relative, sha256, verify_bundle, version_tuple
from .update_gate import startup_permission

DAEMONS = ("identityd", "switchd", "configd", "ifd", "packetd", "l2d", "stpd",
           "lacpd", "lldpd", "statsd", "chassisd", "linkmond", "mgmtd")
SERVICES = tuple(f"fm10k-{name}.service" for name in DAEMONS)
STARTUP_UNITS = ("fm10k-switch.target", "fm10k-panel.service", "fm10k-time.socket",
                 "fm10k-update.socket", "fm10k-update-worker.service")
APT_PACKAGES = ("build-essential", "cmake", "pkg-config", "libpcre2-dev", "libssl-dev", "libcap-dev",
                "python3-fastapi", "python3-pydantic", "python3-uvicorn", "python3-prompt-toolkit", "python3-requests",
                "nginx", "openssl", "ca-certificates", "iproute2", "i2c-tools", "kmod", "dkms", "systemd-timesyncd",
                "adduser", "init-system-helpers")

WAIT_MANAGEMENT_SCRIPT = '''#!/usr/bin/python3
"""Wait until the configured management address is assigned before nginx binds."""
import ipaddress
import json
import subprocess
import sys
import time

interface, address = sys.argv[1:]
address = str(ipaddress.ip_address(address))
deadline = time.monotonic() + 180
while True:
    try:
        result = subprocess.run(
            ["/usr/sbin/ip", "-j", "address", "show", "dev", interface],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode == 0:
            assigned = {
                item["local"]
                for device in json.loads(result.stdout)
                for item in device.get("addr_info", [])
                if "local" in item
            }
            if address in assigned:
                sys.exit(0)
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        pass
    if time.monotonic() >= deadline:
        print(f"management address {address} did not appear on {interface}", file=sys.stderr)
        sys.exit(255)
    time.sleep(1)
'''


class Paths:
    def __init__(self, root=Path("/")):
        self.root = root
        self.base = root / "opt/fm10k-controlpanel"
        self.native = self.base / "native"
        self.etc = root / "etc/fm10k-controlpanel"
        self.boot = self.etc / "native"
        self.native_state = root / "var/lib/fm10k-controlpanel-native"
        self.web_state = root / "var/lib/fm10k-controlpanel"
        self.updates = root / "var/lib/fm10k-controlpanel-updates"
        self.libyang = root / "opt/netlab-deps/libyang2"
        self.marker = root / "run/fm10k-update/maintenance"
        self.journal = self.updates / "transaction.json"
        self.installation = self.updates / "installation.json"


def run(*arguments, timeout=1800, env=None):
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive",
                   "PYTHONDONTWRITEBYTECODE": "1", "FM10K_PACKAGE_NO_START": "1"}
    if env:
        environment.update(env)
    result = subprocess.run([str(item) for item in arguments], capture_output=True, text=True, timeout=timeout, env=environment)
    if result.returncode:
        raise ReleaseError(f"{arguments[0]} failed ({result.returncode}): " + (result.stderr or result.stdout)[-2400:])
    return result.stdout


@contextmanager
def native_build_umask():
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def secure_native_tree(root: Path):
    """Remove write access that the daemon launcher and startup guard reject."""
    for path in (root, *root.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ReleaseError("native build contains an unsupported entry: " + str(path))
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o022:
            path.chmod(mode & ~0o022)


def atomic_write(path: Path, raw: bytes, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save(path, value):
    atomic_write(path, json_bytes(value))


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_tree(root):
    """Persist a checkpoint before the journal can authorize a version swap."""
    directories = [root]
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_dir():
            directories.append(path)
        elif path.is_file():
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        sync_directory(path)
    sync_directory(root.parent)


def durable_replace(source, destination):
    os.replace(source, destination)
    sync_directory(destination.parent)
    if source.parent != destination.parent:
        sync_directory(source.parent)


def management_url(address):
    ip = ipaddress.ip_address(address)
    return "https://" + (f"[{ip}]" if ip.version == 6 else str(ip))


@contextmanager
def operation_lock(paths: Paths):
    paths.updates.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths.updates.chmod(0o700)
    with (paths.updates / "operation.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ReleaseError("another installation or update is already running") from None
        yield


def _copy_inputs(stage, sdk, platform_file, profile):
    target = stage / "hardware/sdk/ies"
    target.mkdir(parents=True)
    shutil.copytree(sdk / "include", target / "include")
    (target / "build").mkdir()
    for name in ("libFocalpointSDK.so", "libLTStdPlatform.so"):
        shutil.copyfile(sdk / "build" / name, target / "build" / name)
    destination = stage / PROFILES[profile].reference
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(platform_file, destination)
    for path in (stage / "hardware/sdk").rglob("*"):
        if path.is_symlink():
            raise ReleaseError("local SDK inputs cannot contain links")
        path.chmod(0o755 if path.is_dir() else 0o644)
    if not inspect_sdk(target, stage / "hardware/sdk-inputs.json")["valid"] or sha256(destination) != PROFILES[profile].sha256:
        raise ReleaseError("local inputs changed while staging the release")


def build_libyang(source: Path, paths: Paths, runner=run):
    if paths.libyang.exists():
        raise ReleaseError("first installation refuses to overwrite an existing libyang prefix")
    dependency = json.loads((source / "deploy/release-dependencies.json").read_text())["libyang"]
    archive = source / "dependencies" / dependency["archive"]
    if sha256(archive) != dependency["sha256"]:
        raise ReleaseError("libyang source checksum mismatch")
    workspace = paths.updates / "libyang-build"
    workspace.mkdir(mode=0o700)
    with tarfile.open(archive) as tar:
        seen, size = set(), 0
        for member in tar.getmembers():
            name = member.name.rstrip("/")
            size += member.size
            if (not safe_relative(name) or name.split("/")[0] != "libyang-2.1.148" or name in seen
                    or not (member.isfile() or member.isdir()) or size > 64 * 1024 * 1024):
                raise ReleaseError("unsafe libyang source archive")
            seen.add(name)
        tar.extractall(workspace, filter="data")
    runner("cmake", "-S", workspace / "libyang-2.1.148", "-B", workspace / "build",
           "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_INSTALL_PREFIX={paths.libyang}", "-DCMAKE_INSTALL_LIBDIR=lib",
           "-DENABLE_TESTS=OFF", "-DENABLE_BUILD_TESTS=OFF")
    runner("cmake", "--build", workspace / "build", "-j1")
    runner("cmake", "--install", workspace / "build")
    shutil.rmtree(workspace)


def copy_eye_firmware(stage, firmware):
    lock = json.loads((stage / "hardware/eye-firmware.json").read_text())
    if firmware.is_symlink() or firmware.stat().st_size != lock["binary_bytes"] or sha256(firmware) != lock["binary_sha256"]:
        raise ReleaseError("optional eye firmware does not match the release")
    destination = stage / "hardware/eye/sbus-master-101a.bin"
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write(destination, firmware.read_bytes(), 0o644)
    if sha256(destination) != lock["binary_sha256"]:
        raise ReleaseError("eye firmware changed while copying")


def stage_native(source: Path, sdk: Path, platform_file: Path, profile: str, paths: Paths, runner=run, *, eye_firmware=None) -> Path:
    with native_build_umask():
        verify_bundle(source)
        paths.base.mkdir(mode=0o755, parents=True, exist_ok=True)
        paths.base.chmod(0o755)
        stage = paths.base / (".stage-" + secrets.token_hex(8))
        shutil.copytree(source, stage)
        stage.chmod(0o755)
        verify_bundle(stage)
        _copy_inputs(stage, sdk, platform_file, profile)
        if eye_firmware is not None:
            copy_eye_firmware(stage, eye_firmware)
        runner("make", "-C", stage / "vendor/netlab", "-j1", "control-plane", "hardware",
               f"NETLAB_SDK_DIR={stage / 'hardware/sdk/ies'}", f"NETLAB_LIBYANG_PREFIX={paths.libyang}")
        secure_native_tree(stage)
        build_directory = stage / "vendor/netlab/build"
        build_stat = build_directory.stat()
        if ((build_stat.st_mode & 0o022) or
                (os.geteuid() == 0 and build_stat.st_uid != 0)):
            raise ReleaseError("native daemon build directory is not trusted")
        environment = {"LD_LIBRARY_PATH": f"{stage / 'hardware/sdk/ies/build'}:{paths.libyang / 'lib'}"}
        for name in (*DAEMONS, "netlab-daemon-launch", "netlab-internal-rpc"):
            binary = stage / "vendor/netlab/build" / name
            binary_stat = binary.stat()
            if ((binary_stat.st_mode & 0o022) or not (binary_stat.st_mode & stat.S_IXOTH) or
                    (os.geteuid() == 0 and binary_stat.st_uid != 0)):
                raise ReleaseError("native daemon executable is not trusted: " + name)
            with binary.open("rb") as stream:
                header = stream.read(20)
            if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
                raise ReleaseError("incomplete amd64 native build: " + name)
            linked = runner("ldd", "-r", binary, env=environment, timeout=30)
            if "not found" in linked or "undefined symbol" in linked:
                raise ReleaseError("unresolved native dependency: " + name)
        return stage


def service_text(name, paths):
    dependencies = ["local-fs.target", "systemd-modules-load.service"]
    if name != "identityd":
        dependencies.append("fm10k-identityd.service")
    if name not in ("identityd", "switchd"):
        dependencies.append("fm10k-switchd.service")
    if name not in ("identityd", "switchd", "configd"):
        dependencies.append("fm10k-configd.service")
    executable = paths.native / "vendor/netlab/build" / ("netlab-daemon-launch" if name in ("identityd", "chassisd") else name)
    command = str(executable) + (" " + name if name in ("identityd", "chassisd") else "")
    return ("[Unit]\nDescription=FM10840 native " + name + "\nAfter=" + " ".join(dependencies) +
            "\nPartOf=fm10k-switch.target\nConflicts=" + " ".join(LEGACY_UNITS) +
            f"\n\n[Service]\nType=simple\nUser=root\nGroup=root\nWorkingDirectory={paths.native}/vendor/netlab\n"
            f"EnvironmentFile={paths.etc}/native.env\nExecStart={command}\nRestart=no\n"
            "TimeoutStartSec=180\nTimeoutStopSec=30\nKillMode=control-group\nUMask=0077\n" +
            ("PrivateIPC=yes\n" if name == "switchd" else "") + "\n[Install]\nWantedBy=fm10k-switch.target\n")


def configure_native(paths: Paths, profile, management_interface, management_ip, runner=run):
    from .auth import Auth
    from .https_setup import prepare as prepare_https
    from .models import Credentials, SwitchConfiguration
    from .netlab_codec import compile_configuration
    from .platform_config import render_netlab_profile, render_sdk_platform

    for group in ("netlab-ipc", "netlab-identityd", "netlab-chassisd", "fm10k-web"):
        import grp
        try:
            grp.getgrnam(group)
        except KeyError:
            runner("addgroup", "--system", group)
    for user in ("netlab-identityd", "netlab-chassisd", "fm10k-web"):
        try:
            pwd.getpwnam(user)
        except KeyError:
            runner("adduser", "--system", "--ingroup", user, "--no-create-home", user)
    runner("adduser", "fm10k-web", "netlab-ipc")
    for directory, mode in ((paths.native_state, 0o700), (paths.etc, 0o755), (paths.boot, 0o755),
                            (paths.native_state / "config", 0o700),
                            (paths.native_state / "config/journal", 0o700),
                            (paths.native_state / "config/rollback", 0o700), (paths.native_state / "scopes", 0o700)):
        directory.mkdir(parents=True, mode=mode, exist_ok=True)
        directory.chmod(mode)
    report = inventory(bdf=BDF)
    from .native_guard import validate_identity
    board = validate_identity(report, profile)
    interfaces = list((paths.root / f"sys/bus/pci/devices/{BDF}/net").iterdir())
    if len(interfaces) != 1:
        raise ReleaseError("ASIC CPU interface is not unique")
    mac = (interfaces[0] / "address").read_text().strip()
    configuration = SwitchConfiguration(profile=profile)
    active = compile_configuration(configuration)
    boot = {
        "active.conf": active,
        "platform.profile": render_netlab_profile(configuration, system_mac=mac, serial=board["identity"]["serial"]).encode(),
        "fm_platform_attributes.cfg": render_sdk_platform((paths.native / PROFILES[profile].reference).read_text(), configuration).encode(),
    }
    for name, raw in boot.items():
        atomic_write(paths.boot / name, raw, 0o644)
    atomic_write(paths.native_state / "config/rollback/0000000000000001.conf", active)
    atomic_write(paths.native_state / "config/journal/tx_counter", b"1\n")
    save(paths.boot / "startup.json", {"schema": 1, "mode": "control", "bootstrap_mode": "observe",
        "seed_commit_id": 1, "profile": profile,
        "sha256": {str(paths.boot / name): hashlib.sha256(raw).hexdigest() for name, raw in boot.items()}})
    environment = {
        "NETLAB_ROOT": str(paths.native / "vendor/netlab"), "NETLAB_CONFIG_DIR": str(paths.native_state / "config"),
        "NETLAB_PLATFORM_PROFILE": str(paths.boot / "platform.profile"), "NETLAB_PORT_SCOPE_DIR": str(paths.native_state / "scopes"),
        "NETLAB_FM10K_NATIVE": "1", "NETLAB_FM10K_OBSERVE_ONLY": "0", "NETLAB_FM10K_STARTUP_MODE": "control",
        "NETLAB_SWITCHD_DISABLE_PORT_RECOVERY": "1", "FM_API_SHM_KEY": "51701",
        "FM_LIBERTY_TRAIL_CONFIG_FILE": str(paths.boot / "fm_platform_attributes.cfg"),
        "LD_LIBRARY_PATH": f"{paths.native / 'hardware/sdk/ies/build'}:{paths.libyang / 'lib'}",
    }
    atomic_write(paths.etc / "native.env", "".join(f"{key}={value}\n" for key, value in environment.items()).encode(), 0o644)
    atomic_write(paths.etc / "panel.env", b"PANEL_BACKEND=netlab\nPANEL_STATE_DIR=/var/lib/fm10k-controlpanel\n"
                 b"PANEL_STATIC_DIR=/usr/share/fm10k-controlpanel/web\nPANEL_NETLAB_ROOT=/usr/lib/fm10k-controlpanel/netlab\nPANEL_SECURE_COOKIE=1\n", 0o644)
    for name in DAEMONS:
        atomic_write(paths.root / f"etc/systemd/system/fm10k-{name}.service", service_text(name, paths).encode(), 0o644)
    atomic_write(paths.root / "etc/systemd/system/fm10k-switch.target", (
        "[Unit]\nDescription=FM10840 native switching\nRequires=" + " ".join(SERVICES) +
        "\nAfter=local-fs.target\nConflicts=" + " ".join(LEGACY_UNITS) + "\n\n[Install]\nWantedBy=multi-user.target\n").encode(), 0o644)
    atomic_write(paths.root / "etc/tmpfiles.d/fm10k-controlpanel.conf", b"d /run/netlab 0711 root root -\n", 0o644)
    atomic_write(paths.root / "etc/modules-load.d/fm10k-controlpanel.conf", b"i2c_i801\ni2c-dev\nfm10k\n", 0o644)
    runner("systemd-tmpfiles", "--create", paths.root / "etc/tmpfiles.d/fm10k-controlpanel.conf")
    auth = Auth(paths.web_state)
    if auth.initialized:
        raise ReleaseError("first installation cannot replace an administrator account")
    password = secrets.token_urlsafe(24)
    auth.setup(Credentials(username="admin", password=password))
    web_user = pwd.getpwnam("fm10k-web")
    os.chown(auth.path, web_user.pw_uid, web_user.pw_gid)
    save(paths.native_state / "initial-admin.json", {"username": "admin", "password": password, "url": management_url(management_ip)})
    tls = paths.etc / "tls"
    prepare_https(tls, paths.native / "deploy/nginx/fm10k-controlpanel.conf.in", management_ip, management_ip, days=365)
    site = paths.root / "etc/nginx/sites-available/fm10k-controlpanel"
    atomic_write(site, (tls / "fm10k-controlpanel.conf").read_bytes(), 0o644)
    enabled = paths.root / "etc/nginx/sites-enabled/fm10k-controlpanel"
    if enabled.exists() or enabled.is_symlink():
        raise ReleaseError("an nginx panel site already exists")
    enabled.symlink_to(site)
    wait_script = paths.etc / "wait-management.py"
    atomic_write(wait_script, WAIT_MANAGEMENT_SCRIPT.encode(), 0o644)
    nginx_dropin = paths.root / "etc/systemd/system/nginx.service.d/fm10k-controlpanel.conf"
    atomic_write(nginx_dropin, (
        "[Service]\n"
        f"ExecCondition=/usr/bin/python3 -I -B {wait_script} {management_interface} {management_ip}\n"
        "TimeoutStartSec=210\n"
    ).encode(), 0o644)
    runner("nginx", "-t", timeout=30)
    runner("systemd-analyze", "verify", *[paths.root / f"etc/systemd/system/fm10k-{name}.service" for name in DAEMONS])
    runner("systemctl", "daemon-reload")
    return configuration.model_dump(mode="json")


def snapshot():
    from .netlab import NetlabBackend
    os.environ["PANEL_NETLAB_ROOT"] = "/usr/lib/fm10k-controlpanel/netlab"
    backend = NetlabBackend()
    try:
        state = backend.snapshot()
        eye = backend.eye_read()
        if not state["hardware_write_ready"] or state["pending"] or eye.get("state") in {"running", "queued", "cancelling", "restoring"}:
            raise ReleaseError("finish configuration confirmation, recovery or eye scanning before updating")
        return state
    finally:
        backend.close()


def health(version, profile, expected_configuration, management_ip=None, *, runner=run, read_snapshot=snapshot,
           timeout=180, tls_cert=None):
    deadline = time.monotonic() + timeout
    last_error = "native control is not ready"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    https_opener = None
    if management_ip is not None:
        certificate = tls_cert or Paths().etc / "tls/server.crt"
        context = ssl.create_default_context(cafile=str(certificate))
        https_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                   urllib.request.HTTPSHandler(context=context))
    while time.monotonic() < deadline:
        try:
            current = read_snapshot()
            if current["configuration"] != expected_configuration or current["configuration"]["profile"] != profile:
                raise ReleaseError("configuration was not preserved")
            states = runner("systemctl", "is-active", *SERVICES, "fm10k-panel.service", timeout=15).splitlines()
            # systemctl returns success if ANY requested unit is active.
            if states != ["active"] * (len(SERVICES) + 1):
                raise ReleaseError("not all native and Web services are active")
            with opener.open("http://127.0.0.1:8080/api/v1/health", timeout=3) as response:
                web = json.loads(response.read(8192))
            if web != {"status": "ok", "mode": "netlab", "version": version}:
                raise ReleaseError("installed Web version, mode or health does not match")
            if https_opener is not None:
                if runner("systemctl", "is-active", "nginx.service", timeout=15).strip() != "active":
                    raise ReleaseError("nginx HTTPS service is not active")
                with https_opener.open(management_url(management_ip) + "/api/v1/health", timeout=3) as response:
                    https_web = json.loads(response.read(8192))
                if https_web != web:
                    raise ReleaseError("HTTPS health does not match the installed Web service")
            return current
        except Exception as error:
            last_error = str(error)
            time.sleep(2)
    raise ReleaseError("release health check failed: " + last_error)


def stop_services(runner=run):
    runner("systemctl", "stop", "fm10k-panel.service", "fm10k-switch.target", *reversed(SERVICES), timeout=180)


def start_services(runner=run):
    runner("systemctl", "start", "fm10k-switch.target", timeout=180)
    runner("systemctl", "restart", "fm10k-panel.service", timeout=45)


def install(source: Path, sdk: Path, platform_file: Path, interface: str, management_ip: str, version: str, *, eye_firmware=None):
    if os.geteuid() != 0:
        raise ReleaseError("run installation as root")
    paths = Paths()
    with native_build_umask(), operation_lock(paths):
        verify_bundle(source, version)
        report = preflight(source, sdk, platform_file, interface, management_ip, eye_firmware=eye_firmware)
        if not report["passed"]:
            raise ReleaseError("fresh installation admission failed")
        runner = run
        if paths.libyang.exists():
            raise ReleaseError("first installation refuses to overwrite an existing libyang prefix")
        runner("apt-get", "update")
        runner("apt-get", "install", "-y", "--no-install-recommends", *APT_PACKAGES, "linux-headers-" + report["host"]["kernel"])
        build_libyang(source, paths, runner)
        stage = stage_native(source, sdk, platform_file, report["profile"], paths, runner, eye_firmware=eye_firmware)
        sync_tree(stage)
        # Re-read identity and owners after the long build, before driver/service changes.
        again = preflight(source, sdk, platform_file, interface, management_ip,
                          eye_firmware=eye_firmware, prepared_libyang=True)
        if not again["passed"] or again["board"]["vpd_sha256"] != report["board"]["vpd_sha256"]:
            raise ReleaseError("installation target changed while building")
        paths.native.parent.mkdir(parents=True, exist_ok=True)
        durable_replace(stage, paths.native)
        package = paths.native / f"packages/fm10k-controlpanel_{version}_all.deb"
        cache = paths.updates / "packages"
        cache.mkdir(mode=0o700, exist_ok=True)
        atomic_write(cache / package.name, package.read_bytes())
        metadata = {"schema": 1, "status": "installing", "version": version, "profile": report["profile"],
            "management_interface": interface, "management_ip": management_ip, "pci_bdf": BDF,
            "vpd_sha256": report["board"]["vpd_sha256"], "package_sha256": sha256(package),
            "sdk_manifest_sha256": sha256(paths.native / "hardware/sdk-inputs.json"),
            "dependencies_sha256": sha256(paths.native / "deploy/release-dependencies.json")}
        save(paths.installation, metadata)
        try:
            runner("apt-get", "install", "-y", "--no-install-recommends", package)
            if report["driver_install_required"]:
                driver = paths.native / "hardware/reference/driver/fm10k-uio-6.12.101-ies2"
                installed_source = Path("/usr/src/fm10k-uio-6.12.101-ies2")
                if installed_source.exists():
                    raise ReleaseError("an existing DKMS source must be reviewed before first installation")
                shutil.copytree(driver, installed_source)
                runner("dkms", "add", "-m", "fm10k-uio", "-v", "6.12.101-ies2")
                runner("dkms", "build", "-m", "fm10k-uio", "-v", "6.12.101-ies2", "-k", report["host"]["kernel"])
                runner("dkms", "install", "-m", "fm10k-uio", "-v", "6.12.101-ies2", "-k", report["host"]["kernel"])
                if report["board"]["driver"] == "fm10k":
                    runner("modprobe", "-r", "fm10k", timeout=30)
            runner("modprobe", "fm10k", timeout=30)
            runner("modprobe", "i2c_i801", timeout=30)
            runner("modprobe", "i2c-dev", timeout=30)
            configuration = configure_native(paths, report["profile"], interface, management_ip, runner)
            start_services(runner)
            runner("systemctl", "start", "fm10k-time.socket", "fm10k-update.socket")
            runner("systemctl", "reload-or-restart", "nginx.service", timeout=45)
            health(version, report["profile"], configuration, management_ip)
            runner("systemctl", "enable", *STARTUP_UNITS, "nginx.service")
            metadata.update(status="ready", installed_at=time.time())
            save(paths.installation, metadata)
            print(json.dumps({"installed": True, "version": version, "profile": report["profile"],
                              "url": management_url(management_ip), "initial_credentials": str(paths.native_state / "initial-admin.json")}), flush=True)
        except BaseException as error:
            metadata["status"] = "installation_failed"
            metadata.pop("installed_at", None)
            cleanup_steps = [lambda: save(paths.installation, metadata)]
            cleanup_steps.extend(lambda unit=unit: runner("systemctl", "disable", unit)
                                 for unit in STARTUP_UNITS)
            cleanup_steps.extend((
                lambda: runner("systemctl", "stop", "fm10k-time.socket", "fm10k-update.socket"),
                lambda: stop_services(runner),
            ))
            for cleanup in cleanup_steps:
                try:
                    cleanup()
                except Exception as cleanup_error:
                    error.add_note("installation cleanup failed: " + str(cleanup_error))
            raise


def installed_metadata(paths):
    from .native_guard import trusted_file
    data = json.loads(trusted_file(paths.installation))
    if data.get("schema") != 1 or data.get("status") != "ready" or data.get("pci_bdf") != BDF:
        raise ReleaseError("this installation is not managed by the release installer")
    version_tuple(data.get("version"))
    if data.get("profile") not in PROFILES:
        raise ReleaseError("installed board profile is unsupported")
    return data


def upgrade_admission(source, metadata, paths, runner=run):
    if (sha256(source / "hardware/sdk-inputs.json") != metadata["sdk_manifest_sha256"]
            or sha256(source / "deploy/release-dependencies.json") != metadata["dependencies_sha256"]):
        raise ReleaseError("SDK or native dependency changes require a separate offline migration")
    sdk = paths.native / "hardware/sdk/ies"
    platform_file = paths.native / PROFILES[metadata["profile"]].reference
    report = preflight(source, sdk, platform_file, metadata["management_interface"], metadata["management_ip"],
                       upgrading=True, root=paths.root, runner=runner)
    if not report["passed"] or report["profile"] != metadata["profile"] or report["board"]["vpd_sha256"] != metadata["vpd_sha256"]:
        raise ReleaseError("fresh OS, board identity, driver or local input admission failed")
    return sdk, platform_file


def _tree_digests(path):
    return {item.relative_to(path).as_posix(): sha256(item) for item in path.rglob("*") if item.is_file()}


def checkpoint_copy(source, destination):
    """copytree preserves modes but not ownership; account files need both."""
    shutil.copytree(source, destination, symlinks=True)
    for origin in [source, *source.rglob("*")]:
        target = destination / origin.relative_to(source)
        metadata = origin.lstat()
        os.chown(target, metadata.st_uid, metadata.st_gid, follow_symlinks=False)
    sync_tree(destination)


def rollback(paths, transaction, *, runner=run, health_check=health):
    """Recovery is also used on the next worker start after an interrupted swap."""
    backup = Path(transaction["backup"])
    if backup.parent != paths.base or not backup.name.startswith(".rollback-"):
        raise ReleaseError("invalid recovery checkpoint path")
    phase = transaction["phase"]
    if phase == "committed":
        return
    stop_services(runner)
    saved_native = backup / "native"
    if saved_native.exists():
        if _tree_digests(saved_native) != transaction["checkpoint_digests"]["native"]:
            raise ReleaseError("native rollback checkpoint integrity failed")
        restored = paths.base / (".restore-" + secrets.token_hex(8))
        checkpoint_copy(saved_native, restored)
        failed = paths.base / (".failed-" + secrets.token_hex(8))
        if paths.native.exists():
            durable_replace(paths.native, failed)
        durable_replace(restored, paths.native)
        # Retain failed code for local diagnosis, never publish its private SDK.
    elif phase not in ("checkpointed", "stopping"):
        raise ReleaseError("native rollback checkpoint is missing; manual recovery is required")
    for saved, destination in (("etc", paths.etc), ("native-state", paths.native_state), ("web-state", paths.web_state)):
        origin = backup / saved
        if origin.exists():
            if _tree_digests(origin) != transaction["checkpoint_digests"][saved]:
                raise ReleaseError("rollback checkpoint integrity failed: " + saved)
            if destination.exists():
                shutil.rmtree(destination)
            checkpoint_copy(origin, destination)
    old = transaction["before"]
    package = backup / "rollback.deb"
    if sha256(package) != old["package_sha256"]:
        raise ReleaseError("rollback Web package integrity failed")
    runner("dpkg", "--force-confold", "-i", package)
    runner("systemctl", "daemon-reload")
    save(paths.installation, old)
    with startup_permission(paths):
        start_services(runner)
        health_check(old["version"], old["profile"], transaction["configuration"])
    transaction["phase"] = "rolled_back"
    save(paths.journal, transaction)


def upgrade(source: Path, *, paths=None, runner=run, read_snapshot=snapshot, health_check=health, progress=None, job_id=None):
    paths = paths or Paths()
    progress = progress or (lambda phase, message: None)
    bundle = verify_bundle(source)
    version = bundle["version"]
    metadata = installed_metadata(paths)
    if version_tuple(version) <= version_tuple(metadata["version"]):
        raise ReleaseError("only a newer stable release can be installed")
    sdk, platform_file = upgrade_admission(source, metadata, paths, runner)
    old_package = paths.updates / f"packages/fm10k-controlpanel_{metadata['version']}_all.deb"
    if not old_package.is_file() or sha256(old_package) != metadata["package_sha256"]:
        raise ReleaseError("a verified rollback package is required")
    read_snapshot()  # No staging if a transaction or eye scan is active.
    progress("preparing", "正在本地构建匹配的原生程序；当前交换服务继续运行。")
    eye_firmware = paths.native / "hardware/eye/sbus-master-101a.bin"
    stage = stage_native(source, sdk, platform_file, metadata["profile"], paths, runner,
                         eye_firmware=eye_firmware if eye_firmware.exists() else None)
    sync_tree(stage)
    upgrade_admission(source, metadata, paths, runner)
    progress("installing", "正在保存配置检查点并切换原生程序与 Web 服务。")
    # Quiesce Web writes, then re-read configd. Verify its durable pointer again
    # after stopping configd to catch a concurrent CLI commit.
    backup = paths.base / (".rollback-" + secrets.token_hex(8))
    backup.mkdir(mode=0o700)
    try:
        runner("systemctl", "stop", "fm10k-panel.service", timeout=45)
        before = read_snapshot()
        transaction = {"schema": 1, "phase": "stopping", "backup": str(backup), "before": metadata,
                       "configuration": before["configuration"], "target_version": version, "job_id": job_id}
        save(paths.journal, transaction)
    except BaseException:
        runner("systemctl", "start", "fm10k-panel.service")
        raise
    checkpoint_ready = False
    try:
        stop_services(runner)
        pointer = int((paths.native_state / "config/journal/tx_counter").read_text().strip())
        if pointer != before["revision"]:
            raise ReleaseError("configuration changed while entering maintenance; retry the update")
        transaction["checkpoint_digests"] = {}
        for name, origin in (("etc", paths.etc), ("native-state", paths.native_state), ("web-state", paths.web_state)):
            checkpoint_copy(origin, backup / name)
            transaction["checkpoint_digests"][name] = _tree_digests(backup / name)
        transaction["checkpoint_digests"]["native"] = _tree_digests(paths.native)
        sync_tree(paths.native)
        atomic_write(backup / "rollback.deb", old_package.read_bytes())
        transaction["phase"] = "checkpointed"
        save(paths.journal, transaction)
        checkpoint_ready = True
        durable_replace(paths.native, backup / "native")
        # Journal records intent before every potentially interrupted operation.
        transaction["phase"] = "switching"
        save(paths.journal, transaction)
        durable_replace(stage, paths.native)
        package = source / f"packages/fm10k-controlpanel_{version}_all.deb"
        runner("dpkg", "--force-confold", "-i", package)
        runner("systemctl", "daemon-reload")
        progress("restarting", "正在检查配置回读、原生服务和 Web 版本。")
        with startup_permission(paths):
            start_services(runner)
            health_check(version, metadata["profile"], before["configuration"])
        if _tree_digests(paths.etc) != transaction["checkpoint_digests"]["etc"]:
            raise ReleaseError("configuration, startup policy or TLS files changed unexpectedly")
        accounts = paths.web_state / "accounts.json"
        if sha256(accounts) != transaction["checkpoint_digests"]["web-state"]["accounts.json"]:
            raise ReleaseError("administrator account changed unexpectedly")
        cached = paths.updates / "packages" / package.name
        atomic_write(cached, package.read_bytes())
        new = {**metadata, "version": version, "package_sha256": sha256(cached), "installed_at": time.time()}
        save(paths.installation, new)
        transaction["phase"] = "committed"
        save(paths.journal, transaction)
        return {"version": version, "checkpoint": str(backup)}
    except BaseException as error:
        if checkpoint_ready:
            progress("rolling_back", "新版健康检查未通过，正在恢复原生程序、Web 包和配置检查点。")
            try:
                rollback(paths, transaction, runner=runner, health_check=health_check)
            except Exception as recovery:
                progress("recovery_required", "自动回退未完成，需要检查本地恢复记录。")
                raise ReleaseError(f"update failed: {error}; rollback failed: {recovery}") from error
            progress("rolled_back", "更新未完成，已恢复并验证原版本。")
        else:
            transaction["phase"] = "aborted"
            save(paths.journal, transaction)
            start_services(runner)
        raise
