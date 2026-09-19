"""Restart-time chassis port-mode apply/rollback helpers."""

import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux target always has fcntl
    fcntl = None

from platform_profile import PlatformProfileError, load_profile


NETLAB_ROOT = os.environ.get(
    "NETLAB_ROOT",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
)
NETSPL_ROOT = os.environ.get(
    "NETLAB_NETSPL_ROOT",
    os.environ.get("NETSPL_ROOT", "/opt/netlab-netspl"),
)
RELEASE_TOOL = "/usr/libexec/netlab/netlab-release-runtime.py"
ACTIVE_CONFIG = "/var/lib/netlab/active.conf"
STATE_DIR = "/var/lib/netlab/port-mode"
RUNTIME_PROFILE = "/var/lib/netlab/platform.profile"
RDI_TARGET = "/etc/rdi/fm_platform_attributes.cfg"
LOG_DIR = "/var/log/netlab"

PORT_MODE_MATRIX = {
    "24x10g": {
        "shape": "24x10g",
        "profiles": {
            "l2": "config/platform/fm10840-24x10g-rubyrapid.profile",
            "l3": "config/platform/fm10840-24x10g-rubyrapid-l3.profile",
        },
    },
    "24x25g": {
        "shape": "24x25g",
        "profiles": {
            "l2": "config/platform/fm10840-24x25g-rubyrapid.profile",
            "l3": "config/platform/fm10840-24x25g-rubyrapid-l3.profile",
        },
    },
    "12x25g-12x10g": {
        "shape": "12x25g-12x10g",
        "profiles": {
            "l2": "config/platform/fm10840-12x25g-12x10g-rubyrapid.profile",
            "l3": "config/platform/fm10840-12x25g-12x10g-rubyrapid-l3.profile",
        },
    },
    "12x10g-3x40g": {
        "shape": "12x10g-3x40g",
        "profiles": {
            "l2": "config/platform/fm10840-12x10g-3x40g-rubyrapid.profile",
        },
    },
    "12x25g-3x100g": {
        "shape": "12x25g-3x100g",
        "profiles": {
            "l2": "config/platform/fm10840-12x25g-3x100g-rubyrapid.profile",
            "l3": "config/platform/fm10840-12x25g-3x100g-rubyrapid-l3.profile",
        },
    },
    "6x40g": {
        "shape": "6x40g",
        "profiles": {
            "l2": "config/platform/fm10840-6x40g-rubyrapid.profile",
        },
    },
    "6x100g": {
        "shape": "6x100g",
        "profiles": {
            "l2": "config/platform/fm10840-6x100g-rubyrapid.profile",
        },
    },
}

TERMINAL_TRANSACTION_PHASES = frozenset((
    "healthy",
    "aborted-before-mutation",
    "restored-after-stop-failure",
    "restored-after-install-failure",
    "restored-after-start-or-health-failure",
    "restored-after-health-failure",
    "restored-after-metadata-failure",
    "restored-after-failure",
    "recovered-after-crash",
))


class PortModeError(RuntimeError):
    pass


def _local_name(tag):
    return tag.rsplit("}", 1)[-1]


def _child(parent, name):
    if parent is None:
        return None
    for node in list(parent):
        if _local_name(node.tag) == name:
            return node
    return None


def _child_text(parent, name):
    node = _child(parent, name)
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value or None


def _sha256(path):
    if not path or not os.path.exists(path):
        return "-"
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_file_binding(path):
    """Read one regular file and bind the returned bytes to an exact digest."""
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return {
            "path": os.path.abspath(path),
            "exists": False,
            "sha256": "-",
            "size": 0,
            "content": b"",
        }
    except OSError as exc:
        raise PortModeError("failed to inspect %s: %s" % (path, exc))
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise PortModeError("authority path is not a regular file: %s" % path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise PortModeError("failed to read %s: %s" % (path, exc))
    identity_before = (before.st_dev, before.st_ino, before.st_size,
                       before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size,
                       opened.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size,
                      after.st_mtime_ns)
    if identity_before != identity_opened or identity_opened != identity_after:
        raise PortModeError("authority file changed while read: %s" % path)
    content = b"".join(chunks)
    if len(content) != opened.st_size:
        raise PortModeError("authority file size changed while read: %s" % path)
    return {
        "path": os.path.abspath(path),
        "exists": True,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "content": content,
        "mode": stat.S_IMODE(opened.st_mode),
        "uid": opened.st_uid,
        "gid": opened.st_gid,
    }


def _binding_record(binding):
    return {key: binding[key] for key in
            ("path", "exists", "sha256", "size")}


def _assert_file_binding(path, expected):
    observed = _binding_record(_read_file_binding(path))
    if observed != expected:
        raise PortModeError(
            "active config changed after intent was prepared; retry the "
            "port-mode transaction")


def _mkdir(path):
    os.makedirs(path, exist_ok=True)


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_copy(src, dst):
    directory = os.path.dirname(os.path.abspath(dst)) or "."
    _mkdir(directory)
    fd, tmp = tempfile.mkstemp(prefix=".netlab-port-mode.", suffix=".tmp",
                               dir=directory)
    try:
        with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
            shutil.copyfileobj(inp, out)
            out.flush()
            os.fsync(out.fileno())
        if os.path.exists(dst):
            stat = os.stat(dst)
            os.chmod(tmp, stat.st_mode & 0o777)
            try:
                os.chown(tmp, stat.st_uid, stat.st_gid)
            except PermissionError:
                pass
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, dst)
        _fsync_dir(directory)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_bytes(path, data):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    _mkdir(directory)
    fd, tmp = tempfile.mkstemp(prefix=".netlab-port-mode.", suffix=".tmp",
                               dir=directory)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        _fsync_dir(directory)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_text(path, text):
    _atomic_write_bytes(path, text.encode("utf-8"))


def _atomic_write_json(path, data):
    _atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def _load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _load_json_strict(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError) as exc:
        raise PortModeError("failed to read transaction manifest %s: %s" %
                            (path, exc))
    if not isinstance(value, dict):
        raise PortModeError("transaction manifest root is not an object: %s" %
                            path)
    return value


def _load_profile_from_path(path):
    old = os.environ.get("NETLAB_PLATFORM_PROFILE")
    os.environ["NETLAB_PLATFORM_PROFILE"] = path
    try:
        return load_profile()
    finally:
        if old is None:
            os.environ.pop("NETLAB_PLATFORM_PROFILE", None)
        else:
            os.environ["NETLAB_PLATFORM_PROFILE"] = old


def active_profile_path():
    env = os.environ.get("NETLAB_PLATFORM_PROFILE")
    if env:
        return env
    for path in (
        "/var/lib/netlab/platform.profile",
        "/etc/netlab/platform.profile",
        os.path.join(NETLAB_ROOT, "config", "platform", "default.profile"),
    ):
        if os.path.exists(path):
            return path
    return "-"


def _profile_external(entry):
    role = (entry.get("role") or "").lower()
    flags = {flag.strip().lower() for flag in
             (entry.get("flags") or "").split(",") if flag.strip()}
    return role == "external" or "external" in flags


def _route_slices_enabled(ffu):
    for first_name, last_name in (
        ("ipv4-uc-first", "ipv4-uc-last"),
        ("ipv4-mc-first", "ipv4-mc-last"),
        ("ipv6-uc-first", "ipv6-uc-last"),
        ("ipv6-mc-first", "ipv6-mc-last"),
    ):
        try:
            first = int(ffu.get(first_name, "-1"), 0)
            last = int(ffu.get(last_name, "-1"), 0)
        except (TypeError, ValueError):
            continue
        if first >= 0 and last >= first:
            return True
    return False


def _profile_speed(entry):
    for key in ("default-speed", "line-rate", "scheduler-speed"):
        value = entry.get(key)
        if value not in (None, ""):
            try:
                return int(value, 0)
            except ValueError:
                return 0
    return 0


def _speed_label(speed_bps):
    mapping = {
        10_000_000_000: "10G",
        25_000_000_000: "25G",
        40_000_000_000: "40G",
        100_000_000_000: "100G",
    }
    return mapping.get(speed_bps, str(speed_bps or "-"))


def _infer_port_mode(external_ports):
    counts = {}
    for entry in external_ports:
        label = _speed_label(_profile_speed(entry))
        counts[label] = counts.get(label, 0) + 1
    if counts == {"10G": 24}:
        return "24x10g"
    if counts == {"25G": 24}:
        return "24x25g"
    if counts == {"25G": 12, "10G": 12}:
        return "12x25g-12x10g"
    if counts == {"10G": 12, "40G": 3}:
        return "12x10g-3x40g"
    if counts == {"25G": 12, "100G": 3}:
        return "12x25g-3x100g"
    if counts == {"40G": 6}:
        return "6x40g"
    if counts == {"100G": 6}:
        return "6x100g"
    return "custom"


def profile_facts(profile):
    platform = profile.get("platform", {})
    external = [p for p in profile.get("ports", []) if _profile_external(p)]
    mode = platform.get("port-mode") or _infer_port_mode(external)
    services = platform.get("network-services")
    if not services:
        route_caps = any(
            "ROUTE" in {cap.strip().upper() for cap in
                        (p.get("capabilities") or "").split(",")
                        if cap.strip()}
            for p in external
        )
        services = "l3" if route_caps and _route_slices_enabled(
            profile.get("ffu", {})) else "l2"
    return {
        "port-mode": mode,
        "network-services": services,
        "chassis-profile": platform.get("chassis-name", "-"),
        "external-ports": len(external),
    }


def active_profile_facts(profile_path=None):
    path = profile_path or active_profile_path()
    if path == "-":
        return {"path": "-", "error": "no platform profile found"}
    try:
        profile = _load_profile_from_path(path)
        facts = profile_facts(profile)
    except PlatformProfileError as exc:
        facts = {"error": str(exc)}
    facts["path"] = path
    facts["sha256"] = _sha256(path)
    return facts


def _configured_intent_from_binding(binding, active_config, fallback,
                                    fallback_profile):
    intent = {"port-mode": None, "network-services": None,
              "source": active_config}
    if binding["exists"]:
        try:
            root = ET.fromstring(binding["content"])
            chassis = None
            for child in list(root):
                if _local_name(child.tag) == "chassis":
                    chassis = child
                    break
            intent["port-mode"] = _child_text(chassis, "port-mode")
            intent["network-services"] = _child_text(chassis,
                                                     "network-services")
        except ET.ParseError as exc:
            raise PortModeError("failed to read active config %s: %s" %
                                (active_config, exc))
    if fallback and (not intent["port-mode"] or
                     not intent["network-services"]):
        facts = active_profile_facts(fallback_profile)
        if not intent["port-mode"]:
            intent["port-mode"] = facts.get("port-mode")
        if not intent["network-services"]:
            intent["network-services"] = facts.get("network-services")
        intent["source"] = "active config with active profile fallback"
    if not intent["port-mode"] or not intent["network-services"]:
        raise PortModeError("active config has no chassis port-mode intent")
    return intent


def read_configured_intent(active_config=ACTIVE_CONFIG, fallback=True,
                           fallback_profile=None):
    binding = _read_file_binding(active_config)
    return _configured_intent_from_binding(
        binding, active_config, fallback, fallback_profile)


def _read_configured_intent_bound(active_config=ACTIVE_CONFIG, fallback=True,
                                  fallback_profile=None):
    binding = _read_file_binding(active_config)
    intent = _configured_intent_from_binding(
        binding, active_config, fallback, fallback_profile)
    return intent, _binding_record(binding)


def resolve_target(port_mode, network_services, netlab_root=NETLAB_ROOT):
    entry = PORT_MODE_MATRIX.get(port_mode)
    if not entry:
        valid = ", ".join(sorted(PORT_MODE_MATRIX))
        raise PortModeError("port-mode %s is not apply-supported; valid: %s" %
                            (port_mode, valid))
    profile_rel = entry["profiles"].get(network_services)
    if not profile_rel:
        valid = ", ".join(sorted(entry["profiles"]))
        raise PortModeError(
            "port-mode %s does not support network-services %s; valid: %s" %
            (port_mode, network_services, valid))
    profile = os.path.join(netlab_root, profile_rel)
    if not os.path.exists(profile):
        raise PortModeError("platform profile not found: %s" % profile)
    return {
        "port-mode": port_mode,
        "network-services": network_services,
        "shape": entry["shape"],
        "profile": profile,
    }


def _snapshot(path, directory, name):
    info = {"path": os.path.abspath(path), "exists": os.path.lexists(path),
            "sha256": "-"}
    if info["exists"]:
        source = _read_file_binding(path)
        backup = os.path.join(directory, name)
        _atomic_write_bytes(backup, source["content"])
        info["backup"] = backup
        info["sha256"] = source["sha256"]
        info["mode"] = source["mode"]
        info["uid"] = source["uid"]
        info["gid"] = source["gid"]
    return info


def _restore_snapshot(info):
    path = info.get("path")
    if not path:
        return
    if info.get("exists"):
        backup = info.get("backup")
        expected = info.get("sha256")
        if (not backup or not expected or expected == "-" or
                _sha256(backup) != expected):
            raise PortModeError("port-mode rollback snapshot integrity failed")
        atomic_copy(info["backup"], path)
        mode = info.get("mode")
        uid = info.get("uid")
        gid = info.get("gid")
        if type(mode) is not int or type(uid) is not int or type(gid) is not int:
            raise PortModeError("port-mode rollback metadata is malformed")
        os.chmod(path, mode)
        try:
            os.chown(path, uid, gid)
        except PermissionError:
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                raise
        with open(path, "rb") as restored:
            os.fsync(restored.fileno())
        _fsync_dir(os.path.dirname(os.path.abspath(path)) or ".")
    elif os.path.lexists(path):
        current = os.lstat(path)
        if stat.S_ISDIR(current.st_mode):
            raise PortModeError(
                "port-mode rollback target became a directory: %s" % path)
        os.unlink(path)
        _fsync_dir(os.path.dirname(os.path.abspath(path)) or ".")


class PortModeManager:
    def __init__(self, netlab_root=NETLAB_ROOT, netspl_root=NETSPL_ROOT,
                 active_config=ACTIVE_CONFIG, state_dir=STATE_DIR,
                 runtime_profile=RUNTIME_PROFILE, rdi_target=RDI_TARGET,
                 log_dir=LOG_DIR, lifecycle=None, root_check=True):
        self.netlab_root = netlab_root
        self.netspl_root = netspl_root
        self.active_config = active_config
        self.state_dir = state_dir
        self.runtime_profile = runtime_profile
        self.rdi_target = rdi_target
        self.log_dir = log_dir
        self.lifecycle = lifecycle
        self.root_check = root_check

    @property
    def status_path(self):
        return os.path.join(self.state_dir, "status.json")

    @property
    def last_success_path(self):
        return os.path.join(self.state_dir, "last-success.json")

    @property
    def lock_path(self):
        return os.path.join(self.state_dir, "lock")

    def _check_root(self):
        if not self.root_check:
            return
        default_paths = (
            self.runtime_profile.startswith("/var/lib/"),
            self.rdi_target.startswith("/etc/"),
        )
        if any(default_paths) and hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PortModeError("port-mode apply requires root")

    def _locked(self):
        _mkdir(self.state_dir)
        handle = open(self.lock_path, "a+", encoding="utf-8")
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def _write_status(self, status):
        status = dict(status)
        status.setdefault("updated-at", time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                       time.gmtime()))
        _atomic_write_json(self.status_path, status)

    def _generate_rdi(self, shape, output):
        sys.path.insert(0, self.netspl_root)
        try:
            try:
                from netspl.rdi import RdiDocument, generate, validate
                from netspl.reference import DEFAULT_REFERENCE_PATH
            except ImportError as exc:
                raise PortModeError("failed to import Netspl from %s: %s" %
                                    (self.netspl_root, exc))
            doc = RdiDocument.read(DEFAULT_REFERENCE_PATH)
            rendered = generate(doc, shape)
            generated = RdiDocument.parse(rendered)
            result = validate(generated, shape_name=shape)
            if not result.ok:
                raise PortModeError("generated RDI failed validation: %s" %
                                    "; ".join(result.errors))
            _atomic_write_text(output, rendered)
        finally:
            try:
                sys.path.remove(self.netspl_root)
            except ValueError:
                pass

    def _audit(self, profile, rdi):
        env = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NETLAB_PLATFORM_PROFILE": profile,
        }
        cmd = [sys.executable, "-I", "-S", "-B",
               os.path.join(self.netlab_root, "scripts",
                            "platform-profile-audit.py"),
               "--rdi", rdi]
        proc = subprocess.run(
            cmd, cwd=self.netlab_root, env=env, universal_newlines=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
        )
        if proc.returncode != 0:
            raise PortModeError("profile/RDI audit failed:\n%s" %
                                proc.stdout.strip())
        return proc.stdout

    def _attest_running(self):
        if self.lifecycle is None:
            raise PortModeError(
                "port-mode mutation requires the canonical immutable release runtime")
        report = self.lifecycle.attest_running()
        release_id = report.get("release-id") if isinstance(report, dict) else None
        if not isinstance(release_id, str) or not release_id:
            raise PortModeError(
                "immutable release attestation returned no exact release id")
        return report

    def _stop_and_attest(self, release_id):
        report = self.lifecycle.stop_and_attest(release_id=release_id)
        if (not isinstance(report, dict) or
                report.get("release-id") != release_id):
            raise PortModeError(
                "stopped attestation changed immutable release identity")
        runtime_files = report.get("runtime-files")
        if not isinstance(runtime_files, dict):
            raise PortModeError(
                "stopped attestation returned no runtime file authority")
        return report

    def _start_and_attest(self, release_id, profile_sha256, rdi_sha256,
                          tx_manifest=None):
        report = self.lifecycle.start_and_attest(
            release_id=release_id,
            profile_sha256=profile_sha256,
            rdi_sha256=rdi_sha256,
            transaction_manifest=tx_manifest,
        )
        if (not isinstance(report, dict) or
                report.get("release-id") != release_id):
            raise PortModeError(
                "post-start attestation changed immutable release identity")
        if _sha256(self.runtime_profile) != profile_sha256:
            raise PortModeError("post-start platform profile checksum drift")
        if _sha256(self.rdi_target) != rdi_sha256:
            raise PortModeError("post-start RDI checksum drift")
        return report

    @staticmethod
    def _record_start_authority(manifest, tx_manifest, release_id,
                                profile_sha256, rdi_sha256):
        manifest["start-authority"] = {
            "release-id": release_id,
            "runtime-profile-sha256": profile_sha256,
            "rdi-sha256": rdi_sha256,
            "transaction-manifest": os.path.abspath(tx_manifest),
        }
        _atomic_write_json(tx_manifest, manifest)

    def _publish_runtime_pair(self, profile_source, rdi_source):
        """Publish one profile/RDI authority pair while the stack is stopped.

        The paths may live on different filesystems, so each destination uses
        its own durable atomic replace.  The canonical lifecycle keeps every
        consumer stopped across both replaces; a failure is restored as a pair
        before any canonical start is attempted.
        """
        expected_profile = _sha256(profile_source)
        expected_rdi = _sha256(rdi_source)
        if expected_profile == "-" or expected_rdi == "-":
            raise PortModeError("port-mode publication source is missing")
        atomic_copy(profile_source, self.runtime_profile)
        atomic_copy(rdi_source, self.rdi_target)
        observed_profile = _sha256(self.runtime_profile)
        observed_rdi = _sha256(self.rdi_target)
        if observed_profile != expected_profile:
            raise PortModeError("published platform profile checksum drift")
        if observed_rdi != expected_rdi:
            raise PortModeError("published RDI checksum drift")
        return observed_profile, observed_rdi

    @staticmethod
    def _restore_runtime_pair(snapshots):
        # Validate both inputs before replacing either destination.  A later
        # I/O failure still leaves the service stopped and therefore cannot
        # expose a mixed pair to a runtime consumer.
        for name in ("platform-profile", "rdi"):
            info = snapshots.get(name) or {}
            if info.get("exists"):
                backup = info.get("backup")
                expected = info.get("sha256")
                if (not backup or not expected or expected == "-" or
                        _sha256(backup) != expected):
                    raise PortModeError(
                        "port-mode rollback snapshot integrity failed")
        _restore_snapshot(snapshots.get("platform-profile", {}))
        _restore_snapshot(snapshots.get("rdi", {}))

    def _assert_snapshot_matches_authority(self, previous, authority):
        runtime_files = authority.get("runtime-files")
        if not isinstance(runtime_files, dict):
            raise PortModeError(
                "immutable release attestation returned no runtime file authority")
        for snapshot_name, authority_name in (
            ("platform-profile", "platform-profile"),
            ("rdi", "rdi"),
        ):
            snapshot = previous.get(snapshot_name) or {}
            attested = runtime_files.get(authority_name) or {}
            if (snapshot.get("exists") is not True or
                    os.path.abspath(snapshot.get("path") or "") !=
                    os.path.abspath(attested.get("path") or "") or
                    snapshot.get("sha256") != attested.get("sha256")):
                raise PortModeError(
                    "%s changed after immutable runtime attestation" %
                    snapshot_name)

    def _assert_applied_matches_authority(self, manifest, authority):
        runtime_files = authority.get("runtime-files")
        if not isinstance(runtime_files, dict):
            raise PortModeError(
                "immutable release attestation returned no runtime file authority")
        expected_profile = (manifest.get("runtime-profile") or {}).get(
            "sha256")
        expected_rdi = (manifest.get("rdi") or {}).get("sha256")
        if (runtime_files.get("platform-profile", {}).get("sha256") !=
                expected_profile or
                runtime_files.get("rdi", {}).get("sha256") != expected_rdi):
            raise PortModeError(
                "current profile/RDI do not match the applied transaction")

    def _restore_after_apply_failure(self, previous, manifest, tx_manifest,
                                     phase, exc, release_id):
        try:
            recovery_stop = self._stop_and_attest(release_id)
            self._restore_runtime_pair(previous)
            self._restore_metadata_before(manifest)
            profile_sha = _sha256(self.runtime_profile)
            rdi_sha = _sha256(self.rdi_target)
            manifest["phase"] = "recovery-start-pending"
            self._record_start_authority(
                manifest, tx_manifest, release_id, profile_sha, rdi_sha)
            recovery_start = self._start_and_attest(
                release_id, profile_sha, rdi_sha, tx_manifest)
        except Exception as recovery_exc:
            manifest["phase"] = "recovery-failed"
            manifest["last-error"] = str(exc)
            manifest["recovery-error"] = str(recovery_exc)
            try:
                _atomic_write_json(tx_manifest, manifest)
            except Exception:
                pass
            raise PortModeError(
                "port-mode apply failed and exact runtime recovery failed: "
                "%s; recovery: %s" % (exc, recovery_exc)) from exc
        manifest["runtime-profile"]["sha256"] = profile_sha
        manifest["rdi"]["sha256"] = rdi_sha
        manifest["phase"] = phase
        manifest["last-error"] = str(exc)
        manifest["recovery-stop-attestation"] = recovery_stop
        manifest["recovery-start-attestation"] = recovery_start
        _atomic_write_json(tx_manifest, manifest)

    def _new_tx_dir(self, action):
        transactions = os.path.join(self.state_dir, "transactions")
        _mkdir(transactions)
        for _ in range(32):
            tx_id = secrets.token_hex(16)
            path = os.path.join(transactions, "%s-%s" % (tx_id, action))
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                continue
            _fsync_dir(transactions)
            return tx_id, path
        raise PortModeError("failed to allocate a unique port-mode transaction")

    def _snapshot_metadata_before(self, tx_dir):
        directory = os.path.join(tx_dir, "metadata-before")
        _mkdir(directory)
        return {
            "last-success": _snapshot(
                self.last_success_path, directory, "last-success.json"),
        }

    def _restore_metadata_before(self, manifest):
        metadata = manifest.get("metadata-before")
        if not isinstance(metadata, dict):
            raise PortModeError(
                "port-mode transaction has no metadata before-image")
        _restore_snapshot(metadata.get("last-success") or {})

    @staticmethod
    def _path_inside(path, directory):
        try:
            return os.path.commonpath((os.path.realpath(path),
                                       os.path.realpath(directory))) == \
                os.path.realpath(directory)
        except (OSError, ValueError):
            return False

    def _validate_snapshot(self, info, expected_path, tx_dir, label,
                           require_exists=False):
        if not isinstance(info, dict) or type(info.get("exists")) is not bool:
            raise PortModeError("%s snapshot is malformed" % label)
        if os.path.abspath(info.get("path") or "") != os.path.abspath(
                expected_path):
            raise PortModeError("%s snapshot path changed" % label)
        if require_exists and info["exists"] is not True:
            raise PortModeError("%s snapshot is unexpectedly absent" % label)
        if info["exists"]:
            backup = info.get("backup")
            expected_sha = info.get("sha256")
            if (not isinstance(backup, str) or
                    not self._path_inside(backup, tx_dir) or
                    not isinstance(expected_sha, str) or
                    len(expected_sha) != 64):
                raise PortModeError("%s snapshot authority is malformed" % label)
            if (type(info.get("mode")) is not int or
                    type(info.get("uid")) is not int or
                    type(info.get("gid")) is not int):
                raise PortModeError("%s snapshot metadata is malformed" % label)
            binding = _read_file_binding(backup)
            if not binding["exists"] or binding["sha256"] != expected_sha:
                raise PortModeError("%s snapshot checksum changed" % label)
        elif info.get("sha256") != "-":
            raise PortModeError("%s absent snapshot has a checksum" % label)

    def _incomplete_transactions(self):
        transactions = os.path.join(self.state_dir, "transactions")
        if not os.path.exists(transactions):
            return []
        if os.path.islink(transactions) or not os.path.isdir(transactions):
            raise PortModeError("port-mode transaction root is not a directory")
        incomplete = []
        for entry in sorted(os.scandir(transactions), key=lambda item: item.name):
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                raise PortModeError(
                    "port-mode transaction entry is not a directory: %s" %
                    entry.path)
            manifest_path = os.path.join(entry.path, "manifest.json")
            if not os.path.exists(manifest_path):
                # Mutation is forbidden until manifest.json is durable, so an
                # unmanifested candidate directory is safe to ignore.
                continue
            if os.path.islink(manifest_path) or not os.path.isfile(manifest_path):
                raise PortModeError(
                    "port-mode transaction manifest is not a regular file")
            manifest = _load_json_strict(manifest_path)
            schema_version = manifest.get("schema-version")
            if schema_version is None:
                # Releases predating durable crash recovery either omitted a
                # phase on completed records or used this legacy terminal
                # phase.  They have no sufficient authority for automation,
                # and must not be mistaken for a new recoverable transaction.
                if (manifest.get("phase") is None or
                        manifest.get("phase") in TERMINAL_TRANSACTION_PHASES):
                    continue
                raise PortModeError(
                    "legacy port-mode transaction has an unknown phase")
            if schema_version != 2:
                raise PortModeError(
                    "port-mode transaction schema version is unsupported")
            phase = manifest.get("phase")
            if not isinstance(phase, str) or not phase:
                raise PortModeError("port-mode transaction phase is malformed")
            if phase not in TERMINAL_TRANSACTION_PHASES:
                incomplete.append((manifest_path, manifest))
        if len(incomplete) > 1:
            raise PortModeError(
                "multiple incomplete port-mode transactions require manual "
                "forensic recovery")
        return incomplete

    def _validate_recovery_manifest(self, tx_manifest, manifest,
                                    expected_release_id=None):
        tx_dir = os.path.dirname(tx_manifest)
        tx_id = manifest.get("tx-id")
        action = manifest.get("action")
        if (not isinstance(tx_id, str) or len(tx_id) != 32 or
                any(char not in "0123456789abcdef" for char in tx_id) or
                action not in ("apply", "rollback") or
                os.path.basename(tx_dir) != "%s-%s" % (tx_id, action)):
            raise PortModeError("port-mode recovery transaction identity is invalid")
        authority = manifest.get("runtime-authority")
        release_id = authority.get("release-id") if isinstance(
            authority, dict) else None
        if (not isinstance(release_id, str) or not release_id or
                (expected_release_id is not None and
                 release_id != expected_release_id)):
            raise PortModeError(
                "port-mode recovery release identity is invalid")
        snapshots = (manifest.get("previous") if action == "apply" else
                     manifest.get("current-before-rollback"))
        if not isinstance(snapshots, dict):
            raise PortModeError("port-mode recovery snapshots are missing")
        self._validate_snapshot(
            snapshots.get("platform-profile"), self.runtime_profile, tx_dir,
            "platform-profile", require_exists=True)
        self._validate_snapshot(
            snapshots.get("rdi"), self.rdi_target, tx_dir, "rdi",
            require_exists=True)
        metadata = manifest.get("metadata-before")
        if not isinstance(metadata, dict):
            raise PortModeError("port-mode recovery metadata snapshot is missing")
        self._validate_snapshot(
            metadata.get("last-success"), self.last_success_path, tx_dir,
            "last-success")
        return release_id, authority, snapshots

    def _validate_last_success(self, manifest, expected_release_id):
        if (manifest.get("schema-version") != 2 or
                manifest.get("action") != "apply" or
                manifest.get("phase") != "healthy"):
            raise PortModeError(
                "last successful port-mode authority is not a terminal "
                "schema-v2 apply")
        start = manifest.get("start-authority")
        tx_manifest = start.get("transaction-manifest") if isinstance(
            start, dict) else None
        transactions = os.path.join(self.state_dir, "transactions")
        if (not isinstance(tx_manifest, str) or
                not self._path_inside(tx_manifest, transactions) or
                os.path.basename(tx_manifest) != "manifest.json"):
            raise PortModeError(
                "last successful port-mode manifest binding is invalid")
        durable = _load_json_strict(tx_manifest)
        if durable != manifest:
            raise PortModeError(
                "last successful port-mode metadata differs from its journal")
        self._validate_recovery_manifest(
            tx_manifest, manifest, expected_release_id)

    def _recover_incomplete_locked(self, expected_release_id=None):
        incomplete = self._incomplete_transactions()
        if not incomplete:
            return []
        if self.lifecycle is None:
            raise PortModeError(
                "incomplete port-mode transaction requires canonical recovery")
        tx_manifest, manifest = incomplete[0]
        release_id, authority, snapshots = self._validate_recovery_manifest(
            tx_manifest, manifest, expected_release_id)
        try:
            stopped = self.lifecycle.prepare_recovery(
                release_id=release_id, runtime_authority=authority)
            if (not isinstance(stopped, dict) or
                    stopped.get("release-id") != release_id):
                raise PortModeError(
                    "port-mode recovery did not prove stopped release identity")
            self._restore_runtime_pair(snapshots)
            self._restore_metadata_before(manifest)
            profile_sha = _sha256(self.runtime_profile)
            rdi_sha = _sha256(self.rdi_target)
            self._record_start_authority(
                manifest, tx_manifest, release_id, profile_sha, rdi_sha)
            started = self._start_and_attest(
                release_id, profile_sha, rdi_sha, tx_manifest)
            manifest["phase"] = "recovered-after-crash"
            manifest["crash-recovery-stop-attestation"] = stopped
            manifest["crash-recovery-start-attestation"] = started
            manifest.pop("recovery-error", None)
            _atomic_write_json(tx_manifest, manifest)
            self._write_status({
                "state": "recovered",
                "action": manifest["action"],
                "tx-id": manifest["tx-id"],
                "runtime-profile-sha256": profile_sha,
                "rdi-sha256": rdi_sha,
            })
            return [manifest]
        except Exception as exc:
            manifest["phase"] = "recovery-failed"
            manifest["recovery-error"] = str(exc)
            try:
                _atomic_write_json(tx_manifest, manifest)
            except Exception:
                pass
            raise PortModeError(
                "incomplete port-mode transaction recovery failed: %s" % exc
            ) from exc

    def recover_incomplete(self, expected_release_id=None):
        self._check_root()
        with self._locked():
            return self._recover_incomplete_locked(expected_release_id)

    def apply(self):
        self._check_root()
        with self._locked():
            self._recover_incomplete_locked()
            tx_id, tx_dir = self._new_tx_dir("apply")
            tx_manifest = None
            manifest = None
            mutation_attempted = False
            try:
                authority = self._attest_running()
                release_id = authority["release-id"]
                intent, active_config_authority = \
                    _read_configured_intent_bound(
                        self.active_config,
                        fallback=True,
                        fallback_profile=(
                            self.runtime_profile
                            if os.path.exists(self.runtime_profile) else None),
                    )
                target = resolve_target(intent["port-mode"],
                                        intent["network-services"],
                                        self.netlab_root)
                candidate_rdi = os.path.join(
                    tx_dir, "fm_platform_attributes.%s.cfg" %
                    target["shape"])
                self._generate_rdi(target["shape"], candidate_rdi)
                audit_output = self._audit(target["profile"], candidate_rdi)
                _atomic_write_text(os.path.join(tx_dir, "audit.txt"),
                                   audit_output)

                previous_dir = os.path.join(tx_dir, "previous")
                _mkdir(previous_dir)
                previous = {
                    "platform-profile": _snapshot(
                        self.runtime_profile, previous_dir,
                        "platform.profile"),
                    "rdi": _snapshot(self.rdi_target, previous_dir,
                                     "fm_platform_attributes.cfg"),
                }
                self._assert_snapshot_matches_authority(previous, authority)
                metadata_before = self._snapshot_metadata_before(tx_dir)
                manifest = {
                    "schema-version": 2,
                    "tx-id": tx_id,
                    "action": "apply",
                    "phase": "prepared",
                    "created-at": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "configured": intent,
                    "active-config-authority": active_config_authority,
                    "applied": target,
                    "runtime-profile": {
                        "path": self.runtime_profile,
                        "sha256": "-",
                    },
                    "rdi": {
                        "path": self.rdi_target,
                        "sha256": "-",
                    },
                    "previous": previous,
                    "metadata-before": metadata_before,
                    "runtime-authority": authority,
                    "audit": os.path.join(tx_dir, "audit.txt"),
                }
                tx_manifest = os.path.join(tx_dir, "manifest.json")
                _atomic_write_json(tx_manifest, manifest)
                self._write_status({
                    "state": "running", "action": "apply", "tx-id": tx_id})

                failure_phase = "restored-after-stop-failure"
                try:
                    mutation_attempted = True
                    stop_attestation = self._stop_and_attest(release_id)
                    self._assert_snapshot_matches_authority(
                        previous, stop_attestation)
                    manifest["phase"] = "stopped"
                    manifest["stop-attestation"] = stop_attestation
                    _atomic_write_json(tx_manifest, manifest)

                    failure_phase = "restored-after-install-failure"
                    _assert_file_binding(
                        self.active_config, active_config_authority)
                    profile_sha, rdi_sha = self._publish_runtime_pair(
                        target["profile"], candidate_rdi)
                    manifest["phase"] = "files-installed"
                    manifest["runtime-profile"]["sha256"] = profile_sha
                    manifest["rdi"]["sha256"] = rdi_sha
                    _atomic_write_json(tx_manifest, manifest)

                    failure_phase = "restored-after-start-or-health-failure"
                    self._record_start_authority(
                        manifest, tx_manifest, release_id, profile_sha, rdi_sha)
                    manifest["start-attestation"] = self._start_and_attest(
                        release_id, profile_sha, rdi_sha, tx_manifest)

                    failure_phase = "restored-after-metadata-failure"
                    manifest["phase"] = "runtime-healthy"
                    _atomic_write_json(tx_manifest, manifest)
                    success_record = dict(manifest)
                    success_record["phase"] = "healthy"
                    _atomic_write_json(self.last_success_path, success_record)
                    self._write_status({
                        "state": "applied",
                        "action": "apply",
                        "tx-id": tx_id,
                        "configured": intent,
                        "applied": target,
                        "runtime-profile-sha256": manifest[
                            "runtime-profile"]["sha256"],
                        "rdi-sha256": manifest["rdi"]["sha256"],
                    })
                    manifest["phase"] = "healthy"
                    _atomic_write_json(tx_manifest, manifest)
                except Exception as exc:
                    if mutation_attempted:
                        self._restore_after_apply_failure(
                            previous, manifest, tx_manifest,
                            failure_phase, exc, release_id)
                    raise
                return manifest
            except Exception as exc:
                if (not mutation_attempted and manifest is not None and
                        tx_manifest is not None):
                    manifest["phase"] = "aborted-before-mutation"
                    manifest["last-error"] = str(exc)
                    try:
                        _atomic_write_json(tx_manifest, manifest)
                    except Exception:
                        pass
                try:
                    self._write_status({
                        "state": "failed",
                        "action": "apply",
                        "tx-id": tx_id,
                        "last-error": str(exc),
                    })
                except Exception:
                    pass
                raise

    def rollback(self):
        self._check_root()
        with self._locked():
            self._recover_incomplete_locked()
            tx_id, tx_dir = self._new_tx_dir("rollback")
            rollback_manifest = None
            rollback_record = None
            mutation_attempted = False
            try:
                authority = self._attest_running()
                release_id = authority["release-id"]
                manifest = _load_json_strict(self.last_success_path)
            except Exception as exc:
                try:
                    self._write_status({
                        "state": "failed",
                        "action": "rollback",
                        "tx-id": tx_id,
                        "last-error": str(exc),
                    })
                except Exception:
                    pass
                raise
            previous = manifest.get("previous") or {}
            if not previous:
                exc = PortModeError("no successful port-mode apply to roll back")
                self._write_status({
                    "state": "failed",
                    "action": "rollback",
                    "tx-id": tx_id,
                    "last-error": str(exc),
                })
                raise exc
            applied_authority = manifest.get("runtime-authority") or {}
            if applied_authority.get("release-id") != release_id:
                exc = PortModeError(
                    "port-mode rollback authority belongs to a different release")
                self._write_status({
                    "state": "failed",
                    "action": "rollback",
                    "tx-id": tx_id,
                    "last-error": str(exc),
                })
                raise exc
            try:
                self._validate_last_success(manifest, release_id)
            except PortModeError as exc:
                self._write_status({
                    "state": "failed",
                    "action": "rollback",
                    "tx-id": tx_id,
                    "last-error": str(exc),
                })
                raise
            try:
                self._assert_applied_matches_authority(manifest, authority)
            except PortModeError as exc:
                self._write_status({
                    "state": "failed",
                    "action": "rollback",
                    "tx-id": tx_id,
                    "last-error": str(exc),
                })
                raise
            current_dir = os.path.join(tx_dir, "current")
            _mkdir(current_dir)
            current = {
                "platform-profile": _snapshot(
                    self.runtime_profile, current_dir, "platform.profile"),
                "rdi": _snapshot(self.rdi_target, current_dir,
                                 "fm_platform_attributes.cfg"),
            }
            self._assert_snapshot_matches_authority(current, authority)
            metadata_before = self._snapshot_metadata_before(tx_dir)
            rollback_manifest = os.path.join(tx_dir, "manifest.json")
            rollback_record = {
                "schema-version": 2,
                "tx-id": tx_id,
                "action": "rollback",
                "phase": "prepared",
                "created-at": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "restored-from": manifest.get("tx-id", "-"),
                "current-before-rollback": current,
                "metadata-before": metadata_before,
                "runtime-authority": authority,
            }
            _atomic_write_json(rollback_manifest, rollback_record)
            self._write_status({
                "state": "running", "action": "rollback", "tx-id": tx_id})
            try:
                mutation_attempted = True
                stop_attestation = self._stop_and_attest(release_id)
                self._assert_snapshot_matches_authority(
                    current, stop_attestation)
                rollback_record["phase"] = "stopped"
                rollback_record["stop-attestation"] = stop_attestation
                _atomic_write_json(rollback_manifest, rollback_record)
                self._restore_runtime_pair(previous)
                self._restore_metadata_before(manifest)
                profile_sha = _sha256(self.runtime_profile)
                rdi_sha = _sha256(self.rdi_target)
                rollback_record["phase"] = "files-restored"
                rollback_record["runtime-profile"] = {
                    "path": self.runtime_profile,
                    "sha256": profile_sha,
                }
                rollback_record["rdi"] = {
                    "path": self.rdi_target,
                    "sha256": rdi_sha,
                }
                self._record_start_authority(
                    rollback_record, rollback_manifest, release_id,
                    profile_sha, rdi_sha)
                start_attestation = self._start_and_attest(
                    release_id, profile_sha, rdi_sha, rollback_manifest)
                rollback_record["phase"] = "runtime-healthy"
                rollback_record["start-attestation"] = start_attestation
                _atomic_write_json(rollback_manifest, rollback_record)
                self._write_status({
                    "state": "rolled-back",
                    "action": "rollback",
                    "tx-id": tx_id,
                    "rolled-back-tx-id": manifest.get("tx-id", "-"),
                    "runtime-profile-sha256": rollback_record[
                        "runtime-profile"]["sha256"],
                    "rdi-sha256": rollback_record["rdi"]["sha256"],
                })
                rollback_record["phase"] = "healthy"
                _atomic_write_json(rollback_manifest, rollback_record)
                return rollback_record
            except Exception as exc:
                recovery_error = None
                if mutation_attempted:
                    try:
                        recovery_stop = self._stop_and_attest(release_id)
                        self._restore_runtime_pair(current)
                        self._restore_metadata_before(rollback_record)
                        current_profile_sha = _sha256(self.runtime_profile)
                        current_rdi_sha = _sha256(self.rdi_target)
                        self._record_start_authority(
                            rollback_record, rollback_manifest, release_id,
                            current_profile_sha, current_rdi_sha)
                        recovery_start = self._start_and_attest(
                            release_id,
                            current_profile_sha,
                            current_rdi_sha,
                            rollback_manifest,
                        )
                        rollback_record["phase"] = "restored-after-failure"
                        rollback_record["last-error"] = str(exc)
                        rollback_record[
                            "recovery-stop-attestation"] = recovery_stop
                        rollback_record[
                            "recovery-start-attestation"] = recovery_start
                        _atomic_write_json(rollback_manifest, rollback_record)
                    except Exception as recovery_exc:
                        recovery_error = recovery_exc
                        if rollback_record is not None:
                            rollback_record["phase"] = "recovery-failed"
                            rollback_record["recovery-error"] = str(
                                recovery_exc)
                            try:
                                _atomic_write_json(
                                    rollback_manifest, rollback_record)
                            except Exception:
                                pass
                elif rollback_record is not None:
                    rollback_record["phase"] = "aborted-before-mutation"
                    rollback_record["last-error"] = str(exc)
                    try:
                        _atomic_write_json(rollback_manifest, rollback_record)
                    except Exception:
                        pass
                try:
                    self._write_status({
                        "state": "failed",
                        "action": "rollback",
                        "tx-id": tx_id,
                        "last-error": (
                            str(exc) if recovery_error is None else
                            "%s; recovery: %s" % (exc, recovery_error)
                        ),
                    })
                except Exception:
                    pass
                if recovery_error is not None:
                    raise PortModeError(
                        "port-mode rollback failed and exact current-state "
                        "recovery failed: %s; recovery: %s" %
                        (exc, recovery_error)) from exc
                raise

    def status(self):
        return port_mode_status(self.active_config, self.state_dir,
                                self.rdi_target, self.runtime_profile)


def port_mode_status(active_config=ACTIVE_CONFIG, state_dir=STATE_DIR,
                     rdi_target=RDI_TARGET, runtime_profile=None):
    status = _load_json(os.path.join(state_dir, "status.json"))
    profile_override = runtime_profile if (
        runtime_profile and os.path.exists(runtime_profile)) else None
    try:
        configured = read_configured_intent(active_config, fallback=True,
                                            fallback_profile=profile_override)
    except PortModeError as exc:
        configured = {"error": str(exc)}
    applied = active_profile_facts(profile_override)
    drift = False
    if "error" not in configured and "error" not in applied:
        drift = (
            configured.get("port-mode") != applied.get("port-mode") or
            configured.get("network-services") !=
            applied.get("network-services")
        )
    return {
        "configured": configured,
        "applied": applied,
        "rdi": {
            "path": rdi_target,
            "sha256": _sha256(rdi_target),
        },
        "transaction": status,
        "drift": drift,
    }


def start_background_action(action, release_tool=None):
    if action not in ("apply", "rollback"):
        raise PortModeError("unsupported port-mode action: %s" % action)
    tool = release_tool or RELEASE_TOOL
    if not os.path.isfile(tool) or not os.access(tool, os.X_OK):
        raise PortModeError("immutable release runtime not found: %s" % tool)
    _mkdir(LOG_DIR)
    log_path = os.path.join(LOG_DIR, "port-mode-%s.log" % action)
    with open(log_path, "ab", buffering=0) as log:
        proc = subprocess.Popen(
            [tool, "port-mode", action],
            cwd="/",
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    return proc.pid, log_path


def format_status_text(data):
    configured = data.get("configured", {})
    applied = data.get("applied", {})
    rdi = data.get("rdi", {})
    tx = data.get("transaction", {})
    lines = [
        "Port-mode apply status:",
        "  Configured port-mode  : %s" % configured.get("port-mode", "-"),
        "  Configured services   : %s" %
        configured.get("network-services", "-"),
        "  Config source         : %s" % configured.get("source", "-"),
        "  Applied port-mode     : %s" % applied.get("port-mode", "-"),
        "  Applied services      : %s" %
        applied.get("network-services", "-"),
        "  Applied profile       : %s" % applied.get("path", "-"),
        "  Profile checksum      : %s" % applied.get("sha256", "-"),
        "  RDI file              : %s" % rdi.get("path", "-"),
        "  RDI checksum          : %s" % rdi.get("sha256", "-"),
        "  Config/applied drift  : %s" %
        ("yes" if data.get("drift") else "no"),
        "  Last transaction      : %s tx=%s action=%s" % (
            tx.get("state", "none"),
            tx.get("tx-id", "-"),
            tx.get("action", "-"),
        ),
    ]
    if tx.get("last-error"):
        lines.append("  Last error            : %s" % tx["last-error"])
    return "\n".join(lines)
