#!/usr/bin/env python3
"""Install the paired RoCE release only after a complete system backup.

Run as root on the target A11 board after reviewing the upgrade. Never flashes
firmware or changes the saved switch configuration. Restores the whole native
runtime, boot metadata and configuration checkpoint if initialization fails.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parents[1]
RUNTIME = Path("/opt/fm10k-controlpanel/native")
BOOT = Path("/etc/fm10k-controlpanel/native")
CONFIG = Path("/var/lib/fm10k-controlpanel-native/config")
DAEMONS = ("panel", "configd", "mgmtd", "l2d", "stpd", "lacpd", "lldpd", "packetd",
           "statsd", "ifd", "chassisd", "linkmond", "switchd", "identityd")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(*args, timeout=180):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stdout[-2000:]} {result.stderr[-2000:]}")
    return result.stdout


def replace(path, content, mode=0o644):
    temporary = path.with_name(path.name + ".roce-new")
    with temporary.open("wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(mode)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--rollback-package", type=Path, required=True)
    parser.add_argument("--system-backup", type=Path)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--preserve-buffer", action="store_true",
                        help="upgrade an initialized RoCE runtime, keeping the verified buffer/startup layout")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() or SOURCE == RUNTIME or not (RUNTIME / "vendor/netlab/build/switchd").is_file():
        raise SystemExit("run the staged source as root on the installed board")
    if not args.preserve_buffer and args.system_backup is None:
        raise SystemExit("initial buffer migration requires a complete system backup")
    if args.system_backup is not None:
        backup_manifest = json.loads((args.system_backup / "manifest.json").read_text())
        if not backup_manifest.get("complete") or not backup_manifest.get("archives_valid"):
            raise SystemExit("a complete, verified system backup is required before deployment")
        sums = dict((name, value) for value, name in
                    (line.split("  ", 1) for line in (args.system_backup / "SHA256SUMS").read_text().splitlines()))
        for name in ("root.tar.zst", "efi.tar.zst"):
            if digest(args.system_backup / name) != sums[name]:
                raise SystemExit("system backup checksum mismatch: " + name)
    if command("dpkg-query", "-W", "-f=${Version}", "fm10k-controlpanel").strip() != args.expected_version:
        raise SystemExit("installed version does not match the reviewed upgrade baseline")
    if command("dpkg-deb", "-f", str(args.package), "Version").strip() != args.target_version:
        raise SystemExit("target package version mismatch")
    if command("dpkg-deb", "-f", str(args.rollback_package), "Version").strip() != args.expected_version:
        raise SystemExit("rollback package does not match the installed baseline")
    sys.path.insert(0, str(SOURCE / "backend"))
    os.environ["PANEL_NETLAB_ROOT"] = str(RUNTIME / "vendor/netlab")
    from fm10k_controlpanel.netlab import NetlabBackend
    from fm10k_controlpanel.netlab_codec import parse_xml
    from fm10k_controlpanel.preflight import inspect_sdk
    for directory in (SOURCE, RUNTIME):
        if not inspect_sdk(directory / "hardware/sdk/ies", SOURCE / "hardware/sdk-inputs.json")["valid"]:
            raise SystemExit("staged and installed SDK inputs must both match the pinned release")
    backend = NetlabBackend()
    before = backend.snapshot()
    if not before["hardware_write_ready"] or before["pending"] or before["configuration"]["profile"] != "sil001-hw5-a11":
        raise SystemExit("expected synchronized A11 control with no pending transaction")
    ports = backend.ports()
    if len(ports) != 24 or any(p["link"] != "down" or p["state_quality"] != "valid" for p in ports):
        raise SystemExit("checkpointed upgrade requires all 24 data ports to be confirmed Down")
    if args.preserve_buffer:
        flow = parse_xml(backend._rpc(7, 68, b"flow-control")).find("flow-control")
        if flow is None or flow.get("roce-buffer-status") != "0":
            raise SystemExit("existing mixed-buffer layout is not ready")
    eye = backend.eye_read()
    if eye.get("state") in ("running", "queued", "cancelling", "restoring"):
        raise SystemExit("finish the eye scan before deployment")
    backend.close()
    binaries = [p for p in (SOURCE / "vendor/netlab/build").iterdir()
                if p.is_file() and not p.is_symlink() and p.stat().st_mode & 0o111 and p.read_bytes()[:4] == b"\x7fELF"]
    required = set(DAEMONS) - {"panel"}
    if not required <= {p.name for p in binaries}:
        raise SystemExit("the matching native build is incomplete")
    paths = json.loads((SOURCE / "release-files.json").read_text())
    for path, expected in paths.items():
        if Path(path).is_absolute() or ".." in Path(path).parts or digest(SOURCE / path) != expected:
            raise SystemExit("source manifest mismatch: " + path)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    checkpoint = Path("/var/backups/fm10k-controlpanel") / ("before-roce-" + stamp)
    checkpoint.mkdir(mode=0o700)
    args.evidence.mkdir(parents=True, exist_ok=True)
    report = {"started_at": time.time(), "before": before, "system_backup": str(args.system_backup) if args.system_backup else None,
              "buffer_preserved": args.preserve_buffer, "expected_version": args.expected_version, "target_version": args.target_version,
              "checkpoint": str(checkpoint), "package_sha256": digest(args.package), "installed": False}
    protected = [Path("/var/lib/fm10k-controlpanel/accounts.json"), Path("/etc/fm10k-controlpanel/panel.env"),
                 Path("/etc/fm10k-controlpanel/native.env")]
    report["protected_hashes"] = {str(p): digest(p) for p in protected}
    active = [f"fm10k-{name}.service" for name in DAEMONS
              if subprocess.run(["systemctl", "is-active", "--quiet", f"fm10k-{name}.service"]).returncode == 0]

    def save_report():
        (args.evidence / "install.json").write_text(json.dumps(report, indent=2))

    def stop():
        command("systemctl", "stop", *active)

    def start():
        for unit in reversed(active):
            command("systemctl", "start", unit)

    def recovered():
        for _ in range(80):
            try:
                state = backend.snapshot()
                if state["hardware_write_ready"] and not state["pending"]:
                    return state
            except Exception:
                pass
            time.sleep(2)
        raise RuntimeError("control did not become synchronized after startup")

    save_report()
    print("Stopping services for checkpointed buffer initialization", flush=True)
    stop()
    checkpoint_ready = False
    try:
        shutil.copytree(RUNTIME, checkpoint / "native", symlinks=True)
        shutil.copytree(BOOT, checkpoint / "boot", symlinks=True)
        shutil.copytree(CONFIG, checkpoint / "config", symlinks=True)
        shutil.copy2(args.rollback_package, checkpoint / "rollback.deb")
        checkpoint_ready = True
        print("Checkpoint saved; installing paired native/Web release", flush=True)
        for relative in paths:
            source, target = SOURCE / relative, RUNTIME / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            replace(target, source.read_bytes(), 0o755 if source.stat().st_mode & 0o111 else 0o644)
        for source in binaries:
            replace(RUNTIME / "vendor/netlab/build" / source.name, source.read_bytes(), 0o755)
        if not args.preserve_buffer:
            platform = BOOT / "fm_platform_attributes.cfg"
            original = platform.read_text()
            updated = "\n".join(line for line in original.splitlines()
                                if not re.match(r"^api\.FM10000\.(wmSelect|cmPauseBufferBytes)\s", line))
            updated += "\n# RC20 static PFC buffer envelope, applied before data-port replay.\napi.FM10000.wmSelect text lossy_lossless\napi.FM10000.cmPauseBufferBytes int 49152\n"
            replace(platform, updated.encode())
            manifest = json.loads((BOOT / "startup.json").read_text())
            manifest["sha256"][str(platform)] = digest(platform)
            replace(BOOT / "startup.json", (json.dumps(manifest, indent=2) + "\n").encode(), 0o600)
        command("dpkg", "--force-confold", "-i", str(args.package))
        start()
        after = recovered()
        if before["configuration"] != after["configuration"]:
            raise RuntimeError("saved configuration was not preserved")
        if any(digest(path) != expected for path, expected in report["protected_hashes"].items()):
            raise RuntimeError("account or environment changed during installation")
        status = backend.operational("roce")
        if not status["buffer_ready"] or not status["configuration_applied"]:
            raise RuntimeError("RoCE buffer or baseline mapping readback failed")
        report.update(installed=True, after=after, operational=status, finished_at=time.time(),
                      native_binaries={p.name: digest(RUNTIME / "vendor/netlab/build" / p.name) for p in binaries})
        save_report()
        print(json.dumps({"installed": True, "revision": after["revision"], "buffer_ready": True,
                          "checkpoint": str(checkpoint)}), flush=True)
    except Exception as error:
        report["error"] = str(error)
        save_report()
        if checkpoint_ready:
            print("Initialization failed; restoring native, boot and configuration checkpoint", flush=True)
            stop()
            for target, saved in ((RUNTIME, checkpoint / "native"), (BOOT, checkpoint / "boot"), (CONFIG, checkpoint / "config")):
                failed = target.with_name(target.name + ".roce-failed-" + stamp)
                os.replace(target, failed)
                shutil.copytree(saved, target, symlinks=True)
            command("dpkg", "--force-confold", "-i", str(checkpoint / "rollback.deb"))
            start()
            report["restored"] = recovered()
            save_report()
        else:
            start()
        raise


if __name__ == "__main__":
    main()
