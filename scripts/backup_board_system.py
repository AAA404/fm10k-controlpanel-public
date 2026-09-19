#!/usr/bin/env python3
"""Full file-system/EFI and boot metadata backup of the verified Debian board.

Run on the target board before deployment. Produces a bare-metal recovery
archive, not an atomic image of a running block device. Requires root.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

DAEMONS = ("panel", "configd", "mgmtd", "l2d", "stpd", "lacpd", "lldpd",
           "packetd", "statsd", "ifd", "chassisd", "linkmond", "switchd", "identityd")


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def main():
    if os.geteuid() or run("findmnt", "-no", "SOURCE", "/").strip() != "/dev/sda2":
        raise SystemExit("expected the verified /dev/sda2 board root filesystem")
    if shutil.disk_usage("/var/backups").free < 5_800_000_000:
        raise SystemExit("insufficient staging space; do not risk filling the root filesystem")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = Path("/var/backups") / ("fm10840-system-" + stamp)
    out.mkdir(mode=0o700)
    os.umask(0o077)
    report = {"started_at": time.time(), "type": "filesystem-and-efi", "complete": False,
              "root": "/dev/sda2", "disk": "/dev/sda", "directory": str(out)}
    sys.path.insert(0, "/usr/lib/fm10k-controlpanel/python")
    os.environ["PANEL_NETLAB_ROOT"] = "/opt/fm10k-controlpanel/native/vendor/netlab"
    from fm10k_controlpanel.netlab import NetlabBackend
    backend = NetlabBackend()
    report["configuration_before"] = backend.snapshot()
    backend.close()
    if report["configuration_before"]["pending"] or not report["configuration_before"]["synchronized"]:
        raise SystemExit("finish or recover the pending configuration before backing up")
    for name, command in {
        "partitions.sfdisk": ["sfdisk", "--dump", "/dev/sda"],
        "lsblk.json": ["lsblk", "-b", "-J", "-o", "NAME,TYPE,SIZE,FSTYPE,UUID,PARTUUID,MOUNTPOINTS"],
        "blkid.txt": ["blkid"], "packages.tsv": ["dpkg-query", "-W"],
        "mounts.txt": ["findmnt"], "units.txt": ["systemctl", "list-unit-files", "--no-pager"],
    }.items():
        (out / name).write_text(run(*command))
    efi = subprocess.run(["efibootmgr", "-v"], capture_output=True, text=True)
    (out / "efibootmgr.txt").write_text(efi.stdout + efi.stderr)
    sectors = int(run("blockdev", "--getsz", "/dev/sda"))
    with open("/dev/sda", "rb", buffering=0) as disk:
        (out / "disk-first-1MiB.bin").write_bytes(disk.read(1048576))
        disk.seek(sectors * 512 - 1048576)
        (out / "disk-last-1MiB.bin").write_bytes(disk.read(1048576))
    active = [f"fm10k-{name}.service" for name in DAEMONS
              if subprocess.run(["systemctl", "is-active", "--quiet", f"fm10k-{name}.service"]).returncode == 0]
    report["active_services"] = active
    (out / "manifest.json").write_text(json.dumps(report, indent=2))
    print(f"BACKUP_DIRECTORY={out}", flush=True)
    try:
        subprocess.run(["systemctl", "stop", *active], check=True, timeout=120)
        run("sync")
        for label, directory in (("root", "/"), ("efi", "/boot/efi")):
            archive = out / (label + ".tar.zst")
            cmd = ["tar", "--create", "--one-file-system", "--acls", "--xattrs", "--xattrs-include=*",
                   "--numeric-owner", "--sparse", "--file=-", "--directory=" + directory]
            if label == "root":
                cmd += ["--exclude=./" + str(out).lstrip("/")]
            cmd += ["."]
            print(f"Archiving {directory}", flush=True)
            with (out / (label + "-tar.log")).open("w") as log, archive.open("wb") as dest:
                # Bound this backup's output below available staging capacity.
                import resource
                def limit_output():
                    resource.setrlimit(resource.RLIMIT_FSIZE, (5_500_000_000, 5_500_000_000))
                tar = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=log)
                zstd = subprocess.Popen(["zstd", "-T1", "-3", "-q"], stdin=tar.stdout, stdout=dest, stderr=log,
                                        preexec_fn=limit_output)
                tar.stdout.close()
                zcode, tcode = zstd.wait(), tar.wait()
            report[label + "_tar_exit"] = tcode
            # GNU tar status 1 may reflect journal/log changes on a live OS;
            # retain the exact warnings, never silently claim a disk snapshot.
            if zcode or tcode not in (0, 1):
                raise RuntimeError(f"backup failed: tar={tcode}, zstd={zcode}")
            subprocess.run(["zstd", "-tq", str(archive)], check=True)
            with (out / (label + "-index.txt")).open("w") as listing:
                subprocess.run(["tar", "--zstd", "-tf", str(archive)], stdout=listing, check=True)
        root_index = (out / "root-index.txt").read_text()
        for required in ("./etc/fstab", "./boot/", "./opt/fm10k-controlpanel/", "./var/lib/fm10k-controlpanel-native/"):
            if required not in root_index:
                raise RuntimeError("missing required system content: " + required)
        if "EFI" not in (out / "efi-index.txt").read_text():
            raise RuntimeError("EFI backup is empty")
        report["archives_valid"] = True
    finally:
        # Identity and ASIC owner start first; systemd resolves dependencies.
        for unit in reversed(active):
            subprocess.run(["systemctl", "start", unit], timeout=180, check=False)
        report["finished_at"] = time.time()
        (out / "manifest.json").write_text(json.dumps(report, indent=2))
    for attempt in range(60):
        try:
            after = backend.snapshot()
            if after["synchronized"] and not after["pending"]:
                report["configuration_after"] = after
                break
        except Exception:
            pass
        time.sleep(2)
    else:
        raise RuntimeError("services restarted but configuration is not yet verified")
    if report["configuration_before"]["configuration"] != after["configuration"]:
        raise RuntimeError("configuration changed during backup")
    report["complete"] = True
    (out / "manifest.json").write_text(json.dumps(report, indent=2))
    hashes = {}
    for path in out.iterdir():
        if path.is_file() and path.name != "SHA256SUMS":
            with path.open("rb") as stream:
                hashes[path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    (out / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())))
    print(json.dumps({"complete": True, "directory": str(out), "hashes": hashes}), flush=True)


if __name__ == "__main__":
    main()
