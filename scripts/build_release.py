#!/usr/bin/env python3
"""Build the public source/installer bundle and paired Debian package."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.release import (COMPATIBILITY, FORMAT, REPOSITORY, MANIFEST_NAME,
    ReleaseError, json_bytes, safe_relative, sha256, validate_manifest, version_tuple)
from build_deb import build as build_deb
from check_public import audit_package, audit_tree, content_issues, source_files


def build(root: Path, output: Path, dependency: Path, *, allow_dirty=False):
    version = (root / "VERSION").read_text().strip()
    version_tuple(version)
    from fm10k_controlpanel import __version__
    versions = [tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"], __version__,
                json.loads((root / "frontend/package.json").read_text())["version"]]
    lockfile = json.loads((root / "frontend/package-lock.json").read_text())
    versions.extend((lockfile["version"], lockfile["packages"][""]["version"]))
    if any(value != version for value in versions):
        raise ReleaseError("VERSION, Python and frontend package versions must agree")
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=root).strip()
    if dirty and not allow_dirty:
        raise ReleaseError("commit the reviewed source before building a release (or use --allow-dirty for a local preview)")
    commit = "0" * 40 if dirty else subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=root, text=True).strip())
    findings, _ = audit_tree(root)
    if findings:
        raise ReleaseError("public source check failed:\n" + "\n".join(findings))
    lock = json.loads((root / "deploy/release-dependencies.json").read_text())["libyang"]
    if sha256(dependency) != lock["sha256"]:
        raise ReleaseError("libyang source does not match the locked SHA-256")
    output.mkdir(parents=True, exist_ok=True)
    package = output / f"fm10k-controlpanel_{version}_all.deb"
    build_deb(root, package, version, epoch)
    findings, _ = audit_package(package, root)
    if findings:
        raise ReleaseError("public package check failed:\n" + "\n".join(findings))
    # Use Git's public file inventory, never copy the workspace recursively.
    files = {}
    executable = {"install.sh"}
    for line in subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root).split(b"\0"):
        if line and line.startswith(b"100755 "):
            executable.add(line.split(b"\t", 1)[1].decode())
    for name in source_files(root):
        if not safe_relative(name) or (root / name).is_symlink():
            raise ReleaseError("unsupported source path: " + name)
        files[name] = ((root / name).read_bytes(), 0o755 if name in executable else 0o644)
    files["packages/" + package.name] = (package.read_bytes(), 0o644)
    files["dependencies/" + lock["archive"]] = (dependency.read_bytes(), 0o644)
    inventory = {name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": mode}
                 for name, (raw, mode) in sorted(files.items())}
    files["bundle-manifest.json"] = (json_bytes({"schema": FORMAT, "repository": REPOSITORY, "version": version,
                                               "compatibility": COMPATIBILITY, "files": inventory}), 0o644)
    archive = output / f"fm10k-controlpanel-{version}.tar.gz"
    with archive.open("wb") as stream, gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            for name, (raw, mode) in sorted(files.items()):
                info = tarfile.TarInfo(f"fm10k-controlpanel-{version}/{name}")
                info.size, info.mode, info.mtime = len(raw), mode, epoch
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                tar.addfile(info, io.BytesIO(raw))
    manifest = validate_manifest({"schema": FORMAT, "repository": REPOSITORY, "version": version, "tag": "v" + version,
        "source_commit": commit, "compatibility": COMPATIBILITY,
        "sdk_manifest_sha256": sha256(root / "hardware/sdk-inputs.json"),
        "assets": {key: {"name": path.name, "sha256": sha256(path), "size": path.stat().st_size}
                   for key, path in (("web", package), ("bundle", archive))}})
    (output / MANIFEST_NAME).write_bytes(json_bytes(manifest))
    assets = [archive, package, output / MANIFEST_NAME]
    (output / "SHA256SUMS").write_text("".join(f"{sha256(path)}  {path.name}\n" for path in assets))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/release")
    parser.add_argument("--libyang-archive", type=Path)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    dependency = args.libyang_archive
    if dependency is None:
        lock = json.loads((ROOT / "deploy/release-dependencies.json").read_text())["libyang"]
        cache = ROOT / "artifacts/dependencies"
        cache.mkdir(parents=True, exist_ok=True)
        dependency = cache / lock["archive"]
        if not dependency.is_file() or sha256(dependency) != lock["sha256"]:
            with urllib.request.urlopen(lock["url"], timeout=30) as source:
                raw = source.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != lock["sha256"]:
                raise ReleaseError("downloaded libyang source failed verification")
            dependency.write_bytes(raw)
    print(json.dumps(build(ROOT, args.output, dependency, allow_dirty=args.allow_dirty), indent=2))


if __name__ == "__main__":
    main()
