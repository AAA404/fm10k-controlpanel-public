#!/usr/bin/env python3
"""Import pinned, user-supplied SDK inputs locally. No download or SDK publishing."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import struct
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.preflight import header_digest


def checked_member(archive, entry):
    names = [name for name in archive.namelist() if name.endswith(entry["suffix"])]
    if len(names) != 1:
        raise ValueError(f"expected exactly one SDK member: {entry['suffix']}")
    info = archive.getinfo(names[0])
    if info.file_size > 64 * 1024 * 1024:
        raise ValueError("SDK member exceeds the pinned size budget")
    data = archive.read(info)
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError(f"SDK SHA-256 mismatch: {entry['suffix']}")
    return data


def import_sdk(source: Path, destination: Path):
    manifest = json.loads((ROOT / "hardware/sdk-inputs.json").read_text())
    if destination.exists():
        raise ValueError(f"destination already exists: {destination}; use a new directory for another import")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".sdk-import-", dir=destination.parent))
    try:
        with zipfile.ZipFile(source) as archive:
            data = checked_member(archive, manifest["archive"])
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                members = tar.getmembers()
                if sum(member.size for member in members) > 100 * 1024 * 1024:
                    raise ValueError("SDK source exceeds the extraction budget")
                for member in members:
                    parts = PurePosixPath(member.name).parts
                    if not parts or ".." in parts or PurePosixPath(member.name).is_absolute():
                        raise ValueError("unsafe SDK archive path")
                    # Keep the ies tree; do not preserve ownership, special files,
                    # symlinks, or archive-supplied permissions.
                    if len(parts) < 2 or parts[1] != "ies":
                        continue
                    target = temporary.joinpath(*parts[1:])
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with tar.extractfile(member) as src, target.open("xb") as out:
                            shutil.copyfileobj(src, out)
                        target.chmod(0o644)
                    else:
                        raise ValueError("SDK archive contains an unsupported special entry")
            build = temporary / "ies/build"
            build.mkdir(parents=True, exist_ok=True)
            for entry in manifest["libraries"]:
                library = checked_member(archive, entry)
                if library[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", library, 18)[0] != 62:
                    raise ValueError("SDK library is not an ELF64 x86-64 binary")
                (build / PurePosixPath(entry["suffix"]).name).write_bytes(library)
        for name in ("fm_sdk.h", "fm_sdk_int.h"):
            if not (temporary / "ies/include" / name).is_file():
                raise ValueError(f"missing required SDK header: {name}")
        headers = header_digest(temporary / "ies/include")
        if any(headers[key] != manifest["headers"][key] for key in ("files", "sha256")):
            raise ValueError("SDK header tree does not match the pinned source archive")
        (temporary / "input-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return destination / "ies"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="user-supplied 网卡sdk.zip")
    parser.add_argument("--destination", type=Path, default=ROOT / "hardware/sdk")
    args = parser.parse_args()
    try:
        print(import_sdk(args.archive, args.destination.resolve()))
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, f"SDK import failed: {error}\n")


if __name__ == "__main__":
    main()
