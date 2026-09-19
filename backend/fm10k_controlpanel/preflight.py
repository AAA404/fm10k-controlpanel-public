"""Read-only Debian/PCI/driver/SDK inventory; no module loading or I2C writes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import sys
import time

PROFILE = "sil001-hw4-b0"
# Kept stdlib-only so this probe can be copied to a board before installation.
CANDIDATE_PROFILES = {"B0": PROFILE, "A11": "sil001-hw5-a11"}


def _identity_strings(data: bytes) -> list[str]:
    # Silicom's identifier resource contains an OEM binary header, NUL/FF
    # padding, and separate model/version/serial strings. Only inspect bytes
    # inside a structurally validated read-only resource, never the raw VPD
    # as a whole (which can include writable or trailing identity lookalikes).
    return [value.decode("ascii").strip() for value in re.findall(rb"[\x20-\x7e]{4,}", data)]


def parse_vpd(data: bytes) -> dict:
    """Decode PCI VPD resource records before interpreting board strings."""
    if not data or len(data) > 32768:
        raise ValueError("empty or oversized PCI VPD")
    offset, values, checksum, ended = 0, [], None, False
    identifier_seen, readonly_seen, keywords_seen = False, False, set()
    while offset < len(data):
        tag = data[offset]
        offset += 1
        if tag & 0x80:
            if offset + 2 > len(data):
                raise ValueError("truncated VPD resource header")
            size = int.from_bytes(data[offset:offset + 2], "little")
            offset += 2
        else:
            if tag == 0x78:
                ended = True
                break
            size = tag & 7
        end = offset + size
        if end > len(data):
            raise ValueError("truncated VPD resource")
        if tag == 0x82:
            if identifier_seen or readonly_seen:
                raise ValueError("duplicate or out-of-order VPD identifier resource")
            identifier_seen = True
            values.extend(_identity_strings(data[offset:end]))
        elif tag == 0x90:  # read-only keyword fields; writable fields cannot prove identity
            if readonly_seen:
                raise ValueError("duplicate VPD read-only resource")
            readonly_seen = True
            cursor = offset
            while cursor < end:
                if cursor + 3 > end:
                    raise ValueError("truncated VPD keyword")
                key, size = data[cursor:cursor + 2], data[cursor + 2]
                cursor += 3
                if cursor + size > end:
                    raise ValueError("VPD keyword exceeds its resource")
                if key in keywords_seen:
                    raise ValueError("duplicate VPD keyword")
                keywords_seen.add(key)
                if key == b"RV":
                    if not size or cursor + size != end:
                        raise ValueError("VPD checksum field must be the final keyword")
                    checksum = sum(data[:cursor + 1]) % 256 == 0
                else:
                    values.extend(_identity_strings(data[cursor:cursor + size]))
                cursor += size
        offset = end
    if not ended or checksum is False or any(byte not in (0, 255) for byte in data[offset:]):
        raise ValueError("VPD end tag or checksum is invalid")
    models = {value.upper() for value in values if re.fullmatch(r"PE31625G24DIRA(?:-MPS)?", value, re.I)}
    revisions = {value for value in values if re.fullmatch(r"\d{4}", value)}
    serials = {value for value in values if re.fullmatch(r"[FS]\d{10,}", value)}
    version = next(iter(revisions)) if len(revisions) == 1 else None
    significant = version.lstrip("0") if version else ""
    family = ("A11" if significant[0] >= "6" else "B0") if significant else None
    return {"model": next(iter(models)) if len(models) == 1 else None,
            "serial": next(iter(serials)) if len(serials) == 1 else None,
            "vpd_version": version, "family": family, "checksum_valid": checksum,
            "family_source": "supplied Aurum VPD-version rule; not an ASIC register"}


def _read_text(path):
    try:
        return path.read_text().strip()
    except OSError:
        return None


def inspect_pci_device(path: Path) -> dict:
    fields = {name: _read_text(path / name) for name in ("vendor", "device", "subsystem_vendor", "subsystem_device", "revision")}
    expected = {"vendor": "0x8086", "device": "0x15a4", "subsystem_vendor": "0x1374", "subsystem_device": "0x01d0"}
    raw = b""
    try:
        with (path / "vpd").open("rb") as stream:
            raw = stream.read(32769)
        identity = parse_vpd(raw)
        vpd_error = None
    except (OSError, ValueError, UnicodeError) as error:
        identity, vpd_error = {}, str(error)
    candidate = CANDIDATE_PROFILES.get(identity.get("family"))
    matched = all(fields[key] == value for key, value in expected.items()) and bool(
        identity.get("model") and identity.get("serial") and candidate
        and identity.get("checksum_valid") is True)
    if vpd_error:
        reason = "invalid_vpd"
    elif any(fields[key] != value for key, value in expected.items()):
        reason = "unsupported_pci_identity"
    elif identity.get("checksum_valid") is not True:
        reason = "missing_vpd_checksum"
    elif not identity.get("model") or not identity.get("serial") or not identity.get("family"):
        reason = "incomplete_or_ambiguous_vpd_identity"
    elif candidate is None:
        reason = "unsupported_board_revision"
    else:
        reason = None
    driver = (path / "driver").resolve().name if (path / "driver").is_symlink() else None
    return {"bdf": path.name, **fields, "identity": identity, "vpd_error": vpd_error,
            "vpd_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "vpd_size": len(raw), "profile_rejection": reason,
            "identity_matched": matched, "candidate_profile": candidate if matched else None,
            "profile_qualification": "unqualified",
            "driver": driver, "uio": sorted(child.name for child in (path / "uio").glob("uio*"))}


def header_digest(directory: Path) -> dict:
    digest = hashlib.sha256()
    files = sorted(path for path in directory.rglob("*") if path.is_file())
    for path in files:
        if path.is_symlink():
            raise ValueError("SDK headers must not contain symbolic links")
        digest.update(path.relative_to(directory).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return {"files": len(files), "sha256": digest.hexdigest()}


def inspect_sdk(sdk: Path, manifest_path: Path) -> dict:
    if not manifest_path.is_file():
        return {"valid": False, "error": "SDK input manifest is missing"}
    manifest = json.loads(manifest_path.read_text())
    try:
        headers = header_digest(sdk / "include")
        expected = manifest.get("headers", {})
        headers["valid"] = headers["files"] > 0 and all(headers[key] == expected.get(key) for key in ("files", "sha256"))
    except (OSError, ValueError) as error:
        headers = {"valid": False, "error": str(error)}
    libraries = []
    for entry in manifest["libraries"]:
        path = sdk / "build" / Path(entry["suffix"]).name
        try:
            if path.is_symlink():
                raise OSError("SDK libraries must not be symbolic links")
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            elf_ok = len(raw) >= 20 and raw[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", raw, 18)[0] == 62
            valid = digest == entry["sha256"] and elf_ok
            libraries.append({"file": str(path), "sha256": digest, "valid": valid})
        except OSError as error:
            libraries.append({"file": str(path), "valid": False, "error": str(error)})
    return {"release": manifest["release"], "libraries": libraries, "headers": headers,
            "valid": headers["valid"] and bool(libraries) and all(library["valid"] for library in libraries),
            "abi": "requires successful native compile/link probe; hashes alone do not prove ABI"}


def inventory(*, sysfs=Path("/sys"), os_release=Path("/etc/os-release"), bdf=None, sdk=None, sdk_manifest=None):
    release = {}
    for line in (_read_text(os_release) or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    pci = sysfs / "bus/pci/devices"
    devices = [inspect_pci_device(path) for path in sorted(pci.glob("*"))
               if (bdf is None or path.name == bdf) and _read_text(path / "device") == "0x15a4"]
    matched = [device for device in devices if device["identity_matched"]]
    host_ok = release.get("ID") == "debian" and release.get("VERSION_ID") == "13" and platform.machine() == "x86_64"
    driver_version = _read_text(sysfs / "module/fm10k/version")
    checks = {"debian13_amd64": host_ok, "unique_supported_board": len(matched) == 1,
              "driver_version": driver_version == "6.12.101-ies2",
              "uio_bound": len(devices) == 1 and devices[0]["driver"] == "fm10k" and bool(devices[0]["uio"])}
    report = {"schema": 1, "sampled_at": time.time(),
              "profile": matched[0]["candidate_profile"] if len(matched) == 1 else None,
              "host": {"os": release, "architecture": platform.machine(), "kernel": platform.release()},
              "devices": devices, "driver_version": driver_version, "checks": checks,
              "hardware_write_ready": False,
              "write_gate": "switchd must independently bind the complete HAL and verify this identity before writes",
              "hardware_qualification": "not-run"}
    if sdk is not None and sdk_manifest is not None:
        report["sdk"] = inspect_sdk(sdk, sdk_manifest)
        checks["sdk_inputs"] = report["sdk"]["valid"]
    report["preflight_passed"] = all(checks.values())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bdf", help="PCI function, required when multiple boards exist")
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--sdk-manifest", type=Path, default=Path("/usr/share/fm10k-controlpanel/sdk-inputs.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.bdf and not re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", args.bdf):
        parser.error("invalid PCI BDF")
    report = inventory(bdf=args.bdf, sdk=args.sdk, sdk_manifest=args.sdk_manifest)
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")
    return 0 if report["preflight_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
