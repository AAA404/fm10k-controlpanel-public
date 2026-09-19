#!/usr/bin/env python3
"""Check source/history or a Debian package for material excluded from publication.

Reports locations and rule names, never matched secret values. This is a
project content gate, not proof that arbitrary credentials can be detected.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
BLOCKED_PARTS = {".git", ".venv", "node_modules", "__pycache__", "artifacts", "local-state", "runtime"}
BLOCKED_SUFFIXES = (".deb", ".ko", ".so", ".a", ".o", ".pyc", ".log", ".pcap", ".pcapng",
                    ".pem", ".key", ".p12", ".pfx", ".7z", ".zip", ".iso", ".img", ".bin",
                    ".tar", ".tar.gz", ".tar.zst", ".tgz")
BLOCKED_NAMES = {".env", "id_rsa", "id_ed25519", "accounts.json", "initial-admin.json",
                 "release-files.json", "reference_original_6x100.cfg", "fm_platform_attributes_silicom_A11h.cfg",
                 "sil001-hw4-b0.cfg", "sil001-hw5-a11.cfg"}
EXTERNAL_PLATFORM_DIGESTS = {
    "38c481b5d8035df14bc517735cd8e1c1ba9936fdc512fd18c849878fe323da98",
    "8f5c1700c48984d539ff526f4a4ba18c814db27282de2afe33c90a2888c87d96",
}
HISTORICAL_DOCUMENT = re.compile(r"(?:VERIFICATION|RELEASE_RC\d+|RELEASE_RDMA100G2|.*(?:2026-\d\d-\d\d|202609\d\d))\.md$", re.I)
SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
    "service token": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,})"),
    "personal workstation path": re.compile(r"/(?:Users|Volumes)/[^\s\"'`]+"),
}
PRIVATE_IP = re.compile(r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")
CONVERSATION_ID = re.compile(r"\b01[0-9a-f]{6}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)


def path_issues(name: str) -> list[str]:
    path = PurePosixPath(name)
    problems = []
    if path.is_absolute() or ".." in path.parts:
        problems.append("unsafe archive path")
    if BLOCKED_PARTS.intersection(path.parts) or any(p in "/" + name for p in ("/hardware/sdk/", "/vendor/sdk/")):
        problems.append("private/generated directory")
    if path.name in BLOCKED_NAMES or path.name.startswith(".env.") and path.name != ".env.example":
        problems.append("private input or credential file")
    if path.name.endswith(BLOCKED_SUFFIXES):
        problems.append("binary, archive, credential or evidence file")
    if HISTORICAL_DOCUMENT.fullmatch(path.name):
        problems.append("historical working document")
    return problems


def content_issues(name: str, data: bytes, markers: tuple[str, ...] = ()) -> list[str]:
    problems = path_issues(name)
    if hashlib.sha256(data).hexdigest() in EXTERNAL_PLATFORM_DIGESTS:
        problems.append("separately supplied platform input")
    if b"\0" in data:
        problems.append("binary content")
        return problems
    text = data.decode("utf-8", errors="replace")
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            problems.append(label)
    if name.endswith(".md"):
        if PRIVATE_IP.search(text):
            problems.append("live private address in documentation")
        if CONVERSATION_ID.search(text):
            problems.append("conversation identifier in documentation")
    if any(marker.casefold() in text.casefold() for marker in markers):
        problems.append("private review marker")
    return problems


def git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, input=data, stderr=subprocess.PIPE)


def source_files(root: Path) -> list[str]:
    return sorted(set(p.decode() for p in git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0") if p))


def document_list(root: Path) -> list[str]:
    names = json.loads((root / "deploy/public-documents.json").read_text())
    if (not isinstance(names, list) or not names or any(not isinstance(n, str) or not re.fullmatch(r"[A-Z0-9_-]+\.md", n) for n in names)
            or len(set(names)) != len(names)):
        raise ValueError("invalid public document allowlist")
    return names


def document_links(root: Path, name: str, text: str) -> list[str]:
    failures = []
    for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
        target = target.strip().strip("<>").split("#", 1)[0]
        if not target or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", target):
            continue
        resolved = (root / name).parent / unquote(target)
        if not resolved.exists():
            failures.append("missing relative documentation target")
    return sorted(set(failures))


def audit_tree(root: Path, markers: tuple[str, ...] = ()) -> tuple[list[str], int]:
    findings = []
    names = source_files(root)
    for name in names:
        path = root / name
        if path.is_symlink():
            findings.append(f"{name}: symbolic link requires explicit publication review")
            continue
        if not path.is_file():
            findings.append(f"{name}: tracked file is missing")
            continue
        data = path.read_bytes()
        issues = content_issues(name, data, markers)
        if name == "README.md" or name.startswith("docs/") and name.endswith(".md"):
            issues.extend(document_links(root, name, data.decode(errors="replace")))
        findings.extend(f"{name}: {issue}" for issue in issues)
    for name in ["LICENSE", "NOTICE", "vendor/netlab/LICENSE", "vendor/netlab/NOTICE",
                 "hardware/reference/driver/fm10k-uio-6.12.101-ies2/COPYING", *["docs/" + n for n in document_list(root)]]:
        if name not in names:
            findings.append(f"{name}: required publication file is missing")
    return findings, len(names)


def audit_history(root: Path, markers: tuple[str, ...] = ()) -> tuple[list[str], int]:
    listing = git(root, "rev-list", "--objects", "--all")
    if not listing:
        return [], 0
    metadata = git(root, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize) %(rest)", data=listing)
    blobs = [line.split(b" ", 3) for line in metadata.splitlines() if b" blob " in line]
    stream = git(root, "cat-file", "--batch", data=b"\n".join(row[0] for row in blobs) + b"\n")
    offset, findings = 0, []
    for row in blobs:
        end = stream.index(b"\n", offset)
        size = int(stream[offset:end].split()[2])
        data = stream[end + 1:end + 1 + size]
        offset = end + 1 + size + 1
        name = row[3].decode() if len(row) > 3 else row[0].decode()
        findings.extend(f"history {row[0].decode()[:12]} {name}: {issue}" for issue in content_issues(name, data, markers))
    messages = git(root, "log", "--all", "--format=%B")
    findings.extend("commit messages: " + issue for issue in content_issues("commit-messages", messages, markers))
    return findings, len(blobs)


def package_entries(raw: bytes):
    if not raw.startswith(b"!<arch>\n"):
        raise ValueError("not a Debian ar archive")
    offset, seen, data_seen = 8, set(), False
    while offset < len(raw):
        header = raw[offset:offset + 60]
        if len(header) != 60 or header[-2:] != b"`\n":
            raise ValueError("invalid ar member header")
        size = int(header[48:58])
        if size < 0 or offset + 60 + size > len(raw):
            raise ValueError("truncated ar member")
        member = header[:16].decode().strip().rstrip("/")
        data = raw[offset + 60:offset + 60 + size]
        offset += 60 + size + size % 2
        if member in seen:
            raise ValueError("duplicate ar member")
        seen.add(member)
        if member == "debian-binary":
            if data != b"2.0\n":
                raise ValueError("unsupported Debian package format")
            continue
        if not member.startswith(("control.tar", "data.tar")):
            raise ValueError("unexpected Debian package member")
        data_seen = data_seen or member.startswith("data.tar")
        paths = set()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for item in archive:
                name = item.name.removeprefix("./")
                if not name or name == ".":
                    continue
                if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
                    raise ValueError("unsafe package member path")
                if item.isdir():
                    continue
                if not item.isfile() or name in paths or item.size > 32 * 1024 * 1024:
                    raise ValueError("unsupported, duplicate or oversized package member")
                paths.add(name)
                yield (name if member.startswith("data.tar") else "DEBIAN/" + name), archive.extractfile(item).read()
    if not data_seen or "debian-binary" not in seen:
        raise ValueError("incomplete Debian package")


def audit_package(path: Path, root: Path = ROOT, markers: tuple[str, ...] = ()) -> tuple[list[str], int]:
    prefix = "usr/share/doc/fm10k-controlpanel/"
    allowed_docs = set(document_list(root)) | {"LICENSE", "NOTICE", "NETLAB-LICENSE", "NETLAB-NOTICE"}
    required = {prefix + n for n in allowed_docs}
    findings, names = [], set()
    for name, data in package_entries(path.read_bytes()):
        names.add(name)
        findings.extend(f"package {name}: {issue}" for issue in content_issues(name, data, markers))
        if name.startswith(prefix) and name[len(prefix):] not in allowed_docs:
            findings.append(f"package {name}: document is not allowlisted")
    findings.extend(f"package {name}: required publication document is missing" for name in sorted(required - names))
    return findings, len(names)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="also scan all reachable Git blobs and commit messages")
    parser.add_argument("--package", type=Path, help="scan a Debian package instead of the source tree")
    parser.add_argument("--private-markers", type=Path, help="local JSON array of exact strings that must not leave the environment")
    args = parser.parse_args()
    markers = ()
    try:
        if args.private_markers:
            values = json.loads(args.private_markers.read_text())
            if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
                raise ValueError("private markers must be nonempty strings in a JSON array")
            markers = tuple(values)
        if args.package:
            findings, count = audit_package(args.package, ROOT, markers)
            label = "package entries"
        else:
            findings, count = audit_tree(ROOT, markers)
            label = "source files"
            if args.history:
                historical, versions = audit_history(ROOT, markers)
                findings.extend(historical)
                label += f", {versions} historical file versions"
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        print("Publication check could not complete: " + str(error))
        return 1
    for finding in findings:
        print(finding)
    if findings:
        print(f"Publication check failed: {len(findings)} findings")
        return 1
    print(f"Publication check passed: {count} {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
