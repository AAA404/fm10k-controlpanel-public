#!/usr/bin/env python3
# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
"""Fail when the public tree contains private, proprietary, or binary input."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()

BLOCKED_PREFIXES = (
    "patches/",
    "third_party/",
    "docs/release/",
)
BLOCKED_SUFFIXES = (
    ".a", ".deb", ".ko", ".o", ".pdf", ".rpm", ".so", ".tar",
    ".tar.gz", ".tgz", ".whl", ".zip",
)

# This file is skipped while scanning so the signatures remain visible and
# reviewable instead of being obfuscated to evade their own rules.
BLOCKED_TEXT = (
    re.compile(r"netlab-switch/netlab-(?:sdk|runtime-bundles|release|lab-infra|core)"),
    re.compile(r"Intel_SRD_Proprietary_License"),
    re.compile(r"HandleMacMovedEvent|fm10000MoveAddressSecure"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
)

PUBLIC_TEST_SUPPORT = (
    "tests/integration/build_support.py",
    "tests/integration/l2_plan_staged_client.py",
)
BLOCKED_PUBLIC_TEST_TEXT = re.compile(
    r"/opt/|NETLAB_VENDOR_ROOT|NETLAB_SDK(?:_DIR|_TREE)?|IES_SDK|fm_sdk\.h"
)


def repository_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        check=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def public_test_files() -> list[Path]:
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "scripts/run-public-tests.py"),
         "--list"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "cannot list public tests")
    return [ROOT / relative for relative in (
        *result.stdout.splitlines(), *PUBLIC_TEST_SUPPORT
    )]


def main() -> int:
    violations: list[str] = []
    files = repository_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if relative == SELF.relative_to(ROOT).as_posix():
            continue
        if relative.startswith(BLOCKED_PREFIXES):
            violations.append(f"blocked path: {relative}")
            continue
        if relative.endswith(BLOCKED_SUFFIXES):
            violations.append(f"binary/archive path: {relative}")
            continue
        try:
            data = path.read_bytes()
        except OSError as error:
            violations.append(f"unreadable path: {relative}: {error}")
            continue
        if b"\0" in data:
            violations.append(f"binary content: {relative}")
            continue
        text = data.decode("utf-8", errors="replace")
        for pattern in BLOCKED_TEXT:
            if pattern.search(text):
                violations.append(f"blocked content {pattern.pattern!r}: {relative}")

    try:
        selected_tests = public_test_files()
    except RuntimeError as error:
        violations.append(f"public test manifest: {error}")
        selected_tests = []
    for path in selected_tests:
        relative = path.relative_to(ROOT).as_posix()
        if not path.is_file():
            violations.append(f"missing public test input: {relative}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if BLOCKED_PUBLIC_TEST_TEXT.search(text):
            violations.append(
                f"public CI test depends on SDK or host-local path: {relative}"
            )

    if violations:
        print("Public surface check failed:", file=sys.stderr)
        print("\n".join(f"- {item}" for item in sorted(violations)),
              file=sys.stderr)
        return 1
    print(f"Public surface check passed: files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
