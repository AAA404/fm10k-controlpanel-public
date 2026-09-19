#!/usr/bin/env python3
"""Run target checks in an isolated Debian 13 container; save real evidence."""
from __future__ import annotations

import json
import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("/src"))
    parser.add_argument("--work", type=Path, default=Path("/work/fm10k-controlpanel"))
    parser.add_argument("--results", type=Path, default=Path("/results"))
    args = parser.parse_args()
    if not Path("/.dockerenv").is_file():
        raise SystemExit("run this validation inside the supplied Docker image, not on the board")
    if platform.machine() != "x86_64" or 'VERSION_ID="13"' not in Path("/etc/os-release").read_text():
        raise SystemExit("Debian 13 amd64 is required")
    source, work, results = args.source.resolve(), args.work.resolve(), args.results.resolve()
    if not (source / "pyproject.toml").is_file() or work.exists() or work.is_relative_to(source):
        raise SystemExit("source must be a project tree and work must be a new directory outside it")
    results.mkdir(parents=True, exist_ok=True)
    print("Copying read-only source into the disposable build directory ...", flush=True)
    shutil.copytree(source, work, ignore=shutil.ignore_patterns(
        ".git", "node_modules", "__pycache__", ".pytest_cache", ".venv", ".verification", "artifacts", "local-state"))
    os.chdir(work)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONPATH"] = str(work / "backend")
    report = {"schema": 1, "system": platform.platform(), "python": platform.python_version(),
              "hardware_access": False, "native_requested": os.environ.get("FM10K_CHECK_NATIVE") == "1",
              "started_at": time.time(), "checks": []}
    def run(name, command, timeout=900, critical=False):
        print(f"Checking {name} ...", flush=True)
        log = results / (name + ".log")
        started = time.time()
        with log.open("w") as stream:
            try:
                result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
        report["checks"].append({"name": name, "exit_code": code, "seconds": time.time() - started, "log": log.name})
        (results / "debian13-report.json").write_text(json.dumps(report, indent=2) + "\n")
        if code:
            print("\n".join(log.read_text(errors="replace").splitlines()[-70:]), flush=True)
            if critical:
                raise SystemExit(code)
        else:
            print(f"PASS {name}", flush=True)
        return code == 0
    run("environment", ["dpkg-query", "-W"])
    run("frontend-dependencies", ["npm", "--prefix", "frontend", "ci", "--no-audit", "--no-fund"], critical=True)
    run("frontend-build", ["npm", "--prefix", "frontend", "run", "build"], critical=True)
    run("python-tests", ["python3", "-m", "pytest", "-q"])
    run("control-plane-build", ["make", "-C", "vendor/netlab", "-j2", "control-plane"])
    run("control-plane-contract-tests", ["python3", "vendor/netlab/scripts/run-public-tests.py"])
    for profile, suffix in (("sil001-hw4-b0", ""), ("sil001-hw5-a11", "-a11")):
        boot = work / ".verification" / ("boot" + suffix)
        if run("synthetic-boot-generation" + suffix, ["python3", "tests/platform_fixture.py",
                                                    str(work / ".verification/platform-inputs"), "--output", str(boot),
                                                   "--profile", profile, "--system-mac", "02:10:84:00:00:01",
                                                   "--serial", "container-test"]):
            # yanglint recognizes data by extension; .conf is the daemon's name.
            shutil.copyfile(boot / "active.conf", boot / "active.xml")
            run("yang-validation" + suffix, ["/opt/netlab-deps/libyang2/bin/yanglint", "-t", "config",
                                            "vendor/netlab/include/netlab/netlab.yang", str(boot / "active.xml")])
    headers = sorted(Path("/usr/src").glob("linux-headers-*-amd64"))
    if not headers:
        raise SystemExit("Debian kernel headers are missing")
    if run("driver-compile", ["make", "-j2", "-C", str(headers[-1]),
                              f"M={work / 'hardware/reference/driver/fm10k-uio-6.12.101-ies2'}", "modules"]):
        run("driver-module-info", ["modinfo", str(work / "hardware/reference/driver/fm10k-uio-6.12.101-ies2/fm10k.ko")])
    if os.environ.get("FM10K_CHECK_NATIVE") == "1":
        if run("sdk-input-validation", ["python3", "scripts/check_sdk.py", "--sdk", str(work / "hardware/sdk/ies")]):
            if run("sdk-switchd-build", ["make", "-C", "vendor/netlab", "-j2", "hardware",
                                         f"NETLAB_SDK_DIR={work / 'hardware/sdk/ies'}"]):
                run("sdk-link-check", ["python3", "scripts/check_sdk.py", "--sdk", str(work / "hardware/sdk/ies"),
                                       "--executable", str(work / "vendor/netlab/build/switchd")])
    package = str(results / "fm10k-controlpanel_0.1.0~dev1_all.deb")
    if run("package-build", ["python3", "scripts/build_deb.py", "--output", package]):
        run("package-public-content", ["python3", "scripts/check_public.py", "--package", package], critical=True)
        run("package-inspect", ["dpkg-deb", "--info", package])
        run("package-index", ["apt-get", "update"])
        if run("package-install", ["apt-get", "install", "-y", package]):
            run("installed-runtime", ["python3", "-I", "scripts/installed_smoke.py"])
            run("https-config", ["python3", "scripts/check_nginx.py"])
            run("systemd-units", ["systemd-analyze", "verify", "/usr/lib/systemd/system/fm10k-panel.service"])
    report["completed_at"] = time.time()
    report["passed"] = all(check["exit_code"] == 0 for check in report["checks"])
    (results / "debian13-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
