#!/usr/bin/env python3
"""Check pinned runtime inputs and Linux linkability without initializing ASIC."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.preflight import inspect_sdk


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--executable", type=Path)
    args = parser.parse_args()
    report = inspect_sdk(args.sdk, ROOT / "hardware/sdk-inputs.json")
    print(json.dumps(report, indent=2))
    if not report["valid"]:
        return 1
    if args.executable:
        # Only our just-built executable is passed to ldd, never an uploaded binary.
        env = {**os.environ, "LD_LIBRARY_PATH": f"{args.sdk / 'build'}:/opt/netlab-deps/libyang2/lib"}
        result = subprocess.run(["ldd", "-r", str(args.executable)], env=env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        print(result.stdout)
        if result.returncode or "not found" in result.stdout or "undefined symbol" in result.stdout:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
