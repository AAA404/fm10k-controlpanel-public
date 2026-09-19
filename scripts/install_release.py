#!/usr/bin/env python3
"""Install a verified release on a new Debian 13 host; default is read-only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.install_checks import preflight
from fm10k_controlpanel.release import verify_bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("check", "install"), default="check")
    parser.add_argument("--sdk", type=Path, required=True, help="locally supplied, pinned IES SDK directory")
    parser.add_argument("--platform", type=Path, required=True, help="original platform cfg for this board revision")
    parser.add_argument("--management-interface", required=True, help="existing independent management interface")
    parser.add_argument("--management-ip", required=True, help="existing address on the management interface")
    parser.add_argument("--eye-firmware", type=Path, help="optional pinned binary made by prepare_eye_firmware.py")
    args = parser.parse_args()
    try:
        bundle = verify_bundle(ROOT)
        report = preflight(ROOT, args.sdk, args.platform, args.management_interface, args.management_ip, eye_firmware=args.eye_firmware)
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
        if not report["passed"]:
            return 1
        if args.action == "install":
            from fm10k_controlpanel.installation import install
            install(ROOT, args.sdk, args.platform, args.management_interface, args.management_ip, bundle["version"], eye_firmware=args.eye_firmware)
    except (OSError, ValueError) as error:
        print("Installation refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
