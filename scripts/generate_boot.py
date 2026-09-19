#!/usr/bin/env python3
"""Render new boot artifacts without modifying configd or hardware."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration, decode_configuration
from fm10k_controlpanel.platform_config import render_sdk_platform, render_netlab_profile
from fm10k_controlpanel.profiles import PROFILES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active-xml", type=Path, help="immutable configd snapshot; omit for initial disabled ports")
    parser.add_argument("--profile", choices=PROFILES, help="new board profile; existing snapshots cannot change profile")
    parser.add_argument("--reference", type=Path, help="exact locked source for the selected profile")
    parser.add_argument("--output", type=Path, required=True, help="a new artifact directory, never /etc/netlab directly")
    parser.add_argument("--system-mac", required=True)
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    config = (decode_configuration(args.active_xml.read_bytes()) if args.active_xml else
              SwitchConfiguration(profile=args.profile or "sil001-hw4-b0"))
    if args.profile and config.profile != args.profile:
        parser.error("profile disagrees with the immutable configd snapshot")
    reference = args.reference or ROOT / PROFILES[config.profile].reference
    if not reference.is_file():
        parser.error("platform input is not bundled; provide --reference or run scripts/import_platform.py "
                     f"--profile {config.profile} --input <licensed-platform.cfg>; see docs/BUILD.md")
    files = {
        "fm_platform_attributes.cfg": render_sdk_platform(reference.read_text(), config).encode(),
        "platform.profile": render_netlab_profile(config, system_mac=args.system_mac, serial=args.serial).encode(),
        "active.conf": compile_configuration(config),
    }
    args.output.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        (args.output / name).write_bytes(data)
    manifest = {"schema": 1, "profile": config.profile, "config_authority": "configd",
                "reference_sha256": PROFILES[config.profile].sha256,
                "hardware_write_ready": False,
                "source": str(args.active_xml) if args.active_xml else "initial-disabled-ports",
                "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    (args.output / "boot-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
