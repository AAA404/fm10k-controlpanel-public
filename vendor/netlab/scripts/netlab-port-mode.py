#!/usr/bin/env python3.11
"""Apply or roll back restart-time NetLab chassis port-mode runtime files."""

import argparse
import os
import sys
import traceback

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin", "cli"))

DEFAULT_ACTIVE_CONFIG = "/var/lib/netlab/active.conf"
DEFAULT_STATE_DIR = "/var/lib/netlab/port-mode"
DEFAULT_RUNTIME_PROFILE = "/var/lib/netlab/platform.profile"
DEFAULT_RDI_TARGET = "/etc/rdi/fm_platform_attributes.cfg"

from port_mode import (PortModeError, RELEASE_TOOL, format_status_text,  # noqa: E402
                       port_mode_status)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Atomically install matching NetLab platform profile and Netspl RDI files.",
    )
    parser.add_argument("action", choices=("apply", "rollback", "status"))
    parser.add_argument("--active-config", default=DEFAULT_ACTIVE_CONFIG)
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    parser.add_argument("--runtime-profile", default=DEFAULT_RUNTIME_PROFILE)
    parser.add_argument("--rdi-target", default=DEFAULT_RDI_TARGET)
    parser.add_argument("--json", action="store_true",
                        help="print raw JSON-like Python status dict for status")
    parser.add_argument("--traceback", action="store_true",
                        help="print Python traceback on failure")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.action != "status" and (
            args.active_config != DEFAULT_ACTIVE_CONFIG or
            args.state_dir != DEFAULT_STATE_DIR or
            args.runtime_profile != DEFAULT_RUNTIME_PROFILE or
            args.rdi_target != DEFAULT_RDI_TARGET):
        parser.error(
            "runtime path overrides are status-only; apply/rollback always "
            "use canonical immutable release paths")
    try:
        if args.action == "status":
            data = port_mode_status(args.active_config, args.state_dir,
                                    args.rdi_target, args.runtime_profile)
            if args.json:
                import json
                print(json.dumps(data, indent=2, sort_keys=True))
            else:
                print(format_status_text(data))
            return 0
        release_tool = RELEASE_TOOL
        command = [release_tool, "port-mode", args.action]
        if args.json:
            command.insert(1, "--json")
        os.execve(
            release_tool,
            command,
            {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, PortModeError, RuntimeError) as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        if args.traceback:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
