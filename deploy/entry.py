#!/usr/bin/python3
"""Installed entry point; package modules are in a root-owned private path."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "python"))
command = sys.argv.pop(1) if len(sys.argv) > 1 else "web"
if command == "web":
    from fm10k_controlpanel.__main__ import main
elif command == "preflight":
    from fm10k_controlpanel.preflight import main
elif command == "https":
    from fm10k_controlpanel.https_setup import main
elif command == "native-startup":
    from fm10k_controlpanel.native_guard import main
elif command == "time-helper":
    from fm10k_controlpanel.time_helper import main
elif command == "update-helper":
    from fm10k_controlpanel.update_helper import main
elif command == "update-worker":
    from fm10k_controlpanel.update_helper import worker_main as main
else:
    raise SystemExit("supported commands: web, preflight, https, native-startup, time-helper, update-helper, update-worker")
raise SystemExit(main())
