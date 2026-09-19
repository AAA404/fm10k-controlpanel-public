#!/usr/bin/env python3
"""Private stdin/stdout ASGI bridge for browser QA; never opens a listener."""
import base64
import json
import os
from pathlib import Path
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from fm10k_controlpanel.app import create_app
from fm10k_controlpanel.simulator import MockConfigd


def main():
    state = Path(sys.argv[1])
    os.environ["PANEL_BACKEND"] = "mock"
    # An explicit backend makes it impossible to point this QA bridge at SDK IPC.
    app = create_app(state_dir=state, backend=MockConfigd(state), secure_cookie=False)
    with TestClient(app, base_url="http://127.0.0.1:18081", raise_server_exceptions=False) as client:
        print(json.dumps({"ready": True}), flush=True)
        for line in sys.stdin:
            request = json.loads(line)
            client.cookies.clear()  # Authentication comes from the browser only.
            response = client.request(request["method"], request["path"],
                                      headers=request.get("headers", {}),
                                      content=base64.b64decode(request.get("body", "")))
            print(json.dumps({"id": request["id"], "status": response.status_code,
                              "headers": dict(response.headers),
                              "body": base64.b64encode(response.content).decode("ascii")}), flush=True)


if __name__ == "__main__":
    main()
