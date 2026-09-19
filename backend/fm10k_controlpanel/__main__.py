import argparse
import os

import uvicorn


def main():
    parser = argparse.ArgumentParser(description="FM10840 Web control panel")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--backend", choices=["mock", "netlab"], default=os.environ.get("PANEL_BACKEND", "mock"))
    parser.add_argument("--state-dir")
    args = parser.parse_args()
    os.environ["PANEL_BACKEND"] = args.backend
    if args.state_dir: os.environ["PANEL_STATE_DIR"] = args.state_dir
    uvicorn.run("fm10k_controlpanel.app:create_app", factory=True, host=args.host, port=args.port,
                workers=1, proxy_headers=True, forwarded_allow_ips="127.0.0.1")


if __name__ == "__main__": main()
