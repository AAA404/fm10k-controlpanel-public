#!/usr/bin/env python3
"""Validate the installed HTTPS renderer and nginx config in a disposable container."""
from pathlib import Path
import shutil
import subprocess
import tempfile

if not Path("/.dockerenv").is_file():
    raise SystemExit("only run inside the supplied disposable Debian container")
with tempfile.TemporaryDirectory(prefix="fm10k-https-check-") as directory:
    output = Path(directory) / "https"
    subprocess.run(["fm10k-https", "--bind", "127.0.0.1", "--server-name", "switch.test",
                    "--self-signed-days", "1", "--output", str(output)], check=True)
    tls = Path("/etc/fm10k-controlpanel/tls")
    tls.mkdir(parents=True, mode=0o700, exist_ok=True)
    for filename in ("server.crt", "server.key"):
        shutil.copy2(output / filename, tls / filename)
    config = Path(directory) / "nginx-test.conf"
    config.write_text("events {}\nhttp {\ninclude /etc/nginx/mime.types;\n" +
                      (output / "fm10k-controlpanel.conf").read_text() + "\n}\n")
    subprocess.run(["nginx", "-t", "-c", str(config)], check=True)
print("Installed HTTPS renderer and nginx configuration passed; no listener started.")
