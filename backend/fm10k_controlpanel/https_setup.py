"""Render HTTPS deployment files without changing services or networking."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess


def listener(bind: str, server_name: str) -> tuple[str, str, str]:
    address = ipaddress.ip_address(bind)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("bind must be one specific management IP")
    try:
        name_ip = ipaddress.ip_address(server_name)
        name = str(name_ip)
        san = "IP:" + name
    except ValueError:
        name = server_name.encode("idna").decode("ascii").lower()
        if len(name) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                      for label in name.split(".")):
            raise ValueError("invalid server name") from None
        san = "DNS:" + name
    listen = f"[{address}]:443" if address.version == 6 else f"{address}:443"
    return listen, name, san


def render(template: str, bind: str, server_name: str) -> str:
    listen, name, _ = listener(bind, server_name)
    return template.replace("@LISTEN@", listen).replace("@SERVER_NAME@", name)


def prepare(output: Path, template: Path, bind: str, server_name: str, *,
            certificate: Path | None = None, private_key: Path | None = None, days=0):
    _, name, san = listener(bind, server_name)
    if bool(certificate) != bool(private_key) or (certificate and days):
        raise ValueError("supply both certificate and private key, or request a self-signed certificate")
    if not certificate and not 1 <= days <= 825:
        raise ValueError("a certificate pair or --self-signed-days (1..825) is required")
    configuration = render(template.read_text(), bind, name)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    cert, key = output / "server.crt", output / "server.key"
    if certificate:
        cert.write_bytes(certificate.read_bytes())
        key.touch(mode=0o600)
        key.write_bytes(private_key.read_bytes())
    else:
        # Only validated names enter the certificate subject and SAN; no shell.
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
                        "-days", str(days), "-subj", "/CN=" + name, "-addext", "subjectAltName=" + san,
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    key.chmod(0o600)
    subprocess.run(["openssl", "x509", "-in", str(cert), "-checkend", "0", "-noout"],
                   check=True, capture_output=True)
    cert_public = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"])
    key_public = subprocess.check_output(["openssl", "pkey", "-in", str(key), "-pubout"], stderr=subprocess.PIPE)
    if cert_public != key_public:
        raise ValueError("certificate and key do not match")
    (output / "fm10k-controlpanel.conf").write_text(configuration)
    report = {"bind": bind, "server_name": name, "self_signed": not bool(certificate),
              "activated": False, "secure_cookie_required": True}
    (output / "https-plan.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="one existing management IP; never a wildcard")
    parser.add_argument("--server-name", required=True, help="management DNS name or IP")
    parser.add_argument("--output", type=Path, required=True, help="new private output directory")
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--self-signed-days", type=int, default=0)
    source = Path(__file__).resolve().parents[2] / "deploy/nginx/fm10k-controlpanel.conf.in"
    parser.add_argument("--template", type=Path, default=source if source.is_file() else
                        Path("/usr/share/fm10k-controlpanel/nginx.conf.in"))
    args = parser.parse_args()
    try:
        report = prepare(args.output, args.template, args.bind, args.server_name,
                         certificate=args.certificate, private_key=args.private_key, days=args.self_signed_days)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"HTTPS preparation failed: {error}\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("Files prepared; follow DEPLOYMENT.md to install and validate nginx before activation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
