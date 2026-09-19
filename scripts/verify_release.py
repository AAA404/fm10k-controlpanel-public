#!/usr/bin/env python3
"""Verify Release assets and, optionally, install only the Web deb in a disposable container."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0,str(ROOT / "backend"))
from fm10k_controlpanel.release import MANIFEST_NAME, extract_bundle, load_json, sha256, validate_manifest, verify_asset
from check_public import audit_package, content_issues


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir",type=Path,required=True)
    parser.add_argument("--install-test",action="store_true")
    parser.add_argument("--native-build-test",action="store_true",help="compile/link only, in a disposable container")
    parser.add_argument("--sdk",type=Path,help="read-only local SDK input for the native build test")
    parser.add_argument("--platform",type=Path,help="read-only original platform input for the native build test")
    parser.add_argument("--profile",choices=("sil001-hw4-b0","sil001-hw5-a11"))
    args=parser.parse_args()
    if args.native_build_test and not all((args.sdk,args.platform,args.profile)):
        parser.error("--native-build-test requires --sdk, --platform and --profile")
    if args.install_test or args.native_build_test:
        if not Path("/.dockerenv").is_file() or Path("/run/systemd/system").exists() or list(Path("/dev").glob("uio*")) or list(Path("/dev").glob("i2c-*")):
            raise SystemExit("verification is restricted to a disposable container with no systemd or device mappings")
    directory=args.release_dir.resolve()
    manifest=validate_manifest(load_json((directory / MANIFEST_NAME).read_bytes()))
    for asset in manifest["assets"].values(): verify_asset(directory / asset["name"],asset)
    expected={path.name:sha256(path) for path in [directory / MANIFEST_NAME,*[directory / a["name"] for a in manifest["assets"].values()]]}
    actual={line.split("  ",1)[1]:line.split("  ",1)[0] for line in (directory / "SHA256SUMS").read_text().splitlines()}
    assert expected==actual,"SHA256SUMS does not match the exact published asset set"
    package=directory / manifest["assets"]["web"]["name"]
    issues,_=audit_package(package)
    assert not issues,issues
    with tempfile.TemporaryDirectory(prefix="fm10k-release-") as temporary:
        source=extract_bundle(directory / manifest["assets"]["bundle"]["name"],Path(temporary) / "extract",manifest["version"])
        assert sha256(source / "hardware/sdk-inputs.json")==manifest["sdk_manifest_sha256"]
        verify_asset(source / "packages" / package.name,manifest["assets"]["web"])
        inventory=load_json((source / "bundle-manifest.json").read_bytes())
        for name in inventory["files"]:
            if name.startswith(("packages/","dependencies/")): continue
            assert not content_issues(name,(source / name).read_bytes()),name
        if args.install_test:
            for field,value in (("Package","fm10k-controlpanel"),("Version",manifest["version"]),("Architecture","all")):
                assert subprocess.check_output(["dpkg-deb","-f",str(package),field],text=True).strip()==value
            subprocess.run(["dpkg","--force-confold","-i",str(package)],check=True)
            subprocess.run(["python3","-I",str(ROOT / "scripts/installed_smoke.py")],check=True)
            subprocess.run(["systemd-analyze","verify","/usr/lib/systemd/system/fm10k-panel.service",
                            "/usr/lib/systemd/system/fm10k-update.socket","/usr/lib/systemd/system/fm10k-update@.service",
                            "/usr/lib/systemd/system/fm10k-update-worker.service"],check=True)
            check=subprocess.run(["sh",str(source / "install.sh"),"check","--sdk","/nonexistent-sdk","--platform","/nonexistent-platform",
                                  "--management-interface","example0","--management-ip","192.0.2.10"],text=True,capture_output=True)
            assert check.returncode==1,(check.stdout,check.stderr)
            report=json.loads(check.stdout)
            assert report["read_only"] and not report["passed"]
        if args.native_build_test:
            from fm10k_controlpanel.installation import Paths, stage_native
            print("Compiling and checking native links; hardware services will not be started.",flush=True)
            stage_native(source,args.sdk,args.platform,args.profile,Paths())
    print(json.dumps({"verified":True,"version":manifest["version"],"hardware_access":False,
                      "container_package_install":args.install_test,"native_build":args.native_build_test}))


if __name__=="__main__": main()
