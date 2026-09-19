import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest


def test_debian_archive_is_deterministic_and_excludes_sdk(tmp_path):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("build_deb", root / "scripts/build_deb.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    first, second = tmp_path / "one.deb", tmp_path / "two.deb"
    module.build(root, first, "0.1.0~test1", 1234567890)
    module.build(root, second, "0.1.0~test1", 1234567890)
    assert first.read_bytes() == second.read_bytes()
    raw, offset, members = first.read_bytes(), 8, {}
    assert raw[:8] == b"!<arch>\n"
    while offset < len(raw):
        header = raw[offset:offset + 60]
        assert header[-2:] == b"`\n"
        size = int(header[48:58])
        members[header[:16].decode().strip().rstrip("/")] = raw[offset + 60:offset + 60 + size]
        offset += 60 + size + size % 2
    assert members["debian-binary"] == b"2.0\n"
    with tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]), mode="r:gz") as control:
        assert b"Architecture: all" in control.extractfile("./control").read()
        assert control.getmember("./postinst").mode == 0o755
    with tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]), mode="r:gz") as data:
        names = data.getnames()
        assert "./usr/lib/systemd/system/fm10k-panel.service" in names
        assert "./usr/lib/systemd/system/fm10k-time.socket" in names
        helper = data.extractfile("./usr/lib/systemd/system/fm10k-time@.service").read()
        assert b"ProtectClock=yes" in helper and b"CapabilityBoundingSet=\n" in helper
        assert b"StandardInput=socket" in helper
        assert "./usr/share/fm10k-controlpanel/web/index.html" in names
        documents = json.loads((root / "deploy/public-documents.json").read_text())
        doc_prefix = "./usr/share/doc/fm10k-controlpanel/"
        packaged_documents = {name[len(doc_prefix):] for name in names if name.startswith(doc_prefix)}
        assert packaged_documents == set(documents) | {"LICENSE", "NOTICE", "NETLAB-LICENSE", "NETLAB-NOTICE"}
        assert not any("libFocalpointSDK" in name or "sdk/ies" in name for name in names)
        package = tmp_path / "installed/fm10k_controlpanel"
        package.mkdir(parents=True)
        for name in ("__init__.py", "_package_version.py"):
            payload = data.extractfile("./usr/lib/fm10k-controlpanel/python/fm10k_controlpanel/" + name).read()
            (package / name).write_bytes(payload)
    version = subprocess.check_output([sys.executable, "-I", "-c",
        "import sys; sys.path.insert(0, sys.argv[1]); import fm10k_controlpanel; print(fm10k_controlpanel.__version__)",
        str(package.parent)], text=True)
    assert version.strip() == "0.1.0~test1"


def test_unlisted_documents_do_not_enter_package(tmp_path):
    source = Path(__file__).resolve().parents[1]
    root = tmp_path / "source"
    for relative in ["backend", "deploy", "docs", "frontend/dist", "hardware/sdk-inputs.json", "LICENSE", "NOTICE",
                     "vendor/netlab/LICENSE", "vendor/netlab/NOTICE", "vendor/netlab/bin/cli/session.py",
                     "vendor/netlab/scripts/netlab_ipc_transport.py"]:
        origin, target = source / relative, root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if origin.is_dir():
            shutil.copytree(origin, target, ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
        else:
            shutil.copyfile(origin, target)
    (root / "docs/UNREVIEWED.md").write_text("Unreviewed operator notes")
    spec = importlib.util.spec_from_file_location("build_deb_isolation", source / "scripts/build_deb.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "checked.deb"
    module.build(root, output, "0.1.0~test1", 0)
    raw, offset = output.read_bytes(), 8
    while offset < len(raw):
        header = raw[offset:offset + 60]
        size = int(header[48:58])
        if header[:16].decode().strip().rstrip("/") == "data.tar.gz":
            with tarfile.open(fileobj=io.BytesIO(raw[offset + 60:offset + 60 + size]), mode="r:gz") as archive:
                assert not any(name.endswith("UNREVIEWED.md") for name in archive.getnames())
            break
        offset += 60 + size + size % 2
    else:
        pytest.fail("package data archive is missing")
