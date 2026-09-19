import importlib.util
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load_script("check_public")
builder = load_script("build_deb")


@pytest.mark.parametrize("name", [
    "docs/VERIFICATION.md", "docs/RELEASE_RC1.md", "docs/report_2026-01-01.md",
    "hardware/sdk/platforms/input.cfg", "usr/lib/hardware/sdk/platforms/input.cfg",
    "usr/share/reference_original_6x100.cfg", "state/accounts.json", "dump.pcap",
])
def test_private_inputs_and_working_records_are_rejected(name):
    assert audit.path_issues(name)


def test_secret_findings_do_not_echo_the_value():
    token = "ghp_" + "x" * 36
    issues = audit.content_issues("config.txt", token.encode())
    assert "service token" in issues
    assert token not in "\n".join(issues)
    key = "-----" + "BEGIN PRIVATE KEY" + "-----"
    assert "private key" in audit.content_issues("config.txt", key.encode())


def test_operator_markers_are_optional_and_case_insensitive():
    assert not audit.content_issues("sample.txt", b"An Internal Sample")
    assert "private review marker" in audit.content_issues("sample.txt", b"An Internal Sample", ("internal sample",))


def test_deleted_secret_is_detected_in_history(tmp_path):
    def command(*args):
        return subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
                              cwd=tmp_path, check=True, capture_output=True)
    command("init", "--initial-branch=main")
    token = "ghp_" + "z" * 36
    path = tmp_path / "removed.txt"
    path.write_text(token)
    command("add", "removed.txt")
    command("commit", "-m", "Initial fixture")
    path.unlink()
    command("add", "-u")
    command("commit", "-m", "Remove fixture")
    issues, count = audit.audit_history(tmp_path)
    assert count == 1
    assert any("service token" in issue and "removed.txt" in issue for issue in issues)
    assert all(token not in issue for issue in issues)


def test_local_document_links_are_checked(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/BUILD.md").write_text("Example")
    assert not audit.document_links(tmp_path, "README.md", "[Build](docs/BUILD.md)")
    assert audit.document_links(tmp_path, "README.md", "[Old](docs/MISSING.md)")


def make_package(extra):
    prefix = "usr/share/doc/fm10k-controlpanel/"
    documents = audit.document_list(ROOT) + ["LICENSE", "NOTICE", "NETLAB-LICENSE", "NETLAB-NOTICE"]
    files = {prefix + name: (b"Public example", 0o644) for name in documents}
    files.update(extra)
    return builder.ar_bytes([
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", builder.tar_bytes({"control": (b"Package: example\n", 0o644)}, 0)),
        ("data.tar.gz", builder.tar_bytes(files, 0)),
    ], 0)


def test_package_scan_rejects_extra_documents_and_embedded_tokens(tmp_path):
    path = tmp_path / "example.deb"
    path.write_bytes(make_package({}))
    assert not audit.audit_package(path)[0]
    token = "ghp_" + "q" * 36
    path.write_bytes(make_package({
        "usr/share/doc/fm10k-controlpanel/INTERNAL.md": (b"Unreviewed document", 0o644),
        "usr/lib/example.py": (token.encode(), 0o644),
    }))
    issues, _ = audit.audit_package(path)
    assert any("document is not allowlisted" in issue for issue in issues)
    assert any("service token" in issue for issue in issues)
    assert all(token not in issue for issue in issues)


def test_truncated_package_is_rejected():
    with pytest.raises(ValueError):
        list(audit.package_entries(make_package({})[:-80]))
