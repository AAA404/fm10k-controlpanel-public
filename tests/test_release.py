import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.error
import urllib.request

import pytest

from fm10k_controlpanel.release import (COMPATIBILITY, FORMAT, GitHubRedirects, GitHubReleases, MANIFEST_NAME,
    REPOSITORY, ReleaseError, extract_bundle, json_bytes, load_json, validate_manifest, verify_asset, verify_bundle, version_tuple)


def manifest(version="0.2.0"):
    return {"schema": FORMAT, "repository": REPOSITORY, "version": version, "tag": "v"+version,
            "source_commit":"a"*40, "sdk_manifest_sha256":"b"*64, "compatibility":copy.deepcopy(COMPATIBILITY),
            "assets":{"bundle":{"name":f"fm10k-controlpanel-{version}.tar.gz","size":4,"sha256":hashlib.sha256(b"test").hexdigest()},
                      "web":{"name":f"fm10k-controlpanel_{version}_all.deb","size":4,"sha256":hashlib.sha256(b"test").hexdigest()}}}


@pytest.mark.parametrize("version", ["1.0.0\n", "v1.0.0", "1.0", "01.2.3", "1.2.3-rc1", "1;id", None])
def test_reject_unstable_and_malformed_versions(version):
    with pytest.raises(ReleaseError):
        version_tuple(version)


def test_numeric_versions_and_manifest_binding():
    assert version_tuple("0.10.0") > version_tuple("0.9.99")
    assert validate_manifest(manifest())
    for key, value in (("repository","somewhere/else"),("tag","v0.3.0"),("schema",2),("source_commit","dirty")):
        broken = manifest()
        broken[key] = value
        with pytest.raises(ReleaseError): validate_manifest(broken)
    for part in ("native_abi", "configuration_schema", "os_version", "driver", "installer_format"):
        broken = manifest()
        broken["compatibility"][part] = "different"
        with pytest.raises(ReleaseError): validate_manifest(broken)
    with pytest.raises(ReleaseError):
        load_json(b'{"version":"1.0.0","version":"2.0.0"}')


def test_redirects_strip_credentials_and_reject_untrusted_origins():
    request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/releases/assets/1",
                                     headers={"Authorization":"Bearer local-test-only"})
    handler = GitHubRedirects()
    redirected = handler.redirect_request(request, None, 302, "found", {}, "https://release-assets.githubusercontent.com/a?signature=example")
    assert not redirected.has_header("Authorization")
    for url in ("http://github.com/x", "https://example.invalid/package", "https://github.com/other/repo/releases/download/a",
                "https://user:pass@github.com/a", "https://api.github.com/user", "https://github.com:444/a", "file:///etc/passwd"):
        with pytest.raises(ReleaseError): handler.redirect_request(request, None, 302, "found", {}, url)


class Opener:
    def __init__(self, responses):
        self.responses, self.requests = list(responses), []

    def open(self, request, timeout):
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return io.BytesIO(response)


def test_github_connection_retries_transient_open_failures(monkeypatch):
    monkeypatch.setattr("fm10k_controlpanel.release.time.sleep", lambda _: None)
    opener = Opener([urllib.error.URLError("temporary"), OSError("reset"), b"ok"])
    assert GitHubReleases(opener=opener)._bytes("/releases/latest", 10) == b"ok"
    assert len(opener.requests) == 3


def test_github_connection_retry_is_bounded_and_http_errors_are_immediate(monkeypatch):
    monkeypatch.setattr("fm10k_controlpanel.release.time.sleep", lambda _: None)
    offline = Opener([urllib.error.URLError("offline") for _ in range(3)])
    with pytest.raises(ReleaseError, match="GitHub connection failed"):
        GitHubReleases(opener=offline)._bytes("/releases/latest", 10)
    assert len(offline.requests) == 3
    denied = Opener([urllib.error.HTTPError("https://api.github.com", 403, "denied", {}, None)])
    with pytest.raises(ReleaseError, match="GitHub access denied"):
        GitHubReleases(opener=denied)._bytes("/releases/latest", 10)
    assert len(denied.requests) == 1


def github_data(value=None):
    value = value or manifest()
    raw = json_bytes(value)
    assets = [{"name":MANIFEST_NAME,"id":1,"size":len(raw)}]
    for index, item in enumerate(value["assets"].values(), 2):
        assets.append({**item,"id":index,"digest":"sha256:"+item["sha256"]})
    return {"id":1,"draft":False,"prerelease":False,"tag_name":value["tag"],"assets":assets}, raw


def test_github_check_uses_only_fixed_repository_and_asset_ids(tmp_path):
    release, raw = github_data()
    opener = Opener([json_bytes(release), raw, b"test"])
    client = GitHubReleases("local-test-only", opener)
    candidate = client.latest()
    asset = candidate["manifest"]["assets"]["bundle"]
    destination = tmp_path / asset["name"]
    client.download(candidate["assets"][asset["name"]], asset, destination)
    assert destination.read_bytes() == b"test"
    assert all(request.full_url.startswith(f"https://api.github.com/repos/{REPOSITORY}/releases/") for request in opener.requests)
    assert candidate["manifest_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("mutation", ["draft", "prerelease", "size", "digest", "tag"])
def test_github_release_must_match_manifest(mutation):
    release, raw = github_data()
    if mutation in ("draft", "prerelease"): release[mutation] = True
    if mutation == "size": release["assets"][1]["size"] += 1
    if mutation == "digest": release["assets"][1]["digest"] = "sha256:"+"0"*64
    if mutation == "tag": release["tag_name"] = "v0.3.0"
    with pytest.raises(ReleaseError):
        GitHubReleases(opener=Opener([json_bytes(release), raw])).latest()


@pytest.mark.parametrize("raw", [b"bad!", b"tes", b"test-too-long"])
def test_corrupt_or_truncated_download_is_removed(tmp_path, raw):
    destination = tmp_path / "download"
    asset = manifest()["assets"]["bundle"]
    client = GitHubReleases(opener=Opener([raw]))
    with pytest.raises(ReleaseError): client.download({"id":1,"size":4}, asset, destination)
    assert not destination.exists()


def archive_with(tmp_path, entries):
    archive = tmp_path / "release.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, kind in entries:
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            info.type = kind
            info.linkname = "../../escape"
            raw = b"unsafe"
            if kind == tarfile.REGTYPE: info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
    return archive


@pytest.mark.parametrize("entries", [
    [("../escape",tarfile.REGTYPE)], [("/escape",tarfile.REGTYPE)],
    [("fm10k-controlpanel-0.2.0/../../escape",tarfile.REGTYPE)],
    [("fm10k-controlpanel-0.2.0/link",tarfile.SYMTYPE)],
    [("fm10k-controlpanel-0.2.0/link",tarfile.LNKTYPE)],
    [("fm10k-controlpanel-0.2.0/device",tarfile.CHRTYPE)],
    [("fm10k-controlpanel-0.2.0/same",tarfile.REGTYPE)]*2,
    [("fm10k-controlpanel-0.2.0/file",tarfile.REGTYPE),("fm10k-controlpanel-0.2.0/file/child",tarfile.REGTYPE)],
])
def test_unsafe_archive_refused_before_any_extraction(tmp_path, entries):
    archive = archive_with(tmp_path, entries)
    output = tmp_path / "unpacked"
    with pytest.raises(ReleaseError): extract_bundle(archive, output, "0.2.0")
    assert not output.exists()


def test_valid_archive_under_os_alias_and_post_extraction_tampering(tmp_path):
    files={"install.sh":b"#!/bin/sh\n", "scripts/install_release.py":b"# fixture\n", "VERSION":b"0.2.0\n",
           "hardware/sdk-inputs.json":b"{}", "packages/fm10k-controlpanel_0.2.0_all.deb":b"fixture package",
           "deploy/release-dependencies.json":b"{}"}
    inventory={name:{"sha256":hashlib.sha256(raw).hexdigest(),"size":len(raw),"mode":0o755 if name=="install.sh" else 0o644}
               for name,raw in files.items()}
    bundle={"schema":1,"repository":REPOSITORY,"version":"0.2.0","compatibility":COMPATIBILITY,"files":inventory}
    archive=tmp_path / "valid.tar.gz"
    with tarfile.open(archive,"w:gz") as tar:
        for name,raw in {**files,"bundle-manifest.json":json_bytes(bundle)}.items():
            member=tarfile.TarInfo("fm10k-controlpanel-0.2.0/"+name)
            member.size=len(raw);member.mode=0o755 if name=="install.sh" else 0o644
            tar.addfile(member,io.BytesIO(raw))
    actual=tmp_path / "actual";actual.mkdir()
    alias=tmp_path / "alias";alias.symlink_to(actual,target_is_directory=True)
    root=extract_bundle(archive,alias / "extract","0.2.0")
    assert verify_bundle(root)["version"]=="0.2.0"
    (root / "unlisted").write_text("unexpected")
    with pytest.raises(ReleaseError,match="unlisted"): verify_bundle(root)
    (root / "unlisted").unlink()
    (root / "VERSION").write_text("0.9.0\n")
    with pytest.raises(ReleaseError,match="integrity mismatch"): verify_bundle(root)


@pytest.mark.parametrize("field,value", [("tag_name", None), ("assets", {}), ("assets", [None]),
                                         ("assets", [{"name": []}])])
def test_malformed_github_metadata_reports_a_release_error(field, value):
    release, raw = github_data()
    release[field] = value
    with pytest.raises(ReleaseError):
        GitHubReleases(opener=Opener([json_bytes(release), raw])).latest()


def test_github_manifest_digest_is_verified():
    release, raw = github_data()
    release["assets"][0]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ReleaseError, match="manifest asset digest"):
        GitHubReleases(opener=Opener([json_bytes(release), raw])).latest()
