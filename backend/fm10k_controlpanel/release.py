"""Versioned release format and bounded GitHub transport (standard library only)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "AAA404/fm10k-controlpanel-public"
API = f"https://api.github.com/repos/{REPOSITORY}"
MANIFEST_NAME = "release-manifest.json"
FORMAT = 1
MAX_ASSET_BYTES = 128 * 1024 * 1024
COMPATIBILITY = {
    "os": "debian", "os_version": "13", "architecture": "x86_64",
    "kernel_series": "6.12", "driver": "6.12.101-ies2", "pci_bdf": "0000:01:00.0",
    "profiles": ["sil001-hw4-b0", "sil001-hw5-a11"],
    "native_abi": 1, "configuration_schema": 1, "installer_format": FORMAT,
    "libyang": "2.1.148",
}


class ReleaseError(ValueError):
    pass


def version_tuple(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})", value):
        raise ReleaseError("release version must be a stable MAJOR.MINOR.PATCH")
    return tuple(int(part) for part in value.split("."))


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def load_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseError("duplicate JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("invalid release JSON") from error


def safe_relative(name: str) -> bool:
    return (isinstance(name, str) and bool(name) and not name.startswith("/")
            and all(part not in {"", ".", ".."} for part in name.split("/"))
            and "\\" not in name and not any(ord(char) < 32 or ord(char) == 127 for char in name))


def validate_digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ReleaseError("invalid SHA-256 digest")
    return value


def validate_manifest(value: dict, tag: str | None = None) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema", "repository", "version", "tag", "source_commit", "compatibility", "sdk_manifest_sha256", "assets"
    }:
        raise ReleaseError("unsupported release manifest")
    version_tuple(value["version"])
    if (value["schema"] != FORMAT or value["repository"] != REPOSITORY
            or value["tag"] != "v" + value["version"] or tag is not None and value["tag"] != tag):
        raise ReleaseError("release tag, repository or format mismatch")
    if value["compatibility"] != COMPATIBILITY:
        raise ReleaseError("release needs a different OS, driver, native ABI or installer")
    if not re.fullmatch(r"[0-9a-f]{40}", str(value["source_commit"])):
        raise ReleaseError("invalid source commit")
    validate_digest(value["sdk_manifest_sha256"])
    assets = value["assets"]
    if not isinstance(assets, dict) or set(assets) != {"bundle", "web"}:
        raise ReleaseError("release must pair native source and Web package")
    expected = {"bundle": f"fm10k-controlpanel-{value['version']}.tar.gz",
                "web": f"fm10k-controlpanel_{value['version']}_all.deb"}
    for key, asset in assets.items():
        if (not isinstance(asset, dict) or set(asset) != {"name", "size", "sha256"}
                or asset["name"] != expected[key] or type(asset["size"]) is not int
                or not 0 < asset["size"] <= MAX_ASSET_BYTES):
            raise ReleaseError("invalid release asset")
        validate_digest(asset["sha256"])
    return value


def verify_asset(path: Path, asset: dict):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != asset["size"] or sha256(path) != asset["sha256"]:
        raise ReleaseError(f"release asset checksum mismatch: {path.name}")


def extract_bundle(archive: Path, destination: Path, version: str) -> Path:
    """Validate every entry before extraction; never create links or special files."""
    version_tuple(version)
    prefix = f"fm10k-controlpanel-{version}"
    if destination.exists():
        raise ReleaseError("release extraction requires a new directory")
    with tarfile.open(archive, "r:gz") as tar:
        entries, seen, total = [], set(), 0
        for member in tar:
            name = member.name.rstrip("/") if member.isdir() else member.name
            if (not safe_relative(name) or PurePosixPath(name).parts[0] != prefix or name in seen
                    or not (member.isfile() or member.isdir()) or member.mode & 0o7022
                    or member.size < 0 or member.size > MAX_ASSET_BYTES):
                raise ReleaseError("unsafe, duplicate or oversized release archive entry")
            total += member.size
            if total > 512 * 1024 * 1024 or len(seen) >= 12000:
                raise ReleaseError("release archive exceeds extraction limits")
            seen.add(name)
            entries.append((name, member))
        # A file cannot also be a parent directory of another entry.
        files = {name for name, member in entries if member.isfile()}
        if any(str(parent) in files for name in seen for parent in PurePosixPath(name).parents):
            raise ReleaseError("release archive file/directory collision")
        destination.mkdir(mode=0o700, parents=True)
        for name, member in entries:
            target = destination / name
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with target.open("xb") as stream, tar.extractfile(member) as source:
                    for data in iter(lambda: source.read(1024 * 1024), b""):
                        stream.write(data)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    root = destination / prefix
    verify_bundle(root, version)
    return root


def verify_bundle(root: Path, version: str | None = None) -> dict:
    if root.is_symlink():
        raise ReleaseError("source bundle root cannot be a symbolic link")
    # Canonicalize OS aliases such as macOS /var -> /private/var. Links within
    # the extracted bundle are still rejected below.
    root = root.resolve(strict=True)
    manifest = load_json((root / "bundle-manifest.json").read_bytes())
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "version", "repository", "compatibility", "files"}:
        raise ReleaseError("invalid source bundle manifest")
    version_tuple(manifest["version"])
    if (manifest["schema"] != FORMAT or manifest["repository"] != REPOSITORY
            or manifest["compatibility"] != COMPATIBILITY
            or version is not None and manifest["version"] != version):
        raise ReleaseError("source bundle compatibility or version mismatch")
    files = manifest["files"]
    if not isinstance(files, dict) or not files or len(files) > 12000:
        raise ReleaseError("invalid source file manifest")
    for name, entry in files.items():
        if not safe_relative(name) or name == "bundle-manifest.json":
            raise ReleaseError("invalid source file path")
        if (not isinstance(entry, dict) or set(entry) != {"sha256", "size", "mode"}
                or entry["mode"] not in (0o644, 0o755) or type(entry["size"]) is not int
                or not 0 <= entry["size"] <= MAX_ASSET_BYTES):
            raise ReleaseError("invalid source file metadata")
        validate_digest(entry["sha256"])
        path = root / name
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ReleaseError("source bundle must not contain symbolic links")
        if (not path.is_file() or path.stat().st_size != entry["size"] or sha256(path) != entry["sha256"]
                or stat.S_IMODE(path.stat().st_mode) != entry["mode"]):
            raise ReleaseError(f"source file integrity mismatch: {name}")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ReleaseError("unsupported source bundle entry")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != set(files) | {"bundle-manifest.json"}:
        raise ReleaseError("unlisted or missing source bundle files")
    required = {"install.sh", "scripts/install_release.py", "VERSION", "hardware/sdk-inputs.json",
                f"packages/fm10k-controlpanel_{manifest['version']}_all.deb", "deploy/release-dependencies.json"}
    if not required <= set(files) or (root / "VERSION").read_text().strip() != manifest["version"]:
        raise ReleaseError("source bundle is incomplete")
    return manifest


class GitHubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme != "https" or target.username or target.password or target.port not in (None, 443)
                or target.hostname not in {"api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}):
            raise ReleaseError("GitHub asset redirected to an untrusted origin")
        if target.hostname == "api.github.com" and not target.path.startswith(f"/repos/{REPOSITORY}/releases/"):
            raise ReleaseError("GitHub redirect left the configured repository")
        if target.hostname == "github.com" and not target.path.startswith(f"/{REPOSITORY}/releases/download/"):
            raise ReleaseError("GitHub redirect left the configured release source")
        redirected = super().redirect_request(request, fp, code, message, headers, newurl)
        if redirected is not None and target.hostname != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


class GitHubReleases:
    def __init__(self, token: str | None = None, opener=None):
        self.token = token
        # Ignore HTTP(S)_PROXY environment inherited from other applications.
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), GitHubRedirects())

    def _open(self, suffix: str, *, binary=False):
        if not re.fullmatch(r"/releases/(?:latest|assets/[1-9][0-9]*|tags/v[0-9]+\.[0-9]+\.[0-9]+)", suffix):
            raise ReleaseError("unsupported GitHub API request")
        headers = {"Accept": "application/octet-stream" if binary else "application/vnd.github+json",
                   "User-Agent": "fm10k-controlpanel-release/1", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        for attempt in range(3):
            try:
                return self.opener.open(urllib.request.Request(API + suffix, headers=headers), timeout=15)
            except urllib.error.HTTPError as error:
                messages = {401: "GitHub credential is invalid", 403: "GitHub access denied or API rate limit reached",
                            404: "No published release is accessible; a private repository needs a read-only server credential"}
                raise ReleaseError(messages.get(error.code, f"GitHub returned HTTP {error.code}")) from None
            except (OSError, urllib.error.URLError):
                if attempt == 2:
                    raise ReleaseError("GitHub connection failed; check DNS, HTTPS access and system time") from None
                time.sleep(attempt + 1)

    def _bytes(self, suffix, limit, *, binary=False):
        with self._open(suffix, binary=binary) as response:
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ReleaseError("GitHub response exceeds size limit")
        return raw

    def latest(self) -> dict:
        release = load_json(self._bytes("/releases/latest", 1024 * 1024))
        if (not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False
                or type(release.get("id")) is not int or release["id"] <= 0):
            raise ReleaseError("only published stable GitHub releases are supported")
        tag = release.get("tag_name", "")
        version_tuple(tag[1:] if isinstance(tag, str) and tag.startswith("v") else "")
        entries = release.get("assets")
        if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
            raise ReleaseError("invalid GitHub release asset list")
        assets = {}
        for asset in entries:
            if not isinstance(asset, dict):
                raise ReleaseError("invalid GitHub release asset")
            name = asset.get("name")
            if not isinstance(name, str) or name in assets:
                raise ReleaseError("ambiguous GitHub release assets")
            assets[name] = asset
        descriptor = assets.get(MANIFEST_NAME)
        raw = self.asset_bytes(descriptor, 128 * 1024)
        manifest_digest = hashlib.sha256(raw).hexdigest()
        if descriptor.get("digest") not in (None, "sha256:" + manifest_digest):
            raise ReleaseError("GitHub manifest asset digest mismatch")
        manifest = validate_manifest(load_json(raw), tag)
        for asset in manifest["assets"].values():
            remote = assets.get(asset["name"])
            if not remote or remote.get("size") != asset["size"]:
                raise ReleaseError("GitHub asset size does not match the release manifest")
            digest = remote.get("digest")
            if digest is not None and digest != "sha256:" + asset["sha256"]:
                raise ReleaseError("GitHub asset digest does not match the release manifest")
        return {"manifest": manifest, "manifest_sha256": manifest_digest,
                "release_id": release["id"], "assets": {name: {"id": item.get("id"), "size": item.get("size")}
                    for name, item in assets.items() if name in {MANIFEST_NAME, *[a["name"] for a in manifest["assets"].values()]}}}

    @staticmethod
    def _asset_id(asset, maximum):
        if (not isinstance(asset, dict) or type(asset.get("id")) is not int or asset["id"] <= 0
                or type(asset.get("size")) is not int or not 0 < asset["size"] <= maximum):
            raise ReleaseError("missing or invalid GitHub release asset")
        return asset["id"]

    def asset_bytes(self, asset, maximum):
        identifier = self._asset_id(asset, maximum)
        raw = self._bytes(f"/releases/assets/{identifier}", maximum, binary=True)
        if len(raw) != asset["size"]:
            raise ReleaseError("truncated GitHub release asset")
        return raw

    def download(self, remote, expected, destination: Path):
        identifier = self._asset_id(remote, MAX_ASSET_BYTES)
        if remote["size"] != expected["size"]:
            raise ReleaseError("release asset size changed")
        created = False
        try:
            count = 0
            with self._open(f"/releases/assets/{identifier}", binary=True) as response, destination.open("xb") as stream:
                created = True
                while True:
                    data = response.read(1024 * 1024)
                    if not data:
                        break
                    count += len(data)
                    if count > expected["size"]:
                        raise ReleaseError("release download exceeds manifest size")
                    stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            verify_asset(destination, expected)
        except BaseException:
            if created:
                destination.unlink(missing_ok=True)
            raise
