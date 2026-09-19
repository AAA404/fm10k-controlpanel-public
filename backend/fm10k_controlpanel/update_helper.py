"""Small root-owned socket API plus a separate durable update worker."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import socket
import stat
import struct
import time

from .installation import (Paths, atomic_write, installed_metadata, operation_lock, rollback,
                           run, save, start_services, upgrade)
from .release import (GitHubReleases, MANIFEST_NAME, REPOSITORY, ReleaseError, extract_bundle,
                      load_json, sha256, validate_manifest, version_tuple, verify_asset)
from .updates import UpdateError, receive_json

BUSY = {"queued", "downloading", "preparing", "installing", "restarting", "rolling_back", "recovery_required"}
TOKEN = Path("/etc/fm10k-controlpanel/github-token")


def lock_writes(paths, identifier):
    # The worker can run before socket activation has created this directory.
    # Web must be able to stat the marker despite the worker's private umask.
    paths.marker.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    paths.marker.parent.chmod(0o755)
    atomic_write(paths.marker, (identifier + "\n").encode(), 0o644)


def github_client(token_file=TOKEN):
    token = None
    if token_file.exists():
        from .native_guard import trusted_file
        if stat.S_IMODE(token_file.stat().st_mode) != 0o600:
            raise ReleaseError("GitHub credential file must have mode 0600")
        token = trusted_file(token_file).decode().strip()
        if not token or len(token) > 512 or any(char.isspace() for char in token):
            raise ReleaseError("GitHub credential file is invalid")
    return GitHubReleases(token)


class UpdateManager:
    def __init__(self, paths=None, client_factory=github_client, runner=run, clock=time.time):
        self.paths = paths or Paths()
        self.client_factory, self.runner, self.clock = client_factory, runner, clock

    def state(self):
        path = self.paths.updates / "state.json"
        return json.loads(path.read_bytes()) if path.exists() else {"state": "idle", "candidate": None, "job": None}

    def write_state(self, state):
        save(self.paths.updates / "state.json", state)

    def status(self):
        try:
            installed = installed_metadata(self.paths)
        except (OSError, ValueError):
            return {"enabled": False, "state": "unavailable", "current_version": None, "repository": REPOSITORY,
                    "component": "native+web", "candidate": None, "job": None,
                    "message": "需要通过完整 Release 安装器建立受支持的原生安装。"}
        state = self.state()
        candidate = state.get("candidate")
        current = installed["version"]
        if candidate and version_tuple(candidate["manifest"]["version"]) <= version_tuple(current):
            candidate = None
        result = {"enabled": True, "state": state["state"], "current_version": current, "repository": REPOSITORY,
                  "release_url": f"https://github.com/{REPOSITORY}/releases", "component": "native+web",
                  "candidate": None, "job": state.get("job"), "checked_at": state.get("checked_at"),
                  "message": state.get("message", "可以检查 GitHub 的最新稳定版本。")}
        if candidate:
            result["candidate"] = {"version": candidate["manifest"]["version"], "manifest_sha256": candidate["manifest_sha256"],
                                   "release_url": f"https://github.com/{REPOSITORY}/releases/tag/{candidate['manifest']['tag']}",
                                   "source_commit": candidate["manifest"]["source_commit"]}
        return result

    def check(self):
        installed = installed_metadata(self.paths)
        state = self.state()
        if state["state"] in BUSY:
            raise UpdateError("更新或恢复正在进行，请等待当前任务结束。")
        state.update(candidate=None, checked_at=self.clock())
        self.write_state(state)
        try:
            candidate = self.client_factory().latest()
            if candidate["manifest"]["sdk_manifest_sha256"] != installed["sdk_manifest_sha256"]:
                raise ReleaseError("release requires different SDK inputs; use an offline migration")
            available = version_tuple(candidate["manifest"]["version"]) > version_tuple(installed["version"])
            state.update(state="available" if available else "up_to_date", candidate=candidate if available else None,
                         message="发现可用稳定版本。安装会重启交换服务并短暂中断数据转发。" if available else "当前已经是最新兼容版本。")
        except (OSError, ValueError) as error:
            state.update(state="check_failed", message=str(error))
        self.write_state(state)
        return self.status()

    def install(self, request):
        if set(request) != {"action", "version", "manifest_sha256", "confirm_restart"} or request["confirm_restart"] is not True:
            raise UpdateError("安装需要指定已检查的版本、清单摘要并确认维护中断。", 422)
        installed = installed_metadata(self.paths)
        state = self.state()
        if state["state"] in BUSY:
            raise UpdateError("已有更新或恢复任务，不能重复安装。")
        candidate = state.get("candidate")
        if (not candidate or not 0 <= self.clock() - state.get("checked_at", 0) <= 3600
                or request["version"] != candidate["manifest"]["version"]
                or request["manifest_sha256"] != candidate["manifest_sha256"]
                or version_tuple(request["version"]) <= version_tuple(installed["version"])):
            raise UpdateError("版本检查已失效，请重新检查后安装。")
        job = {"id": secrets.token_hex(16), "version": request["version"], "state": "queued", "created_at": self.clock()}
        state.update(state="queued", job=job, message="更新已排队，正在进入维护模式。")
        self.write_state(state)
        lock_writes(self.paths, job["id"])
        try:
            self.runner("systemctl", "start", "--no-block", "fm10k-update-worker.service", timeout=10)
        except Exception:
            state["message"] = "任务已保存但启动响应未确认；请检查更新服务状态，不要重复提交。"
            self.write_state(state)
        return self.status()

    def handle(self, request):
        action = request.get("action")
        if action in {"status", "check"}:
            if set(request) != {"action"}:
                raise UpdateError("版本检查不接受自定义 URL、仓库或凭据。", 422)
            return self.status() if action == "status" else self.check()
        if action == "install":
            return self.install(request)
        raise UpdateError("不支持的更新请求。", 422)

    def progress(self, phase, message):
        state = self.state()
        state.update(state=phase, message=message)
        if state.get("job"):
            state["job"].update(state=phase, updated_at=self.clock())
        self.write_state(state)

    def recover(self):
        if not self.paths.journal.exists():
            return False
        transaction = json.loads(self.paths.journal.read_bytes())
        if transaction.get("schema") != 1 or transaction.get("phase") not in {
                "stopping", "checkpointed", "switching", "committed", "aborted", "rolled_back"}:
            raise ReleaseError("unknown update recovery journal; refusing to change services")
        if transaction.get("phase") == "committed":
            state = self.state()
            if state["state"] in BUSY and (state.get("job") or {}).get("version") == transaction.get("target_version"):
                metadata = installed_metadata(self.paths)
                if metadata["version"] != transaction["target_version"]:
                    raise ReleaseError("committed update and installed version disagree")
                self.progress("succeeded", "更新已完成，已恢复任务状态。")
                self.paths.marker.unlink(missing_ok=True)
                return True
            return False
        if transaction.get("phase") in {"aborted", "rolled_back"}:
            state = self.state()
            if (state["state"] in BUSY and transaction.get("job_id")
                    and (state.get("job") or {}).get("id") == transaction["job_id"]):
                self.progress("rolled_back" if transaction["phase"] == "rolled_back" else "failed",
                              "原版本已恢复，已同步中断前保存的任务结果。")
                self.paths.marker.unlink(missing_ok=True)
                return True
            return False
        self.progress("rolling_back", "检测到中断的更新，正在恢复检查点。")
        if transaction.get("phase") == "stopping":
            transaction["phase"] = "aborted"
            save(self.paths.journal, transaction)
            start_services(self.runner)
        else:
            rollback(self.paths, transaction, runner=self.runner)
        self.progress("rolled_back", "已从中断的更新恢复原版本。")
        self.paths.marker.unlink(missing_ok=True)
        return True

    def work(self):
        with operation_lock(self.paths):
            prior = self.state()
            # Even an unreadable recovery journal must retain the write lock.
            if prior["state"] in BUSY or self.paths.journal.exists():
                lock_writes(self.paths, "update-worker")
            try:
                if self.recover():
                    return
            except Exception:
                self.progress("recovery_required", "中断恢复未完成，保留维护锁及检查点；请检查服务日志。")
                raise
            state = self.state()
            if state["state"] not in BUSY:
                self.paths.marker.unlink(missing_ok=True)
                return
            if state["state"] != "queued":
                self.progress("failed", "上次任务在切换前中断，请重新检查版本。")
                self.paths.marker.unlink(missing_ok=True)
                return
            candidate = state["candidate"]
            try:
                installed = installed_metadata(self.paths)
                if version_tuple(candidate["manifest"]["version"]) <= version_tuple(installed["version"]):
                    raise ReleaseError("queued release is no longer newer than the installed version")
                self.progress("downloading", "正在从固定 GitHub 仓库下载并校验发布包。")
                client = self.client_factory()
                raw = client.asset_bytes(candidate["assets"][MANIFEST_NAME], 128 * 1024)
                manifest = validate_manifest(load_json(raw))
                if hashlib.sha256(raw).hexdigest() != candidate["manifest_sha256"] or manifest != candidate["manifest"]:
                    raise ReleaseError("release manifest changed since the administrator checked it")
                directory = self.paths.updates / "downloads" / state["job"]["id"]
                directory.mkdir(mode=0o700, parents=True)
                asset = manifest["assets"]["bundle"]
                archive = directory / asset["name"]
                client.download(candidate["assets"][asset["name"]], asset, archive)
                source = extract_bundle(archive, directory / "source", manifest["version"])
                package = source / "packages" / manifest["assets"]["web"]["name"]
                verify_asset(package, manifest["assets"]["web"])
                if sha256(source / "hardware/sdk-inputs.json") != manifest["sdk_manifest_sha256"]:
                    raise ReleaseError("source bundle SDK contract differs from the release manifest")
                upgraded = upgrade(source, paths=self.paths, runner=self.runner, progress=self.progress, job_id=state["job"]["id"])
                self.progress("succeeded", "原生服务和 Web 已更新，配置与健康检查通过。")
                state = self.state()
                state["job"]["checkpoint"] = upgraded["checkpoint"]
                state["candidate"] = None
                self.write_state(state)
            except Exception:
                if self.state()["state"] not in {"rolled_back", "recovery_required"}:
                    self.progress("failed", "更新未完成；请检查本地服务日志后重新检查版本。")
                raise
            finally:
                if self.state()["state"] != "recovery_required":
                    self.paths.marker.unlink(missing_ok=True)


def main():
    if os.geteuid() != 0:
        raise SystemExit("update helper requires root socket activation")
    with socket.socket(fileno=0) as connection:
        connection.settimeout(30)
        _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid not in {0, pwd.getpwnam("fm10k-web").pw_uid}:
            raise SystemExit("unauthorized update helper peer")
        try:
            request = receive_json(connection, maximum=4096)
            manager = UpdateManager()
            manager.paths.updates.mkdir(mode=0o700, parents=True, exist_ok=True)
            with (manager.paths.updates / "request.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                response = {"ok": True, "data": manager.handle(request)}
        except (OSError, ValueError) as error:
            response = {"ok": False, "error": str(error), "status": getattr(error, "status", 409)}
        connection.sendall((json.dumps(response) + "\n").encode())


def worker_main():
    if os.geteuid() != 0:
        raise SystemExit("update worker requires root")
    UpdateManager().work()
    return 0
