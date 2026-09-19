"""Unprivileged Web client for the restricted release-update socket."""
from __future__ import annotations

import json
from pathlib import Path
import socket

from .release import REPOSITORY

SOCKET = "/run/fm10k-update/control.sock"
MAINTENANCE = Path("/run/fm10k-update/maintenance")


class UpdateError(ValueError):
    def __init__(self, message, status=409):
        super().__init__(message)
        self.status = status


def receive_json(connection, maximum=128 * 1024):
    raw = bytearray()
    while b"\n" not in raw:
        chunk = connection.recv(min(8192, maximum + 1 - len(raw)))
        if not chunk:
            raise UpdateError("更新服务未返回完整响应。", 503)
        raw.extend(chunk)
        if len(raw) > maximum:
            raise UpdateError("更新请求超过大小限制。", 422)
    line, rest = bytes(raw).split(b"\n", 1)
    if rest.strip():
        raise UpdateError("更新服务只接受单个请求。", 422)
    try:
        result = json.loads(line)
    except (ValueError, UnicodeError):
        raise UpdateError("无效的更新请求。", 422) from None
    if not isinstance(result, dict):
        raise UpdateError("更新请求必须是 JSON 对象。", 422)
    return result


class UpdateClient:
    def __init__(self, mode, version, socket_path=SOCKET):
        self.mode, self.version, self.socket_path = mode, version, socket_path

    def maintenance(self):
        return self.mode == "netlab" and MAINTENANCE.exists()

    def unavailable(self, message):
        return {"enabled": False, "state": "unavailable", "current_version": self.version,
                "repository": REPOSITORY, "release_url": f"https://github.com/{REPOSITORY}/releases",
                "component": "native+web", "message": message, "candidate": None, "job": None}

    def request(self, action, body=None):
        if self.mode == "mock":
            if action == "status":
                return self.unavailable("模拟环境不执行安装。完整安装后可检查 GitHub 版本并进行受控更新。")
            raise UpdateError("模拟环境不能下载或安装设备更新。")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(35)
                connection.connect(self.socket_path)
                connection.sendall((json.dumps({**(body or {}), "action": action}) + "\n").encode())
                response = receive_json(connection)
        except (OSError, TimeoutError):
            if action == "status":
                return self.unavailable("更新服务暂不可用，请检查 fm10k-update.socket。")
            raise UpdateError("更新请求未确认，请刷新状态后检查；不会自动重复安装。", 503) from None
        if not response.get("ok"):
            raise UpdateError(str(response.get("error", "更新请求未完成。")), response.get("status", 409))
        return response["data"]
