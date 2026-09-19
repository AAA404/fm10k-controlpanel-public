from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from pathlib import Path

from .models import AdministratorUpdate, Credentials
from .storage import atomic_json, read_json


class AccountSessionExpired(ValueError):
    pass


class AccountWriteUncertain(OSError):
    pass


class Auth:
    def __init__(self, directory: Path, clock=time.time, monotonic=time.monotonic):
        self.path = directory / "accounts.json"
        self.clock = clock
        self.monotonic = monotonic
        self.lock = threading.RLock()
        self.sessions = {}
        self.failures = {}

    @property
    def initialized(self):
        return self.path.exists()

    def setup(self, credentials: Credentials):
        with self.lock:
            if self.initialized: raise ValueError("管理员已初始化")
            salt = secrets.token_hex(24)
            atomic_json(self.path, {"username": credentials.username, "salt": salt,
                                    "rounds": 600_000, "digest": self.digest(credentials.password, salt, 600_000)})
            return self.new_session(credentials.username)

    @staticmethod
    def digest(password, salt, rounds):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), rounds).hex()

    def login(self, credentials: Credentials, address: str):
        with self.lock:
            now, attempts = self._attempts(address)
            stored = read_json(self.path)
            if not stored: raise ValueError("请先初始化管理员")
            actual = self.digest(credentials.password, stored["salt"], stored["rounds"])
            if not (hmac.compare_digest(stored["username"], credentials.username)
                    and hmac.compare_digest(stored["digest"], actual)):
                self.failures[address] = attempts + [now]
                raise ValueError("用户名或密码错误")
            self.failures.pop(address, None)
            return self.new_session(credentials.username)

    def _attempts(self, address):
        now = self.monotonic()
        for key in list(self.failures):
            self.failures[key] = [t for t in self.failures[key] if now - t < 60]
            if not self.failures[key]:
                del self.failures[key]
        attempts = self.failures.get(address, [])
        if len(attempts) >= 5:
            raise PermissionError("密码验证尝试过于频繁，请稍后重试")
        return now, attempts

    def update_administrator(self, token: str | None, update: AdministratorUpdate, address: str):
        with self.lock:
            # Recheck the live session while holding the account lock: another
            # password change may have invalidated the dependency's snapshot.
            current = self.session(token)
            if not current:
                raise AccountSessionExpired("会话已失效，请重新登录")
            now, attempts = self._attempts(address)
            stored = read_json(self.path)
            if not stored or stored["username"] != current["username"]:
                raise AccountSessionExpired("管理员已变化，请重新登录")
            actual = self.digest(update.current_password, stored["salt"], stored["rounds"])
            if not hmac.compare_digest(stored["digest"], actual):
                self.failures[address] = attempts + [now]
                raise ValueError("当前密码不正确")
            if update.username == stored["username"] and update.new_password is None:
                raise ValueError("管理员信息没有变化")
            replacement = dict(stored, username=update.username)
            if update.new_password is not None:
                replacement["salt"] = secrets.token_hex(24)
                replacement["rounds"] = 600_000
                replacement["digest"] = self.digest(update.new_password, replacement["salt"], replacement["rounds"])
            try:
                atomic_json(self.path, replacement)
            except OSError:
                # A directory fsync can fail after rename. Revoke sessions even
                # when the caller cannot know whether the new file committed.
                self.sessions.clear()
                raise AccountWriteUncertain("账号保存结果需核对，会话已失效；请重新登录确认使用的凭据") from None
            self.sessions.clear()
            self.failures.clear()
            return self.new_session(update.username)

    def new_session(self, username):
        with self.lock:
            now = self.monotonic()
            self.sessions = {key: value for key, value in self.sessions.items() if value["deadline"] > now}
            if len(self.sessions) >= 64:
                oldest = min(self.sessions, key=lambda key: self.sessions[key]["deadline"])
                del self.sessions[oldest]
            token = secrets.token_urlsafe(32)
            session = {"username": username, "csrf": secrets.token_urlsafe(32), "deadline": now + 12 * 3600}
            self.sessions[token] = session
            return token, self._public_session(session, now)

    def _public_session(self, session, now):
        # Keep the API's epoch timestamp while duration enforcement is immune
        # to NTP corrections. Monotonic deadlines never leave the process.
        return {"username": session["username"], "csrf": session["csrf"],
                "expires": self.clock() + session["deadline"] - now}

    def session(self, token):
        with self.lock:
            session = self.sessions.get(token)
            now = self.monotonic()
            if not session or session["deadline"] <= now:
                self.sessions.pop(token, None)
                return None
            return self._public_session(session, now)

    def logout(self, token):
        with self.lock: self.sessions.pop(token, None)
