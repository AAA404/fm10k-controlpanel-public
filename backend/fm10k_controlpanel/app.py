from __future__ import annotations

import hmac
import json
import os
import platform
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from . import __version__
from .auth import Auth, AccountSessionExpired, AccountWriteUncertain
from .board import HardwareError, PHYSICAL, bandwidth, lut_points
from .models import (AdministratorUpdate, CommitRequest, Credentials, ManualPwm, Proposal, SwitchConfiguration,
                     STORM_CONTROLLER_CAPACITY, STORM_MIN_RATE_KBPS)
from .service import PanelError, PanelService
from .eye import EyeRequest, export_csv
from .simulator import MockConfigd
from .http_limits import BodyLimit
from .roce import capabilities as roce_capabilities, preflight as roce_preflight
from .updates import status as update_status, UPDATE_MESSAGE
from .time_sync import TimeSyncClient, TimeSyncError, TimeSyncRequest

ROOT = Path(__file__).resolve().parents[2]


def create_app(*, state_dir: Path | None = None, backend=None, secure_cookie: bool | None = None) -> FastAPI:
    directory = state_dir or Path(os.environ.get("PANEL_STATE_DIR", ROOT / "local-state"))
    mode = os.environ.get("PANEL_BACKEND", "mock")
    if backend is None:
        if mode == "mock": backend = MockConfigd(directory)
        elif mode == "netlab":
            from .netlab import NetlabBackend
            backend = NetlabBackend()
        else: raise RuntimeError("PANEL_BACKEND 必须为 mock 或 netlab；不会自动降级为模拟设备")
    service = PanelService(backend, directory)
    auth = Auth(directory)
    time_sync = TimeSyncClient(backend.mode, directory)
    secure = (backend.mode != "mock" or os.environ.get("PANEL_SECURE_COOKIE") == "1") if secure_cookie is None else secure_cookie

    @asynccontextmanager
    async def lifespan(app):
        service.start()
        yield
        service.close()

    app = FastAPI(title="FM10K Control Panel", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.service, app.state.auth = service, auth
    app.state.time_sync = time_sync
    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and origin:
            if origin.rstrip("/") != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "不接受跨站写请求"}, status_code=403)
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > 2_000_000:
                    return JSONResponse({"detail": "请求超过 2 MB 限制"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "无效的 Content-Length"}, status_code=400)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        if request.url.path.startswith("/api/"): response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(PanelError)
    async def panel_error(request, error):
        return JSONResponse({"detail": str(error), "code": error.code}, status_code=error.status)

    @app.exception_handler(HardwareError)
    async def hardware_error(request, error):
        return JSONResponse({"detail": str(error), "code": "hardware_error"}, status_code=503)

    @app.exception_handler(TimeSyncError)
    async def time_sync_error(request, error):
        return JSONResponse({"detail": str(error), "code": "time_sync_error"}, status_code=503)

    @app.exception_handler(ValidationError)
    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        return JSONResponse({"detail": "; ".join(e["msg"] for e in error.errors()), "code": "validation_error"}, status_code=422)

    def session(request: Request):
        value = auth.session(request.cookies.get("fm10k_session"))
        if value is None: raise HTTPException(401, "请先登录")
        return value

    def writable(request: Request, user=Depends(session)):
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), user["csrf"]):
            raise HTTPException(403, "CSRF 校验失败")
        return user

    def login_response(token, value):
        response = JSONResponse({"username": value["username"], "csrf": value["csrf"], "expires": value["expires"]})
        response.set_cookie("fm10k_session", token, httponly=True, secure=secure, samesite="strict", max_age=12 * 3600, path="/")
        return response

    @app.get("/api/v1/health")
    def health():
        return {"status": "degraded" if service.last_error else "ok", "mode": backend.mode, "version": __version__}

    if backend.mode == "mock":
        @app.post("/api/v1/simulation/fault")
        def simulation_fault(body: dict, user=Depends(writable)):
            if set(body) - {"phase", "sensor_error"}:
                raise HTTPException(422, "未知的模拟参数")
            phase = body.get("phase")
            if phase not in {None, "quiesce_protocols", "disable_group", "set_ethernet_mode",
                             "restore_group_configuration", "verify_group", "resume_protocols",
                             "fan_write", "apply_l2", "readback"}:
                raise HTTPException(422, "未知的故障点")
            if type(body.get("sensor_error", False)) is not bool:
                raise HTTPException(422, "sensor_error 必须为布尔值")
            def configure_fault():
                backend.failure = phase
                backend.sensor_error = body.get("sensor_error", False)
            service.scheduler.call(configure_fault)
            service.audit("simulation_fault", actor=user["username"], phase=phase)
            return {"mode": "mock", "phase": phase, "sensor_error": backend.sensor_error}

    @app.get("/api/v1/auth/session")
    def auth_session(request: Request):
        value = auth.session(request.cookies.get("fm10k_session"))
        return {"initialized": auth.initialized, "authenticated": value is not None, "mode": backend.mode,
                **(value or {})}

    @app.post("/api/v1/auth/setup")
    def setup(credentials: Credentials, request: Request):
        # Deployment binds the initialization UI only to the management listener.
        try: token, value = auth.setup(credentials)
        except ValueError as error: raise HTTPException(409, str(error)) from error
        service.audit("administrator_created", actor=credentials.username)
        return login_response(token, value)

    @app.post("/api/v1/auth/login")
    def login(credentials: Credentials, request: Request):
        try: token, value = auth.login(credentials, request.client.host if request.client else "local")
        except PermissionError as error: raise HTTPException(429, str(error)) from error
        except ValueError as error: raise HTTPException(401, str(error)) from error
        service.audit("login", actor=credentials.username)
        return login_response(token, value)

    @app.post("/api/v1/auth/logout")
    def logout(request: Request, user=Depends(writable)):
        auth.logout(request.cookies.get("fm10k_session"))
        response = JSONResponse({"ok": True})
        response.delete_cookie("fm10k_session")
        return response

    @app.post("/api/v1/auth/administrator")
    def update_administrator(update: AdministratorUpdate, request: Request, user=Depends(writable)):
        try:
            token, value = auth.update_administrator(
                request.cookies.get("fm10k_session"), update, request.client.host if request.client else "local")
        except AccountSessionExpired as error:
            raise HTTPException(401, str(error)) from None
        except AccountWriteUncertain as error:
            return JSONResponse({"detail": str(error), "code": "account_write_uncertain"}, status_code=503)
        except PermissionError as error:
            raise HTTPException(429, str(error)) from None
        except ValueError as error:
            raise HTTPException(400, str(error)) from None
        service.audit("administrator_updated", actor=user["username"], username=value["username"])
        return login_response(token, value)

    @app.get("/api/v1/capabilities")
    def capabilities(user=Depends(session)):
        return {"mode": backend.mode, "version": __version__, "profile": service.config()["configuration"]["profile"], "hardware_verified": False,
                "epls": list(PHYSICAL.values()), "port_modes": ["100g", "40g", "split"],
                "lane_speeds_gbps": [10, 25], "fan_response_times": [5.45, 10.9, 21.6, 43.7],
                "storm_control": {"types": ["broadcast", "multicast", "unknown-unicast"],
                                  "minimum_rate_kbps": STORM_MIN_RATE_KBPS,
                                  "controller_capacity": STORM_CONTROLLER_CAPACITY,
                                  "shared_with": ["ingress-rate-limit"]},
                "l2": ["vlan", "fdb", "lag", "lacp", "rstp", "lldp", "igmp-v1-v2", "storm-control", "qos", "local-span"],
                "roce": roce_capabilities(),
                "l3": {"enabled": False, "reason": "首版保留入口，尚未启用三层转发"},
                "unsupported": ["mstp", "igmp-v3", "mld", "mlag", "remote-span", "standard-qsfp-dom"],
                "qualification": "simulated" if backend.mode == "mock" else "pending-hardware-validation",
                "native_integration": getattr(backend, "contract", {})}

    @app.get("/api/v1/config")
    def config(user=Depends(session)): return service.config()

    @app.post("/api/v1/control/recover", status_code=202)
    def recover_control(user=Depends(writable)):
        return service.recover_control(user["username"])

    @app.post("/api/v1/roce/preflight")
    def check_roce(body: dict, user=Depends(writable)):
        current = service.config()
        if body.get("expected_revision") != current["revision"]:
            raise PanelError("配置已变化，请刷新后重新预检", code="stale_revision")
        if not isinstance(body.get("configuration"), dict):
            raise HTTPException(422, "缺少配置对象")
        return roce_preflight(body["configuration"])

    @app.post("/api/v1/config/preview")
    def preview(proposal: Proposal, user=Depends(writable)): return service.preview(proposal)

    @app.post("/api/v1/config/commit", status_code=202)
    def commit(request: CommitRequest, user=Depends(writable)): return service.commit(request, user["username"])

    @app.get("/api/v1/jobs/{job_id}")
    def job(job_id: str, user=Depends(session)): return service.job(job_id)

    @app.post("/api/v1/jobs/{job_id}/confirm")
    def confirm(job_id: str, user=Depends(writable)): return service.finish(job_id, "confirm", user["username"])

    @app.post("/api/v1/jobs/{job_id}/rollback")
    def rollback(job_id: str, user=Depends(writable)): return service.finish(job_id, "rollback", user["username"])

    @app.get("/api/v1/telemetry")
    def telemetry(user=Depends(session)): return service.telemetry()

    @app.get("/api/v1/ports")
    def ports(user=Depends(session)): return {"ports": service.telemetry()["ports"]}

    @app.get("/api/v1/sensors")
    def sensors(user=Depends(session)): return service.telemetry()["sensors"]

    @app.get("/api/v1/optics")
    def optics(user=Depends(session)): return {"modules": service.telemetry()["optics"]}

    @app.get("/api/v1/optics/ports/{port_id}")
    def port_optics(port_id: int, user=Depends(session)): return service.port_optics(port_id)

    @app.post("/api/v1/optics/ports/{port_id}/eye", status_code=202)
    def start_eye(port_id: int, value: EyeRequest, user=Depends(writable)):
        return service.start_eye(port_id, value, user["username"])

    @app.get("/api/v1/optics/eye")
    def latest_eye(user=Depends(session)): return service.read_eye()

    @app.get("/api/v1/optics/eyes/{job_id}")
    def read_eye(job_id: str, user=Depends(session)): return service.read_eye(job_id)

    @app.post("/api/v1/optics/eyes/{job_id}/cancel", status_code=202)
    def cancel_eye(job_id: str, user=Depends(writable)):
        return service.cancel_eye(job_id, user["username"])

    @app.get("/api/v1/optics/eyes/{job_id}/export")
    def download_eye(job_id: str, format: str = "json", user=Depends(session)):
        if format not in {"json", "csv"}: raise HTTPException(422, "格式必须为 json 或 csv")
        value = service.read_eye(job_id)
        headers = {"Content-Disposition": f'attachment; filename="eye-{job_id}.{format}"'}
        if format == "csv": return Response(export_csv(value), media_type="text/csv; charset=utf-8", headers=headers)
        return JSONResponse(value, headers=headers)

    @app.get("/api/v1/sensors/history")
    def history(user=Depends(session)):
        with service.lock: return {"samples": service.history[-720::6], "persistent": False}

    @app.post("/api/v1/fans/manual", status_code=202)
    def manual(value: ManualPwm, user=Depends(writable)):
        return service.operation("manual_pwm", lambda: backend.manual(value), user["username"])

    @app.get("/api/v1/operational/{feature}")
    def operational(feature: str, user=Depends(session)):
        if feature not in {"fdb", "lldp", "lags", "rstp", "igmp", "roce"}: raise HTTPException(404, "未知功能")
        def read():
            data = backend.operational(feature)
            # The browser may have a different wall clock from the switch.
            return {"mode": backend.mode, "data": data, "server_time": service.clock()}
        return service.scheduler.call(read)

    @app.post("/api/v1/fdb/clear", status_code=202)
    def clear_fdb(body: dict, user=Depends(writable)):
        if set(body) - {"port", "vlan"}: raise HTTPException(422, "未知参数")
        port, vlan = body.get("port"), body.get("vlan")
        if port is not None and (type(port) is not int or not 1 <= port <= 24): raise HTTPException(422, "无效端口")
        if vlan is not None and (type(vlan) is not int or not 1 <= vlan <= 4094): raise HTTPException(422, "无效 VLAN")
        return service.operation("clear_dynamic_fdb", lambda: backend.clear_fdb(port, vlan), user["username"])

    @app.get("/api/v1/backups/export")
    def backup(user=Depends(session)):
        return JSONResponse(service.backup(), headers={"Content-Disposition": 'attachment; filename="fm10k-config-backup.json"'})

    @app.post("/api/v1/backups/preview")
    def restore(body: dict, user=Depends(writable)): return service.restore_preview(body)

    @app.get("/api/v1/updates")
    def updates(user=Depends(session)):
        return update_status(__version__)

    @app.post("/api/v1/updates/check")
    @app.post("/api/v1/updates/install")
    def deferred_update(body: dict, user=Depends(writable)):
        return JSONResponse({"detail":UPDATE_MESSAGE, "code":"update_not_enabled"}, status_code=501)

    @app.get("/api/v1/logs")
    def logs(user=Depends(session)):
        path = directory / "audit.jsonl"
        with service.audit_lock:
            lines = path.read_text(encoding="utf-8").splitlines()[-200:] if path.exists() else []
        return {"entries": [json.loads(line) for line in reversed(lines)]}

    @app.get("/api/v1/system")
    def system(user=Depends(session)):
        disk = shutil.disk_usage(directory if directory.exists() else ROOT)
        return {"hostname": platform.node(), "system": platform.platform(), "python": platform.python_version(),
                "version": __version__, "backend": backend.mode, "sdk_owner": "switchd" if backend.mode == "netlab" else "simulator",
                "disk": {"total": disk.total, "used": disk.used, "free": disk.free},
                "driver_baseline": "6.12.101-ies2", "sdk_target": "IES 4.3.2",
                "profile": service.config()["configuration"]["profile"]}

    @app.get("/api/v1/system/time")
    def system_time(user=Depends(session)):
        return time_sync.request("status")

    @app.post("/api/v1/system/time/sync")
    def synchronize_time(body: TimeSyncRequest, user=Depends(writable)):
        def start():
            pending = service.backend.snapshot().get("pending")
            with service.lock:
                busy = any(j["state"] in {"queued", "running", "awaiting_confirmation"} for j in service.jobs.values())
            if pending or busy:
                raise PanelError("请先完成或回滚当前配置任务，再同步系统时间。", code="pending_operation")
            service.audit("time_sync_requested", actor=user["username"], servers=body.servers)
            try:
                result = time_sync.request("sync", body.servers)
            except TimeSyncError as error:
                service.audit("time_sync_failed", actor=user["username"], error=str(error))
                raise
            service.last_sensor_sample = 0
            service.audit("time_sync_started", actor=user["username"], servers=result["servers"], state=result["state"])
            return result
        return service.scheduler.call(start)

    @app.get("/api/v1/l3")
    def l3(user=Depends(session)):
        return {"enabled": False, "entries": ["interfaces", "arp", "routes"], "message": "三层功能预留，当前不启动 rpd/FRR"}

    @app.api_route("/api/v1/l3/{path:path}", methods=["POST", "PUT", "PATCH", "DELETE"])
    def reject_l3(path: str, user=Depends(writable)): raise HTTPException(501, "首版未启用三层配置")

    static = Path(os.environ.get("PANEL_STATIC_DIR", ROOT / "frontend/dist"))
    if static.is_dir():
        assets = static / "assets"
        if assets.is_dir(): app.mount("/assets", StaticFiles(directory=assets), name="assets")
        @app.get("/")
        def index(): return FileResponse(static / "index.html")
    return app
