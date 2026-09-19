from __future__ import annotations

import copy
import hashlib
import itertools
import json
import logging
import queue
import threading
import time
import uuid
from concurrent.futures import Future
from pathlib import Path

from .board import HardwareError, RollbackError, bandwidth, changed_groups, lut_points
from .models import CommitRequest, Proposal, SwitchConfiguration, PHYSICAL
from .port_modes import configuration_changes, group_changes
from .optics import diagnostic_shell, PhyModeChanged, PHY_REFRESH_SECONDS, PHY_STALE_SECONDS, power_for_epl

PORT_SAMPLE_INTERVAL_SECONDS = 1
PORT_STALE_AFTER_SECONDS = 3


class PanelError(Exception):
    def __init__(self, message, status=409, code="conflict"):
        super().__init__(message)
        self.status, self.code = status, code


class OwnerQueue:
    def __init__(self, capacity=32):
        self.queue = queue.PriorityQueue(capacity)
        self.sequence = itertools.count()
        self.keys = set()
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.finalizer = None
        self.thread = threading.Thread(target=self._run, name="panel-ipc-owner", daemon=True)
        self.thread.start()

    def submit(self, function, *, priority=0, key=None):
        with self.lock:
            if self.stopping.is_set():
                raise PanelError("服务正在退出，请稍后重试", 503, "shutting_down")
            if key and key in self.keys: return None
            future = Future()
            try: self.queue.put_nowait((priority, next(self.sequence), function, future, key))
            except queue.Full: raise PanelError("操作队列已满，请稍后重试", 503, "queue_full") from None
            if key: self.keys.add(key)
            return future

    def _run(self):
        while not self.stopping.is_set() or not self.queue.empty():
            try: _, _, function, future, key = self.queue.get(timeout=0.2)
            except queue.Empty: continue
            try: future.set_result(function())
            except Exception as error: future.set_exception(error)
            finally:
                with self.lock:
                    if key: self.keys.discard(key)
                self.queue.task_done()
        if self.finalizer:
            self.finalizer()

    def call(self, function, timeout=30):
        if threading.current_thread() is self.thread: return function()
        return self.submit(function).result(timeout)

    def close(self, finalizer=None, timeout=10):
        with self.lock:
            if not self.stopping.is_set():
                self.finalizer = finalizer
                self.stopping.set()
        # A long IPC transaction can outlive the Web shutdown budget. Its
        # transport must still be closed by its owner after the call finishes.
        self.thread.join(timeout=timeout)


def differences(before, after, path=""):
    result = []
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys(), key=str):
            result += differences(before.get(key), after.get(key), f"{path}/{key}")
    elif before != after:
        result.append({"path": path, "before": before, "after": after})
    return result


class PanelService:
    def __init__(self, backend, state_dir: Path, clock=time.time, monotonic=time.monotonic):
        self.backend = backend
        self.mode = backend.mode
        self.directory = state_dir
        self.clock = clock
        self.monotonic = monotonic
        self.scheduler = OwnerQueue()
        self.lock = threading.RLock()
        self.audit_lock = threading.Lock()
        self.audit_error = None
        self.drafts = {}
        self.jobs = {}
        self.confirmation_deadlines = {}
        self.busy_job = None
        self.cache = {"ports": [], "sensors": {"quality": "pending", "temperatures": [], "fan": {}}, "optics": []}
        self.last_error = None
        self.stop_event = threading.Event()
        self.monitor = None
        self.history = []
        self.last_sensor_sample = 0
        self.last_roce_sample = 0
        self._optics_revision = None
        self._eye_cache = {}
        self._optics_cache = {}
        self._optics_due = {}
        self._optics_inflight = set()

    def start(self):
        try: self.scheduler.call(self._sample, timeout=10)
        except Exception as error: self.last_error = str(error)
        self.monitor = threading.Thread(target=self._monitor, name="panel-cache-scheduler", daemon=True)
        self.monitor.start()

    def _monitor(self):
        while not self.stop_event.wait(PORT_SAMPLE_INTERVAL_SECONDS):
            try: self.scheduler.submit(self._sample, priority=10, key="telemetry")
            except PanelError: pass

    def _sample(self):
        snapshot_received = False
        try:
            snapshot = self.backend.snapshot()
            snapshot_monotonic = self.monotonic()
            snapshot_received = True
            with self.lock:
                self.cache["native_integration"] = copy.deepcopy(getattr(self.backend, "contract", {}))
                self.cache["control_available"] = True
            self._observe_optics_revision(snapshot["revision"])
            ports = self.backend.ports()
            sensors = None
            optics = None
            now = self.clock()
            sensor_tick = self.monotonic()
            if sensor_tick - self.last_sensor_sample >= 5 or not self.last_sensor_sample:
                sensors = self.backend.sensors()
                optics = self.backend.optics()
                self.last_sensor_sample = sensor_tick
            if hasattr(self.backend, "sample_roce") and sensor_tick - self.last_roce_sample >= 10:
                self.last_roce_sample = sensor_tick
                if not snapshot.get("pending") and snapshot.get("configuration", {}).get("qos", {}).get("roce", {}).get("enabled"):
                    self.scheduler.submit(self.backend.sample_roce, priority=20, key="roce-diagnostics")
            with self.lock:
                self.cache["ports"] = ports
                self.cache["sampled_at"] = now
                if sensors is not None:
                    self.cache["sensors"] = sensors
                    self.history.append({"time": sensors.get("sampled_at", now), "temperatures": sensors.get("temperatures", []), "fan": sensors.get("fan", {})})
                    self.history = self.history[-17280:]
                if optics is not None: self.cache["optics"] = optics
                self.last_error = None
                pending = snapshot.get("pending") or {}
                pending_id = pending.get("job_id")
                for job in self.jobs.values():
                    if job["state"] == "awaiting_confirmation" and job["id"] == pending_id:
                        self._observe_confirmation_timer(job["id"], pending, snapshot_monotonic)
                        job["deadline"] = pending.get("deadline")
                    if job["state"] == "awaiting_confirmation" and job["id"] != pending_id:
                        self.confirmation_deadlines.pop(job["id"], None)
                        terminal = snapshot.get("last_transaction") or {}
                        matches = terminal.get("job_id") == job["id"] or (
                            job.get("revision") is not None and terminal.get("revision") == job["revision"])
                        if matches and terminal.get("state") in {"confirmed", "rolled_back"}:
                            confirmed = terminal["state"] == "confirmed"
                            job.update(state="done" if confirmed else "rolled_back",
                                       message="配置已确认" if confirmed else "原配置已恢复", updated=now)
                            self.audit("transaction_reconciled", job_id=job["id"], outcome=terminal["state"])
                        else:
                            # Absence of a timer is not proof of rollback.
                            job.update(message="正在核对配置结果，暂未取得持久化结果证明", updated=now)
        except Exception as error:
            with self.lock:
                self.last_error = str(error)
                if not snapshot_received:
                    self.cache["control_available"] = False
                if self.cache.get("sensors"): self.cache["sensors"]["quality"] = "stale"
                for port in self.cache["ports"]: port["quality"] = "stale"
            raise

    def audit(self, event, **details):
        with self.audit_lock:
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
                path = self.directory / "audit.jsonl"
                if path.exists() and path.stat().st_size > 2_000_000:
                    path.replace(path.with_suffix(".previous.jsonl"))
                with path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"time": self.clock(), "event": event, **details}, ensure_ascii=False) + "\n")
                self.audit_error = None
            except OSError as error:
                # An audit disk failure cannot turn a committed transaction
                # into a reported hardware failure or trigger a second apply.
                self.audit_error = str(error)
                logging.getLogger(__name__).error("audit write failed: %s", error)

    def _observe_optics_revision(self, revision):
        with self.lock:
            if revision != self._optics_revision:
                self._optics_revision = revision
                self._optics_cache.clear()
                self._optics_due.clear()

    def _read_config(self):
        snapshot = self.backend.snapshot()
        self._observe_optics_revision(snapshot["revision"])
        return snapshot

    def config(self):
        snapshot = self.scheduler.call(self._read_config)
        received = self.monotonic()
        if snapshot.get("pending"):
            snapshot["pending"] = {key: snapshot["pending"][key] for key in ("job_id", "phase", "deadline", "remaining_seconds") if key in snapshot["pending"]}
            pending = snapshot["pending"]
            with self.lock:
                self._observe_confirmation_timer(pending.get("job_id"), pending, received)
                # configd owns the timer. Recover the UI job after a Web restart.
                if pending.get("job_id") not in self.jobs:
                    self.jobs[pending["job_id"]] = {
                        "id": pending["job_id"], "kind": "configuration", "actor": "recovered",
                        "revision": snapshot["revision"],
                        "state": pending.get("phase", "awaiting_confirmation"),
                        "deadline": pending.get("deadline"), "updated": self.clock(),
                        "message": "已恢复待确认提交，请确认或回滚",
                    }
        return snapshot

    def _refresh_after_write(self):
        # A failed telemetry read must not change a successful commit's outcome.
        try:
            self._sample()
        except Exception:
            pass  # _sample records the error and marks cached data stale.

    def preview(self, proposal: Proposal):
        current = self.scheduler.call(self.backend.snapshot)
        if proposal.expected_revision != current["revision"]:
            raise PanelError("配置已变化，请刷新后重新预览", code="stale_revision")
        if current.get("pending"):
            raise PanelError("请先确认或回滚当前提交", code="pending_confirmation")
        before = SwitchConfiguration.model_validate(current["configuration"])
        if before.profile != proposal.configuration.profile:
            raise PanelError("板卡 Profile 不能通过在线配置或备份恢复更改", code="profile_mismatch")
        changed = changed_groups(before, proposal.configuration)
        global_qos = before.qos != proposal.configuration.qos
        global_watermarks = global_qos or bool(changed) or any(before.ports[n].mtu != p.mtu for n, p in proposal.configuration.ports.items())
        budget = bandwidth(proposal.configuration)
        draft = {"id": uuid.uuid4().hex, "expected_revision": proposal.expected_revision,
                 "configuration": proposal.configuration.model_dump(mode="json"),
                 "changes": configuration_changes(before, proposal.configuration, differences),
                 "group_changes": group_changes(before, proposal.configuration),
                 "affected_epls": sorted(PHYSICAL) if global_qos else changed, "global_qos_change": global_watermarks, "requires_restart": False, "bandwidth": budget,
                 "requires_bandwidth_ack": bool(changed) and budget["over_sku_budget"],
                 "expires_at": self.clock() + 600, "fan_lut": lut_points(proposal.configuration.fan)}
        from .roce import preflight as roce_preflight
        draft["roce_preflight"] = roce_preflight(draft["configuration"])
        if hasattr(self.backend, "validate"):
            self.scheduler.call(lambda: self.backend.validate(proposal.configuration))
        with self.lock:
            self.drafts = {key: value for key, value in self.drafts.items() if value["expires_at"] > self.clock()}
            if len(self.drafts) >= 64: raise PanelError("草稿过多，请稍后重试", 429)
            self.drafts[draft["id"]] = copy.deepcopy(draft)
        return draft

    def _new_job(self, kind, actor):
        with self.lock:
            if len(self.jobs) >= 128:
                terminal = [key for key, job in self.jobs.items() if job["state"] in {"done", "failed", "rolled_back"}]
                if not terminal: raise PanelError("任务记录已满", 503)
                del self.jobs[terminal[0]]
            job = {"id": uuid.uuid4().hex, "kind": kind, "actor": actor, "state": "queued",
                   "created": self.clock(), "updated": self.clock(), "message": "任务已排队"}
            self.jobs[job["id"]] = job
            return job

    def commit(self, request: CommitRequest, actor):
        with self.lock:
            draft = self.drafts.get(request.draft_id)
            if not draft or draft["expires_at"] <= self.clock(): raise PanelError("预览已过期，请重新预览")
            if self.busy_job: raise PanelError("已有配置正在提交，请等待结果")
            if draft["requires_bandwidth_ack"] and not request.accept_bandwidth_warning:
                raise PanelError("此模式包含内部端口后的预算超过 600G，请确认预算提示", code="bandwidth_ack_required")
            job = self._new_job("configuration", actor)
            self.busy_job = job["id"]

        def work():
            with self.lock: job.update(state="running", message="应用配置并核对硬件", updated=self.clock())
            try:
                target = SwitchConfiguration.model_validate(draft["configuration"])
                snapshot = self.backend.apply(target, draft["expected_revision"], job["id"], request.confirm_timeout)
                pending = snapshot.get("pending")
                with self.lock:
                    self._observe_confirmation_timer(job["id"], pending or {}, self.monotonic())
                    job.update(state="awaiting_confirmation" if pending else "done", revision=snapshot["revision"],
                               deadline=pending.get("deadline") if pending else None,
                               message="已生效，请在倒计时结束前确认" if pending else "配置已应用", updated=self.clock())
                self.audit("configuration_applied", job_id=job["id"], actor=actor, revision=snapshot["revision"], affected_epls=draft["affected_epls"])
                self._refresh_after_write()
            except Exception as error:
                with self.lock: job.update(state="failed", error=str(error), message="配置应用失败", rollback_failed=isinstance(error, RollbackError), updated=self.clock())
                self.audit("configuration_failed", job_id=job["id"], actor=actor, error=str(error))
            finally:
                with self.lock:
                    self.busy_job = None
                    self.drafts.pop(request.draft_id, None)
        try: self.scheduler.submit(work)
        except Exception:
            with self.lock:
                self.busy_job = None
                job.update(state="failed", message="操作队列已满")
            raise
        return self.job(job["id"])

    def _observe_confirmation_timer(self, job_id, pending, received):
        remaining = pending.get("remaining_seconds")
        if type(remaining) is int and remaining >= 0:
            self.confirmation_deadlines[job_id] = received + remaining
        else:
            self.confirmation_deadlines.pop(job_id, None)

    def job(self, job_id):
        with self.lock:
            if job_id not in self.jobs: raise PanelError("任务不存在", 404, "not_found")
            result = copy.deepcopy(self.jobs[job_id])
            if result["state"] == "awaiting_confirmation" and job_id in self.confirmation_deadlines:
                result["remaining_seconds"] = max(0, self.confirmation_deadlines[job_id] - self.monotonic())
            return result

    def recover_control(self, actor):
        if not hasattr(self.backend, "recover_control"):
            raise PanelError("当前后端不支持恢复控制", 409, "recovery_unsupported")
        with self.lock:
            if self.busy_job:
                raise PanelError("已有配置操作正在执行，请等待结果")
            job = self._new_job("control_recovery", actor)
            self.busy_job = job["id"]
            self.drafts.clear()

        def work():
            with self.lock:
                job.update(state="running", message="正在恢复保存配置并核对硬件", updated=self.clock())
            try:
                state = self.backend.recover_control()
                with self.lock:
                    job.update(state="done", revision=state["revision"], message="硬件已同步，控制已恢复", updated=self.clock())
                self.audit("control_recovered", actor=actor, job_id=job["id"], revision=state["revision"])
            except Exception as error:
                with self.lock:
                    job.update(state="failed", error=str(error), message="恢复未完成，控制保持锁定", updated=self.clock())
                self.audit("control_recovery_failed", actor=actor, job_id=job["id"], error=str(error))
            finally:
                self._refresh_after_write()
                with self.lock:
                    self.busy_job = None
        try:
            self.scheduler.submit(work)
        except Exception:
            with self.lock:
                self.busy_job = None
                job.update(state="failed", message="恢复操作未入队")
            raise
        return copy.deepcopy(job)

    def finish(self, job_id, action, actor):
        def work():
            job = self.job(job_id)
            if job["state"] != "awaiting_confirmation": raise PanelError("此任务不在待确认状态")
            try: result = getattr(self.backend, action)(job_id)
            except HardwareError as error: raise PanelError(str(error)) from error
            with self.lock:
                self.jobs[job_id].update(state="done" if action == "confirm" else "rolled_back",
                                        message="配置已确认" if action == "confirm" else "原配置已恢复", updated=self.clock())
                self.confirmation_deadlines.pop(job_id, None)
            self.audit(action, job_id=job_id, actor=actor)
            self._refresh_after_write()
            return result
        return self.scheduler.call(work)

    def operation(self, kind, function, actor):
        job = self._new_job(kind, actor)
        def work():
            with self.lock: job.update(state="running", updated=self.clock())
            try:
                result = function()
                with self.lock: job.update(state="done", result=result, message="操作完成", updated=self.clock())
                self.audit(kind, actor=actor, job_id=job["id"])
                self.last_sensor_sample = 0
                self._refresh_after_write()
            except Exception as error:
                with self.lock: job.update(state="failed", error=str(error), message="操作失败", updated=self.clock())
        try:
            self.scheduler.submit(work)
        except Exception as error:
            with self.lock:
                job.update(state="failed", error=str(error), message="操作未入队", updated=self.clock())
            raise
        return copy.deepcopy(job)

    def telemetry(self):
        with self.lock:
            result = copy.deepcopy({**self.cache, "mode": self.mode, "error": self.last_error,
                                    "audit_error": self.audit_error,
                                    "queue_depth": self.scheduler.queue.qsize(), "hardware_verified": False})
        now = self.clock()
        result.update(server_time=now, port_sample_interval_seconds=PORT_SAMPLE_INTERVAL_SECONDS,
                      port_stale_after_seconds=PORT_STALE_AFTER_SECONDS)
        for port in result["ports"]:
            if not 0 <= now - port.get("sampled_at", 0) <= PORT_STALE_AFTER_SECONDS:
                port["quality"] = "stale"
        sensor = result["sensors"]
        if sensor.get("sampled_at") and not 0 <= now - sensor["sampled_at"] <= 15:
            sensor["quality"] = "stale"
        for measurement in sensor.get("temperatures", []):
            sampled_at = measurement.get("sampled_at", sensor.get("sampled_at"))
            if sampled_at and not 0 <= now - sampled_at <= 15:
                measurement["quality"] = "stale"
        for module in result.get("optics", []):
            power_at = module.get("rx_power_sampled_at")
            if power_at and not 0 <= now - power_at <= 15 and module.get("rx_power_quality") == "valid":
                module["rx_power_quality"] = "stale"
            if module.get("sampled_at") and not 0 <= now - module["sampled_at"] <= 15:
                module["quality"] = "stale"
        fan = sensor.get("fan", {})
        if fan.get("sampled_at") and not 0 <= now - fan["sampled_at"] <= 15:
            fan["quality"] = "stale"
        if fan.get("pwm_sampled_at") and not 0 <= now - fan["pwm_sampled_at"] <= 15:
            fan["pwm_quality"] = "stale"
        return result

    def _collect_optics(self, epl):
        result = diagnostic_shell(epl)
        try:
            snapshot = self._read_config()
            configuration = SwitchConfiguration.model_validate(snapshot["configuration"])
            group = next(group for group in configuration.groups if group.epl == epl)
            result = diagnostic_shell(epl, group.mode, configuration.profile, snapshot["revision"])
            result["phy"] = self.backend.optical_diagnostics(group)
        except PhyModeChanged as error:
            result["phy"].update(reason="mode_changed", error=str(error))
        except Exception as error:
            with self.lock:
                previous = self._optics_cache.get(epl)
                if previous and previous.get("revision") == self._optics_revision and previous["phy"].get("lanes"):
                    result = copy.deepcopy(previous)
                    result["phy"]["quality"] = "stale"
                else:
                    result["phy"]["quality"] = "unavailable"
            result["phy"]["error"] = str(error)
        finally:
            with self.lock:
                self._optics_cache[epl] = result
                self._optics_due[epl] = self.monotonic() + PHY_REFRESH_SECONDS
                self._optics_inflight.discard(epl)

    def port_optics(self, port):
        if type(port) is not int or not 1 <= port <= 24:
            raise PanelError("端口必须在 1–24 范围内", 422, "invalid_port")
        epl = tuple(PHYSICAL)[(port - 1) // 4]
        with self.lock:
            cached = self._optics_cache.get(epl)
            unsupported = cached and cached["phy"]["quality"] == "unsupported"
            if not unsupported and epl not in self._optics_inflight and self.monotonic() >= self._optics_due.get(epl, 0):
                try:
                    future = self.scheduler.submit(lambda: self._collect_optics(epl), priority=20, key=f"optics-{epl}")
                    if future is not None:
                        self._optics_inflight.add(epl)
                except PanelError as error:
                    cached = copy.deepcopy(cached) if cached else diagnostic_shell(epl)
                    cached["phy"].update(quality="stale" if cached["phy"].get("lanes") else "unavailable", error=str(error))
                    self._optics_cache[epl] = cached
                    self._optics_due[epl] = self.monotonic() + PHY_REFRESH_SECONDS
            result = copy.deepcopy(self._optics_cache.get(epl) or diagnostic_shell(epl))
            result.update(port=port, refreshing=epl in self._optics_inflight, server_time=self.clock())
            module = next((m for m in self.cache.get("optics", []) if m.get("mpo") == PHYSICAL[epl]["mpo"]), None)
            result["power"] = power_for_epl(module, epl, result["server_time"])
            result["capabilities"]["rx_power"] = "cxp_average" if result["power"]["channels"] else result["power"]["quality"]
            result["capabilities"]["tx_power"] = result["power"]["tx_quality"]
        sampled = result["phy"].get("sampled_at")
        if sampled is not None and not 0 <= result["server_time"] - sampled <= PHY_STALE_SECONDS and result["phy"]["quality"] in {"valid", "partial", "simulated"}:
            result["phy"]["quality"] = "stale"
        return result

    def start_eye(self, port, request, actor):
        from .eye import merge_chunk
        if type(port) is not int or not 1 <= port <= 24:
            raise PanelError("端口必须在 1–24 范围内", 422, "invalid_port")
        def start():
            if self.busy_job: raise PanelError("配置正在变更，请稍后采集眼图")
            snapshot = self._read_config()
            configuration = SwitchConfiguration.model_validate(snapshot["configuration"])
            group = next(g for g in configuration.groups if g.epl == tuple(PHYSICAL)[(port-1)//4])
            base = PHYSICAL[group.epl]["base"]
            actual = base + request.lane if group.mode == "split" else base
            if group.mode == "split" and actual != port:
                raise PanelError("拆分口与 Lane 不匹配", 422, "port_lane_mismatch")
            if not configuration.ports[actual].enabled:
                raise PanelError("请先启用当前端口再采集眼图", 409, "port_disabled")
            chunk = self.backend.eye_start(actual, request)
            value = merge_chunk(self._eye_cache.get(chunk["id"]), chunk)
            value.update(profile=configuration.profile, revision=snapshot["revision"], mode=group.mode)
            self._eye_cache[value["id"]] = value
            self.audit("eye_scan_started", actor=actor, port=actual, lane=request.lane, job_id=value["id"])
            return copy.deepcopy(value)
        return self.scheduler.call(start)

    def read_eye(self, job_id=None):
        from .eye import merge_chunk, ACTIVE
        import re
        if job_id is not None and not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise PanelError("眼图任务编号无效", 422, "invalid_eye_id")
        def read():
            saved = self._eye_cache.get(job_id)
            if saved and saved.get("state") not in ACTIVE and len(saved.get("errors", [])) == saved.get("columns_done"):
                return copy.deepcopy(saved)
            chunk = self.backend.eye_read(job_id, 0)
            if chunk["state"] == "idle": return chunk
            identity = chunk["id"]
            value = merge_chunk(self._eye_cache.get(identity), chunk)
            for _ in range(3):
                if len(value["errors"]) >= value["columns_done"]: break
                value = merge_chunk(value, self.backend.eye_read(identity, len(value["errors"])))
            self._eye_cache[identity] = value
            # Bounded process cache; the latest native job survives a Web restart.
            while len(self._eye_cache) > 8:
                self._eye_cache.pop(next(iter(self._eye_cache)))
            return copy.deepcopy(value)
        return self.scheduler.call(read)

    def cancel_eye(self, job_id, actor):
        from .eye import merge_chunk
        import re
        if not re.fullmatch(r"[0-9a-f]{32}", job_id):
            raise PanelError("眼图任务编号无效", 422, "invalid_eye_id")
        def cancel():
            chunk = self.backend.eye_cancel(job_id)
            value = merge_chunk(self._eye_cache.get(job_id), chunk)
            self._eye_cache[job_id] = value
            self.audit("eye_scan_cancelled", actor=actor, job_id=job_id)
            return copy.deepcopy(value)
        return self.scheduler.call(cancel)

    def backup(self):
        state = self.config()
        content = {"format": "fm10k-controlpanel-backup", "version": 1,
                   "configuration": state["configuration"]}
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        return {**content, "sha256": hashlib.sha256(canonical).hexdigest()}

    def restore_preview(self, envelope):
        if not isinstance(envelope, dict) or set(envelope) != {"format", "version", "configuration", "sha256"}:
            raise PanelError("备份格式无效", 400)
        content = {key: value for key, value in envelope.items() if key != "sha256"}
        if content["format"] != "fm10k-controlpanel-backup" or content["version"] != 1:
            raise PanelError("不支持的备份版本", 400)
        digest = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if digest != envelope["sha256"]: raise PanelError("备份校验失败", 400)
        target = SwitchConfiguration.model_validate(content["configuration"])
        return self.preview(Proposal(expected_revision=self.config()["revision"], configuration=target))

    def close(self):
        self.stop_event.set()
        if self.monitor: self.monitor.join(timeout=2)
        self.scheduler.close(self.backend.close)
