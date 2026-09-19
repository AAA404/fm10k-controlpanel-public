#!/usr/bin/env python3
"""Verify a confirmation window across configd restart, without changing time.

Run on an idle board after installing the paired native and Web release.
Temporarily changes the LLDP interval, waits for automatic rollback, and checks
that the entry configuration is restored. Does not restart switchd or send data.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["PANEL_NETLAB_ROOT"] = "/opt/fm10k-controlpanel/native/vendor/netlab"
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab import NetlabBackend
from fm10k_controlpanel.service import PanelService


def invocation(unit):
    return subprocess.check_output(["systemctl", "show", unit, "-p", "InvocationID", "--value"], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid(): raise SystemExit("run as root on the board")
    b = NetlabBackend()
    entry = b.snapshot()
    if entry["pending"] or not entry["hardware_write_ready"]:
        raise SystemExit("synchronized control with no pending transaction is required")
    ports = b.ports()
    if len(ports) != 24 or any(p["link"] != "down" or p["state_quality"] != "valid" for p in ports):
        raise SystemExit("all 24 data ports must be confirmed Down")
    if b.eye_read().get("state") in {"running", "queued", "cancelling", "restoring"}:
        raise SystemExit("finish the eye scan first")
    base = SwitchConfiguration.model_validate(entry["configuration"])
    candidate = base.model_copy(deep=True)
    candidate.lldp.transmit_interval = 31 if base.lldp.transmit_interval != 31 else 30
    candidate = SwitchConfiguration.model_validate(candidate.model_dump())
    args.evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = {"started_at": time.time(), "clock_source": "board", "before": entry,
              "system_clock_changed": False, "checks": [], "passed": False, "restored": False}
    target = args.evidence / "native-clock-acceptance.json"
    job_id = uuid.uuid4().hex
    failed = None

    def save(): target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    def ready(timeout=90, pending=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                state = b.snapshot()
                if state["hardware_write_ready"] and (pending or not state["pending"]): return state
            except Exception as error:
                report.setdefault("read_retries", []).append(str(error))
            time.sleep(1)
        raise RuntimeError("control did not return to synchronized state")

    save()
    try:
        b.validate(candidate)
        current = b.apply(candidate, entry["revision"], job_id, 60)
        pending = current["pending"]
        assert pending and pending["job_id"] == job_id and 0 < pending["remaining_seconds"] <= 60
        records = list(Path("/var/lib/fm10k-controlpanel-native/config").rglob("confirmed.json"))
        assert len(records) == 1
        record = json.loads(records[0].read_text())
        assert record["confirm_boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        assert 0 < record["confirm_monotonic_deadline"] - time.monotonic() <= 60
        report["checks"].append({"name": "monotonic-confirmation-record", "passed": True,
                                 "revision": current["revision"], "remaining_seconds": pending["remaining_seconds"]})
        old = invocation("fm10k-configd.service")
        sdk = invocation("fm10k-switchd.service")
        b.close()
        subprocess.run(["systemctl", "restart", "fm10k-configd.service"], check=True, timeout=90)
        current = ready(pending=True)
        assert invocation("fm10k-configd.service") not in {"", old}
        assert invocation("fm10k-switchd.service") == sdk
        assert current["pending"] and current["pending"]["job_id"] == job_id
        assert 0 < current["pending"]["remaining_seconds"] <= pending["remaining_seconds"]
        assert json.loads(records[0].read_text()) == record
        report["checks"].append({"name": "configd-restart-keeps-original-window", "passed": True,
                                 "remaining_seconds": current["pending"]["remaining_seconds"]})
        with tempfile.TemporaryDirectory(prefix="fm10k-clock-api-") as temporary:
            service = PanelService(b, Path(temporary))
            try:
                assert service.config()["pending"]["job_id"] == job_id
                status = service.job(job_id)
                assert 0 < status["remaining_seconds"] <= current["pending"]["remaining_seconds"]
                report["checks"].append({"name": "web-job-countdown-from-native-clock", "passed": True,
                                         "remaining_seconds": status["remaining_seconds"]})
            finally:
                service.scheduler.close()
        current = ready()
        assert current["configuration"] == entry["configuration"]
        assert invocation("fm10k-switchd.service") == sdk
        report["checks"].append({"name": "automatic-timeout-restores-entry-configuration", "passed": True,
                                 "revision": current["revision"]})
    except Exception as error:
        failed = error; report["error"] = str(error)
    finally:
        try:
            current = ready(pending=True)
            if current["pending"] and current["pending"]["job_id"] == job_id:
                b.rollback(job_id); current = ready()
            if current["configuration"] == candidate.model_dump(mode="json"):
                restore_id = uuid.uuid4().hex
                b.apply(base, current["revision"], restore_id, 60); b.confirm(restore_id); current = ready()
            assert current["configuration"] == entry["configuration"] and not current["pending"]
            operational = b.operational("roce")
            assert operational["configuration_applied"] and operational["buffer_ready"]
            ports = b.ports()
            assert len(ports) == 24 and all(p["link"] == "down" and p["state_quality"] == "valid" for p in ports)
            report.update(restored=True, after=current, operational=operational)
        except Exception as error:
            report["restore_error"] = str(error); failed = failed or error
        report.update(passed=failed is None and report["restored"], finished_at=time.time())
        save(); b.close()
    if failed: raise RuntimeError(report.get("error") or report.get("restore_error")) from failed
    print(json.dumps({"passed": True, "checks": len(report["checks"]), "revision": report["after"]["revision"],
                      "restored": True, "system_clock_changed": False}), flush=True)


if __name__ == "__main__":
    main()
