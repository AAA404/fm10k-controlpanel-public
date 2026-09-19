#!/usr/bin/env python3
"""Board-only RDMA extension acceptance through authenticated owner RPC.

Requires all 24 external slots Down. Saves and restores the entry configuration;
does not generate traffic or claim endpoint, ECN, PFC-wire or performance tests.
Run on the target board after installing the paired native and Web build.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ["PANEL_NETLAB_ROOT"] = "/opt/fm10k-controlpanel/native/vendor/netlab"
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab import NetlabBackend


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--restart-native", action="store_true")
    args = parser.parse_args()
    if os.geteuid(): raise SystemExit("run as root on the board")
    b = NetlabBackend()
    entry = b.snapshot()
    if entry["pending"] or not entry["hardware_write_ready"]:
        raise SystemExit("synchronized control with no pending transaction is required")
    ports = b.ports()
    if len(ports) != 24 or any(p["link"] != "down" or p["state_quality"] != "valid" for p in ports):
        raise SystemExit("all 24 external slots must have a valid Down readback")
    base = SwitchConfiguration.model_validate(entry["configuration"])
    if not {13, 17} <= set(base.active_ports()) or 10 not in {v.id for v in base.vlans}:
        raise SystemExit("this fixture requires active P13/P17 slots and existing VLAN 10")
    args.evidence.mkdir(parents=True, exist_ok=True)
    report = {"started_at": time.time(), "before": entry, "checks": [], "traffic_validation": "not-run",
              "endpoint_connected": False, "clock_source": "board", "restored": False}
    path = args.evidence / "rdma-extension-acceptance.json"

    def save():
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    def ready(timeout=180, allow_pending=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                current = b.snapshot()
                if current["hardware_write_ready"] and (allow_pending or not current["pending"]): return current
            except Exception as e:
                report.setdefault("read_retries", []).append(str(e))
            time.sleep(2)
        raise RuntimeError("control did not return to synchronized state")

    def apply(configuration, confirm=True):
        configuration = SwitchConfiguration.model_validate(configuration.model_dump())
        current = ready()
        b.validate(configuration)
        job = uuid.uuid4().hex
        b.apply(configuration, current["revision"], job, 30 if not confirm else 120)
        if confirm: b.confirm(job)
        return job

    def check(name, expected):
        current = ready()
        status = b.operational("roce")
        assert current["configuration"] == expected.model_dump(mode="json"), name
        assert status["configuration_applied"] and status["buffer_ready"], (name, status)
        assert status["traffic_validation"] == "not-run" and not status["diagnostics"]["automatic_recovery"]
        enabled = expected.qos.roce.enabled and expected.qos.roce.classification == "dscp"
        expected_map = [0] * 64
        if enabled:
            expected_map[expected.qos.roce.dscp], expected_map[expected.qos.roce.cnp_dscp] = 3, 6
        assert status["dscp_map"] == expected_map
        assert status["dcbx"]["configuration_matches"]
        if enabled:
            assert status["cnp_queue"]["traffic_class"] == 7 and not status["cnp_queue"]["pfc"]
            assert len(status["dcbx"]["ports"]) == 2
            assert all(p["state"] == "link-down" and p["tx_frames"] == 0 for p in status["dcbx"]["ports"])
            for p in status["ports"]:
                if p["port"] not in (13, 17): continue
                assert p["rx_class_mask"] == p["tx_class_mask"] == 8
                assert p["pause"]["quality"] == "valid" and p["pause"]["rx_quanta"] == [0] * 8
                assert p["cnp_usage_bytes"] is not None
        elif not expected.qos.roce.enabled:
            assert status["dcbx"]["ports"] == [] and status["dcbx"]["mode"] == "off"
        report["checks"].append({"name": name, "revision": current["revision"], "passed": True, "operational": status})
        save()
        print(f"PASS {name}: r{current['revision']}", flush=True)

    save()
    failed = None
    try:
        check("entry-configuration", base)
        raw = copy.deepcopy(entry["configuration"])
        raw["lldp"]["enabled"] = True
        raw["qos"].update(trust="none", default_priority=0, priority_map=[0,1,2,3,4,5,7,6])
        raw["qos"]["roce"].update(enabled=True, ports=[13,17], classification="dscp", dscp=26, cnp_dscp=48, dcbx="ieee")
        for port in (13, 17):
            raw["ports"][str(port)].update(enabled=True, lldp=True, ingress_kbps=0, egress_kbps=0, mtu=1518)
        raw["ports"]["13"].update(vlan_mode="trunk", pvid=None, tagged_vlans=[10])
        raw["ports"]["17"].update(vlan_mode="access", pvid=10, tagged_vlans=[])
        active = SwitchConfiguration.model_validate(raw)
        apply(active); check("DSCP-CNP-ETS-DCBX-mixed-VLAN", active)
        active.qos.roce.dscp = 28
        apply(active); check("DSCP-change-clears-old-classifier", active)
        disabled = active.model_copy(deep=True); disabled.qos.roce.enabled = False
        apply(disabled, confirm=False)
        ready(timeout=90)
        check("confirmation-timeout-restores-policy", active)
        b.recover_control(); check("owner-recovery-replays-policy", active)
        if args.restart_native:
            current_ports = b.ports()
            if any(p["link"] != "down" or p["state_quality"] != "valid" for p in current_ports):
                raise RuntimeError("a link changed state before native restart")
            old = subprocess.check_output(["systemctl", "show", "fm10k-switchd.service", "-p", "InvocationID", "--value"], text=True).strip()
            b.close()
            subprocess.run(["systemctl", "restart", "fm10k-switch.target"], check=True, timeout=180)
            ready()
            new = subprocess.check_output(["systemctl", "show", "fm10k-switchd.service", "-p", "InvocationID", "--value"], text=True).strip()
            assert old and new and old != new
            report["native_restart"] = {"before": old, "after": new}
            check("SDK-restart-replays-DSCP-DCBX", active)
        apply(disabled); check("disable-clears-DSCP-PFC-DCBX", disabled)
    except Exception as error:
        failed = error
        report["error"] = str(error)
    finally:
        try:
            current = ready(allow_pending=True)
            if current["pending"]: b.rollback(current["pending"]["job_id"])
            if ready()["configuration"] != base.model_dump(mode="json"): apply(base)
            check("restored-entry-configuration", base)
            report["restored"] = True
        except Exception as error:
            report["restore_error"] = str(error)
            failed = failed or error
        report["finished_at"] = time.time()
        report["passed"] = failed is None and report["restored"]
        save(); b.close()
    if failed: raise RuntimeError(report.get("error") or report.get("restore_error")) from failed


if __name__ == "__main__":
    main()
