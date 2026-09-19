#!/usr/bin/env python3
"""Board-only PFC configuration/recovery acceptance, through the owner RPC.

Does not generate packets. Restores the entry configuration on completion or
failure; never reports RDMA traffic as tested. Run on the target board.
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

sys.path.insert(0, "/usr/lib/fm10k-controlpanel/python")
os.environ["PANEL_NETLAB_ROOT"] = "/opt/fm10k-controlpanel/native/vendor/netlab"
from fm10k_controlpanel.board import HardwareError
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab import NetlabBackend
from fm10k_controlpanel.netlab_codec import parse_xml


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--restart-native", action="store_true",
                        help="also restart the complete native service target while PFC is enabled")
    args = parser.parse_args()
    if os.geteuid(): raise SystemExit("run as root on the board")
    args.evidence.mkdir(parents=True, exist_ok=True)
    b = NetlabBackend()
    before = b.snapshot()
    if before["pending"] or not before["hardware_write_ready"]:
        raise SystemExit("board must be synchronized without a pending transaction")
    ports = b.ports()
    if len(ports) != 24 or any(p["link"] != "down" or p["state_quality"] != "valid" for p in ports):
        raise SystemExit("board-only acceptance requires verified Down state for all 24 external slots")
    base = SwitchConfiguration.model_validate(before["configuration"])
    report = {"started_at": time.time(), "before": before, "checks": [],
              "traffic_validation": "not-run", "reason": "test host powered off by user"}

    def save():
        (args.evidence / "board-acceptance.json").write_text(json.dumps(report, indent=2))

    def wait_ready(name, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                state = b.snapshot()
                if state["hardware_write_ready"] and not state["pending"]:
                    return state
            except HardwareError as error:
                report.setdefault("restart_read_retries", []).append({"check": name, "error": str(error)})
            time.sleep(2)
        raise RuntimeError(f"{name}: control did not resume synchronized state")

    def apply(config, confirm=True, timeout=120):
        config = SwitchConfiguration.model_validate(config.model_dump())
        current = b.snapshot()
        b.validate(config)
        job = uuid.uuid4().hex
        state = b.apply(config, current["revision"], job, timeout)
        if confirm: state = b.confirm(job)
        return state

    def check(name, expected):
        state = b.snapshot()
        status = b.operational("roce")
        assert state["configuration"] == expected.model_dump(mode="json"), name
        assert state["synchronized"] and not state["pending"], name
        assert status["configuration_applied"] and status["buffer_ready"], name
        assert status["traffic_validation"] == "not-run", name
        if expected.qos.roce.enabled:
            for port in (13, 17):
                actual = next(p for p in status["ports"] if p["port"] == port)
                assert actual["rx_class_mask"] == actual["tx_class_mask"] == 8
                wm = next(p for p in status["watermarks"] if p["port"] == port)
                partition = next(p for p in wm["partitions"] if p["id"] == "1")
                assert 0 < int(partition["private-pause-off-wm"]) < int(partition["private-pause-on-wm"])
            assert status["tc_smp_map"] == ["smp-1" if tc == 3 else "smp-0" for tc in range(8)]
        report["checks"].append({"name": name, "passed": True, "revision": state["revision"], "operational": status})
        save()
        print(f"PASS {name}: revision={state['revision']}", flush=True)

    save()
    try:
        check("initialized-disabled-baseline", base)
        data = copy.deepcopy(before["configuration"])
        for group in data["groups"]:
            if group["epl"] in (5, 6): group["mode"] = "40g"
        if 10 not in {v["id"] for v in data["vlans"]}:
            raise RuntimeError("expected the existing test VLAN10")
        for port in (13, 17):
            data["ports"][str(port)].update(enabled=True, mtu=1518, vlan_mode="trunk", pvid=None,
                                           tagged_vlans=[10], ingress_kbps=0)
        data["qos"].update(trust="none", default_priority=0, priority_map=list(range(8)))
        data["qos"]["roce"].update(enabled=True, ports=[13, 17], priority=3)
        small = SwitchConfiguration.model_validate(data)
        apply(small)
        check("40G-PFC-small-MTU", small)
        jumbo = small.model_copy(deep=True)
        for port in (13, 17): jumbo.ports[port].mtu = 9018
        apply(jumbo)
        check("40G-PFC-jumbo-MTU", jumbo)
        raw_ports = parse_xml(b._rpc(7, 120, b"counters=0"))
        actual_ports = {int(p.get("id")): dict(p.attrib) for p in raw_ports.findall("port")}
        for port in (13, 17):
            assert actual_ports[port]["state-status"] == "0"
            assert int(actual_ports[port]["mtu"]) == 9018
            assert int(actual_ports[port]["max-frame"]) == 9040
        report["jumbo_port_readback"] = {str(p): actual_ports[p] for p in (13, 17)}
        disabled = jumbo.model_copy(deep=True)
        disabled.qos.roce.enabled = False
        pending = apply(disabled, confirm=False, timeout=30)
        assert pending["pending"]
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            time.sleep(2)
            try:
                state = b.snapshot()
            except HardwareError as error:
                # configd may temporarily close its read socket while its
                # confirmation timer applies the rollback. Keep a deadline
                # and preserve every transient error in the evidence.
                report.setdefault("rollback_read_retries", []).append(str(error))
                continue
            if not state["pending"]:
                break
        else: raise RuntimeError("confirmation timeout did not restore the prior configuration")
        check("automatic-timeout-rollback", jumbo)
        b.recover_control()
        check("explicit-control-recovery", jumbo)
        b.close()
        subprocess.run(["systemctl", "restart", "fm10k-configd.service"], check=True, timeout=90)
        wait_ready("configd-restart")
        check("configd-restart-with-PFC", jumbo)
        if args.restart_native:
            def invocation():
                return subprocess.check_output(
                    ["systemctl", "show", "fm10k-switchd.service", "-p", "InvocationID", "--value"],
                    text=True, timeout=10).strip()

            previous = invocation()
            assert previous, "switchd invocation missing before restart"
            b.close()
            subprocess.run(["systemctl", "restart", "fm10k-switch.target"], check=True, timeout=90)
            wait_ready("native-restart", timeout=180)
            current = invocation()
            assert current and current != previous, "switchd was not restarted"
            report["native_restart"] = {"before_invocation": previous, "after_invocation": current}
            check("native-restart-with-PFC", jumbo)
        apply(disabled)
        check("explicit-PFC-disable", disabled)
        report["passed"] = True
    except Exception as error:
        report.update(passed=False, error=str(error))
        raise
    finally:
        try:
            current = b.snapshot()
            if current["pending"]:
                b.rollback(current["pending"]["job_id"])
            if not b.snapshot()["hardware_write_ready"]:
                b.recover_control()
            if b.snapshot()["configuration"] != base.model_dump(mode="json"):
                apply(base)
            check("entry-configuration-restored", base)
            report["restored"] = True
        except Exception as recovery_error:
            report.update(restored=False, recovery_error=str(recovery_error))
            raise
        finally:
            report["finished_at"] = time.time()
            save()
            b.close()


if __name__ == "__main__":
    main()
