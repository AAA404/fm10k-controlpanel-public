#!/usr/bin/env python3
"""Collect board evidence through the running Switch Stack's sole SDK owner.

Diagnostic use before native takeover. No standalone TestPoint/SDK process is
started. The default survey only writes mux/page selectors, with verified
restoration. An optional 1..5 second fan diagnostic raises PWM to full and
restores the previous mode; it never edits the LUT or lowers the initial PWM.
Port, laser, service and network configuration are not modified. A completed
survey is not a forwarding or native-HAL qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid

SERVICE = "pe31625g24dira-switch.service"
RUNTIME = Path("/run/pe31625g24dira-testpoint")
CONFIG_FILES = (
    "/etc/pe31625g24dira/webui/ports.json",
    "/etc/pe31625g24dira/webui/vlans.json",
    "/etc/pe31625g24dira/webui/fan.json",
    "/etc/pe31625g24dira/webui/l2.json",
    "/etc/pe31625g24dira/pe31625g24dira-switch.tp",
    "/etc/pe31625g24dira/pe31625g24dira-fan-init.tp",
    "/usr/share/netfab/fm_platform_attributes.cfg",
    "/opt/pe31625g24dira-switch-manager/reference_original_6x100.cfg",
    "/opt/pe31625g24dira-switch-manager/VERSION",
)


def fan_diagnostic_script(seconds: int) -> str:
    if type(seconds) is not int or not 0 <= seconds <= 5:
        raise ValueError("fan diagnostic duration must be within 0..5 seconds")
    if not seconds:
        return ""
    return r'''
    # Only the known 22.5 kHz high-resolution four-wire fan configuration.
    die "survey fan identity mismatch\n" unless
        $read->('fan.test.manufacturer', 0x4c, 0xfe, 1)->[0] == 1 &&
        $read->('fan.test.revision', 0x4c, 0xff, 1)->[0] == 0x49;
    my $fan_mode = $read->('fan.test.mode.before', 0x4c, 0x4a, 1)->[0];
    my $fan_pwm = $read->('fan.test.pwm.before', 0x4c, 0x4c, 1)->[0];
    die "survey fan configuration mismatch\n" unless
        ($fan_mode == 0x10 || $fan_mode == 0x30) &&
        $read->('fan.test.frequency', 0x4c, 0x4d, 1)->[0] == 8 &&
        ($read->('fan.test.enhanced', 0x4c, 0x45, 1)->[0] & 0x10) &&
        !($read->('fan.test.configuration', 0x4c, 0x03, 1)->[0] & 0x40);
    my $write_fan = sub {
        my ($label, $register, $value) = @_;
        die "survey fan register refused\n" if $register != 0x4a && $register != 0x4c;
        my $status = $chip->fmI2cWriteRead(0, 0x4c, [$register, $value], 2, 0);
        my $actual = $read->($label, 0x4c, $register, 1)->[0];
        die "survey fan write mismatch: $label\n" if $status != 0 || $actual != $value;
    };
    my $fan_error;
    eval {
        $write_fan->('fan.test.mode.full', 0x4a, 0x30);
        $write_fan->('fan.test.pwm.full', 0x4c, 255);
        for my $sample (1 .. FAN_TEST_SECONDS) {
            select(undef, undef, undef, 1.0);
            $read->("fan.test.$sample.tach.low", 0x4c, 0x46, 1);
            $read->("fan.test.$sample.tach.high", 0x4c, 0x47, 1);
            $read->("fan.test.$sample.cpld.low", 0x59, 0xa3, 1);
            $read->("fan.test.$sample.cpld.high", 0x59, 0xa4, 1);
            $read->("fan.test.$sample.pwm", 0x4c, 0x4c, 1);
        }
    };
    $fan_error = $@;
    eval {
        # An automatic curve owns its current duty; restore only its mode.
        $write_fan->('fan.test.pwm.restored', 0x4c, $fan_pwm) if $fan_mode & 0x20;
        $write_fan->('fan.test.mode.restored', 0x4a, $fan_mode);
        $read->('fan.test.pwm.after', 0x4c, 0x4c, 1);
    };
    my $fan_restore_error = $@;
    if ($fan_restore_error) {
        eval {
            $write_fan->('fan.test.mode.failsafe', 0x4a, 0x30);
            $write_fan->('fan.test.pwm.failsafe', 0x4c, 255);
        };
        die "survey fan restore failed; full-speed recovery attempted: $fan_restore_error $@\n";
    }
    die $fan_error if $fan_error;
    print "FM10K_SURVEY_FAN_TEST_RESTORED\n";
'''.replace("FAN_TEST_SECONDS", str(seconds))


def survey_script(marker: str, fan_test_seconds: int = 0) -> str:
    # The TestPoint expert API is the same one used by the installed sensors.tp.
    if not re.fullmatch(r"FM10K_SURVEY_[0-9a-f]{32}", marker):
        raise ValueError("invalid completion marker")
    fan_script = fan_diagnostic_script(fan_test_seconds)
    return r'''# expert
my $chip = $self->{FT}->{CHIP};
my $read = sub {
    my ($label, $addr, $offset, $length) = @_;
    my $bytes = [(0) x $length];
    $bytes->[0] = $offset if $offset >= 0;
    my $status = $chip->fmI2cWriteRead(0, $addr, $bytes, $offset < 0 ? 0 : 1, $length);
    printf("FM10K_SURVEY_READ label=%s addr=%02x offset=%d status=%d data=%s\n",
           $label, $addr, $offset, $status, join('', map { sprintf('%02x', $_) } @$bytes));
    die "survey read failed: $label status=$status\n" if $status != 0;
    return $bytes;
};
my $write_selector = sub {
    my ($label, $addr, $offset, $value) = @_;
    my $bytes = $offset < 0 ? [$value] : [$offset, $value];
    my $status = $chip->fmI2cWriteRead(0, $addr, $bytes, $offset < 0 ? 1 : 2, 0);
    select(undef, undef, undef, 0.035) if $offset == 0x7f;
    my $actual = $read->($label, $addr, $offset, 1)->[0];
    $actual &= 15 if $addr == 0x58;
    die "survey selector failed: $label status=$status actual=$actual wanted=$value\n"
        if $status != 0 || $actual != $value;
};
my $mux = $read->('mux.before', 0x58, -1, 1)->[0] & 15;
my $error;
eval {
    tp("show port 1..24");
    tp("show sensors switch");
    $read->('cpld.tach.low', 0x59, 0xa3, 1);
    $read->('cpld.tach.high', 0x59, 0xa4, 1);
    $write_selector->('mux.lm96163', 0x58, -1, 8);
    for my $reg (0x00, 0x01, 0x10, 0x03, 0x04, 0x19, 0x21, 0x30, 0x33, 0x45 .. 0x4f, 0x50 .. 0x67, 0xfe, 0xff) {
        $read->(sprintf('lm96163.%02x', $reg), 0x4c, $reg, 1);
    }
''' + fan_script + r'''
    for my $mpo (1, 2) {
        $write_selector->("mux.mpo$mpo", 0x58, -1, $mpo);
        $read->("mpo$mpo.temperature", 0x50, 0x16, 2);
        $read->("mpo$mpo.tx", 0x50, 56, 2);
        my $page = $read->("mpo$mpo.page.before", 0x50, 0x7f, 1)->[0];
        my $page_error;
        eval {
            $write_selector->("mpo$mpo.page.zero", 0x50, 0x7f, 0) if $page;
            for (my $offset = 128; $offset < 224; $offset += 12) {
                $read->("mpo$mpo.identity.$offset", 0x50, $offset, 12);
            }
        };
        $page_error = $@;
        eval { $write_selector->("mpo$mpo.page.restored", 0x50, 0x7f, $page) if $page; };
        $page_error .= $@;
        my $actual = $read->("mpo$mpo.page.after", 0x50, 0x7f, 1)->[0];
        die "survey page restore mismatch\n" if $actual != $page;
        die $page_error if $page_error;
    }
};
$error = $@;
eval { $write_selector->('mux.restored', 0x58, -1, $mux); };
$error .= $@;
die $error if $error;
print "''' + marker + r'''_DONE\n";
'''


def run(command: list[str], timeout=15) -> str:
    return subprocess.check_output(command, text=True, errors="replace", timeout=timeout)


def collect(output: Path, timeout: int, fan_test_seconds: int = 0) -> dict:
    fan_diagnostic_script(fan_test_seconds)  # validate before touching the board
    if os.geteuid() != 0:
        raise RuntimeError("run as root on the board, through the existing remote session")
    if run(["systemctl", "is-active", SERVICE]).strip() != "active":
        raise RuntimeError("existing Switch Stack service is not active; no SDK process will be started")
    fifo = RUNTIME / "control"
    metadata = fifo.lstat()
    if not stat.S_ISFIFO(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError("the existing control FIFO is not root-owned and private")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {"schema": 1, "source": "existing-switch-stack", "hardware_access": True,
              "native_hal_validation": False, "started_at": time.time(),
              "configuration_written": bool(fan_test_seconds), "persistent_configuration_written": False,
              "fan_full_test_seconds": fan_test_seconds,
              "selector_writes": "mux/page with verified restore",
              "status": "running", "files": {}}

    def save(name, data):
        path = output / name
        path.write_bytes(data)
        path.chmod(0o600)
        report["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

    marker = "FM10K_SURVEY_" + uuid.uuid4().hex
    path = None
    try:
        for source in CONFIG_FILES:
            save(source.lstrip("/").replace("/", "__"), Path(source).read_bytes())
        save("vpd.bin", Path("/sys/bus/pci/devices/0000:01:00.0/vpd").read_bytes())
        save("service.txt", run(["systemctl", "show", SERVICE, "-p", "MainPID", "-p", "ExecMainStartTimestamp", "-p", "ActiveState"]).encode())
        cursor_text = run(["journalctl", "-u", SERVICE, "-n", "1", "--show-cursor", "--no-pager", "-o", "cat"])
        cursor = re.search(r"^-- cursor: (.+)$", cursor_text, re.M)
        if not cursor:
            raise RuntimeError("journal cursor unavailable")
        script = survey_script(marker, fan_test_seconds).encode()
        save("survey.tp", script)
        descriptor, path = tempfile.mkstemp(prefix="fm10k-survey-", suffix=".tp", dir=RUNTIME)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(script)
        # One atomic FIFO command: the existing owner serializes entire scripts
        # with periodic sampling. Never start another TestPoint or SDK client.
        descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        command = f"load {path}\n".encode()
        try:
            if os.write(descriptor, command) != len(command):
                raise RuntimeError("incomplete FIFO submission")
        finally:
            os.close(descriptor)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            log = run(["journalctl", "-u", SERVICE, "--after-cursor", cursor[1], "--no-pager", "-o", "cat"])
            start = log.find(f"Loading {path}")
            relevant = log[start:] if start >= 0 else ""
            save("survey.log", relevant.encode())
            if marker + "_DONE" in relevant:
                relevant = relevant.split(marker + "_DONE", 1)[0] + marker + "_DONE\n"
                save("survey.log", relevant.encode())
                report["status"] = "collected"
                break
            if any(value in relevant for value in ("syntax error", "survey read failed", "survey selector failed",
                                                  "survey page restore mismatch", "survey fan", "ERROR:")):
                raise RuntimeError("diagnostic execution failed; see survey.log")
            time.sleep(0.5)
        else:
            raise RuntimeError("existing owner did not confirm survey; no retry or service restart attempted")
    except Exception as error:
        report["status"], report["error"] = "failed", str(error)
    finally:
        if path and report["status"] == "collected":
            Path(path).unlink(missing_ok=True)
        elif path:
            report["pending_script"] = path
        report["completed_at"] = time.time()
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        (output / "report.json").chmod(0o600)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new private evidence directory")
    parser.add_argument("--timeout", type=int, default=40)
    parser.add_argument("--fan-full-seconds", type=int, choices=range(6), default=0,
                        help="optional 1..5 second full-speed diagnostic, with previous fan mode restored")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 50:
        parser.error("timeout must be within 1..50 seconds")
    result = collect(args.output.resolve(), args.timeout, args.fan_full_seconds)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "collected" else 1


if __name__ == "__main__":
    raise SystemExit(main())
