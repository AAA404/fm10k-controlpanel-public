import hashlib
import io
import json
import os
from pathlib import Path

import pytest

from fm10k_controlpanel import installation as engine
from fm10k_controlpanel.release import ReleaseError


@pytest.fixture
def upgrade_fixture(tmp_path, monkeypatch):
    paths = engine.Paths(tmp_path / "host")
    process = paths.root / f"proc/{os.getpid()}"
    process.mkdir(parents=True)
    (process / "stat").write_text(f"{os.getpid()} (fixture worker) " + " ".join(["S"] + ["0"]*18 + ["12345"]))
    boot = paths.root / "proc/sys/kernel/random"
    boot.mkdir(parents=True)
    (boot / "boot_id").write_text("synthetic-boot")
    for directory in (paths.native, paths.etc, paths.web_state, paths.native_state / "config/journal", paths.updates / "packages"):
        directory.mkdir(parents=True, exist_ok=True)
    (paths.native / "program").write_text("old native")
    (paths.etc / "native.env").write_text("old native environment")
    (paths.web_state / "accounts.json").write_text('{"account":"unchanged"}')
    (paths.web_state / "accounts.json").chmod(0o600)
    (paths.native_state / "config/journal/tx_counter").write_text("1\n")
    old_package = paths.updates / "packages/fm10k-controlpanel_0.1.0_all.deb"
    old_package.write_bytes(b"old package")
    metadata = {"schema":1,"status":"ready","version":"0.1.0","profile":"sil001-hw4-b0", "package_sha256":engine.sha256(old_package)}
    engine.save(paths.installation,metadata)
    source = tmp_path / "release"
    (source / "packages").mkdir(parents=True)
    (source / "packages/fm10k-controlpanel_0.2.0_all.deb").write_bytes(b"new package")
    configuration = {"profile":"sil001-hw4-b0","ports":{"1":{"enabled":False}}}
    snapshot = lambda:{"revision":1,"configuration":configuration,"hardware_write_ready":True,"pending":None}
    monkeypatch.setattr(engine,"verify_bundle",lambda *_:{"version":"0.2.0"})
    monkeypatch.setattr(engine,"installed_metadata",lambda p:json.loads(p.installation.read_bytes()))
    monkeypatch.setattr(engine,"upgrade_admission",lambda *_:(tmp_path / "sdk",tmp_path / "platform"))
    def stage(*_, **options):
        directory = paths.base / ".stage-test"
        directory.mkdir()
        (directory / "program").write_text("new native")
        return directory
    monkeypatch.setattr(engine,"stage_native",stage)
    commands, health_calls, progress = [], [], []
    def run(*args,**kwargs):
        commands.append(tuple(map(str,args)))
        # This fake is deliberately total: no subprocess can escape the test.
        assert args[0] in {"systemctl","dpkg"}
        return ""
    def healthy(version,profile,config):
        health_calls.append(version)
        assert config == configuration
        return snapshot()
    options = {"paths":paths,"runner":run,"read_snapshot":snapshot,"health_check":healthy,
               "progress":lambda state,message:progress.append(state)}
    return source,paths,options,commands,health_calls,progress


def test_paired_upgrade_preserves_configuration_accounts_and_recovery_package(upgrade_fixture):
    source,paths,options,commands,health_calls,_ = upgrade_fixture
    result = engine.upgrade(source,**options)
    assert (paths.native / "program").read_text() == "new native"
    assert (paths.etc / "native.env").read_text() == "old native environment"
    assert (paths.web_state / "accounts.json").read_text() == '{"account":"unchanged"}'
    assert json.loads(paths.installation.read_bytes())["version"] == "0.2.0"
    checkpoint = Path(result["checkpoint"])
    assert (checkpoint / "native/program").read_text() == "old native"
    assert (checkpoint / "rollback.deb").read_bytes() == b"old package"
    assert health_calls == ["0.2.0"]
    assert any(command[0] == "dpkg" and command[-1].endswith("0.2.0_all.deb") for command in commands)
    assert json.loads(paths.journal.read_bytes())["phase"] == "committed"


def test_health_failure_restores_whole_pair_and_revalidates_old_version(upgrade_fixture):
    source,paths,options,commands,health_calls,progress = upgrade_fixture
    old_health = options["health_check"]
    def fail_new(version,*rest):
        if version == "0.2.0": raise ReleaseError("new native health failed")
        return old_health(version,*rest)
    options["health_check"] = fail_new
    original_owner = (paths.web_state / "accounts.json").stat().st_uid
    with pytest.raises(ReleaseError,match="new native health"):
        engine.upgrade(source,**options)
    assert (paths.native / "program").read_text() == "old native"
    assert json.loads(paths.installation.read_bytes())["version"] == "0.1.0"
    assert (paths.web_state / "accounts.json").stat().st_uid == original_owner
    assert (paths.web_state / "accounts.json").stat().st_mode & 0o777 == 0o600
    assert health_calls == ["0.1.0"]
    assert progress[-2:] == ["rolling_back","rolled_back"]
    assert commands[-2][0] == "systemctl"
    assert any(command[0] == "dpkg" and command[-1].endswith("rollback.deb") for command in commands)
    transaction = json.loads(paths.journal.read_bytes())
    assert transaction["phase"] == "rolled_back"
    assert (Path(transaction["backup"]) / "native/program").exists(), "checkpoint must survive interrupted recovery"


def test_package_install_failure_also_rolls_back(upgrade_fixture):
    source,paths,options,commands,_,progress=upgrade_fixture
    original=options["runner"]
    def fail_new(*args,**kwargs):
        if args[0] == "dpkg" and str(args[-1]).endswith("0.2.0_all.deb"):
            raise ReleaseError("dpkg failed")
        return original(*args,**kwargs)
    options["runner"]=fail_new
    with pytest.raises(ReleaseError,match="dpkg failed"): engine.upgrade(source,**options)
    assert (paths.native / "program").read_text() == "old native"
    assert progress[-1] == "rolled_back"


def test_concurrent_config_commit_aborts_before_package_or_native_swap(upgrade_fixture):
    source,paths,options,commands,_,progress=upgrade_fixture
    original=options["runner"]
    def concurrent(*args,**kwargs):
        if args[:3] == ("systemctl","stop","fm10k-panel.service") and "fm10k-switch.target" in args:
            (paths.native_state / "config/journal/tx_counter").write_text("2\n")
        return original(*args,**kwargs)
    options["runner"]=concurrent
    with pytest.raises(ReleaseError,match="configuration changed"): engine.upgrade(source,**options)
    assert (paths.native / "program").read_text() == "old native"
    assert not any(command[0] == "dpkg" for command in commands)
    assert (paths.native_state / "config/journal/tx_counter").read_text() == "2\n"
    assert json.loads(paths.journal.read_bytes())["phase"] == "aborted"


def test_missing_rollback_package_never_stops_services(upgrade_fixture):
    source,paths,options,commands,_,_=upgrade_fixture
    (paths.updates / "packages/fm10k-controlpanel_0.1.0_all.deb").unlink()
    with pytest.raises(ReleaseError,match="rollback package"): engine.upgrade(source,**options)
    assert commands == []


def test_failed_rollback_is_reported_and_checkpoint_retained(upgrade_fixture):
    source,paths,options,_,_,progress=upgrade_fixture
    options["health_check"]=lambda *_:(_ for _ in ()).throw(ReleaseError("health unavailable"))
    with pytest.raises(ReleaseError,match="rollback failed"): engine.upgrade(source,**options)
    assert progress[-1] == "recovery_required"
    assert paths.journal.exists()


def test_native_units_start_only_through_single_owner_and_private_ipc(tmp_path):
    paths=engine.Paths(tmp_path)
    switch=engine.service_text("switchd",paths)
    config=engine.service_text("configd",paths)
    assert "PrivateIPC=yes" in switch and "fm10k-identityd.service" in switch
    assert "fm10k-switchd.service" in config and "PartOf=fm10k-switch.target" in config
    assert "fm10k-testpoint.service" in switch


def test_recovery_can_resume_after_interrupted_rollback(upgrade_fixture,monkeypatch):
    source,paths,options,_,_,progress=upgrade_fixture
    real_rollback=engine.rollback
    old_health=options["health_check"]
    def fail_new(version,*rest):
        if version=="0.2.0": raise ReleaseError("startup failed")
        return old_health(version,*rest)
    options["health_check"]=fail_new
    monkeypatch.setattr(engine,"rollback",lambda *_a,**_k:(_ for _ in ()).throw(ReleaseError("interrupted recovery")))
    with pytest.raises(ReleaseError,match="rollback failed"): engine.upgrade(source,**options)
    transaction=json.loads(paths.journal.read_bytes())
    assert transaction["phase"]=="switching"
    assert (paths.native / "program").read_text()=="new native"
    real_rollback(paths,transaction,runner=options["runner"],health_check=old_health)
    assert (paths.native / "program").read_text()=="old native"
    assert json.loads(paths.journal.read_bytes())["phase"]=="rolled_back"
    assert json.loads(paths.installation.read_bytes())["version"]=="0.1.0"


def test_optional_eye_firmware_is_pinned_and_copied_without_execution(tmp_path):
    stage=tmp_path / "stage"
    (stage / "hardware").mkdir(parents=True)
    source=tmp_path / "firmware.bin"
    source.write_bytes(b"synthetic firmware")
    manifest={"binary_bytes":source.stat().st_size,"binary_sha256":engine.sha256(source)}
    (stage / "hardware/eye-firmware.json").write_text(json.dumps(manifest))
    engine.copy_eye_firmware(stage,source)
    assert (stage / "hardware/eye/sbus-master-101a.bin").read_bytes()==source.read_bytes()
    source.write_bytes(b"unexpected firmware")
    with pytest.raises(ReleaseError): engine.copy_eye_firmware(stage,source)


def test_one_inactive_daemon_cannot_pass_whole_release_health(monkeypatch):
    configuration = {"profile": "sil001-hw4-b0"}
    ticks = iter([0, 0, 181])
    monkeypatch.setattr(engine.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(engine.time, "sleep", lambda _: None)
    states = ["active"] * (len(engine.SERVICES) + 1)
    states[engine.DAEMONS.index("lldpd")] = "inactive"
    with pytest.raises(ReleaseError, match="not all native and Web services"):
        engine.health("0.2.0", configuration["profile"], configuration,
                      runner=lambda *a, **k: "\n".join(states),
                      read_snapshot=lambda: {"configuration": configuration})


def test_release_health_requires_nginx_and_trusted_https(monkeypatch, tmp_path):
    configuration = {"profile": "sil001-hw5-a11"}
    expected = {"status": "ok", "mode": "netlab", "version": "0.2.0"}
    urls = []

    class Opener:
        def open(self, url, timeout):
            urls.append(url)
            return io.BytesIO(json.dumps(expected).encode())

    monkeypatch.setattr(engine.ssl, "create_default_context", lambda **_: object())
    monkeypatch.setattr(engine.urllib.request, "build_opener", lambda *_: Opener())

    def runner(*args, **_):
        if args[-1] == "nginx.service":
            return "active\n"
        return "\n".join(["active"] * (len(engine.SERVICES) + 1))

    result = engine.health("0.2.0", configuration["profile"], configuration, "192.0.2.10",
                           runner=runner, read_snapshot=lambda: {"configuration": configuration},
                           tls_cert=tmp_path / "cert")
    assert result["configuration"] == configuration
    assert urls == ["http://127.0.0.1:8080/api/v1/health", "https://192.0.2.10/api/v1/health"]

    ticks = iter([0, 0, 181])
    monkeypatch.setattr(engine.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(engine.time, "sleep", lambda _: None)
    with pytest.raises(ReleaseError, match="nginx HTTPS service is not active"):
        engine.health("0.2.0", configuration["profile"], configuration, "192.0.2.10",
                      runner=lambda *args, **_: "inactive\n" if args[-1] == "nginx.service" else runner(*args),
                      read_snapshot=lambda: {"configuration": configuration}, tls_cert=tmp_path / "cert")


def test_journal_write_failure_restarts_web_without_swapping_native(upgrade_fixture, monkeypatch):
    source, paths, options, commands, _, _ = upgrade_fixture
    original = engine.save
    def full_disk(path, value):
        if path == paths.journal:
            raise OSError("disk full")
        original(path, value)
    monkeypatch.setattr(engine, "save", full_disk)
    with pytest.raises(OSError, match="disk full"):
        engine.upgrade(source, **options)
    assert (paths.native / "program").read_text() == "old native"
    assert commands[-1] == ("systemctl", "start", "fm10k-panel.service")
    assert not any(command[0] == "dpkg" for command in commands)


def test_checkpoint_sync_failure_never_switches_native(upgrade_fixture, monkeypatch):
    source, paths, options, commands, _, _ = upgrade_fixture
    original = engine.sync_tree
    def storage_failure(path):
        if path.name == "etc":
            raise OSError("checkpoint storage failure")
        original(path)
    monkeypatch.setattr(engine, "sync_tree", storage_failure)
    with pytest.raises(OSError, match="checkpoint storage failure"):
        engine.upgrade(source, **options)
    assert (paths.native / "program").read_text() == "old native"
    assert json.loads(paths.journal.read_bytes())["phase"] == "aborted"
    assert not any(command[0] == "dpkg" for command in commands)


def test_management_url_handles_ipv6():
    assert engine.management_url("2001:db8::10") == "https://[2001:db8::10]"
    assert engine.management_url("192.0.2.10") == "https://192.0.2.10"


@pytest.mark.parametrize("profile", ["sil001-hw4-b0", "sil001-hw5-a11"])
def test_new_install_generates_closed_configuration_and_private_credentials(tmp_path, monkeypatch, profile):
    from dataclasses import replace
    import grp
    from types import SimpleNamespace
    from platform_fixture import reference_text
    from fm10k_controlpanel.netlab_codec import decode_configuration
    paths = engine.Paths(tmp_path / "host")
    reference = paths.native / "hardware/sdk/platform.cfg"
    reference.parent.mkdir(parents=True)
    reference.write_text(reference_text(profile))
    monkeypatch.setitem(engine.PROFILES, profile, replace(engine.PROFILES[profile],
                        reference="hardware/sdk/platform.cfg", sha256=engine.sha256(reference)))
    template = paths.native / "deploy/nginx/fm10k-controlpanel.conf.in"
    template.parent.mkdir(parents=True)
    template.write_bytes((Path(__file__).resolve().parents[1] / "deploy/nginx/fm10k-controlpanel.conf.in").read_bytes())
    netdev = paths.root / f"sys/bus/pci/devices/{engine.BDF}/net/asic0"
    netdev.mkdir(parents=True)
    (netdev / "address").write_text("02:10:84:00:00:01\n")
    (paths.root / "etc/nginx/sites-enabled").mkdir(parents=True)
    monkeypatch.setattr(engine, "inventory", lambda **_: {
        "preflight_passed": True, "profile": profile,
        "devices": [{"bdf": engine.BDF, "identity": {"serial": "S000000000000"}}]})
    monkeypatch.setattr(grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    monkeypatch.setattr(engine.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    commands = []
    def fake_command(*args, **kwargs):
        assert args[0] in {"adduser", "systemd-tmpfiles", "nginx", "systemd-analyze", "systemctl"}
        commands.append(tuple(map(str,args)))
        return ""
    previous_umask = os.umask(0o002)
    try:
        result = engine.configure_native(paths, profile, "mgmt0", "192.0.2.10", fake_command)
    finally:
        os.umask(previous_umask)
    assert all(not port["enabled"] for port in result["ports"].values())
    assert decode_configuration((paths.boot / "active.conf").read_bytes()).profile == profile
    credentials = paths.native_state / "initial-admin.json"
    assert credentials.stat().st_mode & 0o777 == 0o600
    assert len(json.loads(credentials.read_bytes())["password"]) >= 24
    assert "NETLAB_FM10K_STARTUP_MODE=control" in (paths.etc / "native.env").read_text()
    assert (paths.etc / "tls/server.key").stat().st_mode & 0o777 == 0o600
    for directory in (paths.native_state, paths.native_state / "config",
                      paths.native_state / "config/journal", paths.native_state / "config/rollback"):
        assert directory.stat().st_mode & 0o777 == 0o700
    assert paths.etc.stat().st_mode & 0o777 == 0o755
    assert paths.boot.stat().st_mode & 0o777 == 0o755
    wait_script = paths.etc / "wait-management.py"
    nginx_dropin = paths.root / "etc/systemd/system/nginx.service.d/fm10k-controlpanel.conf"
    assert "address in assigned" in wait_script.read_text()
    assert f"ExecCondition=/usr/bin/python3 -I -B {wait_script} mgmt0 192.0.2.10" in nginx_dropin.read_text()
    assert "TimeoutStartSec=210" in nginx_dropin.read_text()
    assert all("start" not in command and "restart" not in command for command in commands)


def test_native_stage_removes_group_write_even_with_wide_umask(tmp_path, monkeypatch):
    source = tmp_path / "source"
    (source / "vendor/netlab").mkdir(parents=True)
    paths = engine.Paths(tmp_path / "host")
    monkeypatch.setattr(engine, "verify_bundle", lambda *_: None)
    monkeypatch.setattr(engine, "_copy_inputs", lambda *_: None)
    observed_umasks = []

    def fake_runner(*args, **kwargs):
        if args[0] == "make":
            previous = os.umask(0o022)
            os.umask(previous)
            observed_umasks.append(previous)
            build = Path(args[2]) / "build"
            build.mkdir()
            build.chmod(0o775)
            header = b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00"
            for name in (*engine.DAEMONS, "netlab-daemon-launch", "netlab-internal-rpc"):
                binary = build / name
                binary.write_bytes(header)
                binary.chmod(0o775)
            return ""
        assert args[0] == "ldd"
        return "all dependencies resolved"

    previous_umask = os.umask(0o002)
    try:
        stage = engine.stage_native(source, tmp_path / "sdk", tmp_path / "platform",
                                    "sil001-hw4-b0", paths, fake_runner)
    finally:
        os.umask(previous_umask)
    assert observed_umasks == [0o022]
    assert all(not (path.stat().st_mode & 0o022) for path in (stage, *stage.rglob("*")))
    assert (stage / "vendor/netlab/build/netlab-daemon-launch").stat().st_mode & 0o111


@pytest.mark.parametrize("failure", [None, "health", "enable"])
def test_fresh_install_enables_only_after_health_and_cleans_partial_enable(tmp_path, monkeypatch, failure):
    paths = engine.Paths(tmp_path / "host")
    source = tmp_path / "source"
    source.mkdir()
    stage = paths.base / ".stage-test"
    (stage / "packages").mkdir(parents=True)
    (stage / "packages/fm10k-controlpanel_0.2.0_all.deb").write_bytes(b"synthetic web package")
    (stage / "hardware").mkdir()
    (stage / "hardware/sdk-inputs.json").write_text("{}")
    (stage / "deploy").mkdir()
    (stage / "deploy/release-dependencies.json").write_text("{}")
    report = {"passed": True, "profile": "sil001-hw4-b0", "host": {"kernel": "6.12.107+deb13-amd64"},
              "board": {"vpd_sha256": "synthetic-vpd", "driver": "fm10k"},
              "driver_install_required": False}
    events = []

    monkeypatch.setattr(engine, "Paths", lambda: paths)
    monkeypatch.setattr(engine.os, "geteuid", lambda: 0)
    monkeypatch.setattr(engine, "verify_bundle", lambda *_: None)
    monkeypatch.setattr(engine, "preflight", lambda *_a, **_k: report)
    monkeypatch.setattr(engine, "build_libyang", lambda *_: None)
    monkeypatch.setattr(engine, "stage_native", lambda *_a, **_k: stage)
    monkeypatch.setattr(engine, "configure_native", lambda *_: {"profile": report["profile"]})
    monkeypatch.setattr(engine, "start_services", lambda *_: events.append("start"))

    def fake_health(*_):
        events.append("health")
        if failure == "health":
            raise ReleaseError("synthetic health failure")

    def fake_run(*args, **_kwargs):
        events.append(tuple(map(str, args)))
        if failure == "enable" and args[:2] == ("systemctl", "enable"):
            raise ReleaseError("synthetic partial enable failure")
        return ""

    monkeypatch.setattr(engine, "health", fake_health)
    monkeypatch.setattr(engine, "run", fake_run)
    arguments = (source, tmp_path / "sdk", tmp_path / "platform", "mgmt0", "192.0.2.10", "0.2.0")
    if failure:
        with pytest.raises(ReleaseError, match="synthetic .* failure"):
            engine.install(*arguments)
    else:
        engine.install(*arguments)
    metadata = json.loads(paths.installation.read_bytes())
    enables = [item for item in events if isinstance(item, tuple) and item[:2] == ("systemctl", "enable")]
    disables = [item for item in events if isinstance(item, tuple) and item[:2] == ("systemctl", "disable")]
    if failure:
        assert metadata["status"] == "installation_failed" and "installed_at" not in metadata
        if failure == "health":
            assert not enables
        else:
            assert len(enables) == 1
        assert [event[2] for event in disables] == list(engine.STARTUP_UNITS)
        assert any(isinstance(item, tuple) and item[:3] == ("systemctl", "stop", "fm10k-time.socket")
                   for item in events)
    else:
        assert metadata["status"] == "ready" and metadata["installed_at"]
        assert len(enables) == 1 and not disables
        assert events.index("health") < events.index(enables[0])
