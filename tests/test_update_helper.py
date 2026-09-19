import copy
import hashlib
import json

import pytest

from fm10k_controlpanel import update_helper as helper
from fm10k_controlpanel.installation import Paths, save
from fm10k_controlpanel.release import MANIFEST_NAME, ReleaseError, json_bytes
from fm10k_controlpanel.updates import UpdateError
from test_release import manifest


@pytest.fixture
def manager(tmp_path, monkeypatch):
    paths = Paths(tmp_path)
    paths.updates.mkdir(parents=True)
    installed = {"schema":1,"status":"ready","version":"0.1.0","sdk_manifest_sha256":"b"*64}
    save(paths.installation,installed)
    monkeypatch.setattr(helper,"installed_metadata",lambda p:json.loads(p.installation.read_bytes()))
    value = manifest()
    raw = json_bytes(value)
    candidate = {"manifest":value,"manifest_sha256":hashlib.sha256(raw).hexdigest(),"release_id":1,
                 "assets":{MANIFEST_NAME:{"id":1,"size":len(raw)}}}
    calls=[]
    class Client:
        def latest(self): return copy.deepcopy(candidate)
        def asset_bytes(self,*args): return raw
        def download(self,*args): raise AssertionError("unexpected download")
    return helper.UpdateManager(paths,client_factory=Client,runner=lambda *a,**k:calls.append(a),clock=lambda:1000), candidate, calls


def request(candidate):
    return {"action":"install","version":candidate["manifest"]["version"],
            "manifest_sha256":candidate["manifest_sha256"],"confirm_restart":True}


def test_check_and_queue_only_dispatches_fixed_worker(manager):
    updater,candidate,calls=manager
    status=updater.check()
    assert status["state"]=="available" and status["candidate"]["version"]=="0.2.0"
    assert "assets" not in status["candidate"] and "token" not in json.dumps(status)
    queued=updater.handle(request(candidate))
    assert queued["state"]=="queued" and updater.paths.marker.exists()
    assert calls==[("systemctl","start","--no-block","fm10k-update-worker.service")]
    with pytest.raises(UpdateError): updater.handle(request(candidate))
    with pytest.raises(UpdateError): updater.check()
    assert len(calls)==1


def test_unchecked_stale_changed_or_unacknowledged_update_refused(manager):
    updater,candidate,calls=manager
    with pytest.raises(UpdateError): updater.handle(request(candidate))
    updater.check()
    for changes in ({"version":"0.3.0"},{"manifest_sha256":"c"*64},{"confirm_restart":False},{"url":"https://example.invalid"}):
        with pytest.raises(UpdateError): updater.handle({**request(candidate),**changes})
    updater.clock=lambda:5001
    with pytest.raises(UpdateError): updater.handle(request(candidate))
    assert calls==[] and not updater.paths.marker.exists()


def test_failed_check_clears_previous_candidate(manager):
    updater,_,_=manager
    updater.check()
    def fail(): raise ReleaseError("GitHub access denied")
    updater.client_factory=fail
    result=updater.check()
    assert result["state"]=="check_failed" and result["candidate"] is None


def test_equal_or_older_release_is_not_offered(manager):
    updater,_,_=manager
    current=json.loads(updater.paths.installation.read_bytes())
    current["version"]="0.2.0"
    save(updater.paths.installation,current)
    assert updater.check()["state"]=="up_to_date"
    current["version"]="1.0.0"
    save(updater.paths.installation,current)
    assert updater.check()["candidate"] is None


def test_never_accept_client_url_credentials_or_commands(manager):
    updater,_,calls=manager
    for body in ({"action":"check","token":"secret"},{"action":"check","repository":"other/repo"},
                 {"action":"status","command":"id"},{"action":"shell"}):
        with pytest.raises(UpdateError): updater.handle(body)
    assert calls==[]


def test_changed_manifest_fails_before_download_or_service_stop(manager):
    updater,candidate,calls=manager
    updater.check(); updater.handle(request(candidate))
    class Changed:
        def asset_bytes(self,*_): return json_bytes(manifest("0.3.0"))
        def download(self,*_): pytest.fail("must not download changed release")
    updater.client_factory=Changed
    with pytest.raises(ReleaseError,match="changed"): updater.work()
    assert updater.state()["state"]=="failed"
    assert not updater.paths.marker.exists()
    assert len(calls)==1


def test_restart_does_not_repeat_download_or_install(manager):
    updater,candidate,calls=manager
    updater.check(); updater.handle(request(candidate))
    updater.progress("downloading","interrupted download")
    updater.work()
    assert updater.state()["state"]=="failed"
    assert len(calls)==1 and not updater.paths.marker.exists()


def test_uncertain_dispatch_keeps_job_and_maintenance_lock(manager):
    updater,candidate,_=manager
    updater.check()
    def uncertain(*_args,**_kwargs): raise TimeoutError()
    updater.runner=uncertain
    assert updater.handle(request(candidate))["state"]=="queued"
    assert updater.paths.marker.exists()
    with pytest.raises(UpdateError): updater.handle(request(candidate))


def test_reboot_recreates_maintenance_marker_before_recovery(manager,monkeypatch):
    updater,candidate,calls=manager
    updater.check();updater.handle(request(candidate))
    updater.progress("installing","interrupted install")
    updater.paths.marker.unlink()
    save(updater.paths.journal,{"schema":1,"phase":"switching"})
    def recover(paths,transaction,**kwargs):
        assert paths.marker.exists()
        transaction["phase"]="rolled_back"
        save(paths.journal,transaction)
    monkeypatch.setattr(helper,"rollback",recover)
    updater.work()
    assert updater.state()["state"]=="rolled_back" and not updater.paths.marker.exists()
    assert len(calls)==1


def test_recovery_finishes_persisted_rollback_without_running_it_twice(manager):
    updater, candidate, calls = manager
    updater.check(); updater.handle(request(candidate))
    updater.progress("rolling_back", "state update was interrupted")
    save(updater.paths.journal, {"schema": 1, "phase": "rolled_back", "job_id": updater.state()["job"]["id"]})
    updater.work()
    assert updater.state()["state"] == "rolled_back" and not updater.paths.marker.exists()
    assert len(calls) == 1


def test_old_rollback_does_not_consume_a_new_job_for_the_same_version(manager):
    updater, candidate, _ = manager
    updater.check(); updater.handle(request(candidate))
    save(updater.paths.journal, {"schema": 1, "phase": "rolled_back", "job_id": "previous-job"})
    assert updater.recover() is False
    assert updater.state()["state"] == "queued" and updater.paths.marker.exists()


@pytest.mark.parametrize("journal", [b"broken json", b'{"schema":2,"phase":"switching"}', b'{"schema":1,"phase":"unknown"}'])
def test_invalid_recovery_journal_keeps_maintenance_without_service_changes(manager, journal):
    updater, _, calls = manager
    updater.paths.journal.write_bytes(journal)
    with pytest.raises(ValueError): updater.work()
    assert updater.state()["state"] == "recovery_required" and updater.paths.marker.exists()
    assert calls == []


def test_boot_worker_exposes_only_marker_to_web_despite_private_umask(tmp_path):
    import os
    paths = Paths(tmp_path)
    previous = os.umask(0o077)
    try:
        helper.lock_writes(paths, "synthetic-job")
    finally:
        os.umask(previous)
    assert paths.marker.parent.stat().st_mode & 0o777 == 0o755
    assert paths.marker.stat().st_mode & 0o777 == 0o644
