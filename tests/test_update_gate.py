import json
from pathlib import Path

import pytest

from fm10k_controlpanel.update_gate import process_identity, verify_update_gate


def test_interrupted_update_blocks_startup_until_live_worker_grants_permission(tmp_path):
    journal=tmp_path / "var/lib/fm10k-controlpanel-updates/transaction.json"
    journal.parent.mkdir(parents=True)
    journal.write_text('{"schema":1,"phase":"switching"}')
    reader=lambda p:p.read_bytes()
    with pytest.raises(ValueError,match="interrupted update"):
        verify_update_gate(tmp_path,reader)
    process=tmp_path / "proc/321"
    process.mkdir(parents=True)
    (process / "stat").write_text('321 (worker name) '+" ".join(["S"]+["0"]*18+["12345"]))
    boot=tmp_path / "proc/sys/kernel/random/boot_id"
    boot.parent.mkdir(parents=True);boot.write_text("boot-one")
    permission=tmp_path / "run/fm10k-update/startup-permission.json"
    permission.parent.mkdir(parents=True)
    permission.write_text(json.dumps(process_identity(tmp_path,321)))
    verify_update_gate(tmp_path,reader)
    boot.write_text("boot-two")
    with pytest.raises(ValueError,match="interrupted update"): verify_update_gate(tmp_path,reader)
    boot.write_text("boot-one")
    (process / "stat").write_text('321 (new process) '+" ".join(["S"]+["0"]*18+["99999"]))
    with pytest.raises(ValueError,match="interrupted update"): verify_update_gate(tmp_path,reader)
    journal.write_text('{"schema":1,"phase":"committed"}')
    verify_update_gate(tmp_path,reader)
