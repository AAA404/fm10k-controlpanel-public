import pytest

from fm10k_controlpanel import native_guard as guard
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration


def test_control_startup_follows_current_authority_after_seed_compaction(monkeypatch):
    profile = "sil001-hw5-a11"
    pointer = guard.STATE / "config/journal/tx_counter"
    # tx_counter is decimal; configd names immutable snapshots in hexadecimal.
    snapshot = guard.STATE / "config/rollback/0000000000000064.conf"
    config = SwitchConfiguration(profile=profile)
    config.ports[1].name = "persisted after many commits"
    raw = compile_configuration(config)
    files = {pointer: b"100\n", snapshot: raw}
    monkeypatch.setattr(guard, "trusted_file", lambda p: files[p])
    assert guard.validate_replay_authority(profile, 2) == 100
    assert guard.STATE / "config/rollback/0000000000000002.conf" not in files
    for invalid in (b"0\n", b"01\n", b"100 garbage\n", b"100\n\n", b"-1\n", b"1\n"):
        files[pointer] = invalid
        with pytest.raises(ValueError): guard.validate_replay_authority(profile, 2)
    files[pointer] = b"100\n"
    files[snapshot] = compile_configuration(SwitchConfiguration(profile="sil001-hw4-b0"))
    with pytest.raises(ValueError, match="profile"):
        guard.validate_replay_authority(profile, 2)
    files[snapshot] = raw.replace(b"</netlab-config>", b"<routing-options><autonomous-system>65000</autonomous-system></routing-options></netlab-config>")
    with pytest.raises(ValueError, match="L3"):
        guard.validate_replay_authority(profile, 2)
    files[snapshot] = raw
    reads = 0
    def racing_read(path):
        nonlocal reads
        if path == pointer:
            reads += 1
            return b"100\n" if reads == 1 else b"101\n"
        return files[path]
    monkeypatch.setattr(guard, "trusted_file", racing_read)
    with pytest.raises(ValueError, match="changed"):
        guard.validate_replay_authority(profile, 2)
