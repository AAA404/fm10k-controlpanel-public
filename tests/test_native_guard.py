import copy
import pytest

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.native_guard import initial_configuration, validate_identity, validate_initial_configuration
from fm10k_controlpanel.netlab_codec import compile_configuration


def test_observation_seed_cannot_enable_ports_or_change_profile():
    config = SwitchConfiguration(profile="sil001-hw5-a11")
    raw = compile_configuration(config)
    assert validate_initial_configuration(raw, config.profile) == config
    with pytest.raises(ValueError):
        validate_initial_configuration(raw, "sil001-hw4-b0")
    config.ports[1].enabled = True
    with pytest.raises(ValueError):
        validate_initial_configuration(compile_configuration(config), config.profile)


def test_native_identity_is_fresh_and_specific_to_the_selected_board():
    report = {"preflight_passed": True, "profile": "sil001-hw5-a11",
              "devices": [{"bdf": "0000:01:00.0"}]}
    assert validate_identity(report, "sil001-hw5-a11")["bdf"] == "0000:01:00.0"
    for field, value in (("preflight_passed", False), ("profile", "sil001-hw4-b0"),
                         ("devices", [{"bdf": "0000:02:00.0"}]), ("devices", [])):
        invalid = copy.deepcopy(report)
        invalid[field] = value
        with pytest.raises(ValueError):
            validate_identity(invalid, "sil001-hw5-a11")


def test_basic100g_seed_is_explicit_and_exact():
    config = initial_configuration("sil001-hw5-a11", "basic100g")
    assert [n for n, p in config.ports.items() if p.enabled] == [1, 5, 9, 13, 17, 21]
    assert all(p.pvid == 1 for p in config.ports.values() if p.enabled)
    assert not config.rstp.enabled and not config.lldp.enabled
    raw = compile_configuration(config)
    assert validate_initial_configuration(raw, config.profile, "basic100g") == config
    with pytest.raises(ValueError):
        validate_initial_configuration(raw, config.profile, "observe")
    config.ports[1].enabled = False
    with pytest.raises(ValueError):
        validate_initial_configuration(compile_configuration(config), config.profile, "basic100g")
