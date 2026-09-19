import importlib.util
from pathlib import Path

import pytest

from fm10k_controlpanel.models import SwitchConfiguration

spec = importlib.util.spec_from_file_location("acceptance", Path(__file__).resolve().parents[1] / "scripts/acceptance.py")
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


def test_cycle_preserves_other_groups_and_incompatible_dependencies():
    config = SwitchConfiguration().model_dump(mode="json")
    config["ports"]["13"]["name"] = "untouched"
    config["ports"]["2"]["pvid"] = 100
    target = acceptance.target_for_mode(config, 0, ("split", [10, 25, 10, 25]))
    assert target["groups"][1:] == config["groups"][1:]
    assert target["ports"] == config["ports"]
    assert target["ports"]["2"]["pvid"] == 100
    assert not target["ports"]["2"]["enabled"]
    assert config["groups"][0]["mode"] == "100g"


@pytest.mark.parametrize("url", ["http://192.0.2.10", "https://user:pass@example.net", "https://example.net/path", "https://example.net/?secret=x"])
def test_acceptance_rejects_unsafe_origins(url):
    with pytest.raises(ValueError):
        acceptance.validate_url(url)


def test_observer_detects_other_epl_link_loss_and_missing_evidence():
    before = {"ports": [{"id": 5, "epl": 1, "quality": "valid", "link": "up", "enabled": True}]}
    after = {"ports": [{**before["ports"][0], "link": "down"}]}
    with pytest.raises(RuntimeError, match="link"):
        acceptance.compare_other_groups(before, after, 0)
    after["ports"][0]["quality"] = "stale"
    with pytest.raises(RuntimeError, match="stale"):
        acceptance.compare_other_groups(before, after, 0)
