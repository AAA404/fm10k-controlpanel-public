from dataclasses import replace
import hashlib
import importlib.util
from pathlib import Path

import pytest

from fm10k_controlpanel.profiles import PROFILES
from platform_fixture import reference_text

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("import_platform", ROOT / "scripts/import_platform.py")
importer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(importer)


def test_import_checks_digest_before_creating_destination(tmp_path):
    source = tmp_path / "wrong.cfg"
    source.write_text(reference_text("sil001-hw4-b0"))
    target = tmp_path / "repository"
    with pytest.raises(ValueError, match="digest does not match"):
        importer.import_platform("sil001-hw4-b0", source, target)
    assert not target.exists()


def test_import_preserves_bytes_and_refuses_existing_different_file(tmp_path, monkeypatch):
    name = "sil001-hw4-b0"
    data = reference_text(name).encode()
    monkeypatch.setitem(PROFILES, name, replace(PROFILES[name], sha256=hashlib.sha256(data).hexdigest()))
    source = tmp_path / "source.cfg"
    source.write_bytes(data)
    target = tmp_path / "repository"
    imported = importer.import_platform(name, source, target)
    assert imported.read_bytes() == data
    assert imported == target / "hardware/sdk/platforms/sil001-hw4-b0.cfg"
    assert importer.import_platform(name, source, target) == imported
    imported.write_text("operator changes")
    with pytest.raises(ValueError, match="refusing to replace"):
        importer.import_platform(name, source, target)
    assert imported.read_text() == "operator changes"


def test_manufacturer_digests_remain_locked():
    assert {name: spec.sha256 for name, spec in PROFILES.items()} == {
        "sil001-hw4-b0": "38c481b5d8035df14bc517735cd8e1c1ba9936fdc512fd18c849878fe323da98",
        "sil001-hw5-a11": "8f5c1700c48984d539ff526f4a4ba18c814db27282de2afe33c90a2888c87d96",
    }
