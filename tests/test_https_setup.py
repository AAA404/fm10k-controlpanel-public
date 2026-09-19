from pathlib import Path

import pytest

from fm10k_controlpanel.https_setup import listener, prepare, render


@pytest.mark.parametrize("bind,name", [("0.0.0.0", "switch.local"), ("::", "switch.local"),
    ("224.0.0.1", "switch.local"), ("127.0.0.1;", "switch.local"),
    ("127.0.0.1", "a;include /tmp/evil"), ("127.0.0.1", "a\nb"), ("127.0.0.1", "*.local")])
def test_https_rejects_wildcard_binds_and_config_injection(bind, name):
    with pytest.raises(ValueError):
        listener(bind, name)


def test_ipv6_listener_and_real_certificate_pair(tmp_path):
    template = Path(__file__).resolve().parents[1] / "deploy/nginx/fm10k-controlpanel.conf.in"
    text = render(template.read_text(), "fd00::10", "switch.local")
    assert "listen [fd00::10]:443 ssl;" in text
    assert "@LISTEN@" not in text
    output = tmp_path / "https"
    report = prepare(output, template, "127.0.0.1", "switch.local", days=1)
    assert not report["activated"]
    assert output.stat().st_mode & 0o077 == 0
    assert (output / "server.key").stat().st_mode & 0o077 == 0
    assert "BEGIN CERTIFICATE" in (output / "server.crt").read_text()
