import importlib.util
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration, parse_xml

spec = importlib.util.spec_from_file_location('qos_migration', Path(__file__).resolve().parents[1] / 'scripts/migrate_qos_encoding.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


class Backend:
    def __init__(self, mismatch=False):
        self.config = SwitchConfiguration()
        legacy = parse_xml(compile_configuration(self.config))
        for weight in legacy.findall('./class-of-service/scheduler/interfaces/interface/group/weight'):
            weight.text = '1'
        self.xml = ET.tostring(legacy)
        self.before = self.xml
        self.pending = None
        self.revision = 1
        self.calls = []
        self.mismatch = mismatch

    def snapshot(self):
        return {'configuration':self.config.model_dump(mode='json'), 'revision':self.revision,
                'hardware_write_ready':True, 'synchronized':True, 'pending':self.pending}

    def _rpc(self, *args):
        return self.xml

    def validate(self, config):
        assert config == self.config

    def apply(self, config, revision, job, timeout):
        assert config == self.config and revision == self.revision and timeout == 180
        self.calls.append('apply')
        self.revision += 1
        self.pending = {'job_id':job}
        if not self.mismatch: self.xml = compile_configuration(config)
        return self.snapshot()

    def confirm(self, job):
        assert self.pending['job_id'] == job
        self.calls.append('confirm')
        self.pending = None
        return self.snapshot()

    def rollback(self, job):
        assert self.pending['job_id'] == job
        self.calls.append('rollback')
        self.pending = None
        self.xml = self.before
        return self.snapshot()


def test_qos_migration_keeps_intent_and_is_idempotent():
    backend = Backend()
    assert migration.migrate(backend)['needed'] and not backend.calls
    result = migration.migrate(backend, True)
    assert result['applied'] and result['intent_unchanged']
    assert not migration.migrate(backend, True)['needed']
    assert backend.calls == ['apply', 'confirm']


def test_qos_migration_rolls_back_unverified_encoding():
    backend = Backend(mismatch=True)
    with pytest.raises(RuntimeError, match='normalized configuration'):
        migration.migrate(backend, True)
    assert backend.calls == ['apply', 'rollback'] and not backend.pending
