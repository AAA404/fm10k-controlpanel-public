import copy

import pytest

from fm10k_controlpanel.board import changed_groups
from fm10k_controlpanel.models import Proposal, SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration, decode_configuration, parse_xml
from fm10k_controlpanel.service import PanelService
from fm10k_controlpanel.simulator import MockConfigd


def configurations():
    raw = SwitchConfiguration().model_dump()
    raw['vlans'] = [{'id': 10}, {'id': 20}]
    raw['groups'][1]['mode'] = 'split'
    for port in range(5, 9):
        raw['ports'][port].update(enabled=port != 7, pvid=10, vlan_mode='trunk', tagged_vlans=[20])
    split = SwitchConfiguration.model_validate(raw)
    merged = copy.deepcopy(raw)
    group = merged['groups'][1]
    group['mode'] = '100g'
    fields = ('enabled', 'vlan_mode', 'pvid', 'tagged_vlans', 'ingress_filtering')
    group['split_vlan_backup'] = [{key: merged['ports'][port][key] for key in fields} for port in range(5, 9)]
    for port in range(6, 9):
        merged['ports'][port].update(enabled=False, pvid=None, tagged_vlans=[])
    return split, SwitchConfiguration.model_validate(merged)


def test_backup_is_typed_and_dormant_not_an_active_vlan_reference():
    _, merged = configurations()
    raw = merged.model_dump()
    raw['groups'][1]['split_vlan_backup'][3]['pvid'] = 99
    preserved = SwitchConfiguration.model_validate(raw)
    assert preserved.groups[1].split_vlan_backup[3].pvid == 99
    root = parse_xml(compile_configuration(preserved))
    children = [node for node in root.findall('./interfaces/interface')
                if node.findtext('name') in ('et-0/0/5', 'et-0/0/6', 'et-0/0/7')]
    assert all(not node.findall('./unit') for node in children)
    assert decode_configuration(compile_configuration(preserved)) == preserved
    raw['groups'][1]['split_vlan_backup'][3]['tagged_vlans'] = [99]
    with pytest.raises(ValueError, match='Native/Tagged'):
        SwitchConfiguration.model_validate(raw)


def test_metadata_change_does_not_reconfigure_phy():
    _, merged = configurations()
    updated = merged.model_copy(deep=True)
    updated.groups[1].split_vlan_backup[0].enabled = False
    assert changed_groups(merged, updated) == []


def test_preview_names_every_removed_child_and_saved_history(tmp_path):
    split, merged = configurations()
    backend = MockConfigd(tmp_path)
    backend.apply(split, 1, 'a' * 32, 60)
    backend.confirm('a' * 32)
    service = PanelService(backend, tmp_path)
    try:
        draft = service.preview(Proposal(expected_revision=2, configuration=merged))
        assert draft['affected_epls'] == [1]
        group = draft['group_changes'][0]
        assert group['epl'] == 1
        assert [row['port'] for row in group['ports'] if not row['active']] == [6, 7, 8]
        assert all(row['before'] == 'Native 10 · Tagged 20' for row in group['ports'])
        assert '再次拆分时恢复' in group['notes'][0]
        assert any(change.get('label') == 'P6 · PVID / Native VLAN' for change in draft['changes'])
        assert any(change.get('label') == 'EPL 1 · 拆分 VLAN 恢复记录' for change in draft['changes'])
    finally:
        service.close()


def test_history_survives_confirmation_restart_backup_and_rollback(tmp_path):
    split, merged = configurations()
    backend = MockConfigd(tmp_path)
    backend.apply(split, 1, 'a' * 32, 60); backend.confirm('a' * 32)
    backend.apply(merged, 2, 'b' * 32, 60)
    backend.rollback('b' * 32)
    assert backend.configuration == split
    backend.apply(merged, backend.revision, 'c' * 32, 60); backend.confirm('c' * 32)
    backend.close()
    restarted = MockConfigd(tmp_path)
    assert restarted.configuration == merged
    service = PanelService(restarted, tmp_path)
    try:
        exported = service.backup()
        assert exported['configuration']['groups'][1]['split_vlan_backup']
        assert service.restore_preview(exported)['changes'] == []
        draft = service.preview(Proposal(expected_revision=restarted.revision, configuration=split))
        assert '恢复各端口合并前' in draft['group_changes'][0]['notes'][0]
        restarted.apply(split, restarted.revision, 'd' * 32, 60)
        restarted.rollback('d' * 32)
        assert restarted.configuration == merged
    finally:
        service.close()


def test_unconfirmed_merge_does_not_replace_the_persisted_split_profile(tmp_path):
    split, merged = configurations()
    backend = MockConfigd(tmp_path)
    backend.apply(split, 1, 'a' * 32, 60); backend.confirm('a' * 32)
    backend.apply(merged, 2, 'b' * 32, 60)
    backend.close()
    restarted = MockConfigd(tmp_path)
    assert restarted.configuration == split and restarted.pending is None
    restarted.close()
