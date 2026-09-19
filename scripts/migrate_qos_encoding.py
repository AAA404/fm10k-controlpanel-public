#!/usr/bin/env python3
"""Normalize legacy panel QoS through a confirmed configd transaction."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import uuid

installed = Path('/usr/lib/fm10k-controlpanel/python')
if installed.is_dir():
    sys.path.insert(0, str(installed))

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab import CONFIGD, SNAPSHOT, NetlabBackend
from fm10k_controlpanel.netlab_codec import compile_configuration, parse_xml


def scheduler_encoding(root):
    if root.tag == 'fm10k-panel-state':
        root = root.find('netlab-config')
    if root is None:
        raise ValueError('native configuration is missing')
    return {node.findtext('name'): {
        'enabled':node.findtext('traffic-class-enable-mask'),
        'mapping':{tc.findtext('class'):tc.findtext('shaping-group') for tc in node.findall('traffic-class')},
        'groups':{group.findtext('id'):(group.findtext('strict-priority'), group.findtext('weight'))
                  for group in node.findall('group')},
    } for node in root.findall('./class-of-service/scheduler/interfaces/interface')}


def migrate(backend, apply=False):
    before = backend.snapshot()
    if not before['hardware_write_ready'] or before.get('pending'):
        raise RuntimeError('native configuration must be synchronized with no pending commit')
    config = SwitchConfiguration.model_validate(before['configuration'])
    current = scheduler_encoding(parse_xml(backend._rpc(CONFIGD, SNAPSHOT)))
    expected = scheduler_encoding(parse_xml(compile_configuration(config)))
    report = {'before_revision':before['revision'], 'needed':current != expected, 'applied':False}
    if current == expected or not apply:
        return report
    job = uuid.uuid4().hex
    backend.validate(config)
    applied = backend.apply(config, before['revision'], job, 180)
    report.update(job_id=job, applied_revision=applied['revision'])
    try:
        actual = scheduler_encoding(parse_xml(backend._rpc(CONFIGD, SNAPSHOT)))
        if actual != expected or applied['configuration'] != before['configuration']:
            raise RuntimeError('normalized configuration did not match its unchanged user intent')
        final = backend.confirm(job)
        if final['configuration'] != before['configuration'] or not final['synchronized']:
            raise RuntimeError('configuration confirmation did not preserve user intent')
    except Exception:
        state = backend.snapshot()
        if (state.get('pending') or {}).get('job_id') == job:
            backend.rollback(job)
        raise
    report.update(applied=True, final_revision=final['revision'], intent_unchanged=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='apply and confirm; default only reports the difference')
    parser.add_argument('--netlab-root', type=Path, default=Path('/opt/fm10k-controlpanel/native/vendor/netlab'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    os.environ['PANEL_NETLAB_ROOT'] = str(args.netlab_root)
    backend = NetlabBackend()
    try:
        report = migrate(backend, args.apply)
    finally:
        backend.close()
    text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.touch(mode=0o600)
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
