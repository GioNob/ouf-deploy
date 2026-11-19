"""A resumed runtime chooses the SeaweedFS owner and rejects unfinished handovers."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime', Path(sys.argv[1]))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)

with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
    root = Path(tmp).resolve()
    plan = root / 'cold/plan.json'; plan.parent.mkdir()
    original = {'Id': 'a' * 64, 'Image': 'sha256:same-image',
        'Config': {'Labels': {}}, 'HostConfig': {'RestartPolicy': {'Name': 'no'}}, 'Mounts': [],
        'State': {'Status': 'exited', 'Running': False, 'StartedAt': 'old-start'},
        'NetworkSettings': {'Networks': {'ouf-backend': {}}}}
    capture = root / 'original.json'; capture.write_text(json.dumps([original]))
    plan.write_text(json.dumps({'roles': {'onboarding': {'containerId': original['Id'],
        'nativeImage': original['Image'], 'fingerprint': r.fingerprint(original, 'old-start')}}}))
    replacement = copy.deepcopy(original)
    replacement['Id'] = 'd' * 64
    replacement['State'].update(Running=True, Status='running', StartedAt='new-start')
    replacement['Config']['Labels'] = {'ouf.storage.switch': 'fixture-token'}
    replacement['NetworkSettings']['Networks']['ouf-seaweedfs-private'] = {}
    work = root / 'onboarding-seaweedfs-switch-fixture'; work.mkdir()
    (work / 'replacement-container.private.json').write_text(json.dumps(replacement))
    marker = {'status': 'ONBOARDING_SEAWEEDFS_READY', 'privateEvidenceDirectory': str(work),
        'originalContainerId': original['Id'], 'replacementContainerId': replacement['Id'],
        'switchToken': 'fixture-token'}
    marker_path = root / 'onboarding-seaweedfs-current.json'
    docs = {d['Id']: d for d in (original, replacement)}
    def inspect(*ids): return {cid: copy.deepcopy(docs[cid]) for cid in ids}
    with patch.multiple(r, PLAN=plan, PLAN_SHA=r.hashlib.sha256(plan.read_bytes()).hexdigest(),
            ORIGINAL_INSPECT=capture, GROUPS=(('onboarding',),), inspect=inspect):
        marker_path.write_text(json.dumps(marker))
        bound, _ = r.retained_stack()
        assert bound['onboarding'] == replacement['Id']
        marker['status'] = 'SWITCH_IN_PROGRESS'; marker_path.write_text(json.dumps(marker))
        try:
            r.retained_stack(); raise AssertionError('unfinished switch accepted')
        except ValueError as error:
            assert str(error) == 'ONBOARDING_STORAGE_SWITCH_INCOMPLETE'
        marker['status'] = 'ONBOARDING_SEAWEEDFS_READY'; marker_path.write_text(json.dumps(marker))
        docs[original['Id']]['State']['Running'] = True
        try:
            r.retained_stack(); raise AssertionError('two owners accepted')
        except ValueError as error:
            assert str(error) == 'ONBOARDING_STORAGE_BINDING_NOT_PROVEN'
    print('PASS: resume selects replacement; incomplete handover and running old owner are rejected.')
    print('Scope: configuration fixture; no Docker or VPS restart was executed.')
