"""Resume selects both replacement owners and never an old MinIO writer."""
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
    originals, replacements, roles, markers = {}, {}, {}, {}
    for role, old_letter, new_letter in [('onboarding', 'a', 'c'), ('udp', 'b', 'd')]:
        original = {'Id': old_letter * 64, 'Image': 'sha256:' + role,
            'Config': {'Labels': {}}, 'HostConfig': {'RestartPolicy': {'Name': 'no'}}, 'Mounts': [],
            'State': {'Status': 'exited', 'Running': False, 'StartedAt': 'old-' + role},
            'NetworkSettings': {'Networks': {'ouf-backend': {}}}}
        originals[role] = original
        roles[role] = {'containerId': original['Id'], 'nativeImage': original['Image'],
                       'fingerprint': r.fingerprint(original, original['State']['StartedAt'])}
        new = copy.deepcopy(original)
        new['Id'] = new_letter * 64
        new['State'].update(Running=True, Status='running', StartedAt='new-' + role)
        new['Config']['Labels'] = {'ouf.storage.switch': 'token-' + role, 'ouf.storage.backend': 'seaweedfs'}
        new['NetworkSettings']['Networks']['ouf-seaweedfs-private'] = {}
        replacements[role] = new
        work = root / (role + '-seaweedfs-switch-fixture'); work.mkdir()
        (work / 'replacement-container.private.json').write_text(json.dumps(new))
        marker = {'status': role.upper() + '_SEAWEEDFS_READY', 'privateEvidenceDirectory': str(work),
                  'originalContainerId': original['Id'], 'replacementContainerId': new['Id'],
                  'switchToken': 'token-' + role}
        markers[role] = marker
        (root / (role + '-seaweedfs-current.json')).write_text(json.dumps(marker))
    plan.write_text(json.dumps({'roles': roles}))
    captured = root / 'originals.json'; captured.write_text(json.dumps(list(originals.values())))
    docs = {doc['Id']: doc for doc in [*originals.values(), *replacements.values()]}
    def inspect(*ids):
        return {cid: copy.deepcopy(docs[cid]) for cid in ids}
    with patch.multiple(r, PLAN=plan, PLAN_SHA=r.hashlib.sha256(plan.read_bytes()).hexdigest(),
                        ORIGINAL_INSPECT=captured, GROUPS=(('onboarding', 'udp'),), inspect=inspect):
        bound, _ = r.retained_stack()
        assert bound == {role: doc['Id'] for role, doc in replacements.items()}
        marker_path = root / 'udp-seaweedfs-current.json'
        marker_path.write_text(json.dumps(dict(markers['udp'], status='SWITCH_IN_PROGRESS')))
        try:
            r.retained_stack(); raise AssertionError('unfinished UDP switch accepted')
        except ValueError as error:
            assert str(error) == 'UDP_STORAGE_SWITCH_INCOMPLETE'
        marker_path.write_text(json.dumps(markers['udp']))
        originals['udp']['State']['Running'] = True
        try:
            r.retained_stack(); raise AssertionError('old UDP running accepted')
        except ValueError as error:
            assert str(error) == 'UDP_STORAGE_BINDING_NOT_PROVEN'
        originals['udp']['State']['Running'] = False
        replacements['udp']['Config']['Env'] = ['UNEXPECTED=changed']
        try:
            r.retained_stack(); raise AssertionError('UDP configuration drift accepted')
        except ValueError as error:
            assert str(error) == 'RETAINED_CONFIGURATION_CHANGED'
print('PASS: both replacements selected; incomplete UDP switch, running old writer and config drift rejected. No Docker execution.')
