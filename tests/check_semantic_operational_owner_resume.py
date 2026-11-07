#!/usr/bin/env python3
"""Offline effect-order checks: no real manager, network or credential access."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import ExitStack

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE if (HERE / 'resume-current-semantic-operational-owner-20261107.py').exists() else HERE.parent / 'scripts'
def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
r = module('resume', 'resume-current-semantic-operational-owner-20261107.py')
p = module('reader', 'read-current-semantic-policy-20261107.py')
o = module('owner_reader', 'observe-registry-operational-owner-20261024.py')
ISSUER = 'https://issuer.example/realms/ouf'
def token(exp):
    value = {'exp': exp, 'iss': ISSUER, 'azp': 'semantic-fixture', 'scope': 'ouf.authorization.read'}
    body = base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    return ('eyJhbGciOiJSUzI1NiJ9.' + body + '.U1lOVEhFVElD').encode()
doc = {'Id': 'a'*64, 'Image': 'sha256:'+'b'*64, 'Config': {}, 'HostConfig': {}, 'NetworkSettings': {},
       'State': {'Pid': 123, 'StartedAt': 'fixture', 'Running': True, 'Restarting': False},
       'Mounts': [{'Type': 'bind', 'RW': False, 'Source': '/private/semantic', 'Destination': '/run/semantic'}]}
mount = {'gid': 10001, 'sameFileAsCurrentHostSource': True}
values = {'ouf.authorization.registry-token-file': '/run/semantic/token',
          'ouf.authorization.registry-url': 'https://policy.example'+p.POLICY_PATH,
          'ouf.authorization.refresh-seconds': '30', 'ouf.iam.issuer': ISSUER}
c = {'destinations': {'installationRoot': '/private/owner', 'ledgerRoot': '/private/ledger'},
     'serviceUnitPath': '/etc/systemd/system/'+r.SERVICE,
     'ownerInputs': {'binding': {'output_directory': '/private/semantic', 'output_member': 'token',
        'output_gid': 10001, 'endpoint': ISSUER+'/protocol/openid-connect/token',
        'client_id': 'semantic-fixture', 'scope': 'ouf.authorization.read'}, 'iamProfile': {'issuer': ISSUER}}}
START = '/usr/bin/python3 -I -B -S /private/owner/capsule.py worker --configuration /private/owner/configuration.json --configuration-sha256 fixture'
UNIT = ('[Service]\nExecStart=:'+START+'\n').encode()
def service():
    row = {k: '' for k in r.PROPERTIES}
    row.update(LoadState='loaded', UnitFileState='disabled', ActiveState='inactive', SubState='dead',
               MainPID='0', NRestarts='0', Result='success', ExecMainStatus='0', Type='simple',
               User='root', Restart='on-failure', RootDirectory='/private/owner/sandbox',
               NoNewPrivileges='yes', FragmentPath=c['serviceUnitPath'],
               NeedDaemonReload='no', SendSIGKILL='yes', RuntimeDirectoryPreserve='no', TimeoutStopUSec='35s',
               ExecStart='{ path=/usr/bin/python3 ; argv[]='+START+' ; ignore_errors=no ; }')
    return row
def scenario(*, legacy_masked=True, initial='ACTIVE', already=False, fresh=False, wrong_output=False,
             wrong_command=False, start_failure=False, policy_status=200, publication='ACTIVE', drift=False,
             capture=False, capture_bad_bytes=False, omit_hooks=False, missing_scalar=False, nonempty_typed_hook=False):
    state = {'commands': [], 'policyCalls': 0, 'claims': 0, 'running': already, 'enabled': False}
    temporary = tempfile.TemporaryDirectory(dir=HERE)
    root = Path(temporary.name)
    override = root / 'capture.conf'
    network = root / 'network.conf'
    network.write_bytes(b'[Service]\nIPAddressAllow=192.0.2.10/32\n')
    if capture:
        override.write_bytes(r.CAPTURE_BYTES + (b'#changed\n' if capture_bad_bytes else b''))
    config = copy.deepcopy(c)
    if wrong_output: config['ownerInputs']['binding']['output_directory'] = '/wrong'
    confighash = o.digest(o.encoded(config))
    def unit(name):
        if name in r.LEGACY:
            return dict(LoadState='masked' if legacy_masked else 'loaded', ActiveState='inactive',
                        UnitFileState='masked', SubState='dead')
        row = service()
        row['DropInPaths'] = str(network)
        if override.exists():
            row.update(Restart='no', SendSIGKILL='no', RuntimeDirectoryPreserve='yes', TimeoutStopUSec='2min')
            row['DropInPaths'] += ' ' + str(override)
        if omit_hooks:
            for key in r.START_HOOKS: row.pop(key)
        if missing_scalar: row.pop('FragmentPath')
        if state['running']: row.update(ActiveState='active', SubState='running', MainPID='456')
        if state['enabled']: row['UnitFileState'] = 'enabled'
        if wrong_command: row['ExecStart'] = row['ExecStart'].replace('capsule.py', 'other.py')
        return row
    def cmd(*args):
        state['commands'].append(args)
        if args == ('start', r.SERVICE):
            if start_failure: return SimpleNamespace(returncode=1)
            state['running'] = True
        elif args == ('enable', r.SERVICE): state['enabled'] = True
        elif args == ('daemon-reload',):
            assert not override.exists()
            assert (root / 'backup' / 'capture-override.conf').read_bytes() == r.CAPTURE_BYTES
        else: raise AssertionError(args)
        return SimpleNamespace(returncode=0)
    def current_token(): return token(2000 if fresh or state['running'] else 900)
    def object_at(path, *args, **kwargs):
        if str(path) == o.REVIEW:
            return {'configuration': config, 'serviceUnit': {'path': config['serviceUnitPath'], 'sha256': 'unit'}}
        if str(path).endswith('configuration.json'): return config
        kind = publication if state['running'] else initial
        return {'schema': 'ouf.registry-operational-token-ledger.v1', 'installationHash': confighash,
            'state': kind, 'reason': 'TOKEN_ATOMICALLY_PUBLISHED', 'priorControlledAttempts': 321,
            'attempts': 5, 'cumulativeAttempts': 326, 'publications': 2, 'consecutiveFailures': 0,
            'version': 20, 'lastWall': 900, 'nextWall': None, 'tokenExpiresWall': 2000,
            'tokenHash': hashlib.sha256(current_token()).hexdigest()}
    def claim(*args): state['claims'] += 1; return '/private/attempt.json'
    def policy(*args):
        state['policyCalls'] += 1
        return {'httpStatus': policy_status, 'activePolicyResponseRead': policy_status == 200}
    changed = copy.deepcopy(doc)
    if drift: changed['Config'] = {'unexpected': True}
    runtime = {'retained_semantic': lambda _: ({'semantic': doc['Id']}, {doc['Id']: doc}),
        'semantic_process': lambda _: {'processKind': 'APPLICATION_RUNNING'},
        'inspect': lambda _: {doc['Id']: changed}}
    reader = {'declarations': lambda _: (values, {}), 'mounted_read': lambda *a: (current_token(), mount),
        'token_metadata': p.token_metadata, 'endpoint': p.endpoint, 'policy_get': policy}
    owner = dict(vars(o), CONFIG_SHA=confighash, object_at=object_at,
                 read=lambda path, *a: UNIT if str(path) == c['serviceUnitPath'] else Path(path).read_bytes())
    def bus(*args):
        if args[0] == 'call': return 'o "/org/freedesktop/systemd1/unit/test_service"'
        assert args[0] == 'get-property' and args[-3:] == r.START_HOOKS
        return '\n'.join(['a(sasbttttuii) '+('1' if nonempty_typed_hook else '0')] * 3)
    def backup_dir(*args, **kwargs):
        target = root / 'backup'; target.mkdir(); return str(target)
    report = {}
    with ExitStack() as stack:
        stack.enter_context(patch.object(r, 'unit_read', unit)); stack.enter_context(patch.object(r, 'command', cmd))
        stack.enter_context(patch.object(r, 'claim_start', claim))
        stack.enter_context(patch.object(r, 'CAPTURE_OVERRIDE', override))
        stack.enter_context(patch.object(r, 'bus_read', bus))
        stack.enter_context(patch.object(r.tempfile, 'mkdtemp', backup_dir))
        stack.enter_context(patch.object(r.time, 'time', lambda: 1000))
        stack.enter_context(patch.object(r.time, 'sleep', lambda _: None))
        try: r.execute(report, runtime, reader, owner)
        except RuntimeError as exc: report['reason'] = str(exc)
    state['overrideStillPresent'] = override.exists()
    state['networkUnchanged'] = network.read_bytes() == b'[Service]\nIPAddressAllow=192.0.2.10/32\n'
    assert state['networkUnchanged']
    assert 'eyJ' not in json.dumps(report)
    temporary.cleanup()
    return report, state

report, state = scenario()
assert report['status'] == r.SUCCESS and state['commands'] == [('start', r.SERVICE), ('enable', r.SERVICE)]
assert state['policyCalls'] == 1 and state['claims'] == 1
report, state = scenario(already=True, fresh=True)
assert report['status'] == r.SUCCESS and state['commands'] == [('enable', r.SERVICE)] and not state['claims']
cases = [({'legacy_masked': False}, 'LEGACY_PRODUCER_MUST_REMAIN_MASKED_INACTIVE'),
         ({'wrong_output': True}, 'INSTALLED_OWNER_OUTPUT_NOT_CURRENT_MOUNTED_TOKEN'),
         ({'wrong_command': True}, 'LOADED_WORKER_COMMAND_DIFFERS_FROM_REVIEW'),
         ({'initial': 'BLOCKED'}, 'OWNER_LEDGER_REQUIRES_RECONCILIATION'),
         ({'initial': 'REVOKED'}, 'OWNER_LEDGER_REQUIRES_RECONCILIATION'),
         ({'initial': 'DISPATCHING'}, 'PREVIOUS_GRANT_OR_PUBLICATION_OUTCOME_UNKNOWN'),
         ({'initial': 'PUBLISHING'}, 'PREVIOUS_GRANT_OR_PUBLICATION_OUTCOME_UNKNOWN'),
         ({'drift': True}, 'SEMANTIC_RUNTIME_CHANGED')]
for kwargs, reason in cases:
    report, state = scenario(**kwargs)
    assert report.get('reason') == reason, report
    assert not state['commands'] and not state['policyCalls'] and not state['claims']
for kwargs, reason in [({'start_failure': True}, 'EXISTING_OPERATIONAL_OWNER_START_FAILED'),
                      ({'publication': 'BLOCKED'}, 'OWNER_LEDGER_REQUIRES_RECONCILIATION'),
                      ({'policy_status': 401}, 'FRESH_TOKEN_POLICY_GET_NOT_SUCCESSFUL')]:
    report, state = scenario(**kwargs)
    assert report.get('reason') == reason, report
    assert state['commands'] == [('start', r.SERVICE)] and state['claims'] == 1
assert all('unmask' not in call and 'restart' not in call for call in state['commands'])
report, state = scenario(capture=True, omit_hooks=True)
assert report['status'] == r.SUCCESS and report['captureOverrideRemoved']
assert report['serviceAfterOverrideRestore']['Restart'] == 'on-failure'
assert report['omittedTextProperties'] == list(r.START_HOOKS)
assert state['commands'] == [('daemon-reload',), ('start', r.SERVICE), ('enable', r.SERVICE)]
assert not state['overrideStillPresent'] and report['unrelatedDropInsPreserved']
for kwargs, reason in [({'capture': True, 'capture_bad_bytes': True}, 'CAPTURE_OVERRIDE_BYTES_CHANGED'),
                      ({'capture': True, 'initial': 'BLOCKED'}, 'OWNER_LEDGER_REQUIRES_RECONCILIATION'),
                      ({'capture': True, 'already': True}, 'RUNNING_OWNER_WITH_CAPTURE_OVERRIDE_REQUIRES_REVIEW'),
                      ({'omit_hooks': True, 'nonempty_typed_hook': True}, 'TYPED_EMPTY_START_HOOKS_REQUIRED'),
                      ({'missing_scalar': True}, 'SERVICE_METADATA_INCOMPLETE')]:
    report, state = scenario(**kwargs)
    assert report.get('reason') == reason, report
    assert not state['commands'] and not state['claims'] and not state['policyCalls']
    if kwargs.get('capture'): assert state['overrideStillPresent']
print('PASS: 19 offline scenarios, including omitted text properties with typed empty/nonempty hooks, exact capture override restoration and preservation of unrelated drop-ins')
