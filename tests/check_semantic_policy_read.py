#!/usr/bin/env python3
"""Offline checks: selected configuration, mounted token, bounded GET and output."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'read-current-semantic-policy-20261107.py'
if not SOURCE.exists():
    SOURCE = HERE.parent / 'scripts' / SOURCE.name
spec = importlib.util.spec_from_file_location('reader', SOURCE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
assert callable(r.runtime_helper()['retained_semantic'])

def rejected(fn, code):
    try:
        fn()
        raise AssertionError('accepted: ' + code)
    except RuntimeError as exc:
        assert str(exc) == code, str(exc)

def jwt(exp):
    encoded = base64.urlsafe_b64encode(json.dumps({'exp': exp, 'scope': 'PRIVATE_SCOPE_SENTINEL'}).encode()).decode().rstrip('=')
    return ('eyJhbGciOiJub25lIn0.' + encoded + '.c2lnbmF0dXJl').encode()

doc = {'Id': 'a'*64, 'Image': 'sha256:'+'b'*64, 'Config': {'Env': [
    'OUF_AUTHORIZATION_REGISTRY_URL=https://example.invalid'+r.POLICY_PATH,
    'OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE=/run/selected.jwt',
    'OUF_AUTHORIZATION_REFRESH_SECONDS=30',
    'OUF_AUTHORIZATION_MAX_STALENESS_SECONDS=300'], 'Cmd': [], 'Entrypoint': []},
    'State': {'Pid': os.getpid(), 'StartedAt': 'fixture', 'Running': True, 'Restarting': False},
    'HostConfig': {}, 'Mounts': [], 'NetworkSettings': {}}
values, summary = r.declarations(doc)
assert values['ouf.authorization.registry-token-file'] == '/run/selected.jwt'
assert summary['refresh-seconds'] == 30 and not summary['runtimeLoadedPolicyRead']
alias = copy.deepcopy(doc)
alias['Config']['Env'][1] = 'OUF_AUTHORIZATION_REGISTRYTOKENFILE=/run/alias.jwt'
assert r.declarations(alias)[0]['ouf.authorization.registry-token-file'] == '/run/alias.jwt'
conflict = copy.deepcopy(doc)
conflict['Config']['Env'].append('SPRING_APPLICATION_JSON={"ouf":{"authorization":{"registry-url":"https://other.invalid"}}}')
rejected(lambda: r.declarations(conflict), 'CONFLICTING_SELECTED_PROPERTY_DECLARATIONS')
conflict['Config']['Env'][-1] = 'JAVA_TOOL_OPTIONS=-Douf.authorization.registry-token-file=/run/other.jwt'
rejected(lambda: r.declarations(conflict), 'CONFLICTING_SELECTED_PROPERTY_DECLARATIONS')
for bad in ('http://example.invalid'+r.POLICY_PATH, 'https://u:p@example.invalid'+r.POLICY_PATH,
            'https://example.invalid'+r.POLICY_PATH+'?leak=1', 'https://example.invalid/wrong',
            'https://example.invalid:8443'+r.POLICY_PATH):
    rejected(lambda: r.endpoint(bad), 'EXPECTED_HTTPS_POLICY_ENDPOINT_REQUIRED')
assert r.token_metadata(jwt(100), 101)[1]['expiredAtRead']
assert not r.token_metadata(jwt(100), 99)[1]['expiredAtRead']
assert r.token_metadata(jwt(100), 99)[1]['signatureVerifiedLocally'] is False
rejected(lambda: r.token_metadata(b'bad token', 100), 'JWT_TOKEN_SHAPE_INVALID')
assert r.policy_summary(401, b'SECRET')['httpStatus'] == 401
envelope = {'bundleId': 'ouf-lab-authorization', 'bundleVersion': 61,
            'contentHash': r.POLICY61_HASH, 'bundle': {'capabilities': [{'capabilityId': 'ouf.semantic.search'}],
                                                     'grants': [{'capabilityId': 'ouf.semantic.search'}]}}
result = r.policy_summary(200, json.dumps(envelope).encode())
assert result['returnedHashMatchesObservedPolicy61'] and result['semanticSearchDeclared']
assert not result['applicationLoadedPolicyProven'] and not result['applicationJvmTransportTested']

class FakeResponse:
    status = 302
    def read(self, n): raise AssertionError('redirect body must not be read')
class FakeConnection:
    requests = []
    def __init__(self, *args, **kwargs): pass
    def request(self, method, path, headers): self.requests.append((method, path, headers))
    def getresponse(self): return FakeResponse()
    def close(self): pass
with patch.object(r.http.client, 'HTTPSConnection', FakeConnection):
    assert r.policy_get(r.endpoint(values['ouf.authorization.registry-url']), 'SYNTHETIC_TOKEN')['httpStatus'] == 302
assert len(FakeConnection.requests) == 1 and FakeConnection.requests[0][0] == 'GET'

with tempfile.TemporaryDirectory(dir=HERE) as directory:
    token_path = Path(directory) / 'token.jwt'
    token_path.write_bytes(jwt(100))
    os.chmod(token_path, 0o400)
    mounted = copy.deepcopy(doc)
    mounted['Mounts'] = [{'Destination': str(token_path), 'Source': str(token_path), 'Type': 'bind', 'RW': False}]
    # Local sandbox has no /proc/PID/root. Substitute only that root open;
    # remaining fd-relative traversal and file reads exercise real temporary files.
    original_open = os.open
    def fixture_root(path, flags, *args, **kwargs):
        if path == '/proc/' + str(os.getpid()) + '/root':
            path = '/'
        return original_open(path, flags, *args, **kwargs)
    with patch.object(r.os, 'open', side_effect=fixture_root):
        raw, meta = r.mounted_read(mounted, str(token_path), 65536)
        assert raw == jwt(100) and meta['sameFileAsCurrentHostSource']
        mounted['Mounts'][0]['Source'] = str(Path(directory) / 'absent')
        assert r.mounted_read(mounted, str(token_path), 65536)[1]['sameFileAsCurrentHostSource'] is False
    mounted['Mounts'][0]['RW'] = True
    rejected(lambda: r.mounted_read(mounted, str(token_path), 65536), 'READ_ONLY_BIND_REQUIRED')

runtime = {'retained_semantic': lambda checks: (checks.update(semanticConfigurationCheck={'matches': True},
                   retainedConfigurationMismatches=[]) or ({'semantic': doc['Id']}, {doc['Id']: doc})),
           'semantic_process': lambda d: {'processKind': 'APPLICATION_RUNNING'},
           'inspect': lambda cid: {doc['Id']: copy.deepcopy(doc)}}
with patch.object(r, 'mounted_read', return_value=(jwt(100), {'readFromApplicationMountView': True})), \
     patch.object(r, 'policy_get', return_value=r.policy_summary(401, b'')) as get:
    report = {}
    r.execute(report, runtime)
    assert report['status'] == 'SEMANTIC_POLICY_READ_COMPLETE' and get.call_count == 1
    emitted = json.dumps(report)
    assert 'PRIVATE_SCOPE_SENTINEL' not in emitted and jwt(100).decode() not in emitted
    assert '/run/selected.jwt' not in emitted
    drift = copy.deepcopy(doc)
    drift['State']['Pid'] += 1
    runtime['inspect'] = lambda cid: {doc['Id']: drift}
    rejected(lambda: r.execute({}, runtime), 'SEMANTIC_RUNTIME_CHANGED_DURING_READ')
print('PASS: declaration conflicts, alias handling, URL constraints, expiry, mount view, single GET/no redirects, non-disclosure and runtime drift')
