"""Local orchestration/secret tests; not an AWS SDK or SeaweedFS integration test."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

base = Path(__file__).resolve().parent
source = next(p for p in (base / 'probe-current-udp-seaweedfs-20261107.py',
                         base.parent / 'scripts/probe-current-udp-seaweedfs-20261107.py') if p.exists())
spec = importlib.util.spec_from_file_location('udp_probe', source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
assert hashlib.sha256(base64.b64decode(m.CLASS_B64)).hexdigest() == m.CLASS_SHA
secret = 'DO_NOT_EMIT_SECRET'
json_input = json.dumps({'spring': {'datasource': {'password': secret}},
    'ouf': {'udp': {'lake': {'s3': {'endpoint': 'http://ouf-minio:9000', 'bucket': 'ouf-udp',
                                   'region': 'us-east-1', 'path-style': True}}}}})
selected = m.source_json_storage(json_input)
assert len(selected['storageDeclarations']) == 4 and secret not in json.dumps(selected)
flat = m.source_json_storage(json.dumps({'ouf.udp.lake.s3.endpoint': 'https://user:' + secret + '@host:9002',
                                        'unrelated': secret}))
assert secret not in json.dumps(flat) and flat['storageDeclarations'][0]['value'] == '<noncanonical-or-sensitive>'
assert m.safe_setting('endpoint', 42) == '<noncanonical-or-sensitive>'
try:
    m.source_json_storage('{"key":1,"key":2}')
    raise AssertionError('duplicate JSON accepted')
except RuntimeError as error:
    assert str(error) == 'SOURCE_JSON_DUPLICATE_KEY'


def scenario(mode):
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        bindings = root / 'bindings'
        client = bindings / 'clients/udp'
        client.mkdir(parents=True)
        (bindings / 'config/tls').mkdir(parents=True)
        ca = b'fixture-ca'
        (bindings / 'config/tls/ca.pem').write_bytes(ca)
        target = {'OUF_UDP_S3_ENDPOINT': m.ENDPOINT, 'OUF_UDP_S3_BUCKET': m.BUCKET,
                  'OUF_UDP_S3_REGION': 'us-east-1', 'OUF_UDP_S3_PATH_STYLE': 'true'}
        if mode == 'target_drift':
            target['OUF_UDP_S3_BUCKET'] = 'different-bucket'
        (client / 'binding.private.json').write_text(json.dumps({'environment': target}))
        (client / 'credentials').write_text('[default]\naws_access_key_id=fixture\naws_secret_access_key=' + secret + '\n')
        app = {'Id': m.CID, 'Image': m.IMAGE, 'State': {'Running': True, 'StartedAt': 'fixture'},
               'Config': {'Env': ['SPRING_APPLICATION_JSON=' + json_input]},
               'NetworkSettings': {'Networks': {'ouf-backend': {}}}}
        sea = {'Image': m.SEA_IMAGE, 'State': {'Running': True},
               'NetworkSettings': {'Networks': {m.NETWORK: {}}}, 'HostConfig': {'PortBindings': {}},
               'Mounts': [{'Source': str(bindings / 'config'), 'Destination': '/config', 'RW': False}]}
        operations = []
        def inspected(ref):
            assert ref in (m.CID, m.SEA)
            return copy.deepcopy(app if ref == m.CID else sea)
        def docker(*args, **kwargs):
            operations.append(args)
            if args[:2] == ('network', 'inspect'):
                result = json.dumps([{'Internal': True}]).encode()
            elif args[:2] == ('image', 'inspect'):
                result = b'[{"Config":{"Env":[]}}]'
            elif args[0] == 'create':
                assert args[args.index('--network') + 1] == m.NETWORK
                assert m.IMAGE in args
                assert 'AWS_SHARED_CREDENTIALS_FILE=/probe/credentials' in args
                assert secret not in ' '.join(args)
                result = b'f' * 64
            elif args[0] in ('start', 'exec'):
                assert args[1] == 'f' * 64
                result = b''
            else:
                raise AssertionError(args)
            return SimpleNamespace(returncode=0, stdout=result, stderr=b'')
        def java(cid, launcher, phase, key):
            assert cid == 'f' * 64 and key.startswith('diagnostics/seaweedfs-client/')
            if phase == 'check':
                return {'status': 'JAVA_CLIENT_READY', 'exitCode': 0}
            if mode == 'transfer_failure':
                return {'status': 'JAVA_CLIENT_FAILED', 'exitCode': 2}
            return {'status': 'PUT_HEAD_GET_MATCH', 'exitCode': 0, 'bodyMatches': True, 'metadataMatches': True}
        def cleanup(args, **kwargs):
            assert args[:len(m.DOCKER)] == m.DOCKER
            assert args[len(m.DOCKER):len(m.DOCKER) + 2] == ('rm', '-f')
            assert args[-1].startswith('ouf-udp-s3-probe-')
            if mode == 'cleanup_timeout':
                raise subprocess.TimeoutExpired('synthetic-cleanup', 20)
            return SimpleNamespace(returncode=0)
        report = {}
        failure = None
        with contextlib.ExitStack() as stack:
            for name, value in {'ROOT': root, 'BINDINGS': bindings, 'CA_SHA': m.sha(ca),
                                'inspect': inspected, 'original_jar': lambda app: 'fixture.Launcher',
                                'docker': docker, 'java': java}.items():
                stack.enter_context(patch.object(m, name, value))
            stack.enter_context(patch.object(m.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(m.os, 'chown', return_value=None))
            # Test runner is unprivileged; production requires root for private UID-owned files.
            stack.enter_context(patch.object(m.os, 'chmod', return_value=None))
            stack.enter_context(patch.object(m.subprocess, 'run', side_effect=cleanup))
            try:
                m.run(report)
            except RuntimeError as error:
                failure = str(error)
        assert secret not in json.dumps(report)
        if mode == 'target_drift':
            assert failure == 'PREPARED_TARGET_CHANGED'
            assert not any(op[0] == 'create' for op in operations)
            return
        assert not (Path(report['privateEvidenceDirectory']) / 'credentials').exists()
        assert report['temporaryCredentialCopyRemoved'] is True
        assert report['originalApplicationStillRunningUnchangedImage'] is True
        assert not any(op[0] in ('stop', 'restart', 'rename') for op in operations)
        if mode == 'success':
            assert failure is None and report['status'] == 'UDP_INSTALLED_CLIENT_PUT_HEAD_GET_MATCH'
            assert report['temporaryContainerRemoved'] is True
        elif mode == 'transfer_failure':
            assert failure == 'JAVA_TRANSFER_NOT_VERIFIED' and report['temporaryContainerRemoved'] is True
        else:
            assert failure == 'TEMPORARY_CONTAINER_CLEANUP_FAILED' and report['temporaryContainerRemoved'] is False


for mode in ('success', 'target_drift', 'transfer_failure', 'cleanup_timeout'):
    scenario(mode)
print('PASS: source JSON allowlist/redaction/duplicates; orchestration success, target drift, transfer failure, cleanup timeout; embedded bytecode hash. Real installed SDK/TLS not executed.')
