"""Focused replacement sequencing fixture; native Docker/VPS are not simulated as proven."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('switch', Path(sys.argv[1]))
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)


def original(image):
    return {'Id': 'a' * 64, 'Name': '/ouf-onboarding', 'Image': image,
        'State': {'Running': True, 'Restarting': False, 'Status': 'running', 'Pid': 123,
                  'StartedAt': 'original-start'},
        'Config': {'Image': 'installed:tag', 'User': '10003:10003',
            'Entrypoint': ['java', '-jar', '/app/application.jar'], 'Cmd': [],
            'Env': ['OUF_ONBOARDING_STAGING_ENDPOINT=http://ouf-minio:9000',
                    'OUF_ONBOARDING_STAGING_BUCKET=ouf-managed-files',
                    'JAVA_TOOL_OPTIONS=-Xmx512m', 'UNRELATED=keep'], 'Labels': {'existing': 'kept'}},
        'HostConfig': {'NetworkMode': s.BACKEND, 'AutoRemove': False, 'VolumesFrom': None,
            'Memory': 600000000, 'PidsLimit': 128, 'SecurityOpt': ['no-new-privileges'],
            'Binds': ['/retained/secrets:/run/secrets:ro'], 'Mounts': [],
            'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0},
            'PortBindings': {}, 'OomKillDisable': False},
        'Mounts': [{'Type': 'bind', 'Source': '/retained/secrets', 'Destination': '/run/secrets',
                    'RW': False, 'Propagation': 'rprivate'}],
        'NetworkSettings': {'Networks': {s.BACKEND: {'NetworkID': 'backend-id',
            'IPAddress': '172.24.0.12', 'GlobalIPv6Address': '', 'Gateway': '172.24.0.1',
            'MacAddress': '02:42:ac:18:00:0c', 'Aliases': ['ouf-onboarding', 'owner-alias'],
            'IPAMConfig': None}}}}


class SwitchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.helper = s.copier()
        self.app = original(self.helper.APP_IMAGE)

    def test_request_preserves_resources_mounts_image_and_routes(self):
        request = s.make_request(self.app, self.root, 'token', self.helper.APP_IMAGE)
        env = dict(row.split('=', 1) for row in request['Env'])
        self.assertEqual(request['Image'], self.app['Image'])
        self.assertEqual(request['HostConfig']['Memory'], 600000000)
        self.assertEqual(request['HostConfig']['Binds'], self.app['HostConfig']['Binds'])
        self.assertEqual(request['HostConfig']['SecurityOpt'], ['no-new-privileges'])
        self.assertEqual(env['UNRELATED'], 'keep')
        self.assertIn('-Xmx512m', env['JAVA_TOOL_OPTIONS'])
        self.assertEqual(request['NetworkingConfig']['EndpointsConfig'][s.BACKEND]['IPAMConfig']['IPv4Address'], '172.24.0.12')
        self.assertEqual(request['NetworkingConfig']['EndpointsConfig'][s.BACKEND]['Aliases'], ['ouf-onboarding', 'owner-alias'])
        self.assertEqual(env['OUF_ONBOARDING_STAGING_ENDPOINT'], 'https://ouf-seaweedfs-stage:9002')
        self.assertTrue(request['HostConfig']['Mounts'][-1]['ReadOnly'])

    def test_staging_cli_override_replaced_and_custom_truststore_rejected(self):
        self.app['Config']['Cmd'] = ['--server.port=8081', '--ouf.onboarding.staging.endpoint',
                                     'http://old:9000', '--ouf.onboarding.staging.bucket=old']
        request = s.make_request(self.app, self.root, 'token', self.helper.APP_IMAGE)
        self.assertNotIn('http://old:9000', request['Cmd'])
        self.assertEqual(sum(a.startswith('--ouf.onboarding.staging.endpoint=') for a in request['Cmd']), 1)
        self.assertIn('--server.port=8081', request['Cmd'])
        self.app['Config']['Env'].append('JDK_JAVA_OPTIONS=-Djavax.net.ssl.trustStore=/custom')
        with self.assertRaisesRegex(RuntimeError, '^EXISTING_CUSTOM_TRUSTSTORE_REQUIRES_MERGE$'):
            s.make_request(self.app, self.root, 'token', self.helper.APP_IMAGE)

    def run_switch(self, fail=None):
        h = self.helper
        h.ROOT = self.root; h.PLAN = self.root / 'plan.json'; h.BINDINGS = self.root / 'bindings'
        (h.BINDINGS / 'config/tls').mkdir(parents=True)
        (h.BINDINGS / 'config/tls/ca.pem').write_bytes(b'fixture-ca')
        client = h.BINDINGS / 'clients/onboarding'; client.mkdir(parents=True)
        (client / 'binding.private.json').write_text(json.dumps({'environment': {
            'OUF_ONBOARDING_STAGING_ENDPOINT': 'https://ouf-seaweedfs-stage:9002',
            'OUF_ONBOARDING_STAGING_BUCKET': h.BUCKET}}))
        for name in ('access-key', 'secret-key'):
            (client / name).write_text('fixture-' + name)
        prior = self.root / 'prior'; prior.mkdir()
        manifest = [{'key': 'managed-files/fixture', 'sha256': s.digest(b'fixture-body'),
                     'size': 12, 'metadata': {}}]
        manifest_raw = json.dumps(manifest).encode()
        manifest_sha = s.digest(manifest_raw)
        (prior / 'objects-verified.private.json').write_bytes(manifest_raw)
        (prior / 'result.json').write_text(json.dumps({'status': 'CURRENT_ONBOARDING_OBJECTS_ALIGNED', 'manifestSha256': manifest_sha}))
        minio = copy.deepcopy(self.app)
        minio.update(Id='b' * 64, Name='/ouf-minio', Image='sha256:source')
        sea = copy.deepcopy(self.app)
        sea.update(Id='c' * 64, Name='/ouf-seaweedfs-stage', Image=h.SEA_IMAGE)
        sea['NetworkSettings']['Networks'] = {s.PRIVATE: {'IPAddress': '172.30.0.2'}}
        roles = {'onboarding': {'containerId': self.app['Id']},
                 'minio': {'containerId': minio['Id'], 'nativeImage': minio['Image']}}
        h.PLAN.write_text(json.dumps({'roles': roles})); h.PLAN_SHA = s.digest(h.PLAN.read_bytes())
        docs = {row['Id']: copy.deepcopy(row) for row in [self.app, minio, sea]}
        events = []
        class FakeEngine:
            def inspect(self, ref):
                for doc in docs.values():
                    if ref in (doc['Id'], doc['Name'].lstrip('/')):
                        return copy.deepcopy(doc)
                raise AssertionError('fixture reference missing')

            def request(self, method, path, body=None, **kwargs):
                events.append((method, path))
                if method == 'GET' and path == '/networks/' + s.PRIVATE:
                    return {'Internal': True, 'Driver': 'bridge'}
                if path.startswith('/containers/create?'):
                    candidate = copy.deepcopy(self_outer.app)
                    candidate.update(Id='d' * 64, Name='/ouf-onboarding')
                    candidate['Config'] = {k: copy.deepcopy(v) for k, v in body.items() if k not in ('HostConfig', 'NetworkingConfig')}
                    candidate['HostConfig'] = copy.deepcopy(body['HostConfig'])
                    candidate['State'].update(Status='created', Running=False, Pid=0)
                    candidate['Mounts'].append({'Type': 'bind', 'Source': body['HostConfig']['Mounts'][-1]['Source'],
                        'Destination': s.DEST, 'RW': False, 'Propagation': 'rprivate'})
                    candidate['NetworkSettings']['Networks'][s.PRIVATE] = {'IPAddress': '172.30.0.3'}
                    docs[candidate['Id']] = candidate
                    if fail == 'lost-create':
                        raise OSError('simulated lost response')
                    return {'Id': candidate['Id']}
                if path.startswith('/networks/') and path.endswith('/disconnect'):
                    docs[body['Container']]['NetworkSettings']['Networks'].pop(s.BACKEND)
                    return None
                if path.startswith('/networks/') and path.endswith('/connect'):
                    docs[body['Container']]['NetworkSettings']['Networks'][s.BACKEND] = copy.deepcopy(self_outer.app['NetworkSettings']['Networks'][s.BACKEND])
                    return None
                if path.startswith('/containers/'):
                    cid = path.split('/')[2].split('?')[0]
                    doc = docs[cid]
                    if method == 'DELETE':
                        del docs[cid]; return None
                    if '/update' in path:
                        doc['HostConfig'].update(copy.deepcopy(body))
                    elif '/stop?' in path:
                        doc['State'].update(Status='exited', Running=False, Pid=0)
                    elif '/rename?' in path:
                        doc['Name'] = '/' + path.split('name=')[1]
                    elif '/start' in path:
                        doc['State'].update(Status='running', Running=True, Pid=999)
                        if cid == 'd' * 64 and fail == 'lost-start':
                            raise OSError('simulated lost start response')
                    else:
                        raise AssertionError(path)
                    return None
                raise AssertionError((method, path))
        self_outer = self
        engine = FakeEngine()
        def fake_docker(*args, **kwargs):
            output = b''
            if args[0:2] == ('container', 'ls'):
                output = b'\n'.join(json.dumps({'ID': d['Id'], 'Names': d['Name'].lstrip('/')}).encode() for d in docs.values())
            elif args[-2:] in (('id', '-u'), ('id', '-g')):
                output = b'10003\n'
            return types.SimpleNamespace(returncode=0, stdout=output, stderr=b'')
        class FakeS3:
            def __init__(self, *args, **kwargs): self.calls = 0
            def request(self, *args, **kwargs):
                self.calls += 1
                return 200, b'fixture-body', []
        rows = [{'Key': 'managed-files/fixture', 'Size': 12, 'ETag': 'fixture-etag', 'LastModified': 'fixture'}]
        def align(source, destination, given_rows, report, journal):
            self.assertFalse(docs[self.app['Id']]['State']['Running'])
            events.append(('ALIGN', 'original-stopped'))
            if fail == 'copy':
                raise RuntimeError('EXISTING_TARGET_OBJECT_DIFFERS')
            report['objectsAlreadyMatched'] += 1
            return manifest
        h.source_credentials = lambda *args: (('synthetic-user', 'synthetic-secret'), 'us-east-1')
        h.S3 = FakeS3; h.listing = lambda *args: copy.deepcopy(rows); h.align = align
        def fake_trust(app, folder, ca, report):
            (folder / 'truststore.p12').write_bytes(b'fixture-trust')
        report = {'status': 'INCOMPLETE', 'objectsAlreadyMatched': 0, 'objectsCopiedAndVerified': 0, 'putAttempts': 0}
        with patch.multiple(s, ROOT=self.root, MARKER=self.root / 'current.json', PREVIOUS=prior,
                MANIFEST_SHA=manifest_sha, copier=lambda: h, Engine=lambda: engine, docker=fake_docker,
                prepare_truststore=fake_trust, readiness=lambda *args: True), patch.object(s.os, 'chown'):
            if fail:
                with self.assertRaises((RuntimeError, OSError)):
                    s.execute(report)
            else:
                s.execute(report)
        return report, docs, events

    def test_success_freezes_original_before_align_then_starts_new(self):
        report, docs, events = self.run_switch()
        self.assertEqual(report['status'], 'ONBOARDING_SEAWEEDFS_READY')
        self.assertFalse(docs['a' * 64]['State']['Running'])
        self.assertTrue(docs['d' * 64]['State']['Running'])
        self.assertTrue(report['sourceSnapshotUnchangedWhileStopped'])
        self.assertLess(events.index(('ALIGN', 'original-stopped')),
                        events.index(('POST', '/containers/' + 'd' * 64 + '/start')))

    def test_copy_failure_restores_original_without_starting_replacement(self):
        report, docs, events = self.run_switch('copy')
        self.assertTrue(report['originalRestoredBeforeReplacementStart'])
        self.assertTrue(docs['a' * 64]['State']['Running'])
        self.assertNotIn('d' * 64, docs)
        self.assertFalse((self.root / 'current.json').exists())

    def test_lost_create_response_removes_only_created_candidate_and_restores_original(self):
        report, docs, events = self.run_switch('lost-create')
        self.assertTrue(report['originalRestoredBeforeReplacementStart'])
        self.assertTrue(docs['a' * 64]['State']['Running'])
        self.assertEqual(docs['a' * 64]['Name'], '/ouf-onboarding')
        self.assertNotIn('d' * 64, docs)

    def test_lost_start_response_never_restarts_minio_writer(self):
        report, docs, events = self.run_switch('lost-start')
        self.assertFalse(docs['a' * 64]['State']['Running'])
        self.assertTrue(docs['d' * 64]['State']['Running'])
        self.assertIsNone(report['applicationBindingsChanged'])
        self.assertNotIn(('POST', '/containers/' + 'a' * 64 + '/start'), events)
        self.assertTrue((self.root / 'current.json').exists())


unittest.main(argv=[sys.argv[0]])
