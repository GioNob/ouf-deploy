"""Disposable APISIX/etcd CI; runs the actual controller CLI, no production inputs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_operational_ingestion_receipt_20261112 as fixture

p = fixture.c


def docker(*args, timeout=90):
    run = subprocess.run(['docker', *args], capture_output=True, timeout=timeout)
    if run.returncode:
        raise AssertionError('Synthetic Docker fixture failed: ' + run.stderr[:2000].decode(errors='replace'))
    return run.stdout.decode().strip()


class NativeQualification(unittest.TestCase):
    def test_cli_plan_then_two_puts_with_exact_readback(self):
        self.assertEqual(os.geteuid(), 0, 'namespace transport requires root')
        prefix = 'ingestion-receipt-fixture-' + str(os.getpid())
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o755)
            evidence = root / 'evidence'; evidence.mkdir(mode=0o700)
            net = docker('network', 'create', prefix)
            self.addCleanup(lambda: docker('network', 'rm', net))
            etcd_name = prefix + '-etcd'
            etcd = docker('run', '-d', '--name', etcd_name, '--network', net,
                          'quay.io/coreos/etcd:v3.5.17', 'etcd',
                          '--listen-client-urls=http://0.0.0.0:2379',
                          '--advertise-client-urls=http://' + etcd_name + ':2379')
            self.addCleanup(lambda: docker('rm', '-f', etcd))
            # Distinct runtime hosts for all three logical services. The fixture
            # proves DNS/network binding, not operational business responses.
            runtime_bindings = {}
            for i, service in enumerate(sorted(fixture.BINDINGS)):
                host = prefix + '-peer-' + str(i)
                peer = docker('run', '-d', '--name', host, '--network', net,
                              'alpine:3.21', 'sleep', '600')
                self.addCleanup(lambda cid=peer: docker('rm', '-f', cid))
                runtime_bindings[service] = host
            target = '/usr/local/apisix/conf/config.yaml'
            key = 'synthetic-native-admin-key-1234567890'
            config = ('apisix:\n  node_listen: 9080\n  extra_lua_path: /usr/local/apisix/conf/?.lua\n'
                      '  lua_module_hook: ouf_json_precision\n'
                      'deployment:\n  role: traditional\n  role_traditional:\n    config_provider: etcd\n'
                      '  admin:\n    admin_listen:\n      ip: 0.0.0.0\n      port: 9180\n'
                      '    allow_admin:\n      - 127.0.0.1/32\n    admin_key:\n'
                      '      - name: admin\n        key: ' + key + '\n        role: admin\n'
                      '  etcd:\n    host:\n      - http://' + etcd_name + ':2379\n')
            config_file = root / 'config.yaml'; config_file.write_text(config)
            assets = p.ROOT / 'tools/chatbot_file_cohort/assets/apisix'
            cid = docker('run', '-d', '--name', prefix + '-apisix', '--network', net,
                         '--env', fixture.NAME + '=' + fixture.ENV_VALUE,
                         '-v', str(config_file) + ':' + target + ':ro',
                         '-v', str(assets / 'ouf_json_precision.lua') + ':/usr/local/apisix/conf/ouf_json_precision.lua:ro',
                         '-v', str(assets / 'jsonschema.lua') + ':/usr/local/apisix/deps/share/lua/5.1/jsonschema.lua:ro',
                         'apache/apisix@sha256:84e6b5e787e9f889ebff88161cb9a16599bafcffa236c6b54c7f779a0655940d')
            self.addCleanup(lambda: docker('rm', '-f', cid))
            engine = p.Docker(shutil.which('docker'), '/var/run/docker.sock')
            publisher = p.load_helper('apply-gateway-analysis-delta-20261108.py')
            deadline = time.monotonic() + 50
            while True:
                doc = engine.inspect(cid)
                try:
                    probe = subprocess.run(['/usr/bin/nsenter', '--target', str(doc['State']['Pid']), '--net',
                        sys.executable, '-I', '-B', '-S', '-c', publisher.ADMIN_CHILD], capture_output=True, timeout=12,
                        input=json.dumps({'method': 'GET', 'path': '/apisix/admin/routes', 'key': key}).encode())
                    if probe.returncode == 0 and json.loads(probe.stdout)['httpStatus'] == 200:
                        break
                except (ValueError, KeyError):
                    pass
                self.assertLess(time.monotonic(), deadline, 'APISIX startup failed')
                time.sleep(1)
            doc = engine.inspect(cid)
            runtime = root / 'runtime.private.json'
            runtime.write_text(json.dumps({'roles': {'apisix': {'containerId': cid, 'nativeImage': doc['Image']}}}))
            runtime.chmod(0o600)
            runtime_sha = p.hashlib.sha256(runtime.read_bytes()).hexdigest()
            args = SimpleNamespace(docker_bin=shutil.which('docker'), docker_socket='/var/run/docker.sock',
                runtime_plan=runtime, runtime_plan_sha256=runtime_sha,
                apisix_config_target=target, admin_key_file=root / 'unused-key')
            admin = p.make_admin(args, fixture.old.report(), engine)
            legacy = fixture.old.fixture(84)
            retained = p.compile_plan(legacy, fixture.A, runtime_bindings, {'synthetic': 'previous-binding'})
            retained['runtimeBinding'] = {'synthetic': 'previous-transport'}
            before = fixture.q.expected_map(p, retained, fixture.A)
            applied_path, applied_sha = fixture.retain(evidence, retained)
            # Foreign routes use valid APISIX HTTP configuration as well.
            for row in before.values():
                ack = admin.put(row['id'], row)
                self.assertIn(ack['httpStatus'], (200, 201), 'synthetic fixture seeding failed')
            self.assertEqual(admin.routes(), before)
            base = [sys.executable, '-I', '-B', str(p.ROOT / 'scripts/apply-operational-ingestion-receipt-20261112.py'),
                    '--runtime-plan', str(runtime), '--runtime-plan-sha256', runtime_sha,
                    '--evidence-root', str(evidence), '--admin-key-file', str(args.admin_key_file),
                    '--docker-bin', args.docker_bin, '--docker-socket', args.docker_socket,
                    '--apisix-config-target', target,
                    '--applied-plan', str(applied_path), '--applied-plan-sha256', applied_sha,
                    '--ingestion-receipt-key-env', fixture.NAME]
            for service, host in runtime_bindings.items():
                base.extend(['--service-binding', service + '=' + host])
            def cli(*mode):
                result = subprocess.run(base + list(mode), capture_output=True, text=True, timeout=180)
                self.assertEqual(result.stderr, '')
                public = json.loads(result.stdout)  # exactly one public JSON
                for secret in (*fixture.old.SECRETS, key, fixture.NAME, fixture.ENV_VALUE):
                    self.assertNotIn(secret, result.stdout)
                return result.returncode, public
            code, planned = cli('--plan')
            self.assertEqual((code, planned['status'], planned['adminPutAttempts']),
                             (0, 'INGESTION_RECEIPT_PLANNED', 0), planned['reason'])
            self.assertEqual(planned['reason'], 'HUMAN_HASH_APPROVAL_REQUIRED')
            self.assertFalse(planned['runtimeChanged'])
            self.assertTrue(planned['currentMapMatchesAppliedPlan'])
            self.assertEqual(planned['appliedPlanSha256'], applied_sha)
            self.assertEqual((planned['sourceRouteCount'], planned['desiredRouteCount']), (90, 90))
            self.assertEqual(planned['ingestionReceiptKeyEnvSha256'], p.digest(fixture.NAME))
            self.assertTrue(planned['exposedToApisix'])
            self.assertTrue(all(not ch['producerReceiptBefore'] and ch['producerReceiptAfter']
                                for ch in planned['changes']))
            self.assertEqual(admin.routes(), before)
            code, wrong = cli('--apply', '--plan-sha256', '0' * 64)
            self.assertEqual((code, wrong['reason'], wrong['adminPutAttempts']),
                             (1, 'FRESH_PLAN_HASH_MISMATCH', 0))
            self.assertEqual(admin.routes(), before)
            code, applied = cli('--apply', '--plan-sha256', planned['planSha256'])
            self.assertEqual((code, applied['status']), (0, 'INGESTION_RECEIPT_APPLIED'), applied['reason'])
            self.assertEqual((applied['adminGetAttempts'], applied['adminPutAttempts'],
                              applied['routeWritesVerified'], applied['finalRouteCount'],
                              applied['unchangedRoutesVerified']), (5, 2, 2, 90, 88))
            after = admin.routes()
            self.assertEqual(len(after), 90)
            for rid, row in before.items():
                if rid not in fixture.q.TARGETS:
                    self.assertEqual(after[rid], row)
            private_plan = p.decode(p.read(Path(applied['privateEvidenceDirectory']) / 'plan.private.json'))
            for change in private_plan['changes']:
                self.assertEqual(after[change['id']], change['desired'])
                expected = json.loads(json.dumps(before[change['id']]))
                expected['plugins']['serverless-post-function']['functions'] = p.field(
                    change['desired'], 'plugins.serverless-post-function.functions')
                self.assertEqual(after[change['id']], expected)
                fn = p.field(after[change['id']], 'plugins.serverless-post-function.functions')[0]
                self.assertIn('local RECEIPT_KEY_ENV = ' + json.dumps(fixture.NAME) + '\n', fn)
                self.assertIn("'X-OUF-Operational-Receipt'", fn)
            journal = Path(applied['privateEvidenceDirectory'])
            self.assertEqual(journal.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(f.stat().st_mode & 0o777 == 0o600 for f in journal.iterdir()))
            self.assertEqual(len(list(journal.glob('*-ack.private.json'))), 2)
            for entry in journal.iterdir():
                self.assertNotIn(fixture.ENV_VALUE, entry.read_text())
            code, replay = cli('--apply', '--plan-sha256', planned['planSha256'])
            self.assertEqual((code, replay['reason'], replay['adminPutAttempts']),
                             (1, 'PREVIOUS_ATTEMPT_EXISTS_DO_NOT_REPLAY', 0))
            code, signed = cli('--plan')
            self.assertEqual((code, signed['reason'], signed['adminPutAttempts']),
                             (1, 'ALREADY_APPLIED_OR_DIVERGENT', 0))
            self.assertEqual(admin.routes(), after)


if __name__ == '__main__':
    unittest.main()
