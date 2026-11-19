"""Full real CLI plan/apply with synthetic gate/readiness, both legacy profiles.

Run as root only in the isolated CI Engine29.8.1. No skips or target access.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('receipt_native', ROOT / 'scripts/apply-ingestion-operational-receipt-20261112.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def command(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=180)


class Native(unittest.TestCase):
    def exercise(self, explicit, fail_ready=False):
        self.assertEqual(os.geteuid(), 0)
        self.assertEqual(command('docker', 'version', '--format', '{{.Server.Version}}').strip(), b'29.8.1')
        engine = m.Engine('/run/docker.sock')
        prefix = 'receipt-ci-' + uuid.uuid4().hex[:10]
        net, name = prefix + '-net', prefix + '-app'
        old_tag, new_tag = prefix + ':old', prefix + ':new'
        old_rev = 'a' * 40
        ids = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            journal = root / 'journal'
            journal.mkdir(mode=0o700)
            (root / 'server.py').write_text('''import http.server,os
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(503 if os.environ.get('OUF_SUMMARY_ENABLED')=='true' and '--never-ready' in __import__('sys').argv else 200)
  self.end_headers()
 def log_message(self,*a): pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
''')
            # Public synthetic files only. No host installation inputs.
            (root / 'key').write_text('ab' * 32 + '\n')
            (root / 'props').write_text('\n'.join(k + '=' + ('/run/receipt.key' if i == 0 else 'fixture')
                                                  for i, k in enumerate(m.KEYS)) + '\n')
            for filename in ('key', 'props'):
                os.chown(root / filename, 10002, 10002)
                (root / filename).chmod(0o400)
            (root / 'Dockerfile').write_text('FROM python:3.12-alpine\nCOPY server.py /app/server.py\nUSER 10002:10002\nWORKDIR /app\n')
            for tag, rev in ((old_tag, old_rev), (new_tag, m.SOURCE)):
                command('docker', 'build', '--label', m.REVISION + '=' + rev, '-t', tag, str(root))
            old_image = engine.image(old_tag)['Id']
            candidate_image = engine.image(new_tag)['Id']
            command('docker', 'network', 'create', '--internal', net)
            app = ['python3', '/app/server.py', '--spring.flyway.enabled=false',
                   '--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY']
            if fail_ready:
                app.append('--never-ready')
            request = {'Image': old_image, 'Entrypoint': m.ENTRY, 'Cmd': app,
                       'Env': ['SPRING_FLYWAY_ENABLED=false', 'SPRING_CONFIG_ADDITIONAL_LOCATION=file:/run/summary.properties'],
                       'HostConfig': {'NetworkMode': net, 'Memory': 134217728, 'NanoCpus': 500000000,
                                      'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                                      'Binds': [str(root / 'props') + ':/run/summary.properties:ro',
                                                str(root / 'key') + ':/run/receipt.key:ro']},
                       'NetworkingConfig': {'EndpointsConfig': {net: {'MacAddress': '02:42:ac:53:01:11', 'Aliases': ['receipt-fixture']}}}}
            if explicit:
                request['MacAddress'] = '02:42:ac:53:01:11'
            try:
                old_id = engine.api('POST', '/containers/create?name=' + name, request)['Id']
                ids.append(old_id)
                engine.api('POST', '/containers/' + old_id + '/start')
                for _ in range(100):
                    doc = engine.inspect(old_id)
                    if m.process(doc) == m.ENTRY + app and m.gate_armed(doc):
                        break
                    time.sleep(0.1)
                else:
                    self.fail('initial USR1 gate not armed')
                engine.api('POST', '/containers/' + old_id + '/kill?signal=USR1')
                opts = ['--container', name, '--expected-current-image', old_image,
                        '--expected-current-revision', old_rev, '--candidate-image', candidate_image,
                        '--properties-target', '/run/summary.properties', '--docker-socket', '/run/docker.sock',
                        '--nsenter-bin', '/usr/bin/nsenter', '--readiness-path', '/actuator/health/readiness',
                        '--readiness-port', '8080', '--readiness-timeout', '5', '--stop-timeout', '5',
                        '--journal-root', str(journal)]
                args = m.arguments(['--plan'] + opts)
                for _ in range(100):
                    old = engine.inspect(old_id)
                    if m.readiness(old, args):
                        break
                    time.sleep(0.1)
                else:
                    self.fail('initial readiness not 200')
                # No synthetic substitution for the required legacy precondition.
                self.assertEqual(old['Config']['MacAddress'], '02:42:ac:53:01:11')
                before = m.frame(old)
                base = [sys.executable, '-I', '-B', str(ROOT / 'scripts/apply-ingestion-operational-receipt-20261112.py')]
                planned = json.loads(command(*(base + ['--plan'] + opts)))
                self.assertEqual(planned['status'], 'INGESTION_OPERATIONAL_RECEIPT_PLANNED')
                self.assertEqual(planned['reason'], 'HUMAN_HASH_APPROVAL_REQUIRED')
                self.assertFalse(planned['runtimeChanged'])
                self.assertEqual(list(journal.iterdir()), [])
                self.assertEqual(m.frame(engine.inspect(old_id)), before)
                attempt = subprocess.run(base + ['--apply', '--plan-sha256', planned['planSha256']] + opts,
                                         capture_output=True, timeout=60)
                result = json.loads(attempt.stdout)
                new = engine.inspect(name)
                if new['Id'] != old_id:
                    ids.append(new['Id'])
                self.assertEqual(attempt.returncode, 1 if fail_ready else 0, result)
                self.assertEqual(result['status'], 'HELD' if fail_ready else 'INGESTION_OPERATIONAL_RECEIPT_READY', result)
                if fail_ready:
                    self.assertEqual(result['reason'], 'READINESS_TIMEOUT')
                    self.assertTrue(result['runtimeChanged'])
                    self.assertFalse(result['automaticRollback'])
                else:
                    self.assertEqual(result['readinessHttpStatus'], 200)
                    self.assertTrue(result['oldRetainedStopped'])
                    self.assertEqual(result['imageRevision'], m.SOURCE)
                retained = engine.inspect(old_id)
                self.assertFalse(retained['State']['Running'])
                self.assertEqual(retained['State']['StartedAt'], old['State']['StartedAt'])
                self.assertEqual(retained['Name'], '/' + name + '-before-receipt-' + planned['planSha256'][:16])
                self.assertNotIn('MacAddress', retained['Config'])
                self.assertEqual(retained['NetworkSettings']['Networks'], {})
                expected = m.request(old, candidate_image, m.mac_helper())
                m.verify_replacement(old, expected, new, True)
                self.assertEqual(m.process(new), app)
                self.assertEqual(m.environment(new)['OUF_SUMMARY_ENABLED'], 'true')
                attempt_path = journal / ('apply-' + planned['planSha256'])
                stopped = json.loads((attempt_path / 'stopped.private.json').read_text())
                self.assertEqual(stopped['Config']['MacAddress'], old['Config']['MacAddress'])
                self.assertFalse(stopped['State']['Running'])
                self.assertEqual(stopped['HostConfig'], old['HostConfig'])
                self.assertEqual(attempt_path.stat().st_mode & 0o777, 0o700)
                for item in attempt_path.iterdir():
                    self.assertEqual(item.stat().st_mode & 0o777, 0o600)
                for item in journal.iterdir():
                    if item.is_file():
                        self.assertEqual(item.stat().st_mode & 0o777, 0o600)
                # Native same-attempt denial before further effects, including post-failure.
                with self.assertRaisesRegex(RuntimeError, 'EXISTING_ATTEMPT_DO_NOT_REPLAY'):
                    m.begin_attempt(journal, planned['planSha256'])
                self.assertFalse(engine.inspect(old_id)['State']['Running'])
                print(json.dumps({'profile': 'EXPLICIT_LEGACY_CONFIG' if explicit else 'ENDPOINT_ONLY_COMPAT_CONFIG',
                                  'initialLegacyPresent': True, 'oldRetainedStopped': True,
                                  'legacyPresentAfterStopAbsentAfterDetach': True,
                                  'nativeCliPlanApply': True, 'failurePath': fail_ready, 'targetAccessed': False}), flush=True)
            finally:
                # Also retain cleanup coverage when CLI output/CREATE ACK is lost.
                # This is disposable CI cleanup, never controller rollback.
                try:
                    orphan = engine.inspect(name)
                    if orphan['Id'] not in ids and orphan['Image'] == candidate_image:
                        ids.append(orphan['Id'])
                except RuntimeError:
                    pass
                for cid in ids:
                    subprocess.run(['docker', 'rm', '-f', cid], capture_output=True)
                subprocess.run(['docker', 'network', 'rm', net], capture_output=True)
                subprocess.run(['docker', 'image', 'rm', old_tag, new_tag], capture_output=True)

    def test_explicit_legacy(self):
        self.exercise(True)

    def test_endpoint_only_compat_legacy(self):
        self.exercise(False)

    def test_readiness_failure_retains_old_without_rollback(self):
        self.exercise(True, True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
