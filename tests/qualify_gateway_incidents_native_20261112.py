"""Disposable root CI only: real A atomic update and B API1.44 lifecycles, no skips.

The synthetic HTTP owner proves deployment guards, not Java authorization/E2E.
MAC fixture structure is adapted from qualify_ingestion_operational_receipt_native_20261112.py.
"""
import copy
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
spec = importlib.util.spec_from_file_location('gateway_incidents_units', ROOT / 'tests/test_gateway_incidents_deploy_20261112.py')
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)
a, b = u.a, u.b


def command(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=180)


class Native(unittest.TestCase):
    def test_collector_atomic_apply_and_exclusive_replay(self):
        self.assertEqual(os.geteuid(), 0)
        fixture = u.CollectorGuards('test_clean_exact_plan_and_held_cases')
        fixture.before, fixture.after = u.source(a.BASE_SOURCE), u.source(a.SOURCE)
        fixture.setUp()
        try:
            args = fixture.args
            args.journal_root.mkdir(mode=0o700)
            target = args.checkout / 'tools/operational_incidents.py'
            os.chown(target, 10001, 10001)
            target.chmod(0o644)
            old = u.source_module(a.BASE_SOURCE, 'native_old_collector').SQLiteOperationalIncidentStore(args.store)
            old.open_incident(dedup_key='fixture', event_type='fixture', severity='WARNING',
                              error_code=None, impact_summary='synthetic')
            plan = fixture.collect()
            invocations, writers, events = {}, [], []
            def run(argv):
                events.append(argv[-1])
                invocations[argv[-1]] = 'new-invocation'
                if argv[-1] == args.collector_unit:
                    module = u.load('native_new_collector', target)
                    writers.append(module.SQLiteOperationalIncidentStore(args.store))
                return ''
            def observe(args, name):
                result = dict(fixture.units[name])
                result.update(InvocationID=invocations.get(name, 'old-invocation'), Result='success', ExecMainStatus='0')
                return result
            report = {'runtimeChanged': False}
            try:
                a.apply_plan(plan, a.digest(plan), args, report, recollect=lambda *x: fixture.collect(), run=run, observe=observe)
                self.assertEqual(report['status'], 'GATEWAY_COLLECTOR_INCIDENTS_READY')
                self.assertEqual(events, [args.collector_unit, args.probe_unit])
                self.assertEqual(a.sha(target.read_bytes()), a.TARGET_SHA)
                self.assertEqual((target.stat().st_uid, target.stat().st_gid, target.stat().st_mode & 0o777), (10001, 10001, 0o644))
                work = args.journal_root / ('apply-' + a.digest(plan))
                self.assertEqual((work / 'operational_incidents.py.before').read_bytes(), fixture.before)
                self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                for path in work.iterdir():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                with self.assertRaisesRegex(RuntimeError, 'EXISTING_ATTEMPT_DO_NOT_REPLAY'):
                    a.apply_plan(plan, a.digest(plan), args, {}, recollect=lambda *x: fixture.collect())
                self.assertEqual(events, [args.collector_unit, args.probe_unit])
            finally:
                for writer in writers:
                    writer.close()
                old.close()
        finally:
            fixture.doCleanups()

    def exercise_owner(self, explicit, failure=None):
        self.assertEqual(os.geteuid(), 0)
        self.assertEqual(command('docker', 'version', '--format', '{{.Server.Version}}').strip(), b'29.8.1')
        engine = b.Engine('/run/docker.sock')
        prefix = 'gateway-incidents-' + uuid.uuid4().hex[:10]
        net, name = prefix + '-net', prefix + '-owner'
        tags = [prefix + ':old', prefix + ':new']
        ids = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            journal = root / 'journal'
            journal.mkdir(mode=0o700)
            db = root / 'operations.db'
            writer = u.source_module(a.SOURCE, 'native_owner_store').SQLiteOperationalIncidentStore(db)
            (root / 'server.py').write_text('''import http.server,json,os
class H(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  status=int(os.environ.get('FIXTURE_FAILURE','403')) if self.path=='/incidents' and os.path.exists('/app/new') else 403
  self.send_response(status); self.end_headers()
 def do_GET(self):
  self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"DOWN"}')
 def log_message(self,*a): pass
http.server.HTTPServer(('0.0.0.0',8081),H).serve_forever()
''')
            (root / 'Dockerfile').write_text('FROM python:3.12-alpine\nCOPY server.py /app/server.py\nUSER 10001:10001\nWORKDIR /app\nEXPOSE 8081\nENTRYPOINT ["python3","/app/server.py"]\n')
            command('docker', 'build', '-t', tags[0], str(root))
            with (root / 'Dockerfile').open('a') as stream:
                stream.write('COPY new /app/new\n')
            (root / 'new').write_text('synthetic candidate')
            command('docker', 'build', '-t', tags[1], str(root))
            old_image, candidate = [engine.image(tag)['Id'] for tag in tags]
            manifest = {'schema': 'ouf.gateway-owner-incidents-archive.v1', 'sourceCommit': b.SOURCE,
                        'imageIds': [candidate]}
            manifest_path = root / 'manifest.json'
            manifest_path.write_bytes(b.c.encoded(manifest))
            command('docker', 'network', 'create', '--internal', net)
            req = {'Image': old_image, 'HostConfig': {'NetworkMode': net, 'Memory': 134217728,
                    'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'Binds': [str(root) + ':/data:ro']},
                   'Env': ['FIXTURE_FAILURE=' + str(failure or 403)],
                   'NetworkingConfig': {'EndpointsConfig': {net: {'MacAddress': '02:42:ac:53:01:11', 'Aliases': ['gateway-fixture']}}}}
            if explicit:
                req['MacAddress'] = '02:42:ac:53:01:11'
            try:
                cid = engine.api('POST', '/containers/create?name=' + name, req)['Id']
                ids.append(cid)
                engine.api('POST', '/containers/' + cid + '/start')
                opts = ['--container', name, '--expected-current-image', old_image, '--candidate-image', candidate,
                        '--store', str(db), '--store-target', '/data/operations.db', '--bundle-manifest', str(manifest_path),
                        '--manifest-sha256', b.sha(manifest_path.read_bytes()), '--journal-root', str(journal),
                        '--docker-socket', '/run/docker.sock', '--nsenter-bin', '/usr/bin/nsenter',
                        '--summary-path', '/summary', '--incidents-path', '/incidents', '--actuator-path', '/actuator/health',
                        '--readiness-port', '8081', '--readiness-timeout', '4', '--stop-timeout', '5']
                args = b.arguments(['--plan'] + opts)
                for _ in range(100):
                    old = engine.inspect(cid)
                    if b.readiness(old, args) == [403, 403]:
                        break
                    time.sleep(0.1)
                else:
                    self.fail('initial synthetic owner not ready')
                self.assertEqual(old['Config']['MacAddress'], '02:42:ac:53:01:11')
                base = [sys.executable, '-I', '-B', str(ROOT / 'scripts/apply-gateway-owner-incidents-20261112.py')]
                before = b.c.frame(old)
                planned = json.loads(command(*(base + ['--plan'] + opts)))
                self.assertEqual(planned['status'], 'GATEWAY_OWNER_INCIDENTS_PLANNED')
                self.assertEqual(b.c.frame(engine.inspect(cid)), before)
                self.assertEqual(list(journal.iterdir()), [])
                attempt = subprocess.run(base + ['--apply', '--plan-sha256', planned['planSha256']] + opts,
                                         capture_output=True, timeout=90)
                result = json.loads(attempt.stdout)
                new = engine.inspect(name)
                ids.append(new['Id'])
                self.assertTrue(result['runtimeChanged'])
                self.assertFalse(result['automaticRollback'])
                self.assertEqual(attempt.returncode, 1 if failure else 0, result)
                self.assertEqual(result['status'], 'HELD' if failure else 'GATEWAY_OWNER_INCIDENTS_READY', result)
                if failure:
                    self.assertEqual(result['readinessHttpStatuses'], [403, failure])
                else:
                    self.assertEqual(result['readinessHttpStatuses'], [403, 403])
                    # DOWN does not gate readiness.
                    self.assertEqual(result['actuatorInformation'], {'httpStatus': 200, 'status': 'DOWN'})
                retained = engine.inspect(cid)
                self.assertEqual(retained['Name'], '/' + name + '-before-incidents-' + planned['planSha256'][:16])
                self.assertNotIn('MacAddress', retained['Config'])
                b.c.detached(b.mac_helper(), old, retained, retained['Name'])
                b.c.verify_replacement(old, b.request(old, candidate, b.mac_helper()), new, True)
                self.assertEqual(b.c.process(new), [old['Path']] + old['Args'])
                work = journal / ('apply-' + planned['planSha256'])
                stopped = json.loads((work / 'stopped.private.json').read_text())
                self.assertEqual(stopped['Config']['MacAddress'], old['Config']['MacAddress'])
                self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                for path in work.iterdir():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                # Same CLI attempt must fail before any further mutation.
                replay = subprocess.run(base + ['--apply', '--plan-sha256', planned['planSha256']] + opts,
                                        capture_output=True, timeout=15)
                self.assertEqual(json.loads(replay.stdout)['reason'], 'EXISTING_ATTEMPT_DO_NOT_REPLAY')
                self.assertFalse(engine.inspect(cid)['State']['Running'])
                print(json.dumps({'explicitLegacy': explicit, 'initialLegacyPresent': True,
                                  'absentOnlyAfterDetach': True, 'failureStatus': failure,
                                  'cliPlanApply': True, 'targetAccessed': False}), flush=True)
            finally:
                writer.close()
                try:
                    current = engine.inspect(name)
                    if current['Id'] not in ids and current['Image'] == candidate:
                        ids.append(current['Id'])
                except RuntimeError:
                    pass
                # Disposable CI teardown only; never part of controller recovery.
                for cid in ids:
                    subprocess.run(['docker', 'rm', '-f', cid], capture_output=True)
                subprocess.run(['docker', 'network', 'rm', net], capture_output=True)
                subprocess.run(['docker', 'image', 'rm'] + tags, capture_output=True)

    def test_owner_explicit_legacy(self):
        self.exercise_owner(True)

    def test_owner_endpoint_only_with_real_legacy(self):
        self.exercise_owner(False)

    def test_owner_404_is_not_readiness(self):
        self.exercise_owner(True, 404)

    def test_owner_503_is_not_readiness(self):
        self.exercise_owner(True, 503)


if __name__ == '__main__':
    unittest.main(verbosity=2)
