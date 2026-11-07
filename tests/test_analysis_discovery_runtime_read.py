import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/read-analysis-discovery-runtime-20261107.py'
spec = importlib.util.spec_from_file_location('runtime_read', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def doc(n, running=True):
    return {'Id': format(n, '064x'), 'Image': 'sha256:' + 'b' * 64,
            'Config': {'Env': ['PRIVATE_PASSWORD=DO_NOT_EMIT_THIS_SECRET'],
                       'Labels': {}, 'Cmd': ['server'], 'Entrypoint': ['/app/app'],
                       'MacAddress': '02:42:00:00:00:01'},
            'HostConfig': {'RestartPolicy': {'Name': 'no'}, 'Memory': 402653184},
            'Path': '/app/app', 'Args': ['server'], 'Mounts': [],
            'State': {'Running': running, 'StartedAt': '2026-11-07T01:00:00Z', 'Pid': n},
            'NetworkSettings': {'Networks': {'ouf-backend': {'MacAddress': '02:42:00:00:00:01'}}}}


class ReaderTest(unittest.TestCase):
    def fixture(self, root):
        root.mkdir(exist_ok=True)
        plan_path = root / 'cold-host-bound-20261107-v1/plan.private.json'
        plan_path.parent.mkdir()
        (plan_path.parent / 'stop').mkdir()
        roles, originals, live = {}, [], {}
        for n, role in enumerate(sorted(m.ROSTER), 1):
            row = doc(n)
            roles[role] = {'containerId': row['Id'], 'nativeImage': row['Image'], 'fingerprint': m.fingerprint(row)}
            originals.append(row)
            live[row['Id']] = copy.deepcopy(row)
        (plan_path.parent / 'stop/command-182.private').write_text(json.dumps(originals))
        raw = json.dumps({'roles': roles}).encode()
        plan_path.write_bytes(raw)
        for n, role in enumerate(('onboarding', 'udp'), 101):
            replacement = doc(n)
            replacement['Config']['Labels']['ouf.storage.switch'] = 'switch-' + role
            prefix = 'OUF_ONBOARDING_STAGING_' if role == 'onboarding' else 'OUF_UDP_S3_'
            bucket = 'ouf-managed-files' if role == 'onboarding' else 'ouf-udp'
            replacement['Config']['Env'] += [prefix + 'ENDPOINT=https://ouf-seaweedfs-stage:9002', prefix + 'BUCKET=' + bucket]
            replacement['NetworkSettings']['Networks']['ouf-seaweedfs-private'] = {'MacAddress': '02:42:00:00:00:02'}
            work = root / (role + '-seaweedfs-switch-fixture')
            work.mkdir()
            (work / 'replacement-container.private.json').write_text(json.dumps(replacement))
            marker = {'status': role.upper() + '_SEAWEEDFS_READY', 'originalContainerId': roles[role]['containerId'],
                      'replacementContainerId': replacement['Id'], 'privateEvidenceDirectory': str(work),
                      'switchToken': 'switch-' + role}
            (root / (role + '-seaweedfs-current.json')).write_text(json.dumps(marker))
            live[roles[role]['containerId']]['State']['Running'] = False
            live[replacement['Id']] = copy.deepcopy(replacement)
            # Reproduce the reported running replacement delta; do not normalize it.
            del live[replacement['Id']]['Config']['MacAddress']
        return plan_path, roles, live, hashlib.sha256(raw).hexdigest()

    def collect(self, root, mutate=None):
        plan, roles, live, sha = self.fixture(root)
        if mutate:
            mutate(root, roles, live)
        report, calls = {}, []
        def inspect(cid):
            calls.append(cid)
            return copy.deepcopy(live[cid])
        with patch.object(m, 'PLAN_SHA', sha), patch.object(m, 'inspect', side_effect=inspect):
            m.collect(report, root, plan)
        return report, calls

    def test_retained_switches_read_without_rejecting_or_hiding_mac_delta(self):
        with tempfile.TemporaryDirectory() as temp:
            report, calls = self.collect(Path(temp))
            self.assertEqual(report['status'], 'ANALYSIS_DISCOVERY_RUNTIME_READ_COMPLETE')
            self.assertEqual(len(calls), 18)
            self.assertTrue(report['oldWritersStoppedAtBothReads'])
            for role in ('onboarding', 'udp'):
                item = report['services'][role]
                self.assertEqual(item['changedConfigFields'], ['MacAddress'])
                self.assertEqual(item['baselineLegacyMac']['kind'], 'STRING')
                self.assertEqual(item['baselineLegacyMac']['matchingEndpointCount'], 1)
                self.assertEqual(item['currentLegacyMac']['kind'], 'ABSENT')
                self.assertTrue(report['storageDeclarations'][role]['endpointMatchesSeaweedfs'])
            self.assertNotIn('DO_NOT_EMIT_THIS_SECRET', json.dumps(report))
            evidence = Path(report['privateEvidenceDirectory'])
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in evidence.iterdir()))

    def test_all_mac_shapes_distinct_no_global_ignore(self):
        baseline = doc(1)
        for value, kind in ((None, 'NULL'), ('', 'EMPTY_STRING'), ('wrong', 'STRING'), (12, 'OTHER')):
            changed = copy.deepcopy(baseline)
            changed['Config']['MacAddress'] = value
            self.assertEqual(m.mac_shape(changed)['kind'], kind)
            self.assertFalse(m.mac_shape(changed)['formatValid'])
            self.assertNotEqual(m.fingerprint(changed), m.fingerprint(baseline))
        self.assertEqual(m.changes({}, {'MacAddress': None}), ['MacAddress'])
        for value in ('00:00:00:00:00:00', '03:42:00:00:00:01'):
            baseline['Config']['MacAddress'] = value
            self.assertFalse(m.mac_shape(baseline)['unicastNonzero'])

    def test_declarations_preserve_conflicts_and_hide_secrets(self):
        row = doc(1)
        row['Config']['Env'] += [
            'OUF_SCHEMA_GOV_ENABLED=true', 'OUF_DISCOVERY_WORKER_ENABLED=true',
            'OUF_SCHEMA_GOV_TOKEN_ENDPOINT=https://x:SECRET@example.com/token?secret=DO_NOT_EMIT',
            'OUF_SCHEMA_GOV_CLIENT_SECRET_FILE=/private/DO_NOT_EMIT',
            'SPRING_APPLICATION_JSON=' + json.dumps({'ouf': {'semantic': {'providers': {'schema-gov': {'enabled': False}}}}})]
        row['Config']['Cmd'] = ['-Douf.semantic.discovery-worker.enabled=false']
        result = m.declarations(row)
        self.assertFalse(result['precedenceResolved'])
        self.assertEqual([r['summary'] for r in result['properties'][m.PROVIDER + 'enabled']], ['true', 'false'])
        self.assertEqual([r['summary'] for r in result['properties']['ouf.semantic.discovery-worker.enabled']], ['true', 'false'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('DO_NOT_EMIT', json.dumps(result))

    def test_missing_or_false_provider_is_not_inferred_from_source_default(self):
        result = m.declarations(doc(1))
        self.assertEqual(result['properties'], {})
        self.assertFalse(result['packagedDefaultsApplied'])
        row = doc(2)
        row['Config']['Env'] = ['OUF_SCHEMA_GOV_ENABLED=false']
        self.assertEqual(m.declarations(row)['properties'][m.PROVIDER + 'enabled'][0]['summary'], 'false')

    def test_tampered_receipt_stops_before_current_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            def mutate(root, roles, live):
                path = root / 'onboarding-seaweedfs-current.json'
                data = json.loads(path.read_text())
                data['switchToken'] = 'wrong'
                path.write_text(json.dumps(data))
            with self.assertRaisesRegex(RuntimeError, 'STORAGE_RECEIPT_IDENTITY_MISMATCH'):
                self.collect(Path(temp), mutate)

    def test_running_old_writer_is_explicit_not_hidden(self):
        with tempfile.TemporaryDirectory() as temp:
            def mutate(root, roles, live):
                live[roles['onboarding']['containerId']]['State']['Running'] = True
            report, _ = self.collect(Path(temp), mutate)
            self.assertFalse(report['oldWritersStoppedAtBothReads'])
            self.assertFalse(report['storageDeclarations']['onboarding']['oldWriterStoppedAtFirstRead'])

    def test_generation_change_produces_incomplete_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            plan, roles, live, sha = self.fixture(root)
            count = {}
            def inspect(cid):
                count[cid] = count.get(cid, 0) + 1
                row = copy.deepcopy(live[cid])
                if cid == roles['mcp']['containerId'] and count[cid] == 2:
                    row['State']['StartedAt'] = '2026-11-07T22:00:00Z'
                return row
            report = {}
            with patch.object(m, 'PLAN_SHA', sha), patch.object(m, 'inspect', side_effect=inspect):
                m.collect(report, root, plan)
            self.assertEqual(report['status'], 'READ_INCOMPLETE')
            self.assertEqual(report['reason'], 'RUNTIME_CHANGED_DURING_READ')

    def test_plan_hash_mismatch_never_contacts_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            plan, _, _, _ = self.fixture(root)
            with patch.object(m, 'inspect') as inspect:
                with self.assertRaisesRegex(RuntimeError, 'RETAINED_PLAN_MISMATCH'):
                    m.collect({}, root, plan)
                inspect.assert_not_called()

    def test_exception_messages_are_not_emitted(self):
        output = io.StringIO()
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'collect', side_effect=ValueError('PRIVATE_CREDENTIAL')):
            with redirect_stdout(output):
                m.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result['reason'], 'ValueError')
        self.assertFalse(result['deploymentAuthorizedByReader'])
        self.assertNotIn('PRIVATE_CREDENTIAL', output.getvalue())

    def test_reader_contains_no_command_execution_or_write_http(self):
        # The target reader must never become a thinly disguised start/redeploy tool.
        source = SCRIPT.read_text()
        self.assertNotIn('subprocess', source)
        self.assertNotIn('connection.request(\'POST\'', source)
        self.assertNotIn('connection.request(\'PUT\'', source)
        self.assertNotIn('connection.request(\'DELETE\'', source)
        self.assertEqual(source.count("connection.request('GET',"), 1)


if __name__ == '__main__':
    unittest.main()
