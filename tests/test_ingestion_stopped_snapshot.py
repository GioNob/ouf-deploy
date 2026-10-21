import copy
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('stopped_snapshot', ROOT / 'scripts/read-ingestion-rollout-stopped-20261021.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Snapshot(unittest.TestCase):
    def setUp(self):
        self.case = copy.deepcopy(m.CASE)
        self.case['contextPath'] = getattr(self, 'context_override', self.case['contextPath'])
        c = self.case['contextPath']
        names = self.case['expectedAppliedStages'] + [
            'REBIND_GATEWAY_TRANSPORT', 'VERIFY_REBOUND_ROUTE_MAP',
            'PUT_ROUTE.mcp-ingestion-history', 'READ_ROUTE.mcp-ingestion-history',
            'PUT_ROUTE.mcp-ingestion-status', 'READ_ROUTE.mcp-ingestion-status',
            'VERIFY_FINAL', 'ingestion.RESTORE_RESTART', 'gateway.RESTORE_RESTART', 'VERIFY_RESTORED_FINAL']
        stages = [{'name': n, 'kind': 'READ', 'intent': {'fixture': i},
                   'intentHash': m.digest({'fixture': i})} for i, n in enumerate(names)]
        native = {'executionContext': c, 'stages': stages, 'logicalOperationRef': 'a' * 64,
                  **dict.fromkeys(m.FORBIDDEN, False)}
        scope = {'executionContext': c, 'reviewHash': m.digest(native),
                 'stageIntentHashes': {s['name']: s['intentHash'] for s in stages},
                 **dict.fromkeys(m.FORBIDDEN, False)}
        prepared = {'caseHash': self.case['productionCaseHash'],
                    'controlSourceHash': self.case['controlSourceHash'],
                    'sourceClosure': {'declaration': {'fixture': 'synthetic-pinned-declaration'}}}
        self.case['sourceDeclarationHash'] = m.digest(prepared['sourceClosure']['declaration'])
        review = {'executionReview': native, 'scopes': {'ingestionGatewayRollout': scope},
                  'operatorBinding': {'controlSourceHash': self.case['controlSourceHash'],
                    'caseHash': self.case['productionCaseHash'], 'preparationHash': m.digest(prepared),
                    'modeContract': 'EXPLICIT_ONE_STAGE_NO_AUTOMATIC_REPLAY_V1'},
                  'privateFixture': 'CANARY_NEVER_PUBLIC'}
        decision = {'reviewHash': m.digest(review), 'decision': 'APPROVE_EXACT_FINITE_SCOPED_ACTION',
                    'approvedAt': 100, 'expiresAt': 1000}
        row = {'schema': 'ouf.ingestion-rollout-finite-journal.v1', 'nextStage': 18,
               'effects': [{'stage': s['name'], 'intentHash': s['intentHash'], 'state': 'APPLIED'}
                           for s in stages[:18]], 'scopeHash': m.digest(scope), 'budgetReset': False,
               'readState': 'IDLE', 'readAttempts': 18, 'authorityHash': 'b' * 64,
               'createdAt': 100, 'expiresAt': 1000, 'expiresMonotonic': 900,
               'lastWall': 955, 'lastMonotonic': 855, 'bootId': 'fixture-boot'}
        control = {'schema': 'ouf.ingestion-rollout-explicit-production-control.v1',
                   'state': 'RECONCILE_REQUIRED', 'complete': False, 'budgetReset': False,
                   **{k: self.case[k] for k in ('controlSourceHash', 'sourceDeclarationHash')},
                   'caseHash': self.case['productionCaseHash'], 'preparationHash': m.digest(prepared),
                   'reviewHash': m.digest(review), 'decisionHash': m.digest(decision)}
        claim = {'reviewHash': m.digest(native), 'authorityHash': row['authorityHash'],
                 'context': c, 'automaticReplayAllowed': False, 'budgetReset': False}
        self.values = dict(zip([c + '/' + name for name in ('operator-control/recovery.json',
                'preparation.json', 'review.json', 'decision.json', 'recovery.json')],
                [control, prepared, review, decision, row]))
        self.claim = str(Path(c).parent / ('ingestion-rollout-' + 'a' * 64 + '.claim.json'))
        self.values[self.claim] = claim
        self.calls = []

    def read(self, p):
        self.calls.append(p)
        return m.encoded(self.values[p])

    def run_read(self, **kwargs):
        return m.inspect(self.case, read=self.read, clock=lambda: (2000, 1900),
                         boot_read=lambda: 'fixture-boot', **kwargs)

    def test_expired_snapshot_without_current_authority_or_secret_files(self):
        result = self.run_read()
        self.assertEqual(result['nextStageName'], 'REBIND_GATEWAY_TRANSPORT')
        self.assertEqual(len(result['remainingStages']), 10)
        self.assertEqual(result['recordedSecondsRemaining'], 0)
        self.assertFalse(result['pendingStageClaim'])
        self.assertFalse(result['liveRuntimeObserved'])
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertNotIn('CANARY', json.dumps(result))
        self.assertEqual(len(self.calls), 12)
        self.assertEqual(set(self.calls), set(self.values))

    def test_packaged_case_matches_frozen_sealed_delivery(self):
        sealed = ROOT / 'scripts/ingestion-rollout-production-control-20261020.py'
        if not sealed.exists(): sealed = ROOT / 'sealed-production.py'
        values = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(sealed.read_text()).body
                  if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                  and n.targets[0].id in ('DELIVERY', 'CASE')}
        self.assertEqual(m.CASE['productionCaseHash'], m.digest(values['CASE']))
        self.assertEqual(m.CASE['controlSourceHash'], values['DELIVERY']['controlSourceHash'])
        self.assertEqual(m.CASE['sourceDeclarationHash'], m.digest(values['DELIVERY']['nativeDeclaration']))
        profile = json.loads((ROOT / 'releases/ingestion-rollout-stopped-reader-case-20261021.json').read_text())
        self.assertEqual(profile, m.CASE)

    def test_pending_claim_is_not_discarded_or_treated_as_applied(self):
        row = self.values[self.case['contextPath'] + '/recovery.json']
        row['effects'].append({'state': 'CLAIMED'})
        with self.assertRaises(m.Denied): self.run_read()

    def test_altered_applied_intent(self):
        self.values[self.case['contextPath'] + '/recovery.json']['effects'][4]['intentHash'] = 'c' * 64
        with self.assertRaises(m.Denied): self.run_read()

    def test_control_source_case_and_declaration_must_be_pinned(self):
        for key in ('controlSourceHash', 'productionCaseHash', 'sourceDeclarationHash'):
            with self.subTest(key=key):
                case = copy.deepcopy(self.case); case[key] = 'f' * 64
                with self.assertRaises(m.Denied):
                    m.inspect(case, read=self.read)

    def test_no_implicit_other_context_or_progress(self):
        for n in (17, 19, True):
            with self.subTest(n=n):
                self.values[self.case['contextPath'] + '/recovery.json']['nextStage'] = n
                with self.assertRaises(m.Denied): self.run_read()

    def test_fence_is_retained(self):
        self.values[self.claim]['authorityHash'] = 'c' * 64
        with self.assertRaises(m.Denied): self.run_read()

    def test_second_read_detects_changed_journal(self):
        first = self.read
        target = self.case['contextPath'] + '/recovery.json'
        count = 0
        def race(p):
            nonlocal count
            if p == target:
                count += 1
                if count == 2: self.values[p]['lastWall'] += 1
            return first(p)
        with self.assertRaisesRegex(m.Denied, 'CHANGED_DURING_SNAPSHOT'):
            m.inspect(self.case, read=race, clock=lambda: (2000, 1900), boot_read=lambda: 'fixture-boot')

    def test_different_boot_is_explicit(self):
        result = m.inspect(self.case, read=self.read, clock=lambda: (2000, 1900), boot_read=lambda: 'different')
        self.assertFalse(result['sameBoot'])
        self.assertIsNone(result['recordedMonotonicSecondsRemaining'])

    def test_missing_boot_does_not_invent_clock_evidence(self):
        def unavailable(): raise FileNotFoundError()
        result = m.inspect(self.case, read=self.read, clock=lambda: (2000, 1900), boot_read=unavailable)
        self.assertFalse(result['bootEvidenceAvailable'])
        self.assertFalse(result['sameBoot'])
        self.assertIsNone(result['recordedMonotonicSecondsRemaining'])

    def test_duplicate_and_nonfinite_json_denied(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(m.Denied): m.decode(raw)

    def test_nonfinite_journal_clock_denied(self):
        self.values[self.case['contextPath'] + '/recovery.json']['expiresAt'] = 'not-a-time'
        with self.assertRaises(m.Denied): self.run_read()

    @unittest.skipUnless(os.geteuid() == 0, 'isolated root process fixture')
    def test_isolated_process_reads_physical_expired_snapshot_without_writes(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT', str(ROOT))) as tmp:
            fixture = Snapshot()
            fixture.context_override = str(Path(tmp) / 'retained-context')
            fixture.setUp()
            for name, value in fixture.values.items():
                p = Path(name); p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                p.write_bytes(m.encoded(value)); p.chmod(0o600)
            for p in Path(tmp).rglob('*'):
                if p.is_dir(): p.chmod(0o700)
            script = Path(tmp) / 'reader.py'
            source = (ROOT / 'scripts/read-ingestion-rollout-stopped-20261021.py').read_text()
            script.write_text(source.replace('CASE = ' + repr(m.CASE), 'CASE = ' + repr(fixture.case)))
            before = {p: (m.identity(p.stat()), p.read_bytes()) for p in Path(tmp).rglob('*') if p.is_file()}
            result = subprocess.run([sys.executable, '-I', '-B', '-S', str(script)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)
            output = m.decode(result.stdout)
            self.assertEqual(output['status'], 'STOPPED_PREFIX_RECONCILED_NO_AUTHORITY')
            self.assertEqual(output['recordedSecondsRemaining'], 0)
            self.assertNotIn(b'CANARY', result.stdout + result.stderr)
            self.assertEqual(before, {p: (m.identity(p.stat()), p.read_bytes())
                                     for p in Path(tmp).rglob('*') if p.is_file()})


@unittest.skipUnless(os.geteuid() == 0, 'real root custody fixture')
class PhysicalCustody(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT', str(ROOT)))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'record.json'
        self.path.write_bytes(b'{"safe":true}')
        self.path.chmod(0o600)

    def test_real_read_and_permissions(self):
        self.assertEqual(m.private_read(str(self.path)), b'{"safe":true}')
        self.path.chmod(0o644)
        with self.assertRaises(m.Denied): m.private_read(str(self.path))

    def test_symlink_file_and_ancestor_denied(self):
        link = self.root / 'link.json'; link.symlink_to(self.path)
        with self.assertRaises(OSError): m.private_read(str(link))
        directory = self.root / 'link'; directory.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): m.private_read(str(directory / 'record.json'))

    def test_hardlink_and_oversize_denied(self):
        os.link(self.path, self.root / 'second.json')
        with self.assertRaises(m.Denied): m.private_read(str(self.path))
        (self.root / 'second.json').unlink()
        self.path.write_bytes(b'x' * 1048577)
        with self.assertRaises(m.Denied): m.private_read(str(self.path))

    def test_writable_ancestor_denied(self):
        self.root.chmod(0o777)
        with self.assertRaises(m.Denied): m.private_read(str(self.path))


if __name__ == '__main__':
    unittest.main()
