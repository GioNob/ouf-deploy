import copy
import importlib.util
import json
import multiprocessing
import os
import pty
import select
import signal
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.ingestion_rollout_preparation import oauth_budget_extension as m
spec = importlib.util.spec_from_file_location('snapshot', ROOT / 'scripts/read-ingestion-rollout-stopped-20261021.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT', str(ROOT)))
        self.addCleanup(self.tmp.cleanup); self.root = Path(self.tmp.name)
        self.context = self.root / 'old-rollout'; self.context.mkdir(mode=0o700)
        self.old_human = self.root / 'old-human'; self.old_human.mkdir(mode=0o700)
        # This file is deliberately not JSON. Opening/decoding it must fail;
        # only the profile already bound in the old rollout is used by the grant.
        self.secret = self.old_human / 'recovery.json'; self.secret.write_bytes(b'PRIVATE_CREDENTIAL_CANARY_DO_NOT_OPEN')
        self.secret.chmod(0o600)
        selection = {'issuer': 'https://fixture.invalid/realm', 'subject': 'PRIVATE_SUBJECT_CANARY', 'tenant': 'fixture'}
        binding = {**selection, 'selectionHash': s.digest(selection), 'sessionDirectory': str(self.old_human),
            'scopes': ['openid', 'profile'], 'clientId': 'ouf-human-admin', 'expiresAt': 100,
            'retryProfile': {'maximumAttempts': 288, 'automaticBudgetRenewalAllowed': False}}
        profile = {'schema': 'ouf.ingestion-rollout-existing-human-read-only.v1', 'readOnly': True,
            'minimumCumulativeAttempts': 288, 'maximumCumulativeAttempts': 288, 'budgetReset': False,
            'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'expectedBinding': binding,
            'selection': selection, 'expectedBootId': 'fixture-boot',
            'journal': {'path': str(self.secret), 'metadata': [1, 2, 0, 0, 0o100600, 1, 1000, 1, 1], 'sha256': 'a' * 64}}
        self.generations = {name: {'containerId': str(i) * 64, 'pid': i, 'startedAt': 'fixture-start'}
                            for i, name in enumerate(('ingestion', 'gateway'), 3)}
        self.row = {'bootId': 'fixture-boot', 'effects': [{'nativeResource': self.generations[name]}
                    for name in ('ingestion', 'gateway')]}
        self.review = {'executionReview': {'humanReadProfile': profile, 'humanBinding': binding,
            'retainedOwnerHistory': {'maximumCumulativeOAuthAttempts': 288},
            'stages': [{'name': name + '.START_REPLACEMENT'} for name in ('ingestion', 'gateway')]}}
        self.write('review.json', self.review); self.write('recovery.json', self.row)
        receipt = {'status': 'RETAINED_STAGE18_LIVE_INPUTS_MATCHED_NO_AUTHORITY', 'complete': True,
            'readOnly': True, 'predecessorJournalHash': s.digest(self.row), 'predecessorReviewHash': s.digest(self.review),
            'logicalOperationRef': 'b' * 64, 'priorOAuthAttempts': 288, 'additionalOAuthBudgetGranted': False,
            'oauthRequests': 0, 'runtimeEffectsDispatched': 0, 'replacementGenerations': self.generations}
        self.case = {'schema': 'ouf.technical-oauth-budget-extension-case.v1',
            'purpose': 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT', 'journalHash': s.digest(self.row),
            'reviewHash': s.digest(self.review), 'logicalOperationRef': 'b' * 64, 'liveInputReceipt': receipt,
            'maximumAdditionalOAuthAttempts': 4, 'proposedCumulativeCeiling': 292, 'grantIsRuntimeAuthority': False}
        self.observation = {'journalHash': self.case['journalHash'], 'reviewHash': self.case['reviewHash'],
            'logicalOperationRef': 'b' * 64, 'sameBoot': True, 'wallClockConsistent': True,
            'pendingStageClaim': False, 'nextStage': 18, 'recordedSecondsRemaining': 0,
            'recordedMonotonicSecondsRemaining': 0, 'contextPath': str(self.context)}
        self.reads = []
        def read(path): self.reads.append(path); return s.private_read(path)
        self.snapshot = {'CASE': {}, 'inspect': lambda _: copy.deepcopy(self.observation),
                         'private_read': read, 'decode': s.decode, 'digest': s.digest, 'encoded': s.encoded}

    def write(self, name, value):
        p = self.context / name; p.write_bytes(s.encoded(value)); p.chmod(0o600)

    def propose(self): return m.proposal(self.case, self.snapshot, clock=lambda: 200)

    def grant(self, **kwargs):
        return m.grant(self.case, self.snapshot, clock=lambda: 200, **kwargs)


class Proposal(Fixture):
    def test_exact_four_request_proposal_reads_no_credentials_and_writes_nothing(self):
        before = sorted(self.root.rglob('*'))
        result = self.propose()
        self.assertEqual(result['priorOAuthAttempts'], 288)
        self.assertEqual(result['maximumCumulativeOAuthAttempts'], 292)
        self.assertEqual(result['nominalRequests'], ['DISCOVERY', 'DEVICE_START', 'DEVICE_POLL', 'USERINFO'])
        self.assertFalse(result['humanWindowOpened']); self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertNotIn(str(self.secret), self.reads)
        self.assertEqual(before, sorted(self.root.rglob('*')))

    def test_explicit_profile_count_cannot_be_lowered_or_extended(self):
        for count in (287, 289, 292):
            with self.subTest(count=count):
                self.review['executionReview']['humanReadProfile']['minimumCumulativeAttempts'] = count
                self.write('review.json', self.review); self.case['reviewHash'] = s.digest(self.review)
                self.observation['reviewHash'] = self.case['reviewHash']
                with self.assertRaises(m.Denied): self.propose()

    def test_pending_claim_clock_or_rollout_hash_drift_blocks(self):
        for k, value in [('pendingStageClaim', True), ('sameBoot', False), ('wallClockConsistent', False),
                         ('nextStage', 19), ('recordedSecondsRemaining', 1), ('journalHash', 'f' * 64)]:
            with self.subTest(k=k):
                old = copy.deepcopy(self.observation); self.observation[k] = value
                with self.assertRaises(m.Denied): self.propose()
                self.observation = old

    def test_budget_case_or_live_receipt_cannot_grant_authority(self):
        for key, value in [('maximumAdditionalOAuthAttempts', 8), ('proposedCumulativeCeiling', 296), ('grantIsRuntimeAuthority', True)]:
            old = copy.deepcopy(self.case); self.case[key] = value
            with self.assertRaises(m.Denied): self.propose()
            self.case = old
        self.case['liveInputReceipt']['additionalOAuthBudgetGranted'] = True
        with self.assertRaises(m.Denied): self.propose()


@unittest.skipUnless(os.geteuid() == 0, 'physical root exclusive grant fixture')
class Grant(Fixture):
    def test_writable_or_symlinked_budget_parent_is_rejected(self):
        self.root.chmod(0o777)
        with self.assertRaises(m.Denied): m.root_parent(self.root)
        self.root.chmod(0o700)
        alias = self.root / 'alias'; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): m.root_parent(alias)

    def test_linked_or_permissive_lock_cannot_grant(self):
        p = self.propose(); _, lock, _, _ = m.paths(p, s.digest)
        lock.write_bytes(b''); lock.chmod(0o644)
        with self.assertRaises(m.Denied): self.grant(confirm=lambda p, h: True)
        lock.chmod(0o600); os.link(lock, self.root / 'duplicate-lock')
        with self.assertRaises(m.Denied): self.grant(confirm=lambda p, h: True)
        self.assertFalse(list(self.root.glob('*.claim.json')))

    def test_logical_rollout_alias_does_not_change_human_lineage_fence(self):
        p = self.propose()
        self.case['logicalOperationRef'] = self.observation['logicalOperationRef'] = 'd' * 64
        self.case['liveInputReceipt']['logicalOperationRef'] = 'd' * 64
        q = self.propose()
        self.assertNotEqual(s.digest(p), s.digest(q))
        self.assertEqual(m.paths(p, s.digest)[2], m.paths(q, s.digest)[2])

    def test_hardlinked_completed_decision_fails_private_readback(self):
        result = self.grant(confirm=lambda p, h: True)
        os.link(Path(result['contextPath']) / 'decision.json', self.root / 'decision-alias')
        with self.assertRaises(Exception): m.status(self.case, self.snapshot, clock=lambda: 200)

    def test_grant_is_separate_durable_record_without_old_history_changes(self):
        original = {p: p.read_bytes() for p in (self.context / 'review.json', self.context / 'recovery.json', self.secret)}
        result = self.grant(confirm=lambda p, h: True)
        self.assertEqual(result['maximumCumulativeOAuthAttempts'], 292)
        self.assertEqual(result['currentCumulativeOAuthAttempts'], 288)
        self.assertEqual(result['remainingAdditionalOAuthAttempts'], 4)
        self.assertFalse(result['newHumanWindowOpened']); self.assertFalse(result['newLoginPerformed'])
        self.assertEqual(result['oauthRequests'], 0); self.assertEqual(result['runtimeEffectsDispatched'], 0)
        self.assertNotIn('CANARY', json.dumps(result))
        self.assertNotIn(str(self.secret), self.reads)
        for p, raw in original.items(): self.assertEqual(raw, p.read_bytes())
        public = m.status(self.case, self.snapshot, clock=lambda: 200)
        self.assertEqual(public['decisionHash'], result['decisionHash'])

    def test_denied_consent_has_no_new_files(self):
        before = sorted(self.root.rglob('*'))
        with self.assertRaises(m.Denied): self.grant(confirm=lambda p, h: False)
        self.assertEqual(before, sorted(self.root.rglob('*')))

    def test_completed_grant_does_not_repeat_consent_or_create_another_budget(self):
        self.grant(confirm=lambda p, h: True)
        calls = []
        with self.assertRaises(m.Denied): self.grant(confirm=lambda p, h: calls.append(h) or True)
        self.assertFalse(calls)

    def test_crashes_after_claim_or_partial_publication_remain_fenced(self):
        for phase in ('AFTER_CLAIM', 'AFTER_PROPOSAL', 'AFTER_DECISION'):
            with self.subTest(phase=phase):
                f = Fixture(); f.setUp()
                try:
                    def crash(current):
                        if current == phase: raise RuntimeError('synthetic crash')
                    with self.assertRaises(RuntimeError):
                        m.grant(f.case, f.snapshot, confirm=lambda p, h: True, clock=lambda: 200, fault=crash)
                    with self.assertRaises(m.Denied): m.grant(f.case, f.snapshot, confirm=lambda p, h: True, clock=lambda: 200)
                    p = f.propose(); _, _, claim, _ = m.paths(p, s.digest)
                    self.assertTrue(claim.exists())
                finally: f.doCleanups()

    def test_source_drift_after_consent_does_not_consume_claim(self):
        def changed(p, h):
            self.observation['journalHash'] = 'f' * 64
            return True
        with self.assertRaises(m.Denied): self.grant(confirm=changed)
        self.assertFalse(list(self.root.glob('*.claim.json')))

    def test_changed_completed_decision_is_not_accepted_as_granted(self):
        result = self.grant(confirm=lambda p, h: True)
        decision = Path(result['contextPath']) / 'decision.json'
        value = json.loads(decision.read_bytes()); value['additionalOAuthAttempts'] = 8
        decision.write_bytes(s.encoded(value))
        with self.assertRaises(m.Denied): m.status(self.case, self.snapshot, clock=lambda: 200)

    def test_two_processes_cannot_grant_two_budgets(self):
        try: context = multiprocessing.get_context('fork')
        except ValueError: self.skipTest('fork required by Linux qualification')
        barrier = context.Barrier(2); queue = context.Queue()
        def worker():
            def confirm(p, h): barrier.wait(timeout=5); return True
            try: self.grant(confirm=confirm); queue.put('granted')
            except Exception: queue.put('blocked')
        children = [context.Process(target=worker) for _ in range(2)]
        for p in children: p.start()
        for p in children:
            p.join(timeout=10)
            if p.is_alive(): p.terminate(); self.fail('concurrent fixture did not finish')
        self.assertEqual(sorted(queue.get(timeout=2) for _ in range(2)), ['blocked', 'granted'])
        self.assertEqual(len(list(self.root.glob('*.claim.json'))), 1)

    def test_actual_controlling_tty_requires_exact_fresh_phrase(self):
        for accepted in (True, False):
            with self.subTest(accepted=accepted):
                try: child, fd = pty.fork()
                except OSError:
                    if os.environ.get('GITHUB_ACTIONS') == 'true': raise
                    self.skipTest('local PTY unavailable; required in Linux root CI')
                if child == 0:
                    try: m.terminal_confirm({}, 'f' * 64); os._exit(0)
                    except Exception: os._exit(2)
                waited = False
                try:
                    prompt = b''
                    while b'\n> ' not in prompt:
                        self.assertTrue(select.select([fd], [], [], 5)[0], 'fixture prompt not shown')
                        prompt += os.read(fd, 8192)
                    phrase = 'CONCEDO BUDGET OAUTH 288->292 ' + 'f' * 64 if accepted else 'NOT_APPROVED'
                    os.write(fd, phrase.encode() + b'\n')
                    _, status = os.waitpid(child, 0); waited = True
                    self.assertEqual(os.waitstatus_to_exitcode(status), 0 if accepted else 2)
                finally:
                    if not waited:
                        os.kill(child, signal.SIGKILL); os.waitpid(child, 0)
                    os.close(fd)


if __name__ == '__main__': unittest.main()
