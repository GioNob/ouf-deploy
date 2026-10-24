"""Real shell/root launch with explicit native-action substitutes.

This proves sequencing, exact pins, receipt barriers and no retries. It does
not qualify actual issuance/signing, terminal approval, IAM or target effects.
"""
import hashlib
import json
from pathlib import Path
import re
import unittest
import test_postboot_review_wrapper as fixture

ROOT = Path(__file__).resolve().parents[3]
WRAPPER = ROOT / 'releases/semantic-registry-checkpoint-successor-apply-reviewed-20261023.sh'
SOURCE = 'a' * 40


class ApplyWrapper(unittest.TestCase):
    executable = fixture.ReviewWrapper.executable
    calls = fixture.ReviewWrapper.calls

    def setUp(self):
        fixture.ReviewWrapper.setUp(self)
        self.prepared = self.home / 'private'; self.prepared.mkdir(mode=0o700)
        self.preparation_raw = b'{"synthetic":"preparation"}'
        self.review_raw = b'{"synthetic":"review"}'
        for name, raw in [('prepared.json', self.preparation_raw), ('review.json', self.review_raw)]:
            p = self.prepared / name; p.write_bytes(raw); p.chmod(0o600)
        self.review_hash = hashlib.sha256(self.review_raw).hexdigest()

    def capsule(self, fail=None, bad=None, missing_get=False, exclusive=False):
        text = f'''DELIVERY = {{'nativeDeclaration': {{'sourceCommit': {SOURCE!r}, 'sourcePins': {{'ouf-deploy': {SOURCE!r}}}}}}}
import json, os, pathlib, sys
root = pathlib.Path({str(self.home)!r}); mode = sys.argv[1]
assert sys.argv[2] == {self.review_hash!r}
with (root / 'capsule.calls').open('a') as stream:
    stream.write(json.dumps({{'mode': mode, 'isolated': sys.flags.isolated, 'stdinTail': sys.stdin.read()}}) + '\\n')
if mode == 'issue' and {exclusive!r}:
    try:
        with (root / 'issue.claim').open('x') as stream: stream.write('consumed')
    except FileExistsError:
        print('{{"status":"STOP_RECONCILE"}}'); raise SystemExit(2)
if mode == {fail!r}:
    print('{{"status":"STOP_RECONCILE"}}'); raise SystemExit(2)
r = {{'automaticReplayAllowed': False, 'budgetReset': False}}
if mode == 'issue':
    r.update(schema='ouf.semantic-registry-postboot-issued-authority.v1', reviewHash={self.review_hash!r}, runtimeAuthorityIssued=True, runtimeEffectsDispatched=0, releaseAcceptance=False)
elif mode == 'resume':
    r.update(schema='ouf.semantic-registry-checkpoint-successor-installation.v1', nativeCheckpoint=4, retainedControlledGrantAttempts=320, engineGetAllowanceConsumed=2, lifecycleEffectsDispatched=0, oauthRequests=0, runtimeAuthorityIssued=False)
elif mode == 'owner':
    r.update(schema='ouf.semantic-registry-postboot-owner-installed-result.v1', currentSessionBootEstablished=True, retainedFirstGrantReplayed=False, priorControlledGrantAttempts=320, oauthRequests=0, runtimeAuthorityIssued=False)
elif mode == 'continue':
    if not {missing_get!r}: print(json.dumps({{'status':'ORIGINAL_SERVICE_GET_200_WITH_FINITE_OWNER','httpStatus':200,'originalSemanticGetSucceeded':True}}))
    r.update(schema='ouf.semantic-registry-postboot-finite-session-result.v1', status='FINITE_PUBLISHED_TOKEN_WINDOW_ENDED', originalSemanticGetSucceededDuringWindow=True, ownerSessionEnded=True, currentOwnerAdmissionProven=False, continuousServiceRenewalEstablished=False, releaseAcceptance=False)
else: raise SystemExit(9)
if mode == {bad!r}: r['budgetReset'] = 0
print(json.dumps(r), flush=True)
'''
        path = self.home / 'native-capsule.py'; path.write_text(text); path.chmod(0o600)
        return path, hashlib.sha256(text.encode()).hexdigest()

    def run_wrapper(self, *args, **options):
        import subprocess
        path, digest = self.capsule(**options)
        pins = {'SOURCE_COMMIT': SOURCE, 'CAPSULE_COMMIT': 'b' * 40, 'CAPSULE_SHA256': digest,
            'REVIEW_HASH': self.review_hash, 'PREPARATION_HASH': hashlib.sha256(self.preparation_raw).hexdigest(),
            'PREPARATION_ROOT': str(self.prepared), 'RETAINED_CAPSULE': str(path)}
        text = WRAPPER.read_text()
        for key, value in pins.items():
            text, count = re.subn(r"(?m)^(  OUF_POSTBOOT_" + key + r"=)'[^']*'$", lambda m: m[1] + repr(value), text)
            self.assertEqual(count, 1)
        script = self.home / 'apply.sh'; self.executable(script, text)
        return subprocess.run(['/usr/bin/bash', str(script), *args], env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)

    def test_all_four_successor_modes_in_order_with_isolation_and_no_supplied_approval_input(self):
        result = self.run_wrapper(); self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())
        calls = self.calls('capsule.calls')
        self.assertEqual([v['mode'] for v in calls], ['issue','resume','owner','continue'])
        self.assertTrue(all(v['isolated'] == 1 and v['stdinTail'] == '' for v in calls))
        self.assertEqual(self.calls('gh.calls'), [])

    def test_each_native_failure_stops_without_any_later_mode_or_retry(self):
        modes = ['issue','resume','owner','continue']
        for n, mode in enumerate(modes):
            with self.subTest(mode=mode):
                (self.home / 'capsule.calls').unlink(missing_ok=True)
                result = self.run_wrapper(fail=mode); self.assertEqual(result.returncode, 2)
                self.assertEqual([v['mode'] for v in self.calls('capsule.calls')], modes[:n+1])

    def test_success_exit_with_invalid_receipt_is_rejected_at_each_barrier(self):
        modes = ['issue','resume','owner','continue']
        for n, mode in enumerate(modes):
            with self.subTest(mode=mode):
                (self.home / 'capsule.calls').unlink(missing_ok=True)
                result = self.run_wrapper(bad=mode); self.assertEqual(result.returncode, 2)
                self.assertIn(b'EXPECTED_REVIEWED_EXECUTION_RECEIPT_UNCONFIRMED', result.stdout)
                self.assertEqual([v['mode'] for v in self.calls('capsule.calls')], modes[:n+1])

    def test_missing_original_get_cannot_be_called_success(self):
        result = self.run_wrapper(missing_get=True); self.assertEqual(result.returncode, 2)
        self.assertIn(b'EXPECTED_REVIEWED_EXECUTION_RECEIPT_UNCONFIRMED', result.stdout)

    def test_changed_preparation_or_review_stops_before_issue(self):
        for name in ('prepared.json', 'review.json'):
            p = self.prepared / name; before = p.read_bytes(); p.write_bytes(b'{"tamper":true}')
            self.assertEqual(self.run_wrapper().returncode, 2); p.write_bytes(before)
        self.assertEqual(self.calls('capsule.calls'), [])

    def test_symlinked_private_review_rejected_before_issue(self):
        p = self.prepared / 'review.json'; p.unlink(); p.symlink_to(self.prepared / 'prepared.json')
        self.assertEqual(self.run_wrapper().returncode, 2); self.assertEqual(self.calls('capsule.calls'), [])

    def test_arbitrary_modes_and_review_hash_arguments_rejected(self):
        for args in [('prepare',), ('review',), ('issue',), ('continue',), ('a'*64,)]:
            self.assertEqual(self.run_wrapper(*args).returncode, 2)
        self.assertEqual(self.calls('capsule.calls'), [])

    def test_consumed_issuer_cannot_be_replayed_by_wrapper(self):
        self.assertEqual(self.run_wrapper(exclusive=True).returncode, 0)
        self.assertEqual(self.run_wrapper(exclusive=True).returncode, 2)
        self.assertEqual([v['mode'] for v in self.calls('capsule.calls')], ['issue','resume','owner','continue','issue'])
        self.assertEqual((self.home / 'issue.claim').read_text(), 'consumed')

    def test_published_pins_match_immutable_capsule_and_successful_target_receipts(self):
        pins = dict(re.findall(r"(?m)^  OUF_POSTBOOT_([A-Z_0-9]+)='([^']*)'$", WRAPPER.read_text()))
        self.assertEqual(pins['CAPSULE_SHA256'], hashlib.sha256((ROOT/'releases/semantic-registry-checkpoint-successor-20261023.py').read_bytes()).hexdigest())
        self.assertEqual(pins['REVIEW_HASH'], 'fff2e8499488147c3ca602f352e3ecf3dbd21d606809d123a3060c3c4f7fb800')
        self.assertEqual(pins['PREPARATION_HASH'], '9298a73a41fe51f4035745fc9bcb822f6956bb9752df26a54f715d35bbeb17a9')


if __name__ == '__main__': unittest.main()
