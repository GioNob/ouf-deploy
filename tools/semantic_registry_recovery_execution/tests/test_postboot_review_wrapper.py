"""Real shell/isolated-root launcher with disposable gh/sudo and capsule fixtures.

The transport and preparation/review application are explicit substitutes. These
tests prove launch restrictions, pins, receipt gates and no automatic replay;
they do not exercise target preparation, IAM, Docker or the complete native CLI.
The component CI runs this suite from an isolated root-owned checkout.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
WRAPPER = ROOT / 'releases/semantic-registry-postboot-prepare-review-20261023.sh'
SOURCE = 'a' * 40
ARTIFACT = 'b' * 40


class ReviewWrapper(unittest.TestCase):
    wrapper = WRAPPER
    capsule_name = "semantic-registry-postboot-20261023.py"
    audit_path = "evidence/semantic-registry-postboot-source-membership-20261023.json"
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'isolated root-owned component fixture required')
        self.temporary = tempfile.TemporaryDirectory(prefix='postboot-review-wrapper-fixture-', dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.bin = self.home / 'bin'; self.bin.mkdir()
        gh = self.home / 'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
        gh.parent.mkdir(parents=True)
        self.executable(gh, '''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['OUF_WRAPPER_FIXTURE'])
with (root / 'gh.calls').open('a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
if (root / 'download.fail').exists():
    print('disposable private transport diagnostic', file=sys.stderr)
    raise SystemExit(7)
sys.stdout.buffer.write((root / 'fixture-capsule.py').read_bytes())
''')
        self.executable(self.bin / 'sudo', '''#!/bin/sh
printf '%s\\n' "$*" >> "$OUF_WRAPPER_FIXTURE/sudo.calls"
test "$1" = '--' || exit 9
shift
exec "$@"
''')
        self.environment = {**os.environ, 'HOME': str(self.home),
            'PATH': str(self.bin) + ':/usr/bin:/bin', 'OUF_WRAPPER_FIXTURE': str(self.home)}

    def executable(self, path, text):
        path.write_text(text); path.chmod(0o700)

    def capsule(self, *, source=SOURCE, prepare_failure=False, bad_prepare_receipt=False,
                exclusive=False):
        delivery = {'nativeDeclaration': {'sourceCommit': source, 'sourcePins': {'ouf-deploy': source}}}
        text = f'''DELIVERY = {delivery!r}
import json, os, pathlib, sys
root = pathlib.Path({str(self.home)!r})
mode = sys.argv[1]
with (root / 'capsule.calls').open('a') as stream:
    stream.write(json.dumps({{'mode': mode, 'pid': os.getpid(),
        'isolated': sys.flags.isolated, 'noSite': sys.flags.no_site,
        'noBytecode': sys.dont_write_bytecode}}) + '\\n')
if {exclusive!r}:
    try:
        with (root / ('claim.' + mode)).open('x') as stream:
            stream.write('consumed')
    except FileExistsError:
        print('{{"status":"STOP_RECONCILE","reasonCode":"FIXTURE_CLAIM_ALREADY_CONSUMED"}}')
        raise SystemExit(2)
if mode == 'prepare' and {prepare_failure!r}:
    print('{{"status":"STOP_RECONCILE","reasonCode":"FIXTURE_PREPARE_FAILED"}}')
    raise SystemExit(2)
receipt = {{'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
    'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False,
    'runtimeEffectsDispatched': 0}}
if mode == 'prepare':
    receipt.update(schema='ouf.semantic-registry-postboot-preparation-result.v1',
        status='CURRENT_POSTBOOT_INPUTS_PREPARED', complete=True, oauthRequests=0)
    if {bad_prepare_receipt!r}:
        receipt['targetApplyAuthorized'] = True
elif mode == 'review':
    receipt.update(schema='ouf.semantic-registry-postboot-review-result.v1',
        status='COMPLETE_PRIVATE_POSTBOOT_REVIEW_PREPARED', signedScopeCount=11)
else:
    raise SystemExit(9)
print(json.dumps(receipt), flush=True)
'''
        raw = text.encode()
        (self.home / 'fixture-capsule.py').write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def render(self, *, digest=None, source=SOURCE, artifact=ARTIFACT):
        text = self.wrapper.read_text()
        pins = {'SOURCE_COMMIT': source, 'CAPSULE_COMMIT': artifact,
                'CAPSULE_SHA256': digest if digest is not None else self.capsule()}
        for name, value in pins.items():
            text, count = re.subn(r"(?m)^(  OUF_POSTBOOT_" + name + r"=)'[^']*'$",
                                 lambda match: match[1] + repr(value), text)
            self.assertEqual(count, 1)
        path = self.home / 'wrapper.sh'; self.executable(path, text)
        return path

    def run_wrapper(self, *args, **pins):
        return subprocess.run(['/usr/bin/bash', str(self.render(**pins)), *args],
            env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)

    def calls(self, name):
        path = self.home / name
        return [] if not path.exists() else [json.loads(line) for line in path.read_text().splitlines()]

    def retained(self):
        return sorted(self.home.glob('ouf-registry-postboot-review.*'))

    def test_wrapper_is_either_wholly_draft_or_matches_the_audited_capsule(self):
        pins = dict(re.findall(r"(?m)^  OUF_POSTBOOT_(SOURCE_COMMIT|CAPSULE_COMMIT|CAPSULE_SHA256)='([^']*)'$",
                               self.wrapper.read_text()))
        self.assertEqual(set(pins), {'SOURCE_COMMIT', 'CAPSULE_COMMIT', 'CAPSULE_SHA256'})
        if any(value.startswith('PENDING_') for value in pins.values()):
            self.assertEqual(pins, {'SOURCE_COMMIT': 'PENDING_QUALIFIED_SOURCE_COMMIT',
                'CAPSULE_COMMIT': 'PENDING_PUBLISHED_CAPSULE_COMMIT',
                'CAPSULE_SHA256': 'PENDING_VERIFIED_CAPSULE_SHA256'})
            return
        audit = json.loads((ROOT / self.audit_path).read_bytes())
        self.assertEqual(pins['SOURCE_COMMIT'], audit['sourceCommit'])
        self.assertRegex(pins['CAPSULE_COMMIT'], r'^[0-9a-f]{40}$')
        self.assertNotEqual(pins['CAPSULE_COMMIT'], pins['SOURCE_COMMIT'])
        self.assertEqual(pins['CAPSULE_SHA256'], audit['capsule']['sha256'])
        self.assertEqual(pins['CAPSULE_SHA256'], hashlib.sha256((ROOT / audit['capsule']['path']).read_bytes()).hexdigest())

    def test_unqualified_pins_and_forbidden_modes_stop_before_delivery(self):
        result = self.run_wrapper(source='PENDING_QUALIFIED_SOURCE_COMMIT')
        self.assertEqual(result.returncode, 2)
        for args in [('issue',), ('continue',), ('install',), ('bootstrap',), ('owner',),
                     ('status',), ('prepare',), ('prepare-review', 'extra')]:
            with self.subTest(args=args):
                self.assertEqual(self.run_wrapper(*args).returncode, 2)
        self.assertEqual(self.calls('gh.calls'), [])
        self.assertFalse((self.home / 'sudo.calls').exists())
        self.assertEqual(self.retained(), [])

    def test_prepare_then_review_use_distinct_isolated_interpreters_and_retained_logs(self):
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
        calls = self.calls('capsule.calls')
        self.assertEqual([item['mode'] for item in calls], ['prepare', 'review'])
        self.assertEqual(len({item['pid'] for item in calls}), 2)
        for item in calls:
            self.assertEqual(item['isolated'], 1); self.assertEqual(item['noSite'], 1)
            self.assertIs(item['noBytecode'], True)
        gh_calls = self.calls('gh.calls'); self.assertEqual(len(gh_calls), 1)
        self.assertIn('Accept: application/vnd.github.raw+json', gh_calls[0])
        self.assertEqual(gh_calls[0][-1],
            'repos/GioNob/ouf-deploy/contents/releases/' + self.capsule_name + '?ref=' + ARTIFACT)
        directories = self.retained(); self.assertEqual(len(directories), 1)
        directory = directories[0]
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertIn(str(directory / 'operator.log').encode(), result.stdout)
        for name in ('operator.log', 'prepare.log', 'review.log', 'download.stderr', 'prepare.stderr', 'review.stderr'):
            self.assertEqual((directory / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(len((directory / 'operator.log').read_text().splitlines()), 3)

    def test_explicit_review_does_not_prepare(self):
        result = self.run_wrapper('review')
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        self.assertEqual([item['mode'] for item in self.calls('capsule.calls')], ['review'])
        self.assertFalse((self.retained()[0] / 'prepare.log').exists())

    def test_prepare_failure_stops_without_review_or_retry(self):
        result = self.run_wrapper(digest=self.capsule(prepare_failure=True))
        self.assertEqual(result.returncode, 2)
        self.assertEqual([item['mode'] for item in self.calls('capsule.calls')], ['prepare'])
        self.assertEqual(len(self.calls('gh.calls')), 1)
        self.assertIn(b'PREPARATION_OR_REVIEW_NOT_COMPLETED', result.stdout)

    def test_success_exit_with_invalid_prepare_receipt_cannot_advance(self):
        result = self.run_wrapper(digest=self.capsule(bad_prepare_receipt=True))
        self.assertEqual(result.returncode, 2)
        self.assertEqual([item['mode'] for item in self.calls('capsule.calls')], ['prepare'])
        self.assertIn(b'EXPECTED_PRIVATE_REVIEW_RECEIPT_UNCONFIRMED', result.stdout)

    def test_hash_and_embedded_source_mismatch_prevent_capsule_execution(self):
        for embedded, digest in [(SOURCE, '0' * 64), ('c' * 40, None)]:
            with self.subTest(embedded=embedded):
                observed = self.capsule(source=embedded)
                result = self.run_wrapper(digest=digest or observed)
                self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls('capsule.calls'), [])

    def test_download_failure_stops_before_root_launcher_and_keeps_private_diagnostic(self):
        (self.home / 'download.fail').touch()
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'PINNED_CAPSULE_DOWNLOAD_UNCONFIRMED', result.stdout)
        self.assertNotIn(b'disposable private transport diagnostic', result.stdout + result.stderr)
        self.assertFalse((self.home / 'sudo.calls').exists())
        self.assertIn('disposable private transport diagnostic',
            (self.retained()[0] / 'download.stderr').read_text())

    def test_consumed_preparation_is_not_replaced_or_bypassed_on_reinvocation(self):
        digest = self.capsule(exclusive=True)
        self.assertEqual(self.run_wrapper(digest=digest).returncode, 0)
        second = self.run_wrapper(digest=digest)
        self.assertEqual(second.returncode, 2)
        self.assertEqual([item['mode'] for item in self.calls('capsule.calls')], ['prepare', 'review', 'prepare'])
        third = self.run_wrapper('review', digest=digest)
        self.assertEqual(third.returncode, 2)
        self.assertEqual([item['mode'] for item in self.calls('capsule.calls')],
                         ['prepare', 'review', 'prepare', 'review'])
        self.assertEqual((self.home / 'claim.prepare').read_text(), 'consumed')
        self.assertEqual((self.home / 'claim.review').read_text(), 'consumed')


class PropertiesReviewWrapper(ReviewWrapper):
    wrapper = ROOT / 'releases/semantic-registry-postboot-properties-prepare-review-20261023.sh'
    capsule_name = 'semantic-registry-postboot-properties-20261023.py'
    audit_path = 'evidence/semantic-registry-postboot-properties-source-membership-20261023.json'


if __name__ == '__main__':
    unittest.main()
