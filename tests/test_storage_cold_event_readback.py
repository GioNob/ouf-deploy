"""Synthetic retained journals only; no target/provider or service operations."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

r = load('event_readback', 'scripts/read-storage-cold-event-held-20261107.py')
f = load('stop_fixture', 'tests/test_storage_test_cold_stop.py')
linked = load('linked_backup', 'scripts/storage-host-bound-cold-backup-20261107.py')
b, p, d = f.b, f.p, f.d

class JournalRunner(f.FakeRunner):
    def __init__(self, host, root):
        super().__init__(host)
        self.root = root
        self.calls = 3
        (root / 'docker-client').mkdir(mode=0o700)

    def record(self, raw, stderr=b''):
        b.new(self.root / ('command-%03d.private' % self.calls), raw)
        b.new(self.root / ('command-%03d.stderr.private' % self.calls), stderr)
        return raw

    def inventory(self, ids):
        self.calls += 1
        self.record(('\n'.join(sorted(self.host)) + '\n').encode())
        self.calls += 1
        self.record(b.canonical([self.host[cid] for cid in sorted(ids)]))
        self.calls += 1
        self.record(b''.join(b.canonical(self.host[cid]) for cid in sorted(set(self.host) - ids)))
        return copy.deepcopy(self.host)

    def docker(self, *args, **kwargs):
        raw = super().docker(*args, **kwargs)
        return self.record(raw)

class EventReviewTests(unittest.TestCase):
    def setUp(self):
        # Use protected workspace ancestry, not world-writable /tmp.
        self.tmp = tempfile.TemporaryDirectory(prefix='event-review-', dir=ROOT.parent)
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.patch_area = patch.object(r, 'AREA', self.root)
        self.patch_area.start();self.addCleanup(self.patch_area.stop)
        for sub in ('stop', 'capture', 'host-checks'):
            (self.root / sub).mkdir(mode=0o700)
        fixture = f.fixture.ProposalTests();fixture.setUp()
        self.host, self.plan = fixture.host, fixture.plan
        self.plan.update(programSha256=r.PROGRAM_SHA, validUntilEpoch=20000, runtimeSources={})
        for doc in self.host.values():
            doc['State'].update(Paused=False, Restarting=False, OOMKilled=False, Error='')
        cid = self.plan['roles']['onboarding']['containerId']
        self.cid = cid
        self.host[cid]['Config']['Healthcheck'] = {'Test': ['CMD-SHELL', 'curl --header secret-canary https://private-canary']}
        self.plan['roles']['onboarding']['fingerprint'] = b.fingerprint(self.host[cid])
        hashes = {'continuation-result.json': r.HOST_RESULT_SHA}
        self.plan['hostContainmentLink'] = {'hostEvidenceSha256': hashes,
            'runtimeSourceSnapshotSha256': r.SNAPSHOT_SHA}
        b.new(self.root / 'plan.private.json', b.canonical(self.plan))
        b.new(self.root / 'operation-claim.private.json', b.canonical({
            'decisionReference': r.DECISION, 'attempts': 1, 'hostReceiptSha256': hashes}))
        self.run = JournalRunner(self.host, self.root / 'stop')
        for action in ('exec_create: /bin/sh -c curl --header secret-canary https://private-canary',
                       'exec_start: /bin/sh -c curl --header secret-canary https://private-canary', 'exec_die'):
            self.run.events.append({'Type': 'container', 'Action': action,
                'Actor': {'ID': cid, 'Attributes': {'execID': 'private-exec-canary', 'exitCode': '0'}}})
        with self.assertRaisesRegex(b.Held, '^UNEXPECTED_CONTAINER_EVENT$'):
            d.stop_once(vars(b), vars(p), self.plan, self.host, self.root / 'stop', self.run, r.DECISION,
                wall=lambda: self.run.clock, monotonic=lambda: self.run.clock, sleep=self.run.sleep)

    def review(self):
        # Reading must never call providers, writers, live credential trees or capture.
        denied = lambda *a, **kw: self.fail('forbidden mutation/provider/live-source function')
        h = dict(vars(b))
        for name in ('new', 'verify_runtime_sources', 'offline', 'capture', 'Runner'):
            h[name] = denied
        with patch('subprocess.run', denied), patch('subprocess.Popen', denied):
            return r.review(h, linked)

    def test_full_post_mutation_journal_redacted_and_preserved(self):
        before = {str(x.relative_to(self.root)): (x.read_bytes(), b.frame(x.stat()))
            for x in self.root.rglob('*') if x.is_file()}
        result = self.review()
        self.assertEqual(result['mutationRepliesBound'], 49)
        self.assertEqual(result['verifiedRestartPolicyReceipts'], 35)
        self.assertEqual(result['retainedHostContainerCount'], 145)
        self.assertEqual(result['retainedRunningContainerCount'], 0)
        self.assertEqual(len(result['stoppedGroups']), 5)
        self.assertTrue(result['captureDirectoryEmpty'])
        self.assertTrue(all(x['cleanExitAtRetainedObservation'] for x in result['retainedRoles'].values()))
        self.assertEqual(result['events']['unexpectedByOriginalFilter'], 3)
        self.assertFalse(result['events']['healthcheckAttributionProven'])
        self.assertTrue(all(x['linkedExecCommandMatchesConfiguredHealthcheck'] for x in result['events']['groups'] if x['actionFamily'].startswith('exec_')))
        self.assertNotIn('canary', json.dumps(result))
        self.assertNotIn(self.cid, json.dumps(result))
        after = {str(x.relative_to(self.root)): (x.read_bytes(), b.frame(x.stat()))
            for x in self.root.rglob('*') if x.is_file()}
        self.assertEqual(before, after)

    def test_stderr_is_hashed_but_never_exported_or_blocks_diagnosis(self):
        (self.root / 'stop/command-004.stderr.private').write_bytes(b'warning-secret-canary')
        result = self.review()
        self.assertEqual(result['nonemptyCommandStderrFiles'], 1)
        self.assertNotIn('canary', json.dumps(result))

    def test_tampered_intent_rejected(self):
        path = self.root / 'stop/action-001.intent.private.json'
        doc = b.decode(path.read_bytes());doc['args'][1] = '--restart=always'
        path.write_bytes(b.canonical(doc))
        with self.assertRaisesRegex(ValueError, 'ACTION_SCOPE_MISMATCH'):self.review()

    def test_missing_reply_rejected(self):
        (self.root / 'stop/action-049.reply.private.json').unlink()
        with self.assertRaises(FileNotFoundError):self.review()

    def test_receipt_symlink_rejected(self):
        path = self.root / 'stop/command-004.stderr.private'
        path.unlink();path.symlink_to(self.root / 'plan.private.json')
        with self.assertRaises(OSError):self.review()

    def test_foreign_and_unknown_events_not_allowed_or_exposed(self):
        events = [{'Type':'container','Action':'exec_create: private-canary','Actor':{'ID':'foreign-canary','Attributes':{'execID':'x'}}},
                  {'Type':'container','Action':'unknown-private-canary','Actor':{'ID':self.cid}}]
        result = r.summarize_events(events, {self.cid:'onboarding'}, {self.cid}, {self.cid}, self.host)
        self.assertEqual(result['unexpectedByOriginalFilter'],2)
        self.assertEqual(result['groups'][0]['actorClass'],'OTHER_CONTAINER')
        self.assertEqual(result['groups'][1]['actionFamily'],'OTHER')
        self.assertNotIn('canary',json.dumps(result))

if __name__ == '__main__':unittest.main()
