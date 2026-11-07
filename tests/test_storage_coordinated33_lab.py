"""Negative tests for the quiesced joint cut; native qualification is separate."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('cut33', ROOT / 'scripts/run-storage-coordinated33-lab.py')
cut = importlib.util.module_from_spec(spec); spec.loader.exec_module(cut)


def ledger():
    events = [('RESERVED', 'lab-acked', 1, 0), ('ACKED', 'lab-acked', 1, 0),
              ('RESERVED', 'lab-ambiguous', 1, 0), ('DRAINING', None, 2, 1),
              ('RECONCILED', 'lab-ambiguous', 2, 1), ('FROZEN', None, 2, 2)]
    return {'control': {'singleton': True, 'epoch': 2, 'version': 2, 'phase': 'FROZEN'},
        'intents': [dict(operation=op, epoch=1, body_hash=cut.sha(body), body_bytes=len(body),
            state='ACKED' if op == 'lab-acked' else 'RECONCILED') for op, body in sorted(cut.BODIES.items())],
        'events': [dict(sequence=n, kind=k, operation=o, epoch=e, version=v)
                   for n, (k, o, e, v) in enumerate(events, 1)]}


class FixtureS3:
    def __init__(self):
        self.bodies = copy.deepcopy(cut.BODIES)
        self.keys = sorted(self.bodies)
        self.truncated = 'false'
        self.token = ''
        self.metadata = {}
        self.deny_code = 'AccessDenied'
        self.calls = []

    def __call__(self, method, key, body=b'', **kwargs):
        self.calls.append((method, key, kwargs))
        if method == 'GET' and key == '':
            entries = ''.join('<Contents><Key>' + k + '</Key></Contents>' for k in self.keys)
            return (f'<ListBucketResult xmlns="{cut.NS["s"]}"><IsTruncated>{self.truncated}</IsTruncated>'
                    f'{entries}{self.token}</ListBucketResult>').encode(), {}
        if method in ('PUT', 'DELETE'):
            if kwargs['expected'] != (403,):
                raise AssertionError('Only denied requests allowed in frozen verification')
            return f'<Error><Code>{self.deny_code}</Code></Error>'.encode(), {}
        data = self.bodies[key]
        headers = {'content-length': str(len(data)), 'content-type': cut.MIME,
                   'x-amz-meta-ouf-content-hash': cut.sha(cut.BODIES[key]),
                   'x-amz-meta-ouf-recovery-generation': 'fixture33-epoch1', **self.metadata}
        return (data if method == 'GET' else b''), headers


class CommonCutTests(unittest.TestCase):
    def test_real_bytes_and_catalog_reconcile(self):
        api = FixtureS3()
        cut.compare_readback(ledger(), {'objects': cut.read_objects(api)})
        self.assertEqual(2, sum(method == 'HEAD' for method, _, _ in api.calls))

    def test_pending_ack_missing_or_rewritten_prevents_cut(self):
        for mutation in ('pending', 'lost_ack', 'extra', 'hash', 'size'):
            with self.subTest(mutation=mutation):
                value = ledger()
                if mutation == 'pending': value['intents'][1]['state'] = 'PENDING'
                if mutation == 'lost_ack': value['intents'][0]['state'] = 'RECONCILED'
                if mutation == 'extra': value['intents'].append(copy.deepcopy(value['intents'][0]))
                if mutation == 'hash': value['intents'][0]['body_hash'] = '0' * 64
                if mutation == 'size': value['intents'][0]['body_bytes'] += 1
                with self.assertRaisesRegex(RuntimeError, 'EXACT_TERMINAL_INTENTS'):
                    cut.validate_ledger(value)

    def test_unfrozen_or_stale_epoch_prevents_cut(self):
        for field, bad in [('phase', 'DRAINING'), ('epoch', 1), ('version', 1)]:
            value = ledger(); value['control'][field] = bad
            with self.assertRaisesRegex(RuntimeError, 'EXACT_FROZEN_CONTROL'):
                cut.validate_ledger(value)

    def test_original_history_must_survive_restore(self):
        value = ledger(); value['events'][1]['kind'] = 'RECONCILED'
        with self.assertRaisesRegex(RuntimeError, 'EXACT_ACK_AND_FENCE_HISTORY'):
            cut.validate_ledger(value)

    def test_missing_extra_duplicate_objects_fail(self):
        for keys in [['lab-acked'], ['lab-acked', 'lab-ambiguous', 'lab-extra'],
                     ['lab-acked', 'lab-acked', 'lab-ambiguous']]:
            api = FixtureS3(); api.keys = keys
            with self.assertRaisesRegex(RuntimeError, 'EXACT_OBJECT_SET'):
                cut.read_objects(api)

    def test_incomplete_listing_fails(self):
        for truncated, token in [('true', ''), ('false', '<NextContinuationToken>x</NextContinuationToken>')]:
            api = FixtureS3(); api.truncated = truncated; api.token = token
            with self.assertRaisesRegex(RuntimeError, 'COMPLETE_LIST'):
                cut.read_objects(api)

    def test_equal_length_corruption_with_old_hash_fails(self):
        api = FixtureS3(); body = api.bodies['lab-acked']
        api.bodies['lab-acked'] = b'X' + body[1:]
        with self.assertRaisesRegex(RuntimeError, 'EXACT_BODY'):
            cut.read_objects(api)

    def test_mime_hash_generation_and_length_are_checked(self):
        for name, value in [('content-type', 'text/plain'), ('content-length', '0'),
                            ('x-amz-meta-ouf-content-hash', '0' * 64),
                            ('x-amz-meta-ouf-recovery-generation', 'other')]:
            api = FixtureS3(); api.metadata[name] = value
            with self.assertRaisesRegex(RuntimeError, 'GET_HEAD_METADATA'):
                cut.read_objects(api)

    def test_only_explicit_access_denied_counts_as_fence(self):
        api = FixtureS3()
        self.assertEqual(3, len(cut.denied_mutations(api)))
        self.assertEqual([('PUT', 'lab-late'), ('PUT', 'lab-acked'), ('DELETE', 'lab-acked')],
                         [(m, k) for m, k, _ in api.calls])
        api.deny_code = 'InvalidAccessKeyId'
        with self.assertRaisesRegex(RuntimeError, 'EXPLICIT_ACCESS_DENIED'):
            cut.denied_mutations(api)

    def test_readback_is_bound_to_actual_catalog(self):
        observed = {'objects': cut.read_objects(FixtureS3())}
        observed['objects']['lab-acked']['bytes'] += 1
        with self.assertRaisesRegex(RuntimeError, 'CATALOG_S3_MISMATCH'):
            cut.compare_readback(ledger(), observed)

    def test_exact_cohort_binding_works_from_committed_original(self):
        import tempfile
        bound = cut.labs.binding_api.load(ROOT, cut.LOCK_SHA)
        archive = ROOT / 'evidence/artifacts/seaweedfs-generation33-cohort-41794344274.zip'
        with tempfile.TemporaryDirectory() as folder:
            receipt = cut.labs.bind_cohort_artifact(archive, Path(folder) / 'cohort', bound,
                                                   cut.COHORT_ARCHIVE_SHA, cut.COHORT_SHA)
            self.assertEqual(33, cut.binding(receipt)['lock']['generation'])


if __name__ == '__main__':
    unittest.main()
