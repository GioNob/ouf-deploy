"""Fail-closed negative reconciliation; native S3/PG qualification is separate."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from test_storage_coordinated33_lab import FixtureS3, ledger
spec = importlib.util.spec_from_file_location('unresolved33', ROOT / 'scripts/run-storage-unresolved33-lab.py')
negative = importlib.util.module_from_spec(spec); spec.loader.exec_module(negative)


class NegativeS3(FixtureS3):
    def __init__(self, fault):
        super().__init__(); self.fault = fault; self.missing_code = 'NoSuchKey'
        if fault == 'missing': self.keys = ['lab-acked']; del self.bodies['lab-ambiguous']
        else: self.bodies['lab-ambiguous'] = negative.CORRUPT
    def __call__(self, method, key, body=b'', **kwargs):
        if self.fault == 'missing' and key == 'lab-ambiguous':
            self.calls.append((method, key, kwargs))
            assert kwargs['expected'] == (404,)
            return (f'<Error><Code>{self.missing_code}</Code></Error>'.encode() if method == 'GET' else b''), {}
        return super().__call__(method, key, body, **kwargs)


def pending():
    value = ledger(); value['control'].update(phase='DRAINING', version=1)
    value['intents'][1]['state'] = 'PENDING'; value['events'] = value['events'][:4]
    return value


class Calls:
    def __init__(self): self.value = pending(); self.calls = []; self.override = {}; self.mutate = False
    def raw(self, sql): return json.dumps(self.value)
    def call(self, name, *args, **kwargs):
        self.calls.append((name, args))
        if self.mutate: self.value['events'][0]['sequence'] += 100
        return self.override.get(name, {'reconcile':'CONFLICT', 'reserve':'EXISTING_PENDING',
                                       'finish':'FENCED', 'finish_drain':'RECONCILE_REQUIRED'}[name])


class UnresolvedTests(unittest.TestCase):
    def test_missing_object_requires_complete_list_and_explicit_404(self):
        api = NegativeS3('missing'); result = negative.observe(api, 'missing')
        self.assertEqual(['lab-acked'], result['listedKeys'])
        self.assertEqual('NoSuchKey', result['invalidObject']['code'])
        self.assertEqual(['GET', 'HEAD'], [m for m,k,_ in api.calls if k == 'lab-ambiguous'])
        self.assertTrue(all(m in ('GET', 'HEAD') for m,_,_ in api.calls))

    def test_same_length_body_corruption_overrides_claimed_hash(self):
        api = NegativeS3('corrupt'); result = negative.observe(api, 'corrupt')
        actual = result['invalidObject']
        self.assertEqual(len(negative.BODY), actual['bytes'])
        self.assertNotEqual(actual['claimedSha256'], actual['actualSha256'])
        self.assertEqual('EXACT_BODY_REQUIRED', result['rejection'])

    def test_valid_object_cannot_pass_negative_case(self):
        for fault in negative.FAULTS:
            with self.subTest(fault=fault), self.assertRaisesRegex(RuntimeError, 'INVALID_OBJECT_MUST_NOT'):
                negative.observe(FixtureS3(), fault)

    def test_transport_and_permission_errors_are_not_expected_rejection(self):
        for message in ('HTTP_403_GET', 'HTTP_500_GET', 'TIMED_OUT'):
            def fail(*args, **kwargs): raise RuntimeError(message)
            with self.subTest(error=message), self.assertRaisesRegex(RuntimeError, 'EXPECTED_RECONCILIATION_REJECTION'):
                negative.observe(fail, 'missing')

    def test_truncated_or_continued_list_is_not_absence(self):
        for attr, value in [('truncated', 'true'), ('token', '<NextContinuationToken>x</NextContinuationToken>')]:
            api = NegativeS3('missing'); setattr(api, attr, value)
            with self.assertRaisesRegex(RuntimeError, 'EXPECTED_RECONCILIATION_REJECTION'):
                negative.observe(api, 'missing')

    def test_extra_or_duplicate_list_keys_do_not_pass_missing_case(self):
        for keys in ([], ['lab-acked','lab-extra'], ['lab-acked','lab-acked']):
            api = NegativeS3('missing'); api.keys = keys
            with self.assertRaisesRegex(RuntimeError, 'EXACT_NEGATIVE_OBJECT_SET'):
                negative.observe(api, 'missing')

    def test_wrong_404_code_is_not_no_such_key(self):
        api = NegativeS3('missing'); api.missing_code = 'NoSuchBucket'
        with self.assertRaisesRegex(RuntimeError, 'EXPLICIT_NO_SUCH_KEY'):
            negative.observe(api, 'missing')

    def test_original_ack_must_survive_both_negative_cases(self):
        for fault in negative.FAULTS:
            api = NegativeS3(fault); api.bodies['lab-acked'] = b'X' + api.bodies['lab-acked'][1:]
            with self.subTest(fault=fault), self.assertRaisesRegex(RuntimeError, 'ORIGINAL_ACK_BODY'):
                negative.observe(api, fault)

    def test_corrupt_fixture_requires_exact_metadata_and_corruption(self):
        for mutation in ('metadata','body'):
            api = NegativeS3('corrupt')
            if mutation == 'metadata': api.metadata['x-amz-meta-ouf-content-hash'] = '0' * 64
            else: api.bodies['lab-ambiguous'] = b'X' * len(negative.BODY)
            with self.assertRaises(RuntimeError): negative.observe(api, 'corrupt')

    def test_blocked_attempts_preserve_pending_and_do_not_invent_missing_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            for fault in negative.FAULTS:
                calls = Calls(); observation = negative.observe(NegativeS3(fault), fault)
                result = negative.assert_blocked(calls, observation, Path(temp), fault)
                self.assertEqual(pending(), result)
                reconciles = [args for name,args in calls.calls if name == 'reconcile']
                self.assertEqual(0 if fault == 'missing' else 1, len(reconciles))
                if reconciles: self.assertEqual(negative.sha(negative.CORRUPT), reconciles[0][2])

    def test_unexpected_db_success_or_history_change_fails(self):
        observed = negative.observe(NegativeS3('corrupt'), 'corrupt')
        with tempfile.TemporaryDirectory() as temp:
            for name, answer in [('reconcile','RECONCILED'),('reserve','RESERVED'),('finish','ACKED'),('finish_drain','FROZEN')]:
                calls = Calls(); calls.override[name] = answer
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    negative.assert_blocked(calls, observed, Path(temp), 'invalid')
            calls = Calls(); calls.mutate = True
            with self.assertRaises(RuntimeError): negative.assert_blocked(calls, observed, Path(temp), 'mutation')

    def test_terminal_events_or_lost_ack_cannot_pass_pending_validator(self):
        for mutation in ('terminal','state','ack','epoch','history'):
            value = pending()
            if mutation == 'terminal': value['events'].append(copy.deepcopy(value['events'][-1]))
            if mutation == 'state': value['intents'][1]['state'] = 'RECONCILED'
            if mutation == 'ack': value['intents'][0]['state'] = 'PENDING'
            if mutation == 'epoch': value['control']['epoch'] = 1
            if mutation == 'history': value['events'][1]['kind'] = 'RESERVED'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError): negative.validate_pending(value)


if __name__ == '__main__': unittest.main()
