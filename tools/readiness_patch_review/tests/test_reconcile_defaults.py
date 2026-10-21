import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_compiler import fixture, io

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('defaults_reader', ROOT / 'reconcile_defaults.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class DefaultsReconciliationTests(unittest.TestCase):
    def test_closed_boolean_observations_never_print_unexpected_values(self):
        result = r.compare({'OpenStdin': False, 'Env': ['SECRET=never-print']},
                           {'OpenStdin': None, 'Tty': 'never-print'}, {})
        self.assertEqual(result['OpenStdin']['oldImage']['value'], False)
        self.assertIsNone(result['OpenStdin']['candidateImage']['value'])
        self.assertEqual(result['OpenStdin']['capturedContainer'], {'present': False})
        self.assertEqual(result['Tty']['candidateImage'], {'present': True, 'type': 'str', 'isEmpty': False})
        self.assertEqual(r.observation({'Hostname': ''}, 'Hostname'),
                         {'present': True, 'type': 'str', 'isEmpty': True})
        self.assertNotIn('never-print', json.dumps(result))

    def test_tampered_helper_never_executes(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'input_reader.py').write_text('raise RuntimeError("executed")')
            with self.assertRaises(ValueError):
                r.load_io(Path(tmp))

    def test_offline_no_writes_retains_existing_review_and_detects_changed_inputs(self):
        case, snapshot, review, row, packet, candidate = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case['snapshotRoot'] = str(root)
            complete = {'caseHash': case['inputCaseHash'], 'snapshotHash': io.digest(snapshot),
                        'complete': True, 'runtimeAuthorityIssued': False}
            values = {'snapshot.json': snapshot, 'complete.json': complete,
                      'review.json': review, 'recovery.json': row, 'image-inspect.json': [candidate]}
            calls = []
            def read(path, expected=None, root_owned=False):
                calls.append((str(path), expected, root_owned))
                value = values.get(Path(path).name, packet)
                return value, io.encoded(value)
            original = Path.lstat
            def owned(path):
                s = original(path)
                return SimpleNamespace(st_uid=0, st_mode=s.st_mode) if path == root else s
            target = root / ('ingestion-readiness-patch-review-' + io.digest(case))
            with patch.object(io, 'read_json', read), patch.object(Path, 'lstat', owned), \
                    patch('socket.socket', side_effect=AssertionError('network')), \
                    patch('os.mkdir', side_effect=AssertionError('write')):
                result = r.run(io, case)
                self.assertFalse(result['reviewContextExists'])
                self.assertFalse(result['compatibilityEstablished'])
                self.assertNotIn('private-fixture-value', json.dumps(result))
                self.assertTrue(all(x[2] for x in calls))
                self.assertIn(snapshot['retainedReviewHash'], [x[1] for x in calls])
            target.mkdir()
            (target / 'claim.json').write_text('retained')
            with patch.object(io, 'read_json', read), patch.object(Path, 'lstat', owned):
                self.assertTrue(r.run(io, case)['reviewContextExists'])
            self.assertEqual((target / 'claim.json').read_text(), 'retained')
            complete['snapshotHash'] = 'changed'
            with patch.object(io, 'read_json', read):
                with self.assertRaisesRegex(io.Stop, 'EXACT_COMPLETED_INPUT_SNAPSHOT_REQUIRED'):
                    r.run(io, case)


if __name__ == '__main__':
    unittest.main()
