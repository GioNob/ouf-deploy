import importlib.util
import json
from pathlib import Path
import unittest

s = importlib.util.spec_from_file_location('diagnosis', Path(__file__).resolve().parents[1] / 'scripts/read-current-r10-denial.py')
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)

class ProjectionTests(unittest.TestCase):
    def test_secret_fields_and_arbitrary_messages_are_never_emitted(self):
        value = {'status': 'LEASE_WORKER_FAILED', 'reason': 'secret value here',
                 'password': 'fixture-secret', 'exceptionChain': [{'reason': 'NATIVE_READ_FAILED',
                 'stderr': 'fixture-secret', 'exceptionPoints': [{'file': 'fixture-secret'}]}]}
        result = m.project(value)
        self.assertEqual(result['reason'], 'UNPROJECTED')
        self.assertEqual(result['exceptionChain'], [{'reason': 'NATIVE_READ_FAILED'}])
        self.assertNotIn('fixture-secret', json.dumps(result))
    def test_active_failed_and_quiesced_statuses_remain_observations(self):
        for status in ('LEASE_ACTIVE', 'LEASE_WORKER_FAILED', 'QUIESCED'):
            self.assertEqual(m.project({'status': status, 'refreshCount': 12, 'workerPid': 123}),
                             {'status': status, 'refreshCount': 12, 'workerPid': 123})
    def test_types_and_chain_size_are_bounded(self):
        result = m.project({'refreshCount': True, 'workerPid': -1, 'errno': 'private',
                            'setsRevoked': 'true', 'exceptionChain': [{'reason': 'FAILED'}] * 10})
        self.assertEqual(result, {'exceptionChain': [{'reason': 'FAILED'}] * 6})

if __name__ == '__main__':
    unittest.main()
