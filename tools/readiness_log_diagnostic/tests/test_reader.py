import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('reader', Path(__file__).parents[1] / 'reader.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class DiagnosticTests(unittest.TestCase):
    def test_only_closed_codes_and_categories_escape_log_filter(self):
        secret = 'Bearer very-private-value password=never-print https://private/asset'
        result = m.classify((secret + '\nING_ACTIVATION_GATEWAY_503\nING_ACTIVATION_GATEWAY_503 '
                             'ONB_READINESS_DEPENDENCY_503 connect() failed (111: Connection refused) '
                             'ING_ACTIVATION_GATEWAY_503_SECRET').encode())
        self.assertEqual(result['safeCodes'], {'ING_ACTIVATION_GATEWAY_503': 2,
                                              'ONB_READINESS_DEPENDENCY_503': 1})
        self.assertEqual(result['transportCategories'], {'UPSTREAM_CONNECT_REFUSED': 1})
        encoded = json.dumps(result)
        for value in ('very-private-value', 'password', 'https://', '_SECRET'):
            self.assertNotIn(value, encoded)

    def test_multiplex_frames_and_truncation(self):
        raw = b'ING_READINESS_DEADLINE\n'
        frame = struct.pack('>BBBBI', 2, 0, 0, 0, len(raw)) + raw
        self.assertEqual(m.unframe(frame, True), raw)
        with self.assertRaises(m.Stop):
            m.unframe(frame[:-1], True)
        self.assertEqual(m.unframe(raw, False), raw)

    def test_no_default_socket_arbitrary_get_or_extra_budget(self):
        engine = m.Engine({'socketPath': '/fixture/engine'}, {'a' * 64}, 1, 2)
        for path in ('/containers/json', '/v1.44/containers/' + 'b' * 64 + '/json',
                     '/v1.44/containers/' + 'a' * 64 + '/start'):
            with self.assertRaisesRegex(m.Stop, 'CLOSED_NINE_GET_BUDGET'):
                engine.get(path)
        engine.calls = 9
        with self.assertRaisesRegex(m.Stop, 'CLOSED_NINE_GET_BUDGET'):
            engine.get('/v1.44/containers/' + 'a' * 64 + '/json')

    def test_completed_context_and_generation_recheck(self):
        pins = {name: {'containerId': char * 64, 'pid': n, 'startedAt': 'frozen'}
                for name, char, n in [('ingestion', 'a', 1), ('gateway', 'b', 2), ('onboarding', 'c', 3)]}
        stages = [{'name': 'ingestion.START_REPLACEMENT'}, {'name': 'gateway.START_REPLACEMENT'}]
        stages += [{'name': 'other'}] * 26
        effects = [{'state': 'APPLIED', 'nativeResource': pins[name]} for name in ('ingestion', 'gateway')]
        effects += [{'state': 'APPLIED'}] * 26
        review = {'executionReview': {'stages': stages, 'engineBinding': {}, 'runtimeGuardProfile': {
            'unchangedApplications': {'onboarding': {'binding': pins['onboarding']}}}}}
        row = {'nextStage': 28, 'effects': effects}
        case = {'schema': 'ouf.readiness-log-diagnostic-case.v1', 'contextPath': '/fixture',
                'replacementIds': {n: pins[n]['containerId'] for n in ('ingestion', 'gateway')},
                'since': 1, 'until': 2}

        class FakeEngine:
            drift = False
            def __init__(self, *_):
                self.calls = 0
                self.logs = {p['containerId']: 'logs' for p in pins.values()}
            def inspect(self, cid):
                self.calls += 1
                pin = next(p for p in pins.values() if p['containerId'] == cid)
                return {'Id': cid, 'State': {'Pid': pin['pid'] + int(self.drift and self.calls > 6),
                        'StartedAt': 'frozen', 'Running': True}, 'Config': {'Tty': True, 'Env': ['SECRET']}}
            def get(self, path):
                self.calls += 1
                return b'ING_READINESS_DEADLINE secret=hidden'

        def read(path):
            return (review, b'review') if path.endswith('review.json') else (row, b'row')

        with patch.object(m, 'private_json', read), patch.object(m, 'Engine', FakeEngine):
            result = m.run(case)
            self.assertEqual(result['engineGets'], 9)
            self.assertFalse(result['rootCauseEstablished'])
            self.assertNotIn('hidden', json.dumps(result))
            FakeEngine.drift = True
            with self.assertRaisesRegex(m.Stop, 'RUNTIME_GENERATION_CHANGED'):
                m.run(case)
            FakeEngine.drift = False
            row['nextStage'] = 27
            with self.assertRaisesRegex(m.Stop, 'COMPLETED_ROLLOUT_REQUIRED'):
                m.run(case)


if __name__ == '__main__':
    unittest.main()
