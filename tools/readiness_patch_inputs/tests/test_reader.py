import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('patch_reader', Path(__file__).parents[1] / 'reader.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InputCaptureTests(unittest.TestCase):
    def test_public_copy_hash_and_symlink_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'image.tar.gz'
            source.write_bytes(b'public-archive')
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(m.copy_public(source, root / 'retained', expected, 100), 14)
            self.assertEqual(stat.S_IMODE((root / 'retained').stat().st_mode), 0o400)
            with self.assertRaisesRegex(m.Stop, 'PUBLIC_ARTIFACT_HASH_MISMATCH'):
                m.copy_public(source, root / 'wrong', '0' * 64, 100)
            (root / 'link').symlink_to(source)
            with self.assertRaises(OSError):
                m.copy_public(root / 'link', root / 'unsafe', expected, 100)
            (root / 'dirlink').symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                m.copy_public(root / 'dirlink/image.tar.gz', root / 'unsafe2', expected, 100)

    def test_stable_binding_ignores_health_tick_but_rejects_actual_config_change(self):
        first = self.actual('a' * 64, 1)
        second = copy.deepcopy(first)
        second['State']['Health'] = {'Log': ['new health tick']}
        self.assertEqual(m.stable(first), m.stable(second))
        second['Config']['Env'].append('NEW_SETTING=changed')
        self.assertNotEqual(m.stable(first), m.stable(second))

    @staticmethod
    def actual(cid, pid):
        return {'Id': cid, 'Image': 'sha256:' + 'f' * 64, 'RestartCount': 0,
                'Config': {'Env': ['PASSWORD=must-stay-private'], 'Labels': {'org.opencontainers.image.revision': 'baseline'},
                           'Cmd': ['--spring.flyway.enabled=false', '--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY']},
                'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0}},
                'Mounts': [], 'NetworkSettings': {'Networks': {}},
                'State': {'Pid': pid, 'StartedAt': 'fixed-start', 'Running': True, 'Paused': False,
                          'Restarting': False, 'Dead': False}}

    def test_private_snapshot_no_runtime_effects_and_existing_claim_no_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = {name: self.actual(char * 64, i + 1) for i, (name, char) in enumerate(
                [('ingestion', 'a'), ('gateway', 'b'), ('onboarding', 'c'), ('mcp', 'd'), ('udp', 'e'), ('postgres', 'f')])}
            native = {'stages': [{'name': 'ingestion.START_REPLACEMENT', 'intentHash': 'a'},
                                 {'name': 'gateway.START_REPLACEMENT', 'intentHash': 'b'}]
                      + [{'name': 'READ.' + str(i), 'intentHash': str(i)} for i in range(26)],
                      'engineBinding': {}, 'runtimeGuardProfile': {'unchangedApplications': {}},
                      'databaseControlProfile': {'postgresRuntimeBinding': m.stable(actual['postgres']),
                                                 'postgresRestartCount': 0,
                                                 'runtimeBindingProfile': 'ouf.runtime-binding.native-mount-order.v1'}}
            for name in ('onboarding', 'mcp', 'udp'):
                native['runtimeGuardProfile']['unchangedApplications'][name] = {
                    'binding': m.stable(actual[name]), 'restartCount': 0,
                    'bindingProfile': 'ouf.runtime-binding.native-mount-order.v1'}
            row = {'nextStage': 28, 'budgetReset': False,
                   'effects': [{'stage': s['name'], 'intentHash': s['intentHash'], 'state': 'APPLIED'}
                               for s in native['stages']]}
            for i, name in enumerate(('ingestion', 'gateway')):
                row['effects'][i]['nativeResource'] = {key: m.stable(actual[name])[key]
                                                       for key in ('containerId', 'pid', 'startedAt')}
            metadata = {'schema': 'ouf.ingestion-readiness-workload-candidate.v1', 'sourceCommit': 'candidate',
                        'baselineSourceCommit': 'baseline', 'buildRecipeCommit': 'recipe', 'imageId': 'image-id',
                        'migrationChanges': 0, 'highCriticalVulnerabilityGatePassed': True,
                        'imageStartedByCandidateExport': False, 'runtimeAuthorityIssued': False}
            case = {'schema': 'ouf.readiness-patch-input-case.v1',
                    'purpose': 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
                    'snapshotRoot': str(root), 'retainedContext': '/fixture-retained',
                    'replacementIds': {n: actual[n]['Id'] for n in ('ingestion', 'gateway')},
                    'baselineSourceCommit': 'baseline', 'candidateSourceCommit': 'candidate',
                    'buildRecipeCommit': 'recipe', 'candidateImageId': 'image-id',
                    'files': {n: {'sha256': 'fixture', 'maximumBytes': 100} for n in
                              ('image.tar.gz', 'metadata.json', 'image-inspect.json', 'trivy-image.json')}}

            class FakeEngine:
                drift = False
                def __init__(self, *_):
                    self.calls = 0
                def inspect(self, cid):
                    self.calls += 1
                    value = copy.deepcopy(next(v for v in actual.values() if v['Id'] == cid))
                    if self.drift and self.calls > 6:
                        value['State']['Pid'] += 100
                    return value

            def read(path, expected=None, root_owned=False):
                name = Path(path).name
                if name == 'metadata.json':
                    return metadata, b'metadata'
                if name == 'review.json':
                    return {'executionReview': native}, b'review'
                return row, b'row'

            original_lstat = Path.lstat
            def trusted_base(path):
                s = original_lstat(path)
                if path == root:
                    return SimpleNamespace(st_mode=s.st_mode, st_uid=0)
                return s

            with patch.object(m, 'read_json', read), patch.object(m, 'Engine', FakeEngine), \
                    patch.object(m, 'copy_public', return_value=1), patch.object(Path, 'lstat', trusted_base):
                actual['onboarding']['Config']['Env'].append('UNREVIEWED=change')
                with self.assertRaisesRegex(m.Stop, 'UNCHANGED_APPLICATION_CONFIG_DRIFT'):
                    m.run(case, '/fixture-public')
                actual['onboarding']['Config']['Env'].pop()
                metadata['sourceCommit'] = 'wrong-candidate'
                with self.assertRaisesRegex(m.Stop, 'EXACT_QUALIFIED_CANDIDATE_REQUIRED'):
                    m.run(case, '/fixture-public')
                metadata['sourceCommit'] = 'candidate'
                result = m.run(case, '/fixture-public')
                self.assertEqual(result['engineGets'], 12)
                self.assertEqual(result['imagesImported'], 0)
                self.assertFalse(result['runtimeFrameApproved'])
                self.assertFalse(result['runtimeAuthorityIssued'])
                self.assertNotIn('must-stay-private', json.dumps(result))
                captured = Path(result['contextPath'])
                self.assertIn('must-stay-private', (captured / 'snapshot.json').read_text())
                self.assertEqual(stat.S_IMODE((captured / 'snapshot.json').stat().st_mode), 0o400)
                with self.assertRaisesRegex(m.Stop, 'INPUT_SNAPSHOT_ALREADY_EXISTS_DO_NOT_REPLAY'):
                    m.run(case, '/fixture-public')
                case2 = copy.deepcopy(case);case2['testIntent'] = 'new-fixture-drift'
                FakeEngine.drift = True
                with self.assertRaisesRegex(m.Stop, 'RETAINED_RUNTIME_GENERATION_CHANGED'):
                    m.run(case2, '/fixture-public')
                partial = root / ('ingestion-readiness-patch-inputs-' + m.digest(case2))
                self.assertTrue((partial / 'claim.json').exists())
                self.assertFalse((partial / 'complete.json').exists())

    def test_closed_engine_budget_without_socket_fallback(self):
        ids = {c * 64 for c in 'abcdef'}
        engine = m.Engine({}, ids)
        with self.assertRaisesRegex(m.Stop, 'CLOSED_TWELVE_GET_BUDGET'):
            engine.inspect('0' * 64)
        engine.calls = 12
        with self.assertRaisesRegex(m.Stop, 'CLOSED_TWELVE_GET_BUDGET'):
            engine.inspect('a' * 64)


if __name__ == '__main__':
    unittest.main()
