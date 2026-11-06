import importlib.util
import json
import os
from pathlib import Path
import shutil
import unittest

import test_storage_g0_input_draft as fixture
from tools.storage_planning import g0_input_draft as m

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('datasource_review', ROOT / 'scripts/review-storage-g0-datasource-20261106.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class DatasourceReviewTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.InputDraftTests()
        self.f.setUp()
        self.draft = self.f.draft()
        self.draft.mkdir(mode=0o700)
        self.old = {'schema': 'ouf.storage-g0-input-draft-result.v1',
                    'status': 'PRIVATE_INPUT_DRAFT_PREPARED_REVIEW_REQUIRED',
                    'connectionDraftsPrepared': ['s3'],
                    'missingInputs': ['INPUTS_DATASOURCE_OVERRIDE_REQUIRES_REVIEW'] * 3,
                    'providerRequests': 0, 'runtimeAuthorityIssued': False}
        m.put(self.draft / 'result.json', m.encoded(self.old))
        m.put(self.draft / 's3-secret', b'NEVER_READ_OR_PRINT_THIS_S3_SECRET')
        self.old_files = {p.name: p.read_bytes() for p in self.draft.iterdir()}
        for role, prefix in r.PREFIXES.items():
            env = self.f.env[self.f.roster[role]['generation']['pid']]
            for a, b in [('URL', 'URL'), ('USER', 'USERNAME'), ('PASSWORD', 'PASSWORD')]:
                env['SPRING_DATASOURCE_' + b] = env[prefix + '_DB_' + a]

    def tearDown(self):
        self.f.tearDown()

    def run_review(self, **kw):
        args = dict(env_reader=self.f.envread, pin_reader=lambda pid: self.f.pin[pid],
                    boot_reader=lambda: self.f.seed['bootId'])
        args.update(kw)
        return r.review(self.f.stage, self.f.profile, m, **args)

    def test_equal_duplicate_values_and_different_values_are_distinguished(self):
        env = {'OUF_ONB_DB_PASSWORD': 'private:a', 'SPRING_DATASOURCE_PASSWORD': 'private:a'}
        self.assertTrue(r.classify('onboarding', env)['connectionPairs']['password']['byteEqual'])
        env['SPRING_DATASOURCE_PASSWORD'] = 'private:b'
        self.assertFalse(r.classify('onboarding', env)['connectionPairs']['password']['byteEqual'])
        env['SPRING_DATASOURCE_PASSWORD'] = '${OUF_ONB_DB_PASSWORD}'
        row = r.classify('onboarding', env)
        self.assertTrue(row['connectionPairs']['password']['springExactOufPlaceholder'])
        self.assertFalse(row['connectionPairs']['password']['byteEqual'])
        self.assertFalse(row['effectiveConfigurationProven'])

    def test_unknown_variable_names_and_all_values_are_redacted(self):
        env = {'SPRING_DATASOURCE_PRIVATE_SECRET_NAME': 'hidden-value',
               'SPRING_APPLICATION_JSON': '{"password":"hidden-value"}',
               'JAVA_TOOL_OPTIONS': '-Dspring.datasource.password=hidden-value',
               'SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE': 'hidden-value'}
        row = r.classify('udp', env)
        self.assertEqual(row['otherDatasourceVariableCount'], 1)
        self.assertEqual(row['javaVariablesMentioningDatasource'], ['JAVA_TOOL_OPTIONS'])
        self.assertNotIn('hidden-value', json.dumps(row))
        self.assertNotIn('PRIVATE_SECRET_NAME', json.dumps(row))
        self.assertIsNone(row['connectionPairs']['password']['byteEqual'])

    def test_three_reads_private_result_and_no_preparation_replay(self):
        first = self.run_review()
        self.assertEqual(first['status'], 'DATASOURCE_OVERRIDE_METADATA_OBSERVED_REVIEW_REQUIRED')
        self.assertEqual(first['processEnvironmentsRead'], 3)
        self.assertEqual(len(self.f.reads), 3)
        self.assertEqual(set(first['roles']), set(r.PREFIXES))
        self.assertNotIn('fixture', json.dumps(first))
        self.assertNotIn('NEVER_READ', json.dumps(first))
        self.assertFalse(first['targetInputCheckPassed'])
        second = self.run_review(env_reader=lambda _: self.fail('environment replay'))
        self.assertTrue(second.pop('existingResultReadOnly'))
        self.assertEqual(first, second)
        self.assertEqual(self.old_files, {p.name: p.read_bytes() for p in self.draft.iterdir()})
        self.assertFalse(list((self.f.stage / 'evidence').iterdir()))
        scope = self.f.stage / 'inputs' / r.SCOPE
        self.assertEqual(scope.stat().st_mode & 0o777, 0o700)
        self.assertEqual({p.stat().st_mode & 0o777 for p in scope.iterdir()}, {0o600})

    def test_changed_boot_denied_before_environment_read(self):
        result = self.run_review(boot_reader=lambda: 'changed')
        self.assertEqual(result['reason'], 'REVIEW_BOOT_CHANGED')
        self.assertEqual(self.f.reads, [])

    def test_process_drift_during_read_discards_all_metadata(self):
        def drift(pid):
            env = self.f.envread(pid)
            self.f.pin[pid] = dict(self.f.pin[pid], startTicks=0)
            return env
        result = self.run_review(env_reader=drift)
        self.assertEqual(result['reason'], 'REVIEW_PROCESS_CHANGED')
        self.assertEqual(result['processEnvironmentsRead'], 1)
        self.assertEqual(result['roles'], {})

    def test_deadline_does_not_reset_on_reentry(self):
        ticks = iter([0, 16])
        result = self.run_review(clock=lambda: next(ticks))
        self.assertEqual(result['reason'], 'REVIEW_DEADLINE')
        self.assertEqual(self.f.reads, [])
        reread = self.run_review(env_reader=lambda _: self.fail('deadline reset'))
        self.assertTrue(reread['existingResultReadOnly'])
        self.assertEqual(reread['reason'], 'REVIEW_DEADLINE')

    def test_partial_scope_is_preserved_without_resume(self):
        scope = self.f.stage / 'inputs' / r.SCOPE
        scope.mkdir(mode=0o700)
        m.put(scope / 'claim.json', b'{}')
        with self.assertRaises(FileNotFoundError):
            self.run_review()
        self.assertEqual(self.f.reads, [])
        self.assertEqual((scope / 'claim.json').read_bytes(), b'{}')

    def test_unexpected_preparation_denied_before_scope(self):
        self.old['connectionDraftsPrepared'].append('udp')
        (self.draft / 'result.json').write_bytes(m.encoded(self.old))
        with self.assertRaisesRegex(ValueError, 'REVIEW_EXPECTED_THREE_DATABASE_HOLDS'):
            self.run_review()
        self.assertFalse((self.f.stage / 'inputs' / r.SCOPE).exists())

    def test_private_exception_text_never_reaches_report(self):
        def fail(pid):
            raise ValueError('secret-password-and-private-path')
        result = self.run_review(env_reader=fail)
        self.assertEqual(result['reason'], 'REVIEW_LOCAL_OBSERVATION_UNPROVEN')
        self.assertNotIn('secret-password', json.dumps(result))
        self.assertEqual(result['processEnvironmentsRead'], 1)

    def test_exact_bundle_and_tampered_code_or_import_paths(self):
        bootstrap_spec = importlib.util.spec_from_file_location('bootstrap', ROOT / 'scripts/download-and-prepare-storage-g0-inputs-20261106.py')
        bootstrap = importlib.util.module_from_spec(bootstrap_spec)
        bootstrap_spec.loader.exec_module(bootstrap)
        bundle = self.f.root / 'bundle'
        bundle.mkdir(mode=0o700)
        for name in bootstrap.MANIFEST['files']:
            path = bundle / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
            path.chmod(0o400)
        manifest = bundle / 'tool-manifest.json'
        manifest.write_text(json.dumps(bootstrap.MANIFEST, sort_keys=True, indent=2) + '\n')
        manifest.chmod(0o400)
        # Reading is allowed to update access time, never source identity/content.
        os.utime(manifest, (1, manifest.stat().st_mtime))
        self.assertEqual(r.verify_bundle(bundle)['operationId'], 'seaweedfs-g0-20261106-v1')
        path = bundle / 'tools/storage_planning/g0_input_draft.py'
        original = path.read_bytes()
        for kind in ('changed-source', 'symlink', 'extra-import'):
            with self.subTest(kind=kind):
                if kind == 'changed-source':
                    path.chmod(0o600)
                    path.write_bytes(original + b'\n')
                    path.chmod(0o400)
                elif kind == 'symlink':
                    path.unlink()
                    path.symlink_to(ROOT / 'tools/storage_planning/g0_input_draft.py')
                else:
                    (bundle / 'tools/__init__.py').write_text('raise RuntimeError("must not run")')
                with self.assertRaises((ValueError, OSError)):
                    r.verify_bundle(bundle)
                if kind == 'extra-import':
                    (bundle / 'tools/__init__.py').unlink()
                else:
                    path.unlink()
                    path.write_bytes(original)
                    path.chmod(0o400)


if __name__ == '__main__':
    unittest.main()
