import copy
import importlib.util
import json
import os
from pathlib import Path
import unittest

import test_storage_g0_input_draft as fixture
from tools.storage_planning import g0_input_draft as m

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


c = module('db_continuation', 'scripts/continue-storage-g0-databases-20261106.py')
r = module('review_helper', 'scripts/review-storage-g0-datasource-20261106.py')
SOURCE = (ROOT / 'tools/chatbot_file_cohort/preparation.py').read_text()


class DatabaseContinuationTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.InputDraftTests()
        self.f.setUp()
        self.roots = {}
        self.views = []
        self.opened_views = []
        for role, target in c.TARGETS.items():
            root = self.f.root / ('config-' + role)
            path = root / target.lstrip('/')
            path.parent.mkdir(parents=True, mode=0o700)
            path.write_text('{"spring.security.oauth2.client.registration.ouf.client-secret":"fixture-oauth-secret"}'
                            if role == 'onboarding' else 'ouf.ingestion.summary.enabled=true\nouf.ingestion.summary.token=fixture-token\n')
            path.chmod(0o600)
            self.roots[self.f.roster[role]['generation']['pid']] = root
            self.f.seed['observations'][role]['Mounts'] = [{'Type': 'bind', 'RW': False, 'Destination': target,
                'Source': '/opt/ouf/secrets/onboarding-ths.yaml' if role == 'onboarding' else '/opt/ouf/secrets/ingestion-summary.properties'}]
            self.env(role)['SPRING_CONFIG_ADDITIONAL_LOCATION'] = 'file:' + target
        for role in ('onboarding', 'udp'):
            self.env(role)['SPRING_APPLICATION_JSON'] = '{"server.servlet.session.cookie.secure":true,"ouf.authorization.test":"fixture-overlay-secret"}'
        (self.f.root / 'seed.json').write_bytes(m.encoded(self.f.seed))
        self.f.profile['seedCanonicalSha256'] = m.digest(self.f.seed)
        old = self.f.draft()
        old.mkdir(mode=0o700)
        config = copy.deepcopy(self.f.original)
        config.update(operationId=self.f.profile['operationId'], installationRef=self.f.profile['installationRef'])
        config['connectionFiles']['s3'] = str(old / 's3.json')
        m.put(old / 'package-input.review.json', m.encoded(config))
        m.put(old / 's3.json', m.encoded({'schema': 'ouf.storage-g0-collection-input.v1',
             'operationId': self.f.profile['operationId'] + '-s3',
             'installationRef': self.f.profile['installationRef']}))
        m.put(old / 'result.json', m.encoded({'schema': 'ouf.storage-g0-input-draft-result.v1',
             'status': 'PRIVATE_INPUT_DRAFT_PREPARED_REVIEW_REQUIRED', 'connectionDraftsPrepared': ['s3'],
             'runtimeAuthorityIssued': False, 'providerRequests': 0}))
        m.put(old / 's3-secret', b'old-secret-must-stay-untouched')
        self.old_files = {p.name: p.read_bytes() for p in old.iterdir()}
        prior = self.f.stage / 'inputs' / r.SCOPE
        prior.mkdir(mode=0o700)
        self.prior_path = prior / 'result.json'
        m.put(self.prior_path, b'{}')
        self.update_diagnostic()

    def tearDown(self):
        self.f.tearDown()

    def env(self, role):
        return self.f.env[self.f.roster[role]['generation']['pid']]

    def update_diagnostic(self):
        self.prior_path.write_bytes(m.encoded({'status': 'DATASOURCE_OVERRIDE_METADATA_OBSERVED_REVIEW_REQUIRED',
             'roles': {role: r.classify(role, self.env(role)) for role in m.DB_PREFIX},
             'providerRequests': 0, 'runtimeAuthorityIssued': False}))

    def factory(self, pid):
        fd = os.open(self.roots[pid], os.O_RDONLY | os.O_DIRECTORY)
        try:
            binding = m.InputBinding(pid, root=fd, cwd=fd)
        finally:
            os.close(fd)
        self.opened_views.append(binding)
        return binding

    def run_continuation(self, **kwargs):
        options = dict(env_reader=self.f.envread, pin_reader=lambda pid: self.f.pin[pid],
             boot_reader=lambda: self.f.seed['bootId'], command_reader=lambda pid: ['java', '-jar', '/app/application.jar'],
             factory=self.factory)
        options.update(kwargs)
        return c.prepare(self.f.stage, self.f.profile, m, r, SOURCE, **options)

    def new_root(self):
        return self.f.stage / 'inputs' / c.SCOPE

    def assert_no_passwords(self):
        self.assertEqual(list(self.new_root().glob('*.pass')), [])

    def test_known_overlays_prepare_three_drafts_without_touching_s3(self):
        result = self.run_continuation()
        self.assertEqual(result['status'], 'DATABASE_CONNECTION_DRAFTS_PREPARED_REVIEW_REQUIRED')
        self.assertEqual(set(result['connectionDraftsPrepared']), set(m.DB_PREFIX))
        self.assertEqual(result['configurationFilesRead'], 2)
        self.assertEqual(result['processEnvironmentsRead'], 3)
        self.assertEqual(result['commandLinesRead'], 3)
        self.assertEqual(result['credentialFilesWritten'], 3)
        self.assertEqual(result['s3CredentialFilesRead'], 0)
        self.assertFalse(result['targetInputCheckPassed'])
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertNotIn('fixture-', json.dumps(result))
        self.assertEqual(self.old_files, {p.name: p.read_bytes() for p in self.f.draft().iterdir()})
        candidate = m.decode((self.new_root() / 'package-input.review.json').read_bytes())
        self.assertEqual(candidate['connectionFiles']['s3'], str(self.f.draft() / 's3.json'))
        self.assertIn(b'fixture\\:secret\\\\value', (self.new_root() / 'udp.pass').read_bytes())
        self.assertEqual({p.stat().st_mode & 0o777 for p in self.new_root().iterdir()}, {0o600})
        self.assertFalse(list((self.f.stage / 'evidence').iterdir()))
        for binding in self.opened_views:
            with self.assertRaises(OSError):
                os.fstat(binding.root)

    def test_database_override_in_json_blocks_all_password_writes(self):
        self.env('udp')['SPRING_APPLICATION_JSON'] = '{"spring":{"datasource":{"password":"wrong-secret"}}}'
        result = self.run_continuation()
        self.assertEqual(result['reason'], 'CUSTOM_DATASOURCE_CONFIGURATION_REQUIRES_REVIEW')
        self.assert_no_passwords()
        self.assertNotIn('wrong-secret', json.dumps(result))

    def test_configuration_import_in_retained_ths_is_denied(self):
        path = self.roots[self.f.roster['onboarding']['generation']['pid']] / c.TARGETS['onboarding'].lstrip('/')
        path.write_text('{"spring.config.import":"file:/another-secret"}')
        result = self.run_continuation()
        self.assertEqual(result['reason'], 'CUSTOM_DATASOURCE_CONFIGURATION_REQUIRES_REVIEW')
        self.assert_no_passwords()

    def test_ingestion_properties_override_is_denied_without_secret_output(self):
        path = self.roots[self.f.roster['ingestion']['generation']['pid']] / c.TARGETS['ingestion'].lstrip('/')
        path.write_text('spring.datasource.password=another-private-value\n')
        result = self.run_continuation()
        self.assertEqual(result['reason'], 'INGESTION_DATASOURCE_OR_IMPORT_REQUIRES_REVIEW')
        self.assert_no_passwords()
        self.assertNotIn('another-private', json.dumps(result))

    def test_json_duplicates_aliases_nonfinite_and_complex_lists_are_held(self):
        validators = c.predicates(SOURCE, m, lambda *_: self.fail('read'))
        for raw in ['{"a":1,"a":2}', '{"server.port":1,"server":{"port":2}}',
                    '{"a":NaN}', '{"a":[{"spring.config.import":"hidden"}]}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                c.overlay(raw, 'OUF_UDP', validators, m)

    def test_symlink_or_missing_configuration_never_falls_back_to_host(self):
        path = self.roots[self.f.roster['onboarding']['generation']['pid']] / c.TARGETS['onboarding'].lstrip('/')
        path.unlink()
        path.symlink_to(self.f.root / 'seed.json')
        result = self.run_continuation()
        self.assertEqual(result['reason'], 'DB_BOUNDED_REGULAR_CONFIGURATION_REQUIRED')
        self.assertEqual(result['configurationFilesRead'], 0)
        self.assert_no_passwords()

    def test_unrecognized_additional_location_is_denied(self):
        self.env('onboarding')['SPRING_CONFIG_ADDITIONAL_LOCATION'] = 'file:/run/secrets/unknown.yaml'
        self.update_diagnostic()
        result = self.run_continuation()
        self.assertEqual(result['reason'], 'DB_EXACT_RETAINED_CONFIG_SELECTION')
        self.assertEqual(result['configurationFilesRead'], 0)
        self.assert_no_passwords()

    def test_command_line_override_is_denied(self):
        result = self.run_continuation(command_reader=lambda _: ['java', '-Dspring.datasource.password=private'])
        self.assertEqual(result['reason'], 'DB_COMMAND_OR_JVM_OVERRIDE')
        self.assert_no_passwords()
        self.assertNotIn('password=private', json.dumps(result))

    def test_process_drift_after_environment_read_is_held(self):
        def change(pid):
            env = self.f.envread(pid)
            self.f.pin[pid] = dict(self.f.pin[pid], startTicks=0)
            return env
        result = self.run_continuation(env_reader=change)
        self.assertEqual(result['reason'], 'DB_PROCESS_CHANGED')
        self.assertEqual(result['configurationFilesRead'], 0)
        self.assert_no_passwords()

    def test_deadline_and_reentry_preserve_consumed_budget(self):
        ticks = iter([0, 31])
        result = self.run_continuation(clock=lambda: next(ticks))
        self.assertEqual(result['reason'], 'DB_CONTINUATION_DEADLINE')
        again = self.run_continuation(env_reader=lambda _: self.fail('replayed'))
        self.assertTrue(again.pop('existingResultReadOnly'))
        self.assertEqual(again, result)

    def test_partial_scope_never_resumes_or_cleans_passwords(self):
        root = self.new_root()
        root.mkdir(mode=0o700)
        m.put(root / 'onboarding.pass', b'existing-private-value')
        with self.assertRaises(FileNotFoundError):
            self.run_continuation()
        self.assertEqual((root / 'onboarding.pass').read_bytes(), b'existing-private-value')
        self.assertEqual(self.f.reads, [])

    def test_foreign_database_host_is_still_denied_by_original_guard(self):
        self.env('udp')['OUF_UDP_DB_URL'] = 'jdbc:postgresql://another-host/db'
        result = self.run_continuation()
        self.assertEqual(result['reason'], 'INPUTS_POSTGRES_HOST_BINDING')
        self.assert_no_passwords()

    def test_original_source_validators_must_match_exact_git_bytes(self):
        with self.assertRaisesRegex(ValueError, 'DB_EXACT_COHORT_VALIDATORS'):
            c.predicates(SOURCE + '\n', m, lambda *_: None)

    def test_file_drift_before_publication_blocks_drafts(self):
        original = self.factory
        def changing_factory(pid):
            binding = original(pid)
            stable = binding.stable
            calls = [0]
            def drift():
                calls[0] += 1
                if calls[0] == 2:
                    path = self.roots[pid] / c.TARGETS['onboarding'].lstrip('/')
                    if path.exists():
                        path.write_text('{"spring.datasource.url":"changed"}')
                stable()
            binding.stable = drift
            return binding
        result = self.run_continuation(factory=changing_factory)
        self.assertEqual(result['status'], 'HELD')
        self.assert_no_passwords()


if __name__ == '__main__':
    unittest.main()
