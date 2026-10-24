"""Response classification and immutable retained capsule; no target replay."""
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'scripts/observe-registry-frozen-response-20261023.py'
spec = importlib.util.spec_from_file_location('frozen_response_observer_fixture', SCRIPT)
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class Observer(unittest.TestCase):
    def setUp(self):
        self.config = {'semanticReferenceBindings': []}
        self.reference = {'sourceId': 'PRIVATE_SOURCE', 'onboardingVersionId': 'PRIVATE_VERSION',
            'configurationHash': 'sha256:' + hashlib.sha256(json.dumps(self.config,
                sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()}
        self.value = {**self.reference, 'configuration': self.config, 'state': 'IN_REVIEW'}

    def test_exact_camel_case_response_matches_all_five_guard_conditions(self):
        shape = d.shape(self.value, self.reference)['top']
        self.assertTrue(all(shape[key] for key in ('sourceIdMatches', 'versionIdMatches',
            'configurationHashMatches', 'stateAcceptedByCurrentVerifier', 'configurationObject', 'configurationChecksumMatches')))

    def test_snake_case_identity_detected_without_automatic_translation(self):
        value = {'source_id': self.reference['sourceId'], 'onboarding_version_id': self.reference['onboardingVersionId'],
            'configuration_hash': self.reference['configurationHash'], 'configuration': self.config, 'state': 'IN_REVIEW'}
        shape = d.shape(value, self.reference)['top']
        self.assertFalse(shape['sourceIdPresent']); self.assertTrue(shape['snakeSourceIdMatches'])
        self.assertFalse(shape['versionIdPresent']); self.assertTrue(shape['snakeVersionIdMatches'])
        self.assertTrue(shape['snakeConfigurationHashMatches'])

    def test_envelope_is_distinguished_without_selecting_an_alternative_reference(self):
        shape = d.shape({'data': self.value}, self.reference)
        self.assertFalse(shape['top']['sourceIdPresent']); self.assertTrue(shape['data']['sourceIdMatches'])
        self.assertFalse(shape['version']['object'])

    def test_state_change_is_separate_from_identity_or_checksum_change(self):
        value = {**self.value, 'state': 'ACTIVE'}
        shape = d.shape(value, self.reference)
        self.assertEqual(shape['knownState'], 'ACTIVE'); self.assertFalse(shape['top']['stateAcceptedByCurrentVerifier'])
        self.assertTrue(shape['top']['sourceIdMatches']); self.assertTrue(shape['top']['configurationChecksumMatches'])

    def test_private_identifiers_arbitrary_keys_and_error_text_never_projected(self):
        value = {**self.value, 'PRIVATE_KEY': 'PRIVATE_VALUE', 'error': 'PRIVATE_ERROR', 'state': 'PRIVATE_STATE'}
        public = json.dumps(d.shape(value, self.reference))
        for text in ('PRIVATE_SOURCE', 'PRIVATE_VERSION', 'PRIVATE_KEY', 'PRIVATE_VALUE', 'PRIVATE_ERROR', 'PRIVATE_STATE'):
            self.assertNotIn(text, public)

    def test_exact_retained_capsule_decoded_without_application_entry(self):
        case, manifest, loader, sources = d.retained(str(ROOT / 'releases/semantic-registry-postboot-resolver-20261023.py'))
        self.assertEqual(len(sources), 134); self.assertEqual(d.digest(manifest), d.CLOSURE_HASH)
        self.assertEqual(manifest['sourceCommit'], '9f3b33c485d13eae7616408b99141ad09765bd88')
        self.assertEqual(case['preparation']['resolverRecovery']['correctedObservation']['sha256'],
                         'd0aaf645ad17d909e4479fd90cb5c84936126e81bf6931ee27c932ecf5c3e794')

    def test_tampered_capsule_and_symlink_rejected_before_preload(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            file = Path(temporary) / 'tampered'; file.write_bytes(b'X' * 654291)
            with self.assertRaises(d.Stop): d.retained(str(file))
            link = Path(temporary) / 'link'; link.symlink_to(ROOT / 'releases/semantic-registry-postboot-resolver-20261023.py')
            with self.assertRaises(OSError): d.retained(str(link))

    def test_observation_claim_does_not_depend_on_script_version(self):
        claim = {'sourceClosureHash': 'a' * 64, 'bootId': 'same'}
        first = d.observation_root('/fixture', claim, 'same')
        self.assertEqual(first, d.observation_root('/fixture', copy.deepcopy(claim), 'same'))
        self.assertNotEqual(first, d.observation_root('/fixture', claim, 'different'))


class Delivery(unittest.TestCase):
    def fixture(self, directory, content):
        binary = directory / 'bin'; binary.mkdir()
        for name, text in {
            'gh': '#!/bin/sh\nprintf "%s\\n" "$*" >> "$HOME/gh.calls"\ncat "$HOME/source.py"\n',
            'sudo': '#!/bin/sh\ntest "$1" = -- || exit 9\nshift\nexec "$@"\n'}.items():
            target = binary / name; target.write_text(text); target.chmod(0o700)
        (directory / 'source.py').write_bytes(content)
        return {**os.environ, 'HOME': str(directory), 'PATH': str(binary) + ':/usr/bin:/bin'}

    def test_missing_retained_source_stops_before_engine_or_dns(self):
        self.assertFalse(Path(d.CAPSULE).exists())
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            home = Path(temporary); env = self.fixture(home, SCRIPT.read_bytes())
            result = subprocess.run(['bash', str(ROOT / 'releases/semantic-registry-frozen-response-20261023.sh')],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2)
            rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith('{')]
            self.assertEqual(rows[0]['stage'], 'VERIFY_RETAINED_CAPSULE')
            self.assertEqual(rows[0]['exceptionClass'], 'FileNotFoundError')
            self.assertEqual(rows[0]['runtimeEffectsDispatched'], 0)
            calls = (home / 'gh.calls').read_text().splitlines(); self.assertEqual(len(calls), 1)
            self.assertIn('ref=6e1e0496d023b7a38818b211724f1cec036508b5', calls[0])
            self.assertIn('observe-registry-frozen-response-20261023.py', calls[0])
            private = next(home.glob('ouf-frozen-response.*'))
            self.assertEqual((private / 'read.stderr').read_bytes(), b'')

    def test_tamper_rejected_before_code_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            home = Path(temporary); env = self.fixture(home, b'raise RuntimeError("NEVER_EXECUTE")\n')
            result = subprocess.run(['bash', str(ROOT / 'releases/semantic-registry-frozen-response-20261023.sh')],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'EXACT_FROZEN_RESPONSE_ROOT_LAUNCH_UNPROVEN', result.stdout)
            self.assertNotIn(b'NEVER_EXECUTE', result.stdout + result.stderr)

    def test_no_arguments_or_retry_before_download(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            home = Path(temporary); env = self.fixture(home, SCRIPT.read_bytes())
            result = subprocess.run(['bash', str(ROOT / 'releases/semantic-registry-frozen-response-20261023.sh'), 'retry'],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2); self.assertFalse((home / 'gh.calls').exists())


if __name__ == '__main__': unittest.main()
