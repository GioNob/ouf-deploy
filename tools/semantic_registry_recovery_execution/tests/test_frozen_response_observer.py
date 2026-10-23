"""Response classification and immutable retained capsule; no target replay."""
import copy
import hashlib
import importlib.util
import json
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


if __name__ == '__main__': unittest.main()
