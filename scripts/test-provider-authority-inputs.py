import importlib.util
import unittest
from pathlib import Path

s = importlib.util.spec_from_file_location('reader', Path(__file__).with_name('read-provider-authority-inputs.py'))
r = importlib.util.module_from_spec(s)
s.loader.exec_module(r)

class ProjectionTests(unittest.TestCase):
    def test_actual_custody_schema_preserves_snake_case_bindings(self):
        bindings = {'installation_ref': 'ouf-test', 'entity_ref': 'entity-test', 'installer_issuer_ref': 'installer-test', 'attestor_issuer_ref': 'attestor-test', 'installer_key_ref': 'installer-key', 'attestor_key_ref': 'attestor-key'}
        self.assertEqual(r.project({'bindings': bindings})['bindings'], bindings)
    def test_no_key_or_arbitrary_configuration_is_exported(self):
        value = {'schema': 'receipt', 'privateKey': 'secret', 'keys': [{'publicKey': 'also omitted'}], 'bindings': {'installationRef': 'ouf-test', 'clientSecret': 'secret'}, 'inventoryHashes': {'private.pem': 'a' * 64, 'dossier.json': 'b' * 64}}
        self.assertEqual(r.project(value), {'schema': 'receipt', 'bindings': {'installationRef': 'ouf-test'}, 'inventoryHashes': {'dossier.json': 'b' * 64}})
    def test_invalid_identity_and_hash_are_omitted(self):
        value = {'bindings': {'entityRef': 'bad\nidentity'}, 'inventoryHashes': {'dossier.json': 'not a hash'}, 'state': {'nested': 'secret'}}
        self.assertEqual(r.project(value), {'bindings': {}, 'inventoryHashes': {}})
    def test_only_fixed_receipt_files_are_selected(self):
        names = [n for group in r.COHORTS.values() for n in group]
        self.assertEqual(len(names), 4)
        self.assertTrue(all(n.endswith('.json') and '/' not in n and 'key' not in n.replace('key-custody-receipt', '') for n in names))

if __name__ == '__main__': unittest.main()
