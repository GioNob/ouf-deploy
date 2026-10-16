import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('candidate',ROOT/'scripts/prepare-chatbot-semantic-session-candidate-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def test_candidate_source_hashes_match_packaged_bodies(self):
        for name,expected in m.SOURCE_HASHES.items():
            path=ROOT/'tools/semantic_policy_token_owner'/name.replace('-','_')
            self.assertEqual(m.hashlib.sha256(path.read_bytes()).hexdigest(),expected)

    def test_hash_bound_compiler_uses_same_pure_contract_as_qualification(self):
        import test_governed_semantic_session_contract as fixture
        raw=(ROOT/'tools/semantic_policy_token_owner/installed_owner.py').read_bytes()
        ns={'copy':m.copy,'Path':Path,'fingerprint':m.digest,
            'check':lambda ok:m.require(ok,'CONTRACT_FAILED')}
        m.definitions(raw,{'GOVERNED_SESSION','GOVERNED_HISTORY','compile_governed_session'},ns)
        f=fixture.fixture()
        self.assertEqual(ns['compile_governed_session'](*f,'7'*64,'8'*64,60),fixture.compile_fixture(f))

if __name__=='__main__':unittest.main()
