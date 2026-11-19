import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('candidate',ROOT/'scripts/prepare-chatbot-semantic-session-candidate-20261016.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def test_pinned_source_reader_rejects_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            path=Path(d)/'source.py';path.write_bytes(b'print(1)\n');path.chmod(0o600)
            expected=m.hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(m.source(path,expected),b'print(1)\n')
            path.write_bytes(b'print(2)\n')
            with self.assertRaisesRegex(m.ReadDenied,'CANDIDATE_SOURCE_DRIFT'):m.source(path,expected)

    def test_hash_bound_compiler_uses_same_pure_contract_as_qualification(self):
        import test_governed_semantic_session_contract as fixture
        raw=(ROOT/'tools/semantic_policy_token_owner/installed_owner.py').read_bytes()
        ns={'copy':m.copy,'Path':Path,'fingerprint':m.digest,
            'check':lambda ok:m.require(ok,'CONTRACT_FAILED')}
        m.definitions(raw,{'GOVERNED_SESSION','GOVERNED_HISTORY','compile_governed_session'},ns)
        f=fixture.fixture()
        self.assertEqual(ns['compile_governed_session'](*f,'7'*64,'8'*64,60),fixture.compile_fixture(f))

    def test_complete_fixture_with_launcher_umask077_and_simulated_ownership_only(self):
        from test_chatbot_semantic_policy_refresh_reader import Tests as OwnershipFixture
        raw=(ROOT/'tools/semantic_policy_token_owner/producer.py').read_bytes()
        adapter=OwnershipFixture()
        previous=os.umask(0o077)
        try:
            with adapter.ownership_adapter(),patch.object(m,'CONTEXT',ROOT/'unused-context'):
                result=m.qualify_native_publication(raw)
            self.assertTrue(result['fixtureRemoved'])
            self.assertTrue(result['atomicPublisherCodeUsed'])
        finally:os.umask(previous)

if __name__=='__main__':unittest.main()
