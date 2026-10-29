"""Standard issuer effects do not excuse foreign or ambiguous claim mappings."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/semantic_policy_token_owner'))
import iam_binding_candidate as binding
import iam_mapper_semantics_review as semantics
spec = importlib.util.spec_from_file_location('binding_fixture', ROOT / 'tests/test_policy_token_iam_binding_candidate.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)

def standard():
    value = fixture.snapshot()
    value['client']['protocolMappers'] += [
        {'protocol': 'openid-connect', 'protocolMapper': kind, 'config': {
            'access.token.claim': 'true', 'introspection.token.claim': 'true'}}
        for kind in ('oidc-acr-mapper', 'oidc-allowed-origins-mapper', 'oidc-sub-mapper')]
    value['client']['protocolMappers'].append({'protocol': 'openid-connect',
        'protocolMapper': 'oidc-usersessionmodel-note-mapper', 'config': {'claim.name': 'client_id',
            'user.session.note': 'client_id', 'jsonType.label': 'String',
            'access.token.claim': 'true', 'introspection.token.claim': 'true'}})
    return value

class MapperSemanticsTest(unittest.TestCase):
    def test_standard_effects_preserve_parent_uncertainty_but_close_specific_findings(self):
        value = standard(); previous, _ = binding.compile_binding(value, 'a'*64, fixture.REF)
        candidate, public = semantics.review(value, 'a'*64, fixture.REF)
        self.assertIn('UNSUPPORTED_EFFECTIVE_MAPPER', previous['reviewReasons'])
        self.assertEqual(candidate['parentBindingCandidateHash'], binding.sha(binding.encoded(previous)))
        self.assertTrue(public['staticMapperConstraintsComplete'])
        self.assertTrue(public['reservedClaimOverrideMapperObserved'])
        self.assertFalse(public['reservedClaimOverrideRequiresReview'])
        self.assertTrue(public['standardSubjectMapperMatchesServiceAccountSemantics'])
        self.assertTrue(public['serviceAccountClientIdMapperMatchesRegisteredClientSemantics'])
        for key in ('productionApplyReady', 'runtimeAuthorityIssued', 'credentialProvenanceAccepted', 'historicalAccountingReconciled'):
            self.assertFalse(candidate[key])
        self.assertFalse(public['targetProviderImplementationProven'])
        self.assertNotIn('PRIVATE_FIXTURE_CLIENT', json.dumps(public))

    def test_foreign_notes_nested_claim_wrong_type_and_missing_channels_remain_unresolved(self):
        for key, replacement in [('user.session.note','PRIVATE_FOREIGN_NOTE'), ('claim.name','client_id.nested'),
                ('jsonType.label','JSON'), ('access.token.claim','false'), ('introspection.token.claim','false'), ('multivalued','true')]:
            value = standard(); value['client']['protocolMappers'][-1]['config'][key] = replacement
            _, public = semantics.review(value, 'a'*64, fixture.REF)
            self.assertFalse(public['staticMapperConstraintsComplete'])
            self.assertTrue(public['reservedClaimOverrideRequiresReview'])
            self.assertNotIn('PRIVATE_FOREIGN_NOTE', json.dumps(public))

    def test_legacy_client_id_session_note_is_recognized_without_exposing_value(self):
        value = standard(); value['client']['protocolMappers'][-1]['config']['user.session.note'] = 'clientId'
        _, public = semantics.review(value, 'a'*64, fixture.REF)
        self.assertTrue(public['staticMapperConstraintsComplete'])

    def test_other_reserved_subject_and_unknown_provider_effects_still_require_review(self):
        for extra in [fixture.claim('iss','PRIVATE_FOREIGN_ISSUER'), fixture.claim('sub','PRIVATE_FOREIGN_SUBJECT'),
                {'protocol':'openid-connect','protocolMapper':'PRIVATE_DYNAMIC_PROVIDER','config':{}}, {}]:
            value=standard(); value['client']['protocolMappers'].append(extra)
            candidate, public=semantics.review(value,'a'*64,fixture.REF)
            self.assertFalse(public['staticMapperConstraintsComplete'])
            self.assertTrue(candidate['reviewReasons'])
            self.assertNotIn('PRIVATE_', json.dumps(public))

    def test_subject_channels_are_not_inferred_and_unrequested_providers_are_excluded(self):
        value=standard(); del value['client']['protocolMappers'][-2]['config']['introspection.token.claim']
        _, public=semantics.review(value,'a'*64,fixture.REF)
        self.assertIn('STANDARD_SUBJECT_MAPPING_NOT_EXPLICIT',public['reviewReasons'])
        value=standard(); value['optionalScopes'][1]['protocolMappers']=[{}]
        _, public=semantics.review(value,'a'*64,fixture.REF)
        self.assertTrue(public['staticMapperConstraintsComplete'])

    def test_private_publication_reconciles_preserves_old_evidence_and_denies_hash_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            parent=Path(temporary);parent.chmod(0o700)
            path=parent/('policy-token-iam-metadata-'+'a'*32+'.private.json')
            raw=binding.encoded(standard());path.write_bytes(raw);path.chmod(0o600)
            with patch.object(binding,'PARENT',parent):
                first={'privateEvidenceWrites':0};semantics.prepare(str(path),binding.sha(raw),fixture.REF,first)
                output=Path(first['candidatePath']);inode=output.stat().st_ino
                second={'privateEvidenceWrites':0};semantics.prepare(str(path),binding.sha(raw),fixture.REF,second)
                self.assertEqual(first['privateEvidenceWrites'],1)
                self.assertEqual(second['privateEvidenceWrites'],0)
                self.assertEqual(output.stat().st_ino,inode)
                self.assertEqual(output.stat().st_mode&0o777,0o600)
                with self.assertRaises(binding.CandidateDenied):semantics.prepare(str(path),'b'*64,fixture.REF,{'privateEvidenceWrites':0})
            self.assertEqual(path.read_bytes(),raw)

if __name__ == '__main__': unittest.main()
