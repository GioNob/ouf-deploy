"""Approved operator bridge scope and real issuer interoperability; CI only."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import execute_approved_provider_transaction as bridge

class ApprovedBridgeTests(unittest.TestCase):
    def hashes(self):
        return {role:copy.deepcopy(p['inputHashes']) for role,p in bridge.SCOPE['roleProposals'].items()}

    def test_exact_human_scope_has_one_shared_240_second_window(self):
        now=bridge.APPROVED_AT+10
        values=bridge.build_mandates(bridge.SCOPE,self.hashes(),now,bridge.APPROVAL_REF)
        self.assertEqual(set(values),{'adapter','southbound'})
        self.assertEqual({v['expiresAt']-v['issuedAt'] for v in values.values()},{240})
        self.assertEqual({v['approvalRef'] for v in values.values()},{bridge.APPROVAL_REF})
        self.assertEqual({v['state'] for v in values.values()},{'ACTIVE'})

    def test_old_input_acceptance_cannot_replace_new_execution_approval(self):
        with self.assertRaisesRegex(ValueError,'EXPLICIT_RECORDED_HUMAN_APPROVAL_REQUIRED'):
            bridge.build_mandates(bridge.SCOPE,self.hashes(),bridge.APPROVED_AT+10,'OUF_PROVIDER_V2_FULL_INPUT_REVIEW_20261009_005751')

    def test_foreign_candidate_or_scope_denied(self):
        value=copy.deepcopy(bridge.SCOPE);value['roleProposals']['adapter']['containerId']='0'*64
        with self.assertRaisesRegex(ValueError,'APPROVED_EXECUTION_SCOPE_DRIFT'):
            bridge.build_mandates(value,self.hashes(),bridge.APPROVED_AT+10,bridge.APPROVAL_REF)

    def test_modified_private_input_hash_denied(self):
        hashes=self.hashes();hashes['southbound']['framePolicy']='0'*64
        with self.assertRaisesRegex(ValueError,'APPROVED_EIGHT_INPUT_HASHES_DRIFT'):
            bridge.build_mandates(bridge.SCOPE,hashes,bridge.APPROVED_AT+10,bridge.APPROVAL_REF)

    def test_entire_window_must_fit_freshness_without_clipping(self):
        bridge.build_mandates(bridge.SCOPE,self.hashes(),bridge.FRESH_UNTIL-240,bridge.APPROVAL_REF)
        with self.assertRaisesRegex(ValueError,'DEPENDENCY_VALIDITY_DOES_NOT_COVER_240_SECOND_WINDOW'):
            bridge.build_mandates(bridge.SCOPE,self.hashes(),bridge.FRESH_UNTIL-239,bridge.APPROVAL_REF)

    def test_clock_cannot_backdate_before_human_decision(self):
        with self.assertRaisesRegex(ValueError,'ROOT_CLOCK_BEFORE_HUMAN_APPROVAL'):
            bridge.build_mandates(bridge.SCOPE,self.hashes(),bridge.APPROVED_AT-1,bridge.APPROVAL_REF)

    def test_generated_scope_is_consumed_by_real_issuer_preflight_without_keys(self):
        # Disposable fixture bytes/keys/time only; main() never accepts this scope.
        profiles=Path(__file__).resolve().parent.parent/'semantic_transaction_profiles'
        sys.path.insert(0,str(profiles))
        from test_authenticated_transaction import AuthenticatedTransactionTest
        from issue_provider_transaction_authority import issue_role_authority,INPUTS,SCOPES
        from authenticate_provider_transaction import TARGETS,encoded,digest
        fixture=AuthenticatedTransactionTest();fixture.setUp()
        try:
            records={role:{name:raw for name,raw in values.items() if name in INPUTS} for role,values in fixture.records.items()}
            scope=copy.deepcopy(bridge.SCOPE)
            for role,value in scope['roleProposals'].items():
                value.update(TARGETS[role]);value['roleSigningScopes']=SCOPES
                value['inputHashes']={name:digest(raw) for name,raw in records[role].items()}
                value['transactionId']=json.loads(records[role]['preparerTemplate'])['candidate']['transactionId']
                value['sourceClosureHash']=digest(encoded({**{name:digest(raw) for name,raw in fixture.sources.items()},'frame-observer.py':digest(fixture.observer)}))
            with patch.object(bridge,'SCOPE',scope),patch.object(bridge,'APPROVED_AT',fixture.now-1),patch.object(bridge,'FRESH_UNTIL',fixture.now+300):
                mandates=bridge.build_mandates(scope,{r:v['inputHashes'] for r,v in scope['roleProposals'].items()},fixture.now,bridge.APPROVAL_REF)
            for role,value in mandates.items():
                path=fixture.root/(role+'-bridge-mandate.json');fixture.private(path,encoded(value));binding=fixture.bind(path)
                report=issue_role_authority(role,binding,binding['sha256'],records[role],fixture.authority,
                    fixture.sources,fixture.observer,fixture.verifier,fixture.root/'unused-output',fixture.clock,validate_only=True)
                self.assertEqual(report['privateKeysRead'],0);self.assertEqual(report['signaturesIssued'],0)
            self.assertFalse((fixture.root/'unused-output').exists())
        finally:fixture.doCleanups()

if __name__=='__main__':unittest.main()
