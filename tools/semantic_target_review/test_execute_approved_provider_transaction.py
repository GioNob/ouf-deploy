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
    def test_recovery_rejects_partial_execution_and_foreign_context(self):
        denial={'stage':'PREFLIGHT_BOTH_EXPLICIT_ROOT_MANDATES','reason':'PRIVATE_TARGET_INTAKE_UNPROVEN',
            'privateKeysRead':0,'containerLifecycleOperations':0,'targetRuntimeChanged':False}
        claim={'schema':'ouf.semantic-provider-operator-context-claim.v1','state':'CONTEXT_RESERVED',
            'contextDirectory':str(bridge.FAILED_CONTEXT),'approvalRef':bridge.APPROVAL_REF}
        outer={**denial,'phase':'INVOKE_EXISTING_SEALED_APPROVED_TRANSACTION',
            'contextDirectory':str(bridge.FAILED_CONTEXT)}
        present={n:False for n in ('execution-claim.json','issued-signatures','role-authority','intake-claim.json','execution-receipt.json')}
        bridge.validate_pre_key_failure(denial,claim,outer,present)
        for changed in ({**denial,'privateKeysRead':None},{**denial,'privateKeysRead':True},
                        {**denial,'containerLifecycleOperations':1},{**denial,'targetRuntimeChanged':True}):
            with self.assertRaisesRegex(ValueError,'NO_KEY_OR_LIFECYCLE_ATTEMPT_REQUIRED'):
                bridge.validate_pre_key_failure(changed,claim,outer,present)
        with self.assertRaisesRegex(ValueError,'PRE_KEY_RECOVERY_STATE_REQUIRED'):
            bridge.validate_pre_key_failure(denial,claim,outer,{**present,'execution-claim.json':True})
        with self.assertRaisesRegex(ValueError,'EXACT_ORIGINAL_CONTEXT_RESERVATION_REQUIRED'):
            bridge.validate_pre_key_failure(denial,{**claim,'contextDirectory':'/other'},outer,present)

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
            # Reproduce the target cold path: future signature directory absent.
            import provider_transaction_intake as intake
            from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
            pending=fixture.root/'issued-signatures'
            with self.assertRaises(FileNotFoundError):
                DetachedAuthenticator(fixture.crypto['policyBinding'],pending,fixture.crypto['opensslBinding'])
            cfg={'opensslBinding':fixture.crypto['opensslBinding'],
                 'mandatesByRole':{r:fixture.bind(fixture.root/(r+'-bridge-mandate.json')) for r in mandates}}
            with patch.object(intake,'POLICY',fixture.crypto['policyBinding']):
                intake.preflight_root_mandates(fixture.root,cfg,records,fixture.authority,
                    fixture.sources,fixture.observer,fixture.clock)
                # A denial of the second role also leaves no staging/claim/signature output.
                bad=copy.deepcopy(mandates['southbound']);bad['containerId']='0'*64
                fixture.private(fixture.root/'southbound-bridge-mandate.json',encoded(bad))
                cfg['mandatesByRole']['southbound']=fixture.bind(fixture.root/'southbound-bridge-mandate.json')
                with self.assertRaisesRegex(ValueError,'ROOT_ROLE_REVIEW_SCOPE_DRIFT'):
                    intake.preflight_root_mandates(fixture.root,cfg,records,fixture.authority,
                        fixture.sources,fixture.observer,fixture.clock)
            self.assertFalse(pending.exists())
            self.assertFalse((fixture.root/'role-authority').exists())
            self.assertFalse((fixture.root/'execution-claim.json').exists())
            self.assertEqual(list(fixture.root.glob('mandate-preflight-*')),[])
        finally:fixture.doCleanups()

if __name__=='__main__':unittest.main()
