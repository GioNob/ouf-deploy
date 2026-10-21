"""Exact R3 recovery rejection and real fresh-context signing; disposable CI keys."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import execute_bundle_context_recovery as recovery

class BundleRecoveryTests(unittest.TestCase):
    def denial(self):
        return {'stage':'VERIFY_CONTROLLED_DOCKER_COHORT_READBACK',
            'reason':'COHORT_ADMITTED_RUNNING_STATE_UNPROVEN','dockerStartRequests':2,
            'automaticRetryPerformed':False,'candidateObservations':{
                c:{**v,'adapterState':'STAGED','nativeDenialReason':'ADAPTER_BINDING_UNPROVEN_L283'}
                for c,v in recovery.EXPECTED_OBSERVATIONS.items()},
            'dockerResults':{c:{'exitCode':1,'exactCidAcknowledged':False,'errorType':None}
                for c in recovery.EXPECTED_OBSERVATIONS}}

    def test_pending_scope_denies_before_any_file_access(self):
        with patch('os.open',side_effect=AssertionError('unapproved file access')):
            with self.assertRaisesRegex(ValueError,'EXPLICIT_CHANGED_CONTEXT_RECOVERY_APPROVAL_REQUIRED'):
                recovery.main('unapproved','/base','/r3')

    def test_clock_before_approval_denies_before_any_file_access(self):
        with patch.object(recovery,'APPROVAL_REF','CI_ONLY'),patch.object(recovery,'APPROVED_AT',100),\
             patch('time.time',return_value=99),patch('os.open',side_effect=AssertionError('premature file access')):
            with self.assertRaisesRegex(ValueError,'ROOT_CLOCK_BEFORE_HUMAN_APPROVAL'):
                recovery.main('CI_ONLY','/base','/r3')

    def test_exact_failure_and_uncertain_or_partial_outcomes(self):
        recovery.validate_failure(self.denial())
        for section,field,value in [('candidateObservations','adapterState','STARTED'),
            ('candidateObservations','nativeDenialReason','DIFFERENT'),
            ('candidateObservations','stateHash','a'*64),('dockerResults','exitCode',None),
            ('dockerResults','exactCidAcknowledged',True)]:
            d=self.denial();d[section][next(iter(d[section]))][field]=value
            with self.assertRaisesRegex(ValueError,'EXACT_PRE_CREATE_BINDING_DENIAL_REQUIRED'):
                recovery.validate_failure(d)
        d=self.denial();d['candidateObservations'].pop(next(iter(d['candidateObservations'])))
        with self.assertRaisesRegex(ValueError,'BOTH_RETAINED_CANDIDATE_OBSERVATIONS_REQUIRED'):
            recovery.validate_failure(d)

    def test_only_two_wrapper_assertions_repaired(self):
        import execute_approved_provider_transaction as bridge
        raw=bridge.REPAIRED_ENTRY
        revised=recovery.repaired_entry(raw)
        self.assertEqual(revised.count(recovery.PRIOR_WRAPPER.encode()),2)
        self.assertEqual(revised.replace(recovery.PRIOR_WRAPPER.encode(),recovery.EMPTY_WRAPPER.encode()),raw)
        compile(revised,'reviewed-memory-entry','exec')
        with self.assertRaisesRegex(ValueError,'EXACT_PRIOR_WRAPPER_ASSERTIONS_REQUIRED'):
            recovery.repaired_entry(raw+recovery.EMPTY_WRAPPER.encode())

    def test_corrected_contexts_real_issuance_and_installed_allowlist(self):
        profiles=Path(__file__).resolve().parents[1]/'semantic_transaction_profiles'
        sys.path.insert(0,str(profiles))
        from test_authenticated_transaction import AuthenticatedTransactionTest
        from issue_provider_transaction_authority import INPUTS,SCOPES,issue_role_authority
        from authenticate_provider_transaction import TARGETS,build_install_plan,encoded,digest
        from compile_creation_frame_policy import compile_policy
        from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
        import execute_approved_provider_transaction as bridge
        fixture=AuthenticatedTransactionTest();fixture.setUp()
        try:
            records={r:{k:v for k,v in docs.items() if k in INPUTS} for r,docs in fixture.records.items()}
            scope=copy.deepcopy(bridge.SCOPE);new_hashes={}
            for role,values in records.items():
                context=json.loads(values['context']);context['bundleParent']=recovery.OLD_PARENT
                values['context']=encoded(context)
                scope['roleProposals'][role].update(TARGETS[role],inputHashes={k:digest(v) for k,v in values.items()},
                    applicationHash=digest(encoded(json.loads(values['framePolicy'])['expectedOci'])),
                    roleSigningScopes=SCOPES,
                    transactionId=json.loads(values['preparerTemplate'])['candidate']['transactionId'],
                    sourceClosureHash=digest(encoded({**{n:digest(v) for n,v in fixture.sources.items()},'frame-observer.py':digest(fixture.observer)})))
                new_hashes[role]=digest(encoded(dict(context,bundleParent=recovery.NEW_PARENT)))
            saved=copy.deepcopy(scope)
            with patch.object(recovery,'NEW_HASHES',new_hashes):
                changed,next_scope=recovery.changed_records(records,scope,json.loads,encoded,digest,compile_policy)
                self.assertEqual(scope,saved)
                for role in changed:
                    self.assertEqual(changed[role]['framePolicy'],records[role]['framePolicy'])
                    self.assertEqual(json.loads(records[role]['context'])['bundleParent'],recovery.OLD_PARENT)
                foreign=copy.deepcopy(records);foreign['adapter']['context']=encoded(dict(json.loads(foreign['adapter']['context']),rootfsPath='/var/lib/docker/foreign'))
                with self.assertRaisesRegex(ValueError,'RETAINED_ACCEPTED_INPUTS_DRIFT'):
                    recovery.changed_records(foreign,scope,json.loads,encoded,digest,compile_policy)
            with patch.object(bridge,'SCOPE',next_scope),patch.object(bridge,'APPROVED_AT',fixture.now-1),patch.object(bridge,'FRESH_UNTIL',fixture.now+300):
                mandates=bridge.build_mandates(next_scope,{r:{k:digest(v) for k,v in docs.items()} for r,docs in changed.items()},fixture.now,bridge.APPROVAL_REF)
            fresh=fixture.root/'fresh-corrected-signatures';fresh.mkdir(mode=0o700)
            crypto={**fixture.crypto,'signatureDirectory':str(fresh)}
            verifier=DetachedAuthenticator(fixture.crypto['policyBinding'],fresh,fixture.crypto['opensslBinding'],clock=fixture.clock)
            for role,mandate in mandates.items():
                p=fixture.root/(role+'-corrected-mandate.json');fixture.private(p,encoded(mandate))
                out=fixture.root/(role+'-new-authority');out.mkdir(mode=0o700)
                issued=issue_role_authority(role,fixture.bind(p),digest(encoded(mandate)),changed[role],fixture.authority,fixture.sources,fixture.observer,verifier,out,fixture.clock)
                self.assertEqual(issued['signaturesIssued'],4)
                changed[role].update({k:Path(b['path']).read_bytes() for k,b in issued['records'].items()})
            plan=build_install_plan(str(fixture.root/'new-publication'),str(fixture.root/'new-publication/source'),changed,fixture.authority,fixture.sources,fixture.observer,fixture.python,crypto,verifier,fixture.adapter,fixture.clock)
            for candidate in plan['adapterConfiguration']['candidates'].values():
                self.assertEqual(candidate['bundleParents'],[recovery.NEW_PARENT])
        finally:fixture.doCleanups()

if __name__=='__main__':unittest.main()
