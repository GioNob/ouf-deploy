"""Revised-source authority and preserved partial R4 evidence; CI keys only."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import execute_broker_source_recovery as recovery

class BrokerRecoveryTests(unittest.TestCase):
    def test_pending_approval_denies_before_any_file_access(self):
        with patch('os.open',side_effect=AssertionError('unapproved access')):
            with self.assertRaisesRegex(ValueError,'EXPLICIT_REVISED_SOURCE_RECOVERY_APPROVAL_REQUIRED'):
                recovery.main('unapproved','/base','/r3','/repair')

    def test_exact_partial_denial_required(self):
        d={'stage':'VERIFY_CONTROLLED_DOCKER_COHORT_READBACK','reason':'COHORT_ADMITTED_RUNNING_STATE_UNPROVEN',
            'dockerStartRequests':2,'automaticRetryPerformed':False,
            'candidateObservations':{c:{**v,'adapterState':'DELETING' if c==recovery.SOUTH else 'STAGED',
                'nativeDenialReason':'TWO_PHASE_BROKER_DENIED'} for c,v in recovery.EXPECTED_OBSERVATIONS.items()},
            'dockerResults':{c:{'exitCode':1,'exactCidAcknowledged':False,'errorType':None} for c in recovery.EXPECTED_OBSERVATIONS}}
        recovery.validate_failure(d)
        changed=copy.deepcopy(d);changed['candidateObservations'][recovery.SOUTH]['adapterState']='STARTED'
        with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_R4_BROKER_DENIAL_REQUIRED'):recovery.validate_failure(changed)

    def test_only_three_observed_advanced_journals_override_original_hashes(self):
        for p,h in recovery.RETAINED_ADVANCED_HASHES.items():
            self.assertEqual(recovery.retained_publication_hash(str(recovery.OLD_OUTPUT/p),'b'*64),h)
        self.assertEqual(recovery.retained_publication_hash(str(recovery.OLD_OUTPUT/'source/unmodified.py'),'b'*64),'b'*64)
        with self.assertRaisesRegex(ValueError,'RETAINED_FILE_PATH_ESCAPE'):
            recovery.retained_publication_hash('/outside','a'*64)

    def test_revised_closure_fresh_eight_signatures_and_publication(self):
        profiles=Path(__file__).resolve().parents[1]/'semantic_transaction_profiles';sys.path.insert(0,str(profiles))
        from test_authenticated_transaction import AuthenticatedTransactionTest
        from repair_broker_sources import repair
        from issue_provider_transaction_authority import INPUTS,SCOPES,issue_role_authority
        from authenticate_provider_transaction import TARGETS,build_install_plan,encoded,digest
        from publish_provider_transaction import publish_plan
        from compile_creation_frame_policy import compile_policy
        from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
        import execute_approved_provider_transaction as bridge
        fixture=AuthenticatedTransactionTest();fixture.setUp()
        try:
            sources=repair(fixture.sources)
            closure=digest(encoded({**{n:digest(b) for n,b in sources.items()},'frame-observer.py':digest(fixture.observer)}))
            records={r:{k:v for k,v in docs.items() if k in INPUTS} for r,docs in fixture.records.items()}
            scope=copy.deepcopy(bridge.SCOPE);context_hashes={}
            for role,docs in records.items():
                context=json.loads(docs['context']);context['bundleParent']=recovery.NEW_PARENT;docs['context']=encoded(context)
                context_hashes[role]=digest(docs['context'])
                scope['roleProposals'][role].update(TARGETS[role],inputHashes={k:digest(v) for k,v in docs.items()},
                    roleSigningScopes=SCOPES,transactionId=json.loads(docs['preparerTemplate'])['candidate']['transactionId'])
            before=copy.deepcopy(records);original_sources=dict(fixture.sources)
            with patch.object(recovery,'NEW_HASHES',context_hashes),patch.object(recovery,'NEW_CLOSURE',closure):
                next_scope=recovery.accepted_scope(records,scope,json.loads,encoded,digest,compile_policy)
            self.assertEqual(records,before);self.assertEqual(fixture.sources,original_sources)
            with patch.object(bridge,'SCOPE',next_scope),patch.object(bridge,'APPROVED_AT',fixture.now-1),patch.object(bridge,'FRESH_UNTIL',fixture.now+300):
                mandates=bridge.build_mandates(next_scope,{r:{k:digest(v) for k,v in docs.items()} for r,docs in records.items()},fixture.now,bridge.APPROVAL_REF)
            fresh=fixture.root/'fresh-source-signatures';fresh.mkdir(mode=0o700)
            crypto={**fixture.crypto,'signatureDirectory':str(fresh)}
            verifier=DetachedAuthenticator(fixture.crypto['policyBinding'],fresh,fixture.crypto['opensslBinding'],clock=fixture.clock)
            for role,value in mandates.items():
                self.assertEqual(value['sourceClosureHash'],closure)
                p=fixture.root/(role+'-source-mandate.json');fixture.private(p,encoded(value))
                out=fixture.root/(role+'-source-authority');out.mkdir(mode=0o700)
                issued=issue_role_authority(role,fixture.bind(p),digest(encoded(value)),records[role],fixture.authority,sources,fixture.observer,verifier,out,fixture.clock)
                self.assertEqual(issued['signaturesIssued'],4)
                records[role].update({k:Path(b['path']).read_bytes() for k,b in issued['records'].items()})
            output=fixture.root/'revised-publication'
            plan=build_install_plan(str(output),str(output/'source'),records,fixture.authority,sources,fixture.observer,fixture.python,crypto,verifier,fixture.adapter,fixture.clock)
            published=publish_plan(output,plan,sources,fixture.observer)
            self.assertFalse(published['runtimeConfigurationChanged'])
            for n,b in sources.items():self.assertEqual((output/'source'/n).read_bytes(),b)
            for target in TARGETS.values():
                j=json.loads((output/'registry'/target['containerId']/'adapter.json').read_bytes())
                self.assertEqual(j['state'],'STAGED')
            self.assertEqual(fixture.sources,original_sources)
        finally:fixture.doCleanups()

if __name__=='__main__':unittest.main()
