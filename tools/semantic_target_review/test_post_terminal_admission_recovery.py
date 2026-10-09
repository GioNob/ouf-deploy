"""Fresh admission scope after terminal recovery; CI keys confer no target authority."""
import ast,copy,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('recovery',Path(__file__).with_name('execute_post_terminal_admission_recovery.py'))
recovery=importlib.util.module_from_spec(spec);spec.loader.exec_module(recovery)
class RecoveryTests(unittest.TestCase):
    def test_pending_approval_denies_before_any_read(self):
        with patch.object(recovery,'load_definitions') as loader,patch('os.open',side_effect=AssertionError('unapproved read')):
            with self.assertRaisesRegex(ValueError,'EXPLICIT_POST_TERMINAL_ADMISSION_APPROVAL_REQUIRED'):
                recovery.main('unapproved','/base','/r3','/repair','/reader')
        loader.assert_not_called()
    def test_future_approval_clock_denies_before_helpers(self):
        with patch.object(recovery,'APPROVAL_REF','DISPOSABLE_CI_APPROVAL'),patch.object(recovery,'APPROVED_AT',100),patch.object(recovery.time,'time',return_value=99),patch.object(recovery,'load_definitions') as loader:
            with self.assertRaisesRegex(ValueError,'ROOT_CLOCK_BEFORE_HUMAN_APPROVAL'):
                recovery.main('DISPOSABLE_CI_APPROVAL','/base','/r3','/repair','/reader')
        loader.assert_not_called()
    def test_exact_r5_partial_failure_not_r4(self):
        denial={'stage':'VERIFY_CONTROLLED_DOCKER_COHORT_READBACK','reason':'COHORT_ADMITTED_RUNNING_STATE_UNPROVEN',
            'dockerStartRequests':2,'automaticRetryPerformed':False,
            'candidateObservations':{c:{**v,'adapterState':'DELETING' if c==recovery.ADAPTER else 'STAGED',
                'nativeDenialReason':'BROKER_PHASE_COHORT_READY_DENIED' if c==recovery.ADAPTER else None} for c,v in recovery.EXPECTED_OBSERVATIONS.items()},
            'dockerResults':{c:{'exitCode':1,'exactCidAcknowledged':False,'errorType':None} for c in recovery.EXPECTED_OBSERVATIONS}}
        recovery.validate_failure(denial)
        denial['candidateObservations'][recovery.SOUTH]['adapterState']='DELETING'
        with self.assertRaises(ValueError):recovery.validate_failure(denial)
    def preflight(self):
        return {'status':'POST_TERMINAL_ADMISSION_PREREQUISITES_CAPTURED','acceptedInputCount':16,'retainedFilesVerified':91,
            'sourceClosureHash':recovery.NEW_CLOSURE,'successfulMaintenanceResultHash':recovery.SUCCESS_SHA,
            'consumedAliasClaimHash':recovery.ALIAS_CLAIM_SHA,'reviewedDependencyMetadataCovers240Seconds':True,
            'claimsCreated':0,'privateKeysRead':0,'signaturesIssued':0,'containerLifecycleOperations':0,'startAuthorized':False,
            'currentEmptyGuard':{'providerSetsEmpty':True,'lockInodePreserved':True,'candidateStateHashes':{c:v['stateHash'] for c,v in recovery.EXPECTED_OBSERVATIONS.items()}},
            'roles':{r:{'containerId':c,'taskAbsent':True,'nativeEntryAbsentAtRetainedRoot':True,'containerMetadataHash':recovery.METADATA[c]} for r,c in (('adapter',recovery.ADAPTER),('southbound',recovery.SOUTH))}}
    def test_maintenance_receipt_claim_and_task_generation_required(self):
        value=self.preflight();recovery.validate_preflight(value)
        for key,bad in [('successfulMaintenanceResultHash','0'*64),('consumedAliasClaimHash','0'*64),('acceptedInputCount',15),('reviewedDependencyMetadataCovers240Seconds',False)]:
            changed=copy.deepcopy(value);changed[key]=bad
            with self.assertRaises(ValueError):recovery.validate_preflight(changed)
        changed=copy.deepcopy(value);changed['roles']['adapter']['taskAbsent']=False
        with self.assertRaises(ValueError):recovery.validate_preflight(changed)
        changed=copy.deepcopy(value);changed['currentEmptyGuard']['providerSetsEmpty']=False
        with self.assertRaises(ValueError):recovery.validate_preflight(changed)
    def test_only_three_observed_adapter_journals_override(self):
        for p,h in recovery.RETAINED_ADVANCED_HASHES.items():
            self.assertTrue(p.startswith('registry/'+recovery.ADAPTER+'/'))
            self.assertEqual(recovery.retained_publication_hash(str(recovery.OLD_OUTPUT/p),'b'*64),h)
        self.assertEqual(len(recovery.RETAINED_ADVANCED_HASHES),3)
        with self.assertRaisesRegex(ValueError,'RETAINED_FILE_PATH_ESCAPE'):
            recovery.retained_publication_hash('/outside','a'*64)
    def test_real_file_prior_evidence_unchanged_and_drift_denied(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root=Path(temp);paths=[root/'consumed-claim.json',root/'timeout-denial.json',root/'signatures.json']
            for i,p in enumerate(paths):p.write_bytes(str(i).encode())
            entry={'read':lambda p:Path(p).read_bytes(),'digest':lambda b:recovery.hashlib.sha256(b).hexdigest()}
            frozen={str(p):entry['digest'](p.read_bytes()) for p in paths};before={p:p.read_bytes() for p in paths}
            recovery.ensure_preserved(entry,frozen);self.assertEqual(before,{p:p.read_bytes() for p in paths})
            paths[0].write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'RETAINED_R5_OR_TERMINAL_EVIDENCE_CHANGED'):recovery.ensure_preserved(entry,frozen)
    def test_no_claim_reset_cleanup_or_direct_docker_shortcut(self):
        source=Path(recovery.__file__).read_text();tree=ast.parse(source)
        for n in ast.walk(tree):
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute):
                self.assertNotIn(n.func.attr,{'unlink','remove','rmdir','rmtree','kill'})
        self.assertNotIn("['tasks','delete'",source);self.assertNotIn("['start'",source)
        self.assertIn("package/'post-terminal-admission-recovery-claim.json'",source)
    def test_fresh_r6_eight_signatures_and_preserved_publication(self):
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
            self.assertEqual(next_scope['reviewRef'],recovery.REVIEW_REF)
            self.assertEqual(next_scope['reviewRef'],'OUF_PROVIDER_V2_POST_TERMINAL_ADMISSION_REVIEW_20261009_R6')
            with patch.object(bridge,'APPROVAL_REF','DISPOSABLE_R6_APPROVAL'),patch.object(bridge,'SCOPE',next_scope),patch.object(bridge,'APPROVED_AT',fixture.now-1),patch.object(bridge,'FRESH_UNTIL',fixture.now+300):
                mandates=bridge.build_mandates(next_scope,{r:{k:digest(v) for k,v in docs.items()} for r,docs in records.items()},fixture.now,bridge.APPROVAL_REF)
            fresh=fixture.root/'fresh-source-signatures';fresh.mkdir(mode=0o700)
            crypto={**fixture.crypto,'signatureDirectory':str(fresh)}
            verifier=DetachedAuthenticator(fixture.crypto['policyBinding'],fresh,fixture.crypto['opensslBinding'],clock=fixture.clock)
            for role,value in mandates.items():
                self.assertEqual(value['sourceClosureHash'],closure)
                self.assertEqual(value['approvalRef'],'DISPOSABLE_R6_APPROVAL')
                self.assertEqual(value['expiresAt']-value['issuedAt'],240)
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
