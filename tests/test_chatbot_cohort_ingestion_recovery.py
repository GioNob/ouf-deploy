"""Finite phase-6 continuation: immutable CLAIMED create and exact image defaults."""
import copy,hashlib,json,tempfile,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
import test_chatbot_cohort_containers as fixture
from tools.chatbot_file_cohort import ingestion_recovery as r,gateway_recovery as base
from tools.chatbot_file_cohort.containers import CohortContainers,installation_scope
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine

def receipt():
    return {'profile':r.PROFILE,'sourceCommit':r.SOURCE,'reviewHash':r.REVIEW,'authorityHash':r.AUTHORITY,
        'containerJournalHash':r.CONTAINERS,'gatewayJournalHash':r.GATEWAY,'databaseJournalHash':r.DATABASE,
        'cancelledWorkerHash':r.WORKER,'workerSessionHash':r.SESSION,'admissionHash':r.ADMISSION,
        'createdContainerId':r.CREATED,'nativeBindingHash':r.NATIVE,'finalRouteMapHash':r.ROUTES,
        'originalClaimHash':'a'*64,'newCreateAllowed':False,'newGatewayWritesAllowed':False,
        'retainedAppliedContainerEffects':11,'claimedCreateObservationRequired':True}

class IngestionContinuation(unittest.TestCase):
    def test_retained_bindings_reads_all_archive_bytes_for_eight_and_nine_grants(self):
        # Exercise the production binding validator and archive reader together.
        # The enrichment fixture below mocks this historical boundary; this
        # regression must not, because that hid a module/count name collision.
        from tools.chatbot_file_cohort.action_process import observed_private_json
        with tempfile.TemporaryDirectory(prefix='archive-bindings-',dir=fixture.ROOT.parent) as directory:
            root=Path(directory);root.chmod(0o700)
            record=root/'record.json';record.write_text('{}');record.chmod(0o600)
            _,binding=observed_private_json(record,8388608)
            archives={}
            for module in base.ARCHIVES:
                data=b'PGDMP-disposable-binding-fixture-'+module.encode()
                archive=root/(module+'.dump');archive.write_bytes(data);archive.chmod(0o600)
                archives[module]=(len(data),hashlib.sha256(data).hexdigest())
            proof={'profile':base.PROFILE,'gatewayPredecessorAuthorityHash':base.AUTHORITY,
                'gatewayPredecessorSource':base.SOURCE,'gatewayPredecessorReviewHash':base.REVIEW,
                'predecessorTransitionHash':base.TRANSITION_HASH,'cancelledWorkerHash':base.WORKER_HASH,
                'workerSessionHash':base.SESSION_HASH,'databaseJournalHash':base.DATABASE_HASH,
                'containerJournalHash':base.CONTAINERS_HASH,'gatewayJournalHash':base.GATEWAY_HASH,
                'newBudget':{'priorControlledGrantAttempts':8},'registryPhaseReplayAllowed':False,
                'newNodeAttestationAllowed':False,'runningRootfsQualification':base.RUNNING_ROOTFS_QUALIFICATION,
                'newMcpArchiveMaximumAttempts':0,'migrationStartMaximumAttempts':0,
                'migrationCreateAllowed':False,'auditBootstrapAllowed':False,'oldAuthorityExtended':False,
                'recordBindings':[binding],'retainedCohortBackupDirectory':str(root)}
            before={p.name:p.read_bytes()for p in root.iterdir()}
            with patch.object(base,'ARCHIVES',archives),patch.object(base.prior,'ARCHIVES',archives):
                base.retained_bindings(proof)
                latest=copy.deepcopy(proof);latest.update(retainedCreatedIngestion=receipt(),
                    cancelledWorkerHash=r.WORKER,workerSessionHash=r.SESSION,
                    newBudget={'priorControlledGrantAttempts':9})
                base.retained_bindings(latest)
                self.assertEqual({p.name:p.read_bytes()for p in root.iterdir()},before)
                bad=copy.deepcopy(latest);bad['newBudget']['priorControlledGrantAttempts']=8
                with self.assertRaisesRegex(Exception,'EXACT_GATEWAY_RECOVERY_PROOF_REQUIRED'):
                    base.retained_bindings(bad)
                for module in archives:
                    path=root/(module+'.dump');data=path.read_bytes()
                    path.write_bytes(b'X'+data[1:])
                    with self.assertRaisesRegex(Exception,'RETAINED_ARCHIVE_HASH_OR_IDENTITY_DRIFT'):
                        base.retained_bindings(latest)
                    path.write_bytes(data)

    def fixture(self):
        f=fixture.CohortRuntime();self.addCleanup(f.doCleanups)
        owner,native,crypto,now=f.fixture();owner.run_until('onboarding')
        original=owner.observe
        def crash(row,stage):
            if row['module']=='ingestion'and stage=='create':raise RuntimeError('fixture crash after create')
            return original(row,stage)
        owner.observe=crash
        with self.assertRaisesRegex(RuntimeError,'fixture crash'):owner.run_until('ingestion')
        row=next(x for x in owner.plan['replacements']if x['module']=='ingestion')
        actual=native.find(row['name']);actual['State'].update(Restarting=False,Dead=False)
        old=owner.record();self.assertEqual(old['nextStep'],11);self.assertEqual(len(old['effects']),12)
        stack=self.enterContext(ExitStack())
        for name,value in [('AUTHORITY',owner.action.authority_hash),('CONTAINERS',r.digest(old)),
            ('CREATED',actual['Id']),('NATIVE',r.digest(Engine.runtime_binding(actual)))]:stack.enter_context(patch.object(r,name,value))
        proof={'profile':base.PROFILE,'retainedCreatedIngestion':receipt()}
        previous={'ingestionAttempt':{'receipt':proof['retainedCreatedIngestion'],'prepared':{'cohortPlan':owner.plan},'containers':old}}
        raw=owner.journal.record.read_bytes()
        stack.enter_context(patch.object(base,'retained_bindings',side_effect=lambda _:
            self.assertEqual(owner.journal.record.read_bytes(),raw)))
        stack.enter_context(patch.object(base,'current_completed_containers'))
        authority=json.loads(crypto.authority);authority['applicationRegistryCutover']={'postGrantRecovery':proof}
        crypto.authority=fixture.crypto.encoded(authority);crypto.approval['executionAuthorityHash']=fixture.crypto.sha(crypto.authority)
        crypto.write(crypto.mandate,fixture.crypto.encoded(crypto.approval));crypto.approved=fixture.crypto.sha(crypto.mandate.read_bytes())
        for role in crypto.grant['roles']:crypto.sign(role)
        action=AggregateAction(crypto.gate(),crypto.authority,crypto.expected['sourceClosureHash'])
        directory=crypto.root/'new-ingestion-journal';directory.mkdir(mode=0o700)
        successor=CohortContainers(action,native.engine,Journal(directory),owner.plan,owner.clock)
        successor.initialize();successor.health=owner.health
        self.owner,self.native,self.row,self.actual=owner,native,row,actual
        self.successor,self.previous,self.proof,self.crypto=successor,previous,proof,crypto
        return stack

    def test_claimed_create_adoption_never_creates_again_and_starts_exact_id_once(self):
        self.fixture();before=copy.deepcopy(self.native.calls);oldbytes=self.owner.journal.record.read_bytes()
        r.adopt_containers(self.successor,self.previous,self.proof)
        self.assertEqual(self.native.calls,before);self.assertEqual(self.successor.record()['nextStep'],11)
        for name,key in (('registry','registryModulePackageHash'),('database','databasePlanHash'),
            ('authorization','authorizationPlanHash'),('gateway','gatewayPlanHash')):
            self.successor.accept_owner_gate(name,self.successor.plan[key],r.digest({'current':name}))
        self.successor.run_until('ingestion');after=copy.deepcopy(self.native.calls)
        self.assertEqual([s[0]for s in after[len(before):]],['start','update'])
        self.assertEqual(self.native.find(self.row['name'])['Id'],r.CREATED)
        self.assertEqual(self.successor.record()['nextStep'],15)
        self.successor.run_until('ingestion');self.assertEqual(self.native.calls,after)
        self.assertEqual(self.owner.journal.record.read_bytes(),oldbytes)
        with self.assertRaisesRegex(Exception,'EXACT_CREATED|MUST_BE_NEVER|HOST_CONFIG_DRIFT'):r.native_readback(self.previous,self.native.engine)

    def test_duplicates_revocation_wrong_generation_and_changed_intent_block(self):
        self.fixture();r.adopt_containers(self.successor,self.previous,self.proof)
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):r.adopt_containers(self.successor,self.previous,self.proof)
        calls=copy.deepcopy(self.native.calls);self.actual['Id']='f'*64
        with self.assertRaisesRegex(Exception,'EXACT_CREATED'):r.native_readback(self.previous,self.native.engine)
        with self.assertRaisesRegex(Exception,'SIGNED_ID_DRIFT'):self.successor.candidate(self.row)
        self.actual['Id']=r.CREATED
        bad=copy.deepcopy(self.previous['ingestionAttempt']['containers']);bad['effects'][-1]['intentHash']='0'*64
        with self.assertRaises(Exception):r.validate_containers(self.owner.plan,bad)
        self.crypto.approval['state']='REVOKED';self.crypto.write(self.crypto.mandate,fixture.crypto.encoded(self.crypto.approval))
        with self.assertRaises(Exception):self.successor.run_until('ingestion')
        self.assertEqual(self.native.calls,calls)

    def test_image_defaults_are_exact_not_an_allowlist_for_extra_environment(self):
        self.fixture();native_request=self.native.engine.request
        defaults=['IMAGE_A=one','IMAGE_B=two','IMAGE_C=three']
        def request(method,path,*args):
            if '/images/' in path:return 200,{'Id':self.row['creationRequest']['Image'],'Config':{'Env':defaults}}
            return native_request(method,path,*args)
        self.native.engine.request=request;self.actual['Config']['Env']+=defaults
        reader=CohortContainers.__new__(CohortContainers);reader.engine=self.native.engine
        self.assertEqual(reader.candidate(self.row)['Id'],r.CREATED)
        for added in ('UNREVIEWED=private','IMAGE_A=changed'):
            self.actual['Config']['Env'].append(added)
            with self.assertRaises(Exception):reader.candidate(self.row)
            self.actual['Config']['Env'].pop()
        changed=copy.deepcopy(self.row);changed['environmentDelta']={'remove':['IMAGE_A']}
        with self.assertRaisesRegex(Exception,'REMOVED_ENVIRONMENT'):reader.candidate(changed)
        self.actual['Config']['Env']=self.actual['Config']['Env'][:-1]
        with self.assertRaisesRegex(Exception,'CONFIG_DRIFT'):reader.candidate(self.row)

    def test_typed_proof_is_bound_to_nine_grants_and_forbids_create_and_route_replay(self):
        proof={'retainedCreatedIngestion':receipt()};r.validate_proof(proof)
        for key,value in [('newCreateAllowed',True),('newGatewayWritesAllowed',True),('cancelledWorkerHash','0'*64)]:
            altered=copy.deepcopy(proof);altered['retainedCreatedIngestion'][key]=value
            with self.assertRaises(Exception):base.claim_for(altered)
        self.assertEqual(base.claim_for(proof),r.CLAIM)

    def test_complete_private_attempt_enrichment_preserves_claims_and_old_history(self):
        self.fixture()
        from tools.chatbot_file_cohort import gateway_retained,postgrant_recovery as original
        root=self.crypto.root/'latest';root.mkdir(mode=0o700)
        self.enterContext(patch.object(r,'CONTEXT','latest'));self.enterContext(patch.object(r.evidence,'PARENT',self.crypto.root))
        def write(path,value):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(r.evidence.encoded(value));path.chmod(0o600)
            return r.digest(value)
        first={'operation':'a'*64,'scopeHash':'b'*64};self.enterContext(patch.object(original,'FIRST_HASH',r.digest(first)))
        parent_worker={'syntheticEightGrantWorker':True};parent_session={'syntheticSixPredecessorSession':True}
        self.enterContext(patch.object(base,'WORKER_HASH',r.digest(parent_worker)))
        self.enterContext(patch.object(base,'SESSION_HASH',r.digest(parent_session)))
        old_receipt={'syntheticCompletedRuntimeReceipt':True};proof={'profile':base.PROFILE,'retainedNumericGateway':old_receipt}
        gateway={'changes':[{'id':str(i)}for i in range(28)],'proposedRoutes':{'retained':{'id':'retained'}}}
        plan=copy.deepcopy(self.owner.plan);plan['gatewayPlanHash']=r.digest(gateway)
        p={'postGrantRecovery':proof,'cohortPlan':plan,'databasePlan':{'retained':True},
            'postGrantWorkerDirectory':str(root/'worker'),'authorization':{'plan':{}},
            'gatewayPlan':gateway,'gatewayRuntimePlan':{},'registry':{'directoryPlan':{'transition':str(root/'transition')}}}
        declaration={'sourceCommit':r.SOURCE};bundle={'declaration':declaration,'prepared':p}
        bh=write(root/'bundle.json',bundle)
        dirs={n:str(root/n)for n in ('containers','gateway','databases','authorization','gatewayRuntime')}
        process={'authorityDirectory':str(root),'bundle':{'path':str(root/'bundle.json'),'sha256':bh},'directoryPlan':dirs}
        session={'schema':'ouf.policy-token-new-finite-worker-session.v8','predecessorGrantAttempts':8,
            'predecessorFirstGrantOperation':first['operation'],'predecessorFirstGrantScopeHash':first['scopeHash']}
        scopes={'finiteActionProcess':process,'applicationRegistryCutover':{'postGrantRecovery':proof},
            'policyTokenOwnerInstallation':{'journalPath':str(root/'worker')},'policyTokenFiniteWorkerSession':session}
        authority={**scopes,'expiresAt':2000000000};ah=write(root/'authority.json',authority)
        review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{}}},'sourceClosureHash':'c'*64,
            'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(p)}};rh=write(root/'review.json',review)
        write(root/'decision.json',{'state':'ACTIVE','approvedReviewHash':rh,'approvedSourceClosureHash':'c'*64,'expiresAt':2000000000})
        status={'authorityHash':ah,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'COHORT_REPLACEMENT_PROCESS_CONFIG_DRIFT'}
        sh=write(root/'delivery-status.json',status)
        row=copy.deepcopy(self.owner.record());row.update(authorityHash=ah,planHash=r.digest(plan))
        row['gates']['gateway']['scopeHash']=r.digest(gateway)
        ch=write(root/'containers/recovery.json',row)
        gw={'schema':'ouf.chatbot-file-cohort.gateway-publication.v1','authorityHash':ah,'planHash':r.digest(gateway),
            'budgetReset':False,'nextStep':28,'effects':[{'state':'APPLIED','routeId':c['id'],'intentHash':r.digest(c)}for c in gateway['changes']]}
        gh=write(root/'gateway/recovery.json',gw)
        db={'authorityHash':ah,'planHash':r.digest(p['databasePlan']),'backups':{'retained':True},
            'mcpMigration':{'state':'COMPLETE'},'mcpAuditRole':{'state':'CLEAN'}};dh=write(root/'databases/recovery.json',db)
        auth={'authorityHash':ah,'planHash':r.digest({}),'effects':{},'observations':{'AFTER_GATEWAY':{'state':'COMPLETE'}}}
        write(root/'authorization/recovery.json',auth)
        effects=[{'syntheticHistoricalEffect':i}for i in range(8)]
        write(root/'gatewayRuntime/recovery.json',{'authorityHash':ah,'nextStep':8,'planHash':r.digest({}),
            'effects':effects,'retainedNumericGateway':{'proofHash':r.digest(proof)}})
        write(root/'transition/recovery.json',{'nextPhase':10,'effects':[{}]*10})
        worker={'state':'CANCELLED','attempts':1,'publicationCount':1,'controlledPredecessorGrantAttempts':8,
            'controlledCumulativeGrantAttempts':9,'workerSessionHash':r.digest(session),'firstGrantReceiptHash':r.digest(first)}
        wh=write(root/'worker/recovery.json',worker);ss=write(root/'worker/owner-session.json',session)
        admission={'state':'BLOCKED','version':3};ad=write(root/'worker/owner-admission.json',admission)
        write(root/'worker/owner-first-grant.json',first);write(root/'worker/owner-predecessor-worker.json',parent_worker)
        write(root/'worker/owner-predecessor-session.json',parent_session)
        write(self.crypto.root/gateway_retained.CLAIM,{'authorityHash':ah,'proofHash':r.digest(proof),
            'state':'CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY','priorControlledGrantAttempts':8})
        for name,value in [('AUTHORITY',ah),('REVIEW',rh),('STATUS',sh),('CONTAINERS',ch),('GATEWAY',gh),
            ('DATABASE',dh),('WORKER',wh),('SESSION',ss),('ADMISSION',ad),('ROUTES',r.digest(gateway['proposedRoutes']))]:
            self.enterContext(patch.object(r,name,value))
        self.enterContext(patch.object(base,'verify_successor_transition'))
        self.enterContext(patch.object(original,'stopped_process'))
        self.enterContext(patch.object(base,'retained_bindings'))
        previous={'recordBindings':[],'firstGrant':first,'worker':parent_worker,'session':parent_session,
            'prepared':{'cohortPlan':plan,'databasePlan':p['databasePlan']},'databaseJournal':db,
            'containerJournal':{'effects':row['effects'][:10]},'retainedGatewayAttempt':{'receipt':old_receipt,
                'prepared':{'gatewayPlan':gateway,'gatewayRuntimePlan':{}},'journal':{'effects':effects}}}
        before=copy.deepcopy(previous);result=r.enrich(previous)
        self.assertEqual(previous,before);self.assertEqual(result['worker'],worker)
        self.assertEqual(result['prepared'],previous['prepared']);r.validate_proof({'retainedCreatedIngestion':result['ingestionAttempt']['receipt']})
        for binding in result['recordBindings']:
            from tools.chatbot_file_cohort.action_process import private_file
            private_file(binding,8388608)
        write(root/'authorization/recovery.json',{**auth,'effects':{'unexpected':{}}})
        with self.assertRaisesRegex(Exception,'COMPLETED_READONLY_AUTHORIZATION'):r.enrich(previous)

if __name__=='__main__':unittest.main()
