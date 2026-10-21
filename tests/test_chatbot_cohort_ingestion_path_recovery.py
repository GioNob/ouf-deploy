"""Finite phase-6 continuation: immutable CLAIMED create and exact image defaults."""
import copy,hashlib,json,tempfile,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
import test_chatbot_cohort_containers as fixture
from tools.chatbot_file_cohort import ingestion_path_recovery as r,gateway_recovery as base
from tools.chatbot_file_cohort.containers import CohortContainers,installation_scope
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from engine_creation import Engine

def receipt():
    return {'profile':r.PROFILE,'sourceCommit':r.SOURCE,'reviewHash':r.REVIEW,'authorityHash':r.AUTHORITY,
        'containerJournalHash':r.CONTAINERS,'gatewayJournalHash':r.GATEWAY,'databaseJournalHash':r.DATABASE,
        'cancelledWorkerHash':r.WORKER,'workerSessionHash':r.SESSION,'admissionHash':r.ADMISSION,
        'createdContainerId':r.CREATED,'nativeBindingHash':r.NATIVE,'finalRouteMapHash':r.ROUTES,
        'originalClaimHash':'a'*64,'newCreateAllowed':True,'newGatewayWritesAllowed':False,
        'retainedAppliedContainerEffects':12,'failedStartReplayAllowed':False,'proposedIngestionPlanHash':'a'*64}

class IngestionContinuation(unittest.TestCase):
    def fixture(self):
        f=fixture.CohortRuntime();self.addCleanup(f.doCleanups)
        old_fixture=fixture.container_fixture
        def legacy(module):
            old,image,package=old_fixture(module)
            if module=='ingestion':old['Config']['Env'].append('PATH=/legacy/bin')
            return old,image,package
        with patch.object(fixture,'container_fixture',side_effect=legacy):owner,native,crypto,now=f.fixture()
        owner.run_until('onboarding')
        row=next(x for x in owner.plan['replacements']if x['module']=='ingestion')
        defaults={'Env':['PATH=/opt/jre/bin:/usr/bin','JAVA_HOME=/opt/jre'],'Entrypoint':row['creationRequest']['Entrypoint']}
        request=native.engine.request
        def engine(method,path,body=None):
            if '/images/'in path:return 200,{'Id':row['creationRequest']['Image'],'Config':defaults}
            if method=='POST'and path.endswith('/start')and native.find(row['name'])['Id']in path:
                actual=native.find(row['name'])
                if 'PATH=/legacy/bin'in actual['Config']['Env']:
                    actual['State'].update(ExitCode=127,Error='exec: "java": executable file not found in $PATH: unknown')
                    return 500,{'message':'private fixture start failure'}
            result=request(method,path,body)
            if method=='POST'and '/create?'in path:
                actual=native.find(row['name'])
                actual['Config']['Env'].append('JAVA_HOME=/opt/jre')
                actual['State'].update(Restarting=False,Dead=False)
            return result
        native.engine.request=engine
        with self.assertRaisesRegex(Exception,'COHORT_START_REQUIRES_RECONCILIATION'):owner.run_until('ingestion')
        actual=native.find(row['name']);old=owner.record()
        self.assertEqual(old['nextStep'],12);self.assertEqual(len(old['effects']),13)
        stack=self.enterContext(ExitStack())
        for name,value in [('AUTHORITY',owner.action.authority_hash),('CONTAINERS',r.digest(old)),
            ('CREATED',actual['Id']),('NATIVE',r.digest(Engine.runtime_binding(actual)))]:stack.enter_context(patch.object(r,name,value))
        prepared={'cohortPlan':copy.deepcopy(owner.plan),'imagePlan':{'images':[{'module':'ingestion','audit':{
            'imageId':row['creationRequest']['Image'],'imageConfig':defaults}}]}}
        corrected=r.corrected_row(prepared)
        p=receipt();p['proposedIngestionPlanHash']=r.digest(corrected)
        proof={'profile':base.PROFILE,'retainedFailedIngestion':p}
        previous={'failedIngestionAttempt':{'receipt':p,'prepared':prepared,'containers':old}}
        raw=owner.journal.record.read_bytes()
        stack.enter_context(patch.object(base,'retained_bindings',side_effect=lambda _:
            self.assertEqual(owner.journal.record.read_bytes(),raw)))
        stack.enter_context(patch.object(base,'current_completed_containers'))
        plan=copy.deepcopy(owner.plan);plan['replacements'][2]=corrected
        authority=json.loads(crypto.authority);authority['applicationRegistryCutover']={'postGrantRecovery':proof}
        from tools.chatbot_file_cohort.containers import installation_scope
        authority['applicationCohortInstallation']=installation_scope(plan)
        crypto.authority=fixture.crypto.encoded(authority);crypto.approval['executionAuthorityHash']=fixture.crypto.sha(crypto.authority)
        crypto.write(crypto.mandate,fixture.crypto.encoded(crypto.approval));crypto.approved=fixture.crypto.sha(crypto.mandate.read_bytes())
        for role in crypto.grant['roles']:crypto.sign(role)
        action=AggregateAction(crypto.gate(),crypto.authority,crypto.expected['sourceClosureHash'])
        directory=crypto.root/'new-ingestion-path-journal';directory.mkdir(mode=0o700)
        successor=CohortContainers(action,native.engine,Journal(directory),plan,owner.clock)
        successor.initialize();successor.health=owner.health
        self.owner,self.native,self.row,self.actual=owner,native,row,actual
        self.successor,self.previous,self.proof,self.crypto=successor,previous,proof,crypto
        return stack

    def test_new_path_reprocessing_retires_failed_id_once_and_preserves_history(self):
        self.fixture();before=copy.deepcopy(self.native.calls);frozen=self.owner.journal.record.read_bytes()
        failed_id=self.actual['Id'];r.adopt_containers(self.successor,self.previous,self.proof)
        self.assertEqual([x[0]for x in self.native.calls[len(before):]],['rename'])
        for name,key in (('registry','registryModulePackageHash'),('database','databasePlanHash'),
            ('authorization','authorizationPlanHash'),('gateway','gatewayPlanHash')):
            self.successor.accept_owner_gate(name,self.successor.plan[key],r.digest({'current':name}))
        self.successor.run_until('ingestion')
        self.assertEqual([x[0]for x in self.native.calls[len(before):]],['rename','create','start','update'])
        self.assertNotEqual(self.native.find(self.row['name'])['Id'],failed_id)
        self.assertEqual(self.native.find(failed_id)['State']['Status'],'created')
        self.assertEqual(self.native.find(failed_id)['State']['ExitCode'],127)
        self.assertEqual(self.owner.journal.record.read_bytes(),frozen)
        calls=copy.deepcopy(self.native.calls);self.successor.run_until('ingestion');self.assertEqual(calls,self.native.calls)
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):r.adopt_containers(self.successor,self.previous,self.proof)

    def test_corrected_row_changes_only_path_and_prevents_future_bad_plans(self):
        self.fixture()
        from tools.chatbot_file_cohort.plan import validate_packaged_search_path
        prepared=self.previous['failedIngestionAttempt']['prepared']
        old=prepared['cohortPlan']['replacements'][2];new=r.corrected_row(prepared)
        image=prepared['imagePlan']['images'][0]['audit']['imageConfig']
        with self.assertRaisesRegex(Exception,'PACKAGED_JAVA_SEARCH_PATH'):
            validate_packaged_search_path(old['creationRequest'],image)
        validate_packaged_search_path(new['creationRequest'],image)
        before=copy.deepcopy(old);after=copy.deepcopy(new)
        for row in (before,after):
            row.pop('creationRequestHash');row.pop('environmentDelta')
            row['creationRequest']['Env']=[v for v in row['creationRequest']['Env']if not v.startswith('PATH=')]
        self.assertEqual(before,after)
        wrong=copy.deepcopy(prepared);wrong['imagePlan']['images'][0]['audit']['imageConfig']['Env']=['PATH=relative','JAVA_HOME=/opt/jre']
        with self.assertRaisesRegex(Exception,'EXACT_LEGACY_PATH'):r.corrected_row(wrong)

    def test_changed_path_plan_or_native_id_blocks_before_retirement(self):
        self.fixture();before=copy.deepcopy(self.native.calls)
        self.actual['Id']='f'*64
        with self.assertRaisesRegex(Exception,'EXACT_FAILED'):r.adopt_containers(self.successor,self.previous,self.proof)
        self.assertEqual(before,self.native.calls)

    def test_lost_retirement_ack_retains_claim_without_automatic_retry(self):
        self.fixture();self.native.lose_ack='rename';before=copy.deepcopy(self.native.calls)
        with self.assertRaises(Exception):r.adopt_containers(self.successor,self.previous,self.proof)
        self.assertEqual(self.successor.record()['failedIngestionRetirement']['state'],'CLAIMED')
        calls=copy.deepcopy(self.native.calls)
        with self.assertRaises(Exception):r.adopt_containers(self.successor,self.previous,self.proof)
        self.assertEqual(calls,self.native.calls)
        self.assertEqual([x[0]for x in calls[len(before):]],['rename'])

    def test_revocation_blocks_retirement_and_changed_other_configuration_is_denied(self):
        self.fixture();before=copy.deepcopy(self.native.calls)
        self.crypto.approval['state']='REVOKED';self.crypto.write(self.crypto.mandate,fixture.crypto.encoded(self.crypto.approval))
        with self.assertRaises(Exception):r.adopt_containers(self.successor,self.previous,self.proof)
        self.assertEqual(before,self.native.calls)

    def test_typed_proof_binds_ten_grants_and_changed_intent_without_failed_start_replay(self):
        proof={'retainedFailedIngestion':receipt()};r.validate_proof(proof)
        for key,value in [('newCreateAllowed',False),('newGatewayWritesAllowed',True),('cancelledWorkerHash','0'*64)]:
            altered=copy.deepcopy(proof);altered['retainedFailedIngestion'][key]=value
            with self.assertRaises(Exception):base.claim_for(altered)
        self.assertEqual(base.claim_for(proof),r.CLAIM)

    def test_complete_private_attempt_enrichment_preserves_claims_and_old_history(self):
        self.fixture()
        from tools.chatbot_file_cohort import ingestion_recovery as gateway_retained,postgrant_recovery as original
        root=self.crypto.root/'latest';root.mkdir(mode=0o700)
        self.enterContext(patch.object(r,'CONTEXT','latest'));self.enterContext(patch.object(r.evidence,'PARENT',self.crypto.root))
        def write(path,value):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(r.evidence.encoded(value));path.chmod(0o600)
            return r.digest(value)
        first={'operation':'a'*64,'scopeHash':'b'*64};self.enterContext(patch.object(original,'FIRST_HASH',r.digest(first)))
        parent_worker={'syntheticEightGrantWorker':True};parent_session={'syntheticSixPredecessorSession':True}
        self.enterContext(patch.object(gateway_retained,'WORKER',r.digest(parent_worker)))
        self.enterContext(patch.object(gateway_retained,'SESSION',r.digest(parent_session)))
        old_receipt={'syntheticCompletedRuntimeReceipt':True};proof={'profile':base.PROFILE,'retainedCreatedIngestion':old_receipt}
        gateway={'changes':[{'id':str(i)}for i in range(28)],'proposedRoutes':{'retained':{'id':'retained'}}}
        plan=copy.deepcopy(self.owner.plan);plan['gatewayPlanHash']=r.digest(gateway)
        p={'postGrantRecovery':proof,'cohortPlan':plan,'databasePlan':{'retained':True},
            'postGrantWorkerDirectory':str(root/'worker'),'authorization':{'plan':{}},
            'imagePlan':self.previous['failedIngestionAttempt']['prepared']['imagePlan'],
            'gatewayPlan':gateway,'gatewayRuntimePlan':{},'registry':{'directoryPlan':{'transition':str(root/'transition')}}}
        declaration={'sourceCommit':r.SOURCE};bundle={'declaration':declaration,'prepared':p}
        bh=write(root/'bundle.json',bundle)
        dirs={n:str(root/n)for n in ('containers','gateway','databases','authorization','gatewayRuntime')}
        process={'authorityDirectory':str(root),'bundle':{'path':str(root/'bundle.json'),'sha256':bh},'directoryPlan':dirs}
        session={'schema':'ouf.policy-token-new-finite-worker-session.v9','predecessorGrantAttempts':9,
            'predecessorFirstGrantOperation':first['operation'],'predecessorFirstGrantScopeHash':first['scopeHash']}
        scopes={'finiteActionProcess':process,'applicationRegistryCutover':{'postGrantRecovery':proof},
            'policyTokenOwnerInstallation':{'journalPath':str(root/'worker')},'policyTokenFiniteWorkerSession':session}
        authority={**scopes,'expiresAt':2000000000};ah=write(root/'authority.json',authority)
        review={'sourceClosure':{'declaration':declaration,'executables':{'systemctl':{}}},'sourceClosureHash':'c'*64,
            'scopes':scopes,'privateInputHashes':{'preparedInputs':r.digest(p)}};rh=write(root/'review.json',review)
        write(root/'decision.json',{'state':'ACTIVE','approvedReviewHash':rh,'approvedSourceClosureHash':'c'*64,'expiresAt':2000000000})
        status={'authorityHash':ah,'phase':'PAUSED_REQUIRES_RECONCILIATION','reason':'COHORT_START_REQUIRES_RECONCILIATION'}
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
        worker={'state':'CANCELLED','attempts':1,'publicationCount':1,'controlledPredecessorGrantAttempts':9,
            'controlledCumulativeGrantAttempts':10,'workerSessionHash':r.digest(session),'firstGrantReceiptHash':r.digest(first)}
        wh=write(root/'worker/recovery.json',worker);ss=write(root/'worker/owner-session.json',session)
        admission={'state':'BLOCKED','version':3};ad=write(root/'worker/owner-admission.json',admission)
        write(root/'worker/owner-first-grant.json',first);write(root/'worker/owner-predecessor-worker.json',parent_worker)
        write(root/'worker/owner-predecessor-session.json',parent_session)
        write(self.crypto.root/gateway_retained.CLAIM,{'authorityHash':ah,'proofHash':r.digest(proof),
            'state':'CONTINUATION_RESERVED_NO_AUTOMATIC_REPLAY','priorControlledGrantAttempts':9})
        for name,value in [('AUTHORITY',ah),('REVIEW',rh),('STATUS',sh),('CONTAINERS',ch),('GATEWAY',gh),
            ('DATABASE',dh),('WORKER',wh),('SESSION',ss),('ADMISSION',ad),('ROUTES',r.digest(gateway['proposedRoutes']))]:
            self.enterContext(patch.object(r,name,value))
        self.enterContext(patch.object(base,'verify_successor_transition'))
        self.enterContext(patch.object(original,'stopped_process'))
        self.enterContext(patch.object(base,'retained_bindings'))
        previous={'recordBindings':[],'firstGrant':first,'worker':parent_worker,'session':parent_session,
            'prepared':{'cohortPlan':plan,'databasePlan':p['databasePlan']},'databaseJournal':db,
            'containerJournal':{'effects':row['effects'][:10]},'ingestionAttempt':{'receipt':old_receipt},'retainedGatewayAttempt':{'receipt':old_receipt,
                'prepared':{'gatewayPlan':gateway,'gatewayRuntimePlan':{}},'journal':{'effects':effects}}}
        before=copy.deepcopy(previous);result=r.enrich(previous)
        self.assertEqual(previous,before);self.assertEqual(result['worker'],worker)
        self.assertEqual(result['prepared'],previous['prepared']);r.validate_proof({'retainedFailedIngestion':result['failedIngestionAttempt']['receipt']})
        for binding in result['recordBindings']:
            from tools.chatbot_file_cohort.action_process import private_file
            private_file(binding,8388608)
        write(root/'authorization/recovery.json',{**auth,'effects':{'unexpected':{}}})
        with self.assertRaisesRegex(Exception,'COMPLETED_READONLY_AUTHORIZATION'):r.enrich(previous)

if __name__=='__main__':unittest.main()
