"""Real journal/CAS and pure successor contracts, with explicit native Ports fixtures.

This suite does not qualify target process observation, cryptographic issuance,
Engine transport, IAM or the new runtime installer.
"""
import copy,json,tempfile,unittest,sys
from pathlib import Path
from tools.semantic_registry_recovery_execution import core as c,resumption as r
from tools.semantic_registry_recovery_composition.compose import candidate_contract,GATES
from tools.semantic_registry_postboot_owner import contract as oc
from tools.semantic_registry_postboot_owner.tests.fixture import make_context

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'tools'/name) for name in ('semantic_application_cutover','semantic_database_cutover','semantic_frame_compiler','semantic_cohort_admission/cohort-draft','semantic_policy_token_owner')]

class Ports(c.Ports):
    def __init__(self,store,pin):self.store=store;self.pin=pin;self.calls=[];self.paused=False;self.unknown=True
    def guard(self,plan,row,stage):pass
    def apply(self,plan,row,stage):
        self.calls.append(stage['name'])
        if stage['name'] in ('START_NEW_WAIT_GATE','PAUSE_NEW_WAIT_GATE'):
            effects=copy.deepcopy(row['effects']);effects[-1].update(nativeRequestAttempted=True,nativeResponse204=True)
            if stage['name']=='START_NEW_WAIT_GATE':effects[-1]['nativeFirstProcess']=self.proof(False)
            self.store.cas(row,{**row,'effects':effects,'version':row['version']+1})
        if stage['name']=='PAUSE_NEW_WAIT_GATE':self.paused=True
    def proof(self,paused=True):
        return {'newGeneration':self.pin,'processKind':'GATE_WAITING','paused':paused,'startedAt':'FIXTURE_START',
                'durableNativeStartEvidence':True}
    def observe(self,plan,row,stage):
        if stage['name']=='VERIFY_PAUSED_OCI_AND_MOUNTS' and self.unknown:return 'UNKNOWN',{}
        proof=self.proof(self.paused)
        if stage['name']=='VERIFY_FINAL':proof.update(originalSemanticGetSucceeded=True,httpStatus=200)
        return 'APPLIED',proof


def fixture(root):
    plan=candidate_contract({'registry':{'containerId':'a'*64},'requiredGates':list(GATES),'unresolvedGateCount':8},'b'*64,'c'*64)
    pin={'containerId':'a'*64,'bootId':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','pid':4242,'startTicks':100,'namespaceDevice':4,'namespaceInode':12}
    execution=root/('semantic-registry-recovery-'+plan['logicalOperationRef']);execution.mkdir(mode=0o700)
    store=c.Store(execution,plan['logicalOperationRef'])
    row=c.initial(plan,authority_hash='d'*64,expires_unix=1000,expires_monotonic=950,boot_id=pin['bootId'],
        predecessor_history_hash='e'*64,created_unix=100,created_monotonic=50)
    store.initialize(row);ports=Ports(store,pin);runner=c.Runner(plan,store,ports,boot_id=pin['bootId'],clock=lambda:(100,50))
    for _ in range(5):runner.step()
    old=store.read();reads={'schema':'ouf.semantic-registry-recovery-native-read-journal.v1','authorityHash':old['authorityHash'],
        'scopeHash':c.digest(__import__('tools.semantic_registry_recovery_execution.read_budget',fromlist=['read_scope']).read_scope(plan,str(execution))),'counts':{'databaseSessions':1,'gatewayAdminGets':6,'semanticGets':0},'version':7,'budgetReset':False}
    output=root/'output';output.mkdir(mode=0o750);secret=root/'disposable-secret';secret.write_text('DISPOSABLE');secret.chmod(0o400)
    binding={'endpoint':'https://fixture.invalid/token','client_id':'fixture','scope':'policy:read','output_directory':str(output),
        'output_member':'token.jwt','output_gid':10001,'minimum_remaining':90,'maximum_token_seconds':3600}
    original=make_context(root/'metadata',binding,{},'a'*64,secret,
        {'planHash':c.digest(plan),'logicalOperationRef':plan['logicalOperationRef'],'registryId':pin['containerId'],'bootId':pin['bootId']},
        'e'*64,source_paths={name:Path(oc.__file__) for name in oc.SOURCE_FILES})
    prior=oc.compile_scope(original)
    witness={'schema':'ouf.semantic-registry-postboot-gate-witness.v1','checkpoint':4,'paused':True,'processKind':'GATE_WAITING',
        'recoveryPlanHash':c.digest(plan),'recoveryLogicalOperationRef':plan['logicalOperationRef'],'runtimeGeneration':pin}
    owner=oc.initial_record(original,witness,100,50)
    owner.update(state='CANCELLED',reason='CANCELLED_BY_OWNER',attempts=1,controlledCumulativeGrantAttempts=320)
    records={'owner-session.json':prior,'owner-first-grant.json':copy.deepcopy(original['retainedRecords']['owner-first-grant.json']),
        'owner-admission.json':{'state':'BLOCKED','contextRef':prior['contextRef'],'generationRef':prior['generationRef']}}
    maintenance={'status':'JVM_RESIDUE_REMOVED_ORIGINAL_SEAL_RESTORED','complete':True,'originalIndependentRootfsSealMatches':True,
        'expectedRootfsSealUnchanged':True,'samePausedGenerationBeforeAndAfter':True,'directoryRemovalAttempts':6,
        'directoryRemovalsConfirmed':6,'retainedControlledGrantAttempts':320,'javaReleased':False}
    inputs={'schema':'ouf.semantic-registry-resumption-inputs.v1','newGrantAllowance':0,'retainedControlledGrantAttempts':320,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'retainedNativeJournal':old,'retainedNativeReads':reads,
        'retainedOwnerJournal':owner,'retainedOwnerRecords':records,'retainedFence':prior['fenceBinding'],'maintenanceResult':maintenance,
        'identity':{'nativeJournalHash':c.digest(old),'ownerJournalHash':c.digest(owner),'maintenanceResultHash':c.digest(maintenance),
            'priorAuthorityHash':old['authorityHash'],'bootId':pin['bootId']}}
    context=copy.deepcopy(original);context.update(schema='ouf.semantic-registry-postboot-successor-owner-context.v1',
        predecessorContext=original,resumptionInputs=inputs,resumptionBinding={'path':str(root/'inputs.json'),'sha256':c.digest(inputs)},
        predecessorJournalPath=prior['journalPath'],retainedRecords={**records,'recovery.json':owner},sourceClosureHash='f'*64)
    return plan,store,ports,old,reads,context


class Resumption(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(temporary.cleanup);self.root=Path(temporary.name)
        self.plan,self.store,self.ports,self.old,self.reads,self.owner=fixture(self.root)
        self.scope=r.scope(self.plan,self.owner)
    def epoch(self):
        return r.proposed_epoch(self.plan,self.old,self.reads,self.scope,'f'*64,2000,2900,2000,1950)

    def test_real_runner_continues_claimed_read_without_start_pause_replay_or_history_rewrite(self):
        with self.assertRaisesRegex(c.RecoveryDenied,'CURRENT_FINITE_RECOVERY_SCOPE_REQUIRED'):
            c.validate_current(self.plan,self.old,self.old['bootId'],(2000,1950))
        before=copy.deepcopy(self.old);epoch,reads=self.epoch()
        self.assertEqual(epoch['effects'],before['effects']);self.assertEqual(reads['counts'],self.reads['counts'])
        self.assertEqual(reads['version'],self.reads['version']+1);self.assertEqual(epoch['readAttempts'],5)
        self.store.cas(self.old,epoch);self.ports.unknown=False
        runner=c.Runner(self.plan,self.store,self.ports,boot_id=epoch['bootId'],clock=lambda:(2000,1950))
        while runner.current()['nextStage']<12:runner.step()
        result=runner.current();self.assertTrue(result['originalSemanticGetSucceeded'])
        self.assertEqual(self.ports.calls.count('START_NEW_WAIT_GATE'),1);self.assertEqual(self.ports.calls.count('PAUSE_NEW_WAIT_GATE'),1)
        self.assertEqual(result['effects'][:4],before['effects'][:4]);self.assertEqual(result['resumption']['predecessorJournal'],before)
        self.assertEqual(result['effects'][4]['authorityHash'],before['authorityHash'])
        self.assertEqual(result['effects'][4]['completionAuthorityHash'],'f'*64)
        self.assertEqual(result['readAttempts'],13);self.assertEqual(result['version']>before['version'],True)
    def test_historical_prefix_or_claim_generation_or_counter_change_is_refused(self):
        epoch,_=self.epoch()
        for change in ('prefix','claim','generation','reads','predecessor'):
            row=copy.deepcopy(epoch)
            if change=='prefix':row['effects'][1]['nativeEvidence']['paused']=True
            if change=='claim':row['effects'][4]['authorityHash']='f'*64
            if change=='generation':row['newGeneration']['pid']+=1
            if change=='reads':row['readAttempts']=0
            if change=='predecessor':row['resumption']['predecessorNativeReads']['counts']['databaseSessions']=0
            with self.subTest(change=change),self.assertRaises(c.RecoveryDenied):c.validate_current(self.plan,row,row['bootId'],(2000,1950))
    def test_owner_new_session_preserves_first_grant_320_and_fence_lineage(self):
        before=copy.deepcopy(self.owner);scope=oc.compile_scope(self.owner)
        self.assertEqual(scope['predecessorGrantAttempts'],320);self.assertEqual(scope['maximumCumulativeGrantAttempts'],321)
        self.assertNotEqual(scope['journalPath'],self.owner['predecessorJournalPath'])
        self.assertEqual(scope['predecessorFenceBinding'],self.owner['resumptionInputs']['retainedFence'])
        self.assertEqual(scope['firstGrantReceiptHash'],oc.compile_scope(self.owner['predecessorContext'])['firstGrantReceiptHash'])
        self.assertFalse(scope['firstGrantReplayAllowed']);self.assertEqual(before,self.owner)
    def test_owner_cannot_hide_previous_attempt_change_boot_or_revive_active_session(self):
        for key,value in (('controlledCumulativeGrantAttempts',319),('attempts',0),('state','ACTIVE'),('bootId','wrong')):
            context=copy.deepcopy(self.owner);context['retainedRecords']['recovery.json'][key]=value
            context['resumptionInputs']['retainedOwnerJournal'][key]=value
            context['resumptionBinding']['sha256']=c.digest(context['resumptionInputs'])
            with self.subTest(key=key),self.assertRaises(oc.Denied):oc.compile_scope(context)
    def test_second_successor_and_changed_maintenance_are_refused(self):
        context=copy.deepcopy(self.owner);context['predecessorContext']=copy.deepcopy(self.owner)
        with self.assertRaises(oc.Denied):oc.compile_scope(context)
        context=copy.deepcopy(self.owner);context['resumptionInputs']['maintenanceResult']['originalIndependentRootfsSealMatches']=False
        context['resumptionBinding']['sha256']=c.digest(context['resumptionInputs'])
        with self.assertRaises(c.RecoveryDenied):r.scope(self.plan,context)
    def test_successor_window_is_fresh_finite_and_cannot_be_unsigned_epoch(self):
        for issued,expires,wall in ((2001,2900,2000),(2000,2000,2000),(2000,3000,2000)):
            with self.subTest(expires=expires),self.assertRaises(c.RecoveryDenied):
                r.proposed_epoch(self.plan,self.old,self.reads,self.scope,'f'*64,issued,expires,wall,1950)
        row=copy.deepcopy(self.old);row['resumption']={}
        with self.assertRaises(c.RecoveryDenied):c.validate_current(self.plan,row,row['bootId'],(100,50))


class Preparation(unittest.TestCase):
    def setUp(self):
        from tools.semantic_registry_recovery_execution import resumption_prepare as p
        from unittest.mock import patch
        self.p=p
        tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.plan,self.store,self.ports,self.old,self.reads,self.owner=fixture(self.root)
        self.original=self.owner['predecessorContext'];value=copy.deepcopy(self.owner['resumptionInputs'])
        oldprepared={'schema':'ouf.semantic-registry-postboot-prepared-inputs.v1',
            'nativeContext':{'plan':self.plan,'executionRoot':str(self.store.root),'nodeRecipe':{'sourceClosureHash':'e'*64}},
            'ownerContext':self.original,'registryInputs':{'fixture':True},'authorityInputs':{'fixture':True},'sourceClosure':{'fixture':True}}
        oldpath=self.root/'old-prepared.json';oldpath.write_bytes(c.encoded(oldprepared));oldpath.chmod(0o600)
        value['privatePreparedInputs']=str(oldpath)
        value['inputBindings']={str(oldpath):{'sha256':c.digest(oldprepared)},str(self.store.root/'recovery.json'):{'sha256':c.digest(self.old)},
                               str(self.root/'historical-user-capsule.py'):{'sha256':'a'*64}}
        snapshot=self.root/'snapshot.json';snapshot.write_bytes(c.encoded(value));snapshot.chmod(0o400)
        self.case={'schema':p.SCHEMA,'inputs':{'path':str(snapshot),'sha256':c.digest(value)},
            'historicalCapsule':{'path':str(self.root/'historical-user-capsule.py'),'sha256':'a'*64},'ownerBudget':self.original['budget']}
        self.sources={name:('# explicit test source '+name+'\n').encode() for name in oc.SOURCE_FILES}
        self.manifest={'sourceHashes':{name:__import__('hashlib').sha256(raw).hexdigest() for name,raw in self.sources.items()}}
        self.boot=self.root/'boot';self.boot.write_text(self.old['bootId']);real=Path
        for obj,key,value in ((p.p,'PARENT',str(self.root)),(p,'Path',lambda v:self.boot if v=='/proc/sys/kernel/random/boot_id' else real(v))):
            q=patch.object(obj,key,value);q.start();self.addCleanup(q.stop)
    def test_private_successor_preparation_readback_and_no_old_journal_write(self):
        before=self.store.read();result=self.p.prepare(self.case,self.manifest,self.sources)
        self.assertEqual(result['retainedControlledGrantAttempts'],320);self.assertEqual(result['engineGets'],0)
        self.assertFalse(result['runtimeAuthorityIssued']);self.assertEqual(before,self.store.read())
        prepared=self.p.read(self.case,self.manifest)
        self.assertEqual(oc.compile_scope(prepared['ownerContext'])['maximumCumulativeGrantAttempts'],321)
        self.assertEqual(prepared['nativeContext']['nodeRecipe']['sourceClosureHash'],c.digest(self.manifest))
        with self.assertRaises(FileExistsError):self.p.prepare(self.case,self.manifest,self.sources)
    def test_changed_native_journal_before_preparation_is_refused(self):
        self.store.cas(self.old,{**self.old,'version':self.old['version']+1})
        with self.assertRaisesRegex(c.RecoveryDenied,'RETAINED_PREPARATION_HASH_CHANGED'):
            self.p.prepare(self.case,self.manifest,self.sources)
        self.assertFalse(self.p.root(self.case,self.manifest).exists())

class Installer(unittest.TestCase):
    def setUp(self):
        from tools.semantic_registry_recovery_execution import resumption_install as m
        from unittest.mock import patch
        self.m=m;self.patch=patch
        tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.plan,self.store,self.ports,self.old,self.reads,self.owner=fixture(self.root)
        self.scope=r.scope(self.plan,self.owner);self.authority=object()
        self.raw=c.encoded({r.KEY:self.scope,'issuedAt':2000,'expiresAt':2900});self.h=__import__('hashlib').sha256(self.raw).hexdigest()
        self.context={'plan':self.plan,'executionRoot':str(self.store.root),'engineBinding':{'socketPath':str(self.root/'fixture.sock'),'socketBinding':[1,2]},'stoppedSnapshot':{'fixture':True}}
        self.ownerroot=Path(self.owner['predecessorJournalPath']);self.ownerroot.mkdir(mode=0o700)
        def write(path,value):path.write_bytes(c.encoded(value));path.chmod(0o600)
        write(self.store.root/'native-reads.json',self.reads)
        for name,value in self.owner['retainedRecords'].items():write(self.ownerroot/name,value)
        for name in ('invocation.lock','recovery.lock'):(self.ownerroot/name).write_bytes(b'');(self.ownerroot/name).chmod(0o600)
        fence=self.owner['resumptionInputs']['retainedFence'];write(Path(fence['path']),fence['value'])
        self.gets=0;self.changed=False;subject=self
        class FakeEngine:
            def __init__(self,*a):pass
        class FakeLifecycle:
            def __init__(self,*args):pass
            def inspect(self):subject.gets+=1;return {'fixture':True}
            def process_evidence(self,value):
                proof=subject.ports.proof(True)
                if subject.changed:proof['newGeneration']={**proof['newGeneration'],'pid':4243}
                return proof
            def runtime_binding(self,value):return {'fixture':'same'}
        class Scoped:
            hash=self.h
            def guard(inner,row=None):
                if row is not None:c.require(row['authorityHash']==subject.h,'FIXTURE_AUTHORITY_DRIFT')
        retained={'registryInputs':{'creationRequest':{'fixture':True}},'proposal':{'fixture':True}}
        for name,value in {'current_scope':lambda *a:(None,retained,Scoped()),'engine_type':lambda:FakeEngine,
            'Lifecycle':FakeLifecycle,'source_guard':lambda *a:None,'credential_custody':lambda *a:None}.items():
            q=patch.object(m,name,value);q.start();self.addCleanup(q.stop)
    def install(self):return self.m.install(self.context,self.owner,self.authority,self.raw,clock=lambda:(2000,1950))
    def test_actual_claim_counts_cas_predecessor_copy_and_receipt_without_lifecycle_effect(self):
        result=self.install();row=self.store.read();counts=self.m.read_counts(self.store.root)
        self.assertEqual(row['schema'],r.EPOCH);self.assertEqual(row['effects'],self.old['effects'])
        self.assertEqual(counts['counts'],self.reads['counts']);self.assertEqual(counts['version'],self.reads['version']+1)
        self.assertEqual(self.gets,2);self.assertEqual(result['lifecycleEffectsDispatched'],0)
        self.assertEqual(json.loads((self.ownerroot/'recovery.json').read_bytes()),self.owner['retainedRecords']['recovery.json'])
        self.assertTrue((self.store.root/'checkpoint-four-successor-installed.json').is_file())
        with self.assertRaises(c.RecoveryDenied):self.install()
        self.assertEqual(self.gets,2)
    def test_changed_pid_consumes_claim_without_new_epoch_or_retry(self):
        self.changed=True
        with self.assertRaisesRegex(c.RecoveryDenied,'SAME_DURABLY_PAUSED'):self.install()
        self.assertEqual(self.store.read(),self.old);self.assertEqual(self.m.read_counts(self.store.root),self.reads)
        self.changed=False
        with self.assertRaises(FileExistsError):self.install()
        self.assertEqual(self.gets,1)
    def test_crash_between_counter_and_epoch_writes_never_accepted_as_installation(self):
        original=self.m.replace_counts
        def crash(*args):original(*args);raise OSError('INJECTED_CRASH_AFTER_COUNTER_HANDOFF')
        with self.patch.object(self.m,'replace_counts',crash),self.assertRaises(OSError):self.install()
        self.assertEqual(self.store.read(),self.old);self.assertEqual(self.m.read_counts(self.store.root)['authorityHash'],self.h)
        self.assertFalse((self.store.root/'checkpoint-four-successor-installed.json').exists())
        with self.assertRaises(c.RecoveryDenied):self.install()
    def test_occupied_real_predecessor_invocation_lock_prevents_handoff_claim(self):
        from tools.semantic_lease_recovery.recovery_journal import Journal
        with Journal(self.ownerroot).invocation():
            with self.assertRaises(Exception):self.install()
        self.assertEqual(self.gets,0);self.assertEqual(self.store.read(),self.old)
        self.assertEqual(list(self.store.root.glob('checkpoint-four-successor-*.claim.json')),[])

if __name__=='__main__':unittest.main()
