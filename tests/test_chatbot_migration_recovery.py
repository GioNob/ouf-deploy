"""Signed phase-2 owner and durable archive/start checkpoints; synthetic effects."""
import copy,hashlib,json,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_databases as df
import test_chatbot_cohort_backup_recovery as backup
import test_mcp_migration_readback as readback
from tools.chatbot_file_cohort import migration_recovery as m,migration_native as n
from tools.chatbot_file_cohort.plan import digest
from tools.chatbot_file_cohort import postgrant_recovery as root
from tools.chatbot_file_cohort.review import REQUIRED_SCOPES
from cutover_authority import CutoverAuthority
from cutover_executor import Executor
from transition_journal import Transition
from file_only_profile import PHASES
from tools.chatbot_file_cohort.containers import installation_scope
from tools.semantic_policy_token_owner.owner_installation import AggregateAction

class NativeContract(unittest.TestCase):
    def setUp(self):
        p,self.name,self.request,self.actual,self.image=readback.fixture()
        self.actual['Config']['Env']+=self.image['Config']['Env']
        self.actual['Config']['Labels'].update(self.image['Config']['Labels'])
        self.actual['HostConfig']['OomKillDisable']=False
        self.assertEqual(n.request_for(p['cohortPlan']),(self.name,self.request))
    def test_exact_image_merge_and_never_started(self):
        n.native_matches(self.name,self.request,self.image['Config'],self.actual);n.created(self.actual)
        self.assertEqual(len(n.env(self.actual['Config']['Env'])),2)
    def test_unexplained_environment_label_command_network_or_privilege_denied(self):
        for field,value in [('Env',self.actual['Config']['Env']+['EXTRA=x']),('Labels',{}),('Cmd',['serve']),('User','0')]:
            bad=copy.deepcopy(self.actual);bad['Config'][field]=value
            with self.subTest(field=field),self.assertRaises(Exception):n.native_matches(self.name,self.request,self.image['Config'],bad)
        for field,value in [('Privileged',True),('ReadonlyRootfs',False),('RestartPolicy',{'Name':'always'})]:
            bad=copy.deepcopy(self.actual);bad['HostConfig'][field]=value
            with self.subTest(field=field),self.assertRaises(Exception):n.native_matches(self.name,self.request,self.image['Config'],bad)
    def test_duplicate_environment_and_other_native_fields_do_not_hide(self):
        with self.assertRaises(Exception):n.env(['A=x','A=y'])
        pin=n.immutable_native(self.actual);bad=copy.deepcopy(self.actual);bad['HostConfig']['CapAdd']=['SYS_ADMIN']
        self.assertNotEqual(n.immutable_native(bad),pin)
        for value in (True,0,1,'false'):
            bad=copy.deepcopy(self.actual);bad['HostConfig']['OomKillDisable']=value
            if value is True:self.assertNotEqual(n.immutable_native(bad),pin)
            else:
                with self.assertRaises(Exception):n.immutable_native(bad)
        bad=copy.deepcopy(self.actual);bad['HostConfig']['OomKillDisable']=None
        self.assertEqual(n.immutable_native(bad),pin)
    def test_prior_start_or_dead_state_cannot_be_created(self):
        for field,value in [('StartedAt','2026-10-16'),('Running',True),('Pid',1),('Dead',True),('Restarting',True)]:
            bad=copy.deepcopy(self.actual);bad['State'][field]=value
            with self.subTest(field=field),self.assertRaises(Exception):n.created(bad)

class CompleteArchiveAdoption(unittest.TestCase):
    def setUp(self):
        h=df.DatabaseRuntime();self.addCleanup(h.doCleanups)
        self.owner,self.native,self.f,self.observed,self.expected,self.log=h.fixture(mcp_pending=True,backup_reader=True)
        self.oldroot=self.f.root/'four-retained';self.oldroot.mkdir(mode=0o700)
        old=copy.deepcopy(self.owner.record());old['backups']={}
        name,req=n.request_for(self.owner.installation_plan)
        old['mcpMigration']={'state':'CLAIMED','name':name,'intentHash':digest(req)}
        old['mcpAuditRole']={'state':'BOOTSTRAPPED'}
        archives={}
        for row in self.owner.plan['modules']:
            record=self.owner.capture(row);path=self.owner.root/(row['module']+'.dump');data=path.read_bytes();path.unlink()
            target=self.oldroot/path.name;target.write_bytes(data);target.chmod(0o600)
            old['backups'][row['module']]=record;archives[row['module']]=(len(data),hashlib.sha256(data).hexdigest())
        self.previous={'databaseJournal':old,'prepared':{'databasePlan':self.owner.plan},'backupRoot':str(self.oldroot)}
        self.proof={'profile':m.PROFILE,'originalDatabasePlanHash':self.owner.plan_hash,'retainedCohortBackupDirectory':str(self.oldroot)}
        for key,value in [('AUTHORITY',old['authorityHash']),('DATABASE_HASH',digest(old)),('ARCHIVES',archives),('MIGRATION_INTENT',digest(req))]:
            override=patch.object(m,key,value);override.start();self.addCleanup(override.stop)
        def retained(proof):
            for module in archives:m.archive_bytes(proof['retainedCohortBackupDirectory'],module)
        override=patch.object(m,'retained_bindings',side_effect=retained);override.start();self.addCleanup(override.stop)
        authority=json.loads(self.f.authority);authority['applicationRegistryCutover']={'postGrantRecovery':self.proof}
        self.f.authority=df.crypto.encoded(authority);self.f.approval['executionAuthorityHash']=df.crypto.sha(self.f.authority)
        self.f.write(self.f.mandate,df.crypto.encoded(self.f.approval));self.f.approved=df.crypto.sha(self.f.mandate.read_bytes())
        for role in self.f.grant['roles']:self.f.sign(role)
        action=AggregateAction(self.f.gate(),self.f.authority,self.f.expected['sourceClosureHash']);self.owner.action=action
        initial=self.owner.journal.read();following={**initial,'authorityHash':action.authority_hash}
        self.owner.journal.compare_and_save(initial,following)
        self.preserved={p:p.read_bytes() for p in self.oldroot.iterdir()};self.before=self.log.read_text().count('dump')
    def unchanged(self):
        for p,raw in self.preserved.items():self.assertEqual(p.read_bytes(),raw)
        self.assertEqual(self.log.read_text().count('dump'),self.before)
    def test_four_copies_no_dump_and_exact_claim_and_bootstrap_preserved(self):
        m.adopt_backups(self.owner,self.previous,self.proof)
        self.owner.backup_quiesced();self.owner.backup_quiesced()
        self.assertEqual(self.owner.record()['backups'],self.previous['databaseJournal']['backups'])
        self.assertEqual(self.owner.record()['mcpMigration'],self.previous['databaseJournal']['mcpMigration'])
        self.assertEqual(self.owner.record()['mcpAuditRole'],self.previous['databaseJournal']['mcpAuditRole']);self.unchanged()
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):m.adopt_backups(self.owner,self.previous,self.proof)
    def test_interrupted_copy_is_not_resumed_or_overwritten(self):
        real=m.archive_bytes
        def fail(root,module,consume=None):
            if module=='mcp' and consume:raise OSError('fixture interrupted copy')
            return real(root,module,consume)
        with patch.object(m,'archive_bytes',side_effect=fail),self.assertRaises(OSError):m.adopt_backups(self.owner,self.previous,self.proof)
        for op in (self.owner.backup_quiesced,lambda:m.adopt_backups(self.owner,self.previous,self.proof)):
            with self.assertRaisesRegex(Exception,'PARTIAL_MIGRATION_ADOPTION'):op()
        self.unchanged()
    def test_revoked_approval_prevents_copy(self):
        self.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):m.adopt_backups(self.owner,self.previous,self.proof)
        self.assertEqual(list(self.owner.root.iterdir()),[]);self.unchanged()
    def test_start_once_and_ambiguous_effect_cannot_be_replayed(self):
        m.adopt_backups(self.owner,self.previous,self.proof)
        _,name,req,a,i=readback.fixture();self.proof.update(originalDatabasePlanHash=self.owner.plan_hash)
        a['Id']=m.MIGRATION_ID
        from engine_creation import Engine
        override=patch.object(m,'MIGRATION_RUNTIME',digest(Engine.runtime_binding(a)));override.start();self.addCleanup(override.stop)
        request=self.native.engine.request;starts=[]
        def effect(method,path,body=None):
            if method=='GET' and path=='/v1.44/containers/'+m.MIGRATION_ID+'/json':return 200,a
            if method=='POST' and path.endswith('/start'):
                starts.append(path);return 500,{}
            return request(method,path,body)
        # Current authority and immutable scope use the real signed fixture;
        # native image checking has separate positive/negative/native-Docker tests.
        with patch.object(m,'native',return_value=a),patch.object(self.native.engine,'request',side_effect=effect):
            with self.assertRaisesRegex(Exception,'START_REQUIRES_RECONCILIATION'):
                m.start_existing(self.owner,req,name,a,lambda:self.owner.plan['modules'][-1]['beforeMigrations'])
            with self.assertRaisesRegex(Exception,'CONSUMED_RECONCILE_NO_REPLAY'):
                m.start_existing(self.owner,req,name,a,lambda:self.owner.plan['modules'][-1]['beforeMigrations'])
        self.assertEqual(len(starts),1);self.assertEqual(self.owner.record()['governedMigrationRecovery']['startAttempts'],1);self.unchanged()

class RegistryMigrationSuccessor(unittest.TestCase):
    def setUp(self):
        h=backup.VerifiedRegistrySuccessor();self.addCleanup(h.doCleanups);h.setUp();self.h=h;self.f=h.f;self.profile=h.profile
        old=h.successor();self.old=old;self.row=old.t.read();self.assertEqual(self.row['version'],30)
        self.preserved={**h.preserved,str(old.t.journal.record):old.t.journal.record.read_bytes()}
        for name,value in (('AUTHORITY',old.authority_hash),('TRANSITION_HASH',digest(self.row))):
            override=patch.object(m,name,value);override.start();self.addCleanup(override.stop)
        self.prepared={'postGrantRecovery':h.proof,'registry':{'creationRequest':self.profile.request,'intents':h.intents}}
        m.validate_boundary(self.row,self.prepared)
        self.proof={'profile':m.PROFILE,'predecessorAuthorityHash':root.AUTHORITY,'migrationPredecessorAuthorityHash':m.AUTHORITY,
            'predecessorTransitionHash':digest(self.row),'transitionContextHash':self.row['contextHash'],
            'appliedPrefixHash':digest(self.row['effects']),'recordBindings':[]}
        self.intents=copy.deepcopy(h.intents)
        self.intents['ATTEST_NEW_OCI_PEER']={'unusedNewSourceRecipe':True}
        self.intents['RELEASE_PRODUCERS']={'newCohortPlan':True}
        self.scope={'postGrantRecovery':self.proof,'creationRequestHash':self.row['creationRequestHash'],
            'executionProfileHash':self.profile.sha256,'sourceClosureHash':'5'*64,
            'phaseIntentHashes':{k:digest(v) for k,v in self.intents.items()}}
        authority=json.loads(self.f.authority);authority.update(sourceClosureHash='5'*64,phaseIntentHashes=self.scope['phaseIntentHashes'])
        authority.update({key:{'fixtureScope':key} for key in REQUIRED_SCOPES});authority['applicationRegistryCutover']=self.scope
        self.f.expected['sourceClosureHash']='5'*64;self.f.authority=df.crypto.encoded(authority)
        self.f.approval.update(sourceClosureHash='5'*64,executionAuthorityHash=digest(authority),approvalRef='EXACT_VERIFIED_REGISTRY_BACKUP_RECOVERY')
        self.f.write(self.f.mandate,df.crypto.encoded(self.f.approval));self.f.approved=hashlib.sha256(self.f.mandate.read_bytes()).hexdigest()
        for role in self.f.grant['roles']:self.f.sign(role)
        gate=CutoverAuthority(self.f.verifier,self.f.binding(self.f.mandate),self.f.approved,self.f.context,self.f.expected,self.f.clock,execution_profile=self.profile)
        self.action=AggregateAction(gate,self.f.authority,'5'*64)
        self.paths={name:str(self.f.root/('migration-successor-'+name)) for name in ('transition','evidence','before','retirementBefore')}
        for path in self.paths.values():Path(path).mkdir(mode=0o700)
        self.previous={'transition':self.row,'prepared':self.prepared,'payloads':h.previous['payloads']}
        self.calls=[]
    def successor(self):
        with patch.object(m,'retained_bindings'):
            journal=m.seed_registry(self.previous,self.paths,self.action,self.scope)
        t=Transition(journal,self.old.t.context,execution_profile=self.profile)
        def checkpoint(phase,point,row):
            return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,'journalVersion':row['version'],
                'intentHash':digest(self.intents[phase]),'authorityHash':self.action.authority_hash,'sourceClosureHash':self.action.closure,'nativeEvidenceHash':'f'*64}
        adapters={p:SimpleNamespace(apply=lambda _,p=p:self.calls.append(p),observe=lambda _:('APPLIED',{'syntheticEffect':True})) for p in PHASES}
        return Executor(t,self.action.raw,self.action.authority,checkpoint,adapters,self.intents,self.f.clock,aggregate_action=self.action,aggregate_scope=self.scope)
    def unchanged(self):
        for path,data in self.preserved.items():self.assertEqual(Path(path).read_bytes(),data)
    def test_ten_effects_unchanged_only_final_release_can_run(self):
        new=self.successor();new.run(10);self.assertEqual(self.calls,[])
        new.run();self.assertEqual(self.calls,['RELEASE_PRODUCERS'])
        self.assertEqual(new.t.read()['effects'][:10],self.row['effects'])
        new.run();self.assertEqual(self.calls,['RELEASE_PRODUCERS']);self.unchanged()
    def test_changed_historical_effect_flags_marker_and_authority_are_denied(self):
        new=self.successor();seed=new.t.read()
        for change in ('effect','db','writes','marker','authority','cursor'):
            row=copy.deepcopy(seed)
            if change=='effect':row['effects'][9]['nativeEvidenceHash']='f'*64
            if change=='db':row['databaseMayHaveChanged']=False
            if change=='writes':row['applicationWritesMayHaveOccurred']=False
            if change=='marker':row['governedCreatedMigrationContinuation']['proofHash']='f'*64
            if change=='authority':row['governedCreatedMigrationContinuation']['newAuthorityHash']='f'*64
            if change=='cursor':row['nextPhase']=6
            with self.subTest(change=change),self.assertRaises(Exception):m.verify_successor_transition(row,self.scope,self.action.authority_hash)
        self.unchanged()
    def test_duplicate_publication_and_revocation_do_not_replay(self):
        new=self.successor();before=new.t.journal.record.read_bytes()
        with self.assertRaises(Exception):self.successor()
        self.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):new.run()
        self.assertEqual(self.calls,[]);self.assertEqual(new.t.journal.record.read_bytes(),before);self.unchanged()
    def test_changed_consumed_database_intent_is_denied_before_seed(self):
        self.scope['phaseIntentHashes']['ADMIT_MIGRATION']='f'*64
        with self.assertRaises(Exception):self.successor()
        self.assertEqual(list(Path(self.paths['transition']).iterdir()),[]);self.unchanged()


if __name__=='__main__':unittest.main()
