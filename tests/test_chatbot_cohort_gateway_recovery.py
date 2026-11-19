"""Signed phase-5 adoption preserves completed Registry and DB effects."""
import copy,hashlib,json,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_migration_recovery as previous_phase
from test_chatbot_migration_recovery import df,root,REQUIRED_SCOPES,CutoverAuthority,Executor,Transition,PHASES,AggregateAction,digest
from tools.chatbot_file_cohort import gateway_recovery as m

class RegistryGatewaySuccessor(unittest.TestCase):
    def setUp(self):
        h=previous_phase.RegistryMigrationSuccessor();self.addCleanup(h.doCleanups);h.setUp();self.h=h;self.f=h.f;self.profile=h.profile
        old=h.successor();self.old=old;self.row=old.t.read();self.assertEqual(self.row['version'],31)
        self.preserved={**h.preserved,str(old.t.journal.record):old.t.journal.record.read_bytes()}
        for name,value in (('AUTHORITY',old.authority_hash),('TRANSITION_HASH',digest(self.row))):
            override=patch.object(m,name,value);override.start();self.addCleanup(override.stop)
        self.prepared={'postGrantRecovery':h.proof,'registry':{'creationRequest':self.profile.request,'intents':h.intents}}
        m.validate_boundary(self.row,self.prepared)
        self.proof={'profile':m.PROFILE,'predecessorAuthorityHash':root.AUTHORITY,'gatewayPredecessorAuthorityHash':m.AUTHORITY,
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
        self.paths={name:str(self.f.root/('gateway-successor-'+name)) for name in ('transition','evidence','before','retirementBefore')}
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
            if change=='marker':row['governedGatewayContinuation']['proofHash']='f'*64
            if change=='authority':row['governedGatewayContinuation']['newAuthorityHash']='f'*64
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




class CompleteDatabaseAdoption(unittest.TestCase):
    def fixture(self):
        h=previous_phase.CompleteArchiveAdoption();self.addCleanup(h.doCleanups);h.setUp()
        owner=h.owner;old=h.previous['databaseJournal'];binding=next(r for r in owner.plan['modules']if r['module']=='mcp')
        old['mcpMigration'].update(state='COMPLETE',containerId=m.prior.MIGRATION_ID,historyHash=digest(binding['expectedMigrations']))
        old['mcpAuditRole']['state']='CLEAN'
        proof={**h.proof,'profile':m.PROFILE}
        for name,value in [('DATABASE_HASH',digest(old)),('AUTHORITY',old['authorityHash']),('ARCHIVES',m.prior.ARCHIVES)]:
            override=patch.object(m,name,value);override.start();self.addCleanup(override.stop)
        def retained(proof):
            for module in m.ARCHIVES:m.prior.archive_bytes(proof['retainedCohortBackupDirectory'],module)
        override=patch.object(m,'retained_bindings',side_effect=retained);override.start();self.addCleanup(override.stop)
        f=h.f;raw=json.loads(f.authority);raw['applicationRegistryCutover']={'postGrantRecovery':proof}
        f.authority=df.crypto.encoded(raw);f.approval['executionAuthorityHash']=df.crypto.sha(f.authority)
        f.write(f.mandate,df.crypto.encoded(f.approval));f.approved=df.crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        owner.action=AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        initial=owner.journal.read();owner.journal.compare_and_save(initial,{**initial,'authorityHash':owner.action.authority_hash})
        return h,proof
    def test_complete_clean_migration_and_four_backups_adopt_without_effect(self):
        h,proof=self.fixture()
        with patch.object(h.owner,'capture',side_effect=AssertionError('new dump forbidden')):
            m.adopt_backups(h.owner,h.previous,proof)
            h.owner.backup_quiesced();h.owner.backup_quiesced()
        self.assertEqual(h.owner.record()['mcpMigration'],h.previous['databaseJournal']['mcpMigration'])
        self.assertEqual(h.owner.record()['mcpAuditRole']['state'],'CLEAN')
        self.assertFalse(h.owner.record()['governedGatewayRecovery']['migrationReplayAllowed'])
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):m.adopt_backups(h.owner,h.previous,proof)
        h.unchanged()
    def test_crashed_copy_blocks_every_resume_without_new_dump(self):
        h,proof=self.fixture();read=m.prior.archive_bytes
        def interrupt(root,module,consume=None):
            if module=='mcp' and consume is not None:raise OSError('synthetic crash')
            return read(root,module,consume)
        with patch.object(m.prior,'archive_bytes',side_effect=interrupt),self.assertRaises(OSError):
            m.adopt_backups(h.owner,h.previous,proof)
        for operation in (h.owner.backup_quiesced,lambda:m.adopt_backups(h.owner,h.previous,proof)):
            with self.assertRaisesRegex(Exception,'PARTIAL_GATEWAY_CHECKPOINT'):operation()
        h.unchanged()

class CompleteContainerAdoption(unittest.TestCase):
    def fixture(self):
        import test_chatbot_cohort_containers as fixtures
        from tools.chatbot_file_cohort import containers as c
        h=fixtures.CohortRuntime();self.addCleanup(h.doCleanups)
        old,native,f,now=h.fixture();old.run_until('onboarding')
        row=old.record();old.journal.compare_and_save(row,{**row,'version':30});row=old.record()
        self.preserved=old.journal.record.read_bytes();self.old=old
        for name,value in [('CONTAINERS_HASH',digest(row)),('AUTHORITY',old.action.authority_hash)]:
            override=patch.object(m,name,value);override.start();self.addCleanup(override.stop)
        proof={'profile':m.PROFILE,'syntheticRetainedHistory':True}
        plan=copy.deepcopy(old.plan);plan.update(gatewayPlanHash='b'*64,authorizationPlanHash='c'*64)
        signed=json.loads(f.authority);signed.update(applicationCohortInstallation=c.installation_scope(plan),
            applicationRegistryCutover={'postGrantRecovery':proof})
        f.authority=df.crypto.encoded(signed);f.approval['executionAuthorityHash']=df.crypto.sha(f.authority)
        f.write(f.mandate,df.crypto.encoded(f.approval));f.approved=df.crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        action=AggregateAction(f.gate(),f.authority,f.expected['sourceClosureHash'])
        directory=f.root/'gateway-adopted-containers';directory.mkdir(mode=0o700)
        owner=c.CohortContainers(action,native.engine,c.Journal(directory),plan,lambda:now[0]);owner.initialize()
        previous={'containerJournal':row,'prepared':{'cohortPlan':old.plan}}
        override=patch.object(m,'retained_bindings');override.start();self.addCleanup(override.stop)
        return owner,native,f,previous,proof
    def test_adoption_preserves_ten_effects_without_lifecycle_or_readiness_replay(self):
        owner,native,f,previous,proof=self.fixture();calls=copy.deepcopy(native.calls)
        m.adopt_containers(owner,previous,proof)
        adopted=owner.record()
        self.assertEqual(adopted['effects'],previous['containerJournal']['effects'])
        self.assertEqual(adopted['readiness'],previous['containerJournal']['readiness'])
        self.assertEqual(adopted['gates'],{})
        self.assertEqual(adopted['governedGatewayRecovery']['historicalGates'],previous['containerJournal']['gates'])
        for module in ('udp','onboarding'):owner.run_until(module)
        with self.assertRaisesRegex(Exception,'PRECEDING_COHORT_OWNER'):owner.run_until('ingestion')
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):m.adopt_containers(owner,previous,proof)
        self.assertEqual(native.calls,calls)
        self.assertEqual(self.old.journal.record.read_bytes(),self.preserved)
    def test_changed_native_generation_blocks_adoption(self):
        owner,native,f,previous,proof=self.fixture();calls=copy.deepcopy(native.calls)
        target=next(v for v in native.state.values()if v['Name']=='/ouf-udp')
        target['State']['Pid']+=1
        with self.assertRaises(Exception):m.adopt_containers(owner,previous,proof)
        self.assertEqual(owner.record()['nextStep'],0);self.assertEqual(native.calls,calls)
    def test_revocation_blocks_adoption(self):
        owner,native,f,previous,proof=self.fixture();calls=copy.deepcopy(native.calls)
        f.approval['state']='REVOKED';f.write(f.mandate,df.crypto.encoded(f.approval))
        with self.assertRaises(Exception):m.adopt_containers(owner,previous,proof)
        self.assertEqual(owner.journal.read()['nextStep'],0);self.assertEqual(native.calls,calls)

if __name__=='__main__':unittest.main()
