"""File-only profile: real durable journal/signatures, synthetic phase effects."""
import copy,hashlib,json,sys,tempfile,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover')]
import test_cutover_authority_native as crypto
import test_cutover_executor as old
import test_core_adapter_factory as factory_fixture
from file_only_profile import FileOnlyProfile,compile_profile,PROFILE,PHASES
from transition_journal import Transition,PHASES as OLD_PHASES,digest
from cutover_executor import Executor,CutoverDenied
from cutover_authority import CutoverAuthority,AuthorityDenied
from core_adapter_factory import configure_core,configure_owned_core,CORE

def inputs():
    db={'source':'/fixture/db','target':'/run/db','readOnly':True,'uid':10001,'gid':10001,
        'directoryMode':0o500,'fileName':'OUF_SEM_DB_PASSWORD','fileMode':0o400,'maxBytes':4096,'sha256':'b'*64}
    request={'Image':'sha256:'+'a'*64,'User':'10001:10001',
        'Entrypoint':['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar'],
        'Env':['OUF_SCHEMA_GOV_ENABLED=false','OUF_DISCOVERY_WORKER_ENABLED=false','SPRING_CONFIG_IMPORT=configtree:/run/db/'],
        'HostConfig':{'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'NetworkMode':'fixture-bridge',
            'Mounts':[{'Type':'bind','Source':'/fixture/db','Target':'/run/db','ReadOnly':True}]}}
    return request,db

class FileOnlyCutover(unittest.TestCase):
    def fixture(self,overrides=None):
        f=crypto.SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        request,db=inputs();profile=FileOnlyProfile(request,db)
        intents={p:{'syntheticFixturePhase':p} for p in PHASES};intents['CREATE_REPLACEMENT']=request
        if overrides:intents.update(overrides)
        f.expected['creationRequestHash']=digest(request)
        authority={'schema':'ouf.semantic-cutover-execution-authority.v2',
            **{k:v for k,v in f.expected.items() if k!='intakeHash'},'issuedAt':f.now,'expiresAt':f.now+120,
            'phaseIntentHashes':{p:digest(i) for p,i in intents.items()},'automaticReplayAllowed':False,
            'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False,'newDistinctLeaseWorkerRequired':False,
            'deploymentProfile':PROFILE,'executionProfileHash':profile.sha256}
        f.authority=crypto.encoded(authority)
        f.approval.update(schema='ouf.semantic-cutover-human-mandate.v2',**f.expected,
            executionAuthorityHash=crypto.sha(f.authority),deploymentProfile=PROFILE,executionProfileHash=profile.sha256)
        f.write(f.mandate,crypto.encoded(f.approval));f.approved=crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        gate=CutoverAuthority(f.verifier,f.binding(f.mandate),f.approved,f.context,f.expected,f.clock,execution_profile=profile)
        root=f.root/'journal';root.mkdir(mode=0o700);journal=old.j.Journal(root)
        row=Transition.initial_file_only(crypto.sha(f.authority),digest(request),f.expected['predecessorHistoryHash'],f.expected['predecessorIncidentRef'],profile)
        journal.initialize(row);t=Transition(journal,row['contextHash'],execution_profile=profile)
        calls=[];applied=set()
        def checkpoint(phase,point,row):
            return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,
                'journalVersion':row['version'],'intentHash':authority['phaseIntentHashes'][phase],
                'authorityHash':crypto.sha(f.authority),'sourceClosureHash':f.expected['sourceClosureHash'],'nativeEvidenceHash':'f'*64}
        def apply(p):calls.append(p);applied.add(p)
        adapters={p:types.SimpleNamespace(apply=lambda i,p=p:apply(p),
            observe=lambda i,p=p:('APPLIED' if p in applied else 'UNKNOWN',{'syntheticPhase':p})) for p in PHASES}
        executor=Executor(t,f.authority,gate,checkpoint,adapters,intents,f.clock)
        return f,profile,executor,calls

    def test_all_eleven_phases_have_real_dual_signature_gate_and_no_replay(self):
        f,p,e,calls=self.fixture();result=e.run()
        self.assertEqual(calls,list(PHASES));self.assertEqual(result['completedPhaseCount'],11)
        self.assertEqual(result['schema'],'ouf.semantic-cutover-executor-receipt.v2');self.assertEqual(result['executionProfileHash'],p.sha256)
        self.assertFalse(result['releaseAcceptance']);self.assertTrue(result['databaseMayHaveChanged'])
        self.assertNotIn('START_DISTINCT_LEASE_WORKER',calls);self.assertNotIn('INSTALL_AUTHENTICATED_TRANSPORT',calls)
        e.run();self.assertEqual(calls,list(PHASES))

    def test_each_effect_crash_reconciles_without_retransmission(self):
        for phase in PHASES:
            with self.subTest(phase=phase):
                f,p,e,calls=self.fixture();original=e.adapters[phase].apply
                def crash(i):original(i);raise RuntimeError('fixture crash after effect')
                e.adapters[phase].apply=crash
                with self.assertRaises(RuntimeError):e.run()
                self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
                e.t=Transition(old.j.Journal(e.t.journal.root),e.t.context,execution_profile=p)
                e.adapters[phase].apply=original;e.run();self.assertEqual(calls,list(PHASES))

    def test_ambiguous_effect_and_no_effect_remain_consumed(self):
        for outcome in ('UNKNOWN','NO_EFFECT'):
            f,p,e,calls=self.fixture();e.adapters[PHASES[0]].observe=lambda i:(outcome,{'synthetic':True})
            with self.assertRaises(CutoverDenied):e.run()
            with self.assertRaises(CutoverDenied):e.run()
            self.assertEqual(calls,[PHASES[0]])

    def test_both_flags_and_unoverridable_source_channels_required(self):
        cases=[lambda r,d:r['Env'].remove('OUF_SCHEMA_GOV_ENABLED=false'),
            lambda r,d:r['Env'].append('OUF_DISCOVERY_WORKER_ENABLED=true'),
            lambda r,d:r['Env'].append('JAVA_TOOL_OPTIONS=-Douf.semantic.discovery-worker.enabled=true'),
            lambda r,d:r['Env'].append('SPRING_APPLICATION_JSON={}'),
            lambda r,d:r['Env'].append('OUF_SEMANTIC_DISCOVERY_WORKER_ENABLED=true'),
            lambda r,d:r['Entrypoint'].append('--ouf.semantic.discovery-worker.enabled=true'),
            lambda r,d:d.update(fileName='application.properties'),
            lambda r,d:r['HostConfig']['Mounts'][0].update(ReadOnly=False)]
        for change in cases:
            r,d=inputs();change(r,d)
            with self.assertRaises(ValueError):compile_profile(r,d)

    def test_v1_journal_cannot_be_read_as_v2_and_v2_cannot_be_downgraded(self):
        f,p,e,calls=self.fixture()
        with self.assertRaisesRegex(ValueError,'PROFILE_SCHEMA'):Transition(e.t.journal,e.t.context).read()
        legacy=Transition.initial('a'*64,digest(p.request),'c'*64,'d'*64)
        directory=f.root/'legacy';directory.mkdir(mode=0o700);j=old.j.Journal(directory);j.initialize(legacy)
        with self.assertRaisesRegex(ValueError,'PROFILE_SCHEMA'):Transition(j,legacy['contextHash'],execution_profile=p).read()
        self.assertEqual(j.read(),legacy);self.assertEqual(calls,[])

    def test_missing_phase_extra_phase_and_arbitrary_skip_are_denied(self):
        for bad in ('ADMIT_MIGRATION','START_DISTINCT_LEASE_WORKER'):
            f,p,e,calls=self.fixture();adapters=dict(e.adapters);intents=dict(e.intents)
            if bad in adapters:del adapters[bad];del intents[bad]
            else:adapters[bad]=adapters[PHASES[0]];intents[bad]={}
            with self.assertRaises(CutoverDenied):Executor(e.t,e.raw,e.authenticate,e.checkpoint,adapters,intents,e.clock)
            self.assertEqual(calls,[])
        f,p,e,calls=self.fixture()
        with e.t.invocation():
            with self.assertRaisesRegex(ValueError,'PHASE_ORDER'):e.t.begin(PHASES[1],'a'*64,'b'*64,0)

    def test_legacy_human_mandate_and_legacy_signatures_cannot_authorize_v2(self):
        f,p,e,calls=self.fixture()
        with self.assertRaises(AuthorityDenied):f.gate()(f.authority)
        signature=f.signatures/(crypto.sha(f.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')
        raw=json.loads(signature.read_bytes());raw['signature']='0'*128;f.write(signature,crypto.encoded(raw))
        with self.assertRaises(crypto.PreexecDenied):e.run()
        self.assertEqual(calls,[])

    def test_profile_request_tampering_revocation_and_expiry_block_before_effects(self):
        for kind in ('profile','request','human','expiry'):
            f,p,e,calls=self.fixture()
            if kind=='profile':p.compiled['executionProfileHash']='0'*64
            if kind=='request':e.intents['CREATE_REPLACEMENT']['Image']='sha256:'+'0'*64
            if kind=='human':f.approval['state']='REVOKED';f.write(f.mandate,crypto.encoded(f.approval))
            if kind=='expiry':f.now+=181
            with self.assertRaises((ValueError,AuthorityDenied,CutoverDenied)):e.run()
            self.assertEqual(calls,[])

    def test_factory_builds_native_seven_with_exact_four_remaining_owners(self):
        base=factory_fixture.CoreFactory();request,intents,owners,_,admin,calls=base.fixture()
        launch,db=inputs();launch['HostConfig'].update(request['HostConfig']);request.update(launch)
        p=FileOnlyProfile(request,db);h=digest(request)
        intents={k:v for k,v in intents.items() if k in PHASES}
        intents['CREATE_REPLACEMENT']=request
        for phase in ('STAGE_PAUSED_REPLACEMENT','START_REPLACEMENT'):intents[phase]['creationRequestHash']=h
        owners={k:v for k,v in owners.items() if k in PHASES}
        d=tempfile.TemporaryDirectory();self.addCleanup(d.cleanup);Path(d.name).chmod(0o700);j=old.j.Journal(d.name)
        row=Transition.initial_file_only('a'*64,h,'c'*64,'d'*64,p);j.initialize(row)
        t=Transition(j,row['contextHash'],execution_profile=p)
        actual=configure_core(None,t,request,None,admin,intents,owners,lambda point:None,execution_profile=p)
        self.assertEqual(set(actual),set(PHASES));self.assertEqual(len(owners),4);self.assertEqual(calls,[])
        from r12_retirement_adapter import R12RetirementChannel,R12RetirementAdapter
        from native_evidence_store import NativeEvidenceStore
        channel=R12RetirementChannel.__new__(R12RetirementChannel)
        channel.scope={};channel.scope_hash=digest(channel.scope);channel.capture_history_hash='c'*64
        channel.capture={'r12-authorization.json':{'incidentRef':'d'*64}}
        intents['STOP_REVOKE_OLD_LEASE']={'scopeHash':channel.scope_hash,'stopTimeoutSeconds':10}
        before=Path(d.name)/'before';before.mkdir(mode=0o700);evidence=Path(d.name)/'evidence';evidence.mkdir(mode=0o700)
        remaining={k:v for k,v in owners.items() if k!='STOP_REVOKE_OLD_LEASE'}
        actual=configure_owned_core(None,t,request,NativeEvidenceStore(evidence),admin,intents,remaining,
            lambda point:None,channel,NativeEvidenceStore(before),execution_profile=p)
        self.assertEqual(len(remaining),3);self.assertIs(type(actual['STOP_REVOKE_OLD_LEASE']),R12RetirementAdapter)
        self.assertEqual(set(actual),set(PHASES));self.assertEqual(calls,[])
        channel.capture_history_hash='0'*64
        with self.assertRaisesRegex(ValueError,'PREDECESSOR_HISTORY'):
            configure_owned_core(None,t,request,NativeEvidenceStore(evidence),admin,intents,remaining,
                lambda point:None,channel,NativeEvidenceStore(before),execution_profile=p)
        with self.assertRaisesRegex(ValueError,'EXPLICIT_FILE_ONLY'):configure_core(None,t,request,None,admin,intents,owners,lambda point:None)
        owners['START_DISTINCT_LEASE_WORKER']=owners[PHASES[0]]
        with self.assertRaises(ValueError):configure_core(None,t,request,None,admin,intents,owners,lambda point:None,execution_profile=p)

    def test_native_migration_adapter_uses_signed_file_profile_prerequisites(self):
        from test_migration_admission_adapter import Admission
        from migration_admission_adapter import MigrationAdmissionAdapter
        from native_evidence_store import NativeEvidenceStore
        fixture=Admission();legacy,state,paused,writes=fixture.fixture();self.addCleanup(fixture.doCleanups)
        adapter=legacy.adapters['ADMIT_MIGRATION'];intent=adapter.intent
        f,p,e,calls=self.fixture({'ADMIT_MIGRATION':intent})
        directory=f.root/'native';directory.mkdir(mode=0o700);store=NativeEvidenceStore(directory)
        def observe(phase,record):
            store.publish(phase,record);return 'APPLIED',record
        backup={'schema':'ouf.semantic-fenced-backup-executor-evidence.v1','transitionContextHash':e.t.context,
            'databaseContainerId':intent['containerId'],'databaseScopeHash':digest({'name':intent['database'],'oid':intent['databaseOid']}),
            'currentDatabaseState':{'oid':intent['databaseOid'],'closed':True,'prepared':0,'sessions':0}}
        e.adapters['FENCED_BACKUP'].observe=lambda i:observe('FENCED_BACKUP',backup)
        e.adapters['STAGE_PAUSED_REPLACEMENT'].observe=lambda i:observe('STAGE_PAUSED_REPLACEMENT',paused)
        e.adapters['ADMIT_MIGRATION']=MigrationAdmissionAdapter(adapter.admin,adapter.engine,e.t,intent,store)
        e.run(8);self.assertEqual(len(writes),1);self.assertTrue(e.t.read()['databaseMayHaveChanged'])
        e.run(8);self.assertEqual(len(writes),1)

if __name__=='__main__':unittest.main()
