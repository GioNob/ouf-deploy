"""Disposable real Docker/kernel recovery binding and real scoped signatures.

Alpine gate fixture only: no Semantic JVM, token/database/OCI acceptance, target
or production recovery qualification. No release signal is sent by this test.
"""
import copy,json,os,subprocess,sys,time,unittest,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT)]
import test_file_only_preparation
import test_cutover_authority_native as signed
import native_runtime_executor as image_fixture
from engine_creation import Engine
from file_only_profile import FileOnlyProfile,PROFILE,PHASES
from gated_creation_plan import ENTRY
from gated_process_observation import GatedProcessObservation
from cutover_authority import CutoverAuthority
from tools.semantic_registry_recovery_execution import core as c,authorization as a,lifecycle as l,paused_binding as p
from tools.semantic_registry_recovery_execution.mount_observation import RecoveryTokenMountObservation
from tools.semantic_policy_token_owner.mount_observation import generation as mount_generation
from test_renewable_token_mount import FixtureOwner
from tools.semantic_registry_recovery_composition.compose import candidate_contract,GATES

class NativePausedRecovery(unittest.TestCase):
    native=signed.SignedCutover.native
    write=signed.SignedCutover.write
    binding=signed.SignedCutover.binding
    sign=signed.SignedCutover.sign

    @classmethod
    def setUpClass(cls):
        image_fixture.NativeRuntime.setUpClass();cls.image=image_fixture.NativeRuntime.image

    def setUp(self):
        signed.SignedCutover.setUp(self)
        # Disposable configtree mount, independently scoped by this fixture.
        tree=self.root/'db';tree.mkdir(mode=0o500);os.chown(tree,10001,10001)
        password=tree/'OUF_SEM_DB_PASSWORD';password.write_bytes(b'DISPOSABLE_FIXTURE');password.chmod(0o400);os.chown(password,10001,10001)
        configtree={'source':str(tree),'target':'/run/fixture-db','readOnly':True,'uid':10001,'gid':10001,
            'directoryMode':0o500,'fileName':password.name,'fileMode':0o400,'maxBytes':64,'sha256':signed.sha(password.read_bytes())}
        token_root=self.root/'token';token_root.mkdir(mode=0o750);os.chown(token_root,0,10001)
        token=token_root/'token.jwt';token.write_text('DISPOSABLE_FIXTURE_TOKEN');token.chmod(0o440);os.chown(token,0,10001)
        info=token_root.stat()
        self.token_policy={'source':str(token_root),'target':'/run/fixture-token','fileName':token.name,'gid':10001,
            'directoryDevice':info.st_dev,'directoryInode':info.st_ino,'ownerBindingHash':'a'*64,
            'maxBytes':16384,'minimumRemainingSeconds':30}
        request={'Image':self.image,'User':'10001:10001','Entrypoint':ENTRY,
            'Cmd':['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar'],
            'Env':['OUF_SCHEMA_GOV_ENABLED=false','OUF_DISCOVERY_WORKER_ENABLED=false','SPRING_CONFIG_IMPORT=configtree:/run/fixture-db/'],
            'HostConfig':{'NetworkMode':'none','CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
                'RestartPolicy':{'Name':'no','MaximumRetryCount':0},
                'Binds':[str(tree)+':/run/fixture-db:ro',str(token_root)+':/run/fixture-token:ro']}}
        self.profile=FileOnlyProfile(request,configtree)
        socket='/var/run/docker.sock';s=os.stat(socket,follow_symlinks=False)
        engine=Engine(socket,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777));self.engine=engine
        status,created=engine.request('POST','/v1.44/containers/create?name=ouf-recovery-fixture-'+uuid.uuid4().hex,request)
        self.assertEqual(status,201);cid=created['Id'];self.cid=cid
        self.addCleanup(lambda:engine.request('DELETE','/v1.44/containers/'+cid+'?force=true'))
        def inspect():
            status,value=engine.request('GET','/v1.44/containers/'+cid+'/json');self.assertEqual(status,200);return value
        self.inspect=inspect
        self.assertEqual(engine.request('POST','/v1.44/containers/'+cid+'/start')[0],204)
        observer=GatedProcessObservation(request);deadline=time.monotonic()+8
        while True:
            actual=inspect();process=observer.observe(actual['State']['Pid'])
            if process['processKind']=='GATE_WAITING':break
            self.assertLess(time.monotonic(),deadline);time.sleep(.05)
        self.assertEqual(engine.request('POST','/v1.44/containers/'+cid+'/stop?t=1')[0],204)
        baseline=inspect();self.assertEqual(baseline['State']['Status'],'exited')
        self.previous_pid=actual['State']['Pid']
        proposal={'registry':{'containerId':cid,'imageId':self.image,'configHash':c.digest(baseline['Config']),
            'hostConfigHash':c.digest(baseline['HostConfig']),
            'mountsHash':c.digest(sorted(baseline['Mounts'],key=lambda x:x['Destination']))},
            'requiredGates':list(GATES),'unresolvedGateCount':8}
        plan=candidate_contract(proposal,'9'*64,self.expected['predecessorIncidentRef']);self.plan=plan
        self.expected['creationRequestHash']=c.digest(request)
        raw={'schema':'ouf.semantic-cutover-execution-authority.v2',**{k:v for k,v in self.expected.items() if k!='intakeHash'},
            'issuedAt':self.now,'expiresAt':self.now+120,'deploymentProfile':PROFILE,'executionProfileHash':self.profile.sha256,
            'newDistinctLeaseWorkerRequired':False,'phaseIntentHashes':{phase:'a'*64 for phase in PHASES},
            'semanticRegistryRecovery':a.scope(plan)}
        self.authority=c.encoded(raw)
        self.approval.update(schema='ouf.semantic-cutover-human-mandate.v2',**self.expected,
            executionAuthorityHash=signed.sha(self.authority),deploymentProfile=PROFILE,executionProfileHash=self.profile.sha256)
        self.write(self.mandate,c.encoded(self.approval));self.approved=signed.sha(self.mandate.read_bytes())
        for role in self.grant['roles']:self.sign(role)
        authority=CutoverAuthority(self.verifier,self.binding(self.mandate),self.approved,self.context,self.expected,
            self.clock,execution_profile=self.profile)
        scope=a.AuthorityScope(authority,self.authority,plan,request);self.scope=scope
        root=self.root/('semantic-registry-recovery-'+plan['logicalOperationRef']);root.mkdir(mode=0o700)
        store=c.Store(root,plan['logicalOperationRef']);self.store=store
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();mono=time.monotonic()
        store.initialize(c.initial(plan,authority_hash=scope.hash,expires_unix=self.now+110,expires_monotonic=mono+110,
            boot_id=boot,predecessor_history_hash=self.expected['predecessorHistoryHash'],created_unix=self.now,created_monotonic=mono))
        native=l.Lifecycle(engine,scope,store,plan,request,baseline,proposal);self.lifecycle=native
        class FixturePorts(c.Ports):
            # Only lifecycle/generation boundaries are under test; all other
            # production owners are explicitly absent, not fixture-accepted.
            def guard(ports,plan,row,stage):scope.guard(row)
            def apply(ports,plan,row,stage):native.apply(stage)
            def observe(ports,plan,row,stage):
                if stage['kind']=='EFFECT':return native.observe(stage)
                if stage['name']=='VERIFY_CURRENT_GATES':return 'APPLIED',{'syntheticInitialGate':True}
                proof=native.process_evidence(native.inspect())
                if proof['processKind']!='GATE_WAITING':return 'UNKNOWN',{}
                return 'APPLIED',proof
        self.runner=c.Runner(plan,store,FixturePorts(),boot_id=boot)

    def advance_to_paused(self):
        deadline=time.monotonic()+15
        while self.store.read()['nextStage']<4:
            self.runner.step();self.assertLess(time.monotonic(),deadline)
            if self.store.read()['state']=='IN_FLIGHT':time.sleep(.05)
        # Begin the read checkpoint without advancing it so the native binding
        # observes the same current paused journal boundary as production.
        row=self.store.read();stage=self.plan['stages'][4];effects=copy.deepcopy(row['effects'])
        effects.append({'stage':stage['name'],'intentHash':stage['intentHash'],'authorityHash':self.scope.hash,
            'state':'CLAIMED','nativeEvidence':None})
        self.store.cas(row,{**row,'effects':effects,'state':'IN_FLIGHT','version':row['version']+1})
        return p.RecoveryPausedBinding(self.lifecycle,self.profile)

    def test_real_restart_pause_and_fresh_kernel_identity(self):
        binding=self.advance_to_paused();report=binding.observe();pid=report['runtimeBinding']['pid']
        self.assertNotEqual(pid,self.previous_pid)
        self.assertEqual(self.store.read()['newGeneration']['pid'],pid)
        self.assertTrue(self.inspect()['State']['Paused'])
        self.assertFalse(report['ociAccepted']);self.assertEqual(report['signaturesIssued'],0)
        self.assertEqual(self.store.read()['nextStage'],4)

    def test_native_unpause_invalidates_the_observation(self):
        binding=self.advance_to_paused();binding.observe()
        self.assertEqual(self.engine.request('POST','/v1.44/containers/'+self.cid+'/unpause')[0],204)
        with self.assertRaises(c.RecoveryDenied):binding.observe()

    def test_readonly_token_mount_uses_distinct_native_recovery_binding(self):
        binding=self.advance_to_paused();report=binding.observe();pid=report['runtimeBinding']['pid']
        owner=FixtureOwner()
        original=self.lifecycle.engine.runtime_binding;bindings=[]
        def record(actual):
            value=original(actual);bindings.append(value);return value
        self.lifecycle.engine.runtime_binding=record
        try:
            for _ in range(8):
                observation=RecoveryTokenMountObservation(self.token_policy,owner,time.monotonic()+10,pause_binding=binding)
                proof=observation.observe(mount_generation(pid,allow_frozen=True))
        except BaseException:
            # Disposable CI diagnostics print field names only, never bindings
            # or token contents. Production checks remain strict and unchanged.
            print('FIXTURE_RUNTIME_DIFFERENCE_FIELDS='+json.dumps([
                sorted(k for k in a if a[k]!=b[k]) for a,b in zip(bindings,bindings[1:]) if a!=b]))
            raise
        self.assertTrue(proof['sameSourceFileInMountedView'])
        self.assertTrue(proof['effectiveReadOnlyDirectoryBindingObserved'])
        self.assertEqual(owner.calls,8)
        self.assertNotIn('DISPOSABLE_FIXTURE_TOKEN',json.dumps(proof))
        self.assertFalse(proof['runtimeAuthorityIssued'])

if __name__=='__main__':unittest.main()
