"""Actual systemd/SIGTERM/nft and production cumulative cancellation integration.

Synthetic installation, signatures/checkpoints, worker entry and table structure;
not target R12 or complete transport/deployment/CSV acceptance.
"""
import copy,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,time,unittest,uuid
from dataclasses import asdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_lease_recovery')]
from r12_retirement_adapter import R12RetirementChannel,R12RetirementAdapter,encoded,sha
from native_evidence_store import NativeEvidenceStore
from executor_composition_fixture import compose
from transition_journal import digest,Transition
from bounded_recovery import Policy
from test_r12_retirement_adapter import history
from cutover_executor import CutoverDenied
from test_coordination_input_capture import custody
spec=importlib.util.spec_from_file_location('retirement_native_reader',ROOT/'tools/semantic_lease_recovery/reader.py');reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)

def command(*args,input=None):return subprocess.run(args,input=input,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60).stdout
class NativeRetirement(unittest.TestCase):
    def fixture(self,state='ACTIVE'):
        self.assertEqual(os.geteuid(),0)
        temp=tempfile.TemporaryDirectory(prefix='ouf-retirement-',dir=ROOT);self.addCleanup(temp.cleanup);base=Path(temp.name);base.chmod(0o700)
        def write(path,v):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=encoded(v) if type(v) is dict else v;path.write_bytes(raw);path.chmod(0o600);return {'path':str(path),'sha256':sha(raw)}
        suffix=uuid.uuid4().hex[:12];unit='ouf-fixture-retire-'+suffix+'.service';table='ouf_retire_'+suffix
        nft=str(Path(shutil.which('nft')).resolve());systemctl=str(Path(shutil.which('systemctl')).resolve());python=str(Path(sys.executable).resolve())
        def binary(p):return {'path':p,'sha256':sha(Path(p).read_bytes())}
        tx=''
        for f in ('inet','bridge'):
            tx+='add table '+f+' '+table+'\n'
            for i in range(2):
                tx+='add set '+f+' '+table+' provider_'+str(i)+' { type ipv4_addr; flags timeout; timeout 30s; }\n'
                if state=='ACTIVE':tx+='add element '+f+' '+table+' provider_'+str(i)+' { 1.1.1.1 timeout 30s }\n'
        command(nft,'-f','-',input=tx.encode())
        def cleanup():
            subprocess.run([systemctl,'stop',unit],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
            for f in ('inet','bridge'):subprocess.run([nft,'delete','table',f,table],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.addCleanup(cleanup)
        r12=base/'r12';r12.mkdir(mode=0o700);programs={}
        for name in ('bounded_recovery.py','lease_recovery_budget.py','recovery_journal.py'):
            programs[name]=write(r12/name,(ROOT/'tools/semantic_lease_recovery'/name).read_bytes())['sha256']
        programs['activate.py']=write(r12/'activate.py',(ROOT/'tests/fixtures/r12_retirement_worker.py').read_bytes())['sha256']
        for i in range(11):programs['fixture_source_'+str(i)+'.py']=write(r12/('fixture_source_'+str(i)+'.py'),b'# fixture-only non-executed sealed bytes\n')['sha256']
        bindings={'transactionId':'f'*64,'configurationHash':'e'*64,'leaseStructureHash':'a'*64}
        source=base/'owner-source';source.mkdir(mode=0o700);source_hashes={}
        for i in range(8):source_hashes['source'+str(i)+'.py']=write(source/('source'+str(i)+'.py'),b'# fixture-only owner source bytes\n')['sha256']
        tables={f:json.loads(command(nft,'-j','list','table',f,table)) for f in ('inet','bridge')}
        struct=sha(encoded(reader.structure(tables)));bindings['leaseStructureHash']=struct
        owner={'schema':'ouf.fixture-owned-coordinator.v1','binding':bindings,'kernel':{'tableName':table,'providerFlows':[{'source':'172.22.0.'+str(i+2),'allowedPrivateAddresses':[],'leaseSeconds':30,'endpoint':'fixture.invalid','endpointRef':'fixture'+str(i)} for i in range(2)]},
               'expectedStructureHash':struct,'pollSeconds':15,'nftPath':nft,'nftSha256':binary(nft)['sha256'],'journalFile':str(base/'lease.json'),'sourceHashes':source_hashes}
        owner_binding=write(base/'owner.json',owner);write(r12/'fixture-owner.json',owner)
        write(base/'lease.json',{'schema':'ouf.semantic-lease-coordination.v1',**bindings,'state':'LEASE_READY' if state=='ACTIVE' else 'QUIESCED','leaseAuthorized':state=='ACTIVE','startAuthorized':False,'leaseAddresses':[['1.1.1.1'],['1.1.1.1']] if state=='ACTIVE' else [[],[]]})
        cfg={'pythonBinding':binary(python),'commandBindings':{'systemctl':binary(systemctl),'nft':binary(nft)}};cfg_binding=write(base/'execution.json',cfg)
        claim=write(base/'activation.claim',{'startAuthorized':False,'fixtureOnly':True});boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        auth={'schema':'ouf.provider-resilient-r12-authorization.v1','serviceUnit':unit,'hostBootId':boot,'automaticRestart':False,'enableAtBoot':False,'programHashes':programs,'ownerConfigurationHash':owner_binding['sha256'],'activationClaim':json.loads(Path(claim['path']).read_bytes()),'generationRef':'b'*64,'incidentRef':'d'*64,'nativeBindings':{'python':binary(python)},'executionExpiresAt':1}
        auth['contextRef']=digest(auth);auth_binding=write(r12/'authorization.json',auth)
        h=history(state);wall,mono=time.time(),time.monotonic();elapsed=min(200,mono)
        h.update(contextRef=auth['contextRef'],policyHash=digest(asdict(Policy())),startedWall=wall-200,startedMonotonic=mono-elapsed,lastWall=wall,lastMonotonic=mono,healthyMonotonicSeconds=elapsed/2)
        retry=r12/'retry';retry.mkdir(mode=0o700)
        from recovery_journal import Journal
        Journal(retry).initialize(h)
        command('/usr/bin/systemd-run','--unit='+unit,'--service-type=exec','--property=Restart=no','--property=UMask=0077','--property=TimeoutStopSec=45',python,'-I','-B',str(r12/'activate.py'),'--supervise',str(r12/'authorization.json'),auth_binding['sha256'])
        deadline=time.monotonic()+20
        while not (r12/'worker-status.json').exists():
            if time.monotonic()>deadline:
                self.fail('FIXTURE_WORKER_START_FAILED '+command('/usr/bin/journalctl','-u',unit,'--no-pager','-n','20').decode())
            time.sleep(0.05)
        pid=json.loads((r12/'worker-status.json').read_bytes())['workerPid']
        intake=base/'intake';intake.mkdir(mode=0o700)
        files={'native-review-intake.json':{},'existing-authority-profile.json':{},'existing-coordinator.json':owner,
               'retained-human-binding.json':{},'retained-execution-configuration.json':cfg,'r12-authorization.json':auth,
               'r12-activation-claim.json':json.loads(Path(claim['path']).read_bytes()),'r12-worker-invocation.json':json.loads((r12/'worker-invocation-claim.json').read_bytes()),
               'r12-worker-status.json':json.loads((r12/'worker-status.json').read_bytes()),'r12-recovery-history.json':h}
        manifest={'schema':'ouf.native-v11-atomic-review-intake.v1','collectionKind':'EXISTING_COORDINATOR_AND_CUMULATIVE_HISTORY_INPUTS','observationsAreHistorical':True,'runtimeAuthorityIssued':False,'applicationCutoverAuthorized':False,'productionApplyReady':False,'fileHashes':{n:write(intake/n,v)['sha256'] for n,v in files.items()}}
        intake_binding=write(intake/'intake.json',manifest)
        scope={'intakeBinding':intake_binding,'authorizationBinding':auth_binding,'coordinatorBinding':owner_binding,'executionBinding':cfg_binding,'r12Root':str(r12),'activationClaimPath':claim['path'],'ownerSourceRoot':str(source),'programHashes':programs,'unit':unit,'workerPid':pid,'hostBootId':boot}
        channel=R12RetirementChannel(scope,custody,reader.lease_projection)
        before=base/'before';before.mkdir(mode=0o700);before_store=NativeEvidenceStore(before)
        intent={'scopeHash':channel.scope_hash,'stopTimeoutSeconds':55}
        e,store=compose(self,'STOP_REVOKE_OLD_LEASE',intent,lambda t,s:R12RetirementAdapter(channel,t,intent,before_store,s),predecessor_history=channel.capture_history_hash)
        return e,channel,r12,base
    def test_actual_active_worker_stop_and_both_families_empty_without_replay(self):
        e,c,r12,base=self.fixture();e.run(1);c.stop=lambda _:self.fail('NATIVE_STOP_REPLAYED');e.run(1)
        row=json.loads((r12/'retry/recovery.json').read_bytes());self.assertEqual(row['attempts'],24);self.assertEqual(row['publicationCount'],4330);self.assertEqual(row['state'],'CANCELLED')
        self.assertTrue((r12/'revoked').is_file());self.assertTrue((r12/'worker-invocation-claim.json').is_file())
    def test_controller_death_after_real_stop_reconciles_and_paused_cancellation_works(self):
        e,c,r12,base=self.fixture('PAUSED_EXHAUSTED');a=e.adapters['STOP_REVOKE_OLD_LEASE'];original=c.stop
        def crash(seconds):original(seconds);raise RuntimeError('native-controller-gap')
        c.stop=crash
        with self.assertRaises(RuntimeError):e.run(1)
        e.t=Transition(e.t.journal,e.t.context);a.transition=e.t;c.stop=lambda _:self.fail('NATIVE_STOP_REPLAYED');e.run(1)
        self.assertEqual(e.t.read()['nextPhase'],1)
    def test_foreign_marker_or_consumed_claim_drift_preserves_worker(self):
        for drift in ('marker','claim'):
            e,c,r12,base=self.fixture('BLOCKED')
            path=r12/'revoked' if drift=='marker' else base/'activation.claim';path.write_bytes(encoded({'foreign':True}));path.chmod(0o600)
            with self.assertRaises(ValueError):e.run(1)
            self.assertEqual(e.t.read()['state'],'IN_FLIGHT');self.assertTrue(Path('/proc/'+str(c.scope['workerPid'])).exists())

if __name__=='__main__':unittest.main()
