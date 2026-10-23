"""Actual NativePorts/Core wiring with explicitly synthetic native owners.

The real crypto/PG/HTTP/kernel boundaries have separate tests. These fixtures
verify sequencing and refusal, never qualify production owners or a target.
"""
import copy,os,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_current_admission
from tools.semantic_registry_recovery_execution import core as c,native as n,lifecycle as l
from tools.semantic_registry_recovery_execution.admission import CurrentAdmission
from tools.semantic_registry_recovery_execution.gateway import CurrentGateway
from tools.semantic_registry_recovery_execution.semantic_request import OriginalSemanticRequest
from tools.semantic_registry_recovery_composition.compose import candidate_contract,GATES

class NativeWiring(unittest.TestCase):
    def setUp(self):
        proposal={'registry':{'containerId':'a'*64},'requiredGates':list(GATES),'unresolvedGateCount':8}
        self.plan=candidate_contract(proposal,'b'*64,'c'*64)
        self.temp=tempfile.TemporaryDirectory(dir=Path.cwd());self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)/('semantic-registry-recovery-'+self.plan['logicalOperationRef']);root.mkdir(mode=0o700)
        self.store=c.Store(root,self.plan['logicalOperationRef'])
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();wall,mono=time.time(),time.monotonic()
        self.new={'containerId':'a'*64,'bootId':boot,'pid':4242,'startTicks':123,'namespaceDevice':4,'namespaceInode':12}
        self.store.initialize(c.initial(self.plan,authority_hash='d'*64,expires_unix=wall+100,expires_monotonic=mono+100,
            boot_id=boot,predecessor_history_hash='e'*64,created_unix=wall,created_monotonic=mono))
        self.calls=[];self.http=200;self.ready=True;self.sealed=True;self.pause_denied=False;self.kind='GATE_WAITING';self.paused=False
        life=l.Lifecycle.__new__(l.Lifecycle);life.plan=self.plan;life.journal=self.store.read
        life.apply=self.effect;life.observe=lambda stage:('APPLIED',self.proof());life.inspect=lambda:None
        life.process_evidence=lambda actual:self.proof()
        admission=CurrentAdmission.__new__(CurrentAdmission);admission.lifecycle=life;admission.guard=lambda:None
        admission.prerequisites=lambda:{'newGeneration':self.store.read()['newGeneration']}
        def paused():
            if self.pause_denied:raise c.RecoveryDenied('FIXTURE_CURRENT_PAUSED_ADMISSION_DENIED')
            return {'newGeneration':self.new}
        admission.paused=paused
        admission.active=lambda:{'newGeneration':self.new,'activeFrame':{'processKind':self.kind,
            'preJavaFullRootfsSealVerified':self.sealed}}
        admission.readiness=lambda:(('APPLIED',{'newGeneration':self.new,'health200':True}) if self.ready
            else ('UNKNOWN',{'applicationReadinessProven':False}))
        admission.node=SimpleNamespace(apply=lambda:self.calls.append('ATTEST_NEW_GENERATION'),
            observe=lambda:('APPLIED',{'newGeneration':self.new}),
            native_observation=lambda:({'explicitSyntheticPausedReport':True},None,None))
        gateway=CurrentGateway.__new__(CurrentGateway);gateway.lifecycle=life;gateway.guard=lambda:None
        gateway.verify=lambda **kw:{'explicitSyntheticRouteProof':True}
        semantic=OriginalSemanticRequest.__new__(OriginalSemanticRequest);semantic.lifecycle=life;semantic.gateway=gateway
        semantic.guard=lambda:None
        def verify():
            self.calls.append('ORIGINAL_SERVICE_GET')
            return ('APPLIED' if self.http==200 else 'UNKNOWN',{'newGeneration':self.new,'httpStatus':self.http,
                'originalSemanticGetSucceeded':self.http==200})
        semantic.verify=verify
        self.native=n.NativePorts(life,admission,gateway,semantic)
        self.runner=c.Runner(self.plan,self.store,self.native,boot_id=boot)

    def proof(self):return {'newGeneration':self.new,'durableNativeStartEvidence':True,
        'processKind':self.kind,'paused':self.paused}
    def effect(self,stage):
        name=stage['name'];self.calls.append(name)
        if name=='PAUSE_NEW_WAIT_GATE':self.paused=True
        if name=='UNPAUSE_ATTESTED_GENERATION':self.paused=False
        if name=='RELEASE_SAME_GENERATION_SIGUSR1':self.kind='APPLICATION_RUNNING'
        row=self.store.read();effects=copy.deepcopy(row['effects']);effects[-1]['nativeRequestAttempted']=True
        self.store.cas(row,{**row,'effects':effects,'version':row['version']+1})
    def advance(self,count):
        for _ in range(count):self.runner.step()

    def test_actual_native_ports_connect_all_twelve_stages_and_final_service_request(self):
        self.advance(12);self.assertEqual(self.store.read()['state'],'COMPLETED')
        self.assertEqual(self.calls,[name for name,kind in c.ORDER if kind=='EFFECT']+['ORIGINAL_SERVICE_GET'])
        self.assertFalse(self.store.read()['releaseAcceptance'])

    def test_paused_owner_denial_blocks_unpause_dispatch(self):
        self.advance(7);self.pause_denied=True
        with self.assertRaises(c.RecoveryDenied):self.runner.step()
        self.assertNotIn('UNPAUSE_ATTESTED_GENERATION',self.calls)

    def test_changed_full_pre_java_rootfs_blocks_the_signal(self):
        self.advance(9);self.sealed=False
        with self.assertRaisesRegex(c.RecoveryDenied,'PRE_JAVA'):self.runner.step()
        self.assertNotIn('RELEASE_SAME_GENERATION_SIGUSR1',self.calls)

    def test_health200_without_original_request200_cannot_complete(self):
        self.advance(11);self.http=502;self.runner.step()
        self.assertEqual(self.store.read()['state'],'IN_FLIGHT')
        self.assertEqual(self.store.read()['nextStage'],11)
        self.assertFalse(self.store.read()['originalSemanticGetSucceeded'])
        self.assertEqual(self.calls.count('ORIGINAL_SERVICE_GET'),1)

    def test_not_ready_does_not_dispatch_a_final_semantic_request(self):
        self.advance(11);self.ready=False;self.runner.step()
        self.assertNotIn('ORIGINAL_SERVICE_GET',self.calls)
        self.assertEqual(self.store.read()['nextStage'],11)

if __name__=='__main__':unittest.main()
