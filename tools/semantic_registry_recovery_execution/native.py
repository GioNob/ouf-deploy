"""Typed production Ports composition; no launcher/issuer or permissive gates.

All owners must already exist under the SAME current signed recovery scopes.
This connects the twelve stages; installation/source/HUMAN issuance remain
separate. No caller callback can replace a production admission owner.
"""
import copy
from .core import Ports,require,digest
from .lifecycle import Lifecycle,NAMES
from .admission import CurrentAdmission
from .gateway import CurrentGateway
from .semantic_request import OriginalSemanticRequest
from .paused_binding import RecoveryPausedBinding
from .process_binding import RecoveryProcessBinding

class NativePorts(Ports):
    def __init__(self,lifecycle,admission,gateway,semantic):
        require(type(lifecycle) is Lifecycle and type(admission) is CurrentAdmission
            and type(gateway) is CurrentGateway and type(semantic) is OriginalSemanticRequest
            and admission.lifecycle is gateway.lifecycle is semantic.lifecycle is lifecycle
            and semantic.gateway is gateway,'SAME_ACTUAL_RECOVERY_NATIVE_OWNERS_REQUIRED')
        self.lifecycle,self.admission,self.gateway,self.semantic=lifecycle,admission,gateway,semantic
        self.plan_hash=digest(lifecycle.plan)

    def guard(self,plan,row,stage):
        require(digest(plan)==self.plan_hash==digest(self.lifecycle.plan)
            and stage==plan['stages'][row['nextStage']] and row==self.lifecycle.journal(),
            'CURRENT_TYPED_RECOVERY_STAGE_AND_JOURNAL_REQUIRED')
        self.admission.guard();self.gateway.guard();self.semantic.guard()
        require(self.lifecycle.journal()==row,'RECOVERY_NATIVE_GUARD_CHANGED_JOURNAL')

    def gates(self,stage):
        row=self.lifecycle.journal();index=row['nextStage']
        # Before initial start the endpoint must be absent/unoccupied. During
        # an attempted start its outcome is reconciled by Lifecycle, not guessed.
        attempted=(index==1 and row['effects'][-1].get('nativeRequestAttempted') is True)
        if index<2 and not attempted:self.gateway.verify(endpoint_required=False)
        elif index>=2:self.gateway.verify(endpoint_required=True)
        prerequisites=self.admission.prerequisites()
        require(self.lifecycle.journal()==row,'RECOVERY_NATIVE_PREREQUISITES_CHANGED')
        return prerequisites

    def apply(self,plan,row,stage):
        self.guard(plan,row,stage);self.gates(stage)
        name=stage['name'];index=row['nextStage']
        if index==7:
            # Check the current full paused frame/rootfs/current node signature
            # immediately before the separate native unpause dispatch.
            self.admission.paused()
        elif index==9:
            # The unpaused gate must still have its original full image seal,
            # current four mount views and current token before SIGUSR1.
            proof=self.admission.active()
            require(proof['activeFrame']['processKind']=='GATE_WAITING'
                and proof['activeFrame']['preJavaFullRootfsSealVerified'] is True,
                'CURRENT_FULL_PRE_JAVA_ADMISSION_REQUIRED')
        require(self.lifecycle.journal()==row,'RECOVERY_CHANGED_BEFORE_NATIVE_DISPATCH')
        if name in NAMES:self.lifecycle.apply(stage)
        else:
            require(name=='ATTEST_NEW_GENERATION','CLOSED_NATIVE_RECOVERY_EFFECT_REQUIRED')
            self.admission.node.apply()

    def observe(self,plan,row,stage):
        self.guard(plan,row,stage);name=stage['name'];self.gates(stage)
        if name in NAMES:return self.lifecycle.observe(stage)
        if name=='ATTEST_NEW_GENERATION':return self.admission.node.observe()
        if name=='VERIFY_CURRENT_GATES':return 'APPLIED',{'currentAdmissionPrerequisites':self.admission.prerequisites(),
            'sameReviewedRegistryStopped':True,'runtimeAuthorityIssued':False}
        if name=='VERIFY_NEW_WAIT_GENERATION':
            proof=self.lifecycle.process_evidence(self.lifecycle.inspect())
            require(proof['newGeneration']==row['newGeneration'] and proof['processKind']=='GATE_WAITING'
                and proof['paused'] is False,'CURRENT_NEW_WAIT_GENERATION_REQUIRED')
            return 'APPLIED',proof
        if name=='VERIFY_PAUSED_OCI_AND_MOUNTS':
            observed,_,_=self.admission.node.native_observation()
            return 'APPLIED',{'newGeneration':copy.deepcopy(row['newGeneration']),
                'nativeObservationHash':digest(observed),'completeNativeObservationPerformed':True}
        if name=='VERIFY_CURRENT_ADMISSION':return 'APPLIED',self.admission.paused()
        if name=='VERIFY_UNPAUSED_SAME_GATE':return 'APPLIED',self.admission.active()
        require(name in ('VERIFY_APPLICATION_READINESS','VERIFY_FINAL'),'CLOSED_NATIVE_RECOVERY_OBSERVATION_REQUIRED')
        state,ready=self.admission.readiness()
        if state!='APPLIED':return state,ready
        if name=='VERIFY_APPLICATION_READINESS':return state,ready
        # A health response cannot close the incident. Only the same service
        # caller, exact frozen references and ACTIVE identity/version200 can.
        state,proof=self.semantic.verify()
        if state!='APPLIED':return state,proof
        self.admission.active();self.gateway.verify(endpoint_required=True)
        require(self.lifecycle.journal()==row,'RECOVERY_CHANGED_DURING_FINAL_REQUEST_VERIFICATION')
        return state,proof
