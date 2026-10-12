"""Explicit unpause + SIGUSR1 of the same attested pre-application generation.

No start, new PID, signal retransmission, restore or rollback. A failure between
unpause and SIGUSR1 remains IN_FLIGHT. Fresh source-sealed checkpoints own the
current authority, migration, complete signed OCI/peer and distinct lease.
"""
import copy
from engine_creation import Engine
from gated_process_observation import GatedProcessObservation
from gated_creation_plan import ENTRY,PROFILE
from transition_journal import digest,require
from native_evidence_store import NativeEvidenceStore

PHASE='START_REPLACEMENT'
class GatedReleaseAdapter:
    def __init__(self,engine,transition,creation_request,store,before_store,process,checkpoint):
        require(type(engine) is Engine and type(process) is GatedProcessObservation and callable(checkpoint),'TYPED_GATED_RELEASE_CHANNEL_AND_CHECKPOINT_REQUIRED')
        require(creation_request.get('Entrypoint')==ENTRY,'EXPLICIT_PREAPPLICATION_GATE_REQUEST_REQUIRED')
        self.engine,self.transition,self.store,self.before_store,self.process,self.checkpoint=engine,transition,store,before_store,process,checkpoint
        self.request_hash=digest(creation_request);self.intent={'creationRequestHash':self.request_hash,'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT','preApplicationGateProfile':PROFILE};self.intent_hash=digest(self.intent)
        require(type(before_store) is NativeEvidenceStore and type(store) is NativeEvidenceStore and before_store.root!=store.root,'SEPARATE_PRIVATE_PRE_RELEASE_EVIDENCE_REQUIRED')
    def current(self,intent):
        row=self.transition.read()
        require(digest(intent)==self.intent_hash and row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']==PHASE
                and row['effects'][-1]['intentHash']==self.intent_hash and row['creationRequestHash']==self.request_hash
                and row['databaseMayHaveChanged'] is True and row['applicationWritesMayHaveOccurred'] is True,'DURABLE_GATED_APPLICATION_RELEASE_BOUNDARY_REQUIRED')
        stage=next(e for e in row['effects'] if e['phase']=='STAGE_PAUSED_REPLACEMENT' and e['state']=='APPLIED')
        expected=self.engine.runtime_binding(self.store.read('STAGE_PAUSED_REPLACEMENT',stage['nativeEvidenceHash']))
        actual=self.engine.inspect(self.transition)
        require(type(actual) is dict and self.engine.runtime_binding(actual)==expected and actual['State']['Running'] is True
                and actual.get('RestartCount')==0,'SAME_CURRENT_GATED_APPLICATION_GENERATION_REQUIRED')
        return row,actual,self.process.observe(expected['pid'])
    def apply(self,intent):
        row,actual,process=self.current(intent)
        require(actual['State']['Paused'] is True and actual['State']['Status']=='paused' and process['processKind']=='GATE_WAITING','EXACT_PREAPPLICATION_GATE_WAITING_BEFORE_RELEASE_REQUIRED')
        baseline={'schema':'ouf.semantic-gated-release-before.v1','transitionContextHash':self.transition.context,'intentHash':self.intent_hash,
                  'runtimeBinding':self.engine.runtime_binding(actual),'process':process}
        self.before_store.publish(PHASE,baseline)
        cid=actual['Id'];self.checkpoint('BEFORE_UNPAUSE')
        status,_=self.engine.request('POST','/v1.44/containers/'+cid+'/unpause');require(status==204,'GATED_UNPAUSE_OUTCOME_REQUIRES_RECONCILIATION')
        _,fresh,current=self.current(intent)
        require(fresh['State']['Paused'] is False and fresh['State']['Status']=='running' and current==process,'PREAPPLICATION_GATE_CHANGED_BEFORE_SIGNAL')
        self.checkpoint('BEFORE_PREAPPLICATION_SIGUSR1')
        status,_=self.engine.request('POST','/v1.44/containers/'+cid+'/kill?signal=SIGUSR1');require(status==204,'GATED_SIGNAL_OUTCOME_REQUIRES_RECONCILIATION')
    def observe(self,intent):
        try:row,actual,process=self.current(intent)
        except ValueError as error:
            if str(error)!='GATED_PROCESS_CHANGED_DURING_READ':raise
            return 'UNKNOWN',{'processTransitionChangedDuringRead':True,'readOnlyReconciliationRequired':True,
                              'unpauseReplayAllowed':False,'signalReplayAllowed':False}
        try:
            # Bound private before payload; do not adopt an arbitrary process
            # which another invocation happened to start under the same name.
            previous=self.before_store.read_baseline(PHASE,self.transition.context,self.intent_hash)
        except FileNotFoundError:return 'UNKNOWN',{'gatedReleaseBaselineAbsent':True,'signalReplayAllowed':False}
        require(previous.get('schema')=='ouf.semantic-gated-release-before.v1' and previous.get('transitionContextHash')==self.transition.context
                and previous.get('intentHash')==self.intent_hash and previous.get('runtimeBinding')==self.engine.runtime_binding(actual)
                and previous.get('process',{}).get('generation')==process['generation'],'GATED_RELEASE_BASELINE_OR_PROCESS_GENERATION_DRIFT')
        if actual['State']['Paused'] is not False or actual['State']['Status']!='running' or process['processKind']!='APPLICATION_RUNNING':
            return 'UNKNOWN',{'preapplicationReleaseUnproven':True,'unpauseReplayAllowed':False,'signalReplayAllowed':False}
        try:_,after,end=self.current(intent)
        except ValueError as error:
            if str(error)!='GATED_PROCESS_CHANGED_DURING_READ':raise
            return 'UNKNOWN',{'processTransitionChangedDuringRead':True,'readOnlyReconciliationRequired':True,
                              'unpauseReplayAllowed':False,'signalReplayAllowed':False}
        require(self.engine.runtime_binding(after)==self.engine.runtime_binding(actual) and after['State']['Paused'] is False and end==process,'GATED_RELEASE_PROCESS_CHANGED_DURING_READ')
        evidence={'schema':'ouf.semantic-gated-application-release.v1','transitionContextHash':self.transition.context,'intentHash':self.intent_hash,
                  'runtimeBinding':self.engine.runtime_binding(actual),'generation':process['generation'],'processKind':'APPLICATION_RUNNING',
                  'beforeEvidenceHash':digest(previous),'applicationMayHaveWritten':True,'unpauseReplayAllowed':False,'signalReplayAllowed':False,
                  'applicationReadyProven':False,'notReleaseAcceptance':True}
        self.store.publish(PHASE,evidence);return 'APPLIED',evidence
