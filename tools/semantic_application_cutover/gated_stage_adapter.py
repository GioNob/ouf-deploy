"""Start only the preapplication wait gate, verify its handler, then pause once.
An ambiguous start/wait/pause is reconciled, never retransmitted. No JVM, socket,
DB or provider call is issued by the fixed gate. Source-sealed checkpoints own
current authority/custody; observation waits are read-only and finite.
"""
import time
from runtime_adapters import PausedStageAdapter
from gated_creation_plan import ENTRY
from gated_process_observation import GatedProcessObservation
from transition_journal import require

class GatedStageAdapter(PausedStageAdapter):
    def __init__(self,engine,transition,creation_request,store,process,checkpoint):
        require(creation_request.get('Entrypoint')==ENTRY and type(process) is GatedProcessObservation and callable(checkpoint),'EXACT_GATED_STAGE_AND_PROCESS_OBSERVATION_REQUIRED')
        super().__init__(engine,transition,creation_request,store);self.process,self.checkpoint=process,checkpoint
    def apply(self,intent):
        # Reuse the qualified exact created-payload/request checks; replace the
        # two native effects with an explicit bounded gate-read checkpoint.
        created=self.exact(intent,'CREATE_REPLACEMENT')
        row=self.transition.read()
        from transition_journal import digest
        require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']==self.phase and row['effects'][-1]['intentHash']==digest(intent),'DURABLE_GATED_STAGE_BOUNDARY_REQUIRED')
        actual=self.engine.matching_created(self.transition,self.request,self.engine.inspect(self.transition))
        require(digest(actual)==digest(created),'CREATED_GENERATION_CHANGED_BEFORE_GATED_STAGE')
        cid=actual['Id'];self.checkpoint('BEFORE_PREAPPLICATION_START')
        status,_=self.engine.request('POST','/v1.44/containers/'+cid+'/start');require(status==204,'GATED_START_OUTCOME_REQUIRES_RECONCILIATION')
        deadline=time.monotonic()+5
        while True:
            current=self.engine.inspect(self.transition)
            require(type(current) is dict and current['Id']==cid and current['Image']==actual['Image']
                    and current['State']['Running'] is True and current['State']['Paused'] is False,'CURRENT_PREAPPLICATION_PROCESS_REQUIRED')
            observed=self.process.observe(current['State']['Pid'])
            if observed['processKind']=='GATE_WAITING':break
            require(observed['processKind']=='UNPROVEN' and time.monotonic()<deadline,'PREAPPLICATION_WAIT_HANDLER_UNPROVEN')
            time.sleep(.05)
        self.checkpoint('BEFORE_PREAPPLICATION_PAUSE')
        status,_=self.engine.request('POST','/v1.44/containers/'+cid+'/pause');require(status==204,'GATED_PAUSE_OUTCOME_REQUIRES_RECONCILIATION')
    def observe(self,intent):
        current=self.engine.inspect(self.transition)
        require(type(current) is dict and current['State']['Running'] is True and current['State']['Paused'] is True
                and self.process.observe(current['State']['Pid'])['processKind']=='GATE_WAITING','PAUSED_PREAPPLICATION_WAIT_GATE_UNPROVEN')
        return super().observe(intent)
