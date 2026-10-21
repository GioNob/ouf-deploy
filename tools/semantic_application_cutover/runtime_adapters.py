"""Effect-only pause/release adapters; Executor owns durable intent claims.

Signed intents name prior phases, whose private native payloads are bound by
the journal. This avoids inventing container IDs/PIDs before creation. Sealed
checkpoints still prove DB/producer/lease fences, OCI, transport and authority.
"""
import json
from engine_creation import digest,require

class RuntimeAdapter:
    phase=None
    def __init__(self,engine,transition,request,store):
        self.engine,self.transition,self.store=engine,transition,store
        self.request=json.loads(json.dumps(request,allow_nan=False))
    def exact(self,intent,prior):
        row=self.transition.read()
        require(intent=={'creationRequestHash':digest(self.request),'priorEvidencePhase':prior}
                and row['creationRequestHash']==digest(self.request), 'EXACT_SIGNED_RUNTIME_PHASE_REFERENCE_REQUIRED')
        matches=[e for e in row['effects'] if e['phase']==prior and e['state']=='APPLIED']
        require(len(matches)==1,'APPLIED_PRIOR_NATIVE_EVIDENCE_REQUIRED')
        return self.store.read(prior,matches[0]['nativeEvidenceHash'])

class PausedStageAdapter(RuntimeAdapter):
    phase='STAGE_PAUSED_REPLACEMENT'
    def apply(self,intent):
        created=self.exact(intent,'CREATE_REPLACEMENT')
        actual=self.engine.matching_created(self.transition,self.request,self.engine.inspect(self.transition))
        require(digest(actual)==digest(created),'CREATED_GENERATION_CHANGED_BEFORE_STAGE')
        status,_=self.engine.request('POST','/v1.44/containers/'+created['Id']+'/start')
        require(status==204,'PAUSED_STAGE_START_OUTCOME_UNPROVEN')
        status,_=self.engine.request('POST','/v1.44/containers/'+created['Id']+'/pause')
        require(status==204,'PAUSED_STAGE_PAUSE_OUTCOME_UNPROVEN')
    def observe(self,intent):
        created=self.exact(intent,'CREATE_REPLACEMENT')
        actual=self.engine.inspect(self.transition)
        if actual is None:return 'UNKNOWN',{'nativeNameAbsent':True,'absenceDoesNotProveNoEffect':True}
        native_intent={'containerId':created['Id'],'creationRequestHash':digest(self.request),'createdEvidenceHash':digest(created)}
        actual=self.engine.matching_paused(self.transition,self.request,native_intent,actual)
        require(self.engine.inspect(self.transition)==actual,'PAUSED_GENERATION_CHANGED_DURING_RECONCILIATION')
        self.store.publish(self.phase,actual)
        return 'APPLIED',actual

class ReleasePausedAdapter(RuntimeAdapter):
    phase='START_REPLACEMENT'
    def apply(self,intent):
        paused=self.exact(intent,'STAGE_PAUSED_REPLACEMENT')
        actual=self.engine.matching_configuration(self.transition,self.request,self.engine.inspect(self.transition))
        binding=self.engine.runtime_binding(paused)
        require(self.engine.runtime_binding(actual)==binding and actual['State']['Running'] is True
                and actual['State']['Paused'] is True and actual['State']['Status']=='paused','EXACT_ATTESTED_PAUSED_GENERATION_REQUIRED')
        status,_=self.engine.request('POST','/v1.44/containers/'+binding['containerId']+'/unpause')
        require(status==204,'UNPAUSE_OUTCOME_REQUIRES_RECONCILIATION')
    def observe(self,intent):
        paused=self.exact(intent,'STAGE_PAUSED_REPLACEMENT');binding=self.engine.runtime_binding(paused)
        actual=self.engine.inspect(self.transition)
        if actual is None:return 'UNKNOWN',{'nativeNameAbsent':True,'absenceDoesNotProveNoEffect':True}
        actual=self.engine.matching_released(self.transition,self.request,binding,actual)
        following=self.engine.matching_released(self.transition,self.request,binding,self.engine.inspect(self.transition))
        require(self.engine.runtime_binding(following)==self.engine.runtime_binding(actual),'RELEASED_GENERATION_DRIFT')
        # Volatile Engine statistics do not replace the attested generation pin.
        self.store.publish(self.phase,binding)
        return 'APPLIED',binding
