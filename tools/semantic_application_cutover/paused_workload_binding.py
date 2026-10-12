"""Bind native paused workload to the private Stage evidence and current phase.

This observation grants no OCI/rootfs/peer acceptance or signing authority.
The existing node contract for runc-created processes remains separate: an
Engine-paused JVM can have runc state running, and must be described honestly.
"""
from engine_creation import Engine
from transition_journal import digest,require

class PausedWorkloadBinding:
    def __init__(self,engine,transition,creation_request,store):
        require(type(engine) is Engine,'TYPED_PAUSED_WORKLOAD_ENGINE_REQUIRED')
        self.engine,self.transition,self.store=engine,transition,store
        self.request_hash=digest(creation_request)
    def observe(self):
        row=self.transition.read()
        require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']=='ATTEST_NEW_OCI_PEER'
                and row['creationRequestHash']==self.request_hash,'CURRENT_ATTESTATION_PHASE_AND_CREATION_SCOPE_REQUIRED')
        stage=[e for e in row['effects'] if e['phase']=='STAGE_PAUSED_REPLACEMENT' and e['state']=='APPLIED']
        require(len(stage)==1,'APPLIED_PAUSED_STAGE_REQUIRED')
        native=self.store.read('STAGE_PAUSED_REPLACEMENT',stage[0]['nativeEvidenceHash'])
        before=self.engine.inspect(self.transition)
        require(type(before) is dict and before.get('RestartCount')==0
                and before['State']['Running'] is True and before['State']['Paused'] is True
                and before['State']['Status']=='paused' and before['State']['Pid']>1
                and before['HostConfig'].get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0}
                and self.engine.runtime_binding(before)==self.engine.runtime_binding(native),'EXACT_CURRENT_PAUSED_WORKLOAD_GENERATION_REQUIRED')
        binding=self.engine.runtime_binding(before)
        after=self.engine.inspect(self.transition)
        require(type(after) is dict and after['State']['Running'] is True and after['State']['Paused'] is True
                and after['State']['Status']=='paused' and after.get('RestartCount')==0
                and self.engine.runtime_binding(after)==binding,'PAUSED_WORKLOAD_CHANGED_DURING_OBSERVATION')
        return {'schema':'ouf.semantic-paused-workload-binding.v1','transitionContextHash':self.transition.context,
                'creationRequestHash':self.request_hash,'stageEvidenceHash':stage[0]['nativeEvidenceHash'],
                'runtimeBinding':binding,'engineState':'paused','ociAccepted':False,'rootfsAccepted':False,
                'peerAccepted':False,'signaturesIssued':0,'startAuthorized':False}
    def verify_runc_state(self,state,observation):
        fresh=self.observe();require(fresh==observation,'PAUSED_WORKLOAD_OBSERVATION_STALE')
        binding=fresh['runtimeBinding']
        require(type(state) is dict and state.get('id')==binding['containerId']
                and state.get('status')=='running' and state.get('pid')==binding['pid'],
                'EXACT_RUNC_RUNNING_ENGINE_PAUSED_IDENTITY_REQUIRED')
        # Do not rewrite native status to created. Subsequent complete OCI,
        # rootfs, mount/NIC/peer and signed acceptance checks are mandatory.
        return {'stateContract':'RUNC_RUNNING_ENGINE_PAUSED','containerId':binding['containerId'],
                'pid':binding['pid'],'pausedBindingHash':digest(fresh),'completeCreationAccepted':False}
