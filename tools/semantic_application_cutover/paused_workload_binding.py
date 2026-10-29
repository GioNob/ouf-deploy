"""Bind native paused workload to the private Stage evidence and current phase.

This observation grants no OCI/rootfs/peer acceptance or signing authority.
The existing node contract for runc-created processes remains separate: an
Engine-paused JVM has an observed runc state paused, and must be described honestly.
"""
from engine_creation import Engine
from transition_journal import digest,require,hash_value
from file_only_profile import PHASES

class PausedWorkloadBinding:
    def __init__(self,engine,transition,creation_request,store):
        require(type(engine) is Engine,'TYPED_PAUSED_WORKLOAD_ENGINE_REQUIRED')
        self.engine,self.transition,self.store=engine,transition,store
        self.request_hash=digest(creation_request)
        self.retained_checkpoint=None
    @classmethod
    def retained_at_checkpoint(cls,engine,transition,creation_request,store,*,attestation_intent_hash,checkpoint_row):
        """Observe one already accepted node before migration or unpause.

        The caller still owns current action/signature authorization. This
        separate read mode grants nothing and never admits a new attestation.
        Bind the exact current journal snapshot so it cannot cross a phase.
        """
        require(hash_value(attestation_intent_hash),'EXACT_RETAINED_ATTESTATION_INTENT_REQUIRED')
        value=cls(engine,transition,creation_request,store)
        require(checkpoint_row==transition.read(),'CURRENT_RETAINED_PAUSED_CHECKPOINT_REQUIRED')
        value.retained_checkpoint=(digest(checkpoint_row),attestation_intent_hash)
        value.current_row()
        return value
    def current_row(self):
        row=self.transition.read()
        require(row['creationRequestHash']==self.request_hash,'CURRENT_ATTESTATION_PHASE_AND_CREATION_SCOPE_REQUIRED')
        if self.retained_checkpoint is None:
            require(row['state']=='IN_FLIGHT' and row['effects'][-1]['phase']=='ATTEST_NEW_OCI_PEER',
                    'CURRENT_ATTESTATION_PHASE_AND_CREATION_SCOPE_REQUIRED')
        else:
            snapshot,intent_hash=self.retained_checkpoint
            cursor=row.get('nextPhase');effects=row.get('effects')
            require(digest(row)==snapshot and row['state']=='IN_FLIGHT' and type(cursor)is int and cursor in(7,8)
                and type(effects)is list and len(effects)==cursor+1
                and [e.get('phase')for e in effects]==list(PHASES[:cursor+1])
                and all(e.get('state')=='APPLIED'for e in effects[:cursor])
                and effects[-1].get('state')=='IN_FLIGHT'
                and effects[6].get('intentHash')==intent_hash
                and hash_value(effects[6].get('nativeEvidenceHash'))
                and hash_value(effects[6].get('authorityEvidenceHash'))
                and effects[-1].get('authorityEvidenceHash')==effects[6]['authorityEvidenceHash'],
                'EXACT_RETAINED_PAUSED_PRE_MIGRATION_OR_UNPAUSE_CHECKPOINT_REQUIRED')
            evidence=self.store.read('ATTEST_NEW_OCI_PEER',effects[6]['nativeEvidenceHash'])
            require(evidence.get('schema')=='ouf.semantic-owner-signed-paused-node-phase.v1'
                and evidence.get('transitionContextHash')==self.transition.context
                and evidence.get('creationRequestHash')==self.request_hash
                and evidence.get('intentHash')==intent_hash
                and evidence.get('completeNativeObservationPerformed')is True
                and evidence.get('currentScopedAcceptanceSignatureVerified')is True,
                'EXACT_RETAINED_PAUSED_ATTESTATION_RECEIPT_REQUIRED')
        return row
    def observe(self):
        row=self.current_row()
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
        if self.retained_checkpoint is not None:self.current_row()
        return {'schema':'ouf.semantic-paused-workload-binding.v1','transitionContextHash':self.transition.context,
                'creationRequestHash':self.request_hash,'stageEvidenceHash':stage[0]['nativeEvidenceHash'],
                'runtimeBinding':binding,'engineState':'paused','ociAccepted':False,'rootfsAccepted':False,
                'peerAccepted':False,'signaturesIssued':0,'startAuthorized':False}
    def verify_runc_state(self,state,observation):
        fresh=self.observe();require(fresh==observation,'PAUSED_WORKLOAD_OBSERVATION_STALE')
        binding=fresh['runtimeBinding']
        require(type(state) is dict and state.get('id')==binding['containerId']
                and state.get('status')=='paused' and state.get('pid')==binding['pid'],
                'EXACT_RUNC_PAUSED_ENGINE_PAUSED_IDENTITY_REQUIRED')
        # Require native paused status; never rewrite it to created. Subsequent complete OCI,
        # rootfs, mount/NIC/peer and signed acceptance checks are mandatory.
        return {'stateContract':'RUNC_PAUSED_ENGINE_PAUSED','containerId':binding['containerId'],
                'pid':binding['pid'],'pausedBindingHash':digest(fresh),'completeCreationAccepted':False}
