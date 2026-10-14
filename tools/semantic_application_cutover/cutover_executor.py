"""Compose ordered owner adapters with durable effect/reconciliation boundaries.

No CLI, keys, authority issuance, target defaults, retry, wait, restore or reopen.
A sealed installer must authenticate every checkpoint and supply native adapters
for every phase in the signed profile. Fixture checkpoints are never target authority.
"""
import hashlib,json,time
from transition_journal import PHASES,hash_value

class CutoverDenied(RuntimeError):pass

def require(ok,reason):
    if not ok:raise CutoverDenied(reason)

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

class Executor:
    def __init__(self,transition,authority_raw,authenticate,checkpoint,adapters,intents,clock=time.time,*,aggregate_action=None,aggregate_scope=None):
        require(type(authority_raw) is bytes and len(authority_raw)<=131072,'BOUNDED_EXTERNAL_AUTHORITY_REQUIRED')
        self.phases=transition.phases
        self.profile_hash=transition.profile_hash
        self.authority_hash=hashlib.sha256(authority_raw).hexdigest()
        try:self.authority=json.loads(authority_raw)
        except ValueError:raise CutoverDenied('EXTERNAL_AUTHORITY_JSON_REQUIRED') from None
        require(type(self.authority) is dict,'EXTERNAL_AUTHORITY_OBJECT_REQUIRED')
        require(callable(authenticate) and callable(checkpoint),'EXTERNAL_AUTHENTICATION_AND_NATIVE_CHECKPOINTS_REQUIRED')
        require(type(adapters) is dict and type(intents) is dict and set(adapters)==set(intents)==set(self.phases),'ALL_ORDERED_PHASE_ADAPTERS_AND_INTENTS_REQUIRED')
        require(all(callable(getattr(a,'apply',None)) and callable(getattr(a,'observe',None)) for a in adapters.values()),'NATIVE_APPLY_AND_RECONCILE_ADAPTER_REQUIRED')
        self.t,self.raw,self.authenticate,self.checkpoint,self.adapters,self.clock=transition,authority_raw,authenticate,checkpoint,adapters,clock
        # Bind the exact immutable intent for every phase before any effect.
        self.intents={phase:json.loads(json.dumps(intents[phase],allow_nan=False)) for phase in self.phases}
        self.intent_hashes={phase:digest(self.intents[phase]) for phase in self.phases}
        self.aggregate_action,self.aggregate_scope=aggregate_action,aggregate_scope
        if aggregate_action is not None:
            from tools.semantic_policy_token_owner.owner_installation import AggregateAction
            require(type(aggregate_action) is AggregateAction and self.profile_hash is not None
                    and aggregate_action.raw==authority_raw and aggregate_action.authority is authenticate
                    and type(aggregate_scope) is dict,'EXACT_SHARED_AGGREGATE_FILE_AUTHORITY_REQUIRED')
            self.aggregate_scope=json.loads(json.dumps(aggregate_scope,allow_nan=False))
        else:require(aggregate_scope is None,'AGGREGATE_SCOPE_WITHOUT_TYPED_AUTHORITY_DENIED')

    def verify(self,phase,point,row):
        require(set(self.adapters)==set(self.intents)==set(self.phases) and all(digest(self.intents[p])==self.intent_hashes[p] for p in self.phases),'IMMUTABLE_PHASE_ADAPTER_OR_INTENT_DRIFT')
        # The external authenticator must verify the CURRENT signature, policy,
        # revocation and issuer/scope before every native checkpoint/effect.
        require(self.authenticate(self.raw) is True,'CURRENT_EXTERNAL_SIGNATURE_AND_POLICY_REQUIRED')
        require(self.t.phases==self.phases and self.t.profile_hash==self.profile_hash,'CUTOVER_EXECUTOR_PROFILE_DRIFT')
        authority=self.authority;now=self.clock()
        profile_fields=set()
        if self.profile_hash is not None:
            from file_only_profile import PROFILE
            require(self.t.execution_profile.verify(self.intents['CREATE_REPLACEMENT'])==self.profile_hash
                    and authority.get('deploymentProfile')==PROFILE and authority.get('executionProfileHash')==self.profile_hash,
                    'FILE_ONLY_SIGNED_PROFILE_OR_REQUEST_DRIFT')
            profile_fields={'deploymentProfile','executionProfileHash'}
        aggregate_fields=set()
        if self.aggregate_action is not None:
            require(self.aggregate_action.raw==self.raw and self.aggregate_action.authority is self.authenticate
                    and self.aggregate_scope['creationRequestHash']==authority['creationRequestHash']
                    and self.aggregate_scope['executionProfileHash']==self.profile_hash
                    and self.aggregate_scope['sourceClosureHash']==authority['sourceClosureHash']
                    and self.aggregate_scope['phaseIntentHashes']==self.intent_hashes,
                    'AGGREGATE_REGISTRY_SCOPE_DRIFT')
            self.aggregate_action.guard('applicationRegistryCutover',self.aggregate_scope)
            aggregate_fields={'policyTokenOwnerInstallation','policyTokenOutputCustody','policyTokenLegacyRetirement',
                'policyTokenCredentialReestablishment','policyTokenAccountingGapMigration','policyTokenFirstControlledGrant',
                'policyTokenFiniteWorkerSession','tokenOwnerRuntime','applicationCohortInstallation','gatewayRoutePublication',
                'chatbotFileAuthorization','finiteActionProcess','applicationRegistryCutover'}
        require(set(authority)=={'schema','issuedAt','expiresAt','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef','sourceClosureHash','phaseIntentHashes','automaticReplayAllowed','databaseRestoreAuthorized','r12ReplayAuthorized','newDistinctLeaseWorkerRequired'}|profile_fields|aggregate_fields,'EXACT_CUTOVER_AUTHORITY_SCOPE_REQUIRED')
        require(authority['schema']==('ouf.semantic-cutover-execution-authority.v1' if self.profile_hash is None else 'ouf.semantic-cutover-execution-authority.v2'),'EXACT_CUTOVER_AUTHORITY_SCHEMA_REQUIRED')
        require(hash_value(authority['sourceClosureHash']),'SIGNED_SOURCE_CLOSURE_HASH_REQUIRED')
        require(type(authority['issuedAt']) is int and type(authority['expiresAt']) is int and authority['issuedAt']<=now<authority['expiresAt'] and 0<authority['expiresAt']-authority['issuedAt']<=3600,'FINITE_CURRENT_CUTOVER_AUTHORITY_REQUIRED')
        require(authority['phaseIntentHashes']==self.intent_hashes,'SIGNED_PHASE_INTENT_DRIFT')
        require(authority['automaticReplayAllowed'] is False and authority['databaseRestoreAuthorized'] is False and authority['r12ReplayAuthorized'] is False and authority['newDistinctLeaseWorkerRequired'] is (self.profile_hash is None),'CUTOVER_REPLAY_RESTORE_OR_WORKER_POLICY_DRIFT')
        require(self.authority_hash==row['transitionAuthorityEvidenceHash'] and all(authority[k]==row[k] for k in ('creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')),'CUTOVER_AUTHORITY_HISTORY_OR_REQUEST_DRIFT')
        proof=self.checkpoint(phase,point,row)
        # Native custody/command/complete OCI/peer/lease/DB proofs remain owned
        # by the sealed authenticator/checkpoint, not caller-supplied flags.
        require(type(proof) is dict and set(proof)=={'schema','phase','point','journalVersion','intentHash','authorityHash','sourceClosureHash','nativeEvidenceHash'},'EXACT_NATIVE_CHECKPOINT_RECEIPT_REQUIRED')
        require(proof=={**proof,'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,'journalVersion':row['version'],'intentHash':self.intent_hashes[phase],'authorityHash':self.authority_hash,'sourceClosureHash':authority['sourceClosureHash']},'CURRENT_NATIVE_CHECKPOINT_BINDING_DRIFT')
        require(type(proof['nativeEvidenceHash']) is str and len(proof['nativeEvidenceHash'])==64 and all(c in '0123456789abcdef' for c in proof['nativeEvidenceHash']),'NATIVE_CHECKPOINT_EVIDENCE_HASH_REQUIRED')
        return digest(proof)

    def run(self,phase_count=None):
        """Fresh ordered run or native reconciliation; no mutation retransmission.

        An ambiguous native observation remains IN_FLIGHT and stops subsequent
        phases. No-effect remains consumed and requires a new technical decision.
        The dedicated invocation lock is unrelated to the shared network lock.
        """
        if phase_count is None:phase_count=len(self.phases)
        require(type(phase_count) is int and 1<=phase_count<=len(self.phases),'FINITE_ORDERED_PHASE_BOUND_REQUIRED')
        with self.t.invocation():
            while True:
                row=self.t.read()
                if row['state']=='READY' and row['nextPhase']>=phase_count:
                    self.verify(self.phases[row['nextPhase']-1],'PARTIAL_CHECKPOINT_READ_ONLY',row)
                    return self.report(row)
                if row['state']=='COMPLETED':
                    # A repeated completed invocation still authenticates the
                    # current external authority, but cannot replay any effect.
                    self.verify(self.phases[-1],'COMPLETED_READ_ONLY',row)
                    return self.report(row)
                require(row['state'] in {'READY','IN_FLIGHT'},'CONSUMED_NO_EFFECT_REQUIRES_NEW_TECHNICAL_DECISION')
                phase=self.phases[row['nextPhase']];intent_hash=self.intent_hashes[phase]
                if row['state']=='IN_FLIGHT':
                    require(row['effects'][-1]['intentHash']==intent_hash,'IN_FLIGHT_INTENT_DRIFT')
                    self.verify(phase,'BEFORE_NATIVE_RECONCILIATION',row)
                    outcome,evidence=self.adapters[phase].observe(json.loads(json.dumps(self.intents[phase])))
                    require(outcome in {'APPLIED','NO_EFFECT','UNKNOWN'},'EXACT_NATIVE_OUTCOME_REQUIRED')
                    self.verify(phase,'AFTER_NATIVE_RECONCILIATION',self.t.read())
                    row=self.t.reconcile(phase,intent_hash,outcome,digest(evidence),row['version'])
                    require(outcome=='APPLIED','NATIVE_AMBIGUITY_OR_NO_EFFECT_STOPS_CUTOVER')
                    continue
                self.verify(phase,'BEFORE_DURABLE_INTENT',row)
                row=self.t.begin(phase,intent_hash,self.authority_hash,row['version'])
                self.verify(phase,'BEFORE_NATIVE_EFFECT',row)
                self.adapters[phase].apply(json.loads(json.dumps(self.intents[phase])))
                # Successful return alone is insufficient: independently read
                # the exact native effect before recording its completion.
                outcome,evidence=self.adapters[phase].observe(json.loads(json.dumps(self.intents[phase])))
                require(outcome in {'APPLIED','NO_EFFECT','UNKNOWN'},'EXACT_NATIVE_OUTCOME_REQUIRED')
                self.verify(phase,'AFTER_NATIVE_EFFECT',self.t.read())
                row=self.t.reconcile(phase,intent_hash,outcome,digest(evidence),row['version'])
                require(outcome=='APPLIED','NATIVE_AMBIGUITY_OR_NO_EFFECT_STOPS_CUTOVER')

    @staticmethod
    def report(row):
        result={'schema':'ouf.semantic-cutover-executor-receipt.v1','status':'ORDERED_NATIVE_PHASES_COMPLETED_NOT_RELEASE_ACCEPTANCE' if row['state']=='COMPLETED' else 'ORDERED_PARTIAL_CHECKPOINT_NOT_RELEASE_ACCEPTANCE','contextHash':row['contextHash'],'version':row['version'],'completedPhaseCount':row['nextPhase'],'databaseMayHaveChanged':row['databaseMayHaveChanged'],'applicationWritesMayHaveOccurred':row['applicationWritesMayHaveOccurred'],'automaticReplayAllowed':False,'preMigrationRestoreAllowed':False,'releaseAcceptance':False}
        if row['schema']=='ouf.semantic-cutover-journal.v2':
            result.update(schema='ouf.semantic-cutover-executor-receipt.v2',deploymentProfile=row['deploymentProfile'],executionProfileHash=row['executionProfileHash'])
        return result

