"""Signed authority and persistent finite stage engine.

Native ports/issuer/executable closure have separate qualification gates.
This module does not import Engine, OAuth, SQL, key-generation or Gateway ports.
"""
from abc import ABC,abstractmethod
import copy
import json
from pathlib import Path
import time
from tools.ingestion_readiness_patch_execution.contract import AUTHORITY_KEY,READINESS,Denied,Paused,ReadTransient,require,encoded,digest,scope
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from iam_owner_action import publish

class Ports(ABC):
    """Native implementation must independently check HUMAN, DB, owner and generation.

    The native implementation is explicit; this interface discovers no transport.
    Tests also use disposable ports under real fixture role signatures.
    """
    @abstractmethod
    def guard_current(self,stage):raise NotImplementedError
    @abstractmethod
    def apply(self,stage):raise NotImplementedError
    @abstractmethod
    def observe(self,stage):raise NotImplementedError
    def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

class Runner:
    def __init__(self,action,journal,review,ports,clock=lambda:(time.time(),time.monotonic())):
        require(type(action)is AggregateAction and type(journal)is Journal and isinstance(ports,Ports),
                'REAL_SIGNED_AUTHORITY_PRIVATE_JOURNAL_AND_TYPED_PORTS_REQUIRED')
        self.action,self.journal,self.review,self.ports,self.clock=action,journal,copy.deepcopy(review),ports,clock
        self.scope=scope(self.review);self.stages=self.review['stages']
        require(journal.root==Path(self.scope['executionContext']),'SAME_SIGNED_PRIVATE_EXECUTION_CONTEXT_REQUIRED')
        self.expires=json.loads(action.raw)['expiresAt']

    def initialize(self):
        self.action.guard(AUTHORITY_KEY,self.scope);wall,mono=self.clock();remaining=min(900,self.expires-wall)
        require(remaining>0,'CURRENT_FINITE_AUTHORITY_REQUIRED')
        # A second authority/context cannot silently reset the same logical work.
        with protected_directory(self.journal.root.parent)as directory:
            require(publish(directory,'ingestion-readiness-patch-'+self.scope['logicalOperationRef']+'.claim.json',encoded({
                'reviewHash':self.scope['reviewHash'],'authorityHash':self.action.authority_hash,
                'context':str(self.journal.root),'automaticReplayAllowed':False,'budgetReset':False})),
                'LOGICAL_ROLLOUT_ALREADY_CLAIMED_RECONCILE_ONLY')
        self.journal.initialize({'schema':'ouf.ingestion-readiness-patch-finite-journal.v1','scopeHash':digest(self.scope),
            'authorityHash':self.action.authority_hash,'bootId':self.ports.boot(),'version':0,'nextStage':0,'effects':[],
            'createdAt':wall,'expiresAt':wall+remaining,'expiresMonotonic':mono+remaining,'lastWall':wall,'lastMonotonic':mono,
            'readAttempts':0,'stageReadAttempts':0,'readState':'IDLE','nextReadAt':wall,'nextReadMonotonic':mono,
            'budgetReset':False,'incidentState':'OPEN','acceptanceGranted':False})

    def record(self):
        row=self.journal.read();n=row.get('nextStage');effects=row.get('effects',[])
        require(row.get('schema')=='ouf.ingestion-readiness-patch-finite-journal.v1'and row.get('scopeHash')==digest(self.scope)
                and row.get('authorityHash')==self.action.authority_hash and row.get('budgetReset')is False
                and type(n)is int and 0<=n<=len(self.stages)and len(effects)in(n,n+1)
                and all(e['stage']==self.stages[i]['name']and e['intentHash']==self.stages[i]['intentHash']
                        and e['state']==('APPLIED'if i<n else'CLAIMED')for i,e in enumerate(effects))
                and type(row.get('readAttempts'))is int and 0<=row['readAttempts']<=128
                and type(row.get('stageReadAttempts'))is int and 0<=row['stageReadAttempts']<=row['readAttempts']
                and row.get('readState')in('IDLE','ATTEMPTING','RETRY_WAIT','RECONCILE_REQUIRED','EXHAUSTED'),
                'PERSISTENT_ROLLOUT_HISTORY_OR_BUDGET_DRIFT')
        return row

    def guard(self):
        require(scope(self.review)==self.scope,'EXECUTION_REVIEW_CHANGED');self.action.guard(AUTHORITY_KEY,self.scope)
        row=self.record();wall,mono=self.clock()
        require(row['bootId']==self.ports.boot()and wall>=row['lastWall']and mono>=row['lastMonotonic']
                and wall<min(row['expiresAt'],self.expires)and mono<row['expiresMonotonic'],
                'AUTHORITY_EXPIRED_BOOT_OR_CLOCK_DRIFT')
        return row

    def save(self,row,**changes):
        wall,mono=self.clock();following={**row,**changes,'version':row['version']+1,'lastWall':wall,'lastMonotonic':mono}
        self.journal.compare_and_save(row,following);return following

    def check_read_window(self,row,*,reconcile=False):
        wall,mono=self.clock()
        if row['readState']=='EXHAUSTED'or row['readAttempts']>=128:raise Paused('CUMULATIVE_READ_BUDGET_EXHAUSTED')
        if not reconcile and row['readState']in('ATTEMPTING','RECONCILE_REQUIRED'):raise Paused('INTERRUPTED_READ_RECONCILIATION_REQUIRED')
        if wall<row['nextReadAt']or mono<row['nextReadMonotonic']:raise Paused('FINITE_READ_RETRY_WAIT')

    def reserve_read(self,row,*,reconcile=False):
        self.check_read_window(row,reconcile=reconcile)
        return self.save(row,readAttempts=row['readAttempts']+1,stageReadAttempts=row['stageReadAttempts']+1,readState='ATTEMPTING')

    def after_native(self,before):
        """Reload native CAS counters/resources, never accept native progress/reset."""
        after=self.guard()
        require(after['nextStage']==before['nextStage']and len(after['effects'])==len(before['effects'])
                and after['version']>=before['version'],'NATIVE_PORT_CHANGED_RUNNER_PROGRESS')
        for key,value in before.items():
            if key in('version','effects'):continue
            require(key in after,'NATIVE_PORT_REMOVED_PERSISTENT_HISTORY')
            if key.startswith('native')and type(value)is int:
                require(type(after[key])is int and after[key]>=value,'NATIVE_PORT_RESET_CUMULATIVE_COUNTER')
            else:require(encoded(after[key])==encoded(value),'NATIVE_PORT_CHANGED_RUNNER_BUDGET_OR_HISTORY')
        require(all(k.startswith('native')for k in set(after)-set(before)),'UNREVIEWED_NATIVE_JOURNAL_FIELD')
        for index,(old,new)in enumerate(zip(before['effects'],after['effects'])):
            require(all(k in new and encoded(new[k])==encoded(v) for k,v in old.items())
                    and all(k.startswith('native')for k in set(new)-set(old)),
                    'NATIVE_PORT_REWROTE_RETAINED_EFFECT_OR_CLAIM')
            if index<before['nextStage']:require(new==old,'APPLIED_EFFECT_METADATA_IMMUTABLE')
        return after

    def finish(self,row,proof):
        require(type(proof)is dict and proof and len(encoded(proof))<=2048,'BOUNDED_REDACTED_NATIVE_PROOF_REQUIRED')
        effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=proof)
        return self.save(row,effects=effects,nextStage=row['nextStage']+1,stageReadAttempts=0,readState='IDLE',
                         nextReadAt=self.clock()[0],nextReadMonotonic=self.clock()[1])

    def guard_native(self,row,stage,*,reserved=False,reconcile=False):
        try:self.ports.guard_current(stage)
        except ReadTransient as error:
            # Each native component has already persisted its HTTP/SQL attempt.
            # Record this operation-level pause too, without resetting either
            # budget or treating a claimed effect as permission to apply again.
            row=self.after_native(row)
            if not reserved:row=self.reserve_read(row,reconcile=reconcile)
            claimed_effect=stage['kind']=='EFFECT'and len(row['effects'])==row['nextStage']+1
            return self.retry_read(row,{'retryAfterSeconds':error.retry_after_seconds},reconcile_only=claimed_effect)
        return self.after_native(row)

    def observe(self,row,stage,*,reconcile=False):
        row=self.reserve_read(row,reconcile=reconcile);self.guard()
        row=self.guard_native(row,stage,reserved=True,reconcile=reconcile)
        status,proof=self.ports.observe(stage);row=self.after_native(row)
        if status=='APPLIED':return self.finish(row,proof)
        if stage['kind']=='EFFECT'or status!='TRANSIENT':
            self.save(row,readState='RECONCILE_REQUIRED');raise Paused('EFFECT_OR_OBSERVATION_UNPROVEN_NO_REPLAY')
        return self.retry_read(row,proof)

    def retry_read(self,row,proof,*,reconcile_only=False):
        require(type(proof)is dict and type(proof.get('retryAfterSeconds',0))in(int,float),'FINITE_RETRY_AFTER_REQUIRED')
        retry=proof.get('retryAfterSeconds',0);require(0<=retry<float('inf'),'FINITE_NONNEGATIVE_RETRY_AFTER_REQUIRED')
        import hashlib
        attempt=row['stageReadAttempts'];base=READINESS['backoffSeconds'][min(attempt-1,4)]
        jitter=int.from_bytes(hashlib.sha256((self.scope['reviewHash']+str(row['nextStage'])+str(attempt)).encode()).digest()[:2],'big')/65535*.2
        delay=max(retry,base*(1+jitter));wall,mono=self.clock()
        exhausted=row['readAttempts']>=128 or wall+delay>=row['expiresAt']or mono+delay>=row['expiresMonotonic']
        self.save(row,readState='EXHAUSTED'if exhausted else'RECONCILE_REQUIRED'if reconcile_only else'RETRY_WAIT',
                  nextReadAt=wall+delay,nextReadMonotonic=mono+delay)
        if exhausted:raise Paused('FINITE_READ_BUDGET_EXHAUSTED')
        if reconcile_only:raise Paused('CLAIMED_EFFECT_READ_TRANSIENT_RECONCILE_ONLY')
        raise Paused('FINITE_READ_BUDGET_EXHAUSTED'if exhausted else'FINITE_READ_RETRY_WAIT')

    def step(self):
        """One explicit invocation, no background loop or sleeps."""
        with self.journal.invocation():
            row=self.guard();n=row['nextStage']
            if n==len(self.stages):
                if row['incidentState']!='RECOVERED':self.save(row,incidentState='RECOVERED')
                return {'complete':True,'runtimeEffectsAcceptedByPorts':True,'releaseAcceptance':False,
                        'nativeProfilePublished':False,'functionalMilestonesProven':4,'budgetReset':False}
            stage=self.stages[n]
            if len(row['effects'])==n+1 and stage['kind']=='EFFECT':raise Paused('CLAIMED_EFFECT_RECONCILIATION_REQUIRED')
            self.check_read_window(row)
            row=self.guard_native(row,stage)
            wall,mono=self.clock();minimum=210 if stage['name']=='IMPORT_INGESTION_IMAGE'else 45
            if min(row['expiresAt']-wall,row['expiresMonotonic']-mono,self.expires-wall)<minimum:raise Paused('INSUFFICIENT_CURRENT_STAGE_WINDOW')
            if len(row['effects'])==n:
                row=self.save(row,effects=row['effects']+[{'stage':stage['name'],'intentHash':stage['intentHash'],'state':'CLAIMED'}])
            elif stage['kind']=='EFFECT':raise Paused('CLAIMED_EFFECT_RECONCILIATION_REQUIRED')
            if stage['kind']=='EFFECT':
                self.guard();row=self.guard_native(row,stage)
                self.ports.apply(stage)
                # A native port may persist resource identity while the effect
                # remains CLAIMED. Observe against that newest CAS version.
                row=self.after_native(row)
            result=self.observe(row,stage)
            return {'complete':False,'completedStage':stage['name'],'journalVersion':result['version'],'runtimeAuthorityIssued':False}

    def reconcile(self):
        """Observe and close an existing claim only. Never dispatch apply()."""
        with self.journal.invocation():
            row=self.guard();n=row['nextStage']
            require(n<len(self.stages)and len(row['effects'])==n+1,'EXISTING_CLAIM_REQUIRED')
            stage=self.stages[n];self.check_read_window(row,reconcile=True)
            row=self.guard_native(row,stage,reconcile=True)
            result=self.observe(row,stage,reconcile=True)
            return {'reconciledStage':stage['name'],'effectReplayed':False,'journalVersion':result['version']}
