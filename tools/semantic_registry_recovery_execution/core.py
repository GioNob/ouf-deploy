"""Finite recovery dispatch and durable claims; not a native runtime entrypoint.

Native Ports (current authority, owners, paused OCI and exact generation) must
be implemented and qualified separately. No permissive adapter or CLI exists.
"""
from abc import ABC,abstractmethod
from contextlib import contextmanager
import copy,fcntl,hashlib,json,math,os,re,stat,tempfile,time
from pathlib import Path

class RecoveryDenied(RuntimeError):pass
def require(ok,reason):
    if not ok:raise RecoveryDenied(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def hashed(v):return type(v) is str and re.fullmatch('[a-f0-9]{64}',v) is not None

ORDER=(('VERIFY_CURRENT_GATES','READ'),('START_NEW_WAIT_GATE','EFFECT'),
       ('VERIFY_NEW_WAIT_GENERATION','READ'),('PAUSE_NEW_WAIT_GATE','EFFECT'),
       ('VERIFY_PAUSED_OCI_AND_MOUNTS','READ'),('ATTEST_NEW_GENERATION','EFFECT'),
       ('VERIFY_CURRENT_ADMISSION','READ'),('UNPAUSE_ATTESTED_GENERATION','EFFECT'),
       ('VERIFY_UNPAUSED_SAME_GATE','READ'),('RELEASE_SAME_GENERATION_SIGUSR1','EFFECT'),
       ('VERIFY_APPLICATION_READINESS','READ'),('VERIFY_FINAL','READ'))

def validate_plan(plan):
    require(type(plan) is dict and plan.get('schema')=='ouf.semantic-registry-gated-recovery-candidate-contract.v1'
            and hashed(plan.get('logicalOperationRef')) and hashed(plan.get('retainedPredecessorIncidentRef')),
            'EXACT_REGISTRY_RECOVERY_PLAN_REQUIRED')
    require([(r['name'],r['kind']) for r in plan['stages']]==list(ORDER),'EXACT_SPLIT_RECOVERY_STAGE_ORDER_REQUIRED')
    registry_ids=set();proposals=set();histories=set()
    for index,row in enumerate(plan['stages']):
        intent=row['intent']
        require(set(row)=={'name','kind','maximumEffectAttempts','intent','intentHash'}
                and digest(intent)==row['intentHash'] and row['maximumEffectAttempts']==int(row['kind']=='EFFECT')
                and set(intent)=={'logicalOperationRef','stage','registryId','proposalHash','historicalChainHash',
                                  'newGenerationMustComeFromDurableStartEvidence'}
                and intent['logicalOperationRef']==plan['logicalOperationRef'] and intent['stage']==row['name']
                and all(hashed(intent[k]) for k in ('registryId','proposalHash','historicalChainHash'))
                and intent['newGenerationMustComeFromDurableStartEvidence'] is (index>1),
                'EXACT_RECOVERY_STAGE_INTENT_REQUIRED')
        registry_ids.add(intent['registryId']);proposals.add(intent['proposalHash']);histories.add(intent['historicalChainHash'])
    require(len(registry_ids)==len(proposals)==len(histories)==1,'SAME_RECOVERY_SCOPE_AT_EVERY_STAGE_REQUIRED')
    logical=digest({'operation':'REGISTRY_FRESH_GATED_GENERATION_RECOVERY','registryId':next(iter(registry_ids)),
                    'proposalHash':next(iter(proposals)),'historyHash':next(iter(histories))})
    require(logical==plan['logicalOperationRef'],'RECOVERY_LOGICAL_SCOPE_CHANGED')
    for key in ('newRuntimeBudgetGranted','newOAuthBudgetProposed','incidentCauseEquivalenceEstablished',
                'oldAttestationOrGenerationAdoptionAllowed','effectRetryAllowed','providerRecoveryAllowed',
                'gatewayWritesAllowed','databaseMigrationAllowed','automaticAuthenticationAllowed',
                'sourceActivationAllowed','nativeExecutorQualified','runtimeAuthorityIssued','targetApplyAuthorized',
                'automaticReplayAllowed','budgetReset'):
        require(plan.get(key) is False,'PLAN_CANNOT_GRANT_OR_ADOPT_AUTHORITY')
    require(plan.get('existingClaimsRemainConsumed') is True and plan.get('claimedEffectReadOnlyReconciliationRequired') is True
            and plan.get('persistentRecoveryIncidentRequired') is True
            and plan.get('cumulativeOAuthHistoryMustBePreserved') is True
            and plan.get('maximumRuntimeSecondsProposed')==900 and plan.get('maximumReadAttemptsProposed')==128,
            'RETAINED_HISTORY_AND_PROPOSED_LIMITS_REQUIRED')
    return digest(plan)

def generation(value):
    require(type(value) is dict and set(value)=={'containerId','bootId','pid','startTicks','namespaceDevice','namespaceInode'}
            and hashed(value['containerId']) and type(value['bootId']) is str
            and re.fullmatch('[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',value['bootId'])
            and all(type(value[k]) is int and value[k]>0 for k in ('pid','startTicks','namespaceDevice','namespaceInode'))
            and value['pid']>1,'EXACT_FRESH_PROCESS_GENERATION_REQUIRED')
    return value

class Ports(ABC):
    """No production implementation is provided by this dispatch library.

    guard must authenticate the complete CURRENT signed authority and owners at
    every boundary; observe must obtain native evidence. Neither a dictionary
    of passed booleans nor this abstract API is a qualified runtime gate.
    """
    @abstractmethod
    def guard(self,plan,row,stage):pass
    @abstractmethod
    def apply(self,plan,row,stage):pass
    @abstractmethod
    def observe(self,plan,row,stage):pass

class Store:
    """Root-only fixed scope directory; independent short CAS and invocation locks.

    No method creates a new session/authority, resets a budget or overwrites an
    existing initialization. Native installer must create this exact scope path.
    """
    def __init__(self,root,logical):
        require(hashed(logical),'EXACT_LOGICAL_OPERATION_REQUIRED')
        self.root=Path(root);self.logical=logical
        require(self.root.is_absolute() and self.root.name=='semantic-registry-recovery-'+logical
                and '..' not in self.root.parts,'FIXED_RECOVERY_SCOPE_DIRECTORY_REQUIRED')
        for p in [self.root,*self.root.parents]:
            s=p.lstat();require(p.resolve()==p and stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,
                                'ROOT_CONTROLLED_RECOVERY_ANCESTRY_REQUIRED')
        s=self.root.lstat();require(stat.S_IMODE(s.st_mode)==0o700,'PRIVATE_RECOVERY_ROOT_REQUIRED')
        self.identity=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)
    def check(self):
        s=self.root.lstat();require((s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)==self.identity,
                                   'RECOVERY_DIRECTORY_CHANGED')
    @contextmanager
    def lock(self,name):
        self.check();require(name in ('cas.lock','invocation.lock'),'CLOSED_RECOVERY_LOCK_REQUIRED')
        fd=os.open(self.root/name,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1
                    and stat.S_IMODE(s.st_mode)==0o600,'PRIVATE_RECOVERY_LOCK_REQUIRED')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise RecoveryDenied('CONCURRENT_RECOVERY_COMMAND') from None
            self.check();yield
        finally:os.close(fd)
    def read(self):
        self.check();fd=os.open(self.root/'recovery.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1
                    and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=1048576,'BOUNDED_PRIVATE_RECOVERY_JOURNAL_REQUIRED')
            raw=bytearray()
            while len(raw)<=s.st_size:
                block=os.read(fd,min(65536,s.st_size+1-len(raw)))
                if not block:break
                raw.extend(block)
            pin=lambda i:(i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
            require(len(raw)==s.st_size and pin(s)==pin(os.fstat(fd))==pin((self.root/'recovery.json').lstat()),
                    'RECOVERY_JOURNAL_CHANGED_DURING_READ')
            def unique(rows):
                result={}
                for key,value in rows:
                    require(key not in result,'DUPLICATE_RECOVERY_JSON_KEY');result[key]=value
                return result
            value=json.loads(raw,object_pairs_hook=unique)
            require(value['logicalOperationRef']==self.logical,'JOURNAL_SCOPE_CHANGED');return value
        finally:os.close(fd)
    def _write(self,value,*,initialize=False):
        self.check();raw=encoded(value);require(len(raw)<=1048576,'RECOVERY_JOURNAL_SIZE_BOUND')
        fd,name=tempfile.mkstemp(prefix='.pending-',dir=self.root)
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(os.dup(fd),'wb') as output:output.write(raw);output.flush();os.fsync(output.fileno())
            os.fsync(fd)
            if initialize:
                try:os.link(name,self.root/'recovery.json',follow_symlinks=False)
                except FileExistsError:raise RecoveryDenied('EXISTING_RECOVERY_CLAIMS_MUST_BE_PRESERVED') from None
            else:os.replace(name,self.root/'recovery.json')
            directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        finally:
            os.close(fd)
            if os.path.lexists(name):os.unlink(name)
    def initialize(self,value):
        require(value['logicalOperationRef']==self.logical and value['version']==0,'EXACT_INITIAL_RECOVERY_SCOPE_REQUIRED')
        with self.lock('cas.lock'):self._write(value,initialize=True)
    def cas(self,before,after):
        require(after['logicalOperationRef']==before['logicalOperationRef']==self.logical
                and after['version']==before['version']+1,'ORDERED_RECOVERY_CAS_REQUIRED')
        with self.lock('cas.lock'):
            require(self.read()==before,'STALE_RECOVERY_WORKER');self._write(after)

def initial(plan,*,authority_hash,expires_unix,expires_monotonic,boot_id,predecessor_history_hash,
            created_unix,created_monotonic):
    """Pure proposed journal value. Caller independently verifies fresh authority.

    Creating this value never grants a window, budget, identity or effect.
    """
    plan_hash=validate_plan(plan)
    require(hashed(authority_hash) and hashed(predecessor_history_hash)
            and all(type(t) in (int,float) and math.isfinite(t) for t in
                    (created_unix,created_monotonic,expires_unix,expires_monotonic))
            and 0<expires_unix-created_unix<=900 and 0<expires_monotonic-created_monotonic<=900,
            'EXACT_FRESH_AUTHORITY_AND_RETAINED_HISTORY_REQUIRED')
    return {'schema':'ouf.semantic-registry-recovery-journal.v1','logicalOperationRef':plan['logicalOperationRef'],
        'planHash':plan_hash,'predecessorIncidentRef':plan['retainedPredecessorIncidentRef'],
        'predecessorHistoryHash':predecessor_history_hash,'authorityHash':authority_hash,
        'expiresUnix':expires_unix,'expiresMonotonic':expires_monotonic,'bootId':boot_id,
        'createdUnix':created_unix,'createdMonotonic':created_monotonic,
        'lastUnix':created_unix,'lastMonotonic':created_monotonic,
        'version':0,'nextStage':0,'effects':[],'readAttempts':0,'maximumReadAttempts':128,
        'newGeneration':None,'state':'READY','budgetReset':False,'automaticReplayAllowed':False,
        'releaseAcceptance':False,'originalSemanticGetSucceeded':False}

class Runner:
    def __init__(self,plan,store,ports,*,boot_id,clock=lambda:(time.time(),time.monotonic())):
        require(type(store) is Store and isinstance(ports,Ports),'TYPED_RECOVERY_STORE_AND_PORTS_REQUIRED')
        self.plan=copy.deepcopy(plan);self.plan_hash=validate_plan(plan)
        require(store.logical==plan['logicalOperationRef'],'SAME_RECOVERY_PLAN_STORE_REQUIRED')
        self.store,self.ports,self.boot_id,self.clock=store,ports,boot_id,clock
    def current(self):
        require(validate_plan(self.plan)==self.plan_hash,'RECOVERY_PLAN_CHANGED')
        row=self.store.read();wall,mono=self.clock()
        require(row['schema']=='ouf.semantic-registry-recovery-journal.v1' and row['planHash']==self.plan_hash
                and row['bootId']==self.boot_id and wall<row['expiresUnix'] and mono<row['expiresMonotonic']
                and wall>=row['lastUnix']>=row['createdUnix'] and mono>=row['lastMonotonic']>=row['createdMonotonic']
                and 0<row['expiresUnix']-row['createdUnix']<=900
                and 0<row['expiresMonotonic']-row['createdMonotonic']<=900
                and row['budgetReset'] is False and row['automaticReplayAllowed'] is False
                and row['predecessorIncidentRef']==self.plan['retainedPredecessorIncidentRef'],
                'CURRENT_FINITE_RECOVERY_SCOPE_REQUIRED')
        cursor=row['nextStage'];effects=row['effects']
        require(type(cursor) is int and 0<=cursor<=len(ORDER) and type(effects) is list
                and len(effects) in (cursor,cursor+1) and (cursor<len(ORDER) or len(effects)==cursor),
                'ORDERED_RECOVERY_JOURNAL_REQUIRED')
        for i,effect in enumerate(effects):
            stage=self.plan['stages'][i]
            require(effect['stage']==stage['name'] and effect['intentHash']==stage['intentHash']
                    and effect['authorityHash']==row['authorityHash']
                    and effect['state']==('APPLIED' if i<cursor else 'CLAIMED'),'SCOPED_DURABLE_RECOVERY_CLAIMS_REQUIRED')
            if i<cursor:
                require(type(effect['nativeEvidence']) is dict and effect['nativeEvidenceHash']==digest(effect['nativeEvidence']),
                        'RECOVERY_NATIVE_EVIDENCE_CHANGED')
        require(row['maximumReadAttempts']==128 and type(row['readAttempts']) is int
                and 0<=row['readAttempts']<=128,'FINITE_CUMULATIVE_RECOVERY_READ_BUDGET_REQUIRED')
        require(row['state']==('COMPLETED' if cursor==len(ORDER) else 'IN_FLIGHT' if len(effects)>cursor else 'READY'),
                'EXACT_RECOVERY_STATE_REQUIRED')
        if cursor>=2:
            generation(row['newGeneration'])
            start=effects[1]['nativeEvidence']
            require(row['newGeneration']['containerId']==self.plan['stages'][0]['intent']['registryId']
                    and start['newGeneration']==row['newGeneration'] and start['durableNativeStartEvidence'] is True,
                    'DURABLE_NEW_GENERATION_REQUIRED')
        else:require(row['newGeneration'] is None,'NO_HISTORICAL_GENERATION_ADOPTION')
        return row
    def save(self,before,**changes):
        value=copy.deepcopy(before);value.update(changes,version=before['version']+1)
        value['lastUnix'],value['lastMonotonic']=self.clock()
        self.store.cas(before,value);return value
    def step(self):
        # Only one stage per invocation. No retries/sleeps/renewals; a CLAIMED
        # effect follows the observation path forever, regardless of exceptions.
        with self.store.lock('invocation.lock'):
            row=self.current();index=row['nextStage']
            if index==len(ORDER):return row
            require(row['readAttempts']<128,'RECOVERY_READ_BUDGET_EXHAUSTED')
            stage=self.plan['stages'][index]
            self.ports.guard(self.plan,row,stage);require(self.current()==row,'RECOVERY_CHANGED_DURING_GUARD')
            new=len(row['effects'])==index
            if new:
                effects=copy.deepcopy(row['effects']);effects.append({'stage':stage['name'],'intentHash':stage['intentHash'],
                    'authorityHash':row['authorityHash'],'state':'CLAIMED','nativeEvidence':None})
                row=self.save(row,effects=effects,state='IN_FLIGHT')
            if new and stage['kind']=='EFFECT':
                self.ports.guard(self.plan,row,stage);require(self.current()==row,'RECOVERY_CHANGED_BEFORE_EFFECT')
                # Ports must durably fence each underlying native request or
                # signature BEFORE dispatch, and never transmit it twice.
                self.ports.apply(self.plan,row,stage)
            row=self.current();self.ports.guard(self.plan,row,stage)
            require(self.current()==row and row['readAttempts']<128,'RECOVERY_READ_BUDGET_EXHAUSTED')
            row=self.save(row,readAttempts=row['readAttempts']+1)
            state,proof=self.ports.observe(self.plan,row,stage)
            require(state in ('APPLIED','UNKNOWN') and type(proof) is dict and len(encoded(proof))<=131072,
                    'BOUNDED_NATIVE_RECOVERY_OBSERVATION_REQUIRED')
            self.ports.guard(self.plan,row,stage);require(self.current()==row,'RECOVERY_CHANGED_DURING_OBSERVATION')
            if state!='APPLIED':return row
            changes={}
            if stage['name']=='START_NEW_WAIT_GATE':
                fresh=generation(proof['newGeneration'])
                require(fresh['containerId']==stage['intent']['registryId'] and proof.get('durableNativeStartEvidence') is True,
                        'DURABLE_FRESH_START_EVIDENCE_REQUIRED_NO_PID_ADOPTION')
                changes['newGeneration']=fresh
            elif index>1:
                require(proof.get('newGeneration')==row['newGeneration'],'SAME_NEW_GENERATION_REQUIRED')
            if stage['name']=='VERIFY_FINAL':
                require(proof.get('originalSemanticGetSucceeded') is True and proof.get('httpStatus')==200,
                        'ORIGINAL_SEMANTIC_GET_MUST_BE_VERIFIED')
                changes['originalSemanticGetSucceeded']=True
            effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',nativeEvidence=copy.deepcopy(proof),
                                                                   nativeEvidenceHash=digest(proof))
            return self.save(row,effects=effects,nextStage=index+1,state='COMPLETED' if index+1==len(ORDER) else 'READY',**changes)
