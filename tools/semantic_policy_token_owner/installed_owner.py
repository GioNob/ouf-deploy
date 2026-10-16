"""Concrete installed-owner guard; no source/credential/budget initialization.

Uses existing finite HUMAN + two role-framed signatures for infrastructure scope,
and the existing issuer's online admission for IAM validity. Deployment signatures
do not create IAM permissions. Source bytes, owner binding, legacy writer fence
and retained operation/generation are required on every dependent step.
"""
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid
from cutover_authority import CutoverAuthority
from tools.semantic_lease_recovery.bounded_recovery import Permanent,Temporary,fingerprint
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import Binding,CredentialFile,DomainOwner,protected_directory,identity,check
from tools.semantic_policy_token_owner.iam_admission import OnlineIamAdmission,unique
from tools.semantic_policy_token_owner.source_stage import declaration,FILES,stage_authority_matches

GOVERNED_SESSION='ouf.policy-token-governed-worker-session.v1'
GOVERNED_HISTORY='ouf.policy-token-governed-worker-continuation.v1'

def compile_governed_session(review,records,first,policy,context,generation,interval):
    """Pure scope compiler. Its result requires a fresh typed HUMAN authority.

    Counts derive from bound retained records, never from a schema suffix.
    Legacy, unknown earlier accounting remains explicitly unreconciled.
    """
    check(type(review)is dict and review.get('schema')=='ouf.chatbot-semantic-functional-session-review.v1'
        and review.get('readyForExecution')is False and review.get('runtimeAuthorityIssued')is False
        and review.get('humanApprovalGranted')is False)
    required={'recovery.json','owner-session.json','owner-admission.json','owner-status.json'}
    check(type(records)is dict and set(records)==required
        and {k:fingerprint(v)for k,v in records.items()}==review.get('predecessorRecordHashes'))
    old=records['recovery.json'];session=records['owner-session.json'];admission=records['owner-admission.json']
    prior=old.get('controlledCumulativeGrantAttempts');count=old.get('attempts');base=old.get('controlledPredecessorGrantAttempts')
    check(type(prior)is int and type(count)is int and type(base)is int and
        0<=count<=128 and 1<=base<=prior<=1000000 and prior==base+count
        and old.get('state')=='CANCELLED'and old.get('reason')=='CANCELLED_BY_OWNER'
        and admission.get('state')=='BLOCKED'and old.get('workerSessionHash')==fingerprint(session)
        and session.get('predecessorGrantAttempts')==base
        and session.get('schema') in (GOVERNED_SESSION,'ouf.policy-token-new-finite-worker-session.v'+str(base))
        and old.get('policyHash')==fingerprint(session.get('policy'))
        and old.get('contextRef')==session.get('contextRef')and old.get('generationRef')==session.get('generationRef'))
    legacy={'state':'UNKNOWN','cumulativeGrantAttemptCount':None,'reconciled':False,'gapRemainsOpen':True}
    check(old.get('legacyHistory')==legacy and fingerprint(first)==old.get('firstGrantReceiptHash')
        and first.get('state')=='TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED'
        and first.get('attemptSlotsConsumed')==1 and first.get('gapRemainsOpen')is True
        and first.get('historicalAccountingReconciled')is False
        and first.get('legacyHistoricalGrantAttempts')is None
        and first.get('operation')==session.get('predecessorFirstGrantOperation')
        and first.get('scopeHash')==session.get('predecessorFirstGrantScopeHash')
        and first.get('bootId')==old.get('bootId'))
    budget=review.get('proposedFiniteBudget');decision=review.get('requiredOwnerDecision')
    check(type(budget)is dict and budget.get('priorControlledGrantAttempts')==prior
        and budget.get('predecessorWorkerAttempts')==count
        and budget.get('maximumNewTokenGrantAttempts')==128
        and budget.get('maximumCumulativeGrantAttempts')==prior+128
        and budget.get('maximumSeconds')==3600 and budget.get('renewalIntervalSeconds')==interval==60
        and budget.get('automaticRenewalAllowed')is False
        and decision.get('explicitContinuationAfterOwnerCancellationRequired')is True
        and decision.get('freshAuthenticatedHumanDecisionRequired')is True)
    check(type(policy)is dict and set(policy)=={'delays','max_attempts','max_elapsed','attempt_timeout','jitter'}
        and policy['delays']==[5,15,60,300,900]and type(policy['max_attempts'])is int
        and 1<=policy['max_attempts']<=128 and type(policy['max_elapsed'])is int
        and type(policy['attempt_timeout'])is int
        and 1<=policy['attempt_timeout']<=policy['max_elapsed']<=3600 and policy['jitter']==.2)
    check(all(type(x)is str and len(x)==64 and all(c in '0123456789abcdef'for c in x)
        for x in(context,generation,session.get('logicalOwnerScopeHash',''))))
    predecessor=Path(review.get('predecessorJournalDirectory',''))
    check(predecessor.is_absolute()and str(predecessor)==review['predecessorJournalDirectory']
        and '..'not in predecessor.parts and predecessor!=Path('/')
        and decision.get('newJournalAndPersistentFencingRequired')is True)
    parent=predecessor.parent;logical=session['logicalOwnerScopeHash'];review_hash=fingerprint(review)
    journal=str(parent/('semantic-functional-worker-'+review_hash))
    fence={'path':str(parent/('semantic-functional-session-'+logical+'.fence.json')),
        'value':{'schema':'ouf.semantic-functional-session-fence.v1','logicalOwnerScopeHash':logical,
            'reviewHash':review_hash,'journalPath':journal,'predecessorWorkerHash':fingerprint(old),'active':True}}
    return {'schema':GOVERNED_SESSION,'controlledHistoryProfile':GOVERNED_HISTORY,
        'operation':'OPEN_NEW_FINITE_WORKER_AFTER_EXPLICIT_CANCELLED_PREDECESSOR_REVIEW',
        'reviewHash':fingerprint(review),'predecessorRecordHashes':copy.deepcopy(review['predecessorRecordHashes']),
        'predecessorGrantAttempts':prior,'maximumCumulativeGrantAttempts':prior+policy['max_attempts'],
        'logicalOwnerScopeHash':session['logicalOwnerScopeHash'],
        'predecessorFirstGrantOperation':first['operation'],'predecessorFirstGrantScopeHash':first['scopeHash'],
        'firstGrantReceiptHash':fingerprint(first),'contextRef':context,'generationRef':generation,
        'policy':copy.deepcopy(policy),'intervalSeconds':interval,
        'requestedHumanActor':copy.deepcopy(review['requestedHumanActor']),
        'fenceBinding':fence,
        'commandKey':review['commandKey'],'proposalHash':review['proposalHash'],
        'automaticBudgetRenewalAllowed':False,'consumedClaimReplayAllowed':False,
        'legacyHistoryDisposition':'UNKNOWN_RETAINED_NOT_RECONCILED'}

def read_private(directory,name,limit):
    s=os.stat(name,dir_fd=directory,follow_symlinks=False)
    check(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
          and s.st_nlink==1 and 0<s.st_size<=limit)
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        check(identity(s)==identity(os.fstat(fd)));raw=os.read(fd,limit+1)
        check(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))
              ==identity(os.stat(name,dir_fd=directory,follow_symlinks=False)))
        return raw
    finally:os.close(fd)

class AdmissionStore:
    """Scoped marker in the EXISTING owner journal; no new incident authority."""
    def __init__(self,journal,profile_hash,context_ref,generation_ref):
        check(type(journal) is Journal)
        self.journal=journal;self.expected={'ownerProfileHash':profile_hash,'contextRef':context_ref,'generationRef':generation_ref}
        self.read() # Installer must supply an existing admission record. Never create it here.
    def decode(self,raw):
        value=json.loads(raw,object_pairs_hook=unique)
        fields={'schema',*self.expected,'version','state','tokenHash','blockedAttempt'}
        check(type(value) is dict and set(value)==fields and value['schema']=='ouf.policy-token-owner-admission.v1'
              and all(value[k]==v for k,v in self.expected.items())
              and type(value['version']) is int and value['version']>=0
              and value['state'] in ('ACTIVE','BLOCKED')
              and (value['blockedAttempt'] is None or (type(value['blockedAttempt']) is int and value['blockedAttempt']>=0))
              and (value['tokenHash'] is None or (type(value['tokenHash']) is str and len(value['tokenHash'])==64
                   and all(c in '0123456789abcdef' for c in value['tokenHash'])))
              and (value['state']!='ACTIVE' or value['tokenHash'] is not None))
        return value
    def read(self):
        with protected_directory(self.journal.root) as directory:
            self.journal.check_directory();return self.decode(read_private(directory,'owner-admission.json',4096))
    def save(self,expected,state,token_hash=None,blocked_attempt=None):
        with protected_directory(self.journal.root) as directory:
            self.journal.check_directory()
            fd=os.open('owner-admission.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            try:
                s=os.fstat(fd);check(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1)
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                named=os.stat('owner-admission.lock',dir_fd=directory,follow_symlinks=False)
                check(identity(s)==identity(named))
                current=self.decode(read_private(directory,'owner-admission.json',4096))
                if current!=expected:raise Permanent('GENERATION_CHANGED')
                value={**current,'version':current['version']+1,'state':state,'tokenHash':token_hash,'blockedAttempt':blocked_attempt}
                raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();self.decode(raw)
                name='.owner-admission-'+uuid.uuid4().hex
                out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
                try:
                    position=0
                    while position<len(raw):position+=os.write(out,raw[position:])
                    os.fsync(out);check(identity(os.fstat(fd))==identity(os.stat('owner-admission.lock',dir_fd=directory,follow_symlinks=False)));check(self.decode(read_private(directory,'owner-admission.json',4096))==expected)
                    os.replace(name,'owner-admission.json',src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
                    check(identity(os.fstat(out))==identity(os.stat('owner-admission.json',dir_fd=directory,follow_symlinks=False)))
                finally:
                    os.close(out)
                    try:os.unlink(name,dir_fd=directory)
                    except FileNotFoundError:pass
                return value
            finally:os.close(fd)

class LegacyWriterFence:
    """Read only the two previously identified units. Never mask/stop them here."""
    UNITS=('ouf-policy-token@semantic.service','ouf-policy-token@semantic.timer')
    @staticmethod
    def quiescent(rows,units):
        # Keep the standalone worker closure independent of installer modules.
        # Contract tests compare this predicate with the retirement component.
        return set(rows)==set(units) and all(row.get('LoadState')=='masked'
            and row.get('UnitFileState')=='masked' and row.get('Job')==''
            and (row.get('ActiveState'),row.get('SubState')) in (
                {('inactive','dead'),('failed','failed')} if unit.endswith('.timer') else {('inactive','dead')})
            and row.get('MainPID','0' if unit.endswith('.timer') else None)=='0'
            for unit,row in rows.items())
    def read_units(self):
        props={'Id','LoadState','ActiveState','SubState','UnitFileState','MainPID','Job'}
        p=subprocess.run(['/usr/bin/systemctl','show',*self.UNITS,'--no-pager',
            '--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,Job'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        check(p.returncode==0 and 0<len(p.stdout)<=8192)
        rows={}
        for block in p.stdout.decode('ascii').strip().split('\n\n'):
            value={}
            for line in block.splitlines():
                key,sep,item=line.partition('=');check(sep and key in props and key not in value);value[key]=item
            check(props-{'MainPID'}<=set(value)<=props and value['Id'] in self.UNITS and value['Id'] not in rows)
            rows[value['Id']]=value
        check(set(rows)==set(self.UNITS))
        return rows
    def guard(self):
        check(self.quiescent(self.read_units(),self.UNITS));return True

def owner_binding_inputs(binding,credential,admission,journal,context_ref,generation_ref,policy_hash,renewal_profile,interval_seconds,worker_session_hash=None):
    check(type(binding) is Binding and type(credential) is CredentialFile and type(admission) is OnlineIamAdmission
          and admission.credential.path==credential.path and type(journal) is Journal)
    admission.profile.match(binding)
    value={'schema':'ouf.installed-policy-token-owner-binding.v1','binding':binding.__dict__,
            'iamProfile':admission.profile.__dict__,'tlsTrustHash':admission.transport.trust_digest(),
            'journalPolicyHash':policy_hash,'renewalProfile':renewal_profile,
            'intervalSeconds':interval_seconds,'credentialPath':str(credential.path),'journalPath':str(journal.root),
            'journalDirectoryIdentity':{'device':journal.directory_id[0],'inode':journal.directory_id[1]},
            'contextRef':context_ref,'generationRef':generation_ref,'legacyUnits':list(LegacyWriterFence.UNITS)}
    if worker_session_hash is not None:value['workerSessionHash']=worker_session_hash
    return value

def owner_binding(binding,credential,admission,journal,context_ref,generation_ref):
    row=journal.read()
    return owner_binding_inputs(binding,credential,admission,journal,context_ref,generation_ref,
        row.get('policyHash'),row.get('renewalProfile'),row.get('intervalSeconds'),row.get('workerSessionHash'))

class InstalledTokenOwner(DomainOwner):
    def __init__(self,binding,credential,admission,journal,context_ref,generation_ref,manifest,authority,authority_raw,*,observer=False):
        check(type(authority) is CutoverAuthority and type(authority_raw) is bytes and type(observer) is bool)
        self.configuration=copy.deepcopy(owner_binding(binding,credential,admission,journal,context_ref,generation_ref))
        self.profile_hash=fingerprint(self.configuration)
        check(type(manifest) is dict and manifest.get('ownerBindingHash')==self.profile_hash
              and manifest.get('preparationProfile')=='ouf.policy-token-protected-source-stage.v2'
              and set(manifest.get('fileHashes',{}))==FILES
              and stage_authority_matches(authority,authority_raw,manifest))
        scope=json.loads(authority_raw,object_pairs_hook=unique).get('tokenOwnerRuntime')
        check(scope=={'ownerBindingHash':self.profile_hash,'operation':'RENEW_EXISTING_POLICY_READ_CREDENTIAL',
                     'legacyWriterMustBeMasked':True,'credentialReestablishmentRequired':True,'automaticBudgetResetAllowed':False})
        self.binding,self.credential,self.admission,self.journal=binding,credential,admission,journal
        self.context,self.generation=context_ref,generation_ref
        declaration(manifest.get('destination'),manifest.get('sourceCommit'),{name:b'pass' for name in manifest.get('fileHashes',{})},directory_identity=manifest.get('directoryIdentity'),owner_binding_hash=self.profile_hash)
        self.manifest=copy.deepcopy(manifest);self.closure=fingerprint(manifest)
        self.authority,self.raw,self.observer=authority,bytes(authority_raw),observer
        self.store=AdmissionStore(journal,self.profile_hash,context_ref,generation_ref);self.fence=LegacyWriterFence()
    def source_guard(self):
        m=self.manifest;root=Path(m['destination'])/('semantic-native-v11-intake-'+self.closure)
        files={}
        with protected_directory(m['destination']) as parent,protected_directory(root) as directory:
            info=os.fstat(parent);check(m['directoryIdentity']=={'device':info.st_dev,'inode':info.st_ino})
            check(set(os.listdir(directory))==set(m['fileHashes'])|{'intake.json'})
            check(json.loads(read_private(directory,'intake.json',65536),object_pairs_hook=unique)==m)
            for name,expected in m['fileHashes'].items():
                raw=read_private(directory,name,131072);check(hashlib.sha256(raw).hexdigest()==expected);files[name]=raw
            check(m==declaration(m['destination'],m['sourceCommit'],files,directory_identity=m['directoryIdentity'],owner_binding_hash=self.profile_hash))
        return True
    def _verified_state(self,binding_hash):
        check(binding_hash==self.binding.digest()
              and self.configuration==owner_binding(self.binding,self.credential,self.admission,self.journal,self.context,self.generation)
              and fingerprint(self.manifest)==self.closure and stage_authority_matches(self.authority,self.raw,self.manifest))
        check(self.authority(self.raw) is True);self.source_guard();self.fence.guard()
        row=self.journal.read();check(row['contextRef']==self.context and row['generationRef']==self.generation)
        if row['state'] in ('BLOCKED','CANCELLED','PAUSED_EXHAUSTED','RECONCILE_REQUIRED'):raise Permanent('AUTHORITY_REVOKED')
        if 'workerSessionHash' in row:
            self.guard_worker_session(row)
        current=self.store.read()
        if not self.observer and row['state']=='PUBLISHING' and current['state']=='BLOCKED' and current['blockedAttempt']==row['attempts']:
            raise Permanent('AUTHORITY_REVOKED')
        return row,current
    def guard(self,binding_hash):
        row,current=self._verified_state(binding_hash)
        if self.observer:
            if row['state']!='ACTIVE' or current['state']!='ACTIVE':raise Permanent('AUTHORITY_REVOKED')
    def await_active(self,binding_hash,maximum_wait_seconds=3600):
        """Wait for this owner's known renewal, granting no observation meanwhile.

        Each pass repeats signatures, source, legacy fence, generation and
        retained-budget verification. Parked/unknown states never enter a retry
        loop. The ordinary ACTIVE guard remains the only successful return.
        """
        check(self.observer and type(maximum_wait_seconds) is int and 1<=maximum_wait_seconds<=3600)
        deadline=time.monotonic()+maximum_wait_seconds
        previous=time.monotonic()
        while True:
            now=time.monotonic()
            check(previous<=now<deadline)
            previous=now
            row,current=self._verified_state(binding_hash)
            if row['state']=='ACTIVE' and current['state']=='ACTIVE':
                try:return self.guard(binding_hash)
                except Permanent as error:
                    # A legitimate publication may have started between the
                    # two guarded reads. Re-enter the complete verified state
                    # check; actual revocation/parked states fail there.
                    if error.code!='AUTHORITY_REVOKED':raise
                    continue
            check(row['state'] in ('NEW','ATTEMPTING','PUBLISHING','RETRY_WAIT')
                  and current['state'] in ('ACTIVE','BLOCKED'))
            now=time.monotonic()
            check(previous<=now<deadline)
            previous=now
            time.sleep(min(1,deadline-now))
    def guard_worker_session(self,row):
        signed=json.loads(self.raw,object_pairs_hook=unique).get('policyTokenFiniteWorkerSession')
        if type(signed)is dict and signed.get('schema')==GOVERNED_SESSION:
            self.guard_governed_worker_session(row,signed)
            return
        prior=signed.get('predecessorGrantAttempts')if type(signed)is dict else None
        check(type(prior)is int and prior in(1,2,3,4,5,6,8,9,10))
        check(type(signed)is dict and fingerprint(signed)==row['workerSessionHash']
            and self.configuration.get('workerSessionHash')==row['workerSessionHash']
            and signed.get('schema')=='ouf.policy-token-new-finite-worker-session.v'+str(prior)
            and signed.get('contextRef')==self.context and signed.get('generationRef')==self.generation
            and fingerprint(signed.get('policy'))==row['policyHash']
            and signed.get('intervalSeconds')==row['intervalSeconds']
            and signed.get('predecessorGrantAttempts')==prior
            and signed.get('automaticBudgetRenewalAllowed')is False
            and signed.get('consumedClaimReplayAllowed')is False
            and row.get('legacyHistory')=={'state':'UNKNOWN','cumulativeGrantAttemptCount':None,
                'reconciled':False,'gapRemainsOpen':True}
            and row.get('controlledPredecessorGrantAttempts')==prior
            and row.get('controlledCumulativeGrantAttempts')==prior+row['attempts'])
        if prior==1:check('controlledHistoryProfile'not in signed and 'controlledHistoryProfile'not in row)
        with protected_directory(self.journal.root)as directory:
            if prior in(2,3,4,5,6,8,9,10):
                check(signed.get('controlledHistoryProfile')==row.get('controlledHistoryProfile')=='ouf.policy-token-cancelled-worker-continuation.v1'
                    and signed.get('newBudget',{}).get('priorControlledGrantAttempts')==prior)
                for key in('predecessorCancelledWorkerHash','predecessorWorkerSessionHash'):check(signed.get(key)==row.get(key))
                worker_raw=read_private(directory,'owner-predecessor-worker.json',32768)
                session_raw=read_private(directory,'owner-predecessor-session.json',32768)
                check(hashlib.sha256(worker_raw).hexdigest()==signed['predecessorCancelledWorkerHash']
                    and hashlib.sha256(session_raw).hexdigest()==signed['predecessorWorkerSessionHash'])
                previous=json.loads(worker_raw,object_pairs_hook=unique);old_session=json.loads(session_raw,object_pairs_hook=unique)
                previous_count=6 if prior==8 else prior-1
                previous_attempts=2 if prior==8 else 1
                check(previous.get('state')=='CANCELLED'and previous.get('attempts')==previous_attempts
                    and previous.get('controlledPredecessorGrantAttempts')==previous_count and previous.get('controlledCumulativeGrantAttempts')==prior
                    and previous.get('workerSessionHash')==signed['predecessorWorkerSessionHash']
                    and previous.get('firstGrantReceiptHash')==row['firstGrantReceiptHash']
                    and old_session.get('schema')=='ouf.policy-token-new-finite-worker-session.v'+str(previous_count)
                    and old_session.get('predecessorGrantAttempts')==previous_count
                    and old_session.get('logicalOwnerScopeHash')==signed['logicalOwnerScopeHash'])
            check(json.loads(read_private(directory,'owner-session.json',16384),object_pairs_hook=unique)==signed)
            raw=read_private(directory,'owner-first-grant.json',16384)
            check(hashlib.sha256(raw).hexdigest()==row['firstGrantReceiptHash'])
            receipt=json.loads(raw,object_pairs_hook=unique)
            check(receipt.get('operation')==signed['predecessorFirstGrantOperation']
                and receipt.get('scopeHash')==signed['predecessorFirstGrantScopeHash']
                and receipt.get('state')=='TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED'
                and receipt.get('attemptSlotsConsumed')==1 and receipt.get('gapRemainsOpen')is True
                and receipt.get('historicalAccountingReconciled')is False
                and receipt.get('legacyHistoricalGrantAttempts')is None
                and receipt.get('bootId')==row.get('bootId'))
        fd=os.open('/proc/sys/kernel/random/boot_id',os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd);raw=os.read(fd,65)
            check(info.st_uid==info.st_gid==0 and not info.st_mode&0o022
                and raw.decode('ascii').strip()==row['bootId'])
        finally:os.close(fd)

    def guard_governed_worker_session(self,row,signed):
        with protected_directory(self.journal.root)as directory:
            review=json.loads(read_private(directory,'owner-session-review.json',131072),object_pairs_hook=unique)
            records={name:json.loads(read_private(directory,'predecessor-'+name,131072),object_pairs_hook=unique)
                for name in ('recovery.json','owner-session.json','owner-admission.json','owner-status.json')}
            first=json.loads(read_private(directory,'owner-first-grant.json',16384),object_pairs_hook=unique)
            compiled=compile_governed_session(review,records,first,signed['policy'],self.context,self.generation,signed['intervalSeconds'])
            check(compiled==signed and json.loads(read_private(directory,'owner-session.json',131072),object_pairs_hook=unique)==signed)
        prior=signed['predecessorGrantAttempts'];attempts=row.get('attempts')
        fence=signed['fenceBinding'];path=Path(fence['path'])
        check(str(self.journal.root)==fence['value']['journalPath'])
        with protected_directory(path.parent)as directory:
            check(json.loads(read_private(directory,path.name,16384),object_pairs_hook=unique)==fence['value'])
        check(fingerprint(signed)==row.get('workerSessionHash')==self.configuration.get('workerSessionHash')
            and row.get('controlledHistoryProfile')==GOVERNED_HISTORY
            and row.get('controlledPredecessorGrantAttempts')==prior and type(attempts)is int
            and 0<=attempts<=signed['policy']['max_attempts']
            and row.get('controlledCumulativeGrantAttempts')==prior+attempts
            and row.get('controlledCumulativeGrantAttempts')<=signed['maximumCumulativeGrantAttempts']
            and row.get('policyHash')==fingerprint(signed['policy'])
            and row.get('intervalSeconds')==signed['intervalSeconds']
            and row.get('firstGrantReceiptHash')==signed['firstGrantReceiptHash']
            and row.get('legacyHistory')==records['recovery.json']['legacyHistory']
            and row.get('bootId')==first['bootId'])
        fd=os.open('/proc/sys/kernel/random/boot_id',os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd);raw=os.read(fd,65)
            check(info.st_uid==info.st_gid==0 and not info.st_mode&0o022
                and raw.decode('ascii').strip()==row['bootId'])
        finally:os.close(fd)

    def prepare(self,binding_hash,deadline):
        check(not self.observer);self.guard(binding_hash);self.admission.prepare(deadline);self.guard(binding_hash)
    def admit(self,token,valid_until_monotonic,binding_hash,deadline):
        self.guard(binding_hash);before=self.store.read();row=self.journal.read()
        check(row['state']=='ACTIVE' if self.observer else row['state']=='PUBLISHING')
        token_hash=hashlib.sha256(token.encode()).hexdigest()
        if self.observer:check(before['tokenHash']==token_hash)
        self.admission.admit(token,valid_until_monotonic,deadline);self.guard(binding_hash)
        if self.observer:check(self.store.read()==before)
        else:self.store.save(before,'ACTIVE',token_hash)
        return True
    def admit_mounted(self,token,minimum_remaining,binding_hash,deadline):
        """Authenticate this published token using its retained grant window.

        The mount's finite read deadline is not token expiry. Both durable
        clocks, the current admission hash and online IAM must agree. Nothing
        is published, renewed or extended by this observer operation.
        """
        check(self.observer and type(minimum_remaining)is int and 1<=minimum_remaining<=3600
            and type(deadline)in(int,float)and math.isfinite(deadline))
        self.guard(binding_hash);row,current=self._verified_state(binding_hash)
        check(row['state']=='ACTIVE'and current['state']=='ACTIVE')
        wall,mono=self.admission.clock()
        check(all(type(row.get(k))in(int,float)and math.isfinite(row[k])for k in
            ('tokenExpiresWall','tokenExpiresMonotonic','lastWall','lastMonotonic'))
            and row['lastWall']<=wall and row['lastMonotonic']<=mono<deadline
            and deadline<=mono+30)
        required=max(minimum_remaining,self.binding.minimum_remaining)
        valid_until=min(row['tokenExpiresMonotonic'],mono+row['tokenExpiresWall']-wall)
        if valid_until-mono<required:raise Permanent('AUTHORITY_EXPIRED')
        self.admit(token,valid_until,binding_hash,deadline)
        self.guard(binding_hash);end_wall,end_mono=self.admission.clock()
        check(wall<=end_wall and mono<=end_mono<deadline
            and self.journal.read()==row and self.store.read()==current)
        if min(row['tokenExpiresWall']-end_wall,row['tokenExpiresMonotonic']-end_mono)<required:
            raise Permanent('AUTHORITY_EXPIRED')
        return True
    def pause(self):
        if not self.observer:
            # Safe local revocation of THIS retained generation does not require
            # expired authority; a stale generation cannot revoke a newer one.
            before=self.store.read();row=self.journal.read()
            check(row['contextRef']==self.context and row['generationRef']==self.generation)
            if before['state']!='BLOCKED' or before['tokenHash'] is not None or before['blockedAttempt']!=row['attempts']:
                self.store.save(before,'BLOCKED',blocked_attempt=row['attempts'])
