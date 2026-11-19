"""One future governed attempt slot, preserving UNKNOWN legacy accounting.

Component only. No grant, credential read, signing, runtime installation or
permission to start the existing worker. The sealed installer must bind actual
executing bytes and all independent credential/IAM/owner/cutover gates.
"""
import fcntl
import math
import os
import re
import stat
import time
import uuid
import iam_binding_candidate as binding
from cutover_authority import CutoverAuthority

CONTRACT_HASH='f1200b4de0b33899760b1db1406725b6b7d633451b037ec9dc638754ecbcaa17'
GAP_HASH='fbd34408e376a0aca98aed5ba418bf5259a3c390be2a4efff7d8bce007a297d1'
STATES={'NEW_FINITE_SESSION','ATTEMPT_SLOT_CONSUMED_OUTCOME_UNPROVEN'}

def boot_identity():
    fd=os.open('/proc/sys/kernel/random/boot_id',os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd);raw=os.read(fd,65)
        binding.require(info.st_uid==info.st_gid==0 and not info.st_mode&0o022
            and re.fullmatch(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n',raw),
            'KERNEL_BOOT_IDENTITY_UNPROVEN')
        return raw.decode().strip()
    finally:os.close(fd)

def scope(logical_scope_hash,source_closure_hash):
    for value in (logical_scope_hash,source_closure_hash):
        binding.require(type(value)is str and re.fullmatch('[0-9a-f]{64}',value),'EXACT_GAP_MIGRATION_HASH_REQUIRED')
    return {'schema':'ouf.policy-token-accounting-gap-execution-scope.v1','contractHash':CONTRACT_HASH,
        'accountingGapEvidenceHash':GAP_HASH,'logicalOwnerScopeHash':logical_scope_hash,
        'sourceClosureHash':source_closure_hash,'operation':'OPEN_FIRST_CONTROLLED_OWNER_SESSION',
        'legacyHistoryDisposition':'UNKNOWN_RETAINED_NOT_RECONCILED','maximumGrantAttempts':1,
        'maximumElapsedSeconds':300,'automaticBudgetRenewalAllowed':False,'r12ReplayAllowed':False}

class FirstGapSession:
    def __init__(self,authority,authority_raw,logical_scope_hash,source_closure_hash,clock=time.time,monotonic=time.monotonic):
        binding.require(type(authority)is CutoverAuthority and type(authority_raw)is bytes,'CURRENT_EXISTING_DUAL_ROLE_AUTHORITY_REQUIRED')
        self.authority,self.raw,self.clock=authority,bytes(authority_raw),clock
        self.monotonic=monotonic
        self.scope=scope(logical_scope_hash,source_closure_hash)
        binding.require(authority.expected['sourceClosureHash']==source_closure_hash,'INDEPENDENT_GAP_SOURCE_CLOSURE_REQUIRED')
        # Stable across approvals, jobs and restarts. This is only the FIRST
        # migration qualification slot, never an automatic renewal API.
        self.operation=binding.sha(binding.encoded({'logicalScope':logical_scope_hash,'contractHash':CONTRACT_HASH,'gapHash':GAP_HASH}))
        self.name='policy-token-first-gap-session-'+self.operation+'.private.json'
    def guard(self):
        binding.require(binding.decode(self.raw).get('policyTokenAccountingGapMigration')==self.scope,
            'EXPLICIT_SIGNED_GAP_MIGRATION_SCOPE_REQUIRED')
        binding.require(self.authority(self.raw)is True,'CURRENT_HUMAN_AND_DUAL_ROLE_AUTHORITY_REQUIRED')
        if getattr(self,'pregrant_recovery',None) is not None:
            from legacy_retirement import PregrantRecovery
            binding.require(type(self.pregrant_recovery)is PregrantRecovery
                and self.pregrant_recovery.post_credential,'TYPED_POST_CREDENTIAL_SESSION_RECOVERY_REQUIRED')
            # Check only immutable predecessor facts here. The current session
            # may be consumed; its unused expired predecessor never changes.
            self.pregrant_recovery.guard()
    def validate(self,row):
        renewal=self.scope.get('newBudget')
        required={'schema','operation','scope','version','state','sessionDecisionHash','createdAt','lastObservedAt',
            'expiresAt','createdMonotonic','lastMonotonic','expiresMonotonic','bootId',
            'attemptSlotsConsumed','legacyHistory','historicalCumulativeGrantAttemptCount',
            'runtimeAuthorityIssued','notReleaseAcceptance'}
        if renewal is not None:required=required|{'budgetDecision'}
        schema='ouf.policy-token-first-gap-session.v2' if renewal is not None else 'ouf.policy-token-first-gap-session.v1'
        binding.require(type(row)is dict and set(row)==required and row['schema']==schema
            and row['operation']==self.operation and row['scope']==self.scope and type(row['version'])is int and row['version']>=0
            and row['state']in STATES and type(row['sessionDecisionHash'])is str and re.fullmatch('[0-9a-f]{64}',row['sessionDecisionHash'])
            and all(type(row[key])is int for key in ('createdAt','lastObservedAt','expiresAt','attemptSlotsConsumed'))
            and row['createdAt']<=row['lastObservedAt']<=row['expiresAt']
            and 0<row['expiresAt']-row['createdAt']<=300 and row['attemptSlotsConsumed']in (0,1)
            and all(type(row[key])in (float,int)and math.isfinite(row[key])and row[key]>=0
                for key in ('createdMonotonic','lastMonotonic','expiresMonotonic'))
            and row['createdMonotonic']<=row['lastMonotonic']<=row['expiresMonotonic']
            and 0<row['expiresMonotonic']-row['createdMonotonic']<=300
            and type(row['bootId'])is str and re.fullmatch('[0-9a-f-]{36}',row['bootId'])
            and (row['state']=='NEW_FINITE_SESSION')==(row['attemptSlotsConsumed']==0)
            and row['legacyHistory']=={'gapEvidenceHash':GAP_HASH,'state':'UNKNOWN','cumulativeGrantAttemptCount':None,
                'reconciled':False,'gapRemainsOpen':True}
            and row['historicalCumulativeGrantAttemptCount']is None
            and row['runtimeAuthorityIssued']is False and row['notReleaseAcceptance']is True,'RETAINED_GAP_SESSION_DRIFT')
        if renewal is not None:
            decision=row['budgetDecision']
            binding.require(type(decision)is dict and set(decision)=={'actor','reason','decisionRef','authorityHash',
                'predecessorSessionHash','priorGrantAttempts','maximumCumulativeGrantAttempts'}
                and decision['actor']==renewal['actor'] and decision['reason']==renewal['reason']
                and type(decision['decisionRef'])is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',decision['decisionRef'])
                and decision['authorityHash']==row['sessionDecisionHash']
                and decision['predecessorSessionHash']==renewal['predecessorSession']['sha256']
                and decision['priorGrantAttempts']==0 and decision['maximumCumulativeGrantAttempts']==1,
                'EXPLICIT_NEW_FIRST_GRANT_BUDGET_DECISION_REQUIRED')
        return row
    def save(self,directory,row,first=False):
        raw=binding.encoded(self.validate(row))
        if first:
            fd=os.open(self.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            temp=None
        else:
            temp='.'+self.name+'.'+uuid.uuid4().hex
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            if temp:os.replace(temp,self.name,src_dir_fd=directory,dst_dir_fd=directory)
            os.fsync(directory)
            binding.require(binding.read_member(directory,self.name)==raw,'GAP_SESSION_PUBLICATION_RECONCILIATION_REQUIRED')
        finally:os.close(fd)
    def transaction(self,consume):
        self.guard()
        with binding.protected_parent()as directory:
            gap_name='policy-token-owner-accounting-observation-'+GAP_HASH+'.private.json'
            gap_raw=binding.read_member(directory,gap_name)
            binding.require(binding.sha(gap_raw)==GAP_HASH,'EXACT_RETAINED_ACCOUNTING_GAP_HASH_REQUIRED')
            gap=binding.decode(gap_raw)
            binding.require(gap.get('schema')=='ouf.policy-token-accounting-source-observation.v1'
                and gap.get('historicalGrantAttemptCount')is None and gap.get('historicalAccountingReconciled')is False
                and gap.get('auditConfiguration',{}).get('eventsEnabled')is False,
                'EXACT_UNRECONCILED_ACCOUNTING_GAP_REQUIRED')
            fd=os.open(self.name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=directory)
            try:
                info=os.fstat(fd)
                binding.require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600
                    and info.st_nlink==1,'GAP_SESSION_FENCE_CUSTODY_REQUIRED')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                binding.require(binding.identity(info)==binding.identity(os.stat(self.name+'.lock',dir_fd=directory,follow_symlinks=False)),
                    'GAP_SESSION_FENCE_CHANGED')
                self.guard();now=self.clock();mono=self.monotonic();boot=boot_identity()
                binding.require(all(type(value)in (int,float)and math.isfinite(value)and value>=0 for value in (now,mono)),
                    'GAP_SESSION_CLOCK_UNPROVEN');now=int(now)
                try:row=self.validate(binding.decode(binding.read_member(directory,self.name)))
                except FileNotFoundError:
                    binding.require(not consume,'EXISTING_GOVERNED_SESSION_REQUIRED_NO_IMPLICIT_CREATION')
                    signed=binding.decode(self.raw)
                    binding.require(signed['expiresAt']>now,'CURRENT_SESSION_AUTHORITY_REQUIRED')
                    row={'schema':'ouf.policy-token-first-gap-session.v1','operation':self.operation,'scope':self.scope,
                        'version':0,'state':'NEW_FINITE_SESSION','sessionDecisionHash':binding.sha(self.raw),
                        'createdAt':now,'lastObservedAt':now,'expiresAt':min(now+300,signed['expiresAt']),
                        'createdMonotonic':mono,'lastMonotonic':mono,
                        'expiresMonotonic':mono+min(300,signed['expiresAt']-now),'bootId':boot,
                        'attemptSlotsConsumed':0,'legacyHistory':{'gapEvidenceHash':GAP_HASH,'state':'UNKNOWN',
                            'cumulativeGrantAttemptCount':None,'reconciled':False,'gapRemainsOpen':True},
                        'historicalCumulativeGrantAttemptCount':None,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}
                    renewal=self.scope.get('newBudget')
                    if renewal is not None:
                        mandate=binding.decode(self.authority.mandate(self.raw))
                        row['schema']='ouf.policy-token-first-gap-session.v2'
                        row['budgetDecision']={'actor':renewal['actor'],'reason':renewal['reason'],
                            'decisionRef':mandate['approvalRef'],'authorityHash':binding.sha(self.raw),
                            'predecessorSessionHash':renewal['predecessorSession']['sha256'],
                            'priorGrantAttempts':0,'maximumCumulativeGrantAttempts':1}
                    self.guard();self.save(directory,row,first=True);return row
                binding.require(not consume or row['attemptSlotsConsumed']==0,'CONSUMED_SLOT_REQUIRES_RECONCILIATION_NO_REPLAY')
                binding.require(row['lastObservedAt']<=now<row['expiresAt'],'SESSION_EXPIRED_OR_CLOCK_REGRESSED_NO_RENEWAL')
                binding.require(row['bootId']==boot and row['lastMonotonic']<=mono<row['expiresMonotonic'],
                    'SESSION_BOOT_OR_MONOTONIC_DRIFT_NO_RENEWAL')
                self.guard()
                if consume:
                    row.update(version=row['version']+1,lastObservedAt=now,lastMonotonic=mono,attemptSlotsConsumed=1,
                        state='ATTEMPT_SLOT_CONSUMED_OUTCOME_UNPROVEN')
                    binding.require(binding.read_member(directory,gap_name)==gap_raw,'ACCOUNTING_GAP_EVIDENCE_CHANGED')
                    self.save(directory,row)
                elif row['attemptSlotsConsumed']==0:
                    row.update(version=row['version']+1,lastObservedAt=now,lastMonotonic=mono)
                    self.save(directory,row)
                # A new authority/approval does not create another first slot.
                return row
            finally:os.close(fd)
    def open(self):return self.transaction(False)
    def consume_attempt_slot(self):return self.transaction(True)
