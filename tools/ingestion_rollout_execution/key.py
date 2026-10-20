"""One missing dedicated key under current dual-role/HUMAN authority and claim.

Root-custodied local adapter only. No issuer, OAuth, runtime, owner or SQL port.
Partial files remain after STOP; inode proof permits read-only reconciliation,
never regeneration or overwrite. Credential values/hashes are never returned.
"""
import copy
import os
from pathlib import Path
import secrets
import stat
from tools.ingestion_rollout_execution.contract import AUTHORITY_KEY,require,scope,digest
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

def identity(s):return (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)

class NativeKey:
    def __init__(self,action,journal,review,human):
        require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession
                and os.geteuid()==os.getegid()==0,'CURRENT_TYPED_HUMAN_AUTHORITY_ROOT_AND_PRIVATE_JOURNAL_REQUIRED')
        self.action,self.journal,self.review,self.human=action,journal,copy.deepcopy(review),human
        self.scope=scope(self.review);require(journal.root==Path(self.scope['executionContext']),'SAME_SIGNED_KEY_EXECUTION_CONTEXT_REQUIRED')
        self.index=[s['name']for s in review['stages']].index('CREATE_DEDICATED_KEY');self.stage=review['stages'][self.index]
        self.intent=self.stage['intent'];self.path=Path(self.intent['path'])
        require(self.intent['createExclusive']is True and self.intent['overwriteAllowed']is False
                and self.intent['publicValueOrHashAllowed']is False and self.intent['randomBytes']==32
                and self.intent['fileBytes']==64 and self.intent['encoding']=='hex-ascii'and self.intent['mode']==0o400,
                'EXACT_MISSING_KEY_MATERIALIZATION_INTENT_REQUIRED')

    def guard(self):
        require(scope(self.review)==self.scope,'KEY_REVIEW_DRIFT');self.action.guard(AUTHORITY_KEY,self.scope)
        require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        row=self.journal.read()
        require(row.get('scopeHash')==digest(self.scope)and row.get('authorityHash')==self.action.authority_hash
                and row.get('budgetReset')is False and row['nextStage']>=self.index
                and len(row['effects'])>self.index,'SAME_CURRENT_DURABLE_KEY_CLAIM_REQUIRED')
        effect=row['effects'][self.index]
        require(effect['stage']=='CREATE_DEDICATED_KEY'and effect['intentHash']==self.stage['intentHash']
                and effect['state']in('CLAIMED','APPLIED')and all(e['state']=='APPLIED'for e in row['effects'][:self.index]),
                'EXACT_ORDERED_KEY_EFFECT_CLAIM_REQUIRED')
        return row,effect

    def parent(self):
        fds=[];pins=[]
        try:
            parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(parent)
            for name in self.path.parts[1:-1]:
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd);s=os.fstat(fd)
                require(s.st_uid==0 and not s.st_mode&0o022,'ROOT_CUSTODIED_KEY_PATH_REQUIRED')
                pins.append((parent,name,fd,identity(s)));parent=fd
            return parent,fds,pins
        except BaseException:
            for fd in reversed(fds):os.close(fd)
            raise

    @staticmethod
    def recheck(pins):
        for parent,name,fd,pin in pins:
            require(pin==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'KEY_PATH_ANCESTRY_CHANGED')

    def create(self):
        row,effect=self.guard()
        require(row['nextStage']==self.index and effect['state']=='CLAIMED'and 'nativeResource'not in effect
                and not effect.get('nativeAllocationAttempted',False),
                'KEY_ALLOCATION_ALREADY_RESERVED_RECONCILE_NO_REPLAY')
        parent,fds,pins=self.parent()
        try:
            row,effect=self.guard();self.recheck(pins)
            effects=copy.deepcopy(row['effects']);effects[self.index]['nativeAllocationAttempted']=True
            self.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1})
            self.guard()
            fd=os.open(self.path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
            fds.append(fd);s=os.fstat(fd)
            require(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==s.st_gid==0
                    and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==0,'EXCLUSIVE_NEW_PRIVATE_KEY_INODE_REQUIRED')
            # Persist allocation identity before entropy/write. A crash cannot
            # turn a missing result into permission to generate a second key.
            row,effect=self.guard();require('nativeResource'not in effect,'KEY_ALLOCATION_ALREADY_RECORDED')
            effects=copy.deepcopy(row['effects']);effects[self.index]['nativeResource']={
                'path':str(self.path),'device':s.st_dev,'inode':s.st_ino,'exclusiveAllocation':True}
            self.journal.compare_and_save(row,{**row,'effects':effects,'version':row['version']+1})
            self.guard();raw=secrets.token_hex(32).encode('ascii')
            with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.lseek(fd,0,os.SEEK_SET);require(secrets.compare_digest(os.read(fd,65),raw),'NEW_KEY_PRIVATE_READBACK_REQUIRED')
            self.guard();os.fchown(fd,self.intent['uid'],self.intent['gid']);os.fchmod(fd,self.intent['mode']);os.fsync(fd)
            self.recheck(pins);os.fsync(parent);self.guard()
        finally:
            for fd in reversed(fds):os.close(fd)
        status,proof=self.observe();require(status=='APPLIED','NEW_KEY_METADATA_RECONCILIATION_REQUIRED')
        return proof

    def observe(self):
        _,effect=self.guard();allocated=effect.get('nativeResource')
        if allocated is None:return 'UNKNOWN',{}
        parent,fds,pins=self.parent()
        try:
            try:s=os.stat(self.path.name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:return 'UNKNOWN',{}
            self.recheck(pins);self.guard()
            if not(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_dev==allocated['device']and s.st_ino==allocated['inode']
                   and s.st_uid==self.intent['uid']and s.st_gid==self.intent['gid']
                   and stat.S_IMODE(s.st_mode)==self.intent['mode']and s.st_size==64):return 'UNKNOWN',{}
            return 'APPLIED',{'exclusiveKeyMaterializationProven':True,'device':s.st_dev,'inode':s.st_ino,
                             'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,
                             'credentialValueReturned':False,'credentialHashReturned':False}
        finally:
            for fd in reversed(fds):os.close(fd)
