"""Governed, resumable creation of retained ABSENT roots; no runtime install.

Each mkdir has a durable intent first. A crash after mkdir but before its inode
checkpoint requires explicit reconciliation: an unknown directory is never
adopted, removed, chmodded or recreated. Completed checkpoints are only reused
under the same signed scope and current host/authority. No credential is read.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import time
import uuid
import iam_binding_candidate as binding
import legacy_retirement as legacy
from cutover_authority import CutoverAuthority

ROLES={'reviewedCode':'/usr/local/libexec/ouf-policy-token',
    'ownerCredential':'/etc/ouf/policy-token/credentials/semantic',
    'durableRecovery':'/var/lib/ouf/policy-token/semantic'}

def metadata(info,depth):
    return {'depth':depth,'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,
        'modeOctal':format(stat.S_IMODE(info.st_mode),'04o'),'symlink':stat.S_ISLNK(info.st_mode),
        'directory':stat.S_ISDIR(info.st_mode)}

def protected(row):
    return row['directory'] and not row['symlink'] and row['uid']==row['gid']==0 and not int(row['modeOctal'],8)&0o022

class RootCustody:
    def __init__(self,retirement,authority,authority_raw):
        binding.require(type(retirement)is legacy.LegacyRetirement and type(authority)is CutoverAuthority
            and retirement.authority is authority and retirement.raw==authority_raw,'SAME_ROOT_CREATION_AUTHORITY_REQUIRED')
        self.retirement,self.authority,self.raw=retirement,authority,bytes(authority_raw)
        roots=binding.decode(binding.encoded(retirement.host.get('proposedRootsMetadata')))
        binding.require(type(roots)is dict and set(roots)==set(ROLES),'EXACT_THREE_MIGRATION_ROOTS_REQUIRED')
        self.baseline={};self.steps=[]
        for role in sorted(ROLES):
            row=roots[role];path=Path(ROLES[role]);parts=path.parts
            binding.require(type(row)is dict and row.get('path')==str(path) and row.get('state')=='ABSENT'
                and row.get('custodyAccepted')is False and type(row.get('firstMissingDepth'))is int
                and 0<row['firstMissingDepth']<len(parts) and type(row.get('ancestors'))is list
                and len(row['ancestors'])==row['firstMissingDepth'],'RETAINED_ABSENT_ROOT_REQUIRED')
            for depth,ancestor in enumerate(row['ancestors']):
                name=str(Path(*parts[:depth+1]))
                binding.require(set(ancestor)=={'depth','device','inode','uid','gid','modeOctal','symlink','directory'}
                    and ancestor['depth']==depth and protected(ancestor)
                    and type(ancestor['device'])is int and type(ancestor['inode'])is int and ancestor['inode']>0,
                    'RETAINED_ROOT_ANCESTRY_REQUIRED')
                binding.require(name not in self.baseline or self.baseline[name]==ancestor,'SHARED_ANCESTOR_DRIFT')
                self.baseline[name]=ancestor
            for depth in range(row['firstMissingDepth'],len(parts)):
                name=str(Path(*parts[:depth+1]))
                if name not in self.steps:self.steps.append(name)
        binding.require(not set(self.steps)&set(self.baseline) and 0<len(self.steps)<=12,'BOUNDED_DISJOINT_ROOT_CREATION_REQUIRED')
        self.scope={'schema':'ouf.policy-token-root-custody-scope.v1','hostInputsHash':legacy.HOST_HASH,
            'logicalOwnerScopeHash':retirement.scope['logicalOwnerScopeHash'],
            'sourceClosureHash':authority.expected['sourceClosureHash'],'roots':roots,'directories':self.steps,
            'createdModeOctal':'0700','maximumMkdirAttempts':2*len(self.steps),'maximumElapsedSeconds':300,
            'existingDirectoryAdoptionAllowed':False,'automaticRollbackAllowed':False}
        self.operation=binding.sha(binding.encoded({'logicalOwnerScopeHash':self.scope['logicalOwnerScopeHash'],
            'operation':'FIRST_GOVERNED_MIGRATION_ROOT_CREATION'}))
        self.name='policy-token-root-custody-'+self.operation+'.private.json'
    def guard(self):
        binding.require(binding.sha(binding.encoded(self.retirement.host))==legacy.HOST_HASH,'ROOT_HOST_INPUT_DRIFT')
        binding.require(legacy.boot_identity()==self.retirement.host['kernelBootId'],'ROOT_CREATION_BOOT_CHANGED')
        binding.require(binding.decode(self.raw).get('policyTokenRootCustody')==self.scope,
            'EXPLICIT_SIGNED_ROOT_CUSTODY_SCOPE_REQUIRED')
        binding.require(self.authority(self.raw)is True,'CURRENT_ROOT_CUSTODY_AUTHORITY_REQUIRED')
    @contextmanager
    def parent(self,path,created):
        parts=Path(path).parts;fds=[];seals=[]
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
            binding.require(metadata(os.fstat(fd),0)==self.baseline['/'],'ROOT_ANCESTRY_CHANGED')
            for depth,part in enumerate(parts[1:-1],1):
                name=str(Path(*parts[:depth+1]));expected=self.baseline.get(name,created.get(name))
                binding.require(expected is not None,'PARENT_CUSTODY_NOT_CHECKPOINTED')
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(child)
                binding.require(metadata(os.fstat(child),depth)==expected
                    ==metadata(os.stat(part,dir_fd=fd,follow_symlinks=False),depth),'ROOT_ANCESTRY_CHANGED')
                seals.append((fd,part,child,depth,expected));fd=child
            yield fd,parts[-1],len(parts)-1
            for parent,part,child,depth,expected in seals:
                binding.require(metadata(os.fstat(child),depth)==expected
                    ==metadata(os.stat(part,dir_fd=parent,follow_symlinks=False),depth),'ROOT_ANCESTRY_CHANGED')
        finally:
            for fd in reversed(fds):os.close(fd)
    def validate(self,row):
        binding.require(type(row)is dict and set(row)=={'schema','operation','scope','created','pending','state','version',
            'mkdirAttempts','createdMonotonic','lastMonotonic','expiresMonotonic'}
            and row['schema']=='ouf.policy-token-root-custody.v1' and row['operation']==self.operation
            and row['scope']==self.scope and type(row['created'])is dict and type(row['version'])is int
            and row['version']>=0 and row['state']in {'CREATING','ROOTS_CUSTODIED_NOT_RUNTIME_ACCEPTED'},'ROOT_LEDGER_DRIFT')
        count=len(row['created'])
        binding.require(set(row['created'])==set(self.steps[:count]) and count<=len(self.steps)
            and (row['pending']is None or count<len(self.steps) and row['pending']==self.steps[count])
            and (row['state']=='CREATING' or count==len(self.steps) and row['pending']is None),'ROOT_CHECKPOINT_ORDER_DRIFT')
        for path,info in row['created'].items():
            binding.require(set(info)=={'depth','device','inode','uid','gid','modeOctal','symlink','directory'}
                and info['depth']==len(Path(path).parts)-1 and protected(info) and info['modeOctal']=='0700'
                and type(info['device'])is int and type(info['inode'])is int and info['inode']>0,'ROOT_CHECKPOINT_CUSTODY_DRIFT')
        binding.require(type(row['mkdirAttempts'])is int and count<=row['mkdirAttempts']<=self.scope['maximumMkdirAttempts']
            and all(type(row[key])in (int,float) and 0<=row[key]<float('inf')
                for key in ('createdMonotonic','lastMonotonic','expiresMonotonic'))
            and row['createdMonotonic']<=row['lastMonotonic']<row['expiresMonotonic']
            and row['expiresMonotonic']==row['createdMonotonic']+300,'ROOT_FINITE_BUDGET_DRIFT')
        return row
    def current_budget(self,row):
        now=time.monotonic()
        binding.require(row['lastMonotonic']<=now<row['expiresMonotonic'],'ROOT_BUDGET_EXPIRED_OR_CLOCK_DRIFT')
        row['lastMonotonic']=now
    def run(self):
        self.guard()
        with binding.protected_parent()as evidence:
            binding.require(binding.read_member(evidence,'policy-token-migration-host-inputs-'+legacy.HOST_HASH+'.private.json')
                ==self.retirement.host_raw,'RETAINED_ROOT_HOST_INPUT_CHANGED')
            lock=os.open(self.name+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=evidence)
            try:
                info=os.fstat(lock)
                binding.require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'ROOT_FENCE_CUSTODY_REQUIRED')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);seal=binding.identity(info)
                def fence():
                    binding.require(seal==binding.identity(os.fstat(lock))
                        ==binding.identity(os.stat(self.name+'.lock',dir_fd=evidence,follow_symlinks=False)),'ROOT_FENCE_CHANGED')
                def save(row,first=False):
                    self.guard();fence();self.current_budget(row);raw=binding.encoded(self.validate(row))
                    name=self.name if first else '.'+self.name+'.'+uuid.uuid4().hex
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=evidence)
                    try:
                        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                        fence()
                        if not first:os.replace(name,self.name,src_dir_fd=evidence,dst_dir_fd=evidence)
                        os.fsync(evidence)
                        binding.require(binding.read_member(evidence,self.name)==raw,'ROOT_LEDGER_PUBLICATION_UNPROVEN')
                    finally:os.close(fd)
                try:row=self.validate(binding.decode(binding.read_member(evidence,self.name)))
                except FileNotFoundError:
                    now=time.monotonic()
                    row={'schema':'ouf.policy-token-root-custody.v1','operation':self.operation,'scope':self.scope,
                        'created':{},'pending':None,'state':'CREATING','version':0,'mkdirAttempts':0,
                        'createdMonotonic':now,'lastMonotonic':now,'expiresMonotonic':now+300}
                    save(row,first=True)
                for path in self.steps:
                    self.guard();fence();self.current_budget(row)
                    with self.parent(path,row['created'])as (parent,leaf,depth):
                        try:observed=metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False),depth)
                        except FileNotFoundError:observed=None
                        if path in row['created']:
                            binding.require(observed==row['created'][path],'CREATED_ROOT_CHANGED_NO_RECREATE')
                            continue
                        binding.require(observed is None,'UNRECORDED_ROOT_REQUIRES_RECONCILIATION_NO_ADOPTION')
                        binding.require(row['mkdirAttempts']<self.scope['maximumMkdirAttempts'],'ROOT_MKDIR_BUDGET_EXHAUSTED')
                        row.update(pending=path,version=row['version']+1,mkdirAttempts=row['mkdirAttempts']+1);save(row)
                        self.guard();fence();self.current_budget(row)
                        os.mkdir(leaf,0o700,dir_fd=parent);os.fsync(parent)
                        created=metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False),depth)
                        binding.require(protected(created) and created['modeOctal']=='0700','CREATED_ROOT_CUSTODY_UNPROVEN')
                        row['created'][path]=created;row.update(pending=None,version=row['version']+1);save(row)
                self.guard();fence();self.current_budget(row)
                for path in self.steps:
                    with self.parent(path,row['created'])as (parent,leaf,depth):
                        binding.require(metadata(os.stat(leaf,dir_fd=parent,follow_symlinks=False),depth)==row['created'][path],
                            'FINAL_ROOT_CUSTODY_CHANGED')
                if row['state']=='CREATING':
                    row.update(state='ROOTS_CUSTODIED_NOT_RUNTIME_ACCEPTED',version=row['version']+1);save(row)
                return binding.decode(binding.encoded(row))
            finally:os.close(lock)
