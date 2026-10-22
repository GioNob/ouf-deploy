"""Private renewable-token mount witness; no approval or runtime mutation.

Expected root identity and owner binding are independently supplied. No token
hash/body/claims/path is returned. Existing DomainOwner must authenticate the
current credential; synthetic admission is not target acceptance.
"""
import copy,math,os,re,stat,time
from pathlib import Path
from tools.semantic_lease_recovery.bounded_recovery import fingerprint,require
from tools.semantic_policy_token_owner.producer import DomainOwner,protected_directory,identity

def generation(pid,*,allow_frozen=False):
    require(type(pid) is int and pid>0,'EXACT_PROCESS_ID_REQUIRED')
    raw=Path(f'/proc/{pid}/stat').read_bytes()
    require(len(raw)<=8192 and b') ' in raw,'BOUNDED_PROCESS_STAT_REQUIRED')
    fields=raw.rsplit(b') ',1)[1].split()
    require(allow_frozen or fields[0] in (b'T',b't'),'PAUSED_PROCESS_REQUIRED')
    return {'pid':pid,'startTicks':int(fields[19]),
            'mountNamespace':Path(f'/proc/{pid}/ns/mnt').stat().st_ino,
            'networkNamespace':Path(f'/proc/{pid}/ns/net').stat().st_ino}

class RenewableTokenMountObservation:
    def __init__(self,expected,owner,deadline,clock=time.monotonic,*,pause_binding=None,running_binding=None):
        fields={'source','target','fileName','gid','directoryDevice','directoryInode',
                'ownerBindingHash','maxBytes','minimumRemainingSeconds'}
        require(type(expected) is dict and set(expected)==fields and isinstance(owner,DomainOwner),
                'EXACT_RENEWABLE_TOKEN_POLICY_AND_EXISTING_OWNER_REQUIRED')
        for name in ('source','target'):
            p=expected[name]
            require(type(p) is str and re.fullmatch('/[A-Za-z0-9_./-]+',p)
                    and str(Path(p))==p and p!='/' and '..' not in Path(p).parts,
                    'EXPLICIT_CANONICAL_MOUNT_PATH_REQUIRED')
        require(type(expected['fileName']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',expected['fileName'])
                and expected['fileName'] not in {'.','..'}
                and all(type(expected[k]) is int and expected[k]>0 for k in ('gid','directoryInode','maxBytes','minimumRemainingSeconds'))
                and type(expected['directoryDevice']) is int and expected['directoryDevice']>=0
                and expected['maxBytes']<=16384 and expected['minimumRemainingSeconds']<=3600
                and type(expected['ownerBindingHash']) is str and re.fullmatch('[0-9a-f]{64}',expected['ownerBindingHash']),
                'BOUNDED_RENEWABLE_SOURCE_IDENTITY_REQUIRED')
        now=clock();require(type(deadline) in (int,float) and math.isfinite(deadline)
                            and now<deadline<=now+30,'FINITE_MOUNT_OBSERVATION_DEADLINE_REQUIRED')
        self.expected=copy.deepcopy(expected);self.policy_hash=fingerprint(expected)
        self.owner,self.deadline,self.clock=owner,deadline,clock
        if pause_binding is not None:
            from paused_workload_binding import PausedWorkloadBinding
            if type(pause_binding) is not PausedWorkloadBinding:
                from tools.semantic_registry_recovery_execution.paused_binding import RecoveryPausedBinding
                require(type(pause_binding) is RecoveryPausedBinding,'TYPED_ENGINE_PAUSE_BINDING_REQUIRED')
        require(pause_binding is None or running_binding is None,'ONE_NATIVE_MOUNT_PROCESS_BINDING_REQUIRED')
        if running_binding is not None:
            from gated_process_observation import RunningWorkloadBinding
            require(type(running_binding) is RunningWorkloadBinding,'TYPED_RUNNING_REGISTRY_BINDING_REQUIRED')
        self.pause_binding=pause_binding
        self.running_binding=running_binding
    def guard(self):
        require(self.clock()<self.deadline and fingerprint(self.expected)==self.policy_hash,
                'MOUNT_OBSERVATION_DEADLINE_OR_POLICY_DRIFT')
        self.owner.guard(self.expected['ownerBindingHash'])
    def mountinfo(self,pid):
        self.guard();fd=os.open(f'/proc/{pid}/mountinfo',os.O_RDONLY|os.O_NOFOLLOW)
        try:
            raw=os.read(fd,131073);require(len(raw)<=131072,'BOUNDED_MOUNTINFO_REQUIRED');return raw
        finally:os.close(fd)
    def read_token(self,fd):
        self.guard();s=os.fstat(fd);e=self.expected
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==e['gid']
                and stat.S_IMODE(s.st_mode)==0o440 and s.st_nlink==1 and 0<s.st_size<=e['maxBytes'],
                'RENEWABLE_TOKEN_FILE_CUSTODY_DRIFT')
        os.lseek(fd,0,os.SEEK_SET);raw=os.read(fd,e['maxBytes']+1)
        require(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd)),
                'RENEWABLE_TOKEN_CHANGED_DURING_READ')
        token=raw.decode('ascii')
        require(bool(token) and not any(c.isspace() for c in token),'BOUNDED_TOKEN_ENCODING_REQUIRED')
        return token,s
    def observe(self,expected_generation):
        require(type(expected_generation) is dict and set(expected_generation)==
                {'pid','startTicks','mountNamespace','networkNamespace'},'EXACT_PAUSED_GENERATION_REQUIRED')
        self.guard();e=self.expected;pid=expected_generation['pid'];fds=[]
        pause_before=None if self.pause_binding is None else self.pause_binding.observe()
        running_before=None if self.running_binding is None else self.running_binding.observe()
        if running_before is not None:require(running_before['runtimeBinding']['pid']==pid,'EXACT_RUNNING_REGISTRY_PROCESS_REQUIRED')
        if pause_before is not None:require(pause_before['runtimeBinding']['pid']==pid,'EXACT_PAUSED_ENGINE_PROCESS_REQUIRED')
        require(generation(pid,allow_frozen=pause_before is not None or running_before is not None)==expected_generation,'PAUSED_MOUNT_PROCESS_DRIFT')
        try:
            with protected_directory(e['source'],gid=e['gid'],mode=0o750) as source:
                root=os.fstat(source)
                require((root.st_dev,root.st_ino)==(e['directoryDevice'],e['directoryInode'])
                        and os.listdir(source)==[e['fileName']],'APPROVED_RENEWABLE_ROOT_OR_MEMBERSHIP_DRIFT')
                filefd=os.open(e['fileName'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=source);fds.append(filefd)
                token,leaf=self.read_token(filefd)
                require(identity(leaf)==identity(os.stat(e['fileName'],dir_fd=source,follow_symlinks=False)),
                        'RENEWABLE_TOKEN_NAMED_IDENTITY_DRIFT')
                current=os.open(f'/proc/{pid}/root',os.O_PATH|os.O_DIRECTORY);fds.append(current)
                for part in Path(e['target']).parts[1:]:
                    self.guard();current=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current);fds.append(current)
                require(identity(os.fstat(current))==identity(root),'EFFECTIVE_TOKEN_DIRECTORY_IDENTITY_DRIFT')
                mounted=os.open(e['fileName'],os.O_PATH|os.O_NOFOLLOW,dir_fd=current);fds.append(mounted)
                require(identity(os.fstat(mounted))==identity(leaf),'EFFECTIVE_TOKEN_FILE_IDENTITY_DRIFT')
                raw=self.mountinfo(pid);rows=[v.split() for v in raw.decode('ascii').splitlines()]
                matches=[r for r in rows if len(r)>=10 and r[4]==e['target']]
                require(len(matches)==1 and 'ro' in matches[0][5].split(',')
                        and 'rw' not in matches[0][5].split(',') and matches[0].index('-')==6
                        and not any(len(r)>4 and r[4].startswith(e['target']+'/') for r in rows),
                        'READONLY_SINGLETON_TOKEN_MOUNT_REQUIRED')
                self.guard()
                # Existing owner must prove actual issuer/signature/audience/
                # scope/expiry/revocation for THIS exact token, not protocol shape.
                require(self.owner.admit_mounted(token,e['minimumRemainingSeconds'],
                        e['ownerBindingHash'],self.deadline) is True,'CURRENT_TOKEN_OWNER_ADMISSION_REQUIRED')
                require(identity(leaf)==identity(os.fstat(filefd))
                        ==identity(os.stat(e['fileName'],dir_fd=source,follow_symlinks=False)),
                        'TOKEN_ROTATED_OR_MOUNT_CHANGED_DURING_OBSERVATION')
                again,end=self.read_token(filefd)
                require(again==token and identity(end)==identity(leaf)
                        ==identity(os.stat(e['fileName'],dir_fd=source,follow_symlinks=False))
                        ==identity(os.fstat(mounted)) and identity(os.fstat(source))==identity(root)
                        and os.listdir(source)==[e['fileName']] and self.mountinfo(pid)==raw,
                        'TOKEN_ROTATED_OR_MOUNT_CHANGED_DURING_OBSERVATION')
                require(generation(pid,allow_frozen=pause_before is not None or running_before is not None)==expected_generation
                        and (pause_before is None or self.pause_binding.observe()==pause_before)
                        and (running_before is None or self.running_binding.observe()==running_before),
                        'PAUSED_MOUNT_PROCESS_DRIFT');self.guard()
                return {'schema':'ouf.renewable-token-mount-observation.v1','bindingHash':self.policy_hash,
                        'generationHash':fingerprint(expected_generation),'privateBytesRead':leaf.st_size*2,
                        'stableAcrossReads':True,'sameSourceFileInMountedView':True,
                        'effectiveReadOnlyDirectoryBindingObserved':True,'currentOwnerAdmissionObserved':True,
                        'privateMaterialSpooled':False,'privateValuesPrinted':False,
                        'policyAuthenticationProven':False,'completeSixMountClosureProven':False,
                        'completeCreationAccepted':False,'runtimeAuthorityIssued':False,'signaturesIssued':0}
        finally:
            for fd in reversed(fds):os.close(fd)

