"""Bounded read-only observation of one explicit singleton configtree bind.

File bytes are streamed only into a hash, never returned/spooled. Caller owns
independent policy authentication, complete OCI/rootfs and paused generation.
This witness does not approve a policy, issue authority, or change permissions.
"""
import copy,hashlib,os,re,stat
from pathlib import Path
from transition_journal import require,digest,hash_value
from tools.semantic_provider_preexec_native import NativeBackend
from tools.semantic_provider_deployment_authentication import ancestors

def attributes(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

class ConfigtreeMountObservation:
    def __init__(self,expected,budget):
        fields={'source','target','readOnly','uid','gid','directoryMode','fileName','fileMode','maxBytes','sha256'}
        require(os.geteuid()==0 and type(expected) is dict and set(expected)==fields,'EXACT_ROOT_CONFIGTREE_BINDING_REQUIRED')
        for key in ('source','target'):
            value=expected[key]
            require(type(value) is str and re.fullmatch('/[A-Za-z0-9_./-]+',value) and '..' not in Path(value).parts
                    and str(Path(value))==value and value!='/','EXACT_CONFIGTREE_PATH_REQUIRED')
        require(expected['readOnly'] is True and expected['uid']==expected['gid']==10001
                and type(expected['uid']) is int and type(expected['gid']) is int
                and expected['directoryMode']==0o500 and expected['fileMode']==0o400
                and type(expected['fileName']) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',expected['fileName'])
                and type(expected['maxBytes']) is int and 1<=expected['maxBytes']<=1048576
                and hash_value(expected['sha256']),'EXACT_PRIVATE_SINGLETON_CONFIGTREE_REQUIRED')
        self.expected=copy.deepcopy(expected);self.expected_hash=digest(expected);self.budget=budget
    def read_proc(self,path,limit):
        self.budget.check();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            value=bytearray()
            while True:
                self.budget.check();raw=os.read(fd,min(65536,limit+1-len(value)))
                if not raw:break
                value.extend(raw);require(len(value)<=limit,'CONFIGTREE_PROC_READ_UNBOUNDED')
            return bytes(value)
        finally:os.close(fd)
    def file_hash(self,fd):
        e=self.expected;self.budget.check();before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                and (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))==(e['uid'],e['gid'],e['fileMode'])
                and 0<before.st_size<=e['maxBytes'],'PRIVATE_CONFIGTREE_FILE_CUSTODY_DRIFT')
        h=hashlib.sha256();total=0
        while True:
            self.budget.check();block=os.read(fd,min(65536,e['maxBytes']+1-total))
            if not block:break
            total+=len(block);require(total<=e['maxBytes'],'CONFIGTREE_FILE_UNBOUNDED');h.update(block)
        require(total==before.st_size and attributes(before)==attributes(os.fstat(fd))
                and h.hexdigest()==e['sha256'],'CONFIGTREE_PRIVATE_FILE_HASH_OR_METADATA_DRIFT')
        return before,total
    def observe(self,generation):
        e=self.expected;require(digest(e)==self.expected_hash,'CONFIGTREE_POLICY_DRIFT')
        pid=generation['pid'];self.budget.check();require(NativeBackend.generation(None,pid)==generation,'CONFIGTREE_PROCESS_GENERATION_DRIFT')
        mount_ns=Path('/proc/'+str(pid)+'/ns/mnt').stat().st_ino
        source=Path(e['source']);ancestors(source)
        # The source directory itself is deliberately owned by the application.
        # Only its ancestors are required root-owned; child access is FD-relative.
        fds=[]
        try:
            directory=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(directory);before=os.fstat(directory)
            require((before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))==(e['uid'],e['gid'],e['directoryMode'])
                    and attributes(before)==attributes(source.lstat()) and os.listdir(directory)==[e['fileName']],
                    'EXACT_SINGLETON_CONFIGTREE_DIRECTORY_REQUIRED')
            filefd=os.open(e['fileName'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory);fds.append(filefd)
            fileinfo,size=self.file_hash(filefd)
            rootfd=os.open('/proc/'+str(pid)+'/root',os.O_PATH|os.O_DIRECTORY);fds.append(rootfd)
            current=rootfd
            for part in Path(e['target']).parts[1:]:
                self.budget.check();current=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current);fds.append(current)
            require(attributes(os.fstat(current))==attributes(before),'EFFECTIVE_CONFIGTREE_DIRECTORY_IDENTITY_DRIFT')
            view=os.open(e['fileName'],os.O_PATH|os.O_NOFOLLOW,dir_fd=current);fds.append(view)
            require(attributes(os.fstat(view))==attributes(fileinfo),'EFFECTIVE_CONFIGTREE_FILE_IDENTITY_DRIFT')
            raw=self.read_proc('/proc/'+str(pid)+'/mountinfo',131072)
            # Approved paths cannot contain whitespace/escapes. Match exact
            # targets and deny subordinate mounts that could hide the file.
            rows=[line.split() for line in raw.decode('ascii').splitlines()]
            matches=[r for r in rows if len(r)>=10 and r[4]==e['target']]
            require(len(matches)==1 and 'ro' in matches[0][5].split(',') and 'rw' not in matches[0][5].split(',')
                    and matches[0].index('-')==6 and not any(len(r)>4 and r[4].startswith(e['target']+'/') for r in rows),
                    'EFFECTIVE_PRIVATE_READONLY_CONFIGTREE_REQUIRED')
            os.lseek(filefd,0,os.SEEK_SET);again,_=self.file_hash(filefd)
            require(attributes(again)==attributes(fileinfo) and attributes(os.fstat(directory))==attributes(before)==attributes(source.lstat())
                    and os.listdir(directory)==[e['fileName']] and raw==self.read_proc('/proc/'+str(pid)+'/mountinfo',131072)
                    and attributes(os.stat(e['fileName'],dir_fd=directory,follow_symlinks=False))==attributes(fileinfo),
                    'CONFIGTREE_SOURCE_OR_MOUNT_CHANGED')
            require(NativeBackend.generation(None,pid)==generation and Path('/proc/'+str(pid)+'/ns/mnt').stat().st_ino==mount_ns,'CONFIGTREE_PROCESS_GENERATION_DRIFT')
            self.budget.check();require(digest(e)==self.expected_hash,'CONFIGTREE_POLICY_DRIFT')
            return {'schema':'ouf.semantic-singleton-configtree-observation.v1','bindingHash':self.expected_hash,'generationHash':digest(generation),
                    'sourceHash':e['sha256'],'bytes':size,'privateBytesRead':size*2,'singletonDirectoryObserved':True,
                    'effectiveReadOnlyDirectoryBindingObserved':True,'sameSourceFileInMountedView':True,'stableAcrossReads':True,
                    'privateMaterialSpooled':False,'privateValuesPrinted':False,'policyAuthenticationProven':False,
                    'completeCreationAccepted':False,'signaturesIssued':0,'startAuthorized':False}
        finally:
            for fd in reversed(fds):os.close(fd)
