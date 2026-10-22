"""Separate durable native-read counters; never reset the recovery journal."""
import copy,hashlib,json,os,stat,tempfile,time
from pathlib import Path
from .core import require,digest,encoded,Store,validate_current
from .authorization import AuthorityScope

LIMITS={'databaseSessions':128,'gatewayAdminGets':64,'semanticGets':64}

def read_scope(plan,root):
    return {'schema':'ouf.semantic-registry-recovery-read-scope.v1',
        'planHash':digest(plan),'logicalOperationRef':plan['logicalOperationRef'],
        'executionRoot':str(root),'maximumRequests':dict(LIMITS),'automaticResetAllowed':False}

class ReadBudget:
    def __init__(self,store,authority,plan):
        require(type(store) is Store and type(authority) is AuthorityScope,'TYPED_RECOVERY_READ_BUDGET_REQUIRED')
        self.store,self.authority=store,authority;self.plan=copy.deepcopy(plan);self.scope=read_scope(plan,store.root)
        self.path=store.root/'native-reads.json';self.guard();self.read()
    def guard(self):
        self.store.check();row=self.store.read()
        validate_current(self.plan,row,Path('/proc/sys/kernel/random/boot_id').read_text().strip(),(time.time(),time.monotonic()))
        self.authority.guard(row)
        require(read_scope(self.plan,self.store.root)==self.scope
            and json.loads(self.authority.raw).get('semanticRegistryRecoveryReads')==self.scope,
            'CURRENT_SIGNED_RECOVERY_READ_SCOPE_REQUIRED')
    @classmethod
    def initialize(cls,store,authority,plan):
        """Installer-only, after independently issued current scoped authority.

        O_EXCL preserves every existing counter, including exhausted counters.
        This method issues no mandate, permission, window or token budget.
        """
        require(type(store) is Store and type(authority) is AuthorityScope,'ACTUAL_READ_BUDGET_INITIALIZER_REQUIRED')
        current=store.read()
        validate_current(plan,current,Path('/proc/sys/kernel/random/boot_id').read_text().strip(),(time.time(),time.monotonic()))
        authority.guard(current);scope=read_scope(plan,store.root)
        require(json.loads(authority.raw).get('semanticRegistryRecoveryReads')==scope,'SIGNED_READ_SCOPE_BEFORE_INITIALIZATION_REQUIRED')
        row={'schema':'ouf.semantic-registry-recovery-native-read-journal.v1','scopeHash':digest(scope),
            'authorityHash':authority.hash,'counts':{k:0 for k in LIMITS},'version':0,'budgetReset':False}
        with store.lock('cas.lock'):
            fd=os.open(store.root/'native-reads.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                with os.fdopen(os.dup(fd),'wb') as out:out.write(encoded(row));out.flush();os.fsync(out.fileno())
                os.fsync(fd)
                directory=os.open(store.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(directory)
                finally:os.close(directory)
            finally:os.close(fd)
        return cls(store,authority,plan)
    def read(self):
        self.store.check();fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0
                and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=8192,
                'PRIVATE_NATIVE_READ_JOURNAL_REQUIRED')
            raw=os.read(fd,8193)
            pin=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            require(len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(self.path.lstat()),
                'NATIVE_READ_JOURNAL_CHANGED')
            def unique(pairs):
                value={}
                for k,v in pairs:require(k not in value,'DUPLICATE_NATIVE_READ_COUNTER_KEY');value[k]=v
                return value
            value=json.loads(raw,object_pairs_hook=unique)
        finally:os.close(fd)
        require(set(value)=={'schema','scopeHash','authorityHash','counts','version','budgetReset'}
            and value['schema']=='ouf.semantic-registry-recovery-native-read-journal.v1'
            and value['scopeHash']==digest(self.scope) and value['authorityHash']==self.authority.hash
            and value['budgetReset'] is False and type(value['version']) is int and value['version']>=0
            and type(value['counts']) is dict and set(value['counts'])==set(LIMITS)
            and all(type(value['counts'][k]) is int and 0<=value['counts'][k]<=v for k,v in LIMITS.items()),
            'FINITE_SCOPED_NATIVE_READ_COUNTERS_REQUIRED')
        return value
    def reserve(self,name):
        require(name in LIMITS,'CLOSED_NATIVE_READ_REQUEST_REQUIRED');self.guard()
        with self.store.lock('cas.lock'):
            row=self.read();require(row['counts'][name]<LIMITS[name],'RECOVERY_NATIVE_READ_BUDGET_EXHAUSTED')
            following=copy.deepcopy(row);following['counts'][name]+=1;following['version']+=1
            fd,pending=tempfile.mkstemp(prefix='.native-reads-',dir=self.store.root)
            try:
                os.fchmod(fd,0o600)
                with os.fdopen(os.dup(fd),'wb') as out:out.write(encoded(following));out.flush();os.fsync(out.fileno())
                os.fsync(fd);require(self.read()==row,'NATIVE_READ_COUNTER_CAS_CHANGED')
                os.replace(pending,self.path)
                directory=os.open(self.store.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(directory)
                finally:os.close(directory)
            finally:
                os.close(fd)
                if os.path.lexists(pending):os.unlink(pending)
        self.guard()
        return following['counts'][name]
