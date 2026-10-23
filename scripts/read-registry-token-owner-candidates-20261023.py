"""Bounded live owner-journal discovery; no owner selection or runtime action.

Read only the two known metadata schemas under deploy-snapshots, at depth <=3.
Never open token/credential/HUMAN/authority files, use Engine, invoke a program,
acquire a lock, start a worker, or interpret an old dossier as current authority.
"""
import hashlib,json,math,os,re,signal,stat,sys,time
from pathlib import Path

PARENT=Path('/etc/ouf/deploy-snapshots')
MAX_DEPTH=3
MAX_DIRECTORIES=2048
MAX_ENTRIES=32768
MAX_CANDIDATES=64
MAX_READS=256
MAX_BYTES=16*1024*1024
STATES={'NEW','ATTEMPTING','PUBLISHING','RETRY_WAIT','ACTIVE','BLOCKED','CANCELLED','PAUSED_EXHAUSTED','RECONCILE_REQUIRED'}

class Stop(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Stop(reason)
def unique(pairs):
    result={}
    for key,value in pairs:require(key not in result,'DUPLICATE_METADATA_KEY');result[key]=value
    return result
def pin(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def number(v):return type(v) in (int,float) and math.isfinite(v)
def hashed(v):return type(v) is str and re.fullmatch('[a-f0-9]{64}',v) is not None

def locks(raw):
    require(len(raw)<=2097152,'PROC_LOCK_METADATA_BOUND')
    result={}
    rows=raw.decode('ascii').splitlines();require(len(rows)<=32768,'PROC_LOCK_ROW_BOUND')
    for row in rows:
        fields=row.split()
        if 'FLOCK' not in fields or '->' in fields:continue
        require(len(fields)==8 and fields[1:3]==['FLOCK','ADVISORY']
            and fields[3] in ('READ','WRITE') and fields[6:]==['0','EOF'],
            'PROC_FLOCK_FORMAT_UNPROVEN')
        if fields[3]!='WRITE':continue
        match=re.fullmatch('([a-fA-F0-9]+):([a-fA-F0-9]+):([0-9]+)',fields[5])
        require(match is not None and fields[4].isdigit(),'PROC_FLOCK_IDENTITY_UNPROVEN')
        key=(int(match[1],16),int(match[2],16),int(match[3]));pid=int(fields[4])
        require(pid>0 and key not in result,'UNIQUE_NATIVE_EXCLUSIVE_FLOCK_REQUIRED')
        result[key]=pid
    return result

class Reader:
    def __init__(self,parent):
        self.parent=Path(parent);self.reads=0;self.bytes=0;self.started=time.monotonic()
        self.ancestry(self.parent)
    def check(self):require(0<=time.monotonic()-self.started<12,'DISCOVERY_TIME_BOUND')
    def ancestry(self,path):
        require(path.is_absolute() and '..' not in path.parts and path.resolve()==path,
            'CANONICAL_METADATA_DIRECTORY_REQUIRED')
        result=[]
        for p in [*reversed(path.parents),path]:
            s=p.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,
                'ROOT_CONTROLLED_METADATA_DIRECTORY_REQUIRED')
            result.append((p,pin(s)))
        return result
    def read(self,path,maximum):
        self.check();path=Path(path)
        require(path.parent.is_relative_to(self.parent) and path.name in ('owner-admission.json','recovery.json'),
            'ONLY_INSTALLED_OWNER_METADATA_REQUIRED')
        ancestors=self.ancestry(path.parent);require(self.reads<MAX_READS,'METADATA_READ_BOUND')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022
                and before.st_nlink==1 and 0<before.st_size<=maximum,'BOUNDED_ROOT_METADATA_REQUIRED')
            require(self.bytes+before.st_size<=MAX_BYTES,'TOTAL_METADATA_BYTE_BOUND')
            self.reads+=1;self.bytes+=before.st_size
            raw=bytearray()
            while len(raw)<=maximum:
                block=os.read(fd,min(65536,maximum+1-len(raw)))
                if not block:break
                raw.extend(block)
            require(len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(path.lstat())
                and all(pin(p.lstat())==s for p,s in ancestors),'METADATA_CHANGED_DURING_READ')
            value=json.loads(raw,object_pairs_hook=unique,
                parse_constant=lambda _:(_ for _ in ()).throw(Stop('NONFINITE_METADATA_JSON')))
            require(type(value) is dict,'METADATA_OBJECT_REQUIRED')
            return value,hashlib.sha256(raw).hexdigest()
        finally:os.close(fd)

def discover(parent):
    reader=Reader(parent);queue=[(reader.parent,0)];directories=0;entries=0;limited=0;symlinks=0;candidates=[]
    while queue:
        reader.check();path,depth=queue.pop();directories+=1
        require(directories<=MAX_DIRECTORIES,'DISCOVERY_DIRECTORY_BOUND')
        reader.ancestry(path)
        with os.scandir(path) as listing:
            for entry in listing:
                entries+=1;require(entries<=MAX_ENTRIES,'DISCOVERY_ENTRY_BOUND');reader.check()
                if entry.is_symlink():symlinks+=1;continue
                if entry.name=='owner-admission.json':
                    require(entry.is_file(follow_symlinks=False),'OWNER_MARKER_MUST_BE_REGULAR')
                    candidates.append(path);require(len(candidates)<=MAX_CANDIDATES,'OWNER_CANDIDATE_BOUND')
                if entry.is_dir(follow_symlinks=False):
                    info=entry.stat(follow_symlinks=False)
                    if not re.fullmatch('[A-Za-z0-9_.-]{1,160}',entry.name) or depth==MAX_DEPTH \
                        or info.st_uid!=0 or info.st_mode&0o022:
                        limited+=1;continue
                    queue.append((Path(entry.path),depth+1))
                    require(len(queue)+directories<=MAX_DIRECTORIES,'DISCOVERY_DIRECTORY_BOUND')
    return reader,sorted(candidates),{'directoriesListed':directories,'directoryEntriesSeen':entries,
        'subdirectoriesOutsideScope':limited,'symlinksNotFollowed':symlinks}

def project(directory,marker,row,boot,wall,mono,held):
    require(marker.get('schema')=='ouf.policy-token-owner-admission.v1'
        and all(hashed(marker.get(k)) for k in ('ownerProfileHash','contextRef','generationRef'))
        and marker.get('state') in ('ACTIVE','BLOCKED')
        and row.get('schema')=='ouf.bounded-recovery.v1' and row.get('state') in STATES
        and all(row.get(k)==marker[k] for k in ('contextRef','generationRef'))
        and type(row.get('attempts')) is int and 0<=row['attempts']<=128,
        'MATCHING_INSTALLED_OWNER_METADATA_SCHEMAS_REQUIRED')
    same_boot=row.get('bootId')==boot
    expiry=all(number(row.get(k)) for k in ('lastWall','lastMonotonic','tokenExpiresWall','tokenExpiresMonotonic'))
    clocks=expiry and row['lastWall']<=wall and row['lastMonotonic']<=mono
    remaining=min(row['tokenExpiresWall']-wall,row['tokenExpiresMonotonic']-mono) if clocks else None
    cumulative=row.get('controlledCumulativeGrantAttempts')
    require(cumulative is None or type(cumulative) is int and row['attempts']<=cumulative<=1000000,
        'BOUNDED_RETAINED_OWNER_COUNTER_REQUIRED')
    return {'journalPath':str(directory),'recoveryState':row['state'],'admissionState':marker['state'],
        'sameCurrentBoot':same_boot,'retainedTokenWindowRecorded':expiry,
        'retainedTokenWindowPositive':same_boot and clocks and remaining>0,
        'retainedTokenWindowAtLeast90Seconds':same_boot and clocks and remaining>=90,
        'attempts':row['attempts'],'controlledCumulativeGrantAttempts':cumulative,
        'invocationExclusiveLockObserved':held,'currentOwnerIdentityEstablished':False}

def observe(parent=PARENT,proc=Path('/proc')):
    boot_path=proc/'sys/kernel/random/boot_id';boot=boot_path.read_text().strip()
    require(re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot) is not None,'CURRENT_BOOT_REQUIRED')
    reader,paths,coverage=discover(parent)
    def lock_map():
        fd=os.open(proc/'locks',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:return locks(os.read(fd,2097153))
        finally:os.close(fd)
    before=lock_map();rows=[]
    for path in paths:
        # No operation, token, authority or HUMAN file is read. A lock is only
        # observed in /proc/locks; this reader never calls flock or opens it.
        marker,mhash=reader.read(path/'owner-admission.json',8192)
        recovery,rhash=reader.read(path/'recovery.json',65536)
        lock_path=path/'invocation.lock';key=None;lock_pin=None
        try:
            s=lock_path.lstat()
            require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_nlink==1,
                'ROOT_OWNED_OWNER_INVOCATION_LOCK_REQUIRED')
            key=(os.major(s.st_dev),os.minor(s.st_dev),s.st_ino)
            lock_pin=pin(s)
        except FileNotFoundError:pass
        wall,mono=time.time(),time.monotonic()
        rows.append(project(path,marker,recovery,boot,wall,mono,key in before if key is not None else False))
        require(reader.read(path/'owner-admission.json',8192)[1]==mhash
            and reader.read(path/'recovery.json',65536)[1]==rhash,'OWNER_METADATA_CHANGED_DURING_OBSERVATION')
        after=lock_map()
        require(key is None or before.get(key)==after.get(key),'OWNER_INVOCATION_LOCK_CHANGED')
        require((not os.path.lexists(lock_path)) if lock_pin is None else pin(lock_path.lstat())==lock_pin,
            'OWNER_INVOCATION_LOCK_FILE_CHANGED')
    require(boot_path.read_text().strip()==boot,'BOOT_CHANGED_DURING_OBSERVATION');reader.check()
    return {'schema':'ouf.semantic-registry-owner-discovery-result.v1','status':'BOUNDED_OWNER_METADATA_OBSERVED',
        'complete':True,'readOnly':True,'snapshotSearchDepth':MAX_DEPTH,**coverage,
        'metadataReadOperations':reader.reads,'metadataBytesRead':reader.bytes,'candidateCount':len(rows),'candidates':rows,
        'candidateSelectionPerformed':False,'currentOwnerIdentityEstablished':False,
        'otherOwnersNotExcluded':True,'absenceOfMatchDoesNotProveNoOwner':True,
        'credentialFilesOpened':0,'credentialValuesPrinted':False,'rawMetadataPrinted':False,
        'engineGets':0,'databaseCalls':0,'oauthRequests':0,'runtimeEffectsDispatched':0,
        'runtimeAuthorityIssued':False,'activationResubmitted':False,'automaticReplayAllowed':False,
        'budgetReset':False,'rootCauseEstablished':False,'serviceReadinessEstablished':False,'releaseAcceptance':False}

def main():
    require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated
        and sys.flags.no_site and sys.dont_write_bytecode,'ROOT_ISOLATED_NO_ARGUMENT_READER_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('DISCOVERY_TIME_BOUND')));signal.alarm(15)
    try:return observe()
    finally:signal.alarm(0)

if __name__=='__main__':
    try:
        result=main();code=0
    except BaseException as error:
        result={'schema':'ouf.semantic-registry-owner-discovery-result.v1','status':'STOP_RECONCILE',
            'complete':False,'readOnly':True,'reasonCode':str(error) if type(error) is Stop else 'METADATA_OBSERVATION_UNPROVEN',
            'rawErrorPrinted':False,'credentialValuesPrinted':False,'runtimeEffectsDispatched':0,
            'runtimeAuthorityIssued':False,'activationResubmitted':False,'automaticReplayAllowed':False,'budgetReset':False}
        code=1
    print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False));raise SystemExit(code)
