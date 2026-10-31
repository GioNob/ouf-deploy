#!/usr/bin/env python3
"""Installation-specific offline reconciliation; never imports/runs the consumed APPLY."""
import hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path

INPUT_HASH='5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591'
REVIEW_HASH='4cdc8631745c00589e89c4763b34f57451032be714d168447df998dbbd1da328'
MANIFEST_HASH='49ef56c773b4bbb46e7be329931e41a3780fe58d022ff5d284b886c6cf0c0fe5'
ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-read-apply-'+INPUT_HASH)
CODE=Path('/etc/ouf/deploy-snapshots/acquisition-read-native-code-49ef56c773b4bbb4')
NATIVE=Path('/etc/ouf/deploy-snapshots/acquisition-native-execution-inputs-47b206e2eb602c11/native-inputs.json')
CHILD='unapproved-review-reconciliation-v1'
LIMITS={'engineGets':500,'engineWrites':22,'imageLoadAttempts':3,'readinessGets':128,'adminGets':32,'adminPuts':2,'ownerConfigurationReads':64,'serviceCredentialFileReads':1,'quarantineStops':3}
SOURCE_NAMES=set('apply.py protocol.py transport.py ports.py quarantine.py recovery_journal.py engine_creation.py plan_helper.py image_custody.py native_prepare.py authentication.py signing.py auth_protocol.py auth_preexec.py auth_producer.py runtime_binding.py'.split())

class Stop(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Stop(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pairs(rows):
    out={}
    for k,v in rows:
        require(k not in out,'DUPLICATE_RETAINED_JSON_KEY');out[k]=v
    return out
def decode(raw):return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(Stop('NONFINITE_RETAINED_JSON')))
def frame(v):return tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def ancestry(path):
    require(path.is_absolute()and path.resolve()==path,'CANONICAL_RETAINED_PATH_REQUIRED')
    for p in(path,*path.parents):
        s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_RETAINED_ANCESTRY_REQUIRED')
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(path,value):
    raw=encoded(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as s:s.write(raw);s.flush();os.fsync(s.fileno())
    finally:os.close(fd)
    sync(path.parent)
class Reader:
    def __init__(self):self.reads=0;self.bytes=0;self.started=time.monotonic();self.facts={}
    def read(self,path,expected=None):
        require(time.monotonic()-self.started<30,'OFFLINE_RECONCILIATION_DEADLINE');require(self.reads<96,'OFFLINE_METADATA_READ_LIMIT');self.reads+=1
        ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o400 and 0<before.st_size<=8388608,'IMMUTABLE_ROOT_RETAINED_FILE_REQUIRED')
            require(self.bytes+before.st_size<=33554432,'OFFLINE_METADATA_BYTE_LIMIT');raw=os.read(fd,before.st_size+1);self.bytes+=len(raw)
            require(len(raw)==before.st_size and frame(before)==frame(os.fstat(fd))==frame(path.lstat()),'RETAINED_FILE_CHANGED')
            require(expected is None or sha(raw)==expected,'EXACT_RETAINED_HASH_REQUIRED');self.facts[str(path)]=(frame(before),sha(raw));return raw
        finally:os.close(fd)
    def stable(self):
        for name,(metadata,_)in self.facts.items():require(frame(Path(name).lstat())==metadata,'RETAINED_METADATA_CHANGED')

def inventory(root,allow_child):
    ancestry(root);names={p.name for p in root.iterdir()};require(len(names)<=64,'BOUNDED_RETAINED_DIRECTORY_REQUIRED')
    if allow_child:
        require(CHILD in names,'EXCLUSIVE_RECONCILIATION_CLAIM_REQUIRED');names.remove(CHILD)
    require({'preparation-claim.json','review.json'}<=names,'RETAINED_PREPARATION_AND_REVIEW_REQUIRED')
    require(all(n in('preparation-claim.json','review.json')or re.fullmatch(r'preflight-(claim|engine-response|admin)-[0-9]{4}\.json',n)for n in names),'POST_REVIEW_OR_UNEXPECTED_ENTRY_RECONCILE_ONLY')
    for n in names:
        s=(root/n).lstat();require(stat.S_ISREG(s.st_mode)and s.st_nlink==1,'ONLY_REGULAR_RETAINED_PREFLIGHT_FILES')
    return names

def reconcile(reader,root=ROOT,code=CODE,native=NATIVE,review_hash=REVIEW_HASH,manifest_hash=MANIFEST_HASH):
    # Parameters are only for filesystem fixtures. main accepts no alternate paths or hashes.
    ancestry(root);child=root/CHILD;require(not os.path.lexists(child),'RECONCILIATION_SCOPE_CONSUMED_NO_REPLAY')
    child.mkdir(mode=0o700);sync(root)
    put(child/'claim.json',{'schema':'ouf.acquisition-unapproved-review-claim.v1','reviewHash':review_hash,'nativeInputsHash':INPUT_HASH,'maximumSeconds':30,'maximumMetadataReads':96,'maximumMetadataBytes':33554432,'automaticReplayAllowed':False,'budgetReset':False,'runtimeEffectsAuthorized':False})
    names=inventory(root,True);manifest=decode(reader.read(code/'sources.json',manifest_hash));require(type(manifest)is dict and set(manifest)==SOURCE_NAMES,'EXACT_RETAINED_SOURCE_MANIFEST_REQUIRED')
    closure={str(code/'sources.json'):manifest_hash}
    for name,h in manifest.items():
        require(type(h)is str and re.fullmatch('[a-f0-9]{64}',h),'TYPED_RETAINED_SOURCE_HASH_REQUIRED');reader.read(code/name,h);closure[str(code/name)]=h
    raw=reader.read(root/'review.json',review_hash);review=decode(raw);require(encoded(review)==raw,'CANONICAL_RETAINED_REVIEW_REQUIRED')
    require(review['schema']=='ouf.acquisition-read-native-review.v1'and review['executionRoot']==str(root)and review['logicalOperationRef']==INPUT_HASH and review['maximums']==LIMITS,'EXACT_RETAINED_REVIEW_BINDINGS_REQUIRED')
    require(review['nativePlanHash']==sha(encoded(review['nativePlan']))and review['sourceClosure']==closure and review['sourceClosureHash']==sha(encoded(closure)),'SEALED_RETAINED_REVIEW_CLOSURE_REQUIRED')
    require(review['maximumSeconds']==900 and review['negativeCleanup']=={'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':3,'disableCandidateRestartFirst':True},'RETAINED_FINITE_WINDOW_REQUIRED')
    require(all(review[k]is False for k in('databaseRestoreAuthorized','humanBudgetOrSourceActivationAuthorized','automaticReplayAllowed','budgetReset','releaseAcceptance')),'RETAINED_REVIEW_RESTRICTIONS_REQUIRED')
    n=decode(reader.read(native,INPUT_HASH));require(n['schema']=='ouf.acquisition-native-execution-inputs.v1'and n['frozenPlanHash']==review['frozenPlanHash']==review['nativePlan']['frozenPlanHash']and review['nativePlan']['nativeInputsHash']==INPUT_HASH,'RETAINED_NATIVE_INPUT_LINEAGE_REQUIRED')
    preparation=decode(reader.read(root/'preparation-claim.json'));require(preparation=={'schema':'ouf.acquisition-signed-execution-preparation-claim.v1','nativeInputsHash':INPUT_HASH,'maximums':LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False},'EXACT_ORIGINAL_PREPARATION_CLAIM_REQUIRED')
    counts={k:0 for k in LIMITS};serials=set();responses=0;admin=0
    for name in sorted(names-{'review.json','preparation-claim.json'}):
        serial=int(name[-9:-5]);require(serial>0 and serial not in serials,'UNIQUE_RETAINED_PREFLIGHT_SERIAL_REQUIRED');serials.add(serial)
        value=decode(reader.read(root/name))
        if name.startswith('preflight-claim-'):
            require(type(value)is dict and set(value)=={'kind','attempt','attemptNotCompletion'}and value['kind']in counts and value['attemptNotCompletion']is True,'EXACT_RETAINED_PREFLIGHT_CLAIM_REQUIRED')
            k=value['kind'];require(type(value['attempt'])is int and value['attempt']==counts[k]+1 and value['attempt']<=LIMITS[k],'PRESERVED_PREFLIGHT_COUNTER_SEQUENCE_REQUIRED');counts[k]+=1
        elif name.startswith('preflight-engine-response-'):responses+=1
        else:admin+=1
    # Claims and responses have a single global sequence; compare per-kind attempts in that order.
    # All claims for each kind are monotonically named by the original serial generator.
    require(serials==set(range(1,len(serials)+1)),'COMPLETE_RETAINED_PREFLIGHT_SEQUENCE_REQUIRED')
    require(type(review['preflightCounts'])is dict and counts==review['preflightCounts'],'EXACT_RETAINED_PREFLIGHT_COUNTS_REQUIRED')
    require(counts['engineGets']==responses==9 and counts['adminGets']==admin==1 and counts['serviceCredentialFileReads']==1 and counts['ownerConfigurationReads']==5,'OBSERVED_PRE_REVIEW_COUNT_PROFILE_REQUIRED')
    require(all(counts[k]==0 for k in('engineWrites','imageLoadAttempts','readinessGets','adminPuts','quarantineStops')),'NO_RETAINED_MUTATION_OR_READINESS_CLAIMS_REQUIRED')
    reader.stable();require(inventory(root,True)==names,'RETAINED_DIRECTORY_CHANGED')
    result={'schema':'ouf.acquisition-unapproved-review-reconciliation.v1','status':'UNAPPROVED_ACQUISITION_REVIEW_RECONCILED_NO_AUTHORITY','complete':True,'reviewHash':review_hash,'nativeInputsHash':INPUT_HASH,'originalScopeConsumed':True,'originalAuthorityAndJournalAbsent':True,'retainedClaimsProveNoRuntimeEffectsDispatched':True,'currentRuntimeStateObserved':False,'retainedPreflightCounts':counts,'retainedMaximums':LIMITS,'privateMetadataReads':reader.reads,'maximumPrivateMetadataReads':96,'newEngineRequests':0,'newAdminRequests':0,'newCredentialReads':0,'newSigningKeyReads':0,'sqlSessions':0,'oauthRequests':0,'sourceActivations':0,'humanBudgetsGranted':0,'automaticReplayAllowed':False,'budgetReset':False,'continuationAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
    put(child/'complete.json',result);reader.stable();require(inventory(root,True)==names,'RETAINED_DIRECTORY_CHANGED');return result

def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_OFFLINE_READER_REQUIRED')
        def timeout(*_):raise Stop('OFFLINE_RECONCILIATION_DEADLINE')
        signal.signal(signal.SIGALRM,timeout);signal.alarm(30)
        result=reconcile(Reader())
    except Exception as e:
        reason=str(e)if type(e)is Stop and re.fullmatch('[A-Z0-9_]{1,120}',str(e))else'RETAINED_RECONCILIATION_UNPROVEN'
        result={'schema':'ouf.acquisition-unapproved-review-reconciliation.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'automaticReplayAllowed':False,'budgetReset':False,'continuationAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
    print(encoded(result).decode(),flush=True);return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
