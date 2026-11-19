#!/usr/bin/env python3
"""Read only retained transport metadata after the exact pre-review STOP.

No Engine, SQL, HTTP, OAuth, credential/signing-key or old controller execution.
Original files are never written. Alternate cases exist only for isolated tests.
"""
import hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path

TARGET={
 'executionInputsPath':'/etc/ouf/deploy-snapshots/onboarding-diagnostic-image-inputs-5909d1003e88231c-v1/execution-inputs.json',
 'executionInputsHash':'c22586172070809d414d3654f3e002b7e1d84d749daae9b31dac8d1d14cbd0c0',
 'frozenPath':'/etc/ouf/deploy-snapshots/onboarding-budget-v35-54d86bbcd2ea47fd/native-plan-v1/execution-plan.json',
 'frozenHash':'b17c2c99cc791cced8ee00ed190e30b75c518ae84e2dd4a9ae7eef521390c8bd',
 'oldScope':'/etc/ouf/deploy-snapshots/onboarding-diagnostic-update-c22586172070809d-v1',
 'oldCode':'/usr/local/lib/ouf-onboarding-diagnostic-update-687aefc7514bbe7b',
 'oldManifestHash':'687aefc7514bbe7b8c25a7e88cb5621d510d617529576dae46902ba762b1dccf',
 'root':'/etc/ouf/deploy-snapshots/onboarding-diagnostic-transport-stop-read-c2258617-v1'}
FILES={'entry.py','authority.py','context.py','transport.py','ports.py','quarantine.py','state_fence.py','database.py',
 'recovery_journal.py','engine_creation.py','plan_helper.py','image_custody.py','retained_mac.py','terminal.py',
 'authentication.py','signing.py','auth_protocol.py','auth_preexec.py','auth_producer.py','runtime_binding.py','migration-fence.json'}
LIMITS={'engineGets':512,'engineWrites':10,'imageLoadAttempts':1,'readinessGets':96,'adminGets':0,'adminPuts':0,
 'ownerConfigurationReads':64,'ownerConfigurationContentReads':1,'serviceCredentialFileReads':0,'quarantineStops':1,'sqlSessions':4}
EXPECTED_STOP={'applicationE2EProven':False,'automaticReplayAllowed':False,'automaticRollbackPerformed':False,'budgetReset':False,
 'complete':False,'contextPath':None,'reasonCode':'EXACT_RETAINED_NATIVE_DATABASE_TRANSPORT_REQUIRED','releaseAcceptance':False,
 'runtimeEffectsMayBePartial':True,'schema':'ouf.onboarding-diagnostic-update-result.v1','status':'STOP_RECONCILE'}
class Stop(RuntimeError):pass
def require(ok,reason):
 if not ok:raise Stop(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def frame(s):return [getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def unique(rows):
 result={}
 for k,v in rows:require(k not in result,'DUPLICATE_RETAINED_KEY');result[k]=v
 return result
def decode(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Stop('NONFINITE_RETAINED_JSON')))
def ancestry(path):
 require(path.is_absolute()and'..'not in path.parts,'EXACT_ROOT_RETAINED_PATH_REQUIRED')
 for p in(path,*path.parents):
  s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_RETAINED_ANCESTRY_REQUIRED')
def write(root,name,value,mode=0o400):
 raw=value if isinstance(value,bytes)else encoded(value);fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb')as out:os.fchmod(out.fileno(),mode);out.write(raw);out.flush();os.fsync(out.fileno())
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def compare(before,after):
 """Only shapes, field names and hashes. Never print private scalar values."""
 out=[]
 def shape(value,present):return {'present':present,'type':type(value).__name__ if present else'ABSENT','sha256':digest(value)if present else None}
 def segment(key):return key if type(key)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_-]{0,63}',key)else'opaqueKey'
 def walk(a,b,path,pa=True,pb=True,depth=0):
  require(depth<=8 and len(out)<=64,'BOUNDED_TRANSPORT_DIFFERENCES_REQUIRED')
  if pa and pb and type(a)is type(b)and a==b:return
  if pa and pb and type(a)is type(b)is dict:
   require(len(a)<=32 and len(b)<=32,'BOUNDED_TRANSPORT_OBJECT_REQUIRED')
   for k in sorted(set(a)|set(b)):walk(a.get(k),b.get(k),path+[segment(k)],k in a,k in b,depth+1)
  elif pa and pb and type(a)is type(b)is list and len(a)==len(b)<=16:
   for i,(x,y)in enumerate(zip(a,b)):walk(x,y,path+[i],depth=depth+1)
  else:out.append({'field':path,'retained':shape(a,pa),'captured':shape(b,pb)})
 walk(before,after,[]);require(len(out)<=64,'BOUNDED_TRANSPORT_DIFFERENCES_REQUIRED');return out
def reconcile(case=TARGET):
 require(os.geteuid()==os.getegid()==0,'ROOT_RETAINED_READ_REQUIRED');started=time.monotonic();root=Path(case['root']);ancestry(root.parent)
 require(not os.path.lexists(root),'TRANSPORT_STOP_READ_SCOPE_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700);root.chmod(0o700)
 write(root,'claim.json',{'schema':'ouf.onboarding-transport-stop-read-claim.v1','maximumMetadataReads':7,'maximumCodeReads':22,
  'maximumBytes':8388608,'maximumSeconds':60,'runtimeEffectsAllowed':False,'automaticReplayAllowed':False})
 counts={'privateMetadataReads':0,'protectedCodeReads':0,'bytes':0};seals={}
 def read(path,expected=None,*,code=False,limit=2097152,mode=0o400):
  require(time.monotonic()-started<60,'FINITE_RETAINED_READ_DEADLINE');path=Path(path);ancestry(path.parent)
  key='protectedCodeReads'if code else'privateMetadataReads';maximum=22 if code else 7
  require(counts[key]<maximum,'FINITE_RETAINED_READ_COUNT');counts[key]+=1
  write(root,'read-claim-%s-%02d.json'%(key,counts[key]),{'pathHash':sha(str(path).encode()),'attemptNotCompletion':True})
  fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
  try:
   s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode
    and 0<s.st_size<=limit,'EXACT_PROTECTED_RETAINED_FILE_REQUIRED')
   require(counts['bytes']+s.st_size<=8388608,'FINITE_RETAINED_READ_BYTES');raw=os.read(fd,s.st_size+1);counts['bytes']+=len(raw)
   require(len(raw)==s.st_size and frame(s)==frame(os.fstat(fd))==frame(path.lstat()),'RETAINED_FILE_CHANGED_DURING_READ')
   require(expected is None or sha(raw)==expected,'EXACT_RETAINED_FILE_HASH_REQUIRED');seals[str(path)]=frame(s);return raw
  finally:os.close(fd)
 old_code=Path(case['oldCode']);manifest=decode(read(old_code/'sources.json',case['oldManifestHash'],code=True,limit=131072))
 require(type(manifest)is dict and set(manifest)==FILES,'EXACT_STOPPED_CONTROLLER_SOURCE_SET_REQUIRED')
 for name,h in manifest.items():
  require(type(h)is str and re.fullmatch('[a-f0-9]{64}',h),'EXACT_STOPPED_CONTROLLER_SOURCE_HASH_REQUIRED');read(old_code/name,h,code=True,limit=131072)
 old=Path(case['oldScope']);ancestry(old)
 names=[]
 with os.scandir(old)as entries:
  for row in entries:names.append(row.name);require(len(names)<=4,'UNISSUED_PREFLIGHT_ONLY_NO_AUTHORITY_OR_JOURNAL')
 attempts=sorted(n for n in names if re.fullmatch(r'preflight-attempt-[1-9][0-9]{0,9}-[0-9]{5}\.json',n))
 require(len(attempts)==3 and set(names)=={'preparation-claim.json',*attempts},'EXACT_THREE_PRE_REVIEW_METADATA_ATTEMPTS_REQUIRED')
 claim=decode(read(old/'preparation-claim.json',limit=8192))
 require(claim=={'schema':'ouf.onboarding-diagnostic-update-preflight-claim.v1','executionInputsHash':case['executionInputsHash'],
  'maximums':LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False},'EXACT_UNISSUED_ORIGINAL_CLAIM_REQUIRED')
 for i,name in enumerate(attempts,1):
  require(decode(read(old/name,limit=8192))=={'kind':'ownerConfigurationReads','attempt':i,'attemptNotCompletion':True},'EXACT_RETAINED_PREFLIGHT_COUNTS_REQUIRED')
 require(decode(read(old_code/'operator.log',limit=8192,mode=0o600))==EXPECTED_STOP,'EXACT_TERMINAL_TRANSPORT_STOP_REQUIRED')
 prepared=decode(read(case['executionInputsPath'],case['executionInputsHash']));frozen=decode(read(case['frozenPath'],case['frozenHash']))
 require(prepared['schema']=='ouf.onboarding-diagnostic-private-execution-inputs.v1'and prepared['runtimeAuthorityIssued']is False
  and frozen['schema']=='ouf.onboarding-v35-frozen-native-plan.v1','EXACT_PREPARED_AND_HISTORICAL_IDENTITY_REQUIRED')
 profile=frozen['boundDatabaseProfile'];retained=profile['engineBinding'];current=prepared['engineBinding']
 require(type(retained)is dict and type(current)is dict,'TYPED_RETAINED_ENGINE_METADATA_REQUIRED')
 checks={'profileSchema':profile.get('schema')=='ouf.current-onboarding-database-snapshot-profile.v1',
  'engineBinding':retained==current,'runtimeBindingProfile':profile.get('runtimeBindingProfile')=='ouf.runtime-binding.native-mount-order.v1'}
 require(not all(checks.values()),'RETAINED_STOP_CAUSE_NOT_REPRODUCED')
 counts_before={k:0 for k in LIMITS};counts_before['ownerConfigurationReads']=3
 safe_schemas={'ouf.current-onboarding-database-snapshot-profile.v1','ouf.runtime-binding.native-mount-order.v1','ouf.runtime-binding.mounts-sorted-destination.v1'}
 result={'schema':'ouf.onboarding-transport-retained-stop-read.v1','status':'RETAINED_ONBOARDING_TRANSPORT_STOP_OBSERVED_NO_AUTHORITY','complete':True,
  'contextPath':str(root),'guardChecks':checks,'failedGuardChecks':[k for k,v in checks.items()if not v],
  'observedProfileSchema':profile.get('schema')if profile.get('schema')in safe_schemas else'UNRECOGNIZED',
  'observedRuntimeBindingProfile':profile.get('runtimeBindingProfile')if profile.get('runtimeBindingProfile')in safe_schemas else'UNRECOGNIZED',
  'engineBindingDifferences':compare(retained,current),'sameSocketPath':retained.get('socketPath')==current.get('socketPath'),
  'sameSocketCustody':retained.get('socketBinding')==current.get('socketBinding'),'samePeerCredentials':retained.get('peerCredentials')==current.get('peerCredentials'),
  'retainedEngineBindingHash':digest(retained),'capturedEngineBindingHash':digest(current),
  'retainedPreflightCounts':counts_before,'counts':counts,'originalAuthorityAndJournalAbsent':True,
  'pinnedCodeAndRetainedClaimsProveNoRuntimeDispatch':True,'originalScopeConsumed':True,
  'originalFilesWritten':0,'currentRuntimeStateObserved':False,'newEngineRequests':0,'sqlSessions':0,'oauthRequests':0,
  'credentialFileReads':0,'signingKeyReads':0,'configurationContentReads':0,'runtimeAuthorityIssued':False,'continuationAuthorized':False,
  'acquisitionsExecuted':0,'sourceActivations':0,'addressesPrinted':False,'credentialValuesPrinted':False,
  'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
 for path,metadata in seals.items():require(frame(Path(path).lstat())==metadata,'ORIGINAL_RETAINED_FILE_SEAL_CHANGED')
 require(sorted(os.listdir(old))==sorted(names),'ORIGINAL_PREFLIGHT_DIRECTORY_CHANGED');write(root,'result.json',result);return result
def main():
 require(len(sys.argv)==1 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_RETAINED_READ_ONLY_ENTRY_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('FINITE_RETAINED_READ_DEADLINE')));signal.alarm(60)
 try:
  result=reconcile();write(Path(TARGET['root']),'operator.log',encoded(result)+b'\n',0o600);print(encoded(result).decode(),flush=True);return 0
 except Exception as error:
  reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'RETAINED_TRANSPORT_READ_UNPROVEN'
  print(encoded({'schema':'ouf.onboarding-transport-retained-stop-read.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
   'runtimeAuthorityIssued':False,'continuationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}).decode(),flush=True);return 2
 finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
