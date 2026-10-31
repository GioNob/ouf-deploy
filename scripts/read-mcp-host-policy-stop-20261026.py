#!/usr/bin/env python3
"""One finite retained-file reconciliation. No runtime/credential/network access."""
import hashlib,json,os,re,signal,stat,sys
from pathlib import Path
INPUT=Path('/etc/ouf/deploy-snapshots/mcp-denial-update-inputs-9a374dd07745f059-v1/inputs.json')
NATIVE=Path('/etc/ouf/deploy-snapshots/mcp-denial-image-plan-fb4b7c9ae832e779-v1/native-plan.json')
STOPPED=Path('/etc/ouf/deploy-snapshots/mcp-diagnostic-update-ff06ec1afc5da65d-v1')
CODE=Path('/usr/local/lib/ouf-mcp-diagnostic-update-1c9bc1010621eb15')
ROOT=Path('/etc/ouf/deploy-snapshots/mcp-host-policy-stop-read-ff06ec1a-v1')
IH='fb4b7c9ae832e779192f1ff6e032e49c696752e182a57b8e9464f5a76000b3e4'
NH='ff06ec1afc5da65dc6b6c64edb9ab9ec87926f4a9de7aec355b69b96c4cd8653'
SOURCE={'entry.py':'35b7cef0ce2b157ff8a8dfd7e5fdfb165b42a973be57675a8774fd88eb535070','context.py':'b29741540a7e8591d958b450da966e5f8718de33ad67ee1e8a938d2d770d3555','sources.json':'1c9bc1010621eb159a81a486273497427b4119423880a8746c28f4191e2a08a7'}
LIMITS={'engineGets':256,'engineWrites':10,'imageLoadAttempts':1,'readinessGets':96,'adminGets':0,'adminPuts':0,'ownerConfigurationReads':64,'serviceCredentialFileReads':0,'quarantineStops':1}
class Stop(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Stop(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def decode(raw):
    def unique(rows):
        result={}
        for k,v in rows:require(k not in result,'DUPLICATE_RETAINED_KEY');result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'NONFINITE_RETAINED_JSON'))
def frame(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def ancestry(path):
    require(path.is_absolute()and path.resolve()==path,'CANONICAL_ROOT_PATH_REQUIRED')
    for p in(path,*path.parents):
        s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_ANCESTRY_REQUIRED')
def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def put(path,v):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb')as f:os.fchmod(f.fileno(),0o400);f.write(encoded(v));f.flush();os.fsync(f.fileno())
    sync(path.parent)
def fields(host):
    out={}
    for k in('AutoRemove','Memory','OomKillDisable'):
        v=host.get(k);require(v is None or type(v)in(bool,int),'TYPED_HOST_POLICY_METADATA_REQUIRED')
        out[k]={'present':k in host,'type':type(v).__name__,'value':v}
    return out
def observe(root=ROOT,stopped=STOPPED,native=NATIVE,inputs=INPUT,code=CODE,ih=IH,nh=NH,sources=SOURCE):
    ancestry(root.parent);require(not os.path.lexists(root),'RETAINED_HOST_POLICY_READ_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700);root.chmod(0o700);sync(root.parent)
    put(root/'claim.json',{'schema':'ouf.mcp-host-policy-stop-read-claim.v1','maximumFileReads':9,'maximumBytes':13*1024*1024,'networkRequests':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False})
    seals={};counts={'fileReads':0,'bytes':0}
    def read(path,maximum,expected=None,mode=None):
        require(counts['fileReads']<9,'NINE_RETAINED_READS_MAXIMUM');counts['fileReads']+=1;put(root/('read-claim-%02d.json'%counts['fileReads']),{'attemptNotCompletion':True,'maximumBytes':maximum})
        ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)in((mode,)if mode else(0o400,0o600))and 0<s.st_size<=maximum,'PROTECTED_BOUNDED_RETAINED_FILE_REQUIRED')
            raw=b''
            while len(raw)<s.st_size:
                b=os.read(fd,min(65536,s.st_size-len(raw)));require(b,'COMPLETE_RETAINED_READ_REQUIRED');raw+=b
            require(frame(s)==frame(os.fstat(fd))==frame(path.lstat()),'RETAINED_FILE_CHANGED');counts['bytes']+=len(raw);require(counts['bytes']<=13*1024*1024,'FINITE_RETAINED_BYTES_REQUIRED')
            require(expected is None or sha(raw)==expected,'EXACT_RETAINED_BYTES_REQUIRED');seals[path]=frame(s);return raw
        finally:os.close(fd)
    ancestry(stopped);before=frame(stopped.lstat());names=[]
    with os.scandir(stopped)as entries:
        for e in entries:
            names.append(e.name);require(len(names)<=3,'ONLY_PREFLIGHT_FILES_REQUIRED')
    attempts=sorted(n for n in names if re.fullmatch(r'preflight-attempt-[0-9]+-[0-9]{5}\.json',n))
    require(len(attempts)==2 and set(names)=={'preparation-claim.json',*attempts},'EXACT_STOPPED_PREFLIGHT_FILESET_REQUIRED')
    for name,h in sources.items():read(code/name,131072,h,0o400)
    stop=decode(read(code/'operator.log',65536,mode=0o600))
    require(stop.get('schema')=='ouf.mcp-diagnostic-update-result.v1'and stop.get('status')=='STOP_RECONCILE'and stop.get('reasonCode')=='FINITE_RETAINED_MCP_HOST_POLICY_REQUIRED'and stop.get('contextPath')is None and stop.get('complete')is False,'EXACT_RETAINED_HOST_POLICY_STOP_REQUIRED')
    claim=decode(read(stopped/'preparation-claim.json',4096,mode=0o400))
    require(claim=={'schema':'ouf.mcp-diagnostic-update-preflight-claim.v1','nativePlanHash':nh,'maximums':LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False},'EXACT_PREFLIGHT_CLAIM_REQUIRED')
    for i,name in enumerate(attempts,1):
        require(decode(read(stopped/name,4096,mode=0o400))=={'kind':'ownerConfigurationReads','attempt':i,'attemptNotCompletion':True},'EXACT_TWO_PREFLIGHT_READ_CLAIMS_REQUIRED')
    n=decode(read(native,6*1024*1024,nh));inp=decode(read(inputs,6*1024*1024,ih))
    require(n.get('schema')=='ouf.mcp-denial-native-image-plan.v1'and inp.get('schema')=='ouf.mcp-denial-update-inputs.v1'and n['proposal']['capturedInputsHash']==ih,'EXACT_RETAINED_NATIVE_INPUTS_REQUIRED')
    host=n['proposal']['mcpReplacement']['request']['HostConfig'];old=inp['currentObservations']['mcp']['HostConfig'];retained=n['proposal']['mcpReplacement']['oldNativeHostConfig']
    require(old==retained and {**host,'RestartPolicy':old['RestartPolicy']}==old,'RETAINED_HOST_POLICY_COPY_REQUIRED')
    values=fields(host);checks={'autoRemoveExactlyFalse':host.get('AutoRemove')is False,'memoryExactlyInt':type(host.get('Memory'))is int,'memoryStrictlyPositive':type(host.get('Memory'))is int and host['Memory']>0}
    require(not all(checks.values()),'HOST_POLICY_STOP_NOT_REPRODUCED')
    require(frame(stopped.lstat())==before and all(frame(p.lstat())==s for p,s in seals.items()),'ORIGINAL_RETAINED_METADATA_CHANGED')
    result={'schema':'ouf.mcp-host-policy-retained-stop-read.v1','status':'RETAINED_MCP_HOST_POLICY_STOP_OBSERVED_NO_AUTHORITY','complete':True,'hostPolicy':values,'failedGuardChecks':[k for k,v in checks.items()if not v],'retainedHostPolicyCopyExact':True,'retainedOriginalCounts':{'ownerConfigurationReads':2,'engineGets':0,'engineWrites':0},'retainedPreflightFileSetExact':True,'retainedClaimsAndPinnedCodeProveNoRuntimeDispatch':True,'currentRuntimeStateObserved':False,'counts':counts,'newEngineRequests':0,'networkRequests':0,'credentialFileReads':0,'signingKeyReads':0,'oauthRequests':0,'sqlSessions':0,'acquisitionsExecuted':0,'sourceActivations':0,'oldFilesWritten':0,'runtimeAuthorityIssued':False,'continuationAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    put(root/'result.json',result);return result
def main():
    try:
        require(os.geteuid()==os.getegid()==0 and len(sys.argv)==1 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_RETAINED_READ_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_RETAINED_READ_TIMEOUT'));signal.alarm(30);v=observe();print(encoded(v).decode());return 0
    except Exception as e:
        reason=str(e)if isinstance(e,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(e))else'RETAINED_HOST_POLICY_READ_UNPROVEN'
        print(encoded({'schema':'ouf.mcp-host-policy-retained-stop-read.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}).decode());return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
