#!/usr/bin/env python3
"""Classify retained Config fields only. No Engine, HTTP, namespace or credential IO."""
import hashlib,json,os,re,signal,stat,sys
from pathlib import Path
INPUTS=Path('/etc/ouf/deploy-snapshots/acquisition-evidence-current-inputs-v1/inputs.json')
INPUTS_HASH='c40ba6dc86e8be72ddcda2eaef65fe3eb8aa9f24b8ec4b0d5758b0bfeacf1da6'
PARENT=Path('/etc/ouf/deploy-snapshots/acquisition-read-native-plan-v1')
ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-retained-config-difference-v1')
CREATE_FIELDS=set('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck Image Volumes WorkingDir Entrypoint Labels StopSignal StopTimeout'.split())
KNOWN_EXTRA=set('ArgsEscaped Shell OnBuild NetworkDisabled MacAddress'.split())
READS=0
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
    out={}
    for k,v in pairs:require(k not in out,'DUPLICATE_JSON_KEY');out[k]=v
    return out
def decode(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Stop('NONFINITE_JSON')))
def frame(s):return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def ancestry(path):
    require(path.is_absolute()and'..'not in path.parts,'ABSOLUTE_ROOT_PATH_REQUIRED')
    for parent in(path,*path.parents):
        v=parent.lstat();require(stat.S_ISDIR(v.st_mode)and v.st_uid==0 and not v.st_mode&0o022,'ROOT_PRIVATE_ANCESTRY_REQUIRED')
def protected(path,expected=None):
    global READS
    ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        v=os.fstat(fd);require(stat.S_ISREG(v.st_mode)and v.st_uid==v.st_gid==0 and v.st_nlink==1 and stat.S_IMODE(v.st_mode)in(0o400,0o600)and 0<v.st_size<=8*1024*1024,'PROTECTED_BOUNDED_METADATA_REQUIRED')
        raw=os.read(fd,v.st_size+1);require(len(raw)==v.st_size and frame(v)==frame(os.fstat(fd))==frame(path.lstat()),'PRIVATE_METADATA_CHANGED')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'EXACT_PRIVATE_METADATA_HASH_REQUIRED');READS+=1;return raw
    finally:os.close(fd)
def put(path,value):
    raw=encoded(value);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as s:s.write(raw);s.flush();os.fsync(s.fileno())
    finally:os.close(fd)
def classify(config):
    require(type(config)is dict and len(config)<=64 and all(type(k)is str for k in config),'BOUNDED_CONFIG_OBJECT_REQUIRED')
    rows=[]
    for key in sorted(set(config)-CREATE_FIELDS):
        value=config[key];empty=value in(None,False,0,'',[],{})
        row={'field':key if key in KNOWN_EXTRA else 'UNKNOWN_FIELD','fieldNameRecognized':key in KNOWN_EXTRA,'type':type(value).__name__,'defaultEmptyUnderOriginalGuard':empty,'causesOriginalGuardStop':not empty}
        if key not in KNOWN_EXTRA:row['fieldNameSha256']=hashlib.sha256(key.encode()).hexdigest()
        if type(value)is bool:row['booleanClassification']='TRUE'if value else'FALSE'
        if key=='Shell':
            row['shellClassification']={('sh','-c'):'SH',('/bin/sh','-c'):'BIN_SH',('/bin/bash','-c'):'BIN_BASH',('/bin/bash','-o','pipefail','-c'):'BIN_BASH_PIPEFAIL'}.get(tuple(value),'OTHER')if type(value)is list and all(type(v)is str for v in value)else'OTHER'
        rows.append(row)
    return rows
def run(inputs_path=INPUTS,inputs_hash=INPUTS_HASH,parent=PARENT,root=ROOT):
    require(os.geteuid()==os.getegid()==0,'ROOT_RETAINED_READER_REQUIRED');ancestry(root.parent)
    require(not os.path.lexists(root),'RETAINED_READER_CONSUMED_NO_REPLAY');root.mkdir(mode=0o700)
    put(root/'claim.json',{'schema':'ouf.acquisition-retained-config-claim.v1','maximumPrivateReads':6,'maximumSeconds':30,'automaticReplayAllowed':False})
    ancestry(parent);claim=decode(protected(parent/'claim.json'))
    require(claim.get('schema')=='ouf.acquisition-native-plan-claim.v1'and claim.get('caseHash')=='2f9a2336572e1bbc57215bc6fc7b4f3a5f9bc5fa74e160be751cc0f57dcb8a80'and claim.get('maximumEngineGets')==0 and claim.get('maximumAdminGets')==1,'EXACT_STOPPED_PARENT_REQUIRED')
    require(not any(os.path.lexists(parent/name)for name in('gateway-get-claim.json','gateway-response.json','execution-plan.json','complete.json')),'PARENT_ADVANCED_BEYOND_RETAINED_CONFIG_STOP')
    inputs=decode(protected(inputs_path,inputs_hash));require(inputs.get('schema')=='ouf.acquisition-read-current-private-inputs.v1','EXACT_CAPTURED_INPUT_SCHEMA_REQUIRED')
    roles={}
    for role in('ingestion','udp','mcp'):
        ref=inputs['currentObservations'][role];actual=decode(protected(Path(ref['path']),ref['sha256']));roles[role]=classify(actual['Config'])
    protected(inputs_path,inputs_hash)
    first=next((role for role in roles if any(r['causesOriginalGuardStop']for r in roles[role])),None)
    require(first is not None,'RETAINED_STOP_NOT_REPRODUCED')
    result={'schema':'ouf.acquisition-retained-config-difference.v1','status':'RETAINED_CONTAINER_CONFIG_FIELDS_CLASSIFIED','complete':True,'capturedInputsHash':inputs_hash,'roleFields':roles,'firstFailingRoleInOriginalOrder':first,'originalGuardStopReproducedFromRetainedEvidence':True,'privateMetadataReads':READS,'maximumPrivateReads':6,'configurationValuesPrinted':False,'credentialValuesPrinted':False,'currentRuntimeStateObserved':False,'parentFilesWritten':0,'engineGetAttempts':0,'gatewayAdminGetAttempts':0,'networkNamespaceJoins':0,'serviceCredentialFilesOpened':0,'oauthRequests':0,'sqlSessions':0,'containerWrites':0,'imageImports':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    put(root/'complete.json',result);return result
def main():
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_NO_ARGUMENTS_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('FINITE_RETAINED_READER_TIMEOUT')));signal.alarm(30)
        print(encoded(run()).decode());return 0
    except Exception as e:
        code=str(e)if isinstance(e,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(e))else'RETAINED_CONFIG_READER_UNPROVEN'
        print(encoded({'schema':'ouf.acquisition-retained-config-difference.v1','status':'STOP_RECONCILE','reasonCode':code,'complete':False,'privateMetadataReads':READS,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}).decode());return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
