#!/usr/bin/env python3
"""Read retained finite delivery and classify Registry log markers; no recovery."""
import hashlib, http.client, json, os, re, selectors, signal, socket, stat, subprocess, sys, tempfile, time

from pathlib import Path

from urllib.parse import quote

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b')

REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'

AUTHORITY='a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca'

SOURCE='d7bbb768970aad1a001ca4d085bcc87c58a29cec'

UNIT='ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-semantic-denial-readback.v1',check=check,readOnly=True,
        automaticRetry=False,budgetReset=False,acceptanceGranted=False)
    require(not set(values)&set(fixed),'RESERVED_OUTPUT_FIELD')
    print(json.dumps({**fixed,**values},sort_keys=True),flush=True)

class ReadDenied(Exception):pass

def require(ok,code):
    if not ok:raise ReadDenied(code)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def unique(rows):
    d={}
    for k,v in rows:require(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
    return d

def read(path,maximum=262144,expected=None):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_READ_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_BOUNDED_RECORD_REQUIRED')
        raw=bytearray()
        while len(raw)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part)
        require(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'READ_DRIFT')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'READ_HASH_DRIFT')
        return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ReadDenied('NONFINITE_JSON')))
    finally:os.close(fd)

def bounded(argv, seconds=15, maximum=2097152, discard=False):
    """Drain both pipes concurrently; cap bytes/time and kill the CLI on exit."""
    proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    output=bytearray(); errors=bytearray(); count=0; end=time.monotonic()+seconds
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ,'out')
            selector.register(proc.stderr,selectors.EVENT_READ,'err')
            while selector.get_map():
                require(time.monotonic()<end,'DIAGNOSTIC_HOST_TIME_BOUND_EXHAUSTED')
                for key,_ in selector.select(min(0.2,max(0,end-time.monotonic()))):
                    raw=os.read(key.fd,65536)
                    if not raw:selector.unregister(key.fileobj);continue
                    if key.data=='out':
                        count+=len(raw);require(count<=maximum,'DIAGNOSTIC_OUTPUT_BOUND_EXHAUSTED')
                        if not discard:output.extend(raw)
                    else:
                        require(len(errors)+len(raw)<=maximum,'DIAGNOSTIC_STDERR_BOUND_EXHAUSTED')
                        errors.extend(raw)
            code=proc.wait(timeout=max(0.01,end-time.monotonic()))
        return code,bytes(output),bytes(errors),count
    finally:
        if proc.poll() is None:proc.kill()
        proc.wait(timeout=5);proc.stdout.close();proc.stderr.close()

def executable(binding):
    path=Path(binding['path']);info=path.stat()
    require(path.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid==0 and
        not info.st_mode&0o022 and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],
        'NATIVE_EXECUTABLE_BINDING_DRIFT')
    return str(path)

def safe_status(value):
    result={}
    for key in ('state','phase','reason'):
        if key in value:
            v=value[key]
            require(type(v)is str and re.fullmatch('[A-Z][A-Z0-9_]{0,120}',v),'UNSAFE_STATUS_VALUE')
            result[key]=v
    for key in ('attempts','publications','controlledCumulativeGrantAttempts'):
        if key in value:
            v=value[key]
            require(type(v)is int and 0<=v<=1000000,'UNSAFE_COUNTER')
            result[key]=v
    return result

def service_state(binding):
    code,raw,_,_=bounded([executable(binding),'show',UNIT,
        '--property=ActiveState,SubState,MainPID,Result,ExecMainCode,ExecMainStatus,Job'])
    require(code==0,'SYSTEMCTL_READ_FAILED')
    values=dict(line.split('=',1)for line in raw.decode('ascii').splitlines()if '='in line)
    require(set(values)=={'ActiveState','SubState','MainPID','Result','ExecMainCode','ExecMainStatus','Job'},
        'SYSTEMCTL_FIELDS_CHANGED')
    require(all(re.fullmatch('[A-Za-z0-9_:-]{0,80}',v)for v in values.values()),'UNSAFE_SYSTEMCTL_VALUE')
    return values

def log_markers(raw):
    # Counts are evidence of markers in a bounded sample, never proof of cause.
    names=('SEM_CAPABILITY_REQUIRED:ouf.semantic.propose','SEM_PROPOSAL_RECEIPT_INVALID',
        'NO_POLICY_BUNDLE','STALE_POLICY_BUNDLE','BUNDLE_HASH_MISMATCH',
        'CAPABILITY_NOT_DECLARED','ACTOR_NOT_ALLOWED','SCOPE_MISSING','NO_APPLICABLE_GRANT',
        'EXPLICIT_DENY','AUTHORIZATION_UNAVAILABLE')
    return {name:len(re.findall(rb'(?<![A-Z0-9_])'+re.escape(name.encode())+rb'(?![A-Za-z0-9_.:])',raw))for name in names}

def main():
    require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_READER_REQUIRED');signal.alarm(120)
    emit('BEGIN',maximumSeconds=120,grantRequests=0,iamCalls=0,mcpCalls=0,
        databaseCalls=0,gatewayWrites=0,serviceMutations=0,maximumLogLines=200)
    review=read(CONTEXT/'review.json',8388608,REVIEW)
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and all(authority[k]==v for k,v in review['scopes'].items()),'EXACT_RETAINED_AUTHORITY_REQUIRED')
    process=review['scopes']['finiteActionProcess'];programs=review['sourceClosure']['executables']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'PROCESS_BINDING_DRIFT')
    before=service_state(programs['systemctl'])
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']
        and digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    status=read(CONTEXT/'delivery-status.json',16384)
    require(status.get('authorityHash')==AUTHORITY,'STATUS_AUTHORITY_DRIFT')
    emit('DELIVERY',**safe_status(status),systemd=before,recordHash=digest(status),
        authorityExpiredAtRead=time.time()>=authority['expiresAt'],terminalReasonIndependentlyProven=False)
    worker=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(worker)==p['postGrantWorkerDirectory'],'WORKER_BINDING_DRIFT')
    for filename,label in (('recovery.json','WORKER'),('owner-session.json','SESSION'),
                           ('owner-admission.json','ADMISSION'),('owner-status.json','LAST_REPORTED_STATUS')):
        value=read(worker/filename,8388608)
        emit(label,**safe_status(value),recordHash=digest(value),
            liveStateProven=False,cumulativeCountProven='controlledCumulativeGrantAttempts'in value)
    # Exact Registry generation retained in the previous qualified consultation reader.
    registry='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
    from datetime import datetime,timezone
    since=datetime.fromtimestamp(1792148226,tz=timezone.utc).isoformat()
    code,out,err,count=bounded([executable(programs['docker']),'logs','--since',since,
        '--tail','200',registry],seconds=15,maximum=2097152)
    emit('REGISTRY_LOG_SAMPLE',exitCode=code,stdoutBytes=count,stderrBytes=len(err),
        markerCounts=log_markers(out+b'\n'+err),rawLinesPrinted=False,
        ownerEffectivePolicyProven=False,diagnosisFromMarkerAlone=False)
    after=service_state(programs['systemctl'])
    require(before==after,'PROCESS_CHANGED_DURING_READ')
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    emit('END',complete=True,reconciliationPerformed=False,runtimeAuthorityIssued=False,
        completedTechnicalPhases=8,functionalMilestonesProven=0,recordsMayChangeIndependently=True)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False)
        sys.exit(2)


