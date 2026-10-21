"""Fresh isolated bootstrap for the separately sealed HUMAN administrative action."""
import ast,base64,hashlib,json,os,re,stat,sys
from pathlib import Path

def require(ok,reason):
    if not ok:raise ValueError(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))

def raw_read(path,maximum=8388608,expected=None):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
    for parent in path.parents:
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd);require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0
            and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
        pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(len(raw)==st.st_size and pin(st)==pin(os.fstat(fd))==pin(path.lstat())and(expected is None or sha(raw)==expected),
            'PRIVATE_BYTES_CHANGED')
        return raw
    finally:os.close(fd)

def read(path,maximum=8388608,expected=None):
    return json.loads(raw_read(path,maximum,expected))

SAFE_CODES=set()
LAST_PHASE="BOOTSTRAP"
SAFE_CONTEXT=None
SAFE_CASE=None
def emit(value):
    global LAST_PHASE
    if type(value)is str and re.fullmatch("OUF_MCP_INGESTION_PHASE=[A-Z0-9_]{1,100}",value):LAST_PHASE=value.split("=",1)[1]
    print(value,flush=True)

def main(context,package_hash):
    global SAFE_CODES,SAFE_CONTEXT,SAFE_CASE
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
    os.umask(0o077);context=Path(context);SAFE_CONTEXT=context
    require(context.parent==Path('/etc/ouf/deploy-snapshots') and context.name.startswith('installation-owner-update-execution-'),
        'EXACT_ADMINISTRATIVE_CONTEXT_REQUIRED')
    package=read(context/'package.json',expected=package_hash)
    require(package['schema']=='ouf.mcp-ingestion-read-transport-package.v1' and package['runtimeAuthorityIssued']is False,
        'EXACT_ADMINISTRATIVE_PACKAGE_REQUIRED')
    raw={}
    for name,h in package['fileHashes'].items():
        require(Path(name).name==name,'SAFE_PACKAGE_MEMBER_REQUIRED')
        raw[name]=raw_read(context/name,expected=h)
        require(sha(raw[name])==h,'PACKAGE_SOURCE_CHANGED')
    require(set(raw)=={'case.json','bootstrap.py','runtime.py','reader.py','sources.json'}
        and sha(Path(__file__).read_bytes())==package['executionPins']['executorSha256'], 'EXACT_BOOTSTRAP_CLOSURE_REQUIRED')
    case=json.loads(raw['case.json']);SAFE_CASE=case;require(digest(case)==package['executionPins']['caseSha256'],'CASE_CHANGED')
    sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(raw['sources.json']).items()}
    SAFE_CODES={n.value for code in sources.values()for n in ast.walk(ast.parse(code))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
    memory={'__name__':'verified_new_administrative_loader'}
    exec(compile(raw['runtime.py'],'<new-administrative-loader>','exec'),memory)
    entry,declaration=memory['load_entry'](package['sourceCommit'],sources,raw['runtime.py'],package['declarationHash'],
        package['sourcePins'],package['executionPins'])
    require(declaration==package['closure']['declaration'],'DECLARATION_CHANGED')
    # Claim the runtime launch once, before any IAM/issuer/effect dispatch.
    fd=os.open(context/'runtime.claim.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:os.write(fd,encoded({'packageHash':package_hash,'automaticReplayAllowed':False}));os.fsync(fd)
    finally:os.close(fd)
    original=read(case['originalBinding']['path'],expected=case['originalBinding']['sha256'])
    entry.main(original,sources,package['closure'],case,context,read,emit)

if __name__=='__main__':
    try:
        require(len(sys.argv)==3,'EXACT_CONTEXT_AND_PACKAGE_HASH_REQUIRED');main(sys.argv[1],sys.argv[2])
    except (Exception,KeyboardInterrupt)as error:
        report={'schema':'ouf.installation-owner-update-stop.v1','status':'STOP_RECONCILE',
            'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in SAFE_CODES else'PRIVATE_DETAILS_REDACTED',
            'humanSnapshotRole':'EXISTING_SESSION_STOP_READ','currentSuccessorStateRequeried':False,'lastPhase':LAST_PHASE,'contextPath':str(SAFE_CONTEXT)if SAFE_CONTEXT is not None else None,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeCompletionProven':False}
        if SAFE_CONTEXT is not None:
            report['artifactInventory']={n:os.path.lexists(SAFE_CONTEXT/n)for n in('execution-plan.json','review.json','issuance.claim.json','authority.json','recovery.json','update-result.json','login-window-receipt.json','compatibility-review.json','compatibility-decision.json')}
        try:
            if SAFE_CASE is not None:
                binding=SAFE_CASE['humanBinding'];row=read(Path(binding['sessionDirectory'])/'recovery.json',65536)
                if row.get('binding')==binding and row.get('state')in('NEW','DEVICE_START','DEVICE_POLL','REQUESTING','RETRY_WAIT','VERIFYING','READY','BLOCKED')and type(row.get('attempts'))is int and 243<=row['attempts']<=256:
                    report['human']={'state':row['state'],'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'windowExpiresAt':binding['expiresAt']}
        except Exception:report['humanSnapshotAvailable']=False
        print(encoded(report).decode(),flush=True)
        raise SystemExit(2)
