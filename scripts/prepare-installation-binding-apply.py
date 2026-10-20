"""Prepare new219-module two-gate binding action from completed owner files only."""
import ast, base64, gzip, hashlib, io, json, os, re, signal, stat, sys, tarfile, tempfile, time, zipfile
from pathlib import Path, PurePosixPath

def require(ok, code):
    if not ok:
        raise ValueError(code)

def encoded(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(v):
    return hashlib.sha256(v).hexdigest()

def digest(v):
    return sha(encoded(v))

def read(path, expected=None, maximum=8388608):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'EXACT_PRIVATE_PATH_REQUIRED')
    for parent in path.parents:
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and (not st.st_mode & 18), 'PRIVATE_ROOT_ANCESTRY_REQUIRED')
    return file_bytes(path, expected, maximum, private=True)

def file_bytes(path, expected, maximum, private=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and (0 < st.st_size <= maximum) and (not private or (st.st_uid == st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 384)), 'BOUNDED_CUSTODIED_MEMBER_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as f:
            raw = f.read(maximum + 1)
        pin = lambda s: tuple((getattr(s, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')))
        require(len(raw) == st.st_size and pin(st) == pin(os.fstat(fd)) == pin(path.lstat()) and (expected is None or sha(raw) == expected), 'EXACT_MEMBER_BYTES_CHANGED')
        return raw
    finally:
        os.close(fd)

def parsed(path, expected=None, maximum=8388608):
    return json.loads(read(path, expected, maximum))

def write_new(path, raw):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    try:
        with os.fdopen(os.dup(fd), 'wb') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
RESULT='704c8708d668161f0ddea45b997e493ef53dabd48c9db08128362223a33ba46c'
NAMES=('entry','authority','owner','native','baseline','login','runtime','bootstrap','compiler','prepare')
def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)==set(NAMES)and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_BINDING219_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('PREPARATION_DEADLINE')));signal.alarm(120)
 helpers={'__name__':'qualified_completed_owner_baseline'};exec(compile(delivery['baseline'],'<qualified-completed-owner-history-reader>','exec'),helpers)
 package,raw,sources,owner,result,prior,original,binding=helpers['history']()
 require(digest(result)==RESULT,'EXACT_COMPLETED_OWNER_READBACK_REQUIRED')
 # No token refresh or IAM request occurs in preparation.
 row=parsed(Path(binding['sessionDirectory'])/'recovery.json',maximum=65536)
 require(row['binding']==binding and row['state']=='READY'and type(row['attempts'])is int and row['attempts']==251
  and row['budgetReset']is False and row['binding']['expiresAt']==1792425259
  and time.time()>=row['lastObservedAt']
  and not os.path.lexists(Path(binding['sessionDirectory'])/'successor-window.claim.json'),'EXACT_RETAINED251_WINDOW_AND_NO_SUCCESSOR_REQUIRED')
 for name in ('entry','authority','owner','native','baseline','login'):sources['tools.installation_binding_apply.'+name]=delivery[name]
 memory={'__name__':'verified_new_binding219_loader'};exec(compile(delivery['runtime'],'<qualified-binding219-loader>','exec'),memory)
 memory['compile_sources'](sources);require(len(memory['MODULES'])==219,'EXACT_BINDING219_CLOSURE_REQUIRED')
 root=helpers['COMPLETED'].parent;claim_path=root/('installation-binding-native-preparation-'+RESULT+'.claim.json')
 require(not os.path.lexists(claim_path),'BINDING_NATIVE_ALREADY_PREPARED_NO_REPLAY')
 destination=Path(tempfile.mkdtemp(prefix='installation-binding-apply-execution-',dir=root));os.chmod(destination,0o700)
 claim={'context':str(destination),'completedOwnerResultHash':RESULT,'priorOAuthAttempts':251,'maximumCumulativeOAuthAttempts':256,
  'predecessorHumanWindowExpiresAt':1792425259,'requestedNewHumanWindowSeconds':7200,'newAuthenticationRequiresNativeConsent':True,'newFiniteWindowRequiresNativeConsent':True,'budgetReset':False,'automaticReplayAllowed':False}
 write_new(claim_path,encoded(claim));write_new(destination/'gateway-compiler.json',delivery['compiler'])
 old_case=json.loads(raw['case.json'])
 case={'originalBinding':old_case['originalBinding'],'humanBinding':binding,'priorOAuthAttempts':251,
  'completedOwnerResultHash':RESULT,'preparationClaimBinding':{'path':str(claim_path),'sha256':digest(claim)},
  'gatewayCompilerBinding':{'path':str(destination/'gateway-compiler.json'),'sha256':sha(delivery['compiler'])}}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],'reader.py':raw['reader.py'],
  'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit};execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'INSTALLATION_BINDING_APPLY'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution);closure={**package['closure'],'declaration':declaration}
 fresh={**package,'sourceCommit':commit,'sourcePins':pins,'executionPins':execution,'closure':closure,'declarationHash':digest(declaration),
  'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for name,value in members.items():write_new(destination/name,value)
 write_new(destination/'package.json',encoded(fresh))
 report={'schema':'ouf.installation-binding-native-preparation.v1','contextPath':str(destination),'sourceCommit':commit,
  'packageHash':digest(fresh),'sourceClosureHash':digest(closure),'sourceModuleCount':219,'priorOAuthAttempts':251,
  'maximumCumulativeOAuthAttempts':256,'predecessorHumanWindowExpiresAt':1792425259,'requestedNewHumanWindowSeconds':7200,'humanSourceChanged':False,'oauthRequests':0,
  'newAuthenticationRequiresNativeConsent':True,'runtimeAuthorityIssued':False,'ownerMutations':0,'activeProjectionWrites':0,'gatewayWrites':0,
  'imageRebuilt':False,'completedOwnerUpdateReplayed':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));print('OUF_INSTALLATION_BINDING_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
