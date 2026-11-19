"""Prepare one distinct same-window244 capsule from exact stopped213 files; no network or replay."""
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
STOPPED=Path('/etc/ouf/deploy-snapshots/installation-owner-update-execution-cr_wsios')
PACKAGE='174b8f8325a2721eddc90480a0a6851f5b060de10790115e4f655cbd096a3e4a'
CLOSURE='64f6139235d2f06a5c3cc0a7b2393ec6e213c1c4a56b2e392372c2790e9695fd'
ARTIFACTS=('candidate-review.json','execution-plan.json','review.json','decision.json','human.json','authority.json','issuance.claim.json','recovery.json','update-result.json')
def retained():
 package=parsed(STOPPED/'package.json',PACKAGE)
 require(package['sourceCommit']=='15827c6d5ee9ed761ce9a534441e689ea6007dfa'and digest(package['closure'])==CLOSURE
  and package['closure']['declaration']['moduleCount']==213 and package['runtimeAuthorityIssued']is False
  and package['executionPins']['mode']=='INSTALLATION_OWNER_UPDATE','EXACT_STOPPED213_PACKAGE_REQUIRED')
 require(parsed(STOPPED/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False}
  and not any(os.path.lexists(STOPPED/n)for n in ARTIFACTS),'EXACT_PREAUTH_STOP_WITHOUT_LATER_EFFECTS_REQUIRED')
 require(set(package['fileHashes'])=={'case.json','bootstrap.py','runtime.py','reader.py','sources.json'},'EXACT_FIVE_STOPPED_MEMBERS_REQUIRED')
 raw={n:read(STOPPED/n,h)for n,h in package['fileHashes'].items()}
 case=json.loads(raw['case.json']);binding=case['humanBinding'];row=parsed(Path(binding['sessionDirectory'])/'recovery.json',maximum=65536)
 require(row['binding']==binding and row['state']=='BLOCKED'and type(row['attempts'])is int and row['attempts']==244
  and row.get('operation')=='REFRESH'and row.get('reason')=='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN'
  and row['budgetReset']is False and binding['expiresAt']==1792425259 and len(binding['scopes'])==11
  and binding['retryProfile']['maximumAttempts']==256 and time.time()>=row['lastObservedAt']
  and time.time()+1200<binding['expiresAt']and time.monotonic()+1200<row['monotonicDeadline']
  and not os.path.lexists(Path(binding['sessionDirectory'])/'successor-window.claim.json'),'EXACT_BLOCKED244_ORIGINAL_WINDOW_NO_SUCCESSOR_REQUIRED')
 receipt=parsed(STOPPED/'preparation-result.json')
 require(receipt['packageHash']==PACKAGE and receipt['sourceClosureHash']==CLOSURE
  and receipt['candidateImageId']=='sha256:c124a832a1f9f07967a8f3ef9ba9692610ab5c97aa4719e614867f44e6aa63ae'
  and receipt['migrationEvidenceHash']=='d1b046b00ca761e04eb810402840c87e0dcbe7022051ea1ede80adcce68fb99a',
  'EXACT_COMPLETED_IMAGE_AND_MIGRATION_PREPARATION_REQUIRED')
 sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(raw['sources.json']).items()}
 hashes=package['closure']['declaration']['sourceHashes']
 require(set(sources)==set(hashes)and len(sources)==213 and all(sha(v)==hashes[n]for n,v in sources.items()),'STOPPED213_SOURCE_DRIFT')
 for key in('imageBinding','candidateMigrationEvidenceBinding'):
  ref=case[key];read(ref['path'],ref['sha256'])
 return package,case,raw,sources,row,receipt

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)=={'entry','prepare'}and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_DISTINCT_REAUTH_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('PREPARATION_DEADLINE')));signal.alarm(120)
 package,case,raw,sources,row,receipt=retained()
 sources['tools.installation_owner_update.entry']=delivery['entry']
 memory={'__name__':'verified_retained_owner_loader'};exec(compile(raw['runtime.py'],'<exact-retained213-loader>','exec'),memory)
 memory['compile_sources'](sources)
 require(len(memory['MODULES'])==213,'RETAINED213_MODULE_COUNT_REQUIRED')
 original_claim=parsed(case['preparationClaimBinding']['path'],case['preparationClaimBinding']['sha256'])
 require(original_claim['context']==str(STOPPED)and original_claim['priorOAuthAttempts']==243
  and original_claim['budgetReset']is False and original_claim['automaticReplayAllowed']is False,'EXACT_CONSUMED_OWNER_PREPARATION_REQUIRED')
 claim_path=STOPPED.parent/('installation-owner-reauth244-'+digest({'stoppedPackageHash':PACKAGE,'imageId':receipt['candidateImageId']})+'.claim.json')
 require(not os.path.lexists(claim_path),'DISTINCT_REAUTH244_PREPARATION_ALREADY_CLAIMED')
 destination=Path(tempfile.mkdtemp(prefix='installation-owner-update-execution-',dir=STOPPED.parent));os.chmod(destination,0o700)
 claim={**original_claim,'context':str(destination),'priorOAuthAttempts':244,'stoppedPackageHash':PACKAGE,
  'newWindowAllowed':False,'windowExpiresAt':1792425259,'newLoginRequiresNativeConsent':True}
 write_new(claim_path,encoded(claim))
 case={**case,'humanBinding':copy_binding(row['binding']),'priorOAuthAttempts':244,
  'preparationClaimBinding':{'path':str(claim_path),'sha256':digest(claim)},
  'sameWindowReauthentication':{'stoppedContext':str(STOPPED),'stoppedPackageHash':PACKAGE,'stoppedClosureHash':CLOSURE,
   'priorOAuthAttempts':244,'windowExpiresAt':1792425259,'newWindowAllowed':False,'oldRefreshReplayAllowed':False,'budgetReset':False}}
 members={'case.json':encoded(case),'bootstrap.py':raw['bootstrap.py'],'runtime.py':raw['runtime.py'],'reader.py':raw['reader.py'],
  'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit};execution={**package['executionPins'],'caseSha256':digest(case)}
 declaration=memory['declaration'](commit,sources,raw['runtime.py'],pins,execution)
 closure={**package['closure'],'declaration':declaration}
 fresh={**package,'sourceCommit':commit,'sourcePins':pins,'executionPins':execution,'closure':closure,
  'declarationHash':digest(declaration),'fileHashes':{n:sha(v)for n,v in members.items()}}
 for name,value in members.items():write_new(destination/name,value)
 write_new(destination/'package.json',encoded(fresh))
 report={'schema':'ouf.installation-owner-reauth244-preparation.v1','contextPath':str(destination),'sourceCommit':commit,
  'sourceModuleCount':213,'packageHash':digest(fresh),'sourceClosureHash':digest(closure),'stoppedPackageHash':PACKAGE,
  'priorOAuthAttempts':244,'maximumCumulativeOAuthAttempts':256,'humanWindowExpiresAt':1792425259,
  'humanSourceChanged':False,'imageRebuilt':False,'imagePreparationReplayed':False,'newWindowOpened':False,
  'runtimeAuthorityIssued':False,'oauthRequests':0,'ownerRequests':0,'engineCalls':0,'gatewayWrites':0,
  'newLoginRequiresNativeConsent':True,'budgetReset':False,'automaticReplayAllowed':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));print('OUF_INSTALLATION_OWNER_REAUTH244_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
def copy_binding(value):return json.loads(encoded(value))
