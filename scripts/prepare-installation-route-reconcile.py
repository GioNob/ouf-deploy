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
NAMES=('entry','authority','owner','native','baseline','login','reconcile','runtime','bootstrap','human_extension','prepare')
# Exact authenticated target bytes: independent of ast.dump changes in Python3.13.
FROZEN_HUMAN_SOURCE_HASH='305c7804b084b02f0bf7d6c1521c3c5a4f8e7f4e2fb0a15e27f5886a2a685dcc'

def extend_human(raw,extension):
 tree=ast.parse(raw);methods=[n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget']
 require(sha(raw)==FROZEN_HUMAN_SOURCE_HASH and len(methods)==1
  and b'_explicit_264_identity'not in raw and 0<len(extension)<=32768,'EXACT_FROZEN256_PREDECESSOR_GUARD_REQUIRED')
 result=raw+b'\n'+extension;compile(result,'<explicit-budget264-human-v5>','exec');return result

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)==set(NAMES)and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_ROUTE_RECONCILIATION_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('PREPARATION_DEADLINE')));signal.alarm(120)
 retained={'__name__':'qualified_exact_predecessor_readiness'};exec(compile(delivery['reconcile'],'<qualified-predecessor-readiness>','exec'),retained)
 diagnostic=retained['continuation_readiness']();signal.alarm(120)
 require(diagnostic['publicationBytesPresentButJournalUnreconciled']and diagnostic['noGatewayDispatchByThisActionProven']
  and diagnostic['human']['state']=='READY'and diagnostic['human']['attempts']==255 and diagnostic['human']['remainingOAuthAttempts']==1
  and diagnostic['human']['windowStillOpen']and not diagnostic['human']['recordedAccessHas240SecondsMargin'],
  'EXACT_READY255_INSUFFICIENT_BUDGET_AND_PUBLISHED_PROJECTION_REQUIRED')
 first=retained['FIRST'];second=retained['SECOND'];package=retained['parsed'](first/'package.json',retained['PACKAGE'])
 raw={n:retained['read'](first/n,h)for n,h in package['fileHashes'].items()}
 sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(raw['sources.json']).items()}
 predecessor=retained['parsed'](second/'execution-plan.json');journal=retained['parsed'](second/'recovery.json');binding=predecessor['humanBinding']
 row=retained['parsed'](Path(binding['sessionDirectory'])/'recovery.json',maximum=65536)
 require(row['binding']==binding and row['attempts']==255 and row['state']=='READY'and row['budgetReset']is False
  and time.time()<1792436155-1200 and not os.path.lexists(Path(binding['sessionDirectory'])/'successor-window.claim.json'),
  'EXACT_UNCLAIMED255_HUMAN_WITH_REMAINING_WINDOW_REQUIRED')
 for name in('entry','authority','owner','native','baseline','login','reconcile'):sources['tools.installation_route_reconcile.'+name]=delivery[name]
 sources['tools.chatbot_file_cohort.human_session']=extend_human(sources['tools.chatbot_file_cohort.human_session'],delivery['human_extension'])
 memory={'__name__':'qualified_new_route220_loader'};exec(compile(delivery['runtime'],'<qualified-route220-loader>','exec'),memory)
 memory['compile_sources'](sources);require(len(memory['MODULES'])==226,'EXACT_ROUTE226_CLOSURE_REQUIRED')
 root=first.parent;claim_path=root/('installation-route-reconcile-preparation-'+retained['PACKAGE']+'.claim.json')
 require(not os.path.lexists(claim_path),'ROUTE_RECONCILIATION_ALREADY_PREPARED_NO_REPLAY')
 destination=Path(tempfile.mkdtemp(prefix='installation-binding-apply-execution-',dir=root));os.chmod(destination,0o700)
 claim={'context':str(destination),'predecessorContext':str(second),'predecessorJournalHash':digest(journal),
  'priorOAuthAttempts':255,'predecessorMaximumCumulativeOAuthAttempts':256,'maximumCumulativeOAuthAttempts':264,
  'preservedHumanWindowExpiresAt':1792436155,'budgetReset':False,'automaticReplayAllowed':False,'budgetChangeRequiresNativeConsent':True}
 write_new(claim_path,encoded(claim))
 old_case=json.loads(raw['case.json']);case={'originalBinding':old_case['originalBinding'],'humanBinding':binding,
  'predecessorJournalBinding':{'path':str(second/'recovery.json'),'sha256':digest(journal)},
  'predecessorPlanHash':digest(predecessor),'predecessorLogicalRef':predecessor['logicalRef'],
  'preparationClaimBinding':{'path':str(claim_path),'sha256':digest(claim)}}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],'reader.py':raw['reader.py'],
  'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit};execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'INSTALLATION_ROUTE_RECONCILE'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution);closure={**package['closure'],'declaration':declaration}
 fresh={**package,'sourceCommit':commit,'sourcePins':pins,'executionPins':execution,'closure':closure,'declarationHash':digest(declaration),
  'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for name,value in members.items():write_new(destination/name,value)
 write_new(destination/'package.json',encoded(fresh))
 report={'schema':'ouf.installation-route-reconciliation-preparation.v1','contextPath':str(destination),'sourceCommit':commit,
  'packageHash':digest(fresh),'sourceClosureHash':digest(closure),'sourceModuleCount':226,'priorOAuthAttempts':255,
  'predecessorMaximumCumulativeOAuthAttempts':256,'maximumCumulativeOAuthAttemptsProposed':264,'budgetChangeAuthorized':False,
  'preservedHumanWindowExpiresAt':1792436155,'humanSourceChangedInNewSealedPackage':True,'oauthRequests':0,
  'runtimeAuthorityIssued':False,'ownerMutations':0,'activeProjectionWrites':0,'gatewayWrites':0,'journalWritesToPredecessor':0,
  'completedOwnerUpdateReplayed':False,'profilePublicationReplayed':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));print('OUF_INSTALLATION_ROUTE_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
