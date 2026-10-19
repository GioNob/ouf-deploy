"""Installation-specific post-owner CAS planning. No refresh, login or owner mutation."""
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
import importlib,ssl,urllib.request,urllib.error
COMPLETED=Path('/etc/ouf/deploy-snapshots/installation-owner-update-execution-hnfn0zwg')
RESULT_HASH='704c8708d668161f0ddea45b997e493ef53dabd48c9db08128362223a33ba46c'
SOURCE='bcd33c71c7a906ec867c7ab2ccac40e4545a4f31'
ENTRY_HASH='1ce40aecf7f047e43dd9feb7051bd4542034372a458266100df18493ffc42b0f'
PLAN_HASH='6bebb5d19b337d4156bd63be78e4068c7117ecec3f3199ef142046cb20d695e9'
PHASE='VERIFY_COMPLETED_OWNER_HISTORY_AS_FILES'
HUMAN=None
SAFE_CODES=set()

def history():
 result=parsed(COMPLETED/'update-result.json',RESULT_HASH)
 require(result['status']=='ONBOARDING_OWNER_UPDATE_READBACK_COMPLETE'and result['result']['complete']is True
  and result['result']['journalVersion']==29 and result['oauthAttemptsAfter']==251
  and result['sourceCommit']=='b0f5e3dacbe59ebf87e22dd6af2575e41249f51d'
  and result['installationBindingApplied']is False and result['gatewayWrites']==result['databaseMigrationsPerformed']==0,
  'EXACT_COMPLETED_OWNER251_READBACK_REQUIRED')
 package=parsed(COMPLETED/'package.json');package_hash=digest(package)
 require(package['sourceCommit']==SOURCE and package['closure']['declaration']['moduleCount']==213
  and package['closure']['declaration']['entryModule']=='tools.installation_owner_update.entry'
  and package['declarationHash']==digest(package['closure']['declaration'])
  and parsed(COMPLETED/'runtime.claim.json')=={'packageHash':package_hash,'automaticReplayAllowed':False},'EXACT_COMPLETED213_PACKAGE_REQUIRED')
 require(set(package['fileHashes'])=={'case.json','bootstrap.py','runtime.py','reader.py','sources.json'},'EXACT_FIVE_COMPLETED_OWNER_MEMBERS_REQUIRED')
 raw={n:read(COMPLETED/n,h)for n,h in package['fileHashes'].items()}
 sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(raw['sources.json']).items()}
 hashes=package['closure']['declaration']['sourceHashes']
 require(len(sources)==213 and set(sources)==set(hashes)and all(sha(v)==hashes[n]for n,v in sources.items())
  and hashes['tools.installation_owner_update.entry']==ENTRY_HASH
  and sha(raw['runtime.py'])==package['closure']['declaration']['loaderHash'],'EXACT_COMPLETED213_SOURCE_HASHES_REQUIRED')
 case=json.loads(raw['case.json']);plan=parsed(COMPLETED/'execution-plan.json');journal=parsed(COMPLETED/'recovery.json')
 review=parsed(COMPLETED/'review.json');decision=parsed(COMPLETED/'decision.json')
 stages=['VERIFY_INPUTS']+['onboarding.'+n for n in('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD','DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')]+['VERIFY_FINAL']
 require(review['sourceClosureHash']==digest(package['closure'])and review['scopes']['installationOwnerUpdate']['planHash']==digest(plan)
  and decision['reviewHash']==digest(review)and decision['humanSessionHash']==digest(plan['humanBinding'])
  and review['authenticatedHuman']==plan['humanBinding']and journal['scopeHash']==digest(review['scopes']['installationOwnerUpdate'])
  and journal['schema']=='ouf.installation-binding-owner-update-journal.v1'and journal['version']==29 and journal['nextStage']==len(stages)
  and len(journal['effects'])==len(stages)and [r['stage']for r in journal['effects']]==stages
  and all(r['state']=='APPLIED'and r['intentHash']==digest({'planHash':digest(plan),'stage':r['stage']})for r in journal['effects'])
  and journal['incidentState']=='RECOVERED'and journal['budgetReset']is False
  and journal['effects'][-1]['evidence']==result['finalEvidence'],'COMPLETED_OWNER_PLAN_AND_JOURNAL_BINDINGS_REQUIRED')
 original_plan=parsed(case['completedInstallationPlanBinding']['path'],PLAN_HASH)
 original=parsed(case['originalBinding']['path'],case['originalBinding']['sha256'])
 # The completed execution plan selects the authenticated successor. The sealed
 # pre-login case still names the BLOCKED predecessor and must not select it.
 binding=plan['humanBinding']
 require(binding['expiresAt']==1792425259 and binding['sessionDirectory']!=case['humanBinding']['sessionDirectory'],
  'COMPLETED_OWNER_AUTHENTICATED_SUCCESSOR_REQUIRED')
 receipt=parsed(COMPLETED/'login-window-receipt.json')
 require(receipt['directory']==binding['sessionDirectory']and receipt['expiresAt']==1792425259
  and receipt['priorOAuthAttempts']==244 and 244<=receipt['oauthAttemptsAfter']<=251
  and receipt['newWindowOpened']is False and receipt['humanSourceChanged']is False and receipt['budgetReset']is False,
  'EXACT_COMPLETED_SAME_WINDOW_REAUTHENTICATION_REQUIRED')
 return package,raw,sources,plan,result,original_plan,original,binding

def strong_active(body,etag):
 require(type(body)is dict and set(body)=={'installationId','revision','checksum','generation'}
  and type(body['revision'])is int and 1<=body['revision']<2**63
  and type(body['generation'])is int and 1<=body['generation']<2**63
  and type(body['checksum'])is str and re.fullmatch('[0-9a-f]{64}',body['checksum'])
  and etag=='"'+str(body['revision'])+':'+body['checksum']+':'+str(body['generation'])+'"',
  'STRONG_OWNER_ETAG_AND_GENERATION_REQUIRED')
 return {**body,'etag':etag}

def compile_cas(active,revision,after,projection,prior,bindings,compiler):
 require(active==after,'OWNER_ACTIVE_GENERATION_OR_ETAG_DRIFT')
 plain={k:active[k]for k in('installationId','revision','checksum')}
 require(plain==prior['expectedActive']and prior['ownerApplyAuthorized']is False
  and prior['candidatePayloadChecksum']=='ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98',
  'EXACT_COMPLETED_BINDING_INTENT_REQUIRED')
 result=compiler(plain,revision,plain,projection,prior['addedBindings']['ouf-ingestion-runtime'],bindings)
 require(result['candidatePayload']==prior['candidatePayload']and result['candidatePayloadChecksum']==prior['candidatePayloadChecksum'],
  'UNCHANGED_REVIEWED_CANDIDATE_PAYLOAD_REQUIRED')
 result.update(schema='ouf.installation-ingestion-binding-cas-plan.v1',expectedActive={k:active[k]for k in('installationId','revision','checksum','generation')},
  expectedActiveETag=active['etag'],atomicOwnerActivePreconditionSupportProven=True,atomicOwnerReadContractProven=True,atomicOwnerApiLiveWriteTestPerformed=False,
  installedOwnerSourceCommit='b0f5e3dacbe59ebf87e22dd6af2575e41249f51d',retainedDnsProofOnly=True,
  ownerApplyAuthorized=False,futureNativeConsentRequired=True)
 return result

class ThreeReads:
 def __init__(self,selection,human,prior,owner_transport,no_redirect):
  self.credentials=owner_transport(selection,human.token_path,human.token_path,human_session=human)
  base='/api/trusted-human/v1/installations/'+prior['expectedActive']['installationId']
  require(re.fullmatch('[A-Za-z0-9._-]{1,128}',prior['expectedActive']['installationId']),'EXACT_INSTALLATION_ID_REQUIRED')
  self.origin=selection['origin'].rstrip('/');self.paths=[base+'/active',base+'/revisions/'+str(prior['expectedActive']['revision']),base+'/active']
  self.calls=0;self.deadline=time.monotonic()+45
  self.opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),no_redirect())
 def next(self):
  require(self.calls<3 and time.monotonic()<self.deadline,'THREE_FINITE_OWNER_GETS_ONLY')
  token=self.credentials.token('admin');path=self.paths[self.calls];self.calls+=1
  request=urllib.request.Request(self.origin+path,headers={'Authorization':'Bearer '+token,'Accept':'application/json'},method='GET')
  try:
   with self.opener.open(request,timeout=min(10,max(.1,self.deadline-time.monotonic())))as response:
    require(response.status==200,'OWNER_GET_NOT_SUCCESSFUL');raw=response.read(1048577)
    require(0<len(raw)<=1048576,'BOUNDED_OWNER_GET_RESPONSE_REQUIRED')
    return json.loads(raw),response.headers.get('ETag')
  except(urllib.error.HTTPError,urllib.error.URLError,TimeoutError):raise ValueError('OWNER_GET_FAILED_NO_REPLAY')from None

def main():
 global PHASE,HUMAN
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_ONLY_PLAN_DEADLINE')));signal.alarm(120);os.umask(0o077)
 package,raw,sources,owner,result,prior,original,binding=history()
 SAFE_CODES.update(n.value for source in sources.values()for n in ast.walk(ast.parse(source))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value))
 memory={'__name__':'verified_completed213_loader'};exec(compile(raw['runtime.py'],'<exact-completed213-loader>','exec'),memory)
 entry,declaration=memory['load_entry'](SOURCE,sources,raw['runtime.py'],package['declarationHash'],package['sourcePins'],package['executionPins'])
 require(declaration==package['closure']['declaration'],'COMPLETED_SOURCE_DECLARATION_DRIFT');entry.authority.closure_valid(package['closure'])
 p=importlib.import_module('tools.installation_binding_plan.plan');auth=importlib.import_module('tools.ingestion_read_authorization.authorization')
 PHASE='CHECK_COMPLETED_OWNER_HUMAN_NO_REFRESH'
 selection=original['authorization']['plan']['selection'];human=entry.HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt']);HUMAN=human
 row=human._read();human._check(row);human.current()
 require(row['binding']==binding and row['state']=='READY'and type(row['attempts'])is int and 251<=row['attempts']<=256
  and row['accessExpiresAt']>=time.time()+90 and binding['scopes']==entry.SCOPES and len(entry.SCOPES)==11
  and not os.path.lexists(human.directory/'successor-window.claim.json'),'CURRENT_VERIFIED_HUMAN_WITH_NINETY_SECONDS_ACCESS_REQUIRED')
 PHASE='VERIFY_CURRENT_OWNER_AND_INGESTION_GENERATIONS'
 expected={'onboarding':result['finalEvidence']['onboarding']['runtimeBinding'],'ingestion':owner['unchangedApplications']['ingestion'],
  'gateway':owner['gateway']['transport']['runtimeBinding']}
 reader=entry.discovery.Reader(owner['engine'],[r['containerId']for r in expected.values()])
 for name,wanted in expected.items():
  actual=reader.get('/v1.44/containers/'+wanted['containerId']+'/json')
  ordered=name!='gateway'or owner['gateway']['transport'].get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
  require(entry.discovery.runtime(actual,ordered)==wanted,'CURRENT_RETAINED_OWNER_OR_INGESTION_GENERATION_DRIFT')
  if name=='onboarding':require(actual['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==result['sourceCommit'],'EXACT_NEW_OWNER_SOURCE_REQUIRED')
 projection_binding=owner['gateway']['projectionBinding'];projection=json.loads(entry.private_config(projection_binding['path'],projection_binding)[0])
 PHASE='THREE_NEW_OWNER_GETS_WITH_STRONG_ACTIVE_PRECONDITION'
 transport=ThreeReads(selection,human,prior,auth.OwnerTransport,auth.NoRedirect)
 active,etag=transport.next();first=strong_active(active,etag);revision,_=transport.next();after,etag_after=transport.next();last=strong_active(after,etag_after)
 compiled=compile_cas(first,revision,last,projection,prior,{'completedOwnerResultHash':RESULT_HASH,
  'completedOwnerPackageHash':digest(package),'humanBinding':binding,'ownerRuntimeBinding':expected['onboarding'],
  'retainedGatewayRouteMapHash':result['finalEvidence']['routeMapHash'],'previousInstallationPlanHash':PLAN_HASH,
  'projectionBinding':projection_binding,'currentApplications':expected},p.compile_plan)
 require(human._read()==row,'HUMAN_JOURNAL_CHANGED_DURING_READ_ONLY_PLAN')
 PHASE='RETAIN_NEW_PRIVATE_CAS_PLAN_NO_AUTHORITY'
 claim_path=COMPLETED.parent/('installation-binding-cas-plan-'+RESULT_HASH+'.claim.json')
 require(not os.path.lexists(claim_path),'CAS_PLAN_ALREADY_RETAINED_NO_REPLAY')
 context=Path(tempfile.mkdtemp(prefix='installation-binding-cas-plan-',dir=COMPLETED.parent));os.chmod(context,0o700)
 write_new(claim_path,encoded({'context':str(context),'completedOwnerResultHash':RESULT_HASH,'planHash':digest(compiled),'automaticReplayAllowed':False,'budgetReset':False}))
 write_new(context/'installation-cas-plan.json',encoded(compiled))
 report={'schema':'ouf.installation-ingestion-binding-cas-planning-result.v1','status':'CAS_PLAN_RETAINED_NO_OWNER_OR_GATEWAY_WRITES',
  'contextPath':str(context),'planHash':digest(compiled),'complete':True,'readOnlyOwner':True,'ownerGetRequests':transport.calls,
  'engineGetRequests':reader.calls,'expectedActiveRevision':first['revision'],'expectedActiveGeneration':first['generation'],
  'expectedActiveETag':first['etag'],'candidatePayloadChecksum':compiled['candidatePayloadChecksum'],
  'atomicOwnerReadContractProven':True,'atomicOwnerApiLiveWriteTestPerformed':False,'ownerApplyAuthorized':False,
  'oauthRequests':0,'humanAttemptsUnchanged':True,'oauthAttemptsAfter':row['attempts'],'maximumCumulativeOAuthAttempts':256,
  'humanWindowExpiresAt':binding['expiresAt'],'humanJournalWrites':0,'ownerMutationRequests':0,'gatewayWrites':0,
  'projectionExports':0,'activeProjectionWrites':0,'databaseCalls':0,'containerLifecycleOperations':0,'newHumanLoginAllowed':False,
  'retainedDnsProofOnly':True,'liveGatewayRoutesRequeried':False,'retainedMainCalled':False,'runtimeAuthorityIssued':False,
  'sourceActivated':False,'nativeProfilePublished':False,'automaticReplayAllowed':False,'budgetReset':False,
  'notReleaseAcceptance':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(context/'planning-result.json',encoded(report));signal.alarm(0);return report
if __name__=='__main__':
 try:report=main()
 except(Exception,KeyboardInterrupt)as error:
  report={'schema':'ouf.installation-binding-cas-planning-stop.v1','status':'STOP_RECONCILE','complete':False,'phase':PHASE,
   'exceptionClass':type(error).__name__,'reasonCode':str(error)if str(error)in SAFE_CODES else'PRIVATE_DETAILS_REDACTED','oauthRequests':0,
   'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'newHumanLoginAllowed':False}
  if HUMAN is not None:
   try:
    row=HUMAN._read();HUMAN._check_identity_and_budget(row)
    report['human']={'state':row['state'],'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'windowExpiresAt':HUMAN.expires_at}
   except Exception:pass
 print('OUF_INSTALLATION_BINDING_CAS_PLAN_RESULT='+encoded(report).decode(),flush=True);raise SystemExit(0 if report.get('complete')else 2)
