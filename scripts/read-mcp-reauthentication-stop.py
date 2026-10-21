"""Exact latest reauthentication STOP inventory and pure validators; no live calls."""
import ast,base64,hashlib,importlib,json,os,re,signal,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-mbbleugm')
PACKAGE='f4552fa8894c2050e67f025df9d6c14eb02b04a7c6d18d4a9019994d8bda1de9'
CLOSURE='6e2a0e4ec523c7de9c337ce71f18e3b1983205738a2aaccecf2c97319bb313ee'
SOURCE='f57728d2aa68dc9cf58b86a7f3fad04b45df82dc'
ARTIFACTS=('candidate-review.json','execution-plan.json','review.json','decision.json','human.json','authority.json','issuance.claim.json','recovery.json','update-result.json')
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  row=parent.lstat();require(stat.S_ISDIR(row.st_mode)and row.st_uid==0 and not row.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  row=os.fstat(fd);require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0
   and stat.S_IMODE(row.st_mode)==0o600 and row.st_nlink==1 and 0<row.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==row.st_size and pin(row)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None,maximum=8388608):return json.loads(read(path,expected,maximum))
NEW_HASHES={'entry': 'c95ad3808ec9cd5670248a6ea52797fefe24c150d6f8d8bbcf926802ad81a021', 'authority': '58d5762d2e4334a08f731b53187d5d6ee60c02e5aa565e4a340427c0f60f03a1', 'login': '1b9e2c954f2f38edc02a53a9d18dd707c9a16052b3e68757ca687ac3a8d65e89'}
LOADER_HASH='d1f6bd770116fabf758c020081a77785e0edc69a4441c846d5da8244d16c9b7b'
REAUTH_SOURCE='c9d3ca870c95518c94f754640cd68dc8462c609e'
NATIVE_IMAGE='sha256:a0a6f9562ba0b28ba3fef2b3a78bf46e90d9e14c99448d413bacf5d5cb75f182'
STAGES=('VERIFY_INPUTS','mcp.IMPORT_IMAGE','mcp.DISABLE_OLD_RESTART','mcp.STOP_OLD','mcp.DETACH_OLD_ENDPOINT',
 'mcp.RENAME_OLD','mcp.CREATE_REPLACEMENT','mcp.START_REPLACEMENT','mcp.READINESS','mcp.RESTORE_RESTART_POLICY','VERIFY_FINAL')
HUMAN_STATES={'NEW','DEVICE_START','DEVICE_POLL','REQUESTING','RETRY_WAIT','VERIFYING','READY','BLOCKED'}
OPERATIONS={'DISCOVERY','DEVICE_START','DEVICE_POLL','USERINFO','REFRESH'}
def safe_codes(sources):
 return {n.value for raw in sources.values()for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Constant)
  and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
def check(label,callback,codes):
 try:callback();return {'check':label,'passed':True}
 except Exception as error:
  reason=str(error);name=type(error).__name__
  return {'check':label,'passed':False,'exceptionClass':name if name in('PlanDenied','UpdateDenied','HumanSessionPaused','ValueError','TypeError','KeyError','FileNotFoundError','PermissionError')else'OTHER_ERROR',
   'reasonCode':reason if reason in codes else'PRIVATE_DETAILS_REDACTED'}
def human_projection(row,codes):
 require(row['schema']=='ouf.chatbot-human-session.private.v1'and row['state']in HUMAN_STATES
  and row['budgetReset']is False and type(row['attempts'])is int and 217<=row['attempts']<=256,'EXACT_CUMULATIVE_HUMAN_RECORD_REQUIRED')
 safe=lambda x:float(x)if type(x)in(int,float)and abs(x)<1e12 and x==x else None
 reason=row.get('reason');resume=row.get('resumeState');operation=row.get('operation')
 return {'state':row['state'],'operation':operation if type(operation)is str and operation in OPERATIONS else'NONE_OR_REDACTED',
  'reasonCode':reason if type(reason)is str and reason in codes else'NO_SAFE_RECORDED_REASON',
  'resumeState':resume if type(resume)is str and resume in HUMAN_STATES else'NONE_OR_REDACTED',
  'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'remainingAttempts':256-row['attempts'],
  'windowExpiresAt':safe(row['binding'].get('expiresAt')),'lastObservedAt':safe(row.get('lastObservedAt')),
  'nextAttemptAt':safe(row.get('nextAttemptAt')),'accessExpiresAt':safe(row.get('accessExpiresAt')),
  'durableAccessTokenPresent':bool(row.get('accessToken')),'publishedAccessTokenPresent':bool(row.get('publishedAccessToken')),
  'refreshCredentialPresent':bool(row.get('refreshToken')),'budgetReset':False}
def native_projection(row):
 require(row['schema']=='ouf.mcp-ingestion-read-transport-update-journal.v1'
  and type(row['effects'])is list and len(row['effects'])<=len(STAGES)
  and type(row['nextStage'])is int and 0<=row['nextStage']<=len(STAGES)
  and all(type(row[k])is int and 0<=row[k]<=128 for k in('readinessAttempts','cumulativeReadinessAttempts'))
  and row['budgetReset']is False,'EXACT_NATIVE_MCP_JOURNAL_REQUIRED')
 effects=[]
 for index,effect in enumerate(row['effects']):
  require(effect['stage']==STAGES[index]and effect['state']in('CLAIMED','APPLIED'),'EXACT_NATIVE_STAGE_HISTORY_REQUIRED')
  effects.append({'stage':effect['stage'],'state':effect['state']})
 return {'effects':effects,'nextStage':row['nextStage'],'readinessAttempts':row['readinessAttempts'],
  'cumulativeReadinessAttempts':row['cumulativeReadinessAttempts'],'budgetReset':row['budgetReset']}
def jwt_projection(token,binding,now):
 if type(token)is not str or not 0<len(token)<=16384:return {'durableJwtContextAvailable':False}
 try:
  parts=token.split('.');require(len(parts)==3,'JWT_REQUIRED')
  claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)))
  require(type(claims)is dict,'CLAIMS_REQUIRED')
 except Exception:return {'durableJwtContextAvailable':False}
 audience=claims.get('aud');scope=set(str(claims.get('scope','')).split());expiry=claims.get('exp')
 required=['openid','authorization.policy.admin','mcp.connect','authorization.permissions.read',
  'authorization.permissions.propose','authorization.proposal.read','udp.materialization.retry']
 return {'durableJwtContextAvailable':True,'issuerMatched':claims.get('iss')==binding['issuer'],
  'subjectMatched':claims.get('sub')==binding['subject'],'tenantMatched':claims.get('tenant_id')==binding['tenant'],
  'humanActorMatched':claims.get('ouf_actor_type')=='HUMAN','clientMatched':claims.get('azp')=='ouf-human-admin',
  'gatewayAudiencePresent':audience=='ouf-api-gateway'or type(audience)is list and 'ouf-api-gateway'in audience,
  'assuranceClaimPresent':bool(claims.get('acr')),'bindingScopeProfileMatched':binding.get('scopes')==required,'missingRequiredScopes':[s for s in required if s not in scope],
  'currentTimeExpiryPassed':type(expiry)in(int,float)and expiry>now+5,'signatureVerificationProvenByDiagnostic':False}
PHASE='VERIFY_REAUTH_PREPARATION_CLAIM'
def main():
 global PHASE
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_READ_DEADLINE')));signal.alarm(120)
 root=CONTEXT.parent
 path=root/('mcp-ingestion-read-transport-reauth-preparation-'+digest({'stoppedPackageHash':PACKAGE,'imageId':NATIVE_IMAGE})+'.claim.json')
 claim=parsed(path);context=Path(claim['context'])
 require(context.parent==root and re.fullmatch('mcp-ingestion-read-transport-execution-[A-Za-z0-9_-]{8,64}',context.name)
  and context!=CONTEXT and claim=={'context':str(context),'candidateSourceCommit':'1f2c28d7abadae78680b040ba7b58be62ef85ee9',
   'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False,
   'newLoginRequiresNativeConsent':True,'stoppedPackageHash':PACKAGE},'EXACT_DISTINCT_REAUTHENTICATION_CLAIM_REQUIRED')
 PHASE='VERIFY_SEALED_PACKAGE'
 receipt=parsed(context/'preparation-result.json')
 require(receipt['schema']=='ouf.mcp-read-transport-reauthentication-preparation.v1'and receipt['contextPath']==str(context)
  and receipt['sourceCommit']==REAUTH_SOURCE and receipt['sourceModuleCount']==188,'EXACT_PREPARED188_RECEIPT_REQUIRED')
 package=parsed(context/'package.json',receipt['packageHash'])
 require(package['sourceCommit']==REAUTH_SOURCE and digest(package['closure'])==receipt['sourceClosureHash']
  and package['runtimeAuthorityIssued']is False,'EXACT_PREPARED188_PACKAGE_REQUIRED')
 require(parsed(context/'runtime.claim.json')=={'packageHash':receipt['packageHash'],'automaticReplayAllowed':False},'EXACT_CONSUMED_NEW_RUNTIME_CLAIM_REQUIRED')
 case=parsed(context/'case.json',package['fileHashes']['case.json'])
 require(case['preparationClaimBinding']=={'path':str(path),'sha256':digest(claim)}and case['priorOAuthAttempts']==217,'EXACT_NEW_CASE_CLAIM_REQUIRED')
 PHASE='VERIFY188_SOURCE_BYTES'
 previous=parsed(CONTEXT/'package.json',PACKAGE)
 source_rows=parsed(context/'sources.json',package['fileHashes']['sources.json'])
 sources={n:base64.b64decode(v,validate=True)for n,v in source_rows.items()}
 require(len(sources)==188 and all(sha(raw)==package['closure']['declaration']['sourceHashes'][n]for n,raw in sources.items())
  and all(sha(sources[n])==wanted for n,wanted in previous['closure']['declaration']['sourceHashes'].items()),'EXACT188_RETAINED_SOURCE_BYTES_REQUIRED')
 # The three additions and loader have independent public source pins below.
 require(all(sha(sources['tools.mcp_read_transport_reauthentication.'+n])==wanted for n,wanted in NEW_HASHES.items()),'QUALIFIED_REAUTHENTICATION_SOURCES_CHANGED')
 loader=read(context/'runtime.py',LOADER_HASH)
 PHASE='READ_ARTIFACT_INVENTORY'
 inventory={n:os.path.lexists(context/n)for n in(*ARTIFACTS,'login-review.json','login-window-receipt.json')}
 output={'schema':'ouf.mcp-reauthentication-stop-read.v1','complete':True,'readOnly':True,'contextPath':str(context),
  'packageHash':receipt['packageHash'],'sourceClosureHash':receipt['sourceClosureHash'],'sourceModuleCount':188,
  'artifactInventory':inventory,'runtimeClaimPresent':True,'runtimeCompletionProven':False,
  'authorityFilePresent':inventory['authority.json'],'runtimeAuthorityIssued':None if inventory['authority.json']or inventory['issuance.claim.json']else False,
  'humanCredentialJournalsRead':0,'bearerFilesOpened':0,'privateKeyFilesOpened':0,'authorityFilesOpened':False,
  'oauthRequests':0,'ownerRequests':0,'engineCalls':0,'processDispatches':0,'journalWrites':0,
  'originalStopReasonProven':False,'credentialValuesPrinted':False,'credentialJournalHashPrinted':False,
  'automaticReplayAllowed':False,'budgetReset':False,'newHumanLoginAllowedByDiagnostic':False,
  'completedInstallationReadbackReplayed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 if inventory['recovery.json']:output['nativeHistory']=native_projection(parsed(context/'recovery.json'))
 codes=safe_codes(sources);old_binding=case['humanBinding'];old_directory=Path(old_binding['sessionDirectory'])
 login_claim=old_directory/'successor-window.claim.json'
 output['humanSuccessorClaimPresent']=os.path.lexists(login_claim)
 human_row=None
 PHASE='READ_NEW_HUMAN_HISTORY'
 if output['humanSuccessorClaimPresent']:
  require(inventory['login-review.json'],'LOGIN_CLAIM_REQUIRES_PUBLISHED_REVIEW')
  review=parsed(context/'login-review.json');successor=parsed(login_claim);directory=Path(successor['destination'])
  require(directory==old_directory.parent/('human-mcp-read-transport-successor-'+digest(review))
   and successor['reviewHash']==digest(review)and successor['budgetReset']is False,'EXACT_NEW_LOGIN_SUCCESSOR_REQUIRED')
  human_row=parsed(directory/'recovery.json',maximum=65536);binding=human_row['binding'];renewal=human_row['governedWindowRenewal']
  require(renewal['review']==review and digest(renewal['decision'])==successor['decisionHash']
   and binding['sessionDirectory']==str(directory)and binding['tokenPath']==str(directory/'human-access.jwt'),
   'EXACT_LOGIN_RENEWAL_HISTORY_REQUIRED')
  output['humanCredentialJournalsRead']=1;output['human']=human_projection(human_row,codes)
  output['jwtContext']=jwt_projection(human_row.get('accessToken'),binding,time.time())
  if inventory['login-window-receipt.json']:
   login_receipt=parsed(context/'login-window-receipt.json')
   require(login_receipt['schema']=='ouf.mcp-read-transport-human-reauthentication-receipt.v1'
    and login_receipt['reviewHash']==digest(review)and login_receipt['directory']==str(directory)
    and login_receipt['expiresAt']==binding['expiresAt'],'EXACT_COMPLETED_LOGIN_RECEIPT_REQUIRED')
   output['freshIssuerLoginReceiptProven']=True;output['oauthAttemptsAtLoginReceipt']=login_receipt['oauthAttemptsAfter']
 # Pure sealed owner validators only. No entry/main/authenticate/current/refresh,
 # plan compilation, issuer/network call, effect, signature or journal mutation.
 PHASE='PURE_SEALED_VALIDATORS'
 memory={'__name__':'qualified_read_only_sealed_188_loader'}
 exec(compile(loader,'<qualified-read-only-188-loader>','exec'),memory)
 entry,declaration=memory['load_entry'](REAUTH_SOURCE,sources,loader,package['declarationHash'],package['sourcePins'],package['executionPins'])
 require(declaration==package['closure']['declaration'],'EXACT_DIAGNOSTIC_DECLARATION_REQUIRED')
 original=parsed(case['originalBinding']['path'],case['originalBinding']['sha256']);selection=original['authorization']['plan']['selection']
 auth=importlib.import_module('tools.ingestion_read_authorization.authorization')
 checks=[check('oldSessionBinding',lambda:auth.validate_session_binding(old_binding,selection,profile=auth.INGESTION_READ_PROFILE),codes)]
 if human_row is not None:
  h=importlib.import_module('tools.chatbot_file_cohort.human_session')
  human=h.HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
  checks.extend([check('newSessionBinding',lambda:auth.validate_session_binding(binding,selection,profile=auth.INGESTION_READ_PROFILE),codes),
   check('newHumanIdentityAndBudget',lambda:human._check_identity_and_budget(human_row),codes),
   check('newHumanWindowAtDiagnosticTime',lambda:human._check(human_row),codes)])
 output['pureChecksAtDiagnosticTime']=checks
 signal.alarm(0);return output
PUBLIC_DIAGNOSTIC_CODES=frozenset(['APPLIED', 'BLOCKED', 'CLAIMED', 'CLAIMS_REQUIRED', 'DEVICE_POLL', 'DEVICE_START', 'DISCOVERY', 'EXACT188_RETAINED_SOURCE_BYTES_REQUIRED', 'EXACT_COMPLETED_LOGIN_RECEIPT_REQUIRED', 'EXACT_CONSUMED_NEW_RUNTIME_CLAIM_REQUIRED', 'EXACT_CUMULATIVE_HUMAN_RECORD_REQUIRED', 'EXACT_DIAGNOSTIC_DECLARATION_REQUIRED', 'EXACT_DISTINCT_REAUTHENTICATION_CLAIM_REQUIRED', 'EXACT_LOGIN_RENEWAL_HISTORY_REQUIRED', 'EXACT_NATIVE_MCP_JOURNAL_REQUIRED', 'EXACT_NATIVE_STAGE_HISTORY_REQUIRED', 'EXACT_NEW_CASE_CLAIM_REQUIRED', 'EXACT_NEW_LOGIN_SUCCESSOR_REQUIRED', 'EXACT_PREPARED188_PACKAGE_REQUIRED', 'EXACT_PREPARED188_RECEIPT_REQUIRED', 'EXACT_PRIVATE_PATH_REQUIRED', 'FINITE_READ_DEADLINE', 'HUMAN', 'ISOLATED_ROOT_REQUIRED', 'JWT_REQUIRED', 'LOGIN_CLAIM_REQUIRES_PUBLISHED_REVIEW', 'NEW', 'NONE_OR_REDACTED', 'NO_SAFE_RECORDED_REASON', 'OTHER_ERROR', 'PRIVATE_BYTES_CHANGED', 'PRIVATE_CUSTODY_REQUIRED', 'PRIVATE_DETAILS_REDACTED', 'PRIVATE_ROOT_ANCESTRY_REQUIRED', 'PURE_SEALED_VALIDATORS', 'QUALIFIED_REAUTHENTICATION_SOURCES_CHANGED', 'READY', 'READ_ARTIFACT_INVENTORY', 'READ_NEW_HUMAN_HISTORY', 'REFRESH', 'REQUESTING', 'RETRY_WAIT', 'USERINFO', 'VERIFY188_SOURCE_BYTES', 'VERIFYING', 'VERIFY_FINAL', 'VERIFY_INPUTS', 'VERIFY_REAUTH_PREPARATION_CLAIM', 'VERIFY_SEALED_PACKAGE'])
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  result={'schema':'ouf.mcp-reauthentication-stop-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reasonCode':str(error)if str(error)in PUBLIC_DIAGNOSTIC_CODES else'PRIVATE_DETAILS_REDACTED',
   'phase':PHASE,'automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
