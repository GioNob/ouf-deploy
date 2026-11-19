"""Installation-specific, pure read-only reconciliation of tr33g8bg; no runtime imports."""
import base64,hashlib,json,os,re,signal,stat,sys
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-owner-reference-execution-tr33g8bg')
PACKAGE='afff187c6c97fe697ab448b6d88bdd24092c1fd00b0aef01f268e9982e96b5a5'
CLOSURE='0493b8737f3421cd2c3d03eb11e1fb12b34c165c258a064e0905faf666ce7244'
REVIEW='094318901cd46051ff90644f0b5192104878e492f086c17851af1cc4d8075590'
MEMBERS={'case.json','bootstrap.py','runtime.py','reader.py','sources.json'}
ABSENT=('execution-plan.json','review.json','decision.json','issuance.claim.json','authority.json','recovery.json','update-result.json','login-window-receipt.json')
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600
   and before.st_nlink==1 and 0<before.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
  require(len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(path.lstat()),'PRIVATE_READ_CHANGED')
  require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'RETAINED_HASH_MISMATCH');return raw
 finally:os.close(fd)
def parsed(path,expected=None):return json.loads(read(path,expected))
def inspect(context=CONTEXT,package_hash=PACKAGE,closure_hash=CLOSURE,review_hash=REVIEW):
 context=Path(context);s=context.lstat()
 require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'PRIVATE_CONTEXT_REQUIRED')
 package=parsed(context/'package.json',package_hash)
 require(set(package['fileHashes'])==MEMBERS and digest(package['closure'])==closure_hash,'EXACT_PACKAGE_CLOSURE_REQUIRED')
 raw={name:read(context/name,expected)for name,expected in package['fileHashes'].items()}
 require(package['closure']['declaration']['moduleCount']==232,'EXACT232_CLOSURE_REQUIRED')
 sources=json.loads(raw['sources.json']);hashes=package['closure']['declaration']['sourceHashes']
 require(len(sources)==232 and set(sources)==set(hashes),'EXACT_SOURCE_MEMBERS_REQUIRED')
 for name,value in sources.items():
  require(hashlib.sha256(base64.b64decode(value,validate=True)).hexdigest()==hashes[name],'RETAINED_SOURCE_MISMATCH')
 case=json.loads(raw['case.json']);require(digest(case)==package['executionPins']['caseSha256'],'EXACT_CASE_REQUIRED')
 runtime_claim=parsed(context/'runtime.claim.json')
 require(runtime_claim=={'packageHash':package_hash,'automaticReplayAllowed':False},'EXACT_CONSUMED_RUNTIME_CLAIM_REQUIRED')
 preparation=parsed(case['preparationClaimBinding']['path'],case['preparationClaimBinding']['sha256'])
 require(preparation['context']==str(context)and preparation['priorOAuthAttempts']==259
  and preparation['automaticReplayAllowed']is False,'EXACT_PREPARATION_CLAIM_REQUIRED')
 review=parsed(context/'login-review.json',review_hash);decision=parsed(context/'login-decision.json')
 require(review['schema']=='ouf.human-ingestion-owner-rollout-budget-review.v6'
  and review['priorOAuthAttempts']==259 and review['maximumCumulativeOAuthAttempts']==272 and review['budgetReset']is False
  and decision['schema']=='ouf.human-ingestion-owner-rollout-budget-decision.v6'and decision['reviewHash']==review_hash
  and decision['decision']=='APPROVE_EXACT272_AND_NEW7200_WINDOW_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'
  and decision['expiresAt']-decision['approvedAt']==7200,'EXACT_EXPLICIT_BUDGET_DECISION_REQUIRED')
 predecessor=Path(case['humanBinding']['sessionDirectory'])
 require(predecessor.is_absolute()and predecessor.is_relative_to(context.parent),'EXACT_PREDECESSOR_PATH_REQUIRED')
 claim=parsed(predecessor/'successor-window.claim.json')
 destination=predecessor.parent/('human-ingestion-owner-rollout272-'+review_hash)
 require(claim['destination']==str(destination)and claim['reviewHash']==review_hash and claim['decisionHash']==digest(decision)
  and claim['windowExpiresAt']==decision['expiresAt']and claim['priorOAuthAttempts']==259
  and claim['maximumCumulativeOAuthAttempts']==272 and claim['budgetReset']is False,'EXACT_SUCCESSOR_CLAIM_REQUIRED')
 # This is the ONLY credential-bearing file opened. Values/hashes are never emitted.
 row=parsed(destination/'recovery.json');binding=row['binding'];before=case['humanBinding']
 require(row['schema']=='ouf.chatbot-human-session.private.v1'and row['budgetReset']is False
  and row['governedWindowRenewal']=={'review':review,'decision':decision}
  and all(binding[k]==before[k]for k in('selectionHash','issuer','subject','tenant','clientId','scopes'))
  and binding['sessionDirectory']==str(destination)and binding['tokenPath']==str(destination/'human-access.jwt')
  and binding['createdAt']==decision['approvedAt']and binding['expiresAt']==decision['expiresAt']
  and binding['retryProfile']['id']=='ouf.human.ingestion-owner-rollout272.v6'
  and binding['retryProfile']['maximumAttempts']==272,'EXACT_SUCCESSOR_IDENTITY_HISTORY_REQUIRED')
 require(row['state']=='VERIFYING'and type(row['attempts'])is int and row['attempts']==272,'STOP_STATE_CHANGED_REQUIRES_NEW_REVIEW')
 artifacts={name:os.path.lexists(context/name)for name in ABSENT}
 require(not any(artifacts.values()),'ADMINISTRATIVE_ARTIFACTS_CHANGED_REQUIRES_REVIEW')
 require(not os.path.lexists(destination/'human-access.jwt'),'PUBLISHED_BEARER_UNEXPECTED_REQUIRES_REVIEW')
 # Recheck mutable evidence without printing any credential-derived digest.
 require(parsed(destination/'recovery.json')==row and parsed(predecessor/'successor-window.claim.json')==claim
  and parsed(context/'login-decision.json')==decision,'DIAGNOSTIC_SNAPSHOT_CHANGED')
 require({name:os.path.lexists(context/name)for name in ABSENT}==artifacts,'ARTIFACT_INVENTORY_CHANGED')
 return {'schema':'ouf.ingestion-owner-reference-stop-read.v1','complete':True,'readOnly':True,'contextPath':str(context),
  'packageAnd232SourcesVerified':True,'preparationClaimRetained':True,'runtimeClaimRetained':True,'successorClaimRetained':True,
  'artifactInventory':artifacts,'human':{'state':row['state'],'attempts':272,'maximumCumulativeOAuthAttempts':272,
   'remainingAttempts':0,'windowExpiresAt':binding['expiresAt'],'budgetReset':False,'publishedBearerPresent':False,
   'recordedTokenResponseRetained':bool(row.get('accessToken')),'providerVerificationCompleted':False},
  'credentialJournalsOpened':1,'humanCredentialJournalReads':2,'credentialValuesPrinted':False,'credentialHashesPrinted':False,
  'bearerFilesOpened':0,'privateKeyFilesOpened':0,'authorityFilesOpened':False,'oauthRequests':0,'ownerRequests':0,
  'gatewayWrites':0,'journalWrites':0,'containerLifecycleOperations':0,'databaseCalls':0,'processDispatches':0,
  'runtimeMainCalled':False,'preparerMainCalled':False,'runtimeAuthorityIssued':False,'newLoginAllowed':False,
  'newBudgetAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'maximumSeconds':60,
  'remoteOwnerActiveRequeried':False,'notReleaseAcceptance':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
def main():
 require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
  'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(60)
 print(encoded(inspect()).decode(),flush=True)
if __name__=='__main__':
 try:main()
 except (Exception,KeyboardInterrupt)as error:
  print(json.dumps({'schema':'ouf.ingestion-owner-reference-stop-read.v1','complete':False,'status':'STOP_RECONCILE',
   'exceptionClass':type(error).__name__,'reasonCode':'READ_CHECK_FAILED_PRIVATE_DETAILS_REDACTED','readOnly':True,
   'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False}),flush=True);raise SystemExit(2)
