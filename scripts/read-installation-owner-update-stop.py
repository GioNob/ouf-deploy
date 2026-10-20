"""Installation-specific pure STOP reconciliation. No refresh, login or replay."""
import ast,base64,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/installation-owner-update-execution-cr_wsios')
PACKAGE='174b8f8325a2721eddc90480a0a6851f5b060de10790115e4f655cbd096a3e4a'
CLOSURE='64f6139235d2f06a5c3cc0a7b2393ec6e213c1c4a56b2e392372c2790e9695fd'
SOURCE='15827c6d5ee9ed761ce9a534441e689ea6007dfa'
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
def project(row,binding,codes,now,mono):
 require(row['schema']=='ouf.chatbot-human-session.private.v1'and row['binding']==binding
  and binding['expiresAt']==1792425259 and binding['retryProfile']['maximumAttempts']==256
  and row['budgetReset']is False and type(row['attempts'])is int and 244<=row['attempts']<=256,
  'SAME_CUMULATIVE_HUMAN_HISTORY_REQUIRED')
 states={'NEW','DEVICE_START','DEVICE_POLL','REQUESTING','RETRY_WAIT','VERIFYING','READY','BLOCKED'}
 require(row['state']in states,'KNOWN_HUMAN_STATE_REQUIRED')
 safe=lambda x:float(x)if type(x)in(int,float)and abs(x)<1e12 and x==x else None
 reason=row.get('reason');operation=row.get('operation');resume=row.get('resumeState')
 return {'state':row['state'],'reasonCode':reason if type(reason)is str and reason in codes else 'NO_SAFE_RECORDED_REASON',
  'operation':operation if operation in('DISCOVERY','DEVICE_START','DEVICE_POLL','USERINFO','REFRESH')else'NONE_OR_REDACTED',
  'resumeState':resume if type(resume)is str and resume in states else'NONE_OR_REDACTED',
  'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'remainingAttempts':256-row['attempts'],
  'originalWindowExpiresAt':binding['expiresAt'],'wallWindowStillOpen':now<binding['expiresAt'],
  'monotonicWindowStillOpen':mono<row['monotonicDeadline'],'nextAttemptAt':safe(row.get('nextAttemptAt')),
  'refreshAt':safe(row.get('refreshAt')),'accessExpiresAt':safe(row.get('accessExpiresAt')),
  'recordedAccessStillCurrent':type(row.get('accessExpiresAt'))in(int,float)and row['accessExpiresAt']>now+5,
  'lastObservedAt':safe(row.get('lastObservedAt')),'budgetReset':False}
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(60)
 package=parsed(CONTEXT/'package.json',PACKAGE)
 require(package['sourceCommit']==SOURCE and package['schema']=='ouf.mcp-ingestion-read-transport-package.v1'
  and len(package['closure']['declaration']['sourceHashes'])==213 and digest(package['closure'])==CLOSURE and package['runtimeAuthorityIssued']is False,'EXACT_PREPARED_PACKAGE_REQUIRED')
 receipt=parsed(CONTEXT/'preparation-result.json');require(receipt['packageHash']==PACKAGE and receipt['sourceClosureHash']==CLOSURE,'EXACT_PREPARATION_RECEIPT_REQUIRED')
 claim=parsed(CONTEXT/'runtime.claim.json');require(claim=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED_RUNTIME_CLAIM_REQUIRED')
 case=parsed(CONTEXT/'case.json',package['fileHashes']['case.json']);binding=case['humanBinding']
 artifacts={n:os.path.lexists(CONTEXT/n)for n in ARTIFACTS}
 require(not any(artifacts.values()),'LATER_AUTHORITY_OR_EFFECT_RECONCILIATION_REQUIRED')
 sources=parsed(CONTEXT/'sources.json',package['fileHashes']['sources.json'])
 raw=base64.b64decode(sources['tools.chatbot_file_cohort.human_session'],validate=True)
 require(sha(raw)==package['closure']['declaration']['sourceHashes']['tools.chatbot_file_cohort.human_session'],'EXACT_SEALED_HUMAN_SOURCE_REQUIRED')
 codes={n.value for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('HUMAN_[A-Z0-9_]{2,150}',n.value)}
 directory=Path(binding['sessionDirectory']);require(directory.is_absolute()and directory.resolve()==directory
  and CONTEXT.parent in directory.parents and len(directory.relative_to(CONTEXT.parent).parts)<=8
  and binding['tokenPath']==str(directory/'human-access.jwt'),'EXACT_RETAINED_HUMAN_DIRECTORY_REQUIRED')
 journal=parsed(directory/'recovery.json',maximum=65536)
 human=project(journal,binding,codes,time.time(),time.monotonic())
 result={'schema':'ouf.installation-owner-update-stop-read.v1','complete':True,'readOnly':True,
  'contextPath':str(CONTEXT),'runtimeClaimPresent':True,'runtimeCompletionProven':False,
  'artifactInventory':artifacts,'runtimeAuthorityIssued':False,'human':human,'credentialJournalRead':True,
  'sourceModuleCount':213,'packageHash':PACKAGE,'sourceClosureHash':CLOSURE,
  'successorClaimPresent':os.path.lexists(directory/'successor-window.claim.json'),
  'authorityFilesOpened':False,'sourceExecuted':False,'specificIssuerReasonProven':False,
  'noOwnerUpdateDispatchByThisActionProven':True,'installationBindingAppliedByThisAction':False,
  'credentialValuesPrinted':False,'credentialJournalHashPrinted':False,'bearerFilesOpened':0,'privateKeyFilesOpened':0,
  'oauthRequests':0,'ownerRequests':0,'engineCalls':0,'databaseCalls':0,'journalWrites':0,
  'automaticReplayAllowed':False,'budgetReset':False,'newHumanLoginAllowed':False,
  'completedInstallationReadbackReplayed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 signal.alarm(0);return result
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  result={'schema':'ouf.installation-owner-update-stop-read.v1','complete':False,
   'exceptionClass':type(error).__name__,'reason':'PRIVATE_DETAILS_REDACTED','automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
