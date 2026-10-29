"""Bounded protected history reconciliation only; no auth, clocks or journal writes."""
import ast,hashlib,json,os,signal,stat,time
from pathlib import Path
PREPARED=Path('/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-gezxi85l')
STOPPED=Path('/etc/ouf/deploy-snapshots/source-revision-execution-k6rk22xj')
CASE='48e9885c44df65d1cc86272f48cef83af84a001124de4e8689105099384b1ed8'
PACKAGE='7e511c3b332c83765f095541164025cdc27a69fc0397ac4a6625e6ef44b6eea2'
RESULT='a9ecda1c812236605a91415d776d4a69c5487087d2e47dda1642847845d6535e'
def require(ok):
 if not ok:raise ValueError('READ_RECONCILIATION_UNPROVEN')
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def parse(raw):
 def unique(rows):
  value={}
  for key,item in rows:require(key not in value);value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute() and path.resolve()==path)
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=maximum)
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
  require(len(raw)==st.st_size and pin(st)==pin(os.fstat(fd))==pin(path.lstat()) and(expected is None or sha(raw)==expected));return raw
 finally:os.close(fd)
def profile_constants(raw):
 """Extract only closed literal constants from the exact frozen HUMAN module."""
 found={}
 def literal(node):
  if isinstance(node,ast.Name):require(node.id in found);return found[node.id]
  if isinstance(node,ast.BinOp)and isinstance(node.op,ast.Add):
   a,b=literal(node.left),literal(node.right);require(type(a)is list and type(b)is list);return a+b
  return ast.literal_eval(node)
 for node in ast.parse(raw).body:
  if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('CLIENT','LEGACY_SCOPES','SCOPES','PROFILE'):
   found[node.targets[0].id]=literal(node.value)
 require(set(found)=={'CLIENT','LEGACY_SCOPES','SCOPES','PROFILE'});return found

def predicates(row,hb,selection,constants,current_boot,now):
 binding=row.get('binding',{});profile=constants['PROFILE']
 checks={'schemaMatches':row.get('schema')=='ouf.chatbot-human-session.private.v1',
 'selectionHashMatches':binding.get('selectionHash')==digest(selection),
 'issuerMatches':binding.get('issuer')==selection['issuer'],'subjectMatches':binding.get('subject')==selection['subject'],
 'tenantMatches':binding.get('tenant')==selection['tenant'],'clientMatches':binding.get('clientId')==constants['CLIENT'],
 'scopeProfileMatches':binding.get('scopes')in(constants['LEGACY_SCOPES'],constants['SCOPES']),
 'tokenPathMatches':binding.get('tokenPath')==str(Path(hb['sessionDirectory'])/'human-access.jwt'),
 'sessionDirectoryMatches':binding.get('sessionDirectory')==hb['sessionDirectory'],
 'expiryMatches':binding.get('expiresAt')==hb['expiresAt'],'retryProfileMatches':binding.get('retryProfile')==profile,
 'budgetResetFalse':row.get('budgetReset')is False,'currentBootMatches':row.get('bootId')==current_boot,
 'bindingMatchesHistoricalReference':binding==hb,'governedWindowRenewalPresent':'governedWindowRenewal'in row,
 'attemptsWithinMaximum':type(row.get('attempts'))is int and 0<=row['attempts']<=profile['maximumAttempts']}
 renewal=row.get('governedWindowRenewal')
 renewal_checks={}
 if type(renewal)is dict and type(renewal.get('review'))is dict and type(renewal.get('decision'))is dict:
  review=renewal['review'];decision=renewal['decision'];prior=review.get('priorOAuthAttempts');kind=review.get('schema')
  common=review.get('purpose')=='CONFIGURATION_AND_VALIDATION' and review.get('maximumCumulativeOAuthAttempts')==profile['maximumAttempts']
  v2=kind=='ouf.human-explicit-test-budget-review.v2'and review.get('predecessorMaximumCumulativeOAuthAttempts')==128 and type(prior)is int and 124<=prior<=128
  v3=kind=='ouf.human-explicit-test-continuation-review.v3'and review.get('predecessorMaximumCumulativeOAuthAttempts')==256 and type(prior)is int and 129<=prior<256 and review.get('freshIssuerAuthenticationRequired')is True and review.get('failedRefreshReplayAllowed')is False and review.get('budgetReset')is False
  v4=kind=='ouf.human-explicit-capability-scope-review.v4'and review.get('predecessorMaximumCumulativeOAuthAttempts')==256 and type(prior)is int and 129<=prior<256 and review.get('requestedScopes')==constants['SCOPES']and review.get('previousScopes')==constants['LEGACY_SCOPES']and binding.get('scopes')==constants['SCOPES']and review.get('freshIssuerAuthenticationRequired')is True and review.get('budgetReset')is False
  expiry=decision.get('expiresAt');approved=decision.get('approvedAt')
  renewal_checks={'reviewPurposeAndMaximumMatch':common,'reviewSchemaContractMatches':v2 or v3 or v4,
   'cumulativeAttemptsPreserved':type(prior)is int and type(row.get('attempts'))is int and row['attempts']>=prior,
   'decisionHashMatchesReview':decision.get('reviewHash')==digest(review),
   'createdAtMatchesDecision':binding.get('createdAt')==approved,'expiryMatchesDecision':binding.get('expiresAt')==expiry,
   'finiteWindowMatchesProfile':type(expiry)is int and type(approved)is int and expiry-approved==profile['maximumElapsedSeconds']}
 state=row.get('state');operation=row.get('operation')
 expiry=hb.get('expiresAt');last=row.get('lastObservedAt')
 return {'checks':checks,'renewalChecks':renewal_checks,'failedChecks':sorted(k for k,v in checks.items()if not v),
  'state':state if state in ('NEW','READY','BLOCKED','DEVICE_POLL','USERINFO','TOKEN','ATTEMPTING','EXHAUSTED')else'UNCLASSIFIED',
  'operation':operation if operation in ('DEVICE','TOKEN','DEVICE_POLL','USERINFO','REFRESH','LOGIN',None)else'UNCLASSIFIED',
  'attempts':row.get('attempts')if type(row.get('attempts'))is int else None,'maximumAttempts':profile['maximumAttempts'],
  'expiredByWallClock':type(expiry)is int and now>=expiry,'wallClockNotBeforeLastObservation':type(last)in(int,float)and now+2>=last,
  'monotonicComparisonMeaningful':row.get('bootId')==current_boot,'expectedRetryProfileSha256':digest(profile),
  'observedRetryProfileSha256':digest(binding.get('retryProfile')),'bindingSha256':digest(binding),
  'runtimeHistoryAccepted':False,'clockRebased':False,'budgetReset':False}

def chain(hb,selection,constants,current_boot,now,reader):
 snapshots={};rows=[];seen=set()
 def document(path,maximum=65536):
  raw=reader(path,None,maximum);key=str(path);require(key not in snapshots or snapshots[key]==sha(raw));snapshots[key]=sha(raw);return parse(raw)
 for _ in range(8):
  directory=Path(hb['sessionDirectory']);token=Path(hb['tokenPath'])
  require(directory.is_absolute() and directory!=PREPARED.parent and directory.is_relative_to(PREPARED.parent) and str(directory) not in seen and token==directory/'human-access.jwt')
  info=directory.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700)
  seen.add(str(directory));row=document(directory/'recovery.json');report=predicates(row,hb,selection,constants,current_boot,now)
  report.update(sessionDirectory=str(directory),credentialJournalHashPrinted=False);rows.append(report)
  claim_path=directory/'successor-window.claim.json'
  if not os.path.lexists(claim_path):report['successorClaimPresent']=False;break
  report['successorClaimPresent']=True
  require(row.get('binding')==hb)
  claim=document(claim_path);destination=Path(claim['destination'])
  require(destination.parent==directory.parent and destination!=directory and claim['budgetReset']is False)
  following=document(destination/'recovery.json');renewal=following.get('governedWindowRenewal',{})
  valid=(digest(renewal.get('review'))==claim['reviewHash']and digest(renewal.get('decision'))==claim['decisionHash']
    and type(following.get('attempts'))is int and type(row.get('attempts'))is int and following['attempts']>=row['attempts']
    and following['binding']['sessionDirectory']==str(destination))
  report['successorReceiptLinksMatch']=valid;require(valid);hb=following['binding']
 else:raise ValueError('CHAIN_BOUND')
 for path,expected in snapshots.items():reader(path,expected,65536)
 for row in rows:row['journalStableDuringRead']=True
 return rows,snapshots

def compiler_files(directory):
 files={};directories={}
 def walk(p,depth=0):
  start=len(files);require(depth<=6);s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700);directories[str(p)]=pin(s)
  for child in p.iterdir():
   require(len(files)<8)
   if stat.S_ISDIR(child.lstat().st_mode):walk(child,depth+1)
   else:files[str(child.relative_to(directory))]=read(child,maximum=1048576)
  require(len(files)>start)
 walk(directory);require(len(files)==7 and all(pin(Path(p).lstat())==value for p,value in directories.items()));return files

def reconcile_execution(stopped,prepared,result,case):
 require(stopped.parent==prepared.parent and stopped!=prepared)
 expected=compiler_files(prepared/'gateway-compiler');actual=compiler_files(stopped/'gateway-compiler');require(actual==expected)
 allowed={'gateway-compiler','candidate-review.json','prepared-plan.json'}
 info=stopped.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700 and {p.name for p in stopped.iterdir()}==allowed)
 review_raw=read(stopped/'candidate-review.json');plan_raw=read(stopped/'prepared-plan.json');review=parse(review_raw);plan=parse(plan_raw)
 require(review['schema']=='ouf.source-revision-candidate-review.v1' and review['preparedPlanBinding']==case['preparedPlanBinding'] and review['runtimeAuthorityIssued']is False and review['readyForExecution']is False)
 require(plan['schema']=='ouf.source-revision-native-update-plan.v1' and plan['authorityDirectory']==str(stopped)
  and plan['privateReviewBinding']=={'path':str(stopped/'candidate-review.json'),'sha256':sha(review_raw)})
 require(all(plan[k]is False for k in ('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')))
 hashes={**{'gateway-compiler/'+k:sha(v)for k,v in actual.items()},'candidate-review.json':sha(review_raw),'prepared-plan.json':sha(plan_raw)}
 require(pin(stopped.lstat())==pin(info))
 return {'contextPath':str(stopped),'contextFiles':9,'contextClosureSha256':digest(hashes),'exactCompilerSourcesMatch':True,
  'candidateReviewBound':True,'nativePlanBound':True,'authorityAndLoginArtifactsAbsent':True,'retainedFilesPreserved':True}

def main():
 require(os.geteuid()==os.getegid()==0 and __import__('sys').flags.isolated and __import__('sys').flags.no_site and __import__('sys').dont_write_bytecode);signal.alarm(180)
 result=parse(read(PREPARED/'postboot-preparation-result.json',RESULT));case=parse(read(PREPARED/'executor-code/case.json',CASE));package=parse(read(PREPARED/'executor-code/package.json',PACKAGE))
 require(result['caseBinding']['sha256']==CASE and result['runtimeAuthorityIssued']is False and result['readyForExecution']is False)
 constants=profile_constants(read(PREPARED/'executor-code/human_session.py',package['sourceHashes']['tools.chatbot_file_cohort.human_session'],262144))
 original=parse(read(PREPARED/'current-original-preparation.json',result['currentOriginalPreparationBinding']['sha256']))
 selection=original['authorization']['plan']['selection'];binding=case['humanReviewBinding'];review=parse(read(binding['path'],binding['sha256']));hb=review['authenticatedHuman']
 stopped=reconcile_execution(STOPPED,PREPARED,result,case)
 boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();require(len(boot)<=64)
 rows,snapshots=chain(hb,selection,constants,boot,time.time(),read)
 require(reconcile_execution(STOPPED,PREPARED,result,case)==stopped and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot)
 return {'schema':'ouf.source-revision-human-history-read.v1','complete':True,'executionReconciliation':stopped,'sessions':rows,
  'historyBindingsSha256':digest(rows),'credentialJournalHashesPrinted':False,'credentialBearingJournalsRead':sum(p.endswith('/recovery.json')for p in snapshots),'preparedReceiptHashIndependentlyRead':True,'tokenFilesOpened':0,'oauthRequests':0,
  'engineCalls':0,'databaseCalls':0,'journalWrites':0,'runtimeAuthorityIssued':False,'credentialValuesPrinted':False,
  'runtimeHistoryAccepted':False,'automaticRetry':False,'budgetReset':False,'clockRebased':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:output=main()
 except (Exception,KeyboardInterrupt) as error:
  output={'schema':'ouf.source-revision-human-history-read.v1','complete':False,'exceptionClass':type(error).__name__,'rawErrorPrinted':False,'runtimeHistoryAccepted':False,'runtimeAuthorityIssued':False,'automaticRetry':False,'budgetReset':False}
 print(json.dumps(output,sort_keys=True));raise SystemExit(0 if output['complete']else 2)
