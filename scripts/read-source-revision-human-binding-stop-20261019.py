"""Installation-specific HUMAN binding STOP reconciliation; no login or replay."""
import ast,hashlib,json,os,signal,stat,time,types,uuid
from pathlib import Path
PREPARED=Path('/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh')
STOPPED=Path('/etc/ouf/deploy-snapshots/source-revision-execution-daxl0o6h')
CASE='6ac7617fcedf9ff6bba44da6c3f8189d63c080523d2ea6bea628bffb99f1473d'
PACKAGE='bfbbed8649e8fc438e7f71f598bb22a6d2c75335cbf6e2c25969e464e0a62cb7'
RESULT='90559c21350b737c591342163140477bcf42c7f4aa21f4819563c92b7e5ffed6'
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

LOGIN_REVIEW='cc9e1e66dac7ad4ce9c02bd059eaeac53278670b7df6a292580b1cf4ca70bae2'

def constants(raw):
 found={}
 def literal(node):
  if isinstance(node,ast.Name):require(node.id in found);return found[node.id]
  if isinstance(node,ast.BinOp)and isinstance(node.op,ast.Add):return literal(node.left)+literal(node.right)
  return ast.literal_eval(node)
 for node in ast.parse(raw).body:
  if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in ('PROFILE','CLIENT','LEGACY_SCOPES','SCOPES'):
   found[node.targets[0].id]=literal(node.value)
 require(set(found)=={'PROFILE','CLIENT','LEGACY_SCOPES','SCOPES'});return found

def validator_result(raw,name,binding,selection,*,row=None,values=None,directory=None,boot=None):
 # Execute only the exact hash-bound pure predicate, never imports/module code.
 tree=ast.parse(raw)
 if row is None:nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name]
 else:
  classes=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='HumanSession'];require(len(classes)==1)
  nodes=[n for n in classes[0].body if isinstance(n,ast.FunctionDef)and n.name==name]
 require(len(nodes)==1 and not nodes[0].decorator_list)
 ns={'Path':Path,'uuid':uuid,'digest':digest,'require':lambda ok,code:None if ok else (_ for _ in ()).throw(ValueError(code)),**(values or {})}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<verified-pure-binding-predicate>','exec'),ns)
 try:
  if row is None:ns[name](binding,selection)
  else:ns[name](types.SimpleNamespace(selection=selection,directory=directory,token_path=directory/'human-access.jwt',expires_at=binding['expiresAt'],_boot=lambda:boot),row)
  return 'ACCEPTED'
 except ValueError as error:
  code=str(error);return code if code in ('FINITE_NOMINAL_HUMAN_SESSION_CONTEXT_REQUIRED','EXACT_FINITE_HUMAN_SESSION_BINDING_REQUIRED','EXACT_HUMAN_SESSION_PRIVATE_FILE_BINDING_REQUIRED','HUMAN_SESSION_BINDING_OR_HISTORY_DRIFT','HUMAN_SESSION_BUDGET_DRIFT','RENEWED_HUMAN_WINDOW_CUMULATIVE_HISTORY_REQUIRED','EXPLICIT_TEST_SUCCESSOR_BUDGET_RECEIPT_REQUIRED')else'PREDICATE_DENIED'

def execution(stopped,prepared,case):
 expected=compiler_files(prepared/'gateway-compiler');actual=compiler_files(stopped/'gateway-compiler');require(actual==expected)
 info=stopped.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700)
 names={p.name for p in stopped.iterdir()};mandatory={'gateway-compiler','candidate-review.json','prepared-plan.json','login-review.json'}
 require(names in (mandatory,mandatory|{'login-window-receipt.json'}))
 raws={name:read(stopped/name)for name in names-{'gateway-compiler'}}
 review=parse(raws['candidate-review.json']);plan=parse(raws['prepared-plan.json']);login=parse(raws['login-review.json'])
 require(sha(raws['login-review.json'])==LOGIN_REVIEW and digest(login)==LOGIN_REVIEW)
 require(review['schema']=='ouf.source-revision-candidate-review.v1'and review['preparedPlanBinding']==case['preparedPlanBinding']and review['runtimeAuthorityIssued']is False and review['readyForExecution']is False)
 require(plan['schema']=='ouf.source-revision-native-update-plan.v1'and plan['authorityDirectory']==str(stopped)
  and plan['privateReviewBinding']=={'path':str(stopped/'candidate-review.json'),'sha256':sha(raws['candidate-review.json'])})
 require(all(plan[k]is False for k in ('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')))
 require(pin(stopped.lstat())==pin(info))
 hashes={**{'gateway-compiler/'+k:sha(v)for k,v in actual.items()},**{k:sha(v)for k,v in raws.items()}}
 return {'contextPath':str(stopped),'contextFiles':len(hashes),'contextClosureSha256':digest(hashes),
  'exactCompilerSourcesMatch':True,'nativePlanBound':True,'candidateReviewBound':True,'runtimeAuthorityArtifactsAbsent':True,
  'loginWindowReceiptPresent':'login-window-receipt.json'in raws,'retainedFilesPreserved':True},login,raws

def session(prepared,case,selection,login,raws,authorization_source,human_source):
 snapshots={}
 def document(path):
  raw=read(path,maximum=65536);snapshots[str(path)]=sha(raw);return parse(raw)
 predecessor=Path(login['predecessorDirectory']);pinned=case['postbootHumanHistory']['sessions'][-1]
 require(str(predecessor)==pinned['directory']and predecessor.parent.parent==prepared.parent)
 prior=document(predecessor/'recovery.json');require(digest(prior['binding'])==pinned['bindingSha256']and prior['attempts']==pinned['attempts']==175)
 require(login['schema']=='ouf.human-explicit-test-continuation-review.v3'and login['priorOAuthAttempts']==175
  and login['maximumCumulativeOAuthAttempts']==256 and login['newWindowSeconds']==7200 and login['budgetReset']is False
  and login['operationBinding']['preparedReviewHash']==case['preparedPlanBinding']['sha256'])
 claim=document(predecessor/'successor-window.claim.json');directory=Path(claim['destination'])
 require(claim['schema']=='ouf.human-successor-window-claim.v1'and claim['reviewHash']==LOGIN_REVIEW and claim['budgetReset']is False
  and claim['automaticReplayAllowed']is False and directory==predecessor.parent/('human-source-revision-postboot-successor-'+LOGIN_REVIEW))
 info=directory.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700)
 row=document(directory/'recovery.json');binding=row['binding'];renewal=row['governedWindowRenewal'];decision=renewal['decision']
 require(renewal['review']==login and digest(decision)==claim['decisionHash']and decision['reviewHash']==LOGIN_REVIEW
  and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'and binding['createdAt']==decision['approvedAt']
  and binding['expiresAt']==decision['expiresAt']and decision['expiresAt']==decision['approvedAt']+7200)
 values=constants(human_source);boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();require(0<len(boot)<=64)
 require(binding['sessionDirectory']==str(directory)and binding['tokenPath']==str(directory/'human-access.jwt')and binding['selectionHash']==digest(selection)
  and type(row['attempts'])is int and 175<=row['attempts']<=values['PROFILE']['maximumAttempts'])
 if 'login-window-receipt.json'in raws:
  receipt=parse(raws['login-window-receipt.json']);require(receipt=={'directory':str(directory),'expiresAt':binding['expiresAt'],
   'reviewHash':LOGIN_REVIEW,'priorOAuthAttempts':175,'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'postbootFreshLogin':True})
 token_present=os.path.lexists(directory/'human-access.jwt')
 if token_present:
  st=(directory/'human-access.jwt').lstat();require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and st.st_size<=16384)
 nominal=validator_result(authorization_source,'validate_session_binding',binding,selection)
 governed=validator_result(human_source,'_check_identity_and_budget',binding,selection,row=row,values=values,directory=directory,boot=boot)
 now=time.time();state=row.get('state');operation=row.get('operation')
 report={'sessionDirectory':str(directory),'state':state if state in ('NEW','DEVICE_START','DEVICE_POLL','VERIFYING','READY','REQUESTING','BLOCKED','RETRY_WAIT')else'UNCLASSIFIED',
  'operation':operation if operation in (None,'DISCOVERY','DEVICE_START','DEVICE_POLL','USERINFO','REFRESH')else'UNCLASSIFIED',
  'attempts':row['attempts'],'maximumAttempts':values['PROFILE']['maximumAttempts'],'remainingAttempts':values['PROFILE']['maximumAttempts']-row['attempts'],
  'currentBootMatches':row.get('bootId')==boot,'expiredByWallClock':now>=binding['expiresAt'],
  'windowRemainingSeconds':max(0,int(binding['expiresAt']-now)),
  'monotonicDeadlinePassed':time.monotonic()>=row['monotonicDeadline']if row.get('bootId')==boot else None,
  'accessTokenInJournal':type(row.get('accessToken'))is str and bool(row['accessToken']),
  'publishedAccessTokenInJournal':type(row.get('publishedAccessToken'))is str and bool(row['publishedAccessToken']),
  'refreshTokenInJournal':type(row.get('refreshToken'))is str and bool(row['refreshToken']),
  'bearerFilePresentNotOpened':token_present,'accessExpiredByWallClock':now>=row.get('accessExpiresAt',0),
  'deviceChallengePresent':type(row.get('deviceCode'))is str and bool(row['deviceCode']),
  'deviceChallengeExpired':now>=row['deviceDeadline']if type(row.get('deviceDeadline'))in(int,float)else None,
  'successorClaimPresent':os.path.lexists(directory/'successor-window.claim.json'),
  'frozenAuthorizationBindingResult':nominal,'frozenGovernedHumanIdentityResult':governed,
  'scopeListMatchesFrozenHuman':binding.get('scopes')==values['SCOPES'],
  'retryProfileMatchesFrozenHuman':binding.get('retryProfile')==values['PROFILE'],
  'loginReviewAndDecisionLinked':True,'credentialValuesPrinted':False,'journalHashPrinted':False,'runtimeHistoryAccepted':False}
 for path,expected in snapshots.items():read(path,expected,65536)
 require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot and pin(directory.lstat())==pin(info))
 report['journalsStableDuringRead']=True
 return report

def main():
 require(os.geteuid()==os.getegid()==0 and __import__('sys').flags.isolated and __import__('sys').flags.no_site and __import__('sys').dont_write_bytecode);signal.alarm(180)
 result=parse(read(PREPARED/'postboot-preparation-result.json',RESULT));case=parse(read(PREPARED/'executor-code/case.json',CASE));package=parse(read(PREPARED/'executor-code/package.json',PACKAGE))
 require(result['runtimeAuthorityIssued']is False and result['readyForExecution']is False and result['contextPath']==str(PREPARED)
  and result['caseBinding']=={'path':str(PREPARED/'executor-code/case.json'),'sha256':CASE}
  and result['executorCodeBinding']=={'directory':str(PREPARED/'executor-code'),'sourceCommit':'32f86add5b6fb1b17110ca916ed045b28a240c5e','packageSha256':PACKAGE})
 original=parse(read(PREPARED/'current-original-preparation.json',result['currentOriginalPreparationBinding']['sha256']));selection=original['authorization']['plan']['selection']
 require(case['preparedPlanBinding']==result['preparedInputsBinding']and case['postbootOriginalPreparationBinding']==result['currentOriginalPreparationBinding'])
 authorization_source=read(PREPARED/'executor-code/authorization.py',package['sourceHashes']['tools.chatbot_file_cohort.authorization'],262144)
 human_source=read(PREPARED/'executor-code/human_session.py',package['sourceHashes']['tools.chatbot_file_cohort.human_session'],262144)
 stopped,login,raws=execution(STOPPED,PREPARED,case)
 report=session(PREPARED,case,selection,login,raws,authorization_source,human_source)
 require(execution(STOPPED,PREPARED,case)[0]==stopped)
 return {'schema':'ouf.source-revision-human-binding-stop-read.v1','complete':True,'executionReconciliation':stopped,'humanSession':report,
  'preparationResultSha256':RESULT,'preparedReceiptHashIndependentlyRead':True,'humanJournalsRead':2,
  'tokenFilesOpened':0,'oauthRequests':0,'engineCalls':0,'databaseCalls':0,'journalWrites':0,'runtimeAuthorityIssued':False,
  'credentialValuesPrinted':False,'credentialJournalHashesPrinted':False,'automaticRetry':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4,'runtimeHistoryAccepted':False}
if __name__=='__main__':
 try:output=main()
 except (Exception,KeyboardInterrupt)as error:
  output={'schema':'ouf.source-revision-human-binding-stop-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'rawErrorPrinted':False,'runtimeAuthorityIssued':False,'automaticRetry':False,'budgetReset':False,'reconciliationRequired':True}
 print(json.dumps(output,sort_keys=True));raise SystemExit(0 if output['complete']else 2)
