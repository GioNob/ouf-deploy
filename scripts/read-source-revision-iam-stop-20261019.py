"""Installation-specific protected IAM STOP reconciliation; no login or replay."""
import hashlib,json,os,signal,stat
from pathlib import Path
PREPARED=Path('/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh')
STOPPED=Path('/etc/ouf/deploy-snapshots/source-revision-execution-tvc2ilnv')
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
 require(result['schema']=='ouf.source-revision-postboot-preparation-result.v1' and result['contextPath']==str(PREPARED)
  and result['runtimeAuthorityIssued']is False and result['readyForExecution']is False
  and all(result[k]is True for k in ('postbootSuccessorPrepared','nativePlanCompilationProven','effectiveFlywayConfigurationProven','hostCompletionReadbackProven')))
 require(result['caseBinding']=={'path':str(PREPARED/'executor-code/case.json'),'sha256':CASE}
  and result['executorCodeBinding']=={'directory':str(PREPARED/'executor-code'),'sourceCommit':'32f86add5b6fb1b17110ca916ed045b28a240c5e','packageSha256':PACKAGE}
  and package['sourceCommit']=='32f86add5b6fb1b17110ca916ed045b28a240c5e' and package['caseSha256']==CASE)
 require(case['preparedPlanBinding']==result['preparedInputsBinding'] and case['postbootOriginalPreparationBinding']==result['currentOriginalPreparationBinding'])
 for field,name in (('preparedInputsBinding','postboot-private-inputs.json'),('currentOriginalPreparationBinding','current-original-preparation.json'),('nativePlanBinding','prepared-plan.json')):
  binding=result[field];require(binding['path']==str(PREPARED/name));read(PREPARED/name,binding['sha256'])
 stopped=reconcile_execution(STOPPED,PREPARED,result,case)
 require(reconcile_execution(STOPPED,PREPARED,result,case)==stopped)
 read(PREPARED/'postboot-preparation-result.json',RESULT)
 return {'schema':'ouf.source-revision-iam-stop-read.v1','complete':True,'executionReconciliation':stopped,
  'preparedReceiptHashIndependentlyRead':True,'preparationResultSha256':RESULT,'preparedContextPath':str(PREPARED),
  'humanJournalsRead':0,'tokenFilesOpened':0,'oauthRequests':0,'engineCalls':0,'databaseCalls':0,'journalWrites':0,
  'runtimeAuthorityIssued':False,'credentialValuesPrinted':False,'automaticRetry':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4,'iamSessionRenewed':False,'readyForExecution':False}
if __name__=='__main__':
 try:output=main()
 except (Exception,KeyboardInterrupt) as error:
  output={'schema':'ouf.source-revision-iam-stop-read.v1','complete':False,'exceptionClass':type(error).__name__,'rawErrorPrinted':False,'runtimeAuthorityIssued':False,'automaticRetry':False,'budgetReset':False,'reconciliationRequired':True}
 print(json.dumps(output,sort_keys=True));raise SystemExit(0 if output['complete']else 2)
