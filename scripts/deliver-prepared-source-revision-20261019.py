"""Pin an already successful preparation before the existing native HUMAN gates."""
import hashlib,json,os,signal,stat,sys
from pathlib import Path

def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(path,sha,maximum=8388608):
 path=Path(path);require(path.is_absolute() and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd);require(stat.S_ISREG(first.st_mode) and first.st_uid==first.st_gid==0 and stat.S_IMODE(first.st_mode)==0o600 and first.st_nlink==1 and 0<first.st_size<=maximum,'PRIVATE_FILE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==first.st_size and pin(first)==pin(os.fstat(fd))==pin(path.lstat()) and digest(raw)==sha,'PRIVATE_FILE_BYTES_CHANGED');return raw
 finally:os.close(fd)

def run(profile):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.alarm(300)
 context=Path(profile['contextPath']);code=context/'executor-code'
 result=json.loads(read(context/'postboot-preparation-result.json',profile['preparationResultSha256']))
 require(result['schema']=='ouf.source-revision-postboot-preparation-result.v1' and result['contextPath']==str(context)
  and all(result[k] is True for k in ('postbootSuccessorPrepared','nativePlanCompilationProven','effectiveFlywayConfigurationProven','hostCompletionReadbackProven'))
  and result['runtimeAuthorityIssued'] is False and result['readyForExecution'] is False,'SUCCESSFUL_PRIVATE_PREPARATION_REQUIRED')
 expected={'directory':str(code),'sourceCommit':profile['sourceCommit'],'packageSha256':profile['packageSha256']}
 require(result['executorCodeBinding']==expected and result['caseBinding']=={'path':str(code/'case.json'),'sha256':profile['caseSha256']}
  and result['nativePlanBinding']=={'path':str(context/'prepared-plan.json'),'sha256':profile['nativePlanSha256']}
  and result['sourceClosureSha256']==profile['sourceClosureSha256'],'EXACT_COMPLETED_PREPARATION_BINDINGS_REQUIRED')
 for field,name in (('currentOriginalPreparationBinding','current-original-preparation.json'),('preparedInputsBinding','postboot-private-inputs.json')):
  binding=result[field];require(binding['path']==str(context/name),'EXACT_SUCCESSOR_INPUT_PATH_REQUIRED');read(context/name,binding['sha256'])
 read(context/'prepared-plan.json',profile['nativePlanSha256'])
 package=json.loads(read(code/'package.json',profile['packageSha256']));case=json.loads(read(code/'case.json',profile['caseSha256']))
 require(package['schema']=='ouf.source-revision-executable-package.v1' and package['sourceCommit']==profile['sourceCommit']
  and package['executorSha256']==profile['executorSha256'] and package['caseSha256']==profile['caseSha256'],'EXACT_FROZEN_EXECUTOR_PACKAGE_REQUIRED')
 require(case['schema']=='ouf.source-revision-postboot-update-selection.v2' and case['preparedPlanBinding']==result['preparedInputsBinding']
  and case['postbootOriginalPreparationBinding']==result['currentOriginalPreparationBinding'],'EXACT_RECONCILED_CASE_REQUIRED')
 raw=read(code/'execute.py',profile['executorSha256'],262144)
 declaration={'__name__':'verified_delivery_declaration','__file__':str(code/'execute.py')};exec(compile(raw,'<verified-source-revision-declaration>','exec'),declaration)
 overlays=declaration['OVERLAYS'];require(set(overlays)==set(package['sourceHashes']),'EXACT_EXECUTOR_SOURCE_CLOSURE_REQUIRED')
 names={'package.json','case.json','execute.py','runtime.py'}|{name for name,_ in overlays.values()}
 require(len(names)==81 and {p.name for p in code.iterdir()}==names,'EXACT_EIGHTY_ONE_FROZEN_FILES_REQUIRED')
 for module,(name,_)in overlays.items():
  require(Path(name).name==name and name not in ('.','..'),'SAFE_FROZEN_CODE_MEMBER_REQUIRED');read(code/name,package['sourceHashes'][module],262144)
 read(code/'runtime.py',package['loaderSha256'],65536)
 print(json.dumps({'schema':'ouf.prepared-source-revision-delivery.v1','check':'VERIFIED_PREPARED_EXECUTOR',
  'contextPath':str(context),'preparationResultSha256':profile['preparationResultSha256'],'sourceClosureSha256':profile['sourceClosureSha256'],
  'frozenFilesVerified':81,'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}),flush=True)
 sys.argv=[str(code/'execute.py'),str(code),profile['sourceCommit'],profile['packageSha256'],profile['preparationResultSha256']]
 exec(compile(raw,'<verified-source-revision-executor>','exec'),{'__name__':'__main__','__file__':str(code/'execute.py')})

PROFILE={
 'contextPath':'/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-gezxi85l',
 'sourceCommit':'6f8493ec372f8ca3e12c8a4e6df19552e28fd383',
 'preparationResultSha256':'a9ecda1c812236605a91415d776d4a69c5487087d2e47dda1642847845d6535e',
 'packageSha256':'7e511c3b332c83765f095541164025cdc27a69fc0397ac4a6625e6ef44b6eea2',
 'caseSha256':'48e9885c44df65d1cc86272f48cef83af84a001124de4e8689105099384b1ed8',
 'nativePlanSha256':'dcb0952ea7077899953a4c5243c11635fc33f7ce09f4a877f7ac4c461c03442f',
 'sourceClosureSha256':'1820bcea2dc55f605d73381aa7e8318b68e3206601b785ef6f11c4ff051f2d1b',
 'executorSha256':'5ebe410809d674e215917032bcce7428654b1caf2524880aa75bc0ac4e2657d2'}
if __name__=='__main__':
 try:run(PROFILE)
 except (Exception,KeyboardInterrupt) as error:
  print(json.dumps({'schema':'ouf.prepared-source-revision-delivery-stop.v1','complete':False,'exceptionClass':type(error).__name__,
   'rawErrorPrinted':False,'reconciliationRequired':True,'automaticRetry':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}),flush=True)
  raise SystemExit(2)
