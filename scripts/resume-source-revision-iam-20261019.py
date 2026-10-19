"""Pin an already successful preparation before the existing native HUMAN gates."""
import hashlib,json,os,signal,stat,sys,re,resource,subprocess,tempfile
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

def verify_prepared(profile):
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
 original=json.loads(read(context/'current-original-preparation.json',result['currentOriginalPreparationBinding']['sha256']))
 return code,raw,original

PROFILE={
 'contextPath':'/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh',
 'sourceCommit':'32f86add5b6fb1b17110ca916ed045b28a240c5e',
 'preparationResultSha256':'90559c21350b737c591342163140477bcf42c7f4aa21f4819563c92b7e5ffed6',
 'packageSha256':'bfbbed8649e8fc438e7f71f598bb22a6d2c75335cbf6e2c25969e464e0a62cb7',
 'caseSha256':'6ac7617fcedf9ff6bba44da6c3f8189d63c080523d2ea6bea628bffb99f1473d',
 'nativePlanSha256':'db73f2694e2451ca227013ac7db0e912f297eba54194d36574a4492f885896b9',
 'sourceClosureSha256':'f29b50bb6a7a592a44a21923cac3925d21bf9cb10370e941cdfd308f0a1e3115',
 'executorSha256':'5ebe410809d674e215917032bcce7428654b1caf2524880aa75bc0ac4e2657d2'}

RECONCILIATION_SOURCE='"""Installation-specific protected IAM STOP reconciliation; no login or replay."""\nimport hashlib,json,os,signal,stat\nfrom pathlib import Path\nPREPARED=Path(\'/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-kfy691gh\')\nSTOPPED=Path(\'/etc/ouf/deploy-snapshots/source-revision-execution-tvc2ilnv\')\nCASE=\'6ac7617fcedf9ff6bba44da6c3f8189d63c080523d2ea6bea628bffb99f1473d\'\nPACKAGE=\'bfbbed8649e8fc438e7f71f598bb22a6d2c75335cbf6e2c25969e464e0a62cb7\'\nRESULT=\'90559c21350b737c591342163140477bcf42c7f4aa21f4819563c92b7e5ffed6\'\ndef require(ok):\n if not ok:raise ValueError(\'READ_RECONCILIATION_UNPROVEN\')\ndef encoded(value):return json.dumps(value,sort_keys=True,separators=(\',\',\':\'),allow_nan=False).encode()\ndef digest(value):return hashlib.sha256(encoded(value)).hexdigest()\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\ndef parse(raw):\n def unique(rows):\n  value={}\n  for key,item in rows:require(key not in value);value[key]=item\n  return value\n return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))\ndef pin(s):return tuple(getattr(s,k)for k in(\'st_dev\',\'st_ino\',\'st_uid\',\'st_gid\',\'st_mode\',\'st_nlink\',\'st_size\',\'st_mtime_ns\',\'st_ctime_ns\'))\ndef read(path,expected=None,maximum=8388608):\n path=Path(path);require(path.is_absolute() and path.resolve()==path)\n for parent in path.parents:\n  s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022)\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n try:\n  st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and 0<st.st_size<=maximum)\n  with os.fdopen(os.dup(fd),\'rb\')as stream:raw=stream.read(maximum+1)\n  require(len(raw)==st.st_size and pin(st)==pin(os.fstat(fd))==pin(path.lstat()) and(expected is None or sha(raw)==expected));return raw\n finally:os.close(fd)\ndef compiler_files(directory):\n files={};directories={}\n def walk(p,depth=0):\n  start=len(files);require(depth<=6);s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700);directories[str(p)]=pin(s)\n  for child in p.iterdir():\n   require(len(files)<8)\n   if stat.S_ISDIR(child.lstat().st_mode):walk(child,depth+1)\n   else:files[str(child.relative_to(directory))]=read(child,maximum=1048576)\n  require(len(files)>start)\n walk(directory);require(len(files)==7 and all(pin(Path(p).lstat())==value for p,value in directories.items()));return files\n\ndef reconcile_execution(stopped,prepared,result,case):\n require(stopped.parent==prepared.parent and stopped!=prepared)\n expected=compiler_files(prepared/\'gateway-compiler\');actual=compiler_files(stopped/\'gateway-compiler\');require(actual==expected)\n allowed={\'gateway-compiler\',\'candidate-review.json\',\'prepared-plan.json\'}\n info=stopped.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700 and {p.name for p in stopped.iterdir()}==allowed)\n review_raw=read(stopped/\'candidate-review.json\');plan_raw=read(stopped/\'prepared-plan.json\');review=parse(review_raw);plan=parse(plan_raw)\n require(review[\'schema\']==\'ouf.source-revision-candidate-review.v1\' and review[\'preparedPlanBinding\']==case[\'preparedPlanBinding\'] and review[\'runtimeAuthorityIssued\']is False and review[\'readyForExecution\']is False)\n require(plan[\'schema\']==\'ouf.source-revision-native-update-plan.v1\' and plan[\'authorityDirectory\']==str(stopped)\n  and plan[\'privateReviewBinding\']=={\'path\':str(stopped/\'candidate-review.json\'),\'sha256\':sha(review_raw)})\n require(all(plan[k]is False for k in (\'automaticReplayAllowed\',\'manualSqlMigrationAllowed\',\'grantChangesAllowed\',\'semanticDispatchAllowed\',\'automaticRollbackAllowed\',\'identityDecisionsAllowed\',\'profilePublicationAllowed\',\'jobRetriesAllowed\')))\n hashes={**{\'gateway-compiler/\'+k:sha(v)for k,v in actual.items()},\'candidate-review.json\':sha(review_raw),\'prepared-plan.json\':sha(plan_raw)}\n require(pin(stopped.lstat())==pin(info))\n return {\'contextPath\':str(stopped),\'contextFiles\':9,\'contextClosureSha256\':digest(hashes),\'exactCompilerSourcesMatch\':True,\n  \'candidateReviewBound\':True,\'nativePlanBound\':True,\'authorityAndLoginArtifactsAbsent\':True,\'retainedFilesPreserved\':True}\n\ndef main():\n require(os.geteuid()==os.getegid()==0 and __import__(\'sys\').flags.isolated and __import__(\'sys\').flags.no_site and __import__(\'sys\').dont_write_bytecode);signal.alarm(180)\n result=parse(read(PREPARED/\'postboot-preparation-result.json\',RESULT));case=parse(read(PREPARED/\'executor-code/case.json\',CASE));package=parse(read(PREPARED/\'executor-code/package.json\',PACKAGE))\n require(result[\'schema\']==\'ouf.source-revision-postboot-preparation-result.v1\' and result[\'contextPath\']==str(PREPARED)\n  and result[\'runtimeAuthorityIssued\']is False and result[\'readyForExecution\']is False\n  and all(result[k]is True for k in (\'postbootSuccessorPrepared\',\'nativePlanCompilationProven\',\'effectiveFlywayConfigurationProven\',\'hostCompletionReadbackProven\')))\n require(result[\'caseBinding\']=={\'path\':str(PREPARED/\'executor-code/case.json\'),\'sha256\':CASE}\n  and result[\'executorCodeBinding\']=={\'directory\':str(PREPARED/\'executor-code\'),\'sourceCommit\':\'32f86add5b6fb1b17110ca916ed045b28a240c5e\',\'packageSha256\':PACKAGE}\n  and package[\'sourceCommit\']==\'32f86add5b6fb1b17110ca916ed045b28a240c5e\' and package[\'caseSha256\']==CASE)\n require(case[\'preparedPlanBinding\']==result[\'preparedInputsBinding\'] and case[\'postbootOriginalPreparationBinding\']==result[\'currentOriginalPreparationBinding\'])\n for field,name in ((\'preparedInputsBinding\',\'postboot-private-inputs.json\'),(\'currentOriginalPreparationBinding\',\'current-original-preparation.json\'),(\'nativePlanBinding\',\'prepared-plan.json\')):\n  binding=result[field];require(binding[\'path\']==str(PREPARED/name));read(PREPARED/name,binding[\'sha256\'])\n stopped=reconcile_execution(STOPPED,PREPARED,result,case)\n require(reconcile_execution(STOPPED,PREPARED,result,case)==stopped)\n read(PREPARED/\'postboot-preparation-result.json\',RESULT)\n return {\'schema\':\'ouf.source-revision-iam-stop-read.v1\',\'complete\':True,\'executionReconciliation\':stopped,\n  \'preparedReceiptHashIndependentlyRead\':True,\'preparationResultSha256\':RESULT,\'preparedContextPath\':str(PREPARED),\n  \'humanJournalsRead\':0,\'tokenFilesOpened\':0,\'oauthRequests\':0,\'engineCalls\':0,\'databaseCalls\':0,\'journalWrites\':0,\n  \'runtimeAuthorityIssued\':False,\'credentialValuesPrinted\':False,\'automaticRetry\':False,\'budgetReset\':False,\n  \'completedTechnicalPhases\':8,\'functionalMilestonesProven\':4,\'iamSessionRenewed\':False,\'readyForExecution\':False}\nif __name__==\'__main__\':\n try:output=main()\n except (Exception,KeyboardInterrupt) as error:\n  output={\'schema\':\'ouf.source-revision-iam-stop-read.v1\',\'complete\':False,\'exceptionClass\':type(error).__name__,\'rawErrorPrinted\':False,\'runtimeAuthorityIssued\':False,\'automaticRetry\':False,\'budgetReset\':False,\'reconciliationRequired\':True}\n print(json.dumps(output,sort_keys=True));raise SystemExit(0 if output[\'complete\']else 2)\n'
RECONCILIATION_SHA256='bc820d7f8c0f6ce9e4d32ad6d83d77dd288c0e3b542fed8e7114607ddecce608'

# Explicit retained-installation profile, never a reusable installer default.
IAM_PROFILE={'schema':'ouf.source-revision-iam-admin-resume.v1','installationSpecific':True,
 'fenceDirectory':'/etc/ouf/deploy-snapshots/source-revision-iam-resume-tvc2ilnv',
 'stoppedClosureSha256':'e93fd92cae1105c6f5b69e617c5352d8324f65e5c3b13ac758a39dbc3e87a8bc',
 'adminServer':'http://localhost:8080','adminRealm':'master','adminUser':'oufadmin',
 'maximumLoginAttempts':1,'maximumLoginSeconds':300,
 'provenance':'releases/POLICY_TOKEN_ADMIN_REAUTH_AND_RESUME_20261013.md'}

def reconcile():
 require(digest(RECONCILIATION_SOURCE.encode())==RECONCILIATION_SHA256,'READER_SOURCE_CHANGED')
 ns={'__name__':'verified_read_only_reconciliation'}
 exec(compile(RECONCILIATION_SOURCE,'<pinned-iam-stop-read>','exec'),ns)
 report=ns['main']()
 require(report['executionReconciliation']['contextClosureSha256']==IAM_PROFILE['stoppedClosureSha256'],
         'RETAINED_EXECUTION_CLOSURE_CHANGED')
 return report

def reserve(directory,claim):
 directory=Path(directory)
 require(directory.parent.resolve()==directory.parent,'EXACT_FENCE_PARENT_REQUIRED')
 for parent in (directory.parent,*directory.parent.parents):
  info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_FENCE_ANCESTRY_REQUIRED')
 # Exclusive directory is the durable one-use fence, including crash before claim.
 directory.mkdir(mode=0o700)
 fd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(directory/'attempt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  raw=encoded(claim);require(os.write(fd,raw)==len(raw),'DURABLE_CLAIM_WRITE_REQUIRED');os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def output_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(262145,262145))
def bounded_read(argv,env):
 with tempfile.TemporaryFile()as out,tempfile.TemporaryFile()as err:
  reply=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=25,env=env,preexec_fn=output_limit)
  out.seek(0);err.seek(0);raw=out.read(262145);diagnostic=err.read(262145)
 require(reply.returncode==0 and 0<len(raw)<=262144 and len(diagnostic)<=262144,'IAM_READ_NOT_RECONCILED')
 return json.loads(raw)

def admin_login(original,profile,iam):
 selection=original['authorization']['plan']['selection'];binding=selection['docker'];binary=Path(binding['path'])
 container=selection['keycloakContainer'];realm=selection['realm'];engine=original['engine']
 require(re.fullmatch('[0-9a-f]{64}',container) and re.fullmatch('[A-Za-z0-9._:-]{1,128}',realm),'EXACT_IAM_SELECTION_REQUIRED')
 socket=Path(engine['socketPath']);require(socket.is_absolute() and socket.resolve()==socket,'EXACT_ENGINE_PATH_REQUIRED')
 def guard_binary_socket():
  require(binary.is_absolute() and binary.resolve()==binary,'EXACT_DOCKER_PATH_REQUIRED')
  for parent in binary.parents:
   info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'DOCKER_ANCESTRY_REQUIRED')
  info=binary.lstat();require(stat.S_ISREG(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022
    and 0<info.st_size<=134217728 and digest(binary.read_bytes())==binding['sha256'],'DOCKER_EXECUTABLE_CHANGED')
  st=socket.lstat();require(stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)in(0o600,0o660)
    and [st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)]==list(engine['socketBinding']),'ENGINE_SOCKET_CHANGED')
 env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','TERM':'xterm-256color',
      'DOCKER_CONFIG':iam['fenceDirectory']}
 base=[str(binary),'--host','unix://'+str(socket)]
 def generation():
  guard_binary_socket()
  state=bounded_read(base+['inspect','--format','{{json .State}}',container],env)
  require(state.get('Running')is True and type(state.get('Pid'))is int and state['Pid']>0
   and type(state.get('StartedAt'))is str and state['StartedAt'],'KEYCLOAK_GENERATION_REQUIRED')
  return {k:state[k]for k in('Pid','StartedAt')}
 before=generation()
 terminal=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY)
 try:
  require(os.isatty(terminal),'CURRENT_OPERATOR_TERMINAL_REQUIRED')
  reserve(iam['fenceDirectory'],{'schema':iam['schema'],'maximumLoginAttempts':1,'automaticReplayAllowed':False,
   'stoppedClosureSha256':iam['stoppedClosureSha256'],'preparedReceiptSha256':profile['preparationResultSha256'],
   'containerId':container,'generation':before,'passwordReadByDelivery':False,'budgetReset':False})
  require(generation()==before,'KEYCLOAK_GENERATION_CHANGED')
  print('Accesso IAM amministrativo: inserire la password nel prompt Keycloak del terminale; non nella chat.',flush=True)
  argv=base+['exec','-it',container,'/opt/keycloak/bin/kcadm.sh','config','credentials',
   '--server',iam['adminServer'],'--realm',iam['adminRealm'],'--user',iam['adminUser']]
  signal.alarm(0)
  try:subprocess.run(argv,stdin=terminal,stdout=terminal,stderr=terminal,timeout=iam['maximumLoginSeconds'],env=env)
  except subprocess.TimeoutExpired:pass  # One GET resolves an ambiguous completion; never repeat login.
 finally:os.close(terminal)
 signal.alarm(300)
 require(generation()==before,'KEYCLOAK_GENERATION_CHANGED')
 scopes=bounded_read(base+['exec','-i',container,'/opt/keycloak/bin/kcadm.sh','get','client-scopes','-r',realm,'--fields','id,name'],env)
 require(type(scopes)is list and scopes and all(type(row)is dict and set(row)=={'id','name'}
  and type(row['id'])is str and type(row['name'])is str for row in scopes),'IAM_GET_UNPROVEN')
 require(generation()==before,'KEYCLOAK_GENERATION_CHANGED')
 # Match native OwnerTransport's implicit Docker transport to the retained engine.
 os.environ.pop('DOCKER_CONTEXT',None);os.environ['DOCKER_HOST']='unix://'+str(socket)
 print(json.dumps({'schema':iam['schema'],'check':'IAM_GET_RECONCILED','maximumLoginAttempts':1,
  'passwordReadByDelivery':False,'runtimeAuthorityIssued':False,'automaticRetry':False,'budgetReset':False}),flush=True)

def run(profile=PROFILE,iam=IAM_PROFILE):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.alarm(300)
 reconcile();code,raw,original=verify_prepared(profile)
 admin_login(original,profile,iam)
 reconcile();code,raw,original=verify_prepared(profile)
 signal.alarm(0)
 sys.argv=[str(code/'execute.py'),str(code),profile['sourceCommit'],profile['packageSha256'],profile['preparationResultSha256']]
 exec(compile(raw,'<verified-source-revision-executor>','exec'),{'__name__':'__main__','__file__':str(code/'execute.py')})
if __name__=='__main__':
 try:run()
 except (Exception,KeyboardInterrupt)as error:
  print(json.dumps({'schema':'ouf.source-revision-iam-admin-resume-stop.v1','complete':False,
   'exceptionClass':type(error).__name__,'rawErrorPrinted':False,'reconciliationRequired':True,
   'automaticRetry':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}),flush=True)
  raise SystemExit(2)
