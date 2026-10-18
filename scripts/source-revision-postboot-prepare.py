"""One protected postboot preparation; reuse custody, no login or runtime effects."""
import copy,fcntl,hashlib,importlib,json,os,re,signal,stat,sys,tempfile
from pathlib import Path
def require(value,code):
 if not value:raise ValueError(code)
def emit(check,**values):
 print(json.dumps({'schema':'ouf.source-revision-postboot-private-preparation.v1','check':check,'completedTechnicalPhases':8,'functionalMilestonesProven':4,'runtimeAuthorityIssued':False,'runtimeMutations':0,'profilePublications':0,'explicitJobRetries':0,'oauthRequests':0,'credentialValuesPrinted':False,**values},sort_keys=True),flush=True)
def document(context,name,value,shared,reader):
 allowed={'current-original-preparation.json','postboot-private-inputs.json','postboot-preparation-result.json'}
 require(name in allowed,'EXACT_POSTBOOT_DOCUMENT_REQUIRED')
 shared.root_directory(context);raw=shared.encoded(value)
 require(0<len(raw)<=8388608,'POSTBOOT_DOCUMENT_BOUND')
 path=context/name;shared.write_new(path,raw)
 fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 sha=hashlib.sha256(raw).hexdigest()
 require(reader.read(path,sha)==raw,'POSTBOOT_DOCUMENT_READBACK_FAILED')
 return {'path':str(path),'sha256':sha}

def load_staged(profile,reader):
 pin=profile['stagedExecutor'];code=Path(pin['directory']);package=json.loads(reader.read(code/'package.json',pin['packageSha256'],131072,protected=False));require(package['schema']=='ouf.source-revision-executable-package.v1'and package['sourceCommit']==pin['sourceCommit'],'EXACT_QUALIFIED_STAGED_PACKAGE_REQUIRED')
 raw=reader.read(code/'execute.py',package['executorSha256'],131072,protected=False);decl={'__name__':'verified_staged_declaration','__file__':str(code/'execute.py')};exec(compile(raw,'<verified-staged-declaration>','exec'),decl)
 require(set(package['sourceHashes'])==set(decl['OVERLAYS']),'EXACT_STAGED_SOURCE_CLOSURE_REQUIRED')
 case=json.loads(reader.read(code/'case.json',package['caseSha256'],131072,protected=False));require(case['preparedPlanBinding']==profile['historicalPrivateInputs'],'STAGED_CASE_HISTORICAL_BINDING_CHANGED')
 boot=case['retainedBootstrap'];ns={'__name__':'verified_retained_postboot_read_helpers'};exec(compile(reader.read(boot['path'],boot['sha256'],131072),'<verified-retained-read-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);binding=old['scopes']['finiteActionProcess']['bundle'];bundle=ns['read'](binding['path'],8388608,binding['sha256']);_,sources=ns['decode_sources'](bundle);original=bundle['prepared'];require(reader.digest(original)==old['privateInputHashes']['preparedInputs'],'ORIGINAL_PREPARED_HASH_CHANGED')
 files={}
 for module,(name,_)in decl['OVERLAYS'].items():
  files[name]=reader.read(code/name,package['sourceHashes'][module],262144,protected=False)
  sources[module]=files[name]
 loader=reader.read(code/'runtime.py',package['loaderSha256'],65536,protected=False);memory={'__name__':'verified_staged_read_only_memory'};exec(compile(loader,'<verified-staged-memory-loader>','exec'),memory)
 pins={**bundle['declaration']['sourcePins'],'ouf-deploy':package['sourceCommit'],'ouf-onboarding':case['candidateOwnerSourceCommit']};extra={'executorSha256':package['executorSha256'],'caseSha256':package['caseSha256'],'mode':'SOURCE_REVISION_UPDATE'}
 declaration=memory['declaration'](package['sourceCommit'],sources,loader,pins,extra);entry,verified=memory['load_entry'](package['sourceCommit'],sources,loader,reader.digest(declaration),pins,extra);require(verified==declaration,'STAGED_LIBRARY_DECLARATION_CHANGED')
 return ns,original,case,{**old['sourceClosure'],'declaration':declaration},files,package,loader,memory,sources,pins,decl['OVERLAYS']
def reconcile_partial(path,sources,reader):
 path=Path(path)
 require(path.is_absolute() and path.resolve()==path,'EXACT_PARTIAL_CONTEXT_REQUIRED')
 require(len(sources)==7,'EXACT_SEVEN_PARTIAL_COMPILER_MEMBERS_REQUIRED')
 expected={'gateway-compiler/'+name for name in sources}
 expected_dirs={'gateway-compiler'}
 for name in expected:
  expected_dirs.update(str(p) for p in Path(name).parents if str(p)!='.')
 def directory_info(p):
  st=p.lstat()
  require(stat.S_ISDIR(st.st_mode) and st.st_uid==st.st_gid==0
          and stat.S_IMODE(st.st_mode)==0o700,'PARTIAL_DIRECTORY_CUSTODY_REQUIRED')
  return reader.pin(st)
 before=directory_info(path);found={};dirs={}
 def walk(p):
  dirs[str(p.relative_to(path))]=directory_info(p)
  for item in p.iterdir():
   st=item.lstat();relative=str(item.relative_to(path))
   if stat.S_ISDIR(st.st_mode):
    require(relative in expected_dirs,'UNKNOWN_PARTIAL_DIRECTORY');walk(item)
   else:
    require(relative in expected and stat.S_ISREG(st.st_mode),'UNKNOWN_PARTIAL_OR_AUTHORITY_ARTIFACT')
    found[relative.removeprefix('gateway-compiler/')]=reader.read(item,maximum=1048576)
 walk(path)
 require(found==sources and set(dirs)=={'.',*expected_dirs},'PARTIAL_COMPILER_SOURCES_CHANGED')
 require(directory_info(path)==before and all(directory_info(path/name)==pin for name,pin in dirs.items()),
         'PARTIAL_CONTEXT_CHANGED_DURING_READ')
 return {'contextPath':str(path),'exactCompilerSourcesMatch':True,'authorityArtifactsAbsent':True,'retainedFilesPreserved':True}

def freeze_code(context,case,profile,executor_raw,files,package,loader,shared,reader,overlays):
 ns={'__name__':'postboot_executor_declaration'}
 exec(compile(executor_raw,'<verified-postboot-executor>','exec'),ns)
 require(ns['OVERLAYS']==overlays,'POSTBOOT_LIBRARY_CLOSURE_CHANGED')
 case_raw=shared.encoded(case)
 successor={**package,'sourceCommit':profile['successorSourceCommit'],
            'executorSha256':hashlib.sha256(executor_raw).hexdigest(),
            'caseSha256':hashlib.sha256(case_raw).hexdigest()}
 payload={**files,'execute.py':executor_raw,'case.json':case_raw,'runtime.py':loader,'package.json':shared.encoded(successor)}
 require(len(payload)==81,'EXACT_EIGHTY_ONE_PACKAGE_FILES_REQUIRED')
 code=context/'executor-code';code.mkdir(mode=0o700)
 for name,raw in payload.items():
  require(re.fullmatch('[A-Za-z0-9_.-]+',name),'SAFE_POSTBOOT_CODE_MEMBER_REQUIRED')
  shared.write_new(code/name,raw)
  require(reader.read(code/name,hashlib.sha256(raw).hexdigest(),262144)==raw,'POSTBOOT_CODE_READBACK_FAILED')
 fd=os.open(code,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 return successor,{'directory':str(code),'packageSha256':reader.digest(successor),'sourceCommit':profile['successorSourceCommit']}

def run(profile,reader,owner,boot_reader,bootstrap,policy,guard_selection,executor_raw):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_PREPARATION_REQUIRED');require(profile['schema']=='ouf.source-revision-postboot-preparation-selection.v1','VERSIONED_POSTBOOT_SELECTION_REQUIRED');os.umask(0o077);require(type(profile['maximumSeconds']) is int and 30<=profile['maximumSeconds']<=300,'FINITE_POSTBOOT_PREPARATION_REQUIRED');signal.alarm(profile['maximumSeconds'])
 emit('BEGIN',maximumSeconds=profile['maximumSeconds'],newHumanSessionOpened=False)
 root=Path(profile['hostContext']);plan_raw=reader.read(root/'plan.json',profile['hostPlanSha256'],8388608);host=json.loads(plan_raw);journal_raw=reader.read(root/'journal.json',maximum=1048576);journal=json.loads(journal_raw);pointer=json.loads(reader.read(profile['hostIncidentPointer'],maximum=65536));host_proof=policy.completed_host(host,journal,pointer,profile,owner)
 native=bootstrap.provider_guard(boot_reader,guard_selection,owner);require(native['loadedBinding']==host['nativeBootBinding'],'COMPLETED_HOST_NATIVE_BOOT_BINDING_CHANGED');boot=json.loads(boot_reader.sealed(native['loadedBinding']['profile'],native['loadedBinding']['sha256']));coordinated=json.loads(boot_reader.sealed(boot['coordinatedConfiguration'],boot['coordinatedConfigurationHash']));lock=Path(coordinated['commonLockFile']);fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'ROOT_COMMON_LOCK_REQUIRED');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);require((lock.lstat().st_dev,lock.lstat().st_ino)==(info.st_dev,info.st_ino),'COMMON_LOCK_REPLACED')
  bootstrap.provider_guard(boot_reader,guard_selection,owner);api=owner.Engine(host['profile']['socketPath'],host['profile']['engineVersion']);require(list(api.pin)==host['engineSocketBinding'],'COMPLETED_HOST_ENGINE_GENERATION_CHANGED')
  for move in host['moves']:owner.verify_move(api,host,move,connected=True)
  for path,expected in host['configurationFileBindings'].items():require(hashlib.sha256(bootstrap.configuration_bytes(path,host['profile'],owner)).hexdigest()==expected,'COMPLETED_HOST_CONFIGURATION_BYTES_CHANGED')
  ns,original,case,closure,files,package,loader,memory,sources,pins,overlays=load_staged(profile,reader);emit('QUALIFIED_LIBRARIES_LOADED',libraryOnly=True,newHumanSessionOpened=False)
  historical=json.loads(reader.read(profile['historicalPrivateInputs']['path'],profile['historicalPrivateInputs']['sha256'],8388608));private_engine={**historical['engine'],'socketBinding':list(api.pin)}
  Engine=importlib.import_module('engine_creation').Engine;engine=Engine(private_engine['socketPath'],tuple(private_engine['socketBinding']));gateway=importlib.import_module('tools.chatbot_file_cohort.gateway');shared=importlib.import_module('tools.linked_property_rollout.preparation');prep=importlib.import_module('tools.source_revision_update.preparation');native_update=importlib.import_module('tools.source_revision_update.native');raw_runtime=importlib.import_module('tools.source_revision_update.database').raw_runtime
  selected_config=historical['gateway']['transport']['configBinding']['path'];transport=gateway.NamespaceAdmin.observe(engine,selected_config,binding_profile=gateway.MOUNT_SET_BINDING);admin=gateway.NamespaceAdmin(engine,transport);require(admin.routes()==historical['gateway']['beforeRoutes'],'HISTORICAL_GATEWAY_ROUTES_CHANGED')
  ids={v['Id']for v in historical['beforeApplications'].values()}|{v['containerId']for v in historical['unchangedApplications'].values()}|{historical['databasePlan']['postgresRuntimeBinding']['containerId']};observed={cid:api.get('/containers/'+cid+'/json')for cid in ids}
  for cid,row in observed.items():
   if cid in host['unaffected']:
    require({'immutable':owner.immutable(row),'process':owner.process(row),'networks':owner.digest(row['NetworkSettings'])}==host['unaffected'][cid],'UNTOUCHED_HOST_COMPONENT_CHANGED')
   elif cid==host['restartBefore']['Id']:
    require(owner.immutable(row)==owner.immutable(host['restartBefore'])and row['State']['Running']is True,'RETAINED_UDP_CONFIG_OR_RUNNING_STATE_CHANGED')
   else:require(any(move['pin']['containerId']==cid for move in host['moves']),'POSTBOOT_COMPONENT_NOT_COVERED_BY_COMPLETED_HOST_PLAN')
  current_original,current,proof=policy.project(original,historical,observed,private_engine,transport,raw_runtime,native_update.runtime,lambda before,actual:bootstrap.preboot_application_proof(before,actual,owner))
  sources_partial=prep.gateway.source_members(reader.read(current['gatewayPackage']['path'],current['gatewayPackage']['sha256'],67108864),json.loads(prep.package_files(current)('gateway','source-inventory.json')))
  stopped=reconcile_partial(profile['previousPreparationStop'],sources_partial,reader)
  shared.root_directory(Path(profile['privateParent']));context=Path(tempfile.mkdtemp(prefix='source-revision-postboot-prepared-',dir=profile['privateParent']));context.chmod(0o700);emit('PRIVATE_CONTEXT',contextPath=str(context))
  original_binding=document(context,'current-original-preparation.json',current_original,shared,reader)
  program=closure['executables']['docker'];reader.read(program['path'],program['sha256'],134217728)
  onboarding_facts=reader.facts('onboarding',current_original,shared,program,context);require(onboarding_facts['revisionTablePresent']is False and all(onboarding_facts['migrationRolePrivileges'].values())and onboarding_facts['migrations']==historical['databaseFacts']['onboarding']['migrations'],'ONBOARDING_MIGRATION_HISTORY_OR_ROLE_CHANGED');current['databaseFacts']['onboarding']=onboarding_facts
  current['postbootReconciliation']={**proof,**host_proof,'historicalPrivateInputs':profile['historicalPrivateInputs'],'hostJournalSha256':hashlib.sha256(journal_raw).hexdigest(),'currentOriginalPreparationBinding':original_binding,'runtimeAuthorityIssued':False}
  private_binding=document(context,'postboot-private-inputs.json',current,shared,reader)
  proposed_case={**case,'schema':'ouf.source-revision-postboot-update-selection.v2',
   'preparedPlanBinding':private_binding,'postbootOriginalPreparationBinding':original_binding,
   'historicalPreparedPlanBinding':profile['historicalPrivateInputs'],
   'completedHostPlanSha256':profile['hostPlanSha256'],'completedHostContext':profile['hostContext'],
   'qualifiedLibraryPackage':profile['stagedExecutor'],'qualifiedSourceHashesSha256':reader.digest(package['sourceHashes']),'qualifiedLoaderSha256':package['loaderSha256']}
  package,code_binding=freeze_code(context,proposed_case,profile,executor_raw,files,package,loader,shared,reader,overlays)
  extra={'executorSha256':package['executorSha256'],'caseSha256':package['caseSha256'],'mode':'SOURCE_REVISION_UPDATE'}
  pins={**pins,'ouf-deploy':profile['successorSourceCommit']}
  closure['declaration']=memory['declaration'](profile['successorSourceCommit'],sources,loader,pins,extra)
  executor={'__name__':'verified_postboot_consumer'};exec(compile(executor_raw,'<verified-postboot-consumer>','exec'),executor)
  require(executor['select_prepared'](proposed_case,original,ns['read'])==current_original,'POSTBOOT_CONSUMER_PAIR_UNPROVEN')
  # Compile with already-qualified source-owner libraries only. Never call
  # entry.main, login, authority constructors, mutation ports or apply.
  plan,primitives,compiled_private=prep.compile_private(current_original,closure,proposed_case,context,ns['read'],ns)
  importlib.import_module('tools.source_revision_update.authority').closure_valid(closure)
  require(reconcile_partial(profile['previousPreparationStop'],sources_partial,reader)==stopped,'PARTIAL_STOP_CHANGED')
  for cid,before in observed.items():
   after=api.get('/containers/'+cid+'/json')
   require(owner.immutable(after)==owner.immutable(before) and owner.process(after)==owner.process(before)
           and after['NetworkSettings']==before['NetworkSettings'],'GENERATION_CHANGED_DURING_POSTBOOT_PREPARATION')
  engine.check_socket();admin.check()
  for move in host['moves']:owner.verify_move(api,host,move,connected=True)
  for path,expected in host['configurationFileBindings'].items():require(hashlib.sha256(bootstrap.configuration_bytes(path,host['profile'],owner)).hexdigest()==expected,'COMPLETED_HOST_CONFIGURATION_BYTES_CHANGED')
  require(admin.routes()==historical['gateway']['beforeRoutes']and json.loads(reader.read(root/'journal.json',maximum=1048576))==journal,'GATEWAY_OR_COMPLETED_HOST_JOURNAL_CHANGED')
  require(bootstrap.provider_guard(boot_reader,guard_selection,owner)['loadedBinding']==native['loadedBinding'],'NATIVE_BOOT_BINDING_CHANGED_DURING_PREPARATION')
  require((lock.lstat().st_dev,lock.lstat().st_ino)==(info.st_dev,info.st_ino),'COMMON_LOCK_REPLACED')
  result={'schema':'ouf.source-revision-postboot-preparation-result.v1','contextPath':str(context),'hostCompletionReadbackProven':True,'postbootSuccessorPrepared':True,'nativePlanCompilationProven':True,'effectiveFlywayConfigurationProven':True,'currentOriginalPreparationBinding':original_binding,'preparedInputsBinding':private_binding,'caseBinding':{'path':str(context/'executor-code'/'case.json'),'sha256':package['caseSha256']},'executorCodeBinding':code_binding,'sourceClosureSha256':reader.digest(closure),'nativePlanBinding':{'path':str(context/'prepared-plan.json'),'sha256':shared.digest(plan)},'previousStopReconciliation':stopped,'privateArtifactsOnly':True,'databaseReadOnlySessions':4,'candidateArchivesReused':True,'imagesImported':0,'backupPerformed':False,'onboardingFromVersion':33,'onboardingToVersion':34,'udpMigrationVersion':36,'mcpMigrationsUnchanged':True,'routeCount':len(historical['gateway']['beforeRoutes']),'profilePublications':0,'runtimeAuthorityIssued':False,'readyForExecution':False}
  document(context,'postboot-preparation-result.json',result,shared,reader);emit('END',complete=True,**{k:v for k,v in result.items()if k!='schema'});return result
 finally:os.close(fd)
