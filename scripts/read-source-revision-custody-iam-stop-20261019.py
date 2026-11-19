"""Installation-specific protected IAM STOP reconciliation; no login or replay."""
import hashlib,json,os,signal,stat,time
from pathlib import Path
PREPARED=Path('/etc/ouf/deploy-snapshots/source-revision-custody-continuation-dvf517sr')
STOPPED=Path('/etc/ouf/deploy-snapshots/source-revision-execution-kcw73ask')
CASE='4effa9a3b9b4cea3f4ff73a884e034114b04442667fa945373bcd595dfc9780c'
PACKAGE='afc2dbbfa72c14a64b00e9a0fba04fa731bd2ec51b08f5b65211a74a3dafd30d'
RESULT='1de8d0f6740573bc2b4aa4125a67a806a1b6016c1e56a319aa666cb7bb8c0b91'
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

FROZEN_NAMES={'iam_binding_candidate': 'iam_binding_candidate.py', 'migration_root_custody': 'migration_root_custody.py', 'tools.chatbot_file_cohort.continued_owner': 'continued_owner.py', 'tools.chatbot_file_cohort.review': 'review.py', 'tools.chatbot_file_cohort.human_session': 'human_session.py', 'tools.chatbot_file_cohort.gateway': 'gateway.py', 'tools.semantic_policy_token_owner.installed_owner': 'installed_owner.py', 'tools.semantic_policy_token_owner.supervisor': 'supervisor.py', 'image_custody': 'image_custody.py', 'tools.semantic_mcp_update.entry': 'mcp_entry.py', 'tools.semantic_mcp_update.authority': 'mcp_authority.py', 'tools.semantic_mcp_update.permit': 'mcp_permit.py', 'tools.semantic_mcp_update.plan': 'mcp_plan.py', 'tools.semantic_mcp_update.session': 'mcp_session.py', 'tools.semantic_mcp_update.owner': 'mcp_owner.py', 'tools.semantic_mcp_update.native': 'mcp_native.py', 'tools.ingestion_readiness_update.entry': 'readiness_entry.py', 'tools.ingestion_readiness_update.authority': 'readiness_authority.py', 'tools.ingestion_readiness_update.plan': 'readiness_plan.py', 'tools.ingestion_readiness_update.owner': 'readiness_owner.py', 'tools.ingestion_readiness_update.native': 'readiness_native.py', 'tools.onboarding_audit_update.entry': 'audit_entry.py', 'tools.onboarding_audit_update.authority': 'audit_authority.py', 'tools.onboarding_audit_update.owner': 'audit_owner.py', 'tools.onboarding_audit_update.native': 'audit_native.py', 'tools.onboarding_audit_update.preparation': 'audit_preparation.py', 'tools.resolution_ths_update.entry': 'resolution_entry.py', 'tools.resolution_ths_update.authority': 'resolution_authority.py', 'tools.resolution_ths_update.owner': 'resolution_owner.py', 'tools.resolution_ths_update.native': 'resolution_native.py', 'tools.resolution_ths_update.plan': 'resolution_plan.py', 'tools.resolution_ths_configuration.entry': 'config_entry.py', 'tools.resolution_ths_configuration.authority': 'config_authority.py', 'tools.resolution_ths_configuration.owner': 'config_owner.py', 'tools.resolution_ths_configuration.native': 'config_native.py', 'tools.resolution_ths_configuration.plan': 'config_plan.py', 'tools.udp_resolution_update.entry': 'udp_entry.py', 'tools.udp_resolution_update.authority': 'udp_authority.py', 'tools.udp_resolution_update.owner': 'udp_owner.py', 'tools.udp_resolution_update.native': 'udp_native.py', 'tools.udp_resolution_update.plan': 'udp_plan.py', 'tools.udp_resolution_update.preparation': 'udp_preparation.py', 'tools.resolution_comparison_update.entry': 'comparison_entry.py', 'tools.resolution_comparison_update.authority': 'comparison_authority.py', 'tools.resolution_comparison_update.owner': 'comparison_owner.py', 'tools.resolution_comparison_update.native': 'comparison_native.py', 'tools.resolution_comparison_update.plan': 'comparison_plan.py', 'tools.resolution_comparison_update.preparation': 'comparison_preparation.py', 'tools.linked_property_rollout.entry': 'linked_entry.py', 'tools.linked_property_rollout.authority': 'linked_authority.py', 'tools.linked_property_rollout.owner': 'linked_owner.py', 'tools.linked_property_rollout.native': 'linked_native.py', 'tools.linked_property_rollout.plan': 'linked_plan.py', 'tools.linked_property_rollout.preparation': 'linked_preparation.py', 'tools.linked_property_rollout.database': 'linked_database.py', 'tools.linked_property_rollout.configuration': 'linked_configuration.py', 'tools.linked_property_rollout.login': 'linked_login.py', 'tools.chat_recovery_update.entry': 'chat_recovery_entry.py', 'tools.chat_recovery_update.authority': 'chat_recovery_authority.py', 'tools.chat_recovery_update.owner': 'chat_recovery_owner.py', 'tools.chat_recovery_update.native': 'chat_recovery_native.py', 'tools.chat_recovery_update.plan': 'chat_recovery_plan.py', 'tools.chat_recovery_update.preparation': 'chat_recovery_preparation.py', 'tools.chat_recovery_update.database': 'chat_recovery_database.py', 'tools.chat_recovery_update.login': 'chat_recovery_login.py', 'tools.chat_recovery_update.readiness': 'chat_recovery_readiness.py', 'tools.chatbot_file_cohort.authorization': 'authorization.py', 'tools.source_revision_update.entry': 'source_revision_entry.py', 'tools.source_revision_update.authority': 'source_revision_authority.py', 'tools.source_revision_update.owner': 'source_revision_owner.py', 'tools.source_revision_update.native': 'source_revision_native.py', 'tools.source_revision_update.plan': 'source_revision_plan.py', 'tools.source_revision_update.preparation': 'source_revision_preparation.py', 'tools.source_revision_update.database': 'source_revision_database.py', 'tools.source_revision_update.configuration': 'source_revision_configuration.py', 'tools.source_revision_update.login': 'source_revision_login.py', 'tools.source_revision_update.gateway': 'source_revision_gateway.py'}
EXECUTOR='5ebe410809d674e215917032bcce7428654b1caf2524880aa75bc0ac4e2657d2'
CLOSURE='b056490dac4e72d4bee23e2539706b1ac7ca584dae800c59d425806df11dccd2'
PLAN='56bf1dd93394ae8f36276ed8765707084732f2f7d78ce09e954a15c9c36e6591'
CONTINUATION='8e9a32eb2ccb28cae74bdbf56342db12153f34469737f873067cfe6bc2296639'
def prepared_closure(result,case,package):
 code=PREPARED/'executor-code';require(package['schema']=='ouf.source-revision-executable-package.v1'and package['executorSha256']==EXECUTOR
  and set(package['sourceHashes'])==set(FROZEN_NAMES)and result['sourceClosureSha256']==CLOSURE)
 names={'case.json','package.json','runtime.py','execute.py'}|set(FROZEN_NAMES.values())
 require(len(names)==81 and {p.name for p in code.iterdir()}==names)
 for module,name in FROZEN_NAMES.items():read(code/name,package['sourceHashes'][module],262144)
 read(code/'execute.py',EXECUTOR,262144);read(code/'runtime.py',package['loaderSha256'],65536)
 require(result['nativePlanBinding']=={'path':str(PREPARED/'prepared-plan.json'),'sha256':PLAN}
  and result['continuationPlanBinding']=={'path':str(PREPARED/'continuation-plan.json'),'sha256':CONTINUATION})
 read(PREPARED/'continuation-plan.json',CONTINUATION)
 require(case['custodyContinuation']['schema']=='ouf.source-revision-mcp-custody-continuation.v1')
 predecessor=case['custodyContinuation']['scopeSuccessor'];old=Path(predecessor['context'])
 require(old==PREPARED.parent/'source-revision-execution-dvf517sr')
 for binding in (v for k,v in predecessor.items()if k.endswith('Binding')):read(binding['path'],binding['sha256'])
 row=parse(read(predecessor['journalBinding']['path'],predecessor['journalBinding']['sha256']))
 require(row['version']==row['nextStage']==row['readinessAttempts']==row['cumulativeReadinessAttempts']==0
  and row['effects']==[]and row['budgetReset']is False and row['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  and time.time()>=row['expiresAt']and time.monotonic()>=row['expiresMonotonic']and not os.path.lexists(old/'logical-successor.claim.json'))
 return {'frozenFilesVerified':81,'continuationPlanBound':True,'originalScopeUnchanged':True,'successorClaimAbsent':True}

def current_human(case):
 reference=case['postbootResumedHuman'];binding=reference['binding'];directory=Path(binding['sessionDirectory']);raw=read(directory/'recovery.json',maximum=65536);row=parse(raw)
 require(row['schema']=='ouf.chatbot-human-session.private.v1'and row['binding']==binding and row['budgetReset']is False
  and row['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()and row['state']=='READY'and row['attempts']==188
  and reference['minimumOAuthAttempts']==188 and reference['maximumCumulativeOAuthAttempts']==256
  and reference['newLoginAllowed']is False and reference['windowExtensionAllowed']is False
  and time.time()+1200<binding['expiresAt']and time.monotonic()+1200<row['monotonicDeadline']
  and time.time()+2>=row['lastObservedAt']and not os.path.lexists(directory/'successor-window.claim.json'))
 require(read(directory/'recovery.json',maximum=65536)==raw)
 return {'state':'READY','attempts':188,'remainingAttempts':68,'maximumAttempts':256,'bindingPreserved':True,
  'currentBootMatches':True,'originalWindowPreserved':True,'windowRemainingSeconds':int(binding['expiresAt']-time.time()),
  'journalHashPrinted':False,'tokenFilesOpened':0,'newLoginOpened':False}

def main():
 require(os.geteuid()==os.getegid()==0 and __import__('sys').flags.isolated and __import__('sys').flags.no_site and __import__('sys').dont_write_bytecode);signal.alarm(180)
 result=parse(read(PREPARED/'postboot-preparation-result.json',RESULT));case=parse(read(PREPARED/'executor-code/case.json',CASE));package=parse(read(PREPARED/'executor-code/package.json',PACKAGE))
 require(result['schema']=='ouf.source-revision-postboot-preparation-result.v1' and result['contextPath']==str(PREPARED)
  and result['runtimeAuthorityIssued']is False and result['readyForExecution']is False
  and all(result[k]is True for k in ('postbootSuccessorPrepared','nativePlanCompilationProven','effectiveFlywayConfigurationProven','hostCompletionReadbackProven')))
 require(result['caseBinding']=={'path':str(PREPARED/'executor-code/case.json'),'sha256':CASE}
  and result['executorCodeBinding']=={'directory':str(PREPARED/'executor-code'),'sourceCommit':'5571f70b501fffa81b6c9e18b5bb67b0957ed2d9','packageSha256':PACKAGE}
  and package['sourceCommit']=='5571f70b501fffa81b6c9e18b5bb67b0957ed2d9' and package['caseSha256']==CASE)
 require(case['preparedPlanBinding']==result['preparedInputsBinding'] and case['postbootOriginalPreparationBinding']==result['currentOriginalPreparationBinding'])
 for field,name in (('preparedInputsBinding','postboot-private-inputs.json'),('currentOriginalPreparationBinding','current-original-preparation.json'),('nativePlanBinding','prepared-plan.json')):
  binding=result[field];expected=(PREPARED if field=='nativePlanBinding'else PREPARED.parent/'source-revision-postboot-prepared-kfy691gh')/name;require(binding['path']==str(expected));read(expected,binding['sha256'])
 closure=prepared_closure(result,case,package);human=current_human(case)
 stopped=reconcile_execution(STOPPED,PREPARED,result,case)
 require(reconcile_execution(STOPPED,PREPARED,result,case)==stopped)
 read(PREPARED/'postboot-preparation-result.json',RESULT)
 return {'schema':'ouf.source-revision-custody-iam-stop-read.v1','complete':True,'executionReconciliation':stopped,
  'preparedReceiptHashIndependentlyRead':True,'preparationResultSha256':RESULT,'preparedContextPath':str(PREPARED),
  'preparedClosure':closure,'humanSession':human,'humanJournalsRead':1,'credentialJournalHashesPrinted':False,'tokenFilesOpened':0,'oauthRequests':0,'engineCalls':0,'databaseCalls':0,'journalWrites':0,
  'runtimeAuthorityIssued':False,'credentialValuesPrinted':False,'automaticRetry':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4,'iamSessionRenewed':False,'readyForExecution':False}
if __name__=='__main__':
 try:output=main()
 except (Exception,KeyboardInterrupt) as error:
  output={'schema':'ouf.source-revision-custody-iam-stop-read.v1','complete':False,'exceptionClass':type(error).__name__,'rawErrorPrinted':False,'runtimeAuthorityIssued':False,'automaticRetry':False,'budgetReset':False,'reconciliationRequired':True}
 print(json.dumps(output,sort_keys=True));raise SystemExit(0 if output['complete']else 2)
