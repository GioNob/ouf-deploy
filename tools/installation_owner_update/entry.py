"""Distinct native Onboarding-only cutover, preserving completed binding plan and all routes."""
import copy,hashlib,json,os,re,signal,stat,threading,time
from pathlib import Path
from engine_creation import Engine
from image_custody import runtime_image_id
from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused,SCOPES,PROFILE
from tools.linked_property_rollout.preparation import root_directory,read_file,write_new,encoded
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.ingestion_read_gateway_custody.owner import metadata_file
from tools.source_revision_update.plan import replacement
from tools.source_revision_update.native import runtime
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.installation_binding_plan import discovery
from tools.installation_owner_update import authority
from tools.installation_owner_update.owner import require,digest,scope,ReadinessUpdate,UpdatePaused,FORBIDDEN,OLD_ONBOARDING,OLD_SOURCE,NEW_SOURCE
from tools.installation_owner_update.native import NativePorts

PLAN_HASH='6bebb5d19b337d4156bd63be78e4068c7117ecec3f3199ef142046cb20d695e9'
ROUTE_HASH='d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927'
SCHEMAS={'candidate-review.json':'ouf.installation-owner-private-selection.v1',
 'execution-plan.json':'ouf.installation-binding-owner-update-plan.v1','review.json':'ouf.semantic-scoped-infrastructure-review.v1',
 'update-result.json':'ouf.installation-binding-owner-update-result.v1'}
def publish_json(context,name,value):
 require(name in SCHEMAS and type(value)is dict and value.get('schema')==SCHEMAS[name],'EXACT_INSTALLATION_OWNER_UPDATE_DOCUMENT_REQUIRED')
 context=Path(context);require(context.parent==authority.evidence.PARENT and re.fullmatch('installation-owner-update-execution-[A-Za-z0-9_-]{8,64}',context.name),'EXACT_OWNER_UPDATE_CONTEXT_REQUIRED')
 root_directory(context);row=context.lstat();require(row.st_uid==row.st_gid==0 and stat.S_IMODE(row.st_mode)==0o700,'PRIVATE_OWNER_UPDATE_CONTEXT_REQUIRED')
 raw=encoded(value);require(0<len(raw)<=8388608,'BOUNDED_OWNER_UPDATE_DOCUMENT_REQUIRED');write_new(context/name,raw)
 fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 require(read_file(context/name,hashlib.sha256(raw).hexdigest())==raw,'OWNER_UPDATE_DOCUMENT_READBACK_FAILED')

def current_human(selection,case,emit):
 binding=case['humanBinding'];human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 before=human._read();human._check(before)
 require(before['binding']==binding and 243<=case['priorOAuthAttempts']<=before['attempts']<=252
  and binding['scopes']==SCOPES and len(SCOPES)==11 and PROFILE['maximumAttempts']==256
  and before['state']!='BLOCKED'and not os.path.lexists(human.directory/'successor-window.claim.json'),
  'EXISTING_ELEVEN_SCOPE_HUMAN_AND_REMAINING_BUDGET_REQUIRED')
 deadline=min(time.monotonic()+90,before['monotonicDeadline'])
 while True:
  try:
   human.refresh_if_due();after=human._read();human._check(after)
   require(human.current()==binding and before['attempts']<=after['attempts']<=256,'HUMAN_COUNTER_OR_BINDING_CHANGED');return human
  except HumanSessionPaused as error:
   if error.retry_at is None:raise
   require(time.monotonic()<deadline and time.time()<human.expires_at,'HUMAN_PREFLIGHT_REFRESH_WAIT_EXHAUSTED')
   emit('OUF_INSTALLATION_OWNER_WAIT='+encoded({'phase':'EXISTING_HUMAN_REFRESH','attempts':human._read()['attempts'],'nextAttemptAt':error.retry_at,'budgetReset':False}).decode())
   threading.Event().wait(min(5,max(.1,error.retry_at-time.time()),max(.1,deadline-time.monotonic())))

def compile_current(case,context,read,human):
 installation=read(case['completedInstallationPlanBinding']['path'],expected=case['completedInstallationPlanBinding']['sha256'])
 require(digest(installation)==PLAN_HASH and installation['ownerApplyAuthorized']is False,'EXACT_COMPLETED_PLAN_ONLY_BASELINE_REQUIRED')
 previous,result,package_hash=discovery.history();require(package_hash==discovery.PACKAGE,'EXACT_COMPLETED_MCP_HISTORY_REQUIRED')
 old=read(case['installedPlanBinding']['path'],expected=case['installedPlanBinding']['sha256'])
 history=read(case['installedJournalBinding']['path'],expected=case['installedJournalBinding']['sha256'])
 require(history['effects'][-1]['stage']=='VERIFY_FINAL'and all(e['state']=='APPLIED'for e in history['effects'])and history['budgetReset']is False,'EXACT_COMPLETED_INSTALLATION_HISTORY_REQUIRED')
 expected={k:copy.deepcopy(v)for k,v in previous['unchangedApplications'].items()if k!='onboarding'}
 expected['mcp']=copy.deepcopy(result['finalEvidence']['mcp']['runtimeBinding'])
 require({'mcp','udp','ingestion'}<=set(expected)and 'onboarding'not in expected,'EXACT_RETAINED_INDEPENDENT_SERVICES_REQUIRED')
 engine=Engine(previous['engine']['socketPath'],tuple(previous['engine']['socketBinding']))
 def inspect(reference):
  require(re.fullmatch('[0-9a-f]{64}',reference),'EXACT_CONTAINER_ID_REQUIRED')
  status,value=engine.request('GET','/v1.44/containers/'+reference+'/json');require(status==200 and value['State']['Running']is True,'EXACT_RUNNING_APPLICATION_REQUIRED');return value
 actual=inspect(OLD_ONBOARDING)
 require(runtime(actual)==previous['unchangedApplications']['onboarding']and actual['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==OLD_SOURCE,'RETAINED_ONBOARDING_GENERATION_CHANGED')
 for binding in expected.values():require(runtime(inspect(binding['containerId']))==binding,'UNCHANGED_APPLICATION_DRIFT')
 gateway=NamespaceAdmin(engine,previous['gateway']['transport']);routes=gateway.routes()
 require(routes==previous['gateway']['afterRoutes']and len(routes)==82 and digest(routes)==ROUTE_HASH,'EXACT_COMPLETED_GATEWAY82_REQUIRED')
 private_config(previous['gateway']['projectionBinding']['path'],previous['gateway']['projectionBinding'])
 image=read(case['imageBinding']['path'],expected=case['imageBinding']['sha256'])
 migration=read(case['candidateMigrationEvidenceBinding']['path'],expected=case['candidateMigrationEvidenceBinding']['sha256'])
 require(migration['sourceCommit']==NEW_SOURCE and migration['installedSourceCommit']==OLD_SOURCE
  and migration['migrationFilesUnchanged']is True and migration['imageJarBound']is True,'UNCHANGED_IMAGE_MIGRATIONS_PROOF_REQUIRED')
 private={'schema':'ouf.installation-owner-private-selection.v1','completedInstallationPlanHash':PLAN_HASH,
  'completedMcpPackageHash':package_hash,'candidateImage':image,'migrationEvidenceHash':digest(migration),
  'oldRuntimeBinding':runtime(actual),'unchangedApplications':expected,'gatewayRouteMapHash':digest(routes),
  'humanBinding':human.current(),'caseHash':digest(case),'runtimeAuthorityIssued':False}
 publish_json(context,'candidate-review.json',private)
 saved=old['replacements']['onboarding'];selected={'module':'onboarding','name':saved['name'],
  'creationRequest':saved['request'],'restoreRestartPolicy':saved['restoreRestartPolicy']}
 parameters={'deployedSourceCommits':{'onboarding':OLD_SOURCE},'candidateSourceCommits':{'onboarding':NEW_SOURCE},'readiness':{'onboarding':saved['readiness']}}
 row=replacement(selected,actual,image,parameters,'onboarding');row['retiredName']=row['name']+'-installation-owner-retired-'+digest(private)[:12]
 metadata=copy.deepcopy(previous['retainedMcpMetadata']);require(len(metadata)==3,'EXACT_THREE_MCP_METADATA_FILES_REQUIRED')
 for binding in metadata:metadata_file(binding)
 plan={'schema':'ouf.installation-binding-owner-update-plan.v1','authorityDirectory':str(context),
  'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(private)},
  'engine':copy.deepcopy(previous['engine']),'programs':copy.deepcopy(old['programs']),
  'replacements':{'onboarding':row},'unchangedApplications':expected,
  'gateway':{**copy.deepcopy(previous['gateway']),'beforeRoutes':routes,'afterRoutes':copy.deepcopy(routes),'additions':{}},
  'retainedMcpMetadata':metadata,'humanBinding':human.current(),'onboardingMigrationsUnchanged':True,'publicMetadataUnchanged':True,
  'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,'databaseMigration':None,
  **{k:False for k in FORBIDDEN}}
 plan['logicalUpdateRef']=digest({'oldContainerId':OLD_ONBOARDING,'candidateSourceCommit':NEW_SOURCE,'candidateImageId':runtime_image_id(row['imageAudit']),'profile':'ouf.installation-binding-owner-update.v1'})
 scope(plan);return plan,engine

def main(original,sources,closure,case,context,read,emit):
 context=Path(context);emit('OUF_MCP_INGESTION_PHASE=VERIFY_OWNER_UPDATE_SOURCE_CLOSURE');authority.closure_valid(closure)
 claim=read(case['preparationClaimBinding']['path'],expected=case['preparationClaimBinding']['sha256'])
 require(claim['context']==str(context)and claim['candidateSourceCommit']==NEW_SOURCE and claim['completedInstallationPlanHash']==PLAN_HASH
  and claim['priorOAuthAttempts']==case['priorOAuthAttempts']and claim['maximumCumulativeOAuthAttempts']==256
  and claim['budgetReset']is False and claim['automaticReplayAllowed']is False,'EXACT_OWNER_UPDATE_PREPARATION_CLAIM_REQUIRED')
 emit('OUF_MCP_INGESTION_PHASE=EXISTING_HUMAN_SESSION_NO_NEW_LOGIN')
 human=current_human(original['authorization']['plan']['selection'],case,emit)
 emit('OUF_MCP_INGESTION_PHASE=READ_ONLY_CURRENT_ONBOARDING_UPDATE_PLAN');plan,engine=compile_current(case,context,read,human);publish_json(context,'execution-plan.json',plan)
 require(human.expires_at-time.time()>=1200,'EXISTING_HUMAN_WINDOW_TOO_SHORT_FOR_OWNER_UPDATE')
 authority.current_authorities(int(time.time())+900)
 scopes={'installationOwnerUpdate':scope(plan)}
 review=authority.compile_action_review('INSTALLATION_OWNER_UPDATE',closure,scopes,human.current(),context,
  {'predecessorHistoryHash':case['completedInstallationPlanBinding']['sha256'],'predecessorIncidentRef':plan['logicalUpdateRef']},900)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 emit('OUF_MCP_INGESTION_PHASE=NATIVE_ONBOARDING_OWNER_APPROVO_REQUIRED')
 decision=authority.terminal_consent(review,
  'Azione HUMAN distinta: aggiornamento del SOLO owner Onboarding per il binding di installazione. Tecniche8/8; funzionali4/6.\n'
  'Sorgente '+OLD_SOURCE+' -> '+NEW_SOURCE+'. L owner sara brevemente indisponibile; vecchio container conservato fermo.\n'
  'ETag con generazione, precondizione atomica, creazione deduplicata e probe fuori transazione.\n'
  'Configurazione, ambiente, mount, endpoint, policy47,82rotte e metadati0440 conservati; MCP/UDP/Ingestion invariati.\n'
  'Nessuna migrazione DB o SQL manuale, revisione profilo creata/attivata/esportata, fonte o acquisizione.\n'
  'Il piano installazione6bebb5d1 resta SOLO preparato: applicazione del binding e due rotte richiederanno un gate distinto.\n'
  'Sessione HUMAN esistente a11scope, tetto256 senza reset/nuovo login; massimo15minuti, un tentativo per effetto.\n'
  'Dopo STOP/interruzione: riconciliare senza rilancio. Piano privato: '+str(context/'execution-plan.json'))
 action=authority.issue_action(review,decision,human);cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():require(not cancelled.is_set(),'OWNER_UPDATE_CANCELLED');return time.time()
 action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
 try:
  ports=NativePorts(action,engine,plan,human);update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  emit('OUF_MCP_INGESTION_PHASE=ONBOARDING_UPDATE_AND_READBACK')
  while True:
   try:result=update.run();break
   except UpdatePaused as error:
    require(str(error)=='READINESS_RETRY_WAIT','OWNER_UPDATE_RECONCILIATION_REQUIRED')
    row=update.record();emit('OUF_INSTALLATION_OWNER_WAIT='+encoded({'stage':row['effects'][-1]['stage'],'attempts':row['cumulativeReadinessAttempts'],'nextReadAt':row['nextReadAt']}).decode())
    cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
  report={'schema':'ouf.installation-binding-owner-update-result.v1','status':'ONBOARDING_OWNER_UPDATE_READBACK_COMPLETE',
   'contextPath':str(context),'sourceCommit':NEW_SOURCE,'result':result,'finalEvidence':update.record()['effects'][-1]['evidence'],
   'completedInstallationPlanHash':PLAN_HASH,'oauthAttemptsAfter':human._read()['attempts'],'humanWindowExpiresAt':human.expires_at,
   'maximumCumulativeOAuthAttempts':256,'sourceActivated':False,'jobsRetried':0,'grantChanges':0,'gatewayWrites':0,
   'databaseMigrationsPerformed':0,'publicMetadataChanged':False,'installationBindingApplied':False,
   'atomicOwnerApiDeployed':True,'atomicOwnerApiLiveWriteTestPerformed':False,'nativeProfilePublished':False,
   'automaticReplayAllowed':False,'budgetReset':False,'notReleaseAcceptance':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
  publish_json(context,'update-result.json',report);emit('OUF_INSTALLATION_OWNER_UPDATE_RESULT='+encoded(report).decode())
 finally:
  cancelled.set()
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
