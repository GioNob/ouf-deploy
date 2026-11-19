"""Prepare current MCP-only plan and execute only after exact native APPROVO."""
import copy,hashlib,json,os,re,signal,stat,threading,time
from pathlib import Path
from engine_creation import Engine
from image_custody import runtime_image_id
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.ingestion_read_authorization.authorization import validate_session_binding,INGESTION_READ_PROFILE
from tools.linked_property_rollout.preparation import root_directory,read_file,write_new,encoded
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.source_revision_update.plan import replacement
from tools.source_revision_update.native import runtime
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.ingestion_read_transport_update import authority
from tools.ingestion_read_transport_update.owner import require,digest,scope,ReadinessUpdate,UpdatePaused,FORBIDDEN,OLD_MCP,OLD_SOURCE,NEW_SOURCE
from tools.ingestion_read_transport_update.native import NativePorts

def publish_json(context,name,value):
 schemas={'candidate-review.json':'ouf.mcp-read-transport-private-selection.v1',
  'execution-plan.json':'ouf.mcp-ingestion-read-transport-update-plan.v1',
  'review.json':'ouf.semantic-scoped-infrastructure-review.v1',
  'update-result.json':'ouf.mcp-ingestion-read-transport-update-result.v1'}
 require(name in schemas and type(value)is dict and value.get('schema')==schemas[name],
  'EXACT_MCP_UPDATE_DOCUMENT_REQUIRED')
 context=Path(context)
 require(context.parent==authority.evidence.PARENT and re.fullmatch(
  'mcp-ingestion-read-transport-execution-[A-Za-z0-9_-]{8,64}',context.name),'EXACT_MCP_UPDATE_CONTEXT_REQUIRED')
 root_directory(context);row=context.lstat()
 require(row.st_uid==row.st_gid==0 and stat.S_IMODE(row.st_mode)==0o700,'PRIVATE_MCP_UPDATE_CONTEXT_REQUIRED')
 raw=encoded(value);require(0<len(raw)<=8388608,'BOUNDED_MCP_UPDATE_DOCUMENT_REQUIRED')
 path=context/name;write_new(path,raw)
 fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 require(read_file(path,hashlib.sha256(raw).hexdigest())==raw,'MCP_UPDATE_DOCUMENT_READBACK_FAILED')

def current_human(selection,case):
 binding=case['humanBinding'];validate_session_binding(binding,selection,profile=INGESTION_READ_PROFILE)
 human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 before=human._read();human._check(before)
 require(before['binding']==binding and 216<=case['priorOAuthAttempts']<=before['attempts']<=256
  and before['state']!='BLOCKED'and not os.path.lexists(human.directory/'successor-window.claim.json'),
  'SAME_EXISTING_CUMULATIVE_HUMAN_REQUIRED')
 human.refresh_if_due();after=human._read();human._check(after)
 require(human.current()==binding and before['attempts']<=after['attempts']<=256,'HUMAN_COUNTER_OR_BINDING_CHANGED')
 return human

def compile_current(case,context,read,human):
 # Completed execution is history only; no completed reader/installer main runs.
 old=read(case['installedPlanBinding']['path'],expected=case['installedPlanBinding']['sha256'])
 history=read(case['installedJournalBinding']['path'],expected=case['installedJournalBinding']['sha256'])
 require(history['effects'][-1]['stage']=='VERIFY_FINAL'and all(e['state']=='APPLIED'for e in history['effects'])
  and history['budgetReset']is False,'COMPLETED_SOURCE_REVISION_HISTORY_REQUIRED')
 final=history['effects'][-1]['evidence']['applications']
 engine=Engine(old['engine']['socketPath'],tuple(old['engine']['socketBinding']))
 def inspect(reference):
  require(re.fullmatch('[0-9a-f]{64}',reference),'EXACT_CONTAINER_ID_REQUIRED')
  status,value=engine.request('GET','/v1.44/containers/'+reference+'/json')
  require(status==200 and value['State']['Running']is True,'EXACT_RUNNING_APPLICATION_REQUIRED')
  return value
 actual=inspect(OLD_MCP)
 require(runtime(actual)==final['mcp']['runtimeBinding']
  and actual['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==OLD_SOURCE,
  'INSTALLED_MCP_GENERATION_CHANGED')
 expected={'onboarding':final['onboarding']['runtimeBinding'],**old['unchangedApplications']}
 require({'onboarding','udp','ingestion'}<=set(expected)and 'mcp'not in expected and len(expected)<=8,
  'EXACT_RETAINED_UNCHANGED_SERVICES_REQUIRED')
 for value in expected.values():
  require(runtime(inspect(value['containerId']))==value,'UNCHANGED_APPLICATION_DRIFT')
 gateway=NamespaceAdmin(engine,old['gateway']['transport']);routes=gateway.routes()
 require(routes==old['gateway']['afterRoutes']and len(routes)==80,'COMPLETED_GATEWAY_ROUTE_MAP_CHANGED')
 for capability in ('ouf.ingestion.status','ouf.ingestion.history'):
  require(any(r.get('uri')=='/internal/capabilities/v1/execute/'+capability
   and r.get('methods')==['POST']for r in routes.values()),'REVIEWED_INGESTION_GATEWAY_ROUTE_MISSING')
 saved=old['replacements']['mcp']
 selected={'module':'mcp','name':saved['name'],'creationRequest':saved['request'],
  'restoreRestartPolicy':saved['restoreRestartPolicy']}
 image=read(case['imageBinding']['path'],expected=case['imageBinding']['sha256'])
 private={'schema':'ouf.mcp-read-transport-private-selection.v1','completedPlanHash':digest(old),
  'completedJournalHash':digest(history),'image':image,'oldRuntimeBinding':runtime(actual),
  'unchangedApplications':expected,'gatewayRouteMapHash':digest(routes),'humanBinding':human.current(),
  'caseHash':digest(case),'runtimeAuthorityIssued':False}
 publish_json(context,'candidate-review.json',private)
 parameters={'deployedSourceCommits':{'mcp':OLD_SOURCE},'candidateSourceCommits':{'mcp':NEW_SOURCE},
  'readiness':{'mcp':saved['readiness']}}
 row=replacement(selected,actual,image,parameters,'mcp')
 row['retiredName']=row['name']+'-ingestion-read-retired-'+digest(private)[:12]
 metadata=copy.deepcopy(old['retainedMcpMetadata'])
 require(len(metadata)==3,'EXACT_THREE_RETAINED_METADATA_FILES_REQUIRED')
 for binding in metadata:
  info=Path(binding['path']).lstat()
  require(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o440,
   'RETAINED_METADATA_0440_REQUIRED')
  binding['custody']={k:getattr(info,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size')}
 plan={'schema':'ouf.mcp-ingestion-read-transport-update-plan.v1','authorityDirectory':str(context),
  'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(private)},
  'engine':copy.deepcopy(old['engine']),'programs':copy.deepcopy(old['programs']),
  'replacements':{'mcp':row},'unchangedApplications':copy.deepcopy(expected),
  'gateway':{**copy.deepcopy(old['gateway']),'beforeRoutes':routes,'afterRoutes':copy.deepcopy(routes),'additions':{}},
  'retainedMcpMetadata':metadata,'humanBinding':human.current(),
  'mcpMigrationsUnchanged':True,'publicMetadataUnchanged':True,'maximumExecutionSeconds':900,
  'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,'databaseMigration':None,
  **{k:False for k in FORBIDDEN}}
 plan['logicalUpdateRef']=digest({'oldContainerId':OLD_MCP,'candidateSourceCommit':NEW_SOURCE,
  'candidateImageId':runtime_image_id(row['imageAudit']),'profile':'ouf.mcp-ingestion-read-transport-update.v1'})
 scope(plan);return plan,engine

def main(original,sources,closure,case,context,read,emit):
 context=Path(context);emit('OUF_MCP_INGESTION_PHASE=VERIFY_SOURCE_CLOSURE');authority.closure_valid(closure)
 claim_binding=case['preparationClaimBinding'];claim=read(claim_binding['path'],expected=claim_binding['sha256'])
 require(claim['context']==str(context)and claim['candidateSourceCommit']==NEW_SOURCE
  and claim['priorOAuthAttempts']==case['priorOAuthAttempts']and claim['maximumCumulativeOAuthAttempts']==256
  and claim['budgetReset']is False and claim['automaticReplayAllowed']is False,'EXACT_MCP_PREPARATION_CLAIM_REQUIRED')
 emit('OUF_MCP_INGESTION_PHASE=EXISTING_HUMAN_SESSION')
 human=current_human(original['authorization']['plan']['selection'],case)
 authority.current_authorities(int(time.time())+910)
 emit('OUF_MCP_INGESTION_PHASE=READ_ONLY_CURRENT_PLAN')
 plan,engine=compile_current(case,context,read,human);publish_json(context,'execution-plan.json',plan)
 seconds=min(900,human.expires_at-int(time.time())-10)
 require(seconds>=600,'HUMAN_WINDOW_TOO_SHORT_FOR_MCP_UPDATE')
 scopes={'mcpReadTransportUpdate':scope(plan)}
 review=authority.compile_action_review('MCP_READ_TRANSPORT_UPDATE',closure,scopes,human.current(),context,
  {'predecessorHistoryHash':case['installedJournalBinding']['sha256'],'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 emit('OUF_MCP_INGESTION_PHASE=NATIVE_APPROVO_REQUIRED')
 decision=authority.terminal_consent(review,
  'Aggiornamento distinto del solo MCP per i due percorsi Ingestion status/history. Tecniche8/8; funzionali4/6.\n'
  'Sostituisco la sola immagine MCP '+OLD_SOURCE+' con '+NEW_SOURCE+'.\n'
  'MCP sara brevemente indisponibile. Conservo il vecchio container fermo e senza riavvio automatico.\n'
  'Stessa configurazione, ambiente, mount, endpoint e metadati0440; Onboarding/UDP/Ingestion invariati.\n'
  'Nessuna migrazione/SQL, modifica delle80rotte, dei grant/policy47 o dei metadati pubblici.\n'
  'Nessuna attivazione fonte, acquisizione, decisione identita, job o replay storico.\n'
  'Sessione HUMAN e cumulativo256 conservati; massimo15minuti, un tentativo per effetto.\n'
  'Esiti incerti richiedono riconciliazione senza rilancio. Piano: '+str(context/'execution-plan.json'))
 action=authority.issue_action(review,decision,human);cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():
  require(not cancelled.is_set(),'MCP_UPDATE_CANCELLED');return time.time()
 action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
 try:
  ports=NativePorts(action,engine,plan,human);update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  emit('OUF_MCP_INGESTION_PHASE=MCP_UPDATE_AND_READBACK')
  while True:
   try:result=update.run();break
   except UpdatePaused as error:
    require(str(error)=='READINESS_RETRY_WAIT','MCP_UPDATE_RECONCILIATION_REQUIRED')
    row=update.record();emit('OUF_MCP_INGESTION_WAIT='+encoded({'attempts':row['cumulativeReadinessAttempts'],
     'stage':row['effects'][-1]['stage'],'nextReadAt':row['nextReadAt']}).decode())
    cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
  final=update.record()['effects'][-1]['evidence']
  report={'schema':'ouf.mcp-ingestion-read-transport-update-result.v1','status':'MCP_TRANSPORT_UPDATE_READBACK_COMPLETE',
   'contextPath':str(context),'sourceCommit':NEW_SOURCE,'result':result,'finalEvidence':final,
   'oauthAttemptsAfter':human._read()['attempts'],'maximumCumulativeOAuthAttempts':256,
   'sourceActivated':False,'jobsRetried':0,'grantChanges':0,'gatewayWrites':0,'databaseMigrationsPerformed':0,
   'publicMetadataChanged':False,'automaticReplayAllowed':False,'budgetReset':False,
   'completedTechnicalPhases':8,'functionalMilestonesProven':4,'freshChatClientReadProven':False}
  publish_json(context,'update-result.json',report);emit('OUF_MCP_INGESTION_UPDATE_RESULT='+encoded(report).decode())
 finally:
  cancelled.set()
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
