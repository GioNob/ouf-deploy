"""Review and publish only two missing Gateway READ routes; no MCP replacement."""
import copy,hashlib,json,os,re,signal,stat,threading,time
from pathlib import Path
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.source_revision_update.native import runtime
from tools.linked_property_rollout.preparation import root_directory,read_file,write_new,encoded
from tools.mcp_read_transport_compatibility.entry import current_human
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.ingestion_read_gateway_update import authority,compiler
from tools.ingestion_read_gateway_update.owner import require,digest,scope,GatewayUpdate,FORBIDDEN,PROFILE,BEFORE_HASH

def publish_json(context,name,value):
 schemas={'candidate-review.json':'ouf.ingestion-read-gateway-private-review.v1','execution-plan.json':'ouf.ingestion-read-gateway-plan.v1',
  'review.json':'ouf.semantic-scoped-infrastructure-review.v1','update-result.json':'ouf.ingestion-read-gateway-result.v1'}
 require(name in schemas and value.get('schema')==schemas[name],'EXACT_GATEWAY_PUBLICATION_DOCUMENT_REQUIRED')
 context=Path(context);require(context.parent==authority.evidence.PARENT and re.fullmatch('mcp-ingestion-read-transport-execution-[A-Za-z0-9_-]{8,64}',context.name),'EXACT_PRIVATE_CONTEXT_REQUIRED')
 root_directory(context);info=context.lstat();require(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,'PRIVATE_CONTEXT_CUSTODY_REQUIRED')
 raw=encoded(value);require(0<len(raw)<=8388608,'BOUNDED_PRIVATE_DOCUMENT_REQUIRED');write_new(context/name,raw)
 fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 require(read_file(context/name,hashlib.sha256(raw).hexdigest())==raw,'PRIVATE_DOCUMENT_READBACK_FAILED')

def compile_current(case,context,read,human):
 old=read(case['installedPlanBinding']['path'],expected=case['installedPlanBinding']['sha256'])
 history=read(case['installedJournalBinding']['path'],expected=case['installedJournalBinding']['sha256'])
 require(history['effects'][-1]['stage']=='VERIFY_FINAL'and all(e['state']=='APPLIED'for e in history['effects'])and history['budgetReset']is False,'COMPLETED_HISTORY_REQUIRED')
 final=history['effects'][-1]['evidence']['applications']
 expected={'mcp':final['mcp']['runtimeBinding'],'onboarding':final['onboarding']['runtimeBinding'],**old['unchangedApplications']}
 require(set(expected)=={'mcp','onboarding','udp','ingestion'},'EXACT_FOUR_RETAINED_APPLICATIONS_REQUIRED')
 engine=Engine(old['engine']['socketPath'],tuple(old['engine']['socketBinding']))
 for binding in expected.values():
  status,actual=engine.request('GET','/v1.44/containers/'+binding['containerId']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==binding,'RETAINED_APPLICATION_GENERATION_CHANGED')
 admin=NamespaceAdmin(engine,old['gateway']['transport']);before=admin.routes()
 require(before==old['gateway']['afterRoutes']and len(before)==80 and digest(before)==BEFORE_HASH,'EXACT_CURRENT80_RETAINED_ROUTES_REQUIRED')
 projection_raw,projection_binding=private_config(old['gateway']['projectionBinding']['path'],old['gateway']['projectionBinding'])
 bundle=read(case['gatewayCompilerBinding']['path'],expected=case['gatewayCompilerBinding']['sha256'])
 gateway={**compiler.compile_routes(bundle,json.loads(projection_raw),before,context),
  'transport':copy.deepcopy(old['gateway']['transport']),'projectionBinding':projection_binding}
 metadata=copy.deepcopy(old['retainedMcpMetadata']);require(len(metadata)==3,'EXACT_THREE_MCP_METADATA_BINDINGS_REQUIRED')
 for binding in metadata:
  raw=read_file(binding['path'],binding['sha256'],65536);info=Path(binding['path']).lstat()
  require(stat.S_ISREG(info.st_mode)and stat.S_IMODE(info.st_mode)==0o440 and info.st_nlink==1,'RETAINED_METADATA0440_REQUIRED')
  binding['custody']={k:getattr(info,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size')}
 private={'schema':'ouf.ingestion-read-gateway-private-review.v1','caseHash':digest(case),'completedPlanHash':digest(old),
  'completedJournalHash':digest(history),'compilerBinding':case['gatewayCompilerBinding'],'gatewaySourceCommit':compiler.GATEWAY_SOURCE,
  'beforeRouteMapHash':digest(before),'afterRouteMapHash':digest(gateway['afterRoutes']),
  'routeHashes':{k:digest(v)for k,v in gateway['additions'].items()},'humanBinding':human.current(),'runtimeAuthorityIssued':False}
 publish_json(context,'candidate-review.json',private)
 plan={'schema':'ouf.ingestion-read-gateway-plan.v1','authorityDirectory':str(context),
  'privateReviewBinding':{'path':str(Path(context)/'candidate-review.json'),'sha256':digest(private)},
  'engine':copy.deepcopy(old['engine']),'gateway':gateway,'unchangedApplications':expected,'retainedMcpMetadata':metadata,
  'humanBinding':human.current(),'replacements':{},'databaseMigration':None,'maximumExecutionSeconds':900,
  'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':2,**{k:False for k in FORBIDDEN}}
 plan['logicalUpdateRef']=digest({'profile':PROFILE,'beforeRouteMapHash':BEFORE_HASH,'capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
 scope(plan);return plan,engine

def main(original,sources,closure,case,context,read,emit):
 emit('OUF_MCP_INGESTION_PHASE=VERIFY_GATEWAY_ONLY_CLOSURE');authority.closure_valid(closure)
 claim=read(case['preparationClaimBinding']['path'],expected=case['preparationClaimBinding']['sha256'])
 require(claim['context']==str(context)and claim['profile']==PROFILE and claim['automaticReplayAllowed']is False
  and claim['budgetReset']is False and claim['maximumCumulativeOAuthAttempts']==256,'EXACT_GATEWAY_PREPARATION_CLAIM_REQUIRED')
 emit('OUF_MCP_INGESTION_PHASE=EXISTING_READY_HUMAN_ONLY')
 human=current_human(original['authorization']['plan']['selection'],case)
 emit('OUF_MCP_INGESTION_PHASE=COMPILE_TWO_ADDITIVE_GATEWAY_ROUTES')
 plan,engine=compile_current(case,context,read,human);publish_json(context,'execution-plan.json',plan)
 seconds=min(900,human.expires_at-int(time.time())-10);require(seconds>=600,'EXISTING_HUMAN_WINDOW_TOO_SHORT_NO_EXTENSION')
 authority.current_authorities(int(time.time())+seconds)
 review=authority.compile_action_review('INGESTION_READ_GATEWAY_UPDATE',closure,{'ingestionReadGatewayUpdate':scope(plan)},human.current(),context,
  {'predecessorHistoryHash':case['installedJournalBinding']['sha256'],'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 emit('OUF_MCP_INGESTION_PHASE=NATIVE_APPROVO_TWO_GATEWAY_ROUTES_REQUIRED')
 summary=('Azione DISTINTA: aggiungo SOLO due rotte Gateway READ per Ingestion status/history.\n'
  'Percorsi /internal/capabilities/v1/execute/ouf.ingestion.status e ouf.ingestion.history, POST.\n'
  'Scope ingestion.operations.read, stesso workload e delegazione HUMAN firmata; destinazione da profilo validato.\n'
  '80rotte conservate integralmente,82finali; massimo2PUT, una per rotta, con readback.\n'
  'Nessuna modifica o riavvio container MCP/Gateway/Onboarding/UDP/Ingestion; nessuna immagine o migrazione.\n'
  'Nessuna modifica IAM/grant/policy47/metadati, attivazione fonte, acquisizione o job.\n'
  'Sessione HUMAN esistente, nessun login/finestra/budget nuovi. Il consenso precedente solo-MCP non autorizza queste PUT.\n'
  'Questa review autorizza esclusivamente le due aggiunte; aggiornamento MCP seguira con decisione distinta.\n'
  'Massimo15minuti e nessun replay dopo STOP/interruzione. Tecniche8/8; funzionali4/6.\n'
  'Piano privato: '+str(Path(context)/'execution-plan.json')+'\nHash rotte: '+digest(plan['gateway']['additions']))
 decision=authority.terminal_consent(review,summary);action=authority.issue_action(review,decision,human)
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():
  require(not cancelled.is_set(),'GATEWAY_ACTION_CANCELLED');return time.time()
 action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
 try:
  update=GatewayUpdate(action,engine,plan,human,Journal(context));update.initialize()
  emit('OUF_MCP_INGESTION_PHASE=TWO_GATEWAY_PUTS_AND_READBACK')
  result=update.run();result.update(contextPath=str(context),humanAttemptsAfter=human._read()['attempts'],maximumCumulativeOAuthAttempts=256,
   gatewaySourceCommit=compiler.GATEWAY_SOURCE,humanWindowExpiresAt=human.expires_at)
  publish_json(context,'update-result.json',result);emit('OUF_INGESTION_READ_GATEWAY_RESULT='+encoded(result).decode())
 finally:
  cancelled.set()
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
