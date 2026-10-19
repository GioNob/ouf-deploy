"""Three explicit native decisions: fresh HUMAN, owner binding, projection plus two routes."""
import copy,hashlib,json,os,re,signal,stat,tempfile,threading,time
from pathlib import Path
from engine_creation import Engine
from tools.chatbot_file_cohort.human_session import HumanSession,SCOPES
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.ingestion_read_authorization.authorization import OwnerTransport,NoRedirect
from tools.installation_binding_plan import plan as old_planning,discovery
from tools.ingestion_read_gateway_update import compiler
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.ingestion_read_gateway_custody.owner import metadata_file
from tools.installation_binding_apply import baseline,authority,login
from tools.installation_binding_apply.owner import require,digest,encoded,scope,scope_key,FiniteUpdate,FORBIDDEN
from tools.installation_binding_apply.native import Ports,OwnerHttp,baseline_runtime

SCHEMAS={'login-review.json':'ouf.installation-binding-reauth251-review.v1','login-decision.json':'ouf.installation-binding-reauth251-decision.v1',
 'login-window-receipt.json':'ouf.installation-binding-reauth251-receipt.v1','execution-plan.json':'ouf.installation-binding-native-plan.v1',
 'review.json':'ouf.semantic-scoped-infrastructure-review.v1','owner-result.json':'ouf.installation-binding-owner-result.v1',
 'update-result.json':'ouf.installation-binding-projection-routes-result.v1'}
def publish_json(context,name,value):
 context=Path(context);require(context.parent==authority.evidence.PARENT and re.fullmatch('installation-binding-apply-execution-[A-Za-z0-9_-]{8,64}',context.name)
  and name in SCHEMAS and value.get('schema')==SCHEMAS[name],'EXACT_PRIVATE_BINDING_DOCUMENT_REQUIRED')
 raw=encoded(value);require(0<len(raw)<=8388608,'BOUNDED_BINDING_DOCUMENT_REQUIRED');baseline.write_new(context/name,raw)
 require(baseline.read(context/name)==raw,'BINDING_PRIVATE_DOCUMENT_READBACK_REQUIRED')
def alarm(seconds):
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_BINDING_PHASE_DEADLINE')));signal.alarm(seconds)
def common(owner,result,human,binding_plan,projection):
 expected={'onboarding':result['finalEvidence']['onboarding']['runtimeBinding'],**owner['unchangedApplications'],
  'gateway':owner['gateway']['transport']['runtimeBinding']}
 require(set(expected)=={'onboarding','mcp','udp','ingestion','gateway'},'EXACT_FIVE_CURRENT_GENERATIONS_REQUIRED')
 return {'schema':'ouf.installation-binding-native-plan.v1','bindingPlan':binding_plan,'humanBinding':human.current(),
  'engine':copy.deepcopy(owner['engine']),'gateway':{**copy.deepcopy(owner['gateway']),'beforeRoutes':copy.deepcopy(owner['gateway']['afterRoutes'])},
  'currentApplications':expected,'retainedMcpMetadata':copy.deepcopy(owner['retainedMcpMetadata']),
  'projectionBinding':copy.deepcopy(owner['gateway']['projectionBinding']),'sourceProjection':copy.deepcopy(projection),
  'maximumExecutionSeconds':210,'maximumEffectAttemptsPerStage':1,**{k:False for k in FORBIDDEN}}
def current_inputs(owner,result):
 engine=Engine(owner['engine']['socketPath'],tuple(owner['engine']['socketBinding']));actual={}
 pins={'onboarding':result['finalEvidence']['onboarding']['runtimeBinding'],**owner['unchangedApplications'],
  'gateway':owner['gateway']['transport']['runtimeBinding']}
 for name,pin in pins.items():
  status,row=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json');require(status==200,'CURRENT_CONTAINER_INSPECT_REQUIRED')
  require(baseline_runtime(row,name,{'gateway':owner['gateway']})==pin,'CURRENT_OWNER_OR_INDEPENDENT_GENERATION_DRIFT');actual[name]=row
  if name=='onboarding':require(row['Config'].get('Labels',{}).get('org.opencontainers.image.revision')==result['sourceCommit'],'EXACT_DEPLOYED_ATOMIC_OWNER_SOURCE_REQUIRED')
 admin=NamespaceAdmin(engine,owner['gateway']['transport']);routes=admin.routes()
 require(routes==owner['gateway']['afterRoutes']and len(routes)==82 and digest(routes)==discovery.ROUTES,'EXACT_RETAINED82_ROUTES_REQUIRED')
 projection=json.loads(private_config(owner['gateway']['projectionBinding']['path'],owner['gateway']['projectionBinding'])[0])
 for binding in owner['retainedMcpMetadata']:metadata_file(binding)
 alias,addresses=discovery.owner_alias(actual['gateway'],actual['ingestion'])
 transport=owner['gateway']['transport']
 with discovery.gateway_namespace(pins['gateway']['pid'],transport['networkNamespace']):answer=discovery.query_dns(alias,'127.0.0.11')
 require(answer['status']=='RESOLVED'and answer['addresses']and answer['addresses']<=addresses,'CURRENT_INGESTION_ALIAS_DNS_REQUIRED')
 return projection,alias

def approved_action(kind,plan,closure,human,context,summary,cancelled):
 publish_json(context,'execution-plan.json',plan);selected=scope(plan)
 review=authority.compile_action_review(kind,closure,{scope_key(kind):selected},human.current(),context,
  {'predecessorHistoryHash':baseline.RESULT_HASH,'predecessorIncidentRef':plan['logicalRef']},210)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 alarm(90);decision=authority.terminal_consent(review,summary+'\nTecniche8/8;funzionali4/6. Nessun replay dopo STOP/interruzione.\nPiano privato: '+str(context/'execution-plan.json'))
 require(human._read()['accessExpiresAt']>time.time()+120,'CURRENT_HUMAN_TOKEN_MARGIN_REQUIRED_NO_REFRESH')
 action=authority.issue_action(review,decision,human)
 def clock():require(not cancelled.is_set(),'NATIVE_BINDING_CANCELLED');return time.time()
 action.authority.clock=clock;alarm(210);return action

def main(original,sources,closure,case,context,read,emit):
 context=Path(context);authority.closure_valid(closure)
 claim=read(case['preparationClaimBinding']['path'],expected=case['preparationClaimBinding']['sha256'])
 require(claim['context']==str(context)and claim['completedOwnerResultHash']==baseline.RESULT_HASH and claim['priorOAuthAttempts']==251
  and claim['automaticReplayAllowed']is False and claim['budgetReset']is False,'EXACT_BINDING_APPLY_PREPARATION_CLAIM_REQUIRED')
 _,_,_,owner,result,prior,retained_original,binding=baseline.history()
 require(original==retained_original and binding==case['humanBinding'],'COMPLETED_OWNER_CURRENT_SESSION_REQUIRED')
 emit('OUF_BINDING_PHASE=FRESH_HUMAN251_EXPLICIT_CONSENT');alarm(600)
 human=login.authenticate(original['authorization']['plan']['selection'],binding,context,closure,publish_json,emit,case)
 emit('OUF_BINDING_PHASE=CURRENT_OWNER_ETAG_AND_EXACT_CANDIDATE');alarm(90)
 projection,alias=current_inputs(owner,result);require(prior['addedBindings'][old_planning.KEY]==alias,'RETAINED_CANDIDATE_ALIAS_DRIFT')
 transport=baseline.ThreeReads(human.selection,human,prior,OwnerTransport,NoRedirect)
 first,etag=transport.next();active=baseline.strong_active(first,etag);revision,_=transport.next();last,etag=transport.next()
 binding_plan=baseline.compile_cas(active,revision,baseline.strong_active(last,etag),projection,prior,
  {'completedOwnerResultHash':baseline.RESULT_HASH,'humanBinding':human.current(),'currentDnsOwnerAliasProven':True},old_planning.compile_plan)
 plan={**common(owner,result,human,binding_plan,projection),'kind':'INSTALLATION_BINDING_APPLY','authorityDirectory':str(context)}
 plan['logicalRef']=digest({'kind':plan['kind'],'installationId':active['installationId'],'expectedActive':active,'candidatePayloadChecksum':binding_plan['candidatePayloadChecksum']})
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 try:
  emit('OUF_BINDING_PHASE=NATIVE_OWNER_BINDING_APPROVO_REQUIRED')
  action=approved_action(plan['kind'],plan,closure,human,context,
   'Attivo il SOLO binding installation networking.serviceBindings[ouf-ingestion-runtime] nel backend owner nativo.\n'
   'Creo UNA revisione immutabile, valido ambiente, attivo con If-Match ETag revisione/checksum/generazione e conservo export autorevole.\n'
   'Nessun altro campo payload cambia. Il backend verifica HUMAN/capability/proof e precondizione atomica.\n'
   'Massimo3POST owner e1export auditato, un tentativo per effetto,210secondi.\n'
   'NON pubblico ancora file attivi o rotte: quel delta richiedera un APPROVO separato dopo export verificato.\n'
   'Nessuna migrazione/SQL manuale, IAM/grant, restart/container, metadati MCP, fonte o job.',cancelled)
  http=OwnerHttp(human.selection,human,active['installationId'],'ouf-binding-'+plan['logicalRef'][:32])
  ports=Ports(action,plan,human,http,context);update=FiniteUpdate(action,plan,ports,Journal(context));update.initialize();journal=update.run()
  activated=next(e['evidence']['active']for e in journal['effects']if e['stage']=='ACTIVATE_EXPECTED')
  exported=next(e['evidence']['projectionBinding']for e in journal['effects']if e['stage']=='EXPORT_ACTIVE')
  owner_result={'schema':'ouf.installation-binding-owner-result.v1','contextPath':str(context),'complete':True,'ownerInstallationBindingActivated':True,
   'active':activated,'projectionBinding':exported,'ownerPosts':http.posts,'projectionExports':http.exports,'gatewayWrites':0,'activeProjectionWrites':0,
   'oauthAttemptsAfter':human._read()['attempts'],'maximumCumulativeOAuthAttempts':256,'humanWindowExpiresAt':human.expires_at,
   'sourceActivated':False,'automaticReplayAllowed':False,'budgetReset':False,'notReleaseAcceptance':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
  publish_json(context,'owner-result.json',owner_result);emit('OUF_INSTALLATION_BINDING_OWNER_RESULT='+encoded(owner_result).decode())
  emit('OUF_BINDING_PHASE=COMPILE_AUTHORITATIVE_PROJECTION_AND_TWO_ROUTE_HOST_REPLACEMENTS');alarm(90)
  projected=baseline.parsed(exported['path'],exported['sha256']);bundle=read(case['gatewayCompilerBinding']['path'],expected=case['gatewayCompilerBinding']['sha256'])
  before=copy.deepcopy(plan['gateway']['beforeRoutes']);retained={k:v for k,v in before.items()if k not in('mcp-ingestion-status','mcp-ingestion-history')}
  render_root=context/'gateway-render';render_root.mkdir(mode=0o700)
  for name in('old','new'):(render_root/name).mkdir(mode=0o700)
  previous=compiler.compile_routes(bundle,projection,retained,render_root/'old');require(previous['afterRoutes']==before,'AUTHENTICATED_OLD_ROUTE_COMPILER_MUST_REPRODUCE_CURRENT82')
  rendered=compiler.compile_routes(bundle,projected,retained,render_root/'new')
  second=Path(tempfile.mkdtemp(prefix='installation-binding-apply-execution-',dir=context.parent));os.chmod(second,0o700)
  next_binding={**copy.deepcopy(binding_plan),'expectedActive':{k:activated[k]for k in('installationId','revision','checksum','generation')},'expectedActiveETag':activated['etag']}
  following={**common(owner,result,human,next_binding,projection),'kind':'INSTALLATION_PROJECTION_ROUTE_APPLY','authorityDirectory':str(second),
   'exportedProjectionBinding':exported,'projectionHash':exported['sha256'],
   'ownerActivationBinding':{'path':str(context/'owner-result.json'),'sha256':digest(owner_result)}}
  following['gateway']={**following['gateway'],'beforeRoutes':before,'afterRoutes':rendered['afterRoutes']}
  following['logicalRef']=digest({'kind':following['kind'],'active':activated,'oldProjectionHash':following['projectionBinding']['sha256'],'afterRouteMapHash':digest(rendered['afterRoutes'])})
  emit('OUF_BINDING_CONTEXT='+str(second));emit('OUF_BINDING_PHASE=NATIVE_PROJECTION_AND_TWO_ROUTES_APPROVO_REQUIRED')
  action=approved_action(following['kind'],following,closure,human,second,
   'Pubblico la proiezione AUTOREVOLE appena esportata dall owner, dopo verifica ACTIVE corrente.\n'
   'CAS sul file attivo precedente, lock publisher locale senza rete, rename atomico e readback; backup originale conservato.\n'
   'Sostituisco SOLO l host upstream delle2rotte Ingestion status/history dal binding approvato,80rotte conservate.\n'
   'Percorsi, porte, metodi, OIDC, scope, delegazione HUMAN firmata e schema restano identici.\n'
   'Massimo1pubblicazione proiezione e2PUT Gateway, un tentativo per effetto,210secondi.\n'
   'Nessuna ulteriore mutazione owner, migrazione/SQL, IAM/grant, container, metadati MCP, fonte o acquisizione.\n'
   'Un esito parziale/ambiguo resta recintato: nessun rollback o replay automatico.',cancelled)
  baseline.write_new(second/'source-projection.json',private_config(following['projectionBinding']['path'],following['projectionBinding'])[0])
  http2=OwnerHttp(human.selection,human,activated['installationId'],'ouf-projection-'+following['logicalRef'][:32])
  ports2=Ports(action,following,human,http2,second);update2=FiniteUpdate(action,following,ports2,Journal(second));update2.initialize();done=update2.run()
  report={'schema':'ouf.installation-binding-projection-routes-result.v1','status':'OWNER_BINDING_PROJECTION_AND_TWO_ROUTES_COMPLETE',
   'contextPath':str(second),'ownerContextPath':str(context),'complete':True,'activeRevision':activated['revision'],'activeGeneration':activated['generation'],
   'candidatePayloadChecksum':binding_plan['candidatePayloadChecksum'],'projectionHash':exported['sha256'],'routeMapHash':digest(rendered['afterRoutes']),
   'retainedOtherRoutes':80,'routeCount':82,'ownerPosts':http.posts,'projectionExports':http.exports,'activeProjectionWrites':1,'gatewayWrites':2,
   'oauthAttemptsAfter':human._read()['attempts'],'maximumCumulativeOAuthAttempts':256,'humanWindowExpiresAt':human.expires_at,
   'humanSourceChanged':False,'budgetReset':False,'automaticReplayAllowed':False,'databaseMigrationsPerformed':0,'directDatabaseCalls':0,
   'containerLifecycleOperations':0,'grantChanges':0,'publicMetadataChanged':False,'sourceActivated':False,'jobsRetried':0,
   'runtimeAuthorityIssued':True,'nativeScopesCompleted':2,'installationBindingApplied':True,'activeProjectionPublished':True,'nativeProfilePublished':False,'freshChatClientReadProven':False,'notReleaseAcceptance':True,
   'completedTechnicalPhases':8,'functionalMilestonesProven':4}
  publish_json(second,'update-result.json',report);signal.alarm(0);emit('OUF_INSTALLATION_BINDING_APPLY_RESULT='+encoded(report).decode())
 finally:
  for sig,handler in handlers.items():signal.signal(sig,handler)
