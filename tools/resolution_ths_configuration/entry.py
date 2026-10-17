"""Prepare same-image browser configuration and routes before fresh HUMAN review."""
import copy,json,os,signal,time,threading
from pathlib import Path
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.semantic_mcp_update.entry import publish_json
from tools.semantic_mcp_update import session
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.onboarding_audit_update.native import runtime
from tools.resolution_ths_configuration import plan as compiler,authority
from tools.resolution_ths_configuration.owner import require,digest,encoded,scope,ReadinessUpdate,UpdatePaused
from tools.resolution_ths_configuration.native import NativePorts

def main(prepared,sources,closure,case,context,read,ns,emit):
 previous=Path(case['rolloutContext']);prior=read(previous/'review.json',8388608,case['rolloutReviewSha256']);old_plan=read(previous/'execution-plan.json',8388608);record=read(previous/'recovery.json',65536)
 old_scope=prior['scopes']['onboardingAuditUpdate']
 require(prior['kind']=='ONBOARDING_AUDIT_FIX'and digest(old_plan)==old_scope['planHash']and record['scopeHash']==digest(old_scope)and record['version']==29 and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(old_scope['stages'])==11 and all(e['state']=='APPLIED'for e in record['effects']),'EXACT_COMPLETED_COMPATIBILITY_ROLLOUT_REQUIRED')
 failed=Path(case['failedRouteContext'])
 require(failed.parent==context.parent and not any(os.path.lexists(failed/name)for name in('authority.json','decision.json','human.json','issuance.claim.json','review.json','recovery.json')),'EXACT_PRE_AUTHORITY_ROUTE_STOP_REQUIRED')
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 pins={'onboarding':record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'],'ingestion':old_plan['unchangedIngestionRuntimeBinding']};actuals={}
 for name,pin in pins.items():
  status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'CURRENT_APPLICATION_GENERATION_CHANGED');actuals[name]=actual
 origin=prepared['authorization']['plan']['selection']['origin']
 environment,metadata=compiler.patch_environment(actuals['onboarding'],origin,case['thsConfigSha256'])
 transport=copy.deepcopy(old_plan['gateway']['transport']);admin=NamespaceAdmin(engine,transport);routes=admin.routes()
 require(routes==old_plan['gateway']['beforeRoutes']and digest(routes)==case['retainedRouteMapSha256'],'COMPLETE_RETAINED_GATEWAY_ROUTES_REQUIRED')
 additions=compiler.compile_routes(routes);row=compiler.replacement(old_plan,actuals['onboarding'],environment,digest(case))
 # Already-installed image: validate native config against the retained byte audit.
 from image_custody import loaded,runtime_image_id
 require(runtime_image_id(row['imageAudit'])==row['request']['Image']==pins['onboarding']['imageId'],'EXACT_SAME_RETAINED_IMAGE_REQUIRED')
 status,image=engine.request('GET','/v1.44/images/'+row['request']['Image']+'/json');require(status==200,'EXISTING_IMAGE_REQUIRED');loaded(row['imageAudit'],image)
 auth_plan=prepared['authorization']['plan'];catalogue=auth_plan['baseline']['oauth']['scopes']
 require(set(compiler.REQUIRED)<=set(auth_plan['requiredScopes']['ths'])and all(cap in catalogue and catalogue[cap].get('protocol')=='openid-connect'for cap in compiler.REQUIRED),'RETAINED_RESOLUTION_SCOPE_REGISTRATION_REQUIRED')
 hb=prior['authenticatedHuman'];human=HumanSession(prepared['authorization']['plan']['selection'],Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
 require(human._read()['binding']==hb,'EXACT_RETAINED_HUMAN_BINDING_REQUIRED')
 private={'schema':'ouf.resolution-ths-configuration-private-review.v1','predecessorReviewHash':case['rolloutReviewSha256'],'beforeApplicationPin':pins['onboarding'],'configurationMetadata':metadata,'sameNativeImageId':row['request']['Image'],'routeMapHash':digest(routes),'readyForExecution':False,'runtimeAuthorityIssued':False}
 publish_json(context,'candidate-review.json',private)
 plan={'schema':'ouf.resolution-ths-configuration-plan.v1','authorityDirectory':str(context),'engine':copy.deepcopy(prepared['engine']),
  'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(private)},
  'gateway':{'transport':transport,'projectionBinding':copy.deepcopy(old_plan['gateway']['projectionBinding'])},
  'beforeRoutes':routes,'routes':additions,'replacements':{'onboarding':row},'unchangedIngestionRuntimeBinding':pins['ingestion'],
  'configuration':metadata,'reviewedOrigin':origin,'sameImageOnly':True,'containerLifecycleAllowed':True,
  'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':3,
  **{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed')}}
 plan['logicalUpdateRef']=digest({'beforeRoutes':digest(routes),'routes':additions,'replacement':row})
 scope(plan);publish_json(context,'prepared-plan.json',plan)
 emit('OUF_RESOLUTION_CONFIGURATION_PREPARED='+encoded({'contextPath':str(context),'addedBrowserScopes':metadata['addedScopes'],'preservedBrowserScopes':metadata['preservedScopeCount'],'sameNativeImageId':row['request']['Image'],'newRouteCount':3,'newPolicyWorkerStarted':False,'runtimeAuthorityIssued':False,'iamBindingsLiveProven':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode())
 signal.alarm(0)
 if time.time()>=human.expires_at:
  login_review=session.expired_login_review(human,{'configurationPlanHash':digest(plan),'sourceClosureHash':digest(closure)})
  publish_json(context,'login-review.json',login_review)
  consent=authority.terminal_consent(login_review,'Nuova finestra HUMAN per la revisione della configurazione Resolution. Nessun reset OAuth.\nTentativi conservati: '+str(login_review['priorOAuthAttempts'])+'; residui: '+str(login_review['maximumRemainingOAuthAttempts'])+'.\nSeguono browser e APPROVO separato: stessa immagine Onboarding e tre route. Nessun worker policy.',login=True)
  human=session.open_approved_login(human,login_review,consent);human.login(emit=emit)
 else:human.refresh_if_due()
 hb=human.current();plan['humanBinding']=hb;scope(plan);publish_json(context,'execution-plan.json',plan)
 seconds=min(900,human.expires_at-int(time.time())-10);require(seconds>=300,'HUMAN_WINDOW_TOO_SHORT_FOR_CONFIGURATION_UPDATE')
 review=authority.compile_action_review('RESOLUTION_THS_CONFIGURATION',closure,{'resolutionConfigurationUpdate':scope(plan)},hb,context,{'predecessorHistoryHash':case['rolloutReviewSha256'],'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 decision=authority.terminal_consent(review,
  'Configurazione Resolution: stesso binario Onboarding, stesso storage, rete, IP e MAC. Vecchio container fermato e conservato. Tecniche8/8; funzionali2/6.\n'
  'Modifico solo SPRING_APPLICATION_JSON: THS abilitato esplicitamente e aggiungo resolution.issue.read e resolution.match.approve agli scope browser esistenti.\n'
  'Poi tre sole nuove route: lettura casi UDP, conferma HUMAN e pagina browser per ultima.\n'
  'Nessuna modifica IAM/grant/database, decisione di identita o proposta semantica. Nessun nuovo worker policy o grant del worker.\n'
  'Firme infrastrutturali e sessione HUMAN corrente autorizzano solo questo aggiornamento. Le autorizzazioni owner e la policy attiva restano obbligatorie per le successive decisioni THS.\n'
  'Un tentativo per effetto, massimo900secondi. Esito ambiguo: riconciliazione senza replay o rollback automatico.\nRevisione privata: '+str(context/'review.json'))
 require(admin.routes()==routes,'GATEWAY_CHANGED_BEFORE_ISSUANCE');action=authority.issue_action(review,decision,human)
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():require(not cancelled.is_set(),'CONFIGURATION_UPDATE_CANCELLED');return time.time()
 action.authority.clock=current_time
 # The existing finite HUMAN refresh owner keeps the same session, expiry and cumulative budget.
 human.start_refresh(cancelled,emit=emit)
 try:
  ports=NativePorts(action,engine,plan,human);update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  while True:
   try:
    result=update.run();emit('OUF_RESOLUTION_CONFIGURATION_RESULT='+encoded({**result,'contextPath':str(context),'newRouteCount':3,'sameImageOnly':True,'newPolicyWorkerStarted':False,'identityDecisionsPerformed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode());break
   except UpdatePaused as error:
    require(str(error)=='READINESS_RETRY_WAIT','CONFIGURATION_UPDATE_RECONCILIATION_REQUIRED')
    record=update.record();emit('OUF_RESOLUTION_CONFIGURATION_WAIT='+encoded({'stage':record['effects'][-1]['stage'],'attempts':record['readinessAttempts'],'nextReadAt':record['nextReadAt']}).decode());cancelled.wait(min(5,max(0,record['nextReadAt']-time.time())))
 finally:
  cancelled.set()
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
