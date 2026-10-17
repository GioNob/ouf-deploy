"""Prepare a finite UDP then Onboarding update without applying identity decisions."""
import copy,signal,threading,time
from pathlib import Path
from engine_creation import Engine
from image_custody import loaded,runtime_image_id
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused
from tools.resolution_comparison_update.preparation import publish_json
from tools.semantic_mcp_update import session
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.resolution_comparison_update import authority,preparation,plan as compiler
from tools.resolution_comparison_update.owner import require,digest,encoded,scope,ReadinessUpdate,UpdatePaused
from tools.resolution_comparison_update.native import NativePorts,runtime

def predecessor(case,read):
 context=Path(case['rolloutContext']);review=read(context/'review.json',8388608);plan=read(context/'execution-plan.json',8388608);record=read(context/'recovery.json',131072);issued=read(context/'authority.json',131072)
 selected=review['scopes']['resolutionComparisonUpdate']
 require(review['kind']=='RESOLUTION_COMPARISON_UPDATE'and review['authorityDirectory']==str(context)
  and review['sourceClosure']['declaration']['sourceCommit']==case['rolloutSourceCommit']
  and digest(review['sourceClosure'])==review['sourceClosureHash']==issued['sourceClosureHash']
  and digest(issued)==record['authorityHash']and issued['resolutionComparisonUpdate']==selected
  and digest(plan)==selected['planHash']and record['scopeHash']==digest(selected)
  and record['version']==51 and record['incidentState']=='RECOVERED'
  and record['nextStage']==len(record['effects'])==len(selected['stages'])==20
  and [e['stage']for e in record['effects']]==selected['stages']and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':selected['planHash'],'stage':e['stage']})for e in record['effects']),
  'EXACT_COMPLETED_RESOLUTION_COMPARISON_UPDATE_REQUIRED')
 return review,plan,record

def authenticate(human,plan,closure,previous,context,emit):
 if human._read().get('state')=='BLOCKED':
  login=session.blocked_refresh_login_review(human,{'comparisonUpdatePlanHash':digest(plan),'sourceClosureHash':digest(closure),'completedPredecessorHash':digest(previous)})
  publish_json(context,'login-review.json',login)
  consent=authority.terminal_consent(login,'Nuovo login HUMAN per il aggiornamento del confronto Resolution dopo un refresh rifiutato. Il vecchio journal resta bloccato; nessun refresh viene ripetuto.\nOAuth conservati: '+str(login['priorOAuthAttempts'])+'; residui: '+str(login['maximumRemainingOAuthAttempts'])+'. Nessun worker policy. Input gia preparati.',login=True)
  human=session.open_approved_login(human,login,consent);human.login(emit=emit)
 elif time.time()>=human.expires_at:
  login=session.expired_login_review(human,{'comparisonUpdatePlanHash':digest(plan),'sourceClosureHash':digest(closure)})
  publish_json(context,'login-review.json',login)
  consent=authority.terminal_consent(login,'Nuova finestra HUMAN per aggiornare UDP e Onboarding. OAuth conservati: '+str(login['priorOAuthAttempts'])+'; residui: '+str(login['maximumRemainingOAuthAttempts'])+'.\nNessun nuovo worker policy. Seguono browser e APPROVO separato; immagini e input sono gia preparati.',login=True)
  human=session.open_approved_login(human,login,consent);human.login(emit=emit)
 else:
  try:human.refresh_if_due()
  except HumanSessionPaused as error:
   if error.reason!='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN':raise
   return authenticate(human,plan,closure,previous,context,emit)
 return human

def main(prepared,sources,closure,case,context,archive,read,ns,emit):
 authority.closure_valid(closure);context=Path(context)
 previous,old_plan,record=predecessor(case,read)
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 pins={**{name:record['effects'][-1]['evidence']['applications'][name]['runtimeBinding']for name in('udp','onboarding')},**old_plan['unchangedApplications']}
 require(set(pins)=={'udp','onboarding','ingestion'},'RETAINED_APPLICATION_GENERATIONS_REQUIRED')
 actuals={}
 for name,pin in pins.items():
  status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'RETAINED_APPLICATION_GENERATION_CHANGED');actuals[name]=actual
 transport=copy.deepcopy(old_plan['gateway']['transport']);admin=NamespaceAdmin(engine,transport);routes=admin.routes()
 require(routes==old_plan['gateway']['beforeRoutes']and digest(routes)==record['effects'][-1]['evidence']['routeMapHash'],'RETAINED_RESOLUTION_ROUTES_CHANGED')
 retained=old_plan['replacements'];require(set(retained)=={'udp','onboarding'},'EXACT_RETAINED_REPLACEMENTS_REQUIRED')
 for name,row in retained.items():
  actual=actuals[name];require(actual['Image']==runtime_image_id(row['imageAudit']),'EXACT_RETAINED_APPLICATION_IMAGE_REQUIRED')
  status,image=engine.request('GET','/v1.44/images/'+actual['Image']+'/json');require(status==200,'RETAINED_IMAGE_UNAVAILABLE');loaded(row['imageAudit'],image)
 emit('OUF_RESOLUTION_COMPARISON_PHASE=CANDIDATE_BYTE_CUSTODY technical=8/8 functional=2/6')
 following_route=compiler.confirmation_route(routes[case['retainedConfirmRouteId']])
 candidates=preparation.candidate(archive,case,context,prepared['engine'],ns)
 replacements={name:compiler.replacement({'module':name,'name':row['name'],'creationRequest':row['request']},actuals[name],candidates[name],case,name)for name,row in retained.items()}
 private={'schema':'ouf.resolution-comparison-private-review.v1','predecessorReviewHash':digest(previous),'beforeApplications':pins,'candidates':candidates,'gatewayRouteMapHash':digest(routes),'migrationFilesUnchanged':True,'readyForExecution':False,'runtimeAuthorityIssued':False}
 publish_json(context,'candidate-review.json',private)
 plan={'schema':'ouf.resolution-review-refinement-native-update-plan.v1','authorityDirectory':str(context),'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(private)},'engine':copy.deepcopy(prepared['engine']),'programs':{'docker':closure['executables']['docker']},'replacements':replacements,'unchangedApplications':{'ingestion':pins['ingestion']},'gateway':{'transport':transport,'beforeRoutes':routes,'route':following_route,'afterRoutes':{**routes,following_route['id']:following_route},'projectionBinding':copy.deepcopy(old_plan['gateway']['projectionBinding'])},'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':1,**{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed')}}
 plan['logicalUpdateRef']=digest({'retiredContainerIds':sorted(r['oldRuntimeBinding']['containerId']for r in replacements.values()),'routeId':plan['gateway']['route']['id']});scope(plan)
 publish_json(context,'prepared-plan.json',plan)
 emit('OUF_RESOLUTION_COMPARISON_PREPARED='+encoded({'contextPath':str(context),'newImageIds':{name:row['request']['Image']for name,row in replacements.items()},'migrationFilesUnchanged':True,'newPolicyWorkerStarted':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode())
 hb=previous['authenticatedHuman'];human=HumanSession(prepared['authorization']['plan']['selection'],Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
 require(human._read()['binding']==hb,'EXACT_RETAINED_HUMAN_BINDING_REQUIRED');signal.alarm(0)
 human=authenticate(human,plan,closure,previous,context,emit)
 hb=human.current();plan['humanBinding']=hb;scope(plan);publish_json(context,'execution-plan.json',plan)
 seconds=min(900,human.expires_at-int(time.time())-10);require(seconds>=300,'HUMAN_WINDOW_TOO_SHORT_FOR_COMPARISON_UPDATE')
 review=authority.compile_action_review('RESOLUTION_COMPARISON_UPDATE',closure,{'resolutionComparisonUpdate':scope(plan)},hb,context,{'predecessorHistoryHash':digest(previous),'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 decision=authority.terminal_consent(review,'Correzione HTTP400, nota facoltativa e supporto a regole di distinzione configurabili. Tecniche8/8; funzionali2/6.\nDue immagini verificate: prima UDP, poi Onboarding; vecchi container fermati e conservati. Stessi mount, ambiente, rete, IP e MAC.\nIngestion invariato. Una sola route Gateway: sostituzione dello schema body di conferma ereditato dal preflight. Autenticazione, scope, upstream e altre route invariati. La policy di identita attiva resta invariata; le nuove regole richiedono una configurazione separata. Nessuna migrazione DB, modifica grant, decisione di identita o proposta semantica. Nessun nuovo worker policy.\nUn tentativo per effetto, massimo900 secondi; esito ambiguo richiede riconciliazione. Dopo il risultato si verifica la pagina prima di confermare identita.\nRevisione privata: '+str(context/'review.json'))
 require(admin.routes()==routes,'GATEWAY_CHANGED_BEFORE_ISSUANCE');action=authority.issue_action(review,decision,human)
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():require(not cancelled.is_set(),'COMPARISON_UPDATE_CANCELLED');return time.time()
 action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
 try:
  ports=NativePorts(action,engine,plan,human);update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  while True:
   try:
    result=update.run();emit('OUF_RESOLUTION_COMPARISON_UPDATE_RESULT='+encoded({**result,'contextPath':str(context),'maximumGatewayWrites':1,'newPolicyWorkerStarted':False,'identityDecisionsPerformed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode());break
   except UpdatePaused as error:
    require(str(error)=='READINESS_RETRY_WAIT','COMPARISON_UPDATE_RECONCILIATION_REQUIRED')
    row=update.record();emit('OUF_RESOLUTION_COMPARISON_UPDATE_WAIT='+encoded({'stage':row['effects'][-1]['stage'],'attempts':row['readinessAttempts'],'nextReadAt':row['nextReadAt']}).decode());cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
 finally:
  cancelled.set()
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
