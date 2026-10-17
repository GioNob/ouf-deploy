"""Prepare all bytes and retained pins before finite HUMAN infrastructure consent."""
import copy,json,os,signal,threading,time
from pathlib import Path
from engine_creation import Engine
from image_custody import loaded,runtime_image_id
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.semantic_mcp_update.entry import publish_json
from tools.semantic_mcp_update import session
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.udp_resolution_update import authority,preparation,plan as compiler
from tools.udp_resolution_update.owner import require,digest,encoded,scope,ReadinessUpdate,UpdatePaused
from tools.udp_resolution_update.native import NativePorts,runtime

def predecessor(case,read):
 context=Path(case['rolloutContext']);review=read(context/'review.json',8388608);plan=read(context/'execution-plan.json',8388608);record=read(context/'recovery.json',131072)
 selected=review['scopes']['resolutionConfigurationUpdate']
 require(review['kind']=='RESOLUTION_THS_CONFIGURATION'and review['authorityDirectory']==str(context)
  and review['sourceClosure']['declaration']['sourceCommit']==case['rolloutSourceCommit']
  and digest(plan)==selected['planHash']and record['scopeHash']==digest(selected)
  and record['version']==37 and record['incidentState']=='RECOVERED'
  and record['nextStage']==len(record['effects'])==len(selected['stages'])==13
  and [e['stage']for e in record['effects']]==selected['stages']and all(e['state']=='APPLIED'for e in record['effects']),
  'EXACT_COMPLETED_RESOLUTION_CONFIGURATION_REQUIRED')
 return review,plan,record

def main(prepared,sources,closure,case,context,archive,read,ns,emit):
 authority.closure_valid(closure);context=Path(context)
 previous,old_plan,record=predecessor(case,read)
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 pins={'onboarding':record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'],'ingestion':old_plan['unchangedIngestionRuntimeBinding']}
 for name,pin in pins.items():
  status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'RETAINED_APPLICATION_GENERATION_CHANGED')
 transport=copy.deepcopy(old_plan['gateway']['transport']);admin=NamespaceAdmin(engine,transport);routes=admin.routes()
 expected=copy.deepcopy(old_plan['beforeRoutes']);expected.update(old_plan['routes'])
 require(routes==expected and digest(routes)==record['effects'][-1]['evidence']['routeMapHash'],'RETAINED_RESOLUTION_ROUTES_CHANGED')
 saved=[r for r in prepared['cohortPlan']['replacements']if r['module']=='udp'];require(len(saved)==1,'ONE_RETAINED_UDP_CREATION_REQUIRED');saved=saved[0]
 audits=[r['audit']for r in prepared['imagePlan']['images']if r['module']=='udp'];require(len(audits)==1,'RETAINED_UDP_IMAGE_AUDIT_REQUIRED')
 status,actual=engine.request('GET','/v1.44/containers/'+saved['name']+'/json')
 require(status==200 and actual['Image']==runtime_image_id(audits[0]),'EXACT_RETAINED_UDP_IMAGE_REQUIRED')
 status,image=engine.request('GET','/v1.44/images/'+actual['Image']+'/json');require(status==200,'RETAINED_UDP_IMAGE_UNAVAILABLE');loaded(audits[0],image)
 emit('OUF_UDP_RESOLUTION_PHASE=CANDIDATE_BYTE_CUSTODY technical=8/8 functional=2/6')
 candidate=preparation.candidate(archive,case,context,prepared['engine'],ns)
 row=compiler.replacement(saved,actual,candidate,case)
 private={'schema':'ouf.udp-resolution-private-review.v1','predecessorReviewHash':digest(previous),'beforeUdpPin':row['oldRuntimeBinding'],'unchangedApplications':pins,'candidateMetadata':candidate['candidateMetadata'],'imageAudit':candidate['imageAudit'],'imageArchive':candidate['imageArchive'],'gatewayRouteMapHash':digest(routes),'migrationFilesUnchanged':True,'readyForExecution':False,'runtimeAuthorityIssued':False}
 publish_json(context,'candidate-review.json',private)
 plan={'schema':'ouf.udp-resolution-get-native-update-plan.v1','authorityDirectory':str(context),'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(private)},'engine':copy.deepcopy(prepared['engine']),'programs':{'docker':closure['executables']['docker']},'replacements':{'udp':row},'unchangedApplications':pins,'gateway':{'transport':transport,'beforeRoutes':routes,'route':copy.deepcopy(routes[case['retainedReadRouteId']]),'projectionBinding':copy.deepcopy(old_plan['gateway']['projectionBinding'])},'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,**{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed')}}
 plan['logicalUpdateRef']=digest({'retiredContainerIds':[row['oldRuntimeBinding']['containerId']],'routeId':plan['gateway']['route']['id']});scope(plan)
 publish_json(context,'prepared-plan.json',plan)
 emit('OUF_UDP_RESOLUTION_PREPARED='+encoded({'contextPath':str(context),'newImageId':row['request']['Image'],'migrationFilesUnchanged':True,'newPolicyWorkerStarted':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode())
 hb=previous['authenticatedHuman'];human=HumanSession(prepared['authorization']['plan']['selection'],Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
 require(human._read()['binding']==hb,'EXACT_RETAINED_HUMAN_BINDING_REQUIRED');signal.alarm(0)
 if human._read().get('state')=='BLOCKED':
  login=session.blocked_refresh_login_review(human,{'udpUpdatePlanHash':digest(plan),'sourceClosureHash':digest(closure),'completedPredecessorHash':digest(previous)})
  publish_json(context,'login-review.json',login)
  consent=authority.terminal_consent(login,'Nuovo login HUMAN per il solo aggiornamento UDP dopo un refresh rifiutato. Il vecchio journal resta bloccato; nessun refresh viene ripetuto.\nOAuth conservati: '+str(login['priorOAuthAttempts'])+'; residui: '+str(login['maximumRemainingOAuthAttempts'])+'. Nessun worker policy. Input gia preparati.',login=True)
  human=session.open_approved_login(human,login,consent);human.login(emit=emit)
 elif time.time()>=human.expires_at:
  login=session.expired_login_review(human,{'udpUpdatePlanHash':digest(plan),'sourceClosureHash':digest(closure)})
  publish_json(context,'login-review.json',login)
  consent=authority.terminal_consent(login,'Nuova finestra HUMAN per aggiornare solo UDP. OAuth conservati: '+str(login['priorOAuthAttempts'])+'; residui: '+str(login['maximumRemainingOAuthAttempts'])+'.\nNessun nuovo worker policy. Seguono browser e APPROVO separato; immagini e input sono gia preparati.',login=True)
  human=session.open_approved_login(human,login,consent);human.login(emit=emit)
 else:human.refresh_if_due()
 hb=human.current();plan['humanBinding']=hb;scope(plan);publish_json(context,'execution-plan.json',plan)
 seconds=min(900,human.expires_at-int(time.time())-10);require(seconds>=300,'HUMAN_WINDOW_TOO_SHORT_FOR_UDP_UPDATE')
 review=authority.compile_action_review('UDP_RESOLUTION_UPDATE',closure,{'udpResolutionUpdate':scope(plan)},hb,context,{'predecessorHistoryHash':digest(previous),'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
 review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
 decision=authority.terminal_consent(review,'Correzione del solo UDP: contesto di autorizzazione del pacchetto Resolution. Tecniche8/8; funzionali2/6.\nUna nuova immagine gia verificata; vecchio UDP fermato e conservato. Stessi mount, ambiente, rete, IP e MAC.\nOnboarding, Ingestion e Gateway restano invariati. Nessuna migrazione DB, modifica grant, decisione di identita o proposta semantica. Nessun nuovo worker policy.\nUn tentativo per effetto, massimo900 secondi; esito ambiguo richiede riconciliazione. Dopo il risultato si verifica la pagina prima di confermare identita.\nRevisione privata: '+str(context/'review.json'))
 require(admin.routes()==routes,'GATEWAY_CHANGED_BEFORE_ISSUANCE');action=authority.issue_action(review,decision,human)
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():require(not cancelled.is_set(),'UDP_UPDATE_CANCELLED');return time.time()
 action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
 try:
  ports=NativePorts(action,engine,plan,human);update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  while True:
   try:
    result=update.run();emit('OUF_UDP_RESOLUTION_UPDATE_RESULT='+encoded({**result,'contextPath':str(context),'maximumGatewayWrites':0,'newPolicyWorkerStarted':False,'identityDecisionsPerformed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode());break
   except UpdatePaused as error:
    require(str(error)=='READINESS_RETRY_WAIT','UDP_UPDATE_RECONCILIATION_REQUIRED')
    row=update.record();emit('OUF_UDP_RESOLUTION_UPDATE_WAIT='+encoded({'stage':row['effects'][-1]['stage'],'attempts':row['readinessAttempts'],'nextReadAt':row['nextReadAt']}).decode());cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
 finally:
  cancelled.set()
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
