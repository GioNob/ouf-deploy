"""Prepare the entire exact three-route change before one authenticated decision."""
import copy,json,signal,time,threading
from pathlib import Path
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,private_config
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.semantic_mcp_update.entry import publish_json
from tools.semantic_mcp_update.native import private_file
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.onboarding_audit_update.native import runtime
from tools.onboarding_audit_update.entry import read_active_publication
from tools.resolution_ths_update import plan as compiler,authority
from tools.resolution_ths_update.owner import require,digest,encoded,scope,ReadinessUpdate,UpdatePaused
from tools.resolution_ths_update.native import NativePorts

def main(prepared,sources,closure,case,context,read,ns,emit):
 previous=Path(case['rolloutContext']);prior=read(previous/'review.json',8388608,case['rolloutReviewSha256']);old_plan=read(previous/'execution-plan.json',8388608);record=read(previous/'recovery.json',65536)
 old_scope=prior['scopes']['onboardingAuditUpdate']
 require(prior['kind']=='ONBOARDING_AUDIT_FIX'and digest(old_plan)==old_scope['planHash']and record['scopeHash']==digest(old_scope)and record['version']==29 and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(old_scope['stages'])==11 and all(e['state']=='APPLIED'for e in record['effects']),'EXACT_COMPLETED_COMPATIBILITY_ROLLOUT_REQUIRED')
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 pins={'onboarding':record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'],'ingestion':old_plan['unchangedIngestionRuntimeBinding']};actuals={}
 for name,pin in pins.items():
  status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'CURRENT_APPLICATION_GENERATION_CHANGED');actuals[name]=actual
 cfg=compiler.configuration(actuals['onboarding'],prepared['authorization']['plan']['selection']['origin'],case['thsConfigSha256'])
 admin=NamespaceAdmin(engine,old_plan['gateway']['transport']);routes=admin.routes()
 require(routes==old_plan['gateway']['beforeRoutes']and digest(routes)==case['retainedRouteMapSha256'],'COMPLETE_RETAINED_GATEWAY_ROUTES_REQUIRED')
 additions=compiler.compile_routes(routes)
 # Derive the current active worker through the immutable original fence path;
 # never scan or guess another HUMAN/session directory and never install a worker.
 predecessor=read(Path(case['originalPolicyContext'])/'review.json',8388608,case['originalPolicyReviewSha256'])
 fence_path=predecessor['scopes']['policyTokenFiniteWorkerSession']['fenceBinding']['path'];fence=read(fence_path,16384)
 require(fence.get('active')is True,'CURRENT_POLICY_FENCE_REQUIRED');journal=Path(fence['journalPath']);worker=read(journal/'owner-session.json',131072)
 require(worker['fenceBinding']=={'path':fence_path,'value':fence}and worker['predecessorGrantAttempts']==248 and worker['maximumCumulativeGrantAttempts']==316,'EXACT_EXISTING_248_PLUS68_WORKER_REQUIRED')
 row=read_active_publication(Journal(journal),worker,lambda:None,emit=emit)
 worker_expiry=int(row['startedWall']+worker['policy']['max_elapsed']-60)
 hb=prior['authenticatedHuman'];directory=Path(hb['sessionDirectory'])
 human=HumanSession(prepared['authorization']['plan']['selection'],directory,Path(hb['tokenPath']),hb['expiresAt'])
 require(human._read()['binding']==hb,'EXACT_RETAINED_HUMAN_BINDING_REQUIRED')
 plan={'schema':'ouf.resolution-ths-route-plan.v1','authorityDirectory':str(context),'engine':copy.deepcopy(prepared['engine']),
  'gatewayTransport':copy.deepcopy(old_plan['gateway']['transport']),'beforeRoutes':routes,'routes':additions,
  'applicationPins':pins,'configuration':cfg,'reviewedOrigin':prepared['authorization']['plan']['selection']['origin'],
  'humanBinding':hb,'worker':{'scope':worker,'fenceBinding':worker['fenceBinding'],'journalPath':str(journal),'conservativeExpiresAt':worker_expiry},
  'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':3,
  **{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','containerLifecycleAllowed','identityDecisionsAllowed')}}
 plan['logicalUpdateRef']=digest({'beforeRoutes':digest(routes),'routes':additions});scope(plan);publish_json(context,'execution-plan.json',plan)
 emit('OUF_RESOLUTION_ROUTES_PREPARED='+encoded({'contextPath':str(context),'newRouteIds':list(compiler.ROUTES),'existingRouteCount':len(routes),'configurationMetadata':{k:v for k,v in cfg.items()if k!='fileBinding'},'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode())
 signal.alarm(0);human.refresh_if_due();require(human.current()==hb,'SAME_FRESH_HUMAN_SESSION_REQUIRED')
 seconds=min(480,worker_expiry-int(time.time())-10,human.expires_at-int(time.time())-10);require(seconds>=210,'EXISTING_SESSION_WINDOW_TOO_SHORT_FOR_ROUTE_UPDATE')
 review=authority.compile_action_review('RESOLUTION_THS_ROUTES',closure,{'resolutionRoutesUpdate':scope(plan)},hb,context,{'predecessorHistoryHash':case['rolloutReviewSha256'],'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
 review['absoluteExpiresAt']=min(worker_expiry-5,human.expires_at);publish_json(context,'review.json',review)
 decision=authority.terminal_consent(review,
  'Tre sole nuove route: lettura casi UDP, conferma HUMAN UDP, pagina Resolution pubblicata per ultima. Tecniche8/8; funzionali2/6.\n'
  'Preservo tutte le route esistenti, stesso login HUMAN e stessi backend approvati. Nessun container o file configurazione viene modificato.\n'
  'Nessuna decisione sulle12identita, importazione, modifica grant, migrazione o nuovo worker.\n'
  'Un solo tentativo per PUT; timeout o esito ambiguo richiedono riconciliazione, senza ripetizione automatica.\n'
  'Revisione privata: '+str(context/'review.json'))
 require(admin.routes()==routes,'GATEWAY_CHANGED_BEFORE_ISSUANCE');action=authority.issue_action(review,decision,human)
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():require(not cancelled.is_set()and time.time()<worker_expiry,'ROUTE_UPDATE_CANCELLED_OR_POLICY_WINDOW_ENDED');return time.time()
 action.authority.clock=current_time
 try:
  ports=NativePorts(action,engine,plan,human);update=ReadinessUpdate(action,Journal(context),plan,ports);ports.journal=update.journal;update.initialize()
  while True:
   try:
    result=update.run();emit('OUF_RESOLUTION_ROUTES_RESULT='+encoded({**result,'contextPath':str(context),'newRouteCount':3,'containerLifecycleOperations':0,'identityDecisionsPerformed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode());break
   except UpdatePaused as error:
    require(str(error)=='READINESS_RETRY_WAIT','ROUTE_UPDATE_RECONCILIATION_REQUIRED')
    row=update.record();emit('OUF_RESOLUTION_ROUTES_WAIT='+encoded({'stage':row['effects'][-1]['stage'],'attempts':row['readinessAttempts'],'nextReadAt':row['nextReadAt']}).decode());cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
 finally:
  for sig,handler in handlers.items():signal.signal(sig,handler)
