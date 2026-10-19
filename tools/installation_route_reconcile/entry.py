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
from tools.installation_route_reconcile import baseline,authority,login
from tools.installation_route_reconcile.owner import require,digest,encoded,scope,scope_key,FiniteUpdate,FORBIDDEN
from tools.installation_route_reconcile.native import Ports,OwnerHttp,baseline_runtime

SCHEMAS={'login-review.json':'ouf.human-installation-route-budget-review.v5','login-decision.json':'ouf.human-installation-route-budget-decision.v5',
 'login-window-receipt.json':'ouf.installation-route-budget264-receipt.v1','execution-plan.json':'ouf.installation-binding-native-plan.v1',
 'review.json':'ouf.semantic-scoped-infrastructure-review.v1','owner-result.json':'ouf.installation-binding-owner-result.v1',
 'update-result.json':'ouf.installation-route-reconciliation-result.v1'}
def publish_json(context,name,value):
 context=Path(context);require(context.parent==authority.evidence.PARENT and re.fullmatch('installation-binding-apply-execution-[A-Za-z0-9_-]{8,64}',context.name)
  and name in SCHEMAS and value.get('schema')==SCHEMAS[name],'EXACT_PRIVATE_BINDING_DOCUMENT_REQUIRED')
 raw=encoded(value);require(0<len(raw)<=8388608,'BOUNDED_BINDING_DOCUMENT_REQUIRED');baseline.write_new(context/name,raw)
 require(baseline.read(context/name)==raw,'BINDING_PRIVATE_DOCUMENT_READBACK_REQUIRED')
def alarm(seconds):
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_BINDING_PHASE_DEADLINE')));signal.alarm(seconds)
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


from tools.installation_route_reconcile import reconcile as retained

def live_preconditions(plan,human,http):
 human.current();engine=Engine(plan['engine']['socketPath'],tuple(plan['engine']['socketBinding']))
 for name,pin in plan['currentApplications'].items():
  status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
  require(status==200 and baseline_runtime(actual,name,plan)==pin,'CURRENT_GENERATION_DRIFT')
 for binding in plan['retainedMcpMetadata']:metadata_file(binding)
 from tools.installation_route_reconcile.native import approved_projection_bytes
 approved_projection_bytes(plan['projectionBinding']['path'],plan['projectionHash'])
 require(http.active()=={**plan['bindingPlan']['expectedActive'],'etag':plan['bindingPlan']['expectedActiveETag']},'CURRENT_OWNER_ACTIVE6_DRIFT')
 routes=NamespaceAdmin(engine,plan['gateway']['transport']).routes()
 require(routes==plan['gateway']['beforeRoutes'],'CURRENT_GATEWAY_BEFORE82_DRIFT')
 require(digest(retained.parsed(plan['predecessorJournalBinding']['path']))==plan['predecessorJournalBinding']['sha256'],'PREDECESSOR_JOURNAL_DRIFT')

def main(original,sources,closure,case,context,read,emit):
 context=Path(context);authority.closure_valid(closure);alarm(120)
 diagnostic=retained.continuation_readiness();alarm(120)
 require(diagnostic['publicationBytesPresentButJournalUnreconciled']and diagnostic['noGatewayDispatchByThisActionProven']
  and diagnostic['human']['attempts']==255 and diagnostic['human']['windowStillOpen']and not diagnostic['human']['recordedAccessHas240SecondsMargin'],
  'EXACT_PUBLISHED_PROFILE_AND_INSUFFICIENT_READY255_REQUIRED')
 predecessor=retained.parsed(retained.SECOND/'execution-plan.json');journal=retained.parsed(retained.SECOND/'recovery.json')
 require(digest(journal)==case['predecessorJournalBinding']['sha256']and digest(predecessor)==case['predecessorPlanHash'],
  'EXACT_PREPARED_PREDECESSOR_UNCHANGED')
 claim=read(case['preparationClaimBinding']['path'],expected=case['preparationClaimBinding']['sha256'])
 require(claim['context']==str(context)and claim['priorOAuthAttempts']==255 and claim['maximumCumulativeOAuthAttempts']==264,'EXACT_ROUTE_PREPARATION_CLAIM_REQUIRED')
 emit('OUF_BINDING_PHASE=EXPLICIT_BUDGET264_FRESH_HUMAN');alarm(600)
 human=login.authenticate(original['authorization']['plan']['selection'],predecessor['humanBinding'],context,closure,publish_json,emit,case)
 plan={**copy.deepcopy(predecessor),'kind':'INSTALLATION_ROUTE_RECONCILIATION','authorityDirectory':str(context),'humanBinding':human.current(),
  'predecessorJournalBinding':case['predecessorJournalBinding'],'predecessorPlanHash':case['predecessorPlanHash'],
  'reconciliationSourceClosureHash':digest(closure)}
 plan['logicalRef']=digest({'kind':plan['kind'],'predecessorLogicalRef':case['predecessorLogicalRef'],'publishedProjectionHash':plan['projectionHash'],
  'afterRouteMapHash':digest(plan['gateway']['afterRoutes'])})
 emit('OUF_BINDING_PHASE=CURRENT_OWNER_PROFILE_AND_GATEWAY_READS');alarm(90)
 http=OwnerHttp(human.selection,human,plan['bindingPlan']['expectedActive']['installationId'],'ouf-routes-'+plan['logicalRef'][:32],read_only=True)
 live_preconditions(plan,human,http)
 plan['currentPublishedProjectionBinding']=private_config(plan['projectionBinding']['path'])[1]
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 try:
  emit('OUF_BINDING_PHASE=NATIVE_TWO_ROUTES_AND_RECONCILIATION_APPROVO_REQUIRED')
  action=approved_action(plan['kind'],plan,closure,human,context,
   'La proiezione attiva e GIA quella autorevole: NON la ripubblico e non ripeto owner o export.\n'
   'Nuova autorita distinta:210secondi, due ruoli firmati; l autorita precedente resta scaduta.\n'
   'Riconcilio CLAIMED->APPLIED del solo rename gia provato, poi eseguo SOLO2PUT Gateway status/history con readback.\n'
   'Solo host upstream dalle rotte gia approvate;80rotte, porte, metodi, OIDC, delegazione e controlli invariati.\n'
   'Dopo prove correnti e journal nuovo durevole, riconcilio il completamento storico usando riferimenti alla NUOVA autorita.\n'
   'Massimo2transizioni del journal precedente; scadenza originale conservata, nessun uso dell autorita scaduta.\n'
   'Zero POST/export owner, zero pubblicazioni proiezione, container, DB/migrazioni, IAM/grant, fonte o job.\n'
   'Ogni effetto ha claim persistente: STOP/interruzione vietano il rilancio.',cancelled)
  http.deadline=time.monotonic()+210
  ports=Ports(action,plan,human,http,context);update=FiniteUpdate(action,plan,ports,Journal(context));update.initialize();done=update.run()
  prior=retained.parsed(retained.SECOND/'recovery.json')
  report={'schema':'ouf.installation-route-reconciliation-result.v1','status':'PUBLISHED_PROFILE_RECONCILED_AND_TWO_GATEWAY_ROUTES_COMPLETE',
   'contextPath':str(context),'predecessorContextPath':str(retained.SECOND),'complete':True,'runtimeAuthorityIssued':True,
   'predecessorPublicationReplayed':False,'predecessorJournalReconciled':prior['incidentState']=='RECOVERED'and prior['nextStage']==5,
   'predecessorJournalVersion':prior['version'],'predecessorAuthorityExpiresAtPreserved':prior['expiresAt'],
   'activeOwnerRevision':6,'activeOwnerGeneration':6,'projectionHash':plan['projectionHash'],
   'routeMapHash':digest(plan['gateway']['afterRoutes']),'retainedOtherRoutes':80,'routeCount':82,'gatewayWrites':2,
   'ownerPosts':http.posts,'projectionExports':http.exports,'activeProjectionWrites':0,'databaseCalls':0,'containerLifecycleOperations':0,
   'grantChanges':0,'publicMetadataChanged':False,'sourceActivated':False,'jobsRetried':0,'nativeProfilePublished':False,
   'freshChatClientReadProven':False,'notReleaseAcceptance':True,'humanSourceChanged':True,'priorOAuthAttempts':255,
   'oauthAttemptsAfter':human._read()['attempts'],'maximumCumulativeOAuthAttempts':264,'humanWindowExpiresAt':human.expires_at,
   'automaticReplayAllowed':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
  publish_json(context,'update-result.json',report);signal.alarm(0);emit('OUF_INSTALLATION_ROUTE_RESULT='+encoded(report).decode())
 finally:
  for sig,handler in handlers.items():signal.signal(sig,handler)
