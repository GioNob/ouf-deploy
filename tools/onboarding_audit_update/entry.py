"""Reuse the current finite HUMAN/policy session; approve only one Onboarding fix."""
import copy,hashlib,json,os,signal,threading,time
from pathlib import Path
import iam_governance_intake as governance
from cutover_authority import CutoverAuthority
from engine_creation import Engine
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,MOUNT_SET_BINDING
from tools.semantic_mcp_update.entry import publish_json
from tools.onboarding_audit_update import authority,preparation
from tools.onboarding_audit_update.owner import ReadinessUpdate,UpdatePaused,require,digest,encoded,scope
from tools.onboarding_audit_update.native import NativePorts,runtime


def current_policy(case,closure,read,prepared):
 context=Path(case['policyContext']);review=read(context/'review.json',8388608,case['policyReviewSha256'])
 require(review.get('kind')=='POLICY_TEST_SESSION','EXACT_ACTIVE_TEST_POLICY_SESSION_REQUIRED')
 raw=encoded(read(context/'authority.json',131072));require(hashlib.sha256(raw).hexdigest()==case['policyAuthoritySha256'],'EXACT_POLICY_AUTHORITY_REQUIRED')
 expected={k:review[k]for k in('sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')};expected['intakeHash']=digest(review)
 mandate=encoded(read(context/'human.json',131072));mh=hashlib.sha256(mandate).hexdigest()
 verifier=DetachedAuthenticator(governance.POLICY,str(context),closure['executables']['openssl'])
 gate=CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':mh},mh,governance.CONTEXT,expected)
 action=AggregateAction(gate,raw,review['sourceClosureHash']);worker=review['scopes']['policyTokenFiniteWorkerSession']
 action.guard('policyTokenFiniteWorkerSession',worker)
 row=Journal(worker['fenceBinding']['value']['journalPath']).private_read()
 now=time.time()
 require(row.get('workerSessionHash')==digest(worker)and row.get('state')=='ACTIVE'
  and row.get('controlledPredecessorGrantAttempts')==188 and row.get('controlledCumulativeGrantAttempts')==188+row.get('attempts',-1000)<=316
  and row.get('publicationCount',0)>0 and row.get('tokenExpiresWall',0)>now+10
  and now-90<=row.get('lastWall',0)<=now,'CURRENT_ACTIVE_POLICY_PUBLICATION_REQUIRED')
 require(read(worker['fenceBinding']['path'],16384)==worker['fenceBinding']['value'],'CURRENT_EXISTING_POLICY_FENCE_REQUIRED')
 registry=review['scopes']['semanticFunctionalRuntime']['registryGeneration']
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 status,current=engine.request('GET','/v1.44/containers/'+registry['containerId']+'/json')
 require(status==200 and current['State']['Running']is True and runtime(current)==registry,'CURRENT_POLICY_REGISTRY_GENERATION_REQUIRED')
 return review,json.loads(raw)['expiresAt']


def main(prepared,sources,closure,case,context,archive,read,ns,emit=print):
 authority.closure_valid(closure);context=Path(context)
 policy_review,policy_expiry=current_policy(case,closure,read,prepared)
 previous=read(Path(case['rolloutContext'])/'review.json',8388608,case['rolloutReviewSha256'])
 previous_plan=read(Path(case['rolloutContext'])/'execution-plan.json',8388608)
 record=read(Path(case['rolloutContext'])/'recovery.json',65536)
 require(digest(previous_plan)==previous['scopes']['ingestionReadinessUpdate']['planHash']
  and record.get('scopeHash')==digest(previous['scopes']['ingestionReadinessUpdate'])
  and record.get('incidentState')=='RECOVERED'and record.get('version')==57
  and record.get('nextStage')==len(previous['scopes']['ingestionReadinessUpdate']['stages'])
  and all(e['state']=='APPLIED'for e in record['effects']),'EXACT_COMPLETE_PREDECESSOR_ROLLOUT_REQUIRED')
 final=record['effects'][-1]['evidence'];engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 actuals={}
 for name in('onboarding','ingestion'):
  status,actual=engine.request('GET','/v1.44/containers/'+previous_plan['replacements'][name]['name']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==final['applications'][name]['runtimeBinding'],'PREDECESSOR_APPLICATION_GENERATION_CHANGED')
  actuals[name]=actual
 transport=copy.deepcopy(previous_plan['gateway']['transport']);admin=NamespaceAdmin(engine,transport);routes=admin.routes()
 require(digest(routes)==final['routeMapHash']==case['retainedRouteMapHash'],'PRESERVED_GATEWAY_ROUTE_MAP_REQUIRED')
 emit('OUF_ONBOARDING_AUDIT_FIX_PHASE=CANDIDATE_BYTE_CUSTODY technical=8/8 functional=1/6')
 image=preparation.candidate(archive,case,context,prepared['engine'],ns)
 old=actuals['onboarding'];old_plan=previous_plan['replacements']['onboarding'];request=copy.deepcopy(old_plan['request'])
 for key in('User','Entrypoint','Cmd','WorkingDir','Env','Labels','Healthcheck','StopSignal','StopTimeout'):
  if key in old['Config']:request[key]=copy.deepcopy(old['Config'][key])
 audit=image['imageAudit'];config=audit['imageConfig']
 require(all(old['Config'].get(k)==config.get(k)for k in('User','Entrypoint','WorkingDir')),'AUDIT_FIX_NATIVE_LAUNCH_CONTRACT_CHANGED')
 request['Image']=image['nativeImageId'];request['Labels']={**(old['Config'].get('Labels')or{}),'org.opencontainers.image.revision':case['candidateSourceCommit']}
 request['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
 row={'name':old_plan['name'],'retiredName':old_plan['name']+'-audit-fix-retired-'+digest(case)[:12],
  'request':request,'oldRuntimeBinding':runtime(old),'oldNativeHostConfig':copy.deepcopy(old['HostConfig']),
  'oldMounts':copy.deepcopy(old['Mounts']),'restoreRestartPolicy':copy.deepcopy(old['HostConfig']['RestartPolicy']),
  'imageAudit':audit,'imageArchive':image['imageArchive'],'network':copy.deepcopy(old_plan['network']),'readiness':copy.deepcopy(old_plan['readiness'])}
 private={'schema':'ouf.onboarding-audit-fix-private-review.v1','predecessorRolloutReviewSha256':case['rolloutReviewSha256'],
  'candidateMetadata':image['candidateMetadata'],'imageAudit':audit,'imageArchive':image['imageArchive'],
  'oldRuntimeBinding':runtime(old),'retainedIngestionBinding':runtime(actuals['ingestion']),
  'gatewayRouteMapHash':digest(routes),'migrationFilesUnchanged':True,'readyForExecution':False,'runtimeAuthorityIssued':False}
 publish_json(context,'candidate-review.json',private)
 plan={'schema':'ouf.onboarding-audit-get-native-update-plan.v1','authorityDirectory':str(context),
  'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(private)},
  'engine':copy.deepcopy(prepared['engine']),'programs':{'docker':closure['executables']['docker']},
  'replacements':{'onboarding':row},'unchangedIngestionRuntimeBinding':runtime(actuals['ingestion']),
  'gateway':{'transport':transport,'beforeRoutes':routes,'route':copy.deepcopy(previous_plan['gateway']['route']),
   'projectionBinding':copy.deepcopy(previous_plan['gateway']['projectionBinding'])},
  'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,
  'automaticReplayAllowed':False,'databaseMigrationsAllowed':False,'grantChangesAllowed':False,
  'semanticDispatchAllowed':False,'automaticRollbackAllowed':False}
 plan['logicalUpdateRef']=digest({'retiredContainerIds':[row['oldRuntimeBinding']['containerId']],'routeId':plan['gateway']['route']['id']})
 publish_json(context,'execution-plan.json',plan)
 receipt=read(Path(case['policyContext'])/'login-window-receipt.json',131072);human_dir=Path(receipt['directory'])
 human=HumanSession(prepared['authorization']['plan']['selection'],human_dir,human_dir/'human-access.jwt',receipt['expiresAt'])
 signal.alarm(0)
 human.refresh_if_due();hb=human.current()
 require(all(hb[k]==policy_review['authenticatedHuman'][k]for k in('issuer','tenant','subject','sessionId')),'SAME_CURRENT_HUMAN_SESSION_REQUIRED')
 current_policy(case,closure,read,prepared)
 seconds=min(900,policy_expiry-int(time.time())-10);require(seconds>=240,'EXISTING_POLICY_WINDOW_TOO_SHORT_FOR_AUDIT_FIX')
 final_review=authority.compile_action_review('ONBOARDING_AUDIT_FIX',closure,{'onboardingAuditUpdate':scope(plan)},hb,context,
  {'predecessorHistoryHash':case['rolloutReviewSha256'],'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
 final_review['absoluteExpiresAt']=min(policy_expiry-5,human.expires_at)
 publish_json(context,'review.json',final_review)
 decision=authority.terminal_consent(final_review,
  'Correzione del solo Onboarding: lettura configurazione con audit di autorizzazione. Tecniche8/8; funzionali1/6.\n'
  'Una nuova immagine; vecchio Onboarding fermato e conservato; stessi mount, ambiente, rete, IP e MAC.\n'
  'Ingestion e Gateway invariati. Nessuna migrazione DB, modifica grant, ripetizione approvazioni o proposta semantica.\n'
  'Riutilizzo della sessione HUMAN e del worker policy attivi: nessun nuovo login o budget.\n'
  'Un tentativo per effetto, massimo900 secondi; esito incerto richiede riconciliazione.\n'
  'Revisione privata: '+str(context/'review.json'))
 current_policy(case,closure,read,prepared);action=authority.issue_action(final_review,decision,human)
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():require(not cancelled.is_set()and time.time()<policy_expiry,'AUDIT_FIX_CANCELLED_OR_POLICY_EXPIRED');return time.time()
 action.authority.clock=current_time
 try:
  ports=NativePorts(action,engine,plan);update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  while True:
   try:
    result=update.run();emit('OUF_ONBOARDING_AUDIT_FIX_RESULT='+encoded({**result,'contextPath':str(context),
     'maximumGatewayWrites':0,'newPolicyWorkerStarted':False,'completedTechnicalPhases':8,'functionalMilestonesProven':1}).decode());break
   except UpdatePaused as paused:
    require(str(paused)=='READINESS_RETRY_WAIT','AUDIT_FIX_RECONCILIATION_REQUIRED')
    value=update.record();emit('OUF_ONBOARDING_AUDIT_FIX_WAIT='+encoded({'stage':value['effects'][-1]['stage'],'attempts':value['readinessAttempts'],'nextReadAt':value['nextReadAt']}).decode())
    cancelled.wait(min(5,max(0,value['nextReadAt']-time.time())))
 finally:
  for sig,handler in handlers.items():signal.signal(sig,handler)
