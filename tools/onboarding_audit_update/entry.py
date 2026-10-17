"""Reuse the current finite HUMAN/policy session; approve only one Onboarding fix."""
import copy,hashlib,json,os,signal,tempfile,threading,time
from pathlib import Path
import iam_governance_intake as governance
from cutover_authority import CutoverAuthority
from engine_creation import Engine
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from tools.semantic_policy_token_owner.worker_entry import serve
from tools.chatbot_file_cohort.continued_owner import GovernedSemanticOwnerContinuation,TOKEN_STAGE_SOURCE
from tools.semantic_mcp_update.entry import retained_registry
from tools.semantic_mcp_update import session
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,MOUNT_SET_BINDING
from tools.semantic_mcp_update.entry import publish_json
from tools.onboarding_audit_update import authority,preparation
from tools.onboarding_audit_update.owner import ReadinessUpdate,UpdatePaused,require,digest,encoded,scope
from tools.onboarding_audit_update.native import NativePorts,runtime


def read_active_publication(journal,worker,guard,clock=time.time,monotonic=time.monotonic,wait=time.sleep,jitter=None,emit=print):
 """Observe an existing renewal; never drive, restart or write the worker."""
 if jitter is None:jitter=lambda: int.from_bytes(os.urandom(2),'big')/65535
 started=monotonic();delays=(5,15)
 transitions={'NEW':'SCHEDULED_RENEWAL_DUE','ATTEMPTING':'FRESH_ATTEMPT','PUBLISHING':'FRESH_EVIDENCE_READY'}
 for attempt in range(3):
  guard();row=journal.private_read();now=clock()
  require(row.get('workerSessionHash')==digest(worker),'CURRENT_POLICY_SESSION_HASH_MISMATCH')
  count=row.get('attempts');prior=row.get('controlledPredecessorGrantAttempts');total=row.get('controlledCumulativeGrantAttempts')
  require(type(count)is int and count>=1 and prior==worker.get('predecessorGrantAttempts') and prior in(188,248) and total==prior+count<=worker.get('maximumCumulativeGrantAttempts')==316,'CURRENT_POLICY_CONTROLLED_HISTORY_MISMATCH')
  require(type(row.get('publicationCount'))is int and row['publicationCount']>0,'CURRENT_POLICY_PUBLICATION_ABSENT')
  require(type(row.get('tokenExpiresWall'))in(int,float)and row['tokenExpiresWall']>now+10,'CURRENT_POLICY_TOKEN_WINDOW_INSUFFICIENT')
  require(type(row.get('lastWall'))in(int,float)and now-90<=row['lastWall']<=now,'CURRENT_POLICY_PUBLICATION_CLOCK_INVALID')
  if row.get('state')=='ACTIVE':return row
  require(row.get('state')in transitions and row.get('reason')==transitions[row['state']],'CURRENT_POLICY_WORKER_NOT_ACTIVE')
  require(attempt<len(delays),'CURRENT_POLICY_RENEWAL_NOT_COMPLETED')
  noise=jitter();require(type(noise)in(int,float)and 0<=noise<=1,'POLICY_READ_JITTER_INVALID')
  delay=delays[attempt]*(0.8+0.4*noise)
  require(monotonic()+delay-started<=30,'CURRENT_POLICY_READ_WINDOW_EXHAUSTED')
  emit('OUF_ONBOARDING_AUDIT_FIX_POLICY_WAIT='+encoded({'readOnly':True,'state':row['state'],'readAttempt':attempt+1,'waitSeconds':delay}).decode())
  wait(delay)


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
 read_active_publication(Journal(worker['fenceBinding']['value']['journalPath']),worker,
  lambda:action.guard('policyTokenFiniteWorkerSession',worker))
 require(read(worker['fenceBinding']['path'],16384)==worker['fenceBinding']['value'],'CURRENT_EXISTING_POLICY_FENCE_REQUIRED')
 registry=review['scopes']['semanticFunctionalRuntime']['registryGeneration']
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 status,current=engine.request('GET','/v1.44/containers/'+registry['containerId']+'/json')
 require(status==200 and current['State']['Running']is True and runtime(current)==registry,'CURRENT_POLICY_REGISTRY_GENERATION_REQUIRED')
 return review,json.loads(raw)['expiresAt']


def predecessor_application_pins(plan,final):
 require(set(plan['replacements'])in({'onboarding','ingestion'},{'onboarding'}),'EXACT_PREDECESSOR_APPLICATION_SET_REQUIRED')
 require(set(final['applications'])==set(plan['replacements']),'PREDECESSOR_FINAL_APPLICATIONS_MISMATCH')
 pins={name:row['runtimeBinding']for name,row in final['applications'].items()}
 if 'ingestion'not in pins:
  require(plan.get('maximumGatewayWrites')==0 and type(plan.get('unchangedIngestionRuntimeBinding'))is dict,'PREDECESSOR_RETAINED_INGESTION_REQUIRED')
  pins['ingestion']=plan['unchangedIngestionRuntimeBinding']
 require(set(pins)=={'onboarding','ingestion'}and all(type(row.get('containerId'))is str for row in pins.values()),'PREDECESSOR_RUNTIME_PINS_REQUIRED')
 return pins


def main(prepared,sources,closure,case,context,archive,read,ns,emit=print):
 authority.closure_valid(closure);context=Path(context)
 policy_review,policy_expiry=(None,None)if case.get('startPolicyRemainder')is True else current_policy(case,closure,read,prepared)
 previous=read(Path(case['rolloutContext'])/'review.json',8388608,case['rolloutReviewSha256'])
 previous_plan=read(Path(case['rolloutContext'])/'execution-plan.json',8388608)
 record=read(Path(case['rolloutContext'])/'recovery.json',65536)
 previous_scope=previous['scopes'][case.get('predecessorScopeKey','ingestionReadinessUpdate')]
 require(digest(previous_plan)==previous_scope['planHash']
  and record.get('scopeHash')==digest(previous_scope)
  and record.get('incidentState')=='RECOVERED'and record.get('version')==case.get('predecessorJournalVersion',57)
  and record.get('nextStage')==len(previous_scope['stages'])
  and all(e['state']=='APPLIED'for e in record['effects']),'EXACT_COMPLETE_PREDECESSOR_ROLLOUT_REQUIRED')
 final=record['effects'][-1]['evidence'];pins=predecessor_application_pins(previous_plan,final);engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 actuals={}
 for name in('onboarding','ingestion'):
  status,actual=engine.request('GET','/v1.44/containers/'+pins[name]['containerId']+'/json')
  require(status==200 and actual['State']['Running']is True and runtime(actual)==pins[name],'PREDECESSOR_APPLICATION_GENERATION_CHANGED')
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
 if case.get('startPolicyRemainder')is True:
  return run_policy_remainder_and_update(prepared,sources,closure,case,context,plan,read,emit)
 receipt=read(Path(case['policyContext'])/'login-window-receipt.json',131072);human_dir=Path(receipt['directory'])
 human=HumanSession(prepared['authorization']['plan']['selection'],human_dir,human_dir/'human-access.jwt',receipt['expiresAt'])
 return execute_prepared_update(prepared,closure,case,context,plan,human,policy_review,policy_expiry,read,emit)


def execute_prepared_update(prepared,closure,case,context,plan,human,policy_review,policy_expiry,read,emit):
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
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
  'Correzione del solo Onboarding: risorsa pubblicata e modulo ONBOARDING per il grant esistente. Tecniche8/8; funzionali1/6.\n'
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
     'maximumGatewayWrites':0,'newPolicyWorkerStarted':case.get('policyStartedInThisCommand',False),'completedTechnicalPhases':8,'functionalMilestonesProven':1}).decode());break
   except UpdatePaused as paused:
    require(str(paused)=='READINESS_RETRY_WAIT','AUDIT_FIX_RECONCILIATION_REQUIRED')
    value=update.record();emit('OUF_ONBOARDING_AUDIT_FIX_WAIT='+encoded({'stage':value['effects'][-1]['stage'],'attempts':value['readinessAttempts'],'nextReadAt':value['nextReadAt']}).decode())
    cancelled.wait(min(5,max(0,value['nextReadAt']-time.time())))
 finally:
  for sig,handler in handlers.items():signal.signal(sig,handler)


def remainder_worker_review(base,records,journal):
 old=records['recovery.json'];previous=records['owner-session.json']
 require(old['attempts']==old['publicationCount']==60 and old['controlledPredecessorGrantAttempts']==188
  and old['controlledCumulativeGrantAttempts']==248 and old['state']=='CANCELLED'and old['reason']=='CANCELLED_BY_OWNER'
  and previous['maximumCumulativeGrantAttempts']==316,'EXACT_CANCELLED248_POLICY_HISTORY_REQUIRED')
 review=copy.deepcopy(base)
 review.update(schema='ouf.chatbot-semantic-functional-session-review.v3',preparedAt=int(time.time()),
  predecessorRecordHashes={k:digest(v)for k,v in records.items()},predecessorJournalDirectory=str(journal),
  predecessorFenceBinding=copy.deepcopy(previous['fenceBinding']),
  finiteTestProfile={'schema':'ouf.policy-token-test-session-profile.v1','maximumNewTokenGrantAttempts':68,
   'maximumSeconds':3600,'renewalIntervalSeconds':60,'automaticRenewalAllowed':False,
   'purpose':'CONFIGURATION_AND_VALIDATION','preserveCumulativeHistory':True})
 review['proposedFiniteBudget'].update(priorControlledGrantAttempts=248,predecessorWorkerAttempts=60,
  maximumNewTokenGrantAttempts=68,maximumCumulativeGrantAttempts=316,maximumSeconds=3600,
  renewalIntervalSeconds=60,automaticRenewalAllowed=False)
 review['requiredOwnerDecision'].update(explicitNewTestBudgetRequired=True,newCumulativeCeilingRequiresFreshHumanDecision=True)
 review.update(runtimeAuthorityIssued=False,humanApprovalGranted=False,readyForExecution=False)
 return review


def run_policy_remainder_and_update(prepared,sources,closure,case,context,plan,read,emit):
 # Every archive, image, source migration and current application/Gateway pin is
 # already prepared before any HUMAN refresh, terminal decision or new grant.
 predecessor=read(Path(case['policyContext'])/'review.json',8388608,case['policyReviewSha256'])
 previous_scope=predecessor['scopes']['policyTokenFiniteWorkerSession']
 previous_journal=Path(previous_scope['fenceBinding']['value']['journalPath'])
 records={name:read(previous_journal/name,131072)for name in('recovery.json','owner-session.json','owner-admission.json','owner-status.json')}
 first=read(previous_journal/'owner-first-grant.json',16384)
 binding=predecessor['workerReviewBinding'];base=read(binding['path'],8388608,binding['sha256'])
 require(base['retainedOwnerInputsHash']==digest(prepared['owner']),'EXACT_RETAINED_OWNER_INPUTS_REQUIRED')
 review=remainder_worker_review(base,records,previous_journal)
 publish_json(context,'worker-review.json',review);worker_binding={'path':str(context/'worker-review.json'),'sha256':digest(review)}
 policy={'delays':[5,15,60,300,900],'max_attempts':68,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
 worker_scope=compile_governed_session(review,records,first,policy,digest({'operation':review['logicalOperation'],'reviewHash':digest(review)}),digest(review['registryGeneration']),60)
 journal=Path(worker_scope['fenceBinding']['value']['journalPath'])
 with protected_directory(journal.parent)as directory:os.mkdir(journal.name,0o700,dir_fd=directory);os.fsync(directory)
 expected={'sourceClosureHash':digest(closure),'creationRequestHash':digest(review),
  'predecessorHistoryHash':digest(review['predecessorRecordHashes']),'predecessorIncidentRef':worker_scope['logicalOwnerScopeHash'],'intakeHash':digest(review)}
 verifier=DetachedAuthenticator(governance.POLICY,str(context),closure['executables']['openssl'])
 absent={'path':str(context/'UNISSUED-human.json'),'sha256':digest({'unissued':True})}
 unissued=AggregateAction(CutoverAuthority(verifier,absent,absent['sha256'],governance.CONTEXT,expected),encoded({'unissued':True}),digest(closure))
 files={name:sources[module]for name,module in TOKEN_STAGE_SOURCE.items()}
 args=(prepared['owner'],files,closure['declaration']['sourceCommit'],review,records,first,worker_binding,prepared['engine'],journal)
 planned=GovernedSemanticOwnerContinuation(unissued,*args);require(planned.worker_scope==worker_scope,'EXACT_COMPILED_REMAINDER_WORKER_REQUIRED');retained_registry(planned)
 receipt=read(Path(case['policyContext'])/'login-window-receipt.json',131072);human_dir=Path(receipt['directory'])
 human=HumanSession(prepared['authorization']['plan']['selection'],human_dir,human_dir/'human-access.jwt',receipt['expiresAt'])
 signal.alarm(0)
 if time.time()>=human.expires_at:
  login_review=session.expired_login_review(human,{'workerReviewHash':digest(review),'rolloutPlanHash':digest(plan),'sourceClosureHash':digest(closure)})
  publish_json(context,'login-review.json',login_review)
  consent=authority.terminal_consent(login_review,
   'Finestra HUMAN scaduta: nuova finestra solo con consenso esplicito, nessun reset OAuth.\n'
   'Tentativi OAuth conservati: '+str(login_review['priorOAuthAttempts'])+'; residui: '+str(login_review['maximumRemainingOAuthAttempts'])+'.\n'
   'Seguono browser, APPROVO worker248+68=316 e APPROVO separato per il solo Onboarding.',login=True)
  human=session.open_approved_login(human,login_review,consent);human.login(emit=emit)
 else:
  human.refresh_if_due()
  emit('OUF_COMPATIBILITY_SESSION_PHASE=REUSE_CURRENT_HUMAN_WINDOW technical=8/8 functional=1/6')
 hb=human.current();publish_json(context,'login-window-receipt.json',{'directory':str(human.directory),'expiresAt':human.expires_at,'budgetReset':False})
 require(human.expires_at-int(time.time())>=600,'CURRENT_HUMAN_WINDOW_TOO_SHORT_FOR_COMPATIBILITY_UPDATE')
 authority.current_authorities(min(int(time.time())+3610,human.expires_at))
 token_review=authority.compile_action_review('POLICY_TEST_SESSION',closure,planned.scopes(),hb,context,
  {'predecessorHistoryHash':digest(review['predecessorRecordHashes']),'predecessorIncidentRef':worker_scope['logicalOwnerScopeHash']},3600)
 token_review['workerReviewBinding']=worker_binding;token_review['absoluteExpiresAt']=human.expires_at-5
 publish_json(context,'review.json',token_review)
 decision=authority.terminal_consent(token_review,
  'Nuova sessione finita del solo worker policy. Tecniche8/8; funzionali1/6.\n'
  '248 tentativi conservati, massimo68 ulteriori, cumulativo invariato316. Durata massima3600 secondi, entro la finestra HUMAN corrente.\n'
  'Nessun reset, replay, rinnovo automatico, rotazione o modifica grant.\n'
  'Dopo il primo token: APPROVO separato per il solo Onboarding gia preparato. Lascia aperto questo terminale.\n'
  'Revisione privata: '+str(context/'review.json'))
 token_action=authority.issue_action(token_review,decision,human)
 runtime_case={**case,'startPolicyRemainder':False,'policyStartedInThisCommand':True,'policyContext':str(context),
  'policyReviewSha256':digest(token_review),'policyAuthoritySha256':token_action.authority_hash}
 stop=threading.Event();failure=[];snapshot=[None];handlers={}
 def cancelled(*_):stop.set();raise KeyboardInterrupt()
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,cancelled)
 def current_time():require(not stop.is_set(),'COMPATIBILITY_POLICY_SESSION_CANCELLED');return time.time()
 token_action.authority.clock=current_time
 timer=threading.Timer(max(0,decision['expiresAt']-time.time()),stop.set);timer.daemon=True;timer.start()
 try:
  installed=GovernedSemanticOwnerContinuation(token_action,*args);worker=installed.install()
  def worker_emit(value):
   snapshot[0]=worker.r.journal.read()if value.startswith('OUF_POLICY_TOKEN_OWNER_STATUS=')else snapshot[0]
   emit(value)
  def run_worker():
   try:serve(worker,stop,OwnerReporter(worker.r.journal,worker_emit))
   except BaseException as error:failure.append(type(error).__name__);stop.set()
  thread=threading.Thread(target=run_worker,name='finite-compatibility-policy-owner',daemon=True);thread.start()
  emit('OUF_COMPATIBILITY_POLICY_STARTED='+encoded({'contextPath':str(context),'workerJournal':str(journal),
   'authorityHash':token_action.authority_hash,'priorControlledGrantAttempts':248,'maximumNewTokenGrantAttempts':68,
   'maximumCumulativeGrantAttempts':316,'expiresAt':decision['expiresAt'],'budgetReset':False}).decode())
  until=time.monotonic()+90
  while True:
   require(not stop.is_set()and not failure,'REMAINDER_POLICY_OWNER_STOPPED_BEFORE_UPDATE')
   row=snapshot[0]or{}
   if row.get('state')=='ACTIVE'and row.get('publicationCount',0)>=1 and row.get('tokenExpiresWall',0)>time.time()+30:break
   require(time.monotonic()<until,'FIRST_REMAINDER_POLICY_PUBLICATION_NOT_READY');stop.wait(.5)
  rollout=Path(tempfile.mkdtemp(prefix='onboarding-audit-execution-',dir=context.parent));rollout.chmod(0o700)
  plan['authorityDirectory']=str(rollout);publish_json(rollout,'execution-plan.json',plan)
  active_review,expiry=current_policy(runtime_case,closure,read,prepared)
  execute_prepared_update(prepared,closure,runtime_case,rollout,plan,human,active_review,expiry,read,emit)
  emit('OUF_COMPATIBILITY_SESSION_PHASE=KEEP_POLICY_OWNER_RUNNING_FOR_THS_RESUME technical=8/8 functional=1/6')
  while not stop.wait(1):require(not failure and snapshot[0]is not None and snapshot[0].get('state')in('ACTIVE','NEW','RETRY_WAIT'),'REMAINDER_POLICY_OWNER_NO_LONGER_ACTIVE')
 finally:
  stop.set();timer.cancel()
  if 'thread'in locals():thread.join(45)
  for sig,handler in handlers.items():signal.signal(sig,handler)
 emit('OUF_COMPATIBILITY_SESSION_ENDED=NO_AUTOMATIC_RESTART_OR_RESET')
