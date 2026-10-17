"""Finite generic CSV recovery: policy owner, native reviewed job retries, proof.

Application behavior is generic. The pinned case selects one already-approved
job set; no source-domain heuristic or implicit identity decision exists here.
"""
import copy,os,signal,threading,time
from datetime import datetime
from pathlib import Path
import iam_governance_intake as governance
from cutover_authority import CutoverAuthority
from engine_creation import Engine
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.semantic_policy_token_owner.worker_entry import serve
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.continued_owner import GovernedSemanticOwnerContinuation,TOKEN_STAGE_SOURCE
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.chatbot_file_cohort.authorization import OwnerTransport
from tools.semantic_mcp_update.entry import retained_registry
from tools.teatri_materialization_apply import preflight,permissions
from tools.teatri_materialization_apply.native import runtime
from tools.teatri_materialization_apply.owner import require,digest,encoded
from tools.teatri_materialization_apply.preparation import publish_json
from tools.csv_materialization_recovery import authority,retry,continuation
from tools.csv_materialization_recovery.journal import synchronize,report_guard_errors

def main(prepared,sources,closure,case,context,read,ns,emit):
 authority.closure_valid(closure);context=Path(context);selected=case['preparedPlanBinding']
 private=read(selected['path'],8388608,selected['sha256'])
 require(private['schema']=='ouf.csv-last-row-prepared-plan.v1'and private['readyForExecution']is False
  and private['runtimeAuthorityIssued']is False and private['maximumJobRetries']==1,'EXACT_PRIVATE_SINGLE_JOB_PLAN_REQUIRED')
 binding=private['rolloutReviewBinding'];update=read(binding['path'],8388608,binding['sha256']);root=Path(binding['path']).parent
 update_plan=read(root/'execution-plan.json',8388608);record=read(root/'recovery.json',131072)
 require(digest(update_plan)==private['rolloutPlanHash']and update['scopes']['linkedPropertyUpdate']['planHash']==digest(update_plan)
  and record['version']==55 and record['incidentState']=='RECOVERED','COMPLETED_LINKED_PROPERTY_ROLLOUT55_REQUIRED')
 issued=read(root/'authority.json',131072);scope=update['scopes']['linkedPropertyUpdate']
 require(record['scopeHash']==digest(scope)and record['authorityHash']==digest(issued)and issued['linkedPropertyUpdate']==scope
  and record['nextStage']==len(record['effects'])==len(scope['stages'])and [e['stage']for e in record['effects']]==scope['stages']
  and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':scope['planHash'],'stage':e['stage']})for e in record['effects']),
  'EXACT_COMPLETE_RETAINED_ROLLOUT_LINKS_REQUIRED')
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 admin=NamespaceAdmin(engine,update_plan['gateway']['transport']);routes=update_plan['gateway']['afterRoutes']
 proofs=record['effects'][-1]['evidence']['applications']
 pins={**update_plan['unchangedApplications'],**{m:proofs[m]['runtimeBinding']for m in('udp','onboarding')}}
 def guard_apps():
  require(admin.routes()==routes,'GATEWAY_CHANGED_SINCE_PREPARED_ROLLOUT')
  for pin in pins.values():
   status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
   require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'RECOVERY_APPLICATION_GENERATION_CHANGED')
  require(read(root/'recovery.json',131072)==record,'ROLLOUT_RECORD_CHANGED')
 selection=prepared['authorization']['plan']['selection'];one=permissions.job(private['job'],case['issueId'])
 def guard_job():
  found=preflight.sql_fact(prepared,ns,closure['executables']['docker'],'udp',permissions.job_query(one,selection['tenant']))
  permissions.verify_job(found['jobs'],private['job'])
 guard_apps();guard_job()
 future=private['workerReview'];compiled=private['workerScope'];prior=private['workerPredecessorRecords'];journal=Path(prior['journalPath'])
 records={n:read(journal/n,131072,prior['hashes'][n])for n in('recovery.json','owner-session.json','owner-admission.json','owner-status.json')}
 first=read(journal/'owner-first-grant.json',16384,records['recovery.json']['firstGrantReceiptHash'])
 require(read(Path(compiled['predecessorFenceBinding']['path']),16384)==compiled['predecessorFenceBinding']['value'],'PREPARED_PREDECESSOR_FENCE_CHANGED')
 policy={'delays':[5,15,60,300,900],'max_attempts':126,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
 require(compile_governed_session(future,records,first,policy,digest({'operation':future['logicalOperation'],'reviewHash':digest(future)}),digest(future['registryGeneration']),60)==compiled
  and compiled['predecessorGrantAttempts']==318 and compiled['maximumCumulativeGrantAttempts']==444,'EXACT_PREPARED318_TO444_SCOPE_REQUIRED')
 authority.current_authorities(int(time.time())+3610)
 hb=private['human']['sessionBinding'];human=HumanSession(selection,Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
 require(digest(human._read())==private['human']['journalBinding']['sha256']and human._read()['binding']==hb,'PREPARED_HUMAN_JOURNAL_CHANGED')
 require(hb['retryProfile']['maximumAttempts']==256 and private['human']['attempts']==160 and 'udp.materialization.retry'in hb['scopes'],'PRESERVED160_OF256_ISSUER_SCOPE_REQUIRED')
 from tools.teatri_materialization_apply import login
 signal.alarm(0)
 human=login.authenticate(human,{'preparedReview':selected},context,closure,read,emit);hb=human.current()
 require('udp.materialization.retry'in hb['scopes'],'RECOVERY_SCOPE_MUST_BE_VERIFIED_BY_ISSUER')
 transport=OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
 active=transport.active()
 permission=permissions.compile_review(active,one,selection,hb,time.time(),context,digest(closure))
 next_journal=Path(compiled['fenceBinding']['value']['journalPath'])
 publish_json(context,'candidate-review.json',future);worker_binding={'path':str(context/'candidate-review.json'),'sha256':digest(future)}
 with protected_directory(next_journal.parent)as directory:os.mkdir(next_journal.name,0o700,dir_fd=directory);os.fsync(directory)
 expected={'sourceClosureHash':digest(closure),'creationRequestHash':digest(future),'predecessorHistoryHash':digest(future['predecessorRecordHashes']),
  'predecessorIncidentRef':compiled['logicalOwnerScopeHash'],'intakeHash':digest(future)}
 verifier=DetachedAuthenticator(governance.POLICY,str(context),closure['executables']['openssl'])
 absent={'path':str(context/'UNISSUED-human.json'),'sha256':digest({'unissued':True})}
 unissued=AggregateAction(CutoverAuthority(verifier,absent,absent['sha256'],governance.CONTEXT,expected),encoded({'unissued':True}),digest(closure))
 files={name:sources[module]for name,module in TOKEN_STAGE_SOURCE.items()}
 args=(prepared['owner'],files,closure['declaration']['sourceCommit'],future,records,first,worker_binding,prepared['engine'],next_journal)
 planned=GovernedSemanticOwnerContinuation(unissued,*args)
 require(planned.worker_scope==compiled and future['retainedOwnerInputsHash']==digest(prepared['owner']),'EXACT_CURRENT_TOKEN_OWNER_SCOPE_REQUIRED')
 retained_registry(planned)
 review=authority.compile_action_review('POLICY_TEST_SESSION',closure,planned.scopes(),hb,context,
  {'predecessorHistoryHash':digest(future['predecessorRecordHashes']),'predecessorIncidentRef':compiled['logicalOwnerScopeHash']},3600)
 review.update(absoluteExpiresAt=min(permission['absoluteExpiresAt'],hb['expiresAt']-5),
  workerReviewBinding=worker_binding,nativeRecoveryPlanBinding=selected,permissionReview=permission,
  nativeRetryIntent=permissions.retry_intent(one,digest(selected)),maximumOwnerPolicyMutations=2,maximumNativeJobPosts=1,
  identityDecisionsAllowed=False,serviceUpdatesAllowed=False,iamChangesAllowed=False)
 publish_json(context,'permission-review.json',permission);publish_json(context,'review.json',review)
 stop=threading.Event();handlers={};worker_thread=None;timer=None;runtime_started=False
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:stop.set())
 human.start_refresh(stop,emit=emit)
 try:
  decision=authority.terminal_consent(review,
   'Recupero dell unico job residuo, dopo la decisione CREATE_NEW gia registrata. Tecniche8/8; funzionali2/6.\n'
   'Una nuova sessione owner rinnova solo il token di lettura policy:318 tentativi conservati, massimo126 nuovi, tetto444 invariato.\n'
   'Policy41 ->42: un solo grant temporaneo per il job '+one['jobId']+', sorgente/run/tipo/label esatti; tutte le voci preesistenti conservate.\n'
   'Massimo una ripresa nativa, solo se l owner conferma versione11, baseline identica e nessun effetto canonico. Snapshot fresco letto dall owner.\n'
   'Nessuna nuova decisione d identita, immagine, servizio, route, IAM, pubblicazione sorgente o reimportazione CSV.\n'
   'Il worker termina al completamento o STOP, entro un ora; nessun riavvio automatico o reset. Ctrl-C interrompe.\n'
   'Revisione privata completa: '+str(context/'review.json'))
  guard_apps();guard_job()
  require(transport.active()==active,'ACTIVE_POLICY_CHANGED_BEFORE_COMPOSED_ACTION')
  action=authority.issue_action(review,decision,human)
  def clock():require(not stop.is_set(),'LAST_ROW_RECOVERY_CANCELLED');return time.time()
  action.authority.clock=clock
  worker=GovernedSemanticOwnerContinuation(action,*args).install();runtime_started=True
  synchronize(worker.r.journal);report_guard_errors(worker,emit)
  timer=threading.Timer(max(0,decision['expiresAt']-time.time()),stop.set);timer.daemon=True;timer.start()
  worker_thread=threading.Thread(target=serve,args=(worker,stop,OwnerReporter(worker.r.journal,emit)),daemon=True);worker_thread.start()
  emit('OUF_LAST_ROW_RECOVERY_STARTED='+encoded({'contextPath':str(context),'workerJournal':str(next_journal),
   'priorControlledGrantAttempts':318,'maximumCumulativeGrantAttempts':444,'maximumNativeJobPosts':1,'expiresAt':decision['expiresAt'],'budgetReset':False}).decode())
  def worker_guard():
   require(not stop.is_set()and time.time()<decision['expiresAt'],'CURRENT_COMPOSED_RECOVERY_WINDOW_REQUIRED')
   human.current();action.guard('policyTokenFiniteWorkerSession',compiled)
   row=worker.r.journal.read()
   require(row['state']in('ACTIVE','ATTEMPTING','PUBLISHING')and row['publicationCount']>=1
    and row['controlledPredecessorGrantAttempts']==318 and row['controlledCumulativeGrantAttempts']==318+row['attempts']<=444
    and row.get('tokenExpiresWall',0)>time.time()+5,'CURRENT_POLICY_PUBLICATION_REQUIRED')
  deadline=min(time.time()+120,decision['expiresAt'])
  while True:
   require(not stop.is_set()and worker_thread.is_alive()and time.time()<deadline,'FIRST_POLICY_PUBLICATION_NOT_PROVEN')
   state=worker.r.journal.read()
   if state['state']=='ACTIVE'and state['publicationCount']>=1:break
   require(state['state']in('NEW','ATTEMPTING','PUBLISHING','ACTIVE'),'POLICY_WORKER_NOT_ACTIVE');stop.wait(1)
  def command_guard():worker_guard();guard_apps()
  command_guard();guard_job()
  published=permissions.publish(transport,human,permission,review,decision,context,command_guard)
  emit('OUF_LAST_ROW_PERMISSION_PUBLISHED='+encoded(published).decode())
  client=retry.Client(transport)
  # Explicit 401/403 are not automatically retried. A denied native read stops before any retry POST.
  native=retry.prepare(client,[one],digest(selected),min(decision['expiresAt'],int(time.time())+900))
  native.update(authenticatedHuman=hb,sourceClosureHash=digest(closure),workerAuthorityHash=action.authority_hash,
   composedReviewHash=digest(review))
  permissions.authorize_fresh_retry(native,review,decision,time.time())
  retry.document(context,'native-retry-review.json',native)
  receipts=retry.dispatch(client,native,decision,context,command_guard,emit,approved_review=review)
  query=retry.proof_query([one],selection['tenant']);end=min(time.time()+600,decision['expiresAt'])
  while True:
   command_guard();proof=preflight.sql_fact(prepared,ns,closure['executables']['docker'],'udp',query)
   complete=proof['jobCount']==proof['materializedRows']==1
   terminal=any(r['job_state']in('QUARANTINED','FAILED')for r in proof['jobs'])
   if complete or terminal or time.time()>=end:break
   emit('OUF_LAST_ROW_COMMIT_WAIT='+encoded({'acceptedRetries':len(receipts),'materializedRows':proof['materializedRows'],'expectedRows':1}).decode());stop.wait(5)
  from tools.csv_materialization_recovery import readback
  whole=preflight.sql_fact(prepared,ns,closure['executables']['docker'],'udp',readback.acquisition_query('udp',selection['tenant']))
  upstream=preflight.sql_fact(prepared,ns,closure['executables']['docker'],'ingestion',readback.ingestion_query('ingestion',selection['tenant']))
  ledger=readback.row_ledger(whole);linked=readback.upstream_matches(upstream,whole)
  stage3=complete and linked and ledger['allThirteenMaterializedProven']and ledger['confirmedElevenMaterialized']and ledger['originalObjectRetained']
  retry.document(context,'materialization-proof.json',{'singleJob':proof,'rowLedger':ledger,'upstreamHandoffsAndLineageMatch':linked,
   'functionalStage3Proven':stage3,'functionalMilestonesProven':3 if stage3 else 2})
  emit('OUF_LAST_ROW_RECOVERY_RESULT='+encoded({'contextPath':str(context),'complete':stage3,'singleJobCommitted':complete,
   'acceptedRetries':len(receipts),'rowLedger':ledger,'upstreamHandoffsAndLineageMatch':linked,'functionalStage3Proven':stage3,
   'functionalMilestonesProven':3 if stage3 else 2,'identityDecisionsPerformed':False,'sourcePublications':0,'budgetReset':False,
   'continuousCredentialLifecycleProven':False}).decode())
 finally:
  stop.set()
  if timer is not None:timer.cancel()
  if worker_thread is not None:worker_thread.join(40)
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
 emit('OUF_LAST_ROW_RECOVERY_ENDED='+encoded({'runtimeStarted':runtime_started,'automaticRestart':False,'budgetReset':False}).decode())
