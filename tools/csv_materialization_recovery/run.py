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
from tools.csv_materialization_recovery import authority,retry
from tools.csv_materialization_recovery.journal import synchronize

def main(prepared,sources,closure,case,context,read,ns,emit):
 authority.closure_valid(closure);context=Path(context)
 selected=case['preparedPlanBinding'];plan=read(selected['path'],8388608,selected['sha256'])
 login=read(case['humanReviewBinding']['path'],8388608,case['humanReviewBinding']['sha256'])
 require(login['complete']is True and login['recoveryScopeIssuerVerified']is True and login['preparedPlanBinding']==selected,
  'EXACT_ISSUER_VERIFIED_RECOVERY_HUMAN_REQUIRED')
 hb=login['authenticatedHuman'];selection=prepared['authorization']['plan']['selection']
 require(all(hb[k]==selection[k]for k in('issuer','tenant','subject'))and hb['scopes'][-1]=='udp.materialization.retry','SAME_REVIEWED_HUMAN_AND_CAPABILITY_REQUIRED')
 human=HumanSession(selection,Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
 require(human._read()['binding']==hb,'SAME_SCOPE_LOGIN_BINDING_REQUIRED')
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 update=read(plan['updateReviewBinding']['path'],8388608,plan['updateReviewBinding']['sha256'])
 update_plan=read(Path(update['authorityDirectory'])/'execution-plan.json',8388608)
 require(digest(update_plan)==update['scopes']['udpResolutionUpdate']['planHash'],'COMPLETED_UPDATE_PLAN_CHANGED')
 admin=NamespaceAdmin(engine,update_plan['gateway']['transport'])
 def guard_apps():
  require(digest(admin.routes())==plan['gatewayRoutesHash'],'GATEWAY_GENERATION_CHANGED')
  for pin in {**update_plan['unchangedApplications'],'udp':plan['udpRuntimeBinding']}.values():
   status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
   require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'RECOVERY_APPLICATION_GENERATION_CHANGED')
 guard_apps();jobs=plan['jobs']
 current=preflight.sql_fact(prepared,ns,closure['executables']['docker'],'udp',preflight.jobs_query(selection['tenant']))
 permissions.verify_jobs(current['jobs'],jobs)
 future=plan['workerReview'];journal=Path(future['predecessorJournalDirectory'])
 records={n:read(journal/n,131072,h)for n,h in future['predecessorRecordHashes'].items()};first=read(journal/'owner-first-grant.json',16384)
 policy={'delays':[5,15,60,300,900],'max_attempts':128,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
 compiled=compile_governed_session(future,records,first,policy,digest({'operation':future['logicalOperation'],'reviewHash':digest(future)}),digest(future['registryGeneration']),60)
 require(compiled==plan['workerScope']and future['retainedOwnerInputsHash']==digest(prepared['owner']),'EXACT_PREPARED316_PLUS128_WORKER_SCOPE_REQUIRED')
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
 planned=GovernedSemanticOwnerContinuation(unissued,*args);require(planned.worker_scope==compiled,'EXACT_SCOPED_POLICY_WORKER_REQUIRED');retained_registry(planned)
 grant_expiry=int(datetime.fromisoformat(case['maximumGrantExpiry'].replace('Z','+00:00')).timestamp())
 require(time.time()+300<grant_expiry,'TEMPORARY_JOB_GRANTS_TOO_CLOSE_TO_EXPIRY')
 authority.current_authorities(min(int(time.time())+3600,grant_expiry,human.expires_at-5));signal.alarm(0)
 human.refresh_if_due();hb=human.current()
 review=authority.compile_action_review('POLICY_TEST_SESSION',closure,planned.scopes(),hb,context,
  {'predecessorHistoryHash':digest(future['predecessorRecordHashes']),'predecessorIncidentRef':compiled['logicalOwnerScopeHash']},3600)
 review['absoluteExpiresAt']=min(grant_expiry,human.expires_at-5);review['workerReviewBinding']=worker_binding
 review['nativeRecoveryPlanBinding']=selected;publish_json(context,'review.json',review)
 stop=threading.Event();handlers={};worker_thread=None;timer=None
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:stop.set())
 human.start_refresh(stop,emit=emit)
 try:
  decision=authority.terminal_consent(review,
   'Sessione worker per completare il collaudo del flusso CSV generico. Tecniche8/8; funzionali2/6.\n'
   '316 tentativi controllati conservati; massimo128 ulteriori, cumulativo444. Nessun reset o replay del primo grant.\n'
   'Il worker termina comunque entro la scadenza dei permessi temporanei: '+case['maximumGrantExpiry']+'.\n'
   'Questo APPROVO avvia solo il token policy. Seguono letture native degli11 job e APPROVO separato per la loro ripresa.\n'
   'Nessun cambio servizi, IAM, grant o identita. Lascia aperto il terminale; Ctrl-C cancella.\n'
   'Revisione privata: '+str(context/'review.json'))
  guard_apps();action=authority.issue_action(review,decision,human)
  def clock():require(not stop.is_set(),'CSV_RECOVERY_CANCELLED');return time.time()
  action.authority.clock=clock
  worker=GovernedSemanticOwnerContinuation(action,*args).install()
  synchronize(worker.r.journal)
  timer=threading.Timer(max(0,decision['expiresAt']-time.time()),stop.set);timer.daemon=True;timer.start()
  worker_thread=threading.Thread(target=serve,args=(worker,stop,OwnerReporter(worker.r.journal,emit)),daemon=True);worker_thread.start()
  emit('OUF_CSV_RECOVERY_POLICY_STARTED='+encoded({'contextPath':str(context),'workerJournal':str(next_journal),'priorControlledGrantAttempts':316,
   'maximumCumulativeGrantAttempts':444,'expiresAt':decision['expiresAt'],'budgetReset':False}).decode())
  def worker_guard():
   require(not stop.is_set()and time.time()<decision['expiresAt'],'CURRENT_NATIVE_RECOVERY_WINDOW_REQUIRED')
   human.current();row=worker.r.journal.read()
   require(row['state']in('ACTIVE','ATTEMPTING','PUBLISHING')and row['publicationCount']>=1 and row['controlledPredecessorGrantAttempts']==316
    and row['controlledCumulativeGrantAttempts']==316+row['attempts']<=444 and row.get('tokenExpiresWall',0)>time.time()+5,
    'CURRENT_POLICY_PUBLICATION_REQUIRED')
  deadline=min(time.time()+120,decision['expiresAt'])
  while True:
   require(not stop.is_set()and worker_thread.is_alive()and time.time()<deadline,'FIRST_POLICY_PUBLICATION_NOT_PROVEN')
   state=worker.r.journal.read()
   if state['state']=='ACTIVE'and state['publicationCount']>=1:break
   require(state['state']in('NEW','ATTEMPTING','PUBLISHING','ACTIVE'),'POLICY_WORKER_NOT_ACTIVE');stop.wait(1)
  worker_guard();guard_apps()
  client=retry.Client(OwnerTransport(selection,human.token_path,human.token_path,human_session=human))
  for read_attempt in range(1,5):
   try:
    job_review=retry.prepare(client,jobs,digest(selected),min(decision['expiresAt'],int(time.time())+900));break
   except ValueError as error:
    if str(error)!='NATIVE_RECOVERY_HTTP_403'or read_attempt==4:raise
    emit('OUF_CSV_OWNER_POLICY_WAIT='+encoded({'readAttempt':read_attempt,'maximumReadAttempts':4,'jobMutations':0}).decode());stop.wait(15);worker_guard()
  job_review.update(authenticatedHuman=hb,sourceClosureHash=digest(closure),workerAuthorityHash=action.authority_hash)
  retry.document(context,'native-retry-review.json',job_review)
  approved=authority.terminal_consent(job_review,
   'Ripresa tecnica degli11 job gia confermati CREATE_NEW attraverso l API nativa generica.\n'
   'Ogni job e stato letto e autorizzato dall owner: contratto disponibile, baseline uguale, versione e snapshot esatti.\n'
   'Massimo11 POST, uno per job, con operationId persistente. Nessun replay dopo risposta incerta.\n'
   'Nessuna decisione di identita ripetuta, modifica diretta al DB o azzeramento dei contatori. Il caso lasciato in quarantena e escluso.\n'
   'Dopo gli ACK verifico job, oggetti, revisioni e contributi. Il worker termina al completamento o allo STOP.\n'
   'Revisione privata: '+str(context/'native-retry-review.json'))
  retry.document(context,'native-retry-decision.json',approved)
  def dispatch_guard():worker_guard();guard_apps()
  receipts=retry.dispatch(client,job_review,approved,context,dispatch_guard,emit)
  query=retry.proof_query(jobs,selection['tenant']);end=min(time.time()+600,decision['expiresAt'])
  while True:
   worker_guard();guard_apps();proof=preflight.sql_fact(prepared,ns,closure['executables']['docker'],'udp',query)
   complete=proof['jobCount']==proof['distinctObjects']==proof['materializedRows']==len(jobs)
   terminal=any(r['job_state']in('QUARANTINED','FAILED')for r in proof['jobs'])
   if complete or terminal or time.time()>=end:break
   emit('OUF_CSV_MATERIALIZATION_WAIT='+encoded({'acceptedRetries':len(receipts),'materializedRows':proof['materializedRows'],'expectedRows':len(jobs)}).decode());stop.wait(5)
  retry.document(context,'materialization-proof.json',proof)
  emit('OUF_CSV_MATERIALIZATION_RECOVERY_RESULT='+encoded({'contextPath':str(context),'complete':complete,
   'acceptedRetries':len(receipts),'confirmedObjectsMaterialized':complete,'proof':proof,'identityDecisionsPerformed':False,
   'deferredCaseRetried':False,'newPolicyWorkerStarted':True,'budgetReset':False,'functionalMilestonesProven':2}).decode())
 finally:
  stop.set()
  if timer is not None:timer.cancel()
  if worker_thread is not None:worker_thread.join(40)
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
 emit('OUF_CSV_RECOVERY_ENDED=NO_AUTOMATIC_RESTART_OR_RESET')
