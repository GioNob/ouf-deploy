"""One explicit test worker session, then separately approved readiness rollout."""
import copy,json,os,signal,threading,time
from pathlib import Path
import iam_binding_candidate as evidence
import iam_governance_intake as governance
from cutover_authority import CutoverAuthority
from engine_creation import Engine
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from tools.semantic_policy_token_owner.worker_entry import serve
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.continued_owner import GovernedSemanticOwnerContinuation,TOKEN_STAGE_SOURCE
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,MOUNT_SET_BINDING,private_config
from tools.semantic_mcp_update.entry import publish_json,retained_registry
from tools.semantic_mcp_update import session
from tools.ingestion_readiness_update import authority,plan as compiler
from tools.ingestion_readiness_update.owner import ReadinessUpdate,UpdatePaused,require,digest,encoded,scope
from tools.ingestion_readiness_update.native import NativePorts,runtime

def worker_review(base,private,resources):
 review=copy.deepcopy(base);records=resources['workerRecords'];old=records['recovery.json'];previous=records['owner-session.json']
 require(old['attempts']==60 and old['controlledCumulativeGrantAttempts']==188 and previous['maximumCumulativeGrantAttempts']==197,'EXACT_OBSERVED188_HISTORY_REQUIRED')
 review.update(schema='ouf.chatbot-semantic-functional-session-review.v3',preparedAt=int(time.time()),
  predecessorRecordHashes={k:digest(v)for k,v in records.items()},predecessorJournalDirectory=resources['workerJournal'],
  predecessorFenceBinding=copy.deepcopy(previous['fenceBinding']),finiteTestProfile=copy.deepcopy(private['finiteTestProfile']))
 review['proposedFiniteBudget'].update(priorControlledGrantAttempts=188,predecessorWorkerAttempts=60,
  maximumNewTokenGrantAttempts=128,maximumCumulativeGrantAttempts=316,maximumSeconds=3600,renewalIntervalSeconds=60,automaticRenewalAllowed=False)
 review['requiredOwnerDecision'].update(explicitNewTestBudgetRequired=True,newCumulativeCeilingRequiresFreshHumanDecision=True)
 review.update(runtimeAuthorityIssued=False,humanApprovalGranted=False,readyForExecution=False)
 return review

def prepare_execution(prepared,private,binding,context,selection,engine):
 actuals={name:engine.request('GET','/v1.44/containers/'+row['oldRuntimeBinding']['containerId']+'/json')for name,row in private['images'].items()}
 for name,(status,value)in actuals.items():
  require(status==200 and value['State']['Running']is True and runtime(value)==private['images'][name]['oldRuntimeBinding'],'CURRENT_REVIEWED_APPLICATION_CHANGED')
 status,gateway=engine.request('GET','/v1.44/containers/'+private['gateway']['currentGatewayRuntimeBinding']['containerId']+'/json')
 require(status==200 and gateway['State']['Running']is True and runtime(gateway)==private['gateway']['currentGatewayRuntimeBinding'],'CURRENT_REVIEWED_GATEWAY_CHANGED')
 mounts=[m for m in gateway['Mounts']if m['Destination']==selection['gatewayConfigMountTarget']]
 require(len(mounts)==1 and mounts[0]['Type']=='bind'and mounts[0]['RW']is False,'EXACT_SELECTED_GATEWAY_CONFIG_REQUIRED')
 transport=NamespaceAdmin.observe(engine,mounts[0]['Source'],MOUNT_SET_BINDING);admin=NamespaceAdmin(engine,transport)
 _,projection=private_config(private['gateway']['targetProjectionBinding']['path'],private['gateway']['targetProjectionBinding'])
 routes=admin.routes()
 plan=compiler.compile_plan(private,binding,context,{n:v for n,(_,v)in actuals.items()},transport,routes,selection['applications'])
 plan['programs']=copy.deepcopy(selection['programs'])
 require(admin.routes()==routes,'GATEWAY_CHANGED_DURING_EXECUTION_PREPARATION')
 for name,(_,value)in actuals.items():
  status,after=engine.request('GET','/v1.44/containers/'+value['Id']+'/json')
  require(status==200 and runtime(after)==runtime(value),'APPLICATION_CHANGED_DURING_EXECUTION_PREPARATION')
 return plan

def main(prepared,sources,closure,resources,context,emit=print):
 authority.closure_valid(closure);context=Path(context);private=resources['privateReview'];binding=resources['privateReviewBinding']
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 plan=prepare_execution(prepared,private,binding,context,resources['executionSelection'],engine)
 publish_json(context,'execution-plan.json',plan)
 review=worker_review(resources['baseWorkerReview'],private,resources)
 worker_binding={'path':str(context/'worker-review.json'),'sha256':digest(review)};publish_json(context,'worker-review.json',review)
 records=resources['workerRecords'];first=resources['firstGrant'];policy={'delays':[5,15,60,300,900],'max_attempts':128,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
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
 planned=GovernedSemanticOwnerContinuation(unissued,*args);require(planned.worker_scope==worker_scope,'EXACT_COMPILED_TEST_WORKER_REQUIRED');retained_registry(planned)
 authority.current_authorities(int(time.time())+3610)
 previous_path=Path(resources['previousHumanDirectory']);previous=HumanSession(prepared['authorization']['plan']['selection'],previous_path,previous_path/'human-access.jwt',resources['previousHumanExpiry'])
 login_review=session.expired_login_review(previous,{'workerReviewHash':digest(review),'rolloutPlanHash':digest(plan),'sourceClosureHash':digest(closure)})
 publish_json(context,'login-review.json',login_review)
 consent=authority.terminal_consent(login_review,
  'Fasi tecniche8/8; funzionali1/6. Nuova finestra di login HUMAN, nessun reset.\n'
  'OAuth gia consumati: '+str(login_review['priorOAuthAttempts'])+'; residui: '+str(login_review['maximumRemainingOAuthAttempts'])+'.\n'
  'Seguono browser e due APPROVO separati: worker policy, poi aggiornamento di Onboarding/Ingestion e una route GET.',login=True)
 human=session.open_approved_login(previous,login_review,consent);publish_json(context,'login-window-receipt.json',{'directory':str(human.directory),'expiresAt':human.expires_at,'reviewHash':digest(login_review),'budgetReset':False})
 hb=human.login(emit=emit);retained_registry(planned)
 token_review=authority.compile_action_review('POLICY_TEST_SESSION',closure,planned.scopes(),hb,context,
  {'predecessorHistoryHash':digest(review['predecessorRecordHashes']),'predecessorIncidentRef':worker_scope['logicalOwnerScopeHash']},3600)
 token_review['rolloutPrivateReviewBinding']=copy.deepcopy(binding);token_review['workerReviewBinding']=worker_binding
 publish_json(context,'review.json',token_review)
 decision=authority.terminal_consent(token_review,
  'Solo nuova sessione worker policy per configurazione e collaudo. Tecniche8/8; funzionali1/6.\n'
  '188 tentativi controllati conservati; massimo128 nuovi, cumulativo316; durata massima3600 secondi.\n'
  'Nessun rinnovo automatico, replay del primo grant, rotazione credenziale o modifica grant.\n'
  'Dopo il primo token segue APPROVO separato per il rollout. Questo terminale resta aperto sul PC.\n'
  'Revisione privata: '+str(context/'review.json'))
 token_action=authority.issue_action(token_review,decision,human)
 stop=threading.Event();failure=[];snapshot=[None];handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:stop.set())
 def current_time():require(not stop.is_set(),'READINESS_SESSION_CANCELLED');return time.time()
 token_action.authority.clock=current_time
 timer=threading.Timer(max(0,decision['expiresAt']-time.time()),stop.set);timer.daemon=True;timer.start()
 try:
  installed=GovernedSemanticOwnerContinuation(token_action,*args);worker=installed.install()
  def worker_emit(value):
   # Only the owner thread reads its CAS journal; the rollout observes an
   # immutable completed snapshot and cannot contend with a grant transaction.
   snapshot[0]=worker.r.journal.read()if value.startswith('OUF_POLICY_TOKEN_OWNER_STATUS=')else None
   emit(value)
  def run_worker():
   try:serve(worker,stop,OwnerReporter(worker.r.journal,worker_emit))
   except BaseException as error:failure.append(type(error).__name__);stop.set()
  thread=threading.Thread(target=run_worker,name='finite-policy-owner',daemon=True);thread.start()
  emit('OUF_READINESS_POLICY_STARTED='+encoded({'contextPath':str(context),'workerJournal':str(journal),
   'authorityHash':token_action.authority_hash,'priorControlledGrantAttempts':188,'maximumCumulativeGrantAttempts':316,
   'expiresAt':decision['expiresAt'],'budgetReset':False}).decode())
  until=time.monotonic()+90
  while True:
   require(not stop.is_set()and not failure,'POLICY_OWNER_STOPPED_BEFORE_ROLLOUT')
   row=snapshot[0]or{}
   if row.get('state')=='ACTIVE'and row.get('publicationCount',0)>=1 and row.get('tokenExpiresWall',0)>time.time()+30:break
   require(time.monotonic()<until,'FIRST_POLICY_PUBLICATION_NOT_READY');stop.wait(.5)
  # New finite context allows independent exact review and two-role signatures.
  rollout=context.parent/('ingestion-readiness-execution-'+digest({'tokenContext':str(context),'planHash':digest(plan)})[:16])
  with protected_directory(context.parent)as directory:os.mkdir(rollout.name,0o700,dir_fd=directory);os.fsync(directory)
  plan['authorityDirectory']=str(rollout)
  publish_json(rollout,'execution-plan.json',plan)
  final=authority.compile_action_review('INGESTION_READINESS_UPDATE',closure,{'ingestionReadinessUpdate':scope(plan)},human.current(),rollout,
   {'predecessorHistoryHash':binding['sha256'],'predecessorIncidentRef':plan['logicalUpdateRef']},900)
  publish_json(rollout,'review.json',final)
  approval=authority.terminal_consent(final,
   'Aggiornamento Onboarding e Ingestion, piu una sola nuova route Gateway GET. Tecniche8/8; funzionali1/6.\n'
   'Vecchi container fermati e conservati; stessi mount, ambiente, rete, IP e MAC.\n'
   'Nessuna migrazione database, modifica grant, proposta semantica o ripetizione delle approvazioni sorgente.\n'
   'Un tentativo per modifica; esito incerto richiede riconciliazione. Massimo900 secondi.\n'
   'Dopo il rollout resta da riprendere e verificare la sorgente nel THS.\n'
   'Revisione privata: '+str(rollout/'review.json'))
  require(not stop.is_set(),'POLICY_SESSION_NOT_LIVE');retained_registry(installed)
  action=authority.issue_action(final,approval,human)
  def rollout_time():
   now=current_time();latest=snapshot[0]or{}
   require(thread.is_alive()and not failure and latest.get('publicationCount',0)>0
    and latest.get('state')not in('BLOCKED','CANCELLED','PAUSED_EXHAUSTED')
    and latest.get('tokenExpiresWall',0)>now+5,'CURRENT_FINITE_POLICY_PUBLICATION_REQUIRED')
   return now
  action.authority.clock=rollout_time
  ports=NativePorts(action,engine,plan);update=ReadinessUpdate(action,Journal(rollout),plan,ports);update.initialize()
  while True:
   try:
    result=update.run();emit('OUF_READINESS_UPDATE_RESULT='+encoded({**result,'contextPath':str(rollout),'completedTechnicalPhases':8,'functionalMilestonesProven':1}).decode());break
   except UpdatePaused as paused:
    require(str(paused)=='READINESS_RETRY_WAIT','READINESS_UPDATE_RECONCILIATION_REQUIRED')
    row=update.record();emit('OUF_READINESS_UPDATE_WAIT='+encoded({'stage':row['effects'][-1]['stage'],'attempts':row['readinessAttempts'],'nextReadAt':row['nextReadAt']}).decode())
    stop.wait(min(5,max(0,row['nextReadAt']-time.time())))
  emit('OUF_READINESS_UPDATE_PHASE=KEEP_POLICY_OWNER_RUNNING_FOR_THS_RESUME technical=8/8 functional=1/6')
  while not stop.wait(1):
   require(not failure and snapshot[0]is not None and snapshot[0].get('state')in('ACTIVE','RETRY_WAIT','NEW'),'POLICY_OWNER_NO_LONGER_ACTIVE')
 finally:
  stop.set();timer.cancel()
  if 'thread'in locals():thread.join(45)
  for sig,handler in handlers.items():signal.signal(sig,handler)
 emit('OUF_READINESS_SESSION_ENDED=NO_AUTOMATIC_RESTART_OR_RESET')
