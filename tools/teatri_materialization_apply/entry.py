"""Consume a completed private review: native grants, then one UDP update.

Two distinct exact HUMAN decisions. No new worker, identity decision, job retry,
IAM change, database migration or Gateway write is reachable in this command.
"""
import copy,os,signal,threading,time
from pathlib import Path
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.chatbot_file_cohort.authorization import OwnerTransport
from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.teatri_materialization_apply import authority,permissions,preflight,login
from tools.teatri_materialization_apply.preparation import publish_json
from tools.teatri_materialization_apply.owner import require,digest,encoded,scope,ReadinessUpdate,UpdatePaused
from tools.teatri_materialization_apply.native import NativePorts,runtime

def retained_plan(case,read):
 selected=case['preparedReview'];private=read(selected['path'],8388608,selected['sha256'])
 parent=Path(selected['path']).parent
 require(parent.parent==Path('/etc/ouf/deploy-snapshots')and parent.name=='teatri-materialization-review-f1gfuxtz'
  and private['readyForExecution']is False and private['runtimeAuthorityIssued']is False,'EXACT_PRIVATE_PREPARED_REVIEW_REQUIRED')
 b=private['preparedPlanBinding'];require(b['path']==str(parent/'prepared-plan.json'),'EXACT_PREPARED_PLAN_PATH_REQUIRED')
 plan=read(b['path'],8388608,b['sha256']);scope(plan)
 require(plan['replacements']['udp']['request']['Image']=='sha256:9d0c76828beef09591d71d552dd688d07c3e5081f70be46d6bf5269eca9a8792'
  and private['imageAudit']==plan['replacements']['udp']['imageAudit']and private['beforeUdpPin']==plan['replacements']['udp']['oldRuntimeBinding']
  and private['imageArchive']==plan['replacements']['udp']['imageArchive']and private['migrationFilesUnchanged']is True,
  'EXACT_QUALIFIED_UDP_IMAGE_AND_PLAN_REQUIRED')
 permissions.verify_jobs(private['recoveryPreflight']['jobs']['jobs'],case['confirmedJobs'])
 h=private['recoveryPreflight']['workerHistory']
 require(h['state']=='CANCELLED'and h['attempts']==8 and h['controlledCumulativeGrantAttempts']==316
  and h['remainingControlledGrantAttempts']==0,'EXACT_EXHAUSTED316_WORKER_HISTORY_REQUIRED')
 return private,plan

def current_jobs(prepared,ns,program,case):
 found=preflight.sql_fact(prepared,ns,program,'udp',preflight.jobs_query('ouf-lab'))
 require(found['transactionReadOnly']is True and found['confirmedJobCount']==11 and found['distinctContractSets']==1,'EXACT_ELEVEN_CONFIRMED_JOBS_REQUIRED')
 permissions.verify_jobs(found['jobs'],case['confirmedJobs']);return found['jobs']

def main(prepared,sources,closure,case,context,read,ns,emit):
 authority.closure_valid(closure);context=Path(context);private,plan=retained_plan(case,read)
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 require(plan['engine']==prepared['engine']and plan['programs']['docker']==closure['executables']['docker'],'RETAINED_EXECUTION_CHANNEL_CHANGED')
 admin=NamespaceAdmin(engine,plan['gateway']['transport']);routes=plan['gateway']['beforeRoutes']
 def guard():
  require(admin.routes()==routes,'GATEWAY_CHANGED_SINCE_PRIVATE_PREPARATION')
  for pin in {**plan['unchangedApplications'],'udp':plan['replacements']['udp']['oldRuntimeBinding']}.values():
   status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
   require(status==200 and actual['State']['Running']is True and runtime(actual)==pin,'PREPARED_APPLICATION_GENERATION_CHANGED')
 guard();jobs=current_jobs(prepared,ns,closure['executables']['docker'],case)
 # Verify all infrastructure authorities before presenting either consent.
 authority.current_authorities(int(time.time())+910)
 human_review=read(case['currentHumanReview']['path'],8388608,case['currentHumanReview']['sha256']);hb=human_review['authenticatedHuman']
 selection=prepared['authorization']['plan']['selection'];human=HumanSession(selection,Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
 require(human._read()['binding']==hb,'EXACT_CURRENT_HUMAN_BINDING_REQUIRED')
 signal.alarm(0);human=login.authenticate(human,case,context,closure,read,emit);hb=human.current()
 transport=OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
 active=transport.active();permission_review=permissions.compile_review(active,jobs,selection,hb,time.time(),context,digest(closure))
 publish_json(context,'permission-review.json',permission_review)
 cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 human.start_refresh(cancelled,emit=emit)
 try:
  decision=authority.terminal_consent(permission_review,
   'Permessi temporanei per riprendere gli11 job Teatri gia confermati CREATE_NEW. Tecniche8/8; funzionali2/6.\n'
   'Policy40 ->41:11 grant per questo operatore, ciascuno limitato a un job, alla sorgente Teatri e ai dati RESTRICTED.\n'
   'Scadenza massima un ora, entro la finestra HUMAN. Grant preesistenti, ruoli e descrittori conservati. Nessuna modifica IAM.\n'
   'Questa decisione pubblica solo i permessi tramite API owner; non riprende i job e non avvia worker.\n'
   'Segue APPROVO separato per la sola immagine UDP gia preparata. Il caso lasciato in quarantena resta escluso.\n'
   'Revisione privata: '+str(context/'permission-review.json'))
  publish_json(context,'permission-decision.json',decision)
  def publication_guard():
   require(not cancelled.is_set(),'PERMISSION_PUBLICATION_CANCELLED');guard()
   current_jobs(prepared,ns,closure['executables']['docker'],case)
  result=permissions.publish(transport,human,permission_review,decision,context,publication_guard)
  emit('OUF_TEATRI_RECOVERY_PERMISSION_RESULT='+encoded({**result,'contextPath':str(context)}).decode())
  # No policy renewal worker starts here; the already staged image is reused.
  guard();plan=copy.deepcopy(plan);plan.update(authorityDirectory=str(context),humanBinding=human.current())
  scope(plan);publish_json(context,'execution-plan.json',plan)
  seconds=min(900,human.expires_at-int(time.time())-10);require(seconds>=300,'HUMAN_WINDOW_TOO_SHORT_FOR_UDP_UPDATE')
  review=authority.compile_action_review('UDP_RESOLUTION_UPDATE',closure,{'udpResolutionUpdate':scope(plan)},plan['humanBinding'],context,
   {'predecessorHistoryHash':digest(private),'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
  review['absoluteExpiresAt']=human.expires_at-5;review['permissionPublicationBinding']={'path':str(context/'permission-publication.json'),'sha256':digest(result)}
  review['preparedReviewBinding']=case['preparedReview'];publish_json(context,'review.json',review)
  decision=authority.terminal_consent(review,
   'Aggiornamento del solo UDP con l immagine gia qualificata e preparata sul VPS. Tecniche8/8; funzionali2/6.\n'
   'Consente la ripresa tecnica mantenendo le11 decisioni CREATE_NEW; nessun job viene ripreso in questo comando.\n'
   'Vecchio UDP fermato e conservato; stessi mount, ambiente, rete, IP e MAC. Nessun download immagini.\n'
   'Onboarding, Ingestion e Gateway invariati. Nessuna migrazione DB, modifica IAM, nuovo worker o decisione di identita.\n'
   'Un tentativo per effetto, massimo15 minuti. In caso di STOP non rilanciare; conserva il log.\n'
   'Revisione privata: '+str(context/'review.json'))
  guard();action=authority.issue_action(review,decision,human)
  def clock():require(not cancelled.is_set(),'UDP_UPDATE_CANCELLED');return time.time()
  action.authority.clock=clock
  ports=NativePorts(action,engine,plan,human);update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  while True:
   try:
    result=update.run();emit('OUF_TEATRI_MATERIALIZATION_UPDATE_RESULT='+encoded({**result,'contextPath':str(context),
     'maximumGatewayWrites':0,'newPolicyWorkerStarted':False,'identityDecisionsPerformed':False,'jobsRetried':0,
     'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode());break
   except UpdatePaused as error:
    require(str(error)=='READINESS_RETRY_WAIT','UDP_UPDATE_RECONCILIATION_REQUIRED');row=update.record()
    emit('OUF_TEATRI_MATERIALIZATION_UPDATE_WAIT='+encoded({'stage':row['effects'][-1]['stage'],'attempts':row['readinessAttempts'],'nextReadAt':row['nextReadAt']}).decode())
    cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
 finally:
  cancelled.set()
  if human.thread is not None:human.thread.join(35)
  for sig,handler in handlers.items():signal.signal(sig,handler)
