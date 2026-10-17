"""One reviewed eight-attempt remainder; no application or domain mutations."""
import copy,hashlib,os,signal,threading,time
from pathlib import Path
import iam_governance_intake as governance
from cutover_authority import CutoverAuthority
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session
from tools.semantic_policy_token_owner.worker_entry import serve
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from tools.chatbot_file_cohort.continued_owner import GovernedSemanticOwnerContinuation,TOKEN_STAGE_SOURCE
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.semantic_mcp_update.entry import publish_json,retained_registry
from tools.onboarding_audit_update.owner import require,digest,encoded
from tools.teatri_policy_restore import authority

def remainder_review(base,records,journal):
 old=records['recovery.json'];previous=records['owner-session.json']
 require(old.get('state')=='CANCELLED'and old.get('reason')=='CANCELLED_BY_OWNER'
  and old.get('attempts')==old.get('publicationCount')==60
  and old.get('controlledPredecessorGrantAttempts')==248
  and old.get('controlledCumulativeGrantAttempts')==308
  and old.get('workerSessionHash')==digest(previous)
  and previous.get('predecessorGrantAttempts')==248 and previous.get('maximumCumulativeGrantAttempts')==316,
  'EXACT_OBSERVED_CANCELLED308_HISTORY_REQUIRED')
 review=copy.deepcopy(base)
 review.update(schema='ouf.chatbot-semantic-functional-session-review.v3',preparedAt=int(time.time()),
  predecessorRecordHashes={k:digest(v)for k,v in records.items()},predecessorJournalDirectory=str(journal),
  predecessorFenceBinding=copy.deepcopy(previous['fenceBinding']),
  finiteTestProfile={'schema':'ouf.policy-token-test-session-profile.v1','maximumNewTokenGrantAttempts':8,
   'maximumSeconds':3600,'renewalIntervalSeconds':60,'automaticRenewalAllowed':False,
   'purpose':'CONFIGURATION_AND_VALIDATION','preserveCumulativeHistory':True})
 review['proposedFiniteBudget'].update(priorControlledGrantAttempts=308,predecessorWorkerAttempts=60,
  maximumNewTokenGrantAttempts=8,maximumCumulativeGrantAttempts=316,maximumSeconds=3600,renewalIntervalSeconds=60,automaticRenewalAllowed=False)
 review['requiredOwnerDecision'].update(explicitNewTestBudgetRequired=True,newCumulativeCeilingRequiresFreshHumanDecision=True)
 review.update(runtimeAuthorityIssued=False,humanApprovalGranted=False,readyForExecution=False)
 return review

def main(prepared,sources,closure,case,context,read,ns,emit=print):
 authority.closure_valid(closure);context=Path(context);journal=Path(case['workerJournal'])
 records={n:read(journal/n,131072,h)for n,h in case['workerRecordHashes'].items()}
 require(set(records)=={'recovery.json','owner-session.json','owner-admission.json','owner-status.json'},'EXACT_FOUR_WORKER_RECORDS_REQUIRED')
 base=read(journal/'owner-session-review.json',131072,case['workerReviewHash'])
 require(base['retainedOwnerInputsHash']==digest(prepared['owner']),'EXACT_OWNER_INPUTS_REQUIRED')
 review=remainder_review(base,records,journal);first=read(journal/'owner-first-grant.json',16384)
 previous=records['owner-session.json'];require(read(previous['fenceBinding']['path'],16384)==previous['fenceBinding']['value'],'CURRENT_CANCELLED_WORKER_FENCE_REQUIRED')
 reviewed=read(case['currentHumanReview']['path'],8388608,case['currentHumanReview']['sha256']);hb=reviewed['authenticatedHuman']
 require(all(hb[k]==prepared['authorization']['plan']['selection'][k]for k in('issuer','tenant','subject')),'EXACT_RETAINED_HUMAN_REQUIRED')
 directory=Path(hb['sessionDirectory']);human=HumanSession(prepared['authorization']['plan']['selection'],directory,Path(hb['tokenPath']),hb['expiresAt'])
 row=human._read();human._check_identity_and_budget(row)
 require(row['binding']==hb and row['state']=='READY'and 124<=row['attempts']<=128
  and not os.path.lexists(directory/'successor-window.claim.json')and time.time()+610<human.expires_at,
  'CURRENT_READY_HUMAN_WINDOW_REQUIRED')
 policy={'delays':[5,15,60,300,900],'max_attempts':8,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
 worker_scope=compile_governed_session(review,records,first,policy,digest({'operation':review['logicalOperation'],'reviewHash':digest(review)}),digest(review['registryGeneration']),60)
 next_journal=Path(worker_scope['fenceBinding']['value']['journalPath'])
 publish_json(context,'worker-review.json',review);binding={'path':str(context/'worker-review.json'),'sha256':digest(review)}
 with protected_directory(next_journal.parent)as directory_fd:os.mkdir(next_journal.name,0o700,dir_fd=directory_fd);os.fsync(directory_fd)
 expected={'sourceClosureHash':digest(closure),'creationRequestHash':digest(review),'predecessorHistoryHash':digest(review['predecessorRecordHashes']),'predecessorIncidentRef':worker_scope['logicalOwnerScopeHash'],'intakeHash':digest(review)}
 verifier=DetachedAuthenticator(governance.POLICY,str(context),closure['executables']['openssl'])
 absent={'path':str(context/'UNISSUED-human.json'),'sha256':digest({'unissued':True})}
 unissued=AggregateAction(CutoverAuthority(verifier,absent,absent['sha256'],governance.CONTEXT,expected),encoded({'unissued':True}),digest(closure))
 files={name:sources[module]for name,module in TOKEN_STAGE_SOURCE.items()}
 args=(prepared['owner'],files,closure['declaration']['sourceCommit'],review,records,first,binding,prepared['engine'],next_journal)
 planned=GovernedSemanticOwnerContinuation(unissued,*args);require(planned.worker_scope==worker_scope,'EXACT_308_PLUS8_SCOPE_REQUIRED');retained_registry(planned)
 authority.current_authorities(int(time.time())+610);signal.alarm(0)
 # The existing native HUMAN governor counts every request and never renews its window.
 human.refresh_if_due();hb=human.current();require(human._read()['attempts']<=128,'PRESERVED_HUMAN_CEILING_REQUIRED')
 final=authority.compile_action_review('POLICY_TEST_SESSION',closure,planned.scopes(),hb,context,
  {'predecessorHistoryHash':digest(review['predecessorRecordHashes']),'predecessorIncidentRef':worker_scope['logicalOwnerScopeHash']},3600)
 final['workerReviewBinding']=binding;final['absoluteExpiresAt']=min(int(time.time())+600,human.expires_at-5)
 publish_json(context,'review.json',final)
 decision=authority.terminal_consent(final,
  'Ripristino del solo token di lettura policy Registry. Tecniche8/8; funzionali2/6.\n'
  '308 tentativi conservati, massimo8 ulteriori, cumulativo invariato316; durata massima10 minuti.\n'
  'Nessun nuovo login, reset, replay del primo grant, modifica permessi o aggiornamento servizi.\n'
  'Le11 decisioni e il caso lasciato in quarantena restano invariati; nessuna ripresa dei job in questo comando.\n'
  'Lascia aperto questo terminale. Dopo il primo stato ACTIVE usa il secondo terminale per verificare la lettura semantica.\n'
  'Revisione privata: '+str(context/'review.json'))
 action=authority.issue_action(final,decision,human)
 stop=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:stop.set())
 timer=threading.Timer(max(0,decision['expiresAt']-time.time()),stop.set);timer.daemon=True;timer.start()
 def clock():require(not stop.is_set(),'POLICY_RESTORATION_CANCELLED');return time.time()
 action.authority.clock=clock
 try:
  worker=GovernedSemanticOwnerContinuation(action,*args).install()
  emit('OUF_TEATRI_POLICY_RESTORATION_STARTED='+encoded({'contextPath':str(context),'authorityHash':action.authority_hash,'priorControlledGrantAttempts':308,'maximumNewTokenGrantAttempts':8,'maximumCumulativeGrantAttempts':316,'expiresAt':decision['expiresAt'],'budgetReset':False}).decode())
  serve(worker,stop,OwnerReporter(worker.r.journal,emit))
 finally:
  stop.set();timer.cancel()
  for sig,handler in handlers.items():signal.signal(sig,handler)
 emit('OUF_TEATRI_POLICY_RESTORATION_ENDED=NO_AUTOMATIC_RESTART_OR_RESET')
