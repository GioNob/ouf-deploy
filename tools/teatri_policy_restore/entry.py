"""One reviewed eight-attempt remainder; no application or domain mutations."""
import copy,hashlib,os,signal,threading,time,uuid
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
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES
from tools.semantic_mcp_update.entry import publish_json,retained_registry
from tools.onboarding_audit_update.owner import require,digest,encoded
from tools.teatri_policy_restore import authority
from tools.semantic_lease_recovery.recovery_journal import Journal
from iam_owner_action import publish

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

def budget_review(hb,row,operation):
 require(row.get('state')=='BLOCKED'and row.get('operation')=='REFRESH'
  and row.get('reason')=='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN'
  and row.get('binding')==hb and type(row.get('attempts'))is int and 124<=row['attempts']<=128
  and row.get('budgetReset')is False and hb.get('retryProfile',{}).get('maximumAttempts')==128,
  'EXACT_RECEIVED_BLOCKED_REFRESH_REQUIRED')
 return {'schema':'ouf.human-explicit-test-budget-review.v2','predecessorDirectory':hb['sessionDirectory'],
  'predecessorRowHash':digest(row),'predecessorBindingHash':digest(hb),'selectionHash':hb['selectionHash'],
  'priorOAuthAttempts':row['attempts'],'predecessorMaximumCumulativeOAuthAttempts':128,
  'maximumCumulativeOAuthAttempts':256,'maximumRemainingOAuthAttempts':256-row['attempts'],
  'newWindowSeconds':7200,'purpose':'CONFIGURATION_AND_VALIDATION','operationBinding':operation,
  'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,
  'oldCredentialsReusable':False,'automaticRenewalAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False}

def open_test_successor(selection,hb,row,case,context,read,emit):
 review=budget_review(hb,row,{'workerReviewHash':digest(read(context/'worker-review.json',131072)),
  'failedPreparationContextHash':digest(case['failedPreparationContext'])})
 publish_json(context,'login-review.json',review)
 decision=authority.terminal_consent(review,
  'Nuovo login HUMAN dopo il refresh rifiutato. Il vecchio journal resta BLOCKED e non viene modificato.\n'
  'Solo configurazione/collaudo: '+str(row['attempts'])+' richieste OAuth conservate; nuovo massimo cumulativo256, residuo'+str(256-row['attempts'])+'.\n'
  'Durata7200 secondi, nessun rinnovo automatico. Questo consenso apre solo il login, non il worker.\n'
  'Seguono browser e APPROVO separato per il solo worker308+8=316.',login=True)
 require(decision.get('schema')=='ouf.human-login-window-terminal-consent.v1'
  and decision.get('reviewHash')==digest(review)and decision.get('decision')=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and type(decision.get('approvedAt'))is int and decision['approvedAt']<=time.time()<decision['approvedAt']+60
  and decision.get('expiresAt')==decision['approvedAt']+7200,'EXACT_TEST_LOGIN_BUDGET_CONSENT_REQUIRED')
 previous=Path(hb['sessionDirectory']);destination=previous.parent/('human-test-successor-'+digest(review))
 with Journal(previous).invocation():
  require(read(previous/'recovery.json',65536)==row,'BLOCKED_HUMAN_CHANGED_BEFORE_BUDGET_REVIEW')
  claim={'schema':'ouf.human-successor-window-claim.v1','reviewHash':digest(review),'decisionHash':digest(decision),
   'destination':str(destination),'budgetReset':False,'automaticReplayAllowed':False}
  with protected_directory(previous)as directory:require(publish(directory,'successor-window.claim.json',encoded(claim)),'SUCCESSOR_LOGIN_ALREADY_CLAIMED_RECONCILIATION_REQUIRED')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  human=HumanSession(selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  binding={'sessionId':str(uuid.UUID(digest(decision)[:32])),'selectionHash':digest(selection),
   **{k:selection[k]for k in('subject','issuer','tenant')},'clientId':CLIENT,'scopes':list(SCOPES),
   'tokenPath':str(human.token_path),'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
   'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  human.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'bootId':human._boot(),
   'monotonicDeadline':time.monotonic()+decision['expiresAt']-time.time(),'lastObservedAt':time.time(),
   'attempts':row['attempts'],'state':'NEW','budgetReset':False,'governedWindowRenewal':{'review':review,'decision':decision}})
  human._check_identity_and_budget(human._read())
  require(read(previous/'recovery.json',65536)==row,'PREDECESSOR_HUMAN_HISTORY_CHANGED')
 human.login(emit=emit)
 publish_json(context,'login-window-receipt.json',{'directory':str(destination),'expiresAt':human.expires_at,
  'reviewHash':digest(review),'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'budgetReset':False})
 return human

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
 directory=Path(hb['sessionDirectory']);row=read(directory/'recovery.json',65536)
 require(row['binding']==hb and row.get('budgetReset')is False and row['state']=='BLOCKED'
  and row.get('operation')=='REFRESH'and row.get('reason')=='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN'
  and type(row.get('attempts'))is int and 124<=row['attempts']<=128
  and hb.get('retryProfile',{}).get('maximumAttempts')==128
  and not os.path.lexists(directory/'successor-window.claim.json'),'EXACT_BLOCKED_HUMAN_HISTORY_REQUIRED')
 failed=Path(case['failedPreparationContext'])
 require(failed.parent==context.parent and failed.name=='teatri-policy-restore-execution-oy3axaz7'
  and not any(os.path.lexists(failed/n)for n in('review.json','authority.json','human.json','decision.json','issuance.claim.json')),
  'EXACT_PRE_AUTHORITY_FAILED_PREPARATION_REQUIRED')
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
 human=open_test_successor(prepared['authorization']['plan']['selection'],hb,row,case,context,read,emit)
 hb=human.current()
 final=authority.compile_action_review('POLICY_TEST_SESSION',closure,planned.scopes(),hb,context,
  {'predecessorHistoryHash':digest(review['predecessorRecordHashes']),'predecessorIncidentRef':worker_scope['logicalOwnerScopeHash']},3600)
 final['workerReviewBinding']=binding;final['absoluteExpiresAt']=min(int(time.time())+600,human.expires_at-5)
 publish_json(context,'review.json',final)
 decision=authority.terminal_consent(final,
  'Ripristino del solo token di lettura policy Registry. Tecniche8/8; funzionali2/6.\n'
  '308 tentativi conservati, massimo8 ulteriori, cumulativo invariato316; durata massima10 minuti.\n'
  'Nessun reset, replay del primo grant, modifica permessi o aggiornamento servizi.\n'
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
