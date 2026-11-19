"""Explicit native HUMAN capability login; independent of CSV domain values."""
import copy,os,signal,time,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES,LEGACY_SCOPES
from tools.teatri_materialization_apply.owner import require,digest,encoded
from tools.teatri_materialization_apply.preparation import publish_json
from tools.teatri_materialization_apply import authority

def scope_review(human,row,case,closure):
 human._check_identity_and_budget(row)
 require(row['state']=='READY'and row['binding']['scopes']==LEGACY_SCOPES
  and type(row['attempts'])is int and case['minimumPriorOAuthAttempts']<=row['attempts']<256
  and not os.path.lexists(human.directory/'successor-window.claim.json'), 'EXACT_UNCLAIMED_READY_HUMAN_SCOPE_SUCCESSOR_REQUIRED')
 return {'schema':'ouf.human-explicit-capability-scope-review.v4','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorDirectory':str(human.directory),'predecessorRowHash':digest(row),'predecessorBindingHash':digest(row['binding']),
  'selectionHash':digest(human.selection),'priorOAuthAttempts':row['attempts'],'predecessorMaximumCumulativeOAuthAttempts':256,
  'maximumCumulativeOAuthAttempts':256,'maximumRemainingOAuthAttempts':256-row['attempts'],'newWindowSeconds':7200,
  'previousScopes':list(LEGACY_SCOPES),'requestedScopes':list(SCOPES),'requiredCapability':'udp.materialization.retry',
  'freshIssuerAuthenticationRequired':True,'oldCredentialsReusable':False,'failedRefreshReplayAllowed':False,
  'automaticRenewalAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,
  'preparedPlanBinding':copy.deepcopy(case['preparedPlanBinding']),'sourceClosureHash':digest(closure)}

def open_scope_login(human,case,context,closure,read,emit):
 row=human._read();review=scope_review(human,row,case,closure);publish_json(context,'login-review.json',review)
 decision=authority.terminal_consent(review,
  'Login HUMAN per l API generica di ripresa della materializzazione CSV.\n'
  'Richiedo all issuer lo scope udp.materialization.retry, oltre agli scope amministrativi esistenti.\n'
  'OAuth consumati: '+str(row['attempts'])+'; residui: '+str(256-row['attempts'])+'; tetto invariato256.\n'
  'Il vecchio journal resta intatto. Nessuna modifica IAM, grant, route, servizio, job o decisione di identita.\n'
  'Questo consenso apre solo il browser. L issuer deve concedere lo scope: il client non puo autoattribuirselo.\n'
  'Nessun worker parte; durata massima del login7200 secondi, nessun rinnovo automatico.',login=True)
 now=time.time();require(decision.get('reviewHash')==digest(review)and decision.get('decision')=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and decision['approvedAt']<=now<decision['approvedAt']+60 and decision['expiresAt']==decision['approvedAt']+7200,'EXACT_SCOPE_LOGIN_CONSENT_REQUIRED')
 destination=human.directory.parent/('human-capability-successor-'+digest(review))
 with Journal(human.directory).invocation():
  require(read(human.directory/'recovery.json',65536)==row,'HUMAN_PREDECESSOR_CHANGED')
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),'budgetReset':False,'automaticReplayAllowed':False})),
    'HUMAN_CAPABILITY_SUCCESSOR_ALREADY_CLAIMED')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(human.selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  binding={'sessionId':str(uuid.UUID(digest(decision)[:32])),'selectionHash':digest(human.selection),
   **{k:human.selection[k]for k in('subject','issuer','tenant')},'clientId':CLIENT,'scopes':list(SCOPES),
   'tokenPath':str(following.token_path),'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
   'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'bootId':following._boot(),
   'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,'lastObservedAt':time.time(),'attempts':row['attempts'],
   'state':'NEW','budgetReset':False,'governedWindowRenewal':{'review':review,'decision':decision}})
  following._check_identity_and_budget(following._read());require(read(human.directory/'recovery.json',65536)==row,'PREDECESSOR_HISTORY_CHANGED')
 following.login(emit=emit);hb=following.current();result={'schema':'ouf.csv-materialization-recovery-human-login.v1',
  'complete':True,'contextPath':str(context),'authenticatedHuman':hb,'humanDirectory':str(following.directory),
  'attempts':following._read()['attempts'],'maximumCumulativeOAuthAttempts':256,'recoveryScopeIssuerVerified':True,
  'scopeReviewHash':digest(review),'preparedPlanBinding':case['preparedPlanBinding'],'budgetReset':False,
  'iamMutations':0,'grantRequests':0,'jobsRetried':0,'newPolicyWorkerStarted':False,'runtimeAuthorityIssued':False}
 publish_json(context,'review.json',result)
 emit('OUF_CSV_RECOVERY_HUMAN_LOGIN='+encoded({k:v for k,v in result.items()if k!='authenticatedHuman'}|{'reviewPath':str(context/'review.json'),'reviewSha256':digest(result)}).decode())
 return following

def main(prepared,sources,closure,case,context,read,ns,emit):
 selected=case['preparedPlanBinding'];plan=read(selected['path'],8388608,selected['sha256']);hb=plan['authenticatedHuman']
 require(plan['readyForExecution']is False and plan['runtimeAuthorityIssued']is False and plan['newPolicyWorkerStarted']is False
  and plan['jobsRetried']==0 and plan['workerScope']['predecessorGrantAttempts']==316
  and plan['workerScope']['maximumCumulativeGrantAttempts']==444,'EXACT_PRIVATE_PREPARED_NATIVE_RECOVERY_REQUIRED')
 selection=prepared['authorization']['plan']['selection'];require(all(hb[k]==selection[k]for k in('issuer','tenant','subject')),'SAME_REVIEWED_HUMAN_REQUIRED')
 human=HumanSession(selection,Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
 require(human._read()['binding']==hb,'EXACT_CURRENT_HUMAN_BINDING_REQUIRED')
 signal.alarm(0);open_scope_login(human,case,Path(context),closure,read,emit)
