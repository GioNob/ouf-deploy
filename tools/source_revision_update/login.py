"""Explicit fresh authentication within the same 256-attempt test ceiling."""
import copy,os,time,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused,PROFILE,CLIENT,SCOPES
from tools.source_revision_update.owner import require,digest,encoded
from tools.linked_property_rollout.preparation import publish_json
from tools.source_revision_update import authority

LEGACY_SCOPES=['openid','authorization.policy.admin','mcp.connect','authorization.permissions.read','authorization.permissions.propose','authorization.proposal.read']

def qualify(human,row,case,closure):
 human._check_identity_and_budget(row);now=time.time()
 expired=now>=human.expires_at and time.monotonic()>=row['monotonicDeadline']
 blocked=row['state']=='BLOCKED'and row.get('operation')=='REFRESH'and row.get('reason')=='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN'
 require((expired and row['state']=='READY' or blocked)and now+2>=row['lastObservedAt']
  and type(row['attempts'])is int and 129<=row['attempts']<256,'ONLY_EXPIRED_OR_DEFINITIVE_BLOCKED_TEST_LOGIN_ALLOWED')
 require(not os.path.lexists(human.directory/'successor-window.claim.json'),'HUMAN_SUCCESSOR_ALREADY_CLAIMED_RECONCILE')
 return {'schema':'ouf.human-explicit-test-continuation-review.v3','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorDirectory':str(human.directory),'predecessorBindingHash':digest(row['binding']),
  'predecessorRowHash':digest(row),'selectionHash':digest(human.selection),'priorOAuthAttempts':row['attempts'],
  'predecessorMaximumCumulativeOAuthAttempts':256,'maximumCumulativeOAuthAttempts':256,
  'maximumRemainingOAuthAttempts':256-row['attempts'],'newWindowSeconds':7200,'budgetReset':False,
  'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'oldCredentialsReusable':False,
  'automaticRenewalAllowed':False,'runtimeAuthorityIssued':False,'operationBinding':{
   'preparedReviewHash':case['preparedPlanBinding']['sha256'],'sourceClosureHash':digest(closure)}}

def authenticate(human,case,context,closure,read,emit):
 row=human._read();human._check_identity_and_budget(row)
 if row['state']!='BLOCKED'and time.time()<human.expires_at:
  try:human.refresh_if_due();human.current();return human
  except HumanSessionPaused as error:
   if error.reason!='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN':raise
 row=human._read();review=qualify(human,row,case,closure);publish_json(context,'login-review.json',review)
 decision=authority.terminal_consent(review,
  'Nuovo login HUMAN dopo scadenza o refresh definitivamente rifiutato. Il vecchio journal resta intatto.\n'
  'OAuth consumati: '+str(row['attempts'])+'; residui: '+str(256-row['attempts'])+'; massimo cumulativo invariato256.\n'
  'Durata7200 secondi, nessun rinnovo automatico. Questo consenso apre solo il browser; non pubblica permessi e non aggiorna servizi.\n'
  'Segue un APPROVO per backup, migrazione Onboarding V34, aggiornamento Onboarding/MCP, due rotte e i relativi permessi nativi; nessuna pubblicazione del profilo.',login=True)
 now=time.time();require(decision['reviewHash']==digest(review)and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and decision['approvedAt']<=now<decision['approvedAt']+60 and decision['expiresAt']==decision['approvedAt']+7200,'EXACT_LOGIN_WINDOW_CONSENT_REQUIRED')
 destination=human.directory.parent/('human-source-revision-successor-'+digest(review))
 with Journal(human.directory).invocation():
  require(read(human.directory/'recovery.json',65536)==row,'HUMAN_PREDECESSOR_CHANGED')
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),'budgetReset':False,'automaticReplayAllowed':False})),
    'HUMAN_SUCCESSOR_ALREADY_CLAIMED_RECONCILE')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(human.selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  binding={'sessionId':str(uuid.UUID(digest(decision)[:32])),'selectionHash':digest(human.selection),
   **{k:human.selection[k]for k in('subject','issuer','tenant')},'clientId':CLIENT,'scopes':list(SCOPES),
   'tokenPath':str(following.token_path),'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
   'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'bootId':following._boot(),
   'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,'lastObservedAt':time.time(),'attempts':row['attempts'],
   'state':'NEW','budgetReset':False,'governedWindowRenewal':{'review':review,'decision':decision}})
  following._check_identity_and_budget(following._read());require(read(human.directory/'recovery.json',65536)==row,'PREDECESSOR_HUMAN_CHANGED')
 following.login(emit=emit);publish_json(context,'login-window-receipt.json',{'directory':str(destination),'expiresAt':following.expires_at,
  'reviewHash':digest(review),'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'budgetReset':False})
 return following


def historical_row(human,row):
 """Validate immutable preboot evidence only; never make it a current session."""
 binding=row.get('binding',{});now=time.time()
 require(row.get('schema')=='ouf.chatbot-human-session.private.v1'
  and binding.get('selectionHash')==digest(human.selection)
  and all(binding.get(k)==human.selection[k] for k in ('issuer','subject','tenant'))
  and binding.get('clientId')==CLIENT and binding.get('scopes') in (SCOPES, LEGACY_SCOPES)
  and binding.get('tokenPath')==str(human.token_path) and binding.get('sessionDirectory')==str(human.directory)
  and binding.get('expiresAt')==human.expires_at and binding.get('retryProfile')==PROFILE
  and row.get('budgetReset')is False,'POSTBOOT_HUMAN_STATIC_IDENTITY_DRIFT')
 require(type(row.get('bootId'))is str and row['bootId'] and row['bootId']!=human._boot()
  and now>=human.expires_at and type(row.get('lastObservedAt'))in(int,float) and now+2>=row['lastObservedAt'],
  'ONLY_EXPIRED_PREBOOT_HUMAN_HISTORY_ALLOWED')
 require(type(row.get('attempts'))is int and 129<=row['attempts']<PROFILE['maximumAttempts'],
  'POSTBOOT_HUMAN_CUMULATIVE_BUDGET_UNAVAILABLE')
 renewal=row.get('governedWindowRenewal',{});review=renewal.get('review',{});decision=renewal.get('decision',{});prior=review.get('priorOAuthAttempts')
 v2=(review.get('schema')=='ouf.human-explicit-test-budget-review.v2' and review.get('predecessorMaximumCumulativeOAuthAttempts')==128 and type(prior)is int and 124<=prior<=128)
 v3=(review.get('schema')=='ouf.human-explicit-test-continuation-review.v3' and review.get('predecessorMaximumCumulativeOAuthAttempts')==256 and type(prior)is int and 129<=prior<256 and review.get('freshIssuerAuthenticationRequired')is True and review.get('failedRefreshReplayAllowed')is False and review.get('budgetReset')is False)
 v4=(review.get('schema')=='ouf.human-explicit-capability-scope-review.v4' and review.get('predecessorMaximumCumulativeOAuthAttempts')==256 and type(prior)is int and 129<=prior<256 and review.get('requestedScopes')==SCOPES and review.get('previousScopes')==LEGACY_SCOPES and binding.get('scopes')==SCOPES and review.get('freshIssuerAuthenticationRequired')is True and review.get('budgetReset')is False)
 require((v2 or v3 or v4) and review.get('purpose')=='CONFIGURATION_AND_VALIDATION'
  and review.get('maximumCumulativeOAuthAttempts')==PROFILE['maximumAttempts'] and row['attempts']>=prior
  and decision.get('reviewHash')==digest(review) and binding.get('createdAt')==decision.get('approvedAt')
  and binding.get('expiresAt')==decision.get('expiresAt') and type(decision.get('approvedAt'))is int
  and decision['expiresAt']-decision['approvedAt']==PROFILE['maximumElapsedSeconds'],
  'POSTBOOT_HUMAN_RENEWAL_HISTORY_UNPROVEN')


def historical_human(case,selection,read):
 """Follow only the four pinned historical references; return no live authority."""
 reference=case['postbootHumanHistory'];expected=reference['sessions']
 require(reference.get('schema')=='ouf.source-revision-expired-preboot-history.v1' and len(expected)==4 and reference['maximumCumulativeOAuthAttempts']==PROFILE['maximumAttempts']
  and reference['remainingOAuthAttempts']==81,'EXACT_POSTBOOT_HISTORY_PROFILE_REQUIRED')
 review=read(case['humanReviewBinding']['path'],8388608,case['humanReviewBinding']['sha256']);hb=review['authenticatedHuman']
 snapshots={};boot=None;last_attempts=-1
 for index,pin in enumerate(expected):
  human=HumanSession(selection,Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
  row=human._read();historical_row(human,row)
  if boot is None:boot=human._boot()
  require(human._boot()==boot and row['binding']==hb and str(human.directory)==pin['directory']
   and digest(hb)==pin['bindingSha256'] and row['attempts']==pin['attempts'] and row['attempts']>=last_attempts,
   'PINNED_POSTBOOT_HUMAN_HISTORY_CHANGED')
  snapshots[str(human.directory/'recovery.json')]=row;last_attempts=row['attempts'];path=human.directory/'successor-window.claim.json'
  if index==len(expected)-1:
   require(not os.path.lexists(path) and row['state']=='READY' and row['attempts']==175 and row['binding']['scopes']==SCOPES,
    'POSTBOOT_LEAF_CONSUMED_OR_UNPROVEN')
   break
  claim=read(path,65536);destination=Path(claim['destination']);following=read(destination/'recovery.json',65536)
  require(destination.parent==human.directory.parent and destination!=human.directory and claim['budgetReset']is False,
   'EXACT_POSTBOOT_SUCCESSOR_PATH_REQUIRED')
  renewal=following.get('governedWindowRenewal',{})
  require(digest(renewal.get('review'))==claim['reviewHash'] and digest(renewal.get('decision'))==claim['decisionHash']
   and following['binding']['sessionDirectory']==str(destination) and following['attempts']>=row['attempts'],
   'POSTBOOT_SUCCESSOR_LINK_UNPROVEN')
  snapshots[str(path)]=claim;hb=following['binding']
 for path,value in snapshots.items():require(read(path,65536)==value,'POSTBOOT_HISTORY_CHANGED_DURING_READ')
 return human,{'row':row,'snapshots':snapshots,'currentBoot':boot,'reference':reference}


def authenticate_postboot(human,history,case,context,closure,read,emit):
 """New native consent and fresh issuer login; old session is never refreshed."""
 row=history['row'];historical_row(human,row)
 require(human._boot()==history['currentBoot'] and human._read()==row and not os.path.lexists(human.directory/'successor-window.claim.json'),
  'POSTBOOT_HISTORY_OR_CLAIM_CHANGED')
 for path,value in history['snapshots'].items():require(read(path,65536)==value,'POSTBOOT_HISTORY_CHANGED')
 review={'schema':'ouf.human-explicit-test-continuation-review.v3','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorDirectory':str(human.directory),'predecessorBindingHash':digest(row['binding']),
  'predecessorRowHash':digest(row),'selectionHash':digest(human.selection),'priorOAuthAttempts':row['attempts'],
  'predecessorMaximumCumulativeOAuthAttempts':256,'maximumCumulativeOAuthAttempts':256,
  'maximumRemainingOAuthAttempts':256-row['attempts'],'newWindowSeconds':7200,'budgetReset':False,
  'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'oldCredentialsReusable':False,
  'automaticRenewalAllowed':False,'runtimeAuthorityIssued':False,
  'postbootContinuation':{'schema':'ouf.human-expired-preboot-continuation.v1',
   'historyReferenceHash':digest(history['reference']),'predecessorBootSha256':digest(row['bootId']),
   'currentBootSha256':digest(history['currentBoot']),'oldMonotonicDeadlineReused':False},
  'operationBinding':{'preparedReviewHash':case['preparedPlanBinding']['sha256'],'sourceClosureHash':digest(closure)}}
 publish_json(context,'login-review.json',review)
 decision=authority.terminal_consent(review,
  'Nuovo login HUMAN dopo riavvio: storia preboot verificata, sessioni precedenti scadute e non riutilizzabili.\n'
  'OAuth consumati175; residui81; massimo cumulativo invariato256. Nuova finestra7200secondi sul boot corrente.\n'
  'Questo consenso apre solo il login; il successivo APPROVO riguarda backup, Flyway V34, Onboarding/MCP e due rotte.\n'
  'Il ruolo resta da confermare nella THS. Nessuna pubblicazione del profilo o acquisizione CSV.',login=True)
 now=time.time();require(decision['reviewHash']==digest(review)and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and decision['approvedAt']<=now<decision['approvedAt']+60 and decision['expiresAt']==decision['approvedAt']+7200,
  'EXACT_POSTBOOT_LOGIN_CONSENT_REQUIRED')
 destination=human.directory.parent/('human-source-revision-postboot-successor-'+digest(review))
 with Journal(human.directory).invocation():
  require(human._boot()==history['currentBoot'],'POSTBOOT_LOGIN_BOOT_CHANGED')
  for path,value in history['snapshots'].items():require(read(path,65536)==value,'POSTBOOT_HISTORY_CHANGED_BEFORE_CLAIM')
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),'budgetReset':False,'automaticReplayAllowed':False})),
    'POSTBOOT_HUMAN_SUCCESSOR_ALREADY_CLAIMED_RECONCILE')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(human.selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  binding={'sessionId':str(uuid.UUID(digest(decision)[:32])),'selectionHash':digest(human.selection),
   **{k:human.selection[k]for k in('subject','issuer','tenant')},'clientId':CLIENT,'scopes':list(SCOPES),
   'tokenPath':str(following.token_path),'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
   'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'bootId':history['currentBoot'],
   'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,'lastObservedAt':time.time(),'attempts':row['attempts'],
   'state':'NEW','budgetReset':False,'governedWindowRenewal':{'review':review,'decision':decision}})
  following._check_identity_and_budget(following._read());require(human._read()==row,'PREBOOT_JOURNAL_CHANGED')
 following.login(emit=emit)
 publish_json(context,'login-window-receipt.json',{'directory':str(destination),'expiresAt':following.expires_at,
  'reviewHash':digest(review),'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,
  'budgetReset':False,'postbootFreshLogin':True})
 return following
