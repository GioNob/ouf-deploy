"""Explicit fresh authentication within the same 256-attempt test ceiling."""
import copy,os,time,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused,PROFILE,CLIENT,SCOPES
from tools.chat_recovery_update.owner import require,digest,encoded
from tools.linked_property_rollout.preparation import publish_json
from tools.chat_recovery_update import authority

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
  'Segue un APPROVO per backup, migrazione UDP V36 e aggiornamento UDP/MCP; nessun worker policy.',login=True)
 now=time.time();require(decision['reviewHash']==digest(review)and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and decision['approvedAt']<=now<decision['approvedAt']+60 and decision['expiresAt']==decision['approvedAt']+7200,'EXACT_LOGIN_WINDOW_CONSENT_REQUIRED')
 destination=human.directory.parent/('human-chat-recovery-successor-'+digest(review))
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
