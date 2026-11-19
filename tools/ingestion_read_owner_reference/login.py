"""One explicitly consented fresh login251 and new7200s window; cumulative256 retained; no old refresh.
Pause after device creation releases the session invocation lock before waiting
for HUMAN completion. Resume then performs the first provider token request.
"""
import copy,os,stat,termios,time,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES
from tools.chatbot_file_cohort.review import terminal_line,terminal_answer
from tools.ingestion_read_owner_reference.owner import require,encoded,digest
EXPIRES=1792436155
DRAFT_HASH='2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec'
class AwaitingHumanCompletion(Exception):pass

def terminal_phrase(summary,phrase):
 fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
 try:
  require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
  termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,('\n'+summary+'\nScrivi: '+phrase+'\n> ').encode())
  for attempt in range(1,4):
   raw,count=terminal_line(fd);accepted,detail=terminal_answer(raw,phrase.encode('ascii'),count)
   if accepted:return
   os.write(fd,b'\n'+encoded({'status':'NOT_ACCEPTED','attempt':attempt,**detail})+b'\n> ')
  raise ValueError('EXACT_HUMAN_PHRASE_REQUIRED')
 finally:os.close(fd)


def qualify(human,row,closure,logical_ref):
 human._check_identity_and_budget(row)
 require(row['state']=='READY'and row['attempts']==259 and row['budgetReset']is False
  and row['binding']['retryProfile']['maximumAttempts']==264 and row['binding']['expiresAt']==EXPIRES
  and row['binding']['scopes']==SCOPES and len(SCOPES)==11 and PROFILE['maximumAttempts']==272
  and time.time()>=row['lastObservedAt']and time.time()>=EXPIRES and time.monotonic()>=row['monotonicDeadline']
  and not os.path.lexists(human.directory/'successor-window.claim.json')
  and closure['declaration']['moduleCount']==232,'EXACT_EXPIRED_READY259_PREDECESSOR_REQUIRED')
 return {'schema':'ouf.human-ingestion-owner-rollout-budget-review.v6','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorMaximumCumulativeOAuthAttempts':264,'priorOAuthAttempts':259,'maximumCumulativeOAuthAttempts':272,
  'maximumAdditionalRequestsFromCurrentCount':13,'increaseOverPreviousMaximum':8,
  'predecessorWindowExpiresAt':EXPIRES,'newWindowSeconds':7200,'requestedScopes':copy.deepcopy(SCOPES),
  'freshIssuerAuthenticationRequired':True,'sourceClosureHash':digest(closure),'logicalOperationRef':logical_ref,
  'predecessorBindingHash':digest(row['binding']),'predecessorWindowReviewHash':digest(row['governedWindowRenewal']['review']),
  'oldCredentialsReusable':False,'oldRefreshReplayAllowed':False,'automaticRenewalAllowed':False,'budgetReset':False,
  'runtimeAuthorityIssued':False,'humanValidatorVersion':'ouf.human.ingestion-owner-rollout272.v6','humanSourceChanged':True,
  'draftPlanHash':DRAFT_HASH,'separateOwnerConsentRequired':True,'separateRuntimeAndGatewayConsentsRequired':True}

def authenticate(selection,binding,context,closure,publish_json,emit,case):
 human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();review=qualify(human,row,closure,case['logicalRef']);publish_json(context,'login-review.json',review)
 terminal_phrase('Nuova autenticazione HUMAN distinta per il piano Ingestion gia compilato.\n'
  '259 consumati conservati. Massimo264 a272 (+8 sul limite;13richieste residue). Nessun reset.\n'
  'Apro una NUOVA finestra7200secondi soltanto da questo consenso; la vecchia20:55:55 resta scaduta e conservata.\n'
  'Validatore v6 SOLO nel nuovo pacchetto;11scope invariati. Vecchi token/refresh/device non vengono usati.\n'
  'Login FRESCO, stesso HUMAN e verifica provider/userinfo; il provider puo negare.\n'
  'Questo consenso non autorizza effetti owner o runtime: seguira un APPROVO owner distinto.\n'
  'Dopo URL/codice pausa senza lock o polling fino a LOGIN COMPLETATO. Dopo STOP non rilanciare.', 'APPROVO BUDGET272 '+digest(review))
 now=time.time();decision={'schema':'ouf.human-ingestion-owner-rollout-budget-decision.v6','reviewHash':digest(review),
  'approvedAt':int(now),'expiresAt':int(now)+7200,'decision':'APPROVE_EXACT272_AND_NEW7200_WINDOW_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'}
 publish_json(context,'login-decision.json',decision)
 destination=human.directory.parent/('human-ingestion-owner-rollout272-'+digest(review))
 with human.journal.invocation():
  require(human._read()==row,'HUMAN259_CHANGED_DURING_BUDGET_REVIEW');qualify(human,row,closure,case['logicalRef'])
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),'windowExpiresAt':decision['expiresAt'],
    'predecessorMaximumCumulativeOAuthAttempts':264,'maximumCumulativeOAuthAttempts':272,'priorOAuthAttempts':259,
    'budgetReset':False,'automaticReplayAllowed':False,'newWindowAllowed':True})),'HUMAN259_SUCCESSOR_ALREADY_CLAIMED')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  new_binding={**copy.deepcopy(binding),'sessionId':str(uuid.UUID(digest(decision)[:32])),
   'sessionDirectory':str(destination),'tokenPath':str(following.token_path),'createdAt':decision['approvedAt'],'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':new_binding,'bootId':row['bootId'],
   'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,'lastObservedAt':now,'attempts':259,'state':'NEW','budgetReset':False,
   'governedWindowRenewal':{'review':review,'decision':decision},'predecessorWindowReviewHash':review['predecessorWindowReviewHash']})
  following._check(following._read());require(human._read()==row,'PREDECESSOR259_JOURNAL_CHANGED')
 case['humanBinding']=new_binding
 def device_emit(value):
  emit(value)
  if value.startswith('ENTER_DEVICE_CODE='):raise AwaitingHumanCompletion()
 try:following.login(emit=device_emit)
 except AwaitingHumanCompletion:
  pending=following._read();following._check(pending)
  require(pending['state']=='DEVICE_POLL'and pending['attempts']==261,'EXACT_UNPOLLED_DEVICE261_REQUIRED')
  terminal_phrase('Completa il login nel browser. Nessuna richiesta token e ancora stata fatta.\n'
   'La pausa e senza lock d invocazione. Conferma solo dopo successo nel browser.', 'LOGIN COMPLETATO '+digest(review))
  require(following._read()==pending and time.time()<pending['deviceDeadline'],'DEVICE261_CHANGED_OR_EXPIRED_DURING_HUMAN_WAIT')
  following.login(emit=emit)
 fresh=following._read();require(following.current()==new_binding and 263<=fresh['attempts']<=272
  and fresh['binding']['expiresAt']==decision['expiresAt'] and fresh['monotonicDeadline']>row['monotonicDeadline']
  and human._read()==row,'EXACT_VERIFIED272_WITH_EXPLICIT_NEW_WINDOW_REQUIRED')
 receipt={'schema':'ouf.ingestion-owner-rollout-budget272-receipt.v1','directory':str(destination),'reviewHash':digest(review),
  'expiresAt':decision['expiresAt'],'priorOAuthAttempts':259,'oauthAttemptsAfter':fresh['attempts'],'predecessorMaximumCumulativeOAuthAttempts':264,
  'maximumCumulativeOAuthAttempts':272,'newWindowOpened':True,'predecessorWindowExpiresAt':EXPIRES,'humanSourceChanged':True,'oldRefreshReplayed':False,
  'runtimeAuthorityIssued':False,'budgetReset':False}
 publish_json(context,'login-window-receipt.json',receipt);emit('OUF_INGESTION_OWNER_HUMAN='+encoded(receipt).decode());return following
