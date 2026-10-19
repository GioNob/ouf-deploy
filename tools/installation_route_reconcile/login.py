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
from tools.installation_route_reconcile.owner import require,encoded,digest
EXPIRES=1792436155
ORIGINAL_REVIEW='c0f7490ebe641e8a015e09799f6812eb1caf870388f1776a140a34a189cb11c1'
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
 require(row['state']=='READY'and row['attempts']==255 and row['budgetReset']is False
  and row['binding']['retryProfile']['maximumAttempts']==256 and row['binding']['expiresAt']==EXPIRES
  and row['binding']['scopes']==SCOPES and len(SCOPES)==11 and PROFILE['maximumAttempts']==264
  and time.time()>=row['lastObservedAt']and time.time()<EXPIRES-600 and time.monotonic()<row['monotonicDeadline']
  and row['accessExpiresAt']<=time.time()+5 and not os.path.lexists(human.directory/'successor-window.claim.json')
  and closure['declaration']['moduleCount']==226,'EXACT_EXPIRED_READY255_BUDGET_INSUFFICIENT_REQUIRED')
 review=row['governedWindowRenewal']['review']
 require(digest(review)==ORIGINAL_REVIEW and review['priorOAuthAttempts']==251 and review['maximumCumulativeOAuthAttempts']==256,
  'EXACT_PREDECESSOR251_TO255_CONSENT_REQUIRED')
 return {'schema':'ouf.human-installation-route-budget-review.v5','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorMaximumCumulativeOAuthAttempts':256,'priorOAuthAttempts':255,'maximumCumulativeOAuthAttempts':264,
  'maximumAdditionalRequestsFromCurrentCount':9,'increaseOverPreviousMaximum':8,
  'preservedWindowExpiresAt':EXPIRES,'requestedScopes':copy.deepcopy(SCOPES),
  'freshIssuerAuthenticationRequired':True,'remainingBudgetInsufficientForVerifiedRefresh':True,
  'sourceClosureHash':digest(closure),'logicalOperationRef':logical_ref,'predecessorBindingHash':digest(row['binding']),
  'predecessorWindowReviewHash':ORIGINAL_REVIEW,'oldCredentialsReusable':False,'oldRefreshReplayAllowed':False,
  'automaticRenewalAllowed':False,'budgetReset':False,'newWindowOpened':False,'runtimeAuthorityIssued':False,
  'humanValidatorVersion':'ouf.human.installation-route-reconciliation264.v5','humanSourceChanged':True,
  'separateRouteReconciliationConsentRequired':True}

def authenticate(selection,binding,context,closure,publish_json,emit,case):
 human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();review=qualify(human,row,closure,case['predecessorLogicalRef']);publish_json(context,'login-review.json',review)
 terminal_phrase('Revisione HUMAN distinta del budget per la riconciliazione gia pubblicata e2rotte.\n'
  'Contatore255 conservato. Aumento SOLO il massimo cumulativo256 a264 (+8 sul limite;9richieste residue).\n'
  'Scadenza INVARIATA alle20:55:55 italiane. Nessun reset, estensione temporale o rinnovo automatico.\n'
  'Validatore v5 versionato nel NUOVO pacchetto: sorgente HUMAN modificato esplicitamente per questo profilo264.\n'
  'La vecchia sessione e il suo storico restano immutati; vecchi token/refresh/device non vengono usati.\n'
  'Dopo il consenso faccio un login FRESCO e verifico stesso HUMAN/11scope/userinfo. Il provider puo negare.\n'
  'Questo consenso non autorizza effetti Gateway o journal: seguira un APPROVO separato.\n'
  'Dopo STOP/interruzione non rilanciare.', 'APPROVO BUDGET264 '+digest(review))
 now=time.time();decision={'schema':'ouf.human-installation-route-budget-decision.v5','reviewHash':digest(review),
  'approvedAt':int(now),'expiresAt':EXPIRES,'decision':'APPROVE_EXACT264_BUDGET_WITH_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'}
 publish_json(context,'login-decision.json',decision)
 destination=human.directory.parent/('human-installation-route-budget264-'+digest(review))
 with human.journal.invocation():
  require(human._read()==row,'HUMAN255_CHANGED_DURING_BUDGET_REVIEW');qualify(human,row,closure,case['predecessorLogicalRef'])
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),'windowExpiresAt':EXPIRES,
    'predecessorMaximumCumulativeOAuthAttempts':256,'maximumCumulativeOAuthAttempts':264,'priorOAuthAttempts':255,
    'budgetReset':False,'automaticReplayAllowed':False,'newWindowAllowed':False})),'HUMAN255_SUCCESSOR_ALREADY_CLAIMED')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(selection,destination,destination/'human-access.jwt',EXPIRES)
  new_binding={**copy.deepcopy(binding),'sessionId':str(uuid.UUID(digest(decision)[:32])),
   'sessionDirectory':str(destination),'tokenPath':str(following.token_path),'createdAt':decision['approvedAt'],'expiresAt':EXPIRES,'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':new_binding,'bootId':row['bootId'],
   'monotonicDeadline':row['monotonicDeadline'],'lastObservedAt':now,'attempts':255,'state':'NEW','budgetReset':False,
   'governedWindowRenewal':{'review':review,'decision':decision},'predecessorWindowReviewHash':ORIGINAL_REVIEW})
  following._check(following._read());require(human._read()==row,'PREDECESSOR255_JOURNAL_CHANGED')
 case['humanBinding']=new_binding
 def device_emit(value):
  emit(value)
  if value.startswith('ENTER_DEVICE_CODE='):raise AwaitingHumanCompletion()
 try:following.login(emit=device_emit)
 except AwaitingHumanCompletion:
  pending=following._read();following._check(pending)
  require(pending['state']=='DEVICE_POLL'and pending['attempts']==257,'EXACT_UNPOLLED_DEVICE257_REQUIRED')
  terminal_phrase('Completa il login nel browser. Nessuna richiesta token e ancora stata fatta.\n'
   'La pausa e senza lock d invocazione. Conferma solo dopo successo nel browser.', 'LOGIN COMPLETATO '+digest(review))
  require(following._read()==pending and time.time()<pending['deviceDeadline'],'DEVICE257_CHANGED_OR_EXPIRED_DURING_HUMAN_WAIT')
  following.login(emit=emit)
 fresh=following._read();require(following.current()==new_binding and 259<=fresh['attempts']<=264
  and fresh['binding']['expiresAt']==EXPIRES and fresh['monotonicDeadline']==row['monotonicDeadline']
  and human._read()==row,'EXACT_VERIFIED264_WITH_PRESERVED_DEADLINE_REQUIRED')
 receipt={'schema':'ouf.installation-route-budget264-receipt.v1','directory':str(destination),'reviewHash':digest(review),
  'expiresAt':EXPIRES,'priorOAuthAttempts':255,'oauthAttemptsAfter':fresh['attempts'],'predecessorMaximumCumulativeOAuthAttempts':256,
  'maximumCumulativeOAuthAttempts':264,'newWindowOpened':False,'humanSourceChanged':True,'oldRefreshReplayed':False,
  'runtimeAuthorityIssued':False,'budgetReset':False}
 publish_json(context,'login-window-receipt.json',receipt);emit('OUF_INSTALLATION_ROUTE_HUMAN='+encoded(receipt).decode());return following
