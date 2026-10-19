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
from tools.installation_binding_apply.owner import require,encoded,digest
EXPIRES=1792425259
ORIGINAL_REVIEW='2f973bf92defd736e313861b0efafbb0a0d0fb6a7c17bd536f4b71d97d256c71'
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

def qualify(human,row,closure):
 human._check_identity_and_budget(row)
 require(row['binding']['scopes']==SCOPES and len(SCOPES)==11 and PROFILE['maximumAttempts']==256
  and row['state']=='READY'and row['attempts']==251 and row['budgetReset']is False
  and row['binding']['expiresAt']==EXPIRES and row['accessExpiresAt']<time.time()+240
  and time.time()>=row['lastObservedAt']
  and not os.path.lexists(human.directory/'successor-window.claim.json')and closure['declaration']['moduleCount']==219,
  'EXACT_READY251_ORIGINAL_WINDOW_NO_SUCCESSOR_REQUIRED')
 renewal=row['governedWindowRenewal'];review=renewal['review'];decision=renewal['decision']
 require(review['schema']=='ouf.human-explicit-capability-scope-review.v4'and digest(review)==ORIGINAL_REVIEW
  and review['priorOAuthAttempts']==236 and review['requestedScopes']==SCOPES and decision['reviewHash']==digest(review)
  and decision['approvedAt']==row['binding']['createdAt']and decision['expiresAt']==EXPIRES
  and EXPIRES-decision['approvedAt']==7200,'ORIGINAL_WINDOW_CONSENT_AND_DATES_REQUIRED')
 return {'schema':'ouf.human-explicit-test-continuation-review.v3','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorMaximumCumulativeOAuthAttempts':256,'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,
  'sourceClosureHash':digest(closure),'predecessorBindingHash':digest(row['binding']),'predecessorRowHash':digest(row),
  'originalWindowReviewHash':digest(review),'predecessorWindowCreatedAt':row['binding']['createdAt'],'predecessorWindowExpiresAt':EXPIRES,'newWindowSeconds':7200,
  'priorOAuthAttempts':251,'maximumCumulativeOAuthAttempts':256,'remainingOAuthAttempts':5,'requestedScopes':copy.deepcopy(SCOPES),
  'newWindowAllowed':True,'automaticRenewalAllowed':False,'oldCredentialsReusable':False,'oldRefreshReplayAllowed':False,'budgetReset':False,
  'runtimeAuthorityIssued':False,'providerTokenRequestRequiresHumanCompletionAcknowledgement':True,
  'separateOwnerApprovalRequired':True,'separateProjectionGatewayApprovalRequired':True}

def authenticate(selection,binding,context,closure,publish_json,emit,case):
 human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();review=qualify(human,row,closure);publish_json(context,'login-review.json',review)
 terminal_phrase('Nuova autenticazione HUMAN distinta:251/256,5residui,11scope invariati.\n'
  'Apro UNA NUOVA finestra7200secondi dal consenso esplicito; il contatore resta251/256.\n'
  'La finestra originale17:54:19 e il suo storico restano conservati; nessun reset o rinnovo automatico.\n'
  'Il validatore HUMAN e tutti i limiti restano invariati. Il provider puo negare.\n'
  'Dopo URL/codice apro una pausa SENZA lock o polling: completa il login e confermalo nel terminale.\n'
  'Solo allora chiedero il primo token al provider e verifichero identita/scope/userinfo.\n'
  'Questo consenso non autorizza scritture: seguiranno APPROVO distinti per owner, poi proiezione e2rotte.\n'
  'Un solo avvio; STOP/interruzione richiedono riconciliazione.', 'RIAPRO LOGIN '+digest(review))
 now=time.time();decision={'schema':'ouf.installation-binding-reauth251-decision.v1','reviewHash':digest(review),
  'approvedAt':int(now),'expiresAt':int(now)+7200,'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','runtimeAuthorityIssued':False}
 publish_json(context,'login-decision.json',decision)
 destination=human.directory.parent/('human-installation-binding-reauth251-'+digest(review))
 with human.journal.invocation():
  require(human._read()==row,'HUMAN251_CHANGED_DURING_CONSENT');qualify(human,row,closure)
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),'windowExpiresAt':decision['expiresAt'],
    'budgetReset':False,'automaticReplayAllowed':False,'newWindowAllowed':True})),'HUMAN251_SUCCESSOR_ALREADY_CLAIMED')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  new_binding={**copy.deepcopy(binding),'sessionId':str(uuid.UUID(digest(decision)[:32])),
   'sessionDirectory':str(destination),'tokenPath':str(following.token_path),'createdAt':decision['approvedAt'],'expiresAt':decision['expiresAt']}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':new_binding,'bootId':row['bootId'],
   'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,'lastObservedAt':now,'attempts':251,'state':'NEW','budgetReset':False,
   'governedWindowRenewal':{'review':review,'decision':decision},'predecessorWindowReviewHash':review['originalWindowReviewHash']})
  following._check(following._read());require(human._read()==row,'PREDECESSOR251_JOURNAL_CHANGED')
 case['humanBinding']=new_binding
 def device_emit(value):
  emit(value)
  if value.startswith('ENTER_DEVICE_CODE='):raise AwaitingHumanCompletion()
 try:following.login(emit=device_emit)
 except AwaitingHumanCompletion:
  pending=following._read();following._check(pending)
  require(pending['state']=='DEVICE_POLL'and pending['attempts']==253,'EXACT_UNPOLLED_DEVICE253_REQUIRED')
  # login() invocation has unwound here. No lock spans this HUMAN wait.
  terminal_phrase('Completa il login nel browser tramite URL/codice appena mostrati.\n'
   'NON sono ancora state fatte richieste token. Conferma qui solo dopo il successo nel browser.\n'
   'La conferma non sostituisce la verifica del provider e non prolunga la finestra.', 'LOGIN COMPLETATO '+digest(review))
  require(following._read()==pending and time.time()<pending['deviceDeadline'],'DEVICE253_CHANGED_OR_EXPIRED_DURING_HUMAN_WAIT')
  following.login(emit=emit)
 fresh=following._read();require(following.current()==new_binding and 255<=fresh['attempts']<=256
  and fresh['binding']['expiresAt']==decision['expiresAt']and fresh['binding']['createdAt']==decision['approvedAt']
  and fresh['governedWindowRenewal']=={'review':review,'decision':decision}
  and human._read()==row,'FRESH_VERIFIED_HUMAN_WITH_UNCHANGED_WINDOW_REQUIRED')
 receipt={'schema':'ouf.installation-binding-reauth251-receipt.v1','directory':str(destination),'reviewHash':digest(review),
  'expiresAt':following.expires_at,'priorOAuthAttempts':251,'oauthAttemptsAfter':fresh['attempts'],'maximumCumulativeOAuthAttempts':256,
  'newWindowOpenedUnderNativeConsent':True,'predecessorWindowExpiresAt':EXPIRES,'humanSourceChanged':False,'oldRefreshReplayed':False,'runtimeAuthorityIssued':False,'budgetReset':False}
 publish_json(context,'login-window-receipt.json',receipt);emit('OUF_INSTALLATION_BINDING_HUMAN='+encoded(receipt).decode())
 return following
