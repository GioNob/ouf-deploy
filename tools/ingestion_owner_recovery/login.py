"""Fresh HUMAN only after explicit288 consent. An early acknowledgement cannot drain the budget."""
import copy,os,time,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,SCOPES
from tools.ingestion_read_owner_reference.login import terminal_phrase
from tools.ingestion_owner_recovery.owner import require,encoded,digest
from tools.ingestion_owner_recovery import reconcile
DRAFT_HASH='2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec'
def qualify(human,row,closure,logical_ref):
 human._check_identity_and_budget(row)
 require(row['state']=='VERIFYING'and row['attempts']==272 and row['budgetReset']is False
  and row['binding']['retryProfile']['maximumAttempts']==272 and row['binding']['expiresAt']==1792446208
  and row['binding']['scopes']==SCOPES and len(SCOPES)==11 and PROFILE['maximumAttempts']==288
  and time.time()>=row['lastObservedAt']and not os.path.lexists(human.directory/'successor-window.claim.json')
  and not os.path.lexists(human.token_path)and closure['declaration']['moduleCount']==238,
  'EXACT_UNVERIFIED_EXHAUSTED272_PREDECESSOR_REQUIRED')
 return {'schema':'ouf.human-ingestion-owner-recovery-budget-review.v7','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorMaximumCumulativeOAuthAttempts':272,'priorOAuthAttempts':272,'maximumCumulativeOAuthAttempts':288,
  'maximumAdditionalRequestsFromCurrentCount':16,'predecessorWindowExpiresAt':1792446208,'newWindowSeconds':7200,
  'requestedScopes':copy.deepcopy(SCOPES),'freshIssuerAuthenticationRequired':True,'sourceClosureHash':digest(closure),
  'logicalOperationRef':logical_ref,'predecessorBindingHash':digest(row['binding']),
  'predecessorWindowReviewHash':digest(row['governedWindowRenewal']['review']),
  'predecessorPackageHash':reconcile.PACKAGE,'predecessorContextPath':str(reconcile.CONTEXT),
  'oldCredentialsReusable':False,'oldRefreshReplayAllowed':False,'automaticRenewalAllowed':False,'budgetReset':False,
  'runtimeAuthorityIssued':False,'humanValidatorVersion':'ouf.human.ingestion-owner-recovery288.v7','humanSourceChanged':True,
  'browserConfirmationPerPollRequired':True,'verificationBudgetReserved':True,'draftPlanHash':DRAFT_HASH,
  'separateOwnerConsentRequired':True,'separateRuntimeAndGatewayConsentsRequired':True}
def authenticate(selection,binding,context,closure,publish_json,emit,case):
 human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();review=qualify(human,row,closure,case['logicalRef']);publish_json(context,'login-review.json',review)
 terminal_phrase('Recupero distinto: storico272/272 esaurito conservato, senza usare token o refresh precedenti.\n'
  'Propongo massimo288,16richieste residue; NUOVA finestra7200secondi da questo consenso,11scope invariati.\n'
  'Non autorizza effetti owner o runtime. Segue un APPROVO owner separato dopo verifica provider.\n'
  'Il login corretto mostra URL e codice prima di OGNI conferma; ogni conferma permette al massimo un polling.\n'
  'Se il provider dice ancora in attesa, torno a chiedere conferma senza altri polling automatici.\n'
  'La verifica finale ha budget riservato. STOP o interruzione richiedono riconciliazione, nessun rilancio.',
  'APPROVO BUDGET288 '+digest(review))
 now=time.time();decision={'schema':'ouf.human-ingestion-owner-recovery-budget-decision.v7','reviewHash':digest(review),
  'approvedAt':int(now),'expiresAt':int(now)+7200,'decision':'APPROVE_EXACT288_AND_NEW7200_WINDOW_PROTECTED_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'}
 publish_json(context,'login-decision.json',decision)
 destination=human.directory.parent/('human-ingestion-owner-recovery288-'+digest(review))
 with human.journal.invocation():
  require(human._read()==row,'STOPPED272_CHANGED_DURING_BUDGET_REVIEW');qualify(human,row,closure,case['logicalRef'])
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),'windowExpiresAt':decision['expiresAt'],
    'predecessorMaximumCumulativeOAuthAttempts':272,'maximumCumulativeOAuthAttempts':288,'priorOAuthAttempts':272,
    'budgetReset':False,'automaticReplayAllowed':False,'newWindowAllowed':True})),'STOPPED272_SUCCESSOR_ALREADY_CLAIMED')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  new_binding={**copy.deepcopy(binding),'sessionId':str(uuid.UUID(digest(decision)[:32])),
   'sessionDirectory':str(destination),'tokenPath':str(following.token_path),'createdAt':decision['approvedAt'],'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':new_binding,'bootId':row['bootId'],
   'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,'lastObservedAt':now,'attempts':272,'state':'NEW','budgetReset':False,
   'governedWindowRenewal':{'review':review,'decision':decision},'predecessorWindowReviewHash':review['predecessorWindowReviewHash']})
  following._check(following._read());require(human._read()==row,'PREDECESSOR272_JOURNAL_CHANGED')
 case['humanBinding']=new_binding
 def confirm(challenge):
  terminal_phrase('LOGIN NEL BROWSER — questo passaggio non autorizza scritture.\n'
   'Apri QUESTO indirizzo: '+challenge['verificationUri']+'\n'
   'Inserisci QUESTO codice: '+challenge['userCode']+'\n'
   'Completa il login e attendi la pagina di successo. Solo DOPO conferma qui.\n'
   'Se hai confermato troppo presto, puoi completare ora lo stesso login: nessun nuovo codice o nuovo budget.\n'
   'Richieste consumate: '+str(challenge['attempts'])+'/288. La conferma autorizza UNA richiesta token, non prova il login.',
   'LOGIN COMPLETATO '+digest(review))
  return True
 following.login(emit=emit,confirm_browser=confirm)
 fresh=following._read();require(following.current()==new_binding and 276<=fresh['attempts']<=288
  and fresh['binding']['expiresAt']==decision['expiresAt']and human._read()==row,'EXACT_VERIFIED288_WITH_PROTECTED_FRESH_LOGIN_REQUIRED')
 receipt={'schema':'ouf.ingestion-owner-recovery-budget288-receipt.v1','directory':str(destination),'reviewHash':digest(review),
  'expiresAt':decision['expiresAt'],'priorOAuthAttempts':272,'oauthAttemptsAfter':fresh['attempts'],'predecessorMaximumCumulativeOAuthAttempts':272,
  'maximumCumulativeOAuthAttempts':288,'newWindowOpened':True,'predecessorWindowExpiresAt':1792446208,'humanSourceChanged':True,
  'oldRefreshReplayed':False,'oldUnverifiedTokenReused':False,'browserConfirmationPerPollRequired':True,'verificationBudgetReserved':True,
  'runtimeAuthorityIssued':False,'budgetReset':False}
 publish_json(context,'login-window-receipt.json',receipt);emit('OUF_INGESTION_OWNER_RECOVERY_HUMAN='+encoded(receipt).decode());return following
