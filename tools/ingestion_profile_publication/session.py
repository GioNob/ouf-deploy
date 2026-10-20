"""Use only the successful v7 session. At most one declared verified refresh, no login/budget change."""
import time
from pathlib import Path
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.ingestion_read_owner_reference.login import terminal_phrase
from tools.ingestion_profile_publication.owner import require,digest,encoded

def refresh_once(human,row):
 original=human._request;before=row['attempts']
 def capped(current,operation,url,values=None,bearer=None):
  index=current['attempts']-before
  require(index in(0,1)and operation==('REFRESH','USERINFO')[index],'EXACT_ONE_VERIFIED_REFRESH_REQUEST_SEQUENCE_REQUIRED')
  return original(current,operation,url,values,bearer)
 human._request=capped
 try:return human._verify_and_publish(human._renew(row))
 finally:human._request=original

def authenticate(selection,binding,context,publish_json,emit):
 human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();human._check(row)
 require(row['binding']==binding and row['state']=='READY'and row['budgetReset']is False
  and 276<=row['attempts']<=288 and row.get('accessToken')==row.get('publishedAccessToken')
  and binding['expiresAt']==1792450664 and binding['retryProfile']['maximumAttempts']==288,'SAME_SUCCESSFUL_READY288_SESSION_REQUIRED')
 review={'schema':'ouf.ingestion-projection-existing-session-review.v1','sessionBindingHash':digest(binding),
  'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':288,'maximumOAuthRequests':2,
  'windowExpiresAt':binding['expiresAt'],'newLoginAllowed':False,'newBudgetAllowed':False,'budgetReset':False,
  'old272CredentialsReusable':False,'failedRefreshReplayAllowed':False,'ownerMutationAllowed':False,'projectionPublicationAllowed':False}
 publish_json(context,'session-review.json',review)
 terminal_phrase('Uso soltanto la sessione HUMAN gia riuscita per owner7. Nessun nuovo login o budget.\n'
  'Se il bearer non ha margine sufficiente, al massimo UN refresh della sessione corrente e UNA verifica userinfo (2richieste entro288).\n'
  'Non uso le credenziali del tentativo272. Una risposta ambigua o revoca blocca, senza replay.\n'
  'Questo consenso non pubblica file: seguira APPROVO distinto sul piano esatto.\n'
  'Scadenza della finestra invariata; '+str(row['attempts'])+'/288 gia consumate.', 'VERIFICO SESSIONE '+digest(review))
 publish_json(context,'session-decision.json',{'schema':'ouf.ingestion-projection-existing-session-decision.v1',
  'reviewHash':digest(review),'approvedAt':int(time.time()),'decision':'VERIFY_EXISTING_SESSION_MAX_TWO_REQUESTS_NO_NEW_LOGIN_OR_BUDGET'})
 refreshed=False
 with human.journal.invocation():
  require(human._read()==row,'SUCCESSFUL_HUMAN_CHANGED_DURING_SESSION_REVIEW');human._check(row)
  if row['accessExpiresAt']<=time.time()+300:
   require(288-row['attempts']>=2,'VERIFIED_REFRESH_BUDGET_INSUFFICIENT_NO_LOGIN')
   refresh_once(human,row);refreshed=True
  else:human.current()
 fresh=human._read();require(human.current()==binding and fresh['state']=='READY'and 0<=fresh['attempts']-row['attempts']<=2
  and fresh['accessExpiresAt']>time.time()+240,'EXISTING_VERIFIED_SESSION_MARGIN_REQUIRED')
 receipt={'schema':'ouf.ingestion-projection-existing-session-receipt.v1','oauthAttemptsBefore':row['attempts'],
  'oauthAttemptsAfter':fresh['attempts'],'maximumCumulativeOAuthAttempts':288,'maximumOAuthRequests':2,'refreshPerformed':refreshed,
  'windowExpiresAt':binding['expiresAt'],'windowExtended':False,'newLoginPerformed':False,'budgetReset':False,'runtimeAuthorityIssued':False}
 publish_json(context,'session-receipt.json',receipt);emit('OUF_INGESTION_PROJECTION_SESSION='+encoded(receipt).decode());return human
