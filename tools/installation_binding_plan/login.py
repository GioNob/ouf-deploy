"""Explicit native scope-v4 login; no IAM/grant/installation mutation authority."""
import copy,os,time,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES,LEGACY_SCOPES
from tools.source_revision_update import authority as terminal
from tools.installation_binding_plan.plan import require,digest,encoded,publish_json

ADDITIONS=['installation.configuration.read','installation.configuration.write','installation.configuration.activate','installation.configuration.export']
def qualify(human,row,case,closure):
 human._check_identity_and_budget(row)
 require(row['binding']==case['humanBinding']and row['state']=='READY'and 236<=row['attempts']<256
  and row['budgetReset']is False and row['binding']['scopes']==LEGACY_SCOPES
  and SCOPES==LEGACY_SCOPES+ADDITIONS and PROFILE['maximumAttempts']==256 and PROFILE['maximumElapsedSeconds']==7200
  and closure['declaration']['moduleCount']==209 and not os.path.lexists(human.directory/'successor-window.claim.json'),
  'EXACT_RETAINED236_AND_FOUR_INSTALLATION_SCOPE_ADDITIONS_REQUIRED')
 return {'schema':'ouf.human-explicit-capability-scope-review.v4','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorDirectory':str(human.directory),'predecessorBindingHash':digest(row['binding']),'predecessorRowHash':digest(row),
  'selectionHash':digest(human.selection),'priorOAuthAttempts':row['attempts'],'predecessorMaximumCumulativeOAuthAttempts':256,
  'maximumCumulativeOAuthAttempts':256,'maximumRemainingOAuthAttempts':256-row['attempts'],'newWindowSeconds':7200,
  'previousScopes':copy.deepcopy(LEGACY_SCOPES),'requestedScopes':copy.deepcopy(SCOPES),'addedScopes':ADDITIONS,
  'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'oldCredentialsReusable':False,
  'automaticRenewalAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,
  'completedMcpPackageHash':case['completedMcpPackageHash'],'sourceClosureHash':digest(closure),
  'followup':{'profile':'ouf.installation-ingestion-binding-plan.v1','ownerReadOnly':True,'maximumOwnerGetRequests':3,
   'ownerMutationAllowed':False,'installationActivationAllowed':False,'projectionReplacementAllowed':False,
   'gatewayWritesAllowed':False,'sourceActivationAllowed':False,'jobDispatchAllowed':False,
   'futureOwnerWriteRequiresSeparateNativeConsent':True}}

def authenticate(selection,case,context,closure,emit):
 binding=case['humanBinding'];human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();review=qualify(human,row,case,closure);publish_json(context,'login-review.json',review)
 emit('OUF_MCP_INGESTION_PHASE=NATIVE_INSTALLATION_SCOPE_CONSENT_REQUIRED')
 decision=terminal.terminal_consent(review,
  'Azione HUMAN DISTINTA: richiedo i4scope installation.configuration.read/write/activate/export.\n'
  'Stessi soggetto/tenant/issuer/client; nessun nuovo grant, ruolo o modifica IAM. Il provider puo negare.\n'
  'Nuova finestra7200secondi; contatore precedente'+str(row['attempts'])+'/256, nessun reset.\n'
  'Non invio il vecchio access/refresh token; nuovi token solo dopo verifica IAM. Nessun rinnovo automatico.\n'
  'QUESTO COMANDO PREPARA SOLO IL PIANO: massimo3GET owner sulle revisioni attuali.\n'
  'Non crea/attiva revisioni, non esporta proiezioni e non modifica file attivi, rotte, container o fonte.\n'
  'Scritture future richiederanno un piano e un APPROVO distinto; questo consenso apre solo il login.\n'
  'Tecniche8/8; funzionali4/6. Dopo STOP/interruzione: riconciliare senza rilancio.',login=True)
 now=time.time();require(decision['reviewHash']==digest(review)and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and decision['approvedAt']<=now<decision['approvedAt']+60 and decision['expiresAt']==decision['approvedAt']+7200,
  'EXACT_NATIVE_INSTALLATION_SCOPE_CONSENT_REQUIRED')
 destination=human.directory.parent/('human-installation-binding-'+digest(review))
 with human.journal.invocation():
  require(human._read()==row,'PREDECESSOR_CHANGED_DURING_SCOPE_CONSENT');qualify(human,row,case,closure)
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),'budgetReset':False,
    'automaticReplayAllowed':False})),'INSTALLATION_SCOPE_SUCCESSOR_ALREADY_CLAIMED')
  with protected_directory(destination.parent)as directory:os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  new_binding={'sessionId':str(uuid.UUID(digest(decision)[:32])),'selectionHash':digest(selection),
   **{k:selection[k]for k in('subject','issuer','tenant')},'clientId':CLIENT,'scopes':copy.deepcopy(SCOPES),
   'tokenPath':str(following.token_path),'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
   'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':new_binding,'bootId':following._boot(),
   'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,'lastObservedAt':now,'attempts':row['attempts'],
   'state':'NEW','budgetReset':False,'governedWindowRenewal':{'review':review,'decision':decision}})
  following._check_identity_and_budget(following._read());require(human._read()==row,'PREDECESSOR_JOURNAL_CHANGED')
 following.login(emit=emit);require(following.current()==new_binding,'FRESH_INSTALLATION_HUMAN_NOT_PROVEN')
 receipt={'schema':'ouf.installation-binding-scope-login-receipt.v1','directory':str(destination),'reviewHash':digest(review),
  'expiresAt':following.expires_at,'priorOAuthAttempts':row['attempts'],'oauthAttemptsAfter':following._read()['attempts'],
  'maximumCumulativeOAuthAttempts':256,'requestedInstallationScopeCount':4,'budgetReset':False,'oldRefreshReplayed':False,
  'runtimeAuthorityIssued':False,'ownerMutationsPerformed':0,'gatewayWrites':0}
 publish_json(context,'login-window-receipt.json',receipt);emit('OUF_INSTALLATION_BINDING_HUMAN='+encoded(receipt).decode());return following
