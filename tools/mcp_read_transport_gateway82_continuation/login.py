"""One explicitly approved successor to READY229; original refresh is never sent."""
import copy,os,time,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES
from tools.source_revision_update import authority as terminal
from tools.ingestion_read_authorization.authorization import validate_session_binding,INGESTION_READ_PROFILE
from tools.mcp_read_transport_gateway82_continuation import authority
from tools.mcp_read_transport_gateway82.owner import require,digest,encoded,NEW_SOURCE,OLD_MCP,PROFILE as UPDATE_PROFILE
from tools.mcp_read_transport_gateway82_continuation.entry import publish_json,completed_gateway

def qualify(human,row,case,closure):
 human._check_identity_and_budget(row)
 require(row['binding']==case['humanBinding']and row['state']=='READY'and type(row['attempts'])is int
  and 229<=row['attempts']<256 and row['budgetReset']is False and human.expires_at==1792415703 and row['binding']['clientId']==CLIENT and row['binding']['scopes']==list(SCOPES)
  and PROFILE['maximumAttempts']==256 and PROFILE['maximumElapsedSeconds']==7200
  and time.time()>=row['lastObservedAt']and not os.path.lexists(human.directory/'successor-window.claim.json')
  and closure['declaration']['moduleCount']==205,'EXACT_READY229_CUMULATIVE_CONTINUATION_REQUIRED')
 return {'schema':'ouf.human-explicit-test-continuation-review.v3','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorDirectory':str(human.directory),'predecessorBindingHash':digest(row['binding']),
  'predecessorRowHash':digest(row),'selectionHash':digest(human.selection),'priorOAuthAttempts':row['attempts'],
  'predecessorMaximumCumulativeOAuthAttempts':256,'maximumCumulativeOAuthAttempts':256,
  'maximumRemainingOAuthAttempts':256-row['attempts'],'newWindowSeconds':7200,'budgetReset':False,
  'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'oldCredentialsReusable':False,
  'automaticRenewalAllowed':False,'runtimeAuthorityIssued':False,'requestedScopes':list(SCOPES),
  'identityAndScopesUnchanged':True,'reasonCode':'PREDECESSOR_WINDOW_INSUFFICIENT_FOR_QUALIFIED_MCP_ADMISSION',
  'followup':{'profile':UPDATE_PROFILE,'candidateSourceCommit':NEW_SOURCE,'oldContainerId':OLD_MCP,
   'imageCustodyHash':case['imageBinding']['sha256'],'separateNativeApprovalRequired':True,
   'gatewayRouteMapHash':'d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927',
   'migrationAllowed':False,'gatewayWritesAllowed':False,'grantChangesAllowed':False,
   'sourceActivationAllowed':False,'jobDispatchAllowed':False},
  'operationBinding':{'completedGatewayBindingsHash':digest(case['completedGateway']),'sourceClosureHash':digest(closure)}}

def authenticate(selection,case,context,closure,read,emit):
 completed_gateway(case,read);binding=case['humanBinding']
 validate_session_binding(binding,selection,profile=INGESTION_READ_PROFILE)
 human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();review=qualify(human,row,case,closure)
 require(time.time()+1200>=human.expires_at,'ORIGINAL_WINDOW_STILL_SUFFICIENT_NO_RENEWAL')
 authority.current_authorities(int(time.time())+910)
 publish_json(context,'login-review.json',review)
 emit('OUF_MCP_INGESTION_PHASE=NATIVE_DISTINCT_HUMAN_CONTINUATION_REQUIRED')
 summary=('Azione HUMAN DISTINTA: UNA nuova autenticazione dello stesso soggetto/tenant/issuer/client/scope.\n'
  'Finestra precedente non piu sufficiente per il preparatore MCP qualificato; non riduco quel limite.\n'
  'Nuova finestra7200secondi dal consenso; nessun rinnovo automatico. OAuth consumati'+str(row['attempts'])+
  '/256; residui'+str(256-row['attempts'])+', nessun reset del cumulativo.\n'
  'Conservo journal, receipt e claim precedenti. Un nuovo successor claim impedisce il riuso della vecchia sessione.\n'
  'Non invio il vecchio access/refresh token. Fresh login IAM: nessuna revoca o negazione viene aggirata.\n'
  'Questo consenso apre SOLO il login; non concede autorita infrastrutturale.\n'
  'Dopo login verificato: nuovo piano MCP con82rotte invarianti e APPROVO distinto per sostituire solo MCP.\n'
  'Nessuna PUT Gateway, grant/policy/metadato/migrazione/attivazione fonte/acquisizione/job.\n'
  'Tecniche8/8; funzionali4/6. Esito incerto o interruzione: STOP e riconciliazione, nessun rilancio.')
 decision=terminal.terminal_consent(review,summary,login=True);now=time.time()
 require(decision['reviewHash']==digest(review)and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and decision['approvedAt']<=now<decision['approvedAt']+60 and decision['expiresAt']==decision['approvedAt']+7200,
  'EXACT_DISTINCT_HUMAN_CONTINUATION_CONSENT_REQUIRED')
 completed_gateway(case,read)
 destination=human.directory.parent/('human-mcp82-continuation-'+digest(review))
 with human.journal.invocation():
  require(human._read()==row,'READY229_PREDECESSOR_CHANGED');qualify(human,row,case,closure)
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),
    'budgetReset':False,'automaticReplayAllowed':False})),'HUMAN_CONTINUATION_ALREADY_CLAIMED')
  with protected_directory(destination.parent)as directory:
   os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  new_binding={'sessionId':str(uuid.UUID(digest(decision)[:32])),'selectionHash':digest(selection),
   **{k:selection[k]for k in('subject','issuer','tenant')},'clientId':CLIENT,'scopes':list(SCOPES),
   'tokenPath':str(following.token_path),'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
   'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':new_binding,
   'bootId':following._boot(),'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,
   'lastObservedAt':now,'attempts':row['attempts'],'state':'NEW','budgetReset':False,
   'governedWindowRenewal':{'review':review,'decision':decision}})
  following._check_identity_and_budget(following._read());require(human._read()==row,'PREDECESSOR_JOURNAL_CHANGED')
 emit('OUF_MCP_INGESTION_PHASE=FRESH_ISSUER_AUTHENTICATION')
 following.login(emit=emit)
 require(following.current()==new_binding and row['attempts']<=following._read()['attempts']<=256,'FRESH_HUMAN_CONTINUATION_NOT_PROVEN')
 receipt={'schema':'ouf.mcp82-human-continuation-receipt.v1','directory':str(destination),'expiresAt':following.expires_at,
  'reviewHash':digest(review),'priorOAuthAttempts':row['attempts'],'oauthAttemptsAfter':following._read()['attempts'],
  'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'newLoginWindowOpenedUnderNativeConsent':True,
  'oldRefreshReplayed':False,'runtimeAuthorityIssued':False}
 publish_json(context,'login-window-receipt.json',receipt);emit('OUF_MCP82_HUMAN_CONTINUATION='+encoded(receipt).decode());return following
