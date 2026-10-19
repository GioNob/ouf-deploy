"""Explicit one-window reauthentication after reconciled BLOCKED217; no old refresh."""
import copy,os,time,uuid
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES
from tools.source_revision_update import authority as terminal
from tools.ingestion_read_authorization.authorization import validate_session_binding,INGESTION_READ_PROFILE
from tools.mcp_read_transport_reauthentication import authority
from tools.ingestion_read_transport_update.owner import require,digest,encoded,NEW_SOURCE,OLD_MCP,PROFILE as UPDATE_PROFILE
from tools.mcp_read_transport_reauthentication.entry import publish_json
STOPPED=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-mbbleugm')
PACKAGE='f4552fa8894c2050e67f025df9d6c14eb02b04a7c6d18d4a9019994d8bda1de9'
ARTIFACTS=('candidate-review.json','execution-plan.json','review.json','decision.json','human.json','authority.json',
 'issuance.claim.json','recovery.json','update-result.json')
def predecessor(case,closure,read):
 ref=case['reauthentication']
 require(ref=={'schema':'ouf.mcp-read-transport-blocked217-reauthentication.v1','stoppedContext':str(STOPPED),
  'stoppedPackageHash':PACKAGE,'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,
  'newWindowSeconds':7200,'newLoginRequiresNativeConsent':True,'failedRefreshReplayAllowed':False,
  'oldCredentialsReusable':False,'automaticRenewalAllowed':False,'budgetReset':False},'EXACT_REAUTHENTICATION_INTENT_REQUIRED')
 require(not any(os.path.lexists(STOPPED/n)for n in ARTIFACTS),'STOPPED_MCP_ACTION_HAS_LATER_AUTHORITY_OR_EFFECTS')
 package=read(STOPPED/'package.json',expected=PACKAGE)
 claim=read(STOPPED/'runtime.claim.json')
 require(claim=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED_STOPPED_CLAIM_REQUIRED')
 old_case=read(STOPPED/'case.json',expected=package['fileHashes']['case.json'])
 require(all(case[k]==old_case[k]for k in('originalBinding','humanBinding','installedPlanBinding','installedJournalBinding','imageBinding')),
  'RETAINED_IMAGE_INPUTS_AND_BLOCKED_HUMAN_CHANGED')
 require(closure['declaration']['moduleCount']==188,'EXACT_188_MODULE_REAUTHENTICATION_CLOSURE_REQUIRED')
 return ref

def qualify(human,row,case,closure):
 human._check_identity_and_budget(row)
 require(row['binding']==case['humanBinding']and row['state']=='BLOCKED'and row.get('operation')=='REFRESH'
  and row.get('reason')=='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN'and row['attempts']==217
  and PROFILE['maximumAttempts']==256 and PROFILE['maximumElapsedSeconds']==7200
  and len(SCOPES)==7 and SCOPES[-1]=='udp.materialization.retry'and time.time()+2>=row['lastObservedAt']
  and not os.path.lexists(human.directory/'successor-window.claim.json'),'EXACT_BLOCKED217_NO_SUCCESSOR_REQUIRED')
 return {'schema':'ouf.mcp-read-transport-human-reauthentication-review.v1','purpose':'CONFIGURATION_AND_VALIDATION',
  'predecessorDirectory':str(human.directory),'predecessorBindingHash':digest(row['binding']),
  'predecessorRowHash':digest(row),'selectionHash':digest(human.selection),'priorOAuthAttempts':217,
  'predecessorMaximumCumulativeOAuthAttempts':256,'maximumCumulativeOAuthAttempts':256,
  'maximumRemainingOAuthAttempts':39,'newWindowSeconds':7200,'budgetReset':False,
  'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'oldCredentialsReusable':False,
  'automaticRenewalAllowed':False,'runtimeAuthorityIssued':False,'requestedScopes':list(SCOPES),
  'identityAndScopesUnchanged':True,'issuerCauseUnattributed':True,
  'followup':{'profile':UPDATE_PROFILE,'candidateSourceCommit':NEW_SOURCE,'oldContainerId':OLD_MCP,
   'imageCustodyHash':case['imageBinding']['sha256'],'separateNativeApprovalRequired':True,
   'migrationAllowed':False,'gatewayWritesAllowed':False,'grantChangesAllowed':False,
   'sourceActivationAllowed':False,'jobDispatchAllowed':False},
  'operationBinding':{'stoppedPackageHash':PACKAGE,'sourceClosureHash':digest(closure)}}

def authenticate(selection,case,context,closure,read,emit):
 predecessor(case,closure,read);authority.current_authorities(int(time.time())+910)
 binding=case['humanBinding'];validate_session_binding(binding,selection,profile=INGESTION_READ_PROFILE)
 human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();review=qualify(human,row,case,closure)
 publish_json(context,'login-review.json',review)
 emit('OUF_MCP_INGESTION_PHASE=NATIVE_REAUTHENTICATION_CONSENT_REQUIRED')
 decision=terminal.terminal_consent(review,
  'Azione HUMAN distinta: UNA nuova autenticazione dello stesso soggetto/tenant/issuer.\n'
  'Sessione precedente BLOCKED dopo REFRESH217; causa specifica non attribuita. NON ritento quel refresh.\n'
  'Nuova finestra7200secondi dal consenso, senza rinnovo automatico. OAuth consumati217/256; residui39, nessun reset.\n'
  'Stessi7scope, nessun nuovo grant/policy/ruolo, nessuna modifica IAM o revoca aggirata: decide il provider.\n'
  'Questo consenso apre solo il login: nessuna autorita infrastrutturale o modifica ai servizi.\n'
  'Dopo autenticazione verificata seguira un APPROVO distinto per aggiornare il SOLO MCP alla sorgente1f2c28d.\n'
  'Nessuna migrazione/SQL, scrittura Gateway/metadati, attivazione fonte o job.\n'
  'Tecniche8/8; funzionali4/6. Interruzioni o esiti incerti richiedono riconciliazione, non rilancio.',login=True)
 now=time.time()
 require(decision['reviewHash']==digest(review)and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and decision['approvedAt']<=now<decision['approvedAt']+60 and decision['expiresAt']==decision['approvedAt']+7200,
  'EXACT_DISTINCT_REAUTHENTICATION_CONSENT_REQUIRED')
 predecessor(case,closure,read)
 destination=human.directory.parent/('human-mcp-read-transport-successor-'+digest(review))
 with human.journal.invocation():
  require(human._read()==row,'BLOCKED217_PREDECESSOR_CHANGED')
  with protected_directory(human.directory)as directory:
   require(publish(directory,'successor-window.claim.json',encoded({'schema':'ouf.human-successor-window-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'destination':str(destination),
    'budgetReset':False,'automaticReplayAllowed':False})),'BLOCKED_HUMAN_SUCCESSOR_ALREADY_CLAIMED')
  with protected_directory(destination.parent)as directory:
   os.mkdir(destination.name,0o700,dir_fd=directory);os.fsync(directory)
  following=HumanSession(selection,destination,destination/'human-access.jwt',decision['expiresAt'])
  new_binding={'sessionId':str(uuid.UUID(digest(decision)[:32])),'selectionHash':digest(selection),
   **{k:selection[k]for k in('subject','issuer','tenant')},'clientId':CLIENT,'scopes':list(SCOPES),
   'tokenPath':str(following.token_path),'sessionDirectory':str(destination),'createdAt':decision['approvedAt'],
   'expiresAt':decision['expiresAt'],'retryProfile':copy.deepcopy(PROFILE)}
  following.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':new_binding,
   'bootId':following._boot(),'monotonicDeadline':time.monotonic()+decision['expiresAt']-now,
   'lastObservedAt':now,'attempts':217,'state':'NEW','budgetReset':False,
   'governedWindowRenewal':{'review':review,'decision':decision}})
  following._check_identity_and_budget(following._read());require(human._read()==row,'OLD_HUMAN_JOURNAL_CHANGED')
 emit('OUF_MCP_INGESTION_PHASE=FRESH_ISSUER_AUTHENTICATION')
 following.login(emit=emit)
 require(following.current()==new_binding and 217<=following._read()['attempts']<=256,'FRESH_ISSUER_HUMAN_NOT_PROVEN')
 receipt={'schema':'ouf.mcp-read-transport-human-reauthentication-receipt.v1','directory':str(destination),
  'expiresAt':following.expires_at,'reviewHash':digest(review),'priorOAuthAttempts':217,
  'oauthAttemptsAfter':following._read()['attempts'],'maximumCumulativeOAuthAttempts':256,'budgetReset':False,
  'newHumanLoginOpenedUnderNativeConsent':True,'oldRefreshReplayed':False,'runtimeAuthorityIssued':False}
 publish_json(context,'login-window-receipt.json',receipt)
 emit('OUF_MCP_INGESTION_HUMAN_REAUTHENTICATED='+encoded(receipt).decode());return following
