"""Resume one unstarted issuer login in its already approved window, after code consent."""
import copy,os,stat,termios,time
from pathlib import Path
from iam_owner_action import publish
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort import human_session as hs
from tools.chatbot_file_cohort.review import terminal_line,terminal_answer
from tools.ingestion_read_authorization.authorization import validate_session_binding,INGESTION_READ_PROFILE
from tools.mcp_read_transport_compatibility import authority
from tools.mcp_read_transport_compatibility.entry import publish_json
from tools.ingestion_read_transport_update.owner import require,digest,encoded
ORIGIN=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-wiqedn9w')
PACKAGE='4c63051ba4f22d3f83c33b96a5cc150824a6aadf79b9a6948ff09972b8c601be'
OLD_CLOSURE='2eb74254682d3fec8e49f2c5c08acaa83ff87b1f5d736b38124b7380e2a99a76'
OLD_HUMAN='2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285'
EXPIRES=1792415703
RESUME_CLAIM='mcp-read-transport-login-resume.claim.json'
ARTIFACTS=('candidate-review.json','execution-plan.json','review.json','decision.json','human.json','authority.json',
 'issuance.claim.json','recovery.json','update-result.json','login-window-receipt.json')
def original(case,closure,read):
 ref=case['existingWindowCompatibility']
 require(ref['schema']=='ouf.mcp-read-transport-existing-window-compatibility.v1'
  and ref['originContext']==str(ORIGIN)and ref['originPackageHash']==PACKAGE and ref['originClosureHash']==OLD_CLOSURE
  and ref['originalHumanSourceSha256']==OLD_HUMAN and ref['windowExpiresAt']==EXPIRES
  and ref['priorOAuthAttempts']==217 and ref['maximumCumulativeOAuthAttempts']==256
  and ref['newLoginWindowAllowed']is False and ref['approvedLoginConsentChanged']is False
  and ref['budgetReset']is False,'EXACT_EXISTING_WINDOW_COMPATIBILITY_INTENT_REQUIRED')
 require(closure['declaration']['moduleCount']==191
  and getattr(hs,'__qualified_source_sha256__',None)==ref['patchedHumanSourceSha256'],
  'EXACT191_COMPATIBLE_HUMAN_RUNTIME_REQUIRED')
 package=read(ORIGIN/'package.json',expected=PACKAGE)
 require(package['sourceCommit']=='c9d3ca870c95518c94f754640cd68dc8462c609e'
  and digest(package['closure'])==OLD_CLOSURE and read(ORIGIN/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},
  'EXACT_STOPPED188_HISTORY_REQUIRED')
 require(not any(os.path.lexists(ORIGIN/n)for n in ARTIFACTS),'ORIGINAL_ACTION_OR_LOGIN_ALREADY_ADVANCED')
 old_case=read(ORIGIN/'case.json',expected=package['fileHashes']['case.json'])
 require(all(case[k]==old_case[k]for k in('originalBinding','installedPlanBinding','installedJournalBinding','imageBinding')),
  'RETAINED_CANDIDATE_OR_INSTALLATION_INPUTS_CHANGED')
 review=read(ORIGIN/'login-review.json',expected=ref['originalLoginReviewHash'])
 old_directory=Path(old_case['humanBinding']['sessionDirectory']);claim=read(old_directory/'successor-window.claim.json')
 binding=case['humanBinding'];directory=Path(binding['sessionDirectory'])
 require(directory==old_directory.parent/('human-mcp-read-transport-successor-'+digest(review))
  and claim['destination']==str(directory)and claim['reviewHash']==digest(review)and claim['budgetReset']is False,
  'EXACT_ALREADY_APPROVED_NEW_SESSION_REQUIRED')
 return review,claim

def qualify(selection,case,closure,read):
 review,claim=original(case,closure,read);binding=case['humanBinding']
 validate_session_binding(binding,selection,profile=INGESTION_READ_PROFILE)
 human=hs.HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
 row=human._read();human._check(row)
 require(row['binding']==binding and row['state']=='NEW'and row['attempts']==217 and binding['expiresAt']==EXPIRES
  and binding['createdAt']==1792408503 and not row.get('operation')and row['budgetReset']is False
  and not any(row.get(k)for k in('accessToken','publishedAccessToken','refreshToken','deviceCode'))
  and not os.path.lexists(human.token_path)and not os.path.lexists(human.directory/RESUME_CLAIM)
  and not os.path.lexists(human.directory/'successor-window.claim.json'),'EXACT_UNSTARTED_NEW217_WITHOUT_TOKEN_OR_REPLAY_REQUIRED')
 renewal=row['governedWindowRenewal'];decision=renewal['decision']
 require(renewal['review']==review and digest(decision)==claim['decisionHash']and decision['reviewHash']==digest(review)
  and decision['decision']=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and decision['approvedAt']==binding['createdAt']and decision['expiresAt']==binding['expiresAt'],
  'EXACT_UNMODIFIED_ORIGINAL_LOGIN_CONSENT_REQUIRED')
 require(time.time()+1200<human.expires_at and time.monotonic()+1200<row['monotonicDeadline'],
  'EXISTING_WINDOW_TOO_SHORT_NO_EXTENSION')
 return human,row,review

def compile_review(case,closure,human,row,review):
 ref=case['existingWindowCompatibility']
 return {'schema':'ouf.mcp-read-transport-login-compatibility-review.v1','purpose':'RESUME_EXISTING_UNSTARTED_AUTHENTICATION',
  'sourceClosureHash':digest(closure),'originalSourceClosureHash':OLD_CLOSURE,'originalLoginReviewHash':digest(review),
  'originalHumanSourceSha256':OLD_HUMAN,'patchedHumanSourceSha256':ref['patchedHumanSourceSha256'],
  'sessionBindingHash':digest(row['binding']),'windowCreatedAt':1792408503,'windowExpiresAt':EXPIRES,
  'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,'remainingOAuthAttempts':39,
  'maximumLoginStarts':1,'newLoginWindowAllowed':False,'approvedLoginConsentChanged':False,
  'budgetReset':False,'oldCredentialsReusable':False,'oldRefreshReplayAllowed':False,'runtimeAuthorityIssued':False,
  'migrationAllowed':False,'grantChangesAllowed':False,'gatewayWritesAllowed':False,'sourceActivationAllowed':False,
  'jobDispatchAllowed':False,'separateMcpApprovalRequired':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4}

def terminal_consent(review):
 phrase='APPROVO COMPATIBILITA '+digest(review)
 summary=('Compatibilita tecnica del formato gia approvato: una sola prosecuzione della sessione NEW217.\n'
  'NON riapro il login o la finestra: restano13:15:03-15:15:03 italiane del19ottobre2026.\n'
  'Originale review e decisione invariate.217/256consumati,39residui. Nessun reset o token/refresh vecchio.\n'
  'Accetto il solo schema nuovo nello stesso guard, conservando ogni altro controllo di identita/budget/tempo/consenso.\n'
  'Questa decisione autorizza il runtime corretto a iniziare la prima autenticazione gia consentita.\n'
  'Nessuna autorita infrastrutturale: dopo identita verificata seguira APPROVO distinto per il SOLO MCP.\n'
  'Nessuna migrazione, modifica IAM/grant/policy47/metadati/80rotte, fonte, acquisizione o job.\n'
  'Tecniche8/8; funzionali4/6. Nuovo sourceClosureHash: '+review['sourceClosureHash'])
 fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
 try:
  require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
  termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,('\n'+summary+'\nScrivi: '+phrase+'\n> ').encode())
  accepted=False
  for attempt in range(1,4):
   raw,count=terminal_line(fd);accepted,detail=terminal_answer(raw,phrase.encode('ascii'),count)
   if accepted:break
   os.write(fd,b'\n'+encoded({'status':'NOT_ACCEPTED','attempt':attempt,**detail})+b'\n> ')
  require(accepted,'EXACT_COMPATIBILITY_CONSENT_NOT_GIVEN')
 finally:os.close(fd)
 now=int(time.time())
 return {'schema':'ouf.mcp-read-transport-login-compatibility-decision.v1','reviewHash':digest(review),
  'sourceClosureHash':review['sourceClosureHash'],'decision':'APPROVE_SAME_WINDOW_FORMAT_COMPATIBILITY_ONLY',
  'approvedAt':now,'windowExpiresAt':EXPIRES,'newLoginWindowAllowed':False,'runtimeAuthorityIssued':False}

def resume(selection,case,context,closure,read,emit):
 human,row,login_review=qualify(selection,case,closure,read)
 authority.current_authorities(int(time.time())+1800)
 review=compile_review(case,closure,human,row,login_review);publish_json(context,'compatibility-review.json',review)
 emit('OUF_MCP_INGESTION_PHASE=NATIVE_COMPATIBILITY_CONSENT_REQUIRED')
 decision=terminal_consent(review);now=time.time()
 require(decision['reviewHash']==digest(review)and decision['sourceClosureHash']==digest(closure)
  and decision['decision']=='APPROVE_SAME_WINDOW_FORMAT_COMPATIBILITY_ONLY'
  and decision['approvedAt']<=now<decision['approvedAt']+60 and decision['windowExpiresAt']==EXPIRES
  and decision['newLoginWindowAllowed']is False and decision['runtimeAuthorityIssued']is False,
  'EXACT_CURRENT_TECHNICAL_COMPATIBILITY_DECISION_REQUIRED')
 following,unchanged,_=qualify(selection,case,closure,read)
 require(following.directory==human.directory and unchanged==row,'NEW217_CHANGED_AFTER_COMPATIBILITY_REVIEW')
 publish_json(context,'compatibility-decision.json',decision)
 with human.journal.invocation():
  require(human._read()==row,'NEW217_CHANGED_BEFORE_ONE_LOGIN_START')
  with protected_directory(human.directory)as directory:
   require(publish(directory,RESUME_CLAIM,encoded({'schema':'ouf.mcp-read-transport-login-resume-claim.v1',
    'reviewHash':digest(review),'decisionHash':digest(decision),'context':str(context),'sourceClosureHash':digest(closure),
    'originalLoginReviewHash':digest(login_review),'windowExpiresAt':EXPIRES,'priorOAuthAttempts':217,
    'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False})),
    'EXISTING_LOGIN_START_ALREADY_CLAIMED_RECONCILE')
 emit('OUF_MCP_INGESTION_PHASE=CONTINUE_ALREADY_APPROVED_ISSUER_AUTHENTICATION')
 human.login(emit=emit)
 require(human.current()==case['humanBinding']and 217<=human._read()['attempts']<=256,'FRESH_EXISTING_WINDOW_HUMAN_NOT_PROVEN')
 receipt={'schema':'ouf.mcp-read-transport-human-reauthentication-receipt.v1','directory':str(human.directory),
  'expiresAt':EXPIRES,'reviewHash':digest(login_review),'compatibilityReviewHash':digest(review),'priorOAuthAttempts':217,
  'oauthAttemptsAfter':human._read()['attempts'],'maximumCumulativeOAuthAttempts':256,'budgetReset':False,
  'newLoginWindowOpened':False,'originalLoginConsentPreserved':True,'oldRefreshReplayed':False,'runtimeAuthorityIssued':False}
 publish_json(context,'login-window-receipt.json',receipt)
 emit('OUF_MCP_INGESTION_HUMAN_REAUTHENTICATED='+encoded(receipt).decode());return human
