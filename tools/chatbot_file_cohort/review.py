"""One exact current HUMAN review and existing dual-role issuance.

Preparation and signing are separate. An unchanged artifact, a prior approval,
or development delegation never stands in for the current terminal decision.
The deployment remains a finite acceptance session, not permanent acceptance.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import termios
import time

import iam_binding_candidate as evidence
import iam_governance_intake as governance
from iam_owner_action import publish, stdlib_binding
from cutover_authority import CutoverAuthority
from file_only_profile import FileOnlyProfile, PHASES, PROFILE
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_policy_token_owner.owner_installation import AggregateAction

DECISION = 'APPROVE_ONE_FINITE_CHATBOT_FILE_COHORT_ACTION'
SCHEMA = 'ouf.chatbot-file-cohort-full-action-review.v1'
TERMINAL_ATTEMPTS = 3
PASTE_START, PASTE_END = b'\x1b[200~', b'\x1b[201~'
REQUIRED_SCOPES = frozenset({
    'policyTokenOwnerInstallation', 'policyTokenOutputCustody',
    'policyTokenLegacyRetirement', 'policyTokenCredentialReestablishment',
    'policyTokenAccountingGapMigration', 'policyTokenFirstControlledGrant',
    'policyTokenFiniteWorkerSession', 'tokenOwnerRuntime',
    'applicationCohortInstallation', 'gatewayRoutePublication',
    'chatbotFileAuthorization', 'finiteActionProcess', 'applicationRegistryCutover', 'cohortImageImport', 'gatewayRuntimeInstallation'})


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def require(ok, reason):
    evidence.require(ok, reason)


def command_matches(program):
    require(type(program) is dict and set(program) in ({'path','sha256'},{'path','sha256','version'}),
            'EXACT_CURRENT_COMMAND_BINDING_REQUIRED')
    require(governance.executable(program['path'])=={key:program[key] for key in ('path','sha256')},
            'APPROVED_NATIVE_PROGRAM_CHANGED')
    if 'version' in program:
        reply=subprocess.run([program['path'],'version'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=5,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        match=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',reply.stdout)
        require(reply.returncode==0 and len(reply.stdout)<=256 and match is not None
                and match[1].decode()==program['version'],'EXACT_REVIEWED_OPENSSL_VERSION_REQUIRED')
    return True


TOKEN_REVIEW = 'ouf.semantic-token-only-execution-review.v1'
TOKEN_DECISION = 'APPROVE_NEW_FINITE_POLICY_TOKEN_SESSION_AFTER_CANCELLATION'
TOKEN_SCOPES = frozenset({'policyTokenOwnerInstallation', 'policyTokenFiniteWorkerSession',
    'tokenOwnerRuntime', 'semanticFunctionalRuntime'})


def compile_token_review(closure, scopes, proposal_binding, candidate_binding, human_binding, context):
    """Compile only the four token-owner scopes; no application phase authority."""
    require(type(scopes) is dict and set(scopes) == TOKEN_SCOPES,
            'EXACT_TOKEN_ONLY_SCOPES_REQUIRED')
    worker = scopes['policyTokenFiniteWorkerSession']
    require(worker.get('schema') == 'ouf.policy-token-governed-worker-session.v1'
        and worker.get('predecessorGrantAttempts') == 69
        and worker.get('maximumCumulativeGrantAttempts') == 197
        and worker.get('policy', {}).get('max_attempts') == 128
        and worker['policy'].get('max_elapsed') == 3600
        and worker.get('automaticBudgetRenewalAllowed') is False,
        'EXACT_REVIEWED_TOKEN_ONLY_BUDGET_REQUIRED')
    require(type(closure) is dict and set(closure) == {'declaration','executables','stdlibHash','stdlibFileCount'}
        and closure['declaration'].get('requiredPythonFlags') == ['-I','-B','-S']
        and scopes['policyTokenOwnerInstallation'].get('sourceClosureHash') == digest(closure),
        'EXACT_TOKEN_EXECUTABLE_CLOSURE_REQUIRED')
    require(worker.get('reviewHash') == proposal_binding.get('sha256')
        and all(human_binding.get(k) == worker['requestedHumanActor'][k] for k in ('issuer','subject','tenant'))
        and type(human_binding.get('sessionId')) is str,
        'FRESH_EXACT_HUMAN_AND_PROPOSAL_REQUIRED')
    for value in (proposal_binding,candidate_binding):
        require(set(value) == {'path','sha256'} and Path(value['path']).is_absolute()
            and re.fullmatch('[0-9a-f]{64}',value['sha256']), 'EXACT_TOKEN_REVIEW_INPUT_BINDING_REQUIRED')
    require(Path(context).parent == evidence.PARENT
        and re.fullmatch('semantic-token-execution-[A-Za-z0-9_-]{8,64}',Path(context).name),
        'EXACT_PRIVATE_TOKEN_EXECUTION_CONTEXT_REQUIRED')
    return {'schema':TOKEN_REVIEW,'sourceClosure':copy.deepcopy(closure),'sourceClosureHash':digest(closure),
        'scopes':copy.deepcopy(scopes),'proposalBinding':dict(proposal_binding),'candidateBinding':dict(candidate_binding),
        'authenticatedHuman':copy.deepcopy(human_binding),'authorityDirectory':str(context),
        'creationRequestHash':digest(scopes),'predecessorHistoryHash':digest(worker['predecessorRecordHashes']),
        'predecessorIncidentRef':worker['logicalOwnerScopeHash'],
        'maximumElapsedSeconds':3600,'priorControlledGrantAttempts':69,'maximumNewTokenGrantAttempts':128,
        'maximumCumulativeGrantAttempts':197,'firstGrantReplayAuthorized':False,
        'credentialRotationAuthorized':False,'applicationLifecycleAuthorized':False,
        'authorizationGrantChangesAuthorized':False,'databaseMutationsAuthorized':False,
        'gatewayWritesAuthorized':False,'semanticApprovalAuthorized':False,'semanticProposeRetryAuthorized':False,
        'executionMode':'FOREGROUND_NO_RESTART_CANCEL_ON_TERMINAL_SIGNAL',
        'completedTechnicalPhases':8,'functionalMilestonesProven':0,
        'budgetReset':False,'automaticRenewalAllowed':False,'acceptanceGranted':False}


def validate_token_decision(review, decision, now):
    require(review.get('schema') == TOKEN_REVIEW and set(review.get('scopes',{})) == TOKEN_SCOPES,
            'CURRENT_TOKEN_ONLY_REVIEW_REQUIRED')
    require(set(decision) == {'schema','approvalRef','reviewHash','sourceClosureHash','humanSessionHash',
            'approvedAt','expiresAt','decision','state'}
        and decision['schema'] == 'ouf.semantic-token-only-terminal-decision.v1'
        and decision['decision'] == TOKEN_DECISION and decision['state'] == 'ACTIVE'
        and re.fullmatch('semantic-token-[0-9a-f]{24}-[0-9]+', decision['approvalRef'])
        and decision['reviewHash'] == digest(review)
        and decision['sourceClosureHash'] == review['sourceClosureHash']
        and decision['humanSessionHash'] == digest(review['authenticatedHuman'])
        and type(decision['approvedAt']) is int and type(decision['expiresAt']) is int
        and decision['approvedAt'] <= now < decision['expiresAt']
        and decision['expiresAt']-decision['approvedAt'] == review['maximumElapsedSeconds'] == 3600,
        'EXACT_CURRENT_TOKEN_ONLY_DECISION_REQUIRED')


def terminal_token_decision(review, review_path):
    require(review.get('schema') == TOKEN_REVIEW, 'TOKEN_REVIEW_BEFORE_TERMINAL_DECISION_REQUIRED')
    review_hash = digest(review)
    summary = ('\nNuova sessione finita del solo token di lettura policy.\n'
        'Fasi tecniche 8/8 conservate; funzionali 0/6.\n'
        'Revisione privata: '+str(review_path)+'\nSHA256: '+review_hash+'\n'
        'Il worker precedente resta CANCELLED_BY_OWNER. Questa decisione apre una nuova sessione.\n'
        '69 tentativi controllati precedenti conservati; massimo 128 nuovi, cumulativo massimo 197.\n'
        'Massimo 3600 secondi dalla decisione; nessun rinnovo automatico o replay del primo grant.\n'
        'Riusa la credenziale esistente; pubblica solo il token policy. Nessuna rotazione o modifica grant.\n'
        'Nessuna operazione su container, database, Gateway o proposta semantica.\n'
        'La readiness Registry deve ancora essere provata; le approvazioni semantiche restano nel THS.\n'
        'Il comando resta in primo piano: lascia aperto questo terminale. Ctrl-C cancella la sessione.\n'
        'Per approvare la revisione esatta scrivi: APPROVO '+review_hash+'\n> ')
    fd = os.open('/dev/tty', os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd), 'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
        termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,summary.encode('utf-8'))
        for attempt in range(1,TERMINAL_ATTEMPTS+1):
            answer,count=terminal_line(fd)
            accepted,detail=terminal_answer(answer,('APPROVO '+review_hash).encode('ascii'),count)
            if accepted:break
            os.write(fd,b'\n'+encoded({'status':'NOT_ACCEPTED','attempt':attempt,**detail})+b'\n> ')
        require(accepted,'TOKEN_ONLY_SESSION_NOT_APPROVED')
    finally:os.close(fd)
    now=int(time.time())
    return {'schema':'ouf.semantic-token-only-terminal-decision.v1',
        'approvalRef':'semantic-token-'+review_hash[:24]+'-'+str(now),
        'reviewHash':review_hash,'sourceClosureHash':review['sourceClosureHash'],
        'humanSessionHash':digest(review['authenticatedHuman']),'approvedAt':now,'expiresAt':now+3600,
        'decision':TOKEN_DECISION,'state':'ACTIVE'}


def terminal_login_window_decision(review):
    """Local operator consent only; this is not an authenticated HUMAN mandate."""
    require(review.get('schema')=='ouf.human-expired-login-window-review.v1',
            'EXACT_EXPIRED_LOGIN_REVIEW_REQUIRED')
    review_hash=digest(review)
    summary=('\nRiapertura esplicita della sola finestra di login HUMAN.\n'
        'Il login precedente e scaduto; il suo journal resta intatto.\n'
        'Tentativi OAuth gia consumati: '+str(review['priorOAuthAttempts'])+'; residui massimi: '
        +str(review['maximumRemainingOAuthAttempts'])+'; cumulativo massimo: '
        +str(review['maximumCumulativeOAuthAttempts'])+'.\n'
        'Nuova finestra: 7200 secondi. Nessun rinnovo automatico.\n'
        'Questo consenso locale non autentica HUMAN e non autorizza il worker.\n'
        'Seguono login nel browser e revisione esatta separata prima delle firme.\n'
        'Revisione SHA256: '+review_hash+'\n'
        'Per aprire il login scrivi: RIAPRO LOGIN '+review_hash+'\n> ')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
        termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,summary.encode('utf-8'))
        for attempt in range(1,TERMINAL_ATTEMPTS+1):
            answer,count=terminal_line(fd)
            accepted,detail=terminal_answer(answer,('RIAPRO LOGIN '+review_hash).encode('ascii'),count)
            if accepted:break
            os.write(fd,b'\n'+encoded({'status':'NOT_ACCEPTED','attempt':attempt,**detail})+b'\n> ')
        require(accepted,'LOGIN_WINDOW_NOT_APPROVED')
    finally:os.close(fd)
    now=int(time.time())
    return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':review_hash,
        'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}


def issue_token_action(review, decision, human_session):
    """Issue with existing scoped keys only after fresh authenticated exact approval."""
    from tools.chatbot_file_cohort.human_session import HumanSession
    require(type(human_session) is HumanSession and human_session.current() == review['authenticatedHuman'],
            'FRESH_AUTHENTICATED_TOKEN_SESSION_DECISION_REQUIRED')
    now=int(time.time());validate_token_decision(review,decision,now)
    for program in review['sourceClosure']['executables'].values():command_matches(program)
    library=stdlib_binding()
    require(digest(library) == review['sourceClosure']['stdlibHash']
        and len(library['fileHashes']) == review['sourceClosure']['stdlibFileCount'], 'APPROVED_PYTHON_STDLIB_CHANGED')
    profile=evidence.decode(governance.public_input(governance.PROFILE))
    policy=evidence.decode(governance.public_input(governance.POLICY))
    governance.authority_metadata(profile,policy,now)
    expected={k:review[k] for k in ('sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')}
    expected['intakeHash']=digest(review)
    raw=encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',
        **{k:v for k,v in expected.items() if k!='intakeHash'},'issuedAt':now,'expiresAt':decision['expiresAt'],
        **review['scopes'],'semanticTokenOnlyExecution':{'reviewHash':digest(review),
            'humanSessionHash':decision['humanSessionHash'],'approvalRef':decision['approvalRef']},
        'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False})
    mandate=encoded({'schema':'ouf.semantic-cutover-human-mandate.v1','approvalRef':decision['approvalRef'],
        'decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY','state':'ACTIVE',
        'issuedAt':decision['approvedAt'],'expiresAt':decision['expiresAt'],
        'executionAuthorityHash':hashlib.sha256(raw).hexdigest(),**expected})
    from tools.semantic_policy_token_owner.producer import protected_directory
    context=Path(review['authorityDirectory'])
    require(context.parent==evidence.PARENT,'EXACT_TOKEN_EXECUTION_AUTHORITY_PARENT_REQUIRED')
    from tools.chatbot_file_cohort.action_process import private_file
    require(private_file({'path':str(context/'review.json'),'sha256':digest(review)},8388608)==encoded(review),
            'EXACT_PUBLISHED_TOKEN_REVIEW_REQUIRED')
    with protected_directory(context) as directory:
        require(publish(directory,'issuance.claim.json',encoded({'reviewHash':digest(review),
            'decisionHash':digest(decision),'automaticReplayAllowed':False})), 'TOKEN_ISSUANCE_ALREADY_CONSUMED')
        for name,body in (('decision.json',encoded(decision)),('human.json',mandate),('authority.json',raw)):
            require(publish(directory,name,body),'TOKEN_ISSUANCE_ARTIFACT_ALREADY_EXISTS')
        verifier=DetachedAuthenticator(governance.POLICY,str(context),review['sourceClosure']['executables']['openssl'])
        mandate_hash=hashlib.sha256(mandate).hexdigest()
        gate=CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':mandate_hash},
            mandate_hash,governance.CONTEXT,expected)
        for role,issuer_key in (('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            gate.mandate(raw);validate_token_decision(review,decision,int(time.time()))
            require(human_session.current()==review['authenticatedHuman']
                and evidence.decode(governance.public_input(governance.PROFILE))==profile
                and evidence.decode(governance.public_input(governance.POLICY))==policy,
                'TOKEN_SIGNING_HUMAN_OR_ROLE_POLICY_CHANGED')
            signer=ExistingEd25519Signer(profile['keyBindings']['installer'],profile['keyRefs']['installer'],verifier,
                {'role':role,'issuerRef':governance.CONTEXT[issuer_key],
                    'installationRef':governance.CONTEXT['installationRef'],'entityRef':governance.CONTEXT['entityRef']})
            require(publish(directory,hashlib.sha256(raw).hexdigest()+'.'+role+'.json',signer.sign(raw)),
                    'TOKEN_SIGNATURE_ALREADY_EXISTS')
        gate(raw)
    return AggregateAction(gate,raw,review['sourceClosureHash'])


def compile_review(*, source_closure, execution_profile, scopes, phase_intents,
                   lineage, input_hashes, maximum_seconds=3600):
    require(type(execution_profile) is FileOnlyProfile,
            'REAL_FILE_ONLY_EXECUTION_PROFILE_REQUIRED')
    profile_hash = execution_profile.verify(execution_profile.request)
    require(type(scopes) is dict and set(scopes) == REQUIRED_SCOPES
            and all(type(v) is dict and v for v in scopes.values()),
            'COMPLETE_EXACT_AGGREGATE_ACTION_SCOPES_REQUIRED')
    require(type(phase_intents) is dict and set(phase_intents) == set(PHASES)
            and all(type(v) is dict and v for v in phase_intents.values()),
            'ALL_ELEVEN_REVIEWED_APPLICATION_PHASES_REQUIRED')
    require(type(lineage) is dict and set(lineage) == {'predecessorHistoryHash', 'predecessorIncidentRef'}
            and all(re.fullmatch('[0-9a-f]{64}', str(v)) for v in lineage.values()),
            'RETAINED_PREDECESSOR_HISTORY_AND_INCIDENT_REQUIRED')
    require(type(source_closure) is dict and set(source_closure) == {'declaration', 'executables', 'stdlibHash', 'stdlibFileCount'}
            and source_closure['declaration'].get('requiredPythonFlags') == ['-I', '-B', '-S']
            and source_closure['declaration'].get('entryModule') == 'tools.chatbot_file_cohort.delivery'
            and type(source_closure['executables']) is dict
            and {'python', 'docker', 'openssl', 'systemctl', 'systemdRun'} <= set(source_closure['executables'])
            and re.fullmatch('[0-9a-f]{64}', str(source_closure['stdlibHash']))
            and type(source_closure['stdlibFileCount']) is int and source_closure['stdlibFileCount'] > 0,
            'EXACT_FULL_EXECUTABLE_AND_STDLIB_CLOSURE_REQUIRED')
    closure_hash = digest(source_closure)
    require(scopes['policyTokenOwnerInstallation']['sourceClosureHash'] == closure_hash,
            'OWNER_AND_APPLICATION_EXECUTING_CLOSURE_MUST_MATCH')
    require(type(input_hashes) is dict and input_hashes
            and all(type(k) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_.:-]{0,127}', k)
                    and type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for k, v in input_hashes.items()),
            'EXACT_PRIVATE_PREPARED_INPUT_BINDINGS_REQUIRED')
    require(type(maximum_seconds) is int and 1 <= maximum_seconds <= 3600,
            'FINITE_HUMAN_ACCEPTANCE_WINDOW_REQUIRED')
    worker = scopes['policyTokenFiniteWorkerSession']
    recovery=scopes['applicationRegistryCutover'].get('postGrantRecovery')
    paused=type(recovery)is dict and recovery.get('profile')in('ouf.chatbot-paused-unsigned-attestation-reprocessing.v1','ouf.chatbot-paused-unsigned-attestation-reprocessing.v2','ouf.chatbot-signed-paused-admission-reprocessing.v1')
    backup=type(recovery)is dict and recovery.get('profile')=='ouf.chatbot-verified-registry-mcp-backup-recovery.v1'
    migration=type(recovery)is dict and recovery.get('profile')=='ouf.chatbot-created-mcp-migration-continuation.v1'
    gateway=type(recovery)is dict and recovery.get('profile')=='ouf.chatbot-gateway-schema-continuation.v1'
    ingestion=gateway and 'retainedCreatedIngestion' in recovery
    prior=10 if gateway and 'retainedFailedIngestion' in recovery else 9 if ingestion else 8 if gateway else 6 if migration else 5 if backup else 4 if paused and recovery['profile']=='ouf.chatbot-signed-paused-admission-reprocessing.v1'else(3 if paused and recovery['profile'].endswith('.v2')else(2 if paused else 1))
    if paused or backup or migration or gateway:
        require(worker.get('schema')=='ouf.policy-token-new-finite-worker-session.v'+str(prior)
            and worker.get('predecessorCancelledWorkerHash')==recovery['cancelledWorkerHash']
            and worker.get('predecessorWorkerSessionHash')==recovery['workerSessionHash']
            and worker.get('newBudget')==recovery['newBudget'],'EXACT_PAUSED_CUMULATIVE_WORKER_REVIEW_REQUIRED')
    require(worker['policy']['max_elapsed'] <= maximum_seconds
            and worker['legacyHistoryDisposition'] == 'UNKNOWN_RETAINED_NOT_RECONCILED'
            and worker['predecessorGrantAttempts'] == prior
            and worker['automaticBudgetRenewalAllowed'] is False
            and worker['consumedClaimReplayAllowed'] is False,
            'DISTINCT_FINITE_WORKER_AND_RETAINED_UNKNOWN_HISTORY_REQUIRED')
    value = {'schema': SCHEMA, 'sourceClosure': copy.deepcopy(source_closure),
        'sourceClosureHash': closure_hash, 'deploymentProfile': PROFILE,
        'executionProfileHash': profile_hash,
        'creationRequestHash': digest(execution_profile.request),
        **copy.deepcopy(lineage), 'scopes': copy.deepcopy(scopes),
        'phaseIntentHashes': {name: digest(intent) for name, intent in phase_intents.items()},
        'privateInputHashes': copy.deepcopy(input_hashes),
        'maximumElapsedSeconds': maximum_seconds, 'freshHumanDecisionRequired': True,
        'maximumExistingInstallerSignatures': 2, 'additionalNodeAttestationSignatures': 0 if backup or migration or gateway else 1,
        'firstControlledGrantMaximumAttempts': 1, 'firstControlledGrantMaximumSeconds': 300,
        'finiteWorkerMaximumAttempts': worker['policy']['max_attempts'],
        'finiteWorkerMaximumSeconds': worker['policy']['max_elapsed'],
        'legacyHistoricalGrantAttempts': None, 'historicalAccountingReconciled': False,
        'automaticReplayAllowed': False, 'databaseRestoreAuthorized': False,
        'r12ReplayAuthorized': False, 'automaticBudgetRenewalAllowed': False,
        'permanentRuntimeAcceptance': False, 'chatbotEndToEndProven': False,
        'budgetReset': False, 'notReleaseAcceptance': True}
    require(len(encoded(value)) <= 262144, 'BOUNDED_WHOLE_ACTION_REVIEW_REQUIRED')
    return value


def validate_decision(review, decision, now):
    require(type(review) is dict and review.get('schema') == SCHEMA,
            'CURRENT_FULL_ACTION_REVIEW_REQUIRED')
    require(type(decision) is dict and set(decision) == {'schema', 'approvalRef', 'approvedReviewHash',
        'approvedSourceClosureHash', 'approvedAt', 'expiresAt', 'decision', 'state'}
        and decision['schema'] == 'ouf.chatbot-file-cohort-terminal-decision.v1'
        and decision['decision'] == DECISION and decision['state'] == 'ACTIVE'
        and type(decision['approvalRef']) is str
        and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', decision['approvalRef'])
        and decision['approvedReviewHash'] == digest(review)
        and decision['approvedSourceClosureHash'] == review['sourceClosureHash']
        and type(decision['approvedAt']) is int and type(decision['expiresAt']) is int
        and decision['approvedAt'] <= now < decision['expiresAt']
        and 0 < decision['expiresAt']-decision['approvedAt'] <= review['maximumElapsedSeconds'] <= 3600,
        'EXACT_CURRENT_FINITE_HUMAN_DECISION_REQUIRED')


def terminal_answer(raw, expected, byte_count=None):
    """Accept exact text, optionally inside one exact terminal paste envelope.

    Never normalize whitespace, Unicode, hash case or arbitrary ANSI controls.
    Returned diagnostics contain only classifications and counts, no input text.
    """
    count=len(raw) if byte_count is None else byte_count
    one_envelope=(raw.count(PASTE_START)==raw.count(PASTE_END)==1 and raw.endswith(PASTE_END))
    wrapped=one_envelope and raw.startswith(PASTE_START)
    hash_wrapped=one_envelope and raw.startswith(b'APPROVO '+PASTE_START)
    if wrapped:value=raw[len(PASTE_START):-len(PASTE_END)]
    elif hash_wrapped:value=b'APPROVO '+raw[len(b'APPROVO ')+len(PASTE_START):-len(PASTE_END)]
    else:value=raw
    wrapped=wrapped or hash_wrapped
    accepted=count<=128 and value==expected
    if accepted:reason='EXACT_BRACKETED_PASTE' if wrapped else 'EXACT_TEXT'
    elif count>128:reason='INPUT_TOO_LONG'
    elif not value:reason='EMPTY_LINE'
    elif any(c>127 for c in value):reason='NON_ASCII_BYTES'
    elif any(c<32 or c==127 for c in value):reason='TERMINAL_CONTROL_BYTES'
    elif value!=value.strip(b' \t'):reason='EDGE_WHITESPACE'
    elif re.fullmatch(rb'APPROVO [0-9a-f]{64}',value):reason='DIFFERENT_REVIEW_HASH'
    else:reason='EXACT_APPROVAL_TEXT_REQUIRED'
    return accepted,{'reason':reason,'receivedBytes':count,'expectedBytes':len(expected),
        'pasteEnvelopeRecognized':wrapped}


def terminal_line(fd):
    answer=bytearray();count=0
    while count<4096:
        part=os.read(fd,1)
        require(part,'HUMAN_TERMINAL_CLOSED')
        if part in (b'\n',b'\r'):return bytes(answer),count
        count+=1
        if count<=128:answer.extend(part)
    # Do not leave an unbounded rejected paste queued for the invoking shell.
    termios.tcflush(fd,termios.TCIFLUSH)
    return bytes(answer),count


def terminal_decision(review, review_path):
    """Only the operator controlling the terminal can answer this fresh review."""
    require(type(review) is dict and review.get('schema') == SCHEMA,
            'FULL_ACTION_REVIEW_BEFORE_TERMINAL_PROMPT_REQUIRED')
    review_hash = digest(review)
    require(Path(review_path).is_absolute(), 'PUBLISHED_PRIVATE_REVIEW_PATH_REQUIRED')
    gateway=review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-gateway-schema-continuation.v1'
    retained_gateway=bool(review.get('postGrantRecoveryReview',{}).get('retainedNumericGateway'))
    ingestion='retainedCreatedIngestion' in review.get('postGrantRecoveryReview',{})
    path_reprocessing='retainedFailedIngestion' in review.get('postGrantRecoveryReview',{})
    summary = ('\nRevisione unica del ciclo CSV/chatbot.\n'
        'Documento privato completo: '+str(review_path)+'\n'
        'SHA256: '+review_hash+'\n'
        +(('Fase tecnica 6/8: correzione PATH Ingestion; fasi 1–5 completate e conservate.\n' if path_reprocessing else
          'Fase tecnica 6/8: Ingestion già creato e mai avviato; fasi 1–5 completate e conservate.\n' if ingestion else
          'Fase tecnica 5/8: ripresa Gateway; fasi 1–4 completate e conservate.\n')+
          'Quattro backup verificati: zero nuovi dump o restore; migrazioni MCP COMPLETE e privilegi CLEAN.\n'
          'Nessun bootstrap audit, start migrazione, sostituzione UDP/Onboarding o replay Registry.\n'
          +('APISIX già sostituito: otto passi conservati, verifica soltanto; nessun nuovo stop/create/start.\n'
            'I due asset numerici verificati restano montati in sola lettura.\n' if retained_gateway else
            'APISIX viene sostituito con la stessa immagine e due asset verificati montati in sola lettura.\n')+
          ('Gateway completato: nove modifiche storiche e 28 successive conservate; zero nuove scritture.\n'
            'Le 74 route della mappa finale vengono verificate, comprese quelle estranee preservate.\n'
            +('Container Ingestion fallito e claim start conservati; una sola rinomina del CID fallito.\n'
            'Nuovo container dalla stessa immagine: cambia solo PATH, ricavato dai default verificati.\n'
            'Un solo create e start; esiti ambigui richiedono riconciliazione, senza replay.\n'
            'Dieci grant restano conteggiati; il prossimo effettivo sarà l’undicesimo cumulativo.\n' if path_reprocessing else
            'Nessun nuovo rename o create Ingestion: il claim esistente viene riconciliato in sola lettura.\n'
            'Env verificato contro immagine esatta e richiesta; un solo start del container mai avviato.\n'
            'Nove grant restano conteggiati; il prossimo effettivo sarà il decimo cumulativo.\n') if ingestion else
          'Sono conservate nove modifiche Gateway e il decimo claim ambiguo: 28 modifiche restanti,\n'
          'con nuovo intento per lo schema corretto e verifica integrale delle route prima e dopo ogni scrittura.\n'
          'Otto grant restano conteggiati; il prossimo effettivo sarà il nono cumulativo.\n')+
          'La nuova finestra ha massimo 128 tentativi e 3600 secondi, senza rinnovo automatico.\n'
          'Le verifiche di autorizzazione transitorie attendono con budget persistente, jitter e Retry-After.\n'
          if gateway else '')
        +('Fase tecnica 2/8: ripresa dal container MCP già creato e mai avviato.\n'
          'Quattro backup COMPLETE copiati e verificati: zero nuovi dump, zero restore.\n'
          'Nessun nuovo create MCP, bootstrap del ruolo audit o replay delle dieci fasi Registry.\n'
          'Una sola prenotazione di start sul container esistente; esito ambiguo richiede riconciliazione.\n'
          'Configurazione Docker verificata contro immagine originale e richiesta, inclusi Env e Labels.\n'
          'Sei grant consumati restano conteggiati; il prossimo nuovo grant sarà il settimo cumulativo.\n'
          'Nuova finestra finita di massimo 128 tentativi e 3600 secondi; nessun rinnovo automatico.\n'
          if review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-created-mcp-migration-continuation.v1' else '')
        +('Ripresa dopo backup MCP fallito, con Registry già avviato e verificato.\n'
          'Dieci fasi Registry completate restano immutate; nessun replay o nuova attestazione.\n'
          'I tre backup validi sono copiati e verificati; il dump MCP vuoto e il claim fallito restano nello storico.\n'
          'Un solo nuovo dump MCP usa il ruolo amministrativo indicato nella revisione privata.\n'
          'Il ruolo applicativo resta invariato; nessun restore o reset del database.\n'
          'Cinque grant consumati restano conteggiati; il prossimo nuovo grant sarà il sesto cumulativo.\n'
          'Nuova sessione di massimo 128 tentativi e 3600 secondi, senza rinnovo automatico.\n'
          if review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-verified-registry-mcp-backup-recovery.v1' else '')
        +('Ripresa dopo attestazione firmata e controllo precedente alla migrazione.\n'
          'Le sette fasi applicate, la firma precedente, i due intenti falliti e il nuovo intento sospeso restano nello storico.\n'
          'Questa decisione autorizza una nuova attestazione con il codice corretto sullo stesso processo in pausa.\n'
          'Una sola nuova ammissione DB richiede la verifica owner del database ancora chiuso e del backup conservato.\n'
          'Il flag prudenziale databaseMayHaveChanged resta true; nessun ripristino DB o reset.\n'
          'Quattro grant consumati restano conteggiati; il prossimo nuovo grant sara il quinto cumulativo.\n'
          'Nessun replay CREATE/STAGE/SIGUSR1 o primo grant; nuova finestra finita, vecchie firme e claim intatti.\n'
          if review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-signed-paused-admission-reprocessing.v1'else'')
        +('Ripresa dopo correzione della validità del token montato, sullo stesso Registry in pausa.\n'
          'Le sei fasi completate e i due intenti falliti restano conservati con backup e blocco DB.\n'
          'Tre grant già consumati restano conteggiati; il prossimo nuovo grant sarà il quarto cumulativo.\n'
          'Il nuovo worker verifica la scadenza pubblicata e IAM corrente; il minimo di 90 secondi resta invariato.\n'
          'Il precedente esecutore è spento e il worker cancellato; questa decisione non estende la vecchia autorità.\n'
          'Nessun replay CREATE/STAGE/SIGUSR1, nessun reset o rinnovo automatico.\n'
          if review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-paused-unsigned-attestation-reprocessing.v2'else'')
        +('Ripresa dell’attestazione non firmata sullo stesso Registry già in pausa.\n'
          'Le sei fasi completate, il backup e il blocco connessioni DB sono conservati.\n'
          'Si correggono solo la proposta OCI e la baseline dei punti di mount; nessun replay CREATE/STAGE/SIGUSR1.\n'
          'Due grant già consumati restano conteggiati; un nuovo worker ha un budget finito distinto.\n'
          'Il precedente intento fallito resta integralmente nello storico; nessun reset o rinnovo automatico.\n'
          if review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-paused-unsigned-attestation-reprocessing.v1' else (
          'Ripresa dopo un primo grant già consumato e un worker cancellato senza rinnovi.\n'
          'Si conserva il container Registry già creato; zero nuovi caricamenti immagini e zero replay CREATE.\n'
          'Le quattro fasi già applicate, il backup e il blocco nuove connessioni DB restano conservati.\n'
          'Nessuna nuova rotazione credenziale, nessuna ripetizione del primo grant o del ritiro timer.\n'
          'Questa decisione autorizza un nuovo worker finito; il totale riparte da un grant già consumato.\n'
          if review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-postgrant-created-continuation.v1' else ''))
        +('Ripresa con nuova finestra finita: '+str(len(review['previousFiniteActions']))+
          ' tentativi precedenti scaduti e spenti, storico e claim conservati.\n'
          'Verificata assenza di migrazioni e primo grant nei tentativi precedenti.\n'
          if review.get('previousFiniteActions') else '')+
        ('Il caricamento semantic precedente è riconciliato con manifest, configurazione e filesystem esatti.\n'
         'L\'immagine già presente viene verificata senza nuovo caricamento; tentativo precedente conservato.\n'
          if any(p.get('imageImportReadback') for p in review.get('previousFiniteActions',[])) else '')+
        ('Ripresa prima del primo grant: cinque immagini e generazione APISIX già verificate.\n'
         'Il precedente mask/stop e la directory token sono riconciliati senza ripeterli.\n'
         'Il timer mascherato conserva lo stato failed; nessun reset-failed.\n'
         'La vecchia prenotazione resta intatta; una sola continuazione esplicita, senza replay.\n'
          if review.get('scopes',{}).get('policyTokenOwnerInstallation',{}).get('pregrantRecovery') is not None else '')+
        ('La credenziale già pubblicata viene verificata e riutilizzata: zero nuove rotazioni.\n'
         'La sessione precedente scaduta con zero grant resta intatta.\n'
         'Questa nuova decisione apre un solo budget distinto: massimo un grant cumulativo e 300 secondi.\n'
          if (review.get('scopes',{}).get('policyTokenOwnerInstallation',{}).get('pregrantRecovery') or {}).get('priorCredentialMutationAttempts')==1 else '')+
        ('Ruoli già provati prima della quiescenza, accettati solo con policy owner riletta identica.\n'
          'Dopo l\'avvio del nuovo MCP si richiede una lettura MCP nuova prima del rilascio produttori.\n' if retained_gateway else
          'I ruoli OUF risultano già pubblicati: vengono riletti, senza nuova proposta se invariati.\n'
          if review.get('authorizationReview',{}).get('requiresNewRoleConfirmation') is False else
          'Eventuale conferma dei ruoli: apri il link browser esplicito; la proposta dura 15 minuti.\n')+
        ('Dopo Ingestion: sostituzione MCP, verifica complessiva e rilascio produttori.\n' if ingestion else
         'Dopo il Gateway: sostituzione Ingestion e MCP, verifica complessiva e rilascio produttori.\n' if gateway else
         'Include sostituzione dei cinque servizi applicativi, route Gateway, autorizzazioni esplicite,\n')
        +('Nuovo worker finito; checkpoint e storico precedente conservati.\n' if gateway else
          'verifica dei quattro backup esistenti, migrazioni e nuovo worker; storico conservato.\n'
          if review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-created-mcp-migration-continuation.v1' else
          'backup e migrazioni ancora previsti e nuovo worker; storico precedente conservato.\n'
          if review.get('postGrantRecoveryReview')is not None else
          'backup e migrazioni previsti, installazione owner e ritiro del servizio/timer policy-token semantic.\n')+
        'L\'attesa Registry riconcilia solo letture: massimo 128 tentativi e 3600 secondi, entro questa finestra;\n'
        'contatori e scadenze persistenti, nessuna ripetizione di start o SIGUSR1.\n'
        +('Il ruolo audit NOLOGIN resta presente con SET/CREATE/TRIGGER temporanei revocati.\n' if gateway else
          'Il ruolo audit NOLOGIN e i privilegi temporanei SET/CREATE/TRIGGER sono già presenti: nessun nuovo bootstrap.\n'
          if review.get('postGrantRecoveryReview',{}).get('profile')=='ouf.chatbot-created-mcp-migration-continuation.v1' else
          'Se MCP ha le tre migrazioni pendenti: creazione del ruolo audit NOLOGIN con amministratore DB,\n'
          'abilitazioni temporanee SET e CREATE sullo schema; se previsto nel piano, TRIGGER sulla sola security_incident.\n')+

        'Revoca verificata prima del riavvio; proprietario e privilegi preesistenti della tabella preservati.\n'
        +('APISIX completato viene riconciliato in sola lettura; nessuna nuova sostituzione.\n' if retained_gateway else
          'Include sostituzione del container APISIX con la stessa immagine e la configurazione qui revisionata.\n'
          if 'sameImageId' in review['scopes']['gatewayRuntimeInstallation'] else '')
        +('Nessun nuovo primo grant. Nuova sessione distinta di massimo '
          if review.get('postGrantRecoveryReview')is not None else
          'Un primo grant (massimo 300 secondi), poi una sessione distinta di massimo ')
        +str(review['finiteWorkerMaximumAttempts'])+' tentativi e '
        +str(review['finiteWorkerMaximumSeconds'])+' secondi.\n'
        'La storia legacy resta UNKNOWN. Nessun reset, rollback DB o rinnovo automatico del mandato.\n'
        'La finestra complessiva dura al massimo '+str(review['maximumElapsedSeconds'])
        +' secondi; non autorizza un servizio perpetuo.\n'
        'Le approvazioni applicative HUMAN restano nel loro THS.\n'
        'Per approvare questa revisione esatta scrivi: APPROVO '+review_hash+'\n> ')
    fd = os.open('/dev/tty', os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISCHR(info.st_mode) and os.isatty(fd), 'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
        # Input left while the device flow was running is not a decision made
        # after this current review. Show the prompt only after clearing it.
        termios.tcflush(fd,termios.TCIFLUSH)
        os.write(fd, summary.encode('utf-8'))
        expected=('APPROVO '+review_hash).encode('ascii')
        accepted=False
        for attempt in range(1,TERMINAL_ATTEMPTS+1):
            answer,count=terminal_line(fd)
            accepted,detail=terminal_answer(answer,expected,count)
            if accepted:break
            diagnostic={'schema':'ouf.chatbot-human-terminal-input.v1','status':'NOT_ACCEPTED',
                'attempt':attempt,'maximumAttempts':TERMINAL_ATTEMPTS,
                'runtimeAuthorityIssued':False,'inputTextPrinted':False,**detail}
            os.write(fd,b'\n'+encoded(diagnostic)+b'\n')
            if attempt<TERMINAL_ATTEMPTS:
                os.write(fd,('Riprova nello stesso prompt; usa solo il testo esatto, senza spazi aggiuntivi.\n'
                    'APPROVO '+review_hash+'\n> ').encode('ascii'))
        require(accepted,'FULL_ACTION_NOT_APPROVED')
    finally:
        os.close(fd)
    now = int(time.time())
    return {'schema':'ouf.chatbot-file-cohort-terminal-decision.v1',
        'approvalRef':'file-cohort-'+review_hash[:24]+'-'+str(now),
        'approvedReviewHash':review_hash, 'approvedSourceClosureHash':review['sourceClosureHash'],
        'approvedAt':now, 'expiresAt':now+review['maximumElapsedSeconds'],
        'decision':DECISION, 'state':'ACTIVE'}


def envelopes(review, decision, now):
    validate_decision(review, decision, now)
    expected = {key: review[key] for key in ('sourceClosureHash', 'creationRequestHash',
                                             'predecessorHistoryHash', 'predecessorIncidentRef')}
    expected['intakeHash'] = digest(review)
    authority = {'schema':'ouf.semantic-cutover-execution-authority.v2',
        **{k:v for k,v in expected.items() if k != 'intakeHash'},
        'issuedAt':now, 'expiresAt':decision['expiresAt'],
        'deploymentProfile':review['deploymentProfile'], 'executionProfileHash':review['executionProfileHash'],
        'phaseIntentHashes':copy.deepcopy(review['phaseIntentHashes']),
        **copy.deepcopy(review['scopes']), 'automaticReplayAllowed':False,
        'databaseRestoreAuthorized':False, 'r12ReplayAuthorized':False,
        'newDistinctLeaseWorkerRequired':False}
    raw = encoded(authority)
    require(len(raw) <= 131072, 'BOUNDED_SIGNED_AGGREGATE_AUTHORITY_REQUIRED')
    mandate = {'schema':'ouf.semantic-cutover-human-mandate.v2',
        'approvalRef':decision['approvalRef'], 'decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY',
        'state':'ACTIVE', 'issuedAt':decision['approvedAt'], 'expiresAt':decision['expiresAt'],
        'executionAuthorityHash':hashlib.sha256(raw).hexdigest(), **expected,
        'deploymentProfile':review['deploymentProfile'], 'executionProfileHash':review['executionProfileHash']}
    return raw, encoded(mandate), expected


def issue(review, decision, execution_profile):
    """Consume one HUMAN decision before either existing-role private-key read."""
    require(type(execution_profile) is FileOnlyProfile
            and execution_profile.verify(execution_profile.request) == review['executionProfileHash'],
            'EXACT_APPROVED_EXECUTION_PROFILE_REQUIRED')
    now = int(time.time())
    validate_decision(review, decision, now)
    programs = review['sourceClosure']['executables']
    for program in programs.values():
        command_matches(program)
    library = stdlib_binding()
    require(digest(library) == review['sourceClosure']['stdlibHash']
            and len(library['fileHashes']) == review['sourceClosure']['stdlibFileCount'],
            'APPROVED_PYTHON_STDLIB_CHANGED')
    profile = evidence.decode(governance.public_input(governance.PROFILE))
    policy = evidence.decode(governance.public_input(governance.POLICY))
    governance.authority_metadata(profile, policy, now)
    authority_raw, mandate_raw, expected = envelopes(review, decision, now)
    decision_hash = digest(decision)
    context = Path(review['scopes']['finiteActionProcess']['authorityDirectory'])
    require(context.parent == evidence.PARENT
            and re.fullmatch('chatbot-file-cohort-signed-[0-9a-f]{64}', context.name),
            'EXACT_REVIEWED_AUTHORITY_CONTEXT_DESTINATION_REQUIRED')
    name = context.name
    with evidence.protected_parent() as directory:
        claim = 'chatbot-file-cohort-human-'+decision_hash+'.claim.json'
        require(not os.path.lexists(evidence.PARENT/claim), 'HUMAN_FULL_ACTION_ISSUANCE_ALREADY_CONSUMED')
        require(publish(directory, claim, encoded({'schema':'ouf.chatbot-file-cohort-issuance-claim.v1',
            'decisionHash':decision_hash, 'reviewHash':digest(review),
            'state':'ISSUANCE_CONSUMED', 'budgetReset':False, 'automaticReplayAllowed':False})),
            'HUMAN_FULL_ACTION_ISSUANCE_ALREADY_CONSUMED')
        os.mkdir(name, 0o700, dir_fd=directory)
        os.fsync(directory)
        child = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=directory)
        try:
            publish(child, 'review.json', encoded(review))
            publish(child, 'decision.json', encoded(decision))
            publish(child, 'human.json', mandate_raw)
            publish(child, 'authority.json', authority_raw)
            verifier = DetachedAuthenticator(governance.POLICY, str(context), programs['openssl'])
            mandate_hash = hashlib.sha256(mandate_raw).hexdigest()
            gate = CutoverAuthority(verifier, {'path':str(context/'human.json'), 'sha256':mandate_hash},
                mandate_hash, governance.CONTEXT, expected, execution_profile=execution_profile)
            for role, issuer_key in (('DEPLOYMENT_INTENT','intentIssuerRef'),
                                     ('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
                gate.mandate(authority_raw)
                validate_decision(review, decision, int(time.time()))
                require(evidence.decode(governance.public_input(governance.PROFILE)) == profile
                        and evidence.decode(governance.public_input(governance.POLICY)) == policy,
                        'EXISTING_AUTHORITY_PROFILE_OR_POLICY_CHANGED')
                signer = ExistingEd25519Signer(profile['keyBindings']['installer'], profile['keyRefs']['installer'],
                    verifier, {'role':role, 'issuerRef':governance.CONTEXT[issuer_key],
                        'installationRef':governance.CONTEXT['installationRef'], 'entityRef':governance.CONTEXT['entityRef']})
                signature = signer.sign(authority_raw)
                publish(child, hashlib.sha256(authority_raw).hexdigest()+'.'+role+'.json', signature)
            gate(authority_raw)
        finally:
            os.close(child)
    return AggregateAction(gate, authority_raw, review['sourceClosureHash']), context
