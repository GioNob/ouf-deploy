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
    require(worker['policy']['max_elapsed'] <= maximum_seconds
            and worker['legacyHistoryDisposition'] == 'UNKNOWN_RETAINED_NOT_RECONCILED'
            and worker['predecessorGrantAttempts'] == 1
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
        'maximumExistingInstallerSignatures': 2, 'additionalNodeAttestationSignatures': 1,
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


def terminal_decision(review, review_path):
    """Only the operator controlling the terminal can answer this fresh review."""
    require(type(review) is dict and review.get('schema') == SCHEMA,
            'FULL_ACTION_REVIEW_BEFORE_TERMINAL_PROMPT_REQUIRED')
    review_hash = digest(review)
    require(Path(review_path).is_absolute(), 'PUBLISHED_PRIVATE_REVIEW_PATH_REQUIRED')
    summary = ('\nRevisione unica del ciclo CSV/chatbot.\n'
        'Documento privato completo: '+str(review_path)+'\n'
        'SHA256: '+review_hash+'\n'
        'Include sostituzione dei cinque servizi applicativi, route Gateway, autorizzazioni esplicite,\n'
        'backup e migrazioni previsti, installazione owner e ritiro del servizio/timer policy-token semantic.\n'
        +('Include sostituzione del container APISIX con la stessa immagine e la configurazione qui revisionata.\n'
          if 'sameImageId' in review['scopes']['gatewayRuntimeInstallation'] else '')+
        'Un primo grant (massimo 300 secondi), poi una sessione distinta di massimo '
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
        os.write(fd, summary.encode('utf-8'))
        answer = bytearray()
        while len(answer) <= 128:
            part = os.read(fd, 1)
            require(part, 'HUMAN_TERMINAL_CLOSED')
            if part in (b'\n', b'\r'):
                break
            answer.extend(part)
        require(bytes(answer) == ('APPROVO '+review_hash).encode(), 'FULL_ACTION_NOT_APPROVED')
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
