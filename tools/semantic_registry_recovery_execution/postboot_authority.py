"""Exact postboot review, one claimed issuance, and existing typed authority.

No key is opened during preparation/review. Issue requires a fresh controlling
terminal decision over the complete review and consumes one canonical claim
before either role signature. Existing/partial claims are never resumed.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import termios
import time
from contextlib import contextmanager

from .core import require, digest, encoded, hashed
from .factory import factory_scope, require_historical_parent
from .postboot_scopes import compile_scopes, KEYS
from tools.ingestion_readiness_patch_execution import private_file
from tools.semantic_policy_token_owner import iam_governance_intake as governance
from tools.semantic_policy_token_owner.iam_owner_action import stdlib_binding
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, private_bytes
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from cutover_authority import CutoverAuthority
from file_only_profile import FileOnlyProfile, PROFILE, PHASES

SCHEMA = 'ouf.semantic-registry-postboot-complete-review.v1'
DECISION = 'APPROVE_ONE_FINITE_REGISTRY_POSTBOOT_RECOVERY'
REVIEW_SCOPE = 'semanticRegistryPostbootReview'
PARENT = Path('/etc/ouf/deploy-snapshots')
MAXIMUM_SECONDS = 900


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_POSTBOOT_AUTHORITY_JSON_KEY')
            result[key] = value
        return result
    def invalid(_):
        require(False, 'NONFINITE_POSTBOOT_AUTHORITY_JSON')
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    require(type(value) is dict and encoded(value) == raw, 'CANONICAL_POSTBOOT_AUTHORITY_JSON_REQUIRED')
    return value


def retained(context):
    factory_scope(context)
    with private_file.opened(context['retainedInputs'], maximum=8388608) as fd:
        data = bytearray()
        while len(data) <= 8388608:
            block = os.read(fd, min(65536, 8388609 - len(data)))
            if not block:
                break
            data.extend(block)
    require(len(data) <= 8388608, 'BOUNDED_RETAINED_POSTBOOT_INPUT_REQUIRED')
    value = decode(bytes(data)); plan = context['plan']
    require(value.get('schema') == 'ouf.semantic-registry-recovery-private-historical-inputs.v1'
            and value.get('kind') == 'OFFLINE_COMPOSITION_INPUTS_NOT_EXECUTABLE_AUTHORITY'
            and value['candidateContract'] == plan
            and digest(value['historicalBinding']) == plan['stages'][0]['intent']['historicalChainHash']
            and digest(value['proposal']) == plan['stages'][0]['intent']['proposalHash'],
            'EXACT_RETAINED_POSTBOOT_HISTORY_REQUIRED')
    registry = value['registryInputs']
    require_historical_parent(registry, context['executionRoot'])
    return registry


def authority_metadata(inputs):
    require(type(inputs) is dict and set(inputs) == {'authorityProfile', 'trustPolicy', 'context',
                'executables', 'stdlibHash', 'stdlibFileCount'}
            and inputs['authorityProfile'] == governance.PROFILE
            and inputs['trustPolicy'] == governance.POLICY and inputs['context'] == governance.CONTEXT
            and hashed(inputs['stdlibHash']) and type(inputs['stdlibFileCount']) is int
            and 1 <= inputs['stdlibFileCount'] <= 4096,
            'EXACT_EXISTING_POSTBOOT_AUTHORITY_INPUTS_REQUIRED')
    programs = inputs['executables']
    require(type(programs) is dict and set(programs) == {'python', 'docker', 'openssl'},
            'COMPLETE_POSTBOOT_EXECUTABLE_BINDINGS_REQUIRED')
    for name, program in programs.items():
        fields = {'path', 'sha256', 'version'} if name == 'openssl' else {'path', 'sha256'}
        require(type(program) is dict and set(program) == fields and hashed(program['sha256'])
                and type(program['path']) is str and Path(program['path']).is_absolute()
                and '..' not in Path(program['path']).parts, 'EXACT_POSTBOOT_EXECUTABLE_BINDING_REQUIRED')
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+[a-z]?', programs['openssl']['version']) is not None,
            'EXACT_POSTBOOT_OPENSSL_VERSION_REQUIRED')
    profile = decode(governance.public_input(inputs['authorityProfile']))
    policy = decode(governance.public_input(inputs['trustPolicy']))
    governance.authority_metadata(profile, policy, int(time.time()))
    return profile, policy


def compile_review(current_context, owner_context, authority_inputs, source_closure, scopes):
    """Rebuild every native scope from the exact retained/current input bytes."""
    registry = retained(current_context)
    profile = FileOnlyProfile(registry['creationRequest'], registry['configtree'])
    boot = owner_context['recovery']['bootId']
    expected_scopes = compile_scopes(current_context, owner_context, registry, profile, boot)
    require(type(scopes) is dict and scopes == expected_scopes,
            'INDEPENDENT_COMPLETE_POSTBOOT_SCOPE_RECOMPILATION_REQUIRED')
    authority_metadata(authority_inputs)
    require(type(source_closure) is dict
            and source_closure.get('schema') == 'ouf.semantic-registry-postboot-source-closure.v1'
            and source_closure.get('entryModule') == 'tools.semantic_registry_recovery_execution.postboot_entry'
            and source_closure.get('runtimeAuthorityIssued') is False
            and source_closure.get('targetInstallationAccepted') is False
            and source_closure.get('releaseAcceptance') is False
            and owner_context['sourceClosureHash'] == current_context['nodeRecipe']['sourceClosureHash']
                == digest(source_closure), 'ONE_COMPLETE_POSTBOOT_SOURCE_DECLARATION_REQUIRED')
    for name, binding in owner_context['sourceFiles'].items():
        require(source_closure['sourceHashes'].get(name) == binding['sha256'],
                'POSTBOOT_PROTECTED_SOURCE_AND_MEMORY_DECLARATION_MISMATCH')
    plan = current_context['plan']
    return {'schema': SCHEMA, 'currentContext': copy.deepcopy(current_context),
        'ownerContext': copy.deepcopy(owner_context), 'authorityInputs': copy.deepcopy(authority_inputs),
        'sourceClosure': copy.deepcopy(source_closure), 'scopes': copy.deepcopy(expected_scopes),
        'intakeHash': digest(current_context), 'sourceClosureHash': digest(source_closure),
        'creationRequestHash': digest(registry['creationRequest']),
        'predecessorHistoryHash': plan['stages'][0]['intent']['historicalChainHash'],
        'predecessorIncidentRef': plan['retainedPredecessorIncidentRef'],
        'deploymentProfile': PROFILE, 'executionProfileHash': profile.sha256,
        'maximumElapsedSeconds': MAXIMUM_SECONDS, 'bootId': boot,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
        'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}


def recompile(review):
    require(type(review) is dict and review.get('schema') == SCHEMA, 'COMPLETE_POSTBOOT_REVIEW_REQUIRED')
    require(compile_review(review['currentContext'], review['ownerContext'], review['authorityInputs'],
                           review['sourceClosure'], review['scopes']) == review,
            'POSTBOOT_REVIEW_CHANGED_OR_INCOMPLETE')
    return review


@contextmanager
def protected_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and str(path) == str(path.absolute()),
            'EXACT_POSTBOOT_AUTHORITY_DIRECTORY_REQUIRED')
    descriptors = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); descriptors.append(fd)
        for part in path.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        for descriptor in descriptors:
            info = os.fstat(descriptor)
            require(info.st_uid == info.st_gid == 0 and stat.S_ISDIR(info.st_mode)
                    and not info.st_mode & 0o022, 'ROOT_PROTECTED_POSTBOOT_AUTHORITY_ANCESTRY_REQUIRED')
        yield fd
        for descriptor, actual in zip(descriptors, [Path('/'), *list(reversed(path.parents))[1:], path]):
            info, current = os.fstat(descriptor), actual.lstat()
            require((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
                    == (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_gid),
                    'POSTBOOT_AUTHORITY_DIRECTORY_CHANGED')
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def publish(directory, name, raw):
    require(re.fullmatch(r'[A-Za-z0-9_.-]{1,180}', name) is not None
            and type(raw) is bytes and 0 < len(raw) <= 8388608, 'EXACT_POSTBOOT_PRIVATE_ARTIFACT_REQUIRED')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        left = memoryview(raw)
        while left:
            count = os.write(fd, left); require(count > 0, 'POSTBOOT_AUTHORITY_WRITE_FAILED')
            left = left[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def checked_root(prepared_root):
    root = Path(prepared_root)
    require(root.parent == PARENT and re.fullmatch(r'semantic-registry-postboot-inputs-[0-9a-f]{64}', root.name),
            'EXACT_CURRENT_PREPARATION_ROOT_REQUIRED')
    return root


def publish_review(prepared_root, review):
    recompile(review); root = checked_root(prepared_root)
    require(Path(review['currentContext']['executionRoot']).parent == root.parent,
            'SAME_RETAINED_INSTALLATION_AUTHORITY_PARENT_REQUIRED')
    prepared_matches(root, review)
    with protected_directory(root) as fd:
        publish(fd, 'review.json', encoded(review))
    return {'path': str(root / 'review.json'), 'sha256': digest(review)}


def prepared_matches(root, review):
    with protected_directory(root) as directory:
        fd = os.open('prepared.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and stat.S_IMODE(before.st_mode) in (0o400, 0o600) and before.st_nlink == 1
                    and 0 < before.st_size <= 16777216, 'PRIVATE_CURRENT_PREPARATION_REQUIRED')
            raw = bytearray()
            while len(raw) <= before.st_size:
                part = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            def identity(value):
                return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                    == identity(os.stat('prepared.json', dir_fd=directory, follow_symlinks=False)),
                    'CURRENT_PREPARATION_CHANGED')
        finally:
            os.close(fd)
    prepared = decode(bytes(raw))
    require(prepared.get('schema') == 'ouf.semantic-registry-postboot-prepared-inputs.v1'
            and all(prepared.get(k) == review[r] for k, r in (
                ('nativeContext', 'currentContext'), ('ownerContext', 'ownerContext'),
                ('authorityInputs', 'authorityInputs'), ('sourceClosure', 'sourceClosure'))),
            'PUBLISHED_REVIEW_MUST_MATCH_EXACT_CURRENT_PREPARATION')


def read_review(prepared_root, review_binding):
    root = checked_root(prepared_root)
    require(type(review_binding) is dict and set(review_binding) == {'path', 'sha256'}
            and review_binding['path'] == str(root / 'review.json') and hashed(review_binding['sha256']),
            'EXACT_PUBLISHED_POSTBOOT_REVIEW_BINDING_REQUIRED')
    raw = private_bytes(root / 'review.json', 8388608)
    require(hashlib.sha256(raw).hexdigest() == review_binding['sha256'], 'PUBLISHED_POSTBOOT_REVIEW_HASH_DRIFT')
    review = recompile(decode(raw)); prepared_matches(root, review)
    return review


def execution_custody(review):
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'ISOLATED_SEALED_POSTBOOT_AUTHORITY_REQUIRED')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == review['bootId'],
            'CURRENT_BOOT_POSTBOOT_AUTHORITY_REQUIRED')
    closure = review['sourceClosure']
    require(type(closure['sourceHashes']) is dict and 1 <= len(closure['sourceHashes']) <= 256
            and set(closure['sourceHashes']) == set(closure['sourcePaths']),
            'COMPLETE_EXECUTED_POSTBOOT_SOURCE_MAP_REQUIRED')
    for name, expected_hash in closure['sourceHashes'].items():
        module = sys.modules.get(name)
        require(hashed(expected_hash) and module is not None
                and getattr(module, '__qualified_source_sha256__', None) == expected_hash
                and getattr(module, '__qualified_source_path__', None) == closure['sourcePaths'][name],
                'COMPLETE_SEALED_POSTBOOT_SOURCE_EXECUTION_REQUIRED')
    for name, binding in review['ownerContext']['sourceFiles'].items():
        module = sys.modules.get(name)
        require(module is not None and getattr(module, '__qualified_source_sha256__', None) == binding['sha256'],
                'SEALED_EXECUTED_POSTBOOT_SOURCE_REQUIRED')
        with private_file.opened(binding, maximum=262144):
            pass
    programs = review['authorityInputs']['executables']
    require(str(Path(sys.executable).resolve(strict=True)) == programs['python']['path'],
            'SAME_REVIEWED_POSTBOOT_PYTHON_REQUIRED')
    for program in programs.values():
        require(governance.executable(program['path']) == {k: program[k] for k in ('path', 'sha256')},
                'POSTBOOT_EXECUTABLE_CHANGED')
    result = subprocess.run([programs['openssl']['path'], 'version'], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null'})
    match = re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b', result.stdout)
    require(result.returncode == 0 and len(result.stdout) <= 256 and match is not None
            and match[1].decode() == programs['openssl']['version'], 'POSTBOOT_OPENSSL_VERSION_CHANGED')
    library = stdlib_binding()
    require(digest(library) == review['authorityInputs']['stdlibHash']
            and len(library['fileHashes']) == review['authorityInputs']['stdlibFileCount'],
            'POSTBOOT_STDLIB_CHANGED')


def terminal_decision(review, review_path):
    reviewed = digest(review); budget = review['ownerContext']['budget']
    prior = review['scopes']['semanticRegistryPostbootOwner']['predecessorGrantAttempts']
    phases = ('Ripresa checkpoint 4, ammissioni native, attestazione, rilascio e GET originale. '
        if 'semanticRegistryCheckpointResumption' in review['scopes'] else
        'Avvio gated, pausa, ammissioni native, attestazione, rilascio e GET originale. ')
    prompt = ('\nRipristino finito Registry dopo riavvio. Revisione privata: ' + str(review_path)
        + '\nSHA256: ' + reviewed + '\nTentativi SERVICE nuovi: massimo ' + str(budget['maximumGrantAttempts'])
        + '; precedenti controllati conservati: ' + str(prior) + '.\nFinestra massima: '
        + str(review['maximumElapsedSeconds']) + ' secondi. ' + phases
        + 'Nessun reset o rinnovo automatico.\n'
        + 'Per approvare questa revisione esatta scrivi: APPROVO ' + reviewed + '\n> ')
    fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd), 'CONTROLLING_POSTBOOT_HUMAN_TERMINAL_REQUIRED')
        termios.tcflush(fd, termios.TCIFLUSH)
        os.write(fd, prompt.encode())
        answer = bytearray()
        while len(answer) <= 128:
            value = os.read(fd, 1)
            if value in (b'', b'\n'):
                break
            answer.extend(value)
        require(bytes(answer) == ('APPROVO ' + reviewed).encode(), 'POSTBOOT_RECOVERY_NOT_APPROVED')
    finally:
        os.close(fd)
    now = int(time.time())
    return {'schema': 'ouf.semantic-registry-postboot-terminal-decision.v1',
        'approvalRef': 'registry-postboot-' + reviewed[:24] + '-' + str(now),
        'approvedReviewHash': reviewed, 'approvedSourceClosureHash': review['sourceClosureHash'],
        'approvedAt': now, 'expiresAt': now + review['maximumElapsedSeconds'], 'decision': DECISION, 'state': 'ACTIVE'}


def validate_decision(review, decision, now):
    require(type(decision) is dict and set(decision) == {'schema', 'approvalRef', 'approvedReviewHash',
        'approvedSourceClosureHash', 'approvedAt', 'expiresAt', 'decision', 'state'}
        and decision['schema'] == 'ouf.semantic-registry-postboot-terminal-decision.v1'
        and decision['approvedReviewHash'] == digest(review)
        and decision['approvedSourceClosureHash'] == review['sourceClosureHash']
        and decision['decision'] == DECISION and decision['state'] == 'ACTIVE'
        and type(decision['approvedAt']) is int and type(decision['expiresAt']) is int
        and decision['approvalRef'] == 'registry-postboot-' + digest(review)[:24] + '-' + str(decision['approvedAt'])
        and decision['approvedAt'] <= now < decision['expiresAt']
        and decision['expiresAt'] - decision['approvedAt'] == review['maximumElapsedSeconds'],
        'EXACT_CURRENT_POSTBOOT_TERMINAL_DECISION_REQUIRED')


def envelopes(review, decision, now):
    validate_decision(review, decision, now)
    expected = {key: review[key] for key in ('intakeHash', 'sourceClosureHash', 'creationRequestHash',
                                            'predecessorHistoryHash', 'predecessorIncidentRef')}
    # The existing typed protocol requires these fields. They grant no legacy
    # cutover scope and cannot replay any old application phase.
    phase_hashes = {phase: digest({'operation': 'POSTBOOT_RECOVERY_ONLY', 'legacyPhase': phase,
        'planHash': digest(review['currentContext']['plan']), 'legacyExecutorAuthorized': False}) for phase in PHASES}
    authority = {'schema': 'ouf.semantic-cutover-execution-authority.v2',
        **{k: v for k, v in expected.items() if k != 'intakeHash'},
        'issuedAt': now, 'expiresAt': decision['expiresAt'], 'deploymentProfile': PROFILE,
        'executionProfileHash': review['executionProfileHash'], 'phaseIntentHashes': phase_hashes,
        **copy.deepcopy(review['scopes']), REVIEW_SCOPE: {'schema': 'ouf.semantic-registry-postboot-review-scope.v1',
            'reviewHash': digest(review), 'ownerContextHash': digest(review['ownerContext']),
            'authorityInputsHash': digest(review['authorityInputs']), 'bootId': review['bootId']},
        'automaticReplayAllowed': False, 'budgetReset': False, 'databaseRestoreAuthorized': False,
        'r12ReplayAuthorized': False, 'newDistinctLeaseWorkerRequired': False}
    raw = encoded(authority)
    require(len(raw) <= 131072, 'BOUNDED_COMPLETE_POSTBOOT_AUTHORITY_REQUIRED')
    mandate = {'schema': 'ouf.semantic-cutover-human-mandate.v2', 'approvalRef': decision['approvalRef'],
        'decision': 'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY', 'state': 'ACTIVE',
        'issuedAt': decision['approvedAt'], 'expiresAt': decision['expiresAt'],
        'executionAuthorityHash': hashlib.sha256(raw).hexdigest(), **expected,
        'deploymentProfile': PROFILE, 'executionProfileHash': review['executionProfileHash']}
    return raw, encoded(mandate), expected


def claim_name(review):
    # Independent of random preparation names, changed budgets or review bytes.
    # One current-boot logical repair may consume at most one issuance attempt.
    identity = {'logicalOperationRef': review['currentContext']['plan']['logicalOperationRef'],
        'logicalOwnerScopeHash': review['ownerContext']['lineageReceipt']['logicalOwnerScopeHash'],
        'bootId': review['bootId']}
    successor = review['scopes'].get('semanticRegistryCheckpointResumption')
    if successor is not None:
        identity.update(operation='EXPLICIT_CHECKPOINT_FOUR_SUCCESSOR',
                        predecessorJournalHash=successor['predecessorJournalHash'])
    return 'semantic-registry-postboot-issuance-' + digest(identity) + '.claim.json'


def build_runtime(root, review, authority_raw, mandate_raw, expected):
    inputs = review['authorityInputs']; profile, _ = authority_metadata(inputs)
    registry = retained(review['currentContext'])
    execution_profile = FileOnlyProfile(registry['creationRequest'], registry['configtree'])
    require(execution_profile.sha256 == review['executionProfileHash'], 'REVIEWED_POSTBOOT_PROFILE_CHANGED')
    verifier = DetachedAuthenticator(inputs['trustPolicy'], str(root / 'authority'), inputs['executables']['openssl'])
    mandate_hash = hashlib.sha256(mandate_raw).hexdigest()
    gate = CutoverAuthority(verifier, {'path': str(root / 'authority' / 'human.json'), 'sha256': mandate_hash},
        mandate_hash, inputs['context'], expected, execution_profile=execution_profile)
    signer = ExistingEd25519Signer(profile['keyBindings']['attestor'], profile['keyRefs']['attestor'], verifier,
        {'role': 'CREATION_ATTESTATION', 'issuerRef': inputs['context']['attestorRef'],
            'installationRef': inputs['context']['installationRef'], 'entityRef': inputs['context']['entityRef']})
    return gate, authority_raw, verifier, signer


def issue(prepared_root, review_binding, approved_review_hash):
    review = read_review(prepared_root, review_binding); root = checked_root(prepared_root)
    require(approved_review_hash == digest(review), 'EXPLICIT_CURRENT_POSTBOOT_REVIEW_HASH_REQUIRED')
    with protected_directory(PARENT) as parent:
        try:
            os.stat(claim_name(review), dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(False, 'POSTBOOT_ISSUANCE_ALREADY_CONSUMED')
    execution_custody(review)
    decision = terminal_decision(review, review_binding['path'])
    # Recheck metadata after the operator reads/answers, before consumption.
    require(read_review(root, review_binding) == review, 'POSTBOOT_REVIEW_CHANGED_DURING_APPROVAL')
    execution_custody(review)
    raw, mandate, expected = envelopes(review, decision, int(time.time()))
    profile, policy = authority_metadata(review['authorityInputs'])
    claim = {'schema': 'ouf.semantic-registry-postboot-issuance-claim.v1', 'state': 'ISSUANCE_CONSUMED',
        'reviewHash': digest(review), 'decisionHash': digest(decision), 'authorityHash': hashlib.sha256(raw).hexdigest(),
        'preparedRoot': str(root), 'automaticReplayAllowed': False, 'budgetReset': False}
    with protected_directory(PARENT) as parent:
        publish(parent, claim_name(review), encoded(claim))
    with protected_directory(root) as directory:
        os.mkdir('authority', 0o700, dir_fd=directory); os.fsync(directory)
        child = os.open('authority', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            publish(child, 'decision.json', encoded(decision)); publish(child, 'human.json', mandate)
            publish(child, 'authority.json', raw)
            gate, _, verifier, _ = build_runtime(root, review, raw, mandate, expected)
            for role, key in (('DEPLOYMENT_INTENT', 'intentIssuerRef'), ('FINAL_DEPLOYMENT_APPROVAL', 'approvalIssuerRef')):
                gate.mandate(raw)
                validate_decision(review, decision, int(time.time()))
                require(authority_metadata(review['authorityInputs']) == (profile, policy),
                        'EXISTING_POSTBOOT_POLICY_CHANGED_DURING_ISSUANCE')
                context = review['authorityInputs']['context']
                signer = ExistingEd25519Signer(profile['keyBindings']['installer'], profile['keyRefs']['installer'],
                    verifier, {'role': role, 'issuerRef': context[key],
                        'installationRef': context['installationRef'], 'entityRef': context['entityRef']})
                signature = signer.sign(raw)
                publish(child, hashlib.sha256(raw).hexdigest() + '.' + role + '.json', signature)
            require(gate(raw) is True, 'ISSUED_COMPLETE_POSTBOOT_AUTHORITY_REQUIRED')
            receipt = {'schema': 'ouf.semantic-registry-postboot-issued-authority.v1',
                'reviewHash': digest(review), 'authorityHash': hashlib.sha256(raw).hexdigest(),
                'humanHash': hashlib.sha256(mandate).hexdigest(), 'claimHash': digest(claim),
                'runtimeAuthorityIssued': True, 'runtimeEffectsDispatched': 0,
                'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
            publish(child, 'receipt.json', encoded(receipt))
        finally:
            os.close(child)
    return receipt


def load_runtime(prepared_root, review_binding):
    review = read_review(prepared_root, review_binding); root = checked_root(prepared_root)
    execution_custody(review)
    decision = decode(private_bytes(root / 'authority' / 'decision.json'))
    raw = private_bytes(root / 'authority' / 'authority.json')
    mandate = private_bytes(root / 'authority' / 'human.json')
    issued = decode(raw)['issuedAt']
    validate_decision(review, decision, int(time.time()))
    expected_raw, expected_mandate, expected = envelopes(review, decision, issued)
    require(raw == expected_raw and mandate == expected_mandate, 'EXACT_SIGNED_POSTBOOT_REVIEW_ENVELOPES_REQUIRED')
    claim = decode(private_bytes(PARENT / claim_name(review)))
    require(claim == {'schema': 'ouf.semantic-registry-postboot-issuance-claim.v1', 'state': 'ISSUANCE_CONSUMED',
        'reviewHash': digest(review), 'decisionHash': digest(decision), 'authorityHash': hashlib.sha256(raw).hexdigest(),
        'preparedRoot': str(root), 'automaticReplayAllowed': False, 'budgetReset': False},
        'SAME_CONSUMED_POSTBOOT_ISSUANCE_CLAIM_REQUIRED')
    receipt = decode(private_bytes(root / 'authority' / 'receipt.json'))
    require(receipt == {'schema': 'ouf.semantic-registry-postboot-issued-authority.v1',
        'reviewHash': digest(review), 'authorityHash': hashlib.sha256(raw).hexdigest(),
        'humanHash': hashlib.sha256(mandate).hexdigest(), 'claimHash': digest(claim),
        'runtimeAuthorityIssued': True, 'runtimeEffectsDispatched': 0,
        'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False},
        'COMPLETE_POSTBOOT_ISSUANCE_RECEIPT_REQUIRED')
    runtime = build_runtime(root, review, raw, mandate, expected)
    require(runtime[0](raw) is True, 'CURRENT_COMPLETE_POSTBOOT_AUTHORITY_REQUIRED')
    return runtime
