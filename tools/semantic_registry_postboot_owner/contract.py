"""Distinct postboot owner contract; historical first-grant clocks stay historical.

Compilation is pure and grants no budget. Only the exact scope inside a current
CutoverAuthority can authorize installation or a counted SERVICE-token attempt.
"""
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re

CONTEXT = 'ouf.semantic-registry-postboot-owner-context.v1'
SESSION = 'ouf.policy-token-postboot-worker-session.v1'
HISTORY = 'ouf.policy-token-postboot-controlled-continuation.v1'
PROFILE = 'ouf.policy-token-postboot-finite-owner-operation.v1'
SCOPE = 'semanticRegistryPostbootOwner'
RECORDS = ('recovery.json', 'owner-session.json', 'owner-admission.json', 'owner-first-grant.json')
LEGACY = {'state': 'UNKNOWN', 'cumulativeGrantAttemptCount': None, 'reconciled': False, 'gapRemainsOpen': True}
SOURCE_FILES = frozenset({
    'tools.semantic_registry_postboot_owner.contract', 'tools.semantic_registry_postboot_owner.owner',
    'tools.semantic_registry_postboot_owner.installer', 'tools.semantic_registry_postboot_owner.scheduler',
    'tools.semantic_registry_recovery_execution.bootstrap',
    'tools.semantic_policy_token_owner.producer', 'tools.semantic_policy_token_owner.iam_admission',
    'tools.semantic_policy_token_owner.installed_owner', 'tools.semantic_policy_token_owner.supervisor',
    'tools.semantic_lease_recovery.bounded_recovery', 'tools.semantic_lease_recovery.recovery_journal'})


class Denied(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def hashed(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None


def boot(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value) is not None


def path(value):
    require(type(value) is str and 1 < len(value) <= 4096 and value.startswith('/')
            and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts,
            'EXACT_POSTBOOT_PRIVATE_PATH_REQUIRED')
    return PurePosixPath(value)


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def terminal(receipt):
    require(type(receipt) is dict and receipt.get('schema') == 'ouf.semantic-registry-bound-owner-lineage-result.v1'
            and receipt.get('status') == 'HISTORICAL_CREDENTIAL_LINEAGE_RECONCILED'
            and receipt.get('complete') is True and receipt.get('historicalCredentialOutputBindingEstablished') is True
            and receipt.get('boundedLineageStartsAtFirstControlledGrant') is True
            and receipt.get('boundedTerminalIsCurrentAuthority') is False
            and receipt.get('currentOwnerIdentityEstablished') is False
            and receipt.get('currentOwnerAdmissionProven') is False
            and receipt.get('historicalAccountingReconciled') is False
            and receipt.get('legacyHistoricalGrantAttempts') is None,
            'RECONCILED_HISTORICAL_LINEAGE_NOT_CURRENT_AUTHORITY_REQUIRED')
    rows = receipt.get('metadataLineage')
    require(type(rows) is list and 1 <= len(rows) <= 18
            and receipt.get('relatedCandidateCount') == len(rows)
            and len({r.get('candidateOrdinal') for r in rows}) == len(rows), 'BOUNDED_UNIQUE_LINEAGE_REQUIRED')
    by_id = {r['candidateOrdinal']: r for r in rows}
    for row in rows:
        require(integer(row.get('candidateOrdinal'), 0, 17)
                and all(hashed(row.get(k)) for k in ('recoveryHash', 'sessionHash'))
                and row.get('recoveryState') == 'CANCELLED' and row.get('admissionState') == 'BLOCKED'
                and row.get('sameCurrentBoot') is False and row.get('retainedFirstGrantSameCurrentBoot') is False
                and integer(row.get('attempts'), 0, 128)
                and integer(row.get('controlledPredecessorGrantAttempts'), 1, 1000000)
                and row.get('controlledCumulativeGrantAttempts')
                    == row['controlledPredecessorGrantAttempts'] + row['attempts'],
                'EXACT_PREVIOUS_BOOT_CANCELLED_LINEAGE_REQUIRED')
        previous = row.get('predecessorCandidateOrdinal')
        require(previous is None and row['controlledPredecessorGrantAttempts'] == 1
                or previous in by_id and previous != row['candidateOrdinal']
                and row['controlledPredecessorGrantAttempts'] == by_id[previous]['controlledCumulativeGrantAttempts'],
                'LINEAGE_PREDECESSOR_ACCOUNTING_REQUIRED')
    selected = receipt.get('boundedTerminalRecordOrdinal')
    referenced = [r['predecessorCandidateOrdinal'] for r in rows if r['predecessorCandidateOrdinal'] is not None]
    require(len(set(referenced)) == len(referenced) and set(by_id) - set(referenced) == {selected}
            and receipt.get('historicalOwnerAnchorOrdinal') in by_id, 'UNIQUE_RETAINED_TERMINAL_REQUIRED')
    seen = set()
    cursor = selected
    while cursor is not None:
        require(cursor not in seen and cursor in by_id, 'CYCLIC_OR_BROKEN_RETAINED_LINEAGE')
        seen.add(cursor)
        cursor = by_id[cursor]['predecessorCandidateOrdinal']
    require(seen == set(by_id), 'DISCONNECTED_RETAINED_LINEAGE')
    return copy.deepcopy(by_id[selected])


def compile_scope(context):
    fields = {'schema', 'lineageReceipt', 'predecessorJournalPath', 'retainedRecords', 'ownerInputs',
              'recovery', 'sourceClosureHash', 'sourceFiles', 'budget'}
    require(type(context) is dict and set(context) == fields and context['schema'] == CONTEXT,
            'EXACT_POSTBOOT_OWNER_CONTEXT_REQUIRED')
    receipt = context['lineageReceipt']; last = terminal(receipt)
    retained = context['retainedRecords']
    require(type(retained) is dict and set(retained) == set(RECORDS), 'COMPLETE_EXACT_PREDECESSOR_RECORDS_REQUIRED')
    row, session, marker, first = (retained[name] for name in RECORDS)
    require(digest(row) == last['recoveryHash'] and digest(session) == last['sessionHash']
            and digest(first) == receipt.get('firstGrantReceiptHash')
            and row.get('state') == 'CANCELLED' and row.get('reason') == 'CANCELLED_BY_OWNER'
            and marker.get('state') == 'BLOCKED' and marker.get('schema') == 'ouf.policy-token-owner-admission.v1'
            and session.get('schema') == 'ouf.policy-token-governed-worker-session.v1'
            and row.get('workerSessionHash') == digest(session)
            and row.get('policyHash') == digest(session.get('policy'))
            and row.get('firstGrantReceiptHash') == digest(first)
            and row.get('legacyHistory') == LEGACY
            and session.get('logicalOwnerScopeHash') == receipt.get('logicalOwnerScopeHash')
            and all(row.get(k) == session.get(k) == marker.get(k) and hashed(row.get(k))
                    for k in ('contextRef', 'generationRef')),
            'EXACT_TERMINAL_OWNER_RECORD_BINDINGS_REQUIRED')
    prior = row.get('controlledCumulativeGrantAttempts')
    require(prior == last['controlledCumulativeGrantAttempts']
            and row.get('attempts') == last['attempts']
            and row.get('controlledPredecessorGrantAttempts') == last['controlledPredecessorGrantAttempts']
            and session.get('predecessorGrantAttempts') == row['controlledPredecessorGrantAttempts']
            and integer(session.get('policy', {}).get('max_attempts'), 1, 128)
            and row['attempts'] <= session['policy']['max_attempts']
            and first.get('state') == 'TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED'
            and type(first.get('attemptSlotsConsumed')) is int and first['attemptSlotsConsumed'] == 1
            and first.get('gapRemainsOpen') is True and first.get('historicalAccountingReconciled') is False
            and first.get('legacyHistoricalGrantAttempts') is None
            and boot(first.get('bootId')) and first['bootId'] == row.get('bootId')
            and first.get('operation') == session.get('predecessorFirstGrantOperation')
            and first.get('scopeHash') == session.get('predecessorFirstGrantScopeHash'),
            'ORIGINAL_FIRST_GRANT_AND_UNKNOWN_ACCOUNTING_MUST_REMAIN_UNCHANGED')
    recovery = context['recovery']
    require(type(recovery) is dict and set(recovery) == {'planHash', 'logicalOperationRef', 'registryId', 'bootId'}
            and all(hashed(recovery.get(k)) for k in ('planHash', 'logicalOperationRef', 'registryId'))
            and boot(recovery.get('bootId')) and recovery['bootId'] != first['bootId'],
            'DISTINCT_CURRENT_BOOT_RECOVERY_BINDING_REQUIRED')
    owner = context['ownerInputs']
    require(type(owner) is dict and set(owner) == {'binding', 'iamProfile', 'tlsTrustHash', 'credentialPath',
                'credentialMetadata', 'outputDirectoryIdentity'}
            and digest(owner['binding']) == receipt.get('credentialOutputBindingHash')
            and hashed(owner['tlsTrustHash']) and type(owner['iamProfile']) is dict,
            'SAME_RETAINED_CREDENTIAL_OUTPUT_AND_CURRENT_IAM_PROFILE_REQUIRED')
    path(owner['credentialPath']); path(owner['binding']['output_directory'])
    identity = owner['outputDirectoryIdentity']
    require(type(identity) is dict and set(identity) == {'device', 'inode'}
            and integer(identity['device'], 0, 2**64) and integer(identity['inode'], 1, 2**64)
            and type(owner['credentialMetadata']) is list and len(owner['credentialMetadata']) == 9
            and all(integer(x, 0, 2**64) for x in owner['credentialMetadata']), 'CURRENT_OUTPUT_AND_CREDENTIAL_CUSTODY_REQUIRED')
    source = context['sourceFiles']
    require(hashed(context['sourceClosureHash']) and type(source) is dict and set(source) == SOURCE_FILES,
            'COMPLETE_POSTBOOT_OWNER_SOURCE_CLOSURE_REQUIRED')
    for binding in source.values():
        require(type(binding) is dict and set(binding) == {'path', 'sha256', 'metadata', 'ancestors'}
                and hashed(binding['sha256']), 'EXACT_POSTBOOT_SOURCE_FILE_BINDING_REQUIRED')
        path(binding['path'])
    budget = context['budget']
    require(type(budget) is dict and set(budget) == {'maximumGrantAttempts', 'maximumSeconds', 'attemptTimeoutSeconds', 'intervalSeconds'}
            and integer(budget['maximumGrantAttempts'], 1, 128)
            and integer(budget['maximumSeconds'], 1, 900)
            and integer(budget['attemptTimeoutSeconds'], 1, min(30, budget['maximumSeconds']))
            and integer(budget['intervalSeconds'], 1, 3600), 'EXPLICIT_FINITE_POSTBOOT_BUDGET_REQUIRED')
    predecessor = path(context['predecessorJournalPath'])
    previous_fence = session.get('fenceBinding')
    logical = receipt['logicalOwnerScopeHash']
    require(hashed(logical) and type(previous_fence) is dict and set(previous_fence) == {'path', 'value'}
            and previous_fence['path'] == str(predecessor.parent / ('semantic-functional-session-' + logical + '.fence.json'))
            and previous_fence['value'].get('schema') == 'ouf.semantic-functional-session-fence.v1'
            and previous_fence['value'].get('logicalOwnerScopeHash') == logical
            and previous_fence['value'].get('journalPath') == str(predecessor)
            and previous_fence['value'].get('active') is True, 'EXACT_PREDECESSOR_GLOBAL_FENCE_REQUIRED')
    context_hash = digest(context)
    journal = str(predecessor.parent / ('semantic-postboot-worker-' + context_hash))
    policy = {'delays': [5, 15, 60, 300, 900], 'max_attempts': budget['maximumGrantAttempts'],
              'max_elapsed': budget['maximumSeconds'], 'attempt_timeout': budget['attemptTimeoutSeconds'], 'jitter': .2}
    context_ref = digest({'operation': 'REGISTRY_POSTBOOT_EXISTING_CREDENTIAL_OWNER', 'contextHash': context_hash})
    generation_ref = digest({'contextRef': context_ref, 'bootId': recovery['bootId'], 'recovery': recovery})
    next_fence = {'path': previous_fence['path'], 'value': {
        'schema': 'ouf.semantic-postboot-owner-fence.v1', 'logicalOwnerScopeHash': logical,
        'reviewHash': context_hash, 'journalPath': journal, 'predecessorWorkerHash': digest(row),
        'bootId': recovery['bootId'], 'recoveryLogicalOperationRef': recovery['logicalOperationRef'], 'active': True}}
    return {'schema': SESSION, 'operation': 'INSTALL_CURRENT_BOOT_OWNER_WITHOUT_FIRST_GRANT_REPLAY',
        'contextHash': context_hash, 'lineageReceiptHash': digest(receipt),
        'sourceClosureHash': context['sourceClosureHash'], 'sourceFilesHash': digest(source),
        'ownerInputsHash': digest(owner), 'recovery': copy.deepcopy(recovery),
        'contextRef': context_ref, 'generationRef': generation_ref, 'journalPath': journal,
        'predecessorJournalPath': str(predecessor), 'predecessorRecordHashes': {name: digest(retained[name]) for name in RECORDS},
        'logicalOwnerScopeHash': logical, 'firstGrantReceiptHash': digest(first),
        'retainedFirstGrantBootId': first['bootId'], 'currentSessionBootId': recovery['bootId'],
        'predecessorGrantAttempts': prior, 'maximumCumulativeGrantAttempts': prior + budget['maximumGrantAttempts'],
        'controlledHistoryProfile': HISTORY, 'renewalProfile': PROFILE, 'policy': policy,
        'intervalSeconds': budget['intervalSeconds'], 'predecessorFenceBinding': copy.deepcopy(previous_fence),
        'fenceBinding': next_fence, 'firstGrantReplayAllowed': False, 'credentialRotationAllowed': False,
        'historicalClockRewriteAllowed': False, 'historicalAccountingReconciled': False,
        'automaticReplayAllowed': False, 'automaticBudgetRenewalAllowed': False, 'budgetReset': False,
        'legacyHistoricalGrantAttempts': None, 'currentAuthorityRequired': True}


def initial_record(context, gate_proof, wall, mono):
    scope = compile_scope(context)
    require(type(wall) in (int, float) and type(mono) in (int, float)
            and __import__('math').isfinite(wall) and __import__('math').isfinite(mono)
            and wall >= 0 and mono >= 0, 'FINITE_INITIAL_POSTBOOT_CLOCKS_REQUIRED')
    require(gate_proof.get('schema') == 'ouf.semantic-registry-postboot-gate-witness.v1'
            and gate_proof.get('checkpoint') == 4 and gate_proof.get('paused') is True
            and gate_proof.get('processKind') == 'GATE_WAITING'
            and gate_proof.get('recoveryPlanHash') == scope['recovery']['planHash']
            and gate_proof.get('recoveryLogicalOperationRef') == scope['recovery']['logicalOperationRef']
            and gate_proof.get('runtimeGeneration', {}).get('bootId') == scope['currentSessionBootId']
            and gate_proof['runtimeGeneration'].get('containerId') == scope['recovery']['registryId'],
            'DURABLE_PAUSED_CURRENT_BOOT_GATE_BEFORE_OWNER_INSTALLATION_REQUIRED')
    return {'schema': 'ouf.bounded-recovery.v1', 'contextRef': scope['contextRef'], 'generationRef': scope['generationRef'],
        'policyHash': digest(scope['policy']), 'state': 'NEW', 'attempts': 0,
        'startedWall': wall, 'startedMonotonic': mono, 'lastWall': wall, 'lastMonotonic': mono,
        'nextWall': None, 'nextMonotonic': None, 'reason': 'EXPLICIT_CURRENT_BOOT_OWNER_INSTALLATION',
        'renewalProfile': PROFILE, 'intervalSeconds': scope['intervalSeconds'], 'publicationCount': 0,
        'nextRenewalWall': None, 'nextRenewalMonotonic': None, 'tokenExpiresWall': None, 'tokenExpiresMonotonic': None,
        'workerSessionHash': digest(scope), 'firstGrantReceiptHash': scope['firstGrantReceiptHash'],
        'controlledHistoryProfile': HISTORY, 'controlledPredecessorGrantAttempts': scope['predecessorGrantAttempts'],
        'controlledCumulativeGrantAttempts': scope['predecessorGrantAttempts'], 'legacyHistory': copy.deepcopy(LEGACY),
        'bootId': scope['currentSessionBootId'], 'retainedFirstGrantBootId': scope['retainedFirstGrantBootId'],
        'gateGeneration': copy.deepcopy(gate_proof['runtimeGeneration']), 'initialGateWitnessHash': digest(gate_proof)}
