"""Installation-specific retained prefix and granted-budget validation; no network.

The verified snapshot and budget namespaces are supplied by a sealed loader.
This module never opens old bearer/key files or mutates a predecessor record.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import time


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value): return hashlib.sha256(encoded(value)).hexdigest()


def require(ok, code):
    if not ok: raise ValueError(code)


def retained(case, snapshot, budget):
    require(case['schema'] == 'ouf.ingestion-rollout-stage18-successor-case.v1'
            and case['purpose'] == 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
            'EXACT_STAGE18_SUCCESSOR_CASE_REQUIRED')
    granted = budget['status'](case['budgetCase'], snapshot)
    expected = case['budgetReceipt']
    require(granted == expected and granted['complete'] is True
            and granted['status'] == 'NEW_TECHNICAL_OAUTH_BUDGET_GRANTED_NO_LOGIN_OR_RUNTIME_AUTHORITY'
            and granted['currentCumulativeOAuthAttempts'] == 288
            and granted['maximumCumulativeOAuthAttempts'] == 292,
            'EXACT_PRIVATE_COMPLETED_BUDGET_GRANT_REQUIRED')
    p = budget['proposal'](case['budgetCase'], snapshot)
    read, decode = snapshot['private_read'], snapshot['decode']
    old_review = decode(read(p['predecessorContext'] + '/review.json'))
    old_row = decode(read(p['predecessorContext'] + '/recovery.json'))
    require(digest(old_review) == p['predecessorReviewHash']
            and digest(old_row) == p['predecessorJournalHash']
            and old_row['nextStage'] == 18 and len(old_row['effects']) == 18
            and all(e['state'] == 'APPLIED' for e in old_row['effects'])
            and old_row['readState'] == 'IDLE' and old_row['stageReadAttempts'] == 0
            and old_row['budgetReset'] is False
            and old_row['expiresAt'] <= time.time()
            and old_row['expiresMonotonic'] <= time.monotonic(),
            'EXACT_EXPIRED_IDLE_EIGHTEEN_APPLIED_PREFIX_REQUIRED')
    native = old_review['executionReview']
    require(len(native['stages']) == 28
            and native['stages'][18]['name'] == 'REBIND_GATEWAY_TRANSPORT'
            and native['logicalOperationRef'] == p['logicalOperationRef']
            and all(e['stage'] == native['stages'][i]['name']
                    and e['intentHash'] == native['stages'][i]['intentHash']
                    for i, e in enumerate(old_row['effects'])), 'EXACT_ORDERED_RETAINED_INTENTS_REQUIRED')
    return p, old_review, old_row


def root(case): return Path(case['budgetReceipt']['contextPath'])


def context(case): return root(case).parent / ('ingestion-rollout-successor-' + digest(case))


def proof(case, p, old_row):
    return {'schema': 'ouf.ingestion-rollout-stage18-continuation-proof.v1',
        'caseHash': digest(case), 'budgetContext': case['budgetReceipt']['contextPath'],
        'budgetProposalHash': case['budgetReceipt']['proposalHash'],
        'budgetDecisionHash': case['budgetReceipt']['decisionHash'],
        'predecessorContext': p['predecessorContext'],
        'predecessorReviewHash': p['predecessorReviewHash'],
        'predecessorJournalHash': p['predecessorJournalHash'],
        'logicalOperationRef': p['logicalOperationRef'],
        'appliedStageCount': 18, 'retainedEffectsHash': digest(old_row['effects']),
        'priorOAuthAttempts': 288, 'maximumCumulativeOAuthAttempts': 292,
        'oldClaimsReplayAllowed': False, 'budgetReset': False}


def successor_native(case, p, old_review, old_row, profile):
    """Pure compilation; explicitly justified new limits, old history retained."""
    old = old_review['executionReview']; b = profile['expectedBinding']
    require(profile['schema'] == 'ouf.ingestion-rollout-existing-human-read-only.v1'
            and profile['readOnly'] is True and profile['minimumCumulativeAttempts'] == 292
            and profile['maximumCumulativeAttempts'] == 292
            and profile['selection'] == old['humanReadProfile']['selection']
            and b['selectionHash'] == old['humanBinding']['selectionHash']
            and all(b[k] == old['humanBinding'][k] for k in ('issuer', 'subject', 'tenant', 'clientId', 'scopes'))
            and b['retryProfile']['maximumAttempts'] == 292
            and b['retryProfile']['automaticBudgetRenewalAllowed'] is False
            and b['createdAt'] > old['humanBinding']['expiresAt']
            and b['sessionDirectory'] != old['humanBinding']['sessionDirectory']
            and all(profile[k] is False for k in ('runtimeAuthorityIssued', 'automaticReplayAllowed', 'budgetReset')),
            'EXACT_FRESH_COMPLETED292_HUMAN_SELECTION_REQUIRED')
    new = copy.deepcopy(old)
    new.update(executionContext=str(context(case)), humanBinding=copy.deepcopy(b), humanReadProfile=copy.deepcopy(profile))
    # Keep the predecessor history intact as evidence. Only the NEW current
    # review carries the explicitly granted cumulative ceiling.
    new['predecessorRetainedOwnerHistory'] = copy.deepcopy(old['retainedOwnerHistory'])
    new['retainedOwnerHistory']['maximumCumulativeOAuthAttempts'] = 292
    new['stage18ContinuationProof'] = proof(case, p, old_row)
    return new


def imported_record(case, p, old_row, scope_hash, authority_hash, expires_at, *, wall, mono, boot):
    require(old_row['bootId'] == boot and wall >= old_row['lastWall'] and mono >= old_row['lastMonotonic']
            and old_row['expiresAt'] <= wall and old_row['expiresMonotonic'] <= mono
            and 0 < expires_at - wall <= 900,
            'SAME_BOOT_EXPIRED_PARENT_AND_NEW_FINITE_AUTHORITY_REQUIRED')
    row = copy.deepcopy(old_row)
    row.update(scopeHash=scope_hash, authorityHash=authority_hash, version=old_row['version'] + 1,
        expiresAt=expires_at, expiresMonotonic=mono + expires_at - wall,
        lastWall=wall, lastMonotonic=mono, nextReadAt=wall, nextReadMonotonic=mono,
        stage18Successor={'proof': proof(case, p, old_row), 'sessionStartedAt': wall,
            'predecessorVersion': old_row['version'], 'predecessorAuthorityHash': old_row['authorityHash']})
    # effects, all native counters/resource identities, createdAt, readAttempts,
    # stageReadAttempts and incident state are copied without resetting them.
    return row


def verify_imported_prefix(case, p, old_row, row):
    require(row['effects'][:18] == old_row['effects'] and 18 <= row['nextStage'] <= 28
            and row['createdAt'] == old_row['createdAt'] and row['readAttempts'] >= old_row['readAttempts']
            and row['version'] > old_row['version'] and row['budgetReset'] is False
            and row['stage18Successor']['proof'] == proof(case, p, old_row)
            and row['stage18Successor']['predecessorVersion'] == old_row['version']
            and row['stage18Successor']['predecessorAuthorityHash'] == old_row['authorityHash'],
            'IMPORTED_STAGE18_PREFIX_OR_CUMULATIVE_HISTORY_CHANGED')
    for key, value in old_row.items():
        if key.startswith('native'):
            require(key in row and (type(row[key]) is int and row[key] >= value
                    if type(value) is int else row[key] == value), 'IMPORTED_NATIVE_RESOURCE_OR_COUNTER_RESET')
    return row
