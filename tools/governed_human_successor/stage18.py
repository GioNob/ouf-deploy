"""One newly granted stage18 HUMAN window, four explicit requests, no refresh.

Uses the existing qualified explicit-session/operator implementation unchanged.
The exhausted predecessor profile is never rewritten or used for authentication.
"""
import copy
import os
from pathlib import Path
import time
import uuid
import ouf_stopped_snapshot as snapshot
from tools.ingestion_rollout_preparation import oauth_budget_extension as budget, continuation_common as common
from tools.ingestion_rollout_preparation import stage18_control as control
from tools.ingestion_rollout_execution import entry, private_file
from tools.governed_human_successor import contract, operator, window
from tools.governed_human_successor.session import validate_consent
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory

CHECKPOINT = {'phase': 'NOT_STARTED', 'controlPath': None}


def retained(case, closure):
    p, review, row = common.retained(case, vars(snapshot), vars(budget))
    control.preflight(entry, case, vars(snapshot), vars(budget), common)
    profile = review['executionReview']['humanReadProfile']
    previous = snapshot.decode(private_file.read(profile['journal']))
    public = contract.public_history(previous); binding = previous['binding']
    now, mono = time.time(), time.monotonic()
    common.require(previous['state'] == 'READY' and previous['attempts'] == 288
        and previous['budgetReset'] is False and binding == profile['expectedBinding']
        and previous['bootId'] == profile['expectedBootId'] == window.boot_id()
        and previous['monotonicDeadline'] == profile['expectedMonotonicDeadline']
        and common.digest(previous['governedWindowRenewal']) == profile['governedWindowReceiptHash']
        and binding['retryProfile']['maximumAttempts'] == 288
        and now >= binding['expiresAt'] and mono >= previous['monotonicDeadline']
        and now >= previous['accessExpiresAt'] and now >= previous['lastObservedAt'],
        'EXACT_EXPIRED_READY288_PREDECESSOR_REQUIRED')
    history = {k: copy.deepcopy(p['retainedOwnerHistory'][k]) for k in
        ('minimumRetainedOAuthAttempts', 'maximumCumulativeOAuthAttempts', 'ownerPlanHash', 'completedResultHash')}
    history.update(minimumRetainedOAuthAttempts=288, maximumCumulativeOAuthAttempts=292)
    new = contract.validate_review({'schema': contract.SCHEMA,
        'predecessorDirectory': binding['sessionDirectory'],
        'predecessorPublicHistoryHash': common.digest(public),
        'predecessorBindingHash': common.digest(binding), 'selectionHash': p['selectionHash'],
        'bootId': previous['bootId'], 'priorOAuthAttempts': 288, 'maximumCumulativeOAuthAttempts': 292,
        'maximumRemainingOAuthAttempts': 4, 'requestedScopes': copy.deepcopy(binding['scopes']),
        'newWindowSeconds': 7200, 'retainedOwnerHistory': history,
        'operationBinding': {'stage18CaseHash': common.digest(case),
            'budgetProposalHash': case['budgetReceipt']['proposalHash'],
            'budgetDecisionHash': case['budgetReceipt']['decisionHash'],
            'predecessorJournalHash': p['predecessorJournalHash'],
            'predecessorReviewHash': p['predecessorReviewHash'],
            'logicalOperationRef': p['logicalOperationRef'],
            'runtimeControllerHash': case['runtimeControllerHash']},
        'sourceClosureHash': closure, 'predecessorWindowExpiresAt': binding['expiresAt'],
        'freshIssuerAuthenticationRequired': True, 'oldCredentialsReusable': False,
        'oldRefreshReplayAllowed': False, 'browserConfirmationPerPollRequired': True,
        'automaticRenewalAllowed': False, 'automaticReplayAllowed': False,
        'budgetReset': False, 'runtimeAuthorityIssued': False})
    return new, profile, previous, p


def open_window(case, closure):
    operator.validate_transport(case)
    review, profile, previous, p = retained(case, closure)
    destination, ctl = operator.successor_path(review), operator.control_path(review)
    grant_root = common.root(case)
    claim = grant_root / 'stage18-human-window.claim.json'
    original_claim = Path(review['predecessorDirectory']) / 'successor-window.claim.json'
    common.require(not any(os.path.lexists(path) for path in (destination, ctl, claim, original_claim)),
        'STAGE18_HUMAN_WINDOW_ALREADY_CONSUMED_NO_REOPEN')
    CHECKPOINT.update(phase='EXPLICIT_STAGE18_HUMAN_WINDOW_CONSENT', controlPath=str(ctl))
    common.require(operator.terminal_confirm(
        'Apro UNA finestra HUMAN di 7200 secondi. Budget concesso: 288/292, quattro richieste nominali.\n'
        'Ogni richiesta richiede un comando e consenso distinto. Nessun retry automatico o refresh.\n'
        'Storico precedente e 18 stadi applicati conservati; il vecchio rollout non viene eseguito.\n'
        'Questa apertura non invia OAuth e non concede autorita runtime, THS o fonti/job.',
        'APRO FINESTRA HUMAN ' + common.digest(review)) is True, 'EXPLICIT_STAGE18_WINDOW_CONSENT_REQUIRED')
    # Revalidate all inputs after the person answers, before consuming the grant.
    common.require(retained(case, closure)[0] == review, 'STAGE18_REVIEW_CHANGED_AFTER_WINDOW_CONSENT')
    now = int(time.time())
    decision = {'schema': 'ouf.human-login-window-terminal-consent.v1', 'reviewHash': common.digest(review),
        'decision': 'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY', 'approvedAt': now, 'expiresAt': now + 7200}
    validate_consent(review, decision, time.time())
    binding = copy.deepcopy(previous['binding'])
    binding.update(sessionId=str(uuid.UUID(common.digest(decision)[:32])), sessionDirectory=str(destination),
        tokenPath=str(destination / 'human-access.jwt'), createdAt=now, expiresAt=decision['expiresAt'])
    binding['retryProfile'].update(id='ouf.human.stage18-budget-successor.v1', maximumAttempts=292)
    config = {'schema': operator.CONFIG_SCHEMA, 'review': review, 'decision': decision,
        'selection': profile['selection'], 'history': review['retainedOwnerHistory'],
        'predecessorJournal': profile['journal'], 'sourceClosureHash': closure,
        'controlDirectory': str(ctl), 'case': copy.deepcopy(case), 'confirmedRead': {}}
    # An exclusive persistent grant claim fences competing operators. No lock is
    # held for human input or network I/O. A partial write is never removed.
    Journal(grant_root).create(claim, common.encoded({'schema': 'ouf.stage18-human-grant-claim.v1',
        'caseHash': common.digest(case), 'reviewHash': common.digest(review),
        'decisionHash': common.digest(decision), 'controlPath': str(ctl),
        'priorOAuthAttempts': 288, 'maximumCumulativeOAuthAttempts': 292,
        'budgetDecisionHash': case['budgetReceipt']['decisionHash'], 'automaticReplayAllowed': False}))
    Journal(grant_root).sync()
    Journal(Path(review['predecessorDirectory'])).create(original_claim, common.encoded({
        'schema': 'ouf.human-explicit-successor-claim.v1', 'reviewHash': common.digest(review),
        'decisionHash': common.digest(decision), 'destination': str(destination),
        'priorOAuthAttempts': 288, 'maximumCumulativeOAuthAttempts': 292, 'expiresAt': decision['expiresAt'],
        'automaticReplayAllowed': False, 'budgetReset': False, 'runtimeAuthorityIssued': False}))
    Journal(Path(review['predecessorDirectory'])).sync()
    with protected_directory(ctl.parent) as fd:
        os.mkdir(ctl.name, 0o700, dir_fd=fd); os.mkdir(destination.name, 0o700, dir_fd=fd); os.fsync(fd)
    operator.write_new(ctl, 'control.json', config); operator.write_new(ctl, 'binding.json', binding)
    Journal(destination).initialize({'schema': 'ouf.chatbot-human-session.private.v1', 'binding': binding,
        'bootId': review['bootId'], 'monotonicDeadline': time.monotonic() + decision['expiresAt'] - time.time(),
        'lastObservedAt': time.time(), 'attempts': 288, 'state': 'NEW', 'budgetReset': False,
        'governedWindowRenewal': {'review': review, 'decision': decision}})
    return {'state': 'NEW', 'attempts': 288, 'remainingAttempts': 4, 'controlPath': str(ctl),
        'windowExpiresAt': decision['expiresAt'], 'newHumanWindowOpened': True}


def load(selected, case, closure):
    common.retained(case, vars(snapshot), vars(budget))
    config, binding = operator.load_control(selected, case, {}, closure)
    claim = snapshot.decode(snapshot.private_read(str(common.root(case) / 'stage18-human-window.claim.json')))
    common.require(claim == {'schema': 'ouf.stage18-human-grant-claim.v1', 'caseHash': common.digest(case),
        'reviewHash': common.digest(config['review']), 'decisionHash': common.digest(config['decision']),
        'controlPath': selected, 'priorOAuthAttempts': 288, 'maximumCumulativeOAuthAttempts': 292,
        'budgetDecisionHash': case['budgetReceipt']['decisionHash'], 'automaticReplayAllowed': False},
        'EXACT_STAGE18_CONSUMED_HUMAN_GRANT_REQUIRED')
    common.require(config['review']['operationBinding']['stage18CaseHash'] == common.digest(case)
        and config['review']['operationBinding']['runtimeControllerHash'] == case['runtimeControllerHash']
        and config['review']['priorOAuthAttempts'] == 288
        and config['review']['maximumCumulativeOAuthAttempts'] == 292,
        'SAME_STAGE18_SESSION_LIMITS_AND_RUNTIME_BINDING_REQUIRED')
    return config, binding


def execute(mode, selected, case, confirmed_read, closure):
    common.require(confirmed_read == {} and mode in ('prepare', 'open-window', 'step', 'status'),
        'ONE_EXPLICIT_STAGE18_HUMAN_MODE_REQUIRED')
    CHECKPOINT.update(phase='RETAINED_STAGE18_GRANT', controlPath=selected)
    if mode == 'prepare':
        review, _, _, _ = retained(case, closure)
        result = {'status': 'STAGE18_HUMAN_AND_RUNTIME_PREFLIGHT_NO_WINDOW', 'complete': True,
            'reviewHash': common.digest(review), 'attempts': 288, 'remainingAttempts': 4,
            'newHumanWindowOpened': False, 'readOnly': True}
    elif mode == 'open-window':
        common.require(selected is None, 'STAGE18_CONTROL_DERIVED_FROM_REVIEW')
        result = open_window(case, closure)
    else:
        load(selected, case, closure)
        result = operator.step(selected, case, {}, closure) if mode == 'step' else operator.status(selected, case, {}, closure)
        if result.get('state') == 'READY':
            result['productionTokenMarginCovered'] = result.get('tokenSecondsRemaining', 0) > 930
    return {'schema': 'ouf.ingestion-rollout-stage18-human-result.v1', 'complete': False,
        'oauthRequestsReservedThisInvocation': 0, 'maximumCumulativeOAuthAttempts': 292,
        'runtimeAuthorityIssued': False, 'budgetReset': False, 'automaticReplayAllowed': False,
        'completedTechnicalPhases': 8, 'functionalMilestonesProven': 4, 'notReleaseAcceptance': True, **result}
