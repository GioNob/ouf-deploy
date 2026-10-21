"""One explicit technical OAuth budget grant; never opens a login window.

The completed288 ledger and stopped rollout are immutable inputs. The new grant
is a separate record, not a change to the old retry profile or runtime authority.
No credential journal, bearer, key, provider or service is opened by this module.
"""
import copy
import fcntl
import os
from pathlib import Path
import select
import stat
import termios
import time


class Denied(Exception):
    pass


def require(ok, code):
    if not ok: raise Denied(code)


def identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]


def proposal(case, snapshot, *, clock=time.time):
    require(case['schema'] == 'ouf.technical-oauth-budget-extension-case.v1'
            and case['purpose'] == 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT'
            and case['maximumAdditionalOAuthAttempts'] == 4 and case['proposedCumulativeCeiling'] == 292
            and case['grantIsRuntimeAuthority'] is False, 'EXACT_FOUR_REQUEST_BUDGET_CASE_REQUIRED')
    observation = snapshot['inspect'](snapshot['CASE'])
    require(observation['journalHash'] == case['journalHash']
            and observation['reviewHash'] == case['reviewHash']
            and observation['logicalOperationRef'] == case['logicalOperationRef']
            and observation['sameBoot'] is True and observation['wallClockConsistent'] is True
            and observation['pendingStageClaim'] is False and observation['nextStage'] == 18
            and observation['recordedSecondsRemaining'] == 0
            and observation['recordedMonotonicSecondsRemaining'] == 0,
            'EXACT_EXPIRED_NO_PENDING_ROLLOUT_PREFIX_REQUIRED')
    read, decode, digest = [snapshot[k] for k in ('private_read', 'decode', 'digest')]
    context = observation['contextPath']
    review_raw = read(context + '/review.json'); review = decode(review_raw)
    require(digest(review) == case['reviewHash'], 'RETAINED_ROLLOUT_REVIEW_CHANGED')
    native = review['executionReview']; profile = native['humanReadProfile']
    binding = profile['expectedBinding']; selected = profile['selection']
    require(profile['schema'] == 'ouf.ingestion-rollout-existing-human-read-only.v1'
            and profile['readOnly'] is True and profile['minimumCumulativeAttempts'] == 288
            and profile['maximumCumulativeAttempts'] == 288
            and profile['budgetReset'] is False and profile['runtimeAuthorityIssued'] is False
            and profile['automaticReplayAllowed'] is False
            and profile['expectedBinding'] == native['humanBinding']
            and binding['selectionHash'] == digest(selected)
            and binding['retryProfile']['maximumAttempts'] == 288
            and binding['retryProfile']['automaticBudgetRenewalAllowed'] is False
            and all(binding[k] == selected[k] for k in ('issuer', 'subject', 'tenant'))
            and binding['expiresAt'] <= clock()
            and profile['journal']['path'] == binding['sessionDirectory'] + '/recovery.json',
            'EXACT_COMPLETED288_HUMAN_PROFILE_REQUIRED')
    require(profile['journal']['metadata'][5] == 1
            and native['retainedOwnerHistory']['maximumCumulativeOAuthAttempts'] == 288,
            'SAME_COMPLETED_HUMAN_AND_OWNER_HISTORY_REQUIRED')
    # No credential journal is opened, even for hashing. Its recorded seal and
    # completed count are already bound into the pinned issued rollout review.
    receipt = case['liveInputReceipt']
    require(receipt['status'] == 'RETAINED_STAGE18_LIVE_INPUTS_MATCHED_NO_AUTHORITY'
            and receipt['complete'] is True and receipt['readOnly'] is True
            and receipt['predecessorJournalHash'] == case['journalHash']
            and receipt['predecessorReviewHash'] == case['reviewHash']
            and receipt['logicalOperationRef'] == case['logicalOperationRef']
            and receipt['priorOAuthAttempts'] == 288 and receipt['additionalOAuthBudgetGranted'] is False
            and receipt['oauthRequests'] == receipt['runtimeEffectsDispatched'] == 0,
            'PINNED_COMPLETED_LIVE_INPUT_RECEIPT_REQUIRED')
    for module in ('ingestion', 'gateway'):
        i = next(i for i, stage in enumerate(native['stages']) if stage['name'] == module + '.START_REPLACEMENT')
        row = decode(read(context + '/recovery.json'))
        require(digest(row) == case['journalHash'] and profile['expectedBootId'] == row['bootId']
                and row['effects'][i]['nativeResource'] == receipt['replacementGenerations'][module],
                'SAME_RECORDED_REPLACEMENT_PROCESS_REQUIRED')
    require(read(context + '/review.json') == review_raw, 'REVIEW_CHANGED_DURING_BUDGET_PROPOSAL')
    lineage = digest({'predecessorHumanJournalPath': profile['journal']['path'],
                      'predecessorHumanProfileHash': digest(profile), 'priorOAuthAttempts': 288})
    return {'schema': 'ouf.technical-oauth-budget-extension-proposal.v1',
        'purpose': 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
        'reason': 'FINISH_TEN_STAGES_AFTER_EXPIRED_STAGE18_ROLLOUT_WITHOUT_REPLAY',
        'logicalOperationRef': case['logicalOperationRef'], 'predecessorContext': context,
        'predecessorJournalHash': case['journalHash'], 'predecessorReviewHash': case['reviewHash'],
        'predecessorHumanJournalPath': profile['journal']['path'],
        'predecessorHumanProfileHash': digest(profile), 'predecessorHumanJournalSeal': copy.deepcopy(profile['journal']),
        'retainedOwnerHistory': copy.deepcopy(native['retainedOwnerHistory']),
        'selectionHash': digest(selected), 'intendedProviderPrincipal': {k: selected[k] for k in ('issuer', 'subject', 'tenant')},
        'requestedScopes': copy.deepcopy(binding['scopes']), 'clientId': binding['clientId'],
        'liveInputReceiptHash': digest(receipt), 'lineageRef': lineage,
        'priorOAuthAttempts': 288, 'additionalOAuthAttempts': 4, 'maximumCumulativeOAuthAttempts': 292,
        'nominalRequests': ['DISCOVERY', 'DEVICE_START', 'DEVICE_POLL', 'USERINFO'],
        'automaticRetryReserve': 0, 'maximumFutureLoginWindowSeconds': 7200,
        'futureWindowRequiresSeparateTerminalConsent': True, 'freshProviderIdentityStillRequired': True,
        'providerIdentityMustMatchOriginalSelection': True, 'requiredTokenMarginSeconds': 930,
        'runtimeAuthorityStillRequiresSeparateConsent': True, 'maximumFutureRuntimeSeconds': 900,
        'oldCredentialsReusable': False, 'oldClaimsReplayAllowed': False,
        'budgetReset': False, 'automaticRenewalAllowed': False, 'automaticReplayAllowed': False,
        'humanWindowOpened': False, 'runtimeAuthorityIssued': False}


def destination(p, digest):
    parent = Path(p['predecessorContext']).parent
    return parent / ('human-oauth-budget-extension-' + digest(p))


def paths(p, digest):
    parent = Path(p['predecessorContext']).parent
    stem = 'human-oauth-budget-extension-' + p['lineageRef']
    return parent, parent / (stem + '.lock'), parent / (stem + '.claim.json'), destination(p, digest)


def root_parent(path):
    p = Path(path); fds = []; pins = []
    require(p.is_absolute() and '..' not in p.parts, 'EXACT_BUDGET_PARENT_REQUIRED')
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(fd)
        for part in p.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd); fds.append(child)
            info = os.fstat(child)
            require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, 'ROOT_BUDGET_ANCESTRY_REQUIRED')
            pins.append((fd, part, child, identity(info))); fd = child
        require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'PRIVATE_BUDGET_PARENT_REQUIRED')
        return fd, fds, pins
    except BaseException:
        for fd in reversed(fds): os.close(fd)
        raise


def recheck(pins):
    for parent, name, child, pin in pins:
        require(identity(os.fstat(child)) == pin == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                'BUDGET_PARENT_CUSTODY_CHANGED')


def create(parent, name, raw):
    require('/' not in name and name not in ('', '.', '..') and len(raw) <= 65536, 'BOUNDED_EXCLUSIVE_BUDGET_MEMBER_REQUIRED')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent)
    finally: os.close(fd)


def terminal_confirm(p, proposal_hash):
    phrase = 'CONCEDO BUDGET OAUTH 288->292 ' + proposal_hash
    fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd), 'CONTROLLING_HUMAN_TERMINAL_REQUIRED')
        termios.tcflush(fd, termios.TCIFLUSH)
        summary = ('Nuovo budget tecnico finito: 4 richieste provider, cumulativo 288->292; storico 288 immutato.\n'
            'DISCOVERY, DEVICE_START, UNA richiesta token dopo conferma browser, USERINFO; zero riserva retry.\n'
            'Motivo: completare i 10 stadi residui dello stesso rollout fermo al 18.\n'
            'Questa decisione NON apre login/finestra,NON invia OAuth e NON concede autorita runtime o THS.\n'
            'Futura finestra massima 7200 secondi con consenso separato; identita provider fresca obbligatoria.\n'
            'Il codice e tutti i comandi runtime devono essere qualificati prima del token fresco.\n'
            'Revisione SHA256:'+proposal_hash+'\nScrivi esattamente:'+phrase+'\n> ')
        os.write(fd, summary.encode())
        require(bool(select.select([fd], [], [], 60)[0]), 'BUDGET_CONSENT_TIMEOUT_NO_GRANT')
        require(os.read(fd, 1024) == phrase.encode('ascii') + b'\n', 'EXACT_BUDGET_TERMINAL_CONSENT_REQUIRED')
        return True
    finally: os.close(fd)


def grant(case, snapshot, *, confirm=terminal_confirm, clock=time.time, fault=lambda _: None):
    p = proposal(case, snapshot, clock=clock); digest = snapshot['digest']; encoded = snapshot['encoded']
    parent, lock_path, claim_path, output = paths(p, digest)
    require(not os.path.lexists(claim_path) and not os.path.lexists(output), 'BUDGET_GRANT_EXISTS_OR_PARTIAL_STATUS_ONLY')
    proposal_hash = digest(p)
    require(confirm(p, proposal_hash) is True, 'EXPLICIT_NEW_BUDGET_CONSENT_REQUIRED')
    # No lock is held while waiting for a person. This lock protects only local
    # read/CAS/exclusive publication. It is never held across provider/service I/O.
    fd, fds, pins = root_parent(parent)
    lock = None
    try:
        lock = os.open(lock_path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
        info = os.fstat(lock)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'EXACT_BUDGET_LOCK_CUSTODY_REQUIRED')
        lock_pin = identity(info)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recheck(pins)
        require(lock_pin == identity(os.stat(lock_path.name, dir_fd=fd, follow_symlinks=False)), 'BUDGET_LOCK_REPLACED')
        require(proposal(case, snapshot, clock=clock) == p, 'BUDGET_PROPOSAL_CHANGED_AFTER_CONSENT')
        require(not os.path.lexists(claim_path) and not os.path.lexists(output), 'BUDGET_GRANT_EXISTS_OR_PARTIAL_STATUS_ONLY')
        now = int(clock())
        decision = {'schema': 'ouf.technical-oauth-budget-extension-decision.v1', 'decision': 'GRANT_FOUR_ADDITIONAL_TECHNICAL_OAUTH_REQUESTS_ONLY',
            'proposalHash': proposal_hash, 'lineageRef': p['lineageRef'], 'approvedAt': now,
            'decisionRef': 'operator-oauth-budget-' + proposal_hash[:24] + '-' + str(now),
            'authorEvidence': 'EXPLICIT_LOCAL_OPERATOR_TTY_PROVIDER_PRINCIPAL_REVALIDATION_REQUIRED',
            'intendedProviderPrincipal': p['intendedProviderPrincipal'], 'reason': p['reason'],
            'priorOAuthAttempts': 288, 'additionalOAuthAttempts': 4, 'maximumCumulativeOAuthAttempts': 292,
            'maximumFutureLoginWindowSeconds': 7200, 'freshProviderIdentityStillRequired': True,
            'newHumanWindowOpened': False, 'oauthRequestsReserved': 0, 'runtimeAuthorityIssued': False,
            'budgetReset': False, 'automaticReplayAllowed': False}
        claim = {'schema': 'ouf.technical-oauth-budget-extension-claim.v1', 'proposalHash': proposal_hash,
            'decisionHash': digest(decision), 'lineageRef': p['lineageRef'], 'contextPath': str(output),
            'proposal': p, 'decision': decision,
            'priorOAuthAttempts': 288, 'maximumCumulativeOAuthAttempts': 292, 'budgetReset': False,
            'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}
        create(fd, claim_path.name, encoded(claim)); fault('AFTER_CLAIM')
        os.mkdir(output.name, 0o700, dir_fd=fd); os.fsync(fd)
        child = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd); fds.append(child)
        create(child, 'proposal.json', encoded(p)); fault('AFTER_PROPOSAL')
        create(child, 'decision.json', encoded(decision)); fault('AFTER_DECISION')
        recheck(pins)
    finally:
        if lock is not None: os.close(lock)
        for held in reversed(fds): os.close(held)
    return status(case, snapshot, clock=clock)


def status(case, snapshot, *, clock=time.time):
    p = proposal(case, snapshot, clock=clock); digest, read, decode = [snapshot[k] for k in ('digest', 'private_read', 'decode')]
    _, _, claim_path, output = paths(p, digest)
    claim = decode(read(str(claim_path))); retained = decode(read(str(output / 'proposal.json')))
    decision = decode(read(str(output / 'decision.json')))
    require(retained == p and claim['proposalHash'] == digest(p) == decision['proposalHash']
            and claim['decisionHash'] == digest(decision) and claim['contextPath'] == str(output)
            and claim['proposal'] == p and claim['decision'] == decision
            and claim['lineageRef'] == p['lineageRef'] == decision['lineageRef']
            and decision['decision'] == 'GRANT_FOUR_ADDITIONAL_TECHNICAL_OAUTH_REQUESTS_ONLY'
            and decision['priorOAuthAttempts'] == 288 and decision['additionalOAuthAttempts'] == 4
            and decision['maximumCumulativeOAuthAttempts'] == 292 and decision['budgetReset'] is False
            and decision['newHumanWindowOpened'] is False and decision['oauthRequestsReserved'] == 0,
            'EXACT_COMPLETED_NEW_TECHNICAL_BUDGET_RECORD_REQUIRED')
    return {'schema': 'ouf.technical-oauth-budget-extension-result.v1', 'complete': True,
        'status': 'NEW_TECHNICAL_OAUTH_BUDGET_GRANTED_NO_LOGIN_OR_RUNTIME_AUTHORITY',
        'contextPath': str(output), 'proposalHash': digest(p), 'decisionHash': digest(decision),
        'decisionRef': decision['decisionRef'], 'priorOAuthAttempts': 288, 'currentCumulativeOAuthAttempts': 288,
        'additionalOAuthAttemptsGranted': 4, 'maximumCumulativeOAuthAttempts': 292,
        'remainingAdditionalOAuthAttempts': 4, 'newHumanWindowOpened': False,
        'countsAsOfGrant': True, 'subsequentConsumptionNotObserved': True,
        'newLoginPerformed': False, 'oauthRequests': 0, 'engineRequests': 0, 'databaseCalls': 0,
        'gatewayRequests': 0, 'bearerFilesOpened': 0, 'humanCredentialJournalsRead': 0, 'privateKeysRead': 0,
        'runtimeAuthorityIssued': False, 'runtimeEffectsDispatched': 0, 'budgetReset': False,
        'automaticReplayAllowed': False, 'oldSessionUnchanged': True,
        'providerPrincipalStillRequiresFreshAuthentication': True, 'completedTechnicalPhases': 8,
        'functionalMilestonesProven': 4, 'notReleaseAcceptance': True}


def execute(mode, case, snapshot):
    require(mode in ('prepare', 'grant-budget', 'status'), 'ONE_EXPLICIT_BUDGET_MODE_REQUIRED')
    if mode == 'prepare':
        p = proposal(case, snapshot)
        return {'schema': 'ouf.technical-oauth-budget-extension-result.v1', 'complete': True,
            'status': 'TECHNICAL_OAUTH_BUDGET_PROPOSAL_NO_GRANT', 'proposalHash': snapshot['digest'](p),
            'priorOAuthAttempts': 288, 'proposedAdditionalOAuthAttempts': 4, 'proposedCumulativeCeiling': 292,
            'newHumanWindowOpened': False, 'newBudgetGranted': False, 'oauthRequests': 0,
            'runtimeAuthorityIssued': False, 'budgetReset': False, 'automaticReplayAllowed': False}
    return grant(case, snapshot) if mode == 'grant-budget' else status(case, snapshot)
