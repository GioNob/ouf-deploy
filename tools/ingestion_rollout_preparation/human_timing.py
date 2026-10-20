"""Installation-profile-bound, offline reconciliation of recorded HUMAN timing.

This diagnostic accepts expired history, not expired authority. It reads the
exact READY journal selected by its private sealed profile, never its bearer
file. Recorded JWT timestamps are not fresh signature/provider verification.
No network, subprocess, journal write, authentication or runtime dispatch.
"""
import base64
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import time


def require(ok, code):
    if not ok:
        raise ValueError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_TIMING_DOCUMENT_FIELD')
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError('FINITE_TIMING_DOCUMENT_REQUIRED')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def metadata(s):
    return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def selected(path, expected=None):
    """Same root/no-follow custody model as retained inspection; private seal."""
    require(type(path) is str and path.startswith('/') and '\x00' not in path
            and str(PurePosixPath(path)) == path and '..' not in PurePosixPath(path).parts,
            'EXACT_TIMING_DOCUMENT_PATH_REQUIRED')
    p = PurePosixPath(path)
    fds, pins, ancestors = [], [], []
    identity = lambda s: [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(parent)
        current = '/'
        for name in [*p.parts[1:-1], None]:
            row = os.fstat(parent)
            require(stat.S_ISDIR(row.st_mode) and row.st_uid == row.st_gid == 0
                    and not row.st_mode & 0o022, 'ROOT_CUSTODIED_TIMING_ANCESTRY_REQUIRED')
            ancestors.append({'path': current, 'identity': identity(row)})
            if name is None:
                break
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(fd)
            pins.append((parent, name, fd, identity(os.fstat(fd))))
            parent = fd
            current = current.rstrip('/') + '/' + name
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        fds.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and 0 < before.st_size <= 1048576, 'EXACT_PRIVATE_TIMING_DOCUMENT_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(1048577)
        require(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
                == metadata(os.stat(p.name, dir_fd=parent, follow_symlinks=False)),
                'TIMING_DOCUMENT_CHANGED_DURING_READ')
        for directory, name, held, seal in pins:
            require(identity(os.fstat(held)) == seal
                    == identity(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                    'TIMING_ANCESTRY_CHANGED_DURING_READ')
        require(identity(os.fstat(fds[0])) == ancestors[0]['identity'], 'TIMING_ROOT_CHANGED')
        seal = {'path': path, 'sha256': hashlib.sha256(raw).hexdigest(),
                'metadata': metadata(before), 'ancestors': ancestors}
        require(expected is None or seal == expected, 'EXACT_RETAINED_TIMING_SEAL_REQUIRED')
        return decode(raw), seal
    finally:
        for fd in reversed(fds):
            os.close(fd)


def recheck(seal):
    """Metadata only, with all ancestor FDs held; no credential bytes reread."""
    fds, pins = [], []
    identity = lambda s: [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(parent)
        require(identity(os.fstat(parent)) == seal['ancestors'][0]['identity'], 'TIMING_ROOT_CHANGED')
        for item in seal['ancestors'][1:]:
            name = PurePosixPath(item['path']).name
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(fd)
            pins.append((parent, name, fd, item['identity']))
            parent = fd
        require(metadata(os.stat(PurePosixPath(seal['path']).name, dir_fd=parent, follow_symlinks=False))
                == seal['metadata'], 'TIMING_DOCUMENT_CHANGED_DURING_INSPECTION')
        for directory, name, held, expected in pins:
            require(identity(os.fstat(held)) == expected
                    == identity(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                    'TIMING_ANCESTRY_CHANGED_DURING_INSPECTION')
    finally:
        for fd in reversed(fds):
            os.close(fd)


def inspect(case, now=None):
    require(type(case) is dict and set(case) == {
        'schema', 'purpose', 'humanControlPath', 'humanSourceClosureHash', 'ownerPlanBinding',
        'productionContextPath', 'productionControlSourceHash', 'productionCaseHash',
        'expectedAttempts', 'maximumCumulativeOAuthAttempts', 'requiredTokenMarginSeconds'},
        'EXACT_INSTALLATION_TIMING_CASE_REQUIRED')
    require(case['schema'] == 'ouf.ingestion-human-timing-case.v1'
            and case['purpose'] == 'EXACT_RETAINED_INSTALLATION_DIAGNOSTIC_NOT_PORTABLE_DEFAULT'
            and type(case['expectedAttempts']) is type(case['maximumCumulativeOAuthAttempts']) is int
            and 0 <= case['expectedAttempts'] <= case['maximumCumulativeOAuthAttempts'] <= 4096
            and type(case['requiredTokenMarginSeconds']) is int
            and 0 < case['requiredTokenMarginSeconds'] <= 7200,
            'FINITE_EXPLICIT_TIMING_PROFILE_REQUIRED')
    now = time.time() if now is None else now
    require(type(now) in (int, float) and 0 < now < float('inf'), 'FINITE_OBSERVATION_CLOCK_REQUIRED')
    seals = []
    def read(path, expected=None):
        value, seal = selected(path, expected)
        seals.append(seal)
        return value, seal
    control = PurePosixPath(case['humanControlPath'])
    config, _ = read(str(control / 'control.json'))
    review = config['review']
    require(config['schema'] == 'ouf.human-explicit-successor-control.v1'
            and config['controlDirectory'] == str(control)
            and control.name == 'human-successor-control-' + digest(review)
            and config['sourceClosureHash'] == review['sourceClosureHash'] == case['humanSourceClosureHash']
            and config['decision']['reviewHash'] == digest(review)
            and config['decision']['decision'] == 'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
            and review['maximumCumulativeOAuthAttempts'] == case['maximumCumulativeOAuthAttempts'],
            'EXACT_CONSUMED_HUMAN_CONTROL_REQUIRED')
    binding, _ = read(str(control / 'binding.json'))
    profile, _ = read(str(control / 'human-read-profile.json'))
    owner, _ = read(case['ownerPlanBinding']['path'])
    require(digest(owner) == case['ownerPlanBinding']['sha256']
            and digest(config['selection']) == owner['humanBinding']['selectionHash']
            == binding['selectionHash'], 'FULL_SELECTION_MUST_MATCH_COMPLETED_OWNER_PLAN')
    session = control.parent / ('human-successor-' + digest(review))
    require(binding['sessionDirectory'] == str(session)
            and binding['tokenPath'] == str(session / 'human-access.jwt')
            and binding['createdAt'] == config['decision']['approvedAt']
            and binding['expiresAt'] == config['decision']['expiresAt']
            and profile['schema'] == 'ouf.ingestion-rollout-existing-human-read-only.v1'
            and profile['expectedBinding'] == binding and profile['selection'] == config['selection']
            and profile['minimumCumulativeAttempts'] == case['expectedAttempts']
            and profile['maximumCumulativeAttempts'] == case['maximumCumulativeOAuthAttempts']
            and profile['journal']['path'] == str(session / 'recovery.json')
            and profile['readOnly'] is True
            and all(profile[k] is False for k in ('runtimeAuthorityIssued', 'automaticReplayAllowed', 'budgetReset')),
            'EXACT_READY_PRIVATE_READ_PROFILE_REQUIRED')
    claim, _ = read(str(PurePosixPath(review['predecessorDirectory']) / 'successor-window.claim.json'))
    require(claim == {'schema': 'ouf.human-explicit-successor-claim.v1', 'reviewHash': digest(review),
        'decisionHash': digest(config['decision']), 'destination': str(session),
        'priorOAuthAttempts': review['priorOAuthAttempts'],
        'maximumCumulativeOAuthAttempts': case['maximumCumulativeOAuthAttempts'],
        'expiresAt': binding['expiresAt'], 'automaticReplayAllowed': False,
        'budgetReset': False, 'runtimeAuthorityIssued': False}, 'EXACT_CONSUMED_WINDOW_CLAIM_REQUIRED')
    row, _ = read(str(session / 'recovery.json'), profile['journal'])
    require(row['schema'] == 'ouf.chatbot-human-session.private.v1'
            and row['state'] == 'READY' and row['binding'] == binding
            and row['attempts'] == case['expectedAttempts'] and row['budgetReset'] is False
            and row['bootId'] == profile['expectedBootId']
            and row['monotonicDeadline'] == profile['expectedMonotonicDeadline']
            and digest(row['governedWindowRenewal']) == profile['governedWindowReceiptHash']
            and row['governedWindowRenewal'] == {'review': review, 'decision': config['decision']},
            'EXACT_RETAINED_READY_HISTORY_REQUIRED')
    # Read recorded token strings only in the already-sealed journal. Do not
    # open tokenPath, output strings/hashes, or treat payload decoding as IAM.
    token = row['accessToken']
    require(type(token) is str and 0 < len(token) <= 16384
            and token == row['publishedAccessToken'] and len(token.split('.')) == 3,
            'SAME_RECORDED_PUBLISHED_TOKEN_REQUIRED')
    part = token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'BOUNDED_RECORDED_JWT_PAYLOAD_REQUIRED')
    claims = decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    expiry, issued = claims.get('exp'), claims.get('iat')
    require(type(expiry) is int and expiry == row['accessExpiresAt'] and expiry > 0
            and claims.get('iss') == binding['issuer'] and claims.get('sub') == binding['subject']
            and claims.get('tenant_id') == binding['tenant'] and claims.get('azp') == binding['clientId']
            and claims.get('ouf_actor_type') == 'HUMAN'
            and (issued is None or type(issued) is int and 0 < issued <= expiry),
            'EXACT_RECORDED_HUMAN_TIMESTAMP_CONTEXT_REQUIRED')
    production = PurePosixPath(case['productionContextPath'])
    prod, _ = read(str(production / 'operator-control/recovery.json'))
    prepared, _ = read(str(production / 'preparation.json'))
    require(prod['schema'] == 'ouf.ingestion-rollout-explicit-production-control.v1'
            and prod['state'] == 'PRIVATE_READY' and prod['runtimeAuthorityIssued'] is False
            and prod['budgetReset'] is False
            and prod['controlSourceHash'] == case['productionControlSourceHash']
            and prod['caseHash'] == case['productionCaseHash']
            and digest(prepared) == prod['preparationHash']
            and prepared['controlSourceHash'] == prod['controlSourceHash']
            and prepared['caseHash'] == prod['caseHash']
            and not os.path.lexists(str(production / 'recovery.json')),
            'EXACT_UNDISPATCHED_PRODUCTION_PREPARATION_REQUIRED')
    require(re.fullmatch('[0-9a-f]{64}', prod['logicalRef']) is not None,
            'EXACT_PRODUCTION_LOGICAL_REFERENCE_REQUIRED')
    prod_claim, _ = read(str(production.parent / ('ingestion-rollout-control-' + prod['logicalRef'] + '.claim.json')))
    require(prod_claim == {'schema': prod['schema'], 'contextPath': str(production),
        'logicalRef': prod['logicalRef'], 'caseHash': prod['caseHash'],
        'controlSourceHash': prod['controlSourceHash'], 'runtimeAuthorityIssued': False,
        'automaticReplayAllowed': False}, 'EXACT_CONSUMED_PRODUCTION_CLAIM_REQUIRED')
    # Metadata-only recheck after all reads; no second credential-content read.
    for seal in seals:
        recheck(seal)
    remaining = max(0, int(expiry - now))
    lifetime = None if issued is None else expiry - issued
    return {'schema': 'ouf.ingestion-human-timing-inspection-result.v1',
        'status': 'RECORDED_READY_TIMING_RECONCILED_NO_AUTHORITY', 'complete': True, 'readOnly': True,
        'observedAtUnix': now, 'recordedState': 'READY', 'attempts': row['attempts'],
        'maximumCumulativeOAuthAttempts': case['maximumCumulativeOAuthAttempts'],
        'remainingAttempts': case['maximumCumulativeOAuthAttempts'] - row['attempts'],
        'recordedIssuedAtUnix': issued, 'recordedAccessExpiresAtUnix': expiry,
        'recordedIssuedTokenLifetimeSeconds': lifetime, 'recordedTokenSecondsRemaining': remaining,
        'requiredProductionTokenMarginSeconds': case['requiredTokenMarginSeconds'],
        'recordedIssuedLifetimeCouldCoverMargin': None if lifetime is None else lifetime > case['requiredTokenMarginSeconds'],
        'observedRemainingCoversMargin': expiry > now + case['requiredTokenMarginSeconds'],
        'humanWindowExpiresAtUnix': binding['expiresAt'], 'snapshotIsRuntimeAuthority': False,
        'currentProviderPolicyProven': False, 'providerAuthorizationReverified': False,
        'newLoginPerformed': False, 'refreshPerformed': False, 'windowExtended': False,
        'budgetReset': False, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
        'bearerFilesOpened': 0, 'credentialJournalsRead': 1, 'credentialValuesPrinted': False,
        'credentialHashesPrinted': False, 'oauthRequests': 0, 'engineRequests': 0,
        'databaseCalls': 0, 'gatewayRequests': 0, 'ownerRequests': 0, 'journalWrites': 0,
        'containerLifecycleOperations': 0, 'completedOwnerActionReplayed': False,
        'completedPublicationReplayed': False, 'completedTechnicalPhases': 8,
        'functionalMilestonesProven': 4, 'notReleaseAcceptance': True}
