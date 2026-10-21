"""Read one pinned stopped rollout. No retained code execution or service I/O.

Installation-specific forensic snapshot, not a portable default or current
authorization proof. Does not open HUMAN journals, bearer files or private keys.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

CASE = {'schema': 'ouf.ingestion-rollout-stopped-reader-case.v1', 'purpose': 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT', 'contextPath': '/etc/ouf/deploy-snapshots/ingestion-rollout-native-7fs9r6md', 'productionCaseHash': '1406e5d2d158e069d6812091032612549ff297e05abe55e641a65761edaa227a', 'controlSourceHash': '1ef3bac5a90a39589da496ba91a840ca9f4fd7b8f44e7a97bb457fc2778c0057', 'sourceDeclarationHash': 'bf3f33b7ecc6eb06d1e9f87baf14a238338b633a6e2cd816788b04be0a8077a5', 'expectedNextStage': 18, 'expectedTotalStages': 28, 'expectedNextStageName': 'REBIND_GATEWAY_TRANSPORT', 'expectedAppliedStages': ['VERIFY_CURRENT_GATES', 'CREATE_DEDICATED_KEY', 'IMPORT_INGESTION_IMAGE', 'ingestion.DISABLE_OLD_RESTART', 'ingestion.STOP_OLD', 'ingestion.DETACH_113b5f0a3c53059b087a2ce997d2670cc057e88c0c17d4291b3b41a51ce26ba3', 'ingestion.RENAME_OLD', 'ingestion.CREATE_REPLACEMENT', 'ingestion.START_REPLACEMENT', 'ingestion.READINESS', 'gateway.DISABLE_OLD_RESTART', 'gateway.STOP_OLD', 'gateway.DETACH_113b5f0a3c53059b087a2ce997d2670cc057e88c0c17d4291b3b41a51ce26ba3', 'gateway.DETACH_1209d67944755d95601b96719c0a5b1860ac2a6f137c10077da7b4e9967637aa', 'gateway.RENAME_OLD', 'gateway.CREATE_REPLACEMENT', 'gateway.START_REPLACEMENT', 'gateway.READINESS'], 'runtimeAuthorityIssued': False}
FORBIDDEN = ('budgetReset', 'automaticReplayAllowed', 'automaticRollbackAllowed',
             'newLoginAllowed', 'refreshAllowed', 'databaseMigrationAllowed',
             'ownerMutationAllowed', 'projectionPublicationAllowed', 'grantChangesAllowed',
             'sourceActivationAllowed', 'jobDispatchAllowed', 'nativeProfilePublicationAllowed')


class Denied(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Denied(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def decode(raw):
    def unique(pairs):
        value = {}
        for k, v in pairs:
            require(k not in value, 'DUPLICATE_PRIVATE_JSON_FIELD')
            value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'FINITE_PRIVATE_JSON_REQUIRED'))


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid',
                 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def private_read(selected):
    """Bounded FD-relative no-follow traversal and ancestor/file rechecks."""
    p = Path(selected)
    require(p.is_absolute() and '..' not in p.parts and str(p) == selected,
            'EXACT_PRIVATE_PATH_REQUIRED')
    fds, parents = [], []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(fd)
        for part in p.parts[1:-1]:
            current = os.fstat(fd)
            require(current.st_uid == current.st_gid == 0 and not current.st_mode & 0o022,
                    'ROOT_CUSTODIED_ANCESTRY_REQUIRED')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            fds.append(child)
            info = os.fstat(child)
            parents.append((fd, part, child, identity(info)))
            fd = child
        info = os.fstat(fd)
        require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'ROOT_PRIVATE_PARENT_REQUIRED')
        file = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        fds.append(file)
        info = os.fstat(file)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and 0 < info.st_size <= 1048576, 'BOUNDED_ROOT_PRIVATE_FILE_REQUIRED')
        with os.fdopen(os.dup(file), 'rb') as stream:
            raw = stream.read(1048577)
        require(len(raw) == info.st_size and identity(info) == identity(os.fstat(file))
                == identity(os.stat(p.name, dir_fd=fd, follow_symlinks=False)),
                'PRIVATE_FILE_CHANGED_DURING_READ')
        for parent, name, child, pin in parents:
            require(pin == identity(os.fstat(child))
                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'PRIVATE_ANCESTRY_CHANGED_DURING_READ')
        return raw
    finally:
        for fd in reversed(fds):
            os.close(fd)


def inspect(case, read=private_read, clock=lambda: (time.time(), time.monotonic()),
            boot_read=lambda: Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
    require(case['purpose'] == 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT',
            'PINNED_INSTALLATION_CASE_REQUIRED')
    context = case['contextPath']
    selected = [context + '/' + name for name in (
        'operator-control/recovery.json', 'preparation.json', 'review.json',
        'decision.json', 'recovery.json')]
    raw = {p: read(p) for p in selected}
    control, prepared, review, decision, row = [decode(raw[p]) for p in selected]
    require(control['schema'] == 'ouf.ingestion-rollout-explicit-production-control.v1'
            and control['state'] == 'RECONCILE_REQUIRED' and control['complete'] is False
            and control['budgetReset'] is False
            and control['caseHash'] == case['productionCaseHash']
            and control['controlSourceHash'] == case['controlSourceHash']
            and control['sourceDeclarationHash'] == case['sourceDeclarationHash'],
            'EXACT_STOPPED_PRODUCTION_CONTROL_REQUIRED')
    require(digest(prepared) == control['preparationHash']
            and prepared['caseHash'] == case['productionCaseHash']
            and prepared['controlSourceHash'] == case['controlSourceHash']
            and digest(prepared['sourceClosure']['declaration']) == case['sourceDeclarationHash'],
            'PINNED_RETAINED_PREPARATION_REQUIRED')
    require(digest(review) == control['reviewHash'] and digest(decision) == control['decisionHash']
            and decision['reviewHash'] == digest(review)
            and decision['decision'] == 'APPROVE_EXACT_FINITE_SCOPED_ACTION'
            and review['operatorBinding'] == {'controlSourceHash': case['controlSourceHash'],
                'caseHash': case['productionCaseHash'], 'preparationHash': control['preparationHash'],
                'modeContract': 'EXPLICIT_ONE_STAGE_NO_AUTOMATIC_REPLAY_V1'},
            'EXACT_RETAINED_REVIEW_AND_DECISION_REQUIRED')
    native = review['executionReview']
    scope = review['scopes']['ingestionGatewayRollout']
    stages = native['stages']
    require(native['executionContext'] == context and scope['executionContext'] == context
            and scope['reviewHash'] == digest(native)
            and all(native[k] is False and scope[k] is False for k in FORBIDDEN)
            and scope['stageIntentHashes'] == {s['name']: s['intentHash'] for s in stages}
            and all(s['intentHash'] == digest(s['intent']) for s in stages),
            'EXACT_NATIVE_SCOPE_AND_INTENTS_REQUIRED')
    n = case['expectedNextStage']
    require(type(row['nextStage']) is int and row['nextStage'] == n
            and len(stages) == case['expectedTotalStages'] and len(row['effects']) == n
            and stages[n]['name'] == case['expectedNextStageName']
            and [s['name'] for s in stages[:n]] == case['expectedAppliedStages']
            and row['schema'] == 'ouf.ingestion-rollout-finite-journal.v1'
            and row['scopeHash'] == digest(scope) and row['budgetReset'] is False
            and row['readState'] == 'IDLE'
            and all(e['state'] == 'APPLIED' and e['stage'] == s['name']
                and e['intentHash'] == s['intentHash'] for e, s in zip(row['effects'], stages[:n]))
            and type(row['readAttempts']) is int and 0 <= row['readAttempts'] <= 128,
            'EXACT_APPLIED_PREFIX_NO_PENDING_CLAIM_REQUIRED')
    logical = native['logicalOperationRef']
    require(re.fullmatch('[0-9a-f]{64}', logical) is not None, 'EXACT_LOGICAL_FENCE_REQUIRED')
    claim_path = str(Path(context).parent / ('ingestion-rollout-' + logical + '.claim.json'))
    claim_raw = read(claim_path)
    claim = decode(claim_raw)
    require(claim == {'reviewHash': digest(native), 'authorityHash': row['authorityHash'],
                     'context': context, 'automaticReplayAllowed': False, 'budgetReset': False},
            'RETAINED_CONSUMED_LOGICAL_CLAIM_REQUIRED')
    for number in (decision['approvedAt'], decision['expiresAt'], row['createdAt'], row['expiresAt'],
                   row['expiresMonotonic'], row['lastWall'], row['lastMonotonic']):
        require(type(number) in (int, float) and math.isfinite(number), 'FINITE_RETAINED_CLOCK_REQUIRED')
    wall, mono = clock()
    try:
        observed_boot = boot_read()
    except OSError:
        observed_boot = None
    same_boot = observed_boot is not None and observed_boot == row['bootId']
    for p in selected:
        require(read(p) == raw[p], 'STOPPED_CONTEXT_CHANGED_DURING_SNAPSHOT')
    require(read(claim_path) == claim_raw, 'LOGICAL_CLAIM_CHANGED_DURING_SNAPSHOT')
    return {'schema': 'ouf.ingestion-rollout-stopped-snapshot.v1', 'complete': True,
        'status': 'STOPPED_PREFIX_RECONCILED_NO_AUTHORITY', 'contextPath': context,
        'readOnly': True, 'observedAtUnix': wall, 'sameBoot': same_boot,
        'bootEvidenceAvailable': observed_boot is not None,
        'controlState': control['state'], 'nextStage': n, 'nextStageName': stages[n]['name'],
        'appliedStageCount': n, 'remainingStages': [{'name': s['name'], 'kind': s['kind']}
                                                   for s in stages[n:]],
        'pendingStageClaim': False, 'readState': row['readState'], 'readAttempts': row['readAttempts'],
        'recordedAuthorityExpiresAt': decision['expiresAt'],
        'recordedExecutionExpiresAt': row['expiresAt'],
        'recordedSecondsRemaining': max(0, int(min(decision['expiresAt'], row['expiresAt']) - wall)),
        'recordedMonotonicSecondsRemaining': max(0, int(row['expiresMonotonic'] - mono)) if same_boot else None,
        'wallClockConsistent': wall >= row['lastWall'], 'journalHash': digest(row),
        'reviewHash': digest(review), 'logicalOperationRef': logical,
        'providerAuthorizationReverified': False, 'liveRuntimeObserved': False,
        'humanCredentialJournalsRead': 0, 'bearerFilesOpened': 0, 'privateKeysRead': 0,
        'oauthRequests': 0, 'engineRequests': 0, 'databaseCalls': 0, 'gatewayRequests': 0,
        'runtimeAuthorityIssued': False, 'runtimeEffectsDispatched': 0,
        'automaticReplayAllowed': False, 'budgetReset': False, 'notReleaseAcceptance': True,
        'completedTechnicalPhases': 8, 'functionalMilestonesProven': 4}


def main():
    try:
        require(os.geteuid() == os.getegid() == 0 and len(sys.argv) == 1
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: require(False, 'BOUNDED_SNAPSHOT_TIMEOUT'))
        signal.alarm(30)
        print(encoded(inspect(CASE)).decode(), flush=True)
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if type(error) is Denied else 'SNAPSHOT_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        print(encoded({'schema': 'ouf.ingestion-rollout-stopped-snapshot.v1',
            'complete': False, 'status': 'STOP_RECONCILE', 'reasonCode': reason,
            'contextsAndClaimsRetained': True, 'runtimeAuthorityIssued': False,
            'automaticReplayAllowed': False, 'budgetReset': False}).decode(), flush=True)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
