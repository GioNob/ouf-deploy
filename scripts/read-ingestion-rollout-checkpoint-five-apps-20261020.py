"""Distinct five-application checkpoint reconciliation; no retained code execution.

Local evidence and Docker GETs only. No OAuth, provider verification, owner API,
Gateway API, SQL, file mutation, lock creation, login, refresh or runtime authority.
The local session snapshot is deliberately not a current authorization proof.
"""
import base64
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import time

CONTEXT = Path('/etc/ouf/deploy-snapshots/ingestion-profile-publication-execution-0gd3mwft')
OWNER = Path('/etc/ouf/deploy-snapshots/ingestion-owner-recovery-execution-d6o9cpwd')
OWNER_PLAN = 'e5f69f89aa40b8c9b963134d38a6aecaf864499346f9e366539c1eb1aefa0938'
OWNER_RESULT = '7d3902327a9b3641129f4416b66324c4cf727d0e54708216f9df098388a15618'
PROJECTION = 'dd31d2b7de5ae66582275e5ac841584ff784065aa6e362ed0279d45fb6cdbc66'
OLD_PROJECTION = '10b378c05f6ce38d46b8ba9d66a0fa1f9d5ceb0383975ca6c43ba604e9bf599d'
ROUTES = 'ed619aa9415b2e70f61689c3830b3fc89135bc9ab72fc90f24daeba1e7bed8c7'
SOURCE = 'ccbba4ebd986e98b465df733bce0149f8e730fb2'
EXPIRY = 1792450664
APPLICATION_NAMES = frozenset({'onboarding', 'mcp', 'udp', 'ingestion', 'gateway'})
PUBLIC_PROGRESS = {}
MEMBERS = {'case.json', 'bootstrap.py', 'runtime.py', 'reader.py', 'sources.json'}
STAGES = ['VERIFY_INPUTS', 'PUBLISH_ACTIVE_PROJECTION', 'VERIFY_FINAL']
# Filled from the immutable, qualified publication delivery; never executed here.
DELIVERY_PINS = {"authority":"1789bee7325cc2cf5bd1956ae5784ec7c271f2c514a7b9988e40eb17a20fbede","bootstrap":"caa8b4f3feb85d2637d2fbbb103dac6d09a2d0415321e2d5d43a986b0b245199","entry":"7612bf5b1cfde245c75e5a4f3aaaa38e75706e785b3a7e62279accd85b08be28","history":"0dfa6273d6d3d89aa7293a8212adc529d40828301ed91775eb70ce99f97be413","native":"1edf58088674f7b84a9c71ea7ff7c035d5fee1b27d7235f53e123cbeb828fc86","owner":"f130cbc73182ebcbac1abf089077114cee1a7003285d3aa644d47122f13432a2","prepare":"f408a79f53716a13c97b9369a59a94d1085ba8ce4cfd27f7de346161e7295a25","runtime":"8f36a5e294558cc2add57a95b00625401ffe9742b9759de8dc5550268b9eca05","session":"07058bd27cb6d4e6dac6d778a5e6e0a05d530a003003934bb05d7f0bf961f1cc"}
RESULT_HASH = 'c863c8f16f0e2dbe6aa3c8e4f4698f814f0946326f7397fa78b9bbaf373bdfb0'


class Denied(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Denied(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(encoded(value))


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw):
    def bad(_):
        raise Denied('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=bad)


def metadata(info):
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, expected=None, maximum=8388608, projection=False):
    """FD-relative no-follow traversal; retain and recheck every ancestor FD."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'EXACT_PATH_REQUIRED')
    if projection:
        require(path == Path('/opt/ouf/installation/active-projection.json'), 'EXACT_PROJECTION_PATH_REQUIRED')
    descriptors = []
    ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        current = Path('/')
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            current /= name
            if projection and current == Path('/opt/ouf'):
                require(info.st_uid == info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o750,
                        'APPROVED_OUF_PARENT_CUSTODY_REQUIRED')
            else:
                require(info.st_uid == 0 and not info.st_mode & 0o022, 'ROOT_ANCESTRY_REQUIRED')
            if projection and current == path.parent:
                require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                        'PRIVATE_INSTALLATION_DIRECTORY_REQUIRED')
            identity = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode)
            ancestors.append((parent, name, child, identity(info)))
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and 0 < info.st_size <= maximum, 'PRIVATE_FILE_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size and metadata(info) == metadata(os.fstat(fd))
                == metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'FILE_CHANGED_DURING_READ')
        require(expected is None or sha(raw) == expected, 'RETAINED_FILE_HASH_DRIFT')
        for ancestor, name, child, pin in ancestors:
            require(pin == identity(os.fstat(child))
                    == identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)), 'ANCESTRY_CHANGED_DURING_READ')
        return raw, list(metadata(info))
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def parsed(path, expected=None, maximum=8388608):
    return decode(read(path, expected, maximum)[0])


def runtime(value, ordered=True):
    state = value['State']
    require(state['Running'] is True and state.get('Paused', False) is False
            and state.get('Restarting', False) is False and type(state['Pid']) is int
            and state['Pid'] > 0, 'RUNNING_GENERATION_REQUIRED')
    mounts = value['Mounts']
    require(type(mounts) is list and len({m['Destination'] for m in mounts}) == len(mounts),
            'UNIQUE_MOUNTS_REQUIRED')
    return {'containerId': value['Id'], 'imageId': value['Image'], 'pid': state['Pid'],
            'startedAt': state['StartedAt'], 'configHash': digest(value['Config']),
            'hostConfigHash': digest(value['HostConfig']),
            'mountsHash': digest(sorted(mounts, key=lambda m: m['Destination']) if ordered else mounts),
            'networkSettingsHash': digest(value['NetworkSettings'])}


class EngineReader:
    def __init__(self, binding, references):
        self.path = Path(binding['socketPath'])
        self.pin = tuple(binding['socketBinding'])
        require(self.path.is_absolute() and '..' not in self.path.parts and len(self.pin) == 5,
                'EXACT_ENGINE_BINDING_REQUIRED')
        require(1 <= len(references) <= 8 and len(set(references)) == len(references)
                and all(re.fullmatch('[0-9a-f]{64}', r) for r in references), 'BOUNDED_EXACT_CONTAINERS_REQUIRED')
        self.paths = {'/v1.44/containers/' + r + '/json' for r in references}
        self.calls = 0
        self.maximum = 2 * len(references)

    def check(self):
        require(self.path.resolve() == self.path, 'ENGINE_SYMLINK_DENIED')
        info = self.path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) in (0o600, 0o660)
                and (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == self.pin,
                'ENGINE_SOCKET_DRIFT')

    def get(self, reference):
        path = '/v1.44/containers/' + reference + '/json'
        require(path in self.paths and self.calls < self.maximum, 'FINITE_CLOSED_ENGINE_GET_REQUIRED')
        self.check()
        engine_path = str(self.path)
        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(engine_path)
        connection = Connection('retained-engine', timeout=5)
        try:
            self.calls += 1
            connection.request('GET', path)
            reply = connection.getresponse()
            raw = reply.read(4194305)
            require(reply.status == 200 and 0 < len(raw) <= 4194304, 'BOUNDED_ENGINE_REPLY_REQUIRED')
            self.check()
            return decode(raw)
        finally:
            connection.close()


def human_snapshot(row, binding, wall, monotonic, boot):
    require(row['schema'] == 'ouf.chatbot-human-session.private.v1' and row['binding'] == binding
            and row['budgetReset'] is False and type(row['attempts']) is int and 278 <= row['attempts'] <= 288
            and binding['expiresAt'] == EXPIRY and binding['retryProfile']['maximumAttempts'] == 288
            and binding['retryProfile']['id'] == 'ouf.human.ingestion-owner-recovery288.v7', 'EXACT_CURRENT_HUMAN_BINDING_REQUIRED')
    require(row['state'] in ('NEW', 'DEVICE_START', 'DEVICE_POLL', 'REQUESTING', 'RETRY_WAIT', 'VERIFYING', 'READY', 'BLOCKED'),
            'UNKNOWN_HUMAN_STATE')
    for key in ('accessExpiresAt', 'monotonicDeadline', 'lastObservedAt'):
        require(type(row[key]) in (int, float) and math.isfinite(row[key]), 'FINITE_HUMAN_TIMES_REQUIRED')
    stable_clock = boot == row['bootId'] and wall + 2 >= row['lastObservedAt']
    return {'state': row['state'], 'attempts': row['attempts'], 'maximumCumulativeOAuthAttempts': 288,
            'remainingAttempts': 288 - row['attempts'], 'windowExpiresAt': EXPIRY,
            'windowOpenOnRecordedClocks': stable_clock and wall < EXPIRY and monotonic < row['monotonicDeadline'],
            'bootAndWallClockConsistent': stable_clock,
            'recordedAccessTokenExpired': row['accessExpiresAt'] <= wall,
            'recordedTokenSecondsRemaining': max(0, int(row['accessExpiresAt'] - wall)),
            'recordedPublishedTokenMatches': bool(row.get('accessToken')) and row.get('accessToken') == row.get('publishedAccessToken'),
            'providerAuthorizationReverified': False, 'snapshotIsRuntimeAuthority': False, 'budgetReset': False}


def session_directory(binding, owner_plan, review, decision, receipt):
    """Exact successful session provenance, without an invented sibling layout.

    The caller reads owner_plan using the retained OWNER_PLAN SHA256. The v7
    creator derives the session basename from its review; its parent is inherited
    from the predecessor HUMAN directory, not from the publication context.
    File custody is subsequently enforced by the FD-relative reader.
    """
    require(binding == owner_plan['humanBinding'], 'PINNED_SUCCESSFUL_OWNER_SESSION_REQUIRED')
    require(review['schema'] == 'ouf.human-ingestion-owner-recovery-budget-review.v7'
            and review['priorOAuthAttempts'] == 272 and review['maximumCumulativeOAuthAttempts'] == 288
            and review['newWindowSeconds'] == 7200 and review['budgetReset'] is False,
            'EXACT_SUCCESSFUL_V7_REVIEW_REQUIRED')
    review_hash = digest(review)
    require(decision['schema'] == 'ouf.human-ingestion-owner-recovery-budget-decision.v7'
            and decision['reviewHash'] == review_hash
            and decision['decision'] == 'APPROVE_EXACT288_AND_NEW7200_WINDOW_PROTECTED_FRESH_LOGIN_NO_RUNTIME_AUTHORITY'
            and decision['expiresAt'] == binding['expiresAt'] == EXPIRY
            and decision['approvedAt'] == binding['createdAt']
            and decision['expiresAt'] - decision['approvedAt'] == 7200,
            'EXACT_RETAINED_V7_DECISION_REQUIRED')
    directory = Path(binding['sessionDirectory'])
    require(directory.is_absolute() and '..' not in directory.parts
            and str(directory) == binding['sessionDirectory']
            and directory.name == 'human-ingestion-owner-recovery288-' + review_hash
            and binding['tokenPath'] == str(directory / 'human-access.jwt'),
            'EXACT_PROVEN_SUCCESSFUL_SESSION_PATH_REQUIRED')
    require(receipt['schema'] == 'ouf.ingestion-owner-recovery-budget288-receipt.v1'
            and receipt['directory'] == str(directory) and receipt['reviewHash'] == review_hash
            and receipt['expiresAt'] == EXPIRY and receipt['oauthAttemptsAfter'] == 276
            and receipt['maximumCumulativeOAuthAttempts'] == 288 and receipt['budgetReset'] is False,
            'EXACT_SUCCESSFUL276_LOGIN_RECEIPT_REQUIRED')
    return directory


def retained_applications(plan, owner_plan):
    """The immutable Owner7 plan carries all five protected application bindings.

    This is the set constructed by installation_binding_apply.entry.common and
    preserved by later owner/projection plans, not the smaller input-audit subset.
    """
    applications = plan['currentApplications']
    require(type(applications) is dict and set(applications) == APPLICATION_NAMES
            and applications == owner_plan['currentApplications'], 'EXACT_PINNED_FIVE_APPLICATIONS_REQUIRED')
    return applications


def inspect(context=CONTEXT, owner=OWNER, parse=parsed, file_read=read, engine_type=EngineReader,
            clock=lambda: (time.time(), time.monotonic()), boot_read=lambda: Path('/proc/sys/kernel/random/boot_id').read_text().strip()):
    PUBLIC_PROGRESS.clear()
    result = parse(context / 'update-result.json')
    require(digest(result) == RESULT_HASH and result['complete'] is True
            and result['status'] == 'OWNER7_ACTIVE_PROJECTION_PUBLISHED', 'EXACT_COMPLETED_PUBLICATION_RECEIPT_REQUIRED')
    owner_result = parse(owner / 'update-result.json', OWNER_RESULT)
    require(owner_result['status'] == 'OWNER_REFERENCE_ACTIVATED_AND_EXPORTED'
            and owner_result['complete'] is True, 'EXACT_COMPLETED_OWNER_RECEIPT_REQUIRED')
    package = parse(context / 'package.json')
    require(package['sourceCommit'] == SOURCE and set(package['fileHashes']) == MEMBERS,
            'EXACT_PUBLICATION_PACKAGE_REQUIRED')
    raw = {name: file_read(context / name, pin)[0] for name, pin in package['fileHashes'].items()}
    for name in ('bootstrap', 'runtime'):
        require(sha(raw[name + '.py']) == DELIVERY_PINS[name], 'QUALIFIED_PUBLICATION_SOURCE_REQUIRED')
    declaration = package['closure']['declaration']
    require(digest(declaration) == package['declarationHash'] and declaration['moduleCount'] == 244
            and declaration['entryModule'] == 'tools.ingestion_profile_publication.entry', 'EXACT244_CLOSURE_REQUIRED')
    sources = decode(raw['sources.json'])
    require(len(sources) == 244 and set(sources) == set(declaration['sourceHashes']), 'EXACT244_SOURCES_REQUIRED')
    for name, value in sources.items():
        require(sha(base64.b64decode(value, validate=True)) == declaration['sourceHashes'][name], 'SOURCE_HASH_DRIFT')
    for name in ('entry', 'authority', 'owner', 'native', 'history', 'session'):
        require(declaration['sourceHashes']['tools.ingestion_profile_publication.' + name] == DELIVERY_PINS[name],
                'QUALIFIED_PUBLICATION_MODULE_REQUIRED')
    case = decode(raw['case.json'])
    require(digest(case) == package['executionPins']['caseSha256'], 'EXACT_CASE_BINDING_REQUIRED')
    runtime_claim = parse(context / 'runtime.claim.json')
    require(runtime_claim == {'packageHash': digest(package), 'automaticReplayAllowed': False}, 'CONSUMED_RUNTIME_CLAIM_REQUIRED')
    preparation = parse(case['preparationClaimBinding']['path'], case['preparationClaimBinding']['sha256'])
    require(preparation['context'] == str(context) and preparation['ownerResultHash'] == OWNER_RESULT
            and preparation['automaticReplayAllowed'] is False, 'CONSUMED_PREPARATION_CLAIM_REQUIRED')
    plan = parse(context / 'execution-plan.json')
    review = parse(context / 'review.json')
    decision = parse(context / 'decision.json')
    journal = parse(context / 'recovery.json')
    scope = review['scopes']['ingestionActiveProjectionPublication']
    require(scope['planHash'] == digest(plan) and scope['projectionHash'] == PROJECTION
            and scope['ownerResultHash'] == OWNER_RESULT and scope['stages'] == STAGES
            and review['sourceClosureHash'] == digest(package['closure'])
            and decision['reviewHash'] == digest(review) and decision['decision'] == 'APPROVE_EXACT_FINITE_SCOPED_ACTION'
            and journal['scopeHash'] == digest(scope) and journal['incidentState'] == 'RECOVERED'
            and journal['nextStage'] == len(STAGES) and len(journal['effects']) == len(STAGES)
            and [e['stage'] for e in journal['effects']] == STAGES
            and all(e['state'] == 'APPLIED' and e['intentHash'] == digest({'planHash': digest(plan), 'stage': e['stage']})
                    for e in journal['effects']), 'COMPLETED_PUBLICATION_HISTORY_REQUIRED')
    logical = digest({'ownerResultHash': OWNER_RESULT, 'oldProjectionHash': OLD_PROJECTION, 'newProjectionHash': PROJECTION})
    require(plan['logicalRef'] == logical, 'EXACT_LOGICAL_PUBLICATION_REQUIRED')
    effect_claim = parse(context.parent / ('ingestion-active-projection-' + logical + '.claim.json'))
    require(effect_claim == {'context': str(context), 'scopeHash': digest(scope), 'authorityHash': journal['authorityHash'],
                             'automaticReplayAllowed': False, 'budgetReset': False}, 'CONSUMED_EFFECT_CLAIM_REQUIRED')
    require(len(plan['gateway']['beforeRoutes']) == 82 and digest(plan['gateway']['beforeRoutes']) == ROUTES,
            'RETAINED82_ROUTE_BINDING_REQUIRED')
    projection_binding = result['publishedBinding']
    projection, projection_meta = file_read(projection_binding['path'], PROJECTION, projection=True)
    require(projection_meta == projection_binding['metadata'] and sha(projection) == PROJECTION,
            'CURRENT_PROJECTION_BINDING_DRIFT')
    require(journal['effects'][1]['evidence']['publishedBinding'] == projection_binding,
            'EXACT_PUBLISHED_EFFECT_BINDING_REQUIRED')
    binding = plan['humanBinding']
    require(binding == case['humanBinding'], 'SAME_SUCCESSFUL_SESSION_REQUIRED')
    owner_plan = parse(owner / 'execution-plan.json', OWNER_PLAN)
    require(owner_result['planHash'] == OWNER_PLAN, 'EXACT_COMPLETED_OWNER_PLAN_REQUIRED')
    login_review = parse(owner / 'login-review.json')
    login_decision = parse(owner / 'login-decision.json')
    login_receipt = parse(owner / 'login-window-receipt.json')
    directory = session_directory(binding, owner_plan, login_review, login_decision, login_receipt)
    row = parse(directory / 'recovery.json', maximum=65536)
    wall, mono = clock()
    require(row.get('governedWindowRenewal') == {'review': login_review, 'decision': login_decision},
            'SUCCESSFUL_V7_SESSION_LINEAGE_REQUIRED')
    human = human_snapshot(row, binding, wall, mono, boot_read())
    PUBLIC_PROGRESS.update(phase='LOCAL_HUMAN_OBSERVED', human=human,
                           humanSnapshotRechecked=False, engineGetAttemptsStarted=0)
    applications = retained_applications(plan, owner_plan)
    PUBLIC_PROGRESS.update(phase='PINNED_APPLICATIONS_VERIFIED', applicationNames=sorted(applications),
                           applicationCount=len(applications))
    reader = engine_type(plan['engine'], [p['containerId'] for p in applications.values()])
    def observation():
        values = {}
        for name, pin in applications.items():
            ordered = name != 'gateway' or plan['gateway']['transport'].get('runtimeBindingProfile') == 'ouf.apisix-runtime-binding.mount-set.v1'
            PUBLIC_PROGRESS.update(phase='RUNTIME_INSPECTION', currentApplication=name,
                                   engineGetAttemptsStarted=reader.calls + 1)
            values[name] = runtime(reader.get(pin['containerId']), ordered)
        return values
    first = observation()
    second = observation()
    require(first == second, 'RUNTIME_CHANGED_DURING_READ')
    PUBLIC_PROGRESS.update(phase='RUNTIME_OBSERVATIONS_STABLE', runtimeObservationsStable=True)
    require(parse(directory / 'recovery.json', maximum=65536) == row, 'HUMAN_CHANGED_DURING_READ')
    PUBLIC_PROGRESS.update(humanSnapshotRechecked=True)
    require(parse(owner / 'execution-plan.json', OWNER_PLAN) == owner_plan
            and parse(owner / 'login-review.json') == login_review
            and parse(owner / 'login-decision.json') == login_decision
            and parse(owner / 'login-window-receipt.json') == login_receipt, 'SUCCESSFUL_SESSION_PROVENANCE_CHANGED_DURING_READ')
    require(parse(context / 'recovery.json') == journal and parse(context / 'update-result.json') == result
            and parse(context / 'runtime.claim.json') == runtime_claim
            and parse(case['preparationClaimBinding']['path'], case['preparationClaimBinding']['sha256']) == preparation
            and parse(context.parent / ('ingestion-active-projection-' + logical + '.claim.json')) == effect_claim,
            'RETAINED_HISTORY_CHANGED_DURING_READ')
    require(file_read(projection_binding['path'], PROJECTION, projection=True) == (projection, projection_meta), 'PROJECTION_CHANGED_DURING_READ')
    return {'schema': 'ouf.ingestion-rollout-checkpoint-reconcile.v3', 'complete': True, 'readOnly': True,
            'observedAtUnix': int(clock()[0]), 'successfulSessionBoundToPinnedOwnerPlan': True,
            'predecessorDiagnosticStatus': 'STOP_RECONCILE',
            'predecessorDiagnosticReason': 'EXACT_THREE_APPLICATIONS_REQUIRED', 'human': human, 'publicationHistoryReconciled': True,
            'ownerHistoryReconciled': True, 'sourceModuleHashesVerified': 244,
            'consumedClaimsRetained': True, 'activeProjection7BytesAndMetadataUnchanged': True,
            'runtimeBindingsMatchRetained': {name: value == applications[name] for name, value in first.items()},
            'runtimeObservationsStable': True, 'engineGetRequests': reader.calls,
            'applicationCount': len(applications), 'maximumEngineGetRequests': 10,
            'currentOwnerActiveRequeried': False, 'liveGatewayRouteMapRead': False,
            'databaseAdmissionProven': False, 'runtimeRolloutExecutorQualified': False, 'nativeProfilePublished': False,
            'credentialJournalsOpened': 1, 'credentialJournalReads': 2, 'bearerFilesOpened': 0,
            'credentialValuesPrinted': False, 'credentialHashesPrinted': False,
            'oauthRequests': 0, 'ownerRequests': 0, 'gatewayRequests': 0, 'databaseCalls': 0,
            'journalWrites': 0, 'containerLifecycleOperations': 0, 'completedOwnerActionReplayed': False,
            'completedPublicationReplayed': False, 'newLoginPerformed': False, 'refreshPerformed': False,
            'windowExtended': False, 'budgetReset': False, 'automaticReplayAllowed': False,
            'runtimeAuthorityIssued': False, 'completedTechnicalPhases': 8, 'functionalMilestonesProven': 4,
            'notReleaseAcceptance': True}


def main():
    require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0 and sys.flags.isolated
            and sys.flags.no_site and sys.dont_write_bytecode, 'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
    def expired(*_):
        raise Denied('FINITE_READ_DEADLINE')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(60)
    print(encoded(inspect()).decode(), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(encoded({'schema': 'ouf.ingestion-rollout-checkpoint-reconcile.v3', 'complete': False,
                       'status': 'STOP_RECONCILE', 'readOnly': True,
                       'partial': bool(PUBLIC_PROGRESS), 'checkpoint': PUBLIC_PROGRESS,
                       'reasonCode': str(error) if type(error) is Denied else 'PRIVATE_DETAILS_REDACTED',
                       'automaticReplayAllowed': False, 'budgetReset': False, 'runtimeAuthorityIssued': False}).decode(), flush=True)
        raise SystemExit(2)
