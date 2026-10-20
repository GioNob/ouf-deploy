"""Reconcile a failed admin-session context check within its retained read budget.

No admin API request, credential use, login or refresh. The two remaining
Engine GETs bracket FD-relative process-root reads; no archive request is
replayed. The original STOP and claim remain; one reconciliation claim fences
this inspection. Output is booleans/types/timestamps, never identity values.
"""
import base64
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

CHECKPOINT = {'phase': 'NOT_STARTED', 'contextPath': None}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def root_path(pid):
    return '/proc/' + str(pid) + '/root'


def process_start(pid):
    fd = os.open('/proc/' + str(pid) + '/stat', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 8193)
        require(0 < len(raw) <= 8192 and raw.split(b' ', 1)[0] == str(pid).encode(),
            'EXACT_SELECTED_PROCESS_STAT_REQUIRED')
        fields = raw[raw.rfind(b')') + 2:].split()
        require(len(fields) >= 20 and fields[19].isdigit(), 'EXACT_SELECTED_PROCESS_START_REQUIRED')
        return fields[19]
    finally:
        os.close(fd)


def file_identity(s):
    return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
        s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def directory_identity(s):
    return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]


class ProcessFiles:
    def __init__(self, pid):
        require(type(pid) is int and pid > 0, 'EXACT_SELECTED_IAM_PID_REQUIRED')
        self.pid, self.fds, self.directories, self.files = pid, [], [], []
        self.started = process_start(pid)
        # Following this kernel-managed link is deliberate and only for the
        # exact Engine-selected PID. All paths below it are no-follow/FD-relative.
        self.root = os.open(root_path(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.fds.append(self.root)
        self.identity = directory_identity(os.fstat(self.root))
        try:
            s = os.fstat(self.root)
            require(s.st_uid == s.st_gid == 0 and not s.st_mode & 0o002,
                'ROOT_CUSTODIED_SELECTED_CONTAINER_ROOT_REQUIRED')
            self.check()
        except BaseException:
            self.close()
            raise

    def read(self, path, uid, maximum, permissions, *, private_parent=False):
        require(type(path) is str and path.startswith('/') and str(PurePosixPath(path)) == path
            and '..' not in PurePosixPath(path).parts, 'EXACT_PROCESS_ROOT_RELATIVE_PATH_REQUIRED')
        parent = self.root
        for name in PurePosixPath(path).parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            self.fds.append(child)
            s = os.fstat(child)
            require(stat.S_ISDIR(s.st_mode) and s.st_uid in {0, uid} and not s.st_mode & 0o002
                and (not s.st_mode & 0o020 or s.st_gid == 0),
                'CUSTODIED_CONTAINER_METADATA_ANCESTRY_REQUIRED')
            self.directories.append((parent, name, child, directory_identity(s)))
            parent = child
        if private_parent:
            s = os.fstat(parent)
            require(s.st_uid == uid and stat.S_IMODE(s.st_mode) == 0o700,
                'EXACT_PRIVATE_EXISTING_CREDENTIAL_PARENT_REQUIRED')
        name = PurePosixPath(path).name
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        self.fds.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == permissions and 0 < before.st_size <= maximum,
            'EXACT_PROCESS_ROOT_FILE_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size and file_identity(os.fstat(fd)) == file_identity(before)
            == file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
            'PROCESS_ROOT_FILE_CHANGED_DURING_READ')
        self.files.append((parent, name, fd, file_identity(before)))
        return raw

    def check(self):
        require(process_start(self.pid) == self.started
            and directory_identity(os.fstat(self.root)) == self.identity
            == directory_identity(os.stat(root_path(self.pid))), 'SELECTED_IAM_PROCESS_ROOT_CHANGED')
        for parent, name, held, seal in self.directories:
            require(directory_identity(os.fstat(held)) == seal
                == directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                'PROCESS_ROOT_DIRECTORY_CHANGED')
        for parent, name, held, seal in self.files:
            require(file_identity(os.fstat(held)) == seal
                == file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                'PROCESS_ROOT_FILE_CHANGED_AFTER_READ')

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


def kind(value):
    return {type(None): 'MISSING_OR_NULL', bool: 'BOOLEAN', int: 'INTEGER',
        float: 'NUMBER', str: 'STRING', dict: 'OBJECT', list: 'ARRAY'}.get(type(value), 'OTHER')


def classify(api, value, profile, issuer, now):
    require(type(value) is dict, 'RECORDED_ADMIN_CONFIGURATION_OBJECT_REQUIRED')
    row = value.get('endpoints', {}).get(profile['storedServerUrl'], {}).get(profile['adminRealm'])
    require(type(row) is dict, 'EXACT_RETAINED_ADMIN_ENDPOINT_ROW_REQUIRED')
    token = row.get('token')
    require(type(token) is str and 0 < len(token) <= 16384 and len(token.split('.')) == 3,
        'BOUNDED_RETAINED_ADMIN_JWT_REQUIRED')
    part = token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'BOUNDED_RECONCILIATION_JWT_PAYLOAD_REQUIRED')
    claims = api.decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    require(type(claims) is dict, 'RECORDED_ADMIN_JWT_OBJECT_REQUIRED')
    base = issuer.rsplit('/realms/', 1)[0]
    allowed = {base + '/realms/' + profile['adminRealm'], profile['storedServerUrl'] + '/realms/' + profile['adminRealm']}
    checks = {'storedServerMatches': value.get('serverUrl') == profile['storedServerUrl'],
        'storedRealmMatches': value.get('realm') == profile['adminRealm'],
        'storedClientMatches': row.get('clientId') == profile['adminClientId'],
        'externalTokenAbsent': not value.get('externalToken'),
        'issuerMatchesSelectedContext': claims.get('iss') in allowed,
        'authorizedPartyMatchesSelectedClient': claims.get('azp') == profile['adminClientId'],
        'preferredUsernameClaimPresent': type(claims.get('preferred_username')) is str,
        'preferredUsernameMatchesExpected': claims.get('preferred_username') == profile['expectedAdminUser'],
        'jwtExpiryIsInteger': type(claims.get('exp')) is int,
        'cliExpiryIsInteger': type(row.get('expiresAt')) is int}
    context_ok = all(checks[k] for k in ('issuerMatchesSelectedContext',
        'authorizedPartyMatchesSelectedClient', 'preferredUsernameMatchesExpected',
        'jwtExpiryIsInteger', 'cliExpiryIsInteger'))
    exp, issued, cli = claims.get('exp'), claims.get('iat'), row.get('expiresAt')
    expiry = min(exp, cli / 1000) if type(exp) is type(cli) is int else None
    lifetime = exp - issued if type(exp) is type(issued) is int and 0 < issued <= exp else None
    return {'checks': checks, 'originalContextMismatchReproduced': not context_ok,
        'jwtExpiryKind': kind(exp), 'cliExpiryKind': kind(cli),
        'recordedAdminIssuedLifetimeSeconds': lifetime,
        'recordedAdminAccessExpired': exp <= now if type(exp) is int else None,
        'recordedAdminTokenSecondsRemaining': max(0, int(expiry - now)) if expiry is not None else None,
        'identityValuesPrinted': False, 'credentialValuesPrinted': False, 'credentialHashesPrinted': False,
        'recordedClaimsAreRuntimeAuthority': False}


def run(case, api, files, Journal, source_hash):
    CHECKPOINT.update(phase='EXACT_RETAINED_FAILED_READ', contextPath=case['retainedContextPath'])
    old = case['originalReadCase']
    context = Path(case['retainedContextPath'])
    require(case['schema'] == 'ouf.iam-session-context-reconcile-case.v1'
        and case['maximumEngineRequests'] == 7 and case['expectedEngineRequestsBefore'] == 5
        and case['maximumAdditionalEngineRequests'] == 2,
        'EXACT_REMAINING_RETAINED_READ_BUDGET_REQUIRED')
    claim, _ = files.selected(str(context.parent / ('iam-policy-read-' + api.digest(old) + '.claim.json')))
    require(claim == {'schema': api.PROFILE, 'caseHash': api.digest(old), 'contextPath': str(context)},
        'EXACT_RETAINED_FAILED_READ_CLAIM_REQUIRED')
    journal = Journal(context)
    row = journal.read()
    require(row['schema'] == api.PROFILE and row['caseHash'] == api.digest(old)
        and row['state'] == 'STOP_RECONCILE' and row['complete'] is False
        and row['engineRequestsReserved'] == 5 and row['adminGetsReserved'] == 0
        and row['budgetReset'] is row['runtimeAuthorityIssued'] is False,
        'SAME_STOPPED_READ_WITH_FIVE_ENGINE_ZERO_ADMIN_REQUESTS_REQUIRED')
    seals = []
    def read(path):
        value, seal = files.selected(path)
        seals.append(seal)
        return value
    plan = read(old['ownerPlanBinding']['path'])
    config = read(str(PurePosixPath(old['humanControlPath']) / 'control.json'))
    binding = read(str(PurePosixPath(old['humanControlPath']) / 'binding.json'))
    selection = config['selection']
    require(api.digest(plan) == old['ownerPlanBinding']['sha256']
        and config['schema'] == 'ouf.human-explicit-successor-control.v1'
        and config['sourceClosureHash'] == old['humanSourceClosureHash']
        and api.digest(selection) == plan['humanBinding']['selectionHash'] == binding['selectionHash']
        and binding['clientId'] == old['humanClientId'], 'EXACT_OWNER_BOUND_RECONCILIATION_SELECTION_REQUIRED')
    guard = context / 'admin-session-context-reconcile.claim.json'
    require(not os.path.lexists(guard), 'CONSUMED_CONTEXT_RECONCILIATION_STATUS_ONLY_NO_REPLAY')
    journal.create(guard, api.encoded({'schema': case['schema'], 'caseHash': api.digest(case),
        'sourceHash': source_hash, 'initialEngineRequests': 5, 'maximumEngineRequests': 7,
        'newLoginAuthorized': False, 'automaticReplayAllowed': False, 'budgetReset': False}))
    journal.sync()
    api.save(journal, reconciliationState='READING_RECORDED_CONTEXT', reconciliationSourceHash=source_hash)
    process = None
    try:
        engine = api.EngineRead(plan['engine'], journal, selection['keycloakContainer'])
        CHECKPOINT['phase'] = 'PIN_CURRENT_SELECTED_PROCESS'
        container = engine.request('GET')
        before = api.generation(container, selection['keycloakContainer'])
        process = ProcessFiles(before['Pid'])
        passwd = process.read('/etc/passwd', 0, 65536, 0o644)
        path, uid = api.credential_path(container, passwd, old['adminReadProfile'])
        CHECKPOINT['phase'] = 'READ_RECORDED_ADMIN_CONTEXT_METADATA_ONLY'
        raw = process.read(path, uid, 262144, 0o600, private_parent=True)
        result = classify(api, api.decode(raw), old['adminReadProfile'], selection['issuer'], time.time())
        del raw
        process.check()
        require(api.generation(engine.request('GET'), selection['keycloakContainer']) == before,
            'SELECTED_IAM_GENERATION_CHANGED_DURING_RECONCILIATION')
        process.check()
        for seal in seals:
            files.recheck(seal)
        final = journal.read()
        require(final['engineRequestsReserved'] == 7 and final['adminGetsReserved'] == 0,
            'ORIGINAL_RETAINED_READ_BUDGET_MUST_NOT_RESET_OR_EXTEND')
        result.update(schema='ouf.iam-session-context-reconcile-result.v1',
            status='RECORDED_ADMIN_CONTEXT_RECONCILED_NO_AUTHORITY', complete=True, readOnly=True,
            retainedContextPath=str(context), originalPolicyReadStillStopped=True,
            currentProviderPolicyProven=False, engineRequestsBefore=5, engineRequestsReserved=7,
            maximumEngineRequests=7, engineRequestsThisInvocation=2, archiveRequestsThisInvocation=0,
            adminGetsReserved=0, credentialFilesRead=1, humanCredentialJournalsRead=0,
            humanBearerFilesOpened=0, oauthRequests=0, newLoginPerformed=False, refreshPerformed=False,
            iamMutations=0, containerLifecycleOperations=0, runtimeAuthorityIssued=False,
            automaticReplayAllowed=False, budgetReset=False, windowExtended=False,
            completedTechnicalPhases=8, functionalMilestonesProven=4, notReleaseAcceptance=True)
        api.save(journal, reconciliationState='COMPLETE_METADATA_ONLY', reconciliationResult=result)
        CHECKPOINT['phase'] = 'COMPLETE_METADATA_ONLY'
        return result
    except BaseException:
        api.save(journal, reconciliationState='STOP_RECONCILE')
        raise
    finally:
        if process is not None:
            process.close()


def status(case, api, files, Journal):
    result = api.status(case['originalReadCase'], case['retainedContextPath'], files.selected)
    row = Journal(Path(case['retainedContextPath'])).read()
    result.update(schema='ouf.iam-session-context-reconcile-result.v1',
        reconciliationState=row.get('reconciliationState', 'NOT_STARTED'))
    return result
