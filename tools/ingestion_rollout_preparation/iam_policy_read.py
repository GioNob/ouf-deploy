"""One finite administrative API read using an existing, unexpired CLI token.

No kcadm execution, OAuth endpoint, login, refresh or policy mutation exists in
this module. Ente inputs and the selected container come from retained profiles.
Docker archive GETs read exactly passwd and the one documented CLI config; tar
is parsed in memory, never extracted. Only whitelisted policy metadata escapes.
"""
import base64
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse

PROFILE = 'ouf.iam-existing-session-policy-read.v1'
CHECKPOINT = {'phase': 'NOT_STARTED', 'contextPath': None}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def encoded(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(v):
    return hashlib.sha256(encoded(v)).hexdigest()


def decode(raw):
    def unique(pairs):
        value = {}
        for k, v in pairs:
            require(k not in value, 'DUPLICATE_IAM_READ_FIELD')
            value[k] = v
        return value
    def nonfinite(_):
        raise ValueError('FINITE_IAM_READ_JSON_REQUIRED')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def save(journal, **changes):
    before = journal.read()
    journal.compare_and_save(before, {**before, **changes})


class EngineRead:
    def __init__(self, binding, journal, cid):
        require(set(binding) == {'socketPath', 'socketBinding'}
            and re.fullmatch('[0-9a-f]{64}', cid) is not None, 'EXACT_IAM_ENGINE_SELECTION_REQUIRED')
        self.binding, self.journal, self.cid = binding, journal, cid

    def request(self, method, archive=None):
        row = self.journal.read()
        require(row['engineRequestsReserved'] < 7, 'FINITE_IAM_ENGINE_READ_BUDGET_EXHAUSTED')
        require(method in ('GET', 'HEAD') and (method == 'GET' or archive is not None),
            'READ_ONLY_IAM_ENGINE_METHOD_REQUIRED')
        path = '/v1.44/containers/' + self.cid
        path += '/json' if archive is None else '/archive?' + urllib.parse.urlencode({'path': archive})
        def check():
            s = os.stat(self.binding['socketPath'], follow_symlinks=False)
            require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) in (0o600, 0o660)
                and [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
                == self.binding['socketBinding'], 'EXACT_IAM_ENGINE_SOCKET_CUSTODY_REQUIRED')
        check()
        save(self.journal, engineRequestsReserved=row['engineRequestsReserved'] + 1)
        engine_socket = self.binding['socketPath']
        class Local(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect(engine_socket)
        conn = Local('localhost', timeout=10)
        try:
            conn.request(method, path, headers={'Connection': 'close'})
            reply = conn.getresponse()
            raw = reply.read(2097153)
            require(len(raw) <= 2097152, 'BOUNDED_IAM_ENGINE_RESPONSE_REQUIRED')
            check()
            require(reply.status == 200, 'SELECTED_IAM_ENGINE_DOCUMENT_UNAVAILABLE')
            if archive is None:
                return decode(raw)
            header = reply.getheader('X-Docker-Container-Path-Stat', '')
            require(0 < len(header) <= 16384, 'BOUNDED_IAM_ARCHIVE_METADATA_REQUIRED')
            meta = decode(base64.b64decode(header, validate=True))
            require(type(meta) is dict and not meta.get('linkTarget')
                and type(meta.get('mode')) is int, 'NO_SYMLINK_IAM_ARCHIVE_REFERENCE_REQUIRED')
            return raw, meta
        finally:
            conn.close()


def member(raw, meta, name, maximum, uid, permissions):
    require(meta.get('name') == name and type(meta.get('size')) is int
        and 0 < meta['size'] <= maximum and meta['mode'] & 0o777 == permissions
        and not meta['mode'] & (1 << 31) and not meta.get('linkTarget'),
        'EXACT_IAM_ARCHIVE_FILE_METADATA_REQUIRED')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        rows = archive.getmembers()
        require(len(rows) == 1, 'ONE_SELECTED_IAM_ARCHIVE_MEMBER_REQUIRED')
        item = rows[0]
        require(item.name == name and item.isfile() and not item.issym() and not item.islnk()
            and item.size == meta['size'] and item.uid == uid and item.mode == permissions
            and not item.linkname and set(item.pax_headers) <= {'mtime', 'atime', 'ctime'},
            'EXACT_CUSTODIED_IAM_ARCHIVE_MEMBER_REQUIRED')
        with archive.extractfile(item) as stream:
            value = stream.read(maximum + 1)
        require(len(value) == item.size, 'BOUNDED_IAM_ARCHIVE_CONTENT_REQUIRED')
        return value


def credential_path(container, passwd, profile):
    require(profile['locationRule'] == 'CONTAINER_DEFAULT_USER_PASSWD_HOME'
        and profile['relativeConfigPath'] == '.keycloak/kcadm.config',
        'EXPLICIT_DOCUMENTED_CLI_CONFIG_LOCATION_RULE_REQUIRED')
    user = container['Config'].get('User') or '0'
    require(type(user) is str and re.fullmatch('[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)?', user),
        'EXACT_CONTAINER_DEFAULT_USER_REQUIRED')
    user = user.split(':')[0]
    rows = []
    for line in passwd.decode('utf-8').splitlines():
        parts = line.split(':')
        require(len(parts) == 7 and parts[2].isdigit(), 'BOUNDED_CONTAINER_PASSWD_FORMAT_REQUIRED')
        if (user.isdigit() and int(parts[2]) == int(user)) or (not user.isdigit() and parts[0] == user):
            rows.append(parts)
    require(len(rows) == 1, 'UNIQUE_CONTAINER_CLI_USER_REQUIRED')
    uid, home = int(rows[0][2]), rows[0][5]
    require(home.startswith('/') and str(PurePosixPath(home)) == home
        and '..' not in PurePosixPath(home).parts and home != '/', 'EXPLICIT_CONTAINER_USER_HOME_REQUIRED')
    environment = container['Config'].get('Env') or []
    homes = [x[5:] for x in environment if x.startswith('HOME=')]
    require(len(homes) <= 1 and (not homes or homes[0] == home), 'CLI_HOME_ENVIRONMENT_AND_PASSWD_MUST_AGREE')
    require(not any(('user.home' in x or 'kcadm.config' in x) for x in environment
        if x.startswith(('JAVA_', 'JDK_', '_JAVA_', 'KCADM_'))), 'UNREVIEWED_CLI_CONFIG_OVERRIDE_FORBIDDEN')
    return home + '/' + profile['relativeConfigPath'], uid


def token_from_config(value, profile, issuer, now):
    require(type(value) is dict and value.get('serverUrl') == profile['storedServerUrl']
        and value.get('realm') == profile['adminRealm'] and not value.get('externalToken'),
        'EXACT_EXISTING_IAM_CLI_SERVER_AND_REALM_REQUIRED')
    row = value.get('endpoints', {}).get(profile['storedServerUrl'], {}).get(profile['adminRealm'])
    require(type(row) is dict and row.get('clientId') == profile['adminClientId'],
        'EXACT_EXISTING_ADMIN_CLI_SESSION_REQUIRED')
    token = row.get('token')
    require(type(token) is str and 0 < len(token) <= 16384 and len(token.split('.')) == 3,
        'BOUNDED_EXISTING_ADMIN_ACCESS_TOKEN_REQUIRED')
    part = token.split('.')[1]
    require(re.fullmatch('[A-Za-z0-9_-]+', part) is not None, 'BOUNDED_ADMIN_JWT_PAYLOAD_REQUIRED')
    claims = decode(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
    base = issuer.rsplit('/realms/', 1)[0]
    issuers = {base + '/realms/' + profile['adminRealm'],
        profile['storedServerUrl'] + '/realms/' + profile['adminRealm']}
    require(claims.get('iss') in issuers and claims.get('azp') == profile['adminClientId']
        and claims.get('preferred_username') == profile['expectedAdminUser']
        and type(claims.get('exp')) is int and type(row.get('expiresAt')) is int,
        'EXACT_RECORDED_ADMIN_SESSION_CONTEXT_REQUIRED')
    # CLI expiresAt is milliseconds; use the stricter recorded deadline.
    expires = min(claims['exp'], row['expiresAt'] / 1000)
    return token, expires, expires > now + profile['minimumRemainingSeconds']


CHILD = r'''import http.client,ipaddress,json,os,re,signal,sys
signal.alarm(10)
try:
 v=json.loads(sys.stdin.buffer.read(32769))
 if set(v)!={'token','host','port','realm','path'}:raise ValueError()
 if not ipaddress.ip_address(v['host']).is_loopback or type(v['port'])is not int or not 1<=v['port']<=65535:raise ValueError()
 if not re.fullmatch('[A-Za-z0-9._-]{1,128}',v['realm']):raise ValueError()
 base='/admin/realms/'+v['realm']
 if v['path']!=base and not re.fullmatch(re.escape(base)+r'/clients(?:\?clientId=[A-Za-z0-9._-]+&exact=true&first=0&max=2|/[A-Za-z0-9_-]{1,128})',v['path']):raise ValueError()
 if type(v['token'])is not str or not 0<len(v['token'])<=16384 or any(c.isspace()for c in v['token']):raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
 c=http.client.HTTPConnection(v['host'],v['port'],timeout=8)
 c.request('GET',v['path'],headers={'Authorization':'Bearer '+v['token'],'Accept':'application/json','Connection':'close'})
 response=c.getresponse();body=response.read(524289)
 if len(body)>524288:raise ValueError()
 parsed=json.loads(body)if response.status==200 else None
 result=json.dumps({'status':response.status,'body':parsed},sort_keys=True,separators=(',',':'),allow_nan=False).encode()
 if len(result)>1048576:raise ValueError()
 sys.stdout.buffer.write(result);sys.stdout.buffer.flush();c.close()
except BaseException:os._exit(2)
os._exit(0)
'''


def executable(binding):
    path = Path(binding['path']).resolve(strict=True)
    for parent in path.parents:
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022,
            'ROOT_CUSTODIED_IAM_READER_EXECUTABLE_REQUIRED')
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and s.st_nlink == 1
        and s.st_mode & 0o111 and not s.st_mode & 0o022 and 0 < s.st_size <= 64000000,
        'EXACT_IAM_READER_PROGRAM_REQUIRED')
    require(str(path) == binding['path'] and hashlib.sha256(path.read_bytes()).hexdigest() == binding['sha256'],
        'PINNED_IAM_READER_EXECUTABLE_CHANGED')
    return str(path)


def admin_get(journal, program, ns_fd, profile, token, expiry, realm, path):
    row = journal.read()
    require(row['adminGetsReserved'] < 3 and expiry > time.time() + 12,
        'CURRENT_EXISTING_ADMIN_TOKEN_AND_FINITE_GET_BUDGET_REQUIRED')
    save(journal, adminGetsReserved=row['adminGetsReserved'] + 1)
    payload = {'token': token, 'host': profile['connectHost'], 'port': profile['connectPort'],
        'realm': realm, 'path': path}
    run = subprocess.run([executable(program), '-I', '-B', '-S', '-c', CHILD, str(ns_fd)],
        input=encoded(payload), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=12, pass_fds=(ns_fd,), env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
    require(run.returncode == 0 and 0 < len(run.stdout) <= 1048576, 'IAM_READ_ONLY_CHILD_OUTCOME_UNPROVEN')
    result = decode(run.stdout)
    require(result['status'] == 200, 'CURRENT_ADMIN_API_PERMISSION_OR_RESPONSE_UNPROVEN_NO_REFRESH')
    return result['body']


def policy(realm, listing, client, realm_name, client_id):
    require(type(realm) is dict and realm.get('realm') == realm_name
        and type(listing) is list and len(listing) == 1 and listing[0].get('clientId') == client_id
        and type(client) is dict and client.get('id') == listing[0]['id']
        and client.get('clientId') == client_id and client.get('enabled') is True
        and client.get('protocol') == 'openid-connect', 'EXACT_UNIQUE_CURRENT_HUMAN_CLIENT_REQUIRED')
    names = ('access.token.lifespan', 'client.session.idle.timeout', 'client.session.max.lifespan')
    attrs = client.get('attributes') or {}
    require(type(attrs) is dict, 'BOUNDED_CLIENT_TIMEOUT_ATTRIBUTES_REQUIRED')
    selected = {}
    for name in names:
        value = attrs.get(name)
        require(value is None or type(value) is str and re.fullmatch('-?[0-9]{1,9}', value),
            'EXACT_CLIENT_TIMEOUT_VALUE_REQUIRED')
        selected[name] = value
    realm_names = ('accessTokenLifespan', 'ssoSessionIdleTimeout', 'ssoSessionMaxLifespan',
        'clientSessionIdleTimeout', 'clientSessionMaxLifespan')
    values = {k: realm.get(k) for k in realm_names}
    require(type(values['accessTokenLifespan']) is int and values['accessTokenLifespan'] > 0
        and all(v is None or type(v) is int and v >= 0 for v in values.values()),
        'EXACT_REALM_SESSION_AND_TOKEN_TIMEOUTS_REQUIRED')
    return {'realm': realm_name, 'clientId': client_id, 'clientUuid': client['id'],
        'clientTimeoutAttributes': selected, 'realmTimeouts': values,
        'currentClientAndRealmMetadataRead': True, 'effectiveFutureIssuedLifetimeProven': False}


def generation(container, cid):
    require(type(container) is dict and container.get('Id') == cid
        and container.get('State', {}).get('Running') is True
        and type(container['State'].get('Pid')) is int and container['State']['Pid'] > 0
        and type(container['State'].get('StartedAt')) is str and container['State']['StartedAt']
        and re.fullmatch('sha256:[0-9a-f]{64}', container.get('Image', '')),
        'EXACT_RUNNING_SELECTED_IAM_CONTAINER_REQUIRED')
    return {k: container['State'][k] for k in ('Pid', 'StartedAt')} | {'containerId': cid, 'imageId': container['Image']}


def run(case, read_selected, recheck, Journal):
    CHECKPOINT.update(phase='RETAINED_IAM_SELECTION', contextPath=None)
    require(case.get('schema') == 'ouf.iam-current-policy-read-case.v1'
        and case.get('purpose') == 'EXACT_RETAINED_INSTALLATION_DIAGNOSTIC_NOT_PORTABLE_DEFAULT',
        'EXACT_IAM_POLICY_READ_CASE_REQUIRED')
    seals = []
    def read(path):
        value, seal = read_selected(path)
        seals.append(seal)
        return value
    plan = read(case['ownerPlanBinding']['path'])
    require(digest(plan) == case['ownerPlanBinding']['sha256'], 'EXACT_COMPLETED_OWNER_PLAN_REQUIRED')
    control = PurePosixPath(case['humanControlPath'])
    config = read(str(control / 'control.json'))
    binding = read(str(control / 'binding.json'))
    selection = config['selection']
    require(config['schema'] == 'ouf.human-explicit-successor-control.v1'
        and str(control) == config['controlDirectory']
        and control.name == 'human-successor-control-' + digest(config['review'])
        and config['sourceClosureHash'] == case['humanSourceClosureHash']
        and digest(selection) == plan['humanBinding']['selectionHash'] == binding['selectionHash']
        and binding['clientId'] == case['humanClientId']
        and re.fullmatch('[A-Za-z0-9._-]{1,128}', selection['realm']),
        'SAME_FULL_OWNER_BOUND_IAM_SELECTION_REQUIRED')
    prepared = read(str(PurePosixPath(case['productionContextPath']) / 'preparation.json'))
    require(prepared['controlSourceHash'] == case['productionControlSourceHash']
        and prepared['caseHash'] == case['productionCaseHash'], 'EXACT_RETAINED_PROGRAM_PREPARATION_REQUIRED')
    program = prepared['sourceClosure']['executables']['python']
    endpoint = case['adminReadProfile']
    require(endpoint['schema'] == 'ouf.iam-existing-cli-loopback-read-profile.v1'
        and endpoint['storedServerUrl'] == 'http://' + endpoint['storedHost'] + ':' + str(endpoint['connectPort'])
        and endpoint['storedHost'] in ('localhost', endpoint['connectHost'])
        and ipaddress.ip_address(endpoint['connectHost']).is_loopback
        and type(endpoint['connectPort']) is int and 1 <= endpoint['connectPort'] <= 65535
        and type(endpoint['minimumRemainingSeconds']) is int and 45 <= endpoint['minimumRemainingSeconds'] <= 300,
        'EXPLICIT_SELECTED_CLI_LOOPBACK_API_BINDING_REQUIRED')
    parent = Path(plan['authorityDirectory']).parent
    require(parent == Path(case['ownerPlanBinding']['path']).parent.parent,
        'EXACT_RETAINED_IAM_DIAGNOSTIC_PARENT_REQUIRED')
    logical = digest(case)
    claim = parent / ('iam-policy-read-' + logical + '.claim.json')
    require(not os.path.lexists(claim), 'EXISTING_IAM_READ_CLAIM_RECONCILE_WITH_STATUS_NO_REPLAY')
    context = Path(tempfile.mkdtemp(prefix='iam-policy-read-', dir=parent))
    context.chmod(0o700)
    CHECKPOINT.update(phase='RESERVE_PRIVATE_IAM_READ', contextPath=str(context))
    row = {'schema': PROFILE, 'caseHash': logical, 'state': 'PREPARED', 'complete': False,
        'engineRequestsReserved': 0, 'adminGetsReserved': 0, 'budgetReset': False,
        'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False}
    with os.fdopen(os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(encoded({'schema': PROFILE, 'caseHash': logical, 'contextPath': str(context)}))
        stream.flush()
        os.fsync(stream.fileno())
    journal = Journal(context)
    journal.initialize(row)
    ns_fd = None
    try:
        engine = EngineRead(plan['engine'], journal, selection['keycloakContainer'])
        CHECKPOINT['phase'] = 'SELECTED_IAM_CONTAINER_AND_CREDENTIAL_METADATA'
        container = engine.request('GET')
        first = generation(container, selection['keycloakContainer'])
        raw, meta = engine.request('GET', '/etc/passwd')
        passwd = member(raw, meta, 'passwd', 65536, 0, 0o644)
        path, uid = credential_path(container, passwd, endpoint)
        _, directory_meta = engine.request('HEAD', str(PurePosixPath(path).parent))
        require(directory_meta['mode'] & (1 << 31) and directory_meta['mode'] & 0o777 == 0o700,
            'PRIVATE_EXISTING_ADMIN_CONFIG_DIRECTORY_REQUIRED')
        raw, config_meta = engine.request('GET', path)
        credential_raw = member(raw, config_meta, 'kcadm.config', 262144, uid, 0o600)
        _, current_meta = engine.request('HEAD', path)
        require(current_meta == config_meta, 'ADMIN_CONFIG_METADATA_CHANGED_DURING_READ')
        token, expiry, current = token_from_config(decode(credential_raw), endpoint, selection['issuer'], time.time())
        del raw, credential_raw
        result = {'schema': 'ouf.iam-current-policy-read-result.v1', 'contextPath': str(context),
            'readOnly': True, 'complete': True, 'currentProviderPolicyProven': False,
            'cachedAdminAccessTokenSecondsRemaining': max(0, int(expiry - time.time())),
            'newLoginPerformed': False, 'refreshPerformed': False, 'oauthRequests': 0,
            'iamMutations': 0, 'containerLifecycleOperations': 0, 'credentialFilesRead': 1,
            'humanCredentialJournalsRead': 0, 'humanBearerFilesOpened': 0,
            'credentialValuesPrinted': False, 'credentialHashesPrinted': False,
            'humanAttemptsFromRetainedReceipt': case['retainedHumanAttempts'],
            'humanMaximumCumulativeAttempts': case['maximumCumulativeOAuthAttempts'],
            'humanBudgetRequeriedThisInvocation': False, 'budgetReset': False,
            'privateEvidenceOnlyWrites': True, 'existingContextsModified': False,
            'existingJournalWrites': 0,
            'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
            'completedTechnicalPhases': 8, 'functionalMilestonesProven': 4, 'notReleaseAcceptance': True}
        if current:
            CHECKPOINT['phase'] = 'THREE_EXACT_ADMIN_POLICY_GETS_NO_REFRESH'
            before = generation(engine.request('GET'), selection['keycloakContainer'])
            require(before == first, 'IAM_CONTAINER_CHANGED_BEFORE_API_READ')
            ns_path = '/proc/' + str(first['Pid']) + '/ns/net'
            ns_fd = os.open(ns_path, os.O_RDONLY | os.O_CLOEXEC)
            ns = os.fstat(ns_fd)
            base = '/admin/realms/' + selection['realm']
            realm = admin_get(journal, program, ns_fd, endpoint, token, expiry, selection['realm'], base)
            listing = admin_get(journal, program, ns_fd, endpoint, token, expiry, selection['realm'],
                base + '/clients?clientId=' + binding['clientId'] + '&exact=true&first=0&max=2')
            require(type(listing) is list and len(listing) == 1
                and re.fullmatch('[A-Za-z0-9_-]{1,128}', listing[0].get('id', '')),
                'UNIQUE_CURRENT_CLIENT_UUID_REQUIRED')
            client = admin_get(journal, program, ns_fd, endpoint, token, expiry, selection['realm'],
                base + '/clients/' + listing[0]['id'])
            result.update(policy(realm, listing, client, selection['realm'], binding['clientId']))
            require((os.stat(ns_path).st_dev, os.stat(ns_path).st_ino) == (ns.st_dev, ns.st_ino),
                'IAM_NETWORK_NAMESPACE_CHANGED_DURING_READ')
            result.update(status='CURRENT_IAM_TIMEOUT_METADATA_READ_NO_AUTHORITY', currentProviderPolicyProven=True)
        else:
            result.update(status='EXISTING_ADMIN_TOKEN_NOT_CURRENT_NO_LOGIN_OR_REFRESH')
        require(generation(engine.request('GET'), selection['keycloakContainer']) == first,
            'IAM_CONTAINER_CHANGED_DURING_POLICY_READ')
        for seal in seals:
            recheck(seal)
        counters = journal.read()
        result.update(engineRequestsReserved=counters['engineRequestsReserved'],
            adminGetsReserved=counters['adminGetsReserved'])
        save(journal, state='COMPLETE', complete=True, result=result)
        CHECKPOINT['phase'] = 'COMPLETE'
        return result
    except BaseException:
        save(journal, state='STOP_RECONCILE', complete=False)
        raise
    finally:
        if ns_fd is not None:
            os.close(ns_fd)


def status(case, context, read_selected):
    root = Path(context)
    claim, _ = read_selected(str(root.parent / ('iam-policy-read-' + digest(case) + '.claim.json')))
    require(claim == {'schema': PROFILE, 'caseHash': digest(case), 'contextPath': str(root)},
        'EXACT_RETAINED_IAM_READ_CONTEXT_REQUIRED')
    row, _ = read_selected(str(root / 'recovery.json'))
    require(row['schema'] == PROFILE and row['caseHash'] == digest(case), 'EXACT_IAM_READ_JOURNAL_REQUIRED')
    return {'schema': 'ouf.iam-current-policy-read-result.v1', 'status': 'RETAINED_IAM_READ_METADATA_ONLY',
        'state': row['state'], 'contextPath': str(root), 'complete': row['complete'], 'readOnly': True,
        'engineRequestsReserved': row['engineRequestsReserved'], 'adminGetsReserved': row['adminGetsReserved'],
        'engineRequestsThisInvocation': 0, 'adminGetsThisInvocation': 0, 'credentialFilesRead': 0,
        'newLoginPerformed': False, 'refreshPerformed': False, 'oauthRequests': 0,
        'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'budgetReset': False}
