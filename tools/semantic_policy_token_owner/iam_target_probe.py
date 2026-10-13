"""Observe the selected existing Keycloak client through the retained admin route.

The writer configuration selects a client, never authenticates it. Read only
Keycloak metadata using its existing kcadm session. Do not log in, fetch a client
secret, decode a bearer, mint a service token, change IAM or stop the old writer.
Keep principal/mapper metadata only in an exclusive root-private evidence file.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import uuid

UNIT = 'ouf-policy-token@semantic.service'
CONFIGURATION = '/etc/ouf/policy-token/semantic.env'
SERVER = 'http://localhost:8080'
ISSUER = 'https://auth.ouf-lab.it/realms/ouf'
REALM = 'ouf'
CONTAINER = 'ouf-keycloak'
SNAPSHOTS = '/etc/ouf/deploy-snapshots'
KEYS = {'OUF_POLICY_TOKEN_' + name for name in (
    'CLIENT_ID', 'ENDPOINT', 'REQUIRED_SCOPE', 'RUNTIME_DIR', 'RUNTIME_GID', 'SECRET_FILE')}

class ProbeDenied(RuntimeError):
    pass

def require(ok, reason):
    if not ok:
        raise ProbeDenied(reason)

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_INPUT_KEY')
        result[key] = value
    return result

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def read_configuration(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) <= 32,
            'CONFIGURATION_ROUTE_UNPROVEN')
    fds, bindings = [], []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(parent)
        for part in path.parts[1:-1]:
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022,
                    'CONFIGURATION_ANCESTRY_UNPROVEN')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(child)
            require(identity(before) == identity(os.fstat(child)), 'CONFIGURATION_CHANGED')
            bindings.append((parent, part, child, before))
            parent = child
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 65536,
                'CONFIGURATION_CUSTODY_UNPROVEN')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        fds.append(fd)
        require(identity(before) == identity(os.fstat(fd)), 'CONFIGURATION_CHANGED')
        raw = os.read(fd, 65537)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'CONFIGURATION_CHANGED')
        for parent, part, child, before in bindings:
            require(identity(before) == identity(os.fstat(child))
                    == identity(os.stat(part, dir_fd=parent, follow_symlinks=False)), 'CONFIGURATION_CHANGED')
        return raw
    finally:
        for fd in reversed(fds):
            os.close(fd)

def parse_configuration(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        key, sep, value = line.partition('=')
        require(sep and key in KEYS and key not in result, 'CONFIGURATION_SCHEMA_UNPROVEN')
        value = value.strip()
        if value.startswith(('"', "'")):
            require(len(value) >= 2 and value[-1] == value[0], 'CONFIGURATION_SCHEMA_UNPROVEN')
            value = value[1:-1]
        require(not any(c in value for c in ('\\', '"', "'", '\x00', '\r', '\n')),
                'CONFIGURATION_SCHEMA_UNPROVEN')
        result[key] = value
    require(set(result) == KEYS, 'CONFIGURATION_SCHEMA_UNPROVEN')
    require(result['OUF_POLICY_TOKEN_ENDPOINT'] == ISSUER + '/protocol/openid-connect/token',
            'EXISTING_ISSUER_SELECTION_DRIFT')
    require(re.fullmatch('[A-Za-z0-9_.:-]{1,128}', result['OUF_POLICY_TOKEN_CLIENT_ID']) is not None,
            'CLIENT_SELECTION_UNPROVEN')
    scopes = result['OUF_POLICY_TOKEN_REQUIRED_SCOPE'].split()
    require(1 <= len(scopes) <= 32 and len(set(scopes)) == len(scopes)
            and 'authorization.bundle.read' in scopes
            and all(re.fullmatch('[A-Za-z0-9_.:/-]{1,128}', s) for s in scopes), 'SCOPE_SELECTION_UNPROVEN')
    return result

def routing():
    props = ['EnvironmentFiles', 'Environment', 'UnsetEnvironment', 'RootDirectory', 'RootImage',
             'BindPaths', 'BindReadOnlyPaths', 'TemporaryFileSystem']
    result = subprocess.run(['/usr/bin/systemctl', 'show', UNIT, '--no-pager', '--property=' + ','.join(props)],
                            capture_output=True, timeout=5)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 65536, 'CONFIGURATION_ROUTE_UNAVAILABLE')
    fields = {}
    for line in result.stdout.decode('utf-8').splitlines():
        key, sep, value = line.partition('=')
        require(sep and key in props and key not in fields, 'CONFIGURATION_ROUTE_UNPROVEN')
        fields[key] = value
    require(set(fields) == set(props) and all(not fields[key] for key in props[1:]),
            'CONFIGURATION_OVERRIDES_UNPROVEN')
    match = re.fullmatch(r'(/[A-Za-z0-9_./@:-]+) \(ignore_errors=no\)', fields['EnvironmentFiles'])
    require(match is not None, 'SOLE_CONFIGURATION_FILE_REQUIRED')
    require(match[1] == CONFIGURATION, 'SELECTED_CONFIGURATION_PATH_DRIFT')
    return match[1], fields

def iam_get(resource, fields, query=None):
    # Explicit old route and GET only. A missing/expired session requires the
    # operator's existing interactive login, never a credential search/fallback.
    argv = ['/usr/bin/docker', 'exec', CONTAINER, '/opt/keycloak/bin/kcadm.sh',
            'get', resource, '--server', SERVER, '-r', REALM, '--fields', fields]
    if query is not None:
        argv += ['-q', query]
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=15)
    require(result.returncode == 0, 'EXISTING_IAM_GET_UNAVAILABLE')
    require(0 < len(result.stdout) <= 131072, 'IAM_METADATA_UNBOUNDED')
    return json.loads(result.stdout, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'IAM_METADATA_SCHEMA_UNPROVEN'))

def observe(cfg):
    client_id = cfg['OUF_POLICY_TOKEN_CLIENT_ID']
    selected = iam_get('clients', 'id,clientId,enabled,serviceAccountsEnabled,publicClient,clientAuthenticatorType,protocol,protocolMappers',
                       'clientId=' + client_id)
    require(type(selected) is list and len(selected) == 1 and type(selected[0]) is dict,
            'EXACT_IAM_CLIENT_NOT_UNIQUE')
    client = selected[0]
    require(set(client) <= {'id', 'clientId', 'enabled', 'serviceAccountsEnabled', 'publicClient',
                            'clientAuthenticatorType', 'protocol', 'protocolMappers'}
            and client.get('clientId') == client_id and type(client.get('id')) is str
            and re.fullmatch('[0-9a-fA-F-]{36}', client['id']) is not None, 'IAM_CLIENT_IDENTITY_UNPROVEN')
    require(client.get('enabled') is True and client.get('serviceAccountsEnabled') is True
            and client.get('publicClient') is False and client.get('protocol') == 'openid-connect'
            and client.get('clientAuthenticatorType') == 'client-secret', 'IAM_SERVICE_CLIENT_BINDING_UNPROVEN')
    resource = 'clients/' + client['id']
    service = iam_get(resource + '/service-account-user', 'id,enabled')
    require(type(service) is dict and set(service) == {'id', 'enabled'} and type(service.get('id')) is str
            and re.fullmatch('[0-9a-fA-F-]{36}', service['id']) is not None and service.get('enabled') is True,
            'IAM_SERVICE_ACCOUNT_UNPROVEN')
    default = iam_get(resource + '/default-client-scopes', 'id,name,protocol,protocolMappers')
    optional = iam_get(resource + '/optional-client-scopes', 'id,name,protocol,protocolMappers')
    require(all(type(v) is list and len(v) <= 64
                and all(type(s) is dict and set(s) <= {'id', 'name', 'protocol', 'protocolMappers'}
                        and type(s.get('name')) is str and len(s['name']) <= 128 for s in v)
                for v in (default, optional)), 'IAM_SCOPE_METADATA_UNPROVEN')
    names = [s['name'] for s in default + optional]
    require(len(names) == len(set(names)), 'IAM_SCOPE_ASSIGNMENT_AMBIGUOUS')
    requested = cfg['OUF_POLICY_TOKEN_REQUIRED_SCOPE'].split()
    require(set(requested) <= set(names), 'REQUESTED_SCOPE_NOT_ASSIGNED_TO_CLIENT')
    # Save only metadata explicitly selected by the GETs, never client secret
    # endpoints, admin tokens, the original configuration or credential paths.
    return {'schema': 'ouf.policy-token-existing-iam-metadata.v1', 'issuerSelection': ISSUER,
            'realm': REALM, 'client': client, 'serviceAccount': service,
            'defaultScopes': default, 'optionalScopes': optional, 'requestedScopes': requested,
            'credentialProvenanceAccepted': False, 'actualTokenIntrospectionProven': False,
            'targetHttpsPeerBindingProven': False, 'historicalAccountingReconciled': False,
            'runtimeAuthorityIssued': False, 'notReleaseAcceptance': True}

def save_snapshot(snapshot, on_created=lambda _: None):
    # Existing protected evidence parent only; never establish runtime roots.
    # File creation is exclusive and no failed publication is replayed here.
    read_configuration_parent = Path(SNAPSHOTS)
    for parent in (read_configuration_parent, *read_configuration_parent.parents):
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0 and not s.st_mode & 0o022,
                'EVIDENCE_PARENT_CUSTODY_UNPROVEN')
    fd = os.open(SNAPSHOTS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        named = read_configuration_parent.lstat()
        require(identity(named) == identity(os.fstat(fd)), 'EVIDENCE_PARENT_CHANGED')
        name = 'policy-token-iam-metadata-' + uuid.uuid4().hex + '.private.json'
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            on_created(str(read_configuration_parent / name))
            raw = encoded(snapshot)
            require(len(raw) <= 524288, 'IAM_SNAPSHOT_UNBOUNDED')
            os.fchmod(out, 0o600)
            with os.fdopen(os.dup(out), 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.fsync(fd)
            require(identity(os.fstat(out)) == identity(os.stat(name, dir_fd=fd, follow_symlinks=False)),
                    'EVIDENCE_MEMBER_CHANGED')
            current = read_configuration_parent.lstat()
            require((named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode)
                    == (current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode),
                    'EVIDENCE_PARENT_CHANGED')
            return str(read_configuration_parent / name), hashlib.sha256(raw).hexdigest()
        finally:
            os.close(out)
    finally:
        os.close(fd)

def main():
    report = {'schema': 'ouf.policy-token-existing-iam-observation.v1', 'phase': 'ROOT_ENTRY',
              'observationProfile': 'ouf.policy-token-admin-observation.single-attempt.v1',
              'status': 'BLOCKED', 'credentialFilesRead': 0, 'mountedTokenFilesRead': 0,
              'serviceMutations': 0, 'iamMutations': 0, 'tokenGrantRequests': 0,
              'privateEvidenceWrites': 0, 'runtimeAuthorityIssued': False,
              'budgetReset': False, 'r12Touched': False, 'notReleaseAcceptance': True}
    try:
        require(os.geteuid() == os.getegid() == 0, 'ROOT_EXECUTION_REQUIRED')
        def timeout(*_):
            raise ProbeDenied('OBSERVATION_DEADLINE')
        signal.signal(signal.SIGALRM, timeout); signal.alarm(120)
        report['phase'] = 'CONFIGURATION_SELECTION'
        path, route = routing(); raw = read_configuration(path); cfg = parse_configuration(raw)
        report['phase'] = 'EXISTING_IAM_READ'
        snapshot = observe(cfg)
        report['phase'] = 'STABLE_RECHECK'
        require((path, route) == routing() and raw == read_configuration(path), 'CONFIGURATION_CHANGED')
        require(snapshot == observe(cfg), 'IAM_METADATA_CHANGED_DURING_OBSERVATION')
        report['phase'] = 'PRIVATE_EVIDENCE_PUBLICATION'
        def created(location):
            report.update(privateEvidencePath=location, privateEvidenceWrites=1)
        location, digest = save_snapshot(snapshot, created)
        report.update(status='IAM_METADATA_OBSERVED_NOT_ACCEPTED', phase='OBSERVED_NOT_ACCEPTED',
                      privateEvidencePath=location, privateEvidenceHash=digest, privateEvidenceWrites=1,
                      clientServiceAccountEnabled=True, requestedScopesAssigned=True,
                      defaultScopeCount=len(snapshot['defaultScopes']), optionalScopeCount=len(snapshot['optionalScopes']),
                      actualTokenIntrospectionProven=False, historicalAccountingReconciled=False)
        code = 0
    except Exception as error:
        report['reason'] = str(error) if type(error) is ProbeDenied else type(error).__name__
        if isinstance(error, OSError):
            report['errno'] = error.errno
        report['evidencePublicationMayBePartial'] = report['phase'] == 'PRIVATE_EVIDENCE_PUBLICATION'
        code = 1
    finally:
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return code

if __name__ == '__main__':
    raise SystemExit(main())
