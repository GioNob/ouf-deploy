#!/usr/bin/env python3
"""Read the concrete rollout dependencies after the 8 November inventory.

No provider/business/token calls, migration, grant, service or route update.
Two explicit read-only database sessions and one APISIX Admin GET at most.
"""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote, parse_qsl

HELPER = 'read-analysis-discovery-runtime-20261107.py'
HELPER_SHA = 'ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
CONFIG_TARGET = '/usr/local/apisix/conf/config.yaml'
ADMIN_KEY = Path('/opt/ouf/secrets/apisix-admin-key')
FRAME_PINS = {
    'mcp': '976cbfab45ec58589ae2a9b4e8922b93bc16dc840f55c371a036f9ab36c132a3',
    'semantic': 'e5e0030e080d60c3ce59b2d7b4dd5fadd9e56dd1c52a2d1b32aac1733879de07',
    'apisix': '415f9f8b581de338b7ccd1598d3b1fb12e943e9a70957a80a974d5c494db4305',
}
MCP_CHECKSUMS = {'1': 'a70a2389352f5f8387f96b6051becf97f64f1e922aba9c353545449e0fa0b225', '2': '138614ca67d9365e7525c0d56313ab1514e3ea9f1fe32b5095a3d85e3ecbb74d', '3': '044d5d6fe3fdd5f77179a4f677885aa3ca4f72ca1bc52f6f10c44b57306bfb3e', '4': '9bae68eb83dabf8bd80fcfdf38189c54cced1228b3b22a7128c4c5cda3b7c72c', '5': '3dc65eeee6668444e77e3a08982a71a1412fda53c3e8b90cbddd7d6959e5ad54', '6': '8973286df97ef30dd7281dfaf5bfb251ca078d4a2862de235b6988bc5e5eb375', '7': 'ad1e6b93b10ae2b6e407015f4bfb5026f2cd633a8565d30584fddd98e274f174', '8': '2e279669f11a1b4949c93e17522d127003aa7c3f54cd2af0461500676f2bef28', '9': '798ec17290d8952a6824871739d4b352bc3984f4e600fda9c704d6784d704dd2', '10': '64b586222b534976c379dbec667e4bcb3f7c58087b436b02f79f588e3bb9b0a5', '11': 'd6393214c1b83da875015018e5e50833fe6fe4ea0571adf98d5f34fbe390995e', '12': 'de64bdcfa45b1e373807d07e603cd1940defe056cec4a21e0db4c7667330cc68', '13': 'fe9ab352cbf649efecc708b08a9f61ff3c9aadb358211ebd763011ee9fd695b5', '14': '0c15ba1e335c721b8b7cdc5534910a60716033c12259c1909e8b6bd587cc9d24'}


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def helper():
    path = Path(__file__).with_name(HELPER)
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == HELPER_SHA, 'READER_HELPER_HASH_MISMATCH')
    spec = importlib.util.spec_from_file_location('pinned_inventory_reader', path)
    module = importlib.util.module_from_spec(spec)
    # Execute the exact checked bytes, without reopening a mutable path.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def safe_reason(exc):
    return str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__


def save_private(work, name, raw):
    fd = os.open(work / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)


def mount_file(doc, path, read_content=False, maximum=1048576):
    """Read/stat exactly the application's read-only bind view, with no symlink traversal."""
    need(isinstance(path, str) and re.fullmatch('/[A-Za-z0-9_./-]+', path) and
         str(Path(path)) == path and '..' not in Path(path).parts, 'DECLARED_MOUNT_PATH_REQUIRED')
    candidates = [m for m in doc['Mounts'] if path == m['Destination'] or path.startswith(m['Destination'].rstrip('/') + '/')]
    candidates.sort(key=lambda m: len(m['Destination']), reverse=True)
    if not candidates:
        return None, {'status': 'NO_DECLARED_MOUNT', 'contentsRead': False}
    mount = candidates[0]
    need(mount['Type'] == 'bind' and not mount['RW'], 'READ_ONLY_BIND_REQUIRED')
    fds = []
    try:
        parent = os.open('/proc/' + str(doc['State']['Pid']) + '/root', os.O_PATH | os.O_DIRECTORY)
        fds.append(parent)
        parts = Path(path).parts[1:]
        for part in parts[:-1]:
            parent = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(parent)
        flags = (os.O_RDONLY if read_content else os.O_PATH) | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(parts[-1], flags, dir_fd=parent)
        fds.append(fd)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, 'BOUNDED_MOUNTED_FILE_REQUIRED')
        raw = None
        if read_content:
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(maximum + 1)
            need(len(raw) == before.st_size, 'MOUNTED_FILE_LENGTH_CHANGED')
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(os.fstat(fd)) == identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)),
             'MOUNTED_FILE_CHANGED')
        host = os.stat(mount['Source'] + path[len(mount['Destination']):], follow_symlinks=False)
        return raw, {'status': 'MOUNTED_REGULAR_FILE', 'contentsRead': read_content,
                     'readOnlyMount': True, 'sameAsHostSource': (before.st_dev, before.st_ino) == (host.st_dev, host.st_ino),
                     'uid': before.st_uid, 'gid': before.st_gid, 'modeOctal': format(stat.S_IMODE(before.st_mode), '04o'),
                     'nonempty': before.st_size > 0}
    except FileNotFoundError:
        return None, {'status': 'DECLARED_FILE_NOT_FOUND', 'contentsRead': False}
    finally:
        for fd in reversed(fds):
            os.close(fd)


def declared_provider(doc, h):
    env = h.environment(doc)
    result = {'scope': 'DECLARED_ENV_NOT_EFFECTIVE_SPRING_CONFIGURATION',
              'providerEnabledDeclaration': env.get('OUF_SCHEMA_GOV_ENABLED') == 'true',
              'workerEnabledDeclaration': env.get('OUF_DISCOVERY_WORKER_ENABLED') == 'true',
              'externalConfigurationRead': False, 'credentialContentsRead': False}
    paths = []
    for key in ('OUF_SCHEMA_GOV_GATEWAY_BASE_URL', 'OUF_SCHEMA_GOV_SEARCH_PATH', 'OUF_SCHEMA_GOV_FETCH_PATH'):
        value = env.get(key)
        need(isinstance(value, str) and value, 'DECLARED_PROVIDER_ROUTE_BINDINGS_REQUIRED')
        if key.endswith('BASE_URL'):
            url = urlsplit(value)
            need(url.scheme == 'https' and url.hostname and not (url.username or url.password or url.query or url.fragment)
                 and url.path in ('', '/'), 'DECLARED_GATEWAY_ORIGIN_REQUIRED')
            need(re.fullmatch('[A-Za-z0-9.-]{1,253}', url.hostname), 'DECLARED_GATEWAY_HOST_INVALID')
            result['gatewayOrigin'] = {'scheme': 'https', 'host': url.hostname, 'port': url.port or 443}
        else:
            need(re.fullmatch('/[A-Za-z0-9_./-]{1,240}', value) and '..' not in value.split('/'), 'DECLARED_PROVIDER_PATH_INVALID')
            result[key.removeprefix('OUF_SCHEMA_GOV_').lower()] = value
            paths.append(value)
    secret_path = env.get('OUF_SCHEMA_GOV_CLIENT_SECRET_FILE')
    if secret_path:
        _, result['workloadCredentialMount'] = mount_file(doc, secret_path)
    else:
        result['workloadCredentialMount'] = {'status': 'NOT_DECLARED', 'contentsRead': False}
    result['workloadClientDeclared'] = bool(env.get('OUF_SCHEMA_GOV_CLIENT_ID'))
    result['workloadScopeDeclared'] = bool(env.get('OUF_SCHEMA_GOV_WORKLOAD_SCOPE'))
    return result, paths


def schema_limits(schema):
    limits, todo, seen = set(), [schema], 0
    while todo:
        node = todo.pop()
        seen += 1
        need(seen <= 20000, 'SCHEMA_NODE_LIMIT')
        if isinstance(node, dict):
            if type(node.get('maxItems')) is int:
                limits.add(node['maxItems'])
            todo.extend(node.values())
        elif isinstance(node, list):
            todo.extend(node)
    return sorted(limits)


def summarize_routes(data, selected, h):
    need(isinstance(data.get('list'), list) and data.get('total') == len(data['list']) and
         len(data['list']) <= 512, 'COMPLETE_BOUNDED_ROUTE_LIST_REQUIRED')
    result = {}
    for path in selected:
        matches = []
        for entry in data['list']:
            row = entry.get('value', entry)
            if isinstance(row.get('value'), dict):
                row = row['value']
            uris = [row['uri']] if 'uri' in row else row.get('uris', [])
            exact = path in uris
            prefix = any(isinstance(u, str) and u.endswith('*') and path.startswith(u[:-1]) for u in uris)
            if not (exact or prefix):
                continue
            plugins = row.get('plugins') or {}
            validation = plugins.get('request-validation') or {}
            limits = validation.get('body_schema') or {}
            functions = plugins.get('serverless-post-function') or {}
            upstream = row.get('upstream') or {}
            matches.append({'routeSha256': h.digest(row), 'exactPath': exact, 'prefixPath': prefix,
                            'enabled': row.get('status', 1) == 1, 'hostFilterPresent': bool(row.get('host') or row.get('hosts')),
                            'variableConditionsPresent': bool(row.get('vars')),
                            'methods': sorted(m for m in row.get('methods', []) if m in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD')),
                            'openidConnectPresent': 'openid-connect' in plugins,
                            'requestValidationPresent': 'request-validation' in plugins,
                            'maxRequestBodyBytes': validation.get('max_req_body_size'),
                            'schemaArrayMaxItems': schema_limits(limits),
                            'bodySchemaSha256': h.digest(limits),
                            'preFunctionPresent': 'serverless-pre-function' in plugins,
                            'postFunctionSha256': h.digest(functions),
                            'inlineUpstreamPresent': bool(upstream),
                            'upstreamReferencePresent': bool(row.get('upstream_id') or row.get('service_id')),
                            'upstreamScheme': upstream.get('scheme'),
                            'upstreamNodeCount': len(upstream.get('nodes') or {}),
                            'upstreamReadTimeoutSeconds': (upstream.get('timeout') or {}).get('read')})
        result[path] = {'matchingRouteCount': len(matches), 'matches': matches}
    return {'status': 'ROUTE_CONFIGURATION_READ', 'routeCount': len(data['list']),
            'effectiveRoutingOrAdmissionProven': False, 'routes': result}


ADMIN_CHILD = r'''import http.client,json,sys
data=json.loads(sys.stdin.buffer.read(8193))
connection=http.client.HTTPConnection('127.0.0.1',9180,timeout=8)
try:
    connection.request('GET','/apisix/admin/routes',headers={'X-API-KEY':data['key']})
    response=connection.getresponse()
    raw=response.read(8388609)
    if response.status!=200 or len(raw)>8388608: raise RuntimeError('ADMIN_READ_FAILED')
    sys.stdout.buffer.write(raw)
finally: connection.close()
'''


def selected_key(config, h, report):
    # The existing installation uses this exact external key when the literal list is empty.
    lines = config.decode().splitlines()
    starts = [(i, len(line)-len(line.lstrip(' '))) for i, line in enumerate(lines)
              if re.fullmatch(r' *admin_key: *(?:#.*)?', line)]
    need(len(starts) == 1, 'ONE_ADMIN_KEY_SECTION_REQUIRED')
    start, indent = starts[0]
    parents = []
    for line in lines[:start]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        depth = len(line)-len(line.lstrip(' '))
        parents = [row for row in parents if row[0] < depth]
        match = re.fullmatch(r'( *)([A-Za-z_][A-Za-z0-9_]*): *(?:#.*)?', line)
        if match:
            parents.append((depth, match[2]))
    need([p[1] for p in parents if p[0] < indent] == ['deployment', 'admin'], 'ADMIN_SECTION_INVALID')
    records, row = [], None
    for line in lines[start+1:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if len(line)-len(line.lstrip(' ')) <= indent:
            break
        match = re.fullmatch(r' +(- +)?(name|key|role): *(.*?) *', line)
        need(match is not None, 'UNSUPPORTED_ADMIN_KEY_SYNTAX')
        if match[1]:
            if row is not None:
                records.append(row)
            row = {}
        need(row is not None and match[2] not in row, 'DUPLICATE_ADMIN_KEY_FIELD')
        value = match[3]
        if value.startswith('"'):
            value = json.loads(value)
        elif value.startswith("'"):
            need(value.endswith("'"), 'ADMIN_SCALAR_INVALID')
            value = value[1:-1].replace("''", "'")
        else:
            value = value.split(' #', 1)[0].strip()
        row[match[2]] = value
    if row is not None:
        records.append(row)
    if not records:
        report['externalAdminKeyFilesRead'] += 1
        key = h.read(ADMIN_KEY, 8192).decode('ascii').strip()
    else:
        need(len(records) <= 8 and all(set(row) == {'name', 'key', 'role'} for row in records),
             'ADMIN_KEY_RECORD_INVALID')
        admins = [row for row in records if row['role'] == 'admin']
        need(len(admins) == 1, 'ONE_ADMIN_KEY_REQUIRED')
        key = admins[0]['key']
    need(isinstance(key, str) and 16 <= len(key) <= 4096 and
         all(33 <= ord(c) <= 126 for c in key) and not key.startswith(('$ENV', '${', '$secret')),
         'LITERAL_ADMIN_KEY_REQUIRED')
    return key


def routes(doc, selected, h, report, work):
    raw, meta = mount_file(doc, CONFIG_TARGET, True)
    need(raw is not None and meta['sameAsHostSource'], 'CURRENT_ADMIN_CONFIG_MOUNT_REQUIRED')
    report['adminCredentialConfigurationsRead'] += 1
    key = selected_key(raw, h, report)
    report['adminRouteGetAttempts'] += 1
    run = subprocess.run(('/usr/bin/nsenter', '--target', str(doc['State']['Pid']), '--net',
                          sys.executable, '-I', '-B', '-S', '-c', ADMIN_CHILD),
                         input=json.dumps({'key': key}).encode(), capture_output=True, timeout=12)
    need(run.returncode == 0 and len(run.stdout) <= 8 * 1024 * 1024, 'ADMIN_ROUTE_READ_FAILED')
    save_private(work, 'routes.private.json', run.stdout)
    return summarize_routes(h.parse(run.stdout), selected, h)


def db_binding(doc, postgres, module, h):
    env = h.environment(doc)
    raw = env.get('MCP_DATABASE_URL') if module == 'mcp' else env.get('OUF_SEM_DB_URL')
    need(isinstance(raw, str) and raw, 'DECLARED_DATABASE_URL_REQUIRED')
    if module == 'semantic':
        need(raw.startswith('jdbc:'), 'DECLARED_JDBC_URL_REQUIRED')
        raw = raw[5:]
    url = urlsplit(raw)
    need(not any(k.lower() in {'host', 'hostaddr', 'port', 'user', 'password', 'dbname', 'database', 'service'}
                 for k, _ in parse_qsl(url.query)), 'DATABASE_QUERY_IDENTITY_OVERRIDE_UNSUPPORTED')
    user = unquote(url.username or '') if module == 'mcp' else env.get('OUF_SEM_DB_USER', '')
    database = unquote(url.path.removeprefix('/'))
    need(url.scheme in ('postgres', 'postgresql') and not url.fragment and (url.port or 5432) == 5432 and
         all(re.fullmatch('[a-z_][a-z0-9_]{0,62}', s) for s in (user, database)), 'EXACT_DATABASE_IDENTITY_REQUIRED')
    aliases = {postgres.get('Name', '').lstrip('/')}
    for node in postgres['NetworkSettings'].get('Networks', {}).values():
        aliases.update(node.get('Aliases') or [])
        aliases.update(node.get('DNSNames') or [])
        aliases.add(node.get('IPAddress'))
    need(url.hostname in aliases, 'DATABASE_HOST_NOT_RETAINED_POSTGRES')
    return user, database


MCP_QUERY = """SELECT json_build_object(
 'readOnly',current_setting('transaction_read_only')='on',
 'databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),
 'migrations',(SELECT coalesce(json_agg(json_build_object('version',version,'checksum',checksum) ORDER BY version),'[]'::json) FROM ouf_mcp.schema_migration),
 'analysisTablePresent',to_regclass('ouf_mcp.profile_analysis') IS NOT NULL,
 'analysisTaskTablePresent',to_regclass('ouf_mcp.profile_analysis_task') IS NOT NULL);"""
SEMANTIC_QUERY = """SELECT json_build_object(
 'readOnly',current_setting('transaction_read_only')='on',
 'databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),
 'migrations',(SELECT coalesce(json_agg(json_build_object('version',version,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM ouf_sem.flyway_schema_history),
 'discoveryStates',(SELECT coalesce(json_agg(x),'[]'::json) FROM (
   SELECT state,recovery_state,count(*) AS count FROM ouf_sem.discovery_request GROUP BY state,recovery_state ORDER BY state,recovery_state) x));"""


def read_sql(module):
    return ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
            "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s';\n" +
            {'mcp': MCP_QUERY, 'semantic': SEMANTIC_QUERY}[module] + '\nROLLBACK;\n')


def database(doc, postgres, module, h, report, work):
    user, name = db_binding(doc, postgres, module, h)
    command = (*DOCKER, 'exec', '-i', '-e', 'PGOPTIONS=-c default_transaction_read_only=on',
               '-e', 'PGAPPNAME=ouf-analysis-discovery-contract-read', postgres['Id'],
               'psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
               '-h', '/var/run/postgresql', '-U', user, '-d', name)
    report['readOnlyDatabaseSessionsAttempted'] += 1
    run = subprocess.run(command, input=read_sql(module).encode(), capture_output=True, timeout=12)
    save_private(work, module + '-database.stderr.private', run.stderr[:65536])
    need(run.returncode == 0 and len(run.stdout) <= 131072, 'DATABASE_METADATA_READ_FAILED')
    value = h.parse(run.stdout)
    need(value['readOnly'] is True and isinstance(value['migrations'], list) and len(value['migrations']) <= 256,
         'READ_ONLY_BOUNDED_DATABASE_RESULT_REQUIRED')
    save_private(work, module + '-database.private.json', run.stdout)
    value['status'] = 'DATABASE_METADATA_READ'
    value['bindingScope'] = 'DECLARED_APPLICATION_DATABASE_ON_RETAINED_POSTGRES'
    if module == 'mcp':
        versions = [row['version'] for row in value['migrations']]
        value['migrationsMatchQualifiedSourcePrefix'] = (versions == list(range(1, len(versions) + 1)) and
            all(MCP_CHECKSUMS.get(str(row['version'])) == row['checksum'] for row in value['migrations']))
        value['remainingCandidateVersions'] = sorted(int(v) for v in MCP_CHECKSUMS if int(v) not in versions)
    else:
        allowed_states = {'PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED'}
        allowed_recovery = {'ACTIVE', 'RETRY_WAIT', 'PAUSED_EXHAUSTED', 'BLOCKED', 'CANCELLED'}
        need(all(row['state'] in allowed_states and row['recovery_state'] in allowed_recovery and
                 type(row['count']) is int and row['count'] >= 0 for row in value['discoveryStates']), 'UNRECOGNIZED_DISCOVERY_STATE')
        value['pendingOrRunningRequestCount'] = sum(row['count'] for row in value['discoveryStates'] if row['state'] in ('PENDING', 'RUNNING'))
        value['requestIdentifiersOrIntentsRead'] = False
    return value


def collect(h, report):
    raw = h.read(h.PLAN, 1048576)
    need(hashlib.sha256(raw).hexdigest() == h.PLAN_SHA, 'RETAINED_PLAN_CHANGED')
    roles = h.parse(raw)['roles']
    selected = (*FRAME_PINS, 'postgres')
    docs = {name: h.inspect(roles[name]['containerId']) for name in selected}
    for name, doc in docs.items():
        need(doc['Image'] == roles[name]['nativeImage'] and doc['State']['Running'] and
             not doc['State'].get('Paused') and not doc['State'].get('Restarting'), 'EXPECTED_RUNNING_IMAGE_REQUIRED')
        if name in FRAME_PINS:
            need(h.digest(h.frame(doc)) == FRAME_PINS[name], 'CONFIGURATION_CHANGED_SINCE_INVENTORY')
    work = Path(tempfile.mkdtemp(prefix='discovery-contract-read-', dir=h.ROOT))
    os.chmod(work, 0o700)
    report['privateEvidenceDirectory'] = str(work)
    report['components'] = {}
    paths = []
    try:
        report['components']['provider'], paths = declared_provider(docs['semantic'], h)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        report['components']['provider'] = {'status': 'READ_INCOMPLETE', 'reason': safe_reason(exc)}
    selected_paths = ['/mcp', '/internal/capabilities/v1/execute'] + [
        '/internal/capabilities/v1/execute/semantic/discovery/' + op for op in ('request', 'status', 'candidates')]
    # Only configured provider paths are added; no endpoint guessed from source defaults.
    selected_paths += paths
    for name, action in (
        ('routes', lambda: routes(docs['apisix'], selected_paths, h, report, work)),
        ('mcpDatabase', lambda: database(docs['mcp'], docs['postgres'], 'mcp', h, report, work)),
        ('semanticDatabase', lambda: database(docs['semantic'], docs['postgres'], 'semantic', h, report, work))):
        try:
            report['components'][name] = action()
        except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as exc:
            report['components'][name] = {'status': 'READ_INCOMPLETE', 'reason': safe_reason(exc)}
    report['runtimeUnchangedDuringRead'] = all(h.frame(h.inspect(doc['Id'])) == h.frame(doc) for doc in docs.values())
    need(report['runtimeUnchangedDuringRead'], 'RUNTIME_CHANGED_DURING_CONTRACT_READ')
    report['status'] = ('READ_PARTIAL' if any(row.get('status') == 'READ_INCOMPLETE' for row in report['components'].values())
                        else 'DISCOVERY_CONTRACT_READ_COMPLETE')


def main():
    report = {'schema': 'ouf.discovery-contract-read.v1', 'status': 'READ_INCOMPLETE',
              'credentialValuesEmitted': False, 'providerCredentialContentsRead': False,
              'adminCredentialConfigurationsRead': 0, 'externalAdminKeyFilesRead': 0,
              'adminRouteGetAttempts': 0, 'readOnlyDatabaseSessionsAttempted': 0,
              'serviceConfigurationChanged': False, 'serviceStops': 0, 'databaseWrites': 0,
              'businessRequestsIssued': 0, 'providerRequests': 0, 'tokenRequests': 0, 's3Requests': 0,
              'policyGrantsRead': False, 'effectiveProviderConfigurationProven': False}
    def timeout(*_):
        raise RuntimeError('CONTRACT_READ_DEADLINE')
    try:
        need(os.geteuid() == 0, 'ROOT_REQUIRED')
        signal.signal(signal.SIGALRM, timeout)
        signal.alarm(55)
        collect(helper(), report)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, http.client.HTTPException) as exc:
        report.update(status='READ_INCOMPLETE', reason=safe_reason(exc))
    finally:
        signal.alarm(0)
    report['observedAt'] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
