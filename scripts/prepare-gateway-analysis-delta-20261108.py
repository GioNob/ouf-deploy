#!/usr/bin/env python3
"""Compile a private Gateway proposal from the retained 08:31 UTC route read.

Offline preparation only. No Docker, Admin API, database, provider or token call.
Existing authentication bindings are verified and retained; no key is generated.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from datetime import datetime, timezone

ROOT = Path('/var/lib/ouf-storage-migration')
INPUT = ROOT / 'discovery-contract-read-guaps__4'
ASSETS = 'gateway-analysis-assets-20261108.json'
ASSETS_SHA = '98d199c4c00dc88b9cc95b5bbdcf0209aa35a938a8e910369ed59c21f4d62aaf'
PREFIX = '/internal/capabilities/v1/execute/managed.file/'
DISCOVERY = '/internal/capabilities/v1/execute/semantic/discovery/'
BEFORE = {
    '/mcp': '18e8395d0d343b040cfbbf82ebab0be5af744fc5265567238a645c5ea39d269b',
    PREFIX + 'create': '0f08e01b2893eff56769328d39168b907cfe7294c4ca3e16c2a5df5493ad25db',
    PREFIX + 'preview': '3e894b2eaf3b22a18adc3ef7729f7709c3ecb343d19cfafc81c4c2ad4e7a1b08',
    PREFIX + 'profile': '656b000c5dae1ac7bd63b8735a274d007b3b2238c99811a41ac60c90db78cc85',
    PREFIX + 'review-prepare': '8b3f3b29f65910e2ffc8b3a12ad9404901c2582ee42d91e344e0f28d744e0e98',
    '/internal/capabilities/v1/execute': '8e1d457704f0fe064d062cc2000cb47cac83699fcdc53d8fa7afc64423986e2e',
}
CAPS = {'profile': 'ouf.managed-source.file.profile', 'preview': 'ouf.managed-source.preview',
        'create': 'ouf.managed-source.onboarding.create'}
KEYS = ('DELEGATION_KEY_ENV', 'ISSUER', 'AUDIENCE', 'MCP_WORKLOAD', 'OWNER_KEY_ENV')


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()).hexdigest()


def read(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'BOUNDED_REGULAR_INPUT_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        need(len(raw) == before.st_size and (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_ino, after.st_mtime_ns, after.st_ctime_ns), 'INPUT_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def assets(path=None):
    raw = read(path or Path(__file__).with_name(ASSETS), 1048576)
    need(hashlib.sha256(raw).hexdigest() == ASSETS_SHA, 'SOURCE_ASSET_HASH_MISMATCH')
    return decode(raw)


def source(a, version, path):
    return a[version][path]['content']


def schema(a, version, mode):
    if mode == 'review-prepare':
        return json.loads(source(a, version, 'schemas/mcp-gateway-onboarding-review-prepare-dispatch-v1.json'))
    alternatives = json.loads(source(a, version, 'schemas/mcp-gateway-managed-file-dispatch-v1.json'))['oneOf']
    matches = [s for s in alternatives if s['properties']['CapabilityID']['const'] == CAPS[mode]]
    need(matches, 'CAPABILITY_SCHEMA_REQUIRED')
    return matches[0] if len(matches) == 1 else {'oneOf': matches}


def function_source(a, version, kind, constants):
    header = '\n'.join('local ' + key + ' = ' + json.dumps(constants[key]) for key in KEYS)
    return ('return function(conf, ctx)\n' + header + '\n' + source(a, version, 'tools/lua/delegation.lua') +
            '\n' + source(a, version, 'tools/lua/' + kind + '.lua') + '\nend')


def installed_constants(route, a, kind):
    post = route['plugins']['serverless-post-function']
    need(post.get('phase') == 'access' and len(post.get('functions', [])) == 1, 'ONE_OWNER_FUNCTION_REQUIRED')
    function = post['functions'][0]
    lines = function.split('\n')
    need(lines[0] == 'return function(conf, ctx)', 'KNOWN_OWNER_FUNCTION_HEADER_REQUIRED')
    constants = {}
    for key, line in zip(KEYS, lines[1:6]):
        need(line.startswith('local ' + key + ' = '), 'KNOWN_OWNER_CONSTANTS_REQUIRED')
        value = json.loads(line[len('local ' + key + ' = '):])
        need(isinstance(value, str) and 0 < len(value) <= 2048, 'CLOSED_BINDING_VALUE_REQUIRED')
        constants[key] = value
    need(set(constants) == set(KEYS) and all(re.fullmatch('[A-Z][A-Z0-9_]{0,127}', constants[key])
         for key in ('DELEGATION_KEY_ENV', 'OWNER_KEY_ENV')) and constants['DELEGATION_KEY_ENV'] != constants['OWNER_KEY_ENV'],
         'DISTINCT_EXISTING_KEY_REFERENCES_REQUIRED')
    need(function == function_source(a, 'old', kind, constants), 'INSTALLED_OWNER_FUNCTION_NOT_QUALIFIED_BASELINE')
    return constants


def unpack(data):
    need(type(data.get('list')) is list and data.get('total') == len(data['list']) == 84, 'EXACT_RETAINED_84_ROUTES_REQUIRED')
    rows = []
    for entry in data['list']:
        row = entry.get('value', entry)
        if isinstance(row.get('value'), dict):
            row = row['value']
        need(isinstance(row, dict) and isinstance(row.get('id'), (str, int)), 'ROUTE_ID_REQUIRED')
        rows.append(row)
    need(len({str(r['id']) for r in rows}) == len(rows), 'UNIQUE_ROUTE_IDS_REQUIRED')
    return rows


def compile_plan(data, a):
    rows = unpack(data)
    selected = {}
    for uri, expected in BEFORE.items():
        found = [row for row in rows if row.get('uri') == uri]
        need(len(found) == 1 and digest(found[0]) == expected, 'RETAINED_SELECTED_ROUTE_CHANGED')
        selected[uri] = found[0]
    need(source(a, 'old', 'tools/lua/delegation.lua') == source(a, 'candidate', 'tools/lua/delegation.lua'),
         'SHARED_AUTHENTICATION_CODE_MUST_BE_IDENTICAL')
    changes, common = [], None
    for mode in ('preview', 'profile', 'create', 'review-prepare'):
        old = selected[PREFIX + mode]
        constants = installed_constants(old, a, 'execute_managed_file')
        need(common is None or common == constants, 'SAME_MANAGED_OWNER_BINDINGS_REQUIRED')
        common = constants
        need(old['plugins']['request-validation']['body_schema'] == schema(a, 'old', mode),
             'INSTALLED_MANAGED_SCHEMA_NOT_QUALIFIED_BASELINE')
        new = copy.deepcopy(old)
        cap = 3145728 if mode in ('create', 'review-prepare') else 65536
        seconds = 3 if mode == 'profile' else 10
        new['plugins']['request-validation'].update(body_schema=schema(a, 'candidate', mode), max_req_body_size=cap)
        new['plugins'].setdefault('client-control', {})['max_body_size'] = cap
        new['plugins']['serverless-post-function']['functions'] = [function_source(a, 'candidate', 'execute_managed_file', constants)]
        new['upstream']['timeout'] = {'connect': 3, 'send': seconds, 'read': seconds}
        changes.append({'operation': 'UPDATE', 'uri': old['uri'], 'routeId': old['id'],
                        'beforeSha256': digest(old), 'before': old, 'desired': new})
    old = selected['/mcp']
    new = copy.deepcopy(old)
    new['plugins']['request-validation']['max_req_body_size'] = 4194304
    new['plugins'].setdefault('client-control', {})['max_body_size'] = 4194304
    changes.append({'operation': 'UPDATE', 'uri': old['uri'], 'routeId': old['id'],
                    'beforeSha256': digest(old), 'before': old, 'desired': new})
    semantic = [row for row in rows if row.get('uri') == '/internal/capabilities/v1/execute/semantic/search']
    need(len(semantic) == 1, 'ONE_EXISTING_SEMANTIC_READ_ROUTE_REQUIRED')
    constants = installed_constants(semantic[0], a, 'execute_semantic_read')
    need(all(constants[key] == common[key] for key in KEYS[:-1]), 'SAME_ESTABLISHED_IAM_BINDINGS_REQUIRED')
    upstream = semantic[0].get('upstream')
    need(isinstance(upstream, dict) and upstream.get('scheme') in ('http', 'https') and upstream.get('nodes'),
         'CURRENT_SEMANTIC_UPSTREAM_REQUIRED')
    template = selected['/internal/capabilities/v1/execute']
    need(all(name in template.get('plugins', {}) for name in
         ('openid-connect', 'limit-count', 'request-validation', 'serverless-pre-function')), 'AUTHENTICATED_EXECUTE_TEMPLATE_REQUIRED')
    for mode in ('request', 'status', 'candidates'):
        uri, route_id = DISCOVERY + mode, 'mcp-semantic-discovery-' + mode
        need(not any(str(r['id']) == route_id or any(p == uri or (isinstance(p, str) and p.endswith('*') and uri.startswith(p[:-1]))
                     for p in ([r['uri']] if 'uri' in r else r.get('uris', []))) for r in rows),
             'DISCOVERY_ROUTE_COLLISION_RECONCILE')
        new = copy.deepcopy(template)
        for key in ('create_time', 'update_time', 'service_id', 'upstream_id', 'uris'):
            new.pop(key, None)
        new.update(id=route_id, uri=uri, methods=['POST'])
        new.setdefault('labels', {})['ouf-mediation'] = 'semantic-discovery-v1'
        new['plugins']['request-validation'] = {'max_req_body_size': 65536, 'body_schema': json.loads(source(
            a, 'candidate', 'schemas/mcp-gateway-semantic-discovery-' + mode + '-dispatch-v1.json'))}
        new['plugins']['client-control'] = {'max_body_size': 65536}
        new['plugins']['serverless-post-function'] = {'phase': 'access', 'functions': [
            function_source(a, 'candidate', 'execute_semantic_discovery', constants)]}
        new['plugins']['proxy-rewrite'] = {'uri': '/api/internal/v1/semantic/discovery/' + mode}
        new['upstream'] = copy.deepcopy(upstream)
        new['upstream'].update(retries=0, timeout={'connect': 3, 'send': 3, 'read': 3})
        changes.append({'operation': 'ADD', 'uri': uri, 'routeId': route_id, 'beforeSha256': None, 'desired': new})
    changed_ids = {str(x['routeId']) for x in changes if x['operation'] == 'UPDATE'}
    unchanged = [row for row in rows if str(row['id']) not in changed_ids]
    need(len(changes) == 8 and len(unchanged) == 79, 'EXACT_DELTA_SIZE_REQUIRED')
    return {'schema': 'ouf.gateway-analysis-private-proposal.v1', 'sourceAssetsSha256': ASSETS_SHA,
            'sourceRouteCount': 84, 'desiredRouteCount': 87, 'changes': changes,
            'unchangedRoutes': unchanged, 'unchangedRoutesSha256': digest(unchanged),
            'applyImplemented': False, 'freshRuntimeReadRequiredBeforeApply': True,
            'providerSouthboundRoutesCreated': False, 'gatewayOwnerReplacementRequired': False}


def classify_error(raw):
    patterns = {'MISSING_RELATION': rb'relation [^\n]{1,160} does not exist',
                'MISSING_COLUMN': rb'column [^\n]{1,160} does not exist',
                'SQL_PERMISSION_DENIED': rb'permission denied for (?:table|schema|relation|database)',
                'DATABASE_AUTHENTICATION_FAILED': rb'(?:password|peer) authentication failed|no pg_hba.conf entry',
                'DATABASE_NOT_FOUND': rb'database [^\n]{1,160} does not exist',
                'DATABASE_CONNECTION_FAILED': rb'could not connect|connection refused',
                'SQL_TIMEOUT': rb'canceling statement due to (?:statement|lock) timeout'}
    return {'source': 'RETAINED_STDERR_ONLY_NO_NEW_QUERY', 'empty': not bool(raw.strip()),
            'hints': [name for name, pattern in patterns.items() if re.search(pattern, raw, re.I)],
            'rawErrorEmitted': False, 'causeProven': False}


def main():
    result = {'schema': 'ouf.gateway-analysis-preparation.v1', 'status': 'PREPARATION_INCOMPLETE',
              'runtimeChanged': False, 'adminRequests': 0, 'databaseRequests': 0, 'providerRequests': 0,
              'credentialValuesEmitted': False, 'providerEnableDispatched': False, 'gatewayOwnerChanged': False}
    try:
        need(os.geteuid() == 0, 'ROOT_REQUIRED')
        result['semanticDatabaseError'] = classify_error(read(INPUT / 'semantic-database.stderr.private', 65536))
        data = decode(read(INPUT / 'routes.private.json', 8 * 1024 * 1024))
        plan = compile_plan(data, assets())
        work = Path(tempfile.mkdtemp(prefix='gateway-analysis-proposal-', dir=ROOT))
        os.chmod(work, 0o700)
        fd = os.open(work / 'proposal.private.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump(plan, out, sort_keys=True)
            out.write('\n')
        result.update(status='GATEWAY_DELTA_PREPARED_NOT_APPLIED', privateEvidenceDirectory=str(work),
                      proposalSha256=digest(plan), updates=5, additions=3, unchangedRoutes=79,
                      sourceRouteCount=84, desiredRouteCount=87,
                      changes=[{'operation': c['operation'], 'uri': c['uri'], 'beforeSha256': c['beforeSha256'],
                                'desiredSha256': digest(c['desired'])} for c in plan['changes']])
    except (OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError) as exc:
        result['reason'] = str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
    result['observedAt'] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
