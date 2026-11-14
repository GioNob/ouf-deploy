#!/usr/bin/env python3
"""Six-route, hash-bound proposal/apply. No retry, rollback or other effects.

The private proposal includes all route credentials. Only public_plan is printable.
Source functions run from hash-checked assets with in-memory source readers.
"""
import argparse
import ast
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'releases/operational-execute-assets-20261111.json'
ASSETS_SHA = 'c23fec2ec408556c958ef330c21d06d0efa815690598cf4e0df099520c10432f'
HELPERS = {
    'read-discovery-contract-20261108.py': '468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277',
    'read-analysis-discovery-runtime-20261107.py': 'ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4',
    'apply-gateway-analysis-delta-20261108.py': '7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01',
}
IAM_KEYS = ('DELEGATION_KEY_ENV', 'ISSUER', 'AUDIENCE', 'MCP_WORKLOAD')
OP_KEYS = ('CAPABILITY', 'OWNER', 'REQUIRED_SCOPE')
RECEIPT_KEYS = ('INGESTION_RECEIPT_KEY_ENV', 'GATEWAY_RECEIPT_KEY_ENV')
PREFIX = '/internal/capabilities/v1/execute/'
CHANGED_FIELDS = ('plugins.request-validation.body_schema',
                  'plugins.serverless-post-function.functions',
                  'plugins.proxy-rewrite.uri', 'upstream')


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False) + '\n').encode()).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'NONFINITE_JSON_NUMBER'))


def read(path, maximum=16 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'BOUNDED_REGULAR_FILE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(after), 'FILE_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private(work, name, value):
    fd = os.open(work / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write((json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    fsync_dir(work)


class AssetPath:
    """Only gateway source in the manifest can be read by the pinned functions."""
    def __init__(self, files, path=''):
        self.files, self.path = files, path

    def __truediv__(self, path):
        return AssetPath(self.files, (self.path + '/' + path).lstrip('/'))

    def read_text(self):
        return self.files[self.path]['content']


def load_assets(path=ASSETS):
    raw = read(path)
    need(hashlib.sha256(raw).hexdigest() == ASSETS_SHA, 'SOURCE_ASSET_HASH_MISMATCH')
    a = decode(raw)
    need(a['gatewayCommit'] == '8383cfe7946199badc5fcbb1bb3ac25160567541', 'PINNED_GATEWAY_REQUIRED')
    files = a['files']
    for record in files.values():
        need(hashlib.sha256(record['content'].encode()).hexdigest() == record['sha256'], 'ASSET_MEMBER_HASH_MISMATCH')
    tree = ast.parse(files['tools/materialize_operational_execute.py']['content'])
    assignment = next(n for n in tree.body if isinstance(n, ast.Assign) and
                      any(isinstance(t, ast.Name) and t.id == 'CAPABILITIES' for t in n.targets))
    caps = ast.literal_eval(assignment.value)
    schema_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'dispatch_schema')
    env = {'json': json, 'copy': copy, 'ROOT': AssetPath(files), 'CAPABILITIES': caps}
    exec(compile(ast.Module(body=[schema_fn], type_ignores=[]), '<pinned-dispatch-schema>', 'exec'), env)
    f_tree = ast.parse(files['tools/delegation_functions.py']['content'])
    fn = next(n for n in f_tree.body if isinstance(n, ast.FunctionDef) and n.name == 'function')
    def pinned_import(name, *args, **kwargs):
        need(name == 'tools.materialize_operational_execute', 'UNEXPECTED_ASSET_IMPORT')
        return SimpleNamespace(CAPABILITIES=caps)
    fenv = {'json': json, 're': re, 'ROOT': AssetPath(files) / 'tools/lua',
            '__builtins__': {**vars(__import__('builtins')), '__import__': pinned_import}}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), '<pinned-delegation-function>', 'exec'), fenv)
    status_tree = ast.parse(files['tools/materialize_apisix_execute_runtime.py']['content'])
    pre = [n.value for n in ast.walk(status_tree) if isinstance(n, ast.Constant) and
           isinstance(n.value, str) and n.value.startswith('return function(conf, ctx) for name,')]
    need(len(pre) == 1 and len(caps) == 6, 'CLOSED_OPERATIONAL_PROFILE_REQUIRED')
    return SimpleNamespace(capabilities=caps, schema=env['dispatch_schema'], function=fenv['function'],
                           pre={'phase': 'rewrite', 'functions': pre}, files=files)


def parse_bindings(values, assets):
    result = {}
    for value in values:
        parts = value.split('=')
        need(len(parts) == 2, 'SERVICE_BINDING_FORMAT_REQUIRED')
        service, host = parts
        need(service not in result and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,252}', host),
             'UNIQUE_VALID_SERVICE_BINDING_REQUIRED')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            need(False, 'RUNTIME_DNS_HOST_REQUIRED')
        result[service] = host
    need(len(values) == 3 and set(result) == {c[1] for c in assets.capabilities.values()},
         'EXACT_THREE_SERVICE_BINDINGS_REQUIRED')
    return result


def body(row):
    return {k: v for k, v in row.items() if k not in ('create_time', 'update_time')}


def route_map(data):
    need(type(data.get('list')) is list and data.get('total') == len(data['list']) <= 512,
         'COMPLETE_BOUNDED_ROUTE_LIST_REQUIRED')
    result = {}
    for entry in data['list']:
        row = entry.get('value', entry)
        if isinstance(row.get('value'), dict):
            row = row['value']
        rid = str(row.get('id', ''))
        need(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', rid) and rid not in result, 'UNIQUE_ROUTE_ID_REQUIRED')
        result[rid] = body(row)
    return result


def installed_constants(route, capability, a):
    post = route['plugins']['serverless-post-function']
    need(post.get('phase') == 'access' and len(post.get('functions', [])) == 1, 'ONE_OWNER_FUNCTION_REQUIRED')
    lines = post['functions'][0].split('\n')
    need(lines[0] == 'return function(conf, ctx)', 'KNOWN_OWNER_HEADER_REQUIRED')
    # Read the contiguous uppercase constant header, never search the Lua body.
    # The body may start directly with lower-case locals (e.g. local cjson).
    # Unknown, extra, missing and reordered constants all fail.
    header = []
    for line in lines[1:]:
        match = re.fullmatch(r'local\s+([A-Z][A-Z0-9_]*)\s*=\s*(.*)', line)
        if match is None:
            need(not re.match(r'\s*local\s+[A-Z_]', line), 'KNOWN_OWNER_CONSTANTS_REQUIRED')
            break
        header.append((match[1], line))
    keys = tuple(key for key, _ in header)
    if keys == IAM_KEYS + OP_KEYS:
        installed_format = 'current'
    elif keys == IAM_KEYS + RECEIPT_KEYS:
        installed_format = 'legacy-execute-summary'
    else:
        need(False, 'KNOWN_OWNER_CONSTANTS_REQUIRED')
    values = {}
    for key, line in header:
        prefix = 'local ' + key + ' = '
        need(line.startswith(prefix), 'KNOWN_OWNER_CONSTANTS_REQUIRED')
        try:
            value = decode(line[len(prefix):])
        except (ValueError, RuntimeError):
            need(False, 'CLOSED_OWNER_CONSTANT_REQUIRED')
        need(isinstance(value, str) and 0 < len(value) <= 2048, 'CLOSED_OWNER_CONSTANT_REQUIRED')
        values[key] = value
    if installed_format == 'current':
        owner, _, _, _, scope, _ = a.capabilities[capability]
        need((values['CAPABILITY'], values['OWNER'], values['REQUIRED_SCOPE']) == (capability, owner, scope),
             'INSTALLED_OPERATIONAL_CONSTANTS_DIVERGE')
    key_refs = ('DELEGATION_KEY_ENV',) + (RECEIPT_KEYS if installed_format == 'legacy-execute-summary' else ())
    need(all(re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', values[k]) for k in key_refs),
         'EXISTING_KEY_REFERENCE_REQUIRED')
    need(len({values[k] for k in key_refs}) == len(key_refs), 'DISTINCT_INSTALLED_KEY_REFERENCES_REQUIRED')
    return installed_format, {k: values[k] for k in IAM_KEYS + RECEIPT_KEYS if k in values}


def function_source(a, capability, constants):
    c = a.capabilities[capability]
    installation = dict(issuerUrl=constants['ISSUER'], gatewayAudience=constants['AUDIENCE'],
                        mcpServiceIdentity=constants['MCP_WORKLOAD'])
    need(installation['issuerUrl'] == installation['issuerUrl'].rstrip('/'), 'CANONICAL_INSTALLED_ISSUER_REQUIRED')
    return a.function('execute_operational', installation, constants['DELEGATION_KEY_ENV'],
                      owner_key_env=constants.get('GATEWAY_RECEIPT_KEY_ENV') if c[0] == 'gateway' else None,
                      operational_binding={'capability': capability, 'owner': c[0], 'scope': c[4]})


def field(row, path):
    for part in path.split('.'):
        row = row[part]
    return row


def contains_scope(value, scope):
    if isinstance(value, str):
        return scope in value
    if isinstance(value, dict):
        return any(contains_scope(k, scope) or contains_scope(v, scope) for k, v in value.items())
    if isinstance(value, list):
        return any(contains_scope(v, scope) for v in value)
    return False


def compile_plan(rows, a, bindings, observation):
    # The source count is observed, not pinned: the complete route map is bound
    # into the plan hash ('before') and shown to the human in the public plan.
    need(3 <= len(rows) <= 509, 'BOUNDED_SOURCE_ROUTE_COUNT_REQUIRED')
    changes, blockers, common, installed_format = [], [], None, None
    # Qualify all installed headers before rendering any desired route.
    for capability in a.capabilities:
        if not capability.endswith('.summary'):
            continue
        rid = 'execute-' + capability
        need(rid in rows and rows[rid].get('id') == rid and rows[rid].get('uri') == PREFIX + capability,
             'EXACT_INSTALLED_SUMMARY_REQUIRED')
        fmt, constants = installed_constants(rows[rid], capability, a)
        need(installed_format is None or installed_format == fmt, 'INSTALLED_FORMATS_DIVERGE')
        need(common is None or all(common[k] == constants[k] for k in IAM_KEYS), 'INSTALLED_IAM_CONSTANTS_DIVERGE')
        need(common is None or common == constants, 'INSTALLED_RECEIPT_KEY_REFERENCES_DIVERGE')
        installed_format, common = fmt, constants
    need(common is not None and 'GATEWAY_RECEIPT_KEY_ENV' in common,
         'INSTALLED_GATEWAY_RECEIPT_KEY_REFERENCE_REQUIRED')
    for capability, (owner, service, port, path, scope, seconds) in a.capabilities.items():
        if not capability.endswith('.summary'):
            continue
        rid = 'execute-' + capability
        need(rid in rows and rows[rid].get('id') == rid and rows[rid].get('uri') == PREFIX + capability,
             'EXACT_INSTALLED_SUMMARY_REQUIRED')
        old = rows[rid]
        need(old.get('methods') == ['POST'] and not (set(old) & {'upstream_id', 'service_id', 'uris'}),
             'CLOSED_INLINE_SUMMARY_ROUTE_REQUIRED')
        constants = common
        plugins = old['plugins']
        need(set(plugins) == {'limit-count', 'openid-connect', 'proxy-rewrite', 'request-validation',
                              'serverless-pre-function', 'serverless-post-function'}, 'KNOWN_SIX_PLUGINS_REQUIRED')
        # No scope replacement by string substitution: qualify the complete pre
        # function and require the same no-required_scopes OIDC contract as gateway.
        if plugins['serverless-pre-function'] != a.pre:
            blockers.append({'id': rid, 'field': 'plugins.serverless-pre-function',
                             'beforeSha256': digest(plugins['serverless-pre-function']), 'requiredSha256': digest(a.pre)})
        if 'required_scopes' in plugins['openid-connect']:
            blockers.append({'id': rid, 'field': 'plugins.openid-connect.required_scopes',
                             'beforeSha256': digest(plugins['openid-connect']['required_scopes']),
                             'requiredSha256': digest(None)})
        # Detect additional scope-bearing configuration in preserved plugin
        # fields; its semantics cannot be inferred by replacing arbitrary Lua.
        for plugin in ('openid-connect', 'limit-count', 'proxy-rewrite', 'request-validation'):
            preserved = copy.deepcopy(plugins[plugin])
            if plugin == 'openid-connect':
                preserved.pop('required_scopes', None)
            if plugin == 'request-validation':
                preserved.pop('body_schema', None)
            if contains_scope(preserved, scope):
                blockers.append({'id': rid, 'field': 'plugins.' + plugin,
                                 'beforeSha256': digest(preserved), 'requiredSha256': None})
        for target in (capability, capability[:-len('summary')] + 'incidents'):
            c = a.capabilities[target]
            new = copy.deepcopy(old)
            new['id'], new['uri'] = 'execute-' + target, PREFIX + target
            new['plugins']['request-validation']['body_schema'] = a.schema(target)
            new['plugins']['serverless-post-function']['functions'] = [function_source(a, target, constants)]
            new['plugins']['proxy-rewrite']['uri'] = c[3]
            new['upstream'] = {'type': 'roundrobin', 'scheme': 'http', 'nodes': {f'{bindings[c[1]]}:{c[2]}': 1},
                               'retries': 0, 'timeout': dict.fromkeys(('connect', 'send', 'read'), c[5])}
            before = old if target == capability else None
            if before is None:
                need(new['id'] not in rows and all(new['uri'] not in ([r.get('uri')] + r.get('uris', []))
                                                 for r in rows.values()), 'INCIDENT_ROUTE_COLLISION')
            else:
                # The same summary URI must not be shadowed by another exact route.
                need(sum(new['uri'] in ([r.get('uri')] + r.get('uris', [])) for r in rows.values()) == 1,
                     'SUMMARY_URI_COLLISION')
            changes.append({'id': new['id'], 'operation': 'UPDATE' if before else 'ADD',
                            'before': before, 'desired': new})
    changes.sort(key=lambda c: (c['operation'] == 'ADD', c['id']))
    need(len(changes) == 6 and len({c['id'] for c in changes}) == 6, 'EXACT_SIX_CHANGES_REQUIRED')
    return {'schema': 'ouf.operational-execute-plan.v1', 'assetsSha256': ASSETS_SHA,
            'installedFormat': installed_format,
            'bindings': bindings, 'bindingObservation': observation, 'before': rows,
            'changes': changes, 'unsupportedDifferences': blockers}


def public_plan(plan):
    changes = []
    for c in plan['changes']:
        old, new = c['before'], c['desired']
        row = {'id': c['id'], 'uri': new['uri'], 'operation': c['operation'],
               'beforeSha256': digest(old) if old else None, 'afterSha256': digest(new),
               'upstream': new['upstream'], 'ownerPath': new['plugins']['proxy-rewrite']['uri'],
               'aggregateMarkerPresent': "'X-OUF-Delegation-Verified', 'mcp-operational-aggregate-v1'" in
                                         new['plugins']['serverless-post-function']['functions'][0]}
        if new['id'] in ('execute-ouf.gateway.operations.summary', 'execute-ouf.gateway.operations.incidents'):
            row['producerReceipt'] = True
        if old:
            row['beforeAggregateMarkerPresent'] = "'X-OUF-Delegation-Verified', 'mcp-operational-aggregate-v1'" in \
                old['plugins']['serverless-post-function']['functions'][0]
            row['changedFields'] = [{'field': p, 'beforeSha256': digest(field(old, p)),
                                     'afterSha256': digest(field(new, p))}
                                    for p in CHANGED_FIELDS if field(old, p) != field(new, p)]
        changes.append(row)
    public = {'planSha256': digest(plan), 'bindings': plan['bindings'],
            'installedFormat': plan['installedFormat'],
            'bindingObservationSha256': digest(plan['bindingObservation']),
            'sourceRouteCount': len(plan['before']), 'desiredRouteCount': len(plan['before']) + 3,
            'unchangedRoutes': len(plan['before']) - 3,
            'updates': 3, 'additions': 3, 'changes': changes,
            'unsupportedDifferences': plan['unsupportedDifferences']}
    if plan['unsupportedDifferences']:
        public['reviewQuestion'] = ('Autorizzare una revisione distinta dei campi elencati, '
                                    'fuori dal delta summary consentito, prima di procedere?')
    return public


class Docker:
    def __init__(self, binary, socket):
        self.command = (binary, '--host', 'unix://' + socket, '--config', '/nonexistent')

    def run(self, *args):
        env = dict(os.environ, DOCKER_API_VERSION='1.44')
        run = subprocess.run((*self.command, *args), capture_output=True, timeout=12, env=env)
        need(run.returncode == 0 and len(run.stdout) <= 8 * 1024 * 1024, 'DOCKER_READ_UNPROVEN')
        return run.stdout

    def inspect(self, cid):
        need(re.fullmatch(r'[a-f0-9]{64}', cid), 'EXACT_CONTAINER_ID_REQUIRED')
        rows = decode(self.run('container', 'inspect', cid))
        need(len(rows) == 1 and rows[0]['Id'] == cid, 'DOCKER_ID_MISMATCH')
        return rows[0]


def running(doc):
    return doc['State']['Running'] and not doc['State'].get('Paused') and not doc['State'].get('Restarting')


def observe_bindings(docker, apisix, bindings):
    """One resolved address, one running container, one shared network endpoint."""
    need(running(apisix), 'APISIX_RUNNING_REQUIRED')
    networks = apisix['NetworkSettings']['Networks']
    peers = {}
    for network in networks.values():
        docs = decode(docker.run('network', 'inspect', network['NetworkID']))
        need(len(docs) == 1 and docs[0]['Id'] == network['NetworkID'], 'NETWORK_ID_MISMATCH')
        for cid in docs[0].get('Containers', {}):
            if cid != apisix['Id'] and cid not in peers:
                peers[cid] = docker.inspect(cid)
    result = {}
    for service, host in sorted(bindings.items()):
        raw = docker.run('exec', apisix['Id'], 'getent', 'hosts', host)
        addresses = set()
        for line in raw.decode('ascii').splitlines():
            parts = line.split()
            need(len(parts) >= 2, 'BINDING_RESOLUTION_INVALID')
            addresses.add(str(ipaddress.ip_address(parts[0])))
        need(len(addresses) == 1, 'BINDING_UNRESOLVED_OR_AMBIGUOUS')
        address = next(iter(addresses))
        matches = []
        for cid, doc in peers.items():
            if not running(doc):
                continue
            for endpoint in doc['NetworkSettings']['Networks'].values():
                if endpoint['NetworkID'] in {n['NetworkID'] for n in networks.values()} and address in {
                        endpoint.get('IPAddress'), endpoint.get('GlobalIPv6Address')}:
                    matches.append({'containerId': cid, 'image': doc['Image'],
                                    'startedAt': doc['State']['StartedAt'], 'endpoint': endpoint})
        need(len(matches) == 1, 'BINDING_RUNNING_SHARED_PEER_UNPROVEN')
        result[service] = {'host': host, 'address': address, **matches[0]}
    return result


def load_helper(name):
    path = ROOT / 'scripts' / name
    raw = read(path)
    need(hashlib.sha256(raw).hexdigest() == HELPERS[name], 'HELPER_HASH_MISMATCH')
    spec = importlib.util.spec_from_file_location('operational_' + name.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def make_admin(args, report, docker):
    c = load_helper('read-discovery-contract-20261108.py')
    h = load_helper('read-analysis-discovery-runtime-20261107.py')
    publisher = load_helper('apply-gateway-analysis-delta-20261108.py')
    h.inspect = docker.inspect
    c.ADMIN_KEY = args.admin_key_file
    c.CONFIG_TARGET = args.apisix_config_target
    raw = read(args.runtime_plan)
    need(hashlib.sha256(raw).hexdigest() == args.runtime_plan_sha256, 'RUNTIME_PLAN_HASH_MISMATCH')
    role = decode(raw)['roles']['apisix']
    doc = docker.inspect(role['containerId'])
    need(doc['Image'] == role['nativeImage'] and running(doc), 'EXPECTED_RUNNING_APISIX_REQUIRED')
    class Admin(publisher.Admin):
        def plan_frame(self):
            return publisher.stable_frame(self.h, self.apisix)

        def routes(self):
            self.report['adminGetAttempts'] += 1
            response = self.request('GET', '/apisix/admin/routes')
            need(response['httpStatus'] == 200, 'ADMIN_GET_FAILED')
            return route_map(response['body'])
    return Admin(c, h, doc, report)


def begin_attempt(root, sha):
    path = root / ('apply-' + sha)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        need(False, 'PREVIOUS_ATTEMPT_EXISTS_DO_NOT_REPLAY')
    fsync_dir(root)
    return path


def publish(plan, admin, work, report, binding_guard):
    need(not plan['unsupportedDifferences'], 'SUMMARY_PLUGIN_REVIEW_REQUIRED')
    need(len(plan['changes']) == 6, 'EXACT_SIX_CHANGES_REQUIRED')
    expected = copy.deepcopy(plan['before'])
    private(work, 'before.private.json', expected)
    for ordinal, change in enumerate(plan['changes']):
        binding_guard()
        need(admin.routes() == expected, 'ROUTES_CHANGED_BEFORE_WRITE')
        rid, desired = change['id'], change['desired']
        private(work, f'{ordinal:02d}-intent.private.json',
                {'id': rid, 'beforeMapSha256': digest(expected), 'desiredSha256': digest(desired)})
        report['adminPutAttempts'] += 1
        report['runtimeChanged'] = None
        response = admin.put(rid, desired)
        private(work, f'{ordinal:02d}-ack.private.json', response)
        need(response['httpStatus'] in (200, 201), 'ADMIN_PUT_NOT_ACKNOWLEDGED')
        expected[rid] = desired
        need(admin.routes() == expected, 'ROUTE_WRITE_READBACK_MISMATCH')
        private(work, f'{ordinal:02d}-verified.private.json', {'mapSha256': digest(expected)})
        report['routeWritesVerified'] += 1
        report['runtimeChanged'] = True
    need(len(expected) == len(plan['before']) + 3, 'FINAL_ROUTE_COUNT_MISMATCH')
    admin.guard()
    report.update(finalRouteCount=len(expected), unchangedRoutesVerified=len(plan['before']) - 3)


class JsonParser(argparse.ArgumentParser):
    def error(self, message):
        need(False, 'INVALID_CLI_ARGUMENTS')


def arguments(argv):
    p = JsonParser(description=__doc__, add_help=False)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    p.add_argument('--plan-sha256')
    p.add_argument('--service-binding', action='append', required=True)
    p.add_argument('--runtime-plan', type=Path, required=True)
    p.add_argument('--runtime-plan-sha256', required=True)
    p.add_argument('--evidence-root', type=Path, required=True)
    p.add_argument('--admin-key-file', type=Path, required=True)
    p.add_argument('--docker-bin', required=True)
    p.add_argument('--docker-socket', required=True)
    p.add_argument('--apisix-config-target', required=True)
    args = p.parse_args(argv)
    need(bool(args.plan_sha256) == args.apply and all(re.fullmatch('[a-f0-9]{64}', value)
         for value in (args.runtime_plan_sha256, args.plan_sha256 or '0' * 64)), 'APPROVED_PLAN_HASH_REQUIRED')
    return args


def main(argv=None):
    report = {'status': 'HELD', 'reason': 'NOT_STARTED', 'adminGetAttempts': 0,
              'adminPutAttempts': 0, 'routeWritesVerified': 0, 'runtimeChanged': False,
              'adminCredentialConfigurationsRead': 0, 'externalAdminKeyFilesRead': 0}
    try:
        args = arguments(argv)
        need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        info = args.evidence_root.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
             'PRIVATE_ROOT_DIRECTORY_REQUIRED')
        a = load_assets()
        bindings = parse_bindings(args.service_binding, a)
        work = begin_attempt(args.evidence_root, args.plan_sha256) if args.apply else None
        if work is not None:
            report['privateEvidenceDirectory'] = str(work)
            private(work, 'attempt.private.json', {'approvedPlanSha256': args.plan_sha256})
        docker = Docker(args.docker_bin, args.docker_socket)
        admin = make_admin(args, report, docker)
        observation = observe_bindings(docker, admin.apisix, bindings)
        plan = compile_plan(admin.routes(), a, bindings, observation)
        # Include installation generation/transport without publishing its credentials.
        plan['runtimeBinding'] = {'apisixFrameSha256': digest(admin.plan_frame()),
                                  'runtimePlanSha256': args.runtime_plan_sha256,
                                  'dockerSocket': args.docker_socket, 'dockerBinary': args.docker_bin,
                                  'configTarget': args.apisix_config_target,
                                  'adminKeyFile': str(args.admin_key_file)}
        report.update(public_plan(plan))
        if work is None:
            work = Path(tempfile.mkdtemp(prefix='plan-', dir=args.evidence_root))
            os.chmod(work, 0o700)
            fsync_dir(args.evidence_root)
        report['privateEvidenceDirectory'] = str(work)
        private(work, 'plan.private.json', plan)
        need(not plan['unsupportedDifferences'], 'SUMMARY_PLUGIN_REVIEW_REQUIRED')
        if args.apply:
            need(digest(plan) == args.plan_sha256, 'FRESH_PLAN_HASH_MISMATCH')
            def binding_guard():
                admin.guard()
                need(observe_bindings(docker, admin.apisix, bindings) == observation, 'SERVICE_BINDING_CHANGED')
            publish(plan, admin, work, report, binding_guard)
        report.update(status='OPERATIONAL_ROUTES_APPLIED' if args.apply else 'OPERATIONAL_ROUTES_PLANNED',
                      reason='SIX_ROUTE_READBACK_VERIFIED' if args.apply else 'HUMAN_HASH_APPROVAL_REQUIRED')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError,
            subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        safe = str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(status='HELD', reason=safe)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report['status'] != 'HELD' else 1


if __name__ == '__main__':
    sys.exit(main())
