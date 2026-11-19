#!/usr/bin/env python3
"""Hash-bound two-route ingestion receipt delta; Linux isolated root only.

Installation names, credentials and complete maps belong only in private evidence.
No retry, rollback, container lifecycle or other runtime mutation.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER_SHA256 = '4e06c241dd2c6607a683dfb770605a4e3813252bb1e6a2c5c24ea0e4d03c54c3'
TARGETS = tuple('execute-ouf.ingestion.operations.' + op for op in ('incidents', 'summary'))


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def load_controller():
    # Bootstrap the same bounded, no-follow/stable-identity reader before import.
    path = ROOT / 'scripts/apply-operational-execute-routes-20261111.py'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= 1024 * 1024,
             'BOUNDED_CONTROLLER_FILE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(1024 * 1024 + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(after) and len(raw) == before.st_size,
             'CONTROLLER_CHANGED_DURING_READ')
    finally:
        os.close(fd)
    need(hashlib.sha256(raw).hexdigest() == CONTROLLER_SHA256, 'CONTROLLER_HASH_MISMATCH')
    spec = importlib.util.spec_from_file_location('pinned_operational_execute', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def private_directory(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
         'PRIVATE_ROOT_DIRECTORY_REQUIRED')


def read_applied_plan(c, path, root, sha):
    need(re.fullmatch(r'[a-f0-9]{64}', sha), 'APPLIED_PLAN_HASH_REQUIRED')
    # Resolve lexically, never follow a user-supplied symlink. Hold each directory
    # open and traverse by dir_fd, so ancestor replacement cannot redirect read().
    need('..' not in path.parts and '..' not in root.parts, 'APPLIED_PLAN_PATH_INVALID')
    path, root = path.absolute(), root.absolute()
    try:
        relative = path.relative_to(root)
    except ValueError:
        need(False, 'APPLIED_PLAN_OUTSIDE_EVIDENCE_ROOT')
    need(len(relative.parts) >= 2 and relative.name == 'plan.private.json' and
         relative.parent.name == 'apply-' + sha, 'APPLIED_PLAN_DIRECTORY_HASH_MISMATCH')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root.anchor, flags)
    try:
        for part in root.parts[1:]:
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = new
        info = os.fstat(fd)
        need(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_ROOT_DIRECTORY_REQUIRED')
        for part in relative.parts[:-1]:
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            need(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                 'APPLIED_PLAN_PRIVATE_DIRECTORY_REQUIRED')
        pinned = Path('/proc/self/fd') / str(fd) / relative.name
        before = pinned.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and
             stat.S_IMODE(before.st_mode) == 0o600, 'APPLIED_PLAN_PRIVATE_FILE_REQUIRED')
        raw = c.read(pinned)
        after = pinned.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(after), 'APPLIED_PLAN_CHANGED_DURING_READ')
    finally:
        os.close(fd)
    applied = c.decode(raw)
    need(c.digest(applied) == sha, 'APPLIED_PLAN_HASH_MISMATCH')
    return applied


def expected_map(c, applied, a):
    # Qualify the entire retained proposal as an actual output of the pinned
    # controller, including every desired field; do not trust a partial manifest.
    rendered = c.compile_plan(applied['before'], a, applied['bindings'], applied['bindingObservation'])
    rendered['runtimeBinding'] = applied['runtimeBinding']
    need(rendered == applied and not rendered['unsupportedDifferences'], 'APPLIED_PLAN_PROFILE_DIVERGENT')
    expected = copy.deepcopy(applied['before'])
    for change in applied['changes']:
        expected[change['id']] = copy.deepcopy(change['desired'])
    return {rid: c.body(row) for rid, row in expected.items()}


def installed_profile(c, rows, a):
    common, gateway = None, None
    for cap, binding in a.capabilities.items():
        rid = 'execute-' + cap
        need(rid in rows, 'EXACT_OPERATIONAL_ROUTE_REQUIRED')
        row = rows[rid]
        post = row['plugins']['serverless-post-function']
        need(post.get('phase') == 'access' and len(post.get('functions', [])) == 1,
             'ONE_OWNER_FUNCTION_REQUIRED')
        fn = post['functions'][0]
        if binding[0] == 'ingestion':
            need('RECEIPT_KEY_ENV' not in fn, 'ALREADY_APPLIED_OR_DIVERGENT')
        keys = c.IAM_KEYS + c.OP_KEYS + (('RECEIPT_KEY_ENV',) if binding[0] == 'gateway' else ())
        lines = fn.split('\n')
        need(lines[0] == 'return function(conf, ctx)', 'KNOWN_OWNER_HEADER_REQUIRED')
        values = {}
        for index, key in enumerate(keys, 1):
            prefix = 'local ' + key + ' = '
            need(lines[index].startswith(prefix), 'KNOWN_OWNER_CONSTANTS_REQUIRED')
            value = c.decode(lines[index][len(prefix):])
            need(isinstance(value, str) and 0 < len(value) <= 2048, 'CLOSED_OWNER_CONSTANT_REQUIRED')
            values[key] = value
        iam = {key: values[key] for key in c.IAM_KEYS}
        need(common is None or common == iam, 'INSTALLED_IAM_CONSTANTS_DIVERGE')
        common = iam
        need((values['CAPABILITY'], values['OWNER'], values['REQUIRED_SCOPE']) == (cap, binding[0], binding[4]),
             'INSTALLED_OPERATIONAL_CONSTANTS_DIVERGE')
        if binding[0] == 'gateway':
            g = values['RECEIPT_KEY_ENV']
            need(re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', g) and g != iam['DELEGATION_KEY_ENV'],
                 'EXISTING_KEY_REFERENCE_REQUIRED')
            need(gateway is None or gateway == g, 'INSTALLED_GATEWAY_RECEIPT_REFERENCES_DIVERGE')
            gateway = g
        constants = dict(iam, GATEWAY_RECEIPT_KEY_ENV=values.get('RECEIPT_KEY_ENV'))
        need(row.get('id') == rid and row.get('uri') == c.PREFIX + cap and
             fn == c.function_source(a, cap, constants), 'INSTALLED_OPERATIONAL_FUNCTION_DIVERGENT')
    need(common is not None and gateway is not None, 'INSTALLED_GATEWAY_RECEIPT_REFERENCE_REQUIRED')
    return common, gateway


def observe_env(c, apisix, name):
    need(c.running(apisix), 'APISIX_RUNNING_REQUIRED')
    entries = apisix['Config']['Env']
    need(type(entries) is list and all(isinstance(v, str) and '=' in v for v in entries),
         'APISIX_ENV_NAMES_UNPROVEN')
    names = [entry.split('=', 1)[0] for entry in entries]
    need(all(names) and len(names) == len(set(names)), 'APISIX_ENV_NAMES_UNPROVEN')
    # Values never leave this in-memory inspect document, even in private plans.
    need(name in names, 'INGESTION_RECEIPT_KEY_NOT_EXPOSED_TO_APISIX')
    return {'ingestionReceiptKeyEnvSha256': c.digest(name), 'exposedToApisix': True,
            'apisixEnvNamesSha256': c.digest(sorted(names))}


def receipt_function(a, cap, constants, gateway, name):
    receipt_keys = {'gateway': gateway, 'ingestion': name}
    binding = a.capabilities[cap]
    installation = dict(issuerUrl=constants['ISSUER'], gatewayAudience=constants['AUDIENCE'],
                        mcpServiceIdentity=constants['MCP_WORKLOAD'])
    return a.function('execute_operational', installation, constants['DELEGATION_KEY_ENV'],
                      owner_key_env=receipt_keys.get(binding[0]),
                      operational_binding={'capability': cap, 'owner': binding[0], 'scope': binding[4]})


def compile_plan(c, rows, applied, applied_sha, a, bindings, observation, name, apisix):
    need(re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', name), 'INVALID_INGESTION_RECEIPT_KEY_ENV')
    need(c.digest(applied) == applied_sha, 'APPLIED_PLAN_HASH_MISMATCH')
    # Give the explicit already-applied reason even when this also differs from
    # the approved map. Never accept a second application as a no-op.
    for rid in TARGETS:
        if rid in rows:
            route = rows[rid]
            plugins = route.get('plugins') if isinstance(route, dict) else None
            post = plugins.get('serverless-post-function') if isinstance(plugins, dict) else None
            functions = post.get('functions') if isinstance(post, dict) else None
            if isinstance(functions, list):
                need(not any(isinstance(fn, str) and 'RECEIPT_KEY_ENV' in fn for fn in functions),
                     'ALREADY_APPLIED_OR_DIVERGENT')
    expected = expected_map(c, applied, a)
    constants, gateway = installed_profile(c, expected, a)
    need(rows == expected, 'CURRENT_MAP_DIFFERS_FROM_APPLIED_PLAN')
    need(bindings == applied['bindings'], 'SERVICE_BINDINGS_DIFFER_FROM_APPLIED_PLAN')
    need(name not in (constants['DELEGATION_KEY_ENV'], gateway), 'DISTINCT_RECEIPT_KEY_REFERENCES_REQUIRED')
    env = observe_env(c, apisix, name)
    changes = []
    for rid in TARGETS:
        desired = copy.deepcopy(expected[rid])
        desired['plugins']['serverless-post-function']['functions'] = [
            receipt_function(a, rid.removeprefix('execute-'), constants, gateway, name)]
        need(desired != expected[rid], 'EXACT_TWO_UPDATES_REQUIRED')
        changes.append({'id': rid, 'operation': 'UPDATE', 'before': expected[rid], 'desired': desired})
    return {'schema': 'ouf.operational-ingestion-receipt-plan.v1', 'controllerSha256': CONTROLLER_SHA256,
            'assetsSha256': c.ASSETS_SHA, 'appliedPlanSha256': applied_sha,
            'currentMapMatchesAppliedPlan': True, 'environmentObservation': env,
            'bindings': bindings, 'bindingObservation': observation, 'before': rows, 'changes': changes}


def public_plan(c, plan):
    count = len(plan['before'])
    return {'planSha256': c.digest(plan), 'appliedPlanSha256': plan['appliedPlanSha256'],
            'currentMapMatchesAppliedPlan': plan['currentMapMatchesAppliedPlan'],
            **plan['environmentObservation'], 'bindingObservationSha256': c.digest(plan['bindingObservation']),
            'sourceRouteCount': count, 'desiredRouteCount': count, 'unchangedRoutes': count - 2,
            'updates': 2, 'additions': 0,
            'changes': [{'id': ch['id'], 'operation': ch['operation'],
                         'beforeSha256': c.digest(ch['before']), 'afterSha256': c.digest(ch['desired']),
                         'producerReceiptBefore': False, 'producerReceiptAfter': True,
                         'changedFields': ['plugins.serverless-post-function.functions']}
                        for ch in plan['changes']]}


def publish(c, plan, admin, work, report, binding_guard):
    # The pinned publisher fixes six writes and N+3. Only its small sequential
    # journal/readback loop is specialized here to two UPDATEs and N -> N.
    need([ch['id'] for ch in plan['changes']] == list(TARGETS) and
         all(ch['operation'] == 'UPDATE' for ch in plan['changes']), 'EXACT_TWO_UPDATES_REQUIRED')
    expected = copy.deepcopy(plan['before'])
    for ch in plan['changes']:
        desired = copy.deepcopy(expected[ch['id']])
        desired['plugins']['serverless-post-function']['functions'] = c.field(
            ch['desired'], 'plugins.serverless-post-function.functions')
        need(ch['before'] == expected[ch['id']] and ch['desired'] == desired and ch['before'] != desired,
             'ONLY_POST_FUNCTION_DELTA_REQUIRED')
    c.private(work, 'before.private.json', expected)
    for ordinal, change in enumerate(plan['changes']):
        binding_guard()
        need(admin.routes() == expected, 'ROUTES_CHANGED_BEFORE_WRITE')
        rid, desired = change['id'], change['desired']
        c.private(work, f'{ordinal:02d}-intent.private.json',
                  {'id': rid, 'beforeMapSha256': c.digest(expected), 'desiredSha256': c.digest(desired)})
        report['adminPutAttempts'] += 1
        report['runtimeChanged'] = None
        response = admin.put(rid, desired)
        c.private(work, f'{ordinal:02d}-ack.private.json', response)
        need(response['httpStatus'] in (200, 201), 'ADMIN_PUT_NOT_ACKNOWLEDGED')
        expected[rid] = desired
        need(admin.routes() == expected, 'ROUTE_WRITE_READBACK_MISMATCH')
        c.private(work, f'{ordinal:02d}-verified.private.json', {'mapSha256': c.digest(expected)})
        report['routeWritesVerified'] += 1
        report['runtimeChanged'] = True
    need(len(expected) == len(plan['before']), 'FINAL_ROUTE_COUNT_MISMATCH')
    admin.guard()
    report.update(finalRouteCount=len(expected), unchangedRoutesVerified=len(expected) - 2)


def arguments(c, argv):
    p = c.JsonParser(description=__doc__, add_help=False, allow_abbrev=False)
    p.add_argument('--applied-plan', type=Path, required=True)
    p.add_argument('--applied-plan-sha256', required=True)
    p.add_argument('--ingestion-receipt-key-env', required=True)
    extra, rest = p.parse_known_args(argv)
    args = c.arguments(rest)
    need(re.fullmatch(r'[a-f0-9]{64}', extra.applied_plan_sha256), 'APPLIED_PLAN_HASH_REQUIRED')
    need(re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', extra.ingestion_receipt_key_env),
         'INVALID_INGESTION_RECEIPT_KEY_ENV')
    vars(args).update(vars(extra))
    return args


def main(argv=None):
    report = {'status': 'HELD', 'reason': 'NOT_STARTED', 'adminGetAttempts': 0,
              'adminPutAttempts': 0, 'routeWritesVerified': 0, 'runtimeChanged': False,
              'adminCredentialConfigurationsRead': 0, 'externalAdminKeyFilesRead': 0}
    try:
        c = load_controller()
        args = arguments(c, argv)
        need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        private_directory(args.evidence_root)
        applied = read_applied_plan(c, args.applied_plan, args.evidence_root, args.applied_plan_sha256)
        a = c.load_assets()
        bindings = c.parse_bindings(args.service_binding, a)
        work = c.begin_attempt(args.evidence_root, args.plan_sha256) if args.apply else None
        if work is not None:
            report['privateEvidenceDirectory'] = str(work)
            c.private(work, 'attempt.private.json', {'approvedPlanSha256': args.plan_sha256})
        docker = c.Docker(args.docker_bin, args.docker_socket)
        admin = c.make_admin(args, report, docker)
        observation = c.observe_bindings(docker, admin.apisix, bindings)
        plan = compile_plan(c, admin.routes(), applied, args.applied_plan_sha256, a, bindings,
                            observation, args.ingestion_receipt_key_env, admin.apisix)
        plan['runtimeBinding'] = {'apisixFrameSha256': c.digest(admin.plan_frame()),
                                  'runtimePlanSha256': args.runtime_plan_sha256,
                                  'dockerSocket': args.docker_socket, 'dockerBinary': args.docker_bin,
                                  'configTarget': args.apisix_config_target,
                                  'adminKeyFile': str(args.admin_key_file)}
        report.update(public_plan(c, plan))
        if work is None:
            work = Path(tempfile.mkdtemp(prefix='plan-', dir=args.evidence_root))
            os.chmod(work, 0o700)
            c.fsync_dir(args.evidence_root)
        report['privateEvidenceDirectory'] = str(work)
        c.private(work, 'plan.private.json', plan)
        if args.apply:
            need(c.digest(plan) == args.plan_sha256, 'FRESH_PLAN_HASH_MISMATCH')
            def binding_guard():
                admin.guard()
                need(c.observe_bindings(docker, admin.apisix, bindings) == observation, 'SERVICE_BINDING_CHANGED')
                need(observe_env(c, docker.inspect(admin.apisix['Id']), args.ingestion_receipt_key_env) ==
                     plan['environmentObservation'], 'APISIX_ENV_NAMES_CHANGED')
            publish(c, plan, admin, work, report, binding_guard)
        report.update(status='INGESTION_RECEIPT_APPLIED' if args.apply else 'INGESTION_RECEIPT_PLANNED',
                      reason='TWO_ROUTE_READBACK_VERIFIED' if args.apply else 'HUMAN_HASH_APPROVAL_REQUIRED')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError,
            subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        safe = str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(status='HELD', reason=safe)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report['status'] != 'HELD' else 1


if __name__ == '__main__':
    sys.exit(main())
