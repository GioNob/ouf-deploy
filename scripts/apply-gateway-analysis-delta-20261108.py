#!/usr/bin/env python3
"""Apply exactly the prepared eight-route delta and read Semantic metadata.

No container replacement, SQL write, token request or provider activation.
One attempt directory; interrupted/uncertain writes require reconciliation.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path('/var/lib/ouf-storage-migration')
PROPOSAL = ROOT / 'gateway-analysis-proposal-9rj147d5/proposal.private.json'
PROPOSAL_SHA = '2876c0c3a892f0dce8accb08f5cbac523cfc541c43a264dfcb5944cd003c8f19'
WORK = ROOT / ('gateway-analysis-apply-' + PROPOSAL_SHA[:16])
HELPER = 'read-discovery-contract-20261108.py'
HELPER_SHA = '468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277'
DESIRED = [
    'fb39113031c41b3773a6ed525d8fb0c24ab9686994802091e15d6fa49b5c40e8',
    '48229254f6b019a6a49abaf5728f5f59bcf77ab7f9ff1159d3df55fd3dbb92d6',
    '48e1134462bd05feb4658bcba7315da5370d551b62790443cda7bf63dbf0bf69',
    'c7ec69f67c7753c4f246a75c78785a9512f0977f8b01f51d8bff1155f0737325',
    '86015e6bd9a1359ab960922751ec0d55805f8ac6b047709c9dca3b96a223abfc',
    '04098beeb098a2730e46d2b1a64ee8d0c8145666e550dcb3b7b2c9b1aa612efe',
    '226e556614b30476041a95155f640c7b70656b2e521778128a1270ab1094e596',
    'f8a112f06b0cf42d3306f36bc172ba62e4db0267f3e4985c770a2e77b0d6c466',
]


def need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def digest(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()).hexdigest()


def reason(exc):
    return str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__


def helpers():
    path = Path(__file__).with_name(HELPER)
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == HELPER_SHA, 'HELPER_HASH_MISMATCH')
    spec = importlib.util.spec_from_file_location('contract_reader', path)
    c = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), c.__dict__)
    return c, c.helper()


def private(work, name, value):
    raw = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()
    fd = os.open(work / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def body(row):
    # APISIX owns these timestamps. All other fields remain exact, including id,
    # numeric contract bounds, plugins, credentials and upstream configuration.
    return {k: v for k, v in row.items() if k not in ('create_time', 'update_time')}


def route_map(data):
    need(type(data.get('list')) is list and data.get('total') == len(data['list']) <= 87,
         'COMPLETE_BOUNDED_ROUTE_LIST_REQUIRED')
    result = {}
    for entry in data['list']:
        row = entry.get('value', entry)
        if isinstance(row.get('value'), dict):
            row = row['value']
        identifier = str(row.get('id', ''))
        need(re.fullmatch('[A-Za-z0-9_.-]{1,128}', identifier) and identifier not in result,
             'UNIQUE_ROUTE_IDENTIFIER_REQUIRED')
        result[identifier] = body(row)
    return result


def validate_plan(plan):
    need(digest(plan) == PROPOSAL_SHA, 'EXACT_PREPARED_PROPOSAL_REQUIRED')
    changes = plan['changes']
    need(len(changes) == 8 and [digest(c['desired']) for c in changes] == DESIRED,
         'EXACT_EIGHT_DESIRED_ROUTES_REQUIRED')
    need([c['operation'] for c in changes] == ['UPDATE'] * 5 + ['ADD'] * 3 and
         len(plan['unchangedRoutes']) == 79, 'EXACT_EIGHT_ROUTE_OPERATIONS_REQUIRED')
    rows = plan['unchangedRoutes'] + [c['before'] for c in changes[:5]]
    expected = route_map({'list': rows, 'total': len(rows)})
    need(len(expected) == 84, 'EXACT_SOURCE_ROUTE_COUNT_REQUIRED')
    for change in changes:
        rid = str(change['routeId'])
        need(str(change['desired']['id']) == rid and change['desired']['uri'] == change['uri'],
             'EXACT_ROUTE_TARGET_REQUIRED')
        if change['operation'] == 'ADD':
            need(rid not in expected, 'ADDITION_ALREADY_PRESENT')
    return expected


ADMIN_CHILD = r'''import http.client,json,sys
data=json.loads(sys.stdin.buffer.read(1048577))
method,path=data['method'],data['path']
if not ((method=='GET' and path=='/apisix/admin/routes') or
        (method=='PUT' and path.startswith('/apisix/admin/routes/'))):raise RuntimeError()
connection=http.client.HTTPConnection('127.0.0.1',9180,timeout=8)
try:
    payload=None if method=='GET' else json.dumps(data['body'],allow_nan=False).encode()
    connection.request(method,path,body=payload,headers={'X-API-KEY':data['key'],'Content-Type':'application/json'})
    reply=connection.getresponse();raw=reply.read(8388609)
    if len(raw)>8388608:raise RuntimeError()
    print(json.dumps({'httpStatus':reply.status,'body':json.loads(raw)}))
finally:connection.close()
'''


class Admin:
    def __init__(self, c, h, apisix, report):
        self.c, self.h, self.apisix, self.report = c, h, apisix, report
        self.guard()
        raw, meta = c.mount_file(apisix, c.CONFIG_TARGET, True)
        need(raw is not None and meta['sameAsHostSource'], 'CURRENT_ADMIN_MOUNT_REQUIRED')
        self.config = raw
        report['adminCredentialConfigurationsRead'] += 1
        self.key = c.selected_key(raw, h, report)

    def guard(self):
        need(self.h.frame(self.h.inspect(self.apisix['Id'])) == self.h.frame(self.apisix),
             'APISIX_RUNTIME_CHANGED')

    def request(self, method, path, value=None):
        self.guard()
        raw, meta = self.c.mount_file(self.apisix, self.c.CONFIG_TARGET, True)
        need(raw == self.config and meta['sameAsHostSource'], 'ADMIN_CONFIG_CHANGED')
        run = subprocess.run(('/usr/bin/nsenter', '--target', str(self.apisix['State']['Pid']), '--net',
                              sys.executable, '-I', '-B', '-S', '-c', ADMIN_CHILD),
                             input=json.dumps({'key': self.key, 'method': method, 'path': path, 'body': value}).encode(),
                             capture_output=True, timeout=12)
        need(run.returncode == 0 and len(run.stdout) <= 12 * 1024 * 1024, 'ADMIN_RESPONSE_UNPROVEN')
        return self.h.parse(run.stdout)

    def routes(self):
        self.report['adminGetAttempts'] += 1
        response = self.request('GET', '/apisix/admin/routes')
        need(response['httpStatus'] == 200, 'ADMIN_GET_FAILED')
        return route_map(response['body'])

    def put(self, rid, value):
        need(re.fullmatch('[A-Za-z0-9_.-]{1,128}', rid), 'EXACT_ROUTE_IDENTIFIER_REQUIRED')
        return self.request('PUT', '/apisix/admin/routes/' + rid, value)


def publish(plan, expected, admin, work, report):
    observed = admin.routes()
    need(observed == expected, 'CURRENT_ROUTES_DIFFER_FROM_PREPARED_BASELINE')
    private(work, 'before.private.json', observed)
    for ordinal, change in enumerate(plan['changes']):
        # This detects drift before/after each write. The Admin API does not
        # provide a transaction across all routes; do not claim atomic CAS.
        need(admin.routes() == expected, 'ROUTES_CHANGED_BEFORE_WRITE')
        rid, desired = str(change['routeId']), body(change['desired'])
        private(work, f'{ordinal:02d}-intent.json', {'routeId': rid, 'desiredSha256': digest(desired),
                                                   'previousMapSha256': digest(expected)})
        report['adminPutAttempts'] += 1
        report['runtimeChanged'] = None  # dispatched outcome may be unknown
        response = admin.put(rid, desired)
        private(work, f'{ordinal:02d}-ack.private.json', response)
        need(response['httpStatus'] in (200, 201), 'ADMIN_PUT_NOT_ACKNOWLEDGED')
        expected = {**expected, rid: desired}
        need(admin.routes() == expected, 'ROUTE_WRITE_READBACK_MISMATCH')
        private(work, f'{ordinal:02d}-verified.json', {'routeId': rid, 'resultMapSha256': digest(expected)})
        report['routeWritesVerified'] += 1
        report['runtimeChanged'] = True
    need(len(expected) == 87, 'FINAL_ROUTE_COUNT_MISMATCH')
    admin.guard()
    report.update(gatewayStatus='GATEWAY_EIGHT_ROUTES_APPLIED_VERIFIED', finalRouteCount=87,
                  unchangedRoutesVerified=79, updatedRoutesVerified=5, addedRoutesVerified=3)


SEMANTIC_QUERY = """BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s';
SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='ouf_sem.discovery_request'::regclass
 AND attname='recovery_state' AND attnum>0 AND NOT attisdropped)
 THEN 'recovery_state' ELSE 'NULL::text' END AS recovery_expression \\gset
SELECT json_build_object(
 'readOnly',current_setting('transaction_read_only')='on',
 'databaseOid',(SELECT oid FROM pg_database WHERE datname=current_database()),
 'migrations',(SELECT coalesce(json_agg(json_build_object('version',version,'checksum',checksum,'success',success) ORDER BY installed_rank),'[]'::json) FROM ouf_sem.flyway_schema_history),
 'recoveryColumnPresent',EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='ouf_sem.discovery_request'::regclass AND attname='recovery_state' AND attnum>0 AND NOT attisdropped),
 'discoveryStates',(SELECT coalesce(json_agg(x),'[]'::json) FROM (
   SELECT state,:recovery_expression AS recovery_state,count(*) AS count
   FROM ouf_sem.discovery_request GROUP BY state,:recovery_expression
   ORDER BY state,:recovery_expression) x));
ROLLBACK;
"""


def semantic_read(c, h, semantic, postgres, work, report):
    user, name = c.db_binding(semantic, postgres, 'semantic', h)
    report['readOnlyDatabaseSessionsAttempted'] += 1
    run = subprocess.run((*c.DOCKER, 'exec', '-i', '-e', 'PGOPTIONS=-c default_transaction_read_only=on',
                          '-e', 'PGAPPNAME=ouf-semantic-recovery-metadata-read', postgres['Id'],
                          'psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
                          '-h', '/var/run/postgresql', '-U', user, '-d', name),
                         input=SEMANTIC_QUERY.encode(), capture_output=True, timeout=12)
    c.save_private(work, 'semantic-database.stderr.private', run.stderr[:65536])
    need(run.returncode == 0 and len(run.stdout) <= 131072, 'SEMANTIC_METADATA_READ_FAILED')
    value = h.parse(run.stdout)
    need(value['readOnly'] is True and type(value['recoveryColumnPresent']) is bool and
         isinstance(value['migrations'], list) and len(value['migrations']) <= 256,
         'BOUNDED_READ_ONLY_DATABASE_RESULT_REQUIRED')
    allowed = {'ACTIVE', 'RETRY_WAIT', 'PAUSED_EXHAUSTED', 'BLOCKED', 'CANCELLED'}
    need(all(x['state'] in {'PENDING','RUNNING','SUCCEEDED','FAILED','CANCELLED'} and
             (x['recovery_state'] is None or x['recovery_state'] in allowed) and
             type(x['count']) is int and x['count'] >= 0 for x in value['discoveryStates']),
         'UNEXPECTED_DISCOVERY_STATE')
    need(h.frame(h.inspect(semantic['Id'])) == h.frame(semantic) and
         h.frame(h.inspect(postgres['Id'])) == h.frame(postgres), 'DATABASE_BINDING_CHANGED')
    private(work, 'semantic-metadata.private.json', value)
    value.update(status='SEMANTIC_METADATA_READ', identifiersOrIntentsRead=False,
                 v12RecordedSuccessful=any(str(row['version']) == '12' and row['success'] is True for row in value['migrations']),
                 sourceV12IntroducesRecoveryState=True, migrationAppliedByScript=False)
    return value


def main():
    report = {'schema': 'ouf.gateway-analysis-apply.v1', 'status': 'INCOMPLETE',
              'gatewayStatus': 'NOT_ATTEMPTED', 'runtimeChanged': False,
              'adminGetAttempts': 0, 'adminPutAttempts': 0, 'routeWritesVerified': 0,
              'adminCredentialConfigurationsRead': 0, 'externalAdminKeyFilesRead': 0,
              'readOnlyDatabaseSessionsAttempted': 0, 'databaseWrites': 0,
              'containerConfigurationChanged': False, 'serviceStops': 0, 'gatewayOwnerReplaced': False,
              'providerEnableDispatched': False, 'providerRequests': 0, 'tokenRequests': 0,
              's3Requests': 0, 'businessRequestsIssued': 0, 'credentialValuesEmitted': False}
    try:
        need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        c, h = helpers()
        plan = h.parse(h.read(PROPOSAL, 8 * 1024 * 1024))
        expected = validate_plan(plan)
        # A pre-existing attempt is never resumed automatically, even if only
        # a preflight ran. No duplicate write, reset or rollback is implicit.
        WORK.mkdir(mode=0o700)
        report['privateEvidenceDirectory'] = str(WORK)
        private(WORK, 'attempt.json', {'proposalSha256': PROPOSAL_SHA})
        signal.signal(signal.SIGALRM, lambda *_: need(False, 'APPLY_DEADLINE'))
        signal.alarm(60 + 40 * len(plan['changes']))
        raw = h.read(h.PLAN, 1048576)
        need(hashlib.sha256(raw).hexdigest() == h.PLAN_SHA, 'RETAINED_PLAN_CHANGED')
        roles = h.parse(raw)['roles']
        docs = {name: h.inspect(roles[name]['containerId']) for name in ('apisix','semantic','postgres')}
        for name, doc in docs.items():
            need(doc['Image'] == roles[name]['nativeImage'] and doc['State']['Running'] and
                 not doc['State'].get('Paused') and not doc['State'].get('Restarting'), 'EXPECTED_RUNNING_IMAGE_REQUIRED')
            if name in c.FRAME_PINS:
                need(h.digest(h.frame(doc)) == c.FRAME_PINS[name], 'CURRENT_RUNTIME_FRAME_CHANGED')
        try:
            report['semanticDatabase'] = semantic_read(c, h, docs['semantic'], docs['postgres'], WORK, report)
        except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as exc:
            report['semanticDatabase'] = {'status': 'READ_INCOMPLETE', 'reason': reason(exc)}
        admin = Admin(c, h, docs['apisix'], report)
        publish(plan, expected, admin, WORK, report)
        report['status'] = ('GATEWAY_APPLIED_SEMANTIC_METADATA_READ' if
                            report['semanticDatabase']['status'] == 'SEMANTIC_METADATA_READ' else
                            'GATEWAY_APPLIED_SEMANTIC_READ_INCOMPLETE')
    except FileExistsError:
        report.update(status='HELD', reason='PREVIOUS_ATTEMPT_EXISTS_DO_NOT_REPLAY',
                      privateEvidenceDirectory=str(WORK))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        report.update(status='HELD', reason=reason(exc))
    finally:
        signal.alarm(0)
    report['observedAt'] = datetime.now(timezone.utc).isoformat()
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
