#!/usr/bin/env python3
"""Installation-specific, fixed READ of the existing reviewed draft.

Fresh HUMAN owner admission brackets one native read-only SQL transaction.
The retained physical profile supplies transport, never historical authority.
There is no registration, CREATE, preview, publish, arbitrary SQL or retry port.
"""
import hashlib
from email.utils import parsedate_to_datetime
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

CONTEXT = '/home/oufadmin/ouf-acquisition-descriptor-publication-20261025'
ROOT = '/etc/ouf/deploy-snapshots/acquisition-existing-draft-lookup-5a31ae519ef9ee4e-v1'
PROFILE = '/etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6/current-onboarding-database-snapshot-v1/snapshot-inputs.json'
PROFILE_HASH = '000bf9de27a5a89d6132c2e594650282818957d322baa7b9166762fd0ac0eb0c'
LOGIN = '/usr/local/lib/ouf-acquisition-permission-descriptor-read-062b1e201904b9fd/read.py'
LOGIN_HASH = '062b1e201904b9fd7a10efcad371de17d4c0fbc3411710c310186aa7381c5cad'
REVIEW_HASH = '5a31ae519ef9ee4e14cf9258f91739ba27aa07a290f5f07b277cb8d3a44de911'
CANDIDATE_HASH = '027f626dce41cac0dc2d1dd9338bd2aeb20bc474a438e6e26a68d4214271b46b'
BASE_RESPONSE = '5de0b80b176ab6cbcb4b0e933d7408558731610c50521c466736d7464578ef70'
BASE_HASH = '6209fe7a832a4b92fcd543304a5480edb85f6f66dfe8476245075509e2c7f46b'
BASE_REF = 'ouf-lab-authorization:48'
SUBJECT = 'b93d8cf6-cd14-4ee6-91d7-84cd76c4f500'
TENANT = 'ouf-lab'
ADMIN = 'https://api.ouf-lab.it/api/trusted-human/v1/authorization'
CAPS = ('ingestion.contract.read', 'ingestion.lineage.read', 'urban.object.read',
        'lineage.object.read', 'lineage.property.read')
RETAINED_COUNTS = {'administrativeWrites': 6, 'ownerGets': 6, 'previewPosts': 0, 'bytes': 346780}
MAX_BYTES = 32*1024*1024


class Stop(Exception): pass


def require(value, reason):
    if not value: raise Stop(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value): return hashlib.sha256(encoded(value)).hexdigest()


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
                                             'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ancestry(path, owners=(0,)):
    require(Path(path).is_absolute(), 'ABSOLUTE_EXACT_PATH_REQUIRED')
    for parent in Path(path).parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in owners and not info.st_mode & 0o022,
                'PROTECTED_ANCESTRY_REQUIRED')


def read_file(path, owner, mode, maximum, expected=None):
    ancestry(path, (0, owner))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= maximum,
                'EXACT_PRIVATE_OR_PROTECTED_FILE_REQUIRED')
        parts = []
        remaining = info.st_size + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk: break
            parts.append(chunk); remaining -= len(chunk)
        raw = b''.join(parts)
        require(len(raw) == info.st_size and identity(info) == identity(os.fstat(fd)) == identity(os.lstat(path)),
                'RETAINED_FILE_CHANGED')
        require(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'EXACT_RETAINED_FILE_HASH_REQUIRED')
        return raw
    finally:
        os.close(fd)


class Journal:
    def __init__(self, root=ROOT):
        self.root = Path(root)
        ancestry(self.root)
        try: os.mkdir(self.root, 0o700)
        except FileExistsError: raise Stop('LOOKUP_SCOPE_CONSUMED_NO_REPLAY') from None
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fchmod(fd, 0o700); os.fsync(fd)
        finally: os.close(fd)
        self.sync(self.root.parent)
        self.row = {'schema': 'ouf.existing-descriptor-draft-lookup-journal.v1', 'state': 'CLAIMED',
                    'counts': dict(RETAINED_COUNTS), 'nativeSqlSessionAttempts': 0,
                    'containerExecAttempts': 0, 'engineGets': 0, 'iamCounts': {},
                    'budgetReset': False, 'automaticReplayAllowed': False}
        self.save()

    @staticmethod
    def sync(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)

    def write(self, name, value, *, exclusive=True):
        require(name in {'state.json', 'inputs.json', 'database-response.json', 'owner-draft-response.json',
                         'result.json', 'lookup-claim.json'}, 'EXACT_LOOKUP_ARTIFACT_REQUIRED')
        require(not exclusive or not os.path.lexists(self.root/name), 'LOOKUP_ARTIFACT_EXISTS')
        temporary = self.root/(name+'.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(encoded(value)); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, self.root/name)
        self.sync(self.root)

    def save(self): self.write('state.json', self.row, exclusive=False)

    def reserve(self, key, maximum):
        require(type(self.row[key]) is int and self.row[key] < maximum, 'FINITE_LOOKUP_BUDGET_EXHAUSTED')
        self.row[key] += 1
        self.save()


def retained(owner):
    info = os.lstat(CONTEXT)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and stat.S_IMODE(info.st_mode) == 0o700,
            'EXACT_ORIGINAL_CONTEXT_REQUIRED')
    review = json.loads(read_file(CONTEXT+'/review.json', owner, 0o600, 6*1024*1024))
    old = json.loads(read_file(CONTEXT+'/state.json', owner, 0o600, 131072))
    require(digest(review) == REVIEW_HASH and old.get('reviewHash') == REVIEW_HASH
            and old.get('humanReviewApproved') is True and old.get('state') == 'STOP_RECONCILE'
            and old.get('budgetReset') is False and old.get('automaticReplayAllowed') is False
            and old.get('counts') == RETAINED_COUNTS, 'EXACT_CONSUMED_REVIEW_AND_COUNTS_REQUIRED')
    candidate = review['candidatePolicy']
    require(digest(candidate) == CANDIDATE_HASH and candidate['version'] == 49
            and len(candidate['grants']) == review['baselineGrantCount'] == 106
            and digest(candidate['grants']) == review['baselineGrantsHash']
            and review['activatedDescriptorIds'] == list(CAPS), 'EXACT_APPROVED_CANDIDATE_REQUIRED')
    effects = old.get('effects', {})
    require(set(effects) == {'CREATE_DRAFT'} | {'REGISTER:'+cap for cap in CAPS}
            and effects['CREATE_DRAFT'] == {'state': 'CLAIMED', 'bodyHash': CANDIDATE_HASH}
            and all(effects['REGISTER:'+cap]['state'] == 'APPLIED' for cap in CAPS)
            and old.get('draftId') is None, 'EXACT_RETAINED_EFFECT_PREFIX_REQUIRED')
    return review, candidate


def identifier(value):
    require(isinstance(value, str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}', value), 'EXACT_DATABASE_IDENTIFIER_REQUIRED')
    return '"'+value+'"'


def profile(raw):
    bundle = json.loads(raw)
    require(bundle['schema'] == 'ouf.current-onboarding-database-private-snapshot.v1'
            and bundle['historicalAuthorityReused'] is False and bundle['targetApplyAuthorized'] is False,
            'RETAINED_PROFILE_IS_TRANSPORT_NOT_AUTHORITY')
    p = bundle['profile']
    require(p['schema'] == 'ouf.current-onboarding-database-snapshot-profile.v1'
            and p['runtimeBindingProfile'] == 'ouf.runtime-binding.native-mount-order.v1'
            and p['maximumSqlSessionAttempts'] == 1 and p['historicalAuthorityReused'] is False
            and p['migrationAuthorized'] is False, 'EXACT_RETAINED_NATIVE_PROFILE_REQUIRED')
    i = p['identity']
    for key in ('database', 'runtimeRole', 'adminRole'): identifier(i[key])
    require(i['schema'] == 'ouf_onboarding' and type(i['databaseOid']) is int and i['databaseOid'] > 0
            and type(i['postgresPort']) is int and 1 <= i['postgresPort'] <= 65535,
            'EXACT_RETAINED_DATABASE_IDENTITY_REQUIRED')
    require(re.fullmatch('[a-f0-9]{64}', p['postgresRuntimeBinding']['containerId'])
            and re.fullmatch('[a-f0-9]{64}', p['dockerExecutable']['sha256']), 'EXACT_NATIVE_PROGRAM_AND_CONTAINER_REQUIRED')
    for selected in [p['dockerExecutable']['path'], p['engineBinding']['socketPath'], p['unixSocketDirectory'],
                     *p['containerPrograms'].values()]:
        require(isinstance(selected, str) and selected.startswith('/') and '\x00' not in selected
                and '..' not in Path(selected).parts, 'EXACT_ABSOLUTE_NATIVE_BINDING_REQUIRED')
    return p


def query(p, candidate):
    # Only a hash-verified approved payload is encoded; the generated SQL has no selector port.
    require(digest(candidate) == CANDIDATE_HASH, 'EXACT_SQL_CANDIDATE_REQUIRED')
    payload = encoded(candidate).hex()
    return ("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
            "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s';\n"
            "SET LOCAL idle_in_transaction_session_timeout='5s'; SET LOCAL search_path=pg_catalog;\n"
            'SET LOCAL ROLE '+identifier(p['identity']['runtimeRole'])+';\n'+"""
WITH matches AS (
 SELECT d.draft_id,d.revision,d.state,d.base_active_ref,d.created_by,d.tenant_id,
  (SELECT count(*) FROM ouf_authorization.admin_audit a
    WHERE a.action='CREATE_DRAFT' AND a.target_ref=d.draft_id::text
    AND a.subject_id=d.created_by AND a.tenant_id=d.tenant_id
    AND a.actor_type='HUMAN') AS create_audit_count
 FROM ouf_authorization.policy_draft d
 WHERE d.created_by='"""+SUBJECT+"""' AND d.tenant_id='"""+TENANT+"""'
 AND d.base_active_ref='ouf-lab-authorization:48'
 AND d.payload=convert_from(decode('"""+payload+"""','hex'),'UTF8')::jsonb
 ORDER BY d.draft_id LIMIT 2
)
SELECT jsonb_build_object(
 'database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
 'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'postgresPort',current_setting('port')::integer,
 'activePolicy',(SELECT b.bundle_payload FROM ouf_authorization.active_policy_bundle a
    JOIN ouf_authorization.policy_bundle b USING(bundle_id,version) WHERE a.singleton_key=true),
 'matches',coalesce((SELECT jsonb_agg(jsonb_build_object('id',draft_id::text,'revision',revision,
    'state',state,'baseActiveRef',base_active_ref,'creator',created_by,'tenant',tenant_id,
    'createAuditCount',create_audit_count) ORDER BY draft_id) FROM matches),'[]'::jsonb));
ROLLBACK;
""")


def arguments(p, config):
    i, c = p['identity'], p['containerPrograms']
    return [p['dockerExecutable']['path'], '--host', 'unix://'+p['engineBinding']['socketPath'], '--config', str(config),
            'exec', '-i', p['postgresRuntimeBinding']['containerId'], c['env'], '-i', 'LC_ALL=C',
            'PGPASSFILE=/dev/null', 'PGSERVICEFILE=/dev/null', 'PGSYSCONFDIR=/nonexistent',
            'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000',
            c['timeout'], '-s', 'KILL', '15', c['psql'], '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
            '-v', 'VERBOSITY=sqlstate', '-h', p['unixSocketDirectory'], '-p', str(i['postgresPort']),
            '-U', i['adminRole'], '-d', i['database']]


def bounded_read(argv, sql):
    raw = sql.encode()
    require(0 < len(raw) <= 12*1024*1024, 'FINITE_FIXED_SQL_REQUIRED')
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={'LC_ALL': 'C'}, start_new_session=True)
    out, err, offset, deadline = bytearray(), bytearray(), 0, time.monotonic()+20
    try:
        with selectors.DefaultSelector() as watch:
            watch.register(proc.stdin, selectors.EVENT_WRITE, 'in')
            watch.register(proc.stdout, selectors.EVENT_READ, 'out')
            watch.register(proc.stderr, selectors.EVENT_READ, 'err')
            while watch.get_map():
                require(time.monotonic() < deadline, 'FINITE_NATIVE_SQL_TIMEOUT')
                for key, _ in watch.select(min(.2, max(0, deadline-time.monotonic()))):
                    if key.data == 'in':
                        try: offset += os.write(key.fd, raw[offset:offset+4096])
                        except BrokenPipeError: offset = len(raw)
                        if offset == len(raw): watch.unregister(key.fileobj); proc.stdin.close()
                        continue
                    block = os.read(key.fd, 65536)
                    if not block: watch.unregister(key.fileobj); continue
                    selected, maximum = (out, 6*1024*1024) if key.data == 'out' else (err, 65536)
                    require(len(selected)+len(block) <= maximum, 'BOUNDED_NATIVE_SQL_RESPONSE_REQUIRED')
                    selected.extend(block)
        status = proc.wait(timeout=max(.01, deadline-time.monotonic()))
        try:
            require(status == 0 and not err and out, 'NATIVE_SQL_UNPROVEN_NO_REPLAY')
            return json.loads(out)
        except Exception:
            failure = Stop('NATIVE_SQL_UNPROVEN_NO_REPLAY')
            failure.native_evidence = {'exitStatus':status, 'stdoutUtf8':out.decode('utf-8',errors='replace'),
                                       'stderrUtf8':err.decode('utf-8',errors='replace')}
            raise failure from None
    finally:
        if proc.poll() is None: os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        for pipe in (proc.stdin, proc.stdout, proc.stderr): pipe.close()


def socket_check(p):
    selected = p['engineBinding']
    # /var/run is commonly a root-owned alias of /run. The exact pinned socket
    # inode/custody still has to match, and its resolved directory is protected.
    ancestry(Path(selected['socketPath']).resolve())
    info = os.lstat(selected['socketPath'])
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
            and [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)] == selected['socketBinding'],
            'EXACT_RETAINED_ENGINE_SOCKET_REQUIRED')


def current_postgres(p, journal):
    socket_check(p)
    selected = p['engineBinding']['socketPath']
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout); self.sock.connect(selected)
    journal.reserve('engineGets', 2)
    connection = Local('localhost', timeout=15)
    try:
        connection.request('GET', '/v1.44/containers/'+p['postgresRuntimeBinding']['containerId']+'/json')
        response = connection.getresponse(); raw = response.read(2097153)
        require(response.status == 200 and len(raw) <= 2097152, 'EXACT_POSTGRES_INSPECTION_REQUIRED')
        actual = json.loads(raw)
    finally: connection.close()
    socket_check(p)
    # Binding digest intentionally uses the qualified native engine encoding (ASCII escaped).
    engine_digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    binding = {'containerId': actual['Id'], 'imageId': actual['Image'], 'pid': actual['State']['Pid'],
               'startedAt': actual['State']['StartedAt'], 'configHash': engine_digest(actual['Config']),
               'hostConfigHash': engine_digest(actual['HostConfig']), 'mountsHash': engine_digest(actual['Mounts']),
               'networkSettingsHash': engine_digest(actual['NetworkSettings'])}
    require(binding == p['postgresRuntimeBinding'] and actual['State']['Running'] is True
            and actual['State']['Paused'] is False, 'POSTGRES_GENERATION_DRIFT_NO_REPLAY')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): raise Stop('OWNER_REDIRECT_DENIED')


class Owner:
    def __init__(self, token, journal, *, clock=time.monotonic, sleep=time.sleep, wall=time.time):
        self.token, self.journal = token, journal
        self.draft_id = None
        self.clock, self.sleep, self.wall = clock, sleep, wall
        self.deadline = clock()+90
        self.stages = 0
        self.opener = urllib.request.build_opener(NoRedirect())

    def get(self, path):
        require(path == '/policies/active' or self.draft_id is not None and path == '/policies/'+self.draft_id,
                'ONLY_ACTIVE_AND_EXACT_EXISTING_DRAFT_GET_ALLOWED')
        require(self.stages < 3, 'ONLY_THREE_OWNER_LOOKUP_STAGES')
        self.stages += 1
        for attempt in range(1, 9):
            require(self.clock() < self.deadline, 'FINITE_OWNER_LOOKUP_EXPIRED')
            self.journal.row['readProgress'] = {'stage': self.stages, 'attempt': attempt, 'state': 'ATTEMPTING'}
            self.journal.save()
            try:
                return self.once(path)
            except urllib.error.HTTPError as error:
                require(error.code in (408, 429, 502, 503, 504), 'OWNER_GET_PERMANENT_DENIAL_NO_RETRY')
                value = error.headers.get('Retry-After')
                try:
                    retry_after = 0 if value is None else float(value) if value.isdigit() else parsedate_to_datetime(value).timestamp()-self.wall()
                    require(0 <= retry_after < 86400, 'INVALID_OWNER_RETRY_AFTER')
                except (ValueError, TypeError, OverflowError): raise Stop('INVALID_OWNER_RETRY_AFTER') from None
            except (TimeoutError, ConnectionError):
                retry_after = 0
            except urllib.error.URLError as error:
                require(isinstance(error.reason, (TimeoutError, ConnectionError)), 'OWNER_GET_UNKNOWN_TRANSPORT_NO_RETRY')
                retry_after = 0
            jitter = int(digest({'stage': self.stages, 'attempt': attempt})[:8], 16)/0xffffffff
            delay = max(retry_after, (5, 15, 60, 300, 900)[min(attempt-1, 4)]*(1+.2*jitter))
            require(attempt < 8 and self.clock()+delay < self.deadline, 'FINITE_OWNER_READ_RETRY_EXHAUSTED')
            due = self.clock()+delay
            self.journal.row['readProgress'].update(state='RETRY_WAIT', nextRetryAt=self.wall()+delay)
            self.journal.save()
            while self.clock() < due: self.sleep(min(1, due-self.clock()))
        raise Stop('FINITE_OWNER_READ_RETRY_EXHAUSTED')

    def once(self, path):
        counts = self.journal.row['counts']
        require(counts['ownerGets'] < 30, 'FINITE_CUMULATIVE_OWNER_GET_LIMIT')
        counts['ownerGets'] += 1; self.journal.save()
        request = urllib.request.Request(ADMIN+path, method='GET',
                                        headers={'Authorization': 'Bearer '+self.token, 'Accept': 'application/json'})
        reply = self.opener.open(request, timeout=min(15, max(.1,self.deadline-self.clock())))
        with reply:
            raw = reply.read(5*1024*1024+1)
            # Persist the returned UUID-bearing response before all shape/JSON guards.
            if self.draft_id is not None and path == '/policies/'+self.draft_id:
                self.journal.write('owner-draft-response.json', {'status': reply.code,
                    'etag': reply.headers.get('ETag'), 'bodyUtf8': raw.decode('utf-8', errors='replace')})
            counts['bytes'] += len(raw); self.journal.save()
            require(reply.geturl() == ADMIN+path and reply.code == 200 and len(raw) <= 5*1024*1024
                    and counts['bytes'] <= MAX_BYTES, 'FINITE_EXACT_OWNER_RESPONSE_REQUIRED')
            return json.loads(raw), reply.headers.get('ETag')


def active(value):
    require(value.get('policyRef') == BASE_REF and value.get('contentHash', '').removeprefix('sha256:') == BASE_HASH
            and digest(value) == BASE_RESPONSE, 'EXACT_CURRENT_OWNER_BASE_REQUIRED')
    return value['policy']


def select_match(report, p, before):
    i = p['identity']
    require(report['database'] == i['database'] and report['databaseOid'] == i['databaseOid']
            and report['postgresPort'] == i['postgresPort'] and report['role'] == i['runtimeRole']
            and report['transactionReadOnly'] is True and report['activePolicy'] == before,
            'CURRENT_DATABASE_AND_OWNER_POLICY_MUST_MATCH')
    rows = report.get('matches')
    require(isinstance(rows, list) and len(rows) == 1, 'EXACTLY_ONE_EXISTING_DRAFT_REQUIRED_NO_CREATE')
    row = rows[0]
    require(isinstance(row.get('id'), str) and str(uuid.UUID(row['id'])) == row['id'], 'OWNER_DRAFT_UUID_REQUIRED')
    return row


def validate_draft(value, selected, candidate, etag):
    require(selected['creator'] == SUBJECT and selected['tenant'] == TENANT and selected['createAuditCount'] == 1
            and selected['baseActiveRef'] == BASE_REF and selected['state'] == 'DRAFT'
            and type(selected['revision']) is int and selected['revision'] == 0,
            'EXACT_EXISTING_UNEDITED_OWNER_DRAFT_REQUIRED')
    require(value == {'id': selected['id'], 'revision': 0, 'state': 'DRAFT', 'baseActiveRef': BASE_REF, 'policy': candidate}
            and etag == '"0"', 'EXACT_OWNER_DRAFT_AND_ZERO_ETAG_REQUIRED')


def observe(journal, candidate, p, owner, native=bounded_read, inspect=current_postgres):
    before, _ = owner.get('/policies/active')
    policy = active(before)  # Owner verifies the real JWT and current HUMAN admin permission.
    inspect(p, journal)
    config = journal.root/'empty-docker-config'
    os.mkdir(config, 0o700)
    require(not os.listdir(config), 'EMPTY_DOCKER_CONFIG_REQUIRED')
    sql = query(p, candidate)
    journal.write('lookup-claim.json', {'reviewHash': REVIEW_HASH, 'candidateHash': CANDIDATE_HASH,
        'profileHash': PROFILE_HASH, 'queryHash': hashlib.sha256(sql.encode()).hexdigest(),
        'maximumSqlSessionAttempts': 1, 'maximumMatchingRows': 2, 'writesAllowed': False,
        'historicalAuthorityReused': False, 'automaticReplayAllowed': False})
    journal.reserve('nativeSqlSessionAttempts', 1)
    journal.reserve('containerExecAttempts', 1)
    try:
        report = native(arguments(p, config), sql)
    except Stop as error:
        if hasattr(error, 'native_evidence'): journal.write('database-response.json', error.native_evidence)
        raise
    journal.write('database-response.json', report)  # UUID retained BEFORE selection/guards.
    inspect(p, journal)
    require(not os.listdir(config), 'EMPTY_DOCKER_CONFIG_CHANGED')
    after, _ = owner.get('/policies/active')
    require(after == before, 'OWNER_ACTIVE_CHANGED_DURING_NATIVE_LOOKUP')
    active(after)
    selected = select_match(report, p, policy)
    journal.row.update(draftId=selected['id'], databaseMatchRetained=True); journal.save()
    owner.draft_id = selected['id']
    value, etag = owner.get('/policies/'+selected['id'])
    validate_draft(value, selected, candidate, etag)
    result = {'schema': 'ouf.existing-descriptor-draft-lookup-result.v1',
        'status': 'EXISTING_DESCRIPTOR_DRAFT_OWNER_CONFIRMED_NO_PUBLICATION', 'complete': True,
        'draftId': selected['id'], 'draftRevision': 0, 'basePolicyRef': BASE_REF,
        'reviewHash': REVIEW_HASH, 'candidatePolicyHash': CANDIDATE_HASH, 'candidateGrantCount': 106,
        'counts': dict(journal.row['counts']), 'nativeSqlSessionAttempts': journal.row['nativeSqlSessionAttempts'],
        'containerExecAttempts': journal.row['containerExecAttempts'], 'engineGets': journal.row['engineGets'],
        'iamCounts': journal.row['iamCounts'], 'newAdministrativeWrites': 0,
        'registrationsRepeated': 0, 'draftsCreated': 0, 'publishRequests': 0, 'previews': 0,
        'serviceCredentialFilesRead': 0, 'installationSigningKeysRead': False,
        'historicalAuthorityReused': False, 'runtimeAuthorityIssued': False, 'continuationAuthorized': False,
        'budgetReset': False, 'automaticReplayAllowed': False, 'sourceActivations': 0,
        'acquisitionsExecuted': 0, 'registryWorkerTouched': False,
        'applicationE2EProven': False, 'releaseAcceptance': False, 'contextPath': str(journal.root)}
    journal.write('result.json', result)
    journal.row['state'] = 'COMPLETE'; journal.save()
    return result


def main():
    journal = None
    try:
        require(os.geteuid() == os.getegid() == 0 and len(sys.argv) == 1 and sys.stdin.isatty()
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'EXACT_ISOLATED_ROOT_INTERACTIVE_LOOKUP_REQUIRED')
        operator = pwd.getpwnam('oufadmin').pw_uid
        require(operator > 0 and os.environ.get('SUDO_UID') == str(operator), 'EXACT_OUFADMIN_SUDO_CONTEXT_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('FINITE_LOOKUP_WINDOW_EXPIRED')))
        signal.alarm(720)
        journal = Journal()
        print('PrivateContext='+str(journal.root), flush=True)
        review, candidate = retained(operator)
        raw = read_file(PROFILE, 0, 0o400, 2*1024*1024, PROFILE_HASH)
        selected = profile(raw)
        program = selected['dockerExecutable']['path']
        info = os.lstat(program)
        require(stat.S_IMODE(info.st_mode) in (0o755, 0o555), 'PROTECTED_DOCKER_PROGRAM_REQUIRED')
        read_file(program, 0, stat.S_IMODE(info.st_mode), 64*1024*1024, selected['dockerExecutable']['sha256'])
        raw_login = read_file(LOGIN, 0, 0o444, 32768, LOGIN_HASH)
        journal.write('inputs.json', {'review': review, 'transportProfile': selected,
                                      'retainedCounts': RETAINED_COUNTS, 'historicalAuthorityReused': False})
        namespace = {'__name__': 'qualified_login_definitions_only', '__file__': LOGIN}
        exec(compile(raw_login, LOGIN, 'exec'), namespace)
        def reserve(counts):
            journal.row['iamCounts'] = dict(counts); journal.save()
        iam = namespace['Transport'](reserve=reserve)
        token = namespace['login'](iam)
        signal.alarm(90)
        result = observe(journal, candidate, selected, Owner(token, journal))
    except Exception as error:
        reason = str(error) if type(error).__name__ == 'Stop' and re.fullmatch('[A-Z0-9_]{1,120}', str(error)) else 'LOOKUP_UNPROVEN_RECONCILE_NO_REPLAY'
        result = {'schema': 'ouf.existing-descriptor-draft-lookup-result.v1', 'status': 'STOP_RECONCILE',
                  'complete': False, 'reasonCode': reason, 'continuationAuthorized': False,
                  'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'budgetReset': False,
                  'newAdministrativeWrites': 0, 'publishRequests': 0, 'applicationE2EProven': False,
                  'releaseAcceptance': False}
        if journal is not None:
            journal.row.update(state='STOP_RECONCILE', reasonCode=reason); journal.save()
            result.update(counts=journal.row['counts'], nativeSqlSessionAttempts=journal.row['nativeSqlSessionAttempts'],
                          containerExecAttempts=journal.row['containerExecAttempts'], engineGets=journal.row['engineGets'],
                          contextPath=str(journal.root))
            journal.write('result.json', result)
    finally:
        signal.alarm(0)
    print(encoded(result).decode(), flush=True)
    return 0 if result.get('complete') else 2


if __name__ == '__main__': raise SystemExit(main())
