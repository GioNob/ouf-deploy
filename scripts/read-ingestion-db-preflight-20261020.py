"""Finite native Ingestion DB preflight; no retained source execution or mutation.

Private retained bindings, four Docker GETs and one fixed read-only SQL session.
No OAuth, owner/Gateway API, migration, privilege change, login or runtime authority.
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
import selectors
import subprocess
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


INPUT = Path('/etc/ouf/deploy-snapshots/ingestion-read-owner-inputs-z048j_zr')
INPUT_HASH = '7b5d811ba31ab5899f969759eb5140c586785b1a17bdfe9287b6666ba788b314'
MANIFEST = json.loads('{"imageId":"sha256:51a514d8e07ad7448f98a3886e0c9c6d5b50829f85d320785038a2c76eae46f3","migrationCount":18,"migrations":[{"checksum":28809713,"resourceSha256":"8b439684da2cc31c62cfebf4ce4d939f9c8ac9b533a8c9490f5455384c064bb8","script":"V1__ingestion_runtime_core.sql","success":true,"type":"SQL","version":"1"},{"checksum":-1190230229,"resourceSha256":"5e3b53341e396f7bf4ba937db2c61e96e9fdedac6420eb0de15350457ee6c528","script":"V2__durable_ack_and_replay.sql","success":true,"type":"SQL","version":"2"},{"checksum":1677862093,"resourceSha256":"a6e9eb043defdcd8590b94c690911955ec8957ba016b70967e9aef90943bedf4","script":"V3__trusted_operations.sql","success":true,"type":"SQL","version":"3"},{"checksum":960152441,"resourceSha256":"b112711bd994cff5b0bdd3671937754f6e33fd85a705a102eed23fe9f207b44c","script":"V4__scheduler_and_source_health.sql","success":true,"type":"SQL","version":"4"},{"checksum":-2033393121,"resourceSha256":"4e24738272c8fae7233d2601736662eff80d5913fbef6c88ab6dc1f511f65763","script":"V5__replay_execution_lifecycle.sql","success":true,"type":"SQL","version":"5"},{"checksum":-2023917644,"resourceSha256":"5bf72f99f9c861678d3e8469ed2f71cd9cd55fccb835dbcd685e9c0d9fe6d46f","script":"V6__protected_operational_log.sql","success":true,"type":"SQL","version":"6"},{"checksum":-848911848,"resourceSha256":"48527993d3d8b50d98dc396e6d9b013410cd9db28d35fb76bff14cc23e46f9f2","script":"V7__execution_worker_and_snapshot.sql","success":true,"type":"SQL","version":"7"},{"checksum":-61585214,"resourceSha256":"33853cbd55d09ad901d4af6589ad36c1d4d6da1116f10a14bdb3bb2f0bd8332c","script":"V8__schema_surveillance.sql","success":true,"type":"SQL","version":"8"},{"checksum":-1413097987,"resourceSha256":"ed0236c8b6b6c66767813a0da7d3d92457ba0968c7e4376a35b0119f22a752d9","script":"V9__runtime_issue_governance.sql","success":true,"type":"SQL","version":"9"},{"checksum":1627974653,"resourceSha256":"41f8c2362122caa3e9e4d82df0588452a87efdde0f2c518ee47e1bd3570a03dc","script":"V10__quarantine_lifecycle.sql","success":true,"type":"SQL","version":"10"},{"checksum":-1835304128,"resourceSha256":"97243be62e65879aed425855895456ef0f9e1579cf0b271bcbfc2b0864069e17","script":"V11__classified_source_resilience.sql","success":true,"type":"SQL","version":"11"},{"checksum":-1198212964,"resourceSha256":"9fa09325985424125528420db82bce2c52f7ae75dffc7759207c7eb1666b5b2c","script":"V12__governed_lifecycle_and_historical_replay.sql","success":true,"type":"SQL","version":"12"},{"checksum":1850262212,"resourceSha256":"30402c3c225297436b9bc4e65dceca2c3ba29a3caeffc79692ea7cccf50a000d","script":"V13__pressure_admission_retry_budget.sql","success":true,"type":"SQL","version":"13"},{"checksum":-1324686996,"resourceSha256":"5d6acf3516504590fe84d833803db55b87b3858a35c31a88a56e3599ceba916d","script":"V14__published_activation_schedule.sql","success":true,"type":"SQL","version":"14"},{"checksum":-1837994869,"resourceSha256":"e9abf1e1c192be62a4624f8a7ba551be28013ab3a58698a4ad13231fba29abaa","script":"V15__human_recovery_sessions.sql","success":true,"type":"SQL","version":"15"},{"checksum":-405299983,"resourceSha256":"6fcf10b6bfbc8e71002fb9378e6a1ff45b70abb4a8f5cd863a1f207c42cb2eb9","script":"V16__incident_observation_time.sql","success":true,"type":"SQL","version":"16"},{"checksum":-1241321010,"resourceSha256":"3695a5853afac3923a3428a54739d55d09cf31cc147bf46bfab8505f1c2d0716","script":"V17__incident_publication_and_cursor.sql","success":true,"type":"SQL","version":"17"},{"checksum":1281376280,"resourceSha256":"7519073ac4075c40ed743489a2aefc7f63d8dcd3b1078e6108e50104f2fa8220","script":"V18__incident_publication_bookmarks.sql","success":true,"type":"SQL","version":"18"}],"schema":"ouf.ingestion-candidate-db-read-manifest.v1","sourceCommit":"663faa03288f9ad7775382b9757e44eaba4f51ca"}')
SQL = "-- Closed read-only native diagnostic. No application functions, locks or writes.\nBEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nSET LOCAL statement_timeout = '5s';\nSET LOCAL lock_timeout = '1s';\nSET LOCAL idle_in_transaction_session_timeout = '5s';\nSET LOCAL search_path = pg_catalog;\nSELECT jsonb_build_object(\n 'observedAtUnix',extract(epoch FROM transaction_timestamp())::bigint,\n 'database',current_database(),'role',current_user,\n 'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),\n 'readOnly',current_setting('transaction_read_only')='on',\n 'serverVersionNum',current_setting('server_version_num')::integer,\n 'encoding',current_setting('server_encoding'),\n 'allowConnections',(SELECT datallowconn FROM pg_database WHERE datname=current_database()),\n 'preparedTransactions',(SELECT count(*) FROM pg_prepared_xacts WHERE database=current_database()),\n 'connectAllowed',has_database_privilege(current_user,current_database(),'CONNECT'),\n 'schemaUsage',has_schema_privilege(current_user,'ouf_ingestion','USAGE'),\n 'schemaCreate',has_schema_privilege(current_user,'ouf_ingestion','CREATE'),\n 'roleFlags',(SELECT jsonb_build_object('superuser',rolsuper,'createRole',rolcreaterole,\n   'createDb',rolcreatedb,'replication',rolreplication,'bypassRls',rolbypassrls)\n   FROM pg_roles WHERE rolname=current_user),\n 'broadRoleMemberships',jsonb_build_object(\n   'pg_read_all_data',pg_has_role(current_user,'pg_read_all_data','MEMBER'),\n   'pg_write_all_data',pg_has_role(current_user,'pg_write_all_data','MEMBER'),\n   'pg_execute_server_program',pg_has_role(current_user,'pg_execute_server_program','MEMBER'),\n   'pg_read_server_files',pg_has_role(current_user,'pg_read_server_files','MEMBER'),\n   'pg_write_server_files',pg_has_role(current_user,'pg_write_server_files','MEMBER'),\n   'pg_signal_backend',pg_has_role(current_user,'pg_signal_backend','MEMBER')),\n 'history',COALESCE((SELECT jsonb_agg(x ORDER BY installed_rank) FROM\n   (SELECT installed_rank,version,script,type,checksum,success\n    FROM ouf_ingestion.flyway_schema_history ORDER BY installed_rank LIMIT 65)x),'[]'::jsonb),\n 'catalog',jsonb_build_object(\n  'relations',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT c.relname AS name,c.relkind::text AS kind,c.relrowsecurity AS rls,c.relforcerowsecurity AS force_rls\n    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p','S','v','m')\n      AND c.relname<>'flyway_schema_history' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),\n  'columns',COALESCE((SELECT jsonb_agg(x ORDER BY relation,position) FROM\n   (SELECT c.relname AS relation,a.attnum AS position,a.attname AS name,\n      format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull AS not_null,\n      pg_get_expr(d.adbin,d.adrelid) AS default_expression,a.attidentity::text AS identity,\n      a.attgenerated::text AS generated,coll.collname AS collation\n    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace\n      JOIN pg_attribute a ON a.attrelid=c.oid\n      LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum\n      LEFT JOIN pg_collation coll ON coll.oid=a.attcollation\n    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p','v','m') AND c.relname<>'flyway_schema_history'\n      AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum LIMIT 2049)x),'[]'::jsonb),\n  'constraints',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM\n   (SELECT c.relname AS relation,p.conname AS name,p.contype::text AS type,\n      p.convalidated AS validated,p.condeferrable AS deferrable,p.condeferred AS deferred,\n      pg_get_constraintdef(p.oid,true) AS definition\n    FROM pg_constraint p JOIN pg_namespace n ON n.oid=p.connamespace\n      LEFT JOIN pg_class c ON c.oid=p.conrelid\n    WHERE n.nspname='ouf_ingestion' AND COALESCE(c.relname,'')<>'flyway_schema_history'\n    ORDER BY c.relname,p.conname LIMIT 513)x),'[]'::jsonb),\n  'indexes',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT ic.relname AS name,i.indisvalid AS valid,i.indisready AS ready,\n      i.indisunique AS unique_index,i.indisprimary AS primary_index,pg_get_indexdef(i.indexrelid) AS definition\n    FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace\n      JOIN pg_class ic ON ic.oid=i.indexrelid\n    WHERE n.nspname='ouf_ingestion' AND c.relname<>'flyway_schema_history'\n    ORDER BY ic.relname LIMIT 257)x),'[]'::jsonb),\n  'triggers',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM\n   (SELECT c.relname AS relation,t.tgname AS name,t.tgtype::integer AS type,t.tgenabled::text AS enabled,\n      pg_get_triggerdef(t.oid,true) AS definition\n    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' AND NOT t.tgisinternal AND c.relname<>'flyway_schema_history'\n    ORDER BY c.relname,t.tgname LIMIT 257)x),'[]'::jsonb),\n  'functions',COALESCE((SELECT jsonb_agg(x ORDER BY name,arguments) FROM\n   (SELECT p.proname AS name,pg_get_function_identity_arguments(p.oid) AS arguments,\n      pg_get_functiondef(p.oid) AS definition\n    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace\n    WHERE n.nspname='ouf_ingestion' AND p.prokind IN('f','p')\n    ORDER BY p.proname,pg_get_function_identity_arguments(p.oid) LIMIT 129)x),'[]'::jsonb),\n  'sequences',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT c.relname AS name,s.seqstart AS start,s.seqincrement AS increment,s.seqmin AS minimum,\n      s.seqmax AS maximum,s.seqcache AS cache,s.seqcycle AS cycle\n    FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),\n  'policies',COALESCE((SELECT jsonb_agg(x ORDER BY relation,name) FROM\n   (SELECT c.relname AS relation,p.polname AS name,p.polcmd::text AS command,p.polpermissive AS permissive,\n      pg_get_expr(p.polqual,p.polrelid) AS qualifier,pg_get_expr(p.polwithcheck,p.polrelid) AS with_check\n    FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' ORDER BY c.relname,p.polname LIMIT 129)x),'[]'::jsonb)),\n 'tablePrivileges',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT c.relname AS name,has_table_privilege(current_user,c.oid,'SELECT') AS select_allowed,\n      has_table_privilege(current_user,c.oid,'INSERT') AS insert_allowed,\n      has_table_privilege(current_user,c.oid,'UPDATE') AS update_allowed,\n      has_table_privilege(current_user,c.oid,'DELETE') AS delete_allowed\n    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' AND c.relkind IN('r','p') ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),\n 'sequencePrivileges',COALESCE((SELECT jsonb_agg(x ORDER BY name) FROM\n   (SELECT c.relname AS name,has_sequence_privilege(current_user,c.oid,'USAGE') AS usage_allowed\n    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace\n    WHERE n.nspname='ouf_ingestion' AND c.relkind='S' ORDER BY c.relname LIMIT 129)x),'[]'::jsonb),\n 'functionExecuteAllowed',COALESCE((SELECT bool_and(has_function_privilege(current_user,p.oid,'EXECUTE'))\n    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='ouf_ingestion'),false),\n 'pressurePolicies',COALESCE((SELECT jsonb_agg(x) FROM\n   (SELECT policy_key,state,global_running_limit,soft_outbox_limit,hard_outbox_limit,recovery_outbox_limit\n    FROM ouf_ingestion.runtime_pressure_policy ORDER BY policy_key LIMIT 2)x),'[]'::jsonb),\n 'work',jsonb_build_object(\n   'runnableRuns',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_run\n       WHERE state IN('READY','PREFLIGHT','RUNNING','DRAINING') LIMIT 10001)x),\n   'eligibleSchedules',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_schedule\n       WHERE state='ACTIVE' AND publication_enabled AND NOT activation_blocked\n       AND (NOT trigger_once OR consumed_publication_id IS DISTINCT FROM publication_id) LIMIT 10001)x),\n   'liveScheduleLeases',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.ing_schedule\n       WHERE lease_until>transaction_timestamp() LIMIT 10001)x),\n   'unackedOutbox',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.handoff_outbox WHERE state<>'ACKED' LIMIT 10001)x),\n   'liveOutboxLeases',(SELECT count(*) FROM (SELECT 1 FROM ouf_ingestion.handoff_outbox\n       WHERE lease_until>transaction_timestamp() AND state='DELIVERING' LIMIT 10001)x)),\n 'connections',jsonb_build_object(\n   'serverMaximum',current_setting('max_connections')::integer,\n   'serverObserved',(SELECT count(*) FROM pg_stat_activity),\n   'databaseObserved',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()),\n   'databaseLimit',(SELECT datconnlimit FROM pg_database WHERE datname=current_database()),\n   'lockWaiters',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'),\n   'unobservablePeers',(SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state IS NULL),\n   'advisoryLocks',(SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND pid<>pg_backend_pid()))\n);\nROLLBACK;\n"
TABLES = frozenset(['audit_event', 'checkpoint_history', 'handoff_outbox', 'historical_contract_legal_hold_event', 'incident_bookmark_page', 'incident_bookmark_scope', 'incident_history_coverage', 'incident_publication_bookmark', 'incident_publication_clock', 'incident_publication_history_floor', 'incident_read_cursor', 'incident_read_item', 'incident_read_session', 'incident_transition', 'ing_lineage', 'ing_partition', 'ing_quarantine', 'ing_run', 'ing_schedule', 'ing_watermark', 'onboarding_review_outbox', 'operational_event', 'processing_attempt', 'protected_log_access_audit', 'replay_attempt', 'replay_execution', 'replay_request', 'run_recovery_session', 'runtime_configuration_snapshot', 'runtime_issue', 'runtime_pressure_policy', 'schema_observation', 'source_health'])
SEQUENCES = frozenset(['operational_event_event_id_seq', 'incident_transition_transition_id_seq'])
REFERENCE_CATALOG_SHA256 = None
DB_PROGRESS = {}


def identifier(value):
    require(type(value) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}', value), 'BOUNDED_DATABASE_IDENTIFIER_REQUIRED')
    return value


def expected_history():
    return [{k: row[k] for k in ('version', 'script', 'type', 'checksum', 'success')} for row in MANIFEST['migrations']]


def history_without_marker(rows):
    require(type(rows) is list and 1 <= len(rows) <= 64, 'BOUNDED_MIGRATION_HISTORY_REQUIRED')
    result = [{k: row[k] for k in ('version', 'script', 'type', 'checksum', 'success')} for row in rows]
    marker = {'version': None, 'script': '"ouf_ingestion"', 'type': 'SCHEMA', 'checksum': None, 'success': True}
    retained_marker = bool(result and result[0] == marker)
    return (result[1:] if retained_marker else result), retained_marker


def selection(parse=parsed):
    """Only the prepared DB/role/OID chosen by the completed original scope."""
    owner_plan = parse(OWNER / 'execution-plan.json', OWNER_PLAN)
    owner_result = parse(OWNER / 'update-result.json', OWNER_RESULT)
    require(owner_result['complete'] is True and owner_result['planHash'] == OWNER_PLAN, 'COMPLETED_OWNER7_PLAN_REQUIRED')
    package = parse(CONTEXT / 'package.json')
    require(package['sourceCommit'] == SOURCE and package['closure']['declaration']['moduleCount'] == 244,
            'COMPLETED_PUBLICATION_PACKAGE_REQUIRED')
    review = parse(CONTEXT / 'review.json')
    decision = parse(CONTEXT / 'decision.json')
    require(review['sourceClosureHash'] == digest(package['closure']) and decision['reviewHash'] == digest(review),
            'PUBLICATION_SOURCE_SELECTION_BINDING_REQUIRED')
    require(parse(CONTEXT / 'runtime.claim.json') == {'packageHash': digest(package), 'automaticReplayAllowed': False},
            'CONSUMED_PUBLICATION_CLAIM_REQUIRED')
    case = parse(CONTEXT / 'case.json', package['fileHashes']['case.json'])
    require(digest(case) == package['executionPins']['caseSha256'] and case['humanBinding'] == owner_plan['humanBinding'],
            'EXACT_COMPLETED_CASE_REQUIRED')
    original = parse(case['originalBinding']['path'], case['originalBinding']['sha256'])
    require(original['schema'] == 'ouf.chatbot-file-cohort-prepared-inputs.v1'
            and original['engine'] == owner_plan['engine']
            and digest(original['databasePlan']) == original['cohortPlan']['databasePlanHash'],
            'EXACT_ORIGINAL_DATABASE_PLAN_REQUIRED')
    database = original['databasePlan']
    modules = {row['module']: row for row in database['modules']}
    require(len(database['modules']) == len(modules) == 4 and set(modules) == {'onboarding', 'udp', 'ingestion', 'mcp'},
            'ORIGINAL_FOUR_DATABASE_BINDINGS_REQUIRED')
    binding = modules['ingestion']
    require(binding['schema'] == 'ouf_ingestion' and type(binding['databaseOid']) is int and binding['databaseOid'] > 0,
            'EXACT_INGESTION_DATABASE_OID_REQUIRED')
    identifier(binding['database']); identifier(binding['user'])
    retained, _ = history_without_marker(binding['expectedMigrations'])
    require(retained == expected_history(), 'RETAINED_COHORT_MIGRATIONS_MUST_MATCH_EXACT_CANDIDATE')
    inputs = parse(INPUT / 'inputs.json', INPUT_HASH)
    candidate = inputs['candidateMetadata']
    require(candidate['sourceCommit'] == MANIFEST['sourceCommit'] and candidate['imageId'] == MANIFEST['imageId']
            and candidate['migrationInventory'] == {r['script']: r['resourceSha256'] for r in MANIFEST['migrations']},
            'EXACT_PRIVATE_CANDIDATE_SQL_RESOURCE_BINDING_REQUIRED')
    return {'engine': owner_plan['engine'], 'ingestion': owner_plan['currentApplications']['ingestion'],
            'postgres': database['postgresRuntimeBinding'], 'database': binding['database'], 'user': binding['user'],
            'databaseOid': binding['databaseOid'], 'docker': package['closure']['executables']['docker'],
            'dockerConfigDirectory': str(OWNER), 'originalBinding': case['originalBinding']}


def verify_executable(binding):
    path = Path(binding['path'])
    require(path.is_absolute(), 'ABSOLUTE_NATIVE_EXECUTABLE_REQUIRED')
    resolved = path.resolve(strict=True)
    for parent in resolved.parents:
        info = parent.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'EXECUTABLE_ANCESTRY_REQUIRED')
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
                and before.st_mode & 0o111 and 0 < before.st_size <= 268435456, 'NATIVE_EXECUTABLE_CUSTODY_REQUIRED')
        digestor = hashlib.sha256()
        with os.fdopen(os.dup(fd), 'rb') as stream:
            for part in iter(lambda: stream.read(1048576), b''): digestor.update(part)
        require(digestor.hexdigest() == binding['sha256'] and metadata(before) == metadata(os.fstat(fd))
                == metadata(resolved.stat()) and path.resolve(strict=True) == resolved, 'NATIVE_EXECUTABLE_DRIFT')
        return str(resolved)
    finally:
        os.close(fd)


def selected_config_matches(value, pg, selected):
    """Reconfirm the retained JDBC role/database and explicit Docker network peer."""
    from urllib.parse import urlsplit, unquote, parse_qsl
    values = {}
    for entry in value['Config'].get('Env', []):
        key, sep, content = entry.partition('=')
        require(sep and key not in values, 'UNIQUE_RUNTIME_ENVIRONMENT_REQUIRED')
        values[key] = content
    require(values.get('OUF_ING_DB_USER') == selected['user'], 'CURRENT_RUNTIME_DATABASE_ROLE_CHANGED')
    url = values.get('OUF_ING_DB_URL', '')
    require(url.startswith('jdbc:postgresql://'), 'RETAINED_POSTGRESQL_JDBC_REQUIRED')
    parsed = urlsplit(url[5:])
    require(not parsed.username and not parsed.password and not parsed.fragment
            and unquote(parsed.path) == '/' + selected['database'] and parsed.port in (None, 5432),
            'CURRENT_RUNTIME_DATABASE_CHANGED')
    parameters = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    require(not {key.lower() for key, _ in parameters} & {'user','username','password','host','hostaddr','port','dbname','database','service','servicefile'},
            'DATABASE_URL_IDENTITY_OVERRIDE_DENIED')
    peers = {pg['Name'].lstrip('/'), pg['Config'].get('Hostname')}
    shared = False
    for network in pg['NetworkSettings']['Networks'].values():
        if any(n.get('NetworkID') == network.get('NetworkID') and n.get('NetworkID')
               for n in value['NetworkSettings']['Networks'].values()):
            shared = True
            peers.update(network.get('Aliases') or [])
            peers.add(network.get('IPAddress'))
    require(shared and parsed.hostname in peers, 'EXACT_RETAINED_DATABASE_NETWORK_PEER_REQUIRED')
    return {'directFlywayEnvironmentExplicitFalse': values.get('SPRING_FLYWAY_ENABLED', '').lower() == 'false',
            'effectiveStartupMigrationPolicyProven': False}


def bounded_command(arguments, seconds=20, maximum=524288):
    """No inherited credentials; drain capped pipes and retain no raw error output."""
    proc = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}, start_new_session=True)
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + seconds
    try:
        with selectors.DefaultSelector() as watch:
            watch.register(proc.stdout, selectors.EVENT_READ, 'out')
            watch.register(proc.stderr, selectors.EVENT_READ, 'err')
            while watch.get_map():
                require(time.monotonic() < deadline, 'FINITE_NATIVE_READ_TIMEOUT')
                for key, _ in watch.select(min(.2, max(0, deadline-time.monotonic()))):
                    raw = os.read(key.fd, 65536)
                    if not raw: watch.unregister(key.fileobj); continue
                    target, limit = (output, maximum) if key.data == 'out' else (errors, 65536)
                    require(len(target) + len(raw) <= limit, 'NATIVE_OUTPUT_BOUND_EXHAUSTED')
                    target.extend(raw)
            status = proc.wait(timeout=max(.01, deadline-time.monotonic()))
        return status, bytes(output), bytes(errors)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        proc.stdout.close(); proc.stderr.close()


def native_arguments(selected, executable):
    identifier(selected['user']); identifier(selected['database'])
    require(re.fullmatch('[0-9a-f]{64}', selected['postgres']['containerId']), 'EXACT_POSTGRES_CONTAINER_REQUIRED')
    # The retained PostgreSQL17 adapter runs psql on that exact container's Unix socket.
    # It never connects to an arbitrary host, forwards a credential or uses a pgpass file.
    return [executable, '--host', 'unix://' + selected['engine']['socketPath'], '--config', selected['dockerConfigDirectory'],
            'exec', selected['postgres']['containerId'], 'env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'LC_ALL=C',
            'PGPASSFILE=/dev/null', 'PGSERVICEFILE=/dev/null', 'PGSYSCONFDIR=/nonexistent',
            'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000',
            'timeout', '-s', 'KILL', '15', 'psql', '-X', '-w', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
            '-v', 'VERBOSITY=sqlstate', '-h', '/var/run/postgresql', '-U', selected['user'], '-d', selected['database'], '-c', SQL]


APPEND_ONLY = frozenset({'audit_event','checkpoint_history','historical_contract_legal_hold_event','ing_lineage',
                        'operational_event','processing_attempt','protected_log_access_audit','replay_attempt',
                        'replay_request','runtime_configuration_snapshot'})
NO_DELETE = frozenset({'incident_transition','run_recovery_session','incident_publication_history_floor'})
NO_UPDATE = frozenset({'incident_bookmark_scope','incident_read_item','incident_publication_bookmark'})


def analyze(facts, selected):
    require(facts['readOnly'] is True and facts['database'] == selected['database']
            and facts['role'] == selected['user'] and facts['databaseOid'] == selected['databaseOid'],
            'EXACT_READ_ONLY_DATABASE_AND_RUNTIME_ROLE_REQUIRED')
    actual, marker = history_without_marker(facts['history'])
    history_matches = actual == expected_history()
    catalog = facts['catalog']
    limits = {'relations':128,'columns':2048,'constraints':512,'indexes':256,'triggers':256,'functions':128,'sequences':128,'policies':128}
    catalog_bounded = set(catalog) == set(limits) and all(type(catalog[k]) is list and len(catalog[k]) <= n for k,n in limits.items())
    catalog_hash = digest(catalog)
    reference_qualified = type(REFERENCE_CATALOG_SHA256) is str and re.fullmatch('[0-9a-f]{64}', REFERENCE_CATALOG_SHA256) is not None
    catalog_matches = bool(reference_qualified and catalog_bounded and catalog_hash == REFERENCE_CATALOG_SHA256)
    rows = {r['name']: r for r in facts['tablePrivileges']}
    gaps = []
    for table in sorted(TABLES | {'flyway_schema_history'}):
        permissions = {'select_allowed'} if table == 'flyway_schema_history' else {'select_allowed','insert_allowed','update_allowed','delete_allowed'}
        if table in APPEND_ONLY: permissions -= {'update_allowed','delete_allowed'}
        if table in NO_DELETE: permissions.discard('delete_allowed')
        if table in NO_UPDATE: permissions.discard('update_allowed')
        for permission in sorted(permissions):
            if rows.get(table, {}).get(permission) is not True: gaps.append({'table': table, 'permission': permission})
    seq = {r['name']:r for r in facts['sequencePrivileges']}
    privileges_match = (set(rows) == TABLES | {'flyway_schema_history'} and not gaps
                        and set(seq) == SEQUENCES and all(r['usage_allowed'] is True for r in seq.values())
                        and facts['connectAllowed'] is True and facts['schemaUsage'] is True
                        and facts['functionExecuteAllowed'] is True)
    narrow_role = (set(facts['roleFlags']) == {'superuser','createRole','createDb','replication','bypassRls'}
                   and all(v is False for v in facts['roleFlags'].values())
                   and all(v is False for v in facts['broadRoleMemberships'].values()))
    policies = facts['pressurePolicies']
    policy_valid = (len(policies) == 1 and policies[0]['policy_key'] == 'GLOBAL'
                    and 0 < policies[0]['recovery_outbox_limit'] < policies[0]['soft_outbox_limit'] < policies[0]['hard_outbox_limit']
                    and 1 <= policies[0]['global_running_limit'] <= 128)
    policy = policies[0] if policy_valid else None
    work, connections = facts['work'], facts['connections']
    counts_bounded = all(type(v) is int and 0 <= v <= 10001 for v in work.values())
    work_drained = counts_bounded and all(work[k] == 0 for k in ('runnableRuns','eligibleSchedules','liveScheduleLeases','liveOutboxLeases'))
    headroom = connections['serverMaximum'] - connections['serverObserved']
    database_headroom = connections['databaseLimit'] < 0 or connections['databaseLimit'] - connections['databaseObserved'] >= 2
    pressure_safe = bool(policy_valid and policy['state'] == 'NORMAL' and counts_bounded
                         and work['unackedOutbox'] < min(10001, policy['soft_outbox_limit'])
                         and headroom >= 5 and database_headroom and connections['lockWaiters'] == 0
                         and connections['unobservablePeers'] == 0 and connections['advisoryLocks'] == 0
                         and facts['preparedTransactions'] == 0 and facts['allowConnections'] is True)
    postgres_compatible = 170000 <= facts['serverVersionNum'] < 180000 and facts['encoding'] == 'UTF8'
    return {'databaseIdentityAndRoleMatched':True,'transactionReadOnly':True,
            'installedSqlMigrationCount':len(actual),'schemaCreationMarkerRetained':marker,
            'sqlHistoryMatchesCandidate':history_matches,'noSqlResourcesPendingByHistory':history_matches,
            'catalogDigest':catalog_hash,'catalogReferenceQualified':reference_qualified,
            'runtimeCatalogMatchesQualifiedCandidate':catalog_matches,'catalogWithinBounds':catalog_bounded,
            'runtimeTableCount':len(TABLES),'requiredRuntimePrivilegesAvailable':privileges_match,'privilegeGaps':gaps,
            'runtimeRoleBroadFlagsAbsent':narrow_role,'runtimeRoleFlags':facts['roleFlags'],
            'runtimeRoleBroadMemberships':facts['broadRoleMemberships'],'schemaCreatePrivilegePresent':facts['schemaCreate'],
            'postgres17Utf8':postgres_compatible,'storedPressureState':policy['state'] if policy and policy['state'] in ('NORMAL','SOFT_PRESSURE','HARD_PRESSURE','RECOVERY') else 'UNKNOWN',
            'pressureAndControlHeadroomWithinReadProfile':pressure_safe,'observedConnectionHeadroom':headroom,
            'workCountsBounded':counts_bounded,'workCountsLowerBounds':work,'runtimeWorkDrainedAtSnapshot':work_drained,
            'databaseReadPrerequisitesProven':bool(history_matches and catalog_matches and privileges_match and narrow_role
                                                 and pressure_safe and work_drained and postgres_compatible)}


def collect(selected, engine_type=EngineReader, execute=bounded_command, executable_check=verify_executable, before_read=None):
    reader = engine_type(selected['engine'], [selected['postgres']['containerId'], selected['ingestion']['containerId']])
    pg = reader.get(selected['postgres']['containerId'])
    app = reader.get(selected['ingestion']['containerId'])
    require(runtime(pg, ordered=False) == selected['postgres'] and runtime(app) == selected['ingestion'], 'CURRENT_DATABASE_OR_INGESTION_GENERATION_DRIFT')
    startup = selected_config_matches(app, pg, selected)
    executable = executable_check(selected['docker'])
    require(not os.path.lexists(Path(selected['dockerConfigDirectory']) / 'config.json'), 'EMPTY_RETAINED_DOCKER_CLI_CONFIG_REQUIRED')
    DB_PROGRESS.update(phase='EXACT_DATABASE_AND_RUNTIME_BINDINGS_VERIFIED', engineGetRequests=reader.calls)
    if before_read is not None: before_read()
    DB_PROGRESS.update(phase='FIXED_READ_ONLY_DATABASE_SESSION', nativeSqlSessionsStarted=1)
    code, raw, errors = execute(native_arguments(selected, executable))
    if code:
        state = re.search(rb'\b(?:ERROR|FATAL):\s+([0-9A-Z]{5})\b', errors)
        if state: DB_PROGRESS['nativeSqlState'] = state[1].decode()
        raise Denied('NATIVE_FIXED_READ_ONLY_SQL_FAILED')
    facts = decode(raw)
    report = analyze(facts, selected)
    DB_PROGRESS.update(phase='DATABASE_FACTS_OBSERVED', databaseFacts=report)
    require(runtime(reader.get(selected['postgres']['containerId']), ordered=False) == selected['postgres']
            and runtime(reader.get(selected['ingestion']['containerId'])) == selected['ingestion'], 'GENERATIONS_CHANGED_DURING_DATABASE_READ')
    require(executable_check(selected['docker']) == executable
            and not os.path.lexists(Path(selected['dockerConfigDirectory']) / 'config.json'), 'NATIVE_CHANNEL_CHANGED_DURING_READ')
    return {'schema':'ouf.ingestion-db-read-preflight.v1','complete':True,'readOnly':True,
            'observedAtUnix':facts['observedAtUnix'],**report,**startup,'engineGetRequests':reader.calls,
            'nativeSqlSessions':1,'maximumNativeSqlSessions':1,'maximumSeconds':90,
            'schemaOrDataMutations':0,'databaseMigrationPerformed':False,'runtimeAuthorityIssued':False,
            'databaseAdmissionProven':False,'runtimeStartupMigrationPolicyProven':False,
            'freshRuntimeHUMANAndOwnerReadStillRequired':True,'currentOwnerActiveRequeried':False,
            'candidateImageImportedByThisAction':False,'credentialFilesOpened':0,'credentialValuesPrinted':False,
            'credentialHashesPrinted':False,'oauthRequests':0,'ownerRequests':0,'gatewayRequests':0,
            'journalWrites':0,'containerLifecycleOperations':0,'processDispatches':1,'newLoginPerformed':False,
            'windowExtended':False,'budgetReset':False,'automaticReplayAllowed':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}


def main():
    require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0 and sys.flags.isolated
            and sys.flags.no_site and sys.dont_write_bytecode, 'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
    def expired(*_): raise Denied('FINITE_DB_PREFLIGHT_DEADLINE')
    signal.signal(signal.SIGALRM, expired); signal.alarm(90)
    DB_PROGRESS.clear(); DB_PROGRESS.update(phase='RETAINED_DATABASE_SELECTION')
    chosen = selection()
    report = collect(chosen)
    require(selection() == chosen, 'RETAINED_DATABASE_SELECTION_CHANGED_DURING_READ')
    print(encoded(report).decode(), flush=True)


if __name__ == '__main__':
    try: main()
    except (Exception, KeyboardInterrupt) as error:
        print(encoded({'schema':'ouf.ingestion-db-read-preflight.v1','complete':False,'status':'STOP_RECONCILE',
                       'readOnly':True,'partial':bool(DB_PROGRESS),'checkpoint':DB_PROGRESS,
                       'reasonCode':str(error) if type(error) is Denied else 'PRIVATE_DETAILS_REDACTED',
                       'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}).decode(), flush=True)
        raise SystemExit(2)

