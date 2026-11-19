import ast
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('contract', ROOT / 'scripts/read-discovery-contract-20261108.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
h = m.helper()


def application(url='postgresql://app:PRIVATE_DB_PASSWORD@pg:5432/ouf_mcp?sslmode=require'):
    return {'Config': {'Env': ['MCP_DATABASE_URL=' + url]}, 'Mounts': []}


def postgres(cid='a' * 64):
    return {'Id': cid, 'Name': '/pg', 'NetworkSettings': {'Networks': {'backend': {'Aliases': ['pg'], 'IPAddress': '172.20.0.2'}}}}


class ContractReaderTests(unittest.TestCase):
    def test_exact_qualified_helper(self):
        self.assertEqual(h.PLAN_SHA, 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d')
        self.assertEqual(len(m.MCP_CHECKSUMS), 14)
        ast.parse(m.ADMIN_CHILD)

    def test_db_binding_does_not_forward_password_or_change_host(self):
        self.assertEqual(m.db_binding(application(), postgres(), 'mcp', h), ('app', 'ouf_mcp'))
        for url in ('postgresql://app@elsewhere/ouf_mcp', 'postgresql://app@pg/ouf_mcp?host=elsewhere',
                    'postgresql://app@pg/ouf_mcp?dbname=other', 'postgresql://app@pg/invalid-name'):
            with self.assertRaises(RuntimeError):
                m.db_binding(application(url), postgres(), 'mcp', h)

    def test_routes_distinguish_missing_exact_and_conditional_prefix(self):
        secret = 'PRIVATE_LUA_SECRET'
        rows = {'total': 2, 'list': [
            {'value': {'uri': '/mcp', 'plugins': {'request-validation': {'max_req_body_size': 1048576}}, 'status': 1}},
            {'value': {'uri': '/provider/*', 'vars': [['arg_x', '==', 'private']], 'plugins': {
                'openid-connect': {'client_secret': secret},
                'serverless-post-function': {'functions': [secret]},
                'request-validation': {'body_schema': {'properties': {'properties': {'maxItems': 256}}}}}}}]}
        result = m.summarize_routes(rows, ['/mcp', '/provider/query', '/missing'], h)
        self.assertEqual(result['routes']['/missing']['matchingRouteCount'], 0)
        self.assertTrue(result['routes']['/mcp']['matches'][0]['exactPath'])
        provider = result['routes']['/provider/query']['matches'][0]
        self.assertTrue(provider['prefixPath'])
        self.assertTrue(provider['variableConditionsPresent'])
        self.assertEqual(provider['schemaArrayMaxItems'], [256])
        self.assertFalse(result['effectiveRoutingOrAdmissionProven'])
        self.assertNotIn(secret, json.dumps(result))

    def test_truncated_routes_never_mean_absent(self):
        with self.assertRaisesRegex(RuntimeError, 'COMPLETE_BOUNDED_ROUTE_LIST_REQUIRED'):
            m.summarize_routes({'total': 2, 'list': []}, ['/mcp'], h)

    def test_provider_missing_mount_is_reported_without_reading_secret(self):
        row = {'Config': {'Env': ['OUF_SCHEMA_GOV_ENABLED=false', 'OUF_DISCOVERY_WORKER_ENABLED=false',
                'OUF_SCHEMA_GOV_GATEWAY_BASE_URL=https://gateway.example.test',
                'OUF_SCHEMA_GOV_SEARCH_PATH=/internal/provider/query', 'OUF_SCHEMA_GOV_FETCH_PATH=/internal/provider/fetch',
                'OUF_SCHEMA_GOV_CLIENT_SECRET_FILE=/run/secrets/not-mounted']}, 'Mounts': []}
        result, paths = m.declared_provider(row, h)
        self.assertFalse(result['providerEnabledDeclaration'])
        self.assertFalse(result['workerEnabledDeclaration'])
        self.assertEqual(result['workloadCredentialMount']['status'], 'NO_DECLARED_MOUNT')
        self.assertFalse(result['credentialContentsRead'])
        self.assertEqual(paths, ['/internal/provider/query', '/internal/provider/fetch'])

    def test_credential_metadata_uses_process_view_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / 'credential'
            target.write_text('PRIVATE_VALUE')
            row = {'State': {'Pid': os.getpid()}, 'Mounts': [{'Destination': str(target), 'Source': str(target), 'Type': 'bind', 'RW': False}]}
            # A controlled process-root view, independent of this runner's procfs sandbox.
            original_open = os.open
            process_root = '/proc/' + str(os.getpid()) + '/root'
            def open_view(path, flags, *args, **kwargs):
                return original_open('/' if path == process_root else path, flags, *args, **kwargs)
            with patch.object(m.os, 'open', side_effect=open_view):
                raw, meta = m.mount_file(row, str(target))
            self.assertIsNone(raw)
            self.assertFalse(meta['contentsRead'])
            self.assertTrue(meta['sameAsHostSource'])
            target.unlink()
            target.symlink_to('/etc/passwd')
            with patch.object(m.os, 'open', side_effect=open_view):
                with self.assertRaisesRegex(RuntimeError, 'BOUNDED_MOUNTED_FILE_REQUIRED'):
                    m.mount_file(row, str(target))

    def test_admin_secret_only_in_stdin_and_no_raw_route_output(self):
        secret = 'SYNTHETIC_ONLY_KEY_123456789'
        conf = ('deployment:\n  admin:\n    admin_key:\n      - name: admin\n        key: ' + secret + '\n        role: admin\n').encode()
        report = {'adminCredentialConfigurationsRead': 0, 'externalAdminKeyFilesRead': 0, 'adminRouteGetAttempts': 0}
        row = {'State': {'Pid': 123}}
        with tempfile.TemporaryDirectory() as temp, patch.object(m, 'mount_file', return_value=(conf, {'sameAsHostSource': True})), \
                patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'{"total":0,"list":[]}')) as run:
            result = m.routes(row, ['/mcp'], h, report, Path(temp))
        self.assertEqual(report['adminRouteGetAttempts'], 1)
        self.assertNotIn(secret, repr(run.call_args.args))
        self.assertIn(secret, run.call_args.kwargs['input'].decode())
        self.assertNotIn(secret, json.dumps(result))

    def test_database_result_checks_exact_history_without_migration(self):
        value = {'readOnly': True, 'databaseOid': 16400,
                 'migrations': [{'version': i, 'checksum': m.MCP_CHECKSUMS[str(i)]} for i in range(1, 14)],
                 'analysisTablePresent': False, 'analysisTaskTablePresent': False}
        def execute(value):
            with tempfile.TemporaryDirectory() as temp, patch.object(m.subprocess, 'run',
                return_value=SimpleNamespace(returncode=0, stdout=json.dumps(value).encode(), stderr=b'')) as run:
                report = {'readOnlyDatabaseSessionsAttempted': 0}
                out = m.database(application(), postgres(), 'mcp', h, report, Path(temp))
                self.assertNotIn('PRIVATE_DB_PASSWORD', repr(run.call_args))
                self.assertIn('READ ONLY', run.call_args.kwargs['input'].decode())
                self.assertNotIn('CREATE', run.call_args.kwargs['input'].decode())
                self.assertEqual(report['readOnlyDatabaseSessionsAttempted'], 1)
                return out
        result = execute(value)
        self.assertTrue(result['migrationsMatchQualifiedSourcePrefix'])
        self.assertEqual(result['remainingCandidateVersions'], [14])
        changed = copy.deepcopy(value)
        changed['migrations'][0]['checksum'] = 'f' * 64
        self.assertFalse(execute(changed)['migrationsMatchQualifiedSourcePrefix'])

    def test_unknown_exception_does_not_expose_stderr_or_credentials(self):
        output = io.StringIO()
        with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'collect', side_effect=ValueError('PRIVATE_ERROR')):
            with redirect_stdout(output):
                m.main()
        report = json.loads(output.getvalue())
        self.assertEqual(report['reason'], 'ValueError')
        self.assertNotIn('PRIVATE_ERROR', output.getvalue())


@unittest.skipUnless(os.environ.get('OUF_CONTRACT_NATIVE') == '1', 'native Docker/PostgreSQL fixture enabled in dedicated CI')
class NativeDatabaseRead(unittest.TestCase):
    @classmethod
    def command(cls, *args, input=None):
        return subprocess.run(('docker', *args), input=input, capture_output=True, timeout=60, check=True).stdout

    @classmethod
    def setUpClass(cls):
        cls.cid = None
        def cleanup():
            if cls.cid:
                cls.command('rm', '-f', cls.cid)
        cls.addClassCleanup(cleanup)
        cls.command('pull', 'postgres:17-alpine')
        cls.cid = cls.command('run', '-d', '--network', 'none', '--label', 'ouf.fixture=discovery-contract-read',
                              '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', 'postgres:17-alpine').decode().strip()
        until = time.monotonic() + 45
        while time.monotonic() < until:
            ready = subprocess.run(('docker', 'exec', cls.cid, 'pg_isready', '-h', '127.0.0.1'), capture_output=True, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError('DISPOSABLE_POSTGRES_NOT_READY')
        values = ','.join("(%d,'%s')" % (i, m.MCP_CHECKSUMS[str(i)]) for i in range(1, 14))
        sql = """CREATE SCHEMA ouf_mcp;
CREATE TABLE ouf_mcp.schema_migration(version integer PRIMARY KEY,checksum char(64));
INSERT INTO ouf_mcp.schema_migration VALUES """ + values + ";" + """
CREATE SCHEMA ouf_sem;
CREATE TABLE ouf_sem.flyway_schema_history(installed_rank integer,version text,checksum integer,success boolean);
INSERT INTO ouf_sem.flyway_schema_history VALUES(1,'11',111,true),(2,'12',222,true);
CREATE TABLE ouf_sem.discovery_request(state text,recovery_state text);
INSERT INTO ouf_sem.discovery_request VALUES('PENDING','ACTIVE'),('PENDING','PAUSED_EXHAUSTED'),('SUCCEEDED','ACTIVE');
CREATE ROLE fixture_mcp LOGIN;
CREATE ROLE fixture_semantic LOGIN;
GRANT USAGE ON SCHEMA ouf_mcp TO fixture_mcp;
GRANT SELECT ON ALL TABLES IN SCHEMA ouf_mcp TO fixture_mcp;
GRANT USAGE ON SCHEMA ouf_sem TO fixture_semantic;
GRANT SELECT ON ALL TABLES IN SCHEMA ouf_sem TO fixture_semantic;
"""
        cls.command('exec', '-i', cls.cid, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres', input=sql.encode())

    def test_actual_postgres_history_backlog_and_read_only_enforcement(self):
        app = application('postgresql://fixture_mcp@pg/postgres')
        app['Config']['Env'] += ['OUF_SEM_DB_URL=jdbc:postgresql://pg/postgres', 'OUF_SEM_DB_USER=fixture_semantic']
        report = {'readOnlyDatabaseSessionsAttempted': 0}
        with tempfile.TemporaryDirectory() as temp:
            mcp = m.database(app, postgres(self.cid), 'mcp', h, report, Path(temp))
            semantic = m.database(app, postgres(self.cid), 'semantic', h, report, Path(temp))
        self.assertTrue(mcp['readOnly'])
        self.assertTrue(mcp['migrationsMatchQualifiedSourcePrefix'])
        self.assertEqual(mcp['remainingCandidateVersions'], [14])
        self.assertEqual(semantic['pendingOrRunningRequestCount'], 2)
        self.assertEqual(report['readOnlyDatabaseSessionsAttempted'], 2)
        attempt = subprocess.run(('docker', 'exec', '-i', self.cid, 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'postgres'),
                                 input=b"BEGIN READ ONLY; INSERT INTO ouf_sem.discovery_request VALUES('PENDING','ACTIVE'); ROLLBACK;", capture_output=True, timeout=10)
        self.assertNotEqual(attempt.returncode, 0)
        self.assertIn(b'read-only transaction', attempt.stderr)
        count = self.command('exec', self.cid, 'psql', '-XAt', '-U', 'postgres', '-d', 'postgres', '-c', 'SELECT count(*) FROM ouf_sem.discovery_request')
        self.assertEqual(count.strip(), b'3')


if __name__ == '__main__':
    unittest.main()
