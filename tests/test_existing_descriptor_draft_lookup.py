"""Synthetic owner/protocol fixtures. Real native PG/Engine qualification is separate."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('existing_draft_lookup', ROOT/'scripts/lookup-existing-descriptor-draft-20261025.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def fixture():
    policy = {'bundleId': 'ouf-lab-authorization', 'version': 48, 'publishedAt': '2026-10-25T00:00:00Z',
              'capabilities': [], 'grants': [{'grantId': 'g'+str(i), 'private': "CANARY_'\\copy;--"} for i in range(106)]}
    before = {'policyRef': m.BASE_REF, 'contentHash': 'sha256:'+m.BASE_HASH, 'policy': policy}
    candidate = copy.deepcopy(policy); candidate.update(version=49)
    candidate['capabilities'] = [{'capabilityId': cap} for cap in m.CAPS]
    selected = {'id': '00000000-0000-4000-8000-000000000001', 'revision': 0, 'state': 'DRAFT',
                'baseActiveRef': m.BASE_REF, 'creator': m.SUBJECT, 'tenant': m.TENANT, 'createAuditCount': 1}
    p = {'identity': {'database': 'lookup_test', 'databaseOid': 123, 'runtimeRole': 'lookup_runtime',
                     'adminRole': 'postgres', 'postgresPort': 5432},
         'containerPrograms': {'env': '/usr/bin/env', 'timeout': '/usr/bin/timeout', 'psql': '/usr/bin/psql'},
         'dockerExecutable': {'path': '/usr/bin/docker'}, 'unixSocketDirectory': '/var/run/postgresql',
         'postgresRuntimeBinding': {'containerId': 'a'*64},
         'engineBinding': {'socketPath': '/var/run/docker.sock'}}
    report = {'database': 'lookup_test', 'databaseOid': 123, 'role': 'lookup_runtime', 'postgresPort': 5432,
              'transactionReadOnly': True, 'activePolicy': copy.deepcopy(policy), 'matches': [copy.deepcopy(selected)]}
    return before, candidate, p, selected, report


class Reply:
    def __init__(self, url, value, etag='"0"'):
        self.code, self.url, self.value, self.headers = 200, url, value, {'ETag': etag}
    def geturl(self): return self.url
    def read(self, count): return m.encoded(self.value)[:count]
    def __enter__(self): return self
    def __exit__(self, *args): pass


class OwnerFixture:
    def __init__(self, before, candidate, selected):
        self.before, self.candidate, self.selected = before, candidate, selected
        self.calls = []; self.denied = False; self.change = False
    def open(self, request, **kwargs):
        assert request.get_method() == 'GET'
        assert request.data is None
        assert request.get_header('Authorization') == 'Bearer SYNTHETIC_TOKEN'
        self.calls.append(request.full_url)
        if self.denied: raise m.urllib.error.HTTPError(request.full_url, 403, 'denied', {}, None)
        if request.full_url.endswith('/policies/active'):
            value = copy.deepcopy(self.before)
            if self.change and len(self.calls) == 2: value['policyRef'] = 'CHANGED'
        else:
            assert request.full_url.endswith('/policies/'+self.selected['id'])
            value = {'id': self.selected['id'], 'revision': 0, 'state': 'DRAFT',
                     'baseActiveRef': m.BASE_REF, 'policy': self.candidate}
        return Reply(request.full_url, value)


class LookupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('LOOKUP_TEST_ROOT', str(ROOT)))
        self.before, self.candidate, self.p, self.selected, self.report = fixture()
        self.patch = patch.multiple(m, CANDIDATE_HASH=m.digest(self.candidate), BASE_RESPONSE=m.digest(self.before))
        self.patch.start()
        self.j = m.Journal(Path(self.tmp.name)/'fixed')
        self.owner = m.Owner('SYNTHETIC_TOKEN', self.j)
        self.fixture = OwnerFixture(self.before, self.candidate, self.selected)
        self.owner.opener = self.fixture
        self.native_calls = []
    def tearDown(self):
        self.patch.stop(); self.tmp.cleanup()
    def native(self, argv, sql):
        self.native_calls.append((argv, sql))
        assert 'CANARY' not in ' '.join(argv)
        assert 'CANARY' not in sql  # full reviewed policy is hex, never a SQL literal or psql command.
        return copy.deepcopy(self.report)
    def inspect(self, p, journal): journal.reserve('engineGets', 2)
    def run_lookup(self):
        return m.observe(self.j, self.candidate, self.p, self.owner, native=self.native, inspect=self.inspect)
    def test_success_zero_revision_and_cumulative_counters(self):
        result = self.run_lookup()
        self.assertTrue(result['complete'])
        self.assertEqual(result['counts']['administrativeWrites'], 6)
        self.assertEqual(result['counts']['ownerGets'], 9)
        self.assertEqual(result['nativeSqlSessionAttempts'], 1)
        self.assertEqual(result['engineGets'], 2)
        self.assertEqual(len(self.native_calls), 1)
        self.assertFalse(result['continuationAuthorized'])
        self.assertNotIn('CANARY', json.dumps(result))
    def test_scope_consumed_no_second_query(self):
        self.run_lookup()
        with self.assertRaisesRegex(m.Stop, 'CONSUMED_NO_REPLAY'): m.Journal(self.j.root)
        with self.assertRaises(m.Stop): self.run_lookup()
        self.assertEqual(len(self.native_calls), 1)
    def test_no_registration_create_preview_publish_or_generic_get_port(self):
        for path in ('/capabilities', '/policies', '/policies/other', '/policies/'+self.selected['id']+':publish'):
            with self.assertRaises(m.Stop): self.owner.get(path)
        self.assertFalse(self.fixture.calls)
    def test_zero_and_ambiguous_rows_retained_never_selected(self):
        for rows in ([], [self.selected, dict(self.selected, id=str(uuid.uuid4()))]):
            with self.subTest(rows=len(rows)):
                root = Path(self.tmp.name)/('rows'+str(len(rows)))
                j = m.Journal(root); o = m.Owner('SYNTHETIC_TOKEN', j); o.opener = self.fixture
                report = dict(self.report, matches=rows)
                with self.assertRaisesRegex(m.Stop, 'EXACTLY_ONE'):
                    m.observe(j, self.candidate, self.p, o, native=lambda *_: report, inspect=self.inspect)
                self.assertTrue((root/'database-response.json').exists())
                self.assertNotIn('draftId', j.row)
    def test_db_identity_role_readonly_active_mismatch(self):
        for key, value in [('database', 'other'), ('databaseOid', 124), ('role', 'postgres'),
                           ('transactionReadOnly', False), ('postgresPort', 5433), ('activePolicy', {})]:
            with self.subTest(key=key):
                report = dict(self.report, **{key:value})
                with self.assertRaises(m.Stop): m.select_match(report, self.p, self.before['policy'])
    def test_cross_tenant_creator_audit_revision_and_state_denied(self):
        value = {'id': self.selected['id'], 'revision': 0, 'state': 'DRAFT', 'baseActiveRef': m.BASE_REF, 'policy': self.candidate}
        for key, changed in [('creator','other'),('tenant','other'),('createAuditCount',0),('createAuditCount',2),
                             ('revision',1),('revision',-1),('revision',False),('state','PUBLISHED'),('baseActiveRef','other')]:
            with self.subTest(key=key, changed=changed):
                with self.assertRaises(m.Stop): m.validate_draft(value, dict(self.selected, **{key:changed}), self.candidate, '"0"')
        for tag in (None, '"1"', '0'):
            with self.assertRaises(m.Stop): m.validate_draft(value, self.selected, self.candidate, tag)
    def test_owner_denied_before_query(self):
        self.fixture.denied = True
        with self.assertRaises(m.Stop): self.run_lookup()
        self.assertFalse(self.native_calls)
        self.assertEqual(self.j.row['counts']['ownerGets'], 7)
    def test_transient_owner_get_pauses_with_jitter_and_preserves_counts(self):
        current = [0.0]; pauses = []
        def sleep(seconds): current[0] += seconds; pauses.append(seconds)
        self.owner = m.Owner('SYNTHETIC_TOKEN', self.j, clock=lambda: current[0], sleep=sleep, wall=lambda:1000+current[0])
        calls = [0]
        fixture = self.fixture
        class Flaky:
            def open(self, request, **kwargs):
                calls[0] += 1
                if calls[0] == 1: raise m.urllib.error.HTTPError(request.full_url,503,'synthetic',{'Retry-After':'7'},None)
                return fixture.open(request, **kwargs)
        self.owner.opener = Flaky()
        result = self.run_lookup()
        self.assertEqual(result['counts']['ownerGets'],10)
        self.assertEqual(sum(pauses),7)
        self.assertTrue(all(p <= 1 for p in pauses))
        self.assertEqual(len(self.native_calls),1)
    def test_read_retry_budget_never_retries_sql_or_unknown_errors(self):
        current=[0.0]
        self.owner = m.Owner('SYNTHETIC_TOKEN',self.j,clock=lambda:current[0],sleep=lambda s:current.__setitem__(0,current[0]+s))
        class Failed:
            def open(self,request,**kwargs):raise m.urllib.error.HTTPError(request.full_url,503,'synthetic',{'Retry-After':'90'},None)
        self.owner.opener=Failed()
        with self.assertRaisesRegex(m.Stop,'RETRY_EXHAUSTED'):self.run_lookup()
        self.assertEqual(self.j.row['counts']['ownerGets'],7)
        self.assertEqual(self.j.row['nativeSqlSessionAttempts'],0)
    def test_owner_revocation_after_query_keeps_uuid_response(self):
        def native(*args):
            self.fixture.denied = True
            return self.native(*args)
        with self.assertRaises(m.Stop):
            m.observe(self.j, self.candidate, self.p, self.owner, native=native, inspect=self.inspect)
        self.assertTrue((self.j.root/'database-response.json').exists())
        self.assertEqual(len(self.native_calls), 1)
    def test_owner_change_after_query_stops(self):
        self.fixture.change = True
        with self.assertRaisesRegex(m.Stop, 'ACTIVE_CHANGED'): self.run_lookup()
        self.assertTrue((self.j.root/'database-response.json').exists())
    def test_lost_sql_response_consumes_query_and_exec(self):
        def lost(*args): raise TimeoutError('PRIVATE_ERROR_CANARY')
        with self.assertRaises(TimeoutError):
            m.observe(self.j, self.candidate, self.p, self.owner, native=lost, inspect=self.inspect)
        self.assertEqual(self.j.row['nativeSqlSessionAttempts'], 1)
        self.assertEqual(self.j.row['containerExecAttempts'], 1)
        self.assertEqual(len(self.fixture.calls), 1)
    def test_raw_owner_receipt_and_id_before_final_guard(self):
        self.selected['revision'] = 1
        self.report['matches'] = [self.selected]
        with self.assertRaises(m.Stop): self.run_lookup()
        self.assertEqual(self.j.row['draftId'], self.selected['id'])
        self.assertTrue((self.j.root/'owner-draft-response.json').exists())
    def test_candidate_tampering_and_sql_identifier_injection(self):
        candidate = copy.deepcopy(self.candidate); candidate['grants'][0]['private'] = 'changed'
        with self.assertRaises(m.Stop): m.query(self.p, candidate)
        with self.assertRaises(m.Stop): m.identifier('role"; COMMIT;')
    def test_root_umask077_private_artifact_custody(self):
        prior = os.umask(0o077)
        try:
            j = m.Journal(Path(self.tmp.name)/'umask077')
            j.write('result.json', {'private':True})
        finally: os.umask(prior)
        self.assertEqual((j.root.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((j.root/'result.json').stat().st_mode & 0o777), 0o600)
    def test_read_symlink_wrong_owner_or_mode_denied(self):
        path = Path(self.tmp.name)/'source'; path.write_text('exact'); path.chmod(0o600)
        raw = m.read_file(path, os.getuid(), 0o600, 10, hashlib.sha256(b'exact').hexdigest())
        self.assertEqual(raw, b'exact')
        link = path.with_name('link'); link.symlink_to(path)
        with self.assertRaises(OSError): m.read_file(link, os.getuid(), 0o600, 10)
        with self.assertRaises(m.Stop): m.read_file(path, os.getuid(), 0o400, 10)
        with self.assertRaises(m.Stop): m.read_file(path, os.getuid(), 0o600, 10, '0'*64)
    def test_bounded_real_subprocess_sql_stdin_and_no_ambient_environment(self):
        code = "import sys,os,json; s=sys.stdin.read(); print(json.dumps({'length':len(s),'noHome':'HOME' not in os.environ}))"
        result = m.bounded_read([sys_executable(), '-I', '-S', '-c', code], 'x'*100000)
        self.assertEqual(result, {'length':100000, 'noHome':True})
        with self.assertRaises(m.Stop): m.bounded_read([sys_executable(), '-c', 'import sys;sys.exit(1)'], 'sql')
    def test_exact_libpq_devnull_warning_only(self):
        warning = 'WARNING: password file "/dev/null" is not a plain file\n'
        for selected in (warning, 'UNKNOWN_WARNING\n'):
            code = 'import sys;sys.stdin.read();sys.stderr.write('+repr(selected)+');print("{}")'
            if selected == warning:
                self.assertEqual(m.bounded_read([sys_executable(),'-I','-S','-c',code],'sql'),{})
            else:
                with self.assertRaises(m.Stop):m.bounded_read([sys_executable(),'-I','-S','-c',code],'sql')


def sys_executable():
    import sys
    return sys.executable


if __name__ == '__main__': unittest.main()
