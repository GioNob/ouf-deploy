"""Actual Docker/PG17 transport and owner DDL; IAM/owner policy fixtures synthetic.

No target access, production approvals or lifecycle qualification is claimed.
The disposable CI PostgreSQL lifecycle is setup, never a repair operation.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lookup_protocol_fixtures', ROOT/'tests/test_existing_descriptor_draft_lookup.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
m = f.m


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert os.geteuid() == 0, 'actual root required; no skips'
        cls.docker = shutil.which('docker'); assert cls.docker
        subprocess.run([cls.docker, 'version'], check=True, stdout=subprocess.DEVNULL)
        cls.cid = subprocess.check_output([cls.docker, 'run', '-d', '--name', 'ouf-draft-lookup-ci-'+uuid.uuid4().hex[:8],
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_DB=lookup_test', 'postgres:17'], text=True).strip()
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ['LOOKUP_TEST_ROOT'])
        for _ in range(120):
            if subprocess.run([cls.docker, 'exec', cls.cid, 'pg_isready', '-U', 'postgres', '-d', 'lookup_test'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
            time.sleep(.5)
        else: raise AssertionError('real postgres not ready')
        ddl = '\n'.join((ROOT/'tests/fixtures'/name).read_text() for name in (
            'onboarding-V15-authorization-policy-registry.sql', 'onboarding-V16-authorization-admin-lifecycle.sql',
            'onboarding-V26-protected-superadmin-role.sql'))
        cls.psql(ddl+"""
CREATE ROLE lookup_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE lookup_denied NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA ouf_authorization TO lookup_runtime;
GRANT SELECT ON ouf_authorization.policy_draft,ouf_authorization.admin_audit,
 ouf_authorization.policy_bundle,ouf_authorization.active_policy_bundle TO lookup_runtime;
""")
        cls.database_oid = int(cls.psql("select oid from pg_database where datname='lookup_test';").strip())
        cls.binary = Path(cls.docker)

    @classmethod
    def tearDownClass(cls):
        subprocess.run([cls.docker, 'rm', '-f', cls.cid], check=True, stdout=subprocess.DEVNULL)
        cls.temp.cleanup()

    @classmethod
    def psql(cls, sql, check=True):
        result = subprocess.run([cls.docker, 'exec', '-i', cls.cid, 'psql', '-X', '-w', '-q', '-A', '-t',
            '-U', 'postgres', '-d', 'lookup_test', '-v', 'ON_ERROR_STOP=1'], input=sql, text=True, capture_output=True)
        if check: assert result.returncode == 0, result.stderr
        return result.stdout

    def setUp(self):
        self.before, self.candidate, self.p, self.selected, self.report = f.fixture()
        self.p['identity']['databaseOid'] = self.database_oid
        socket_path = '/var/run/docker.sock'
        info = os.lstat(socket_path)
        self.p['engineBinding'] = {'socketPath': socket_path,
            'socketBinding': [info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode & 0o777]}
        self.p['dockerExecutable'] = {'path': self.docker, 'sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest()}
        actual = json.loads(subprocess.check_output([self.docker, 'inspect', self.cid]))[0]
        engine_digest = lambda value: hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
        self.p['postgresRuntimeBinding'] = {'containerId':self.cid,'imageId':actual['Image'],'pid':actual['State']['Pid'],
            'startedAt':actual['State']['StartedAt'],'configHash':engine_digest(actual['Config']),
            'hostConfigHash':engine_digest(actual['HostConfig']),'mountsHash':engine_digest(actual['Mounts']),
            'networkSettingsHash':engine_digest(actual['NetworkSettings'])}
        self.patch = patch.multiple(m,CANDIDATE_HASH=m.digest(self.candidate),BASE_RESPONSE=m.digest(self.before))
        self.patch.start()
        self.j = m.Journal(Path(self.temp.name)/uuid.uuid4().hex)
        self.owner = m.Owner('SYNTHETIC_TOKEN', self.j)
        self.owner.opener = f.OwnerFixture(self.before, self.candidate, self.selected)
        self.psql('TRUNCATE ouf_authorization.policy_draft,ouf_authorization.admin_audit,ouf_authorization.active_policy_bundle,ouf_authorization.policy_bundle CASCADE;')
        hexed = lambda value: "convert_from(decode('"+m.encoded(value).hex()+"','hex'),'UTF8')::jsonb"
        self.psql("INSERT INTO ouf_authorization.policy_bundle VALUES('ouf-lab-authorization',48,now(),'SYNTHETIC_HUMAN','fixture',"+hexed(self.before['policy'])+");\n"
            "INSERT INTO ouf_authorization.active_policy_bundle(singleton_key,bundle_id,version) VALUES(true,'ouf-lab-authorization',48);\n"
            "INSERT INTO ouf_authorization.policy_draft(draft_id,state,base_active_ref,payload,created_by,tenant_id) VALUES('"+self.selected['id']+"','DRAFT','"+m.BASE_REF+"',"+hexed(self.candidate)+",'"+m.SUBJECT+"','"+m.TENANT+"');\n"
            "INSERT INTO ouf_authorization.admin_audit VALUES('00000000-0000-4000-8000-000000000099','CREATE_DRAFT','"+self.selected['id']+"','"+m.SUBJECT+"','"+m.TENANT+"','HUMAN','decision:synthetic-not-policy-ref','synthetic',now());")

    def tearDown(self): self.patch.stop()
    def run_lookup(self, **kwargs): return m.observe(self.j,self.candidate,self.p,self.owner,**kwargs)

    def test_actual_lookup_and_owner_zero_revision(self):
        result = self.run_lookup()
        self.assertTrue(result['complete']); self.assertEqual(result['draftRevision'],0)
        raw = json.loads((self.j.root/'database-response.json').read_text())
        self.assertTrue(raw['transactionReadOnly']); self.assertEqual(raw['role'],'lookup_runtime')
        self.assertEqual(result['engineGets'],2); self.assertEqual(result['nativeSqlSessionAttempts'],1)
        self.assertEqual(result['counts']['administrativeWrites'],6)
        self.assertEqual(self.psql('select count(*) from ouf_authorization.policy_draft;').strip(),'1')

    def test_zero_cross_tenant_and_wrong_creator_are_not_selected(self):
        for field,value in [('tenant_id','other'),('created_by','other')]:
            with self.subTest(field=field):
                # Independent fixture contexts, not a production scope reset.
                self.j = m.Journal(Path(self.temp.name)/uuid.uuid4().hex)
                self.owner = m.Owner('SYNTHETIC_TOKEN',self.j); self.owner.opener=f.OwnerFixture(self.before,self.candidate,self.selected)
                self.psql("UPDATE ouf_authorization.policy_draft SET "+field+"='"+value+"';")
                with self.assertRaisesRegex(m.Stop,'EXACTLY_ONE'): self.run_lookup()
                self.assertTrue((self.j.root/'database-response.json').exists())
                self.psql("UPDATE ouf_authorization.policy_draft SET tenant_id='"+m.TENANT+"',created_by='"+m.SUBJECT+"';")

    def test_ambiguous_native_rows_are_durable_and_no_selection(self):
        self.psql("INSERT INTO ouf_authorization.policy_draft(draft_id,revision,state,base_active_ref,payload,created_by,tenant_id) SELECT '00000000-0000-4000-8000-000000000002'::uuid,revision,state,base_active_ref,payload,created_by,tenant_id FROM ouf_authorization.policy_draft;")
        with self.assertRaisesRegex(m.Stop,'EXACTLY_ONE'): self.run_lookup()
        self.assertEqual(len(json.loads((self.j.root/'database-response.json').read_text())['matches']),2)
        self.assertNotIn('draftId',self.j.row)

    def test_full_candidate_equality_excludes_changed_payload(self):
        self.psql("UPDATE ouf_authorization.policy_draft SET payload=jsonb_set(payload,'{version}','50');")
        with self.assertRaisesRegex(m.Stop,'EXACTLY_ONE'): self.run_lookup()

    def test_pg_generation_drift_before_query(self):
        self.p['postgresRuntimeBinding']['pid'] += 1
        with self.assertRaisesRegex(m.Stop,'GENERATION_DRIFT'): self.run_lookup()
        self.assertEqual(self.j.row['nativeSqlSessionAttempts'],0)

    def test_pg_generation_drift_after_query_keeps_response(self):
        calls=[]
        def inspect(p,j):
            calls.append(1)
            if len(calls)==2:p['postgresRuntimeBinding']['pid']+=1
            m.current_postgres(p,j)
        with self.assertRaisesRegex(m.Stop,'GENERATION_DRIFT'):self.run_lookup(inspect=inspect)
        self.assertEqual(self.j.row['nativeSqlSessionAttempts'],1)
        self.assertTrue((self.j.root/'database-response.json').exists())

    def test_actual_sql_transaction_forbids_write(self):
        config=self.j.root/'empty';config.mkdir()
        sql=m.query(self.p,self.candidate).replace('WITH matches AS (',"UPDATE ouf_authorization.policy_draft SET revision=1;\nWITH matches AS (")
        with self.assertRaises(m.Stop):m.bounded_read(m.arguments(self.p,config),sql)
        self.assertEqual(self.psql('SELECT revision FROM ouf_authorization.policy_draft;').strip(),'0')

    def test_actual_runtime_role_cannot_bypass_schema_permissions(self):
        self.p['identity']['runtimeRole']='lookup_denied'
        with self.assertRaises(m.Stop):self.run_lookup()
        self.assertEqual(self.j.row['nativeSqlSessionAttempts'],1)

    def test_unrelated_role_cannot_read_private_artifacts(self):
        self.run_lookup()
        result=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','cat',str(self.j.root/'database-response.json')],capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b'CANARY',result.stdout)


if __name__=='__main__':unittest.main(verbosity=2)
