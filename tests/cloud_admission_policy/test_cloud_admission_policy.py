import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

source=next(p/'scripts/read-cloud-admission-policy-20261019.py' for p in Path(__file__).parents if (p/'scripts/read-cloud-admission-policy-20261019.py').is_file())
spec=importlib.util.spec_from_file_location('reader',source)
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)

class ReaderTests(unittest.TestCase):
    def test_closed_database_and_read_only_queries(self):
        for database in ('ouf_mcp','ouf_onboarding'):
            sql=reader.query(database)
            self.assertTrue(sql.startswith('BEGIN READ ONLY;'))
            self.assertTrue(sql.endswith('ROLLBACK;'))
            for mutation in ('INSERT ','UPDATE ','DELETE ','TRUNCATE ','CREATE ','ALTER ','COPY '):
                self.assertNotIn(mutation,sql.upper())
        with self.assertRaises(ValueError): reader.query('postgres')

    def test_error_payload_never_printed(self):
        with patch.object(reader,'collect',side_effect=RuntimeError('TOKEN_CANARY')),patch('builtins.print') as output:
            self.assertEqual(reader.main(),1)
            text=output.call_args.args[0]
            self.assertNotIn('TOKEN_CANARY',text)
            self.assertFalse(json.loads(text)['complete'])

    def test_custody_denial_precedes_sql(self):
        with patch.object(reader,'inspect',return_value={'image':'wrong','revision':'wrong'}),patch.object(reader,'call') as call:
            with self.assertRaises(ValueError): reader.collect()
            call.assert_not_called()

    def test_foreign_database_or_write_transaction_rejected(self):
        for fact in ({'database':'other','transactionReadOnly':True},{'database':'ouf_mcp','transactionReadOnly':False}):
            with self.assertRaises(ValueError):reader.validate('ouf_mcp',fact)

    def test_extra_payload_rejected(self):
        fact={'database':'ouf_mcp','transactionReadOnly':True,'windows':[],'revisionAttempts':[],'raw':'private'}
        with self.assertRaises(ValueError):reader.validate('ouf_mcp',fact)

    def test_no_privilege_escalation_or_shell(self):
        with patch.object(reader.subprocess,'run') as run:
            run.return_value=subprocess.CompletedProcess([],0,b'{}',b'')
            reader.call(['version'])
            args,kw=run.call_args
            self.assertEqual(args[0],['/usr/bin/docker','version'])
            self.assertNotIn('shell',kw)
            self.assertEqual(kw['env']['DOCKER_HOST'],'unix:///var/run/docker.sock')

    @unittest.skipUnless(os.getenv('OUF_NATIVE_METADATA_SQL')=='1','native fixture only')
    def test_native_postgres_read_only_and_closed_policy_metadata(self):
        def sql(value):
            p=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',value],capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            return p.stdout
        # Explicit minimal fixture: only columns used by the reviewed SELECTs.
        sql("""CREATE SCHEMA ouf_mcp;CREATE SCHEMA ouf_authorization;
CREATE TABLE ouf_mcp.budget_window(budget_window_id uuid,principal_id text,tenant_id text,policy_ref text,window_start timestamptz,window_end timestamptz,consumed_tool_calls bigint,reserved_tool_calls bigint,consumed_result_bytes bigint,reserved_result_bytes bigint,consumed_distinct_objects bigint,reserved_distinct_objects bigint,limit_tool_calls bigint,limit_result_bytes bigint,limit_distinct_objects bigint);
CREATE TABLE ouf_mcp.budget_object_debt(budget_window_id uuid,debt_amount bigint,debt_state text);
CREATE TABLE ouf_mcp.tool_attempt(attempt_id uuid,principal_id text,tenant_id text,capability_id text,idempotency_key text,admitted_at timestamptz,state text,dispatch_state text);
CREATE TABLE ouf_authorization.active_policy_bundle(bundle_id text,version int,singleton_key boolean);
CREATE TABLE ouf_authorization.policy_bundle(bundle_id text,version int,bundle_payload jsonb);
CREATE TABLE ouf_authorization.capability_registration(capability_id text,descriptor jsonb);
INSERT INTO ouf_mcp.budget_window VALUES('00000000-0000-0000-0000-000000000001','b93d8cf6-cd14-4ee6-91d7-84cd76c4f500','ouf-lab','fixture','2026-10-19T07:40:00Z','2026-10-19T07:41:00Z',2,0,1000,0,13,0,NULL,NULL,NULL);
INSERT INTO ouf_authorization.active_policy_bundle VALUES('fixture',45,true);
INSERT INTO ouf_authorization.policy_bundle VALUES('fixture',45,'{"capabilities":[],"grants":[]}');""")
        # current_database is the fixture name; validate after verifying the query envelope.
        m=json.loads(sql(reader.query('ouf_mcp')))
        self.assertTrue(m['transactionReadOnly']);self.assertTrue(m['windows'][0]['exceedsRevisionEnvelope'])
        self.assertEqual(m['windows'][0]['consumedObjects'],13)
        a=json.loads(sql(reader.query('ouf_onboarding')))
        self.assertTrue(a['transactionReadOnly']);self.assertEqual(a['ingestionOperationsActive'],0)
        self.assertEqual(a['ingestionOperationsRegistered'],0);self.assertEqual(a['activePolicyVersion'],45)
        self.assertEqual(sql('SELECT count(*) FROM ouf_mcp.budget_window;').strip(),'1')

if __name__=='__main__':unittest.main()
