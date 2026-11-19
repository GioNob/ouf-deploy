import base64, copy, hashlib, importlib.util, json, os, pathlib, subprocess, tempfile, unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('preflight', ROOT / 'scripts/read-mcp-analysis-preflight-20261108.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c, h = m.helpers()

def database():
    return {'readOnly': True, 'databaseOid': '21560',
            'migrations': [{'version': i, 'checksum': c.MCP_CHECKSUMS[str(i)]} for i in range(1,14)],
            'analysisTablePresent': False, 'analysisTaskTablePresent': False,
            'applicationRole': {k: True for k in ('canCreateInSchema','canUseSchema','canReadMigrationHistory','canRecordMigration')}}

class Preflight(unittest.TestCase):
    def test_prefix_permissions_and_wrong_database(self):
        self.assertTrue(m.database_result(database(), c.MCP_CHECKSUMS)['ordinaryMigration14MetadataPrerequisites'])
        for key in ('canCreateInSchema','canUseSchema','canReadMigrationHistory','canRecordMigration'):
            value = database(); value['applicationRole'][key] = False
            self.assertFalse(m.database_result(value, c.MCP_CHECKSUMS)['ordinaryMigration14MetadataPrerequisites'])
        for key, val in (('databaseOid', 1), ('readOnly', False)):
            value = database(); value[key] = val
            with self.assertRaises(RuntimeError): m.database_result(value, c.MCP_CHECKSUMS)

    def test_changed_or_partial_history_and_existing_tables(self):
        for change in ('checksum','partial','table','extra'):
            value = database()
            if change == 'checksum': value['migrations'][0]['checksum'] = '0'*64
            if change == 'partial': value['migrations'].pop()
            if change == 'table': value['analysisTablePresent'] = True
            if change == 'extra': value['migrations'].append({'version':14,'checksum':c.MCP_CHECKSUMS['14']})
            self.assertFalse(m.database_result(value,c.MCP_CHECKSUMS)['ordinaryMigration14MetadataPrerequisites'])

    def test_public_permit_metadata_is_not_authority(self):
        profile = b'{"public":"profile"}'; pin = hashlib.sha256(profile).hexdigest()
        raw = lambda payload: json.dumps({'payload':base64.b64encode(json.dumps(payload).encode()).decode(),
                                          'approval': {'signature': 'DO_NOT_EMIT'}}).encode()
        value = m.permit_summary(profile,raw({'issuedAt':10,'expiresAt':20,'reason':'DO_NOT_EMIT'}),pin,21)
        self.assertTrue(value['expiredAtRead']); self.assertTrue(value['profileHashMatchesDeclaration'])
        self.assertFalse(value['signatureVerifiedByReader']); self.assertNotIn('DO_NOT_EMIT',json.dumps(value))
        self.assertFalse(m.permit_summary(profile,raw({'issuedAt':10,'expiresAt':20}), '0'*64,15)['profileHashMatchesDeclaration'])
        with self.assertRaises(RuntimeError): m.permit_summary(profile,raw({'issuedAt':10,'expiresAt':True}),pin,15)

    def test_credentials_stat_only_and_no_arbitrary_values_emitted(self):
        doc={'State':{'Pid':123}, 'Config':{'Env':['MCP_OIDC_CLIENT_SECRET_FILE=/run/private-secret',
             'MCP_FINGERPRINT_KEY=PRIVATE_KEY','MCP_WORKLOAD_TOKEN=PRIVATE_TOKEN','MCP_DATABASE_URL=PRIVATE_DSN']}}
        file=lambda *path: SimpleNamespace(read_bytes=lambda: b'/usr/local/bin/ouf-mcp\0server\0')
        contract=SimpleNamespace(mount_file=lambda doc,path,read: (self.assertFalse(read),{'status':'MOUNTED_REGULAR_FILE','contentsRead':False}))
        with patch.object(m,'Path',side_effect=file), patch.object(h,'read',return_value=b'synthetic-binary'):
            value=m.startup(doc,contract,h,None,{'publicReprocessingMetadataFilesRead':0})
        result=json.dumps(value)
        for secret in ('PRIVATE_KEY','PRIVATE_TOKEN','PRIVATE_DSN','private-secret'): self.assertNotIn(secret,result)
        self.assertTrue(value['processIsMcpServer']); self.assertFalse(value['credentialContentsRead'])

    def test_no_mutating_sql_and_fixed_helpers(self):
        self.assertIn('READ ONLY',m.QUERY); self.assertTrue(m.QUERY.rstrip().endswith('ROLLBACK;'))
        self.assertNotRegex(m.QUERY.lower(),r'\b(insert|update|delete|alter|drop|grant|revoke|create)\s+(table|schema|role|into|from)\b')
        self.assertEqual(c.MCP_CHECKSUMS['14'],'0c15ba1e335c721b8b7cdc5534910a60716033c12259c1909e8b6bd587cc9d24')

class NativeQuery(unittest.TestCase):
    @unittest.skipUnless(os.getenv('OUF_NATIVE_PREFLIGHT') == '1','native PostgreSQL fixture not selected')
    def test_query_under_application_role_preserves_history(self):
        def sql(body):
            p=subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],input=body.encode(),capture_output=True,timeout=15)
            self.assertEqual(p.returncode,0,p.stderr.decode()); return p.stdout.decode().strip()
        rows=','.join("(%d,'%s')"%(i,c.MCP_CHECKSUMS[str(i)]) for i in range(1,14))
        sql("CREATE ROLE fixture NOLOGIN; CREATE SCHEMA ouf_mcp AUTHORIZATION fixture; SET ROLE fixture; CREATE TABLE ouf_mcp.schema_migration(version integer primary key,checksum char(64)); INSERT INTO ouf_mcp.schema_migration VALUES "+rows+';')
        before=sql('SELECT json_agg(t ORDER BY version) FROM ouf_mcp.schema_migration t;')
        result=json.loads(sql('SET ROLE fixture; '+m.QUERY))
        self.assertTrue(result['readOnly']); self.assertFalse(result['applicationRole']['superuser'])
        self.assertTrue(result['applicationRole']['canCreateInSchema']); self.assertTrue(result['applicationRole']['canRecordMigration'])
        self.assertEqual(result['migrations'],database()['migrations']); self.assertFalse(result['analysisTablePresent'])
        self.assertEqual(before,sql('SELECT json_agg(t ORDER BY version) FROM ouf_mcp.schema_migration t;'))
        sql('REVOKE CREATE ON SCHEMA ouf_mcp FROM fixture;')
        result=json.loads(sql('SET ROLE fixture; '+m.QUERY))
        self.assertFalse(result['applicationRole']['canCreateInSchema'])
        self.assertTrue(result['applicationRole']['canRecordMigration'])

if __name__=='__main__': unittest.main(verbosity=2)
