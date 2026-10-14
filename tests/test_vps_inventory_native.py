"""Actual Docker/PostgreSQL reads; disposable schema fixture, no VPS effects."""
import importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
SCRIPT=Path(__file__).resolve().parents[1]/'scripts/collect-vps-inventory.py'
spec=importlib.util.spec_from_file_location('inventory',SCRIPT);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

@unittest.skipUnless(os.environ.get('OUF_INVENTORY_PG_CID'),'native PostgreSQL container not selected')
class NativeInventory(unittest.TestCase):
    def test_all_five_histories_and_read_only_session_preserve_rows_and_roles(self):
        cid=os.environ['OUF_INVENTORY_PG_CID']
        sql='CREATE TABLE audit_preserved(k int primary key, v text); INSERT INTO audit_preserved VALUES(1,\'retained\');'
        for schema in ('ouf_sem','ouf_onboarding','ouf_ingestion','ouf_udp'):
            sql+=f"CREATE SCHEMA {schema}; CREATE TABLE {schema}.flyway_schema_history(installed_rank int,version text,script text,type text,checksum int,success bool); INSERT INTO {schema}.flyway_schema_history VALUES(1,'1','V1__fixture.sql','SQL',123,true);"
        sql+="CREATE SCHEMA ouf_mcp; CREATE TABLE ouf_mcp.schema_migration(version int,checksum text); INSERT INTO ouf_mcp.schema_migration VALUES(1,repeat('a',64));"
        subprocess.run(['docker','exec','-i',cid,'psql','-X','-v','ON_ERROR_STOP=1','-U','bootstrap','-d','inventory_test'],input=sql.encode(),check=True,stdout=subprocess.DEVNULL)
        with tempfile.TemporaryDirectory() as directory:
            native=p.Native(Path('/usr/bin/docker').resolve(),directory,seconds=90)
            pg=native.inspect(cid);host=pg['Name'].lstrip('/')
            expression="SELECT json_build_object('roles',(SELECT count(*) FROM pg_roles),'rows',(SELECT json_agg(audit_preserved ORDER BY k) FROM audit_preserved))"
            before=native.query(cid,'bootstrap','inventory_test',expression)
            observed={}
            for module,prefix in (('semantic','OUF_SEM'),('onboarding','OUF_ONB'),('ingestion','OUF_ING'),('udp','OUF_UDP'),('mcp','MCP')):
                env=[prefix+'_DB_URL=jdbc:postgresql://'+host+':5432/inventory_test',prefix+'_DB_USER=bootstrap'] if module!='mcp' else ['MCP_DATABASE_URL=postgresql://bootstrap@'+host+':5432/inventory_test']
                row={'Config':{'Env':env}}
                # The service container uses its native default bridge in CI.
                real_network=next(iter(pg['NetworkSettings']['Networks'].values()))
                selected=json.loads(json.dumps(pg));selected['NetworkSettings']['Networks']['ouf-backend']=real_network
                observed[module]=p.db_inventory(native,selected,module,row)
            after=native.query(cid,'bootstrap','inventory_test',expression)
            self.assertEqual(before,after)
            self.assertEqual(set(observed),{'semantic','onboarding','ingestion','udp','mcp'})
            self.assertTrue(all(v['transactionReadOnly'] and v['migrationCount']==1 for v in observed.values()))
            self.assertTrue(all(v['administration']['superuser'] for v in observed.values()))
            self.assertIsNone(observed['mcp']['administration']['incident'])

if __name__=='__main__':unittest.main()
