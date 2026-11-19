"""Exact before/after history gates, independent from backup fixture tests."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chat_recovery_update.database import Database,sql
from tools.chat_recovery_update.owner import MIGRATION,UpdateDenied
class History(unittest.TestCase):
 def setUp(self):
  self.before={m:{'database':m,'databaseOid':i,'role':'admin',
   'migrations':[{'installed_rank':35,'version':'35'}] if m=='udp' else [{'version':13,'checksum':'same'}]}
   for i,m in enumerate(('udp','mcp'))}
  self.before['udp'].update(ownsMaterializationJob=True,recoveryColumnCount=0)
  self.db=Database({'database':{'before':self.before}}, {}, {})
  self.db.verify_backup=lambda:None
  self.observed=copy.deepcopy(self.before);self.db.facts=lambda m:self.observed[m]
 def migrate(self):
  self.observed['udp']['recoveryColumnCount']=4
  self.observed['udp']['migrations'].append({'installed_rank':36,'version':'36','script':MIGRATION['script'],'checksum':MIGRATION['checksum'],'success':True})
 def test_only_exact_addition_and_unchanged_mcp_succeed(self):
  self.db.verify_before();self.migrate()
  self.assertTrue(self.db.verify_migrated()['mcpMigrationsUnchanged'])
 def test_prefix_mcp_oid_and_partial_schema_drift_block(self):
  self.migrate();valid=copy.deepcopy(self.observed)
  for module,key,value in [('udp','recoveryColumnCount',3),('udp','ownsMaterializationJob',False),
                           ('mcp','migrations',[]),('udp','databaseOid',999),('udp','migrations',[])]:
   self.observed=copy.deepcopy(valid);self.observed[module][key]=value
   with self.subTest(module=module,key=key),self.assertRaises(UpdateDenied):self.db.verify_migrated()
 def test_preflight_rejects_partial_or_already_applied_migration(self):
  self.observed['udp']['recoveryColumnCount']=1
  with self.assertRaises(UpdateDenied):self.db.verify_before()
 def test_metadata_queries_cannot_write_or_accept_identifiers(self):
  for module in ('udp','mcp'):
   query=sql(module,'fixture_app')
   self.assertTrue(query.startswith('BEGIN READ ONLY;'))
   self.assertTrue(query.endswith('ROLLBACK;'))
   for token in ('UPDATE ','DELETE ','INSERT ','ALTER ','GRANT '):self.assertNotIn(token,query)
  with self.assertRaises(UpdateDenied):sql('udp',"bad';")
if __name__=='__main__':unittest.main()
