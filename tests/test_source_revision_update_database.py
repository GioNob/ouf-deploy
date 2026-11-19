"""Exact before/after history gates, independent from backup fixture tests."""
import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.source_revision_update.database import Database,sql
from tools.source_revision_update.owner import MIGRATION,UpdateDenied
class History(unittest.TestCase):
 def setUp(self):
  self.before={m:{'database':m,'databaseOid':i,'role':'admin',
   'migrations':[{'installed_rank':33,'version':'33'}] if m=='onboarding' else [{'version':13,'checksum':'same'}]}
   for i,m in enumerate(('onboarding','udp','mcp'))}
  self.before['onboarding'].update(revisionTablePresent=False,revisionTableOwned=None,revisionAppendOnly=False)
  self.db=Database({'database':{'before':self.before}}, {}, {})
  self.db.verify_backup=lambda:None
  self.observed=copy.deepcopy(self.before);self.db.facts=lambda m:self.observed[m]
 def migrate(self):
  self.observed['onboarding'].update(revisionTablePresent=True,revisionTableOwned=True,revisionAppendOnly=True)
  self.observed['onboarding']['migrations'].append({'installed_rank':34,'version':'34','script':MIGRATION['script'],'checksum':MIGRATION['checksum'],'success':True})
 def test_only_exact_addition_and_unchanged_mcp_succeed(self):
  self.db.verify_before();self.migrate()
  self.assertTrue(self.db.verify_migrated()['mcpMigrationsUnchanged'])
 def test_prefix_mcp_oid_and_partial_schema_drift_block(self):
  self.migrate();valid=copy.deepcopy(self.observed)
  for module,key,value in [('onboarding','revisionAppendOnly',False),('onboarding','revisionTableOwned',False),('udp','migrations',[]),
                           ('mcp','migrations',[]),('onboarding','databaseOid',999),('onboarding','migrations',[])]:
   self.observed=copy.deepcopy(valid);self.observed[module][key]=value
   with self.subTest(module=module,key=key),self.assertRaises(UpdateDenied):self.db.verify_migrated()
 def test_preflight_rejects_partial_or_already_applied_migration(self):
  self.observed['onboarding']['revisionTablePresent']=True
  with self.assertRaises(UpdateDenied):self.db.verify_before()
 def test_metadata_queries_cannot_write_or_accept_identifiers(self):
  for module in ('onboarding','mcp'):
   query=sql(module,'fixture_app')
   self.assertTrue(query.startswith('BEGIN READ ONLY;'))
   self.assertTrue(query.endswith('ROLLBACK;'))
   for token in ('UPDATE ','DELETE ','INSERT ','ALTER ','GRANT '):self.assertNotIn(token,query)
  with self.assertRaises(UpdateDenied):sql('onboarding',"bad';")
if __name__=='__main__':unittest.main()
