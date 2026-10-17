import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]/'scripts/prepare-chat-recovery-inputs-20261018.py'
spec=importlib.util.spec_from_file_location('preparation',SOURCE)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class MigrationContract(unittest.TestCase):
 def udp(self):
  return {'transactionReadOnly':True,'ownsMaterializationJob':True,'recoveryColumnCount':0,
   'migrations':[{'installed_rank':i+1,**{k:r[k] for k in('version','script','checksum','success')}}for i,r in enumerate(p.PROFILE['udpMigrations'][:-1])]}
 def test_current_prefix_and_unchanged_mcp(self):
  p.validate_database('udp',self.udp(),p.PROFILE)
  p.validate_database('mcp',{'transactionReadOnly':True,'migrations':p.PROFILE['mcpMigrations']},p.PROFILE)
 def test_stale_schema_and_partial_migration_rejected(self):
  for change in('checksum','success','version','recoveryColumnCount','ownsMaterializationJob','transactionReadOnly'):
   row=self.udp()
   if change in('checksum','success','version'):row['migrations'][-1][change]=None
   else:row[change]=1 if change=='recoveryColumnCount' else False
   with self.subTest(change=change),self.assertRaises(ValueError):p.validate_database('udp',row,p.PROFILE)
 def test_mcp_missing_or_changed_history_rejected(self):
  for rows in(p.PROFILE['mcpMigrations'][:-1],[{'version':1,'checksum':'0'*64}]):
   with self.assertRaises(ValueError):p.validate_database('mcp',{'transactionReadOnly':True,'migrations':rows},p.PROFILE)
 def test_sql_scoped_to_readonly_and_current_role(self):
  for module in('udp','mcp'):
   query=p.sql(module,'ouf_app')
   self.assertTrue(query.startswith('BEGIN READ ONLY;'))
   self.assertTrue(query.endswith('ROLLBACK;'))
   for forbidden in('UPDATE ','DELETE ','INSERT ','ALTER ','CREATE ','GRANT '):self.assertNotIn(forbidden,query)
  with self.assertRaises(ValueError):p.sql('udp',"x'; select secret")
 def test_private_write_never_overwrites_and_keeps_mode(self):
  with tempfile.TemporaryDirectory()as tmp:
   path=Path(tmp)/'plan.json';p.private_write(path,b'private')
   self.assertEqual(path.stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):p.private_write(path,b'changed')
   self.assertEqual(path.read_bytes(),b'private')
 def test_private_root_rejects_writable_ancestor(self):
  if os.geteuid()!=0:self.skipTest('root fixture')
  with tempfile.TemporaryDirectory(dir='/root')as tmp:
   root=Path(tmp);root.chmod(0o700);p.root_dir(root)
   root.chmod(0o777)
   with self.assertRaises(ValueError):p.root_dir(root)
if __name__=='__main__':unittest.main()
