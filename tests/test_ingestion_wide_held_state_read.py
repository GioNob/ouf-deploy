import copy,importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('reader',ROOT/'scripts/read-ingestion-wide-held-state-20261108.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def db():return {'readOnly':True,'databaseOid':'21554','applicationRoleSuperuser':False,
 'migrations':[{'version':'18','checksum':1281376280,'success':True,'type':'SQL','installedRank':18,'installedOn':'2026-10-16T09:57:54.665384'}],
 'activity':{'runStates':{'SUCCEEDED':3},'handoffStates':{'ACKED':34},'unexpiredPartitionLeases':0},
 'retainedRows':{t:{'rows':3,'fingerprint':'a'*32} for t in m.TABLES}}
def doc(running=False):return {'Id':m.CID,'Image':m.IMAGE,'Name':'/fixture','State':{'Running':running,'Pid':7 if running else 0,'ExitCode':0,'OOMKilled':False,'StartedAt':'same'},
 'Config':{'Env':['SECRET=PRIVATE_VALUE']},'HostConfig':{},'Mounts':[],'Path':'java','Args':['private'], 'NetworkSettings':{'Networks':{'backend':{'MacAddress':'private'}}}}
class Tests(unittest.TestCase):
 def test_exact_changed_section_and_table(self):
  b=db();a=copy.deepcopy(b);a['retainedRows']['ing_schedule']['fingerprint']='b'*32
  r=m.compare(b,a);self.assertEqual(r['changedSections'],['retainedRows']);self.assertEqual(r['changedTables'],['ing_schedule'])
  self.assertTrue(r['migrationHistoryUnchanged']);self.assertFalse(r['tableComparisons']['ing_schedule']['rowCountChanged'])
  self.assertNotIn('b'*32,json.dumps(r));self.assertFalse(r['causeOfChangesProven'])
 def test_history_and_activity_deltas_preserved(self):
  b=db();a=copy.deepcopy(b);a['migrations'][0]['checksum']=1;a['activity']['runStates']={'SUCCEEDED':4};a['retainedRows']['ing_run']['rows']=4
  r=m.compare(b,a);self.assertEqual(r['changedSections'],['migrations','activity','retainedRows']);self.assertEqual(r['migrationChanges'][0]['changedFields'],['checksum'])
  self.assertEqual(r['activityAfterStop']['runStates'],{'SUCCEEDED':4});self.assertTrue(r['tableComparisons']['ing_run']['rowCountChanged'])
 def test_unknown_arbitrary_metadata_rejected(self):
  for mode in ('state','table','history','fingerprint'):
   a=db()
   if mode=='state':a['activity']['runStates']={'PRIVATE_VALUE':1}
   if mode=='table':a['retainedRows']['PRIVATE_VALUE']={'rows':1,'fingerprint':'a'*32}
   if mode=='history':a['migrations'][0]['version']='PRIVATE_VALUE'
   if mode=='fingerprint':a['retainedRows']['ing_run']['fingerprint']='PRIVATE_VALUE'
   with self.assertRaises(RuntimeError):m.compare(db(),a)
 def test_file_reader_is_nonmutating_and_does_one_inspect(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp)/'held';root.mkdir();a=db();a['retainedRows']['ing_partition']['fingerprint']='b'*32
   files={'before-database.private.json':db(),'stopped-database.private.json':a,'old.private.json':doc(True),'stopped.private.json':doc()}
   for n,v in files.items():(root/n).write_text(json.dumps(v))
   original={p.name:p.read_bytes() for p in root.iterdir()};calls=[];report={}
   def inspect():calls.append(1);return doc()
   m.collect(report,root,inspect)
   self.assertEqual(calls,[1]);self.assertEqual(report['status'],'INGESTION_HELD_STATE_READ_COMPLETE')
   self.assertEqual(original,{p.name:p.read_bytes() for p in root.iterdir()});self.assertNotIn('PRIVATE_VALUE',json.dumps(report))
   self.assertEqual(report['databaseComparison']['changedTables'],['ing_partition']);self.assertTrue(report['oldContainer']['retainedStoppedRecordConfirmsStop'])
 def test_inspect_failure_still_returns_retained_delta(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp)
   for n,v in {'before-database.private.json':db(),'stopped-database.private.json':db(),'old.private.json':doc(True),'stopped.private.json':doc()}.items():(root/n).write_text(json.dumps(v))
   def fail():raise ValueError('PRIVATE_VALUE')
   report={};m.collect(report,root,fail);self.assertEqual(report['status'],'READ_PARTIAL');self.assertEqual(report['databaseComparison']['changedSections'],[]);self.assertNotIn('PRIVATE_VALUE',json.dumps(report))
if __name__=='__main__':unittest.main(verbosity=2)
