import importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('correction',ROOT/'tools/storage_migration/target_inventory_reconciliation.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ReconciliationTests(unittest.TestCase):
 def test_exact_reported_stop_is_required(self):
  self.assertEqual(m.FAILED_RESULT['directEngineGets'],1);self.assertEqual(m.FAILED_RESULT['cumulativeDirectEngineGets'],36)
  self.assertEqual(m.PROFILE['previousControlAttempts'],13);self.assertEqual(m.PROFILE['maximumEngineGets'],13)
 def test_names_have_no_role_authority(self):
  cid='a'*64
  for name in ['/minio','/ouf_minio','/stack.minio.1','/ouf-minio']:
   doc={'Id':cid,'Name':name,'Image':'sha256:exact','State':{'Running':True,'Paused':False,'Pid':2},'Args':['server','/data'],'Config':{'Env':[]}}
   self.assertEqual(m.minio_admission(doc,'sha256:exact',cid)[0],2)
   with self.assertRaises(m.Stop):m.minio_admission(doc,'sha256:exact','b'*64)
 def test_wrong_image_and_listener_are_denied(self):
  d={'Id':'a'*64,'Name':'/minio','Image':'sha256:other','State':{'Running':True,'Paused':False,'Pid':2},'Args':['server','/data'],'Config':{'Env':[]}}
  with self.assertRaises(m.Stop):m.minio_admission(d,'sha256:exact','a'*64)
  d['Image']='sha256:exact';d['Args']=['server','--address',':9002','/data']
  with self.assertRaises(m.Stop):m.minio_admission(d,'sha256:exact','a'*64)
 def test_engine_does_not_allow_inventory_or_unbound_id(self):
  e=m.Engine.__new__(m.Engine);e.control=type('Control',(),{'check':lambda self:None})();e.gets=0;e.allowed={'/v1.44/containers/'+'a'*64+'/json'}
  for path in ['/containers/json?all=1','/v1.44/containers/'+'b'*64+'/json','/images/json']:
   with self.assertRaises(m.Stop):e.get(path)
  self.assertEqual(e.gets,0)
 @unittest.skipUnless(os.geteuid()==0,'private root custody fixture')
 def test_predecessor_is_preserved_and_tampering_denied(self):
  parent='/root' if os.environ.get('GITHUB_ACTIONS')=='true' else ROOT
  with tempfile.TemporaryDirectory(dir=parent) as tmp:
   p=Path(tmp);p.chmod(0o700);old=p/'old';old.mkdir(mode=0o700)
   records={'capture.claim.json':{'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False},'storage-baseline.claim.json':{'profile':m.FAILED_PROFILE,'automaticReplayAllowed':False},'result.json':m.FAILED_RESULT}
   for name,value in records.items():(old/name).write_bytes(m.encoded(value));(old/name).chmod(0o600)
   before={q.name:q.read_bytes() for q in old.iterdir()}
   with patch.object(m,'PREDECESSOR',old):
    c=m.Capture(p/'new');frames=m.reconcile_failed_scope(c)
    self.assertEqual(len(frames),4);self.assertEqual(before,{q.name:q.read_bytes() for q in old.iterdir()})
    changed={**m.FAILED_RESULT,'directEngineGets':2};(old/'result.json').write_bytes(m.encoded(changed))
    with self.assertRaises(m.Stop):m.reconcile_failed_scope(m.Capture(p/'tampered'))
 def test_s3_backend_stays_exact_original_executable(self):
  self.assertEqual(m.BACKEND_SHA,'430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8')
  self.assertNotEqual(m.SCOPE,m.PREDECESSOR)
