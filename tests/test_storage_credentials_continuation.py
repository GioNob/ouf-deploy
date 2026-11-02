import os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
from tools.storage_migration import target_inventory_credentials as m
class ContinuationTests(unittest.TestCase):
 def test_lineage_preserves_fourteen_controls_and_fortynine_gets(self):
  self.assertEqual(m.PROFILE['previousControlAttempts'],14);self.assertEqual(m.PROFILE['previousEngineGets'],49);self.assertEqual(m.PROFILE['maximumEngineGets'],2);self.assertEqual(m.FAILED['directEngineGets'],13)
 def test_no_inventory_and_no_other_container_get(self):
  e=m.Engine.__new__(m.Engine);e.control=type('Control',(),{'check':lambda self:None})();e.gets=0;e.allowed={'/v1.44/containers/'+'a'*64+'/json'}
  for path in ['/containers/json?all=1','/v1.44/containers/'+'b'*64+'/json']:
   with self.assertRaises(m.base.Stop):e.get(path)
  self.assertEqual(e.gets,0)
 def test_third_read_denied_before_contact(self):
  e=m.Engine.__new__(m.Engine);e.gets=2
  with self.assertRaises(m.base.Stop):e.get('/v1.44/containers/'+'a'*64+'/json')
 def test_original_sdk_and_no_runtime_authority(self):
  self.assertEqual(m.base.BACKEND_SHA,'430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8');self.assertFalse(m.PROFILE['runtimeAuthorityIssued']);self.assertFalse(m.PROFILE['automaticReplayAllowed'])
 @unittest.skipUnless(os.geteuid()==0,'root custody fixture')
 def test_changed_control14_stop_is_rejected_before_engine(self):
  from unittest.mock import patch
  parent='/root' if os.environ.get('GITHUB_ACTIONS')=='true' else ROOT
  with tempfile.TemporaryDirectory(dir=parent) as tmp:
   root=Path(tmp);root.chmod(0o700);old=root/'old';prev=root/'prev';old.mkdir(mode=0o700);prev.mkdir(mode=0o700)
   claim={'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False}
   for name,value in [('capture.claim.json',claim),('storage-baseline.claim.json',{'profile':m.base.FAILED_PROFILE,'automaticReplayAllowed':False}),('result.json',m.base.FAILED_RESULT)]:p=old/name;p.write_bytes(m.base.encoded(value));p.chmod(0o600)
   for name,value in [('capture.claim.json',claim),('storage-baseline.claim.json',{'profile':m.base.PROFILE,'automaticReplayAllowed':False}),('result.json',{**m.FAILED,'directEngineGets':12}),('predecessor-reconciliation.json',{}),('host-baseline.private.json',{})]:p=prev/name;p.write_bytes(m.base.encoded(value));p.chmod(0o600)
   with patch.object(m.base,'PREDECESSOR',old),patch.object(m,'PREVIOUS',prev):
    with self.assertRaises(m.base.Stop):m.history(m.Capture(root/'new'))
