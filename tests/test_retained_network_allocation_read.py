import importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('allocation',Path(__file__).resolve().parents[1]/'scripts/read-retained-network-allocation.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Read(unittest.TestCase):
 def test_closed_projection(self):
  value={'id':'a'*64,'name':'/fixture','image':'sha256:'+'b'*64,'running':False,'networks':{},'Env':['SECRET_CANARY']}
  self.assertNotIn('SECRET_CANARY',json.dumps(m.metadata(value)))
 def test_generation_drift_prevents_fleet_read(self):
  calls=[]
  def invoke(args):calls.append(args);return json.dumps({'id':'a'*64,'image':'sha256:'+'b'*64,'running':True}).encode()
  with patch.object(m.m,'invoke',side_effect=invoke):
   with self.assertRaises(ValueError):m.collect({'currentApplications':{'udp':{'containerId':'a'*64,'imageId':'sha256:'+'b'*64}}})
  self.assertEqual(len(calls),1)
 def test_metadata_rejects_invalid_identity(self):
  with self.assertRaises(ValueError):m.metadata({'id':'private-payload','name':'/fixture','image':'sha256:'+'b'*64,'running':False,'networks':{}})
if __name__=='__main__':unittest.main()
