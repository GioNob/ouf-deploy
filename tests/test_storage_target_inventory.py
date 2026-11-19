import importlib.util,json,os,sys,fcntl
from pathlib import Path
import unittest
ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
s=importlib.util.spec_from_file_location('target',ROOT/'tools/storage_migration/target_inventory.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

def doc(**changes):
 r={'Id':'a'*64,'Name':'/ouf-minio','Image':'sha256:expected','State':{'Running':True,'Paused':False,'Pid':123},'Args':['server','/data'],'Config':{'Env':['MINIO_ROOT_USER=synthetic','MINIO_ROOT_PASSWORD=secret-value']}}
 r.update(changes);return r
class TargetGuardTest(unittest.TestCase):
 def test_selects_only_ouf(self):self.assertEqual(m.select_containers([{'Id':'a'*64,'Names':['/ouf-minio']},{'Id':'b'*64,'Names':['/unrelated']}]),['a'*64])
 def test_duplicate_or_unbounded_container_set_denied(self):
  for rows in [[{'Id':'a'*64,'Names':['/ouf-minio']}]*2,[{'Id':format(i,'064x'),'Names':['/ouf-'+str(i)]} for i in range(65)]]:
   with self.assertRaises(ValueError):m.select_containers(rows)
 def test_native_image_and_running_admission(self):
  self.assertEqual(m.minio_admission(doc(),'sha256:expected')[0],123)
  for d in [doc(Image='sha256:other'),doc(State={'Running':False,'Paused':False,'Pid':123}),doc(State={'Running':True,'Paused':True,'Pid':123})]:
   with self.assertRaises(ValueError):m.minio_admission(d,'sha256:expected')
 def test_wrong_listener_denied(self):
  with self.assertRaises(ValueError):m.minio_admission(doc(Args=['server','/data','--address',':9002']),'sha256:expected')
 def test_duplicate_environment_denied(self):
  with self.assertRaises(ValueError):m.environment(doc(Config={'Env':['A=one','A=two']}))
 def test_unselected_environment_values_not_spooled(self):self.assertNotIn('secret-value',json.dumps(m.filtered_binding(doc())))
 def test_credentials_require_explicit_sources(self):
  with self.assertRaises(ValueError):m.credential(os.getpid(),{},'MINIO_ROOT_PASSWORD')
  self.assertEqual(m.credential(os.getpid(),{'MINIO_ROOT_PASSWORD':'synthetic'},'MINIO_ROOT_PASSWORD'),b'synthetic')
 def test_anonymous_descriptor_has_all_immutable_seals(self):
  fd=m.sealed_descriptor(b'synthetic')
  try:
   self.assertEqual(fcntl.fcntl(fd,getattr(fcntl,'F_GET_SEALS',1034))&15,15);self.assertEqual(os.read(fd,20),b'synthetic')
   with self.assertRaises(OSError):os.write(fd,b'changed')
  finally:os.close(fd)
