import ast,hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('preboot',Path(__file__).resolve().parents[1]/'scripts/read-preboot-network-contract.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Read(unittest.TestCase):
 def fixture(self):
  temp=tempfile.TemporaryDirectory(dir='/root');self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700)
  def write(name,value):
   path=root/name;raw=json.dumps(value).encode();path.write_bytes(raw);path.chmod(0o600);return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
  owner=write('owner',{'schema':'fixture','ip':'10.9.0.2','secret':'SECRET_CANARY'});empty=write('empty',{'ip':'10.9.0.3'})
  boot=write('boot',{'schema':'ouf.semantic-coordinated-boot-profile.v1','coordinatedConfiguration':owner['path'],'coordinatedConfigurationHash':owner['sha256'],'bootConfiguration':empty['path'],'bootConfigurationHash':empty['sha256']})
  prepared=write('prepared',{'schema':'ouf.source-revision-private-inputs.v1','runtimeAuthorityIssued':False,'beforeApplications':{'udp':{'Id':'a'*64,'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'10.9.0.4'}}},'Config':{'Env':['SECRET_CANARY']}}},'gateway':{'projectionRaw':'{"url":"https://10.9.0.5:8080/SECRET_CANARY"}','beforeRoutes':{'fixture':{'upstream':'10.9.0.4:8080'}}}})
  return {'schema':'ouf.preboot-network-contract-read-selection.v1','preparedPlan':prepared,'bootProfile':boot}
 def test_sealed_real_private_files_and_closed_redaction(self):
  result=m.collect(self.fixture());self.assertTrue(result['complete']);self.assertNotIn('SECRET_CANARY',json.dumps(result));self.assertEqual(result['installationProjectionIPv4'],['10.9.0.5']);self.assertEqual(result['gatewayRouteIPv4'],['10.9.0.4']);self.assertEqual(result['runtimeMutations'],0)
 def test_changed_input_blocks_without_fallback(self):
  selection=self.fixture();Path(selection['preparedPlan']['path']).write_text('{}')
  with self.assertRaises(ValueError):m.collect(selection)
 def test_world_readable_and_symlink_rejected(self):
  for mode in ('public','link'):
   selection=self.fixture();pin=selection['preparedPlan'];path=Path(pin['path'])
   if mode=='public':path.chmod(0o644)
   else:
    target=path.with_name('moved');path.rename(target);path.symlink_to(target)
   with self.subTest(mode=mode),self.assertRaises(Exception):m.collect(selection)
 def test_malformed_or_adversarial_literal_not_emitted(self):
  self.assertEqual(m.ipv4_literals({'secret':'SECRET_CANARY 999.2.3.4','10.9.0.2':'x'}),['10.9.0.2'])
  with self.assertRaises(ValueError):m.unique([('key',1),('key',2)])
 def test_launcher_compiles_and_pins_exact_executable_and_selection(self):
  root=Path(__file__).resolve().parents[1];launcher=(root/'scripts/launch-preboot-network-contract-read-20261018.sh').read_text()
  body=launcher.split("<<'OUF_VERIFIED_PREBOOT_NETWORK_READ'",1)[1].split('\n',1)[1].rsplit('\nOUF_VERIFIED_PREBOOT_NETWORK_READ',1)[0]
  ast.parse(body)
  for name in ('scripts/read-preboot-network-contract.py','releases/preboot-network-contract-read-selection-20261018.json'):
   self.assertIn(hashlib.sha256((root/name).read_bytes()).hexdigest(),launcher)
if __name__=='__main__':unittest.main()
