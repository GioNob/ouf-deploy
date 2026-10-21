import importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];spec=importlib.util.spec_from_file_location('custody_metadata',ROOT/'scripts/read-mounted-configuration-custody.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Metadata(unittest.TestCase):
 def test_metadata_identifies_mode_size_owner_links_and_never_reads_contents(self):
  with tempfile.TemporaryDirectory()as temp:
   path=Path(temp)/'fixture.conf';path.write_text('PRIVATE_CONTENT_CANARY');path.chmod(0o664);os.link(path,Path(temp)/'alias')
   with patch('builtins.open',side_effect=AssertionError('CONTENT_READ_FORBIDDEN')),patch.object(Path,'read_bytes',side_effect=AssertionError('CONTENT_READ_FORBIDDEN')):out=r.inspect_path(path,[os.getuid()])
   self.assertEqual(out['file']['mode'],'0664');self.assertEqual(out['file']['linkCount'],2);self.assertTrue(out['file']['groupOrOtherWritable']);self.assertNotIn('PRIVATE_CONTENT_CANARY',json.dumps(out))
 def test_missing_symlink_and_empty_are_separate_metadata(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);path=root/'empty.conf';path.touch();(root/'alias').symlink_to(path)
   self.assertFalse(r.inspect_path(path,[os.getuid()])['file']['nonemptyBoundedFile']);self.assertTrue(r.inspect_path(root/'alias',[os.getuid()])['file']['symlink']);self.assertEqual(r.inspect_path(root/'missing',[os.getuid()])['file']['errorClass'],'FileNotFoundError')
 def test_only_scanned_configuration_mounts_in_same_fleet_scope(self):
  cid='a'*64;other='b'*64;profile={'schema':'ouf.host-network-reconciliation.v1','maximumContainers':128,'configurationOwnerUids':[0],'restart':{'containerId':cid}}
  rows=[{'id':cid,'running':False,'mounts':[{'Type':'bind','Source':'/fixture/config.yml','Destination':'/etc/config.yml','RW':False},{'Type':'bind','Source':'/fixture/secret','Destination':'/secret','RW':False}]},{'id':other,'running':False,'mounts':[{'Type':'bind','Source':'/unselected/config.yml','Destination':'/config.yml','RW':False}]}]
  with patch.object(r.m,'invoke',side_effect=[(cid+'\n'+other+'\n').encode(),'\n'.join(json.dumps(row)for row in rows).encode()]),patch.object(r,'inspect_path',return_value={'contentReads':0})as inspect:out=r.collect(profile)
  self.assertEqual(out['filesObserved'],1);self.assertEqual(inspect.call_args.args[0],Path('/fixture/config.yml'));self.assertEqual(out['fileContentsRead'],0)
if __name__=='__main__':unittest.main()
