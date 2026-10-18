import copy,errno,importlib.util,os,shutil,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
t=load('custody_base_fixture',ROOT/'tests/test_host_network_reconciliation.py');b=t.b;m=t.m
class Custody(unittest.TestCase):
 def setUp(self):
  self.assertFalse(Path('/etc/ouf/deploy-snapshots').exists(),'never run mutation fixtures on installed OUF host')
  self.root=Path(tempfile.mkdtemp(prefix='ouf-custody-fixture-',dir='/root'));self.addCleanup(shutil.rmtree,self.root);self.root.chmod(0o700)
  self.path=self.root/'file.yaml';self.path.write_bytes(b'retained private fixture');self.p,_,_=t.fixture();self.p['schema']='ouf.host-network-reconciliation.v2';self.p['configurationCustody']={'schema':'ouf.mounted-file-custody.v1','applicationReadOnlyFiles':[],'operatorGroupFiles':[]}
 def app(self):
  self.path.chmod(0o400);os.chown(self.path,10003,10003)
  rule={'sourcePath':str(self.path),'containerId':'a'*64,'destination':'/run/secrets/file.yaml','uid':10003,'gid':10003,'mode':'0400','containerUser':'10003:10003'};self.p['configurationCustody']['applicationReadOnlyFiles']=[rule];return rule
 def group(self):
  self.path.chmod(0o664);os.chown(self.path,1000,1000);self.p['configurationOwnerUids']=[0,1000]
  rule={'sourcePath':str(self.path),'containerId':'a'*64,'destination':'/etc/service/file.yaml','uid':1000,'gid':1000,'mode':'0664','writerUids':[1000]};self.p['configurationCustody']['operatorGroupFiles']=[rule]
  self.enterContext(patch.object(b.grp,'getgrgid',return_value=types.SimpleNamespace(gr_mem=[])))
  self.enterContext(patch.object(b.pwd,'getpwall',return_value=[types.SimpleNamespace(pw_uid=1000,pw_gid=1000)]))
  self.enterContext(patch.object(b.os,'getxattr',side_effect=OSError(errno.ENODATA,'redacted fixture')));return rule
 def test_profile_is_closed_and_does_not_globally_trust_application_uid(self):
  self.app();self.assertEqual(m.validate_profile(self.p),self.p);self.assertNotIn(10003,self.p['configurationOwnerUids'])
  bad=copy.deepcopy(self.p);bad['configurationCustody']['allowAnyOwner']=True
  with self.assertRaises(ValueError):m.validate_profile(bad)
  bad=copy.deepcopy(self.p);bad['configurationCustody']['applicationReadOnlyFiles'][0]['mode']='0600'
  with self.assertRaises(ValueError):m.validate_profile(bad)
 def test_exact_read_only_application_delegation_preserves_bytes_mode_owner(self):
  self.app();before=self.path.stat();self.assertEqual(b.configuration_bytes(self.path,self.p,m),b'retained private fixture');after=self.path.stat()
  self.assertEqual((before.st_uid,before.st_gid,before.st_mode,before.st_size),(after.st_uid,after.st_gid,after.st_mode,after.st_size))
  self.p['configurationCustody']['applicationReadOnlyFiles']=[]
  with self.assertRaises(ValueError):b.configuration_bytes(self.path,self.p,m)
 def test_wrong_owner_writable_leaf_or_unprotected_ancestry_is_rejected(self):
  self.app();self.path.chmod(0o600)
  with self.assertRaises(ValueError):b.configuration_bytes(self.path,self.p,m)
  self.path.chmod(0o400);os.chown(self.path,10004,10003)
  with self.assertRaises(ValueError):b.configuration_bytes(self.path,self.p,m)
  os.chown(self.path,10003,10003);self.root.chmod(0o755);original=Path.lstat
  def public_root(path):
   info=original(path)
   if path==Path('/root'):
    values=list(info);values[0]=(info.st_mode&~0o777)|0o755;return os.stat_result(values)
   return info
  with patch.object(Path,'lstat',public_root),self.assertRaises(ValueError):b.configuration_bytes(self.path,self.p,m)
 def test_exact_operator_group_with_no_acl_introduces_no_new_writer(self):
  self.group();before=self.path.stat();self.assertEqual(b.configuration_bytes(self.path,self.p,m),b'retained private fixture');self.assertEqual(self.path.stat().st_mode,before.st_mode)
 def test_additional_writer_extended_acl_or_unknown_acl_error_is_rejected(self):
  self.group()
  with patch.object(b.pwd,'getpwall',return_value=[types.SimpleNamespace(pw_uid=42,pw_gid=1000)]),self.assertRaisesRegex(ValueError,'WRITERS_CHANGED'):b.configuration_bytes(self.path,self.p,m)
  with patch.object(b.os,'getxattr',return_value=b'private acl'),self.assertRaisesRegex(ValueError,'EXTENDED_CONFIGURATION_ACL'):b.configuration_bytes(self.path,self.p,m)
  with patch.object(b.os,'getxattr',side_effect=OSError(errno.EACCES,'private')),self.assertRaisesRegex(ValueError,'ACL_READ_UNPROVEN'):b.configuration_bytes(self.path,self.p,m)
 def test_exact_mount_container_user_and_read_only_binding_required(self):
  rule=self.app();row={'Id':'a'*64,'Config':{'User':rule['containerUser'],'Env':[]},'Mounts':[{'Type':'bind','Source':str(self.path),'Destination':rule['destination'],'RW':False}]};scan,bindings=b.configuration_scanner(None,self.p,m);scan(row,self.p);self.assertEqual(len(bindings),1)
  for label in ('id','user','rw'):
   bad=copy.deepcopy(row)
   if label=='id':bad['Id']='b'*64
   elif label=='user':bad['Config']['User']='10004:10004'
   else:bad['Mounts'][0]['RW']=True
   with self.subTest(label=label),self.assertRaises(ValueError):scan(bad,self.p)
 def test_links_and_metadata_changes_during_read_remain_rejected(self):
  self.app();alias=self.root/'alias';os.link(self.path,alias)
  with self.assertRaises(ValueError):b.configuration_bytes(self.path,self.p,m)
  alias.unlink();original=os.read
  def raced(fd,size):
   value=original(fd,size);os.chmod(self.path,0o600);return value
  with patch.object(b.os,'read',side_effect=raced),self.assertRaisesRegex(ValueError,'CHANGED_DURING_READ'):b.configuration_bytes(self.path,self.p,m)
if __name__=='__main__':unittest.main()
