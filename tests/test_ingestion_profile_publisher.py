"""Real FD custody, flock, CAS, rename and fsync; no network or owner mocks in publisher."""
import ast,fcntl,hashlib,importlib.util,json,os,stat,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
SOURCE=HERE/'native.py'
if not SOURCE.exists():SOURCE=ROOT/'tools/ingestion_profile_publication/native.py'
GATEWAY=ROOT/'installation_binding_apply/custody_stop/gateway_fixture.py'
if not GATEWAY.exists():GATEWAY=ROOT/'tools/chatbot_file_cohort/gateway.py'
def require(ok,reason):
 if not ok:raise ValueError(reason)
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def custody():
 tree=ast.parse(GATEWAY.read_bytes());wanted={'selected_directory_custody','selected_file_custody','private_config'}
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in wanted]
 ns={'os':os,'stat':stat,'hashlib':hashlib,'Path':Path,'require':require,'_EXISTING_CONFIG_CUSTODY':{}}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-custody-functions>','exec'),ns);return ns
class Publisher(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.shared=self.root/'shared';self.shared.mkdir(mode=0o750);self.parent=self.shared/'installation';self.parent.mkdir(mode=0o700)
  self.path=self.parent/'active-projection.json';self.old=b'{"revision":6}';self.new=b'{"revision":7}';self.path.write_bytes(self.old);self.path.chmod(0o600)
  self.c=custody();ns={'os':os,'stat':stat,'hashlib':hashlib,'Path':Path,'re':__import__('re'),'fcntl':fcntl,'require':require,'private_config':self.c['private_config']}
  tree=ast.parse(SOURCE.read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='publish')
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-native-publisher>','exec'),ns);self.publish=ns['publish']
  self.binding=self.c['private_config'](str(self.path))[1];self.logical='a'*64;self.guards=0
 def guard(self):self.guards+=1
 def test_real_cas_publication_and_original_retained_backup(self):
  backup=self.root/'previous-active-projection.json';backup.write_bytes(self.old);backup.chmod(0o600)
  binding=self.publish(self.binding,self.new,self.logical,self.guard)
  self.assertEqual(self.path.read_bytes(),self.new);self.assertEqual(backup.read_bytes(),self.old)
  self.assertEqual(binding['sha256'],hashlib.sha256(self.new).hexdigest());self.assertEqual(self.guards,2)
  self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
  with self.assertRaises(Exception):self.publish(self.binding,self.new,self.logical,self.guard)
 def test_cas_drift_never_overwrites_changed_target(self):
  self.path.write_bytes(b'OTHER')
  with self.assertRaises(Exception):self.publish(self.binding,self.new,self.logical,self.guard)
  self.assertEqual(self.path.read_bytes(),b'OTHER')
 def test_common_lock_is_nonblocking_and_prevents_second_publisher(self):
  lock=self.parent/'.ouf-active-projection.publish.lock';fd=os.open(lock,os.O_RDWR|os.O_CREAT,0o600)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaises(BlockingIOError):self.publish(self.binding,self.new,self.logical,self.guard)
  finally:os.close(fd)
  self.assertEqual(self.path.read_bytes(),self.old)
 def test_revocation_before_rename_preserves_old_bytes_and_temporary_evidence(self):
  def guard():
   self.guards+=1
   if self.guards==2:raise ValueError('REVOKED')
  with self.assertRaisesRegex(ValueError,'REVOKED'):self.publish(self.binding,self.new,self.logical,guard)
  self.assertEqual(self.path.read_bytes(),self.old);self.assertTrue(list(self.parent.glob('*.tmp')))
 def test_symlink_target_and_world_writable_ancestry_rejected(self):
  self.path.unlink();self.path.symlink_to(self.root/'outside')
  with self.assertRaises(Exception):self.publish(self.binding,self.new,self.logical,self.guard)
  self.path.unlink();self.path.write_bytes(self.old);self.path.chmod(0o600);self.shared.chmod(0o777)
  with self.assertRaises(Exception):self.publish(self.binding,self.new,self.logical,self.guard)
 def test_approved_nonroot_parent_custody_survives_final_readback(self):
  if os.environ.get('OUF_NATIVE_UIDS')=='1':
   os.chown(self.shared,1000,1000)
   expected=(1000,1000,0o750)
  else:expected=(self.shared.stat().st_uid,self.shared.stat().st_gid,0o750)
  self.c['_EXISTING_CONFIG_CUSTODY'][str(self.path)]={'parents':{str(self.shared):expected,str(self.parent):(0,0,0o700)},'file':(0,0,0o600)}
  binding=self.publish(self.binding,self.new,self.logical,self.guard)
  self.assertEqual(binding['sha256'],hashlib.sha256(self.new).hexdigest());self.assertEqual(self.path.read_bytes(),self.new)
 def test_readback_failure_preserves_new_bytes_and_never_rolls_back(self):
  real=self.c['private_config']
  def reader(path,expected=None):
   raw,b=real(path,expected)
   if expected is None and raw==self.new:return b'UNPROVEN_READBACK',b
   return raw,b
  self.publish.__globals__['private_config']=reader
  with self.assertRaisesRegex(ValueError,'APPROVED_CUSTODY_PUBLICATION_READBACK_FAILED'):self.publish(self.binding,self.new,self.logical,self.guard)
  self.assertEqual(self.path.read_bytes(),self.new)
  with self.assertRaises(Exception):self.publish(self.binding,self.new,self.logical,self.guard)
 def test_publisher_has_no_network_process_or_owner_dispatch(self):
  tree=ast.parse(SOURCE.read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='publish')
  text=ast.unparse(node)
  for forbidden in('http.','gateway.','engine.','subprocess.','urlopen','OwnerHttp'):self.assertNotIn(forbidden,text)
if __name__=='__main__':unittest.main()
