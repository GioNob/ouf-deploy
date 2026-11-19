import os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
from tools.storage_migration.minio_input_observation import InputBinding
from tools.storage_migration.minio_credential_binding import Binding
from tools.m2_discovery_installation_profile.custody_capture import Stop
ENV={'MINIO_ROOT_USER':'wrong-env-user','MINIO_ROOT_PASSWORD':'wrong-env-password','MINIO_ACCESS_KEY_FILE':'access_key','MINIO_SECRET_KEY_FILE':'secret_key','MINIO_ROOT_USER_FILE':'live-user','MINIO_ROOT_PASSWORD_FILE':'live-password','MINIO_CONFIG_ENV_FILE':'config.env'}
@unittest.skipUnless(os.geteuid()==0,'root fixture')
class InputObservationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir='/root' if os.environ.get('GITHUB_ACTIONS')=='true' else ROOT);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.cwd=self.root/'work';self.cwd.mkdir(mode=0o700)
  self.a=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);self.b=os.open(self.cwd,os.O_RDONLY|os.O_DIRECTORY);self.addCleanup(os.close,self.a);self.addCleanup(os.close,self.b)
  self.binding=InputBinding(0,self.a,self.b);self.addCleanup(self.binding.close)
 def file(self,name,value=b'file-user',mode=0o600):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value);p.chmod(mode);return p
 def pair(self,mode=0o600):return self.file('work/live-user',b'file-user',mode),self.file('work/live-password',b'file-password',mode)
 def test_exact_previous_zero_bytes_five_candidates_stop_reproduced_then_0644_observed(self):
  self.pair(0o644);old=Binding(0,self.a,self.b)
  try:
   with self.assertRaisesRegex(Stop,'PRIVATE_BOUNDED_REGULAR_CREDENTIAL_SOURCE_REQUIRED'):old.resolve(ENV)
   self.assertEqual((old.opened,old.bytes,len(old.probes)),(0,0,5))
  finally:old.close()
  meta=self.binding.preflight(ENV);self.assertTrue(meta['metadataComplete']);self.assertFalse(meta['policyBlocked']);self.assertEqual(self.binding.opened,0)
  self.assertTrue(any('OTHER_PERMISSION_BITS' in r.get('previousGuardFailedPredicates',[]) for r in meta['candidates']));self.assertFalse(meta['sourceCustodyAdmitted'])
  self.assertEqual(self.binding.resolve(ENV)[0],[b'file-user',b'file-password'])
 def test_nonroot_owner_is_observed_and_unchanged(self):
  files=self.pair()
  try:
   for p in files:os.chown(p,10001,10001)
  except OSError:
   if os.environ.get('GITHUB_ACTIONS')=='true':raise
   self.skipTest('workspace filesystem does not map the fixture UID; required in native CI')
  self.binding.preflight(ENV);self.assertEqual(self.binding.resolve(ENV)[0],[b'file-user',b'file-password']);self.assertEqual(files[0].stat().st_uid,10001)
  self.assertTrue(any('NON_ROOT_OWNER' in r.get('previousGuardFailedPredicates',[]) for r in self.binding.public_metadata()['candidates']))
 def test_hardlink_is_reported_without_modifying_any_alias(self):
  user,password=self.pair();os.link(user,self.root/'alias');before=user.stat();self.binding.preflight(ENV);self.binding.resolve(ENV)
  self.assertEqual(user.stat().st_nlink,2);self.assertEqual(user.read_bytes(),b'file-user');self.assertTrue(any('LINK_COUNT_NOT_ONE' in r.get('previousGuardFailedPredicates',[]) for r in self.binding.public_metadata()['candidates']))
 def test_all_candidates_classified_before_any_content_when_oversize(self):
  self.pair();self.file('work/live-user',b'x'*4097);meta=self.binding.preflight(ENV)
  self.assertTrue(meta['policyBlocked']);self.assertEqual(len(self.binding.observed),9);self.assertEqual((self.binding.opened,self.binding.bytes),(0,0));self.assertTrue(any(r['source']=='ROOT_PASSWORD' and r['kind']=='REGULAR' for r in meta['candidates']))
 def test_selected_symlink_denied_without_following_it(self):
  self.pair();p=self.cwd/'live-user';p.unlink();p.symlink_to(self.file('real'))
  meta=self.binding.preflight(ENV);self.assertTrue(meta['policyBlocked']);self.assertTrue(any(r['kind']=='SYMLINK' for r in meta['candidates']));self.assertEqual(self.binding.bytes,0)
 def test_fifo_classified_without_io(self):
  self.pair();p=self.cwd/'live-user';p.unlink();os.mkfifo(p,0o600);meta=self.binding.preflight(ENV);self.assertTrue(meta['policyBlocked']);self.assertEqual(self.binding.opened,0)
 def test_missing_defaults_preserve_explicit_env(self):
  env={**ENV,'MINIO_ROOT_USER_FILE':'access_key','MINIO_ROOT_PASSWORD_FILE':'secret_key'};self.binding.preflight(env);self.assertEqual(self.binding.resolve(env)[0],[b'wrong-env-user',b'wrong-env-password'])
 def test_config_env_0644_is_literal_and_can_override(self):
  self.pair();self.file('work/config.env',b'MINIO_ROOT_USER=cfg-user\nMINIO_ROOT_PASSWORD=cfg-password\n',0o644);self.binding.preflight(ENV);self.assertEqual(self.binding.resolve(ENV)[0],[b'cfg-user',b'cfg-password'])
 def test_unused_directory_prefix_does_not_replace_cwd_file(self):
  self.pair();(self.root/'run/secrets/live-user').mkdir(parents=True);meta=self.binding.preflight(ENV);self.assertFalse(meta['policyBlocked']);self.assertEqual(self.binding.resolve(ENV)[0][0],b'file-user')
 def test_modified_input_is_denied_after_read(self):
  files=self.pair();self.binding.preflight(ENV);self.binding.resolve(ENV);files[0].write_bytes(b'changed')
  with self.assertRaises(Stop):self.binding.stable()
 def test_newly_appeared_candidate_is_denied(self):
  self.binding.preflight(ENV);self.file('work/live-user')
  with self.assertRaises(Stop):self.binding.resolve(ENV)
 def test_public_metadata_contains_no_path_or_value(self):
  import json
  self.pair();self.binding.preflight(ENV);self.binding.resolve(ENV);raw=json.dumps(self.binding.public_metadata());self.assertNotIn('live-user',raw);self.assertNotIn('file-password',raw);self.assertNotIn(str(self.root),raw)
