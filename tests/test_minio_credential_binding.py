import json,os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).parents[1];sys.path.insert(0,str(ROOT))
from tools.storage_migration.minio_credential_binding import Binding
from tools.m2_discovery_installation_profile.custody_capture import Stop
ENV={'MINIO_ROOT_USER':'explicit-user','MINIO_ROOT_PASSWORD':'explicit-password','MINIO_ACCESS_KEY_FILE':'access_key','MINIO_SECRET_KEY_FILE':'secret_key','MINIO_ROOT_USER_FILE':'access_key','MINIO_ROOT_PASSWORD_FILE':'secret_key','MINIO_CONFIG_ENV_FILE':'config.env'}
@unittest.skipUnless(os.geteuid()==0,'root-owned credential fixture')
class CredentialTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir='/root' if os.environ.get('GITHUB_ACTIONS')=='true' else ROOT);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.cwd=self.root/'work';self.cwd.mkdir(mode=0o700)
  a=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY);b=os.open(self.cwd,os.O_RDONLY|os.O_DIRECTORY)
  try:self.binding=Binding(0,a,b)
  finally:os.close(a);os.close(b)
  self.addCleanup(self.binding.close)
 def file(self,name,value):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value);p.chmod(0o600);return p
 def test_image_defaults_missing_keep_explicit_values(self):
  values,meta=self.binding.resolve(ENV);self.assertEqual(values,[b'explicit-user',b'explicit-password']);self.assertEqual(meta['secretFilesOpened'],0)
 def test_relative_run_secrets_override_explicit_env(self):
  self.file('run/secrets/access_key',b'file-user\n');self.file('run/secrets/secret_key',b'file-password\n')
  values,meta=self.binding.resolve(ENV);self.assertEqual(values,[b'file-user',b'file-password']);self.assertEqual(meta['secretFilesOpened'],2)
 def test_relative_cwd_fallback(self):
  self.file('work/access_key',b'cwd-user');self.file('work/secret_key',b'cwd-password');self.assertEqual(self.binding.resolve(ENV)[0],[b'cwd-user',b'cwd-password'])
 def test_absolute_reference(self):
  self.file('keys/user',b'absolute-user');self.file('keys/password',b'absolute-password')
  self.assertEqual(self.binding.resolve({'MINIO_ROOT_USER_FILE':'/keys/user','MINIO_ROOT_PASSWORD_FILE':'/keys/password'})[0],[b'absolute-user',b'absolute-password'])
 def test_vendor_prefixed_candidate_precedes_absolute_fallback(self):
  self.file('keys/user',b'fallback-user');self.file('run/secrets/keys/user',b'prefixed-user');self.file('keys/password',b'absolute-password')
  self.assertEqual(self.binding.resolve({'MINIO_ROOT_USER_FILE':'/keys/user','MINIO_ROOT_PASSWORD_FILE':'/keys/password'})[0][0],b'prefixed-user')
 def test_current_files_override_legacy_files(self):
  self.file('run/secrets/legacy',b'legacy-user');self.file('run/secrets/current',b'current-user')
  self.assertEqual(self.binding.resolve({**ENV,'MINIO_ACCESS_KEY_FILE':'legacy','MINIO_ROOT_USER_FILE':'current'})[0][0],b'current-user')
 def test_config_last_wins_quotes_comments_region(self):
  self.file('run/secrets/access_key',b'file-user');self.file('work/config.env',b'# comment\nexport MINIO_ROOT_USER="config-user"\nMINIO_ROOT_PASSWORD=old\nMINIO_ROOT_PASSWORD=\'final password\'\nMINIO_REGION_NAME=custom-region\n')
  values,meta=self.binding.resolve(ENV);self.assertEqual(values,[b'config-user',b'final password']);self.assertEqual(self.binding.region,'custom-region');self.assertNotIn('config-user',json.dumps(meta))
 def test_config_is_literal_not_shell_code(self):
  self.file('work/config.env',b'MINIO_ROOT_PASSWORD=$(touch should-not-exist)\n');self.assertEqual(self.binding.resolve(ENV)[0][1],b'$(touch should-not-exist)');self.assertFalse((self.cwd/'should-not-exist').exists())
 def test_empty_file_does_not_override(self):
  self.file('run/secrets/access_key',b'');self.assertEqual(self.binding.resolve(ENV)[0][0],b'explicit-user')
 def test_changed_file_is_denied(self):
  p=self.file('run/secrets/access_key',b'file-user');self.binding.resolve(ENV);p.write_bytes(b'changed-user')
  with self.assertRaises(Stop):self.binding.stable()
 def test_appeared_default_file_is_denied(self):
  self.binding.resolve(ENV);self.file('run/secrets/access_key',b'appeared-user')
  with self.assertRaises(Stop):self.binding.stable()
 def test_symlink_is_denied_without_fallback(self):
  p=self.file('keys/real',b'synthetic');(self.cwd/'access_key').symlink_to(p)
  with self.assertRaises(Stop):self.binding.resolve(ENV)
 def test_fifo_is_denied_without_open_for_io(self):
  os.mkfifo(self.cwd/'access_key',0o600)
  with self.assertRaises(Stop):self.binding.resolve(ENV)
  self.assertEqual(self.binding.opened,0)
 def test_public_secret_mode_is_denied(self):
  p=self.file('run/secrets/access_key',b'synthetic');p.chmod(0o644)
  with self.assertRaises(Stop):self.binding.resolve(ENV)
 def test_sdk_would_change_boundary_whitespace_is_denied(self):
  with self.assertRaises(Stop):self.binding.resolve({**ENV,'MINIO_ROOT_PASSWORD':' password '})
 def test_partial_root_pair_does_not_fall_back_to_legacy(self):
  with self.assertRaises(Stop):self.binding.resolve({'MINIO_ROOT_USER':'root','MINIO_ACCESS_KEY':'legacy','MINIO_SECRET_KEY':'legacy-password'})
 def test_traversal_and_noncanonical_references_denied(self):
  for name in ['../key','./key','keys//key','//keys/key']:
   with self.assertRaises(Stop):self.binding.resolve({**ENV,'MINIO_ROOT_USER_FILE':name})
 def test_oversize_file_is_denied(self):
  self.file('run/secrets/access_key',b'a'*4097)
  with self.assertRaises(Stop):self.binding.resolve(ENV)
 def test_file_unicode_whitespace_matches_go_trimspace(self):
  self.file('run/secrets/access_key','\u00a0file-user\u3000'.encode());self.assertEqual(self.binding.resolve(ENV)[0][0],b'file-user')
 def test_env_unicode_whitespace_would_be_changed_by_sdk_is_denied(self):
  with self.assertRaises(Stop):self.binding.resolve({**ENV,'MINIO_ROOT_PASSWORD':'\u00a0password'})
