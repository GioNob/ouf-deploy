"""Configured PostgreSQL secret custody and sanitized bootstrap failures."""
import ast,copy,importlib.util,json,os,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit,unquote
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.semantic_mcp_update import entry as m

class Channel(unittest.TestCase):
 def test_explicit_environment_preserves_reserved_characters(self):
  value='synthetic:p@ss/word \ninside'
  self.assertEqual(m.configured_admin_password({'Mounts':[]},{'POSTGRES_PASSWORD':value}),value)
 def test_no_fallback_or_ambiguous_credential_channels(self):
  for values in ({},{'POSTGRES_PASSWORD':''},{'POSTGRES_PASSWORD':'synthetic','POSTGRES_PASSWORD_FILE':'/run/secrets/password'}):
   with self.assertRaises(m.UpdateDenied):m.configured_admin_password({'Mounts':[]},values)
 def test_file_must_be_explicit_absolute_and_mounted_read_only(self):
  for path in ('relative','/run/../secret','/run//secret','/run/./secret','/run/secret\n'):
   with self.assertRaises(m.UpdateDenied):m.configured_admin_password({'Mounts':[]},{'POSTGRES_PASSWORD_FILE':path})
  for mounts in ([],[{'Destination':'/run/secrets','Source':'/unused','Type':'bind','RW':True}],
   [{'Destination':'/run/secrets','Source':'/unused','Type':'volume','RW':False}]):
   with self.assertRaises(m.UpdateDenied):m.configured_admin_password({'Mounts':mounts},{'POSTGRES_PASSWORD_FILE':'/run/secrets/password'})
 def test_same_selected_database_and_generation_guard(self):
  actual={'State':{'Running':True},'Config':{'Env':['POSTGRES_USER=administrator','POSTGRES_PASSWORD=synthetic:@/ pass']},'Mounts':[]}
  pin={'containerId':'fixture-pg'}
  review={'database':{'postgresRuntimeBinding':pin,'backupReader':'administrator','binding':{'database':'fixture_db'}},
   'oldNativeConfig':{'Env':['MCP_DATABASE_URL=postgresql://application:old@pg.fixture:5432/fixture_db?sslmode=disable']}}
  class Engine:
   def __init__(self):self.calls=[]
   def request(self,method,path):self.calls.append((method,path));return 200,copy.deepcopy(actual)
  e=Engine()
  with patch.object(m.Engine,'runtime_binding',return_value=pin):url=m.admin_database_url(review,e)
  parsed=urlsplit(url);self.assertEqual(unquote(parsed.password),'synthetic:@/ pass');self.assertEqual(parsed.hostname,'pg.fixture')
  self.assertEqual(parsed.port,5432);self.assertEqual(parsed.path,'/fixture_db');self.assertEqual(parsed.query,'sslmode=disable')
  self.assertEqual(len(e.calls),2)
  with patch.object(m.Engine,'runtime_binding',side_effect=[pin,{'containerId':'changed'}]):
   with self.assertRaisesRegex(m.UpdateDenied,'POSTGRES_CHANGED'):m.admin_database_url(review,Engine())

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1' and os.geteuid()==0,'native root filesystem custody')
class NativeSecret(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT','/root'));self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.secret=self.root/'password';self.secret.write_bytes(b'synthetic:@/ secret\n\n');self.secret.chmod(0o440)
  self.actual={'Mounts':[{'Destination':'/run/secrets/password','Source':str(self.secret),'Type':'bind','RW':False}]}
  self.values={'POSTGRES_PASSWORD_FILE':'/run/secrets/password'}
 def test_file_mount_and_directory_mount_match_postgres_newline_semantics(self):
  self.assertEqual(m.configured_admin_password(self.actual,self.values),'synthetic:@/ secret')
  self.actual['Mounts'][0].update(Destination='/run/secrets',Source=str(self.root))
  self.assertEqual(m.configured_admin_password(self.actual,self.values),'synthetic:@/ secret')
 def test_symlink_hardlink_world_readable_and_empty_rejected(self):
  self.secret.chmod(0o644)
  with self.assertRaises(m.UpdateDenied):m.configured_admin_password(self.actual,self.values)
  self.secret.chmod(0o440);os.link(self.secret,self.root/'hardlink')
  with self.assertRaises(m.UpdateDenied):m.configured_admin_password(self.actual,self.values)
  (self.root/'hardlink').unlink();self.secret.unlink();self.secret.symlink_to(self.root/'other')
  with self.assertRaises(OSError):m.configured_admin_password(self.actual,self.values)
  self.secret.unlink();self.secret.write_bytes(b'\n\n');self.secret.chmod(0o400)
  with self.assertRaisesRegex(m.UpdateDenied,'NONEMPTY_ADMIN_SECRET'):m.configured_admin_password(self.actual,self.values)
 def test_file_swap_during_read_is_rejected(self):
  real_read=os.read;swapped=False
  def changing(fd,size):
   nonlocal swapped
   result=real_read(fd,size)
   if not swapped:
    swapped=True;self.secret.unlink();self.secret.write_bytes(b'different synthetic secret');self.secret.chmod(0o440)
   return result
  with patch.object(m.os,'read',side_effect=changing):
   with self.assertRaisesRegex(m.UpdateDenied,'ADMIN_SECRET_CHANGED'):m.configured_admin_password(self.actual,self.values)

class BootstrapFailure(unittest.TestCase):
 def test_actual_main_exception_handler_reports_stop_without_secondary_error_or_private_values(self):
  source=(ROOT/'scripts/execute-semantic-mcp-scoped-20261017.py').read_text();tree=ast.parse(source)
  guard=tree.body[-1];self.assertIsInstance(guard,ast.If)
  for reason,expected in [('EXISTING_EXPLICIT_ADMIN_CREDENTIAL_CHANNEL_REQUIRED','EXISTING_EXPLICIT_ADMIN_CREDENTIAL_CHANNEL_REQUIRED'),
   ('synthetic private / value','LOCAL_EXECUTION_UNPROVEN')]:
   output=[]
   def main():raise m.UpdateDenied(reason)
   ns={'main':main,'sys':sys,'re':__import__('re'),'emit':lambda check,**row:output.append((check,row))}
   with self.assertRaises(SystemExit)as exit:exec(compile(ast.Module(body=guard.body,type_ignores=[]),'<actual-bootstrap-handler>','exec'),ns)
   self.assertEqual(exit.exception.code,2);self.assertEqual(output[0][0],'STOP');self.assertEqual(output[0][1]['reason'],expected)
   self.assertNotIn('synthetic private',str(output));self.assertFalse(output[0][1]['exceptionMessagePrinted'])
if __name__=='__main__':unittest.main()
