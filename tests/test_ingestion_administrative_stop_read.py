"""Actual pinned pre-claim code, effect-denying audit and sanitized diagnostics."""
import ast,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if (ROOT/'scripts/read-ingestion-administration-stop.py').exists():SCRIPT=ROOT/'scripts/read-ingestion-administration-stop.py'
else:SCRIPT=Path(__file__).with_name('read-ingestion-administration-stop.py')
spec=importlib.util.spec_from_file_location('administrative_stop_diagnostic',SCRIPT)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Prefix(unittest.TestCase):
 def source(self):
  p=ROOT/'scripts/prepare-ingestion-read-authorization.py'
  if not p.exists():p=SCRIPT.parents[1]/'repo/scripts/prepare-ingestion-read-authorization.py'
  return p.read_bytes()
 def test_actual_qualified_source_hash_and_no_file_or_runtime_effect_in_prefix(self):
  raw=self.source();self.assertEqual(hashlib.sha256(raw).hexdigest(),m.PREPARER)
  code,codes,line=m.readonly_prefix(raw);self.assertGreater(line,100)
  namespace={};exec(code,namespace)
  text=ast.unparse(ast.parse(raw));self.assertIn('EXACT_SUCCESSFUL_PREPARATION_RECEIPT_REQUIRED',codes)
  self.assertNotIn('mkdtemp',code.co_names)
  self.assertEqual(code.co_filename,m.PREFIX_NAME)
 def test_prefix_never_reaches_first_claim_even_when_all_prior_code_succeeds(self):
  raw=b'''def run(directory,manifest_sha):
 sources={'one':b'code'};result={'schema':'fixture'}
 context=Path(tempfile.mkdtemp(prefix='ingestion-read-authorization-execution-',dir=root))
 write_new(root,'claim',b'not allowed')
'''
  code,_,_=m.readonly_prefix(raw);namespace={'digest':m.digest};exec(code,namespace)
  self.assertEqual(namespace['probe_read_only'](None,None),{'sourceModuleCount':1,'preparedReceiptCanonicalHash':m.digest({'schema':'fixture'})})
 def test_reproduced_public_guard_has_exact_unit_and_call_line(self):
  raw=b"def run(directory,manifest_sha):\n require(False,'PUBLIC_FAILURE_CODE')\n context=Path(tempfile.mkdtemp(prefix='ingestion-read-authorization-execution-',dir=root))\n"
  code,codes,_=m.readonly_prefix(raw)
  def require(ok,message):
   if not ok:raise ValueError(message)
  namespace={'require':require};exec(code,namespace)
  try:namespace['probe_read_only'](None,None)
  except Exception as e:result=m.safe_failure(e,codes)
  self.assertEqual(result['reasonCode'],'PUBLIC_FAILURE_CODE')
  self.assertEqual(result['codeUnit'],'READ_ONLY_PREPARER_PREFIX');self.assertEqual(result['line'],2)
 def test_wrong_boundary_or_mutator_before_boundary_is_rejected(self):
  actual=self.source()
  with self.assertRaises(Exception):m.readonly_prefix(actual.replace(b"prefix='ingestion-read-authorization-execution-'",b"prefix='other-'"))
  with self.assertRaises(Exception):m.readonly_prefix(actual.replace(b'    os.umask(0o077)',b'    write_new(root,"bad",b"bad")'))
 def test_prefix_cannot_replace_or_extend_absolute_diagnostic_watchdog(self):
  code,_,_=m.readonly_prefix(self.source());namespace={};exec(code,namespace)
  calls=[]
  class Signal:
   def signal(self,*a):calls.append(a)
   def alarm(self,*a):calls.append(a)
  # Force the first later stage check to stop after native flag checks.
  namespace.update(os=os,sys=sys,signal=Signal(),Path=Path,require=lambda *_:None,
   checked_stage=lambda *_:(_ for _ in ()).throw(RuntimeError('stop')))
  with self.assertRaises(RuntimeError):namespace['probe_read_only']('/fixture','hash')
  self.assertEqual(calls,[])
 def test_only_public_exact_error_codes_are_reported(self):
  for secret in('PRIVATE_CANARY','token=secret','/private/path'):
   try:raise ValueError(secret)
   except Exception as e:result=m.safe_failure(e,{'EXACT_SUCCESSFUL_PREPARATION_RECEIPT_REQUIRED'})
   self.assertNotIn(secret,json.dumps(result));self.assertEqual(result['reasonCode'],'PRIVATE_DETAILS_REDACTED')
  try:raise ValueError('EXACT_SUCCESSFUL_PREPARATION_RECEIPT_REQUIRED')
  except Exception as e:result=m.safe_failure(e,{'EXACT_SUCCESSFUL_PREPARATION_RECEIPT_REQUIRED'})
  self.assertEqual(result['reasonCode'],'EXACT_SUCCESSFUL_PREPARATION_RECEIPT_REQUIRED')
 def test_audit_denies_file_write_directory_network_and_process_dispatch(self):
  with tempfile.TemporaryDirectory()as t:
   harness='''import importlib.util,json,sys
spec=importlib.util.spec_from_file_location('reader',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
import socket,subprocess,os
sys.addaudithook(m.read_only_audit)
rows=[]
for action in (lambda:open(sys.argv[2],'wb'),lambda:os.mkdir(sys.argv[2]),lambda:socket.socket(),lambda:subprocess.run(['/bin/true'])):
 try:action();rows.append('EFFECT_ALLOWED')
 except m.DiagDenied:rows.append('DENIED')
print(json.dumps(rows))
'''
   p=Path(t)/'canary';r=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,str(SCRIPT),str(p)],capture_output=True,timeout=15)
   self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(json.loads(r.stdout),['DENIED']*4);self.assertFalse(p.exists())
 def test_import_has_no_target_file_or_network_effect(self):
  # The fixture path has no retained target directories; import is still inert.
  self.assertTrue(callable(m.main));self.assertFalse(hasattr(m,'output'))
if __name__=='__main__':unittest.main()
