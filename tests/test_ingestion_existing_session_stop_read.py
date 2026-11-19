"""Read-only bootstrap boundary, custody failures and secret-safe diagnostics."""
import ast,base64,hashlib,importlib.util,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/read-ingestion-existing-session-stop.py'
BOOT=ROOT/'scripts/execute-ingestion-read-authorization.py'
RUNTIME=ROOT/'tools/ingestion_read_authorization/runtime.py'
if not SCRIPT.exists():
 SCRIPT=Path(__file__).with_name('read-ingestion-existing-session-stop.py')
 BOOT=Path(__file__).parents[1]/'repo/scripts/execute-ingestion-read-authorization.py'
 RUNTIME=Path(__file__).parents[1]/'repo/tools/ingestion_read_authorization/runtime.py'
spec=importlib.util.spec_from_file_location('readonly_child',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Boundaries(unittest.TestCase):
 def test_exact_native_bootstrap_hash_and_before_claim_boundary(self):
  raw=BOOT.read_bytes();self.assertEqual(m.sha(raw),m.BOOTSTRAP)
  _,line=m.bootstrap_prefix(raw);self.assertEqual(line,52)
  tree=ast.parse(raw);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main')
  self.assertTrue(any(n.lineno==line for n in fn.body))
 def test_changed_claim_boundary_and_added_effect_dispatch_rejected(self):
  raw=BOOT.read_text()
  for changed in (raw.replace("context/'runtime.claim.json'","context/'other.claim.json'"),
    raw.replace("    package=read(context/", "    entry.main()\n    package=read(context/",1)):
   with self.assertRaises(m.ReadDenied):m.bootstrap_prefix(changed.encode())
 def test_audit_rejects_writes_network_processes_keys_and_human_credentials(self):
  for flags in (os.O_WRONLY,os.O_RDWR,os.O_CREAT,os.O_TRUNC,os.O_APPEND):
   with self.assertRaises(m.ReadDenied):m.audit('open',('/fixture/member',None,flags))
  for event in m.DENIED:
   with self.assertRaises(m.ReadDenied):m.audit(event,())
  for path in ('/fixture/human-access.jwt','/fixture/signing.pem','/fixture/human-successor/recovery.json',
    '/fixture/human-successor/invocation.lock','/fixture/key.key'):
   with self.assertRaises(m.ReadDenied):m.audit('open',(path,None,os.O_RDONLY))
  m.audit('open',('/fixture/login-review.json',None,os.O_RDONLY))
  m.audit('open',('/fixture/authorization/recovery.json',None,os.O_RDONLY))
 def test_safe_failure_only_exposes_verified_literal_codes_and_code_locations(self):
  for secret in ('PRIVATE_TOKEN_CANARY','UPPERCASE_PASSWORD_VALUE'):
   error=ValueError(secret);result=m.safe_failure(error,{'PRIVATE_BYTES_CHANGED'},set())
   self.assertEqual(result['reasonCode'],'PRIVATE_DETAILS_REDACTED');self.assertNotIn(secret,json.dumps(result))
  self.assertEqual(m.safe_failure(ValueError('PRIVATE_BYTES_CHANGED'),{'PRIVATE_BYTES_CHANGED'},set())['reasonCode'],'PRIVATE_BYTES_CHANGED')
 def test_no_human_session_refresh_login_authority_or_owner_mutation_in_diagnostic(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(any(c.endswith(('.refresh_if_due','.authenticate','.issue_action','.observe','.current','.start_refresh'))for c in calls))
  self.assertNotIn('entry.main',calls);self.assertNotIn('entry.authority.closure_valid',calls)

class NativePrefix(unittest.TestCase):
 def fixture(self):
  temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(temp.cleanup)
  root=Path(temp.name);root.chmod(0o700);context=root/'ingestion-read-authorization-execution-abcdefgh';context.mkdir(mode=0o700)
  loader=RUNTIME.read_bytes();ns={'__name__':'qualified_closed_loader'};exec(compile(loader,str(RUNTIME),'exec'),ns)
  sources={name:b'pass\n'for name in ns['MODULES']};sources[ns['ENTRY']]=b'MARKER="CLOSED_ENTRY_IMPORTED"\n'
  case={'sourceId':'fixture'};boot=BOOT.read_bytes();pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40}
  execution={'executorSha256':m.sha(boot),'caseSha256':m.digest(case),'mode':'INGESTION_READ_AUTHORIZATION'}
  declaration=ns['declaration']('a'*40,sources,loader,pins,execution)
  members={'case.json':m.encoded(case),'bootstrap.py':boot,'runtime.py':loader,'reader.py':b'pass\n',
   'sources.json':m.encoded({n:base64.b64encode(v).decode()for n,v in sources.items()})}
  package={'schema':'ouf.ingestion-read-administrative-package.v1','runtimeAuthorityIssued':False,
   'fileHashes':{n:m.sha(v)for n,v in members.items()},'sourceCommit':'a'*40,'executionPins':execution,
   'sourcePins':pins,'declarationHash':m.digest(declaration),'closure':{'declaration':declaration}}
  for name,raw in {**members,'package.json':m.encoded(package)}.items():
   path=context/name;path.write_bytes(raw);path.chmod(0o600)
  return root,context,package
 def probe(self,root,context,package):
  harness='''import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('reader',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root,context=Path(sys.argv[2]),Path(sys.argv[3]);raw=(context/'bootstrap.py').read_bytes()
program,line=m.bootstrap_prefix(raw);namespace={'__name__':'qualified_native_definitions','__file__':str(context/'bootstrap.py')}
exec(compile(raw,'<verified-native-bootstrap-definitions>','exec'),namespace)
namespace['Path']=lambda p:root if str(p)=='/etc/ouf/deploy-snapshots'else Path(p)
exec(program,namespace);sys.addaudithook(m.audit)
try:
 result=namespace['probe_bootstrap_readonly'](str(context),sys.argv[4])
 print(json.dumps({'passed':True,'moduleCount':len(result['sources']),'marker':result['entry'].MARKER,'claimPresent':(context/'runtime.claim.json').exists()}))
except Exception as error:print(json.dumps({'passed':False,'failure':m.safe_failure(error,m.public_codes(raw),set())}))
'''
  result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,str(SCRIPT),str(root),str(context),m.digest(package)],capture_output=True,timeout=30)
  self.assertEqual(result.returncode,0,result.stderr.decode());return json.loads(result.stdout)
 def test_exact_closed_181_module_bootstrap_prefix_never_writes_runtime_claim(self):
  root,context,package=self.fixture();result=self.probe(root,context,package)
  self.assertEqual(result,{'passed':True,'moduleCount':181,'marker':'CLOSED_ENTRY_IMPORTED','claimPresent':False})
  self.assertFalse((context/'runtime.claim.json').exists())
 def test_case_hash_failure_is_reproduced_with_safe_bootstrap_line_and_no_claim(self):
  root,context,package=self.fixture();(context/'case.json').write_bytes(b'{"private":"PRIVATE_CANARY"}')
  result=self.probe(root,context,package);self.assertFalse(result['passed'])
  self.assertEqual(result['failure']['reasonCode'],'PRIVATE_BYTES_CHANGED')
  self.assertEqual(result['failure']['codeUnit'],'BOOTSTRAP_HELPERS');self.assertIsInstance(result['failure']['line'],int)
  self.assertNotIn('PRIVATE_CANARY',json.dumps(result));self.assertFalse((context/'runtime.claim.json').exists())
 def test_original_existing_runtime_claim_is_preserved(self):
  root,context,package=self.fixture();path=context/'runtime.claim.json';path.write_bytes(b'consumed');path.chmod(0o600)
  result=self.probe(root,context,package);self.assertTrue(result['passed']);self.assertTrue(result['claimPresent'])
  self.assertEqual(path.read_bytes(),b'consumed')
if __name__=='__main__':unittest.main()
