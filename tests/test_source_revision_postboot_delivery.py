"""Exact pinned delivery validation; target protected reads are denied by fixture."""
import contextlib,hashlib,importlib.util,io,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
COMMIT='32f86add5b6fb1b17110ca916ed045b28a240c5e'
class Delivery(unittest.TestCase):
 def exercise(self,change):
  spec=importlib.util.spec_from_file_location('stage',ROOT/'scripts/stage-source-revision-postboot.py')
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent))) as temp:
   directory=Path(temp)/'stage'
   with contextlib.redirect_stdout(io.StringIO()):m.stage(ROOT,directory,COMMIT)
   self.assertEqual(hashlib.sha256((directory/'manifest.json').read_bytes()).hexdigest(),'345999734e39e5e1bae941ba41d7c6825d71459f444d2febd98e02cd2ff479fb')
   if change in ('entry','login'):(directory/(change+'.py')).write_bytes(b'PRIVATE_CANARY')
   if change=='manifest':(directory/'manifest.json').write_bytes(b'PRIVATE_CANARY')
   if change=='configuration':(directory/'configuration.py').write_bytes(b'PRIVATE_CANARY')
   if change=='member':(directory/'prepare.py').write_bytes(b'PRIVATE_CANARY')
   if change=='link':(directory/'run.py').unlink();(directory/'run.py').symlink_to(directory/'reader.py')
   text=(ROOT/'scripts/launch-source-revision-postboot-human-20261019.sh').read_text()
   payload=text.split("<<'OUF_POSTBOOT_PREPARATION' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_POSTBOOT_PREPARATION',1)[0]
   code='''import os,sys,json
source=sys.argv[1];stage=sys.argv[2];raw=open(source).read();actual_open=os.open;actual_stat=os.stat;protected=[]
def guarded(path,*args,**kwargs):
 if str(path).startswith('/etc/ouf/'):
  protected.append(str(path));raise FileNotFoundError('PRIVATE_CANARY')
 return actual_open(path,*args,**kwargs)
def guarded_stat(path,*args,**kwargs):
 if str(path).startswith('/etc/ouf/'):
  protected.append(str(path));raise RuntimeError('PRIVATE_CANARY')
 return actual_stat(path,*args,**kwargs)
os.open=guarded;os.stat=guarded_stat;sys.argv=['delivery',stage]
try:exec(compile(raw,'<delivery-test>','exec'),{'__name__':'__main__'})
except SystemExit as error:print(json.dumps({'fixtureExit':error.code,'protectedReadAttempts':len(protected)}))
'''
   script=Path(temp)/'delivery.py';script.write_text(payload)
   result=subprocess.run([sys.executable,'-I','-B','-S','-c',code,str(script),str(directory)],capture_output=True,timeout=20)
   self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stderr,b'')
   self.assertNotIn(b'PRIVATE_CANARY',result.stdout)
   rows=[json.loads(line) for line in result.stdout.splitlines()]
   self.assertEqual(rows[-1],{'fixtureExit':2,'protectedReadAttempts':0 if change else 1},result.stdout.decode())
   self.assertFalse(rows[-2]['complete']);self.assertFalse(rows[-2]['runtimeAuthorityIssued'])
 def test_exact_payload_reaches_only_first_protected_read_and_redacts_error(self):self.exercise(None)
 def test_changed_manifest_stops_before_protected_reads(self):self.exercise('manifest')
 def test_changed_module_stops_before_protected_reads(self):self.exercise('member')
 def test_changed_configuration_successor_stops_before_protected_reads(self):self.exercise('configuration')
 def test_changed_entry_successor_stops_before_protected_reads(self):self.exercise('entry')
 def test_changed_login_successor_stops_before_protected_reads(self):self.exercise('login')
 def test_linked_dispatcher_stops_before_protected_reads(self):self.exercise('link')
if __name__=='__main__':unittest.main()
