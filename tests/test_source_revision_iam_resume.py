import contextlib,hashlib,importlib.util,io,json,os,pty,signal,socket,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
import test_prepared_source_revision_delivery as old
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('resume',ROOT/'scripts/resume-source-revision-iam-20261019.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Resume(unittest.TestCase):
 def temp(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def tearDown(self):signal.alarm(0)
 def test_prepared_verification_preserves_fixture_and_never_executes_it(self):
  with self.temp()as temp:
   profile,result=old.PreparedDelivery().fixture(Path(temp));before={str(p):p.read_bytes()for p in Path(temp).rglob('*')if p.is_file()}
   with contextlib.redirect_stdout(io.StringIO())as output:code,raw,original=m.verify_prepared(profile)
   self.assertEqual(code,Path(temp)/'executor-code');self.assertNotIn('NATIVE_GATE_FIXTURE',output.getvalue());self.assertNotIn('CANARY',output.getvalue())
   self.assertEqual(before,{str(p):p.read_bytes()for p in Path(temp).rglob('*')if p.is_file()})
 def test_all_pinned_files_reject_before_admin_login(self):
  for name in ('postboot-preparation-result.json','prepared-plan.json','postboot-private-inputs.json','current-original-preparation.json','executor-code/case.json','executor-code/package.json','executor-code/execute.py','executor-code/runtime.py','executor-code/member0.py'):
   with self.subTest(name=name),self.temp()as temp:
    profile,_=old.PreparedDelivery().fixture(Path(temp));(Path(temp)/name).write_bytes(b'CANARY')
    with patch.object(m,'reconcile'),patch.object(m,'admin_login')as login,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ValueError):m.run(profile)
    login.assert_not_called()
 def test_reconciler_is_exact_qualified_reader_and_pins_observed_closure(self):
  self.assertEqual(m.RECONCILIATION_SOURCE,(ROOT/'scripts/read-source-revision-iam-stop-20261019.py').read_text())
  self.assertEqual(m.digest(m.RECONCILIATION_SOURCE.encode()),m.RECONCILIATION_SHA256)
  self.assertEqual(m.IAM_PROFILE['stoppedClosureSha256'],'e93fd92cae1105c6f5b69e617c5352d8324f65e5c3b13ac758a39dbc3e87a8bc')
  evidence=json.loads((ROOT/'evidence/source-revision-iam-stop-20261019.json').read_bytes());self.assertEqual(m.PROFILE['packageSha256'],evidence['packageSha256']);self.assertEqual(m.PROFILE['preparationResultSha256'],evidence['preparationResultSha256'])
  self.assertEqual(m.PROFILE['executorSha256'],m.digest((ROOT/'scripts/execute-source-revision-postboot.py').read_bytes()))
 def test_fence_exclusive_and_durable_even_without_completed_claim(self):
  with self.temp()as temp:
   directory=Path(temp)/'fence';m.reserve(directory,{'maximumLoginAttempts':1})
   self.assertEqual(json.loads(m.read(directory/'attempt.json',m.digest((directory/'attempt.json').read_bytes()))),{'maximumLoginAttempts':1})
   with self.assertRaises(FileExistsError):m.reserve(directory,{})
   (directory/'attempt.json').unlink()
   with self.assertRaises(FileExistsError):m.reserve(directory,{})
 def admin_fixture(self,root):
  binary=root/'docker';binary.write_bytes(b'FIXTURE_ONLY');binary.chmod(0o700)
  sock=socket.socket(socket.AF_UNIX);path=root/'engine.sock';sock.bind(str(path));path.chmod(0o600);st=path.lstat()
  original={'authorization':{'plan':{'selection':{'docker':{'path':str(binary),'sha256':m.digest(binary.read_bytes())},'keycloakContainer':'a'*64,'realm':'fixture'}}},'engine':{'socketPath':str(path),'socketBinding':[st.st_dev,st.st_ino,st.st_uid,st.st_gid,st.st_mode&0o777]}}
  iam={**m.IAM_PROFILE,'fenceDirectory':str(root/'fence')};return sock,original,iam
 def exercise_login(self,kind):
  with self.temp()as temp:
   sock,original,iam=self.admin_fixture(Path(temp));master,terminal=pty.openpty();realopen=os.open;calls=[];state={'Running':True,'Pid':123,'StartedAt':'fixture-generation'};inspections=0
   def opener(path,*args,**kwargs):return os.dup(terminal)if path=='/dev/tty'else realopen(path,*args,**kwargs)
   def observe(argv,env):
    nonlocal inspections
    calls.append(argv)
    if 'inspect'in argv:
     inspections+=1
     return {**state,'Pid':124}if kind=='generation'and inspections>1 else state
    if kind=='unproven':raise ValueError('GET_UNPROVEN')
    return [{'id':'fixture','name':'scope'}]
   login=Mock(return_value=Mock(returncode=0))
   if kind=='timeout':login.side_effect=subprocess.TimeoutExpired('fixture',300)
   if kind=='cancel':login.side_effect=KeyboardInterrupt()
   if kind=='binary':Path(original['authorization']['plan']['selection']['docker']['path']).write_bytes(b'drift')
   before_env=dict(os.environ)
   try:
    with patch.object(m.os,'open',side_effect=opener),patch.object(m,'bounded_read',side_effect=observe),patch.object(m.subprocess,'run',login),contextlib.redirect_stdout(io.StringIO())as out:
     if kind in ('unproven','generation','binary'):
      with self.assertRaises(ValueError):m.admin_login(original,m.PROFILE,iam)
     elif kind=='cancel':
      with self.assertRaises(KeyboardInterrupt):m.admin_login(original,m.PROFILE,iam)
     else:m.admin_login(original,m.PROFILE,iam)
     self.assertNotIn('FIXTURE_ONLY',out.getvalue())
    count=0 if kind in ('binary','generation')else 1;self.assertEqual(login.call_count,count)
    if kind!='binary':
     self.assertTrue((Path(iam['fenceDirectory'])/'attempt.json').is_file())
     with patch.object(m.os,'open',side_effect=opener),patch.object(m,'bounded_read',side_effect=lambda *args:state),patch.object(m.subprocess,'run')as again,self.assertRaises(FileExistsError):m.admin_login(original,m.PROFILE,iam)
     again.assert_not_called()
    if kind in ('ok','timeout','unproven'):self.assertEqual(sum('client-scopes'in c for c in calls),1)
    if count:
     argv=login.call_args.args[0];self.assertIn('-it',argv);self.assertIn('master',argv);self.assertNotIn('--password',argv)
     self.assertEqual(login.call_args.kwargs['stdin'],login.call_args.kwargs['stdout']);self.assertEqual(login.call_args.kwargs['stdout'],login.call_args.kwargs['stderr'])
   finally:os.environ.clear();os.environ.update(before_env);os.close(master);os.close(terminal);sock.close()
 def test_current_terminal_login_and_readback(self):self.exercise_login('ok')
 def test_ambiguous_timeout_uses_one_get_without_repeating_login(self):self.exercise_login('timeout')
 def test_failed_readback_blocks_after_consuming_attempt(self):self.exercise_login('unproven')
 def test_generation_change_blocks_before_login(self):self.exercise_login('generation')
 def test_docker_drift_blocks_before_claim_or_login(self):self.exercise_login('binary')
 def test_cancelled_login_retains_consumed_fence(self):self.exercise_login('cancel')
 def test_order_revalidates_then_reaches_only_native_fixture(self):
  events=[]
  with self.temp()as temp:
   code=Path(temp);raw=b'raise SystemExit(0)'
   with patch.object(m,'reconcile',side_effect=lambda:events.append('reconcile')),patch.object(m,'verify_prepared',side_effect=lambda profile:(events.append('verify')or(code,raw,{}))),patch.object(m,'admin_login',side_effect=lambda *args:events.append('admin')),self.assertRaises(SystemExit)as stopped:m.run(m.PROFILE)
   self.assertEqual(stopped.exception.code,0);self.assertEqual(events,['reconcile','verify','admin','reconcile','verify'])
if __name__=='__main__':unittest.main()
