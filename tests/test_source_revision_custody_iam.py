import contextlib,hashlib,importlib.util,io,json,os,signal,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_source_revision_iam_resume as previous
import test_source_revision_iam_stop_read as old_read
import test_prepared_source_revision_delivery as delivery
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('custody_iam_resume','scripts/resume-source-revision-custody-iam-20261019.py');r=load('custody_iam_read','scripts/read-source-revision-custody-iam-stop-20261019.py')
class Administrative(unittest.TestCase):
 temp=previous.Resume.temp
 tearDown=previous.Resume.tearDown
 def admin_fixture(self,root):
  sock,original,iam=previous.Resume.admin_fixture(self,root);iam['stoppedClosureSha256']='a'*64;return sock,original,iam
 exercise_login=previous.Resume.exercise_login
 test_current_terminal_login_and_readback=previous.Resume.test_current_terminal_login_and_readback
 test_ambiguous_timeout_uses_one_get_without_repeating_login=previous.Resume.test_ambiguous_timeout_uses_one_get_without_repeating_login
 test_failed_readback_blocks_after_consuming_attempt=previous.Resume.test_failed_readback_blocks_after_consuming_attempt
 test_generation_change_blocks_before_login=previous.Resume.test_generation_change_blocks_before_login
 test_docker_drift_blocks_before_claim_or_login=previous.Resume.test_docker_drift_blocks_before_claim_or_login
 test_cancelled_login_retains_consumed_fence=previous.Resume.test_cancelled_login_retains_consumed_fence
 test_fence_exclusive_and_durable_even_without_completed_claim=previous.Resume.test_fence_exclusive_and_durable_even_without_completed_claim
 def setUp(self):self.p=patch.object(previous,'m',m);self.p.start();self.addCleanup(self.p.stop)
 def report(self):return {'executionReconciliation':{'contextClosureSha256':'a'*64,'authorityAndLoginArtifactsAbsent':True},'humanSession':{'attempts':188}}
 def test_reconcile_verify_one_login_reconcile_verify_then_fresh_process(self):
  events=[]
  with self.temp()as temp:
   code=Path(temp)
   with patch.object(m,'reconcile',side_effect=lambda:events.append('read')or self.report()),patch.object(m,'verify_prepared',side_effect=lambda profile:events.append('verify')or(code,b'pass',{})),patch.object(m,'admin_login',side_effect=lambda *args:events.append('IAM')),patch.object(m.os,'execv',side_effect=SystemExit(0))as process,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(SystemExit):m.run()
   self.assertEqual(events,['read','verify','IAM','read','verify']);argv=process.call_args.args[1];self.assertEqual(argv[:6],['/usr/bin/python3','-u','-I','-B','-S','-c']);self.assertEqual(argv[-2:], [m.PROFILE['executorSha256'],str(code/'execute.py')])
 def test_unknown_stop_never_reaches_password_and_changed_stop_never_hands_off(self):
  with patch.object(m,'reconcile',side_effect=ValueError('STOP_UNPROVEN')),patch.object(m,'admin_login')as login,self.assertRaises(ValueError):m.run()
  login.assert_not_called()
  with self.temp()as temp:
   before=self.report();after=self.report();after['executionReconciliation']['contextClosureSha256']='b'*64
   with patch.object(m,'reconcile',side_effect=[before,after]),patch.object(m,'verify_prepared',return_value=(Path(temp),b'pass',{})),patch.object(m,'admin_login')as login,patch.object(m.os,'execv')as process,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ValueError):m.run()
   self.assertEqual(login.call_count,1);process.assert_not_called()
 def test_verifier_reloads_retained_input_paths_and_never_executes_native_fixture(self):
  with self.temp()as temp:
   profile,_=delivery.PreparedDelivery().fixture(Path(temp));profile['retainedInputContext']=temp
   with contextlib.redirect_stdout(io.StringIO())as output:code,raw,original=m.verify_prepared(profile)
   self.assertEqual(original,{'secret':'CANARY'});self.assertNotIn('NATIVE_GATE_FIXTURE',output.getvalue());self.assertNotIn('CANARY',output.getvalue())
   (Path(temp)/'executor-code/member0.py').write_bytes(b'drift')
   with patch.object(m,'reconcile',return_value=self.report()),patch.object(m,'admin_login')as login,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(ValueError):m.run(profile)
   login.assert_not_called()
 def test_exact_reader_and_corrected_verifier_qualified_bytes_and_new_fence(self):
  import ast
  tree=ast.parse((ROOT/'scripts/prepare-source-revision-custody-continuation.py').read_text());source=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='VERIFIER_SOURCE'for t in n.targets)))
  self.assertTrue((ROOT/'scripts/resume-source-revision-custody-iam-20261019.py').read_text().startswith('"""One-use IAM recovery after protected kcw reconciliation; no new HUMAN login."""\n'+source))
  self.assertEqual(m.RECONCILIATION_SOURCE,(ROOT/'scripts/read-source-revision-custody-iam-stop-20261019.py').read_text());self.assertEqual(m.RECONCILIATION_SHA256,hashlib.sha256(m.RECONCILIATION_SOURCE.encode()).hexdigest());self.assertIn('kcw73ask',m.IAM_PROFILE['fenceDirectory']);self.assertNotIn('tvc2ilnv',m.IAM_PROFILE['fenceDirectory'])

class Read(unittest.TestCase):
 temp=previous.Resume.temp
 def tearDown(self):signal.alarm(0)
 def put(self,path,value):path.write_bytes(r.encoded(value));path.chmod(0o600)
 def test_original_nine_file_reconciler_still_rejects_authority_unknown_sources_and_drift(self):
  test=old_read.Files()
  with patch.object(old_read,'m',r):test.test_exact_nine_execution_files_and_refusal_of_unknown_authority_or_sources()
 def test_human_metadata_check_no_bearer_open_and_no_mutation(self):
  with self.temp()as temp:
   root=Path(temp);binding={'sessionDirectory':str(root),'expiresAt':time.time()+3600};row={'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'budgetReset':False,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'state':'READY','attempts':188,'monotonicDeadline':time.monotonic()+3600,'lastObservedAt':time.time(),'accessToken':'CREDENTIAL_CANARY'};self.put(root/'recovery.json',row);raw=(root/'recovery.json').read_bytes();case={'postbootResumedHuman':{'binding':binding,'minimumOAuthAttempts':188,'maximumCumulativeOAuthAttempts':256,'newLoginAllowed':False,'windowExtensionAllowed':False}}
   result=r.current_human(case);self.assertEqual(result['attempts'],188);self.assertNotIn('CANARY',json.dumps(result));self.assertEqual(raw,(root/'recovery.json').read_bytes());self.assertEqual(list(root.iterdir()),[root/'recovery.json'])
   for change,value in [('attempts',189),('state','BLOCKED'),('monotonicDeadline',time.monotonic()-1),('bootId','old')]:
    bad={**row,change:value};self.put(root/'recovery.json',bad)
    with self.assertRaises(ValueError):r.current_human(case)
 def test_prepared_all81_files_continuation_and_old_claim_without_executing_code(self):
  with self.temp()as temp:
   root=Path(temp);prepared=root/'capsule';prepared.mkdir(mode=0o700);profile,result=delivery.PreparedDelivery().fixture(prepared);code=prepared/'executor-code';package=json.loads((code/'package.json').read_bytes());case=json.loads((code/'case.json').read_bytes())
   old=root/'source-revision-execution-dvf517sr';old.mkdir(mode=0o700);journal={'version':0,'nextStage':0,'readinessAttempts':0,'cumulativeReadinessAttempts':0,'effects':[],'budgetReset':False,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'expiresAt':time.time()-1,'expiresMonotonic':time.monotonic()-1};self.put(old/'recovery.json',journal);jb={'path':str(old/'recovery.json'),'sha256':hashlib.sha256((old/'recovery.json').read_bytes()).hexdigest()};case['custodyContinuation']={'schema':'ouf.source-revision-mcp-custody-continuation.v1','scopeSuccessor':{'context':str(old),'journalBinding':jb}};self.put(prepared/'continuation-plan.json',{});cont=hashlib.sha256((prepared/'continuation-plan.json').read_bytes()).hexdigest();result['continuationPlanBinding']={'path':str(prepared/'continuation-plan.json'),'sha256':cont}
   names={'fixture.module'+str(i):'member'+str(i)+'.py'for i in range(77)}
   with patch.multiple(r,PREPARED=prepared,EXECUTOR=profile['executorSha256'],FROZEN_NAMES=names,CLOSURE=profile['sourceClosureSha256'],PLAN=profile['nativePlanSha256'],CONTINUATION=cont):
    before={str(p):p.read_bytes()for p in root.rglob('*')if p.is_file()};self.assertEqual(r.prepared_closure(result,case,package)['frozenFilesVerified'],81);self.assertEqual(before,{str(p):p.read_bytes()for p in root.rglob('*')if p.is_file()})
    self.put(old/'logical-successor.claim.json',{})
    with self.assertRaises(ValueError):r.prepared_closure(result,case,package)
    (old/'logical-successor.claim.json').unlink();(code/'member0.py').write_bytes(b'drift')
    with self.assertRaises(ValueError):r.prepared_closure(result,case,package)
 def test_reader_imports_no_subprocess_network_or_owner_execution(self):
  import ast
  tree=ast.parse((ROOT/'scripts/read-source-revision-custody-iam-stop-20261019.py').read_text());names={alias.name for node in tree.body if isinstance(node,ast.Import)for alias in node.names};self.assertEqual(names,{'hashlib','json','os','signal','stat','time'});self.assertEqual(r.STOPPED.name,'source-revision-execution-kcw73ask');self.assertEqual(r.RESULT,m.PROFILE['preparationResultSha256']);self.assertEqual(r.PACKAGE,m.PROFILE['packageSha256'])

class RootShim(unittest.TestCase):
 def exercise(self,tamper):
  import subprocess,sys
  text=(ROOT/'scripts/launch-source-revision-custody-iam-20261019.sh').read_text();payload=text.split("<<'OUF_HUMAN_HISTORY_READ' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_HUMAN_HISTORY_READ',1)[0]
  with tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])as temp:
   helper=Path(temp)/'helper.py';helper.write_bytes(b'print("PRIVATE_CANARY")'if tamper else(ROOT/'scripts/resume-source-revision-custody-iam-20261019.py').read_bytes())
   harness='''import os,sys,json
raw,helper=sys.argv[1:];protected=[]
def wrap(original):
 def checked(path,*args,**kwargs):
  if str(path).startswith('/etc/ouf/'):
   protected.append(str(path));raise RuntimeError('PRIVATE_CANARY')
  return original(path,*args,**kwargs)
 return checked
for name in ('stat','lstat','open'):setattr(os,name,wrap(getattr(os,name)))
sys.argv=['delivery',helper]
try:exec(compile(raw,'<exact-root-shim>','exec'),{'__name__':'__main__'})
except SystemExit as error:print(json.dumps({'fixtureExit':error.code,'protectedReadAttempts':len(protected)}))
'''
   result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,payload,str(helper)],capture_output=True,timeout=20);self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stderr,b'');self.assertNotIn(b'PRIVATE_CANARY',result.stdout);rows=[json.loads(line)for line in result.stdout.splitlines()];self.assertEqual(rows[-1]['protectedReadAttempts'],0 if tamper else 1)
   if not tamper:self.assertFalse(rows[0]['complete']);self.assertTrue(rows[0]['reconciliationRequired']);self.assertEqual(rows[-1]['fixtureExit'],2)
 def test_exact_shim_reaches_first_protected_read_only(self):self.exercise(False)
 def test_tampered_shim_stops_before_any_protected_read(self):self.exercise(True)
 def test_exact_helper_sha_and_git_blob_are_pinned_before_sudo(self):
  raw=(ROOT/'scripts/resume-source-revision-custody-iam-20261019.py').read_bytes();sha=hashlib.sha256(raw).hexdigest();blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest();launcher=(ROOT/'scripts/launch-source-revision-custody-iam-20261019.sh').read_text();self.assertEqual(launcher.count(sha),2);self.assertIn('/git/blobs/'+blob,launcher);self.assertNotIn('curl ',launcher)
