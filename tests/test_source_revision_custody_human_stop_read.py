import ast,copy,hashlib,importlib.util,json,os,signal,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_source_revision_human_binding_stop_read as old
import test_source_revision_iam_stop_read as old_files
import test_source_revision_custody_iam as prepared_fixture
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('custody_human_read',ROOT/'scripts/read-source-revision-custody-human-stop-20261019.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
HUMAN=(ROOT/'tools/csv_materialization_recovery/human_session.py').read_bytes()
class Diagnostic(unittest.TestCase):
 def temp(self):return tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])
 def tearDown(self):signal.alarm(0)
 def put(self,path,value):path.write_bytes(m.encoded(value));path.chmod(0o600)
 def fixture(self,root,operation='REFRESH',state='BLOCKED'):
  f=old.BindingRead();prepared,case,selection,login,raws,directory,row=f.fixture(root)
  row.update(attempts=189 if operation=='REFRESH'else 190,state=state,operation=operation,reason='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN',accessExpiresAt=time.time()-100)
  self.put(directory/'recovery.json',row);review_path=root/'native-login-review.json';self.put(review_path,login);receipt_path=root/'native-login-receipt.json';self.put(receipt_path,json.loads(raws['login-window-receipt.json']))
  case['postbootResumedHuman']={'binding':row['binding'],'minimumOAuthAttempts':188,'maximumCumulativeOAuthAttempts':256,'newLoginAllowed':False,'windowExtensionAllowed':False,'loginReviewBinding':{'path':str(review_path),'sha256':m.sha(review_path.read_bytes())},'loginReceiptBinding':{'path':str(receipt_path),'sha256':m.sha(receipt_path.read_bytes())}}
  return case,selection,directory,row
 def test_blocked_refresh_or_userinfo_preserves_counters_credentials_and_no_bearer_read(self):
  for operation in ('REFRESH','USERINFO'):
   with self.subTest(operation=operation),self.temp()as temp:
    root=Path(temp);case,selection,directory,row=self.fixture(root,operation);before={str(p):p.read_bytes()for p in root.rglob('*')if p.is_file()};reader=m.read;opened=[]
    def tracked(path,*args,**kwargs):self.assertNotEqual(Path(path).name,'human-access.jwt');opened.append(str(path));return reader(path,*args,**kwargs)
    with patch.object(m,'read',side_effect=tracked):report=m.current_human(case,selection,HUMAN+b'\nraise RuntimeError("MODULE_EXECUTION_FORBIDDEN")\n')
    self.assertEqual(report['operation'],operation);self.assertEqual(report['attemptsConsumedSincePrepared'],1 if operation=='REFRESH'else 2);self.assertEqual(report['remainingAttempts'],256-row['attempts']);self.assertTrue(report['bearerFilePresentNotOpened']);self.assertEqual(report['frozenIdentityAndBudgetPredicate'],'ACCEPTED');self.assertFalse(report['runtimeHistoryAccepted']);self.assertFalse(report['httpStatusOrIssuerErrorPersistedByFrozenFailurePath']);self.assertNotIn('PRIVATE_',json.dumps(report));self.assertNotIn('MODULE_EXECUTION',json.dumps(report));self.assertNotIn('bindingSha256',json.dumps(report));self.assertEqual(before,{str(p):p.read_bytes()for p in root.rglob('*')if p.is_file()})
 def test_expired_window_is_historical_read_without_rebase_or_new_budget(self):
  with self.temp()as temp:
   case,selection,directory,row=self.fixture(Path(temp));future=row['binding']['expiresAt']+1
   with patch.object(m.time,'time',return_value=future):report=m.current_human(case,selection,HUMAN)
   self.assertTrue(report['expiredByWallClock']);self.assertEqual(report['windowRemainingSeconds'],0);self.assertEqual(report['attempts'],189);self.assertFalse(report['newHumanLoginOpened'])
 def test_unknown_failure_text_is_redacted_and_journal_or_identity_drift_blocks(self):
  for change in ('unknown','budget','identity','unstable','boot','bearerlink'):
   with self.subTest(change=change),self.temp()as temp:
    root=Path(temp);case,selection,directory,row=self.fixture(root);reader=m.read
    if change=='unknown':row['reason']='PRIVATE_SECRET_CANARY';self.put(directory/'recovery.json',row)
    if change=='budget':row['attempts']=257;self.put(directory/'recovery.json',row)
    if change=='identity':selection={**selection,'subject':'wrong'}
    if change=='boot':row['bootId']='old-boot';self.put(directory/'recovery.json',row)
    if change=='bearerlink':(directory/'human-access.jwt').unlink();(directory/'human-access.jwt').symlink_to(directory/'recovery.json')
    count=0
    def unstable(path,*args,**kwargs):
     nonlocal count
     if Path(path)==directory/'recovery.json':
      count+=1
      if count>1:raise ValueError('JOURNAL_CHANGED')
     return reader(path,*args,**kwargs)
    with patch.object(m,'read',side_effect=unstable if change=='unstable'else reader):
     if change=='unknown':self.assertEqual(m.current_human(case,selection,HUMAN)['reason'],'UNCLASSIFIED')
     else:
      with self.assertRaises((ValueError,KeyError)):m.current_human(case,selection,HUMAN)
 def test_nine_execution_files_reject_any_authority_login_or_compiler_drift(self):
  f=old_files.Files()
  with patch.object(old_files,'m',m):f.test_exact_nine_execution_files_and_refusal_of_unknown_authority_or_sources()
 def test_iam_fence_is_consumed_exactly_once_and_original_kcw_closure_pinned(self):
  with self.temp()as temp:
   root=Path(temp);f=old_files.Files()
   with patch.object(old_files,'m',m):prepared,stopped,case=f.execution(root)
   stopped.rename(root/'source-revision-execution-kcw73ask');stopped=root/'source-revision-execution-kcw73ask';plan=json.loads((stopped/'prepared-plan.json').read_bytes());plan['authorityDirectory']=str(stopped);plan['privateReviewBinding']['path']=str(stopped/'candidate-review.json');self.put(stopped/'prepared-plan.json',plan);report=m.reconcile_execution(stopped,prepared,{},case)
   fence=root/'fence';fence.mkdir(mode=0o700);row={'schema':'ouf.source-revision-custody-iam-admin-resume.v1','maximumLoginAttempts':1,'automaticReplayAllowed':False,'budgetReset':False,'passwordReadByDelivery':False,'stoppedClosureSha256':report['contextClosureSha256'],'preparedReceiptSha256':m.RESULT,'containerId':'a'*64};self.put(fence/'attempt.json',row);before=(fence/'attempt.json').read_bytes()
   with patch.multiple(m,PREPARED=prepared,IAM_FENCE=fence,KCW_CLOSURE=report['contextClosureSha256']):
    self.assertTrue(m.iam_and_previous_execution({},case,{'keycloakContainer':'a'*64})['iamAttemptFencePresentAndBound']);self.assertEqual((fence/'attempt.json').read_bytes(),before)
    row['maximumLoginAttempts']=2;self.put(fence/'attempt.json',row)
    with self.assertRaises(ValueError):m.iam_and_previous_execution({},case,{'keycloakContainer':'a'*64})
 def test_actual_prepared_81_file_and_unconsumed_scope_guards_are_unchanged(self):
  # Reuse the already qualified real-file fixture against the new module functions.
  with patch.object(prepared_fixture,'r',m):prepared_fixture.Read().test_prepared_all81_files_continuation_and_old_claim_without_executing_code()
 def test_no_network_subprocess_login_refresh_or_full_module_execution(self):
  source=(ROOT/'scripts/read-source-revision-custody-human-stop-20261019.py').read_text();tree=ast.parse(source);imports={a.name for n in tree.body if isinstance(n,ast.Import)for a in n.names};self.assertEqual(imports,{'ast','hashlib','json','os','signal','stat','time','types','uuid'});self.assertEqual(m.STOPPED.name,'source-revision-execution-inmfuoj2');self.assertEqual(m.RESULT,'1de8d0f6740573bc2b4aa4125a67a806a1b6016c1e56a319aa666cb7bb8c0b91');self.assertEqual(m.KCW_CLOSURE,'153581a3f2294823d08c3668fb98433d49a34dd51a95056a24111379a4d07e9f');self.assertNotIn('refresh_if_due(',source)

 def test_complete_main_reads_only_and_preserves_all_private_files(self):
  with self.temp()as temp:
   root=Path(temp);case,selection,directory,row=self.fixture(root);selection['keycloakContainer']='a'*64;row['binding']['selectionHash']=m.digest(selection);self.put(directory/'recovery.json',row)
   prepared=root/'prepared';code=prepared/'executor-code';code.mkdir(mode=0o700);retained=root/'source-revision-postboot-prepared-kfy691gh';retained.mkdir(mode=0o700)
   def binding(path,value):self.put(path,value);return {'path':str(path),'sha256':m.sha(path.read_bytes())}
   original=binding(retained/'current-original-preparation.json',{'authorization':{'plan':{'selection':selection}}});inputs=binding(retained/'postboot-private-inputs.json',{})
   case['preparedPlanBinding']=inputs;case['postbootOriginalPreparationBinding']=original;case['schema']='ouf.source-revision-postboot-update-selection.v2'
   predecessor=root/'source-revision-execution-dvf517sr';predecessor.mkdir(mode=0o700);old_journal={'version':0,'nextStage':0,'readinessAttempts':0,'cumulativeReadinessAttempts':0,'effects':[],'budgetReset':False,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'expiresAt':time.time()-1,'expiresMonotonic':time.monotonic()-1};jb=binding(predecessor/'recovery.json',old_journal);case['custodyContinuation']={'schema':'ouf.source-revision-mcp-custody-continuation.v1','scopeSuccessor':{'context':str(predecessor),'journalBinding':jb}}
   source_hashes={}
   for module,name in m.FROZEN_NAMES.items():
    raw=HUMAN if module=='tools.chatbot_file_cohort.human_session'else b'pass\n';(code/name).write_bytes(raw);(code/name).chmod(0o600);source_hashes[module]=m.sha(raw)
   for name,raw in [('execute.py',(ROOT/'scripts/execute-source-revision-postboot.py').read_bytes()),('runtime.py',b'pass\n')]:
    (code/name).write_bytes(raw);(code/name).chmod(0o600)
   cb=binding(code/'case.json',case);package={'schema':'ouf.source-revision-executable-package.v1','sourceCommit':'5571f70b501fffa81b6c9e18b5bb67b0957ed2d9','caseSha256':cb['sha256'],'executorSha256':m.EXECUTOR,'loaderSha256':m.sha(b'pass\n'),'sourceHashes':source_hashes};pb=binding(code/'package.json',package)
   for base in (prepared,root/'source-revision-execution-kcw73ask',root/'source-revision-execution-inmfuoj2'):
    if not base.exists():base.mkdir(mode=0o700)
    (base/'gateway-compiler').mkdir(mode=0o700)
    for i in range(7):
     path=base/'gateway-compiler'/('file'+str(i)+'.py');path.write_bytes(b'pass\n');path.chmod(0o600)
    rb=binding(base/'candidate-review.json',{'schema':'ouf.source-revision-candidate-review.v1','preparedPlanBinding':inputs,'runtimeAuthorityIssued':False,'readyForExecution':False})
    binding(base/'prepared-plan.json',{'schema':'ouf.source-revision-native-update-plan.v1','authorityDirectory':str(base),'privateReviewBinding':rb,**{k:False for k in ('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')}})
   plan={'path':str(prepared/'prepared-plan.json'),'sha256':m.sha((prepared/'prepared-plan.json').read_bytes())};continued=binding(prepared/'continuation-plan.json',{})
   result={'schema':'ouf.source-revision-postboot-preparation-result.v1','contextPath':str(prepared),'runtimeAuthorityIssued':False,'readyForExecution':False,**{k:True for k in ('postbootSuccessorPrepared','nativePlanCompilationProven','effectiveFlywayConfigurationProven','hostCompletionReadbackProven')},'caseBinding':cb,'executorCodeBinding':{'directory':str(code),'sourceCommit':package['sourceCommit'],'packageSha256':pb['sha256']},'preparedInputsBinding':inputs,'currentOriginalPreparationBinding':original,'nativePlanBinding':plan,'sourceClosureSha256':m.CLOSURE,'continuationPlanBinding':continued};result_binding=binding(prepared/'postboot-preparation-result.json',result)
   previous=m.reconcile_execution(root/'source-revision-execution-kcw73ask',prepared,result,case);fence=root/'iam-fence';fence.mkdir(mode=0o700);binding(fence/'attempt.json',{'schema':'ouf.source-revision-custody-iam-admin-resume.v1','maximumLoginAttempts':1,'automaticReplayAllowed':False,'budgetReset':False,'passwordReadByDelivery':False,'stoppedClosureSha256':previous['contextClosureSha256'],'preparedReceiptSha256':result_binding['sha256'],'containerId':selection['keycloakContainer']})
   before={str(p):p.read_bytes()for p in root.rglob('*')if p.is_file()}
   with patch.multiple(m,PREPARED=prepared,STOPPED=root/'source-revision-execution-inmfuoj2',IAM_FENCE=fence,CASE=cb['sha256'],PACKAGE=pb['sha256'],RESULT=result_binding['sha256'],PLAN=plan['sha256'],CONTINUATION=continued['sha256'],KCW_CLOSURE=previous['contextClosureSha256']):report=m.main()
   self.assertTrue(report['complete']);self.assertEqual(report['executionReconciliation']['contextFiles'],9);self.assertEqual(report['humanSession']['attempts'],189);self.assertEqual(report['preparedClosure']['frozenFilesVerified'],81);self.assertNotIn('PRIVATE_',json.dumps(report));self.assertEqual(before,{str(p):p.read_bytes()for p in root.rglob('*')if p.is_file()})

class RootShim(prepared_fixture.RootShim):
 def exercise(self,tamper):
  import subprocess,sys
  text=(ROOT/'scripts/launch-source-revision-custody-human-stop-read-20261019.sh').read_text();payload=text.split("<<'OUF_HUMAN_HISTORY_READ' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_HUMAN_HISTORY_READ',1)[0]
  with tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])as temp:
   helper=Path(temp)/'helper.py';helper.write_bytes(b'print("PRIVATE_CANARY")'if tamper else(ROOT/'scripts/read-source-revision-custody-human-stop-20261019.py').read_bytes())
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
try:exec(compile(raw,'<exact-read-only-root-shim>','exec'),{'__name__':'__main__'})
except SystemExit as error:print(json.dumps({'fixtureExit':error.code,'protectedReadAttempts':len(protected)}))
'''
   result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,payload,str(helper)],capture_output=True,timeout=20);self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stderr,b'');self.assertNotIn(b'PRIVATE_CANARY',result.stdout);rows=[json.loads(line)for line in result.stdout.splitlines()];self.assertEqual(rows[-1]['protectedReadAttempts'],0 if tamper else 1)
   if not tamper:self.assertFalse(rows[0]['complete']);self.assertTrue(rows[0]['reconciliationRequired']);self.assertEqual(rows[-1]['fixtureExit'],2)
 def test_exact_helper_sha_and_git_blob_are_pinned_before_sudo(self):
  raw=(ROOT/'scripts/read-source-revision-custody-human-stop-20261019.py').read_bytes();sha=hashlib.sha256(raw).hexdigest();blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest();launcher=(ROOT/'scripts/launch-source-revision-custody-human-stop-read-20261019.sh').read_text();self.assertEqual(launcher.count(sha),2);self.assertIn('/git/blobs/'+blob,launcher)
