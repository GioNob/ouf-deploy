import copy,importlib.util,json,os,signal,tempfile,time,unittest,uuid
from pathlib import Path
from unittest.mock import patch
import test_source_revision_human_history_read as old
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('binding_read',ROOT/'scripts/read-source-revision-human-binding-stop-20261019.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
AUTH=(ROOT/'tools/chatbot_file_cohort/authorization.py').read_bytes();HUMAN=(ROOT/'tools/csv_materialization_recovery/human_session.py').read_bytes();VALUES=m.constants(HUMAN)
class BindingRead(old.Files):
 def fixture(self,root,state='READY'):
  prepared=root/'prepared';prepared.mkdir(mode=0o700);pred=root/'semantic'/'predecessor';selection,prior_binding,prior=old.fixture(pred);prior['attempts']=175;self.put(pred/'recovery.json',prior)
  private={'path':'/fixed/input','sha256':'a'*64};case={'preparedPlanBinding':private,'postbootHumanHistory':{'sessions':[{'directory':str(pred),'bindingSha256':m.digest(prior_binding),'attempts':175}]}}
  login={'schema':'ouf.human-explicit-test-continuation-review.v3','purpose':'CONFIGURATION_AND_VALIDATION','predecessorDirectory':str(pred),'priorOAuthAttempts':175,'maximumCumulativeOAuthAttempts':256,'predecessorMaximumCumulativeOAuthAttempts':256,'newWindowSeconds':7200,'budgetReset':False,'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'operationBinding':{'preparedReviewHash':'a'*64}}
  reviewsha=m.digest(login);directory=pred.parent/('human-source-revision-postboot-successor-'+reviewsha);now=int(time.time());decision={'reviewHash':reviewsha,'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
  claim={'schema':'ouf.human-successor-window-claim.v1','reviewHash':reviewsha,'decisionHash':m.digest(decision),'destination':str(directory),'budgetReset':False,'automaticReplayAllowed':False};self.put(pred/'successor-window.claim.json',claim)
  binding={**prior_binding,'sessionId':str(uuid.uuid4()),'createdAt':now,'expiresAt':now+7200,'sessionDirectory':str(directory),'tokenPath':str(directory/'human-access.jwt')}
  row={'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'budgetReset':False,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'attempts':180,'state':state,'operation':'USERINFO'if state=='READY'else'DEVICE_START','lastObservedAt':time.time(),'monotonicDeadline':time.monotonic()+7200,'governedWindowRenewal':{'review':login,'decision':decision},'accessExpiresAt':now+300}
  if state=='READY':
   row.update(accessToken='PRIVATE_ACCESS_CANARY',publishedAccessToken='PRIVATE_PUBLISHED_CANARY',refreshToken='PRIVATE_REFRESH_CANARY');self.put(directory/'human-access.jwt',b'PRIVATE_BEARER_CANARY')
  else:row.update(deviceCode='PRIVATE_DEVICE_CANARY',deviceDeadline=now+600)
  self.put(directory/'recovery.json',row)
  receipt={'directory':str(directory),'expiresAt':binding['expiresAt'],'reviewHash':reviewsha,'priorOAuthAttempts':175,'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'postbootFreshLogin':True}
  raws={'login-window-receipt.json':m.encoded(receipt)}if state=='READY'else{}
  return prepared,case,selection,login,raws,directory,row
 def tearDown(self):signal.alarm(0)
 def test_ready_and_polling_state_redaction_preservation_and_actual_guard_mismatch(self):
  for state in ('READY','DEVICE_POLL'):
   with self.subTest(state=state),self.temporary()as temp:
    prepared,case,selection,login,raws,directory,row=self.fixture(Path(temp),state);before={str(p):p.read_bytes()for p in Path(temp).rglob('*')if p.is_file()};opened=[];reader=m.read
    def tracking(path,*args,**kwargs):
     self.assertNotEqual(Path(path).name,'human-access.jwt');opened.append(str(path));return reader(path,*args,**kwargs)
    with patch.object(m,'LOGIN_REVIEW',m.digest(login)),patch.object(m,'read',side_effect=tracking):report=m.session(prepared,case,selection,login,raws,AUTH,HUMAN)
    self.assertEqual(report['state'],state);self.assertEqual(report['attempts'],180);self.assertEqual(report['remainingAttempts'],76);self.assertEqual(report['frozenAuthorizationBindingResult'],'FINITE_NOMINAL_HUMAN_SESSION_CONTEXT_REQUIRED');self.assertEqual(report['frozenGovernedHumanIdentityResult'],'ACCEPTED');self.assertTrue(report['journalsStableDuringRead']);self.assertEqual(report['bearerFilePresentNotOpened'],state=='READY')
    self.assertNotIn('PRIVATE_',json.dumps(report));self.assertNotIn('decisionHash',json.dumps(report));self.assertNotIn('bindingSha256',json.dumps(report));self.assertEqual(before,{str(p):p.read_bytes()for p in Path(temp).rglob('*')if p.is_file()})
 def test_pure_predicate_keeps_nominal_contract_and_reproduces_test_contract_failure(self):
  with self.temporary()as temp:
   prepared,case,selection,login,raws,directory,row=self.fixture(Path(temp));binding=copy.deepcopy(row['binding'])
   self.assertEqual(m.validator_result(AUTH+b'\nraise RuntimeError("CANARY")\n','validate_session_binding',binding,selection),'FINITE_NOMINAL_HUMAN_SESSION_CONTEXT_REQUIRED')
   binding['scopes']=VALUES['LEGACY_SCOPES'];binding['retryProfile']={**binding['retryProfile'],'id':'ouf.chatbot-human-session.finite.v1','maximumAttempts':128}
   self.assertEqual(m.validator_result(AUTH,'validate_session_binding',binding,selection),'ACCEPTED')
 def test_changed_journal_and_wrong_claim_or_receipt_stop(self):
  for change in ('journal','claim','receipt'):
   with self.subTest(change=change),self.temporary()as temp:
    prepared,case,selection,login,raws,directory,row=self.fixture(Path(temp));reader=m.read
    def unstable(path,expected=None,maximum=8388608):
     if expected and Path(path)==directory/'recovery.json':raise ValueError('DRIFT')
     return reader(path,expected,maximum)
    if change=='claim':
     path=Path(login['predecessorDirectory'])/'successor-window.claim.json';claim=json.loads(path.read_bytes());claim['decisionHash']='0'*64;self.put(path,claim)
    if change=='receipt':raws['login-window-receipt.json']=b'{}'
    with patch.object(m,'LOGIN_REVIEW',m.digest(login)),patch.object(m,'read',side_effect=unstable if change=='journal'else reader),self.assertRaises((ValueError,KeyError)):m.session(prepared,case,selection,login,raws,AUTH,HUMAN)
 def test_expired_session_is_reported_without_rebase_or_new_budget(self):
  with self.temporary()as temp:
   prepared,case,selection,login,raws,directory,row=self.fixture(Path(temp));future=row['binding']['expiresAt']+1
   with patch.object(m,'LOGIN_REVIEW',m.digest(login)),patch.object(m.time,'time',return_value=future):report=m.session(prepared,case,selection,login,raws,AUTH,HUMAN)
   self.assertTrue(report['expiredByWallClock']);self.assertEqual(report['windowRemainingSeconds'],0);self.assertEqual(report['attempts'],180)
 def test_execution_with_login_receipt_and_authority_refusal(self):
  for change in (None,'authority','compiler','review','unknown'):
   with self.subTest(change=change),self.temporary()as temp:
    prepared,stopped,case=self.execution(Path(temp));login={'fixture':'review'};self.put(stopped/'login-review.json',login);self.put(stopped/'login-window-receipt.json',{})
    if change=='authority':self.put(stopped/'authority.json',{})
    if change=='unknown':(stopped/'authorization').mkdir(mode=0o700)
    if change=='compiler':self.put(stopped/'gateway-compiler/file0.py',b'drift')
    if change=='review':self.put(stopped/'login-review.json',{})
    with patch.object(m,'LOGIN_REVIEW',m.digest(login)):
     if change:
      with self.assertRaises(ValueError):m.execution(stopped,prepared,case)
     else:
      report,_,_=m.execution(stopped,prepared,case);self.assertEqual(report['contextFiles'],11);self.assertTrue(report['runtimeAuthorityArtifactsAbsent']);self.assertTrue(report['loginWindowReceiptPresent'])
if __name__=='__main__':unittest.main()

class ExactRootShim(unittest.TestCase):
 def exercise(self,tamper):
  import subprocess,sys
  text=(ROOT/'scripts/launch-source-revision-human-binding-stop-read-20261019.sh').read_text();payload=text.split("<<'OUF_HUMAN_HISTORY_READ' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_HUMAN_HISTORY_READ',1)[0]
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent))) as temp:
   helper=Path(temp)/'helper.py';helper.write_bytes(b'print("PRIVATE_CANARY")'if tamper else(ROOT/'scripts/read-source-revision-human-binding-stop-20261019.py').read_bytes())
   harness='''import os,sys,json
raw=sys.argv[1];helper=sys.argv[2];original_stat=os.stat;protected=[]
def checked(path,*args,**kwargs):
 if str(path).startswith('/etc/ouf/'):
  protected.append(str(path));raise RuntimeError('PRIVATE_CANARY')
 return original_stat(path,*args,**kwargs)
os.stat=checked;sys.argv=['delivery',helper]
try:exec(compile(raw,'<root-shim>','exec'),{'__name__':'__main__'})
except SystemExit as error:print(json.dumps({'fixtureExit':error.code,'protectedReadAttempts':len(protected)}))
'''
   result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,payload,str(helper)],capture_output=True,timeout=20)
   self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stderr,b'');self.assertNotIn(b'PRIVATE_CANARY',result.stdout)
   rows=[json.loads(line)for line in result.stdout.splitlines()];self.assertEqual(rows[-1]['protectedReadAttempts'],0 if tamper else 1)
   if not tamper:self.assertFalse(rows[0]['complete']);self.assertTrue(rows[0]['reconciliationRequired']);self.assertEqual(rows[-1]['fixtureExit'],2)
 def test_exact_shell_shim_reaches_first_protected_read_only(self):self.exercise(False)
 def test_shell_shim_tampered_helper_never_reaches_protected_read(self):self.exercise(True)
