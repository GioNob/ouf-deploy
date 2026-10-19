"""Existing native finite login path, with real root journals and explicit issuer boundary."""
import contextlib,copy,hashlib,io,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_source_revision_update_configuration
import test_source_revision_custody_human_stop_read as fixture
from tools.source_revision_update import login as l
from tools.csv_materialization_recovery import human_session as native
ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(os.environ.get('OUF_HUMAN_RECOVERY')=='1','explicit sealed blocked-HUMAN successor required')
class Recovery(unittest.TestCase):
 def temp(self):return tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])
 def read(self,path,maximum,expected=None):
  raw=Path(path).read_bytes();self.assertLessEqual(len(raw),maximum)
  if expected:self.assertEqual(hashlib.sha256(raw).hexdigest(),expected)
  return json.loads(raw)
 def environment(self):
  stack=contextlib.ExitStack()
  for name in ('HumanSession','PROFILE','CLIENT','SCOPES','LEGACY_SCOPES'):stack.enter_context(patch.object(l,name,getattr(native,name)))
  return stack
 def fixture(self,root):
  case,selection,directory,row=fixture.Diagnostic().fixture(root);ref=case['postbootResumedHuman'];case['postbootBlockedHuman']={'schema':'ouf.source-revision-blocked-human-predecessor.v1',**{k:ref[k]for k in ('binding','loginReviewBinding','loginReceiptBinding')},'attempts':189,'maximumCumulativeOAuthAttempts':256,'blockedRefreshReplayAllowed':False,'newLoginRequiresNativeConsent':True};context=root/'new-execution';context.mkdir(mode=0o700)
  for name in ('recovery.lock','invocation.lock'):p=directory/name;p.write_bytes(b'');p.chmod(0o600)
  return case,selection,directory,row,context
 def test_native_login_after_explicit_consent_preserves189_then_actual_device_grant_reaches_ready(self):
  import test_source_revision_update_governed_continuation as jwt_fixture
  with self.temp()as temp,self.environment():
   root=Path(temp);case,selection,directory,row,context=self.fixture(root);human=l.blocked_human(case,selection,self.read);before=(directory/'recovery.json').read_bytes();calls=[];decisions=[]
   def consent(review,summary,login=False):
    self.assertTrue(login);self.assertEqual(review['priorOAuthAttempts'],189);self.assertEqual(review['maximumRemainingOAuthAttempts'],67);self.assertFalse(review['failedRefreshReplayAllowed']);self.assertIn('causa specifica non registrata',summary);self.assertFalse((directory/'successor-window.claim.json').exists());decisions.append(review)
    now=int(time.time());return {'reviewHash':l.digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
   def http(session,url,values=None,bearer=None):
    calls.append((url,values))
    if values and values.get('grant_type')=='refresh_token':raise AssertionError('BLOCKED_REFRESH_NEVER_REPLAYED')
    if url.endswith('/.well-known/openid-configuration'):
     return 200,{'issuer':selection['issuer'],**{k:selection['issuer']+'/protocol/openid-connect/'+v for k,v in [('device_authorization_endpoint','auth/device'),('token_endpoint','token'),('userinfo_endpoint','userinfo')]}},None
    if url.endswith('/auth/device'):return 200,{'device_code':'PRIVATE_NEW_DEVICE','user_code':'ABCD-EFGH','verification_uri':selection['issuer']+'/device','expires_in':600,'interval':5},None
    if values and values.get('grant_type')=='urn:ietf:params:oauth:grant-type:device_code':
     return 200,{'access_token':jwt_fixture.Governed().jwt(selection),'refresh_token':'PRIVATE_NEW_REFRESH','token_type':'bearer'},None
    if url.endswith('/userinfo'):return 200,{'sub':selection['subject']},None
    raise AssertionError('UNEXPECTED_NATIVE_REQUEST')
   with patch.object(l.authority,'terminal_consent',side_effect=consent),patch.object(native.HumanSession,'_http',http),patch.object(native.HumanSession,'refresh_if_due',side_effect=AssertionError('NO_BLOCKED_REFRESH')),contextlib.redirect_stdout(io.StringIO())as output:
    following=l.authenticate(human,case,context,{'closure':'new-qualified'},self.read,lambda *_:None)
   after=following._read();following._check_identity_and_budget(after);self.assertEqual(after['state'],'READY');self.assertEqual(after['attempts'],193);self.assertLessEqual(after['attempts'],256);self.assertEqual(before,(directory/'recovery.json').read_bytes());self.assertTrue((directory/'successor-window.claim.json').exists());self.assertTrue((context/'login-window-receipt.json').exists());self.assertEqual(len(decisions),1);self.assertNotIn('PRIVATE_',output.getvalue());self.assertTrue(calls)
 def test_refusal_no_claim_no_issuer_request(self):
  with self.temp()as temp,self.environment():
   case,selection,directory,row,context=self.fixture(Path(temp));human=l.blocked_human(case,selection,self.read)
   with patch.object(l.authority,'terminal_consent',side_effect=ValueError('DECLINED')),patch.object(native.HumanSession,'login')as login,self.assertRaises(ValueError):l.authenticate(human,case,context,{},self.read,print)
   login.assert_not_called();self.assertFalse((directory/'successor-window.claim.json').exists());self.assertEqual(human._read()['attempts'],189)
 def test_issuer_failure_after_claim_retains_history_and_blocks_second_successor(self):
  with self.temp()as temp,self.environment():
   case,selection,directory,row,context=self.fixture(Path(temp));human=l.blocked_human(case,selection,self.read);before=(directory/'recovery.json').read_bytes()
   def consent(review,*args,**kwargs):
    now=int(time.time());return {'reviewHash':l.digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
   with patch.object(l.authority,'terminal_consent',side_effect=consent),patch.object(native.HumanSession,'login',side_effect=RuntimeError('ISSUER_BOUNDARY_STOP')),self.assertRaises(RuntimeError):l.authenticate(human,case,context,{},self.read,print)
   self.assertEqual(before,(directory/'recovery.json').read_bytes());self.assertTrue((directory/'successor-window.claim.json').exists())
   with patch.object(native.HumanSession,'login')as login,self.assertRaises(Exception):l.blocked_human(case,selection,self.read)
   login.assert_not_called()
 def test_exact_counter_boot_reason_operation_and_old_receipt_drift_block(self):
  for change in ('counter','boot','reason','operation','claim','receipt','budget'):
   with self.subTest(change=change),self.temp()as temp,self.environment():
    case,selection,directory,row,context=self.fixture(Path(temp))
    if change=='counter':row['attempts']=190
    if change=='boot':row['bootId']='old-boot'
    if change=='reason':row['reason']='HUMAN_OAUTH_OUTCOME_UNPROVEN'
    if change=='operation':row['operation']='USERINFO'
    if change=='budget':row['budgetReset']=True
    if change=='claim':(directory/'successor-window.claim.json').write_bytes(b'{}')
    if change=='receipt':Path(case['postbootBlockedHuman']['loginReceiptBinding']['path']).write_bytes(b'{}')
    (directory/'recovery.json').write_bytes(l.encoded(row))
    with patch.object(l.authority,'terminal_consent')as consent,patch.object(native.HumanSession,'_http')as network,self.assertRaises(Exception):l.blocked_human(case,selection,self.read)
    consent.assert_not_called();network.assert_not_called()
 def test_expired_blocked_window_is_only_predecessor_evidence_not_rebased(self):
  with self.temp()as temp,self.environment():
   case,selection,directory,row,context=self.fixture(Path(temp));before=(directory/'recovery.json').read_bytes();future=row['binding']['expiresAt']+1
   with patch.object(l.time,'time',return_value=future):human=l.blocked_human(case,selection,self.read);review=l.qualify(human,human._read(),case,{'closure':'new'})
   self.assertEqual(review['priorOAuthAttempts'],189);self.assertEqual(before,(directory/'recovery.json').read_bytes());self.assertEqual(human.expires_at,row['binding']['expiresAt'])
