import base64,contextlib,copy,hashlib,importlib.util,io,json,os,signal,tempfile,time,unittest,uuid
from pathlib import Path
from unittest.mock import patch
import test_source_revision_update_configuration
import test_source_revision_human_binding_stop_read as fixtures
import test_source_revision_authorization as owner_fixture
from tools.source_revision_update import login as l
from tools.chatbot_file_cohort import authorization as auth
from tools.csv_materialization_recovery import human_session as native
from tools.semantic_lease_recovery.recovery_journal import Journal
ROOT=Path(__file__).resolve().parents[1]
class Governed(unittest.TestCase):
 def environment(self):
  stack=contextlib.ExitStack()
  for name in ('HumanSession','PROFILE','CLIENT','SCOPES','LEGACY_SCOPES'):stack.enter_context(patch.object(l,name,getattr(native,name)))
  return stack
 def temporary(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def read(self,path,maximum,expected=None):
  raw=Path(path).read_bytes();self.assertLessEqual(len(raw),maximum)
  if expected:self.assertEqual(hashlib.sha256(raw).hexdigest(),expected)
  return json.loads(raw)
 def fixture(self,root):
  f=fixtures.BindingRead();prepared,case,selection,review,raws,directory,row=f.fixture(root)
  row['attempts']=186;row.update(endpoints={'token_endpoint':selection['issuer']+'/token','userinfo_endpoint':selection['issuer']+'/userinfo'},refreshAt=time.time()-10,accessExpiresAt=time.time()-10)
  row['accessToken']=row['publishedAccessToken']='OLD.PRIVATE.ACCESS';f.put(directory/'recovery.json',row)
  for name in ('recovery.lock','invocation.lock'):p=directory/name;p.write_bytes(b'');p.chmod(0o600)
  review_path=root/'review.json';f.put(review_path,review);receipt_path=root/'receipt.json';receipt_path.write_bytes(raws['login-window-receipt.json']);receipt_path.chmod(0o600)
  reference={'schema':'ouf.source-revision-current-human-continuation.v1','binding':row['binding'],'loginReviewBinding':{'path':str(review_path),'sha256':l.digest(review)},'loginReceiptBinding':{'path':str(receipt_path),'sha256':hashlib.sha256(receipt_path.read_bytes()).hexdigest()},'minimumOAuthAttempts':186,'maximumCumulativeOAuthAttempts':256,'newLoginAllowed':False,'windowExtensionAllowed':False}
  case['postbootResumedHuman']=reference;context=root/'new-execution';context.mkdir(mode=0o700)
  return case,selection,directory,row,context
 def jwt(self,selection):
  claims={'iss':selection['issuer'],'sub':selection['subject'],'tenant_id':selection['tenant'],'ouf_actor_type':'HUMAN','azp':native.CLIENT,'acr':'fixture','aud':'ouf-api-gateway','scope':' '.join(native.SCOPES),'exp':time.time()+300}
  return 'header.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.signature'
 def test_real_native_rotation_preserves_window_counts_186_to188_then_compiles_owner_plan_and_scope(self):
  with self.temporary()as temp,self.environment():
   case,selection,directory,row,context=self.fixture(Path(temp));calls=[];human=l.resumed_human(case,selection,self.read)
   def http(url,values=None,bearer=None):
    calls.append((url,values,bearer))
    if values is not None:
     self.assertEqual(values['grant_type'],'refresh_token');self.assertEqual(values['refresh_token'],'PRIVATE_REFRESH_CANARY')
     return 200,{'access_token':self.jwt(selection),'refresh_token':'NEW_PRIVATE_REFRESH','token_type':'bearer'},None
    self.assertEqual(url,selection['issuer']+'/userinfo');return 200,{'sub':selection['subject']},None
   with patch.object(human,'_http',side_effect=http),patch.object(human,'login',side_effect=AssertionError('NO_NEW_LOGIN')),contextlib.redirect_stdout(io.StringIO())as out:
    same=l.refresh_resumed_human(human,case,context,self.read,print)
   self.assertIs(same,human);after=human._read();self.assertEqual(after['attempts'],188);self.assertEqual(after['binding'],row['binding']);self.assertEqual(after['monotonicDeadline'],row['monotonicDeadline']);self.assertEqual(after['state'],'READY');self.assertEqual(len(calls),2);self.assertNotIn('PRIVATE',out.getvalue())
   selected,observed=owner_fixture.existing.fixture();binding=human.current();binding['selectionHash']=auth.digest(selected)
   for key in ('issuer','subject','tenant'):binding[key]=selected[key]
   plan=auth.compile_plan(observed,owner_fixture.primitives(),selected,include_ingestion_status=False,now='2026-10-18T06:00:00Z',session_binding=binding)
   scope=auth.authorization_scope(plan);self.assertEqual(scope['sessionBinding'],binding);self.assertEqual(scope['profile'],auth.REVISION_PROFILE);self.assertFalse(scope['tokenIssuanceAuthorized'])
 def test_governed_contract_is_explicit_revision_only_nominal_default_remains(self):
  with self.temporary()as temp:
   case,selection,directory,row,context=self.fixture(Path(temp));binding=row['binding']
   auth.validate_session_binding(binding,selection,profile=auth.REVISION_PROFILE)
   for profile in (None,auth.PROFILE,'unknown'):
    with self.subTest(profile=profile),self.assertRaises(Exception):auth.validate_session_binding(binding,selection,profile=profile)
   nominal={**binding,'scopes':native.LEGACY_SCOPES,'retryProfile':{**native.PROFILE,'id':'ouf.chatbot-human-session.finite.v1','maximumAttempts':128}}
   auth.validate_session_binding(nominal,selection)
   for change in ('issuer','scopes','retryProfile','expiresAt'):
    bad=copy.deepcopy(binding)
    if change=='issuer':bad['issuer']='https://wrong.invalid'
    if change=='scopes':bad['scopes'].append('unreviewed.scope')
    if change=='retryProfile':bad['retryProfile']['maximumAttempts']=257
    if change=='expiresAt':bad['expiresAt']+=1
    with self.subTest(change=change),self.assertRaises(Exception):auth.validate_session_binding(bad,selection,profile=auth.REVISION_PROFILE)
 def test_expiry_counter_drift_existing_claim_and_blocked_state_do_not_open_login(self):
  for change in ('expiry','attempts','claim','blocked'):
   with self.subTest(change=change),self.temporary()as temp,self.environment():
    case,selection,directory,row,context=self.fixture(Path(temp))
    if change=='expiry':row['monotonicDeadline']=time.monotonic()-1
    if change=='attempts':row['attempts']=187
    if change=='blocked':row['state']='BLOCKED'
    if change=='claim':p=directory/'successor-window.claim.json';p.write_bytes(b'{}');p.chmod(0o600)
    (directory/'recovery.json').write_bytes(l.encoded(row))
    with patch.object(native.HumanSession,'login')as login,patch.object(native.HumanSession,'_http')as http,self.assertRaises(Exception):l.resumed_human(case,selection,self.read)
    login.assert_not_called();http.assert_not_called()
 def test_ambiguous_native_refresh_consumes_one_attempt_and_blocks_without_replay(self):
  with self.temporary()as temp,self.environment():
   case,selection,directory,row,context=self.fixture(Path(temp));human=l.resumed_human(case,selection,self.read)
   with patch.object(human,'_http',side_effect=OSError('UNCERTAIN'))as http:
    with self.assertRaises(native.HumanSessionPaused):l.refresh_resumed_human(human,case,context,self.read,print)
    self.assertEqual(human._read()['attempts'],187);self.assertEqual(human._read()['state'],'BLOCKED')
    with self.assertRaises(Exception):l.refresh_resumed_human(human,case,context,self.read,print)
    self.assertEqual(http.call_count,1)
 def test_nominal_repository_default_is_not_promoted_to_test_mode(self):
  self.assertEqual((ROOT/'tools/source_revision_update/governed_authorization.py').read_bytes(),(ROOT/'tools/chatbot_file_cohort/authorization.py').read_bytes())
  self.assertIn('profile=primitives.profile', (ROOT/'tools/source_revision_update/governed_authorization.py').read_text())
if __name__=='__main__':unittest.main()
