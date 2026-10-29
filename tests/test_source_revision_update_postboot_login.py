"""Real root journals and unchanged HUMAN guard; OAuth/terminal are explicit test boundaries."""
import copy,importlib.util,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_source_revision_update_configuration
from tools.source_revision_update import login as l
from tools.csv_materialization_recovery import human_session as native
from tools.semantic_lease_recovery.recovery_journal import Journal
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('history_fixture',ROOT/'tests/test_source_revision_human_history_read.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
class PostbootLogin(unittest.TestCase):
 def fixture(self,root):
  selection=None;sessions=[];rows=[]
  for i,attempts in enumerate((153,160,168,175)):
   directory=root/('human'+str(i));directory.mkdir(mode=0o700);sel,hb,row=f.fixture(directory);row['attempts']=attempts
   Journal(directory).initialize(row);selection=sel
   sessions.append({'directory':str(directory),'bindingSha256':l.digest(hb),'attempts':attempts});rows.append(row)
  for i in range(3):
   renewal=rows[i+1]['governedWindowRenewal'];value={'destination':sessions[i+1]['directory'],'budgetReset':False,'reviewHash':l.digest(renewal['review']),'decisionHash':l.digest(renewal['decision'])}
   self.put(root/('human'+str(i))/'successor-window.claim.json',value)
  hb_review={'authenticatedHuman':rows[0]['binding']};self.put(root/'human-review.json',hb_review)
  case={'postbootHumanHistory':{'schema':'ouf.source-revision-expired-preboot-history.v1','sessions':sessions,'maximumCumulativeOAuthAttempts':256,'remainingOAuthAttempts':81},'humanReviewBinding':{'path':str(root/'human-review.json'),'sha256':l.digest(hb_review)},'preparedPlanBinding':{'path':'/exact/prepared','sha256':'a'*64}}
  context=root/'execution';context.mkdir(mode=0o700)
  return selection,case,context
 def put(self,path,value):
  path.write_bytes(l.encoded(value));path.chmod(0o600)
 def read(self,path,maximum,expected=None):
  raw=Path(path).read_bytes();self.assertLessEqual(len(raw),maximum)
  if expected:self.assertEqual(l.digest(json.loads(raw)),expected)
  return json.loads(raw)
 def environment(self):
  from contextlib import ExitStack
  stack=ExitStack()
  for name in ('HumanSession','PROFILE','CLIENT','SCOPES','LEGACY_SCOPES'):stack.enter_context(patch.object(l,name,getattr(native,name)))
  stack.enter_context(patch.object(native.HumanSession,'_boot',return_value='new-boot'))
  stack.enter_context(patch.object(l.time,'time',return_value=10000))
  return stack
 def temporary(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def test_expired_history_is_readable_but_unchanged_native_guard_still_rejects_it(self):
  with self.temporary()as temp,self.environment():
   selection,case,context=self.fixture(Path(temp));human,history=l.historical_human(case,selection,self.read)
   self.assertEqual(history['row']['attempts'],175)
   with self.assertRaisesRegex(Exception,'HUMAN_SESSION_BINDING_OR_HISTORY_DRIFT'):human._check_identity_and_budget(history['row'])
 def test_fresh_boot_login_preserves_175_budget_and_old_journals(self):
  with self.temporary()as temp,self.environment():
   root=Path(temp);selection,case,context=self.fixture(root);human,history=l.historical_human(case,selection,self.read);before={p:p.read_bytes()for p in root.glob('human*/recovery.json')};calls=[]
   def consent(review,summary,login=False):
    self.assertTrue(login);self.assertFalse((human.directory/'successor-window.claim.json').exists());self.assertEqual(review['priorOAuthAttempts'],175);self.assertEqual(review['maximumRemainingOAuthAttempts'],81)
    return {'reviewHash':l.digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':10000,'expiresAt':17200}
   def issuer_login(following,emit):
    row=following._read();following._check_identity_and_budget(row);self.assertEqual(row['bootId'],'new-boot');self.assertEqual(row['state'],'NEW');self.assertEqual(row['attempts'],175);self.assertNotIn('refreshToken',row);calls.append(following)
   with patch.object(l.authority,'terminal_consent',side_effect=consent),patch.object(native.HumanSession,'login',issuer_login):
    following=l.authenticate_postboot(human,history,case,context,{'decl':'qualified'},self.read,lambda *_:None)
   self.assertEqual(calls,[following]);self.assertEqual(before,{p:p.read_bytes()for p in before});self.assertTrue((human.directory/'successor-window.claim.json').exists());self.assertTrue((context/'login-window-receipt.json').exists())
 def test_history_drift_budget_exhaustion_current_boot_and_existing_claim_refuse_before_consent(self):
  for change in ('subject','attempts','boot','claim','renewal'):
   with self.subTest(change=change),self.temporary()as temp,self.environment():
    root=Path(temp);selection,case,context=self.fixture(root);path=root/'human3/recovery.json';row=self.read(path,65536)
    if change=='subject':row['binding']['subject']='other'
    if change=='attempts':row['attempts']=256
    if change=='boot':row['bootId']='new-boot'
    if change=='claim':self.put(root/'human3/successor-window.claim.json',{'consumed':True})
    if change=='renewal':row['governedWindowRenewal']['decision']['reviewHash']='bad'
    self.put(path,row)
    with patch.object(l.authority,'terminal_consent')as terminal,self.assertRaises(Exception):l.historical_human(case,selection,self.read)
    terminal.assert_not_called()
 def test_no_consent_or_changed_history_cannot_create_claim(self):
  for change in ('reject','history','boot'):
   with self.subTest(change=change),self.temporary()as temp,self.environment():
    root=Path(temp);selection,case,context=self.fixture(root);human,history=l.historical_human(case,selection,self.read)
    def consent(review,summary,login=False):
     if change=='reject':raise ValueError('NOT_ACCEPTED')
     if change=='history':row=human._read();Journal(human.directory).compare_and_save(row,{**row,'attempts':176})
     if change=='boot':human._boot=lambda:'third-boot'
     return {'reviewHash':l.digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':10000,'expiresAt':17200}
    with patch.object(l.authority,'terminal_consent',side_effect=consent),patch.object(native.HumanSession,'login')as network,self.assertRaises(Exception):l.authenticate_postboot(human,history,case,context,{},self.read,lambda *_:None)
    network.assert_not_called();self.assertFalse((human.directory/'successor-window.claim.json').exists())
 def test_crash_after_claim_blocks_replay_and_does_not_reset_predecessor(self):
  with self.temporary()as temp,self.environment():
   root=Path(temp);selection,case,context=self.fixture(root);human,history=l.historical_human(case,selection,self.read);before=(human.directory/'recovery.json').read_bytes()
   def consent(review,*args,**kwargs):return {'reviewHash':l.digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':10000,'expiresAt':17200}
   with patch.object(l.authority,'terminal_consent',side_effect=consent),patch.object(native.HumanSession,'login',side_effect=RuntimeError('NETWORK_BOUNDARY_STOP')),self.assertRaises(RuntimeError):l.authenticate_postboot(human,history,case,context,{},self.read,lambda *_:None)
   self.assertEqual((human.directory/'recovery.json').read_bytes(),before)
   with self.assertRaises(Exception):l.historical_human(case,selection,self.read)
if __name__=='__main__':unittest.main()
