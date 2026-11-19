"""Same test ceiling with real loopback OAuth and unchanged blocked predecessor."""
import copy,json,os,sys,tempfile,unittest,uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_chatbot_cohort_human_session as oauth
from tools.csv_materialization_recovery import human_session as h
from tools.chatbot_file_cohort import human_session as standard
with patch.object(standard,'LEGACY_SCOPES',h.LEGACY_SCOPES,create=True):
 from tools.csv_materialization_recovery import entry as login
from tools.teatri_materialization_apply.owner import digest,encoded
from tools.semantic_lease_recovery.recovery_journal import Journal

class Login(unittest.TestCase):
 def setUp(self):
  base=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(base.cleanup)
  c=oauth.HumanSessionTest()
  with patch.object(oauth,'ROOT',Path(base.name)):c.setUp()
  self.addCleanup(c.doCleanups);self.c=c
  self.old=c.directory/'blocked-test';self.old.mkdir(mode=0o700);self.context=c.directory/'materialization';self.context.mkdir(mode=0o700)
  now=int(c.clock.time());self.hb={'sessionId':'current-test','selectionHash':digest(c.selection),**{k:c.selection[k]for k in('issuer','tenant','subject')},'clientId':h.CLIENT,'scopes':list(h.LEGACY_SCOPES),'tokenPath':str(self.old/'human-access.jwt'),'sessionDirectory':str(self.old),'createdAt':now-500,'expiresAt':now+6700,'retryProfile':copy.deepcopy(h.PROFILE)}
  review={'schema':'ouf.human-explicit-test-budget-review.v2','purpose':'CONFIGURATION_AND_VALIDATION','predecessorMaximumCumulativeOAuthAttempts':128,'priorOAuthAttempts':125,'maximumCumulativeOAuthAttempts':256}
  decision={'reviewHash':digest(review),'approvedAt':self.hb['createdAt'],'expiresAt':self.hb['expiresAt']}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':self.hb,'attempts':133,'state':'READY','operation':'USERINFO','budgetReset':False,'bootId':'explicit-disposable-kernel-fixture','lastObservedAt':c.clock.time(),'monotonicDeadline':c.clock.monotonic()+6700,'governedWindowRenewal':{'review':review,'decision':decision},'accessToken':'PRIVATE_OLD_ACCESS','refreshToken':'PRIVATE_OLD_REFRESH'}
  Journal(self.old).initialize(self.row);self.before=(self.old/'recovery.json').read_bytes()
  self.human=h.HumanSession(c.selection,self.old,self.old/'human-access.jwt',self.hb['expiresAt'])
  self.case={'preparedPlanBinding':{'path':'/fixture/private/plan.json','sha256':'a'*64},'minimumPriorOAuthAttempts':133};self.closure={'source':'b'*64};self.read=lambda p,*a:json.loads(Path(p).read_bytes())
  self.prompts=[]
  def consent(review,summary,login):
   self.prompts.append((review,summary));return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
  self.authority=SimpleNamespace(terminal_consent=consent)
 def test_fresh_login_keeps133_consumed_reaches137_without_old_refresh(self):
  c=self.c;original=h.HumanSession.login
  def fresh(session,emit):session.opener=oauth.FixtureOpener(c.server.server_port);return original(session,emit,oauth.ImmediateFixtureWait(c.clock))
  with patch.object(oauth.module,'SCOPES',h.SCOPES),patch.object(h,'time',c.clock),patch.object(login,'time',c.clock),patch.object(login,'authority',self.authority),patch.object(login,'HumanSession',h.HumanSession),patch.object(login,'PROFILE',h.PROFILE),patch.object(login,'SCOPES',h.SCOPES),patch.object(login,'LEGACY_SCOPES',h.LEGACY_SCOPES),patch.object(h.HumanSession,'_boot',return_value='explicit-disposable-kernel-fixture'),patch.object(h.HumanSession,'login',fresh):
   following=login.open_scope_login(self.human,self.case,self.context,self.closure,self.read,c.output.append)
   row=following._read();following._check_identity_and_budget(row)
   self.assertEqual(row['attempts'],137);self.assertEqual(row['binding']['retryProfile']['maximumAttempts'],256)
   self.assertEqual(row['state'],'READY');self.assertEqual(c.fixture.refreshes,0);self.assertEqual((self.old/'recovery.json').read_bytes(),self.before)
   self.assertNotIn('PRIVATE_OLD',json.dumps(row));self.assertEqual(self.prompts[0][0]['maximumRemainingOAuthAttempts'],123)
   self.assertEqual(following.current()['subject'],'human-fixture')
   row['attempts']=256;following.journal.record.write_bytes(encoded(row));calls=len(c.fixture.calls)
   with self.assertRaisesRegex(Exception,'BUDGET_EXHAUSTED'):following._request(row,'USERINFO',row['endpoints']['userinfo_endpoint'],bearer=row['accessToken'])
   self.assertEqual(len(c.fixture.calls),calls)
   row['attempts']=0;following.journal.record.write_bytes(encoded(row))
   with self.assertRaisesRegex(Exception,'CUMULATIVE_HISTORY'):following._check_identity_and_budget(row)
 def test_issuer_token_without_requested_recovery_scope_cannot_complete(self):
  c=self.c;original=h.HumanSession.login
  def fresh(session,emit):session.opener=oauth.FixtureOpener(c.server.server_port);return original(session,emit,oauth.ImmediateFixtureWait(c.clock))
  with patch.object(oauth.module,'SCOPES',h.LEGACY_SCOPES),patch.object(h,'time',c.clock),patch.object(login,'time',c.clock),patch.object(login,'authority',self.authority),patch.object(login,'HumanSession',h.HumanSession),patch.object(login,'PROFILE',h.PROFILE),patch.object(login,'SCOPES',h.SCOPES),patch.object(login,'LEGACY_SCOPES',h.LEGACY_SCOPES),patch.object(h.HumanSession,'_boot',return_value='explicit-disposable-kernel-fixture'),patch.object(h.HumanSession,'login',fresh):
   with self.assertRaisesRegex(Exception,'EXACT_CURRENT_HUMAN_CONTEXT_REQUIRED'):login.open_scope_login(self.human,self.case,self.context,self.closure,self.read,c.output.append)
   self.assertFalse((self.context/'review.json').exists());self.assertEqual((self.old/'recovery.json').read_bytes(),self.before)
   self.assertFalse(any('OUF_CSV_RECOVERY_HUMAN_LOGIN='in line for line in c.output))
 def test_ambiguous_request_never_qualifies_and_wrong_consent_has_no_claim(self):
  c=self.c
  with patch.object(oauth.module,'SCOPES',h.SCOPES),patch.object(h,'time',c.clock),patch.object(login,'time',c.clock),patch.object(h.HumanSession,'_boot',return_value='explicit-disposable-kernel-fixture'):
   for changes in({'state':'REQUESTING'},{'state':'BLOCKED'},{'attempts':0},{'attempts':256}):
    with self.assertRaises(Exception):login.scope_review(self.human,{**self.row,**changes},self.case,self.closure)
   with patch.object(login,'authority',SimpleNamespace(terminal_consent=lambda *a,**k:{'reviewHash':'wrong','decision':'DECLINE'})):
    with self.assertRaises(Exception):login.open_scope_login(self.human,self.case,self.context,self.closure,self.read,lambda _:None)
   self.assertFalse((self.old/'successor-window.claim.json').exists());self.assertEqual((self.old/'recovery.json').read_bytes(),self.before)
