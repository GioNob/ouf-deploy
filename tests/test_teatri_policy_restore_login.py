"""New typed test budget, native private journals and real loopback OAuth; no target IAM."""
import ast,copy,json,os,time,uuid,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_chatbot_cohort_human_session as oauth
from tools.teatri_policy_restore import human_session_v2 as h
from tools.chatbot_file_cohort import human_session as standard
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory
from iam_owner_action import publish
from tools.semantic_mcp_update.owner import digest,encoded,require
ROOT=Path(__file__).resolve().parents[1]
tree=ast.parse((ROOT/'tools/teatri_policy_restore/entry.py').read_text())
def functions():
 ns={'Path':Path,'os':os,'time':time,'copy':copy,'uuid':uuid,'Journal':Journal,'protected_directory':protected_directory,'publish':publish,'digest':digest,'encoded':encoded,'require':require,'HumanSession':h.HumanSession,'PROFILE':h.PROFILE,'CLIENT':h.CLIENT,'SCOPES':h.SCOPES}
 def publish_json(context,name,value):
  with protected_directory(context)as directory:require(publish(directory,name,encoded(value)),'ALREADY_PRESENT')
 ns['publish_json']=publish_json
 for name in('budget_review','open_test_successor'):
  fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name);exec(compile(ast.Module(body=[fn],type_ignores=[]),'<test-budget>','exec'),ns)
 return ns
class TestBudget(unittest.TestCase):
 def setUp(self):
  c=oauth.HumanSessionTest();c.setUp();self.addCleanup(c.doCleanups);self.c=c
  self.old=c.directory/'old';self.old.mkdir(mode=0o700);self.context=c.directory/'operation';self.context.mkdir(mode=0o700)
  self.ns=functions();self.ns['time']=c.clock
  now=int(c.clock.time());self.hb={'sessionId':'old','selectionHash':digest(c.selection),**{k:c.selection[k]for k in('issuer','tenant','subject')},'clientId':h.CLIENT,'scopes':list(h.SCOPES),'tokenPath':str(self.old/'human-access.jwt'),'sessionDirectory':str(self.old),'createdAt':now-7000,'expiresAt':now+200,'retryProfile':copy.deepcopy(standard.PROFILE)}
  self.row={'binding':self.hb,'attempts':125,'state':'BLOCKED','operation':'REFRESH','reason':'HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN','budgetReset':False,'accessToken':'PRIVATE_OLD_ACCESS','refreshToken':'PRIVATE_OLD_REFRESH'}
  Journal(self.old).initialize(self.row);self.before=(self.old/'recovery.json').read_bytes()
  (self.context/'worker-review.json').write_bytes(encoded({'worker':'eight-attempt-fixture'}));(self.context/'worker-review.json').chmod(0o600)
  self.case={'failedPreparationContext':'/fixture/failed-preparation'};self.prompts=[]
  def consent(review,summary,login):
   self.prompts.append((review,summary));return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':digest(review),'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
  self.ns['authority']=SimpleNamespace(terminal_consent=consent)
  self.read=lambda p,*a:json.loads(Path(p).read_bytes())
 def test_native_successor_preserves125_and_completes_real_device_login_without_old_refresh(self):
  original=h.HumanSession.login;c=self.c
  def login(session,emit):
   session.opener=oauth.FixtureOpener(c.server.server_port)
   return original(session,emit,oauth.ImmediateFixtureWait(c.clock))
  with patch.object(h,'time',c.clock),patch.object(h.HumanSession,'_boot',return_value='explicit-disposable-kernel-fixture'),patch.object(h.HumanSession,'login',login):
   new=self.ns['open_test_successor'](c.selection,self.hb,self.row,self.case,self.context,self.read,c.output.append)
   row=new._read();new._check_identity_and_budget(row)
   self.assertEqual(row['attempts'],129);self.assertEqual(row['binding']['retryProfile']['maximumAttempts'],256);self.assertEqual(row['state'],'READY');self.assertEqual(c.fixture.refreshes,0)
   self.assertNotIn('PRIVATE_OLD',json.dumps(row));self.assertEqual((self.old/'recovery.json').read_bytes(),self.before)
   self.assertEqual(self.prompts[0][0]['priorOAuthAttempts'],125);self.assertEqual(self.prompts[0][0]['maximumRemainingOAuthAttempts'],131)
   self.assertFalse(self.prompts[0][0]['runtimeAuthorityIssued']);self.assertNotIn('PRIVATE_',json.dumps(self.prompts))
   self.assertEqual(new.current()['subject'],'human-fixture')
   row['attempts']=256;new.journal.record.write_bytes(encoded(row));calls=len(c.fixture.calls)
   with self.assertRaisesRegex(Exception,'BUDGET_EXHAUSTED'):new._request(row,'USERINFO',row['endpoints']['userinfo_endpoint'],bearer=row['accessToken'])
   self.assertEqual(len(c.fixture.calls),calls)
   row['attempts']=0;new.journal.record.write_bytes(encoded(row))
   with self.assertRaisesRegex(Exception,'CUMULATIVE_HISTORY'):new._check_identity_and_budget(row)
 def test_wrong_consent_is_rejected_before_claim_and_ambiguous_refresh_never_qualifies(self):
  for changes in({'state':'REQUESTING'},{'reason':'HUMAN_OAUTH_OUTCOME_UNPROVEN'},{'operation':'USERINFO'},{'attempts':129}):
   with self.assertRaises(Exception):self.ns['budget_review'](self.hb,{**self.row,**changes},{'scope':'a'*64})
  self.ns['authority']=SimpleNamespace(terminal_consent=lambda *a,**k:{'schema':'wrong'})
  with self.assertRaises(Exception):self.ns['open_test_successor'](self.c.selection,self.hb,self.row,self.case,self.context,self.read,lambda _:None)
  self.assertFalse((self.old/'successor-window.claim.json').exists());self.assertEqual((self.old/'recovery.json').read_bytes(),self.before)
 def test_profile_is_workflow_specific_and_cannot_initialize_without_review(self):
  self.assertEqual(standard.PROFILE['maximumAttempts'],128);self.assertEqual(h.PROFILE['maximumAttempts'],256)
  session=h.HumanSession(self.c.selection,self.c.directory,self.c.directory/'human-access.jwt',int(time.time())+600)
  with self.assertRaisesRegex(h.HumanSessionPaused,'RECEIPT_REQUIRED'):session.login(lambda _:self.fail('no prompt'))
  self.assertFalse(session.journal.record.exists())
if __name__=='__main__':unittest.main()
