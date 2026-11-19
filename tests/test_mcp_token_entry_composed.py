"""Native owner/TLS/signatures with explicit synthetic terminal and OAuth boundary."""
import copy,dataclasses,json,os,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_semantic_token_execution as old
from tools.semantic_mcp_update import entry as m
from tools.semantic_mcp_update import authority,session
from tools.chatbot_file_cohort.human_session import HumanSession,PROFILE,CLIENT,SCOPES
from tools.semantic_policy_token_owner.installed_owner import compile_governed_session

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','native UID/GID, procfs and root-owned fixture required')
class Entry(unittest.TestCase):
 def setUp(self):
  self.e=old.Execution();self.e.setUp();self.addCleanup(self.e.doCleanups)
  f=self.e.f;g=self.e.g;self.f=f;self.g=g
  # The explicit retained fixture models the observed second cancelled worker.
  previous=f.records['owner-session.json'];logical=previous['logicalOwnerScopeHash']
  fence_path=f.installed.journal.root.parent/('semantic-functional-session-'+logical+'.fence.json')
  previous.update(schema='ouf.policy-token-governed-worker-session.v1',predecessorGrantAttempts=69,
   maximumCumulativeGrantAttempts=197,reviewHash='7'*64,
   fenceBinding={'path':str(fence_path),'value':{'schema':'ouf.semantic-functional-session-fence.v1',
    'logicalOwnerScopeHash':logical,'journalPath':str(f.installed.journal.root),'reviewHash':'7'*64,
    'predecessorWorkerHash':'8'*64,'active':True}})
  row=f.records['recovery.json'];row.update(controlledPredecessorGrantAttempts=69,
   controlledCumulativeGrantAttempts=128,publicationCount=59,workerSessionHash=m.digest(previous))
  f.records['owner-status.json'].update(attempts=59,publications=59)
  for name,value in f.records.items():g.write(f.installed.journal.root/name,m.encoded(value))
  g.write(fence_path,m.encoded(previous['fenceBinding']['value']));self.before={name:(f.installed.journal.root/name).read_bytes()for name in f.records}
  self.context=g.root/'semantic-mcp-update-execution-abcdefgh';self.context.mkdir(mode=0o700)
  self.previous=g.root/'human-session-window2';self.previous.mkdir(mode=0o700)
  actor=f.review['requestedHumanActor'];expiry=1792172784
  self.old_human=HumanSession(actor,self.previous,self.previous/'human-access.jwt',expiry)
  binding={'sessionId':'synthetic-expired-session','selectionHash':m.digest(actor),**actor,'clientId':CLIENT,'scopes':SCOPES,
   'sessionDirectory':str(self.previous),'tokenPath':str(self.previous/'human-access.jwt'),'createdAt':expiry-7200,
   'expiresAt':expiry,'retryProfile':PROFILE}
  earlier={'maximumCumulativeOAuthAttempts':128,'priorOAuthAttempts':42}
  self.old_human.journal.initialize({'schema':'ouf.chatbot-human-session.private.v1','binding':binding,
   'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'monotonicDeadline':time.monotonic()-1,
   'lastObservedAt':time.time()-2,'attempts':49,'state':'READY','operation':'USERINFO','budgetReset':False,
   'publishedAccessToken':'SYNTHETIC_PRIVATE_OLD_TOKEN','refreshToken':'SYNTHETIC_PRIVATE_OLD_REFRESH',
   'governedWindowRenewal':{'review':earlier,'decision':{'reviewHash':m.digest(earlier),'approvedAt':binding['createdAt'],'expiresAt':expiry}}})
  self.prepared={'owner':f.value,'engine':f.engine_binding,'authorization':{'plan':{'selection':actor}}}
  self.resources={'baseWorkerReview':f.review,'workerRecords':f.records,'workerJournal':str(f.installed.journal.root),
   'firstGrant':f.first,'mcpReviewBinding':{'path':str(g.root/'mcp-review.json'),'sha256':'9'*64},
   'previousHumanDirectory':str(self.previous),'previousHumanExpiry':expiry}
  self.closure=copy.deepcopy(self.e.closure);self.closure['declaration']['entryModule']='tools.semantic_mcp_update.entry'
  self.sources={module:f.base.files[name]for name,module in m.TOKEN_STAGE_SOURCE.items()}
  self.output=[];self.decisions=[]
 def consent(self,review,summary,login=False):
  self.decisions.append(('LOGIN'if login else'ACTION',m.digest(review)));now=int(time.time())
  if login:return {'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':m.digest(review),
   'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':now,'expiresAt':now+7200}
  return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':m.digest(review),
   'approvalRef':'mcp-scoped-'+m.digest(review)[:24]+'-'+str(now),'sourceClosureHash':review['sourceClosureHash'],
   'humanSessionHash':m.digest(review['authenticatedHuman']),'approvedAt':now,'expiresAt':now+3600,
   'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
 def test_complete_remainder_entry_has_two_distinct_decisions_one_real_grant_and_unchanged_old_records(self):
  def login(human,emit=print):return human._read()['binding']
  def current(human):return human._read()['binding']
  def serve(worker,stop,reporter):
   self.assertEqual(worker.r.policy.max_attempts,69);row=worker.tick();self.assertEqual(row['state'],'ACTIVE')
   self.assertEqual(row['controlledCumulativeGrantAttempts'],129);reporter.report(worker.status(row));stop.set()
  before=self.f.grants()
  with patch.object(authority,'terminal_consent',side_effect=self.consent),patch.object(authority,'stdlib_binding',return_value={'fileHashes':{}}),\
   patch.object(HumanSession,'login',login),patch.object(HumanSession,'current',current),patch.object(m,'serve',side_effect=serve):
   m.token_main(self.prepared,self.sources,self.closure,self.resources,self.context,self.output.append,transport=self.f.installed.first.transport)
  self.assertEqual(self.f.grants(),before+1);self.assertEqual([x[0]for x in self.decisions],['LOGIN','ACTION'])
  for name,raw in self.before.items():self.assertEqual((self.f.installed.journal.root/name).read_bytes(),raw)
  self.assertNotIn('SYNTHETIC_PRIVATE',str(self.output));self.assertTrue(any(x.startswith('OUF_POLICY_REMAINDER_STARTED=')for x in self.output))
  self.assertEqual(self.old_human._read()['attempts'],49)
 def test_rejected_runtime_decision_has_no_grant_or_fence_change(self):
  def deny(review,summary,login=False):
   if login:return self.consent(review,summary,True)
   raise RuntimeError('SYNTHETIC_OPERATOR_DID_NOT_APPROVE')
  path=Path(self.f.records['owner-session.json']['fenceBinding']['path']);before=path.read_bytes();grants=self.f.grants()
  with patch.object(authority,'terminal_consent',side_effect=deny),patch.object(authority,'stdlib_binding',return_value={'fileHashes':{}}),\
   patch.object(HumanSession,'login',lambda human,emit=print:human._read()['binding']):
   with self.assertRaisesRegex(RuntimeError,'SYNTHETIC_OPERATOR_DID_NOT_APPROVE'):
    m.token_main(self.prepared,self.sources,self.closure,self.resources,self.context,self.output.append,transport=self.f.installed.first.transport)
  self.assertEqual(self.f.grants(),grants);self.assertEqual(path.read_bytes(),before)
  self.assertFalse((self.context/'issuance.claim.json').exists())
if __name__=='__main__':unittest.main()
