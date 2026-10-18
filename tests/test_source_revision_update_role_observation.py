"""Real signed authorization owner; network fixture exercises finite read recovery."""
import copy,sys,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_source_revision_authorization as fixtures
from tools.source_revision_update import entry
from tools.chatbot_file_cohort import authorization as auth

class RoleObservation(unittest.TestCase):
 def setUp(self):
  self.fixture=fixtures.RevisionSignedOwner();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.now=float(self.fixture.crypto.now);self.mono=1000.;self.calls=[]
  self.messages=[];self.cancelled=threading.Event()
  for name,fn in [('time',lambda:self.now),('monotonic',lambda:self.mono)]:
   p=patch.object(entry.time,name,fn);p.start();self.addCleanup(p.stop)
  p=patch.object(self.cancelled,'wait',side_effect=self.advance);p.start();self.addCleanup(p.stop)
 def advance(self,delay):
  self.now+=delay;self.mono+=delay;self.fixture.crypto.now=self.now;return False
 def run_reads(self,answers):
  def tool(name,args,key):
   self.calls.append((name,args,key,self.now))
   answer=answers.pop(0)
   if isinstance(answer,Exception):raise answer
   return answer
  with patch.object(self.fixture.transport,'tool',side_effect=tool):
   entry.wait_for_role(self.fixture.delta,self.fixture.transport,'fixture-proposal',self.cancelled,self.messages.append)
 def test_pending_then_published_has_admission_spacing_and_no_mutation(self):
  self.run_reads([{'proposalId':'fixture-proposal','state':'PENDING'},
                  {'proposalId':'fixture-proposal','state':'PUBLISHED'}])
  self.assertEqual(len(self.calls),2);self.assertGreaterEqual(self.calls[1][3]-self.calls[0][3],31)
  row=self.fixture.delta.record()['sourceRevisionRoleObservation']
  self.assertEqual(row['attempts'],2);self.assertEqual(row['state'],'COMPLETE');self.assertFalse(row['budgetReset'])
  self.assertFalse(self.fixture.owner.calls)
 def test_transient_network_and_retry_after_preserve_one_budget(self):
  self.run_reads([auth.AuthorizationPaused('AUTHORIZATION_HTTP_503',retryAfterSeconds=40),
                  {'proposalId':'fixture-proposal','state':'PUBLISHED'}])
  self.assertGreaterEqual(self.calls[1][3]-self.calls[0][3],40)
  self.assertEqual(self.fixture.delta.record()['sourceRevisionRoleObservation']['attempts'],2)
 def test_unknown_failure_never_dispatches_second_request(self):
  with self.assertRaises(Exception):self.run_reads([auth.AuthorizationPaused('AUTHORIZATION_HTTP_403')])
  self.assertEqual(len(self.calls),1)
  self.assertEqual(self.fixture.delta.record()['sourceRevisionRoleObservation']['state'],'ATTEMPTING')
  with self.assertRaises(Exception):self.run_reads([])
  self.assertEqual(len(self.calls),1)
 def test_wrong_proposal_cannot_complete_the_review(self):
  with self.assertRaises(Exception):self.run_reads([{'proposalId':'other','state':'PUBLISHED'}])
  self.assertEqual(len(self.calls),1)
 def test_invalid_retry_after_blocks_without_reset(self):
  with self.assertRaises(Exception):self.run_reads([auth.AuthorizationPaused('AUTHORIZATION_HTTP_429',retryAfterInvalid=True)])
  self.assertEqual(len(self.calls),1)
 def test_revoked_human_authority_stops_before_network(self):
  f=self.fixture.crypto;f.approval['state']='REVOKED';f.write(f.mandate,fixtures.existing.encoded(f.approval))
  with self.assertRaises(Exception):self.run_reads([])
  self.assertFalse(self.calls)

if __name__=='__main__':unittest.main()
