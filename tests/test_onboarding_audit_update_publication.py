"""Actual entrypoint function: concurrent renewal is observed, never driven."""
import ast,copy,hashlib,json,unittest
from pathlib import Path

class Denied(RuntimeError):pass
def require(ok,reason):
 if not ok:raise Denied(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

class Publication(unittest.TestCase):
 def setUp(self):
  import time
  source=Path(__file__).resolve().parents[1]/'tools/onboarding_audit_update/entry.py'
  tree=ast.parse(source.read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='read_active_publication')
  ns={'time':time,'require':require,'digest':digest,'encoded':encoded}
  exec(compile(ast.Module(body=[fn],type_ignores=[]),str(source),'exec'),ns)
  self.read=ns['read_active_publication'];self.worker={'scope':'same-signed-worker'};self.now=1000.;self.waits=[];self.guards=0
  self.row={'workerSessionHash':digest(self.worker),'state':'ACTIVE','reason':'RECOVERED','attempts':27,'controlledPredecessorGrantAttempts':188,'controlledCumulativeGrantAttempts':215,'publicationCount':27,'tokenExpiresWall':1292.,'lastWall':993.}
 def run_rows(self,rows):
  outer=self
  class Journal:
   def private_read(self):
    outer.reads+=1;return copy.deepcopy(rows.pop(0)if len(rows)>1 else rows[0])
  self.reads=0
  def guard():self.guards+=1
  def wait(delay):self.waits.append(delay);self.now+=delay
  return self.read(Journal(),self.worker,guard,clock=lambda:self.now,monotonic=lambda:self.now,wait=wait,jitter=lambda:0.5,emit=lambda _:None)
 def test_observed_target_active_record_passes_without_wait(self):
  self.assertEqual(self.run_rows([self.row])['controlledCumulativeGrantAttempts'],215);self.assertEqual(self.waits,[])
 def test_each_normal_inflight_state_then_active_is_read_only(self):
  for state,reason in [('NEW','SCHEDULED_RENEWAL_DUE'),('ATTEMPTING','FRESH_ATTEMPT'),('PUBLISHING','FRESH_EVIDENCE_READY')]:
   self.now=1000.;self.waits=[]
   self.assertEqual(self.run_rows([{**self.row,'state':state,'reason':reason},self.row])['state'],'ACTIVE')
   self.assertEqual(self.waits,[5.]);self.assertEqual(self.reads,2)
 def test_cancelled_blocked_ambiguous_and_unknown_never_wait(self):
  for state in ('CANCELLED','BLOCKED','RECONCILE_REQUIRED','RETRY_WAIT','PAUSED_EXHAUSTED','UNKNOWN'):
   self.waits=[]
   with self.assertRaisesRegex(Denied,'CURRENT_POLICY_WORKER_NOT_ACTIVE'):self.run_rows([{**self.row,'state':state}])
   self.assertEqual(self.waits,[])
 def test_identity_history_staleness_expiry_fail_without_wait(self):
  for changes in ({'workerSessionHash':'0'*64},{'controlledCumulativeGrantAttempts':214},{'lastWall':900.},{'tokenExpiresWall':1009.},{'publicationCount':0}):
   self.waits=[]
   with self.assertRaises(Denied):self.run_rows([{**self.row,**changes}])
   self.assertEqual(self.waits,[])
 def test_stuck_publication_has_three_reads_and_finite_twenty_second_wait(self):
  with self.assertRaisesRegex(Denied,'CURRENT_POLICY_RENEWAL_NOT_COMPLETED'):self.run_rows([{**self.row,'state':'PUBLISHING','reason':'FRESH_EVIDENCE_READY'}])
  self.assertEqual(self.waits,[5.,15.]);self.assertEqual(self.reads,3);self.assertEqual(self.guards,3)
 def test_token_expiry_during_wait_blocks_acceptance(self):
  with self.assertRaisesRegex(Denied,'CURRENT_POLICY_TOKEN_WINDOW_INSUFFICIENT'):self.run_rows([{**self.row,'state':'ATTEMPTING','reason':'FRESH_ATTEMPT','tokenExpiresWall':1012.},{**self.row,'tokenExpiresWall':1012.}])
  self.assertEqual(self.waits,[5.])
if __name__=='__main__':unittest.main()
