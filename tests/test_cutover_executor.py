"""Owner-adapter composition fixtures, never target signed authority."""
import json,sys,tempfile,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
from cutover_executor import Executor,CutoverDenied,digest
from transition_journal import Transition,PHASES
import importlib.util
JOURNAL=ROOT/'tools/semantic_lease_recovery/recovery_journal.py'
if not JOURNAL.exists():JOURNAL=ROOT/'tests/fixtures/recovery_journal.py'
s=importlib.util.spec_from_file_location('journal',JOURNAL);j=importlib.util.module_from_spec(s);s.loader.exec_module(j)
class Composition(unittest.TestCase):
 def fixture(self,mutate=None):
  directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup);root=Path(directory.name);root.chmod(0o700)
  intents={p:{'fixturePhase':p,'scope':'isolated-fixture-only'} for p in PHASES}
  authority={'schema':'ouf.semantic-cutover-execution-authority.v1','issuedAt':100,'expiresAt':200,'creationRequestHash':'b'*64,'predecessorHistoryHash':'c'*64,'predecessorIncidentRef':'d'*64,'sourceClosureHash':'e'*64,'phaseIntentHashes':{p:digest(v) for p,v in intents.items()},'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False,'newDistinctLeaseWorkerRequired':True}
  if mutate:mutate(authority)
  raw=json.dumps(authority,sort_keys=True,separators=(',',':')).encode();sha=__import__('hashlib').sha256(raw).hexdigest()
  initial=Transition.initial(sha,'b'*64,'c'*64,'d'*64);journal=j.Journal(root);journal.initialize(initial);t=Transition(journal,initial['contextHash'])
  calls=[];state={};observations={};clock=[150];authenticated=[True]
  def checkpoint(phase,point,row):return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,'journalVersion':row['version'],'intentHash':authority['phaseIntentHashes'][phase],'authorityHash':sha,'sourceClosureHash':authority['sourceClosureHash'],'nativeEvidenceHash':'f'*64}
  adapters={}
  for p in PHASES:
   def apply(intent,p=p):calls.append(p);state[p]=True
   def observe(intent,p=p):return observations.get(p,('APPLIED' if state.get(p) else 'UNKNOWN',{'fixtureNativeState':state.get(p,False)}))
   adapters[p]=types.SimpleNamespace(apply=apply,observe=observe)
  e=Executor(t,raw,lambda raw:authenticated[0],checkpoint,adapters,intents,lambda:clock[0])
  return e,calls,state,observations,clock,authenticated,root
 def test_all_thirteen_phases_are_composed_in_order_and_repeat_has_no_effects(self):
  e,calls,*_=self.fixture();r=e.run();self.assertEqual(calls,list(PHASES));self.assertEqual(r['completedPhaseCount'],13);self.assertFalse(r['releaseAcceptance']);self.assertFalse(r['automaticReplayAllowed']);self.assertTrue(r['databaseMayHaveChanged']);self.assertTrue(r['applicationWritesMayHaveOccurred']);e.run();self.assertEqual(calls,list(PHASES))
 def test_partial_checkpoint_never_runs_later_effects_or_claims_completion(self):
  e,calls,*_=self.fixture();r=e.run(5);self.assertEqual(calls,list(PHASES[:5]));self.assertEqual(r['status'],'ORDERED_PARTIAL_CHECKPOINT_NOT_RELEASE_ACCEPTANCE');self.assertFalse(r['releaseAcceptance']);e.run(5);self.assertEqual(calls,list(PHASES[:5]));e.run();self.assertEqual(calls,list(PHASES))
 def test_crash_after_each_phase_effect_reopens_without_duplicate(self):
  for phase in PHASES:
   with self.subTest(phase=phase):
    e,calls,state,observations,clock,authenticated,root=self.fixture();original=e.adapters[phase].apply
    def crash(intent):original(intent);raise RuntimeError('fixture-crash')
    e.adapters[phase].apply=crash
    with self.assertRaisesRegex(RuntimeError,'fixture-crash'):e.run()
    self.assertEqual(e.t.read()['state'],'IN_FLIGHT');self.assertEqual(calls.count(phase),1)
    e.t=Transition(j.Journal(root),e.t.context);e.adapters[phase].apply=original;e.run();self.assertEqual(calls,list(PHASES))
 def test_ambiguous_effect_is_never_replayed_or_skipped(self):
  e,calls,state,observations,*_=self.fixture();observations[PHASES[2]]=('UNKNOWN',{'fixtureUnknown':True})
  with self.assertRaises(CutoverDenied):e.run()
  self.assertEqual(calls,list(PHASES[:3]));self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
  with self.assertRaises(CutoverDenied):e.run()
  self.assertEqual(calls,list(PHASES[:3]));observations[PHASES[2]]=('APPLIED',{'fixtureReconciled':True});e.run();self.assertEqual(calls,list(PHASES))
 def test_no_effect_stays_consumed_and_cannot_be_retried(self):
  e,calls,state,observations,*_=self.fixture();observations[PHASES[0]]=('NO_EFFECT',{'fixtureProvenAbsent':True})
  with self.assertRaises(CutoverDenied):e.run()
  self.assertEqual(e.t.read()['state'],'NO_EFFECT_REQUIRES_NEW_DECISION')
  with self.assertRaises(CutoverDenied):e.run()
  self.assertEqual(calls,[PHASES[0]])
 def test_expired_revoked_drift_or_restore_authority_blocks_before_first_effect(self):
  for mutation in (lambda a:a.update(expiresAt=100),lambda a:a.update(expiresAt=4000),lambda a:a.update(databaseRestoreAuthorized=True),lambda a:a.update(r12ReplayAuthorized=True),lambda a:a.update(creationRequestHash='a'*64)):
   e,calls,*_=self.fixture(mutation)
   with self.assertRaises(CutoverDenied):e.run()
   self.assertEqual(calls,[]);self.assertEqual(e.t.read()['version'],0)
  e,calls,state,observations,clock,authenticated,*_=self.fixture();authenticated[0]=False
  with self.assertRaises(CutoverDenied):e.run()
  self.assertEqual(calls,[])
 def test_authority_revocation_after_claim_leaves_ambiguity_without_effect(self):
  e,calls,state,observations,clock,authenticated,*_=self.fixture();original=e.checkpoint
  def checkpoint(p,point,row):
   proof=original(p,point,row)
   if point=='BEFORE_DURABLE_INTENT':authenticated[0]=False
   return proof
  e.checkpoint=checkpoint
  with self.assertRaises(CutoverDenied):e.run()
  self.assertEqual(calls,[]);self.assertEqual(e.t.read()['state'],'IN_FLIGHT')
 def test_noop_stale_version_or_foreign_source_checkpoint_blocks(self):
  for change in (None,'journalVersion','sourceClosureHash','intentHash'):
   e,calls,*_=self.fixture();original=e.checkpoint
   if change is None:e.checkpoint=lambda *args:None
   else:
    def wrong(*args):
     proof=original(*args);proof[change]=0 if change=='journalVersion' else '0'*64;return proof
    e.checkpoint=wrong
   with self.assertRaises(CutoverDenied):e.run()
   self.assertEqual(calls,[])
 def test_missing_adapter_or_mutated_intent_is_not_admitted(self):
  e,calls,*_=self.fixture();del e.adapters[PHASES[-1]]
  with self.assertRaises(CutoverDenied):Executor(e.t,e.raw,e.authenticate,e.checkpoint,e.adapters,e.intents,e.clock)
  e,calls,*_=self.fixture();e.intents[PHASES[0]]['scope']='drift'
  with self.assertRaisesRegex(CutoverDenied,'IMMUTABLE_PHASE_ADAPTER_OR_INTENT_DRIFT'):e.run()
  self.assertEqual(calls,[])
if __name__=='__main__':unittest.main()
