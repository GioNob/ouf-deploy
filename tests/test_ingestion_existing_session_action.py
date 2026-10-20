"""Governed continuation: real orchestration with synthetic owner/HUMAN boundary."""
import ast,copy,hashlib,importlib.util,json,os,signal,threading,time,types,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/prepare-ingestion-existing-session-action.py'
ENTRY=ROOT/'scripts/ingestion-existing-session-entry.py'
if not SCRIPT.exists():
 SCRIPT=Path(__file__).with_name('prepare-ingestion-existing-session-action.py')
 ENTRY=Path(__file__).with_name('ingestion-existing-session-entry.py')
spec=importlib.util.spec_from_file_location('child_preparation',SCRIPT)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
def require(ok,code):
 if not ok:raise ValueError(code)
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def load_entry():
 tree=ast.parse(ENTRY.read_bytes());tree.body=[n for n in tree.body if not isinstance(n,(ast.Import,ast.ImportFrom))]
 ns={'Path':Path,'require':require,'digest':digest,'os':os,'time':time,'signal':signal,'threading':threading,
  'encoded':lambda v:json.dumps(v).encode()}
 exec(compile(tree,'<qualified-existing-session-entry>','exec'),ns);return ns
class Human:
 def __init__(self,*a):self.directory=Path('/fixture/human');self.attempts=212;self.binding={'sessionDirectory':'/fixture/human','tokenPath':'/fixture/human/token','expiresAt':int(time.time())+7200};self.expires_at=self.binding['expiresAt'];self.token_path=Path('/fixture/token');self.thread=None;self.state='READY';self.expired=False;self.refreshes=0
 def _read(self):return {'attempts':self.attempts,'binding':copy.deepcopy(self.binding),'state':self.state}
 def _check_identity_and_budget(self,row):require(row['attempts']<=256,'BUDGET')
 def _check(self,row):require(not self.expired,'EXPIRED')
 def refresh_if_due(self):self.refreshes+=1;self.attempts+=2
 def current(self):return copy.deepcopy(self.binding)
 def start_refresh(self,*a,**kw):pass
class Boundary(unittest.TestCase):
 def setUp(self):self.ns=load_entry();self.human=Human()
 def test_current_session_refresh_preserves_cumulative_count_and_binding(self):
  self.assertEqual(self.ns['refresh_existing'](self.human,self.human.binding,212),214)
  self.assertEqual(self.human.refreshes,1)
 def test_expiry_blocked_lower_counter_and_successor_prevent_refresh(self):
  for kind in ('expired','blocked','counter','successor','identity'):
   h=Human()
   if kind=='expired':h.expired=True
   if kind=='blocked':h.state='BLOCKED'
   if kind=='counter':h.attempts=211
   binding=copy.deepcopy(h.binding)
   if kind=='identity':binding['subject']='other'
   with patch.object(os.path,'lexists',return_value=kind=='successor'):
    with self.subTest(kind=kind),self.assertRaises(Exception):self.ns['refresh_existing'](h,binding,212)
   self.assertEqual(h.refreshes,0)
 def test_exhaustion_and_refresh_counter_regression_fail_closed(self):
  for resulting in (211,257):
   h=Human();h.refresh_if_due=lambda:setattr(h,'attempts',resulting)
   with self.assertRaises(Exception):self.ns['refresh_existing'](h,h.binding,212)
 def setup_main(self):
  self.events=[];self.plan={'selection':{},'baseline':{'policy':'unchanged'},'helperBindings':{'sha':'sealed'}}
  self.case={'humanBinding':self.human.binding,'priorOAuthAttempts':212,'sourceId':'fixture','predecessorHistoryHash':'e'*64}
  owner=types.SimpleNamespace(bindings={'sha':'sealed'})
  self.transport=types.SimpleNamespace(observe=lambda:copy.deepcopy(self.plan['baseline']))
  self.authority=Mock();self.authority.compile_action_review.return_value={}
  self.authority.terminal_consent.side_effect=lambda *a:self.events.append('APPROVO')or{'decision':'native'}
  self.authority.issue_action.side_effect=lambda *a:self.events.append('issue')or Mock()
  self.authorization=Mock();self.authorization.OwnerTransport.return_value=self.transport
  self.delta=Mock();self.delta.apply.side_effect=lambda:self.events.append('apply')or{'readback':'fixture'}
  self.authorization.AuthorizationDelta.return_value=self.delta
  self.ns.update(authority=self.authority,authorization=self.authorization,HumanSession=lambda *a:self.human,
   validate_continuation=lambda *a:self.plan,validate_plan=lambda *a:None,primitives=lambda *a:owner,
   publish_json=lambda *a:self.events.append('publish:'+a[1]),Journal=lambda *a:Mock())
 def invoke(self):
  with patch.object(Path,'mkdir'),patch.object(os.path,'lexists',return_value=False):
   self.ns['main']({'authorization':{'plan':{'selection':{}}}}, {}, {}, self.case,Path('/fixture/child'),Mock(),Mock())
 def test_baseline_drift_stops_before_review_signing_and_mutation(self):
  self.setup_main();self.transport.observe=lambda:{'policy':'changed'}
  with self.assertRaisesRegex(ValueError,'COMPLETE_AUTHORIZATION_PREFLIGHT_DRIFT'):self.invoke()
  self.authority.terminal_consent.assert_not_called();self.authority.issue_action.assert_not_called();self.delta.apply.assert_not_called()
 def test_declining_native_approval_never_issues_or_applies(self):
  self.setup_main();self.authority.terminal_consent.side_effect=ValueError('DECLINED')
  with self.assertRaisesRegex(ValueError,'DECLINED'):self.invoke()
  self.authority.issue_action.assert_not_called();self.delta.apply.assert_not_called()
 def test_exact_plan_approval_precedes_issuance_and_owner_delta(self):
  self.setup_main();self.invoke()
  self.assertLess(self.events.index('APPROVO'),self.events.index('issue'))
  self.assertLess(self.events.index('issue'),self.events.index('apply'))
  args=self.authorization.AuthorizationDelta.call_args.args
  self.assertIs(args[1],self.plan);self.assertEqual(self.human.attempts,214)
 def test_no_login_or_iam_reauthentication_or_old_entry_dispatch_available(self):
  tree=ast.parse(ENTRY.read_bytes())
  calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(any(c.endswith(('.authenticate','.login','.ensure'))for c in calls))
  self.assertNotIn('login',ast.unparse(tree));self.assertNotIn('iam.ensure',ast.unparse(tree))
 def test_plan_file_bindings_and_claim_are_rechecked_before_execution(self):
  context=Path('/fixture/child');binding={'session':'existing'}
  plan={'sessionBinding':binding};plan_hash=digest(plan)
  continuation={'schema':'ouf.ingestion-existing-session-continuation.v1','newHumanLoginAllowed':False,
   'budgetReset':False,'maximumCumulativeOAuthAttempts':256,'fileBindings':{'/fixture/evidence':'e'*64},
   'claimBinding':{'path':'/fixture/claim','sha256':'c'*64},'originalContext':'/fixture/old',
   'preflightContext':'/fixture/preflight','planHash':plan_hash,'planPath':'/fixture/plan'}
  case={'existingSessionContinuation':continuation,'priorOAuthAttempts':212,'humanBinding':binding,'sourceId':'source'}
  claim={'context':str(context),'originalContext':'/fixture/old','preflightContext':'/fixture/preflight',
   'planHash':plan_hash,'priorOAuthAttempts':212,'maximumCumulativeOAuthAttempts':256,
   'budgetReset':False,'automaticReplayAllowed':False}
  calls=[]
  def read(path,**kw):
   calls.append((path,kw));return copy.deepcopy(claim if path=='/fixture/claim'else plan)
  self.ns['validate_plan']=Mock()
  with patch.object(os.path,'lexists',return_value=False):
   self.assertEqual(self.ns['validate_continuation'](case,read,context),plan)
  self.assertEqual(calls[0],('/fixture/evidence',{'expected':'e'*64}))
  self.assertEqual(calls[-1],('/fixture/plan',{'expected':plan_hash}))
  with patch.object(os.path,'lexists',return_value=True):
   with self.assertRaisesRegex(ValueError,'PREDECESSOR_AUTHORITY_OR_EFFECT_RECONCILIATION_REQUIRED'):
    self.ns['validate_continuation'](case,read,context)
  claim['budgetReset']=True
  with patch.object(os.path,'lexists',return_value=False):
   with self.assertRaisesRegex(ValueError,'EXACT_ONE_USE_CONTINUATION_CLAIM_REQUIRED'):
    self.ns['validate_continuation'](case,read,context)
 def test_new_entry_fits_existing_closed_181_module_loader(self):
  path=ROOT/'tools/ingestion_read_authorization/runtime.py'
  if not path.exists():path=Path(__file__).parents[1]/'repo/tools/ingestion_read_authorization/runtime.py'
  namespace={'__name__':'qualified_loader'};exec(compile(path.read_bytes(),str(path),'exec'),namespace)
  sources={name:b'pass\n'for name in namespace['MODULES']}
  self.assertEqual(len(sources),181)
  sources[namespace['ENTRY']]=ENTRY.read_bytes()
  self.assertEqual(set(namespace['compile_sources'](sources)),set(sources))
class PreflightBindings(unittest.TestCase):
 def fixture(self):
  plan={'sessionBinding':{'session':'existing'},'baseline':{'policy':'45'}}
  report={'schema':'ouf.ingestion-administrative-existing-session-preflight.v1','preflightPassed':True,
   'phase':'PREFLIGHT_COMPILED_NO_AUTHORITY','planHash':digest(plan),'diagnosticContextPath':str(p.PREFLIGHT),
   'oauthAttemptsAfter':212,'oauthAttemptsBefore':210,'maximumCumulativeOAuthAttempts':256,
   'originalHumanWindowExpiresAt':1792405963,**{k:False for k in ('newHumanLoginAllowed','budgetReset',
    'automaticReplayAllowed','ownerMutationsAllowed','iamMutationsAllowed','runtimeAuthorityIssued','sourceActivated')}}
  receipt={'packageHash':'p'*64};context=Path('/fixture/original')
  claim={'schema':'ouf.ingestion-read-existing-session-preflight-claim.v1','sourceHash':p.DIAGNOSTIC,
   'originalContext':str(context),'packageHash':receipt['packageHash'],'context':str(p.PREFLIGHT),
   'priorOAuthAttempts':210,'humanBindingHash':digest(plan['sessionBinding']),
   'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False}
  return report,plan,copy.deepcopy(plan['baseline']),claim,receipt,context
 def test_valid_bound_preflight_is_accepted_without_effects(self):
  args=self.fixture()
  with patch.object(p,'PLAN',digest(args[1])):p.validate_preflight(*args)
 def test_stale_plan_foreign_claim_budget_reset_and_issued_authority_rejected(self):
  for where,key,value in ((0,'planHash','tampered'),(0,'budgetReset',True),(0,'runtimeAuthorityIssued',True),
   (3,'originalContext','foreign'),(3,'humanBindingHash','foreign'),(3,'maximumCumulativeOAuthAttempts',257),
   (2,'policy','changed')):
   args=list(self.fixture());args[where][key]=value
   with patch.object(p,'PLAN',digest(args[1])):
    with self.subTest(key=key),self.assertRaises(Exception):p.validate_preflight(*args)
 def test_preparation_never_runs_preflight_main_login_or_completed_readback(self):
  calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)]
  self.assertFalse(any(c.endswith(('.authenticate','.login','.refresh_if_due'))for c in calls))
  self.assertNotIn("ns['main']",calls);self.assertNotIn('entry.main',calls)
if __name__=='__main__':unittest.main()
