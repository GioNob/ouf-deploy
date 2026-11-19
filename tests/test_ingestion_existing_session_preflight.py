"""No live credentials/targets. Native read boundaries and cumulative accounting."""
import ast,copy,hashlib,importlib.util,json,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/diagnose-ingestion-administrative-preflight.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).with_name('diagnose-ingestion-administrative-preflight.py')
spec=importlib.util.spec_from_file_location('native_preflight',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ADMIN='/api/trusted-human/v1/authorization'
class Transport:
 def __init__(self,*a,**k):
  self.calls=[];self.selection={'clients':{'chatgpt':{'clientId':'fixture-chat'},'ths':{'clientId':'fixture-ths'}}}
 def request(self,path,method='GET',body=None,**kw):self.calls.append(('HTTP',method,path));return (200,{}, {})
 def kc(self,verb,path,*args,**kw):self.calls.append(('IAM',verb,path));return []
 def tool(self,name,arguments,key):
  self.calls.append(('MCP',name));return self.request('/mcp','POST',{'method':'tools/call','params':{'name':name,'arguments':arguments}})
 def observe(self):return copy.deepcopy(OBSERVED)
OBSERVED={'active':{'policyRef':'fixture:45','policy':{'capabilities':[],'grants':[{'grantId':'unchanged'}]}},
 'registrations':{},'roles':{'roles':[{'roleId':'admin'}]},'oauth':{'scopes':{'ingestion.operations.read':{'protocolMappers':[{'config':'PRIVATE_MAPPER_CANARY'}]}},
 'clients':{'chatgpt':{'default':[]}}}}
class Human:
 token_path=Path('/fixture/human-access.jwt')
 def __init__(self,attempts=203,expired=False,blocked=False):
  self.attempts=attempts;self.binding={'sessionId':'fixture','expiresAt':7200};self.expired=expired;self.blocked=blocked;self.refreshes=0
 def _read(self):return {'attempts':self.attempts,'binding':copy.deepcopy(self.binding),'state':'BLOCKED'if self.blocked else'READY',
  'publishedAccessToken':'PRIVATE_TOKEN_CANARY','refreshToken':'PRIVATE_TOKEN_CANARY'}
 def _check(self,row):
  if self.expired:raise ValueError('EXPIRED_WINDOW')
 def refresh_if_due(self):self.refreshes+=1;self.attempts+=2
 def current(self):return copy.deepcopy(self.binding)
class Guards(unittest.TestCase):
 def setUp(self):self.report={};self.transport=Transport();m.constrain_transport(self.transport,ADMIN,self.report)
 def test_policy_mutation_grant_proposal_and_iam_writes_are_rejected_before_dispatch(self):
  for call in (lambda:self.transport.request(ADMIN+'/policies','POST',{}),
    lambda:self.transport.tool('authorization.permissions.propose',{},'key'),
    lambda:self.transport.kc('create','client-scopes',body={}),
    lambda:self.transport.request('/other/owner')):
   with self.assertRaises(Exception):call()
  self.assertEqual(self.transport.calls,[])
 def test_exact_reads_remain_available_and_role_read_cannot_be_duplicated(self):
  self.transport.request(ADMIN+'/policies/active');self.transport.request(ADMIN+'/capabilities?limit=200&offset=0')
  self.transport.kc('get','client-scopes')
  self.transport.kc('get','clients','-q','clientId=fixture-chat','--fields','id,clientId,enabled,protocol')
  self.transport.tool('authorization.permissions.read',{'view':'ROLES'},'key')
  self.assertEqual(self.report['mcpRoleDispatches'],1)
  with self.assertRaises(Exception):self.transport.tool('authorization.permissions.read',{'view':'ROLES'},'second')
  self.assertEqual(self.report['mcpRoleDispatches'],1)
 def test_direct_rpc_does_not_bypass_one_role_dispatch_limit(self):
  body={'method':'tools/call','params':{'name':'authorization.permissions.read','arguments':{'view':'ROLES'}}}
  self.transport.request('/mcp','POST',body)
  with self.assertRaises(Exception):self.transport.request('/mcp','POST',body)
  self.assertEqual(len(self.transport.calls),1)
 def test_finite_get_budget_and_exact_iam_query_arguments(self):
  for _ in range(8):self.transport.request(ADMIN+'/policies/active')
  with self.assertRaises(Exception):self.transport.request(ADMIN+'/policies/active')
  before=len(self.transport.calls)
  for args in(('get','client-scopes','--config','other'),('get','clients','-q','clientId=foreign','--fields','id,clientId,enabled,protocol')):
   with self.assertRaises(Exception):self.transport.kc(*args)
  self.assertEqual(len(self.transport.calls),before)
class ExistingWindow(unittest.TestCase):
 def run_probe(self,human):
  report={};saved={};transports=[]
  def factory(*a,**kw):
   t=Transport();transports.append(t);return t
  def compile_plan(observed,owner,selection,**kw):
   self.assertFalse(kw['include_ingestion_status']);self.assertEqual(kw['source_id'],'fixture-source')
   return {'registrationAdditions':[{}],'addedDescriptors':[{}],'scopeCreations':{},'scopeBindings':[],
    'targetRoles':observed['roles'],'baseline':observed,'sessionBinding':kw['session_binding']}
  entry=types.SimpleNamespace(authorization=types.SimpleNamespace(ADMIN=ADMIN,OwnerTransport=factory,compile_plan=compile_plan),
   validate_plan=lambda *_:None)
  try:m.bounded_preflight(entry,{}, {'sourceId':'fixture-source'},{},human,object(),report,lambda n,v:saved.update({n:v}))
  except Exception:return report,saved,transports,sys.exc_info()[1]
  return report,saved,transports,None
 def test_only_existing_refresh_advances_cumulative_counter_and_plan_is_private(self):
  human=Human();report,saved,transports,error=self.run_probe(human)
  self.assertIsNone(error);self.assertEqual(human.refreshes,1);self.assertEqual(report['oauthAttemptsBefore'],203)
  self.assertEqual(report['oauthAttemptsAfter'],205);self.assertFalse(report['budgetReset']);self.assertTrue(report['preflightPassed'])
  self.assertEqual(set(saved),{'observed-owner-baseline.json','candidate-authorization-plan.json'})
  self.assertNotIn('PRIVATE_TOKEN_CANARY',json.dumps(report));self.assertNotIn('PRIVATE_MAPPER_CANARY',json.dumps(report))
  self.assertEqual(report['observedSummary']['ingestionScopeMapperCount'],1)
 def test_expired_or_blocked_window_never_refreshes_or_contacts_owner(self):
  for human in(Human(expired=True),Human(blocked=True)):
   report,saved,transports,error=self.run_probe(human)
   self.assertIsNotNone(error);self.assertEqual(human.refreshes,0);self.assertEqual(transports,[]);self.assertEqual(saved,{})
 def test_accounting_widening_is_detected_before_owner_reads(self):
  human=Human(attempts=255);report,saved,transports,error=self.run_probe(human)
  self.assertIsNotNone(error);self.assertEqual(transports,[]);self.assertEqual(saved,{})
 def test_unknown_private_failure_and_mapper_values_are_never_reported(self):
  try:raise ValueError('PRIVATE_TOKEN_CANARY')
  except Exception as e:result=m.safe_failure(e,{'PUBLIC_CODE'})
  self.assertNotIn('PRIVATE_TOKEN_CANARY',json.dumps(result));self.assertEqual(result['reasonCode'],'PRIVATE_DETAILS_REDACTED')
 def test_another_operation_login_cannot_supply_this_capsule_session(self):
  selection={'issuer':'fixture','tenant':'fixture','subject':'human'}
  previous={'sessionDirectory':'/fixture/previous'};case={'humanBinding':previous,'preparedPlanBinding':{'sha256':'a'*64}}
  closure={'fixture':'closure'}
  review={'selectionHash':m.digest(selection),'predecessorDirectory':previous['sessionDirectory'],
   'predecessorBindingHash':m.digest(previous),'operationBinding':{'preparedReviewHash':'a'*64,'sourceClosureHash':'other'},
   'priorOAuthAttempts':203,'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'runtimeAuthorityIssued':False}
  receipt={'reviewHash':m.digest(review),'budgetReset':False,'maximumCumulativeOAuthAttempts':256,'priorOAuthAttempts':203}
  entry=types.SimpleNamespace(HumanSession=unittest.mock.Mock())
  with patch.object(m,'read',side_effect=[receipt,review]):
   with self.assertRaisesRegex(m.PreflightDenied,'EXACT_EXISTING_LOGIN_OPERATION_BINDING_REQUIRED'):
    m.existing_human(entry,case,selection,closure)
  entry.HumanSession.assert_not_called()
 def test_public_owner_http_status_remains_actionable_without_response_payload(self):
  try:raise ValueError('AUTHORIZATION_HTTP_403')
  except Exception as error:result=m.safe_failure(error,set())
  self.assertEqual(result['reasonCode'],'AUTHORIZATION_HTTP_403');self.assertFalse(result['rawErrorPrinted'])
 def test_program_contains_no_login_authority_or_administrative_dispatch_calls(self):
  calls={n.func.attr for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)}
  self.assertFalse(calls&{'login','authenticate','issue_action','apply','main','start_refresh'})
 def test_pure_primitives_failure_happens_before_session_read_or_new_claim(self):
  raw=SCRIPT.read_bytes();entry=types.SimpleNamespace(primitives=lambda *_:(_ for _ in ()).throw(ValueError('PURE_FACTORY_FAILURE')))
  with patch.object(m,'__qualified_source_sha256__',hashlib.sha256(raw).hexdigest(),create=True),patch.object(m,'__qualified_source_bytes__',raw,create=True),\
    patch.object(m,'load_capsule',return_value=(entry,{}, {},{}, {},{}, {'PURE_FACTORY_FAILURE'})),\
    patch.object(m,'existing_human')as human,patch.object(m.tempfile,'mkdtemp')as mkdir:
   result=m.main()
  human.assert_not_called();mkdir.assert_not_called();self.assertEqual(result['phase'],'QUALIFIED_OWNER_PRIMITIVES')
  self.assertEqual(result['failure']['reasonCode'],'PURE_FACTORY_FAILURE');self.assertEqual(result['nativeRefreshInvocations'],0)
if __name__=='__main__':unittest.main()
