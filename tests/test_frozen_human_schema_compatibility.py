"""Exact public frozen method, before/after schema compatibility and deny cases."""
import ast,copy,hashlib,importlib.util,json,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
TRANSFORM=ROOT/'scripts/human-renewal-compatibility-source.py';FIXTURE=ROOT/'tests/fixtures/mcp-human-renewal-guard-2e96cfc5.py'
if not TRANSFORM.exists():TRANSFORM=Path(__file__).with_name('transformer.py');FIXTURE=Path(__file__).with_name('frozen_guard_fixture.py')
spec=importlib.util.spec_from_file_location('qualified_frozen_schema_transform',TRANSFORM);t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def required(ok,reason):
 if not ok:raise ValueError(reason)
def environment():
 scopes=['openid','authorization.policy.admin','mcp.connect','authorization.permissions.read','authorization.permissions.propose','authorization.proposal.read','udp.materialization.retry']
 profile={'maximumAttempts':256,'maximumElapsedSeconds':7200}
 return {'require':required,'digest':digest,'CLIENT':'ouf-human-admin','SCOPES':scopes,'LEGACY_SCOPES':scopes[:-1],'PROFILE':profile}
def data():
 env=environment();selection={'issuer':'issuer','subject':'subject','tenant':'tenant'}
 self=types.SimpleNamespace(selection=selection,directory=Path('/fixture/human'),token_path=Path('/fixture/human/human-access.jwt'),expires_at=1792415703,_boot=lambda:'boot')
 binding={**selection,'selectionHash':digest(selection),'clientId':'ouf-human-admin','scopes':env['SCOPES'],
  'sessionDirectory':str(self.directory),'tokenPath':str(self.token_path),'createdAt':1792408503,'expiresAt':self.expires_at,'retryProfile':env['PROFILE']}
 review={'schema':t.REVIEW_SCHEMA,'purpose':'CONFIGURATION_AND_VALIDATION','predecessorMaximumCumulativeOAuthAttempts':256,
  'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,'maximumRemainingOAuthAttempts':39,'newWindowSeconds':7200,
  'freshIssuerAuthenticationRequired':True,'failedRefreshReplayAllowed':False,'oldCredentialsReusable':False,
  'automaticRenewalAllowed':False,'budgetReset':False,'identityAndScopesUnchanged':True,'requestedScopes':env['SCOPES'],
  'operationBinding':{'sourceClosureHash':t.ORIGINAL_CLOSURE},'followup':{'profile':'ouf.mcp-ingestion-read-transport-update.v1',
   'candidateSourceCommit':'1f2c28d7abadae78680b040ba7b58be62ef85ee9','separateNativeApprovalRequired':True,
   **{k:False for k in('migrationAllowed','gatewayWritesAllowed','grantChangesAllowed','sourceActivationAllowed','jobDispatchAllowed')}}}
 decision={'reviewHash':digest(review),'approvedAt':binding['createdAt'],'expiresAt':binding['expiresAt']}
 row={'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'bootId':'boot','attempts':217,'budgetReset':False,
  'governedWindowRenewal':{'review':review,'decision':decision}}
 return self,row
class FrozenCompatibility(unittest.TestCase):
 def setUp(self):
  self.raw=FIXTURE.read_bytes()
  with patch.object(t,'ORIGINAL_SHA256',hashlib.sha256(self.raw).hexdigest()):self.patched=t.transform(self.raw)
  before=environment();after=environment();exec(compile(self.raw,'<exported-original-method>','exec'),before);exec(compile(self.patched,'<compatible-method>','exec'),after)
  self.before=before['HumanSession']._check_identity_and_budget;self.after=after['HumanSession']._check_identity_and_budget
 def test_reproduces_actual_denial_then_accepts_same_unmodified_review_decision_and_row(self):
  actor,row=data();snapshot=copy.deepcopy(row)
  with self.assertRaisesRegex(ValueError,'RENEWED_HUMAN_WINDOW_CUMULATIVE_HISTORY_REQUIRED'):self.before(actor,row)
  self.after(actor,row);self.assertEqual(row,snapshot)
 def test_legacy_v2_v3_v4_acceptance_is_unchanged(self):
  for schema,prior,previous in(('ouf.human-explicit-test-budget-review.v2',128,128),('ouf.human-explicit-test-continuation-review.v3',217,256),('ouf.human-explicit-capability-scope-review.v4',217,256)):
   actor,row=data();review=row['governedWindowRenewal']['review'];review.update(schema=schema,priorOAuthAttempts=prior,predecessorMaximumCumulativeOAuthAttempts=previous,previousScopes=environment()['LEGACY_SCOPES'])
   row['governedWindowRenewal']['decision']['reviewHash']=digest(review)
   self.before(actor,row);self.after(actor,row)
 def test_new_protocol_widening_and_wrong_original_closure_are_denied(self):
  for key,value in(('priorOAuthAttempts',218),('maximumRemainingOAuthAttempts',40),('newWindowSeconds',14400),
   ('oldCredentialsReusable',True),('automaticRenewalAllowed',True),('failedRefreshReplayAllowed',True),
   ('freshIssuerAuthenticationRequired',False),('identityAndScopesUnchanged',False)):
   actor,row=data();review=row['governedWindowRenewal']['review'];review[key]=value;row['governedWindowRenewal']['decision']['reviewHash']=digest(review)
   with self.subTest(key=key),self.assertRaises(Exception):self.after(actor,row)
  actor,row=data();review=row['governedWindowRenewal']['review'];review['operationBinding']['sourceClosureHash']='f'*64;row['governedWindowRenewal']['decision']['reviewHash']=digest(review)
  with self.assertRaises(Exception):self.after(actor,row)
 def test_migration_gateway_grant_source_and_job_authority_are_denied(self):
  for flag in('migrationAllowed','gatewayWritesAllowed','grantChangesAllowed','sourceActivationAllowed','jobDispatchAllowed'):
   actor,row=data();review=row['governedWindowRenewal']['review'];review['followup'][flag]=True;row['governedWindowRenewal']['decision']['reviewHash']=digest(review)
   with self.subTest(flag=flag),self.assertRaises(Exception):self.after(actor,row)
 def test_all_existing_identity_budget_consent_and_time_predicates_still_deny(self):
  for change in('subject','scopes','budgetReset','attempts','decisionHash','createdAt','expiresAt','boot','receipt'):
   actor,row=data()
   if change=='subject':row['binding']['subject']='other'
   if change=='scopes':row['binding']['scopes']=[]
   if change=='budgetReset':row['budgetReset']=True
   if change=='attempts':row['attempts']=257
   if change=='decisionHash':row['governedWindowRenewal']['decision']['reviewHash']='f'*64
   if change=='createdAt':row['binding']['createdAt']+=1
   if change=='expiresAt':row['binding']['expiresAt']+=1
   if change=='boot':row['bootId']='other'
   if change=='receipt':del row['governedWindowRenewal']
   with self.subTest(change=change),self.assertRaises(Exception):self.after(actor,row)
 def test_whole_ast_is_unchanged_after_removing_only_added_schema_branch(self):
  before=ast.parse(ast.unparse(ast.parse(self.raw)));after=ast.parse(self.patched)
  branch=t.target(after).args[0].values[0];branch.values.pop()
  self.assertEqual(ast.dump(before,include_attributes=False),ast.dump(after,include_attributes=False))
 def test_unqualified_source_never_gets_patched(self):
  with self.assertRaisesRegex(ValueError,'EXACT_AUTHENTICATED_FROZEN_HUMAN_SOURCE_REQUIRED'):t.transform(self.raw)
if __name__=='__main__':unittest.main()
