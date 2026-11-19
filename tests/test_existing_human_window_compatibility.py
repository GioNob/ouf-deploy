"""Real login/journals with the target-exported guard in a full runtime fixture."""
import ast,copy,hashlib,importlib.util,json,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_mcp_transport_reauthentication as previous
from tools.mcp_read_transport_reauthentication import login as old_login
from tools.mcp_read_transport_compatibility import continuation as m,authority as a
from tools.chatbot_file_cohort import human_session as h
from tools.semantic_lease_recovery.recovery_journal import Journal
spec=importlib.util.spec_from_file_location('qualified_human_schema_transform',ROOT/'scripts/human-renewal-compatibility-source.py');transform=importlib.util.module_from_spec(spec);spec.loader.exec_module(transform)
class ExistingWindowNative(unittest.TestCase):
 def setUp(self):
  self.p=previous.Reauthentication();self.p.setUp();self.addCleanup(self.p.doCleanups);p=self.p
  p.wall=1792410000;p.row['lastObservedAt']=p.wall-5;p.write(p.directory/'recovery.json',p.row)
  review=old_login.qualify(p.human,p.row,p.case,p.closure)
  review['operationBinding']['sourceClosureHash']='2eb74254682d3fec8e49f2c5c08acaa83ff87b1f5d736b38124b7380e2a99a76'
  self.review=review;self.directory=p.root/('human-mcp-read-transport-successor-'+m.digest(review));self.directory.mkdir(mode=0o700)
  self.binding={**copy.deepcopy(p.binding),'createdAt':1792408503,'expiresAt':m.EXPIRES,
   'sessionDirectory':str(self.directory),'tokenPath':str(self.directory/'human-access.jwt')}
  decision={'schema':'ouf.human-login-window-terminal-consent.v1','reviewHash':m.digest(review),
   'decision':'OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY','approvedAt':1792408503,'expiresAt':m.EXPIRES}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':self.binding,'bootId':p.human._boot(),
   'monotonicDeadline':p.mono+m.EXPIRES-p.wall,'lastObservedAt':p.wall,'attempts':217,'state':'NEW','budgetReset':False,
   'governedWindowRenewal':{'review':review,'decision':decision}}
  Journal(self.directory).initialize(self.row)
  p.write(p.directory/'successor-window.claim.json',{'reviewHash':m.digest(review),'decisionHash':m.digest(decision),
   'destination':str(self.directory),'budgetReset':False,'automaticReplayAllowed':False})
  p.write(p.stopped/'login-review.json',review)
  self.origin_closure={'declaration':{'moduleCount':188}}
  package={'sourceCommit':'c9d3ca870c95518c94f754640cd68dc8462c609e','closure':self.origin_closure,
   'fileHashes':{'case.json':m.digest(p.old_case)}}
  p.write(p.stopped/'package.json',package);self.package_hash=m.digest(package)
  p.write(p.stopped/'runtime.claim.json',{'packageHash':self.package_hash,'automaticReplayAllowed':False})
  raw=Path(h.__file__).read_bytes();tree=ast.parse(raw)
  fixture=ast.parse((ROOT/'tests/fixtures/mcp-human-renewal-guard-2e96cfc5.py').read_bytes())
  method=next(n for c in fixture.body if isinstance(c,ast.ClassDef)for n in c.body if isinstance(n,ast.FunctionDef))
  cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='HumanSession')
  cls.body=[copy.deepcopy(method)if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget'else n for n in cls.body]
  exported_runtime=(ast.unparse(ast.fix_missing_locations(tree))+'\n').encode()
  with patch.object(transform,'ORIGINAL_SHA256',hashlib.sha256(exported_runtime).hexdigest()):compatible=transform.transform(exported_runtime)
  self.module=types.ModuleType('qualified_actual_guard_full_runtime_fixture');sys.modules[self.module.__name__]=self.module
  self.addCleanup(lambda:sys.modules.pop(self.module.__name__,None));exec(compile(compatible,'<real-login-with-exported-target-guard>','exec'),self.module.__dict__)
  self.module.PROFILE=copy.deepcopy(h.PROFILE);self.module.SCOPES=list(h.SCOPES);self.module.LEGACY_SCOPES=h.SCOPES[:-1]
  self.module.__qualified_source_sha256__=hashlib.sha256(compatible).hexdigest()
  for target,key,value in((m,'ORIGIN',p.stopped),(m,'PACKAGE',self.package_hash),(m,'OLD_CLOSURE',m.digest(self.origin_closure)),
   (m,'hs',self.module),(a,'current_authorities',lambda *args:({},{}))):
   pa=patch.object(target,key,value);pa.start();self.addCleanup(pa.stop)
  self.case={**p.old_case,'humanBinding':self.binding,'priorOAuthAttempts':217,'existingWindowCompatibility':{
   'schema':'ouf.mcp-read-transport-existing-window-compatibility.v1','originContext':str(p.stopped),
   'originPackageHash':self.package_hash,'originClosureHash':m.digest(self.origin_closure),
   'originalHumanSourceSha256':m.OLD_HUMAN,'patchedHumanSourceSha256':self.module.__qualified_source_sha256__,
   'originalLoginReviewHash':m.digest(review),'windowExpiresAt':m.EXPIRES,'priorOAuthAttempts':217,
   'maximumCumulativeOAuthAttempts':256,'newLoginWindowAllowed':False,'approvedLoginConsentChanged':False,'budgetReset':False}}
  self.closure={'declaration':{'moduleCount':191}}
  def consent(review):return {'schema':'ouf.mcp-read-transport-login-compatibility-decision.v1','reviewHash':m.digest(review),
   'sourceClosureHash':m.digest(self.closure),'decision':'APPROVE_SAME_WINDOW_FORMAT_COMPATIBILITY_ONLY',
   'approvedAt':int(p.wall+p.elapsed),'windowExpiresAt':m.EXPIRES,'newLoginWindowAllowed':False,'runtimeAuthorityIssued':False}
  pa=patch.object(m,'terminal_consent',side_effect=consent);self.consent=pa.start();self.addCleanup(pa.stop)
 def resume(self):return m.resume(self.p.selection,self.case,self.p.context,self.closure,previous.p.parsed,self.p.emits.append)
 def actual_login(self):
  parent=self.p;original=self.module.HumanSession.login
  class Stopper:
   def is_set(self):return False
   def wait(self,seconds):parent.elapsed+=seconds
  def login(instance,**kwargs):return original(instance,stop=Stopper(),**kwargs)
  return patch.object(self.module.HumanSession,'login',login)
 def provider(self,instance,*args,**kwargs):return self.p.provider(instance,*args,**kwargs)
 def provider_patch(self):
  parent=self
  def invoke(instance,*args,**kwargs):return parent.provider(instance,*args,**kwargs)
  return patch.object(self.module.HumanSession,'_http',invoke)
 def test_real_login_with_actual_guard_preserves_original_review_decision_window_and217_counter(self):
  original_login_review=(self.p.stopped/'login-review.json').read_bytes();original_decision=copy.deepcopy(self.row['governedWindowRenewal']['decision'])
  with self.provider_patch(),self.actual_login():human=self.resume()
  self.assertEqual(human._read()['attempts'],221);self.assertEqual(human.current(),self.binding)
  self.assertEqual(human._read()['governedWindowRenewal']['decision'],original_decision)
  self.assertEqual((self.p.stopped/'login-review.json').read_bytes(),original_login_review)
  self.assertEqual(human.expires_at,m.EXPIRES);self.assertEqual(len(self.p.calls),4)
  self.assertTrue((self.directory/m.RESUME_CLAIM).exists());self.assertFalse((self.p.context/'authority.json').exists())
 def test_technical_decline_starts_no_request_and_leaves_new217_unchanged(self):
  self.consent.side_effect=ValueError('DECLINED')
  with self.assertRaises(Exception):self.resume()
  self.assertEqual(previous.p.parsed(self.directory/'recovery.json'),self.row)
  self.assertFalse((self.directory/m.RESUME_CLAIM).exists());self.assertEqual(self.p.calls,[])
 def test_already_started_request_token_or_changed_counter_cannot_resume(self):
  for changes in({'state':'REQUESTING','operation':'DISCOVERY'},{'attempts':218},{'accessToken':'SECRET'},{'deviceCode':'SECRET'}):
   with self.subTest(changes=changes):
    self.p.write(self.directory/'recovery.json',{**self.row,**changes})
    with self.assertRaises(Exception):m.qualify(self.p.selection,self.case,self.closure,previous.p.parsed)
  self.consent.assert_not_called()
 def test_window_extension_and_consent_change_are_denied(self):
  for key,value in(('newLoginWindowAllowed',True),('approvedLoginConsentChanged',True),('windowExpiresAt',m.EXPIRES+1),('maximumCumulativeOAuthAttempts',384)):
   case=copy.deepcopy(self.case);case['existingWindowCompatibility'][key]=value
   with self.subTest(key=key),self.assertRaises(Exception):m.qualify(self.p.selection,case,self.closure,previous.p.parsed)
 def test_second_start_is_fenced_even_in_a_different_context(self):
  with self.provider_patch(),self.actual_login():self.resume()
  count=len(self.p.calls)
  with self.assertRaises(Exception):self.resume()
  self.assertEqual(len(self.p.calls),count)
 def test_provider_denial_is_preserved_without_new_window_or_native_authority(self):
  def denied(instance,url,values=None,bearer=None):
   if url.endswith('/device'):return 400,{'error':'unauthorized_client'},0
   return self.provider(instance,url,values,bearer)
  with patch.object(self.module.HumanSession,'_http',denied),self.actual_login(),self.assertRaises(self.module.HumanSessionPaused):self.resume()
  row=previous.p.parsed(self.directory/'recovery.json');self.assertEqual(row['state'],'BLOCKED');self.assertEqual(row['attempts'],219)
  self.assertEqual(row['binding']['expiresAt'],m.EXPIRES);self.assertFalse((self.p.context/'authority.json').exists())
 def test_row_drift_after_technical_consent_stops_before_first_oauth(self):
  original=self.consent.side_effect
  def consent(review):
   decision=original(review);self.p.write(self.directory/'recovery.json',{**self.row,'attempts':218});return decision
  self.consent.side_effect=consent
  with self.assertRaises(Exception):self.resume()
  self.assertFalse((self.directory/m.RESUME_CLAIM).exists());self.assertEqual(self.p.calls,[])
class ClosedCompatibility(unittest.TestCase):
 def test_new_loader_adds_three_modules_and_uses_specific_entry(self):
  from tools.mcp_read_transport_compatibility import runtime as loader
  from tools.mcp_read_transport_reauthentication import runtime as previous_loader
  self.assertEqual(len(loader.MODULES),191);self.assertEqual(len(previous_loader.MODULES),188)
  self.assertEqual(loader.MODULES-previous_loader.MODULES,{'tools.mcp_read_transport_compatibility.'+n for n in('entry','authority','continuation')})
  sources={n:b'pass\n'for n in loader.MODULES}
  for n in('entry','authority','continuation'):sources['tools.mcp_read_transport_compatibility.'+n]=(ROOT/'tools/mcp_read_transport_compatibility'/(n+'.py')).read_bytes()
  loader.compile_sources(sources);self.assertEqual(loader.ENTRY,'tools.mcp_read_transport_compatibility.entry')
 def test_entry_uses_existing_window_resume_and_never_calls_new_authenticate(self):
  raw=(ROOT/'tools/mcp_read_transport_compatibility/entry.py').read_bytes();calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Call)]
  self.assertIn('resume',calls);self.assertNotIn('authenticate',calls)
class RealCompatibilityAuthority(unittest.TestCase):
 @classmethod
 def setUpClass(cls):previous.RealReauthenticationAuthority.setUpClass()
 def setUp(self):
  self.base=previous.RealReauthenticationAuthority();self.base.setUp();self.addCleanup(self.base.doCleanups)
  self.prior=self.base.prior;self.closure=copy.deepcopy(self.base.closure)
  self.closure['declaration']['entryModule']='tools.mcp_read_transport_compatibility.entry';self.closure['declaration']['moduleCount']=191
  self.review=a.compile_action_review('MCP_READ_TRANSPORT_UPDATE',self.closure,self.prior.scopes,self.prior.hb,
   self.prior.context,{'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':self.prior.plan['logicalUpdateRef']},480)
  self.prior.c.write(self.prior.context/'review.json',a.encoded(self.review))
 def decision(self):self.prior.review=self.review;return self.prior.decision()
 def test_actual_two_role_signatures_bind_the_specific_compatibility_entry_and_exact_mcp_scope(self):
  action=a.issue_action(self.review,self.decision(),self.prior.human)
  self.assertTrue(action.guard('mcpReadTransportUpdate',self.prior.scopes['mcpReadTransportUpdate']))
  self.assertEqual(len(list(self.prior.context.glob('*.DEPLOYMENT_INTENT.json'))),1)
  self.assertEqual(len(list(self.prior.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
  self.assertFalse((self.prior.c.root/'UNREAD-ATTESTOR.pem').exists())
 def test_technical_login_compatibility_is_not_a_runtime_scope_or_login_window_grant(self):
  with self.assertRaises(Exception):a.compile_action_review('MCP_READ_TRANSPORT_UPDATE',self.closure,
   {**self.prior.scopes,'loginCompatibility':{'allowed':True}},self.prior.hb,self.prior.context,
   {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':'c'*64},480)
  with self.assertRaises(Exception):a.terminal_consent(self.review,'No new login window',login=True)
if __name__=='__main__':unittest.main()
