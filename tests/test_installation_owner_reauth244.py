"""Real finite HUMAN device flow and original frozen renewal guard, no old refresh."""
import ast,base64,copy,hashlib,importlib.util,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_installation_owner_update as existing
import test_installation_ingestion_binding_plan as prior
from tools.chatbot_file_cohort import human_session as h
from tools.installation_owner_update import runtime as loader,entry as retained_entry
spec=importlib.util.spec_from_file_location('same_window_entry',ROOT/'tools/installation_owner_reauthentication/entry.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec=importlib.util.spec_from_file_location('same_window_preparer',ROOT/'scripts/prepare-installation-owner-reauth244.py');prep=importlib.util.module_from_spec(spec);spec.loader.exec_module(prep)

class SameWindow(unittest.TestCase):
 def setUp(self):
  self.old=prior.NativeScopeLogin();self.old.setUp();self.addCleanup(self.old.doCleanups)
  # Establish the original v4 consent and window using the actual scope-login flow.
  with patch.object(h.HumanSession,'_http',lambda instance,*a,**kw:self.old.provider(instance,*a,**kw)),self.old.actual_login():self.human=self.old.authenticate()
  self.row=self.human._read();self.row.update(attempts=244,state='BLOCKED',operation='REFRESH',reason='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN')
  (self.human.directory/'recovery.json').write_bytes(m.encoded(self.row))
  self.old.calls.clear();self.old.emits.clear()
  self.context=self.old.root/'installation-owner-update-execution-abcdefgh';self.context.mkdir(mode=0o700)
  self.stopped=self.old.root/'stopped';self.stopped.mkdir(mode=0o700)
  for obj,key,value in((m,'EXPIRES',self.human.expires_at),(m,'ORIGINAL_REVIEW_HASH',m.digest(self.row['governedWindowRenewal']['review'])),(m,'STOPPED',self.stopped),(m.authority.evidence,'PARENT',self.old.root),(m,'PROFILE',self.old.profile),(m,'SCOPES',prior.t.REQUESTED)):
   p=patch.object(obj,key,value);p.start();self.addCleanup(p.stop)
  self.case={'humanBinding':self.row['binding'],'priorOAuthAttempts':244}
  for key in ('originalBinding','installedPlanBinding','installedJournalBinding','completedInstallationPlanBinding','imageBinding','candidateMigrationEvidenceBinding'):self.case[key]={'path':key,'sha256':'a'*64}
  self.closure={'declaration':{'moduleCount':213}}
  raw=m.encoded(self.case);(self.stopped/'case.json').write_bytes(raw)
  package={'closure':self.closure,'fileHashes':{'case.json':hashlib.sha256(raw).hexdigest()}}
  self.package_hash=m.digest(package);(self.stopped/'package.json').write_bytes(m.encoded(package))
  (self.stopped/'runtime.claim.json').write_bytes(m.encoded({'packageHash':self.package_hash,'automaticReplayAllowed':False}))
  for obj,key,value in((m,'STOP_PACKAGE',self.package_hash),(m,'STOP_CLOSURE',m.digest(self.closure))):
   p=patch.object(obj,key,value);p.start();self.addCleanup(p.stop)
  self.case['sameWindowReauthentication']={'stoppedContext':str(self.stopped),'stoppedPackageHash':self.package_hash,'stoppedClosureHash':m.digest(self.closure),'priorOAuthAttempts':244,'windowExpiresAt':self.human.expires_at,'newWindowAllowed':False,'oldRefreshReplayAllowed':False,'budgetReset':False}
  self.consent=patch.object(m,'authentication_consent',side_effect=self.approve).start();self.addCleanup(patch.stopall)
 def approve(self,review):return {'schema':'ouf.installation-owner-same-window-reauth-decision.v1','reviewHash':m.digest(review),'decision':'APPROVE_ONE_FRESH_AUTHENTICATION_NO_NEW_WINDOW','approvedAt':int(time.time()),'windowExpiresAt':m.EXPIRES,'newWindowAllowed':False,'runtimeAuthorityIssued':False}
 def read(self,path,expected=None):
  raw=Path(path).read_bytes()
  if expected is not None:self.assertEqual(hashlib.sha256(raw).hexdigest(),expected)
  return json.loads(raw)
 def run_login(self,provider=None):
  with patch.object(h.HumanSession,'_http',lambda instance,*a,**kw:provider(*a,**kw)if provider else self.old.provider(instance,*a,**kw)),self.old.actual_login():
   return m.authenticate_same_window(self.old.selection,self.case,self.context,self.closure,self.read,self.old.emits.append)
 def successor(self):return Path(self.read(self.human.directory/'successor-window.claim.json')['destination'])
 def test_real_frozen_guard_device_flow_preserves_window_original_receipt_and_cumulative244(self):
  following=self.run_login();row=following._read()
  self.assertEqual(row['attempts'],248);self.assertEqual(len(self.old.calls),4)
  self.assertEqual(row['binding']['createdAt'],self.row['binding']['createdAt']);self.assertEqual(following.expires_at,self.human.expires_at)
  self.assertEqual(row['monotonicDeadline'],self.row['monotonicDeadline']);self.assertEqual(row['governedWindowRenewal'],self.row['governedWindowRenewal'])
  following._check(row);self.assertEqual(self.human._read(),self.row)
  self.assertEqual(self.case['humanBinding'],following.current());self.assertNotIn('DO_NOT_',str(self.old.calls));self.assertNotIn('FRESH_REFRESH_ONLY','\n'.join(self.old.emits))
  self.assertFalse((self.context/'authority.json').exists())
  with self.assertRaises(Exception):self.run_login()
 def test_declined_consent_has_no_successor_provider_or_owner_effect(self):
  self.consent.side_effect=ValueError('DECLINED')
  with self.assertRaises(ValueError):self.run_login()
  self.assertFalse((self.human.directory/'successor-window.claim.json').exists());self.assertEqual(self.old.calls,[]);self.assertEqual(self.human._read(),self.row)
 def test_changed_counter_window_boot_consent_or_existing_successor_rejected_before_login(self):
  for change in ({'attempts':245},{'budgetReset':True},{'state':'READY'},{'bootId':'wrong'},{'monotonicDeadline':time.monotonic()+100},{'governedWindowRenewal':{}}):
   with self.subTest(change=change),self.assertRaises(Exception):m.qualify_reauthentication(self.human,{**self.row,**change},self.case,self.closure)
  self.consent.assert_not_called();self.assertEqual(self.old.calls,[])
 def test_provider_denial_is_durable_cumulative246_no_old_refresh_or_replay(self):
  def deny(instance_url,values=None,bearer=None):
   if instance_url.endswith('/device'):return 400,{'error':'unauthorized_client'},0
   return self.old.provider(None,instance_url,values,bearer)
  with self.assertRaises(h.HumanSessionPaused):self.run_login(deny)
  row=self.read(self.successor()/'recovery.json');self.assertEqual(row['state'],'BLOCKED');self.assertEqual(row['attempts'],246)
  self.assertEqual(self.human._read(),self.row)
  with self.assertRaises(Exception):self.run_login()
 def test_budget_used_by_device_poll_stops_before_owner_approval(self):
  polls=[0]
  def pending(url,values=None,bearer=None):
   if url.endswith('/token')and polls[0]<5:polls[0]+=1;return 400,{'error':'authorization_pending'},0
   return self.old.provider(None,url,values,bearer)
  with self.assertRaises(Exception):self.run_login(pending)
  row=self.read(self.successor()/'recovery.json');self.assertEqual(row['attempts'],253)
  self.assertFalse((self.context/'authority.json').exists());self.assertFalse((self.context/'login-window-receipt.json').exists())
 def test_predecessor_drift_during_native_consent_denies_without_login(self):
  def change(review):
   decision=self.approve(review);(self.human.directory/'recovery.json').write_bytes(m.encoded({**self.row,'attempts':245}));return decision
  self.consent.side_effect=change
  with self.assertRaises(Exception):self.run_login()
  self.assertEqual(self.old.calls,[]);self.assertFalse((self.human.directory/'successor-window.claim.json').exists())
 def test_stop_history_advancement_or_input_drift_is_denied(self):
  (self.stopped/'authority.json').write_text('{}')
  with self.assertRaises(Exception):self.run_login()
  self.consent.assert_not_called();self.assertEqual(self.old.calls,[])

class ClosedCode(unittest.TestCase):
 def test_closed213_imports_and_all_owner_execution_code_retained(self):
  raw=(ROOT/'tools/installation_owner_reauthentication/entry.py').read_bytes();sources={n:b'pass\n'for n in loader.MODULES};sources[loader.ENTRY]=raw
  self.assertEqual(len(loader.compile_sources(sources)),213)
  before=ast.parse((ROOT/'tools/installation_owner_update/entry.py').read_bytes());after=ast.parse(raw)
  old={n.name:n for n in before.body if isinstance(n,ast.FunctionDef)};new={n.name:n for n in after.body if isinstance(n,ast.FunctionDef)}
  new['owner_main'].name='main'
  for name in ('current_human','compile_current','main'):
   self.assertEqual(ast.dump(old[name],include_attributes=False),ast.dump(new['owner_main'if name=='main'else name],include_attributes=False))
 def test_preparer_has_no_provider_engine_or_historical_runtime_execution(self):
  tree=ast.parse((ROOT/'scripts/prepare-installation-owner-reauth244.py').read_bytes());calls={ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)}
  self.assertFalse(any(x.endswith(('.request','.login','.refresh_if_due','.issue_action','.import_image'))for x in calls))
  self.assertEqual(len([x for x in ast.walk(tree)if isinstance(x,ast.Call)and ast.unparse(x.func)=='os.execv']),1)
if __name__=='__main__':unittest.main()
