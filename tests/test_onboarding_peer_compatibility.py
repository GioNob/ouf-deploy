"""Observed transport enrichment and unissued preflight, not an authority."""
import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
core=module('peer_core',BASE/'tools/onboarding_diagnostic_update/authority.py')
database=module('peer_database',BASE/'tools/onboarding_diagnostic_update/database.py')
context=module('peer_context',BASE/'tools/onboarding_diagnostic_update/context.py')
helper=module('peer_plan',BASE/'tools/acquisition_read_native/plan_helper.py')
class Compatibility(unittest.TestCase):
 def setUp(self):
  self.old={'socketPath':'/run/docker.sock','socketBinding':[1,2,0,998,0o660]}
  self.now={**copy.deepcopy(self.old),'peerCredentials':[123,0,0]}
  self.profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1','runtimeBindingProfile':'ouf.runtime-binding.native-mount-order.v1','engineBinding':self.old}
 def hashes(self):return {'retainedEngineBindingHash':core.digest(self.old),'capturedEngineBindingHash':core.digest(self.now),'peerCredentialsHash':core.digest(self.now.get('peerCredentials'))}
 def verify(self):return database.retained_transport(core,self.profile,self.now,self.hashes())
 def test_exact_enrichment_preserves_both_input_dictionaries(self):
  before=copy.deepcopy((self.profile,self.now));proof=self.verify();self.assertEqual((self.profile,self.now),before);self.assertFalse(proof['historicalMetadataRewritten']);self.assertTrue(proof['liveCapturedPeerVerificationOnEveryEngineRequestRequired'])
 def test_missing_null_empty_or_nonroot_current_peer_denied(self):
  for value in(None,[],[123,1,0],[123,0,-1],[0,0,0],[True,0,0],[123.0,0,0]):
   with self.subTest(value=value):
    self.now['peerCredentials']=value
    with self.assertRaises(core.Stop):self.verify()
  self.now.pop('peerCredentials')
  with self.assertRaises(core.Stop):self.verify()
 def test_historical_peer_present_is_not_this_observed_profile(self):
  self.old['peerCredentials']=[123,0,0]
  with self.assertRaises(core.Stop):self.verify()
 def test_root_uid_and_exact_captured_group_are_preserved(self):
  self.now['peerCredentials']=[123,0,998];proof=self.verify();self.assertEqual(proof['peerCredentialsHash'],core.digest([123,0,998]))
 def test_actual_reconciled_pid1_tuple_hash_is_accepted_without_rewriting(self):
  self.now['peerCredentials']=[1,0,0]
  self.assertEqual(core.digest(self.now['peerCredentials']),'7ff52993d5d3cb149089942de7fc7a6511db2671cf2125976c081ad6fff89772')
  proof=self.verify();self.assertTrue(proof['liveCapturedPeerVerificationOnEveryEngineRequestRequired']);self.assertEqual(self.now['peerCredentials'],[1,0,0])
 def test_any_socket_or_retained_field_change_denied_even_with_updated_hashes(self):
  for key,value in(('socketPath','/other/socket'),('socketBinding',[1,3,0,998,0o660])):
   before=copy.deepcopy(self.now);self.now[key]=value
   with self.assertRaises(core.Stop):self.verify()
   self.now=before
  self.now['unexpectedField']=True
  with self.assertRaises(core.Stop):self.verify()
 def test_wrong_schema_or_mount_profile_not_normalized(self):
  for key,value in(('schema','other'),('runtimeBindingProfile','ouf.runtime-binding.mounts-sorted-destination.v1')):
   before=self.profile[key];self.profile[key]=value
   with self.assertRaises(core.Stop):self.verify()
   self.profile[key]=before
 def test_hashes_must_match_the_reconciled_result(self):
  hashes=self.hashes();hashes['peerCredentialsHash']='0'*64
  with self.assertRaisesRegex(core.Stop,'RECONCILED'):database.retained_transport(core,self.profile,self.now,hashes)
 def test_retained_field_json_types_cannot_compare_equal_implicitly(self):
  self.now['socketBinding'][0]=1.0
  with self.assertRaises(core.Stop):self.verify()

@unittest.skipUnless(os.geteuid()==0,'root custody fixture')
class Preflight(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_ONBOARDING_UPDATE_TEST_ROOT',str(BASE.parent)));self.folder=Path(self.tmp.name)
  self.old=self.folder/'old';self.old.mkdir(mode=0o700);self.child=self.old/'retained-peer-credentials-continuation-v1';self.child.mkdir(mode=0o700)
  readroot=self.folder/'read';readroot.mkdir(mode=0o700)
  self.result=json.loads((BASE/'tests/fixtures/onboarding-peer-reconciled-result.json').read_bytes());self.result['contextPath']=str(readroot)
  self.put(readroot/'result.json',self.result)
  self.case=copy.deepcopy(context.TARGET);self.case['executionRoot']=str(self.child);self.case['priorStop'].update(root=str(self.old),resultPath=str(readroot/'result.json'),resultHash=core.digest(self.result))
  self.put(self.old/'preparation-claim.json',{'schema':'ouf.onboarding-diagnostic-update-preflight-claim.v1','executionInputsHash':self.case['executionInputsHash'],'maximums':core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
  for i in range(1,4):self.put(self.old/('preflight-attempt-1234-%05d.json'%i),{'kind':'ownerConfigurationReads','attempt':i,'attemptNotCompletion':True})
  self.ctx=context.Context.__new__(context.Context);self.ctx.root=self.child;self.ctx.core=core;self.ctx.p=helper;self.ctx.case=self.case
  self.ctx.execution=None;self.ctx.counts={k:0 for k in core.LIMITS};self.ctx.counts['ownerConfigurationReads']=3;self.ctx.serial=0;self.ctx.prior_seals={}
 def put(self,p,v):
  if p.exists():p.chmod(0o600)
  p.write_bytes(core.encoded(v));p.chmod(0o400)
 def tearDown(self):self.tmp.cleanup()
 def test_original_three_attempts_are_cumulative_and_files_preserved(self):
  before={p:p.read_bytes()for p in self.old.iterdir()if p.is_file()};self.ctx.reconcile_preflight(self.case['priorStop'])
  self.assertEqual(self.ctx.counts['ownerConfigurationReads'],8);self.assertEqual(before,{p:p.read_bytes()for p in before})
  self.assertEqual(self.ctx.retained_preflight['separateConsumedReaderCounts'],self.result['counts']);self.assertFalse(self.ctx.retained_preflight['oldAuthorityReused'])
 def test_old_authority_or_journal_cannot_be_adopted(self):
  self.put(self.old/'authority.json',{})
  with self.assertRaisesRegex(context.Stop,'NO_OLD_AUTHORITY'):self.ctx.reconcile_preflight(self.case['priorStop'])
 def test_wrong_original_count_or_maximum_cannot_be_reset(self):
  p=self.old/'preflight-attempt-1234-00003.json';self.put(p,{'kind':'ownerConfigurationReads','attempt':2,'attemptNotCompletion':True})
  with self.assertRaisesRegex(context.Stop,'COUNTS_REQUIRED'):self.ctx.reconcile_preflight(self.case['priorStop'])
 def test_read_report_cannot_claim_another_difference(self):
  self.result['sameSocketCustody']=False;self.put(Path(self.case['priorStop']['resultPath']),self.result);self.case['priorStop']['resultHash']=core.digest(self.result)
  with self.assertRaisesRegex(context.Stop,'ABSENT_PEER_RECONCILIATION'):self.ctx.reconcile_preflight(self.case['priorStop'])
 def second_stop(self):
  self.first=self.child;self.ctx.root=self.first/'pid1-peer-continuation-v1';self.ctx.root.mkdir(mode=0o700);self.ctx.counts['ownerConfigurationReads']=11
  self.put(self.first/'preparation-claim.json',{'schema':'ouf.onboarding-diagnostic-update-preflight-claim.v1','executionInputsHash':self.case['executionInputsHash'],'maximums':core.LIMITS,'runtimeEffectsDispatched':0,'automaticReplayAllowed':False,'budgetReset':False})
  for serial,attempt in enumerate(range(4,12),1):self.put(self.first/('preflight-attempt-2345-%05d.json'%serial),{'kind':'ownerConfigurationReads','attempt':attempt,'attemptNotCompletion':True})
  code=self.folder/'code';code.mkdir(mode=0o700);manifest={}
  names={'entry.py','authority.py','context.py','transport.py','ports.py','quarantine.py','state_fence.py','database.py','recovery_journal.py','engine_creation.py','plan_helper.py','image_custody.py','retained_mac.py','terminal.py','authentication.py','signing.py','auth_protocol.py','auth_preexec.py','auth_producer.py','runtime_binding.py','migration-fence.json'}
  for name in names:
   raw=('CI_NOT_EXECUTED:'+name).encode();(code/name).write_bytes(raw);(code/name).chmod(0o400);manifest[name]=core.sha(raw)
  self.put(code/'sources.json',manifest)
  self.put(code/'operator.log',{'applicationE2EProven':False,'automaticReplayAllowed':False,'automaticRollbackPerformed':False,'budgetReset':False,'complete':False,'contextPath':None,'reasonCode':'EXACT_CURRENT_ROOT_ENGINE_PEER_CREDENTIALS_REQUIRED','releaseAcceptance':False,'runtimeEffectsMayBePartial':True,'schema':'ouf.onboarding-diagnostic-update-result.v1','status':'STOP_RECONCILE'});(code/'operator.log').chmod(0o600)
  return {'root':str(self.first),'codeRoot':str(code),'manifestHash':core.digest(manifest)}
 def test_second_stop_eight_more_attempts_carried_without_new_budget(self):
  stop=self.second_stop();before={p:p.read_bytes()for folder in(self.old,self.first)for p in folder.iterdir()if p.is_file()}
  self.ctx.reconcile_preflight(self.case['priorStop'],stop);self.assertEqual(self.ctx.counts['ownerConfigurationReads'],48)
  self.assertEqual(self.ctx.retained_preflight['retainedPreflightCounts']['ownerConfigurationReads'],11);self.assertEqual(core.LIMITS['ownerConfigurationReads'],64)
  self.assertEqual(before,{p:p.read_bytes()for p in before});self.assertEqual(len(self.ctx.prior_inventories),2)
 def test_second_stop_unknown_effect_or_authority_cannot_be_adopted(self):
  stop=self.second_stop();self.put(self.first/'recovery.json',{})
  with self.assertRaisesRegex(context.Stop,'NO_AUTHORITY_OR_JOURNAL'):self.ctx.reconcile_preflight(self.case['priorStop'],stop)
 def test_second_stop_counter_cannot_be_reset(self):
  stop=self.second_stop();p=self.first/'preflight-attempt-2345-00008.json';self.put(p,{'kind':'ownerConfigurationReads','attempt':10,'attemptNotCompletion':True})
  with self.assertRaisesRegex(context.Stop,'FOUR_TO_ELEVEN'):self.ctx.reconcile_preflight(self.case['priorStop'],stop)
 def test_second_stop_prior_code_tamper_denied(self):
  stop=self.second_stop();p=Path(stop['codeRoot'])/'database.py';p.chmod(0o600);p.write_bytes(b'TAMPER');p.chmod(0o400)
  with self.assertRaises(Exception):self.ctx.reconcile_preflight(self.case['priorStop'],stop)
if __name__=='__main__':unittest.main(verbosity=2)
