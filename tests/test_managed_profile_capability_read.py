"""Synthetic IAM/owner only; no live login/approval or target authority."""
import base64,copy,importlib.util,json,types,unittest
from pathlib import Path
from unittest.mock import patch
BASE=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('new_reader',BASE/'scripts/read-managed-profile-capabilities-20261028.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Fake:
 def __init__(self,replies):self.replies=list(replies);self.calls=[];self.counts={'ownerGets':0};self.now=0;self.deadline=600
 def clock(self):return self.now
 def sleep(self,n):self.now+=n
 def request(self,url,**kwargs):
  self.calls.append((url,kwargs));self.counts['ownerGets']+=1;value=self.replies.pop(0)
  if isinstance(value,Exception):raise value
  return value

def active(missing=()):
 return {'policyRef':'ouf-lab-authorization:56','contentHash':'sha256:'+m.CASE['policyHash'],'policy':{'bundleId':'ouf-lab-authorization','version':56,'capabilities':[
  {'capabilityId':cap,'operation':'READ'if cap.endswith('preview')else'EXECUTE','requiredScope':cap,'allowedActors':['HUMAN']}for cap in m.CASE['requiredRoleCapabilities']if cap not in missing],
  'grants':[{'private':'PRIVATE_UNRELATED_GRANT_CANARY'}]}}
def registered(policy):
 return [{'capability_id':d['capabilityId'],'owner_ref':'onboarding','descriptor':d}for d in policy['policy']['capabilities']]
class Read(unittest.TestCase):
 def observe(self,policy,rows=None,after=None):
  saved={};t=Fake([(200,policy),(200,registered(policy)if rows is None else rows),(200,policy if after is None else after)])
  result=m.observe(t,'PRIVATE_BEARER_CANARY',retain=lambda n,v:saved.update({n:copy.deepcopy(v)}));return result,t,saved
 def test_missing_native_descriptor_identified_with_private_evidence_and_no_grant_output(self):
  policy=active([m.CAPS[2]]);result,t,saved=self.observe(policy)
  self.assertEqual(result['invalidRoleCapabilities'],[m.CAPS[2]]);self.assertTrue(result['complete'])
  self.assertEqual(len(t.calls),3);self.assertEqual(set(saved),{'active-before.json','registrations-00000.json','active-after.json'})
  self.assertEqual(saved['active-before.json'],policy);self.assertNotIn('PRIVATE_',json.dumps(result))
  self.assertEqual(result['policyWrites'],0);self.assertEqual(result['humanBudgetsGranted'],0);self.assertEqual(result['resumes'],0)
  self.assertFalse(result['runtimeAuthorityIssued']);self.assertFalse(result['applicationE2EProven'])
 def test_registered_but_not_published_is_distinguished(self):
  full=active();current=active([m.CAPS[2]]);result,_,_=self.observe(current,registered(full))
  target=next(x for x in result['descriptors']if x['capabilityId']==m.CAPS[2])
  self.assertIsNone(target['activeDescriptor']);self.assertIsNotNone(target['registeredDescriptor']);self.assertEqual(target['registeredOwnerRef'],'onboarding')
 def test_incompatible_existing_role_descriptor_also_reported(self):
  policy=active();cap=m.CASE['requiredRoleCapabilities'][0]
  next(x for x in policy['policy']['capabilities']if x['capabilityId']==cap)['allowedActors']=['SERVICE']
  result,_,_=self.observe(policy);self.assertIn(cap,result['invalidRoleCapabilities'])
 def test_exact_policy_drift_stops_before_catalogue_reads_but_retains_response(self):
  policy=active();policy['contentHash']='sha256:'+'0'*64;saved={};t=Fake([(200,policy)])
  with self.assertRaisesRegex(m.Stop,'NO_DRIFT_ADOPTION'):m.observe(t,'synthetic',retain=lambda n,v:saved.update({n:v}))
  self.assertEqual(len(t.calls),1);self.assertIn('active-before.json',saved)
 def test_policy_change_during_catalogue_not_adopted(self):
  policy=active();changed=copy.deepcopy(policy);changed['policy']['version']=57
  with self.assertRaisesRegex(m.Stop,'ACTIVE_CHANGED_RECONCILE'):self.observe(policy,after=changed)
 def test_duplicate_active_and_registered_ids_fail_closed(self):
  policy=active();policy['policy']['capabilities']*=2
  with self.assertRaisesRegex(m.Stop,'DUPLICATE_ACTIVE'):self.observe(policy)
  policy=active();rows=registered(policy);rows.append(rows[0])
  with self.assertRaisesRegex(m.Stop,'DUPLICATE_REGISTERED'):self.observe(policy,rows)
 def test_pagination_is_bounded_and_complete(self):
  policy=active();page=[{'capability_id':'ci-'+str(i),'owner_ref':'ci','descriptor':{'capabilityId':'ci-'+str(i)}}for i in range(200)]
  t=Fake([(200,policy),(200,page),(200,registered(policy)),(200,policy)])
  result=m.observe(t,'synthetic');self.assertTrue(result['complete']);self.assertEqual(len(t.calls),4)
  self.assertTrue(t.calls[2][0].endswith('offset=200'))
 def test_owner_error_is_not_retried(self):
  t=Fake([m.Stop('OWNER_HTTP_403')])
  with self.assertRaisesRegex(m.Stop,'OWNER_HTTP_403'):m.observe(t,'synthetic')
  self.assertEqual(len(t.calls),1)
 def test_http_transport_has_no_mutation_or_arbitrary_host(self):
  t=m.Transport()
  with patch.object(t.opener,'open')as opened:
   for url,kwargs in[(m.ADMIN+'/capabilities',{'form':{'x':'y'},'token':'private'}),(m.ADMIN+'/policies/x:publish',{'token':'private'}),('https://elsewhere.invalid',{})]:
    with self.assertRaisesRegex(m.Stop,'EXACT_READ_ENDPOINT'):t.request(url,**kwargs)
   opened.assert_not_called()
 def test_failed_get_is_reserved_and_deadline_is_finite(self):
  t=m.Transport()
  with patch.object(t.opener,'open',side_effect=OSError('PRIVATE_CANARY'))as opened:
   with self.assertRaisesRegex(m.Stop,'READ_TRANSPORT_STOP'):t.request(m.ADMIN+'/policies/active',token='private')
   self.assertEqual(t.counts['ownerGets'],1);self.assertEqual(opened.call_count,1)
  t.deadline=0
  with self.assertRaisesRegex(m.Stop,'FINITE_READ_EXPIRED'):t.request(m.ADMIN+'/policies/active',token='private')
 def login_fixture(self,subject=None,error=None):
  claims={'iss':m.ISSUER,'sub':subject or m.SUBJECT,'tenant_id':'ouf-lab','ouf_actor_type':'HUMAN','exp':2000,'scope':'openid authorization.policy.admin'}
  token='synthetic.'+base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')+'.signature'
  replies=[(200,{'issuer':m.ISSUER,'device_authorization_endpoint':m.ISSUER+'/protocol/openid-connect/auth/device','token_endpoint':m.ISSUER+'/protocol/openid-connect/token'}),
   (200,{'verification_uri':m.ISSUER+'/device','user_code':'CI-ONLY','device_code':'private-device','expires_in':600})]
  replies+=[(400,{'error':error})]if error else[(400,{'error':'authorization_pending'}),(400,{'error':'slow_down'}),(200,{'access_token':token,'refresh_token':'PRIVATE_REFRESH'})]
  return Fake(replies),token
 def test_same_verified_human_account_and_bounded_device_flow_no_secret_print(self):
  t,token=self.login_fixture();output=[];self.assertEqual(m.login(t,sleep=t.sleep,emit=output.append,wall=lambda:1000),token)
  self.assertEqual(t.now,20);self.assertNotIn(token,' '.join(output));self.assertNotIn('private-device',' '.join(output));self.assertNotIn('PRIVATE_REFRESH',' '.join(output))
 def test_wrong_account_and_denied_login_stop_before_owner(self):
  t,_=self.login_fixture(subject='wrong')
  with self.assertRaisesRegex(m.Stop,'EXACT_OUF_ADMIN'):m.login(t,sleep=t.sleep,emit=lambda _:None,wall=lambda:1000)
  self.assertFalse(any(u.startswith(m.ADMIN)for u,_ in t.calls))
  t,_=self.login_fixture(error='access_denied')
  with self.assertRaisesRegex(m.Stop,'DEVICE_LOGIN_STOP'):m.login(t,sleep=t.sleep,emit=lambda _:None,wall=lambda:1000)
  self.assertEqual(len(t.calls),3)
 def test_production_main_requires_real_tty_before_scope_or_login(self):
  with patch.object(m.sys,'argv',['reader']),patch.object(m.sys,'flags',types.SimpleNamespace(isolated=1,no_site=1)),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'Transport')as transport:
   with self.assertRaisesRegex(m.Stop,'INTERACTIVE_OPERATOR_TERMINAL'):m.main()
   transport.assert_not_called()
if __name__=='__main__':unittest.main()
