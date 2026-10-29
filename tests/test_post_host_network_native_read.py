import copy,importlib.util,json,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];spec=importlib.util.spec_from_file_location('post_network_read',ROOT/'scripts/read-post-host-network-native.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Read(unittest.TestCase):
 def fixture(self):
  profile=json.loads((ROOT/'releases/host-network-reconciliation-20261018.json').read_bytes());apps=json.loads((ROOT/'releases/source-revision-private-preparation-20261018.json').read_bytes());probes=json.loads((ROOT/'releases/post-host-network-native-health-20261018.json').read_bytes());rows=[]
  for pin in [*profile['moves'],*apps['currentApplications'].values()]:
   role=next((k for k,v in apps['currentApplications'].items()if v['containerId']==pin['containerId']),None);ip=pin.get('newIPv4')if role is None else probes['applications'][role]['ipv4'];rows.append({'id':pin['containerId'],'name':'/'+pin.get('name',role),'image':pin['imageId'],'revision':pin.get('sourceCommit'),'state':{'Running':True,'Status':'running','Pid':100,'StartedAt':'fixture','Error':'PRIVATE_ERROR_CANARY'},'restarts':0,'networks':{profile['network']['name']:{'NetworkID':profile['network']['id'],'IPAddress':ip,'IPAMConfig':{'IPv4Address':ip}}}})
  raw='\n'.join(json.dumps(row)for row in rows).encode();return profile,apps,probes,rows,raw
 def test_exact_endpoints_health_and_no_raw_state_error(self):
  p,a,h,rows,raw=self.fixture()
  with patch.object(r.m,'invoke',return_value=raw)as invoke:result=r.collect(p,a,h,probe_fn=lambda *args:{'ready':True,'requests':1})
  self.assertEqual(result['httpHealthGets'],3);self.assertEqual(result['engineWrites'],0);self.assertTrue(result['allThreeNativeReadinessProven']);self.assertFalse(result['providerReadinessProven']);self.assertNotIn('PRIVATE_ERROR_CANARY',json.dumps(result));self.assertEqual(invoke.call_count,2);self.assertEqual(invoke.call_args.args[0][0],'inspect')
 def test_wrong_fixed_endpoint_or_process_race_is_not_accepted(self):
  p,a,h,rows,raw=self.fixture();bad=copy.deepcopy(rows);bad[0]['networks'][p['network']['name']]['IPAddress']='172.18.0.99';wrong='\n'.join(json.dumps(row)for row in bad).encode()
  with patch.object(r.m,'invoke',return_value=wrong),self.assertRaises(ValueError):r.collect(p,a,h,probe_fn=lambda *args:{'ready':True,'requests':1})
  bad=copy.deepcopy(rows);bad[0]['state']['Pid']=101;changed='\n'.join(json.dumps(row)for row in bad).encode()
  with patch.object(r.m,'invoke',side_effect=[raw,changed]),self.assertRaises(ValueError):r.collect(p,a,h,probe_fn=lambda *args:{'ready':True,'requests':1})
 def test_unready_is_reported_without_retry_or_health_body(self):
  p,a,h,rows,raw=self.fixture()
  with patch.object(r.m,'invoke',return_value=raw):result=r.collect(p,a,h,probe_fn=lambda *args:{'ready':False,'httpStatus':503,'requests':1})
  self.assertFalse(result['allThreeNativeReadinessProven']);self.assertFalse(result['automaticRetry']);self.assertEqual(result['httpHealthGets'],3)
 def test_http_redirect_is_not_followed_and_body_is_not_printed(self):
  response=types.SimpleNamespace(status=302,read=lambda n:b'PRIVATE_BODY_CANARY');connection=types.SimpleNamespace(request=lambda *args,**kwargs:None,getresponse=lambda:response,close=lambda:None)
  with patch.object(r.http.client,'HTTPConnection',return_value=connection):result=r.probe('172.18.0.5',{'port':8080,'path':'/actuator/health/readiness'})
  self.assertFalse(result['ready']);self.assertFalse(result['redirectFollowed']);self.assertNotIn('PRIVATE_BODY_CANARY',json.dumps(result))
if __name__=='__main__':unittest.main()
