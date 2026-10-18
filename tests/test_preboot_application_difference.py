import copy,importlib.util,json,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
t=load('existing_network_fixture',ROOT/'tests/test_host_network_reconciliation.py')
d=load('application_difference',ROOT/'scripts/read-preboot-application-difference.py')
m=t.m
class Difference(unittest.TestCase):
 def test_opaque_values_and_unknown_field_names_never_printed(self):
  _,_,rows=t.fixture();a=copy.deepcopy(rows[2]);b=copy.deepcopy(a)
  b['Config']['Env']=['TOKEN=PRIVATE_VALUE_CANARY'];b['Config']['Labels']={'PRIVATE_KEY_CANARY':'PRIVATE_LABEL_CANARY'};b['HostConfig']['PRIVATE_FIELD_CANARY']='/private/path'
  result=d.compare(a,b,m);text=json.dumps(result)
  self.assertFalse(result['immutableMatches']);self.assertGreater(result['differenceCount'],0)
  for value in ('PRIVATE_VALUE_CANARY','PRIVATE_KEY_CANARY','PRIVATE_LABEL_CANARY','PRIVATE_FIELD_CANARY','/private/path'):self.assertNotIn(value,text)
 def test_order_only_is_reported_without_adopting_baseline(self):
  _,_,rows=t.fixture();a=copy.deepcopy(rows[2]);a['Mounts']=[{'Source':'one','Destination':'/one'},{'Source':'two','Destination':'/two'}];b=copy.deepcopy(a);b['Mounts'].reverse()
  result=d.compare(a,b,m);self.assertFalse(result['immutableMatches']);self.assertTrue(result['sections']['Mounts']['orderOnly']);self.assertEqual(result['differences'][0]['path'],'Mounts.order')
 def test_boolean_integer_and_output_bounds(self):
  _,_,rows=t.fixture();a=copy.deepcopy(rows[2]);b=copy.deepcopy(a);b['HostConfig']['Privileged']=0
  self.assertFalse(d.compare(a,b,m)['sections']['HostConfig']['equal']);self.assertGreater(d.compare(a,b,m)['differenceCount'],0)
  b['HostConfig'].update({str(i):i for i in range(200)});r=d.compare(a,b,m,maximum=12);self.assertTrue(r['truncated']);self.assertEqual(len(r['differences']),12)
class ProtectedRead(unittest.TestCase):
 def fixture(self):
  harness=t.Bootstrap();harness.setUp();self.addCleanup(harness.doCleanups)
  root,p,api,reader,contracts,selection,report=harness.setup_case()
  apps={role:copy.deepcopy(list(api.rows.values())[2])for role in ('udp','mcp','onboarding')}
  for i,(role,row)in enumerate(apps.items()):row['Id']=str(i+1)*64;row['Name']='/'+role
  current=copy.deepcopy(apps);current['udp']['Config']['Env']=['PRIVATE_CANARY']
  proof={'loadedBinding':report['loadedBinding'],'emptyProviderProof':{'ownerState':'BLOCKED','emptyKernelProven':True,'providerStartAllowed':False}}
  bootstrap=types.SimpleNamespace(provider_guard=lambda *args:copy.deepcopy(proof));contracts.read=lambda _:{'beforeApplications':apps}
  calls=[];changed=[False]
  class API:
   def get(self,path):
    calls.append(('GET',path));row=copy.deepcopy(next(v for v in current.values()if v['Id']in path))
    if changed[0]and len(calls)>6:row['Config']['Env']=['CHANGED_DURING_READ']
    return row
   def request(self,method,path,value,versioned):
    row=self.get(path);row['HostConfig']['MemorySwappiness']=None;return row
   def write(self,*args):raise AssertionError('WRITE_FORBIDDEN')
  return root,p,API(),reader,contracts,bootstrap,selection,apps,calls,changed
 def run_case(self,case):
  root,p,api,reader,contracts,bootstrap,selection,apps,calls,changed=case
  pins={'bootProfile':{'path':'fixture-boot','sha256':'a'*64},'preparedPlan':{'path':'sealed','sha256':'f'*64}}
  with patch.object(m,'Engine',return_value=api):return d.run(m,reader,contracts,bootstrap,selection,pins,p,{'incidentPointer':str(root/'incident.json')})
 def test_all_three_roles_both_representations_and_no_writes_or_private_artifacts(self):
  case=self.fixture();before=sorted(case[0].iterdir());r=self.run_case(case)
  self.assertEqual(set(r['applications']),{'udp','mcp','onboarding'});self.assertEqual(len(case[8]),9);self.assertEqual(sorted(case[0].iterdir()),before);self.assertEqual(r['engineWrites'],0);self.assertFalse(r['baselineAdopted']);self.assertNotIn('PRIVATE_CANARY',json.dumps(r));self.assertFalse(r['applications']['udp']['legacyApi144']['immutableMatches'])
 def test_configuration_race_rejected(self):
  case=self.fixture();case[9][0]=True
  with self.assertRaisesRegex(ValueError,'CHANGED_DURING'):self.run_case(case)
 def test_existing_incident_blocks_before_engine(self):
  case=self.fixture();(case[0]/'incident.json').write_text('{}')
  with self.assertRaisesRegex(ValueError,'INCIDENT_EXISTS'):self.run_case(case)
  self.assertEqual(case[8],[])
if __name__=='__main__':unittest.main()
