import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chat_recovery_update import plan as p
from tools.chat_recovery_update.owner import UpdateDenied
class Replacement(unittest.TestCase):
 def fixture(self,module):
  config={'User':'fixture','Entrypoint':['/app/server'],'Cmd':[],'WorkingDir':'/app',
          'Env':['PRIVATE_CANARY=preserved'],'Labels':{'org.opencontainers.image.revision':'a'*40}}
  host={'NetworkMode':'fixture','RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},
        'Binds':['/root/retained:/run/reprocessing:ro']}
  actual={'Name':'/fixture-'+module,'Id':'a'*64,'Image':'sha256:'+'b'*64,
          'Config':config,'HostConfig':host,'Mounts':[{'Type':'bind','Source':'/root/retained','Destination':'/run/reprocessing','RW':False}],
          'State':{'Running':True,'Pid':7,'StartedAt':'original'},
          'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'10.90.0.2','MacAddress':'02:00:00:00:00:01','NetworkID':'n'*64}}}}
  saved={'module':module,'name':'fixture-'+module,'restoreRestartPolicy':copy.deepcopy(host['RestartPolicy']),'creationRequest':{'HostConfig':copy.deepcopy(host),
         'NetworkingConfig':{'EndpointsConfig':{'fixture':{'Aliases':['retained-alias']}}}}}
  image={'imageArchive':{'path':'/root/image.tar','sha256':'f'*64},
         'imageAudit':{'imageConfig':{**copy.deepcopy(config),'Labels':{'org.opencontainers.image.revision':'c'*40}}}}
  case={'candidateSourceCommits':{module:'c'*40},'deployedSourceCommits':{module:'a'*40},
        'readiness':{module:{'readinessPort':8080,'readinessPath':'/health/ready' if module=='mcp' else '/actuator/health/readiness'}}}
  saved['creationRequest']['HostConfig']['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
  return saved,actual,image,case
 def compile(self,args,module):
  with patch.object(p,'runtime_image_id',return_value='sha256:'+'d'*64):
   return p.replacement(*args,module)
 def test_both_contracts_preserve_environment_mounts_network_and_restart(self):
  for module in ('udp','mcp'):
   args=self.fixture(module);before=copy.deepcopy(args)
   result=self.compile(args,module);actual=args[1]
   self.assertEqual(result['request']['Env'],actual['Config']['Env'])
   self.assertEqual(result['oldMounts'],actual['Mounts'])
   self.assertEqual(result['request']['HostConfig']['Binds'],actual['HostConfig']['Binds'])
   self.assertEqual(result['restoreRestartPolicy'],actual['HostConfig']['RestartPolicy'])
   self.assertEqual(result['request']['HostConfig']['RestartPolicy']['Name'],'no')
   self.assertEqual(result['request']['NetworkingConfig']['EndpointsConfig']['fixture']['Aliases'],['retained-alias'])
   self.assertEqual(args,before)
 def test_source_process_and_endpoint_contract_drift_block(self):
  for change in ('source','process','endpoint','readiness'):
   args=self.fixture('mcp')
   if change=='source':args[2]['imageAudit']['imageConfig']['Labels']['org.opencontainers.image.revision']='e'*40
   if change=='process':args[2]['imageAudit']['imageConfig']['User']='changed'
   if change=='endpoint':args[1]['NetworkSettings']['Networks']['fixture']['IPAddress']='127.0.0.1'
   if change=='readiness':args[3]['readiness']['mcp']['readinessPath']='/actuator/health/readiness'
   with self.subTest(change=change),self.assertRaises(UpdateDenied):self.compile(args,'mcp')
 def test_saved_host_request_must_match_current_host_configuration(self):
  with patch.object(p,'requested_host_config_matches',return_value=False):
   with self.assertRaises(UpdateDenied):p.replacement(*self.fixture('udp'),'udp')
 def test_real_matcher_accepts_only_completed_restored_policy(self):
  for module in ('udp','mcp'):
   args=self.fixture(module)
   self.assertEqual(args[0]['creationRequest']['HostConfig']['RestartPolicy']['Name'],'no')
   self.assertEqual(self.compile(args,module)['restoreRestartPolicy']['Name'],'unless-stopped')
   args[1]['HostConfig']['RestartPolicy']={'Name':'always','MaximumRetryCount':0}
   with self.assertRaisesRegex(UpdateDenied,'RETAINED_RESTART_POLICY_CHANGED'):self.compile(args,module)
 def test_real_matcher_rejects_unrelated_host_drift_and_missing_proof(self):
  for change in ('bind','network','missing-proof'):
   args=self.fixture('udp')
   if change=='bind':args[1]['HostConfig']['Binds']=['/other:/run/reprocessing:ro']
   if change=='network':args[1]['HostConfig']['NetworkMode']='other'
   if change=='missing-proof':args[0].pop('restoreRestartPolicy')
   with self.subTest(change=change),self.assertRaises(UpdateDenied):self.compile(args,'udp')
if __name__=='__main__':unittest.main()
