import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.udp_resolution_update.plan import replacement
from tools.udp_resolution_update.owner import scope,digest

class Replacement(unittest.TestCase):
 def fixture(self):
  config={'User':'10004:10004','Entrypoint':['java','-jar','/app/app.jar'],'Cmd':None,'WorkingDir':'/app','Env':['PORT=8080','SYNTHETIC=do-not-change'],'Labels':{'org.opencontainers.image.revision':'a'*40}}
  host={'NetworkMode':'retained-network','RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'ReadonlyRootfs':True,'Binds':['/fixture:/run/fixture:ro']}
  network={'retained-network':{'NetworkID':'3'*64,'IPAddress':'172.30.80.10','MacAddress':'02:42:ac:1e:50:0a','GlobalIPv6Address':''}}
  actual={'Id':'1'*64,'Image':'sha256:'+'2'*64,'Config':config,'HostConfig':host,'Mounts':[{'Source':'/fixture','Destination':'/run/fixture','Type':'bind','RW':False}],'NetworkSettings':{'Networks':network},'Name':'/ouf-udp','State':{'Running':True,'Pid':123,'StartedAt':'fixture'}}
  request={**copy.deepcopy(config),'Image':actual['Image'],'HostConfig':copy.deepcopy(host),'NetworkingConfig':{'EndpointsConfig':{'retained-network':{'Aliases':['ouf-udp']}}}}
  saved={'module':'udp','name':'ouf-udp','creationRequest':request};image={'imageAudit':{'imageId':'sha256:'+'4'*64,'imageConfig':copy.deepcopy(config)},'imageArchive':{'path':'/fixture/tagless.tar','sha256':'5'*64}}
  case={'deployedSourceCommit':'a'*40,'candidateSourceCommit':'b'*40,'readiness':{'readinessPort':8080,'readinessPath':'/actuator/health/readiness'}}
  return saved,actual,image,case
 def test_preserves_process_environment_storage_and_endpoint(self):
  saved,actual,image,case=self.fixture();before=copy.deepcopy((saved,actual,image,case));row=replacement(saved,actual,image,case)
  self.assertEqual((saved,actual,image,case),before)
  self.assertEqual(row['request']['Env'],actual['Config']['Env']);self.assertEqual(row['oldMounts'],actual['Mounts'])
  self.assertEqual(row['request']['Image'],image['imageAudit']['imageId']);self.assertEqual(row['network']['ip'],'172.30.80.10')
  self.assertEqual(row['request']['NetworkingConfig']['EndpointsConfig']['retained-network']['MacAddress'],'02:42:ac:1e:50:0a')
  self.assertEqual(row['restoreRestartPolicy'],actual['HostConfig']['RestartPolicy'])
 def test_wrong_source_changed_launch_or_multiple_networks_are_rejected(self):
  for kind in('source','launch','network'):
   saved,actual,image,case=self.fixture()
   if kind=='source':actual['Config']['Labels']['org.opencontainers.image.revision']='c'*40
   if kind=='launch':image['imageAudit']['imageConfig']['Entrypoint']=['other']
   if kind=='network':actual['NetworkSettings']['Networks']['foreign']={}
   with self.assertRaises(Exception):replacement(saved,actual,image,case)
 def test_signed_scope_rejects_extra_apps_domain_decisions_and_gateway_writes(self):
  saved,actual,image,case=self.fixture();row=replacement(saved,actual,image,case)
  plan={'schema':'ouf.udp-resolution-get-native-update-plan.v1','replacements':{'udp':row},'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,'gateway':{'route':{'id':'retained-route'}},'privateReviewBinding':{'sha256':'f'*64},**{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed')}}
  plan['logicalUpdateRef']=digest({'retiredContainerIds':[actual['Id']],'routeId':'retained-route'});scope(plan)
  for key in('identityDecisionsAllowed','databaseMigrationsAllowed','grantChangesAllowed','maximumGatewayWrites'):
   with self.assertRaises(Exception):scope({**plan,key:True})
  with self.assertRaises(Exception):scope({**plan,'replacements':{**plan['replacements'],'onboarding':row}})
if __name__=='__main__':unittest.main()
