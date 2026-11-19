"""Plan compiler boundary tests; synthetic secrets never leave the private plan."""
import base64,copy,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft') ]
from tools.semantic_mcp_update import plan as m
from tools.semantic_mcp_update.owner import scope

class Compiler(unittest.TestCase):
 def fixture(self):
  host={'NetworkMode':'fixture-net','RestartPolicy':{'Name':'on-failure','MaximumRetryCount':5},
   'ReadonlyRootfs':True,'Binds':['/fixture/secret:/run/secret:ro']}
  old={'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],'Cmd':['server'],'WorkingDir':'/app',
   'Env':['MCP_DATABASE_URL=postgres://app:APP_SECRET@pg.fixture:5432/fixture?sslmode=disable','MCP_FINGERPRINT_KEY=PRIVATE_FINGERPRINT'],
   'Labels':{'org.opencontainers.image.revision':'a'*40}}
  claim={'manifestChecksum':'a'*64,'attemptId':'b'*36,'lockVersion':2,'requestHash':'c'*64,'servicePrincipalId':'fixture-workload'}
  history={'humanSubject':'fixture-human','tenant':'fixture-tenant','semanticCommandKey':'stable-owner-key'}
  mounts=[{'Destination':'/run/secret','Source':'/fixture/secret','Type':'bind','RW':False}]
  review={'schema':'ouf.mcp-one-component-update-private-review.v2','readyForExecution':False,'runtimeAuthorityIssued':False,
   'oldNativeConfig':old,'retainedApplicationCreationRequest':{'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':{'fixture-net':{'Aliases':['fixture-mcp']}}}},
   'oldNativeHostConfig':host,'oldNativeMounts':mounts,'oldRuntimeBinding':{'containerId':'1'*64,'mountsHash':m.digest(mounts)},
   'database':{'binding':{'user':'app','database':'fixture','databaseOid':42},'backupReader':'admin','postgresRuntimeBinding':{},
    'before':[],'after':[],'maximumBackupBytes':1073741824},
   'oldNativeNetworks':{'fixture-net':{'IPAddress':'172.29.77.9','MacAddress':'02:42:ac:1d:4d:09','NetworkID':'d'*64}},
   'imageImport':{'nativeImageId':'sha256:'+'e'*64,'archivePath':'/fixture/candidate.tagless.tar'},
   'imageAudit':{'imageId':'sha256:'+'e'*64},'migrationContract':{'command':'migrate-semantic-reprocessing','committedMembershipAllowed':False},
   'retainedClaim':claim,'history':history,'rolePreflight':{'retentionFunctionHash':'f'*64},
   'imagePackage':{'sourceCommit':'b'*40},'engine':{},'programs':{}}
  policy={'installationRef':'fixture','entityRef':'fixture'};policyraw=json.dumps(policy)
  profile={'schema':'ouf.mcp-reprocessing-key-profile.v1','trustPolicyHash':m.hashlib.sha256(policyraw.encode()).hexdigest(),
   'installationRef':'fixture','entityRef':'fixture','installerKeyRef':'existing-fixture-key','intentIssuerRef':'fixture-installer','approvalIssuerRef':'fixture-installer'}
  profileraw=json.dumps(profile);profilehash=m.hashlib.sha256(profileraw.encode()).hexdigest()
  permit={'schema':'ouf.mcp-semantic-reprocessing-session.v1','keyProfileHash':profilehash,'installationRef':'fixture',
   'manifestChecksum':claim['manifestChecksum'],'predecessorAttemptId':claim['attemptId'],'predecessorLockVersion':2,
   'requestHash':claim['requestHash'],'servicePrincipalId':claim['servicePrincipalId'],'humanSubject':history['humanSubject'],
   'tenantId':history['tenant'],'commandKey':history['semanticCommandKey'],'capabilityId':'ouf.semantic.propose','owner':'semantic',
   'operationClass':'COMMAND','priorToolCalls':1,'maximumNewToolCalls':1,'maximumCumulativeToolCalls':2,'expiresAt':2000000000}
  raw=json.dumps(permit).encode();header={'payloadHash':m.hashlib.sha256(raw).hexdigest(),'keyRef':'existing-fixture-key',
   'issuerRef':'fixture-installer','signature':'1'*128}
  files={'profile.json':profileraw,'policy.json':policyraw,'permit.json':json.dumps({'payload':base64.b64encode(raw).decode(),
   'intent':{**header,'role':'DEPLOYMENT_INTENT'},'approval':{**header,'role':'FINAL_DEPLOYMENT_APPROVAL'}})}
  binding={'path':'/fixture/private-review/review.json','sha256':m.digest(review)}
  selection={'schema':'ouf.mcp-single-update-execution-selection.v1','oldContainerName':'fixture-mcp',
   'metadataMountTarget':'/run/mcp-reprocessing','readinessPort':8080}
  return review,binding,Path('/fixture/semantic-mcp-update-execution-abcdefgh'),selection,files,'postgres://admin:ADMIN_SECRET@pg.fixture:5432/fixture?sslmode=disable'
 def test_exact_addresses_mounts_secrets_process_and_restart_policy(self):
  fixture=self.fixture();before=copy.deepcopy(fixture);plan=m.compile_plan(*fixture)
  self.assertEqual(fixture,before);replacement=plan['replacement']['request'];migration=plan['migration']['request']
  self.assertEqual(replacement['Cmd'],['server']);self.assertEqual(replacement['Entrypoint'],['/usr/local/bin/ouf-mcp'])
  self.assertNotIn('ADMIN_SECRET',json.dumps(replacement));self.assertIn('ADMIN_SECRET',json.dumps(migration))
  self.assertNotIn('PRIVATE_FINGERPRINT',json.dumps(migration));self.assertIn('APP_SECRET',json.dumps(replacement))
  self.assertEqual(replacement['HostConfig']['RestartPolicy']['Name'],'no')
  self.assertEqual(plan['replacement']['restoreRestartPolicy']['Name'],'on-failure')
  self.assertEqual(len(replacement['HostConfig']['Binds']),2);self.assertEqual(plan['network']['ip'],'172.29.77.9')
  self.assertEqual(scope(plan)['maximumEffectAttemptsPerStage'],1);self.assertFalse(scope(plan)['semanticDispatchAllowed'])
 def test_wrong_database_admin_origin_or_reprocessing_owner_key_is_denied(self):
  fixture=list(self.fixture());fixture[-1]=fixture[-1].replace('pg.fixture','other.fixture')
  with self.assertRaises(Exception):m.compile_plan(*fixture)
  fixture=list(self.fixture());files=copy.deepcopy(fixture[4]);envelope=json.loads(files['permit.json'])
  payload=json.loads(base64.b64decode(envelope['payload']));payload['commandKey']='different-key'
  envelope['payload']=base64.b64encode(json.dumps(payload).encode()).decode();files['permit.json']=json.dumps(envelope);fixture[4]=files
  with self.assertRaises(Exception):m.compile_plan(*fixture)
 def test_parent_hash_drift_and_overlapping_mounts_fail_before_plan(self):
  fixture=list(self.fixture());fixture[1]['sha256']='0'*64
  with self.assertRaises(Exception):m.compile_plan(*fixture)
  fixture=list(self.fixture());fixture[0]['oldNativeMounts'][0]['Destination']='/run';fixture[1]['sha256']=m.digest(fixture[0])
  with self.assertRaises(Exception):m.compile_plan(*fixture)
 def test_existing_reprocessing_fields_or_wrong_server_command_never_get_replaced_silently(self):
  for alteration in ('feature','command'):
   fixture=list(self.fixture())
   if alteration=='feature':fixture[0]['oldNativeConfig']['Env'].append('MCP_REPROCESSING_PERMIT_FILE=/old')
   else:fixture[0]['oldNativeConfig']['Cmd']=['maintenance-worker']
   fixture[1]['sha256']=m.digest(fixture[0])
   with self.subTest(alteration=alteration),self.assertRaises(Exception):m.compile_plan(*fixture)
 def test_retained_mount_order_projection_is_normalized_without_changing_mounts(self):
  fixture=list(self.fixture());mounts=fixture[0]['oldNativeMounts'];mounts.insert(0,{'Destination':'/z','Source':'/z','Type':'bind','RW':False})
  fixture[0]['oldRuntimeBinding']['mountsHash']=m.digest(sorted(mounts,key=lambda row:row['Destination']));fixture[1]['sha256']=m.digest(fixture[0])
  plan=m.compile_plan(*fixture);self.assertEqual(plan['oldMounts'],mounts)
  self.assertEqual(plan['oldRuntimeBinding']['mountsHash'],m.digest(mounts))
 def test_observed_postgres_mounts_are_bound_without_order_dependency(self):
  fixture=list(self.fixture());mounts=[{'Destination':'/z','Source':'/secret','RW':False},{'Destination':'/a','Source':'/data','RW':True}]
  fixture[0]['database']['postgresRuntimeBinding']={'mountsHash':m.digest(sorted(mounts,key=lambda row:row['Destination']))}
  fixture[1]['sha256']=m.digest(fixture[0]);plan=m.compile_plan(*fixture,postgres_mounts=mounts)
  self.assertEqual(plan['postgresMounts'],mounts)
  changed=copy.deepcopy(mounts);changed[0]['Source']='/changed'
  with self.assertRaisesRegex(Exception,'EXACT_OBSERVED_POSTGRES_MOUNTS_REQUIRED'):m.compile_plan(*fixture,postgres_mounts=changed)
if __name__=='__main__':unittest.main()
